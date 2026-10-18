//! The app: one handle ([`App`], cheap to clone) owning the configuration, the
//! agent, the control supervisor, game detection, fingerprint, map sync and the
//! game process. The UI reads [`App::snapshot`] and listens to [`App::subscribe`]
//! (a [`Change`] per updated part); commands are async methods returning
//! [`CommandError`]s.

use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use beacon_proto::control::{Chunk, ClientMsg, ErrorCode, MapInfo, ServerMsg};
use beacon_proto::fingerprint::{beacon_serial, Fingerprint};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::agent::{AgentHandle, AgentOptions, AgentStats};
use crate::config::{
    validate_player_name, ConfigStore, LaunchOptions, RedundancyOverrides, ServerAddr, RES_RANGE,
};
use crate::control::{self, ConnectParams, ControlEvent, ControlHandle, Credentials, Deps, StatusReport};
use crate::fingerprint::{self, FingerprintError};
use crate::game::detect::{self, GameInfo, Registry, SystemRegistry, UserDirs};
use crate::game::hook::{self, HookError, HookStatus, HOOK_DLL_NAME};
use crate::game::launch::{self, HookEnv, LaunchError, LaunchSpec};
use crate::game::netini::{self, NETWORK_INI};
use crate::game::userdir;
use crate::logging;
use crate::maps::{self, ChunkError, ChunkSource, InstalledRecord, MapState};
use crate::paths::DataDirs;
use crate::state::{
    diff_files, AppState, Change, ChatLine, ConnectionState, FingerprintState, GameProcess, MapEntry,
    MapsState, Notice, NoticeLevel, PeerFiles, ServerInfo, SettingsView, MAX_PEER_FILES,
};
use crate::util;

/// Map chunk requests are paced to at most ~300 per second (the server allows 400).
const CHUNK_GAP: Duration = Duration::from_micros(3300);
/// Wait for one chunk.
const CHUNK_TIMEOUT: Duration = Duration::from_secs(15);
/// Wait for the map listing.
const LISTING_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest chat line sent.
const CHAT_MAX: usize = 500;

/// Options of an app instance. Every path is injectable (tests use temp dirs).
pub struct AppOptions {
    /// Beacon's data directory.
    pub data: DataDirs,
    /// Game folder override (`--game-dir`; wins over the setting).
    pub game_dir: Option<PathBuf>,
    /// Hook DLL to install (`--hook-dll`); default: `wsock32.dll` next to `Beacon.exe`.
    pub hook_dll: Option<PathBuf>,
    /// Test mode (`--multi`; also implied by `--instance N ≥ 2`).
    pub multi: bool,
    /// Launch options for this run (`--windowed --xres --yres`), instead of the setting.
    pub launch: Option<LaunchOptions>,
    /// Registry access (fake in tests).
    pub registry: Arc<dyn Registry + Send + Sync>,
    /// `%APPDATA%` (base of BFME's user folder).
    pub appdata: Option<PathBuf>,
    /// Agent tuning (the redundancy comes from the settings).
    pub agent: AgentOptions,
    /// Compute the game-data fingerprint (background thread).
    pub fingerprint: bool,
    /// Maps folder override (tests).
    pub maps_dir: Option<PathBuf>,
}

impl AppOptions {
    /// Defaults for a data directory: real registry and `%APPDATA%`.
    pub fn new(data: DataDirs) -> Self {
        Self {
            data,
            game_dir: None,
            hook_dll: None,
            multi: false,
            launch: None,
            registry: Arc::new(SystemRegistry),
            appdata: crate::paths::appdata_dir(),
            agent: AgentOptions::default(),
            fingerprint: true,
            maps_dir: None,
        }
    }

    /// Test mode: `BEACON_MULTI=1` and an own user folder.
    pub fn test_mode(&self) -> bool {
        self.multi || self.data.instance() >= 2
    }
}

/// Category of a [`CommandError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandErrorKind {
    /// Invalid argument (address, name, setting).
    InvalidInput,
    /// Requires a connection.
    NotConnected,
    /// Host only.
    NotHost,
    /// No usable game installation.
    GameNotFound,
    /// The game is already running.
    GameRunning,
    /// A foreign `wsock32.dll` is in the game folder.
    HookForeign,
    /// The hook DLL is in use (game running).
    HookInUse,
    /// Beacon's hook DLL is missing or invalid.
    HookMissing,
    /// Smart App Control blocked the game.
    SmartAppControlBlocked,
    /// Starting the game failed otherwise.
    LaunchFailed,
    /// Another operation of this kind is running.
    Busy,
    /// File system error.
    Io,
}

/// A failed command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandError {
    /// Category.
    pub kind: CommandErrorKind,
    /// Human-readable text.
    pub message: String,
}

impl CommandError {
    fn new(kind: CommandErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn invalid(message: impl fmt::Display) -> Self {
        Self::new(CommandErrorKind::InvalidInput, message.to_string())
    }

    fn not_connected() -> Self {
        Self::new(CommandErrorKind::NotConnected, "not connected to a server")
    }
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CommandError {}

impl From<HookError> for CommandError {
    fn from(e: HookError) -> Self {
        let kind = match e {
            HookError::Foreign(_) => CommandErrorKind::HookForeign,
            HookError::InUse(_) => CommandErrorKind::HookInUse,
            HookError::SourceMissing(..) | HookError::SourceInvalid(_) => CommandErrorKind::HookMissing,
            HookError::PermissionDenied(_) | HookError::Io(..) => CommandErrorKind::Io,
        };
        Self::new(kind, e.to_string())
    }
}

impl From<LaunchError> for CommandError {
    fn from(e: LaunchError) -> Self {
        let kind = match e {
            LaunchError::SmartAppControlBlocked(_) => CommandErrorKind::SmartAppControlBlocked,
            LaunchError::ExeMissing(_) => CommandErrorKind::GameNotFound,
            _ => CommandErrorKind::LaunchFailed,
        };
        Self::new(kind, e.to_string())
    }
}

/// Errors of [`App::start`].
#[derive(Debug)]
pub enum StartError {
    /// The data directory cannot be created.
    DataDir(PathBuf, std::io::Error),
    /// The agent's socket cannot be bound.
    Agent(std::io::Error),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataDir(p, e) => write!(f, "cannot create {}: {e}", p.display()),
            Self::Agent(e) => write!(f, "cannot open the agent socket: {e}"),
        }
    }
}

impl std::error::Error for StartError {}

/// Arguments of [`App::connect`].
#[derive(Clone, Default, Deserialize)]
pub struct ConnectRequest {
    /// `host[:port]`.
    pub server: String,
    /// Player name.
    pub name: String,
    /// Server password (omit with `use_remembered`).
    pub password: Option<String>,
    /// Use the remembered key of this server.
    #[serde(default)]
    pub use_remembered: bool,
    /// Remember the key (DPAPI) after a successful login.
    #[serde(default)]
    pub remember: bool,
}

impl fmt::Debug for ConnectRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectRequest")
            .field("server", &self.server)
            .field("name", &self.name)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("use_remembered", &self.use_remembered)
            .field("remember", &self.remember)
            .finish()
    }
}

/// Changes for [`App::update_settings`]; `None` keeps a value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct SettingsPatch {
    /// Player name.
    pub player_name: Option<String>,
    /// Game folder; `""` = detect from the registry.
    pub game_dir: Option<String>,
    /// BFME command-line options.
    pub launch: Option<LaunchOptions>,
    /// Set BFME's LAN name before launch.
    pub name_sync: Option<bool>,
    /// Start BFME when the host starts.
    pub auto_launch_on_host_start: Option<bool>,
    /// Redundancy overrides.
    pub redundancy: Option<RedundancyOverrides>,
}

enum ChunkReply {
    Chunk(Chunk),
    Error(ErrorCode, String),
}

struct Inner {
    opts: AppOptions,
    config: Arc<ConfigStore>,
    state: Mutex<AppState>,
    changes: broadcast::Sender<Change>,
    agent: AgentHandle,
    control: tokio::sync::Mutex<Option<ControlHandle>>,
    generation: AtomicU64,
    events_tx: mpsc::Sender<(u64, ControlEvent)>,
    status_tx: watch::Sender<StatusReport>,
    fingerprint_tx: watch::Sender<Option<Arc<Fingerprint>>>,
    fp_cancel: Mutex<Arc<AtomicBool>>,
    session_name: Mutex<Option<String>>,
    session_server: Mutex<String>,
    chunk_sink: Mutex<Option<mpsc::Sender<ChunkReply>>>,
    maps_listing: watch::Sender<Option<Arc<Vec<MapInfo>>>>,
    sync_running: AtomicBool,
    launching: AtomicBool,
    notice_seq: AtomicU64,
    quit_tx: watch::Sender<bool>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The app handle.
#[derive(Clone)]
pub struct App {
    inner: Arc<Inner>,
}

impl fmt::Debug for App {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("App")
            .field("data_dir", &self.inner.opts.data.root())
            .finish_non_exhaustive()
    }
}

impl App {
    /// Starts the app: loads the configuration, starts the agent, the event pumps,
    /// the game detection and (if enabled) the fingerprint thread. Needs a tokio
    /// runtime.
    pub async fn start(opts: AppOptions) -> Result<Self, StartError> {
        let root = opts.data.root().to_path_buf();
        std::fs::create_dir_all(&root).map_err(|e| StartError::DataDir(root.clone(), e))?;
        let (config, warning) = ConfigStore::load(&opts.data.config_file());
        let cfg = config.get();
        let agent_opts = AgentOptions {
            redundancy: cfg.redundancy,
            ..opts.agent
        };
        let (agent, _agent_task) = AgentHandle::start(agent_opts).await.map_err(StartError::Agent)?;
        let state = AppState {
            version: crate::VERSION.to_owned(),
            instance: opts.data.instance(),
            test_mode: opts.test_mode(),
            data_dir: root,
            connection: ConnectionState::Disconnected,
            server: None,
            players: Vec::new(),
            chat: Default::default(),
            maps: MapsState {
                maps_dir: opts.maps_dir.clone(),
                ..MapsState::default()
            },
            game: None,
            hook: HookStatus::Unknown,
            game_process: None,
            agent: agent.stats(),
            fingerprint: FingerprintState::Unavailable {
                reason: "game detection running".into(),
            },
            peer_files: BTreeMap::new(),
            settings: SettingsView::from_config(&cfg),
            notices: Default::default(),
        };
        let (changes, _) = broadcast::channel(256);
        let (events_tx, events_rx) = mpsc::channel(256);
        let inner = Arc::new(Inner {
            opts,
            config: Arc::new(config),
            state: Mutex::new(state),
            changes,
            agent,
            control: tokio::sync::Mutex::new(None),
            generation: AtomicU64::new(0),
            events_tx,
            status_tx: watch::channel(StatusReport::default()).0,
            fingerprint_tx: watch::channel(None).0,
            fp_cancel: Mutex::new(Arc::new(AtomicBool::new(false))),
            session_name: Mutex::new(None),
            session_server: Mutex::new(String::new()),
            chunk_sink: Mutex::new(None),
            maps_listing: watch::channel(None).0,
            sync_running: AtomicBool::new(false),
            launching: AtomicBool::new(false),
            notice_seq: AtomicU64::new(0),
            quit_tx: watch::channel(false).0,
        });
        if let Some(w) = warning {
            inner.notice(NoticeLevel::Warning, w);
        }
        tokio::spawn(pump_control(Arc::clone(&inner), events_rx));
        tokio::spawn(pump_agent(Arc::clone(&inner), inner.agent.watch_stats()));
        let detect_inner = Arc::clone(&inner);
        tokio::spawn(async move { detect_inner.detect().await });
        Ok(Self { inner })
    }

    /// A copy of the current state.
    pub fn snapshot(&self) -> AppState {
        lock(&self.inner.state).clone()
    }

    /// Change notifications (lagging receivers miss some: re-read the snapshot).
    pub fn subscribe(&self) -> broadcast::Receiver<Change> {
        self.inner.changes.subscribe()
    }

    /// The agent's loopback port and local token (what the hook gets).
    pub fn agent_endpoint(&self) -> (u16, u32) {
        (self.inner.agent.port(), self.inner.agent.token())
    }

    /// Current agent statistics.
    pub fn agent_stats(&self) -> AgentStats {
        self.inner.agent.stats()
    }

    /// The data directories.
    pub fn data_dirs(&self) -> &DataDirs {
        &self.inner.opts.data
    }

    /// Connects (replacing any current connection). Progress and errors appear in
    /// `connection`; this only fails for invalid input.
    pub async fn connect(&self, req: ConnectRequest) -> Result<(), CommandError> {
        let mut req = req;
        let addr = ServerAddr::parse(&req.server).map_err(CommandError::invalid)?;
        validate_player_name(&req.name).map_err(CommandError::invalid)?;
        let credentials = match req.password.take() {
            Some(p) if !p.is_empty() => Credentials::Password(p),
            _ if req.use_remembered => Credentials::Remembered,
            _ => return Err(CommandError::invalid("a password is required")),
        };
        let inner = &self.inner;
        let mut control = inner.control.lock().await;
        if let Some(old) = control.take() {
            old.disconnect().await;
        }
        let name = req.name.clone();
        if let Err(e) = inner.config.update(|c| {
            c.player_name = Some(name.clone());
            c.last_server = Some(addr.key());
        }) {
            warn!("cannot save the settings: {e}");
        }
        *lock(&inner.session_name) = Some(name.clone());
        *lock(&inner.session_server) = addr.key();
        inner.refresh_settings();
        // New generation and state in one step: events of the old session that are
        // still queued can no longer change the state.
        let generation = inner.new_generation(ConnectionState::Connecting {
            server: addr.key(),
            attempt: 0,
        });
        info!(server = %addr, name = %name, "connecting");
        let deps = Deps {
            config: Arc::clone(&inner.config),
            agent: inner.agent.clone(),
            events: inner.events_tx.clone(),
            generation,
            status: inner.status_tx.subscribe(),
            fingerprint: inner.fingerprint_tx.subscribe(),
        };
        *control = Some(control::spawn(
            ConnectParams {
                addr,
                name,
                credentials,
                remember: req.remember,
            },
            deps,
        ));
        Ok(())
    }

    /// Disconnects (no reconnect).
    pub async fn disconnect(&self) {
        let inner = &self.inner;
        let mut control = inner.control.lock().await;
        inner.new_generation(ConnectionState::Disconnected);
        if let Some(h) = control.take() {
            h.disconnect().await;
            // The supervisor ends the relay session itself unless it had to be aborted.
            inner.agent.set_session(None).await;
            info!("disconnected");
        }
    }

    /// Sends a chat line.
    pub async fn send_chat(&self, text: &str) -> Result<(), CommandError> {
        let text = text.trim();
        if text.is_empty() {
            return Err(CommandError::invalid("empty message"));
        }
        let text: String = text.chars().take(CHAT_MAX).collect();
        self.inner.send(ClientMsg::Chat { text }).await
    }

    /// Sets the ready flag.
    pub async fn set_ready(&self, ready: bool) -> Result<(), CommandError> {
        self.inner.send(ClientMsg::Ready { ready }).await
    }

    /// Host only: every player's launcher starts BFME.
    pub async fn launch_all(&self) -> Result<(), CommandError> {
        self.inner.require_host()?;
        self.inner.send(ClientMsg::LaunchAll).await
    }

    /// Host only: removes a player.
    pub async fn kick(&self, name: &str) -> Result<(), CommandError> {
        self.inner.require_host()?;
        self.inner
            .send(ClientMsg::Kick {
                name: name.to_owned(),
            })
            .await
    }

    /// Asks the server for another player's file list (appears in `peer_files`).
    pub async fn request_fingerprint(&self, name: &str) -> Result<(), CommandError> {
        self.inner
            .send(ClientMsg::FingerprintGet {
                name: name.to_owned(),
            })
            .await
    }

    /// Starts BFME (hook install, name sync, test-mode user folder, process).
    pub async fn launch_game(&self) -> Result<(), CommandError> {
        Arc::clone(&self.inner).launch_game().await
    }

    /// Changes settings (validated; saved at once).
    pub async fn update_settings(&self, patch: SettingsPatch) -> Result<(), CommandError> {
        if let Some(n) = &patch.player_name {
            validate_player_name(n).map_err(CommandError::invalid)?;
        }
        let game_dir = match patch.game_dir.as_deref().map(str::trim) {
            None => None,
            Some("") => Some(None),
            Some(d) => {
                let p = PathBuf::from(d);
                if !p.is_absolute() {
                    return Err(CommandError::invalid("the game folder must be an absolute path"));
                }
                Some(Some(p))
            }
        };
        if let Some(l) = &patch.launch {
            for v in [l.xres, l.yres].into_iter().flatten() {
                if !RES_RANGE.contains(&v) {
                    return Err(CommandError::invalid(format!(
                        "resolution {v} outside {}..={}",
                        RES_RANGE.start(),
                        RES_RANGE.end()
                    )));
                }
            }
        }
        if let Some(r) = &patch.redundancy {
            for v in [r.lobby, r.game, r.other].into_iter().flatten() {
                if !(1..=beacon_proto::relay::MAX_REDUNDANCY).contains(&v) {
                    return Err(CommandError::invalid("redundancy must be 1..=3"));
                }
            }
        }
        let before = self.inner.config.get();
        let patch2 = patch.clone();
        self.inner
            .config
            .update(move |c| {
                if let Some(n) = patch2.player_name {
                    c.player_name = Some(n);
                }
                if let Some(d) = game_dir {
                    c.game_dir = d;
                }
                if let Some(l) = patch2.launch {
                    c.launch = l;
                }
                if let Some(v) = patch2.name_sync {
                    c.name_sync = v;
                }
                if let Some(v) = patch2.auto_launch_on_host_start {
                    c.auto_launch_on_host_start = v;
                }
                if let Some(r) = patch2.redundancy {
                    c.redundancy = r;
                }
            })
            .map_err(|e| CommandError::new(CommandErrorKind::Io, format!("cannot save the settings: {e}")))?;
        let after = self.inner.config.get();
        self.inner.refresh_settings();
        if after.redundancy != before.redundancy {
            self.inner.agent.set_redundancy(after.redundancy).await;
        }
        if after.game_dir != before.game_dir {
            let inner = Arc::clone(&self.inner);
            tokio::spawn(async move { inner.detect().await });
        }
        Ok(())
    }

    /// Downloads missing maps (runs in the background; progress in `maps.sync`).
    pub async fn sync_maps(&self) -> Result<(), CommandError> {
        let inner = &self.inner;
        if !lock(&inner.state).is_connected() {
            return Err(CommandError::not_connected());
        }
        let maps_dir = inner
            .maps_dir()
            .ok_or_else(|| CommandError::new(CommandErrorKind::GameNotFound, "the BFME maps folder is unknown"))?;
        if inner.sync_running.swap(true, Ordering::SeqCst) {
            return Err(CommandError::new(CommandErrorKind::Busy, "a map sync is already running"));
        }
        // Visible at once: the snapshot after this call shows the running sync.
        inner.update(Change::Maps, |s| {
            s.maps.sync = crate::state::SyncProgress {
                running: true,
                ..Default::default()
            };
        });
        let inner = Arc::clone(inner);
        tokio::spawn(async move {
            inner.run_sync(maps_dir).await;
            inner.sync_running.store(false, Ordering::SeqCst);
        });
        Ok(())
    }

    /// Forgets the pinned identity (and remembered key) of a server.
    pub async fn reset_server_pin(&self, address: &str) -> Result<bool, CommandError> {
        let addr = ServerAddr::parse(address).map_err(CommandError::invalid)?;
        let had = self
            .inner
            .config
            .reset_pin(&addr)
            .map_err(|e| CommandError::new(CommandErrorKind::Io, e.to_string()))?;
        self.inner.refresh_settings();
        if had {
            self.inner
                .notice(NoticeLevel::Info, format!("the identity of {addr} will be pinned again at the next login"));
        }
        Ok(had)
    }

    /// Forgets the remembered key of a server.
    pub async fn forget_password(&self, address: &str) -> Result<bool, CommandError> {
        let addr = ServerAddr::parse(address).map_err(CommandError::invalid)?;
        let had = self
            .inner
            .config
            .forget_psk(&addr)
            .map_err(|e| CommandError::new(CommandErrorKind::Io, e.to_string()))?;
        self.inner.refresh_settings();
        Ok(had)
    }

    /// Restores BFME's original LAN name (Network.ini `UserName`).
    pub async fn restore_user_name(&self) -> Result<bool, CommandError> {
        let prefs = self
            .inner
            .user_dirs()
            .map(|u| u.prefs_dir)
            .ok_or_else(|| CommandError::new(CommandErrorKind::GameNotFound, "BFME's user folder is unknown"))?;
        let backup = self.inner.opts.data.name_backup_file();
        tokio::task::spawn_blocking(move || netini::restore_user_name(&prefs.join(NETWORK_INI), &backup))
            .await
            .map_err(|e| CommandError::new(CommandErrorKind::Io, e.to_string()))?
            .map_err(|e| CommandError::new(CommandErrorKind::Io, e.to_string()))
    }

    /// Another start asked this instance to show itself: publishes
    /// [`Change::Activate`].
    pub fn activate(&self) {
        self.inner.notify(Change::Activate);
    }

    /// Shuts down: disconnects, stops the fingerprint thread and the agent, and
    /// publishes [`Change::Quit`]. A running game keeps running (without network).
    pub async fn quit(&self) {
        if *self.inner.quit_tx.borrow() {
            return;
        }
        self.disconnect().await;
        lock(&self.inner.fp_cancel).store(true, Ordering::Relaxed);
        self.inner.agent.shutdown().await;
        let game_running = lock(&self.inner.state)
            .game_process
            .as_ref()
            .is_some_and(|g| g.running);
        if game_running {
            warn!("BFME is still running; it has no network without Beacon");
        }
        self.inner.notify(Change::Quit);
        self.inner.quit_tx.send_replace(true);
    }

    /// Starts [`quit`](Self::quit) in the background (for synchronous callers such as
    /// the handover listener). Outside a tokio runtime it only logs a warning.
    pub fn request_quit(&self) {
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                let app = self.clone();
                rt.spawn(async move { app.quit().await });
            }
            Err(_) => warn!("request_quit called outside the runtime; ignored"),
        }
    }

    /// Resolves once [`quit`](Self::quit) was called.
    pub async fn quit_requested(&self) {
        let mut rx = self.inner.quit_tx.subscribe();
        while !*rx.borrow_and_update() {
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Inner {
    fn notify(&self, change: Change) {
        let _ = self.changes.send(change);
    }

    fn update(&self, change: Change, f: impl FnOnce(&mut AppState)) {
        f(&mut lock(&self.state));
        self.notify(change);
    }

    /// Like [`update`](Self::update), but only while `generation` is current
    /// (checked under the state lock).
    fn update_current(&self, generation: u64, change: Change, f: impl FnOnce(&mut AppState)) -> bool {
        let mut st = lock(&self.state);
        if self.generation.load(Ordering::SeqCst) != generation {
            return false;
        }
        f(&mut st);
        drop(st);
        self.notify(change);
        true
    }

    /// Starts a new connection generation with `connection` as state (session
    /// data cleared); returns the generation.
    fn new_generation(&self, connection: ConnectionState) -> u64 {
        *lock(&self.chunk_sink) = None;
        let mut st = lock(&self.state);
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        st.connection = connection;
        st.server = None;
        st.players.clear();
        drop(st);
        self.notify(Change::Connection);
        self.notify(Change::Lobby);
        generation
    }

    fn notice(&self, level: NoticeLevel, text: impl Into<String>) {
        let text = text.into();
        match level {
            NoticeLevel::Info => info!("{text}"),
            NoticeLevel::Warning => warn!("{text}"),
            NoticeLevel::Error => tracing::error!("{text}"),
        }
        let id = self.notice_seq.fetch_add(1, Ordering::Relaxed) + 1;
        self.update(Change::Notice, |s| {
            s.push_notice(Notice {
                id,
                ts_ms: util::unix_ms(),
                level,
                text,
            });
        });
    }

    fn refresh_settings(&self) {
        let view = SettingsView::from_config(&self.config.get());
        self.update(Change::Settings, |s| s.settings = view);
    }

    async fn send(&self, msg: ClientMsg) -> Result<(), CommandError> {
        if !lock(&self.state).is_connected() {
            return Err(CommandError::not_connected());
        }
        let control = self.control.lock().await;
        match control.as_ref() {
            Some(h) if h.send_wait(msg).await => Ok(()),
            _ => Err(CommandError::not_connected()),
        }
    }

    fn require_host(&self) -> Result<(), CommandError> {
        match &lock(&self.state).server {
            Some(s) if s.you_are_host => Ok(()),
            Some(_) => Err(CommandError::new(CommandErrorKind::NotHost, "only the host can do this")),
            None => Err(CommandError::not_connected()),
        }
    }

    fn hook_source(&self) -> Option<PathBuf> {
        self.opts.hook_dll.clone().or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(|d| d.join(HOOK_DLL_NAME)))
        })
    }

    /// The user folder the game of this instance uses (test mode: below the
    /// instance's `BEACON_USERDIR`).
    fn user_dirs(&self) -> Option<UserDirs> {
        let game = lock(&self.state).game.clone()?;
        if self.opts.test_mode() {
            Some(game.user_dirs_below(&self.opts.data.userdata_dir()))
        } else {
            game.user
        }
    }

    fn maps_dir(&self) -> Option<PathBuf> {
        self.opts
            .maps_dir
            .clone()
            .or_else(|| self.user_dirs().map(|u| u.maps_dir))
    }

    // ---- detection and fingerprint ----------------------------------------

    async fn detect(self: Arc<Self>) {
        let cfg = self.config.get();
        let override_dir = self.opts.game_dir.clone().or(cfg.game_dir);
        let registry = Arc::clone(&self.opts.registry);
        let appdata = self.opts.appdata.clone();
        let hook_src = self.hook_source();
        let result = tokio::task::spawn_blocking(move || {
            let info = detect::detect(override_dir.as_deref(), &*registry, appdata.as_deref());
            let hook = match (&info.game_dir, &hook_src) {
                (Some(dir), Some(src)) => hook::status(dir, src),
                (Some(_), None) => HookStatus::SourceMissing {
                    expected: PathBuf::from(HOOK_DLL_NAME),
                },
                (None, _) => HookStatus::Unknown,
            };
            (info, hook)
        })
        .await;
        let Ok((info, hook_status)) = result else {
            self.notice(NoticeLevel::Error, "game detection failed");
            return;
        };
        for w in &info.warnings {
            self.notice(NoticeLevel::Warning, w.clone());
        }
        if let Some(exe) = &info.exe {
            info!(
                exe = %exe.path.display(),
                identity = exe.known.as_deref().unwrap_or("unknown"),
                "BFME found"
            );
        }
        let game_dir = info.game_dir.clone().filter(|_| info.exe.is_some());
        self.update(Change::Game, |s| s.game = Some(info));
        self.update(Change::Hook, |s| s.hook = hook_status);
        let maps_dir = self.maps_dir();
        self.update(Change::Maps, |s| s.maps.maps_dir = maps_dir);
        match game_dir {
            Some(dir) if self.opts.fingerprint => self.start_fingerprint(dir),
            Some(_) => self.update(Change::Fingerprint, |s| {
                s.fingerprint = FingerprintState::Unavailable {
                    reason: "disabled".into(),
                }
            }),
            None => self.update(Change::Fingerprint, |s| {
                s.fingerprint = FingerprintState::Unavailable {
                    reason: "BFME not found".into(),
                }
            }),
        }
    }

    fn start_fingerprint(self: &Arc<Self>, game_dir: PathBuf) {
        let cancel = {
            let mut slot = lock(&self.fp_cancel);
            slot.store(true, Ordering::Relaxed);
            let fresh = Arc::new(AtomicBool::new(false));
            *slot = Arc::clone(&fresh);
            fresh
        };
        let hook = self.hook_source().filter(|p| p.is_file());
        let cache = self.opts.data.cache_file();
        let inner = Arc::downgrade(self);
        let spawned = std::thread::Builder::new()
            .name("fingerprint".into())
            .spawn(move || {
                let mut last = std::time::Instant::now();
                let result = fingerprint::run(&game_dir, hook.as_deref(), &cache, &cancel, &mut |p| {
                    let done = p.files_done == p.files_total;
                    if done || last.elapsed() >= Duration::from_millis(250) {
                        last = std::time::Instant::now();
                        if let Some(inner) = inner.upgrade() {
                            inner.update(Change::Fingerprint, |s| {
                                s.fingerprint = FingerprintState::Computing { progress: *p }
                            });
                        }
                    }
                });
                let Some(inner) = inner.upgrade() else { return };
                match result {
                    Ok(fp) => {
                        info!(digest = %fp.short(), files = fp.entries.len(), "game-data fingerprint ready");
                        let state = FingerprintState::Ready {
                            digest: fp.digest_hex.clone(),
                            short: fp.short().to_owned(),
                            files: fp.entries.len(),
                        };
                        inner.fingerprint_tx.send_replace(Some(Arc::new(fp)));
                        inner.update(Change::Fingerprint, |s| s.fingerprint = state);
                    }
                    Err(FingerprintError::Cancelled) => {}
                    Err(e) => {
                        warn!("fingerprint failed: {e}");
                        inner.update(Change::Fingerprint, |s| {
                            s.fingerprint = FingerprintState::Failed { error: e.to_string() }
                        });
                    }
                }
            });
        if let Err(e) = spawned {
            self.notice(NoticeLevel::Error, format!("cannot start the fingerprint thread: {e}"));
        }
    }

    // ---- control events ---------------------------------------------------

    fn our_name(&self) -> Option<String> {
        lock(&self.session_name).clone()
    }

    async fn on_control(self: &Arc<Self>, generation: u64, ev: ControlEvent) {
        let server = lock(&self.session_server).clone();
        match ev {
            ControlEvent::Connecting { attempt } => {
                self.update_current(generation, Change::Connection, |s| {
                    s.connection = ConnectionState::Connecting { server, attempt };
                });
            }
            ControlEvent::Authenticating => {
                self.update_current(generation, Change::Connection, |s| {
                    s.connection = ConnectionState::Authenticating { server };
                });
            }
            ControlEvent::Connected(c) => {
                info!(
                    "connected to {} ({:?}) as {}, vIP {}{}",
                    c.address,
                    c.server_name,
                    self.our_name().unwrap_or_default(),
                    c.vip,
                    if c.you_are_host { ", host" } else { "" }
                );
                if c.newly_pinned {
                    info!("pinned the identity of {}", c.address);
                }
                if !c.motd.is_empty() {
                    info!("MOTD: {}", c.motd);
                }
                self.update_current(generation, Change::Connection, |s| {
                    s.connection = ConnectionState::Connected {
                        server: c.address.clone(),
                    };
                    s.server = Some(ServerInfo {
                        address: c.address.clone(),
                        name: c.server_name.clone(),
                        motd: c.motd.clone(),
                        vip: c.vip.to_string(),
                        you_are_host: c.you_are_host,
                        relay_addr: c.relay_addr.to_string(),
                        newly_pinned: c.newly_pinned,
                    });
                });
                self.refresh_settings();
            }
            ControlEvent::Message(msg) => self.on_server_msg(generation, msg).await,
            ControlEvent::Disconnected { error, retry_in } => {
                let connection = match (error, retry_in) {
                    (Some(error), Some(delay)) => ConnectionState::Reconnecting {
                        server,
                        retry_in_ms: u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                        message: error.to_string(),
                        error,
                    },
                    (Some(error), None) => {
                        self.notice(NoticeLevel::Error, error.to_string());
                        ConnectionState::Failed {
                            server,
                            message: error.to_string(),
                            error,
                        }
                    }
                    (None, _) => ConnectionState::Disconnected,
                };
                *lock(&self.chunk_sink) = None;
                if self.update_current(generation, Change::Connection, |s| {
                    s.connection = connection;
                    s.server = None;
                    s.players.clear();
                }) {
                    self.notify(Change::Lobby);
                }
            }
        }
    }

    async fn on_server_msg(self: &Arc<Self>, generation: u64, msg: ServerMsg) {
        match msg {
            ServerMsg::Lobby { players } => {
                let me = self.our_name().map(|n| n.to_lowercase());
                let summary: Vec<String> = players
                    .iter()
                    .map(|p| {
                        format!(
                            "{} ({}{}{}{})",
                            p.name,
                            p.vip,
                            if p.is_host { ", host" } else { "" },
                            if p.ready { ", ready" } else { "" },
                            if p.in_game { ", in game" } else { "" }
                        )
                    })
                    .collect();
                debug!("lobby: {}", summary.join(", "));
                self.update_current(generation, Change::Lobby, |s| {
                    if let (Some(server), Some(me)) = (&mut s.server, &me) {
                        if let Some(p) = players.iter().find(|p| p.name.to_lowercase() == *me) {
                            server.you_are_host = p.is_host;
                        }
                    }
                    s.players = players;
                });
            }
            ServerMsg::Chat { from, text, ts } => {
                if from.is_empty() {
                    info!("[server] {text}");
                } else {
                    info!("[chat] {from}: {text}");
                }
                self.update_current(generation, Change::Chat, |s| s.push_chat(ChatLine { from, text, ts }));
            }
            ServerMsg::Maps { maps } => self.on_listing(maps),
            ServerMsg::Chunk(c) => {
                if let Some(sink) = lock(&self.chunk_sink).as_ref() {
                    let _ = sink.try_send(ChunkReply::Chunk(c));
                }
            }
            ServerMsg::Error { code, text } => {
                let routed = matches!(
                    code,
                    ErrorCode::UnknownMap | ErrorCode::UnknownFile | ErrorCode::BadOffset | ErrorCode::RateLimited
                ) && lock(&self.chunk_sink)
                    .as_ref()
                    .is_some_and(|sink| sink.try_send(ChunkReply::Error(code, text.clone())).is_ok());
                if !routed {
                    self.notice(NoticeLevel::Warning, format!("server: {text}"));
                }
            }
            ServerMsg::FingerprintFiles { name, files, complete } => {
                let ours = self.fingerprint_tx.borrow().clone();
                let differs = ours.map(|fp| diff_files(&fp.entries, &files)).unwrap_or_default();
                self.update(Change::PeerFiles, |s| {
                    if !s.peer_files.contains_key(&name) && s.peer_files.len() >= MAX_PEER_FILES {
                        s.peer_files.pop_first();
                    }
                    s.peer_files.insert(name, PeerFiles { files, complete, differs });
                });
            }
            ServerMsg::Launch => {
                info!("the host started the game");
                let auto = self.config.get().auto_launch_on_host_start;
                let running = lock(&self.state)
                    .game_process
                    .as_ref()
                    .is_some_and(|g| g.running);
                if auto && !running {
                    let inner = Arc::clone(self);
                    tokio::spawn(async move {
                        if let Err(e) = Arc::clone(&inner).launch_game().await {
                            inner.notice(NoticeLevel::Error, format!("cannot start BFME: {e}"));
                        }
                    });
                } else if !running {
                    self.notice(NoticeLevel::Info, "the host started the game");
                }
            }
            ServerMsg::Welcome { .. } | ServerMsg::Pong { .. } | ServerMsg::Kick { .. } | ServerMsg::Unknown => {}
        }
    }

    fn on_listing(self: &Arc<Self>, maps: Vec<MapInfo>) {
        let maps = Arc::new(maps);
        self.maps_listing.send_replace(Some(Arc::clone(&maps)));
        info!("server offers {} map(s)", maps.len());
        let inner = Arc::clone(self);
        tokio::spawn(async move { inner.refresh_map_states(maps, &BTreeMap::new()).await });
    }

    /// Recomputes the local state of every listed map (blocking work off the
    /// runtime); `failures` keep their error text.
    async fn refresh_map_states(&self, maps: Arc<Vec<MapInfo>>, failures: &BTreeMap<String, String>) {
        let maps_dir = self.maps_dir();
        let listing = Arc::clone(&maps);
        let entries = tokio::task::spawn_blocking(move || match maps_dir {
            Some(dir) => {
                let record = InstalledRecord::load(&dir);
                maps::plan(&listing, &dir, &record)
                    .into_iter()
                    .map(|p| MapEntry {
                        state: p.state(),
                        problem: p.invalid.clone().or_else(|| {
                            (p.state() == MapState::Conflict)
                                .then(|| "a local file differs and was not installed by Beacon".to_owned())
                        }),
                        files: p.files.len(),
                        total_size: p.total_size,
                        name: p.name,
                    })
                    .collect::<Vec<_>>()
            }
            None => listing
                .iter()
                .map(|m| MapEntry {
                    name: m.name.clone(),
                    total_size: m.total_size,
                    files: m.files.len(),
                    state: MapState::Missing,
                    problem: Some("the BFME maps folder is unknown".into()),
                })
                .collect(),
        })
        .await
        .unwrap_or_default();
        self.update(Change::Maps, |s| {
            s.maps.listing_received = true;
            s.maps.maps = entries
                .into_iter()
                .map(|mut e| {
                    if let Some(why) = failures.get(&e.name) {
                        e.state = MapState::Failed;
                        e.problem = Some(why.clone());
                    }
                    e
                })
                .collect();
        });
    }

    // ---- map sync ---------------------------------------------------------

    async fn run_sync(self: &Arc<Self>, maps_dir: PathBuf) {
        let mut listing_rx = self.maps_listing.subscribe();
        listing_rx.borrow_and_update();
        let listing = match self.send(ClientMsg::MapList).await {
            Ok(()) => match tokio::time::timeout(LISTING_TIMEOUT, listing_rx.changed()).await {
                Ok(Ok(())) => listing_rx.borrow_and_update().clone(),
                _ => self.maps_listing.borrow().clone(),
            },
            Err(_) => None,
        };
        let Some(listing) = listing else {
            self.finish_sync(Some("no map listing from the server".into()), Vec::new());
            return;
        };
        let dir = maps_dir.clone();
        let plan_listing = Arc::clone(&listing);
        let plans = tokio::task::spawn_blocking(move || {
            let record = InstalledRecord::load(&dir);
            (maps::plan(&plan_listing, &dir, &record), record)
        })
        .await;
        let Ok((plans, mut record)) = plans else {
            self.finish_sync(Some("planning failed".into()), Vec::new());
            return;
        };
        let todo: Vec<_> = plans.into_iter().filter(|p| p.state() == MapState::Missing).collect();
        let total = todo.iter().fold(0u64, |a, p| a.saturating_add(p.bytes_needed()));
        self.update(Change::Maps, |s| s.maps.sync.bytes_total = total);
        let (sink_tx, sink_rx) = mpsc::channel(16);
        *lock(&self.chunk_sink) = Some(sink_tx);
        let mut source = ControlChunkSource {
            inner: Arc::clone(self),
            rx: sink_rx,
            last: None,
        };
        let mut downloaded = Vec::new();
        let mut failures = BTreeMap::new();
        let mut done = 0u64;
        let mut last_report = Instant::now();
        for plan in &todo {
            info!(map = %plan.name, bytes = plan.bytes_needed(), "downloading map");
            self.update(Change::Maps, |s| {
                s.maps.sync.current = Some(plan.name.clone());
                if let Some(e) = s.maps.maps.iter_mut().find(|e| e.name == plan.name) {
                    e.state = MapState::Downloading;
                }
            });
            let mut failed = None;
            for f in plan
                .files
                .iter()
                .filter(|f| matches!(f.action, maps::Action::Download | maps::Action::Replace))
            {
                let mut on_bytes = |n: u64| {
                    done = done.saturating_add(n);
                    if last_report.elapsed() >= Duration::from_millis(200) {
                        last_report = Instant::now();
                        self.update(Change::Maps, |s| s.maps.sync.bytes_done = done);
                    }
                };
                if let Err(e) = maps::download_file(&mut source, &maps_dir, &plan.name, f, &mut record, &mut on_bytes).await {
                    failed = Some(e.to_string());
                    break;
                }
            }
            match failed {
                Some(why) => {
                    warn!(map = %plan.name, "map download failed: {why}");
                    failures.insert(plan.name.clone(), why);
                }
                None => {
                    info!(map = %plan.name, "map installed");
                    downloaded.push(plan.name.clone());
                }
            }
        }
        *lock(&self.chunk_sink) = None;
        self.update(Change::Maps, |s| s.maps.sync.bytes_done = done);
        let error = (!failures.is_empty()).then(|| format!("{} map(s) failed", failures.len()));
        self.refresh_map_states(listing, &failures).await;
        self.finish_sync(error, downloaded);
    }

    fn finish_sync(&self, error: Option<String>, downloaded: Vec<String>) {
        if let Some(e) = &error {
            self.notice(NoticeLevel::Warning, format!("map sync: {e}"));
        }
        self.update(Change::Maps, |s| {
            s.maps.sync.running = false;
            s.maps.sync.current = None;
            s.maps.sync.downloaded = downloaded;
            s.maps.sync.last_error = error;
        });
    }

    // ---- game -------------------------------------------------------------

    async fn launch_game(self: Arc<Self>) -> Result<(), CommandError> {
        if self.launching.swap(true, Ordering::SeqCst) {
            return Err(CommandError::new(CommandErrorKind::Busy, "BFME is being started"));
        }
        let result = self.launch_inner().await;
        self.launching.store(false, Ordering::SeqCst);
        if let Err(e) = &result {
            self.notice(NoticeLevel::Error, format!("cannot start BFME: {e}"));
        }
        result
    }

    async fn launch_inner(self: &Arc<Self>) -> Result<(), CommandError> {
        let st = lock(&self.state).clone();
        if st.game_process.as_ref().is_some_and(|g| g.running) {
            return Err(CommandError::new(CommandErrorKind::GameRunning, "BFME is already running"));
        }
        let server = st.server.clone().ok_or_else(CommandError::not_connected)?;
        let vip: Ipv4Addr = server
            .vip
            .parse()
            .map_err(|_| CommandError::new(CommandErrorKind::NotConnected, "no virtual IP yet"))?;
        let game = st
            .game
            .clone()
            .ok_or_else(|| CommandError::new(CommandErrorKind::GameNotFound, "the game detection is still running"))?;
        let not_found = || CommandError::new(CommandErrorKind::GameNotFound, "BFME was not found; set the game folder");
        let game_dir = game.game_dir.clone().ok_or_else(not_found)?;
        let exe = game.exe_path().ok_or_else(not_found)?;
        let cfg = self.config.get();
        let name = self
            .our_name()
            .or(cfg.player_name.clone())
            .ok_or_else(|| CommandError::invalid("no player name"))?;
        let launch_opts = self.opts.launch.clone().unwrap_or_else(|| cfg.launch.clone());
        let hook_src = self
            .hook_source()
            .ok_or_else(|| CommandError::new(CommandErrorKind::HookMissing, "Beacon's wsock32.dll was not found"))?;
        let test_mode = self.opts.test_mode();
        let userdir = test_mode.then(|| self.opts.data.userdata_dir());
        let prefs_dir = self.user_dirs().map(|u| u.prefs_dir);
        let real_prefs = game.user.as_ref().map(|u| u.prefs_dir.clone());
        let backup = self.opts.data.name_backup_file();
        let logs = self.opts.data.logs_dir();
        let (agent_port, token) = (self.agent.port(), self.agent.token());
        let name_sync = cfg.name_sync;

        let job = tokio::task::spawn_blocking(move || -> Result<_, CommandError> {
            let mut notes = Vec::new();
            match hook::install(&game_dir, &hook_src)? {
                hook::InstallOutcome::AlreadyCurrent => {}
                outcome => notes.push(format!("hook DLL {outcome:?}: {}", game_dir.join(HOOK_DLL_NAME).display())),
            }
            if let (Some(base), Some(prefs)) = (&userdir, &prefs_dir) {
                let p = userdir::prepare(base, prefs, real_prefs.as_deref(), &name, &backup)
                    .map_err(|e| CommandError::new(CommandErrorKind::Io, e.to_string()))?;
                if !p.copied.is_empty() {
                    notes.push(format!("test mode: copied {} into {}", p.copied.join(", "), p.prefs_dir.display()));
                }
            }
            if name_sync {
                if let Some(prefs) = &prefs_dir {
                    match netini::sync_user_name(&prefs.join(NETWORK_INI), &name, &backup) {
                        Ok(r) if r.changed => notes.push(format!(
                            "BFME LAN name set to {name:?} (was {:?})",
                            r.previous.unwrap_or_default()
                        )),
                        Ok(_) => {}
                        Err(e) => notes.push(format!("cannot set the BFME LAN name: {e}")),
                    }
                }
            }
            let log = logging::hook_log_path(&logs).ok();
            let spec = LaunchSpec {
                exe,
                cwd: game_dir,
                args: launch_opts.args(),
                env: HookEnv {
                    agent_port,
                    token,
                    vip,
                    serial: beacon_serial(&name),
                    log: log.clone(),
                    multi_userdir: userdir,
                },
            };
            info!(exe = %spec.exe.display(), args = ?spec.args, "starting BFME");
            let child = launch::spawn(&spec)?;
            Ok((child, log, notes))
        });
        let (mut child, log, notes) = job
            .await
            .map_err(|e| CommandError::new(CommandErrorKind::LaunchFailed, e.to_string()))??;
        for n in notes {
            self.notice(NoticeLevel::Info, n);
        }
        let pid = child.id();
        info!(pid, "BFME started");
        self.status_tx.send_modify(|r| r.in_game = true);
        self.update(Change::Game, |s| {
            s.game_process = Some(GameProcess {
                pid,
                started_at_ms: util::unix_ms(),
                running: true,
                exit_code: None,
                hook_log: log,
            });
        });
        let hook_status = {
            let dir = game.game_dir.clone();
            let src = self.hook_source();
            tokio::task::spawn_blocking(move || match (dir, src) {
                (Some(d), Some(s)) => hook::status(&d, &s),
                _ => HookStatus::Unknown,
            })
            .await
            .unwrap_or(HookStatus::Unknown)
        };
        self.update(Change::Hook, |s| s.hook = hook_status);
        let inner = Arc::clone(self);
        tokio::spawn(async move {
            let code = tokio::task::spawn_blocking(move || child.wait())
                .await
                .ok()
                .and_then(Result::ok)
                .and_then(|s| s.code());
            inner.on_game_exit(pid, code).await;
        });
        Ok(())
    }

    async fn on_game_exit(&self, pid: u32, code: Option<i32>) {
        info!(pid, ?code, "BFME exited");
        self.agent.game_exited().await;
        self.status_tx.send_modify(|r| r.in_game = false);
        self.update(Change::Game, |s| {
            if let Some(g) = s.game_process.as_mut().filter(|g| g.pid == pid) {
                g.running = false;
                g.exit_code = code;
            }
        });
    }
}

async fn pump_control(inner: Arc<Inner>, mut rx: mpsc::Receiver<(u64, ControlEvent)>) {
    let mut quit = inner.quit_tx.subscribe();
    loop {
        let (generation, ev) = tokio::select! {
            ev = rx.recv() => match ev {
                Some(e) => e,
                None => return,
            },
            _ = quit.wait_for(|q| *q) => return,
        };
        if generation == inner.generation.load(Ordering::SeqCst) {
            inner.on_control(generation, ev).await;
        }
    }
}

async fn pump_agent(inner: Arc<Inner>, mut stats: watch::Receiver<AgentStats>) {
    while stats.changed().await.is_ok() {
        let s = stats.borrow_and_update().clone();
        inner.status_tx.send_if_modified(|r| {
            let changed = r.rtt_ms != s.rtt_ms || r.loss_pct != s.loss_pct;
            r.rtt_ms = s.rtt_ms;
            r.loss_pct = s.loss_pct;
            changed
        });
        inner.update(Change::Agent, |st| st.agent = s);
    }
}

/// Map chunks over the control connection, paced below the server's limit.
struct ControlChunkSource {
    inner: Arc<Inner>,
    rx: mpsc::Receiver<ChunkReply>,
    last: Option<Instant>,
}

impl ChunkSource for ControlChunkSource {
    async fn get(&mut self, map: &str, file: &str, offset: u64) -> Result<Chunk, ChunkError> {
        if let Some(t) = self.last {
            tokio::time::sleep_until(t + CHUNK_GAP).await;
        }
        self.last = Some(Instant::now());
        while self.rx.try_recv().is_ok() {}
        let msg = ClientMsg::MapGet {
            map: map.to_owned(),
            file: file.to_owned(),
            offset,
        };
        if self.inner.send(msg).await.is_err() {
            return Err(ChunkError::Disconnected);
        }
        match tokio::time::timeout(CHUNK_TIMEOUT, self.rx.recv()).await {
            Ok(Some(ChunkReply::Chunk(c))) => Ok(c),
            Ok(Some(ChunkReply::Error(code, text))) => Err(ChunkError::Server(code, text)),
            Ok(None) => Err(ChunkError::Disconnected),
            Err(_) => Err(ChunkError::Timeout),
        }
    }
}

/// Reads the game detection synchronously (used by `Beacon.exe detect`).
pub fn detect_now(game_dir: Option<&Path>, hook_dll: Option<&Path>) -> (GameInfo, HookStatus) {
    let info = detect::detect(game_dir, &SystemRegistry, crate::paths::appdata_dir().as_deref());
    let hook = match (&info.game_dir, hook_dll) {
        (Some(dir), Some(src)) => hook::status(dir, src),
        (Some(_), None) => HookStatus::SourceMissing {
            expected: PathBuf::from(HOOK_DLL_NAME),
        },
        (None, _) => HookStatus::Unknown,
    };
    (info, hook)
}
