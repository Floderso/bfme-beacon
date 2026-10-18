//! Shared server state: the lobby behind a mutex (never held across `.await`),
//! lobby/event fan-out channels, the relay handle, the map repository, the
//! handshake guard and counters. Control connections call into it; the status
//! endpoint reads it.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use beacon_proto::control::{
    is_safe_file_name, is_safe_rel_path, Chunk, ConfigStatus, Error as ControlError, ErrorCode,
    GameConfig, Player, ServerHello, ServerMsg,
};
use beacon_proto::fingerprint::{self, FileEntry};
use beacon_proto::relay::{RelayKey, KEY_LEN};
use tokio::sync::{broadcast, mpsc, watch, Semaphore};
use tracing::{debug, info, warn};

use crate::config::Settings;
use crate::limits::{canonical_ip, Denied, GuardConfig, HandshakeGuard};
use crate::lobby::{self, FingerprintList, JoinError, JoinRequest, Lobby};
use crate::maps::{self, ChunkError, MapRepo};
use crate::relay::{RelayHandle, RelayStats};
use crate::webhook::{EventKind, Notifier};
use crate::{lock, unix_ms};

/// Capacity of the chat/launch broadcast channel (a lagging connection skips).
pub const EVENT_QUEUE_LEN: usize = 256;
/// Chat lines replayed to a joining player.
pub const CHAT_HISTORY_LEN: usize = 20;
/// Minimum time between two `launch_all`.
pub const LAUNCH_COOLDOWN: Duration = Duration::from_secs(10);
/// Maximum number of fingerprint entries stored per player.
pub const MAX_FINGERPRINT_FILES: usize = 8192;
/// Minimum time between two game-configuration changes (each one is a large
/// message to every player).
pub const CONFIG_COOLDOWN: Duration = Duration::from_secs(2);
const CHUNK_READERS: usize = 4;
const VERSION_MAX: usize = 32;
const MAX_REPORTED_RTT_MS: u32 = 60_000;

/// An error answer: code and German text for the player.
pub type Reject = (ErrorCode, String);

fn reject(code: ErrorCode, text: impl Into<String>) -> Reject {
    (code, text.into())
}

/// The lobby as sent to every connection (pre-encoded once).
#[derive(Debug)]
pub struct LobbyView {
    /// The player list.
    pub players: Vec<Player>,
    /// `{"t":"lobby",…}` JSON.
    pub json: Arc<[u8]>,
}

impl LobbyView {
    fn new(players: Vec<Player>) -> Result<Self, ControlError> {
        let json = (ServerMsg::Lobby {
            players: players.clone(),
        })
        .to_json()?;
        Ok(Self {
            players,
            json: json.into(),
        })
    }

    fn empty() -> Self {
        Self::new(Vec::new()).unwrap_or_else(|_| Self {
            players: Vec::new(),
            json: Arc::from(&br#"{"t":"lobby","players":[]}"#[..]),
        })
    }
}

/// The lobby's game configuration as sent to every connection (pre-encoded once).
#[derive(Debug)]
pub struct ConfigView {
    /// The configuration; `None` = vanilla.
    pub config: Option<Arc<GameConfig>>,
    /// Who set it (empty for the start-up state).
    pub by: String,
    /// `{"t":"game_config",…}` JSON.
    pub json: Arc<[u8]>,
}

impl ConfigView {
    fn new(config: Option<Arc<GameConfig>>, by: String) -> Result<Self, ControlError> {
        let json = (ServerMsg::GameConfig {
            config: config.as_deref().cloned().map(Box::new),
            by: by.clone(),
        })
        .to_json()?;
        Ok(Self {
            config,
            by,
            json: json.into(),
        })
    }

    fn vanilla() -> Self {
        Self::new(None, String::new()).unwrap_or_else(|_| Self {
            config: None,
            by: String::new(),
            json: Arc::from(&br#"{"t":"game_config","config":null,"by":""}"#[..]),
        })
    }
}

/// Monotonic counters for `/status`.
#[derive(Debug, Default)]
pub struct Counters {
    /// Accepted TCP connections.
    pub connections_total: AtomicU64,
    /// Open TCP connections.
    pub connections_active: AtomicU64,
    /// Connections refused before the handshake (ban, limits).
    pub connections_refused: AtomicU64,
    /// Failed handshakes (wrong password, garbage, timeout).
    pub handshake_failures: AtomicU64,
    /// Successful logins.
    pub logins: AtomicU64,
    /// Chat lines.
    pub chat_lines: AtomicU64,
    /// Map chunks served.
    pub chunks_served: AtomicU64,
    /// Map bytes served.
    pub chunk_bytes: AtomicU64,
}

fn bump(counter: &AtomicU64, n: u64) {
    counter.fetch_add(n, Ordering::Relaxed);
}

pub(crate) struct ConnHandle {
    pub(crate) kick: watch::Sender<Option<String>>,
    pub(crate) peer: SocketAddr,
    pub(crate) kicked: bool,
}

pub(crate) struct HubState {
    pub(crate) lobby: Lobby,
    pub(crate) conns: HashMap<u64, ConnHandle>,
    chat_history: VecDeque<Arc<[u8]>>,
    last_launch: Option<Instant>,
    last_config_change: Option<Instant>,
}

/// Everything [`Hub::new`] needs.
pub struct HubInit {
    /// Validated settings.
    pub settings: Arc<Settings>,
    /// Relay command handle.
    pub relay: RelayHandle,
    /// Relay statistics.
    pub relay_stats: watch::Receiver<Arc<RelayStats>>,
    /// Map repository.
    pub maps: watch::Receiver<Arc<MapRepo>>,
    /// Rescan trigger.
    pub rescan: mpsc::Sender<()>,
    /// Notifications.
    pub notifier: Option<Notifier>,
    /// Sticky vIP table updates (for persistence).
    pub vips: watch::Sender<Arc<BTreeMap<String, Ipv4Addr>>>,
    /// Restored sticky vIP table.
    pub restored_vips: BTreeMap<String, Ipv4Addr>,
    /// UDP port of the relay (announced in `welcome`).
    pub relay_port: u16,
}

/// Shared server state.
pub struct Hub {
    pub(crate) settings: Arc<Settings>,
    hello_line: Arc<[u8]>,
    pub(crate) state: Mutex<HubState>,
    lobby_tx: watch::Sender<Arc<LobbyView>>,
    config_tx: watch::Sender<Arc<ConfigView>>,
    events_tx: broadcast::Sender<Arc<[u8]>>,
    relay: RelayHandle,
    pub(crate) relay_stats: watch::Receiver<Arc<RelayStats>>,
    pub(crate) maps: watch::Receiver<Arc<MapRepo>>,
    rescan: mpsc::Sender<()>,
    notifier: Option<Notifier>,
    vips_tx: watch::Sender<Arc<BTreeMap<String, Ipv4Addr>>>,
    pub(crate) guard: Mutex<HandshakeGuard>,
    chunk_readers: Semaphore,
    relay_port: u16,
    /// Counters.
    pub counters: Counters,
    /// Start time.
    pub started: Instant,
    /// Start time, ms since the Unix epoch.
    pub started_unix_ms: u64,
}

/// A successful login.
pub struct Joined {
    /// Member id.
    pub id: u64,
    /// Relay session id.
    pub session: u32,
    /// Relay key.
    pub key: RelayKey,
    /// Assigned vIP.
    pub vip: Ipv4Addr,
    /// The player is host.
    pub is_host: bool,
    /// Kick signal (reason).
    pub kick_rx: watch::Receiver<Option<String>>,
    /// Lobby updates.
    pub lobby_rx: watch::Receiver<Arc<LobbyView>>,
    /// Game-configuration updates.
    pub config_rx: watch::Receiver<Arc<ConfigView>>,
    /// Chat lines and launch commands.
    pub events_rx: broadcast::Receiver<Arc<[u8]>>,
    /// Recent chat lines to replay.
    pub history: Vec<Arc<[u8]>>,
}

/// An admitted TCP connection (counts towards the per-IP limits until dropped).
pub struct Admission {
    hub: Arc<Hub>,
    ip: IpAddr,
    pending: bool,
}

impl Admission {
    /// Reports the handshake outcome (once).
    pub fn handshake_done(&mut self, ok: bool) {
        if !self.pending {
            return;
        }
        self.pending = false;
        let ban = lock(&self.hub.guard).handshake_done(self.ip, ok, Instant::now());
        if !ok {
            bump(&self.hub.counters.handshake_failures, 1);
        }
        if let Some(ban) = ban {
            warn!(ip = %self.ip, "too many failed handshakes, refusing this IP for {} s", ban.as_secs());
        }
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        lock(&self.hub.guard).disconnected(self.ip, self.pending, Instant::now());
        self.hub
            .counters
            .connections_active
            .fetch_sub(1, Ordering::Relaxed);
    }
}

fn random<const N: usize>() -> Option<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).ok()?;
    Some(bytes)
}

impl Hub {
    /// Creates the hub.
    pub fn new(init: HubInit) -> Result<Arc<Self>, String> {
        let settings = init.settings;
        let hello = ServerHello {
            kdf: settings.kdf,
            ..ServerHello::new(settings.server_name.clone(), settings.salt)
        };
        let hello_line: Arc<[u8]> = hello.to_line().map_err(|e| e.to_string())?.into();
        let limits = &settings.limits;
        let mut lobby = Lobby::new(
            settings.max_players,
            &settings.admin_names,
            Duration::from_secs(limits.kick_ban_secs),
        );
        let restored = lobby.restore_vips(&init.restored_vips);
        if restored > 0 {
            info!("restored {restored} sticky vIPs");
        }
        let ban = Duration::from_secs(limits.handshake_ban_secs);
        let guard = HandshakeGuard::new(GuardConfig {
            max_failures: limits.handshake_failures,
            ban,
            max_ban: ban.max(Duration::from_secs(15 * 60)),
            max_conns_per_ip: limits.max_connections_per_ip,
            max_pending_total: limits.max_pending_handshakes,
            ..GuardConfig::default()
        });
        let (lobby_tx, _) = watch::channel(Arc::new(LobbyView::empty()));
        let (config_tx, _) = watch::channel(Arc::new(ConfigView::vanilla()));
        let (events_tx, _) = broadcast::channel(EVENT_QUEUE_LEN);
        Ok(Arc::new(Self {
            settings,
            hello_line,
            state: Mutex::new(HubState {
                lobby,
                conns: HashMap::new(),
                chat_history: VecDeque::new(),
                last_launch: None,
                last_config_change: None,
            }),
            lobby_tx,
            config_tx,
            events_tx,
            relay: init.relay,
            relay_stats: init.relay_stats,
            maps: init.maps,
            rescan: init.rescan,
            notifier: init.notifier,
            vips_tx: init.vips,
            guard: Mutex::new(guard),
            chunk_readers: Semaphore::new(CHUNK_READERS),
            relay_port: init.relay_port,
            counters: Counters::default(),
            started: Instant::now(),
            started_unix_ms: unix_ms(),
        }))
    }

    /// Settings.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// The plaintext hello line.
    pub fn hello_line(&self) -> &[u8] {
        &self.hello_line
    }

    /// UDP relay port.
    pub fn relay_port(&self) -> u16 {
        self.relay_port
    }

    /// Admits a new TCP connection or refuses it (ban, limits).
    pub fn admit(self: &Arc<Self>, peer: SocketAddr) -> Result<Admission, Denied> {
        let ip = canonical_ip(peer.ip());
        let result = lock(&self.guard).admit(ip, Instant::now());
        match result {
            Ok(()) => {
                bump(&self.counters.connections_total, 1);
                bump(&self.counters.connections_active, 1);
                Ok(Admission {
                    hub: Arc::clone(self),
                    ip,
                    pending: true,
                })
            }
            Err(denied) => {
                bump(&self.counters.connections_refused, 1);
                Err(denied)
            }
        }
    }

    /// Adds a player to the lobby (after `hello`). The caller must call
    /// [`leave`](Self::leave) when the connection ends.
    pub fn join(
        &self,
        name: &str,
        version: &str,
        fingerprint: Option<String>,
        peer: SocketAddr,
    ) -> Result<Joined, Reject> {
        let fingerprint = match fingerprint {
            None => None,
            Some(f) if lobby::is_valid_fingerprint(&f) => Some(f.to_ascii_lowercase()),
            Some(_) => {
                return Err(reject(
                    ErrorCode::BadRequest,
                    "Ungültiger Fingerprint (64 Hex-Ziffern erwartet).",
                ))
            }
        };
        let version: String = version
            .chars()
            .filter(|c| !c.is_control())
            .take(VERSION_MAX)
            .collect();
        let key = random::<KEY_LEN>()
            .map(RelayKey::from_bytes)
            .ok_or_else(|| reject(ErrorCode::Internal, "Kein Zufall verfügbar."))?;
        let mut st = lock(&self.state);
        let mut session = 0u32;
        for _ in 0..64 {
            let candidate = random::<4>().map(u32::from_le_bytes).unwrap_or(0);
            if candidate != 0 && !st.lobby.session_in_use(candidate) {
                session = candidate;
                break;
            }
        }
        if session == 0 {
            return Err(reject(ErrorCode::Internal, "Kein Zufall verfügbar."));
        }
        let joined = st
            .lobby
            .join(
                JoinRequest {
                    name: name.to_owned(),
                    version,
                    fingerprint,
                    session,
                },
                Instant::now(),
            )
            .map_err(|e| match e {
                JoinError::BadName(e) => reject(ErrorCode::BadName, e.to_string()),
                JoinError::NameTaken => reject(
                    ErrorCode::NameTaken,
                    format!("Der Name „{name}“ ist schon vergeben."),
                ),
                JoinError::Full => reject(ErrorCode::ServerFull, "Der Server ist voll."),
                JoinError::Kicked { remaining } => reject(
                    ErrorCode::BadRequest,
                    format!(
                        "Du wurdest entfernt und kannst in {} s wieder beitreten.",
                        remaining.as_secs().max(1)
                    ),
                ),
            })?;
        let (kick, kick_rx) = watch::channel(None);
        st.conns.insert(
            joined.id,
            ConnHandle {
                kick,
                peer,
                kicked: false,
            },
        );
        let is_host = st.lobby.is_host(joined.id);
        let count = st.lobby.len();
        if joined.vips_changed {
            self.vips_tx.send_replace(Arc::new(st.lobby.vip_table()));
        }
        self.publish_lobby_locked(&st);
        // Subscribing under the lock keeps history and live events consistent.
        let events_rx = self.events_tx.subscribe();
        let lobby_rx = self.lobby_tx.subscribe();
        let config_rx = self.config_tx.subscribe();
        let history = st.chat_history.iter().cloned().collect();
        drop(st);

        bump(&self.counters.logins, 1);
        info!(name, vip = %joined.vip, %peer, session = format_args!("{session:08x}"), "player joined");
        self.notice(format!("{name} ist beigetreten."));
        if joined.host_changed {
            self.notice(format!("{name} ist jetzt Host."));
        }
        self.notify(
            EventKind::Join,
            format!(
                "{name} ist beigetreten ({count}/{} Spieler).",
                self.settings.max_players
            ),
        );
        Ok(Joined {
            id: joined.id,
            session,
            key,
            vip: joined.vip,
            is_host,
            kick_rx,
            lobby_rx,
            config_rx,
            events_rx,
            history,
        })
    }

    /// Registers the relay session of a joined player; `false` if the relay stopped.
    pub async fn activate_relay(&self, joined: &Joined) -> bool {
        self.relay
            .add(joined.session, joined.key.clone(), joined.vip)
            .await
    }

    /// Removes a player (connection closed). Synchronous, so it can run in `Drop`.
    pub fn leave(&self, id: u64) {
        let mut st = lock(&self.state);
        let handle = st.conns.remove(&id);
        let Some(left) = st.lobby.leave(id) else {
            return;
        };
        self.relay.remove(left.member.session);
        self.publish_lobby_locked(&st);
        let count = st.lobby.len();
        drop(st);
        let name = left.member.name;
        info!(name, "player left");
        if !handle.is_some_and(|h| h.kicked) {
            self.notice(format!("{name} hat die Lobby verlassen."));
            self.notify(
                EventKind::Leave,
                format!(
                    "{name} hat den Server verlassen ({count}/{} Spieler).",
                    self.settings.max_players
                ),
            );
        }
        if let Some(host) = left.new_host {
            self.notice(format!("{host} ist jetzt Host."));
        }
    }

    /// A chat line from a player.
    pub fn chat(&self, id: u64, text: &str) -> Result<(), Reject> {
        let text = lobby::sanitize_chat(text, self.settings.limits.chat_max_len)
            .map_err(|e| reject(ErrorCode::BadRequest, e.to_string()))?;
        let name = lock(&self.state)
            .lobby
            .member(id)
            .map(|m| m.name.clone())
            .ok_or_else(|| reject(ErrorCode::BadRequest, "Nicht angemeldet."))?;
        bump(&self.counters.chat_lines, 1);
        self.push_chat(name, text);
        Ok(())
    }

    /// A server notice in the chat (`from` = "").
    pub fn notice(&self, text: String) {
        self.push_chat(String::new(), text);
    }

    fn push_chat(&self, from: String, text: String) {
        let msg = ServerMsg::Chat {
            from,
            text,
            ts: unix_ms(),
        };
        let json: Arc<[u8]> = match msg.to_json() {
            Ok(j) => j.into(),
            Err(e) => {
                warn!("chat line not encodable: {e}");
                return;
            }
        };
        let mut st = lock(&self.state);
        st.chat_history.push_back(Arc::clone(&json));
        while st.chat_history.len() > CHAT_HISTORY_LEN {
            st.chat_history.pop_front();
        }
        // Sent under the lock: see `join`.
        let _ = self.events_tx.send(json);
    }

    /// Updates the ready flag.
    pub fn set_ready(&self, id: u64, ready: bool) {
        let mut st = lock(&self.state);
        let Some(m) = st.lobby.member_mut(id) else {
            return;
        };
        m.ready = ready;
        self.publish_lobby_locked(&st);
    }

    /// Updates game state, the agent's relay measurements and the readiness for
    /// the game configuration. A change of `in_game` or of the readiness state
    /// is published at once; new measurements and progress percentages (which
    /// launchers report continuously) go out with the periodic lobby refresh, so
    /// that N players reporting every second do not cause N² full lobby messages
    /// per second.
    pub fn set_status(
        &self,
        id: u64,
        in_game: bool,
        rtt_ms: Option<u32>,
        loss_pct: Option<u8>,
        config: Option<ConfigStatus>,
    ) {
        let mut st = lock(&self.state);
        let Some(m) = st.lobby.member_mut(id) else {
            return;
        };
        let config = config.and_then(ConfigStatus::sanitized);
        let config_changed = match (&m.config, &config) {
            (None, None) => false,
            (Some(a), Some(b)) => a.id != b.id || a.state != b.state || a.missing != b.missing,
            _ => true,
        };
        let state_changed = m.in_game != in_game || config_changed;
        m.in_game = in_game;
        m.reported_rtt_ms = rtt_ms.map(|r| r.min(MAX_REPORTED_RTT_MS));
        m.reported_loss_pct = loss_pct.map(|l| l.min(100));
        m.config = config;
        if state_changed {
            self.publish_lobby_locked(&st);
        }
    }

    /// Host action: sets the lobby's game configuration (`None` = vanilla). The
    /// configuration is validated, stored and sent to every player; every ready
    /// flag and readiness report is reset.
    pub fn set_game_config(&self, id: u64, config: Option<Box<GameConfig>>) -> Result<(), Reject> {
        if let Some(c) = &config {
            c.validate().map_err(|e| {
                reject(
                    ErrorCode::BadRequest,
                    format!("Ungültige Spielkonfiguration ({e})."),
                )
            })?;
        }
        let now = Instant::now();
        let mut st = lock(&self.state);
        if !st.lobby.is_host(id) {
            return Err(reject(
                ErrorCode::NotHost,
                "Nur der Host kann die Spielversion wählen.",
            ));
        }
        let host = st
            .lobby
            .member(id)
            .map(|m| m.name.clone())
            .unwrap_or_default();
        let current = self.config_tx.borrow().config.clone();
        if current.as_deref() == config.as_deref() {
            return Ok(());
        }
        if st
            .last_config_change
            .is_some_and(|t| now.saturating_duration_since(t) < CONFIG_COOLDOWN)
        {
            return Err(reject(
                ErrorCode::RateLimited,
                "Die Spielversion wurde gerade erst geändert; bitte kurz warten.",
            ));
        }
        let config: Option<Arc<GameConfig>> = config.map(|c| Arc::new(*c));
        let view = ConfigView::new(config.clone(), host.clone()).map_err(|_| {
            reject(
                ErrorCode::BadRequest,
                "Die Spielkonfiguration ist zu groß für eine Nachricht.",
            )
        })?;
        st.last_config_change = Some(now);
        st.lobby.reset_readiness();
        // Sent under the lock: a player joining now gets either the old
        // configuration and then this change, or this one.
        self.config_tx.send_replace(Arc::new(view));
        self.publish_lobby_locked(&st);
        drop(st);
        let text = match &config {
            Some(c) => {
                info!(host, id = %c.id, guid = %c.guid, version = %c.version, language = %c.language,
                      files = c.files.len(), "game configuration set");
                format!(
                    "{host} hat die Spielversion gewählt: {} {} ({}).",
                    c.name, c.version, c.language
                )
            }
            None => {
                info!(host, "game configuration reset to vanilla");
                format!("{host} hat die Spielversion auf „Vanilla (eigene Installation)“ zurückgesetzt.")
            }
        };
        self.notice(text);
        Ok(())
    }

    /// The current game configuration (`None` = vanilla).
    pub fn game_config(&self) -> Arc<ConfigView> {
        Arc::clone(&self.config_tx.borrow())
    }

    /// Stores a player's fingerprint file list; a complete list also updates the
    /// player's combined fingerprint.
    pub fn set_fingerprint_files(&self, id: u64, files: Vec<FileEntry>, complete: bool) {
        let mut files = files;
        let mut complete = complete;
        if files.len() > MAX_FINGERPRINT_FILES {
            files.truncate(MAX_FINGERPRINT_FILES);
            complete = false;
        }
        let mut st = lock(&self.state);
        let Some(m) = st.lobby.member_mut(id) else {
            return;
        };
        let (files, complete) = fit_fingerprint_answer(&m.name, files, complete);
        if complete {
            m.fingerprint = Some(fingerprint::combine(&files));
        }
        m.files = Some(Arc::new(FingerprintList { files, complete }));
        self.publish_lobby_locked(&st);
    }

    /// Another player's fingerprint list (`fingerprint_files`).
    pub fn fingerprint_files(&self, name: &str) -> Result<ServerMsg, Reject> {
        let st = lock(&self.state);
        let member = st.lobby.find(name).and_then(|id| st.lobby.member(id));
        match member.and_then(|m| m.files.clone().map(|f| (m.name.clone(), f))) {
            Some((name, list)) => Ok(ServerMsg::FingerprintFiles {
                name,
                files: list.files.clone(),
                complete: list.complete,
            }),
            None => Err(reject(
                ErrorCode::UnknownPlayer,
                "Unbekannter Spieler oder keine Dateiliste vorhanden.",
            )),
        }
    }

    /// Host action: every launcher starts BFME.
    pub fn launch_all(&self, id: u64) -> Result<(), Reject> {
        let now = Instant::now();
        let mut st = lock(&self.state);
        if !st.lobby.is_host(id) {
            return Err(reject(ErrorCode::NotHost, "Nur der Host kann das Spiel starten."));
        }
        if st
            .last_launch
            .is_some_and(|t| now.saturating_duration_since(t) < LAUNCH_COOLDOWN)
        {
            return Err(reject(
                ErrorCode::RateLimited,
                "Das Spiel wurde gerade erst gestartet; bitte kurz warten.",
            ));
        }
        let config = self.config_tx.borrow().config.clone();
        if let Some(config) = config {
            let waiting = st.lobby.not_ready_for(&config.id);
            if !waiting.is_empty() {
                return Err(reject(
                    ErrorCode::NotReady,
                    format!(
                        "Noch nicht alle sind für „{} {}“ bereit: {}.",
                        config.name,
                        config.version,
                        waiting.join(", ")
                    ),
                ));
            }
        }
        st.last_launch = Some(now);
        let host = st
            .lobby
            .member(id)
            .map(|m| m.name.clone())
            .unwrap_or_default();
        let names: Vec<String> = st.lobby.members().map(|(_, m)| m.name.clone()).collect();
        if let Ok(json) = ServerMsg::Launch.to_json() {
            let _ = self.events_tx.send(json.into());
        }
        drop(st);
        info!(host, players = names.len(), "launch_all");
        self.notice(format!("{host} startet das Spiel."));
        self.notify(
            EventKind::Launch,
            format!("{host} startet das Spiel: {}.", names.join(", ")),
        );
        Ok(())
    }

    /// Host action: removes a player.
    pub fn kick(&self, id: u64, target: &str) -> Result<(), Reject> {
        let mut st = lock(&self.state);
        if !st.lobby.is_host(id) {
            return Err(reject(ErrorCode::NotHost, "Nur der Host kann Spieler entfernen."));
        }
        let Some(target_id) = st.lobby.find(target) else {
            return Err(reject(ErrorCode::UnknownPlayer, "Unbekannter Spieler."));
        };
        if target_id == id {
            return Err(reject(
                ErrorCode::BadRequest,
                "Du kannst dich nicht selbst entfernen.",
            ));
        }
        let host = st
            .lobby
            .member(id)
            .map(|m| m.name.clone())
            .unwrap_or_default();
        let target_name = st
            .lobby
            .member(target_id)
            .map(|m| m.name.clone())
            .unwrap_or_default();
        st.lobby.ban_name(&target_name, Instant::now());
        if let Some(conn) = st.conns.get_mut(&target_id) {
            conn.kicked = true;
            conn.kick
                .send_replace(Some(format!("Du wurdest von {host} entfernt.")));
        }
        drop(st);
        info!(host, target = target_name, "kick");
        self.notice(format!("{target_name} wurde von {host} entfernt."));
        self.notify(
            EventKind::Kick,
            format!("{target_name} wurde von {host} entfernt."),
        );
        Ok(())
    }

    /// The pre-encoded `maps` message.
    pub fn maps_listing(&self) -> Arc<[u8]> {
        Arc::clone(&self.maps.borrow().listing)
    }

    /// The current map repository.
    pub fn map_repo(&self) -> Arc<MapRepo> {
        Arc::clone(&self.maps.borrow())
    }

    /// One chunk of a map file (`map_get`).
    pub async fn map_chunk(&self, map: &str, file: &str, offset: u64) -> Result<Chunk, Reject> {
        let unknown_map = || reject(ErrorCode::UnknownMap, "Unbekannte Karte.");
        let unknown_file = || reject(ErrorCode::UnknownFile, "Unbekannte Datei.");
        if !is_safe_file_name(map) {
            return Err(unknown_map());
        }
        if !is_safe_rel_path(file) {
            return Err(unknown_file());
        }
        let repo = self.map_repo();
        if repo.map(map).is_none() {
            return Err(unknown_map());
        }
        let entry = repo.file(map, file).cloned().ok_or_else(unknown_file)?;
        if offset > entry.size {
            return Err(reject(ErrorCode::BadOffset, "Offset hinter dem Dateiende."));
        }
        let _permit = self
            .chunk_readers
            .acquire()
            .await
            .map_err(|_| reject(ErrorCode::Internal, "Server wird beendet."))?;
        let dir = self.settings.maps_dir.clone();
        let map_name = map.to_owned();
        let path = entry.path.clone();
        let read =
            tokio::task::spawn_blocking(move || maps::read_chunk(&dir, &map_name, &entry, offset))
                .await;
        match read {
            Ok(Ok((data, eof))) => {
                bump(&self.counters.chunks_served, 1);
                bump(&self.counters.chunk_bytes, data.len() as u64);
                Chunk::new(map, path, offset, &data, eof)
                    .map_err(|_| reject(ErrorCode::Internal, "Interner Fehler."))
            }
            Ok(Err(ChunkError::BadOffset)) => {
                Err(reject(ErrorCode::BadOffset, "Offset hinter dem Dateiende."))
            }
            Ok(Err(ChunkError::Changed)) => {
                self.request_rescan();
                Err(reject(
                    ErrorCode::Internal,
                    "Die Datei hat sich auf dem Server geändert; bitte die Kartenliste neu laden.",
                ))
            }
            Ok(Err(ChunkError::Io(e))) => {
                warn!(map, file = path, "map read failed: {e}");
                Err(reject(ErrorCode::Internal, "Die Datei konnte nicht gelesen werden."))
            }
            Err(e) => {
                warn!("map read task failed: {e}");
                Err(reject(ErrorCode::Internal, "Interner Fehler."))
            }
        }
    }

    /// Asks the map scanner for a rescan (coalesced).
    pub fn request_rescan(&self) {
        let _ = self.rescan.try_send(());
    }

    /// Re-publishes the lobby (fresh relay statistics).
    pub fn publish_lobby(&self) {
        let st = lock(&self.state);
        self.publish_lobby_locked(&st);
    }

    fn publish_lobby_locked(&self, st: &HubState) {
        let stats = Arc::clone(&self.relay_stats.borrow());
        let players = st.lobby.players(|m| {
            stats
                .sessions
                .get(&m.session)
                .and_then(|s| s.upstream_loss_pct)
        });
        self.lobby_tx.send_if_modified(|current| {
            if current.players == players {
                return false;
            }
            match LobbyView::new(players) {
                Ok(view) => {
                    *current = Arc::new(view);
                    true
                }
                Err(e) => {
                    warn!("lobby not encodable: {e}");
                    false
                }
            }
        });
    }

    /// The current lobby view.
    pub fn lobby_view(&self) -> Arc<LobbyView> {
        Arc::clone(&self.lobby_tx.borrow())
    }

    /// Queues a webhook notification (if configured and enabled for `kind`).
    pub fn notify(&self, kind: EventKind, body: String) {
        if let Some(n) = &self.notifier {
            n.notify(kind, body);
        } else {
            debug!(event = kind.name(), "{body}");
        }
    }
}

/// Cuts a fingerprint list so that the `fingerprint_files` answer fits into one
/// message (the request was limited the same way, but the answer adds the name).
fn fit_fingerprint_answer(name: &str, mut files: Vec<FileEntry>, mut complete: bool) -> (Vec<FileEntry>, bool) {
    for _ in 0..32 {
        let msg = ServerMsg::FingerprintFiles {
            name: name.to_owned(),
            files: files.clone(),
            complete,
        };
        match msg.to_json() {
            Ok(_) => return (files, complete),
            Err(ControlError::TooLarge { len, max }) if !files.is_empty() => {
                let scaled = (files.len() as u128)
                    .saturating_mul(max as u128)
                    .saturating_mul(9)
                    / (10u128.saturating_mul(len.max(1) as u128));
                let keep = usize::try_from(scaled)
                    .unwrap_or(0)
                    .min(files.len().saturating_sub(1));
                files.truncate(keep);
                complete = false;
            }
            Err(_) => return (Vec::new(), false),
        }
    }
    (Vec::new(), false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_answer_is_cut_to_fit() {
        let entry = |i: usize| FileEntry::new(&format!("data/{i:05}-{}.big", "x".repeat(150)), 1, &"a".repeat(64));
        let files: Vec<FileEntry> = (0..400).map(entry).collect();
        let (kept, complete) = fit_fingerprint_answer("Frodo", files.clone(), true);
        assert!(!complete);
        assert!(!kept.is_empty() && kept.len() < files.len());
        let msg = ServerMsg::FingerprintFiles {
            name: "Frodo".into(),
            files: kept,
            complete,
        };
        assert!(msg.to_json().is_ok());
        let small: Vec<FileEntry> = (0..3).map(entry).collect();
        assert_eq!(fit_fingerprint_answer("Frodo", small.clone(), true), (small, true));
    }
}
