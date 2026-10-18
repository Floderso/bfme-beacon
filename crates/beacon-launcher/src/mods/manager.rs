//! The app's mod state: the host's catalog, the lobby's configuration, the local
//! preparation (one at a time, on its own thread, cancelled when the lobby's
//! configuration changes), the readiness report for the server, the storage
//! overview and clean-up.
//!
//! The manager publishes three watch channels the app forwards: the UI view
//! ([`ModsView`]), the readiness for `status` ([`ConfigStatus`]) and the ready
//! instance for the game start and the fingerprint ([`ReadyInstance`]).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use beacon_proto::control::{ConfigState, ConfigStatus, GameConfig, PackageRef, MAX_STATUS_TEXT_CHARS};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{info, warn};

use super::http::{HttpTransport, WinHttp};
use super::import::ImportSources;
use super::instance::{self, LinkMode};
use super::library::{AioLocations, PackageSet};
use super::prepare::{self, MissingFile, PrepError, PrepOutcome, PrepProgress, PrepareInput};
use super::resolve::{self, CatalogEntry};
use super::store::Store;
use super::workshop::{self, WorkshopClient, WorkshopOptions};
use super::{fsx, human_size, ModPaths, WORKSHOP_DOWNLOADS_AVAILABLE};

/// Most import folders remembered.
pub const MAX_IMPORT_DIRS: usize = 16;
/// The UI view is updated at most this often while preparing.
const VIEW_INTERVAL: Duration = Duration::from_millis(250);

/// Mod settings (`config.json` → `mods`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ModSettings {
    /// Folder for the store and the instances (default `<data dir>\mods`).
    pub dir: Option<PathBuf>,
    /// Folders searched for package files ("Dateien aus Ordner importieren").
    pub import_dirs: Vec<PathBuf>,
    /// Download missing package files from the BFME Workshop.
    pub workshop_downloads: bool,
}

impl ModSettings {
    /// Drops invalid values (hand-edited files).
    pub fn sanitize(&mut self) {
        if self.dir.as_ref().is_some_and(|d| !d.is_absolute()) {
            self.dir = None;
        }
        let mut seen = BTreeSet::new();
        self.import_dirs
            .retain(|d| d.is_absolute() && seen.insert(d.to_string_lossy().to_lowercase()));
        self.import_dirs.truncate(MAX_IMPORT_DIRS);
    }
}

/// The local preparation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LocalState {
    /// No configuration in the lobby: BFME starts from the normal installation.
    Vanilla,
    /// Preparing.
    Preparing {
        /// Progress.
        progress: PrepProgress,
    },
    /// The instance is complete.
    Ready {
        /// `instances\<id>`.
        instance_dir: PathBuf,
        /// Where BFME starts.
        game_dir: PathBuf,
        /// `-mod` folder (type-1 packages).
        mod_dir: Option<PathBuf>,
        /// Hardlinks or copies.
        link_mode: LinkMode,
        /// A note for the user (copies instead of hardlinks).
        notice: Option<String>,
    },
    /// Files are missing.
    Missing {
        /// Number of missing files.
        count: usize,
        /// The first ones.
        files: Vec<MissingFile>,
        /// Hints.
        notes: Vec<String>,
    },
    /// Preparing failed or was cancelled.
    Error {
        /// German text.
        message: String,
    },
}

/// The lobby's configuration as the UI shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LobbyConfigView {
    /// Configuration id.
    pub id: String,
    /// Package guid.
    pub guid: String,
    /// Version.
    pub version: String,
    /// Name.
    pub name: String,
    /// Author.
    pub author: String,
    /// Language variant.
    pub language: String,
    /// Number of files.
    pub files: usize,
    /// Known total size.
    pub total_size: u64,
    /// Every package (attribution).
    pub layers: Vec<PackageRef>,
    /// Who set it.
    pub set_by: String,
    /// Uses a `-mod` folder.
    pub uses_mod_dir: bool,
}

/// One instance folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstanceView {
    /// Configuration id.
    pub id: String,
    /// Name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// Language.
    pub language: String,
    /// Complete.
    pub complete: bool,
    /// Files.
    pub files: usize,
    /// Size of the files (extra space only with copies).
    pub bytes: u64,
    /// Hardlinks or copies.
    pub link_mode: LinkMode,
    /// The lobby's current configuration.
    pub current: bool,
}

/// Disk usage.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StorageView {
    /// The mods folder.
    pub root: PathBuf,
    /// Files in the store.
    pub store_files: usize,
    /// Their size (what Beacon's mod support occupies with hardlinks).
    pub store_bytes: u64,
    /// Instance folders.
    pub instances: Vec<InstanceView>,
    /// Free space on the volume.
    pub free_bytes: Option<u64>,
    /// Hardlinks possible.
    pub link_mode: Option<LinkMode>,
    /// Why not.
    pub link_note: Option<String>,
}

/// Settings as the UI shows them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModSettingsView {
    /// The mods folder in use.
    pub dir: PathBuf,
    /// It is the default below Beacon's data folder.
    pub dir_is_default: bool,
    /// Import folders.
    pub import_dirs: Vec<PathBuf>,
    /// The setting.
    pub workshop_downloads: bool,
    /// Downloads can be switched on in this build.
    pub workshop_available: bool,
}

/// Everything the UI shows about mods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModsView {
    /// The lobby's configuration (`None` = vanilla).
    pub lobby: Option<LobbyConfigView>,
    /// The local preparation.
    pub local: LocalState,
    /// Selectable configurations (host).
    pub catalog: Vec<CatalogEntry>,
    /// The catalog was read.
    pub catalog_loaded: bool,
    /// Manifests that could not be read.
    pub catalog_problems: Vec<String>,
    /// The game's language code (registry), default for the host's choice.
    pub game_language: Option<String>,
    /// Disk usage.
    pub storage: StorageView,
    /// Settings.
    pub settings: ModSettingsView,
}

impl ModsView {
    /// An empty view (before the manager runs).
    pub fn placeholder() -> Self {
        Self {
            lobby: None,
            local: LocalState::Vanilla,
            catalog: Vec::new(),
            catalog_loaded: false,
            catalog_problems: Vec::new(),
            game_language: None,
            storage: StorageView::default(),
            settings: ModSettingsView {
                dir: PathBuf::new(),
                dir_is_default: true,
                import_dirs: Vec::new(),
                workshop_downloads: false,
                workshop_available: WORKSHOP_DOWNLOADS_AVAILABLE,
            },
        }
    }
}

/// A complete instance of the lobby's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyInstance {
    /// Configuration id.
    pub config_id: String,
    /// Where BFME starts.
    pub game_dir: PathBuf,
    /// `-mod` folder.
    pub mod_dir: Option<PathBuf>,
}

/// An injected workshop (tests): options and transport.
#[derive(Clone)]
pub struct WorkshopSetup {
    /// Options (endpoints, back-off).
    pub options: WorkshopOptions,
    /// Transport.
    pub transport: Arc<dyn HttpTransport>,
}

impl std::fmt::Debug for WorkshopSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkshopSetup").field("options", &self.options).finish_non_exhaustive()
    }
}

/// What [`ModManager::cleanup`] removed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CleanupReport {
    /// Instance folders removed.
    pub instances: usize,
    /// Store files removed.
    pub files: usize,
    /// Bytes freed.
    pub bytes: u64,
}

/// Options of the manager.
#[derive(Debug, Clone)]
pub struct ModManagerOptions {
    /// Beacon's data folder (default mods folder below it).
    pub data_dir: PathBuf,
    /// `%APPDATA%` (the AIO's library and cache).
    pub appdata: Option<PathBuf>,
    /// A test workshop instead of the real one.
    pub workshop: Option<WorkshopSetup>,
}

struct MgrState {
    settings: ModSettings,
    game_dir: Option<PathBuf>,
    game_language: Option<String>,
    lobby: Option<(Arc<GameConfig>, String)>,
    set: Arc<PackageSet>,
}

/// The manager.
pub struct ModManager {
    opts: ModManagerOptions,
    state: Mutex<MgrState>,
    view_tx: watch::Sender<ModsView>,
    status_tx: watch::Sender<ConfigStatus>,
    ready_tx: watch::Sender<Option<ReadyInstance>>,
    cancel: Mutex<Arc<AtomicBool>>,
    generation: AtomicU64,
}

impl std::fmt::Debug for ModManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModManager").field("opts", &self.opts).finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn short(text: &str) -> String {
    text.chars().take(MAX_STATUS_TEXT_CHARS).collect()
}

impl ModManager {
    /// A manager with `settings`; call [`set_environment`](Self::set_environment)
    /// once the game detection is done.
    pub fn new(opts: ModManagerOptions, mut settings: ModSettings) -> Arc<Self> {
        settings.sanitize();
        let paths = paths_for(&opts.data_dir, &settings);
        let view = ModsView {
            lobby: None,
            local: LocalState::Vanilla,
            catalog: Vec::new(),
            catalog_loaded: false,
            catalog_problems: Vec::new(),
            game_language: None,
            storage: StorageView {
                root: paths.root().to_path_buf(),
                ..StorageView::default()
            },
            settings: settings_view(&opts, &settings),
        };
        let mgr = Arc::new(Self {
            state: Mutex::new(MgrState {
                settings,
                game_dir: None,
                game_language: None,
                lobby: None,
                set: Arc::new(PackageSet::new()),
            }),
            opts,
            view_tx: watch::channel(view).0,
            status_tx: watch::channel(ConfigStatus::vanilla()).0,
            ready_tx: watch::channel(None).0,
            cancel: Mutex::new(Arc::new(AtomicBool::new(false))),
            generation: AtomicU64::new(0),
        });
        mgr.refresh_storage();
        mgr
    }

    /// The UI view.
    pub fn view(&self) -> watch::Receiver<ModsView> {
        self.view_tx.subscribe()
    }

    /// The current UI view.
    pub fn snapshot(&self) -> ModsView {
        self.view_tx.borrow().clone()
    }

    /// The readiness report for the server.
    pub fn status(&self) -> watch::Receiver<ConfigStatus> {
        self.status_tx.subscribe()
    }

    /// The ready instance of the lobby's configuration.
    pub fn ready(&self) -> watch::Receiver<Option<ReadyInstance>> {
        self.ready_tx.subscribe()
    }

    /// The current ready instance.
    pub fn ready_instance(&self) -> Option<ReadyInstance> {
        self.ready_tx.borrow().clone()
    }

    /// The lobby's configuration.
    pub fn lobby_config(&self) -> Option<Arc<GameConfig>> {
        lock(&self.state).lobby.as_ref().map(|(c, _)| Arc::clone(c))
    }

    /// The folders in use.
    pub fn paths(&self) -> ModPaths {
        paths_for(&self.opts.data_dir, &lock(&self.state).settings)
    }

    /// Workshop downloads can be enabled (a test endpoint, or a build with
    /// permission).
    pub fn workshop_available(&self) -> bool {
        self.opts.workshop.is_some() || WORKSHOP_DOWNLOADS_AVAILABLE
    }

    fn update_view(&self, f: impl FnOnce(&mut ModsView)) {
        self.view_tx.send_modify(f);
    }

    /// The game folder (registry or setting) and the game's language code.
    pub fn set_environment(self: &Arc<Self>, game_dir: Option<PathBuf>, game_language: Option<String>) {
        let restart = {
            let mut st = lock(&self.state);
            let changed = st.game_dir != game_dir;
            st.game_dir = game_dir;
            st.game_language.clone_from(&game_language);
            changed && st.lobby.is_some()
        };
        self.update_view(|v| v.game_language = game_language);
        self.reload_catalog();
        if restart {
            self.restart();
        }
    }

    /// New settings (from the app's configuration).
    pub fn set_settings(self: &Arc<Self>, mut settings: ModSettings) {
        settings.sanitize();
        let (restart, view) = {
            let mut st = lock(&self.state);
            let changed = st.settings.dir != settings.dir
                || st.settings.import_dirs != settings.import_dirs
                || st.settings.workshop_downloads != settings.workshop_downloads;
            st.settings = settings.clone();
            (changed && st.lobby.is_some(), settings_view(&self.opts, &settings))
        };
        self.update_view(|v| v.settings = view);
        self.refresh_storage();
        if restart && !matches!(self.snapshot().local, LocalState::Ready { .. }) {
            self.restart();
        }
    }

    /// The lobby's configuration changed (`None` = vanilla). Cancels a running
    /// preparation and starts one for the new configuration.
    pub fn set_lobby_config(self: &Arc<Self>, config: Option<Arc<GameConfig>>, set_by: String) {
        {
            let mut st = lock(&self.state);
            let same = match (&st.lobby, &config) {
                (Some((a, _)), Some(b)) => a.id == b.id,
                (None, None) => true,
                _ => false,
            };
            if same {
                if let Some((_, by)) = &mut st.lobby {
                    by.clone_from(&set_by);
                }
                return;
            }
            st.lobby = config.clone().map(|c| (c, set_by.clone()));
        }
        let view = config.as_ref().map(|c| LobbyConfigView {
            id: c.id.clone(),
            guid: c.guid.clone(),
            version: c.version.clone(),
            name: c.name.clone(),
            author: c.author.clone(),
            language: c.language.clone(),
            files: c.files.len(),
            total_size: c.total_size(),
            layers: c.layers.clone(),
            set_by,
            uses_mod_dir: c.has_mod_dir(),
        });
        self.update_view(|v| v.lobby = view);
        self.restart();
    }

    /// Prepares the lobby's configuration again (after the user added files).
    pub fn retry(self: &Arc<Self>) {
        self.restart();
    }

    /// Cancels the running preparation.
    pub fn cancel(&self) {
        lock(&self.cancel).store(true, Ordering::Relaxed);
    }

    /// Stops everything (app shutdown).
    pub fn shutdown(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.cancel();
    }

    fn restart(self: &Arc<Self>) {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let cancel = {
            let mut slot = lock(&self.cancel);
            slot.store(true, Ordering::Relaxed);
            let fresh = Arc::new(AtomicBool::new(false));
            *slot = Arc::clone(&fresh);
            fresh
        };
        let (config, settings, game_dir) = {
            let st = lock(&self.state);
            (st.lobby.as_ref().map(|(c, _)| Arc::clone(c)), st.settings.clone(), st.game_dir.clone())
        };
        self.ready_tx.send_replace(None);
        let Some(config) = config else {
            self.status_tx.send_replace(ConfigStatus::vanilla());
            self.update_view(|v| v.local = LocalState::Vanilla);
            return;
        };
        let preparing = ConfigStatus {
            id: config.id.clone(),
            state: ConfigState::Preparing,
            progress: Some(0),
            missing: None,
            text: None,
        };
        self.status_tx.send_replace(preparing);
        self.update_view(|v| {
            v.local = LocalState::Preparing {
                progress: PrepProgress::default(),
            }
        });
        let mgr = Arc::downgrade(self);
        let paths = paths_for(&self.opts.data_dir, &settings);
        let aio = AioLocations::new(self.opts.appdata.as_deref(), game_dir.as_deref());
        let sources = ImportSources {
            game_dir,
            aio_caches: aio.caches,
            extra_dirs: settings.import_dirs.clone(),
            exclude: vec![paths.root().to_path_buf()],
        };
        let workshop = if settings.workshop_downloads {
            match &self.opts.workshop {
                Some(setup) => Some(WorkshopClient::new(setup.options.clone(), Arc::clone(&setup.transport), paths.manifest_cache())),
                None if WORKSHOP_DOWNLOADS_AVAILABLE => Some(WorkshopClient::new(
                    WorkshopOptions::default(),
                    Arc::new(WinHttp {
                        user_agent: workshop::user_agent(),
                        system_proxy: true,
                    }),
                    paths.manifest_cache(),
                )),
                None => None,
            }
        } else {
            None
        };
        let spawned = std::thread::Builder::new().name("mods-prepare".into()).spawn(move || {
            info!(id = %config.id, name = %config.name, version = %config.version, language = %config.language, "preparing the game configuration");
            let input = PrepareInput {
                config: &config,
                paths: &paths,
                sources: &sources,
                workshop: workshop.as_ref(),
            };
            let mut last_view = Instant::now();
            let mut last_percent = 0u8;
            let result = prepare::prepare(&input, &cancel, &mut |p| {
                let Some(m) = mgr.upgrade() else { return };
                if m.generation.load(Ordering::SeqCst) != generation {
                    return;
                }
                if p.percent != last_percent {
                    last_percent = p.percent;
                    m.status_tx.send_modify(|s| s.progress = Some(p.percent));
                }
                if last_view.elapsed() >= VIEW_INTERVAL {
                    last_view = Instant::now();
                    m.update_view(|v| v.local = LocalState::Preparing { progress: p.clone() });
                }
            });
            let Some(m) = mgr.upgrade() else { return };
            if m.generation.load(Ordering::SeqCst) != generation {
                return;
            }
            m.finish(&config, result);
        });
        if let Err(e) = spawned {
            self.update_view(|v| {
                v.local = LocalState::Error {
                    message: format!("Beacon konnte die Vorbereitung nicht starten: {e}"),
                }
            });
        }
    }

    fn finish(&self, config: &GameConfig, result: Result<PrepOutcome, PrepError>) {
        let (status, local, ready) = match result {
            Ok(PrepOutcome::Ready { instance, notice }) => {
                info!(id = %config.id, dir = %instance.game_dir.display(), mode = ?instance.record.link_mode, "game configuration ready");
                if let Some(n) = &notice {
                    warn!("{n}");
                }
                (
                    ConfigStatus::ready(config.id.clone()),
                    LocalState::Ready {
                        instance_dir: instance.root.clone(),
                        game_dir: instance.game_dir.clone(),
                        mod_dir: instance.mod_dir.clone(),
                        link_mode: instance.record.link_mode,
                        notice,
                    },
                    Some(ReadyInstance {
                        config_id: config.id.clone(),
                        game_dir: instance.game_dir,
                        mod_dir: instance.mod_dir,
                    }),
                )
            }
            Ok(PrepOutcome::Missing { count, files, notes }) => {
                warn!(id = %config.id, count, "game configuration: files missing");
                let names: Vec<&str> = files.iter().take(3).map(|f| f.path.as_str()).collect();
                let more = if count > names.len() { ", …" } else { "" };
                (
                    ConfigStatus {
                        id: config.id.clone(),
                        state: ConfigState::Missing,
                        progress: None,
                        missing: Some(u32::try_from(count).unwrap_or(u32::MAX)),
                        text: Some(short(&format!("{}{more}", names.join(", ")))),
                    },
                    LocalState::Missing { count, files, notes },
                    None,
                )
            }
            Err(e) => {
                let message = e.to_string();
                warn!(id = %config.id, "game configuration not prepared: {message}");
                (
                    ConfigStatus {
                        id: config.id.clone(),
                        state: ConfigState::Error,
                        progress: None,
                        missing: None,
                        text: Some(short(&message)),
                    },
                    LocalState::Error { message },
                    None,
                )
            }
        };
        self.status_tx.send_replace(status);
        self.ready_tx.send_replace(ready);
        self.update_view(|v| v.local = local);
        self.refresh_storage_now();
    }

    /// Reads the AIO's library and the manifest cache again (background).
    pub fn reload_catalog(self: &Arc<Self>) {
        let mgr = Arc::downgrade(self);
        let (aio, cache, language, store_dir) = {
            let st = lock(&self.state);
            let paths = paths_for(&self.opts.data_dir, &st.settings);
            (
                AioLocations::new(self.opts.appdata.as_deref(), st.game_dir.as_deref()),
                paths.manifest_cache(),
                st.game_language.clone(),
                paths.store(),
            )
        };
        let spawned = std::thread::Builder::new().name("mods-catalog".into()).spawn(move || {
            let set = PackageSet::load(&aio, Some(&cache));
            let store = Store::open(&store_dir).ok();
            let known = |md5: &str| store.as_ref().and_then(|s| s.known_size(md5));
            let catalog = resolve::catalog(&set, language.as_deref(), &known);
            let problems: Vec<String> = set
                .problems
                .iter()
                .take(20)
                .map(|(p, e)| format!("{}: {e}", p.display()))
                .collect();
            info!(packages = set.len(), entries = catalog.len(), "package catalog read");
            let Some(m) = mgr.upgrade() else { return };
            lock(&m.state).set = Arc::new(set);
            m.update_view(|v| {
                v.catalog = catalog;
                v.catalog_problems = problems;
                v.catalog_loaded = true;
            });
        });
        if let Err(e) = spawned {
            warn!("cannot read the package catalog: {e}");
        }
    }

    /// Builds the configuration for a catalog key (`guid@version`) and language
    /// (blocking: reads the store index).
    pub fn resolve(&self, key: &str, language: Option<&str>) -> Result<GameConfig, String> {
        let (set, game_language, store_dir) = {
            let st = lock(&self.state);
            (Arc::clone(&st.set), st.game_language.clone(), paths_for(&self.opts.data_dir, &st.settings).store())
        };
        let (guid, version) = key.split_once('@').ok_or_else(|| format!("invalid key {key:?}"))?;
        let layers = resolve::layers(&set, guid, Some(version)).map_err(|e| e.to_string())?;
        let offered = resolve::languages(&layers);
        let language = match language {
            Some(l) => l.to_owned(),
            None => resolve::default_language(&offered, game_language.as_deref()),
        };
        let store = Store::open(&store_dir).ok();
        let known = |md5: &str| store.as_ref().and_then(|s| s.known_size(md5));
        resolve::build_config(&layers, &language, &known).map_err(|e| e.to_string())
    }

    /// Recomputes the storage overview (background).
    pub fn refresh_storage(self: &Arc<Self>) {
        let mgr = Arc::downgrade(self);
        let spawned = std::thread::Builder::new().name("mods-storage".into()).spawn(move || {
            if let Some(m) = mgr.upgrade() {
                m.refresh_storage_now();
            }
        });
        if let Err(e) = spawned {
            warn!("cannot compute the mod storage: {e}");
        }
    }

    fn refresh_storage_now(&self) {
        let (paths, current) = {
            let st = lock(&self.state);
            (paths_for(&self.opts.data_dir, &st.settings), st.lobby.as_ref().map(|(c, _)| c.id.clone()))
        };
        let view = storage_view(&paths, current.as_deref());
        self.update_view(|v| v.storage = view);
    }

    /// Removes instance folders other than the lobby's current one (and the one
    /// a running game uses), then store files no remaining instance needs, and
    /// unfinished downloads. Blocking.
    pub fn cleanup(&self, in_use: Option<&str>) -> Result<CleanupReport, String> {
        let (paths, current) = {
            let st = lock(&self.state);
            (paths_for(&self.opts.data_dir, &st.settings), st.lobby.as_ref().map(|(c, _)| c.id.clone()))
        };
        let preparing = matches!(self.snapshot().local, LocalState::Preparing { .. });
        let keep: BTreeSet<String> = current.into_iter().chain(in_use.map(str::to_owned)).collect();
        let mut report = CleanupReport::default();
        let mut needed: BTreeSet<String> = BTreeSet::new();
        for (dir, record) in instance::list(&paths.instances()) {
            if keep.contains(&record.id) {
                needed.extend(record.md5s.iter().cloned());
                continue;
            }
            instance::remove(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            report.instances += 1;
            if record.link_mode == LinkMode::Copy {
                report.bytes = report.bytes.saturating_add(record.bytes);
            }
        }
        if preparing {
            // A running preparation may be filling the store right now.
            return Ok(report);
        }
        if let Some(config) = self.lobby_config() {
            needed.extend(config.files.iter().map(|f| f.md5.clone()));
        }
        let store = Store::open(&paths.store()).map_err(|e| e.to_string())?;
        for (md5, size) in store.entries() {
            if !needed.contains(&md5) {
                store.remove(&md5).map_err(|e| format!("{md5}: {e}"))?;
                report.files += 1;
                report.bytes = report.bytes.saturating_add(size);
            }
        }
        for md5 in &needed {
            store.protect(md5);
        }
        let _ = fsx::remove_tree(&paths.downloads());
        info!(instances = report.instances, files = report.files, freed = %human_size(report.bytes), "mod storage cleaned up");
        self.refresh_storage_now();
        Ok(report)
    }
}

fn paths_for(data_dir: &Path, settings: &ModSettings) -> ModPaths {
    ModPaths::new(settings.dir.clone().unwrap_or_else(|| ModPaths::default_root(data_dir)))
}

fn settings_view(opts: &ModManagerOptions, s: &ModSettings) -> ModSettingsView {
    ModSettingsView {
        dir: paths_for(&opts.data_dir, s).root().to_path_buf(),
        dir_is_default: s.dir.is_none(),
        import_dirs: s.import_dirs.clone(),
        workshop_downloads: s.workshop_downloads && (opts.workshop.is_some() || WORKSHOP_DOWNLOADS_AVAILABLE),
        workshop_available: opts.workshop.is_some() || WORKSHOP_DOWNLOADS_AVAILABLE,
    }
}

fn storage_view(paths: &ModPaths, current: Option<&str>) -> StorageView {
    let (store_files, store_bytes) = Store::open(&paths.store()).map(|s| s.usage()).unwrap_or_default();
    let instances = instance::list(&paths.instances())
        .into_iter()
        .map(|(_, r)| InstanceView {
            current: current == Some(r.id.as_str()),
            id: r.id,
            name: r.name,
            version: r.package_version,
            language: r.language,
            complete: r.complete,
            files: r.files,
            bytes: r.bytes,
            link_mode: r.link_mode,
        })
        .collect();
    let (mode, note) = instance::probe_link_mode(&paths.store(), &paths.instances());
    StorageView {
        root: paths.root().to_path_buf(),
        store_files,
        store_bytes,
        instances,
        free_bytes: fsx::free_space(paths.root()),
        link_mode: Some(mode),
        link_note: note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_are_sanitized() {
        let mut s = ModSettings {
            dir: Some(PathBuf::from("relative")),
            import_dirs: vec![
                PathBuf::from("C:\\A"),
                PathBuf::from("c:\\a"),
                PathBuf::from("rel"),
                PathBuf::from("D:\\B"),
            ],
            workshop_downloads: true,
        };
        s.sanitize();
        assert_eq!(s.dir, None);
        assert_eq!(s.import_dirs, [PathBuf::from("C:\\A"), PathBuf::from("D:\\B")]);
        let view = settings_view(
            &ModManagerOptions {
                data_dir: PathBuf::from("C:\\data"),
                appdata: None,
                workshop: None,
            },
            &s,
        );
        assert!(!view.workshop_downloads, "not available in this build");
        assert!(!view.workshop_available);
        assert_eq!(view.dir, PathBuf::from("C:\\data").join("mods"));
    }
}
