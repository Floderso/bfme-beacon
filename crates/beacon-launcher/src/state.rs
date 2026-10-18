//! The app state the UI renders ([`AppState`], serialisable) and the change
//! notifications ([`Change`]) sent whenever a part of it changes.

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;

use beacon_proto::control::Player;
use beacon_proto::fingerprint::FileEntry;
use serde::Serialize;

use crate::agent::AgentStats;
use crate::config::{Config, LaunchOptions, RedundancyOverrides};
use crate::control::ControlError;
use crate::fingerprint::Progress;
use crate::game::detect::GameInfo;
use crate::game::hook::HookStatus;
use crate::maps::MapState;
use crate::mods::manager::ModsView;

/// Chat lines kept.
pub const CHAT_HISTORY: usize = 200;
/// Notices kept.
pub const NOTICE_HISTORY: usize = 50;
/// Other players' fingerprint lists kept.
pub const MAX_PEER_FILES: usize = 32;

/// Which part of the state changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// `connection` / `server`.
    Connection,
    /// `players`.
    Lobby,
    /// `chat`.
    Chat,
    /// `maps`.
    Maps,
    /// `game` / `game_process`.
    Game,
    /// `hook`.
    Hook,
    /// `agent` (about once per second).
    Agent,
    /// `fingerprint`.
    Fingerprint,
    /// `peer_files`.
    PeerFiles,
    /// `settings`.
    Settings,
    /// `notices`.
    Notice,
    /// `mods` (game configuration, preparation, catalog, storage).
    Mods,
    /// A second start asked this instance to show itself (open the UI).
    Activate,
    /// The app is shutting down.
    Quit,
}

/// Connection state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConnectionState {
    /// Not connected.
    Disconnected,
    /// TCP connect / hello.
    Connecting {
        /// Server address.
        server: String,
        /// Attempt (1-based).
        attempt: u32,
    },
    /// Key derivation and handshake.
    Authenticating {
        /// Server address.
        server: String,
    },
    /// In the lobby.
    Connected {
        /// Server address.
        server: String,
    },
    /// Connection lost; next attempt scheduled.
    Reconnecting {
        /// Server address.
        server: String,
        /// Delay until the next attempt.
        retry_in_ms: u64,
        /// Why.
        error: ControlError,
        /// Human-readable text.
        message: String,
    },
    /// Stopped after a permanent error (wrong password, changed identity, kick …).
    Failed {
        /// Server address.
        server: String,
        /// Why.
        error: ControlError,
        /// Human-readable text.
        message: String,
    },
}

/// The server of the current session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServerInfo {
    /// Canonical address.
    pub address: String,
    /// Name from the hello.
    pub name: String,
    /// Message of the day.
    pub motd: String,
    /// Our vIP.
    pub vip: String,
    /// We are the host.
    pub you_are_host: bool,
    /// Relay endpoint.
    pub relay_addr: String,
    /// Optional protocol features of the server (`game_config`, …).
    pub features: Vec<String>,
    /// The identity was pinned at this login (first connection).
    pub newly_pinned: bool,
}

/// One chat line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChatLine {
    /// Sender (empty = server notice).
    pub from: String,
    /// Text.
    pub text: String,
    /// Server time (ms since the Unix epoch).
    pub ts: u64,
}

/// One map of the server's listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MapEntry {
    /// Map name.
    pub name: String,
    /// Size of all files.
    pub total_size: u64,
    /// Number of files.
    pub files: usize,
    /// Local state.
    pub state: MapState,
    /// Details for conflicts, rejected entries and failures.
    pub problem: Option<String>,
}

/// Progress of a map sync.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SyncProgress {
    /// A sync is running.
    pub running: bool,
    /// Map being downloaded.
    pub current: Option<String>,
    /// Bytes downloaded in this sync.
    pub bytes_done: u64,
    /// Bytes to download in this sync.
    pub bytes_total: u64,
    /// Maps downloaded in the last sync.
    pub downloaded: Vec<String>,
    /// Error of the last sync.
    pub last_error: Option<String>,
}

/// Maps: listing, local state, sync progress.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MapsState {
    /// The local `Maps` folder (unknown without a game installation).
    pub maps_dir: Option<PathBuf>,
    /// The server sent its listing.
    pub listing_received: bool,
    /// The server's maps.
    pub maps: Vec<MapEntry>,
    /// Sync progress.
    pub sync: SyncProgress,
}

/// The game process started by Beacon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GameProcess {
    /// Process id.
    pub pid: u32,
    /// Start time (ms since the Unix epoch).
    pub started_at_ms: u64,
    /// Still running.
    pub running: bool,
    /// Exit code once ended.
    pub exit_code: Option<i32>,
    /// The hook's log file.
    pub hook_log: Option<PathBuf>,
}

/// State of the own fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum FingerprintState {
    /// No game found (or disabled).
    Unavailable {
        /// Why.
        reason: String,
    },
    /// Being computed.
    Computing {
        /// Progress.
        progress: Progress,
    },
    /// Done.
    Ready {
        /// 64 hex digits.
        digest: String,
        /// First 12 digits.
        short: String,
        /// Number of entries.
        files: usize,
    },
    /// Failed.
    Failed {
        /// Why.
        error: String,
    },
}

/// Another player's fingerprint list (answer to a request).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerFiles {
    /// Their entries.
    pub files: Vec<FileEntry>,
    /// The list is complete.
    pub complete: bool,
    /// Paths that differ from ours (missing on either side or different content).
    pub differs: Vec<String>,
}

/// A known server (settings view, no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServerView {
    /// Canonical address.
    pub address: String,
    /// Pinned server name, if pinned.
    pub pinned_name: Option<String>,
    /// When it was pinned.
    pub pinned_at_ms: Option<u64>,
    /// A key is remembered (DPAPI).
    pub remembered: bool,
}

/// Settings (from `config.json`, without secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettingsView {
    /// Player name.
    pub player_name: Option<String>,
    /// Last server.
    pub last_server: Option<String>,
    /// Known servers.
    pub servers: Vec<ServerView>,
    /// Game folder override.
    pub game_dir: Option<PathBuf>,
    /// BFME command-line options.
    pub launch: LaunchOptions,
    /// Set BFME's LAN name before launch.
    pub name_sync: bool,
    /// Start BFME when the host starts.
    pub auto_launch_on_host_start: bool,
    /// Redundancy overrides.
    pub redundancy: RedundancyOverrides,
}

impl SettingsView {
    /// The view of a configuration.
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            player_name: cfg.player_name.clone(),
            last_server: cfg.last_server.clone(),
            servers: cfg
                .servers
                .iter()
                .map(|s| ServerView {
                    address: s.address.clone(),
                    pinned_name: s.pin.as_ref().map(|p| p.server_name.clone()),
                    pinned_at_ms: s.pin.as_ref().map(|p| p.pinned_at_ms),
                    remembered: s.remembered_psk.is_some(),
                })
                .collect(),
            game_dir: cfg.game_dir.clone(),
            launch: cfg.launch.clone(),
            name_sync: cfg.name_sync,
            auto_launch_on_host_start: cfg.auto_launch_on_host_start,
            redundancy: cfg.redundancy,
        }
    }
}

/// Severity of a notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeLevel {
    /// Information.
    Info,
    /// Something the user should know.
    Warning,
    /// Something failed.
    Error,
}

/// A message for the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Notice {
    /// Increasing id.
    pub id: u64,
    /// Time (ms since the Unix epoch).
    pub ts_ms: u64,
    /// Severity.
    pub level: NoticeLevel,
    /// Text.
    pub text: String,
}

/// Everything the UI shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppState {
    /// Launcher version.
    pub version: String,
    /// Instance number.
    pub instance: u32,
    /// Test mode (`BEACON_MULTI`, own user folder).
    pub test_mode: bool,
    /// Beacon's data folder.
    pub data_dir: PathBuf,
    /// Connection.
    pub connection: ConnectionState,
    /// Current server.
    pub server: Option<ServerInfo>,
    /// Lobby.
    pub players: Vec<Player>,
    /// Chat (last [`CHAT_HISTORY`] lines).
    pub chat: VecDeque<ChatLine>,
    /// Maps.
    pub maps: MapsState,
    /// Game detection (`None` while it runs).
    pub game: Option<GameInfo>,
    /// Hook DLL in the game folder.
    pub hook: HookStatus,
    /// The game process started by Beacon.
    pub game_process: Option<GameProcess>,
    /// Agent statistics.
    pub agent: AgentStats,
    /// Own fingerprint.
    pub fingerprint: FingerprintState,
    /// Other players' file lists (requested with `request_fingerprint`).
    pub peer_files: BTreeMap<String, PeerFiles>,
    /// Settings.
    pub settings: SettingsView,
    /// Notices (last [`NOTICE_HISTORY`]).
    pub notices: VecDeque<Notice>,
    /// Mod support: the lobby's game configuration, the local preparation, the
    /// host's catalog, storage and settings.
    pub mods: ModsView,
}

impl AppState {
    /// Appends a chat line (bounded).
    pub fn push_chat(&mut self, line: ChatLine) {
        while self.chat.len() >= CHAT_HISTORY {
            self.chat.pop_front();
        }
        self.chat.push_back(line);
    }

    /// Appends a notice (bounded).
    pub fn push_notice(&mut self, notice: Notice) {
        while self.notices.len() >= NOTICE_HISTORY {
            self.notices.pop_front();
        }
        self.notices.push_back(notice);
    }

    /// `true` while logged in.
    pub fn is_connected(&self) -> bool {
        matches!(self.connection, ConnectionState::Connected { .. })
    }
}

/// Paths in `theirs` that differ from `ours` (sorted, unique).
pub fn diff_files(ours: &[FileEntry], theirs: &[FileEntry]) -> Vec<String> {
    let a: BTreeMap<&str, &FileEntry> = ours.iter().map(|e| (e.path.as_str(), e)).collect();
    let b: BTreeMap<&str, &FileEntry> = theirs.iter().map(|e| (e.path.as_str(), e)).collect();
    let mut out: Vec<String> = a
        .iter()
        .filter(|(p, e)| b.get(*p) != Some(*e))
        .map(|(p, _)| (*p).to_owned())
        .chain(b.keys().filter(|p| !a.contains_key(*p)).map(|p| (*p).to_owned()))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_histories() {
        let mut s = AppState {
            version: String::new(),
            instance: 1,
            test_mode: false,
            data_dir: PathBuf::new(),
            connection: ConnectionState::Disconnected,
            server: None,
            players: vec![],
            chat: VecDeque::new(),
            maps: MapsState::default(),
            game: None,
            hook: HookStatus::Unknown,
            game_process: None,
            agent: AgentStats::default(),
            fingerprint: FingerprintState::Unavailable { reason: String::new() },
            peer_files: BTreeMap::new(),
            settings: SettingsView::from_config(&Config::default()),
            notices: VecDeque::new(),
            mods: ModsView::placeholder(),
        };
        for i in 0..CHAT_HISTORY + 10 {
            s.push_chat(ChatLine { from: "a".into(), text: i.to_string(), ts: 0 });
        }
        assert_eq!(s.chat.len(), CHAT_HISTORY);
        assert_eq!(s.chat.front().unwrap().text, "10");
        for i in 0..NOTICE_HISTORY + 1 {
            s.push_notice(Notice { id: i as u64, ts_ms: 0, level: NoticeLevel::Info, text: String::new() });
        }
        assert_eq!(s.notices.len(), NOTICE_HISTORY);
        let json = serde_json::to_value(&s).unwrap();
        assert_eq!(json["connection"]["state"], "disconnected");
        assert_eq!(json["hook"]["state"], "unknown");
    }

    #[test]
    fn file_diff() {
        let e = |p: &str, h: &str| FileEntry::new(p, 1, h);
        let ours = [e("a.big", "11"), e("b.big", "22"), e("c.big", "33")];
        let theirs = [e("a.big", "11"), e("b.big", "99"), e("d.big", "44")];
        assert_eq!(diff_files(&ours, &theirs), ["b.big", "c.big", "d.big"]);
        assert!(diff_files(&ours, &ours).is_empty());
    }
}
