//! Configuration file (TOML), its validation into the runtime [`Settings`], the
//! example written by `init-config`, and the textual salt/PSK update done by
//! `set-password` (comments and layout of the file are preserved).

use std::fmt;
use std::fs;
use std::io::{self, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use beacon_proto::control::{
    KdfParams, ServerHello, HANDSHAKE_TIMEOUT, IDLE_TIMEOUT, PSK_LEN, SALT_LEN,
};
use beacon_proto::net::{self, VIP_POOL_SIZE};
use beacon_proto::relay::MAX_REDUNDANCY;
use serde::Deserialize;
use tracing::level_filters::LevelFilter;

use crate::hexfmt;
use crate::lobby;
use crate::webhook::{WebhookConfig, WebhookSettings};

/// Default port number (TCP control and UDP relay).
pub const DEFAULT_PORT: u16 = 28086;
/// Default address of the status endpoint.
pub const DEFAULT_STATUS_BIND: &str = "127.0.0.1:28087";
/// Default config file name (relative to the working directory).
pub const DEFAULT_CONFIG_FILE: &str = "config.toml";
/// Environment variable naming the config file.
pub const CONFIG_ENV: &str = "BEACON_CONFIG";
/// Environment variable overriding `log_level`.
pub const LOG_LEVEL_ENV: &str = "BEACON_LOG_LEVEL";
/// Minimum password length accepted by `set-password`.
pub const MIN_PASSWORD_LEN: usize = 8;
/// Maximum password length in bytes.
pub const MAX_PASSWORD_LEN: usize = 1024;
/// Maximum length of `server_name` in characters.
pub const SERVER_NAME_MAX: usize = 64;
/// Maximum length of `motd` in characters.
pub const MOTD_MAX: usize = 2000;
/// Upper bound for `chat_max_len`.
pub const CHAT_MAX_LEN_LIMIT: usize = 2000;
const MAX_CONFIG_LEN: u64 = 1 << 20;

/// The configuration file as written by the operator. Every field has a default.
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Server name (hello line, notifications).
    pub server_name: String,
    /// Message of the day (sent in `welcome`).
    pub motd: String,
    /// Port number for TCP control and UDP relay.
    pub port: u16,
    /// Listen address (`0.0.0.0`, `[::]`, …).
    pub bind: String,
    /// Maximum number of connected players.
    pub max_players: usize,
    /// Names that are host whenever they are connected.
    pub admin_names: Vec<String>,
    /// Argon2id parameters announced in the hello.
    pub kdf: KdfParams,
    /// Argon2id salt, 32 hex digits (written by `set-password`).
    pub salt: String,
    /// Derived Noise PSK, 64 hex digits (written by `set-password`).
    pub psk: String,
    /// Redundancy per port class.
    pub redundancy: RedundancyConfig,
    /// Rate limits and abuse protection.
    pub limits: LimitsConfig,
    /// Map repository (`<maps_dir>/<MapName>/…`).
    pub maps_dir: String,
    /// Periodic map rescan in seconds (0 = off).
    pub map_rescan_secs: u64,
    /// Writable directory for persistent state (`""` = none).
    pub data_dir: String,
    /// Status endpoint address (`""` = disabled).
    pub status_bind: String,
    /// `error`, `warn`, `info`, `debug`, `trace` or `off`.
    pub log_level: String,
    /// Optional notifications.
    pub webhook: Option<WebhookConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_name: "BFME Beacon".to_owned(),
            motd: String::new(),
            port: DEFAULT_PORT,
            bind: "0.0.0.0".to_owned(),
            max_players: 16,
            admin_names: Vec::new(),
            kdf: KdfParams::DEFAULT,
            salt: String::new(),
            psk: String::new(),
            redundancy: RedundancyConfig::default(),
            limits: LimitsConfig::default(),
            maps_dir: "maps".to_owned(),
            map_rescan_secs: 60,
            data_dir: "data".to_owned(),
            status_bind: DEFAULT_STATUS_BIND.to_owned(),
            log_level: "info".to_owned(),
            webhook: None,
        }
    }
}

/// `[redundancy]`: how many times each forwarded DATA packet is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RedundancyConfig {
    /// BFME lobby ports 8086–8093.
    pub lobby: u8,
    /// BFME in-game ports 8094–8101.
    pub game: u8,
    /// Any other virtual port.
    pub other: u8,
}

impl Default for RedundancyConfig {
    fn default() -> Self {
        Self {
            lobby: beacon_proto::relay::default_redundancy(*net::LOBBY_PORTS.start()),
            game: beacon_proto::relay::default_redundancy(*net::GAME_PORTS.start()),
            other: 1,
        }
    }
}

impl RedundancyConfig {
    /// Copies to send for a datagram to `dst_vport` (1..=[`MAX_REDUNDANCY`]).
    pub fn for_port(&self, dst_vport: u16) -> u8 {
        let n = if net::is_lobby_port(dst_vport) {
            self.lobby
        } else if net::is_game_port(dst_vport) {
            self.game
        } else {
            self.other
        };
        n.clamp(1, MAX_REDUNDANCY)
    }
}

/// `[limits]`: rate limits and abuse protection.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Relay packets per second per session.
    pub relay_pps: u32,
    /// Relay burst per session.
    pub relay_burst: u32,
    /// Invalid UDP datagrams per second per source IP before it is ignored.
    pub preauth_pps: u32,
    /// Burst of invalid UDP datagrams per source IP.
    pub preauth_burst: u32,
    /// Control messages per second per connection (map chunks excluded).
    pub control_msgs_per_s: u32,
    /// Control message burst.
    pub control_burst: u32,
    /// Map chunk requests per second per connection (32 KiB each).
    pub map_chunks_per_s: u32,
    /// Chat lines per minute per player.
    pub chat_per_minute: u32,
    /// Chat burst.
    pub chat_burst: u32,
    /// Maximum chat line length in characters.
    pub chat_max_len: usize,
    /// Failed handshakes per IP before a temporary ban.
    pub handshake_failures: u32,
    /// First ban length in seconds (doubles per further ban, max 15 min).
    pub handshake_ban_secs: u64,
    /// Concurrent unfinished handshakes in total.
    pub max_pending_handshakes: usize,
    /// Concurrent connections per IP.
    pub max_connections_per_ip: u32,
    /// A kicked name cannot rejoin for this many seconds.
    pub kick_ban_secs: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            relay_pps: 800,
            relay_burst: 1600,
            preauth_pps: 100,
            preauth_burst: 200,
            control_msgs_per_s: 50,
            control_burst: 100,
            map_chunks_per_s: 400,
            chat_per_minute: 20,
            chat_burst: 5,
            chat_max_len: 300,
            handshake_failures: 5,
            handshake_ban_secs: 60,
            max_pending_handshakes: 64,
            max_connections_per_ip: 16,
            kick_ban_secs: 60,
        }
    }
}

impl LimitsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let positive: [(&str, u64); 11] = [
            ("relay_pps", self.relay_pps.into()),
            ("relay_burst", self.relay_burst.into()),
            ("preauth_pps", self.preauth_pps.into()),
            ("preauth_burst", self.preauth_burst.into()),
            ("control_msgs_per_s", self.control_msgs_per_s.into()),
            ("control_burst", self.control_burst.into()),
            ("map_chunks_per_s", self.map_chunks_per_s.into()),
            ("chat_per_minute", self.chat_per_minute.into()),
            ("chat_burst", self.chat_burst.into()),
            ("handshake_failures", self.handshake_failures.into()),
            ("max_connections_per_ip", self.max_connections_per_ip.into()),
        ];
        if let Some((name, _)) = positive.iter().find(|(_, v)| *v == 0) {
            return Err(invalid(format!("limits.{name} must be at least 1")));
        }
        if !(1..=CHAT_MAX_LEN_LIMIT).contains(&self.chat_max_len) {
            return Err(invalid(format!(
                "limits.chat_max_len must be 1..={CHAT_MAX_LEN_LIMIT}"
            )));
        }
        if self.max_pending_handshakes == 0 {
            return Err(invalid("limits.max_pending_handshakes must be at least 1"));
        }
        Ok(())
    }
}

/// The Noise PSK; `Debug` does not print it.
#[derive(Clone, PartialEq, Eq)]
pub struct Psk(pub [u8; PSK_LEN]);

impl fmt::Debug for Psk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Psk(<redacted>)")
    }
}

/// Validated runtime settings.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Server name.
    pub server_name: String,
    /// Message of the day.
    pub motd: String,
    /// Listen address for TCP and UDP.
    pub bind_ip: IpAddr,
    /// Port number for TCP and UDP (0 = any free port, used by tests).
    pub port: u16,
    /// Maximum number of connected players.
    pub max_players: usize,
    /// Admin names.
    pub admin_names: Vec<String>,
    /// KDF parameters announced in the hello.
    pub kdf: KdfParams,
    /// Argon2id salt announced in the hello.
    pub salt: [u8; SALT_LEN],
    /// Noise PSK.
    pub psk: Psk,
    /// Redundancy per port class.
    pub redundancy: RedundancyConfig,
    /// Rate limits.
    pub limits: LimitsConfig,
    /// Map repository directory.
    pub maps_dir: PathBuf,
    /// Periodic rescan interval.
    pub map_rescan: Option<Duration>,
    /// Persistent state directory.
    pub data_dir: Option<PathBuf>,
    /// Status endpoint address.
    pub status_bind: Option<SocketAddr>,
    /// Log level.
    pub log_level: LevelFilter,
    /// Notifications.
    pub webhook: Option<WebhookSettings>,
    /// TCP accept → Noise handshake complete (and again for the first message).
    pub handshake_timeout: Duration,
    /// A session that sends nothing for this long is dropped.
    pub idle_timeout: Duration,
    /// How often the lobby is re-published with fresh relay statistics.
    pub lobby_refresh: Duration,
}

/// Errors of loading or validating the configuration.
#[derive(Debug)]
pub enum ConfigError {
    /// The file could not be read or written.
    Io {
        /// File concerned.
        path: PathBuf,
        /// Cause.
        source: io::Error,
    },
    /// TOML syntax or schema error.
    Parse(String),
    /// A value is out of range.
    Invalid(String),
    /// `salt`/`psk` are not set.
    NoPassword,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Parse(msg) => write!(f, "invalid config: {msg}"),
            Self::Invalid(msg) => write!(f, "invalid config: {msg}"),
            Self::NoPassword => f.write_str(
                "no server password set: run `beacon-server set-password` first \
                 (it stores salt and psk in the config)",
            ),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn invalid(msg: impl Into<String>) -> ConfigError {
    ConfigError::Invalid(msg.into())
}

fn io_err(path: &Path, source: io::Error) -> ConfigError {
    ConfigError::Io {
        path: path.to_path_buf(),
        source,
    }
}

impl Config {
    /// Parses TOML text.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Reads and parses a config file (at most 1 MiB).
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::from_toml(&read_bounded(path)?)
    }

    /// Validates the configuration. Relative paths are resolved against
    /// `base_dir` (the directory of the config file).
    pub fn into_settings(self, base_dir: &Path) -> Result<Settings, ConfigError> {
        let server_name = self.server_name.trim().to_owned();
        if server_name.is_empty()
            || server_name.chars().count() > SERVER_NAME_MAX
            || server_name.chars().any(char::is_control)
        {
            return Err(invalid(format!(
                "server_name must be 1..={SERVER_NAME_MAX} printable characters"
            )));
        }
        if self.motd.chars().count() > MOTD_MAX
            || self
                .motd
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            return Err(invalid(format!(
                "motd must be at most {MOTD_MAX} characters without control characters"
            )));
        }
        let bind_ip = parse_bind(&self.bind)?;
        if !(1..=VIP_POOL_SIZE).contains(&self.max_players) {
            return Err(invalid(format!("max_players must be 1..={VIP_POOL_SIZE}")));
        }
        for name in &self.admin_names {
            lobby::validate_name(name)
                .map_err(|e| invalid(format!("admin_names: {name:?}: {e}")))?;
        }
        self.kdf
            .validate()
            .map_err(|e| invalid(format!("kdf: {e}")))?;
        let (salt, psk) = match (self.salt.trim(), self.psk.trim()) {
            ("", _) | (_, "") => return Err(ConfigError::NoPassword),
            (salt, psk) => (
                hexfmt::decode::<SALT_LEN>(salt)
                    .ok_or_else(|| invalid("salt must be 32 hex digits"))?,
                hexfmt::decode::<PSK_LEN>(psk)
                    .ok_or_else(|| invalid("psk must be 64 hex digits"))?,
            ),
        };
        let hello = ServerHello {
            kdf: self.kdf,
            ..ServerHello::new(server_name.clone(), salt)
        };
        hello
            .to_line()
            .map_err(|e| invalid(format!("server_name: {e}")))?;
        for (name, n) in [
            ("lobby", self.redundancy.lobby),
            ("game", self.redundancy.game),
            ("other", self.redundancy.other),
        ] {
            if !(1..=MAX_REDUNDANCY).contains(&n) {
                return Err(invalid(format!(
                    "redundancy.{name} must be 1..={MAX_REDUNDANCY}"
                )));
            }
        }
        self.limits.validate()?;
        if self.maps_dir.trim().is_empty() {
            return Err(invalid("maps_dir must not be empty"));
        }
        let maps_dir = resolve(base_dir, self.maps_dir.trim());
        let data_dir = match self.data_dir.trim() {
            "" => None,
            dir => Some(resolve(base_dir, dir)),
        };
        let status_bind = parse_status_bind(&self.status_bind)?;
        if let Some(status) = status_bind {
            if status.port() == self.port && self.port != 0 {
                return Err(invalid("status_bind must use a different port than `port`"));
            }
        }
        let log_level = parse_level(&self.log_level).ok_or_else(|| {
            invalid("log_level must be one of off, error, warn, info, debug, trace")
        })?;
        let webhook = match &self.webhook {
            Some(w) => Some(
                WebhookSettings::from_config(w, &server_name)
                    .map_err(|e| invalid(format!("webhook: {e}")))?,
            ),
            None => None,
        };
        Ok(Settings {
            server_name,
            motd: self.motd,
            bind_ip,
            port: self.port,
            max_players: self.max_players,
            admin_names: self.admin_names,
            kdf: self.kdf,
            salt,
            psk: Psk(psk),
            redundancy: self.redundancy,
            limits: self.limits,
            maps_dir,
            map_rescan: (self.map_rescan_secs > 0)
                .then(|| Duration::from_secs(self.map_rescan_secs)),
            data_dir,
            status_bind,
            log_level,
            webhook,
            handshake_timeout: HANDSHAKE_TIMEOUT,
            idle_timeout: IDLE_TIMEOUT,
            lobby_refresh: Duration::from_secs(2),
        })
    }
}

/// Parses `bind`: an IP address, IPv6 optionally in brackets (`"[::]"`).
pub fn parse_bind(text: &str) -> Result<IpAddr, ConfigError> {
    let t = text.trim();
    let t = t
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(t);
    t.parse::<IpAddr>().map_err(|_| {
        invalid(format!(
            "bind: invalid address {text:?} (examples: \"0.0.0.0\", \"[::]\")"
        ))
    })
}

/// Parses `status_bind` (`""`/`"off"` = disabled).
pub fn parse_status_bind(text: &str) -> Result<Option<SocketAddr>, ConfigError> {
    match text.trim() {
        "" | "off" => Ok(None),
        t => t.parse::<SocketAddr>().map(Some).map_err(|_| {
            invalid(format!(
                "status_bind: invalid address {text:?} (example: \"127.0.0.1:28087\")"
            ))
        }),
    }
}

/// Parses a log level name.
pub fn parse_level(text: &str) -> Option<LevelFilter> {
    match text.trim().to_ascii_lowercase().as_str() {
        "off" => Some(LevelFilter::OFF),
        "error" => Some(LevelFilter::ERROR),
        "warn" | "warning" => Some(LevelFilter::WARN),
        "info" => Some(LevelFilter::INFO),
        "debug" => Some(LevelFilter::DEBUG),
        "trace" => Some(LevelFilter::TRACE),
        _ => None,
    }
}

fn resolve(base_dir: &Path, path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        p
    } else {
        base_dir.join(p)
    }
}

/// The config path: the argument, else `$BEACON_CONFIG`, else `config.toml`.
pub fn config_path(arg: Option<PathBuf>) -> PathBuf {
    arg.or_else(|| {
        std::env::var_os(CONFIG_ENV)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    })
    .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_FILE))
}

/// Directory against which relative paths in the config file are resolved.
pub fn base_dir_of(config_path: &Path) -> PathBuf {
    match config_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

fn read_bounded(path: &Path) -> Result<String, ConfigError> {
    let meta = fs::metadata(path).map_err(|e| io_err(path, e))?;
    if meta.len() > MAX_CONFIG_LEN {
        return Err(invalid(format!("{} is larger than 1 MiB", path.display())));
    }
    fs::read_to_string(path).map_err(|e| io_err(path, e))
}

// ---------------------------------------------------------------------------
// init-config / set-password
// ---------------------------------------------------------------------------

/// The commented example configuration written by `init-config`.
pub const EXAMPLE_CONFIG: &str = r#"# BFME Beacon server configuration (created by `beacon-server init-config`).
# Relative paths are resolved against the directory of this file.
# Reload: restart the server (maps are rescanned on SIGHUP and periodically).

# Name shown to players and in notifications.
server_name = "BFME Beacon"

# Message of the day, shown in the lobby after joining.
motd = "Willkommen in Mittelerde!"

# One port number for TCP (control channel) and UDP (relay).
# Forward BOTH protocols on your router.
port = 28086

# Listen address: "0.0.0.0" (IPv4), "[::]" (IPv6 and IPv4) or one specific address.
bind = "0.0.0.0"

# Maximum number of connected players (1-253).
max_players = 16

# Players with these names are host whenever they are connected (case-insensitive).
# Otherwise the first player is host; the role moves on when the host leaves.
admin_names = []

# Server password: set it with `beacon-server set-password`. It stores a random
# salt and the derived key here, never the password itself. Keep this file
# private: the key grants access like the password. Run set-password again after
# changing [kdf].
salt = ""
psk = ""

# Map repository: one folder per map (<maps_dir>/<MapName>/...); read-only access
# is enough. Maps are announced with size and BLAKE3 of every file.
maps_dir = "maps"

# Rescan the map folder every N seconds (0 = only at start and on SIGHUP).
map_rescan_secs = 60

# Writable folder for persistent state (sticky virtual IPs). "" = no persistence.
data_dir = "data"

# Status endpoint (GET /health, GET /status as JSON). Keep it local.
# "" disables it (then `beacon-server health` cannot work).
status_bind = "127.0.0.1:28087"

# Log level: error, warn, info, debug, trace (the BEACON_LOG_LEVEL env var wins).
log_level = "info"

# Argon2id cost of the password key derivation (minimum: m = 19456, t = 2, p = 1).
[kdf]
m = 19456
t = 2
p = 1

# How often the relay sends each game datagram (identical copies after 3 ms and
# 10 ms) so that a lost packet does not freeze the game. 1-3.
[redundancy]
lobby = 3  # BFME lobby ports 8086-8093 (many lobby messages are sent only once)
game = 2   # in-game ports 8094-8101
other = 1

[limits]
relay_pps = 800              # relay packets per second and player
relay_burst = 1600
preauth_pps = 100            # invalid UDP datagrams per second and source IP
preauth_burst = 200
control_msgs_per_s = 50      # control messages per second and connection
control_burst = 100
map_chunks_per_s = 400       # map download requests (32 KiB each) per second
chat_per_minute = 20
chat_burst = 5
chat_max_len = 300           # characters
handshake_failures = 5       # failed logins per IP before a temporary ban
handshake_ban_secs = 60      # first ban; doubles for every further ban (max 15 min)
max_pending_handshakes = 64
max_connections_per_ip = 16  # players behind one router share an IP
kick_ban_secs = 60           # a kicked player cannot rejoin for this long

# Optional notifications, e.g. to ntfy: HTTP POST, body = text, header "Title".
# Only plain http:// URLs are supported (no TLS): use a local ntfy instance.
# Events: start, stop, join, leave, launch, kick.
#[webhook]
#url = "http://127.0.0.1:8080/beacon"
#token = ""                       # sent as "Authorization: Bearer <token>"
#events = ["join", "launch"]
#title = ""                       # default: server_name
#[webhook.headers]                # extra headers, e.g. for ntfy
#Priority = "default"
#Tags = "crossed_swords"
"#;

/// Writes [`EXAMPLE_CONFIG`] to `path` (`-` = stdout). Refuses to overwrite an
/// existing file unless `force`.
pub fn write_example(path: &Path, force: bool) -> Result<(), ConfigError> {
    if path.as_os_str() == "-" {
        let mut out = io::stdout().lock();
        return out
            .write_all(EXAMPLE_CONFIG.as_bytes())
            .and_then(|()| out.flush())
            .map_err(|e| io_err(path, e));
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            invalid(format!(
                "{} already exists (use --force to overwrite)",
                path.display()
            ))
        } else {
            io_err(path, e)
        }
    })?;
    file.write_all(EXAMPLE_CONFIG.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| io_err(path, e))
}

/// Checks a new server password.
pub fn validate_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "the password must have at least {MIN_PASSWORD_LEN} characters"
        ));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(format!(
            "the password must not be longer than {MAX_PASSWORD_LEN} bytes"
        ));
    }
    if password.chars().any(char::is_control) {
        return Err("the password must not contain control characters".to_owned());
    }
    Ok(())
}

/// A freshly generated salt with the PSK derived from it.
pub struct NewSecret {
    /// Random salt.
    pub salt: [u8; SALT_LEN],
    /// Argon2id(password, salt).
    pub psk: [u8; PSK_LEN],
}

/// Generates a random salt and derives the PSK for `password`.
pub fn derive_secret(password: &str, kdf: &KdfParams) -> Result<NewSecret, ConfigError> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).map_err(|e| invalid(format!("no randomness available: {e}")))?;
    let psk = beacon_proto::control::derive_psk(password, &salt, kdf)
        .map_err(|e| invalid(format!("key derivation failed: {e}")))?;
    Ok(NewSecret { salt, psk })
}

/// Sets `password` in the config file at `path`: generates a salt, derives the
/// PSK with the file's `[kdf]` and rewrites only the `salt`/`psk` lines.
pub fn set_password_file(path: &Path, password: &str) -> Result<(), ConfigError> {
    validate_password(password).map_err(invalid)?;
    let text = read_bounded(path)?;
    let cfg = Config::from_toml(&text)?;
    cfg.kdf
        .validate()
        .map_err(|e| invalid(format!("kdf: {e}")))?;
    let secret = derive_secret(password, &cfg.kdf)?;
    let updated = set_secret_in_text(
        &text,
        &hexfmt::encode(&secret.salt),
        &hexfmt::encode(&secret.psk),
    )?;
    write_file_replacing(path, updated.as_bytes()).map_err(|e| io_err(path, e))
}

/// Replaces (or inserts) the top-level `salt` and `psk` keys in the TOML `text`,
/// keeping everything else byte for byte; verifies the result parses back to
/// exactly these values.
pub fn set_secret_in_text(text: &str, salt_hex: &str, psk_hex: &str) -> Result<String, ConfigError> {
    let updated = update_top_level_keys(text, &[("salt", salt_hex), ("psk", psk_hex)]);
    let cfg = Config::from_toml(&updated)?;
    if cfg.salt != salt_hex || cfg.psk != psk_hex {
        return Err(invalid(
            "could not update salt/psk automatically; set them by hand",
        ));
    }
    Ok(updated)
}

fn is_table_header(line: &str) -> bool {
    let code = line.split('#').next().unwrap_or("").trim();
    code.starts_with('[') && code.ends_with(']')
}

fn key_of(line: &str) -> Option<&str> {
    let (key, _) = line.trim_start().split_once('=')?;
    let key = key.trim();
    (!key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
    .then_some(key)
}

fn update_top_level_keys(text: &str, pairs: &[(&str, &str)]) -> String {
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut done = vec![false; pairs.len()];
    let mut out: Vec<String> = Vec::new();
    let mut in_top = true;
    let missing = |done: &[bool]| -> Vec<String> {
        pairs
            .iter()
            .zip(done)
            .filter(|(_, d)| !**d)
            .map(|((k, v), _)| format!("{k} = \"{v}\""))
            .collect()
    };
    for line in text.lines() {
        if in_top && is_table_header(line) {
            in_top = false;
            let mut block = missing(&done);
            done.iter_mut().for_each(|d| *d = true);
            if !block.is_empty() {
                // Insert above the comment block that belongs to the header.
                let mut at = out.len();
                while at > 0
                    && out
                        .get(at - 1)
                        .is_some_and(|l| l.trim_start().starts_with('#'))
                {
                    at -= 1;
                }
                block.push(String::new());
                for (i, l) in block.into_iter().enumerate() {
                    out.insert(at + i, l);
                }
            }
        }
        if in_top {
            if let Some(key) = key_of(line) {
                if let Some(i) = pairs.iter().position(|(k, _)| *k == key) {
                    if let (Some(flag), Some((k, v))) = (done.get_mut(i), pairs.get(i)) {
                        if !*flag {
                            *flag = true;
                            out.push(format!("{k} = \"{v}\""));
                            continue;
                        }
                    }
                }
            }
        }
        out.push(line.to_owned());
    }
    if in_top {
        out.extend(missing(&done));
    }
    let mut result = out.join(newline);
    if text.is_empty() || text.ends_with('\n') {
        result.push_str(newline);
    }
    result
}

/// Replaces the file at `path` with `data`: written to a temporary file next to
/// it (same permissions) and renamed over it; if that is impossible (e.g. a
/// single-file Docker bind mount), the file is overwritten in place.
pub fn write_file_replacing(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut tmp_name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "config.toml".into());
    tmp_name.push(format!(".tmp-{}", std::process::id()));
    let tmp = path.with_file_name(tmp_name);
    let perms = fs::metadata(path).ok().map(|m| m.permissions());
    match write_and_rename(path, &tmp, data, perms) {
        Ok(()) => Ok(()),
        Err(_) => {
            let _ = fs::remove_file(&tmp);
            let mut file = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)?;
            file.write_all(data)?;
            file.sync_all()
        }
    }
}

fn write_and_rename(
    path: &Path,
    tmp: &Path,
    data: &[u8],
    perms: Option<fs::Permissions>,
) -> io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    if let Some(p) = perms {
        fs::set_permissions(tmp, p)?;
    }
    fs::rename(tmp, path)
}

/// Reads `status_bind` from the config without requiring a password (used by
/// `health`).
pub fn status_addr_of(cfg: &Config) -> Result<Option<SocketAddr>, ConfigError> {
    parse_status_bind(&cfg.status_bind)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT_HEX: &str = "000102030405060708090a0b0c0d0e0f";
    const PSK_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn with_secret(text: &str) -> String {
        set_secret_in_text(text, SALT_HEX, PSK_HEX).unwrap()
    }

    #[test]
    fn example_parses_and_validates_once_a_password_is_set() {
        let cfg = Config::from_toml(EXAMPLE_CONFIG).unwrap();
        assert_eq!(cfg.port, DEFAULT_PORT);
        assert!(matches!(
            cfg.clone().into_settings(Path::new(".")),
            Err(ConfigError::NoPassword)
        ));
        let text = with_secret(EXAMPLE_CONFIG);
        let s = Config::from_toml(&text)
            .unwrap()
            .into_settings(Path::new("/srv/beacon"))
            .unwrap();
        assert_eq!(s.port, 28086);
        assert_eq!(s.max_players, 16);
        assert_eq!(s.redundancy.for_port(8086), 3);
        assert_eq!(s.redundancy.for_port(8094), 2);
        assert_eq!(s.redundancy.for_port(9000), 1);
        assert_eq!(s.status_bind, Some("127.0.0.1:28087".parse().unwrap()));
        assert_eq!(s.maps_dir, Path::new("/srv/beacon").join("maps"));
        assert_eq!(s.psk.0, [0x11; 32]);
        assert_eq!(format!("{:?}", s.psk), "Psk(<redacted>)");
        assert!(!format!("{s:?}").contains("1111111111"));
    }

    #[test]
    fn deploy_example_is_valid() {
        let text = include_str!("../../../deploy/homelab-beacon/config.toml");
        let cfg = Config::from_toml(text).unwrap();
        let s = Config::from_toml(&with_secret(text))
            .unwrap()
            .into_settings(Path::new("/"))
            .unwrap();
        assert_eq!(s.port, 28086);
        assert_eq!(s.maps_dir, Path::new("/maps"));
        assert_eq!(s.data_dir.as_deref(), Some(Path::new("/data")));
        // Inside the container the status endpoint must listen on all interfaces;
        // compose publishes it on 127.0.0.1 only.
        assert_eq!(s.status_bind, Some("0.0.0.0:28087".parse().unwrap()));
        assert!(cfg.salt.is_empty() && cfg.psk.is_empty());
    }

    #[test]
    fn defaults_apply_to_an_almost_empty_file() {
        let text = format!("salt = \"{SALT_HEX}\"\npsk = \"{PSK_HEX}\"\n");
        let s = Config::from_toml(&text)
            .unwrap()
            .into_settings(Path::new("."))
            .unwrap();
        assert_eq!(s.port, 28086);
        assert_eq!(s.bind_ip, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(s.limits, LimitsConfig::default());
        assert_eq!(s.kdf, KdfParams::DEFAULT);
        assert_eq!(s.map_rescan, Some(Duration::from_secs(60)));
        assert_eq!(s.log_level, LevelFilter::INFO);
        assert!(s.webhook.is_none());
    }

    #[test]
    fn bind_accepts_bracketed_ipv6() {
        assert_eq!(parse_bind("[::]").unwrap(), "::".parse::<IpAddr>().unwrap());
        assert_eq!(parse_bind("::").unwrap(), "::".parse::<IpAddr>().unwrap());
        assert_eq!(parse_bind(" 192.0.2.7 ").unwrap(), "192.0.2.7".parse::<IpAddr>().unwrap());
        assert!(parse_bind("localhost").is_err());
        assert!(parse_bind("[::").is_err());
    }

    #[test]
    fn rejects_bad_values() {
        let base = format!("salt = \"{SALT_HEX}\"\npsk = \"{PSK_HEX}\"\n");
        let cases = [
            "max_players = 0\n",
            "max_players = 254\n",
            "bind = \"nope\"\n",
            "status_bind = \"127.0.0.1\"\n",
            "status_bind = \"127.0.0.1:28086\"\n",
            "log_level = \"loud\"\n",
            "admin_names = [\"\"]\n",
            "admin_names = [\"ThisNameIsWayTooLong\"]\n",
            "server_name = \"\"\n",
            "[redundancy]\nlobby = 4\n",
            "[redundancy]\ngame = 0\n",
            "[limits]\nrelay_pps = 0\n",
            "[limits]\nchat_max_len = 0\n",
            "[kdf]\nm = 1024\nt = 2\np = 1\n",
            "[webhook]\nurl = \"https://ntfy.sh/x\"\n",
        ];
        for case in cases {
            let text = format!("{base}{case}");
            let result = Config::from_toml(&text).and_then(|c| c.into_settings(Path::new(".")));
            assert!(result.is_err(), "accepted: {case}");
        }
        // Bad secrets.
        for (salt, psk) in [("abc", PSK_HEX), (SALT_HEX, "zz"), ("", PSK_HEX), (SALT_HEX, "")] {
            let text = format!("salt = \"{salt}\"\npsk = \"{psk}\"\n");
            assert!(Config::from_toml(&text)
                .unwrap()
                .into_settings(Path::new("."))
                .is_err());
        }
        // Unknown keys are typos.
        assert!(Config::from_toml("prot = 1\n").is_err());
        assert!(Config::from_toml("[limits]\nrelay_ppps = 1\n").is_err());
        assert!(Config::from_toml("port = \"x\"\n").is_err());
    }

    #[test]
    fn secret_update_replaces_lines_in_place() {
        let text = "# c\nserver_name = \"A\"\nsalt = \"\"   \npsk = \"old\"\n\n# kdf\n[kdf]\nm = 19456\nt = 2\np = 1\n";
        let out = with_secret(text);
        assert_eq!(
            out,
            format!("# c\nserver_name = \"A\"\nsalt = \"{SALT_HEX}\"\npsk = \"{PSK_HEX}\"\n\n# kdf\n[kdf]\nm = 19456\nt = 2\np = 1\n")
        );
        // Idempotent.
        assert_eq!(with_secret(&out), out);
    }

    #[test]
    fn secret_update_inserts_missing_keys_before_tables() {
        let text = "server_name = \"A\"\n\n# Limits.\n[limits]\nchat_burst = 3\n";
        let out = with_secret(text);
        assert_eq!(
            out,
            format!("server_name = \"A\"\n\nsalt = \"{SALT_HEX}\"\npsk = \"{PSK_HEX}\"\n\n# Limits.\n[limits]\nchat_burst = 3\n")
        );
        // Keys inside tables are not touched; missing top-level keys are appended.
        let text = "port = 1\n";
        assert_eq!(
            with_secret(text),
            format!("port = 1\nsalt = \"{SALT_HEX}\"\npsk = \"{PSK_HEX}\"\n")
        );
        assert_eq!(
            with_secret(""),
            format!("salt = \"{SALT_HEX}\"\npsk = \"{PSK_HEX}\"\n")
        );
        // CRLF files stay CRLF.
        let out = with_secret("port = 1\r\nsalt = \"\"\r\n");
        assert_eq!(out, format!("port = 1\r\nsalt = \"{SALT_HEX}\"\r\npsk = \"{PSK_HEX}\"\r\n"));
    }

    #[test]
    fn secret_update_refuses_what_it_cannot_handle() {
        // A multi-line string value under the key cannot be replaced line-wise.
        let text = "salt = \"\"\"\nx\n\"\"\"\npsk = \"\"\n";
        assert!(set_secret_in_text(text, SALT_HEX, PSK_HEX).is_err());
        assert!(set_secret_in_text("this is = not toml [", SALT_HEX, PSK_HEX).is_err());
    }

    #[test]
    fn password_rules() {
        assert!(validate_password("short").is_err());
        assert!(validate_password("long enough").is_ok());
        assert!(validate_password("tab\there!").is_err());
        assert!(validate_password(&"x".repeat(MAX_PASSWORD_LEN + 1)).is_err());
    }

    #[test]
    fn set_password_and_init_config_files() {
        let dir = std::env::temp_dir().join(format!("beacon-cfg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        write_example(&path, false).unwrap();
        assert!(write_example(&path, false).is_err(), "no overwrite without force");
        write_example(&path, true).unwrap();
        set_password_file(&path, "correct horse").unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("correct horse"));
        let s = Config::from_toml(&text)
            .unwrap()
            .into_settings(&dir)
            .unwrap();
        let expect = beacon_proto::control::derive_psk("correct horse", &s.salt, &s.kdf).unwrap();
        assert_eq!(s.psk.0, expect);
        // Everything but the two lines is unchanged.
        let changed: Vec<_> = EXAMPLE_CONFIG
            .lines()
            .zip(text.lines())
            .filter(|(a, b)| a != b)
            .collect();
        assert_eq!(changed.len(), 2);
        assert!(set_password_file(&path, "short").is_err());
        assert!(set_password_file(&dir.join("missing.toml"), "long enough").is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn config_path_and_base_dir() {
        assert_eq!(config_path(Some("x.toml".into())), PathBuf::from("x.toml"));
        assert_eq!(base_dir_of(Path::new("config.toml")), PathBuf::from("."));
        assert_eq!(base_dir_of(Path::new("/etc/b/config.toml")), PathBuf::from("/etc/b"));
    }
}
