//! `config.json`: settings, known servers with their pinned identity (TOFU) and
//! the optional remembered key.
//!
//! * **Pinning**: the first successful login to an address stores the server's
//!   name, Argon2 salt and KDF parameters ([`PinnedIdentity`]). A later hello with a
//!   different salt or KDF is refused before any key is derived
//!   ([`check_pin`] → `IdentityChanged`) until the user resets the pin.
//! * **Remember password** stores only the derived 32-byte PSK, encrypted with DPAPI
//!   for the current Windows user (never the password).
//!
//! The file is replaced atomically on every change; a corrupt file is moved aside
//! (`config.json.corrupt-<stamp>`) and defaults are used.

use std::fmt;
use std::io;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use beacon_proto::control::{base64_decode, base64_encode, KdfParams, ServerHello, PSK_LEN, SALT_LEN};
use beacon_proto::relay::MAX_REDUNDANCY;
use serde::{Deserialize, Serialize};

use crate::util;

/// Default port of a Beacon server (TCP control + UDP relay).
pub const DEFAULT_PORT: u16 = 28086;
/// Current `config.json` format version.
pub const CONFIG_VERSION: u32 = 1;
/// Largest accepted `config.json`.
const MAX_CONFIG_LEN: u64 = 1 << 20;
/// Most servers remembered.
pub const MAX_SERVERS: usize = 64;
/// BFME uses at most 12 UTF-16 units of the LAN name (spec 04 §4.5); the server
/// enforces the same limit.
pub const NAME_MAX_UTF16: usize = 12;
/// Punctuation allowed in player names (same set as the server).
const NAME_PUNCTUATION: &str = " -_.!?#()[]{}+*'&@~^=$%";
/// Accepted `-xres`/`-yres` range.
pub const RES_RANGE: std::ops::RangeInclusive<u32> = 320..=16_384;

// ---------------------------------------------------------------------------
// Server addresses
// ---------------------------------------------------------------------------

/// Why a server address was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrError(pub String);

impl fmt::Display for AddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid server address: {}", self.0)
    }
}

impl std::error::Error for AddrError {}

/// `host[:port]` of a server (port default [`DEFAULT_PORT`]); IPv6 literals in
/// brackets (`[::1]:28086`) or bare without a port. The host is lower-cased; the
/// canonical text ([`key`](Self::key)) identifies pins.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerAddr {
    host: String,
    port: u16,
}

impl ServerAddr {
    /// Parses `host[:port]`.
    pub fn parse(text: &str) -> Result<Self, AddrError> {
        let text = text.trim();
        if text.is_empty() {
            return Err(AddrError("empty".into()));
        }
        if text.len() > 300 {
            return Err(AddrError("too long".into()));
        }
        let (host, port) = if let Some(rest) = text.strip_prefix('[') {
            let (inner, after) = rest
                .split_once(']')
                .ok_or_else(|| AddrError("missing ']'".into()))?;
            inner
                .parse::<Ipv6Addr>()
                .map_err(|_| AddrError(format!("{inner:?} is not an IPv6 address")))?;
            let port = match after {
                "" => DEFAULT_PORT,
                p => parse_port(p.strip_prefix(':').ok_or_else(|| AddrError("junk after ']'".into()))?)?,
            };
            (inner.to_ascii_lowercase(), port)
        } else if text.matches(':').count() > 1 {
            text.parse::<Ipv6Addr>()
                .map_err(|_| AddrError(format!("{text:?} is not an IPv6 address (use [addr]:port)")))?;
            (text.to_ascii_lowercase(), DEFAULT_PORT)
        } else {
            let (host, port) = match text.split_once(':') {
                Some((h, p)) => (h, parse_port(p)?),
                None => (text, DEFAULT_PORT),
            };
            if !is_valid_hostname(host) {
                return Err(AddrError(format!("{host:?} is not a valid host name")));
            }
            (host.to_ascii_lowercase(), port)
        };
        Ok(Self { host, port })
    }

    /// The host (name, IPv4 or IPv6 literal without brackets).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Canonical `host:port` (`[v6]:port`).
    pub fn key(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for ServerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.key())
    }
}

fn parse_port(p: &str) -> Result<u16, AddrError> {
    if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AddrError(format!("bad port {p:?}")));
    }
    p.parse::<u16>()
        .ok()
        .filter(|&n| n != 0)
        .ok_or_else(|| AddrError(format!("bad port {p:?}")))
}

fn is_valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

// ---------------------------------------------------------------------------
// Player names
// ---------------------------------------------------------------------------

/// Why a player name was refused (same rules as the server).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// Empty.
    Empty,
    /// More than [`NAME_MAX_UTF16`] UTF-16 units.
    TooLong,
    /// Leading, trailing or double spaces.
    Spaces,
    /// A character outside letters, digits and the allowed punctuation.
    InvalidChar(char),
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the player name is empty"),
            Self::TooLong => write!(f, "the player name is longer than {NAME_MAX_UTF16} characters"),
            Self::Spaces => f.write_str("the player name has leading, trailing or double spaces"),
            Self::InvalidChar(c) => write!(f, "the player name contains {c:?}"),
        }
    }
}

impl std::error::Error for NameError {}

/// Checks a player name like the server does.
pub fn validate_player_name(name: &str) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.encode_utf16().count() > NAME_MAX_UTF16 {
        return Err(NameError::TooLong);
    }
    if name.starts_with(' ') || name.ends_with(' ') || name.contains("  ") {
        return Err(NameError::Spaces);
    }
    match name
        .chars()
        .find(|&c| !(c.is_alphanumeric() || NAME_PUNCTUATION.contains(c)))
    {
        Some(c) => Err(NameError::InvalidChar(c)),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// The file
// ---------------------------------------------------------------------------

/// A server identity remembered after the first successful login (TOFU).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedIdentity {
    /// Server name from the hello.
    pub server_name: String,
    /// Argon2id salt, base64.
    pub salt: String,
    /// Argon2id parameters.
    pub kdf: KdfParams,
    /// When the pin was stored (ms since the Unix epoch).
    pub pinned_at_ms: u64,
}

impl PinnedIdentity {
    /// The pin for a hello.
    pub fn from_hello(hello: &ServerHello) -> Self {
        Self {
            server_name: hello.name.clone(),
            salt: base64_encode(&hello.salt),
            kdf: hello.kdf,
            pinned_at_ms: util::unix_ms(),
        }
    }

    /// The decoded salt (`None` if the stored value is malformed).
    pub fn salt_bytes(&self) -> Option<[u8; SALT_LEN]> {
        base64_decode(&self.salt)
            .ok()
            .and_then(|b| <[u8; SALT_LEN]>::try_from(b.as_slice()).ok())
    }
}

/// Result of comparing a server hello with the stored pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinCheck {
    /// No pin yet: trust on first use (stored after a successful login).
    Unpinned,
    /// Same salt and KDF parameters.
    Matches,
    /// Salt or KDF differ: refuse to log in.
    Changed {
        /// The stored identity.
        pinned: PinnedIdentity,
    },
}

/// Compares a hello with the pin (the server name is informational only).
pub fn check_pin(pin: Option<&PinnedIdentity>, hello: &ServerHello) -> PinCheck {
    match pin {
        None => PinCheck::Unpinned,
        Some(p) if p.salt_bytes() == Some(hello.salt) && p.kdf == hello.kdf => PinCheck::Matches,
        Some(p) => PinCheck::Changed { pinned: p.clone() },
    }
}

/// One known server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerEntry {
    /// Canonical address ([`ServerAddr::key`]).
    pub address: String,
    /// Identity pinned at the first successful login.
    #[serde(default)]
    pub pin: Option<PinnedIdentity>,
    /// The derived PSK, DPAPI-encrypted for the current user, base64.
    #[serde(default)]
    pub remembered_psk: Option<String>,
}

/// BFME command-line options (spec 04 §2.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LaunchOptions {
    /// `-win`.
    pub windowed: bool,
    /// `-xres W`.
    pub xres: Option<u32>,
    /// `-yres H`.
    pub yres: Option<u32>,
    /// `-noshellmap` (faster start).
    pub noshellmap: bool,
}

impl Default for LaunchOptions {
    fn default() -> Self {
        Self {
            windowed: false,
            xres: None,
            yres: None,
            noshellmap: true,
        }
    }
}

impl LaunchOptions {
    /// The game's arguments, e.g. `["-win", "-xres", "1280", "-yres", "720", "-noshellmap"]`.
    pub fn args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if self.windowed {
            args.push("-win".to_owned());
        }
        if let Some(x) = self.xres.filter(|x| RES_RANGE.contains(x)) {
            args.extend(["-xres".to_owned(), x.to_string()]);
        }
        if let Some(y) = self.yres.filter(|y| RES_RANGE.contains(y)) {
            args.extend(["-yres".to_owned(), y.to_string()]);
        }
        if self.noshellmap {
            args.push("-noshellmap".to_owned());
        }
        args
    }
}

/// Advanced: copies per DATA packet instead of the defaults (lobby 3, game 2,
/// other 1); each `1..=3`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RedundancyOverrides {
    /// Lobby ports 8086–8093.
    pub lobby: Option<u8>,
    /// Game ports 8094–8101.
    pub game: Option<u8>,
    /// Other ports.
    pub other: Option<u8>,
}

impl RedundancyOverrides {
    /// Copies for a destination port.
    pub fn for_port(&self, dst_vport: u16) -> u8 {
        use beacon_proto::net::{is_game_port, is_lobby_port};
        let over = if is_lobby_port(dst_vport) {
            self.lobby
        } else if is_game_port(dst_vport) {
            self.game
        } else {
            self.other
        };
        over.filter(|n| (1..=MAX_REDUNDANCY).contains(n))
            .unwrap_or_else(|| beacon_proto::relay::default_redundancy(dst_vport))
    }
}

/// `config.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Format version ([`CONFIG_VERSION`]).
    pub version: u32,
    /// Player name (also the BFME LAN name with `name_sync`).
    pub player_name: Option<String>,
    /// Last server connected to (canonical address).
    pub last_server: Option<String>,
    /// Known servers.
    pub servers: Vec<ServerEntry>,
    /// Game folder override (otherwise the registry `InstallPath`).
    pub game_dir: Option<PathBuf>,
    /// BFME command-line options.
    pub launch: LaunchOptions,
    /// Set BFME's LAN name (Network.ini `UserName`) to the player name before launch.
    pub name_sync: bool,
    /// Start BFME when the host starts the game (`launch` from the server).
    pub auto_launch_on_host_start: bool,
    /// Advanced redundancy overrides.
    pub redundancy: RedundancyOverrides,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            player_name: None,
            last_server: None,
            servers: Vec::new(),
            game_dir: None,
            launch: LaunchOptions::default(),
            name_sync: true,
            auto_launch_on_host_start: true,
            redundancy: RedundancyOverrides::default(),
        }
    }
}

impl Config {
    /// Parses and sanitises `config.json` text.
    pub fn from_json(text: &[u8]) -> Result<Self, serde_json::Error> {
        let mut cfg: Self = serde_json::from_slice(text)?;
        cfg.sanitize();
        Ok(cfg)
    }

    /// Drops or clamps invalid values (hand-edited files).
    pub fn sanitize(&mut self) {
        self.version = CONFIG_VERSION;
        if self
            .player_name
            .as_deref()
            .is_some_and(|n| validate_player_name(n).is_err())
        {
            self.player_name = None;
        }
        let mut seen = std::collections::HashSet::new();
        self.servers.retain_mut(|s| match ServerAddr::parse(&s.address) {
            Ok(a) => {
                s.address = a.key();
                if s.pin.as_ref().is_some_and(|p| p.salt_bytes().is_none() || p.kdf.validate().is_err()) {
                    s.pin = None;
                }
                seen.insert(s.address.clone())
            }
            Err(_) => false,
        });
        self.servers.truncate(MAX_SERVERS);
        self.last_server = self
            .last_server
            .as_deref()
            .and_then(|a| ServerAddr::parse(a).ok())
            .map(|a| a.key());
        if self.game_dir.as_ref().is_some_and(|d| !d.is_absolute()) {
            self.game_dir = None;
        }
        for v in [&mut self.launch.xres, &mut self.launch.yres] {
            if v.is_some_and(|x| !RES_RANGE.contains(&x)) {
                *v = None;
            }
        }
        for v in [
            &mut self.redundancy.lobby,
            &mut self.redundancy.game,
            &mut self.redundancy.other,
        ] {
            if v.is_some_and(|n| !(1..=MAX_REDUNDANCY).contains(&n)) {
                *v = None;
            }
        }
    }

    /// The entry of a server.
    pub fn server(&self, addr: &ServerAddr) -> Option<&ServerEntry> {
        let key = addr.key();
        self.servers.iter().find(|s| s.address == key)
    }

    /// Applies `f` to the entry of a server (created if missing) and moves it to the
    /// front of the list (the oldest entries make room).
    pub fn with_server<R>(&mut self, addr: &ServerAddr, f: impl FnOnce(&mut ServerEntry) -> R) -> R {
        let key = addr.key();
        let mut entry = match self.servers.iter().position(|s| s.address == key) {
            Some(i) => self.servers.remove(i),
            None => ServerEntry {
                address: key,
                pin: None,
                remembered_psk: None,
            },
        };
        let r = f(&mut entry);
        self.servers.insert(0, entry);
        self.servers.truncate(MAX_SERVERS);
        r
    }
}

/// Errors of the remembered-key store.
#[derive(Debug)]
pub enum SecretError {
    /// Nothing remembered for this server.
    NotRemembered,
    /// DPAPI failed (other Windows user, other PC, damaged entry).
    Dpapi(io::Error),
    /// The decrypted entry has the wrong length.
    Malformed,
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotRemembered => f.write_str("no remembered password for this server"),
            Self::Dpapi(e) => write!(f, "the remembered password cannot be decrypted ({e})"),
            Self::Malformed => f.write_str("the remembered password entry is damaged"),
        }
    }
}

impl std::error::Error for SecretError {}

/// `config.json` in memory, saved atomically on every change.
#[derive(Debug)]
pub struct ConfigStore {
    path: PathBuf,
    cfg: Mutex<Config>,
}

impl ConfigStore {
    /// Loads the file; a missing file yields defaults, a corrupt one is moved aside
    /// (the returned warning says so).
    pub fn load(path: &Path) -> (Self, Option<String>) {
        let (cfg, warning) = match util::read_bounded(path, MAX_CONFIG_LEN) {
            Ok(text) => match Config::from_json(&text) {
                Ok(cfg) => (cfg, None),
                Err(e) => {
                    let aside = path.with_file_name(format!(
                        "config.json.corrupt-{}",
                        util::utc_stamp(std::time::SystemTime::now())
                    ));
                    let moved = std::fs::rename(path, &aside).is_ok();
                    let warning = if moved {
                        format!(
                            "config.json was damaged ({e}); moved to {} and started with defaults",
                            aside.display()
                        )
                    } else {
                        format!("config.json was damaged ({e}); started with defaults")
                    };
                    (Config::default(), Some(warning))
                }
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => (Config::default(), None),
            Err(e) => (
                Config::default(),
                Some(format!("config.json unreadable ({e}); started with defaults")),
            ),
        };
        (
            Self {
                path: path.to_path_buf(),
                cfg: Mutex::new(cfg),
            },
            warning,
        )
    }

    /// The file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Config> {
        self.cfg.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A copy of the current configuration.
    pub fn get(&self) -> Config {
        self.lock().clone()
    }

    /// Applies `f` and saves the result (the change stays in memory if saving fails).
    pub fn update<R>(&self, f: impl FnOnce(&mut Config) -> R) -> io::Result<R> {
        let mut cfg = self.lock();
        let r = f(&mut cfg);
        cfg.sanitize();
        let json = serde_json::to_vec_pretty(&*cfg).map_err(io::Error::other)?;
        util::write_atomic(&self.path, &json)?;
        Ok(r)
    }

    /// The pinned identity of a server.
    pub fn pin(&self, addr: &ServerAddr) -> Option<PinnedIdentity> {
        self.lock().server(addr).and_then(|s| s.pin.clone())
    }

    /// Stores (or refreshes the name of) the pin after a successful login.
    pub fn store_pin(&self, addr: &ServerAddr, hello: &ServerHello) -> io::Result<()> {
        self.update(|cfg| {
            cfg.with_server(addr, |entry| match &mut entry.pin {
                Some(p) if check_pin(Some(p), hello) == PinCheck::Matches => {
                    p.server_name.clone_from(&hello.name);
                }
                pin => *pin = Some(PinnedIdentity::from_hello(hello)),
            });
            cfg.last_server = Some(addr.key());
        })
    }

    /// Removes the pin (and the remembered key, which belongs to the old identity).
    /// Returns `true` if there was one.
    pub fn reset_pin(&self, addr: &ServerAddr) -> io::Result<bool> {
        self.update(|cfg| {
            let key = addr.key();
            match cfg.servers.iter_mut().find(|s| s.address == key) {
                Some(s) => {
                    let had = s.pin.is_some();
                    s.pin = None;
                    s.remembered_psk = None;
                    had
                }
                None => false,
            }
        })
    }

    /// The remembered PSK of a server (DPAPI-decrypted).
    pub fn remembered_psk(&self, addr: &ServerAddr) -> Result<[u8; PSK_LEN], SecretError> {
        let blob = self
            .lock()
            .server(addr)
            .and_then(|s| s.remembered_psk.clone())
            .ok_or(SecretError::NotRemembered)?;
        let blob = base64_decode(&blob).map_err(|_| SecretError::Malformed)?;
        let mut plain = crate::sys::dpapi_unprotect(&blob).map_err(SecretError::Dpapi)?;
        let psk = <[u8; PSK_LEN]>::try_from(plain.as_slice()).map_err(|_| SecretError::Malformed);
        util::wipe(&mut plain);
        psk
    }

    /// Stores the PSK, DPAPI-encrypted for the current user.
    pub fn remember_psk(&self, addr: &ServerAddr, psk: &[u8; PSK_LEN]) -> io::Result<()> {
        let blob = crate::sys::dpapi_protect(psk)?;
        self.update(|cfg| {
            cfg.with_server(addr, |entry| entry.remembered_psk = Some(base64_encode(&blob)));
        })
    }

    /// Forgets the remembered PSK; `true` if there was one.
    pub fn forget_psk(&self, addr: &ServerAddr) -> io::Result<bool> {
        self.update(|cfg| {
            let key = addr.key();
            cfg.servers
                .iter_mut()
                .find(|s| s.address == key)
                .and_then(|s| s.remembered_psk.take())
                .is_some()
        })
    }

    /// `true` if a PSK is remembered for the server.
    pub fn has_remembered_psk(&self, addr: &ServerAddr) -> bool {
        self.lock()
            .server(addr)
            .is_some_and(|s| s.remembered_psk.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(salt: u8, m: u32) -> ServerHello {
        ServerHello {
            kdf: KdfParams { m, ..KdfParams::DEFAULT },
            ..ServerHello::new("Home", [salt; SALT_LEN])
        }
    }

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("beacon-config-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn addresses() {
        let a = ServerAddr::parse("Home.Example.org").unwrap();
        assert_eq!((a.host(), a.port()), ("home.example.org", DEFAULT_PORT));
        assert_eq!(a.key(), "home.example.org:28086");
        assert_eq!(ServerAddr::parse(" 10.0.0.5:1234 ").unwrap().key(), "10.0.0.5:1234");
        assert_eq!(ServerAddr::parse("[::1]:99").unwrap().key(), "[::1]:99");
        assert_eq!(ServerAddr::parse("[::1]").unwrap().port(), DEFAULT_PORT);
        assert_eq!(ServerAddr::parse("fe80::1").unwrap().key(), "[fe80::1]:28086");
        assert_eq!(ServerAddr::parse("my_box").unwrap().host(), "my_box");
        for bad in [
            "", "host:", "host:0", "host:65536", "host:x", "-a.b", "a..b", "a b", "[::1", "[x]:1",
            "[::1]x", "1:2:3", "host:1:2", "a/b", "http://x",
        ] {
            assert!(ServerAddr::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn names() {
        for ok in ["Floderso", "Sölron", "a b", "x-_.!?#()", "Twelve_Chars"] {
            assert_eq!(validate_player_name(ok), Ok(()), "{ok:?}");
        }
        assert_eq!(validate_player_name(""), Err(NameError::Empty));
        assert_eq!(validate_player_name("ThirteenChars"), Err(NameError::TooLong));
        assert_eq!(validate_player_name(" a"), Err(NameError::Spaces));
        assert_eq!(validate_player_name("a  b"), Err(NameError::Spaces));
        assert_eq!(validate_player_name("a/b"), Err(NameError::InvalidChar('/')));
        assert_eq!(validate_player_name("a\u{0}"), Err(NameError::InvalidChar('\0')));
    }

    #[test]
    fn pin_check() {
        let h = hello(1, 19_456);
        assert_eq!(check_pin(None, &h), PinCheck::Unpinned);
        let pin = PinnedIdentity::from_hello(&h);
        assert_eq!(check_pin(Some(&pin), &h), PinCheck::Matches);
        let renamed = ServerHello {
            name: "Other name".into(),
            ..h.clone()
        };
        assert_eq!(check_pin(Some(&pin), &renamed), PinCheck::Matches);
        assert!(matches!(check_pin(Some(&pin), &hello(2, 19_456)), PinCheck::Changed { .. }));
        assert!(matches!(check_pin(Some(&pin), &hello(1, 20_000)), PinCheck::Changed { .. }));
        let broken = PinnedIdentity {
            salt: "!!".into(),
            ..pin
        };
        assert!(matches!(check_pin(Some(&broken), &h), PinCheck::Changed { .. }));
    }

    #[test]
    fn store_pins_persist_and_reset() {
        let dir = temp("pins");
        let path = dir.join("config.json");
        let (store, warning) = ConfigStore::load(&path);
        assert!(warning.is_none());
        let addr = ServerAddr::parse("example.org").unwrap();
        assert!(store.pin(&addr).is_none());
        store.store_pin(&addr, &hello(1, 19_456)).unwrap();
        let (reloaded, _) = ConfigStore::load(&path);
        let pin = reloaded.pin(&addr).unwrap();
        assert_eq!(pin.salt_bytes(), Some([1; SALT_LEN]));
        assert_eq!(reloaded.get().last_server.as_deref(), Some("example.org:28086"));
        // A renamed server keeps its pin; the name is refreshed.
        reloaded
            .store_pin(&addr, &ServerHello { name: "New".into(), ..hello(1, 19_456) })
            .unwrap();
        assert_eq!(reloaded.pin(&addr).unwrap().server_name, "New");
        assert!(reloaded.reset_pin(&addr).unwrap());
        assert!(!reloaded.reset_pin(&addr).unwrap());
        assert!(reloaded.pin(&addr).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn remembered_psk_is_dpapi_protected() {
        let dir = temp("psk");
        let path = dir.join("config.json");
        let (store, _) = ConfigStore::load(&path);
        let addr = ServerAddr::parse("example.org:1").unwrap();
        assert!(matches!(store.remembered_psk(&addr), Err(SecretError::NotRemembered)));
        let psk = [0x5a; PSK_LEN];
        store.remember_psk(&addr, &psk).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&base64_encode(&psk)), "plaintext PSK on disk");
        let (reloaded, _) = ConfigStore::load(&path);
        assert_eq!(reloaded.remembered_psk(&addr).unwrap(), psk);
        assert!(reloaded.forget_psk(&addr).unwrap());
        assert!(!reloaded.has_remembered_psk(&addr));
        // Resetting the pin also forgets the key.
        reloaded.remember_psk(&addr, &psk).unwrap();
        reloaded.reset_pin(&addr).unwrap();
        assert!(!reloaded.has_remembered_psk(&addr));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_and_hand_edited_files() {
        let dir = temp("corrupt");
        let path = dir.join("config.json");
        std::fs::write(&path, b"{not json").unwrap();
        let (store, warning) = ConfigStore::load(&path);
        assert!(warning.unwrap().contains("damaged"));
        assert_eq!(store.get(), Config::default());
        assert!(!path.exists(), "moved aside");
        let edited = br#"{"player_name":"bad/name","servers":[{"address":"x y"},{"address":"A.b:7"},{"address":"a.b:7"}],
            "launch":{"windowed":true,"xres":5,"yres":720},"redundancy":{"lobby":9,"game":2},"game_dir":"relative","unknown":1}"#;
        let cfg = Config::from_json(edited).unwrap();
        assert_eq!(cfg.player_name, None);
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].address, "a.b:7");
        assert_eq!(cfg.launch.xres, None);
        assert_eq!(cfg.launch.yres, Some(720));
        assert_eq!(cfg.redundancy.lobby, None);
        assert_eq!(cfg.redundancy.game, Some(2));
        assert_eq!(cfg.game_dir, None);
        assert!(cfg.name_sync && cfg.auto_launch_on_host_start);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn launch_args_and_redundancy() {
        let o = LaunchOptions {
            windowed: true,
            xres: Some(1280),
            yres: Some(720),
            noshellmap: true,
        };
        assert_eq!(o.args(), ["-win", "-xres", "1280", "-yres", "720", "-noshellmap"]);
        assert!(LaunchOptions { noshellmap: false, ..Default::default() }.args().is_empty());
        let r = RedundancyOverrides::default();
        assert_eq!((r.for_port(8086), r.for_port(8094), r.for_port(5000)), (3, 2, 1));
        let r = RedundancyOverrides {
            lobby: Some(1),
            game: Some(3),
            other: Some(9),
        };
        assert_eq!((r.for_port(8093), r.for_port(8101), r.for_port(5000)), (1, 3, 1));
    }
}
