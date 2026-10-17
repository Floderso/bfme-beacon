//! The launcher → hook environment contract (architecture §4.3) and the two
//! hook-local variables `BEACON_LOG_LEVEL` and `BEACON_TEST_ARMED_WITHOUT_EXE`.
//!
//! Read once in `DllMain(PROCESS_ATTACH)` with `GetEnvironmentVariableW` into fixed
//! buffers (no allocation); the value parsers are `beacon_proto::env`'s.

use std::net::Ipv4Addr;

use beacon_proto::env as penv;

use crate::ffi;
use crate::wide::WideBuf;

/// `debug` enables per-datagram log lines (anything else: bind/close/errors only).
pub const LOG_LEVEL: &str = "BEACON_LOG_LEVEL";
/// `1` arms socket virtualisation without the exe identity check and without any
/// IAT patch. For the hook harness only.
pub const TEST_ARMED_WITHOUT_EXE: &str = "BEACON_TEST_ARMED_WITHOUT_EXE";

/// Longest accepted `BEACON_USERDIR` in characters. The game appends
/// `\My Battle for Middle-earth Files\` and file names to the returned folder in
/// `MAX_PATH` stack buffers (spec 04 §4.1), so the base must stay well below 260.
pub const USERDIR_MAX: usize = 200;
/// Capacity of path buffers handed to `SHGetSpecialFolderPath` callers (`MAX_PATH`
/// plus terminator).
pub const PATH_CAP: usize = 261;
/// Capacity of the log path buffer.
pub const LOG_PATH_CAP: usize = 521;

/// Result of reading one variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvValue {
    /// Not set (or empty).
    Unset,
    /// Longer than the buffer.
    TooLong,
    /// Set; this many UTF-16 units were written (no terminator counted).
    Len(usize),
}

/// Source of environment variables (the process environment, or a map in tests).
pub trait EnvSource {
    /// Reads `name` into `buf`.
    fn read(&self, name: &str, buf: &mut [u16]) -> EnvValue;
}

/// The real process environment (`GetEnvironmentVariableW`).
pub struct ProcessEnv;

impl EnvSource for ProcessEnv {
    fn read(&self, name: &str, buf: &mut [u16]) -> EnvValue {
        let mut wname = WideBuf::<64>::new();
        if !wname.push_ascii(name) {
            return EnvValue::Unset;
        }
        let cap = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `wname` is NUL-terminated, `buf` is writable for `cap` units.
        let n = unsafe { ffi::GetEnvironmentVariableW(wname.as_ptr(), buf.as_mut_ptr(), cap) };
        let n = usize::try_from(n).unwrap_or(usize::MAX);
        if n == 0 {
            EnvValue::Unset
        } else if n >= buf.len() {
            EnvValue::TooLong
        } else {
            EnvValue::Len(n)
        }
    }
}

/// An ASCII value read into a fixed buffer.
enum Ascii<'a> {
    Unset,
    Invalid,
    Value(&'a str),
}

fn read_ascii<'a>(env: &impl EnvSource, name: &str, out: &'a mut [u8; 64]) -> Ascii<'a> {
    let mut wide = [0u16; 64];
    let n = match env.read(name, &mut wide) {
        EnvValue::Unset => return Ascii::Unset,
        EnvValue::TooLong => return Ascii::Invalid,
        EnvValue::Len(n) => n,
    };
    let Some(src) = wide.get(..n) else {
        return Ascii::Invalid;
    };
    for (dst, &c) in out.iter_mut().zip(src) {
        match u8::try_from(c) {
            Ok(b) if b.is_ascii() => *dst = b,
            _ => return Ascii::Invalid,
        }
    }
    match out.get(..n).and_then(|b| core::str::from_utf8(b).ok()) {
        Some(s) => Ascii::Value(s),
        None => Ascii::Invalid,
    }
}

/// Why an armed configuration is unusable (the hook then stays passive and logs it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// `BEACON_AGENT_PORT` is not a port `1..=65535`.
    AgentPort,
    /// `BEACON_LOCAL_TOKEN` missing.
    TokenMissing,
    /// `BEACON_LOCAL_TOKEN` not 1–8 hex digits.
    TokenInvalid,
    /// `BEACON_VIP` missing.
    VipMissing,
    /// `BEACON_VIP` not a player vIP in `198.18.0.2..=198.18.0.254`.
    VipInvalid,
}

impl ConfigError {
    /// Log text.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::AgentPort => "BEACON_AGENT_PORT is not a port 1..65535",
            Self::TokenMissing => "BEACON_LOCAL_TOKEN is missing",
            Self::TokenInvalid => "BEACON_LOCAL_TOKEN is not 1-8 hex digits",
            Self::VipMissing => "BEACON_VIP is missing",
            Self::VipInvalid => "BEACON_VIP is not in 198.18.0.2..198.18.0.254",
        }
    }
}

/// Why test mode (`BEACON_MULTI=1`) cannot be honoured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultiProblem {
    /// `BEACON_USERDIR` missing.
    UserdirMissing,
    /// `BEACON_USERDIR` not an absolute path of at most [`USERDIR_MAX`] characters.
    UserdirInvalid,
}

/// The parsed configuration of an armed hook.
#[derive(Clone, Copy)]
pub struct Config {
    /// The agent's loopback UDP port.
    pub agent_port: u16,
    /// Local token carried in every hook → agent frame.
    pub token: u32,
    /// This player's vIP.
    pub vip: Ipv4Addr,
    /// `BEACON_SERIAL`, if set and well-formed.
    pub serial: Option<[u8; penv::SERIAL_LEN]>,
    /// `BEACON_SERIAL` was set but malformed (ignored, the registry value passes through).
    pub serial_invalid: bool,
    /// `BEACON_MULTI=1` with a valid `BEACON_USERDIR`.
    pub multi: bool,
    /// The per-instance user-data base (only with `multi`).
    pub userdir: Option<WideBuf<PATH_CAP>>,
    /// `BEACON_MULTI=1` was requested but cannot be honoured.
    pub multi_problem: Option<MultiProblem>,
}

/// `true` if `BEACON_AGENT_PORT` is set at all (the launcher wants the hook armed).
pub fn agent_port_set(env: &impl EnvSource) -> bool {
    let mut buf = [0u16; 16];
    env.read(penv::AGENT_PORT, &mut buf) != EnvValue::Unset
}

/// `true` if `BEACON_TEST_ARMED_WITHOUT_EXE=1`.
pub fn test_armed_without_exe(env: &impl EnvSource) -> bool {
    let mut out = [0u8; 64];
    matches!(read_ascii(env, TEST_ARMED_WITHOUT_EXE, &mut out), Ascii::Value(v) if penv::is_enabled(v))
}

/// `true` for an absolute Windows path (`X:\…` or `\\server\…`) of at most
/// [`USERDIR_MAX`] characters without characters that are invalid in paths.
pub fn is_valid_userdir(path: &[u16]) -> bool {
    let at = |i: usize| path.get(i).copied().unwrap_or(0);
    let is = |i: usize, c: u8| at(i) == u16::from(c);
    if path.len() < 3 || path.len() > USERDIR_MAX {
        return false;
    }
    let drive = u8::try_from(at(0)).is_ok_and(|b| b.is_ascii_alphabetic())
        && is(1, b':')
        && (is(2, b'\\') || is(2, b'/'));
    let unc = is(0, b'\\') && is(1, b'\\');
    let clean = path.iter().enumerate().all(|(i, &c)| {
        c >= 0x20
            && !(c == u16::from(b':') && i != 1)
            && !b"\"<>|?*".iter().any(|&bad| c == u16::from(bad))
    });
    (drive || unc) && clean
}

/// Parses the armed configuration.
pub fn parse(env: &impl EnvSource) -> Result<Config, ConfigError> {
    let mut buf = [0u8; 64];
    let agent_port = match read_ascii(env, penv::AGENT_PORT, &mut buf) {
        Ascii::Value(s) => penv::parse_agent_port(s).ok_or(ConfigError::AgentPort)?,
        Ascii::Unset | Ascii::Invalid => return Err(ConfigError::AgentPort),
    };
    let token = match read_ascii(env, penv::LOCAL_TOKEN, &mut buf) {
        Ascii::Value(s) => penv::parse_token(s).ok_or(ConfigError::TokenInvalid)?,
        Ascii::Unset => return Err(ConfigError::TokenMissing),
        Ascii::Invalid => return Err(ConfigError::TokenInvalid),
    };
    let vip = match read_ascii(env, penv::VIP, &mut buf) {
        Ascii::Value(s) => penv::parse_vip(s).ok_or(ConfigError::VipInvalid)?,
        Ascii::Unset => return Err(ConfigError::VipMissing),
        Ascii::Invalid => return Err(ConfigError::VipInvalid),
    };

    let (serial, serial_invalid) = match read_ascii(env, penv::SERIAL, &mut buf) {
        Ascii::Value(s) if penv::is_valid_serial(s) => {
            let mut serial = [0u8; penv::SERIAL_LEN];
            serial.copy_from_slice(s.as_bytes().get(..penv::SERIAL_LEN).unwrap_or(&[0; 20]));
            (Some(serial), false)
        }
        Ascii::Unset => (None, false),
        Ascii::Value(_) | Ascii::Invalid => (None, true),
    };

    let multi_requested =
        matches!(read_ascii(env, penv::MULTI, &mut buf), Ascii::Value(s) if penv::is_enabled(s));
    let (multi, userdir, multi_problem) = if multi_requested {
        let mut wide = [0u16; PATH_CAP];
        match env.read(penv::USERDIR, &mut wide) {
            EnvValue::Unset => (false, None, Some(MultiProblem::UserdirMissing)),
            EnvValue::TooLong => (false, None, Some(MultiProblem::UserdirInvalid)),
            EnvValue::Len(n) => {
                let dir = wide
                    .get(..n)
                    .filter(|p| is_valid_userdir(p))
                    .and_then(WideBuf::<PATH_CAP>::from_slice);
                match dir {
                    Some(dir) => (true, Some(dir), None),
                    None => (false, None, Some(MultiProblem::UserdirInvalid)),
                }
            }
        }
    } else {
        (false, None, None)
    };

    Ok(Config {
        agent_port,
        token,
        vip,
        serial,
        serial_invalid,
        multi,
        userdir,
        multi_problem,
    })
}

/// Logging settings (`BEACON_LOG`, `BEACON_LOG_LEVEL`).
#[derive(Clone, Copy)]
pub struct LogSettings {
    /// Log file path.
    pub path: WideBuf<LOG_PATH_CAP>,
    /// Per-datagram lines.
    pub debug: bool,
}

/// `Some` if `BEACON_LOG` is set to a usable path.
pub fn log_settings(env: &impl EnvSource) -> Option<LogSettings> {
    let mut wide = [0u16; LOG_PATH_CAP];
    let path = match env.read(penv::LOG, &mut wide) {
        EnvValue::Len(n) => wide.get(..n).and_then(WideBuf::<LOG_PATH_CAP>::from_slice)?,
        EnvValue::Unset | EnvValue::TooLong => return None,
    };
    let mut buf = [0u8; 64];
    let debug = matches!(
        read_ascii(env, LOG_LEVEL, &mut buf),
        Ascii::Value(s) if s.trim().eq_ignore_ascii_case("debug")
    );
    Some(LogSettings { path, debug })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MapEnv(HashMap<&'static str, String>);

    impl EnvSource for MapEnv {
        fn read(&self, name: &str, buf: &mut [u16]) -> EnvValue {
            match self.0.get(name) {
                None => EnvValue::Unset,
                Some(v) if v.is_empty() => EnvValue::Unset,
                Some(v) => {
                    let w: Vec<u16> = v.encode_utf16().collect();
                    if w.len() >= buf.len() {
                        return EnvValue::TooLong;
                    }
                    buf[..w.len()].copy_from_slice(&w);
                    EnvValue::Len(w.len())
                }
            }
        }
    }

    fn env(pairs: &[(&'static str, &str)]) -> MapEnv {
        MapEnv(pairs.iter().map(|&(k, v)| (k, v.to_owned())).collect())
    }

    const BASE: [(&str, &str); 3] = [
        ("BEACON_AGENT_PORT", "50123"),
        ("BEACON_LOCAL_TOKEN", "a1b2c3d4"),
        ("BEACON_VIP", "198.18.0.7"),
    ];

    fn with(extra: &[(&'static str, &str)]) -> MapEnv {
        let mut pairs: Vec<(&'static str, &str)> = BASE.to_vec();
        pairs.extend_from_slice(extra);
        env(&pairs)
    }

    #[test]
    fn minimal_armed_config() {
        let e = with(&[]);
        assert!(agent_port_set(&e));
        let c = parse(&e).unwrap();
        assert_eq!(c.agent_port, 50123);
        assert_eq!(c.token, 0xA1B2_C3D4);
        assert_eq!(c.vip, Ipv4Addr::new(198, 18, 0, 7));
        assert!(c.serial.is_none() && !c.serial_invalid);
        assert!(!c.multi && c.userdir.is_none() && c.multi_problem.is_none());
        assert!(!test_armed_without_exe(&e));
        assert!(log_settings(&e).is_none());
    }

    #[test]
    fn missing_or_bad_required_values() {
        assert!(!agent_port_set(&env(&[])));
        let e = env(&[("BEACON_AGENT_PORT", "x"), ("BEACON_LOCAL_TOKEN", "1"), ("BEACON_VIP", "198.18.0.7")]);
        assert!(agent_port_set(&e));
        assert_eq!(parse(&e).err(), Some(ConfigError::AgentPort));
        let e = env(&[("BEACON_AGENT_PORT", "0"), ("BEACON_LOCAL_TOKEN", "1"), ("BEACON_VIP", "198.18.0.7")]);
        assert_eq!(parse(&e).err(), Some(ConfigError::AgentPort));
        let e = env(&[("BEACON_AGENT_PORT", "5"), ("BEACON_VIP", "198.18.0.7")]);
        assert_eq!(parse(&e).err(), Some(ConfigError::TokenMissing));
        let e = env(&[("BEACON_AGENT_PORT", "5"), ("BEACON_LOCAL_TOKEN", "xyz"), ("BEACON_VIP", "198.18.0.7")]);
        assert_eq!(parse(&e).err(), Some(ConfigError::TokenInvalid));
        let e = env(&[("BEACON_AGENT_PORT", "5"), ("BEACON_LOCAL_TOKEN", "1")]);
        assert_eq!(parse(&e).err(), Some(ConfigError::VipMissing));
        for bad in ["198.18.0.1", "198.18.0.255", "10.0.0.5", "nonsense", "198.18.0.1234"] {
            let e = env(&[("BEACON_AGENT_PORT", "5"), ("BEACON_LOCAL_TOKEN", "1"), ("BEACON_VIP", bad)]);
            assert_eq!(parse(&e).err(), Some(ConfigError::VipInvalid), "{bad}");
        }
        let long = "1".repeat(100);
        let e = env(&[("BEACON_AGENT_PORT", "5"), ("BEACON_LOCAL_TOKEN", &long), ("BEACON_VIP", "198.18.0.7")]);
        assert_eq!(parse(&e).err(), Some(ConfigError::TokenInvalid));
        let e = env(&[("BEACON_AGENT_PORT", "5"), ("BEACON_LOCAL_TOKEN", "ä1"), ("BEACON_VIP", "198.18.0.7")]);
        assert_eq!(parse(&e).err(), Some(ConfigError::TokenInvalid));
    }

    #[test]
    fn serial() {
        let c = parse(&with(&[("BEACON_SERIAL", "ABCDEFGHIJ0123456789")])).unwrap();
        assert_eq!(&c.serial.unwrap(), b"ABCDEFGHIJ0123456789");
        for bad in ["abcdefghij0123456789", "ABC", "ABCDEFGHIJ01234567890"] {
            let c = parse(&with(&[("BEACON_SERIAL", bad)])).unwrap();
            assert!(c.serial.is_none() && c.serial_invalid, "{bad}");
        }
    }

    #[test]
    fn multi_mode() {
        let c = parse(&with(&[("BEACON_MULTI", "1"), ("BEACON_USERDIR", r"D:\Beacon\inst2")])).unwrap();
        assert!(c.multi && c.multi_problem.is_none());
        let dir: Vec<u16> = r"D:\Beacon\inst2".encode_utf16().collect();
        assert_eq!(c.userdir.unwrap().as_slice(), dir.as_slice());

        let c = parse(&with(&[("BEACON_MULTI", "1")])).unwrap();
        assert!(!c.multi && c.userdir.is_none());
        assert_eq!(c.multi_problem, Some(MultiProblem::UserdirMissing));

        let c = parse(&with(&[("BEACON_MULTI", "1"), ("BEACON_USERDIR", "relative\\dir")])).unwrap();
        assert_eq!(c.multi_problem, Some(MultiProblem::UserdirInvalid));

        let c = parse(&with(&[("BEACON_MULTI", "0"), ("BEACON_USERDIR", r"D:\x")])).unwrap();
        assert!(!c.multi && c.userdir.is_none() && c.multi_problem.is_none());
    }

    #[test]
    fn userdir_rules() {
        let ok = |s: &str| is_valid_userdir(&s.encode_utf16().collect::<Vec<_>>());
        assert!(ok(r"C:\Users\x\AppData\Roaming\Beacon\2"));
        assert!(ok("D:/beacon/inst"));
        assert!(ok(r"\\server\share\dir"));
        assert!(ok(r"C:\Spiele\Ünïcode"));
        assert!(!ok("C:"));
        assert!(!ok(r"dir\sub"));
        assert!(!ok(r"C:\a:b"));
        assert!(!ok(r"C:\a?b"));
        assert!(!ok(r"\\?\C:\x"));
        assert!(!ok("C:\\a\u{1}b"));
        assert!(!ok(&format!(r"C:\{}", "a".repeat(USERDIR_MAX))));
        assert!(ok(&format!(r"C:\{}", "a".repeat(USERDIR_MAX - 3))));
    }

    #[test]
    fn test_flag_and_log() {
        let e = with(&[
            ("BEACON_TEST_ARMED_WITHOUT_EXE", "1"),
            ("BEACON_LOG", r"C:\Temp\hook.log"),
            ("BEACON_LOG_LEVEL", " Debug "),
        ]);
        assert!(test_armed_without_exe(&e));
        let log = log_settings(&e).unwrap();
        assert!(log.debug);
        assert_eq!(log.path.len(), r"C:\Temp\hook.log".len());
        let e = with(&[("BEACON_TEST_ARMED_WITHOUT_EXE", "yes"), ("BEACON_LOG", "x.log")]);
        assert!(!test_armed_without_exe(&e));
        assert!(!log_settings(&e).unwrap().debug);
    }

    #[test]
    fn process_env_reads_real_variables() {
        // The process environment is shared by all tests: use a unique name.
        std::env::set_var("BEACON_HOOK_UNIT_TEST_VAR", "4711");
        let mut buf = [0u16; 8];
        assert_eq!(ProcessEnv.read("BEACON_HOOK_UNIT_TEST_VAR", &mut buf), EnvValue::Len(4));
        let mut small = [0u16; 4];
        assert_eq!(ProcessEnv.read("BEACON_HOOK_UNIT_TEST_VAR", &mut small), EnvValue::TooLong);
        assert_eq!(ProcessEnv.read("BEACON_HOOK_UNIT_TEST_UNSET", &mut buf), EnvValue::Unset);
    }
}
