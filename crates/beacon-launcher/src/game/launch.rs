//! Starts `lotrbfme.exe` with the hook's environment (architecture §4.3) and the
//! command line from the launch options (spec 04 §2.7).
//!
//! `std::process::Command` performs the `CreateProcessW` call (application name =
//! the exe path, working directory = the game folder, environment = inherited +
//! `BEACON_*`, standard handles = null). Inherited `BEACON_*` variables are removed
//! first so stale values from Beacon's own environment never reach the game
//! (`BEACON_LOG_LEVEL` passes through for diagnostics).

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use beacon_proto::env as penv;

/// `ERROR_SYSTEM_INTEGRITY_POLICY_VIOLATION`: Smart App Control / WDAC blocked the exe.
pub const ERROR_APP_CONTROL_BLOCKED: i32 = 4551;
/// `ERROR_ACCESS_DISABLED_BY_POLICY` (Software Restriction Policies / AppLocker).
pub const ERROR_ACCESS_DISABLED_BY_POLICY: i32 = 1260;
/// `ERROR_ELEVATION_REQUIRED` (the exe is marked "run as administrator").
pub const ERROR_ELEVATION_REQUIRED: i32 = 740;

/// Environment for the hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookEnv {
    /// Agent's loopback UDP port.
    pub agent_port: u16,
    /// Local token.
    pub token: u32,
    /// The player's vIP.
    pub vip: Ipv4Addr,
    /// CD-key replacement (`fingerprint::beacon_serial`).
    pub serial: String,
    /// Hook log file.
    pub log: Option<PathBuf>,
    /// Test mode: per-instance user data base (`BEACON_MULTI=1` + `BEACON_USERDIR`).
    pub multi_userdir: Option<PathBuf>,
}

impl HookEnv {
    /// The `BEACON_*` variables.
    pub fn vars(&self) -> Vec<(&'static str, OsString)> {
        let mut v: Vec<(&'static str, OsString)> = vec![
            (penv::AGENT_PORT, self.agent_port.to_string().into()),
            (penv::LOCAL_TOKEN, penv::format_token(self.token).into()),
            (penv::VIP, self.vip.to_string().into()),
            (penv::SERIAL, self.serial.clone().into()),
        ];
        if let Some(log) = &self.log {
            v.push((penv::LOG, log.as_os_str().to_owned()));
        }
        if let Some(dir) = &self.multi_userdir {
            v.push((penv::MULTI, "1".into()));
            v.push((penv::USERDIR, dir.as_os_str().to_owned()));
        }
        v
    }
}

/// Everything needed to start the game.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    /// `<game dir>\lotrbfme.exe`.
    pub exe: PathBuf,
    /// Working directory (the game folder: the engine loads data relative to it).
    pub cwd: PathBuf,
    /// Command-line arguments.
    pub args: Vec<String>,
    /// Hook environment.
    pub env: HookEnv,
}

/// Why the game could not be started.
#[derive(Debug)]
pub enum LaunchError {
    /// The exe does not exist.
    ExeMissing(PathBuf),
    /// Smart App Control (or WDAC) blocked the exe (os error 4551).
    SmartAppControlBlocked(PathBuf),
    /// A software restriction policy blocked the exe (os error 1260).
    PolicyBlocked(PathBuf),
    /// The exe requires administrator rights (os error 740).
    ElevationRequired(PathBuf),
    /// Other start failure.
    Io(PathBuf, io::Error),
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExeMissing(p) => write!(f, "{} does not exist", p.display()),
            Self::SmartAppControlBlocked(p) => write!(
                f,
                "Windows Smart App Control blocked {} (os error 4551). Beacon never \
                 modifies the exe; use an unmodified installation",
                p.display()
            ),
            Self::PolicyBlocked(p) => write!(f, "a system policy blocked {} (os error 1260)", p.display()),
            Self::ElevationRequired(p) => write!(
                f,
                "{} is set to run as administrator (os error 740); remove that compatibility \
                 setting so Beacon can start it",
                p.display()
            ),
            Self::Io(p, e) => write!(f, "cannot start {}: {e}", p.display()),
        }
    }
}

impl std::error::Error for LaunchError {}

/// Maps a `CreateProcess` failure to a [`LaunchError`].
pub fn classify_spawn_error(exe: &Path, e: io::Error) -> LaunchError {
    match e.raw_os_error() {
        Some(ERROR_APP_CONTROL_BLOCKED) => LaunchError::SmartAppControlBlocked(exe.to_path_buf()),
        Some(ERROR_ACCESS_DISABLED_BY_POLICY) => LaunchError::PolicyBlocked(exe.to_path_buf()),
        Some(ERROR_ELEVATION_REQUIRED) => LaunchError::ElevationRequired(exe.to_path_buf()),
        _ if e.kind() == io::ErrorKind::NotFound => LaunchError::ExeMissing(exe.to_path_buf()),
        _ => LaunchError::Io(exe.to_path_buf(), e),
    }
}

/// Names of inherited variables to remove: every `BEACON_*` except
/// `BEACON_LOG_LEVEL` (case-insensitive, like the Windows environment).
pub fn inherited_beacon_vars(vars: impl Iterator<Item = OsString>) -> Vec<OsString> {
    vars.filter(|k| {
        let upper = k.to_string_lossy().to_ascii_uppercase();
        upper.starts_with("BEACON_") && upper != "BEACON_LOG_LEVEL"
    })
    .collect()
}

/// The `Command` for a spec (not yet started).
pub fn command(spec: &LaunchSpec) -> Command {
    let mut cmd = Command::new(&spec.exe);
    cmd.args(&spec.args)
        .current_dir(&spec.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for key in inherited_beacon_vars(std::env::vars_os().map(|(k, _)| k)) {
        cmd.env_remove(key);
    }
    for (k, v) in spec.env.vars() {
        cmd.env(k, v);
    }
    cmd
}

/// Starts the game.
pub fn spawn(spec: &LaunchSpec) -> Result<Child, LaunchError> {
    if !spec.exe.is_file() {
        return Err(LaunchError::ExeMissing(spec.exe.clone()));
    }
    command(spec)
        .spawn()
        .map_err(|e| classify_spawn_error(&spec.exe, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> HookEnv {
        HookEnv {
            agent_port: 50_000,
            token: 0xdead_beef,
            vip: Ipv4Addr::new(198, 18, 0, 7),
            serial: "ABCDEFGHIJ0123456789".into(),
            log: Some(PathBuf::from(r"C:\logs\hook.log")),
            multi_userdir: None,
        }
    }

    #[test]
    fn hook_environment() {
        let vars = env().vars();
        let get = |k: &str| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string_lossy().into_owned());
        assert_eq!(get("BEACON_AGENT_PORT").as_deref(), Some("50000"));
        assert_eq!(get("BEACON_LOCAL_TOKEN").as_deref(), Some("deadbeef"));
        assert_eq!(get("BEACON_VIP").as_deref(), Some("198.18.0.7"));
        assert_eq!(get("BEACON_SERIAL").as_deref(), Some("ABCDEFGHIJ0123456789"));
        assert_eq!(get("BEACON_LOG").as_deref(), Some(r"C:\logs\hook.log"));
        assert_eq!(get("BEACON_MULTI"), None);
        // Values round-trip through the hook's parsers.
        assert_eq!(penv::parse_agent_port(&get("BEACON_AGENT_PORT").unwrap()), Some(50_000));
        assert_eq!(penv::parse_token(&get("BEACON_LOCAL_TOKEN").unwrap()), Some(0xdead_beef));
        assert!(penv::parse_vip(&get("BEACON_VIP").unwrap()).is_some());
        assert!(penv::is_valid_serial(&get("BEACON_SERIAL").unwrap()));
        let multi = HookEnv {
            multi_userdir: Some(PathBuf::from(r"C:\b\userdata")),
            ..env()
        }
        .vars();
        assert!(multi.iter().any(|(k, v)| *k == "BEACON_MULTI" && v == "1"));
        assert!(multi.iter().any(|(k, v)| *k == "BEACON_USERDIR" && v == r"C:\b\userdata"));
    }

    #[test]
    fn stale_variables_are_removed() {
        let names = ["PATH", "BEACON_VIP", "beacon_multi", "BEACON_LOG_LEVEL", "BEACON_TEST_ARMED_WITHOUT_EXE", "XBEACON_X"];
        let removed = inherited_beacon_vars(names.iter().map(OsString::from));
        assert_eq!(removed, ["BEACON_VIP", "beacon_multi", "BEACON_TEST_ARMED_WITHOUT_EXE"]);
    }

    #[test]
    fn spawn_errors_are_typed() {
        let exe = Path::new(r"C:\x\lotrbfme.exe");
        assert!(matches!(
            classify_spawn_error(exe, io::Error::from_raw_os_error(4551)),
            LaunchError::SmartAppControlBlocked(_)
        ));
        assert!(matches!(
            classify_spawn_error(exe, io::Error::from_raw_os_error(1260)),
            LaunchError::PolicyBlocked(_)
        ));
        assert!(matches!(
            classify_spawn_error(exe, io::Error::from_raw_os_error(740)),
            LaunchError::ElevationRequired(_)
        ));
        assert!(matches!(
            classify_spawn_error(exe, io::Error::new(io::ErrorKind::NotFound, "x")),
            LaunchError::ExeMissing(_)
        ));
        let missing = LaunchSpec {
            exe: std::env::temp_dir().join("beacon-no-such-dir").join("lotrbfme.exe"),
            cwd: std::env::temp_dir(),
            args: vec![],
            env: env(),
        };
        assert!(matches!(spawn(&missing), Err(LaunchError::ExeMissing(_))));
    }

    #[test]
    fn command_line_and_environment() {
        let spec = LaunchSpec {
            exe: PathBuf::from(r"C:\BFME1\lotrbfme.exe"),
            cwd: PathBuf::from(r"C:\BFME1"),
            args: vec!["-win".into(), "-noshellmap".into()],
            env: env(),
        };
        let cmd = command(&spec);
        assert_eq!(cmd.get_program(), r"C:\BFME1\lotrbfme.exe");
        assert_eq!(cmd.get_args().collect::<Vec<_>>(), ["-win", "-noshellmap"]);
        assert_eq!(cmd.get_current_dir(), Some(Path::new(r"C:\BFME1")));
        let envs: Vec<_> = cmd.get_envs().collect();
        assert!(envs
            .iter()
            .any(|(k, v)| *k == "BEACON_VIP" && *v == Some(std::ffi::OsStr::new("198.18.0.7"))));
    }
}
