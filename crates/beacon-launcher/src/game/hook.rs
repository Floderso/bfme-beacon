//! Installs Beacon's `wsock32.dll` (crate `beacon-hook`) into the game folder.
//!
//! * Source: the `wsock32.dll` next to `Beacon.exe` (or `--hook-dll`). It must carry
//!   the marker `BFME-BEACON-HOOK/<version>`.
//! * A `wsock32.dll` in the game folder **without** the marker belongs to someone
//!   else (another network tool, a wrapper): it is never overwritten
//!   ([`HookError::Foreign`]).
//! * Copy = temporary file in the game folder + rename over the old file (atomic). A
//!   DLL loaded by a running game cannot be replaced ([`HookError::InUse`]); the old
//!   one stays.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::util;

/// File name of the hook in the game folder.
pub const HOOK_DLL_NAME: &str = "wsock32.dll";
/// Marker prefix compiled into `beacon-hook` (`BEACON_HOOK_MARKER`).
pub const MARKER_PREFIX: &[u8] = b"BFME-BEACON-HOOK/";
/// Largest DLL the launcher reads.
const MAX_DLL_SIZE: u64 = 32 << 20;
/// Longest version text after the marker prefix.
const MAX_VERSION_LEN: usize = 32;

/// The version text after the marker (`None` if the bytes carry no marker).
pub fn find_marker(bytes: &[u8]) -> Option<String> {
    let start = bytes
        .windows(MARKER_PREFIX.len())
        .position(|w| w == MARKER_PREFIX)?
        + MARKER_PREFIX.len();
    let rest = bytes.get(start..)?;
    let version: String = rest
        .iter()
        .take(MAX_VERSION_LEN)
        .take_while(|&&b| b.is_ascii_graphic())
        .map(|&b| char::from(b))
        .collect();
    Some(version)
}

/// State of the hook in the game folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HookStatus {
    /// The game folder is unknown.
    Unknown,
    /// Beacon's own `wsock32.dll` is missing (broken installation).
    SourceMissing {
        /// Where it was expected.
        expected: PathBuf,
    },
    /// No `wsock32.dll` in the game folder (installed on first launch).
    NotInstalled {
        /// Version that will be installed.
        available: String,
    },
    /// Identical to Beacon's DLL.
    UpToDate {
        /// Its version.
        version: String,
    },
    /// Another version of Beacon's hook (replaced on the next launch).
    Outdated {
        /// Installed version.
        installed: String,
        /// Version that will be installed.
        available: String,
    },
    /// A `wsock32.dll` that is not Beacon's: never overwritten.
    Foreign {
        /// Its path.
        path: PathBuf,
    },
    /// The files could not be read.
    Error {
        /// Description.
        message: String,
    },
}

/// What [`install`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallOutcome {
    /// The installed DLL was already identical.
    AlreadyCurrent,
    /// Newly installed.
    Installed,
    /// An older/other Beacon version was replaced.
    Updated,
}

/// Why the hook could not be installed.
#[derive(Debug)]
pub enum HookError {
    /// Beacon's own DLL is missing or unreadable.
    SourceMissing(PathBuf, io::Error),
    /// The source file is not Beacon's hook (no marker).
    SourceInvalid(PathBuf),
    /// A foreign `wsock32.dll` is in the game folder.
    Foreign(PathBuf),
    /// The DLL is loaded by a running game and cannot be replaced.
    InUse(PathBuf),
    /// No write permission in the game folder.
    PermissionDenied(PathBuf),
    /// Other I/O error.
    Io(PathBuf, io::Error),
}

impl fmt::Display for HookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceMissing(p, e) => write!(
                f,
                "Beacon's wsock32.dll is missing ({}: {e}); reinstall Beacon",
                p.display()
            ),
            Self::SourceInvalid(p) => write!(
                f,
                "{} is not Beacon's hook DLL (marker missing)",
                p.display()
            ),
            Self::Foreign(p) => write!(
                f,
                "{} belongs to another program (it is not Beacon's hook). Beacon never \
                 overwrites it: move it out of the game folder (e.g. rename it to \
                 wsock32.dll.bak) and start again",
                p.display()
            ),
            Self::InUse(p) => write!(
                f,
                "{} is in use (BFME is running); close the game to update the hook",
                p.display()
            ),
            Self::PermissionDenied(p) => write!(
                f,
                "no permission to write {} (game folder write-protected, e.g. under \
                 Program Files); allow writing or move the game",
                p.display()
            ),
            Self::Io(p, e) => write!(f, "{}: {e}", p.display()),
        }
    }
}

impl std::error::Error for HookError {}

fn read_dll(path: &Path) -> io::Result<Vec<u8>> {
    util::read_bounded(path, MAX_DLL_SIZE)
}

/// The hook's state in `game_dir` compared with `source`.
pub fn status(game_dir: &Path, source: &Path) -> HookStatus {
    let src = match read_dll(source) {
        Ok(b) => b,
        Err(_) => {
            return HookStatus::SourceMissing {
                expected: source.to_path_buf(),
            }
        }
    };
    let Some(available) = find_marker(&src) else {
        return HookStatus::Error {
            message: format!("{} is not Beacon's hook DLL", source.display()),
        };
    };
    let target = game_dir.join(HOOK_DLL_NAME);
    match read_dll(&target) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => HookStatus::NotInstalled { available },
        Err(e) => HookStatus::Error {
            message: format!("{}: {e}", target.display()),
        },
        Ok(installed) if installed == src => HookStatus::UpToDate { version: available },
        Ok(installed) => match find_marker(&installed) {
            Some(version) => HookStatus::Outdated {
                installed: version,
                available,
            },
            None => HookStatus::Foreign { path: target },
        },
    }
}

fn classify_write_error(path: &Path, e: io::Error) -> HookError {
    if e.kind() == io::ErrorKind::PermissionDenied {
        HookError::PermissionDenied(path.to_path_buf())
    } else {
        HookError::Io(path.to_path_buf(), e)
    }
}

/// Installs or updates the hook (see the module docs).
pub fn install(game_dir: &Path, source: &Path) -> Result<InstallOutcome, HookError> {
    let src = read_dll(source).map_err(|e| HookError::SourceMissing(source.to_path_buf(), e))?;
    if find_marker(&src).is_none() {
        return Err(HookError::SourceInvalid(source.to_path_buf()));
    }
    let target = game_dir.join(HOOK_DLL_NAME);
    let outcome = match read_dll(&target) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => InstallOutcome::Installed,
        Err(e) => return Err(HookError::Io(target, e)),
        Ok(existing) if existing == src => return Ok(InstallOutcome::AlreadyCurrent),
        Ok(existing) if find_marker(&existing).is_some() => InstallOutcome::Updated,
        Ok(_) => return Err(HookError::Foreign(target)),
    };
    let tmp = util::temp_sibling(&target, "beacon-new");
    let write = (|| {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(&src)?;
        f.sync_all()
    })();
    if let Err(e) = write {
        let _ = fs::remove_file(&tmp);
        return Err(classify_write_error(&target, e));
    }
    // Re-check right before the rename: a foreign DLL may have appeared meanwhile.
    if outcome == InstallOutcome::Installed && target.exists() {
        if let Ok(existing) = read_dll(&target) {
            if find_marker(&existing).is_none() {
                let _ = fs::remove_file(&tmp);
                return Err(HookError::Foreign(target));
            }
        }
    }
    if let Err(e) = fs::rename(&tmp, &target) {
        let _ = fs::remove_file(&tmp);
        // We could create a file in the folder, so a refused rename means the old
        // DLL is locked (mapped by the running game).
        return Err(match e.kind() {
            io::ErrorKind::PermissionDenied => HookError::InUse(target),
            _ if matches!(e.raw_os_error(), Some(32 | 33 | 1224)) => HookError::InUse(target),
            _ => HookError::Io(target, e),
        });
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dll(version: &str, body: &[u8]) -> Vec<u8> {
        let mut v = b"MZ\x90\x00 some code ".to_vec();
        v.extend_from_slice(body);
        v.extend_from_slice(MARKER_PREFIX);
        v.extend_from_slice(version.as_bytes());
        v.extend_from_slice(b"\0 trailing data");
        v
    }

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("beacon-hook-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("game")).unwrap();
        d
    }

    #[test]
    fn marker_search() {
        assert_eq!(find_marker(&dll("0.1.0", b"x")).as_deref(), Some("0.1.0"));
        assert_eq!(find_marker(b"BFME-BEACON-HOOK/"), Some(String::new()));
        assert_eq!(find_marker(b"BFME-BEACON-HOO"), None);
        assert_eq!(find_marker(b""), None);
        let long = [MARKER_PREFIX, &[b'9'; 100][..]].concat();
        assert_eq!(find_marker(&long).map(|v| v.len()), Some(MAX_VERSION_LEN));
    }

    #[test]
    fn install_update_and_status() {
        let d = temp("install");
        let game = d.join("game");
        let src = d.join("wsock32.dll");
        fs::write(&src, dll("0.2.0", b"new")).unwrap();
        assert_eq!(
            status(&game, &src),
            HookStatus::NotInstalled { available: "0.2.0".into() }
        );
        assert_eq!(install(&game, &src).unwrap(), InstallOutcome::Installed);
        assert_eq!(fs::read(game.join(HOOK_DLL_NAME)).unwrap(), fs::read(&src).unwrap());
        assert_eq!(status(&game, &src), HookStatus::UpToDate { version: "0.2.0".into() });
        assert_eq!(install(&game, &src).unwrap(), InstallOutcome::AlreadyCurrent);
        // An older Beacon hook is replaced.
        fs::write(game.join(HOOK_DLL_NAME), dll("0.1.0", b"old")).unwrap();
        assert_eq!(
            status(&game, &src),
            HookStatus::Outdated { installed: "0.1.0".into(), available: "0.2.0".into() }
        );
        assert_eq!(install(&game, &src).unwrap(), InstallOutcome::Updated);
        assert_eq!(fs::read(game.join(HOOK_DLL_NAME)).unwrap(), fs::read(&src).unwrap());
        let names: Vec<_> = fs::read_dir(&game).unwrap().filter_map(Result::ok).collect();
        assert_eq!(names.len(), 1, "no temporary files left");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn foreign_dll_is_never_overwritten() {
        let d = temp("foreign");
        let game = d.join("game");
        let src = d.join("wsock32.dll");
        fs::write(&src, dll("0.2.0", b"new")).unwrap();
        let foreign = b"MZ another wsock32 proxy".to_vec();
        fs::write(game.join(HOOK_DLL_NAME), &foreign).unwrap();
        assert!(matches!(status(&game, &src), HookStatus::Foreign { .. }));
        let err = install(&game, &src).unwrap_err();
        assert!(matches!(err, HookError::Foreign(_)));
        assert!(err.to_string().contains("never"));
        assert_eq!(fs::read(game.join(HOOK_DLL_NAME)).unwrap(), foreign);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn bad_sources() {
        let d = temp("source");
        let game = d.join("game");
        let missing = d.join("nope.dll");
        assert!(matches!(install(&game, &missing), Err(HookError::SourceMissing(..))));
        assert!(matches!(status(&game, &missing), HookStatus::SourceMissing { .. }));
        let unmarked = d.join("plain.dll");
        fs::write(&unmarked, b"MZ plain").unwrap();
        assert!(matches!(install(&game, &unmarked), Err(HookError::SourceInvalid(_))));
        assert!(!game.join(HOOK_DLL_NAME).exists());
        let _ = fs::remove_dir_all(&d);
    }

    #[cfg(windows)]
    #[test]
    fn locked_target_reports_in_use() {
        use std::os::windows::fs::OpenOptionsExt;
        let d = temp("inuse");
        let game = d.join("game");
        let src = d.join("wsock32.dll");
        fs::write(&src, dll("0.2.0", b"new")).unwrap();
        let target = game.join(HOOK_DLL_NAME);
        fs::write(&target, dll("0.1.0", b"old")).unwrap();
        // Like a mapped image: readable, but neither writable nor deletable.
        let _lock = OpenOptions::new()
            .read(true)
            .share_mode(1) // FILE_SHARE_READ
            .open(&target)
            .unwrap();
        let err = install(&game, &src).unwrap_err();
        assert!(matches!(err, HookError::InUse(_)), "{err:?}");
        assert_eq!(find_marker(&fs::read(&target).unwrap()).as_deref(), Some("0.1.0"));
        drop(_lock);
        let _ = fs::remove_dir_all(&d);
    }
}
