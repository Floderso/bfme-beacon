//! Test mode (two BFME instances on one PC, spec 04 §3.2–§3.3): every instance gets
//! its own user data base (`BEACON_USERDIR`, returned by the hook for
//! `CSIDL_APPDATA`). On first use the real `Options.ini`/`Network.ini` are copied
//! into it (reading the real folder only) and a distinct `UserName` is set.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::netini::{self, NETWORK_INI};

/// The hook accepts `BEACON_USERDIR` values up to this many UTF-16 units (the game
/// appends its leaf folder in `MAX_PATH` buffers).
pub const USERDIR_MAX: usize = 200;
/// Preference files copied on first use.
pub const COPIED_FILES: [&str; 2] = ["Options.ini", NETWORK_INI];

/// Errors preparing a test-mode user directory.
#[derive(Debug)]
pub enum UserDirError {
    /// The path is not usable as `BEACON_USERDIR` (relative, too long, bad characters).
    Unusable(PathBuf),
    /// File system error.
    Io(PathBuf, io::Error),
}

impl fmt::Display for UserDirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unusable(p) => write!(
                f,
                "{} cannot be used as the instance's user folder (must be an absolute path \
                 of at most {USERDIR_MAX} characters); use a shorter --data-dir",
                p.display()
            ),
            Self::Io(p, e) => write!(f, "{}: {e}", p.display()),
        }
    }
}

impl std::error::Error for UserDirError {}

/// Same rule as the hook: `X:\…` or `\\server\…`, at most [`USERDIR_MAX`] UTF-16
/// units, no control characters, no `"<>|?*`, `:` only as the drive separator.
pub fn is_valid_userdir(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    let units: Vec<u16> = text.encode_utf16().collect();
    if units.len() < 3 || units.len() > USERDIR_MAX {
        return false;
    }
    let b = text.as_bytes();
    let drive = b.first().is_some_and(u8::is_ascii_alphabetic)
        && b.get(1) == Some(&b':')
        && matches!(b.get(2), Some(b'\\' | b'/'));
    let unc = text.starts_with("\\\\");
    let clean = text.char_indices().all(|(i, c)| {
        !c.is_control() && !(c == ':' && i != 1) && !"\"<>|?*".contains(c)
    });
    (drive || unc) && clean
}

/// Result of [`prepare`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    /// The directory holding the instance's `Options.ini`/`Network.ini`.
    pub prefs_dir: PathBuf,
    /// Files copied now (first use).
    pub copied: Vec<String>,
    /// The `UserName` was set now (first use).
    pub named: bool,
}

/// Creates the instance's preference directory `prefs_dir` (below the
/// `BEACON_USERDIR` base `userdir`); on first use copies the preference files from
/// `real_prefs_dir` and sets `UserName` to `user_name`.
pub fn prepare(
    userdir: &Path,
    prefs_dir: &Path,
    real_prefs_dir: Option<&Path>,
    user_name: &str,
    backup_file: &Path,
) -> Result<Prepared, UserDirError> {
    if !is_valid_userdir(userdir) {
        return Err(UserDirError::Unusable(userdir.to_path_buf()));
    }
    fs::create_dir_all(prefs_dir).map_err(|e| UserDirError::Io(prefs_dir.to_path_buf(), e))?;
    let netini_path = prefs_dir.join(NETWORK_INI);
    let first_use = !netini_path.exists();
    let mut copied = Vec::new();
    if first_use {
        if let Some(real) = real_prefs_dir.filter(|r| *r != prefs_dir) {
            for name in COPIED_FILES {
                let (src, dst) = (real.join(name), prefs_dir.join(name));
                if dst.exists() || !src.is_file() {
                    continue;
                }
                fs::copy(&src, &dst).map_err(|e| UserDirError::Io(dst.clone(), e))?;
                copied.push(name.to_owned());
            }
        }
        netini::sync_user_name(&netini_path, user_name, backup_file).map_err(|e| match e {
            netini::NameSyncError::Io(p, e) => UserDirError::Io(p, e),
        })?;
    }
    Ok(Prepared {
        prefs_dir: prefs_dir.to_path_buf(),
        copied,
        named: first_use,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userdir_rules() {
        assert!(is_valid_userdir(Path::new(r"C:\Users\x\AppData\Roaming\Beacon\instance-2\userdata")));
        assert!(is_valid_userdir(Path::new(r"\\server\share\x")));
        assert!(!is_valid_userdir(Path::new(r"relative\x")));
        assert!(!is_valid_userdir(Path::new(r"C:\a|b")));
        assert!(!is_valid_userdir(Path::new(r"C:\a:b")));
        assert!(!is_valid_userdir(&PathBuf::from(format!(r"C:\{}", "a".repeat(USERDIR_MAX)))));
    }

    #[test]
    fn first_use_copies_and_names() {
        let base = std::env::temp_dir().join(format!("beacon-userdir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let real = base.join("real");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("Options.ini"), b"Resolution = 800 600\r\n").unwrap();
        fs::write(real.join(NETWORK_INI), b"Color = 3\r\nUserName = A_00\r\n").unwrap();
        let userdir = base.join("userdata");
        let prefs = userdir.join("My Battle for Middle-earth Files");
        let backup = base.join("name-backup.json");
        let p = prepare(&userdir, &prefs, Some(&real), "Instanz2", &backup).unwrap();
        assert_eq!(p.copied, ["Options.ini", NETWORK_INI]);
        assert!(p.named);
        assert_eq!(fs::read(prefs.join("Options.ini")).unwrap(), b"Resolution = 800 600\r\n");
        let net = fs::read(prefs.join(NETWORK_INI)).unwrap();
        assert_eq!(netini::find_value(&net, "Color").as_deref(), Some("3"));
        assert_eq!(
            netini::decode_user_name(&netini::find_value(&net, "UserName").unwrap()),
            "Instanz2"
        );
        // The real files are untouched.
        assert_eq!(fs::read(real.join(NETWORK_INI)).unwrap(), b"Color = 3\r\nUserName = A_00\r\n");
        // Second use: nothing copied again.
        let p = prepare(&userdir, &prefs, Some(&real), "Other", &backup).unwrap();
        assert!(p.copied.is_empty() && !p.named);
        let _ = fs::remove_dir_all(&base);
    }
}
