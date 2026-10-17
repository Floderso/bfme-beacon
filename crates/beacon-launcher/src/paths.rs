//! Beacon's own data directory: `%APPDATA%\Beacon` (or `--data-dir`), one
//! sub-directory `instance-N` per extra instance (`--instance N`, N ≥ 2).
//!
//! ```text
//! <data dir>\config.json          settings, servers with pinned identity, DPAPI PSKs
//! <data dir>\cache.json           fingerprint hash cache (path, size, mtime → BLAKE3)
//! <data dir>\name-backup.json     original Network.ini UserName values (restore-name)
//! <data dir>\running.json         port + token of the running instance (handover)
//! <data dir>\logs\                beacon-<stamp>.log, hook-<stamp>.log (rotated)
//! <data dir>\userdata\            test mode: BEACON_USERDIR of this instance
//! ```

use std::fmt;
use std::path::{Path, PathBuf};

/// Highest `--instance` number (BFME probes 8 lobby ports per PC).
pub const MAX_INSTANCE: u32 = 8;

/// Errors resolving the data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// `%APPDATA%` is not set and no `--data-dir` was given.
    NoAppData,
    /// `--instance` outside `1..=MAX_INSTANCE`.
    BadInstance(u32),
    /// `--data-dir` is not absolute.
    NotAbsolute(PathBuf),
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAppData => f.write_str("%APPDATA% is not set; pass --data-dir"),
            Self::BadInstance(n) => write!(f, "--instance must be 1..={MAX_INSTANCE} (got {n})"),
            Self::NotAbsolute(p) => write!(f, "--data-dir must be an absolute path ({})", p.display()),
        }
    }
}

impl std::error::Error for PathError {}

/// `%APPDATA%` (the roaming application data folder), if set.
pub fn appdata_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// The resolved data directory of one launcher instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataDirs {
    root: PathBuf,
    instance: u32,
}

impl DataDirs {
    /// `data_dir` (absolute) or `%APPDATA%\Beacon`; for `instance >= 2` the
    /// sub-directory `instance-N`.
    pub fn resolve(data_dir: Option<&Path>, instance: u32) -> Result<Self, PathError> {
        let base = match data_dir {
            Some(d) if d.is_absolute() => d.to_path_buf(),
            Some(d) => return Err(PathError::NotAbsolute(d.to_path_buf())),
            None => appdata_dir().ok_or(PathError::NoAppData)?.join("Beacon"),
        };
        Self::with_base(base, instance)
    }

    /// Like [`resolve`](Self::resolve) with an explicit base directory.
    pub fn with_base(base: PathBuf, instance: u32) -> Result<Self, PathError> {
        if !(1..=MAX_INSTANCE).contains(&instance) {
            return Err(PathError::BadInstance(instance));
        }
        let root = if instance >= 2 {
            base.join(format!("instance-{instance}"))
        } else {
            base
        };
        Ok(Self { root, instance })
    }

    /// The directory itself.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The instance number (1 = default).
    pub fn instance(&self) -> u32 {
        self.instance
    }

    /// `config.json`.
    pub fn config_file(&self) -> PathBuf {
        self.root.join("config.json")
    }

    /// `cache.json` (fingerprint hash cache).
    pub fn cache_file(&self) -> PathBuf {
        self.root.join("cache.json")
    }

    /// `name-backup.json` (original Network.ini `UserName` values).
    pub fn name_backup_file(&self) -> PathBuf {
        self.root.join("name-backup.json")
    }

    /// `running.json` (handover to the running instance).
    pub fn running_file(&self) -> PathBuf {
        self.root.join("running.json")
    }

    /// `logs\`.
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    /// `userdata\` – the `BEACON_USERDIR` of this instance in test mode.
    pub fn userdata_dir(&self) -> PathBuf {
        self.root.join("userdata")
    }

    /// Name of the named mutex guarding this data directory.
    pub fn mutex_name(&self) -> String {
        let key = self.root.to_string_lossy().to_lowercase();
        let hash = beacon_proto::blake3::hash(key.as_bytes()).to_hex();
        format!("Local\\BFME-Beacon-{}", hash.get(..24).unwrap_or(""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_layout() {
        let base = std::env::temp_dir().join("beacon-paths");
        let one = DataDirs::with_base(base.clone(), 1).unwrap();
        assert_eq!(one.root(), base.as_path());
        assert_eq!(one.config_file(), base.join("config.json"));
        let two = DataDirs::with_base(base.clone(), 2).unwrap();
        assert_eq!(two.root(), base.join("instance-2").as_path());
        assert_eq!(two.userdata_dir(), base.join("instance-2").join("userdata"));
        assert_ne!(one.mutex_name(), two.mutex_name());
        assert!(one.mutex_name().starts_with("Local\\BFME-Beacon-"));
        assert_eq!(
            DataDirs::with_base(base.clone(), 0),
            Err(PathError::BadInstance(0))
        );
        assert_eq!(
            DataDirs::with_base(base, MAX_INSTANCE + 1),
            Err(PathError::BadInstance(MAX_INSTANCE + 1))
        );
        assert!(matches!(
            DataDirs::resolve(Some(Path::new("relative")), 1),
            Err(PathError::NotAbsolute(_))
        ));
    }
}
