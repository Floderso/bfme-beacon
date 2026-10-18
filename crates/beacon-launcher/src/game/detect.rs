//! Finds the BFME1 installation, identifies `lotrbfme.exe` and resolves the user
//! data directories (spec 04 §4.1, §4.8, §5).
//!
//! * Game folder: the `game_dir` setting, else the registry value `InstallPath` of
//!   `HKLM\SOFTWARE\WOW6432Node\Electronic Arts\EA Games\The Battle for Middle-earth`
//!   (32-bit view; per value HKCU as fallback, like the game).
//! * Exe identity: SHA-256 of `lotrbfme.exe` compared with [`KNOWN_EXES`]; an unknown
//!   exe is allowed with a warning.
//! * User data: preference files (`Options.ini`, `Network.ini`) live in
//!   `%APPDATA%\<UserDataLeafName>` – the **registry** leaf only; without it the game
//!   uses the bare `%APPDATA%` (spec 04 §4.1 pitfall). Maps/replays use the ASCII dir
//!   (`%APPDATA%\<registry leaf or "My Battle for Middle-earth Files">`). User maps
//!   are in `<ASCII dir>\Maps` if `UseLocalUserMaps` = 0, else (also when the value is
//!   missing) in `<install>\UserData\Maps` (spec 04 §4.8).

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::sys::{self, Hive};

/// The game executable.
pub const EXE_NAME: &str = "lotrbfme.exe";
/// Registry key of BFME1 (below `HKLM\SOFTWARE`, 32-bit view, or `HKCU\SOFTWARE`).
pub const REG_KEY: &str = "SOFTWARE\\Electronic Arts\\EA Games\\The Battle for Middle-earth";
/// `UserDataLeafName` default from GameData.ini (`ini.big`, `_patch106.big`).
pub const DEFAULT_LEAF: &str = "My Battle for Middle-earth Files";

/// A known `lotrbfme.exe` build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownExe {
    /// SHA-256 of the file, lowercase hex.
    pub sha256: &'static str,
    /// Display name.
    pub label: &'static str,
}

/// The exe builds Beacon knows (others are allowed with a warning).
pub const KNOWN_EXES: &[KnownExe] = &[KnownExe {
    sha256: "c1a907c44b84df129c1f18dc7365ea25ba438f9b8f39a374b86ed852936ff0a9",
    label: "Vanilla 1.03 (BFME Workshop / All-in-One)",
}];

/// The label of a known exe hash.
pub fn known_exe(sha256_hex: &str) -> Option<&'static str> {
    KNOWN_EXES
        .iter()
        .find(|k| k.sha256.eq_ignore_ascii_case(sha256_hex))
        .map(|k| k.label)
}

/// Source of BFME registry values: HKLM (32-bit view), then per value HKCU.
pub trait Registry {
    /// A string value of the BFME key.
    fn string(&self, value: &str) -> Option<String>;
    /// A DWORD value of the BFME key.
    fn dword(&self, value: &str) -> Option<u32>;
}

/// The real registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRegistry;

impl Registry for SystemRegistry {
    fn string(&self, value: &str) -> Option<String> {
        sys::reg_string(Hive::LocalMachine, REG_KEY, value)
            .or_else(|| sys::reg_string(Hive::CurrentUser, REG_KEY, value))
    }

    fn dword(&self, value: &str) -> Option<u32> {
        sys::reg_dword(Hive::LocalMachine, REG_KEY, value)
            .or_else(|| sys::reg_dword(Hive::CurrentUser, REG_KEY, value))
    }
}

/// Where the game folder came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GameDirSource {
    /// The `game_dir` setting / `--game-dir`.
    Override,
    /// Registry `InstallPath`.
    Registry,
    /// Not found.
    None,
}

/// Identity of `lotrbfme.exe`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExeIdentity {
    /// Full path.
    pub path: PathBuf,
    /// File size.
    pub size: u64,
    /// SHA-256, lowercase hex (`None` if it could not be computed).
    pub sha256: Option<String>,
    /// Label of a known build; `None` = unknown exe (allowed, with a warning).
    pub known: Option<String>,
}

/// The user data directories as the game resolves them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserDirs {
    /// Preference files (`Options.ini`, `Network.ini`).
    pub prefs_dir: PathBuf,
    /// ASCII user dir (maps, replays).
    pub data_dir: PathBuf,
    /// User maps folder.
    pub maps_dir: PathBuf,
    /// The leaf name in use for the ASCII dir.
    pub leaf: String,
    /// `UserDataLeafName` exists in the registry (otherwise prefs are in the bare base dir).
    pub leaf_in_registry: bool,
    /// Maps are in `<install>\UserData\Maps` (`UseLocalUserMaps` ≠ 0 or missing).
    pub use_local_user_maps: bool,
}

/// Resolves the user directories below `base` (`%APPDATA%`, or `BEACON_USERDIR` in
/// test mode) like `GlobalData::parseGameDataDefinition` and `getUserMapDir`.
pub fn resolve_user_dirs(
    base: &Path,
    install: Option<&Path>,
    registry_leaf: Option<&str>,
    use_local_user_maps: Option<u32>,
) -> UserDirs {
    let registry_leaf = registry_leaf.map(str::trim).filter(|l| !l.is_empty());
    let leaf = registry_leaf.unwrap_or(DEFAULT_LEAF).to_owned();
    let prefs_dir = match registry_leaf {
        Some(l) => base.join(l),
        None => base.to_path_buf(),
    };
    let data_dir = base.join(&leaf);
    // Absent value → TRUE (spec 04 §4.8).
    let local = use_local_user_maps.is_none_or(|v| v != 0);
    let maps_dir = match (local, install) {
        (true, Some(dir)) => dir.join("UserData").join("Maps"),
        _ => data_dir.join("Maps"),
    };
    UserDirs {
        prefs_dir,
        data_dir,
        maps_dir,
        leaf,
        leaf_in_registry: registry_leaf.is_some(),
        use_local_user_maps: local,
    }
}

/// Result of the game detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GameInfo {
    /// The game folder, if found.
    pub game_dir: Option<PathBuf>,
    /// Where it came from.
    pub source: GameDirSource,
    /// `lotrbfme.exe`, if present.
    pub exe: Option<ExeIdentity>,
    /// The real user data directories (below `%APPDATA%`).
    pub user: Option<UserDirs>,
    /// Registry `UserDataLeafName` (also needed for test-mode user dirs).
    pub registry_leaf: Option<String>,
    /// Registry `UseLocalUserMaps`.
    pub registry_use_local_user_maps: Option<u32>,
    /// Registry `Language` (`English`, `German`, …).
    pub registry_language: Option<String>,
    /// Human-readable problems.
    pub warnings: Vec<String>,
}

impl GameInfo {
    /// The exe path if the game was found.
    pub fn exe_path(&self) -> Option<PathBuf> {
        self.exe.as_ref().map(|e| e.path.clone())
    }

    /// User directories below another base (test mode: the instance's
    /// `BEACON_USERDIR`).
    pub fn user_dirs_below(&self, base: &Path) -> UserDirs {
        resolve_user_dirs(
            base,
            self.game_dir.as_deref(),
            self.registry_leaf.as_deref(),
            self.registry_use_local_user_maps,
        )
    }
}

/// SHA-256 identity of an exe.
pub fn identify_exe(path: &Path) -> Result<ExeIdentity, std::io::Error> {
    let size = std::fs::metadata(path)?.len();
    let (sha256, known) = match sys::sha256_file(path) {
        Ok(d) => {
            let hex = sys::hex(&d);
            let known = known_exe(&hex).map(str::to_owned);
            (Some(hex), known)
        }
        Err(e) => {
            tracing::warn!("cannot hash {}: {e}", path.display());
            (None, None)
        }
    };
    Ok(ExeIdentity {
        path: path.to_path_buf(),
        size,
        sha256,
        known,
    })
}

/// Detects the game: folder, exe identity and user directories.
pub fn detect(override_dir: Option<&Path>, reg: &dyn Registry, appdata: Option<&Path>) -> GameInfo {
    let mut warnings = Vec::new();
    let (game_dir, source) = match override_dir {
        Some(d) => (Some(d.to_path_buf()), GameDirSource::Override),
        None => match reg.string("InstallPath").map(|p| p.trim().to_owned()) {
            Some(p) if !p.is_empty() => (Some(PathBuf::from(p)), GameDirSource::Registry),
            _ => (None, GameDirSource::None),
        },
    };
    if game_dir.is_none() {
        warnings.push(
            "BFME was not found (no InstallPath in the registry); set the game folder".to_owned(),
        );
    }
    let exe = game_dir.as_ref().and_then(|dir| {
        let path = dir.join(EXE_NAME);
        match identify_exe(&path) {
            Ok(id) => {
                if id.known.is_none() {
                    warnings.push(format!(
                        "unknown {EXE_NAME} (SHA-256 {}); all players need the identical exe",
                        id.sha256.as_deref().unwrap_or("?")
                    ));
                }
                Some(id)
            }
            Err(e) => {
                warnings.push(format!("{} not usable: {e}", path.display()));
                None
            }
        }
    });
    let registry_leaf = reg.string("UserDataLeafName").filter(|l| !l.trim().is_empty());
    let registry_use_local_user_maps = reg.dword("UseLocalUserMaps");
    let registry_language = reg
        .string("Language")
        .map(|l| l.trim().chars().take(32).collect::<String>())
        .filter(|l| !l.is_empty());
    let user = appdata.map(|base| {
        resolve_user_dirs(
            base,
            game_dir.as_deref(),
            registry_leaf.as_deref(),
            registry_use_local_user_maps,
        )
    });
    if game_dir.is_some() && registry_leaf.is_none() {
        warnings.push(
            "registry value UserDataLeafName is missing: BFME keeps Options.ini/Network.ini \
             directly in %APPDATA%"
                .to_owned(),
        );
    }
    if appdata.is_none() {
        warnings.push("%APPDATA% is not set: user data folder unknown".to_owned());
    }
    GameInfo {
        game_dir,
        source,
        exe,
        user,
        registry_leaf,
        registry_use_local_user_maps,
        registry_language,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct FakeRegistry {
        strings: HashMap<&'static str, String>,
        dwords: HashMap<&'static str, u32>,
    }

    impl Registry for FakeRegistry {
        fn string(&self, value: &str) -> Option<String> {
            self.strings.get(value).cloned()
        }
        fn dword(&self, value: &str) -> Option<u32> {
            self.dwords.get(value).copied()
        }
    }

    #[test]
    fn user_dirs_follow_the_registry() {
        let base = Path::new(r"C:\Users\x\AppData\Roaming");
        let install = Path::new(r"C:\BFME1");
        let d = resolve_user_dirs(base, Some(install), Some(DEFAULT_LEAF), Some(0));
        assert_eq!(d.prefs_dir, base.join(DEFAULT_LEAF));
        assert_eq!(d.maps_dir, base.join(DEFAULT_LEAF).join("Maps"));
        assert!(d.leaf_in_registry && !d.use_local_user_maps);
        // Missing leaf: preferences in the bare base, maps with the GameData default.
        let d = resolve_user_dirs(base, Some(install), None, Some(0));
        assert_eq!(d.prefs_dir, base);
        assert_eq!(d.data_dir, base.join(DEFAULT_LEAF));
        assert!(!d.leaf_in_registry);
        // Missing UseLocalUserMaps means TRUE.
        let d = resolve_user_dirs(base, Some(install), Some("Leaf"), None);
        assert_eq!(d.maps_dir, install.join("UserData").join("Maps"));
        assert_eq!(d.prefs_dir, base.join("Leaf"));
        let d = resolve_user_dirs(base, Some(install), Some("  "), Some(1));
        assert_eq!(d.prefs_dir, base);
        assert_eq!(d.maps_dir, install.join("UserData").join("Maps"));
    }

    #[test]
    fn detect_without_install() {
        let reg = FakeRegistry::default();
        let info = detect(None, &reg, Some(Path::new(r"C:\appdata")));
        assert_eq!(info.source, GameDirSource::None);
        assert!(info.game_dir.is_none() && info.exe.is_none());
        assert!(info.warnings.iter().any(|w| w.contains("not found")));
        assert!(info.user.is_some());
    }

    #[cfg(windows)]
    #[test]
    fn detect_with_override_and_unknown_exe() {
        let dir = std::env::temp_dir().join(format!("beacon-detect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(EXE_NAME), b"not the game").unwrap();
        let mut reg = FakeRegistry::default();
        reg.strings.insert("InstallPath", r"C:\ignored".into());
        reg.strings.insert("UserDataLeafName", DEFAULT_LEAF.into());
        reg.dwords.insert("UseLocalUserMaps", 0);
        let info = detect(Some(&dir), &reg, Some(Path::new(r"C:\appdata")));
        assert_eq!(info.source, GameDirSource::Override);
        let exe = info.exe.as_ref().unwrap();
        assert_eq!(exe.size, 12);
        assert_eq!(exe.known, None);
        assert_eq!(exe.sha256.as_deref().map(str::len), Some(64));
        assert!(info.warnings.iter().any(|w| w.contains("unknown")));
        let below = info.user_dirs_below(Path::new(r"D:\inst\userdata"));
        assert_eq!(below.prefs_dir, Path::new(r"D:\inst\userdata").join(DEFAULT_LEAF));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn known_exe_table() {
        assert_eq!(
            known_exe("C1A907C44B84DF129C1F18DC7365EA25BA438F9B8F39A374B86ED852936FF0A9"),
            Some("Vanilla 1.03 (BFME Workshop / All-in-One)")
        );
        assert_eq!(known_exe("00"), None);
    }
}
