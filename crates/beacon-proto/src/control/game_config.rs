//! The lobby's game configuration ("Spielversion / Mod", `docs/dev/mods.md`).
//!
//! The host picks a BFME1 package configuration (for example "Patch 2.22 7.0.5" or
//! "Legends of the 3rd Age 0.5.2 + Patch 1.06") and sends it with
//! `set_game_config`. The server checks it ([`GameConfig::validate`]), stores it and
//! sends `game_config` to every player; `null` means "vanilla": everybody plays
//! with their current installation, as before.
//!
//! A configuration carries the **expected file set** of the instance folder: every
//! file the BFME Workshop launcher would put into the game folder (or, for type-1
//! mods, into the `-mod` folder) for this package, its dependencies, the base game
//! and the chosen language variant, as `(path, MD5, size)`. Clients prepare and
//! verify exactly this set without fetching any manifest. [`GameConfig::id`] is a
//! digest of the set (see [`GameConfig::compute_id`]); it names the instance
//! folder and identifies readiness reports.
//!
//! Every player reports its readiness for the current configuration in `status`
//! ([`ConfigStatus`]); the lobby shows it per player and the server refuses
//! `launch_all` until everybody is ready.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::path::is_safe_package_path;

/// Feature name the server announces in `welcome.features` when it understands
/// `set_game_config`, `game_config` and readiness reports.
pub const FEATURE_GAME_CONFIG: &str = "game_config";
/// [`ConfigStatus::id`] of the vanilla configuration (no instance folder).
pub const VANILLA_CONFIG_ID: &str = "vanilla";
/// Length of [`GameConfig::id`] in hex digits (128 bits).
pub const CONFIG_ID_LEN: usize = 32;
/// Most files in one configuration. The base game plus Patch 1.06 has 352; 512
/// entries with typical paths still fit into one control message.
pub const MAX_CONFIG_FILES: usize = 512;
/// Most packages in [`GameConfig::layers`].
pub const MAX_CONFIG_LAYERS: usize = 16;
/// Largest single file (Shadow and Flame's archive is 1.75 GB).
pub const MAX_CONFIG_FILE_SIZE: u64 = 4 << 30;
/// Largest sum of all file sizes.
pub const MAX_CONFIG_TOTAL_SIZE: u64 = 64 << 30;
/// Longest display text (name, author) in characters.
pub const MAX_CONFIG_TEXT_CHARS: usize = 100;
/// Longest package guid.
pub const MAX_GUID_LEN: usize = 64;
/// Longest package version.
pub const MAX_VERSION_LEN: usize = 40;
/// Longest [`ConfigStatus::text`] in characters.
pub const MAX_STATUS_TEXT_CHARS: usize = 200;
/// File name reserved at the top of the game folder: Beacon's hook DLL.
pub const RESERVED_HOOK_NAME: &str = "wsock32.dll";
/// BLAKE3 key-derivation context of [`GameConfig::compute_id`].
pub const ID_CONTEXT: &str = "BFME Beacon 2026-10-18 game configuration v1";

/// Which folder of the instance a file belongs to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileDir {
    /// The game folder (`instances\<id>\game\`): patches, enhancements, the base game.
    #[default]
    Game,
    /// The `-mod` folder (`instances\<id>\mod\`) of a type-1 package.
    Mod,
}

impl FileDir {
    /// `true` for [`FileDir::Game`] (the default, left out of the JSON).
    pub fn is_game(&self) -> bool {
        *self == Self::Game
    }
}

/// One file of a configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConfigFile {
    /// Path below the folder, normalised with
    /// [`normalize_package_path`](super::normalize_package_path): lower case, `\`.
    pub path: String,
    /// MD5 of the content, 32 lowercase hex digits.
    pub md5: String,
    /// Size in bytes; `0` = unknown (the workshop's sizes are not reliable).
    pub size: u64,
    /// Target folder (omitted for the game folder).
    #[serde(default, skip_serializing_if = "FileDir::is_game")]
    pub dir: FileDir,
}

/// One package of the configuration, for attribution and manifest lookups.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PackageRef {
    /// Workshop guid (`official-0`, `original-BFME1` or a UUID).
    pub guid: String,
    /// Exact version.
    pub version: String,
    /// Display name.
    pub name: String,
    /// Author as published.
    #[serde(default)]
    pub author: String,
    /// Workshop type: 0 patch, 1 mod, 2 enhancement.
    #[serde(default)]
    pub kind: u8,
}

/// The lobby's game configuration (`set_game_config` / `game_config`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameConfig {
    /// [`compute_id`](Self::compute_id) of the file set, 32 lowercase hex digits.
    pub id: String,
    /// Guid of the selected package.
    pub guid: String,
    /// Version of the selected package.
    pub version: String,
    /// Display name (e.g. "Legends of the 3rd Age").
    pub name: String,
    /// Author of the selected package.
    #[serde(default)]
    pub author: String,
    /// Language variant (`EN`, `DE`, …) the file set was resolved for.
    pub language: String,
    /// Every package of the configuration, highest priority first (enhancements,
    /// the package, its dependencies, the base game).
    #[serde(default)]
    pub layers: Vec<PackageRef>,
    /// The expected file set, sorted by `(dir, path)`.
    pub files: Vec<ConfigFile>,
}

/// Why a configuration was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// No files.
    Empty,
    /// More than [`MAX_CONFIG_FILES`] files.
    TooManyFiles(usize),
    /// More than [`MAX_CONFIG_LAYERS`] packages.
    TooManyLayers(usize),
    /// A path that is not a normalised safe package path.
    BadPath(String),
    /// A path that appears twice in the same folder.
    DuplicatePath(String),
    /// A path Beacon reserves (its hook DLL).
    ReservedPath(String),
    /// A malformed MD5.
    BadMd5(String),
    /// A file larger than [`MAX_CONFIG_FILE_SIZE`].
    FileTooLarge(String),
    /// The files add up to more than [`MAX_CONFIG_TOTAL_SIZE`].
    TooLarge(u64),
    /// A display text that is empty where required, too long or has control
    /// characters (the field name).
    BadText(&'static str),
    /// A malformed guid.
    BadGuid(String),
    /// A malformed version.
    BadVersion(String),
    /// A malformed language code.
    BadLanguage(String),
    /// The id does not match the file set.
    BadId,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the configuration has no files"),
            Self::TooManyFiles(n) => write!(f, "too many files ({n} > {MAX_CONFIG_FILES})"),
            Self::TooManyLayers(n) => write!(f, "too many packages ({n} > {MAX_CONFIG_LAYERS})"),
            Self::BadPath(p) => write!(f, "invalid file path {p:?}"),
            Self::DuplicatePath(p) => write!(f, "duplicate file path {p:?}"),
            Self::ReservedPath(p) => write!(f, "reserved file path {p:?}"),
            Self::BadMd5(p) => write!(f, "invalid MD5 for {p:?}"),
            Self::FileTooLarge(p) => write!(f, "file too large: {p:?}"),
            Self::TooLarge(n) => write!(f, "the files are too large in total ({n} bytes)"),
            Self::BadText(field) => write!(f, "invalid text in {field}"),
            Self::BadGuid(g) => write!(f, "invalid package guid {g:?}"),
            Self::BadVersion(v) => write!(f, "invalid package version {v:?}"),
            Self::BadLanguage(l) => write!(f, "invalid language code {l:?}"),
            Self::BadId => f.write_str("the configuration id does not match its files"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// `true` for 32 lowercase hex digits.
pub fn is_md5_hex(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `true` for a workshop guid: 1–64 of `A-Z a-z 0-9 -`.
pub fn is_valid_guid(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_GUID_LEN
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// `true` for a package version: 1–40 of `A-Z a-z 0-9 . _ + -`.
pub fn is_valid_version(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_VERSION_LEN
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// `true` for a language code as the workshop uses them: `ALL` or 2–3 capital
/// letters (`EN`, `DE`, …).
pub fn is_valid_language(text: &str) -> bool {
    (2..=3).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_uppercase())
}

fn is_valid_text(text: &str, required: bool) -> bool {
    (!required || !text.trim().is_empty())
        && text.chars().count() <= MAX_CONFIG_TEXT_CHARS
        && !text.chars().any(char::is_control)
}

/// `true` for a [`GameConfig::id`] (32 lowercase hex digits).
pub fn is_valid_config_id(text: &str) -> bool {
    is_md5_hex(text)
}

impl GameConfig {
    /// The digest that names this configuration: BLAKE3 in key-derivation mode
    /// with [`ID_CONTEXT`] over the files sorted by `(dir, path)`, each as
    /// `dir byte ('g' or 'm') ‖ path ‖ 0x00 ‖ md5 ‖ 0x0A`; the first
    /// [`CONFIG_ID_LEN`] hex digits. Sizes, names and the language are not part of
    /// it: the same files make the same instance.
    pub fn compute_id(&self) -> String {
        let mut files: Vec<&ConfigFile> = self.files.iter().collect();
        files.sort_by(|a, b| (a.dir, &a.path).cmp(&(b.dir, &b.path)));
        let mut hasher = blake3::Hasher::new_derive_key(ID_CONTEXT);
        for f in files {
            hasher.update(match f.dir {
                FileDir::Game => b"g",
                FileDir::Mod => b"m",
            });
            hasher.update(f.path.as_bytes());
            hasher.update(&[0]);
            hasher.update(f.md5.as_bytes());
            hasher.update(b"\n");
        }
        let hex = hasher.finalize().to_hex();
        hex.get(..CONFIG_ID_LEN).unwrap_or_default().to_owned()
    }

    /// Sorts the files by `(dir, path)`, sets [`id`](Self::id) and validates.
    pub fn finalize(mut self) -> Result<Self, ConfigError> {
        self.files.sort_by(|a, b| (a.dir, &a.path).cmp(&(b.dir, &b.path)));
        self.id = self.compute_id();
        self.validate()?;
        Ok(self)
    }

    /// Checks every bound and rule (what the server enforces before it accepts a
    /// configuration, and what clients check before they touch the disk).
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.files.is_empty() {
            return Err(ConfigError::Empty);
        }
        if self.files.len() > MAX_CONFIG_FILES {
            return Err(ConfigError::TooManyFiles(self.files.len()));
        }
        if self.layers.len() > MAX_CONFIG_LAYERS {
            return Err(ConfigError::TooManyLayers(self.layers.len()));
        }
        if !is_valid_guid(&self.guid) {
            return Err(ConfigError::BadGuid(self.guid.clone()));
        }
        if !is_valid_version(&self.version) {
            return Err(ConfigError::BadVersion(self.version.clone()));
        }
        if !is_valid_text(&self.name, true) {
            return Err(ConfigError::BadText("name"));
        }
        if !is_valid_text(&self.author, false) {
            return Err(ConfigError::BadText("author"));
        }
        if !is_valid_language(&self.language) {
            return Err(ConfigError::BadLanguage(self.language.clone()));
        }
        for layer in &self.layers {
            if !is_valid_guid(&layer.guid) {
                return Err(ConfigError::BadGuid(layer.guid.clone()));
            }
            if !is_valid_version(&layer.version) {
                return Err(ConfigError::BadVersion(layer.version.clone()));
            }
            if !is_valid_text(&layer.name, true) {
                return Err(ConfigError::BadText("layers.name"));
            }
            if !is_valid_text(&layer.author, false) {
                return Err(ConfigError::BadText("layers.author"));
            }
        }
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        for f in &self.files {
            let canonical = f.path.replace('/', "\\").to_lowercase();
            if canonical != f.path || !is_safe_package_path(&f.path) {
                return Err(ConfigError::BadPath(f.path.clone()));
            }
            if f.dir == FileDir::Game && f.path == RESERVED_HOOK_NAME {
                return Err(ConfigError::ReservedPath(f.path.clone()));
            }
            if !seen.insert((f.dir, f.path.as_str())) {
                return Err(ConfigError::DuplicatePath(f.path.clone()));
            }
            if !is_md5_hex(&f.md5) {
                return Err(ConfigError::BadMd5(f.path.clone()));
            }
            if f.size > MAX_CONFIG_FILE_SIZE {
                return Err(ConfigError::FileTooLarge(f.path.clone()));
            }
            total = total.saturating_add(f.size);
        }
        // A file that is also a folder of another entry ("a" and "a\b") cannot exist.
        for (dir, path) in &seen {
            let mut prefix = String::new();
            for component in path.split('\\') {
                if !prefix.is_empty() && seen.contains(&(*dir, prefix.as_str())) {
                    return Err(ConfigError::DuplicatePath(path.to_string()));
                }
                if !prefix.is_empty() {
                    prefix.push('\\');
                }
                prefix.push_str(component);
            }
        }
        if total > MAX_CONFIG_TOTAL_SIZE {
            return Err(ConfigError::TooLarge(total));
        }
        if !is_valid_config_id(&self.id) || self.id != self.compute_id() {
            return Err(ConfigError::BadId);
        }
        Ok(())
    }

    /// Sum of the known file sizes.
    pub fn total_size(&self) -> u64 {
        self.files.iter().fold(0u64, |acc, f| acc.saturating_add(f.size))
    }

    /// `true` if some files belong to a `-mod` folder (type-1 package).
    pub fn has_mod_dir(&self) -> bool {
        self.files.iter().any(|f| f.dir == FileDir::Mod)
    }
}

/// Readiness of one player for a configuration (inside `status` and `lobby`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigState {
    /// The instance is complete and verified (or vanilla).
    Ready,
    /// Files are being checked, imported, downloaded or linked.
    Preparing,
    /// Files are missing and cannot be obtained automatically.
    Missing,
    /// Preparing failed.
    Error,
    /// A state this version does not know.
    #[serde(other)]
    Unknown,
}

/// A player's readiness report: `{"id":…, "state":…, "progress"?, "missing"?, "text"?}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConfigStatus {
    /// The configuration this report is about: a [`GameConfig::id`] or
    /// [`VANILLA_CONFIG_ID`].
    pub id: String,
    /// State.
    pub state: ConfigState,
    /// Progress in percent while preparing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<u8>,
    /// Number of missing files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<u32>,
    /// Short detail (error text, first missing files), at most
    /// [`MAX_STATUS_TEXT_CHARS`] characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

impl ConfigStatus {
    /// Ready for `id`.
    pub fn ready(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            state: ConfigState::Ready,
            progress: None,
            missing: None,
            text: None,
        }
    }

    /// The vanilla report (always ready).
    pub fn vanilla() -> Self {
        Self::ready(VANILLA_CONFIG_ID)
    }

    /// `true` if this report says "ready for `id`".
    pub fn is_ready_for(&self, id: &str) -> bool {
        self.state == ConfigState::Ready && self.id == id
    }

    /// The report with its bounds enforced (for the server): `None` if the id is
    /// malformed; progress is capped at 100; the text loses control characters and
    /// is cut to [`MAX_STATUS_TEXT_CHARS`].
    pub fn sanitized(self) -> Option<Self> {
        if self.id != VANILLA_CONFIG_ID && !is_valid_config_id(&self.id) {
            return None;
        }
        let text = self
            .text
            .map(|t| {
                t.chars()
                    .map(|c| if c.is_control() { ' ' } else { c })
                    .take(MAX_STATUS_TEXT_CHARS)
                    .collect::<String>()
                    .trim()
                    .to_owned()
            })
            .filter(|t| !t.is_empty());
        Some(Self {
            id: self.id,
            state: self.state,
            progress: self.progress.map(|p| p.min(100)),
            missing: self.missing,
            text,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> GameConfig {
        GameConfig {
            id: String::new(),
            guid: "00a88275-5bbd-4147-9644-b3d9731f3692".into(),
            version: "0.5.2".into(),
            name: "Legends of the 3rd Age".into(),
            author: "pallando".into(),
            language: "EN".into(),
            layers: vec![PackageRef {
                guid: "4ae751aa-2df4-4bfd-8ba0-1d21c3d80152".into(),
                version: "1.0.0".into(),
                name: "Patch 1.06".into(),
                author: "The 1.06 Team".into(),
                kind: 0,
            }],
            files: vec![
                ConfigFile {
                    path: "lotrbfme.exe".into(),
                    md5: "0".repeat(32),
                    size: 10,
                    dir: FileDir::Game,
                },
                ConfigFile {
                    path: "_zlot3a_data.big".into(),
                    md5: "a".repeat(32),
                    size: 20,
                    dir: FileDir::Game,
                },
                ConfigFile {
                    path: "data\\movies\\intro.vp6".into(),
                    md5: "b".repeat(32),
                    size: 0,
                    dir: FileDir::Game,
                },
            ],
        }
    }

    #[test]
    fn finalize_sorts_and_names() {
        let c = sample().finalize().unwrap();
        assert_eq!(c.id.len(), CONFIG_ID_LEN);
        assert!(is_valid_config_id(&c.id));
        let paths: Vec<&str> = c.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["_zlot3a_data.big", "data\\movies\\intro.vp6", "lotrbfme.exe"]);
        assert_eq!(c.total_size(), 30);
        assert!(!c.has_mod_dir());
        // Names, sizes, language and order do not change the id; content does.
        let mut renamed = sample();
        renamed.name = "Other".into();
        renamed.language = "DE".into();
        renamed.files.reverse();
        if let Some(f) = renamed.files.first_mut() {
            f.size = 99;
        }
        assert_eq!(renamed.finalize().unwrap().id, c.id);
        let mut changed = sample();
        if let Some(f) = changed.files.first_mut() {
            f.md5 = "c".repeat(32);
        }
        assert_ne!(changed.finalize().unwrap().id, c.id);
        let mut moved = sample();
        if let Some(f) = moved.files.first_mut() {
            f.dir = FileDir::Mod;
        }
        let moved = moved.finalize().unwrap();
        assert_ne!(moved.id, c.id);
        assert!(moved.has_mod_dir());
    }

    #[test]
    fn validation_rules() {
        let ok = sample().finalize().unwrap();
        assert_eq!(ok.validate(), Ok(()));
        let check = |f: &dyn Fn(&mut GameConfig)| {
            let mut c = sample();
            f(&mut c);
            c.files.sort_by(|a, b| (a.dir, &a.path).cmp(&(b.dir, &b.path)));
            c.id = c.compute_id();
            c.validate()
        };
        assert_eq!(check(&|c| c.files.clear()), Err(ConfigError::Empty));
        assert!(matches!(check(&|c| c.files[0].path = "..\\x.big".into()), Err(ConfigError::BadPath(_))));
        assert!(matches!(check(&|c| c.files[0].path = "Upper.big".into()), Err(ConfigError::BadPath(_))));
        assert!(matches!(check(&|c| c.files[0].path = "a/b.big".into()), Err(ConfigError::BadPath(_))));
        assert!(matches!(check(&|c| c.files[0].path = "c:\\x.big".into()), Err(ConfigError::BadPath(_))));
        assert!(matches!(check(&|c| c.files[0].path = "wsock32.dll".into()), Err(ConfigError::ReservedPath(_))));
        assert_eq!(
            check(&|c| {
                c.files[0].path = "wsock32.dll".into();
                c.files[0].dir = FileDir::Mod;
            }),
            Ok(()),
            "only the game folder's hook name is reserved"
        );
        assert!(matches!(
            check(&|c| c.files[1].path = c.files[0].path.clone()),
            Err(ConfigError::DuplicatePath(_))
        ));
        assert!(matches!(
            check(&|c| {
                c.files[0].path = "data".into();
                c.files[1].path = "data\\x.big".into();
            }),
            Err(ConfigError::DuplicatePath(_))
        ));
        assert!(matches!(check(&|c| c.files[0].md5 = "A".repeat(32)), Err(ConfigError::BadMd5(_))));
        assert!(matches!(check(&|c| c.files[0].md5 = "a".repeat(31)), Err(ConfigError::BadMd5(_))));
        assert!(matches!(
            check(&|c| c.files[0].size = MAX_CONFIG_FILE_SIZE + 1),
            Err(ConfigError::FileTooLarge(_))
        ));
        assert!(matches!(check(&|c| c.guid = "a b".into()), Err(ConfigError::BadGuid(_))));
        assert!(matches!(check(&|c| c.version = String::new()), Err(ConfigError::BadVersion(_))));
        assert!(matches!(check(&|c| c.language = "english".into()), Err(ConfigError::BadLanguage(_))));
        assert_eq!(check(&|c| c.name = " ".into()), Err(ConfigError::BadText("name")));
        assert_eq!(check(&|c| c.author = "a\nb".into()), Err(ConfigError::BadText("author")));
        assert_eq!(check(&|c| c.name = "x".repeat(101)), Err(ConfigError::BadText("name")));
        assert!(matches!(
            check(&|c| c.layers[0].guid = "../x".into()),
            Err(ConfigError::BadGuid(_))
        ));
        assert!(matches!(
            check(&|c| c.layers = vec![c.layers[0].clone(); MAX_CONFIG_LAYERS + 1]),
            Err(ConfigError::TooManyLayers(_))
        ));
        assert!(matches!(
            check(&|c| {
                let f = c.files[0].clone();
                c.files = (0..=MAX_CONFIG_FILES)
                    .map(|i| ConfigFile {
                        path: format!("f{i}.big"),
                        ..f.clone()
                    })
                    .collect();
            }),
            Err(ConfigError::TooManyFiles(_))
        ));
        assert!(matches!(
            check(&|c| {
                for f in &mut c.files {
                    f.size = MAX_CONFIG_FILE_SIZE;
                }
                let f = c.files[0].clone();
                for i in 0..20 {
                    c.files.push(ConfigFile {
                        path: format!("x{i}.big"),
                        ..f.clone()
                    });
                }
            }),
            Err(ConfigError::TooLarge(_))
        ));
        let mut wrong_id = ok.clone();
        wrong_id.id = "f".repeat(32);
        assert_eq!(wrong_id.validate(), Err(ConfigError::BadId));
        assert!(ConfigError::BadPath("x".into()).to_string().contains("\"x\""));
    }

    #[test]
    fn text_rules() {
        assert!(is_valid_guid("official-0") && is_valid_guid("original-BFME1"));
        assert!(!is_valid_guid("") && !is_valid_guid("a:b") && !is_valid_guid(&"a".repeat(65)));
        assert!(is_valid_version("2.1.0.0.0") && is_valid_version("7.0.5"));
        assert!(!is_valid_version("1 0") && !is_valid_version("1/0"));
        assert!(is_valid_language("EN") && is_valid_language("ALL"));
        assert!(!is_valid_language("en") && !is_valid_language("E") && !is_valid_language("ENGL"));
        assert!(is_md5_hex("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(!is_md5_hex("D41D8CD98F00B204E9800998ECF8427E"));
    }

    #[test]
    fn status_sanitizing() {
        let s = ConfigStatus {
            id: "a".repeat(32),
            state: ConfigState::Preparing,
            progress: Some(250),
            missing: None,
            text: Some(format!("  bad\ntext{}", "x".repeat(500))),
        }
        .sanitized()
        .unwrap();
        assert_eq!(s.progress, Some(100));
        let text = s.text.unwrap();
        assert!(text.starts_with("bad text"));
        assert_eq!(text.chars().count(), MAX_STATUS_TEXT_CHARS - 2);
        assert!(ConfigStatus::vanilla().sanitized().is_some());
        assert!(ConfigStatus::ready("../../x").sanitized().is_none());
        let empty_text = ConfigStatus {
            text: Some(" \n ".into()),
            ..ConfigStatus::vanilla()
        };
        assert_eq!(empty_text.sanitized().unwrap().text, None);
        assert!(ConfigStatus::ready("x").is_ready_for("x"));
        assert!(!ConfigStatus::ready("x").is_ready_for("y"));
    }
}
