//! BFME Workshop manifests (`BfmeWorkshopEntry`, spec 10 §2.3) as the AIO stores
//! them in `%APPDATA%\BFME Workshop\Library\<guid>.json` and as the workshop API
//! returns them. Parsing is lenient about fields Beacon does not use and strict
//! about everything that reaches the disk: guids, versions, file names (normalised
//! safe package paths), MD5s and sizes are checked; anything else makes the
//! manifest unusable.

use std::fmt;

use beacon_proto::control::{
    is_md5_hex, is_valid_guid, is_valid_language, is_valid_version, normalize_package_path,
    MAX_CONFIG_FILE_SIZE, MAX_CONFIG_TEXT_CHARS,
};
use serde::{Deserialize, Deserializer, Serialize};

/// Largest manifest accepted (the base game's has 376 files, about 160 KB).
pub const MAX_MANIFEST_BYTES: u64 = 8 << 20;
/// Most files in one manifest.
pub const MAX_MANIFEST_FILES: usize = 4096;
/// Most dependencies of one package.
pub const MAX_DEPENDENCIES: usize = 32;
/// Most social links kept.
pub const MAX_SOCIAL_LINKS: usize = 8;

/// The workshop's package type (spec 10 §2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageKind {
    /// 0: installed into the game folder.
    Patch,
    /// 1: installed into a separate folder, started with `-mod`.
    Mod,
    /// 2: installed into the game folder on top of a patch it depends on.
    Enhancement,
    /// 3: maps for `%APPDATA%\…\Maps\Workshop` (not supported by Beacon).
    MapPack,
    /// 4: a local snapshot (not supported by Beacon).
    Snapshot,
    /// Any other value.
    Other,
}

impl PackageKind {
    /// The kind of the workshop's `Type` number.
    pub fn from_number(n: i64) -> Self {
        match n {
            0 => Self::Patch,
            1 => Self::Mod,
            2 => Self::Enhancement,
            3 => Self::MapPack,
            4 => Self::Snapshot,
            _ => Self::Other,
        }
    }

    /// The workshop's number (`GameConfig` layers carry it).
    pub fn number(self) -> u8 {
        match self {
            Self::Patch => 0,
            Self::Mod => 1,
            Self::Enhancement => 2,
            Self::MapPack => 3,
            Self::Snapshot => 4,
            Self::Other => 255,
        }
    }
}

/// The languages a file is installed for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "codes")]
pub enum FileLanguages {
    /// `ALL` or empty: every language.
    All,
    /// Only these codes (`EN`, `DE`, …).
    Only(Vec<String>),
}

impl FileLanguages {
    /// Parses the workshop's `Language` text (`ALL`, empty or `EN DE …`). Invalid
    /// codes are dropped; a list without valid codes means "never".
    pub fn parse(text: &str) -> Self {
        let text = text.trim();
        if text.is_empty() || text.eq_ignore_ascii_case("all") {
            return Self::All;
        }
        let codes = text
            .split_whitespace()
            .map(str::to_ascii_uppercase)
            .filter(|c| is_valid_language(c) && c != "ALL")
            .collect();
        Self::Only(codes)
    }

    /// The AIO's filter: `ALL`/empty, or the list contains `language`.
    pub fn includes(&self, language: &str) -> bool {
        match self {
            Self::All => true,
            Self::Only(codes) => codes.iter().any(|c| c.eq_ignore_ascii_case(language)),
        }
    }
}

/// One file of a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageFile {
    /// The name as published (`apt\AptLevel0.big`).
    pub name: String,
    /// The normalised destination path (`apt\aptlevel0.big`).
    pub path: String,
    /// MD5, lowercase hex.
    pub md5: String,
    /// Size as published; `0` = unknown (the workshop's sizes are unreliable).
    pub size: u64,
    /// Languages.
    pub languages: FileLanguages,
    /// Download URL as published (checked again before any download).
    pub url: Option<String>,
}

/// A dependency: `guid` or `guid:version`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct DependencyRef {
    /// Guid.
    pub guid: String,
    /// Pinned version, if any.
    pub version: Option<String>,
}

impl DependencyRef {
    /// Parses `guid` or `guid:version`.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let (guid, version) = match text.split_once(':') {
            Some((g, v)) => (g, Some(v)),
            None => (text, None),
        };
        if !is_valid_guid(guid) || version.is_some_and(|v| !is_valid_version(v)) {
            return None;
        }
        Some(Self {
            guid: guid.to_owned(),
            version: version.map(str::to_owned),
        })
    }
}

impl fmt::Display for DependencyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.version {
            Some(v) => write!(f, "{}:{v}", self.guid),
            None => f.write_str(&self.guid),
        }
    }
}

/// A checked manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Package {
    /// Guid.
    pub guid: String,
    /// Display name (control characters removed, at most 100 characters).
    pub name: String,
    /// Version.
    pub version: String,
    /// Author (cleaned like the name).
    pub author: String,
    /// Owner account uuid (the CDN prefix of its files).
    pub owner: String,
    /// Game: 0 BFME1, 1 BFME2, 2 RotWK.
    pub game: i64,
    /// Type.
    pub kind: PackageKind,
    /// The package's language list as published.
    pub language: String,
    /// Files.
    pub files: Vec<PackageFile>,
    /// Dependencies.
    pub dependencies: Vec<DependencyRef>,
    /// `https://` links from `SocialLinks`.
    pub social_links: Vec<String>,
    /// Publication time of this version (Unix ms).
    pub creation_time: Option<i64>,
}

/// Why a manifest is unusable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// Larger than [`MAX_MANIFEST_BYTES`].
    TooLarge,
    /// Not valid JSON or not a manifest.
    Json(String),
    /// A malformed guid or version.
    BadIdentity(String),
    /// Too many files or dependencies.
    TooMany(&'static str),
    /// A file with an unsafe name, a bad MD5 or an absurd size.
    BadFile(String),
    /// A malformed dependency.
    BadDependency(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("manifest too large"),
            Self::Json(e) => write!(f, "not a workshop manifest: {e}"),
            Self::BadIdentity(t) => write!(f, "invalid guid or version: {t}"),
            Self::TooMany(what) => write!(f, "too many {what}"),
            Self::BadFile(t) => write!(f, "invalid file entry: {t}"),
            Self::BadDependency(t) => write!(f, "invalid dependency {t:?}"),
        }
    }
}

impl std::error::Error for ManifestError {}

fn null_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawManifest {
    guid: String,
    name: String,
    version: String,
    #[serde(default, deserialize_with = "null_default")]
    author: String,
    #[serde(default, deserialize_with = "null_default")]
    owner: String,
    #[serde(default, deserialize_with = "null_default")]
    game: i64,
    #[serde(default, rename = "Type", deserialize_with = "null_default")]
    kind: i64,
    #[serde(default, deserialize_with = "null_default")]
    language: String,
    #[serde(default, deserialize_with = "null_default")]
    files: Vec<RawFile>,
    #[serde(default, deserialize_with = "null_default")]
    dependencies: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    social_links: Vec<serde_json::Value>,
    #[serde(default)]
    creation_time: Option<i64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawFile {
    #[serde(default, deserialize_with = "null_default")]
    name: String,
    #[serde(default, deserialize_with = "null_default")]
    url: String,
    #[serde(default, deserialize_with = "null_default")]
    md5: String,
    #[serde(default, deserialize_with = "null_default")]
    language: String,
    #[serde(default, deserialize_with = "null_default")]
    size: i64,
}

/// Display text: control characters removed, trimmed, at most 100 characters.
pub fn clean_text(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(MAX_CONFIG_TEXT_CHARS)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Parses and checks a manifest (UTF-8 JSON, with or without a byte-order mark).
pub fn parse_manifest(bytes: &[u8]) -> Result<Package, ManifestError> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_MANIFEST_BYTES {
        return Err(ManifestError::TooLarge);
    }
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let raw: RawManifest = serde_json::from_slice(bytes).map_err(|e| ManifestError::Json(e.to_string()))?;
    if !is_valid_guid(&raw.guid) || !is_valid_version(&raw.version) {
        return Err(ManifestError::BadIdentity(format!(
            "{:?} {:?}",
            raw.guid.chars().take(80).collect::<String>(),
            raw.version.chars().take(80).collect::<String>()
        )));
    }
    if raw.files.len() > MAX_MANIFEST_FILES {
        return Err(ManifestError::TooMany("files"));
    }
    if raw.dependencies.len() > MAX_DEPENDENCIES {
        return Err(ManifestError::TooMany("dependencies"));
    }
    let mut files = Vec::with_capacity(raw.files.len());
    for f in raw.files {
        let shown = f.name.chars().take(80).collect::<String>();
        let path = normalize_package_path(&f.name).ok_or_else(|| ManifestError::BadFile(shown.clone()))?;
        let md5 = f.md5.trim().to_ascii_lowercase();
        if !is_md5_hex(&md5) {
            return Err(ManifestError::BadFile(format!("{shown}: MD5")));
        }
        let size = u64::try_from(f.size).unwrap_or(0);
        if size > MAX_CONFIG_FILE_SIZE {
            return Err(ManifestError::BadFile(format!("{shown}: size")));
        }
        files.push(PackageFile {
            name: f.name,
            path,
            md5,
            size,
            languages: FileLanguages::parse(&f.language),
            url: Some(f.url).filter(|u| !u.is_empty() && u.len() <= 512),
        });
    }
    let dependencies = raw
        .dependencies
        .iter()
        .map(|d| DependencyRef::parse(d).ok_or_else(|| ManifestError::BadDependency(d.chars().take(80).collect())))
        .collect::<Result<Vec<_>, _>>()?;
    let social_links = raw
        .social_links
        .iter()
        .filter_map(|v| v.as_str())
        .filter(|s| s.starts_with("https://") && s.len() <= 300 && !s.chars().any(|c| c.is_control() || c == ' '))
        .take(MAX_SOCIAL_LINKS)
        .map(str::to_owned)
        .collect();
    let name = clean_text(&raw.name);
    Ok(Package {
        name: if name.is_empty() { raw.guid.clone() } else { name },
        guid: raw.guid,
        version: raw.version,
        author: clean_text(&raw.author),
        owner: raw.owner.chars().take(64).collect(),
        game: raw.game,
        kind: PackageKind::from_number(raw.kind),
        language: clean_text(&raw.language),
        files,
        dependencies,
        social_links,
        creation_time: raw.creation_time,
    })
}

impl Package {
    /// `guid@version`, the catalog key.
    pub fn key(&self) -> String {
        format!("{}@{}", self.guid, self.version)
    }

    /// `true` for the base-game packages (`original-…`).
    pub fn is_base(&self) -> bool {
        self.guid.starts_with(crate::mods::BASE_GUID_PREFIX)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A synthetic manifest shaped like the real ones (no real data).
    pub(crate) fn manifest_json(guid: &str, name: &str, version: &str, kind: i64, files: &[(&str, &str, i64, &str)], deps: &[&str]) -> String {
        let files: Vec<serde_json::Value> = files
            .iter()
            .map(|(n, md5, size, lang)| {
                serde_json::json!({
                    "Guid": md5, "Name": n,
                    "Url": format!("https://workshop-files.bfmeladder.com/11111111-2222-3333-4444-555555555555/{md5}"),
                    "Md5": md5, "Language": lang, "Size": size
                })
            })
            .collect();
        serde_json::json!({
            "Guid": guid, "Name": name, "Version": version,
            "Description": "synthetic", "Changelog": "", "SocialLinks": ["https://example.org/x", "javascript:alert(1)"],
            "Language": "EN", "ArtworkUrl": "", "ScreenshotUrls": [],
            "Author": "Tester\u{0007}", "Owner": "11111111-2222-3333-4444-555555555555",
            "Game": 0, "Type": kind, "CreationTime": 1745263725377i64,
            "Files": files, "Maps": [{"Id": "x", "Name": "Map", "Game": 0, "Preview": "", "Width": 1.5, "Height": 2.0, "Spots": []}],
            "Factions": [{"Name": "Rohan", "Id": 3}], "Colors": null, "Dependencies": deps, "Visibility": null
        })
        .to_string()
    }

    #[test]
    fn parses_a_manifest() {
        let json = manifest_json(
            "4ae751aa-2df4-4bfd-8ba0-1d21c3d80152",
            "Patch X",
            "1.0.0",
            0,
            &[
                ("_patchX.big", &"a".repeat(32), 100, "ALL"),
                ("apt\\AptLevel0.big", &"B".repeat(32), -5, "DE FR"),
                ("_german.big", &"c".repeat(32), 0, "DE"),
            ],
            &["official-0:7.0.4", "original-BFME1"],
        );
        let mut bytes = b"\xef\xbb\xbf".to_vec();
        bytes.extend_from_slice(json.as_bytes());
        let p = parse_manifest(&bytes).unwrap();
        assert_eq!(p.key(), "4ae751aa-2df4-4bfd-8ba0-1d21c3d80152@1.0.0");
        assert_eq!(p.kind, PackageKind::Patch);
        assert_eq!(p.author, "Tester");
        assert_eq!(p.files[1].path, "apt\\aptlevel0.big");
        assert_eq!(p.files[1].md5, "b".repeat(32));
        assert_eq!(p.files[1].size, 0, "negative sizes are unknown");
        assert!(p.files[1].languages.includes("de") && !p.files[1].languages.includes("EN"));
        assert!(p.files[0].languages.includes("EN"));
        assert_eq!(
            p.dependencies,
            [
                DependencyRef { guid: "official-0".into(), version: Some("7.0.4".into()) },
                DependencyRef { guid: "original-BFME1".into(), version: None },
            ]
        );
        assert_eq!(p.social_links, ["https://example.org/x"]);
        assert!(!p.is_base());
    }

    #[test]
    fn rejects_unsafe_manifests() {
        let bad = |files: &[(&str, &str, i64, &str)], deps: &[&str]| {
            parse_manifest(manifest_json("g-1", "N", "1.0", 0, files, deps).as_bytes())
        };
        let md5 = "a".repeat(32);
        assert!(matches!(bad(&[("..\\evil.big", &md5, 1, "ALL")], &[]), Err(ManifestError::BadFile(_))));
        assert!(matches!(bad(&[("C:\\evil.big", &md5, 1, "ALL")], &[]), Err(ManifestError::BadFile(_))));
        assert!(matches!(bad(&[("nul.big", &md5, 1, "ALL")], &[]), Err(ManifestError::BadFile(_))));
        assert!(matches!(bad(&[("x.big", "zz", 1, "ALL")], &[]), Err(ManifestError::BadFile(_))));
        assert!(matches!(
            bad(&[("x.big", &md5, i64::MAX, "ALL")], &[]),
            Err(ManifestError::BadFile(_))
        ));
        assert!(matches!(bad(&[], &["a b"]), Err(ManifestError::BadDependency(_))));
        assert!(matches!(
            parse_manifest(manifest_json("../x", "N", "1.0", 0, &[], &[]).as_bytes()),
            Err(ManifestError::BadIdentity(_))
        ));
        assert!(matches!(parse_manifest(b"[]"), Err(ManifestError::Json(_))));
        assert!(matches!(
            parse_manifest(&vec![b' '; (MAX_MANIFEST_BYTES + 1) as usize]),
            Err(ManifestError::TooLarge)
        ));
        // Nulls where lists are expected are treated as empty.
        let nulls = r#"{"Guid":"g","Name":"n","Version":"1","Files":null,"Dependencies":null,"SocialLinks":null,"Author":null}"#;
        let p = parse_manifest(nulls.as_bytes()).unwrap();
        assert!(p.files.is_empty() && p.dependencies.is_empty());
    }

    #[test]
    fn languages() {
        assert_eq!(FileLanguages::parse(""), FileLanguages::All);
        assert_eq!(FileLanguages::parse("all"), FileLanguages::All);
        assert_eq!(FileLanguages::parse("en de x1"), FileLanguages::Only(vec!["EN".into(), "DE".into()]));
        assert!(!FileLanguages::parse("1 2").includes("EN"));
        assert_eq!(PackageKind::from_number(1).number(), 1);
        assert_eq!(PackageKind::from_number(9), PackageKind::Other);
    }
}
