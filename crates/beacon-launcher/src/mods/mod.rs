//! Mod support: BFME1 package configurations from the BFME Workshop in Beacon
//! instance folders (design: `docs/dev/mods.md`, research: spec 10).
//!
//! The lobby host picks a configuration (a BFME Workshop package with its
//! dependencies, the base game and a language variant); the server sends it to
//! every player as a [`GameConfig`] with the expected file set. Every Beacon
//! then prepares exactly that set and starts BFME from its own instance folder:
//!
//! * [`store`] – a content-addressed store `store\<md5>`: every file
//!   MD5-verified on the way in, read-only, owned by Beacon.
//! * [`instance`] – `instances\<id>\game\` (and `mod\` for type-1 packages): the
//!   on-disk layout the BFME Workshop launcher (AIO) would produce, as NTFS
//!   hardlinks into the store (copies where hardlinks fail). The hook DLL goes
//!   into the instance; the real installation is never touched.
//! * Sources, in this order: the store; [`import`] from the user's own files
//!   (the AIO caches by MD5, the game folder and user-added folders, found by
//!   path, size and MD5); [`workshop`] downloads from the workshop CDN (only with
//!   the `workshop_downloads` setting, which this build keeps off: the BFME
//!   Foundation Team has not agreed yet). Base-game files and executables only
//!   ever come from the user's own installation.
//! * [`manifest`], [`library`], [`resolve`] – the AIO's manifests (read-only from
//!   `%APPDATA%\BFME Workshop\Library`) and the AIO's resolution rules (layers,
//!   first destination wins, language filter) that turn a package into a
//!   [`GameConfig`].
//! * [`prepare`] runs one preparation (blocking, cancellable); [`manager`] keeps
//!   the state for the UI and the readiness report for the server.

pub mod fsx;
pub mod hash;
pub mod http;
pub mod import;
pub mod instance;
pub mod library;
pub mod manager;
pub mod manifest;
pub mod prepare;
pub mod resolve;
pub mod store;
pub mod workshop;

use std::path::{Path, PathBuf};

pub use beacon_proto::control::GameConfig;

/// Workshop downloads are compiled in but unavailable until the BFME Foundation
/// Team agrees (spec 10 §0, R10-8): with `false` the `workshop_downloads` setting
/// cannot be switched on and the real API and CDN are never contacted. Tests use
/// an injected endpoint instead.
pub const WORKSHOP_DOWNLOADS_AVAILABLE: bool = false;

/// Guid of the BFME1 base game package (`original-BFME1`, EA content: never
/// downloaded, only imported from the user's installation).
pub const BASE_GUID: &str = "original-BFME1";

/// Guid prefix of the base-game packages of all three games.
pub const BASE_GUID_PREFIX: &str = "original-";

/// MD5 of empty content (Patch 1.08 Reforged ships an empty `_aptpatch.big`).
pub const EMPTY_MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";

/// Name of the AIO's folder below `%APPDATA%` and next to the game folder.
pub const AIO_FOLDER: &str = "BFME Workshop";

/// Largest `instance.json` read.
pub const MAX_RECORD_BYTES: u64 = 4 << 20;

/// Beacon's folders for mod support (all on one volume so that hardlinks work).
///
/// ```text
/// <root>\store\<md5>              verified files (read-only), store\index.json
/// <root>\instances\<id>\game\     the game folder of a configuration
/// <root>\instances\<id>\mod\      the -mod folder of a type-1 package
/// <root>\instances\<id>\instance.json
/// <root>\downloads\<md5>.part     unfinished downloads (resume)
/// <root>\workshop\manifests\      fetched workshop manifests (guid@version.json)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModPaths {
    root: PathBuf,
}

impl ModPaths {
    /// The layout below `root`.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// The default root below Beacon's data folder.
    pub fn default_root(data_dir: &Path) -> PathBuf {
        data_dir.join("mods")
    }

    /// The root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `store\`.
    pub fn store(&self) -> PathBuf {
        self.root.join("store")
    }

    /// `instances\`.
    pub fn instances(&self) -> PathBuf {
        self.root.join("instances")
    }

    /// `downloads\`.
    pub fn downloads(&self) -> PathBuf {
        self.root.join("downloads")
    }

    /// `workshop\manifests\`.
    pub fn manifest_cache(&self) -> PathBuf {
        self.root.join("workshop").join("manifests")
    }
}

/// The workshop language code of BFME's registry `Language` value (spec 10 §3,
/// `Registry` L153–176): `English` → `EN`, `German` → `DE`, …
pub fn language_code(registry_language: &str) -> Option<&'static str> {
    let code = match registry_language.trim().to_ascii_lowercase().as_str() {
        "english" => "EN",
        "german" | "deutsch" => "DE",
        "french" => "FR",
        "spanish" => "ES",
        "italian" => "IT",
        "dutch" => "NL",
        "polish" => "PL",
        "norwegian" => "NO",
        "swedish" => "SV",
        "russian" => "RU",
        "turkish" => "TR",
        _ => return None,
    };
    Some(code)
}

/// Extensions of files that Windows or the game load as code. Such files are
/// only ever taken from the user's own installation at the same relative path
/// (never from a cache, a search by MD5 or a download), so a lobby host cannot
/// make a known DLL appear under another name.
pub const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "asi", "m3d", "flt", "mix", "com", "bat", "cmd", "scr", "ps1", "vbs", "js", "msi", "sys",
    "cpl", "ocx", "drv", "lnk", "url",
];

/// `true` if `path` (a normalised package path) names an executable file.
pub fn is_executable_path(path: &str) -> bool {
    path.rsplit_once('.').is_some_and(|(_, ext)| {
        EXECUTABLE_EXTENSIONS
            .iter()
            .any(|e| e.eq_ignore_ascii_case(ext))
    })
}

/// A normalised package path (`a\b\c`) below `base`.
pub fn join_package_path(base: &Path, path: &str) -> PathBuf {
    let mut p = base.to_path_buf();
    for component in path.split('\\') {
        p.push(component);
    }
    p
}

/// Bytes as German text ("3,6 GB", "512 MB").
pub fn human_size(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10), ("B", 1)];
    for (unit, size) in UNITS {
        if bytes >= size || size == 1 {
            let value = bytes as f64 / size as f64;
            let text = if size == 1 || value >= 100.0 {
                format!("{value:.0}")
            } else {
                format!("{value:.1}")
            };
            return format!("{} {unit}", text.replace('.', ","));
        }
    }
    format!("{bytes} B")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_codes() {
        assert_eq!(language_code("English"), Some("EN"));
        assert_eq!(language_code(" german "), Some("DE"));
        assert_eq!(language_code("Klingon"), None);
    }

    #[test]
    fn executables() {
        assert!(is_executable_path("lotrbfme.exe"));
        assert!(is_executable_path("mss\\mssds3d.m3d"));
        assert!(is_executable_path("DSOUND.DLL"));
        assert!(!is_executable_path("_patch106.big"));
        assert!(!is_executable_path("asset.dat"));
        assert!(!is_executable_path("noextension"));
    }

    #[test]
    fn paths_and_sizes() {
        let base = Path::new("C:\\x");
        assert_eq!(join_package_path(base, "data\\movies\\a.vp6"), base.join("data").join("movies").join("a.vp6"));
        let p = ModPaths::new(PathBuf::from("C:\\b"));
        assert_eq!(p.store(), PathBuf::from("C:\\b").join("store"));
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1536), "1,5 KB");
        assert_eq!(human_size(3_865_000_000), "3,6 GB");
        assert_eq!(human_size(500 << 20), "500 MB");
    }
}
