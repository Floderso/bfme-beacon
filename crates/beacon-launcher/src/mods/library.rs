//! Package sources for the host's catalog: the AIO's local library (read-only:
//! `%APPDATA%\BFME Workshop\Library\*.json`, plus `Config\active_patch_0.json`
//! for "active in the AIO") and Beacon's own cache of workshop manifests.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;

use super::manifest::{parse_manifest, Package, MAX_MANIFEST_BYTES};
use super::AIO_FOLDER;
use crate::util;

/// Most manifest files read from one folder.
pub const MAX_LIBRARY_FILES: usize = 1000;

/// Where a package's manifest came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageSource {
    /// The AIO's local library.
    Aio,
    /// Beacon's cache of manifests fetched from the workshop API.
    Workshop,
}

/// The AIO's folders Beacon reads (never writes).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AioLocations {
    /// `%APPDATA%\BFME Workshop\Library`.
    pub library: Option<PathBuf>,
    /// `%APPDATA%\BFME Workshop\Config`.
    pub config: Option<PathBuf>,
    /// The download caches: `<parent of the game folder>\BFME Workshop\Cache` and
    /// `%APPDATA%\BFME Workshop\Cache` (files named `<md5>.pfcache`).
    pub caches: Vec<PathBuf>,
}

impl AioLocations {
    /// The AIO's folders for an `%APPDATA%` and a game folder.
    pub fn new(appdata: Option<&Path>, game_dir: Option<&Path>) -> Self {
        let aio = appdata.map(|a| a.join(AIO_FOLDER));
        let mut caches = Vec::new();
        if let Some(parent) = game_dir.and_then(Path::parent) {
            caches.push(parent.join(AIO_FOLDER).join("Cache"));
        }
        if let Some(a) = &aio {
            caches.push(a.join("Cache"));
        }
        Self {
            library: aio.as_ref().map(|a| a.join("Library")),
            config: aio.as_ref().map(|a| a.join("Config")),
            caches,
        }
    }
}

/// Packages by `(guid, version)`, with their source.
#[derive(Debug, Clone, Default)]
pub struct PackageSet {
    packages: BTreeMap<(String, String), (Arc<Package>, PackageSource)>,
    /// Files that could not be used, with the reason.
    pub problems: Vec<(PathBuf, String)>,
    /// The package the AIO has active for BFME1 (`active_patch_0.json`).
    pub active: Option<(String, String)>,
}

impl PackageSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a package (an AIO entry wins over a cached workshop entry).
    pub fn insert(&mut self, package: Package, source: PackageSource) {
        let key = (package.guid.clone(), package.version.clone());
        match self.packages.get(&key) {
            Some((_, PackageSource::Aio)) if source == PackageSource::Workshop => {}
            _ => {
                self.packages.insert(key, (Arc::new(package), source));
            }
        }
    }

    /// A package: the exact version, or (without a version) the newest one known
    /// (the AIO's library holds the version it synced last).
    pub fn get(&self, guid: &str, version: Option<&str>) -> Option<Arc<Package>> {
        match version {
            Some(v) => self
                .packages
                .get(&(guid.to_owned(), v.to_owned()))
                .map(|(p, _)| Arc::clone(p)),
            None => self
                .packages
                .iter()
                .filter(|((g, _), _)| g == guid)
                .max_by_key(|(_, (p, source))| (*source == PackageSource::Aio, p.creation_time.unwrap_or(0)))
                .map(|(_, (p, _))| Arc::clone(p)),
        }
    }

    /// The source of a package.
    pub fn source(&self, guid: &str, version: &str) -> Option<PackageSource> {
        self.packages
            .get(&(guid.to_owned(), version.to_owned()))
            .map(|(_, s)| *s)
    }

    /// Every package.
    pub fn iter(&self) -> impl Iterator<Item = (&Arc<Package>, PackageSource)> {
        self.packages.values().map(|(p, s)| (p, *s))
    }

    /// Number of packages.
    pub fn len(&self) -> usize {
        self.packages.len()
    }

    /// `true` without packages.
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }

    /// Reads every `*.json` manifest of a folder (bounded, read-only).
    pub fn read_dir(&mut self, dir: &Path, source: PackageSource) {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                self.problems.push((dir.to_path_buf(), e.to_string()));
                return;
            }
        };
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("json")))
            .collect();
        files.sort();
        for path in files.into_iter().take(MAX_LIBRARY_FILES) {
            match util::read_bounded(&path, MAX_MANIFEST_BYTES) {
                Ok(bytes) => match parse_manifest(&bytes) {
                    Ok(p) => self.insert(p, source),
                    Err(e) => self.problems.push((path, e.to_string())),
                },
                Err(e) => self.problems.push((path, e.to_string())),
            }
        }
    }

    /// The AIO's library and active BFME1 patch, plus Beacon's manifest cache.
    pub fn load(aio: &AioLocations, workshop_cache: Option<&Path>) -> Self {
        let mut set = Self::new();
        if let Some(lib) = &aio.library {
            set.read_dir(lib, PackageSource::Aio);
        }
        if let Some(cache) = workshop_cache {
            set.read_dir(cache, PackageSource::Workshop);
        }
        if let Some(cfg) = &aio.config {
            let active = cfg.join("active_patch_0.json");
            if let Ok(bytes) = util::read_bounded(&active, MAX_MANIFEST_BYTES) {
                match parse_manifest(&bytes) {
                    Ok(p) => {
                        set.active = Some((p.guid.clone(), p.version.clone()));
                        // The active manifest is the exact synced version.
                        set.insert(p, PackageSource::Aio);
                    }
                    Err(e) => set.problems.push((active, e.to_string())),
                }
            }
        }
        set
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mods::manifest::tests::manifest_json;

    #[test]
    fn reads_a_library_read_only() {
        let root = std::env::temp_dir().join(format!("beacon-lib-{}", std::process::id()));
        let _ = crate::mods::fsx::remove_tree(&root);
        let appdata = root.join("appdata");
        let lib = appdata.join(AIO_FOLDER).join("Library");
        let cfg = appdata.join(AIO_FOLDER).join("Config");
        fs::create_dir_all(&lib).unwrap();
        fs::create_dir_all(&cfg).unwrap();
        let md5 = "a".repeat(32);
        fs::write(lib.join("p1.json"), manifest_json("pkg-1", "One", "1.0", 0, &[("a.big", &md5, 1, "ALL")], &[])).unwrap();
        fs::write(lib.join("bad.json"), b"{not json").unwrap();
        fs::write(lib.join("readme.txt"), b"ignored").unwrap();
        fs::write(cfg.join("active_patch_0.json"), manifest_json("pkg-1", "One", "1.1", 0, &[], &[])).unwrap();
        let cache = root.join("cache");
        fs::create_dir_all(&cache).unwrap();
        fs::write(cache.join("x.json"), manifest_json("pkg-1", "One (cached)", "1.0", 0, &[], &[])).unwrap();
        fs::write(cache.join("y.json"), manifest_json("pkg-2", "Two", "2.0", 1, &[], &[])).unwrap();
        let before: Vec<_> = fs::read_dir(&lib).unwrap().flatten().map(|e| e.path()).collect();

        let aio = AioLocations::new(Some(&appdata), Some(Path::new("C:\\BFME1")));
        assert_eq!(aio.caches[0], Path::new("C:\\").join(AIO_FOLDER).join("Cache"));
        let set = PackageSet::load(&aio, Some(&cache));
        assert_eq!(set.len(), 3);
        assert_eq!(set.problems.len(), 1, "{:?}", set.problems);
        assert_eq!(set.active, Some(("pkg-1".into(), "1.1".into())));
        assert_eq!(set.get("pkg-1", Some("1.0")).unwrap().name, "One", "the AIO wins over the cache");
        assert_eq!(set.source("pkg-2", "2.0"), Some(PackageSource::Workshop));
        assert!(set.get("pkg-1", None).is_some());
        assert!(set.get("pkg-3", None).is_none());
        let after: Vec<_> = fs::read_dir(&lib).unwrap().flatten().map(|e| e.path()).collect();
        assert_eq!(before, after, "nothing written into the AIO's folder");
        let _ = crate::mods::fsx::remove_tree(&root);
    }
}
