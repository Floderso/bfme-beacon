//! Import from the user's own files: every file a configuration needs and the
//! store lacks is looked for by MD5 in
//!
//! 1. the AIO's download caches (`<md5>.pfcache`, exact name),
//! 2. the game folder and the user-added folders at the file's own relative
//!    path (the only source for executables, see
//!    [`is_executable_path`](super::is_executable_path)),
//! 3. the same folders searched for files of the right size (or, where the
//!    manifest has no size, the right name).
//!
//! A candidate is copied into the store and kept only if its MD5 matches. Sources
//! are only ever read: Beacon never writes into the AIO's folders, the game
//! installation or the user's folders, and never links to them.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use beacon_proto::control::GameConfig;

use super::fsx::{self, WalkedFile};
use super::store::{Store, StoreError};
use super::{is_executable_path, join_package_path, EMPTY_MD5};

/// Deepest folder level searched below a source.
pub const MAX_SEARCH_DEPTH: usize = 8;
/// Most directory entries looked at per source.
pub const MAX_SEARCH_ENTRIES: usize = 200_000;

/// Where to look.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportSources {
    /// The game folder (registry or setting).
    pub game_dir: Option<PathBuf>,
    /// The AIO's download caches.
    pub aio_caches: Vec<PathBuf>,
    /// Folders the user added ("Dateien aus Ordner importieren").
    pub extra_dirs: Vec<PathBuf>,
    /// Folders never searched (Beacon's own store and instances).
    pub exclude: Vec<PathBuf>,
}

/// A file the store lacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    /// MD5.
    pub md5: String,
    /// Size (0 = unknown).
    pub size: u64,
    /// The configuration paths that need this content.
    pub paths: Vec<String>,
    /// Some path is an executable: only taken from the same relative path.
    pub executable: bool,
}

/// The files of `config` that the store lacks (one entry per content).
pub fn wanted_files(config: &GameConfig, store: &Store) -> Vec<Wanted> {
    let mut by_md5: BTreeMap<String, Wanted> = BTreeMap::new();
    for f in &config.files {
        let w = by_md5.entry(f.md5.clone()).or_insert_with(|| Wanted {
            md5: f.md5.clone(),
            size: f.size,
            paths: Vec::new(),
            executable: false,
        });
        w.size = w.size.max(f.size);
        w.paths.push(f.path.clone());
        w.executable |= is_executable_path(&f.path);
    }
    by_md5.into_values().filter(|w| store.get(&w.md5).is_none()).collect()
}

/// Progress of [`import`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportProgress {
    /// Files imported.
    pub files_done: usize,
    /// Bytes copied (including rejected candidates).
    pub bytes_done: u64,
    /// The file being copied.
    pub current: Option<String>,
}

/// What [`import`] achieved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Files imported.
    pub imported: usize,
    /// Their size.
    pub bytes: u64,
    /// Candidates that had the right size or name but other content.
    pub rejected: usize,
    /// What is still missing.
    pub missing: Vec<Wanted>,
}

/// Why the import stopped.
#[derive(Debug)]
pub enum ImportError {
    /// Cancelled.
    Cancelled,
    /// Writing into the store failed.
    Store(StoreError),
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("cancelled"),
            Self::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ImportError {}

struct Run<'a> {
    store: &'a Store,
    cancel: &'a AtomicBool,
    progress: &'a mut dyn FnMut(&ImportProgress),
    state: ImportProgress,
    report: ImportReport,
}

impl Run<'_> {
    /// Tries one candidate: `Ok(true)` if it was the wanted content.
    fn try_candidate(&mut self, w: &Wanted, path: &Path) -> Result<bool, ImportError> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(ImportError::Cancelled);
        }
        let Ok(meta) = std::fs::metadata(path) else {
            return Ok(false);
        };
        if !meta.is_file() || (w.size > 0 && meta.len() != w.size) {
            return Ok(false);
        }
        self.state.current = w.paths.first().cloned();
        (self.progress)(&self.state);
        let mut copied = 0u64;
        let result = {
            let state = &mut self.state;
            let progress: &mut dyn FnMut(&ImportProgress) = &mut *self.progress;
            self.store.import_file(path, &w.md5, w.size, self.cancel, &mut |n| {
                copied = copied.saturating_add(n);
                state.bytes_done = state.bytes_done.saturating_add(n);
                if copied % (64 << 20) < n {
                    progress(state);
                }
            })
        };
        match result {
            Ok(stored) => {
                tracing::info!(file = %path.display(), md5 = %w.md5, "imported into the store");
                self.state.files_done += 1;
                self.report.imported += 1;
                self.report.bytes = self.report.bytes.saturating_add(stored.size);
                (self.progress)(&self.state);
                Ok(true)
            }
            Err(StoreError::Cancelled) => Err(ImportError::Cancelled),
            Err(StoreError::Mismatch { .. } | StoreError::WrongSize { .. }) => {
                tracing::debug!(file = %path.display(), md5 = %w.md5, "candidate has other content");
                self.report.rejected += 1;
                Ok(false)
            }
            Err(StoreError::Io(e)) if e.kind() != std::io::ErrorKind::StorageFull => {
                tracing::warn!(file = %path.display(), "cannot import: {e}");
                Ok(false)
            }
            Err(e) => Err(ImportError::Store(e)),
        }
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

/// Imports what it can find of `wanted` into the store.
pub fn import(
    store: &Store,
    wanted: Vec<Wanted>,
    sources: &ImportSources,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&ImportProgress),
) -> Result<ImportReport, ImportError> {
    let mut run = Run {
        store,
        cancel,
        progress,
        state: ImportProgress::default(),
        report: ImportReport::default(),
    };
    let mut todo: BTreeMap<String, Wanted> = wanted.into_iter().map(|w| (w.md5.clone(), w)).collect();
    if todo.remove(EMPTY_MD5).is_some() {
        store.ensure_empty().map_err(ImportError::Store)?;
        run.report.imported += 1;
    }
    // 1. The AIO's caches, by name.
    let keys: Vec<String> = todo.keys().cloned().collect();
    for md5 in keys {
        let Some(w) = todo.get(&md5).cloned() else { continue };
        if w.executable {
            continue;
        }
        for cache in &sources.aio_caches {
            if run.try_candidate(&w, &cache.join(format!("{md5}.pfcache")))? {
                todo.remove(&md5);
                break;
            }
        }
    }
    // 2. The same relative path in the user's folders.
    let roots: Vec<&PathBuf> = sources.game_dir.iter().chain(sources.extra_dirs.iter()).collect();
    let keys: Vec<String> = todo.keys().cloned().collect();
    'wanted: for md5 in keys {
        let Some(w) = todo.get(&md5).cloned() else { continue };
        for root in &roots {
            for path in &w.paths {
                if run.try_candidate(&w, &join_package_path(root, path))? {
                    todo.remove(&md5);
                    continue 'wanted;
                }
            }
        }
    }
    // 3. Search by size (or name, where the size is unknown).
    if todo.values().any(|w| !w.executable) {
        let mut by_size: HashMap<u64, Vec<String>> = HashMap::new();
        let mut by_name: HashMap<String, Vec<String>> = HashMap::new();
        for w in todo.values().filter(|w| !w.executable) {
            if w.size > 0 {
                by_size.entry(w.size).or_default().push(w.md5.clone());
            } else {
                for p in &w.paths {
                    by_name.entry(file_name(p).to_owned()).or_default().push(w.md5.clone());
                }
            }
        }
        let skip = |p: &Path| sources.exclude.iter().any(|x| fsx::is_inside(p, x));
        let mut candidates: BTreeMap<String, Vec<WalkedFile>> = BTreeMap::new();
        for root in &roots {
            if run.cancel.load(Ordering::Relaxed) {
                return Err(ImportError::Cancelled);
            }
            if skip(root) {
                continue;
            }
            let found = match fsx::walk_files(root, MAX_SEARCH_DEPTH, MAX_SEARCH_ENTRIES, &skip) {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!("cannot search {}: {e}", root.display());
                    continue;
                }
            };
            for f in found {
                let lname = f.name.to_lowercase();
                let mut hits: Vec<&String> = by_size.get(&f.size).map(|v| v.iter().collect()).unwrap_or_default();
                if let Some(v) = by_name.get(&lname) {
                    hits.extend(v.iter());
                }
                for md5 in hits {
                    candidates.entry(md5.clone()).or_default().push(f.clone());
                }
            }
        }
        for (md5, mut files) in candidates {
            let Some(w) = todo.get(&md5).cloned() else { continue };
            // Same file name first: the likeliest match.
            let names: Vec<&str> = w.paths.iter().map(|p| file_name(p)).collect();
            files.sort_by_key(|f| !names.contains(&f.name.to_lowercase().as_str()));
            for f in files {
                if run.try_candidate(&w, &f.path)? {
                    todo.remove(&md5);
                    break;
                }
            }
        }
    }
    run.report.missing = todo.into_values().collect();
    Ok(run.report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mods::hash::md5_hex;
    use crate::mods::store::write_new;
    use beacon_proto::control::{ConfigFile, FileDir};

    fn temp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("beacon-import-{tag}-{}", std::process::id()));
        let _ = fsx::remove_tree(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn cfg(files: &[(&str, &[u8], bool)]) -> GameConfig {
        GameConfig {
            id: String::new(),
            guid: "p".into(),
            version: "1".into(),
            name: "P".into(),
            author: String::new(),
            language: "EN".into(),
            layers: Vec::new(),
            files: files
                .iter()
                .map(|(p, data, known)| ConfigFile {
                    path: (*p).into(),
                    md5: md5_hex(data),
                    size: if *known { data.len() as u64 } else { 0 },
                    dir: FileDir::Game,
                })
                .collect(),
        }
        .finalize()
        .unwrap()
    }

    fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>, bool)> {
        let mut out: Vec<_> = fsx::walk_files(dir, 16, 10_000, &|_| false)
            .unwrap()
            .into_iter()
            .map(|f| {
                let ro = std::fs::metadata(&f.path).unwrap().permissions().readonly();
                (f.rel, std::fs::read(&f.path).unwrap(), ro)
            })
            .collect();
        out.sort();
        out
    }

    #[test]
    fn finds_files_by_md5_and_never_writes_to_sources() {
        let d = temp("find");
        let game = d.join("BFME1");
        let extra = d.join("Mod stuf").join("BFME1 copy");
        let cache = d.join("BFME Workshop").join("Cache");
        let config = cfg(&[
            ("lotrbfme.exe", b"the exe", true),
            ("_patch106.big", b"patch 1.06", true),
            ("data.big", b"data with unknown size", false),
            ("_zlot3a_data.big", b"lot3a data", true),
            ("asset.dat", b"cached asset", true),
            ("_aptpatch.big", b"", false),
            ("evil.dll", b"some dll", true),
            ("nowhere.big", b"not anywhere", true),
        ]);
        write_new(&game.join("lotrbfme.exe"), b"the exe").unwrap();
        write_new(&game.join("_patch106.big"), b"patch 1.06").unwrap();
        write_new(&game.join("Data.big"), b"data with unknown size").unwrap();
        // Right size, wrong content, same name: rejected; the right one elsewhere.
        write_new(&extra.join("_zlot3a_data.big"), b"lot3a DATA").unwrap();
        write_new(&extra.join("backup").join("renamed.big"), b"lot3a data").unwrap();
        write_new(&cache.join(format!("{}.pfcache", md5_hex(b"cached asset"))), b"cached asset").unwrap();
        // An executable found by MD5 under another name or in a cache is not used.
        write_new(&extra.join("other.dll"), b"some dll").unwrap();
        write_new(&cache.join(format!("{}.pfcache", md5_hex(b"some dll"))), b"some dll").unwrap();
        let before = (snapshot(&game), snapshot(&extra), snapshot(&cache));

        let store = Store::open(&d.join("beacon").join("store")).unwrap();
        let wanted = wanted_files(&config, &store);
        assert_eq!(wanted.len(), 8);
        let sources = ImportSources {
            game_dir: Some(game.clone()),
            aio_caches: vec![cache.clone(), d.join("missing-cache")],
            extra_dirs: vec![extra.clone()],
            exclude: vec![d.join("beacon")],
        };
        let mut last = ImportProgress::default();
        let report = import(&store, wanted, &sources, &AtomicBool::new(false), &mut |p| last = p.clone()).unwrap();
        let mut missing: Vec<&str> = report.missing.iter().map(|w| w.paths[0].as_str()).collect();
        missing.sort_unstable();
        assert_eq!(missing, ["evil.dll", "nowhere.big"], "{report:?}");
        assert_eq!(report.imported, 6);
        assert!(report.rejected >= 1);
        assert_eq!(last.files_done, 5);
        for data in [&b"the exe"[..], b"patch 1.06", b"data with unknown size", b"lot3a data", b"cached asset", b""] {
            assert!(store.get(&md5_hex(data)).is_some());
        }
        assert_eq!(before, (snapshot(&game), snapshot(&extra), snapshot(&cache)), "sources unchanged");
        // Everything there now: nothing wanted any more.
        assert_eq!(wanted_files(&config, &store).len(), 2);
        let _ = fsx::remove_tree(&d);
    }

    #[test]
    fn cancellation_stops_the_import() {
        let d = temp("cancel");
        write_new(&d.join("game").join("a.big"), b"aaa").unwrap();
        let store = Store::open(&d.join("store")).unwrap();
        let config = cfg(&[("a.big", b"aaa", true)]);
        let sources = ImportSources {
            game_dir: Some(d.join("game")),
            ..ImportSources::default()
        };
        let r = import(&store, wanted_files(&config, &store), &sources, &AtomicBool::new(true), &mut |_| {});
        assert!(matches!(r, Err(ImportError::Cancelled)));
        let _ = fsx::remove_tree(&d);
    }
}
