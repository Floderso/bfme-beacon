//! Game-data fingerprint (architecture §8): BLAKE3 over the sorted
//! `(relative lowercase path, size, BLAKE3)` entries of
//!
//! * `lotrbfme.exe`,
//! * every `*.big` below the game folder, recursively – the engine mounts all of
//!   them, including sub-folders and backup copies (spec 04 §6.2),
//! * the loose files below `Data\` except `Data\Movies` (videos only: about 1 GB,
//!   language dependent, never part of the game logic),
//! * the hook DLL (`wsock32.dll`, the file Beacon installs) and
//! * the Beacon build id ([`FileEntry::build_id`]).
//!
//! File hashes are cached in `cache.json` by `(path, size, mtime)`. Symbolic links
//! and junctions are not followed. The computation runs on a background thread
//! ([`run`] is blocking; the app spawns it) and can be cancelled.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;

use beacon_proto::blake3;
use beacon_proto::fingerprint::{normalize_path, FileEntry, Fingerprint};
use serde::{Deserialize, Serialize};

use crate::game::detect::EXE_NAME;
use crate::game::hook::HOOK_DLL_NAME;
use crate::util;

/// Most files in one fingerprint.
pub const MAX_FILES: usize = 20_000;
/// Deepest folder level searched for `*.big`.
pub const MAX_DEPTH: usize = 12;
/// Most directory entries looked at while searching (files and folders).
pub const MAX_ENTRIES: usize = 500_000;
/// Loose `Data\` sub-trees left out (normalised, lowercase).
pub const EXCLUDED_DIRS: &[&str] = &["data/movies"];
/// Largest `cache.json`.
const MAX_CACHE_LEN: u64 = 32 << 20;
const CACHE_VERSION: u32 = 1;
const READ_BUF: usize = 1 << 20;
/// Progress is reported at least every this many bytes.
const PROGRESS_STEP: u64 = 64 << 20;

/// One file of the fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Source {
    /// Path relative to the game folder as recorded (`/`-separated).
    pub rel: String,
    /// Absolute path.
    pub abs: PathBuf,
}

/// Errors of the fingerprint computation.
#[derive(Debug)]
pub enum FingerprintError {
    /// More than [`MAX_FILES`] files.
    TooManyFiles,
    /// A file could not be read.
    Io(PathBuf, io::Error),
    /// Cancelled.
    Cancelled,
}

impl fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyFiles => write!(
                f,
                "too many files in the game folder (more than {MAX_FILES} game files or {MAX_ENTRIES} entries)"
            ),
            Self::Io(p, e) => write!(f, "{}: {e}", p.display()),
            Self::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for FingerprintError {}

fn is_big(name: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("big"))
}

fn is_excluded(rel_norm: &str) -> bool {
    EXCLUDED_DIRS
        .iter()
        .any(|d| rel_norm == *d || rel_norm.starts_with(&format!("{d}/")))
}

/// The files of the fingerprint (sorted by normalised path, unique).
pub fn collect(game_dir: &Path, hook_dll: Option<&Path>) -> Result<Vec<Source>, FingerprintError> {
    let mut found: BTreeMap<String, Source> = BTreeMap::new();
    let mut add = |rel: String, abs: PathBuf| -> Result<(), FingerprintError> {
        if found.len() >= MAX_FILES {
            return Err(FingerprintError::TooManyFiles);
        }
        found.entry(normalize_path(&rel)).or_insert(Source { rel, abs });
        Ok(())
    };
    let exe = game_dir.join(EXE_NAME);
    if exe.is_file() {
        add(EXE_NAME.to_owned(), exe)?;
    }
    // Depth-first walk without following links/junctions.
    let mut stack: Vec<(PathBuf, String, usize)> = vec![(game_dir.to_path_buf(), String::new(), 0)];
    let mut visited = 0usize;
    while let Some((dir, prefix, depth)) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if depth == 0 => return Err(FingerprintError::Io(dir, e)),
            Err(e) => {
                tracing::debug!("skipping {}: {e}", dir.display());
                continue;
            }
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_ENTRIES {
                return Err(FingerprintError::TooManyFiles);
            }
            let Ok(kind) = entry.file_type() else { continue };
            if kind.is_symlink() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let rel_norm = normalize_path(&rel);
            if is_excluded(&rel_norm) {
                continue;
            }
            if kind.is_dir() {
                if depth < MAX_DEPTH {
                    stack.push((entry.path(), rel, depth + 1));
                }
            } else if kind.is_file() && (is_big(&name) || rel_norm.starts_with("data/")) {
                add(rel, entry.path())?;
            }
        }
    }
    if let Some(hook) = hook_dll.filter(|h| h.is_file()) {
        // Recorded under the name it has in the game folder.
        found.insert(
            normalize_path(HOOK_DLL_NAME),
            Source {
                rel: HOOK_DLL_NAME.to_owned(),
                abs: hook.to_path_buf(),
            },
        );
    }
    Ok(found.into_values().collect())
}

/// One cached file hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEntry {
    /// File size.
    pub size: u64,
    /// Modification time, ns since the Unix epoch.
    pub mtime_ns: u64,
    /// BLAKE3, lowercase hex.
    pub blake3: String,
}

/// `cache.json`: file hashes by absolute path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashCache {
    /// Format version.
    pub version: u32,
    /// Entries keyed by the lower-cased absolute path.
    pub entries: BTreeMap<String, CacheEntry>,
}

fn cache_key(abs: &Path) -> String {
    abs.to_string_lossy().to_lowercase()
}

impl HashCache {
    /// Loads the cache; anything unreadable yields an empty cache.
    pub fn load(path: &Path) -> Self {
        util::read_bounded(path, MAX_CACHE_LEN)
            .ok()
            .and_then(|t| serde_json::from_slice::<Self>(&t).ok())
            .filter(|c| c.version == CACHE_VERSION)
            .unwrap_or_default()
    }

    /// Saves the cache atomically.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let json = serde_json::to_vec(self).map_err(io::Error::other)?;
        util::write_atomic(path, &json)
    }

    fn lookup(&self, abs: &Path, size: u64, mtime_ns: u64) -> Option<String> {
        self.entries
            .get(&cache_key(abs))
            .filter(|e| e.size == size && e.mtime_ns == mtime_ns && e.blake3.len() == 64)
            .map(|e| e.blake3.clone())
    }

    fn insert(&mut self, abs: &Path, entry: CacheEntry) {
        self.version = CACHE_VERSION;
        self.entries.insert(cache_key(abs), entry);
    }

    /// Keeps only the entries of `sources`.
    pub fn retain_sources(&mut self, sources: &[Source]) {
        let keep: BTreeSet<String> = sources.iter().map(|s| cache_key(&s.abs)).collect();
        self.entries.retain(|k, _| keep.contains(k));
    }
}

/// Progress of a computation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Progress {
    /// Files finished.
    pub files_done: usize,
    /// Files in total.
    pub files_total: usize,
    /// Bytes finished (including cache hits).
    pub bytes_done: u64,
    /// Bytes in total.
    pub bytes_total: u64,
}

fn mtime_ns(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn hash_file(
    path: &Path,
    cancel: &AtomicBool,
    on_bytes: &mut dyn FnMut(u64),
) -> Result<String, FingerprintError> {
    let io_err = |e| FingerprintError::Io(path.to_path_buf(), e);
    let mut file = File::open(path).map_err(io_err)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; READ_BUF];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(FingerprintError::Cancelled);
        }
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_err(e)),
        };
        hasher.update(buf.get(..n).unwrap_or_default());
        on_bytes(u64::try_from(n).unwrap_or(0));
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Hashes `sources` (using and updating `cache`) and combines the entries plus the
/// build id into the fingerprint.
pub fn compute(
    sources: &[Source],
    cache: &mut HashCache,
    build_id: &str,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&Progress),
) -> Result<Fingerprint, FingerprintError> {
    let mut metas = Vec::with_capacity(sources.len());
    let mut p = Progress {
        files_total: sources.len(),
        ..Progress::default()
    };
    for s in sources {
        let meta = fs::metadata(&s.abs).map_err(|e| FingerprintError::Io(s.abs.clone(), e))?;
        p.bytes_total = p.bytes_total.saturating_add(meta.len());
        metas.push(meta);
    }
    progress(&p);
    let mut entries = Vec::with_capacity(sources.len() + 1);
    let mut last_report = 0u64;
    for (s, meta) in sources.iter().zip(&metas) {
        let (size, mtime) = (meta.len(), mtime_ns(meta));
        let hash = match cache.lookup(&s.abs, size, mtime) {
            Some(h) => {
                p.bytes_done = p.bytes_done.saturating_add(size);
                h
            }
            None => {
                let h = hash_file(&s.abs, cancel, &mut |n| {
                    p.bytes_done = p.bytes_done.saturating_add(n);
                    if p.bytes_done.saturating_sub(last_report) >= PROGRESS_STEP {
                        last_report = p.bytes_done;
                        progress(&p);
                    }
                })?;
                cache.insert(
                    &s.abs,
                    CacheEntry {
                        size,
                        mtime_ns: mtime,
                        blake3: h.clone(),
                    },
                );
                h
            }
        };
        entries.push(FileEntry::new(&s.rel, size, &hash));
        p.files_done += 1;
        progress(&p);
    }
    entries.push(FileEntry::build_id(build_id));
    Ok(Fingerprint::new(entries))
}

/// Collects, hashes (with `cache_file`) and returns the fingerprint; the cache is
/// pruned to the current files and saved.
pub fn run(
    game_dir: &Path,
    hook_dll: Option<&Path>,
    cache_file: &Path,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&Progress),
) -> Result<Fingerprint, FingerprintError> {
    let sources = collect(game_dir, hook_dll)?;
    let mut cache = HashCache::load(cache_file);
    let result = compute(&sources, &mut cache, crate::BUILD_ID, cancel, progress);
    if result.is_ok() {
        cache.retain_sources(&sources);
    }
    // Partial work is kept even after an error or cancellation.
    if let Err(e) = cache.save(cache_file) {
        tracing::warn!("cannot save {}: {e}", cache_file.display());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(name: &str, files: &[(&str, &[u8])]) -> PathBuf {
        let d = std::env::temp_dir().join(format!("beacon-fp-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        for (rel, data) in files {
            let p = d.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, data).unwrap();
        }
        d
    }

    const FILES: &[(&str, &[u8])] = &[
        ("lotrbfme.exe", b"exe"),
        ("INI.big", b"ini"),
        ("_patch106.big", b"patch"),
        ("apt/AptLevel0.BIG", b"apt"),
        ("backup/old.big", b"old"),
        ("Data/INI/Weapon.ini", b"loose"),
        ("Data/Movies/intro.vp6", b"video"),
        ("readme.txt", b"ignored"),
        ("dsound.dll", b"ignored"),
    ];

    #[test]
    fn collects_the_mounted_files() {
        let d = tree("collect", FILES);
        let hook = d.join("hook.dll");
        fs::write(&hook, b"hook").unwrap();
        let rels: Vec<String> = collect(&d, Some(&hook))
            .unwrap()
            .into_iter()
            .map(|s| normalize_path(&s.rel))
            .collect();
        assert_eq!(
            rels,
            [
                "_patch106.big",
                "apt/aptlevel0.big",
                "backup/old.big",
                "data/ini/weapon.ini",
                "ini.big",
                "lotrbfme.exe",
                "wsock32.dll"
            ]
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn digest_is_order_independent_and_cached() {
        let a = tree("a", FILES);
        let mut reversed = FILES.to_vec();
        reversed.reverse();
        let b = tree("b", &reversed);
        let cancel = AtomicBool::new(false);
        let fp = |dir: &Path, cache: &mut HashCache| {
            let sources = collect(dir, None).unwrap();
            compute(&sources, cache, "test-build", &cancel, &mut |_| {}).unwrap()
        };
        let (mut ca, mut cb) = (HashCache::default(), HashCache::default());
        let fa = fp(&a, &mut ca);
        let fb = fp(&b, &mut cb);
        assert_eq!(fa.digest_hex, fb.digest_hex);
        let paths: Vec<&str> = fa.entries.iter().map(|e| e.path.as_str()).collect();
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        assert_eq!(paths, sorted);
        assert!(paths.contains(&"<beacon-build>"));
        assert_eq!(ca.entries.len(), 6);
        // A cache hit is used as-is (same size and mtime).
        let key = cache_key(&a.join("INI.big"));
        ca.entries.get_mut(&key).unwrap().blake3 = "0".repeat(64);
        assert_ne!(fp(&a, &mut ca).digest_hex, fa.digest_hex);
        // A changed file is re-hashed.
        fs::write(b.join("INI.big"), b"INI").unwrap();
        assert_ne!(fp(&b, &mut cb).digest_hex, fa.digest_hex);
        // The build id is part of the digest.
        let sources = collect(&a, None).unwrap();
        let other = compute(&sources, &mut HashCache::default(), "other", &cancel, &mut |_| {}).unwrap();
        assert_ne!(other.digest_hex, fa.digest_hex);
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
    }

    #[test]
    fn run_saves_the_cache_and_reports_progress() {
        let d = tree("run", FILES);
        let cache_file = d.join("cache").join("cache.json");
        let cancel = AtomicBool::new(false);
        let mut last = Progress::default();
        let fp = run(&d, None, &cache_file, &cancel, &mut |p| last = *p).unwrap();
        assert_eq!(last.files_done, last.files_total);
        assert_eq!(last.bytes_done, last.bytes_total);
        assert_eq!(HashCache::load(&cache_file).entries.len(), fp.entries.len() - 1);
        cancel.store(true, Ordering::Relaxed);
        fs::write(d.join("new.big"), b"new").unwrap();
        assert!(matches!(
            run(&d, None, &cache_file, &cancel, &mut |_| {}),
            Err(FingerprintError::Cancelled)
        ));
        assert!(matches!(
            collect(&d.join("missing"), None),
            Err(FingerprintError::Io(..))
        ));
        let _ = fs::remove_dir_all(&d);
    }
}
