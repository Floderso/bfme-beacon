//! Map repository (architecture §8): `<maps_dir>/<MapName>/<file>` (one optional
//! sub-folder level), announced as a manifest of `(path, size, blake3)` per file.
//!
//! Only names passing [`is_safe_file_name`] are listed; symbolic links, hidden
//! files and case-insensitive duplicates (which would collide on Windows) are
//! skipped. Chunks are served only for files in the current manifest, so a request
//! can never name a path outside the repository. Hashes are cached by
//! `(path, size, mtime)` across rescans.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use beacon_proto::blake3;
use beacon_proto::control::{
    is_safe_file_name, is_safe_rel_path, MapFile, MapInfo, ServerMsg, CHUNK_MAX, MAX_MSG_LEN,
};
use tracing::{debug, warn};

/// Maximum number of maps listed.
pub const MAX_MAPS: usize = 1000;
/// Maximum number of files per map.
pub const MAX_FILES_PER_MAP: usize = 256;
/// Files larger than this are skipped.
pub const MAX_FILE_SIZE: u64 = 1 << 30;
const HASH_BUF: usize = 64 * 1024;

/// A scanned repository.
#[derive(Debug, Clone)]
pub struct MapRepo {
    /// Maps sorted by name (case-insensitive).
    pub maps: Vec<MapInfo>,
    /// The pre-encoded `maps` message (JSON).
    pub listing: Arc<[u8]>,
    /// Some maps were left out because the listing must fit into one message.
    pub truncated: bool,
    /// Entries that were skipped (unsafe names, links, limits, I/O errors).
    pub skipped: usize,
    /// When the scan finished.
    pub scanned_at: Option<SystemTime>,
}

impl Default for MapRepo {
    fn default() -> Self {
        Self::from_maps(Vec::new(), 0, None)
    }
}

impl MapRepo {
    fn from_maps(mut maps: Vec<MapInfo>, skipped: usize, scanned_at: Option<SystemTime>) -> Self {
        let (listing, truncated) = encode_listing(&mut maps);
        Self {
            maps,
            listing,
            truncated,
            skipped,
            scanned_at,
        }
    }

    /// A map by exact name.
    pub fn map(&self, name: &str) -> Option<&MapInfo> {
        self.maps.iter().find(|m| m.name == name)
    }

    /// A file of a map; `file` may use `/` or `\` as separator.
    pub fn file(&self, map: &str, file: &str) -> Option<&MapFile> {
        let wanted = file.replace('\\', "/");
        self.map(map)?.files.iter().find(|f| f.path == wanted)
    }

    /// Sum of all file sizes.
    pub fn total_size(&self) -> u64 {
        self.maps
            .iter()
            .fold(0u64, |acc, m| acc.saturating_add(m.total_size))
    }
}

/// Encodes `maps` as one `ServerMsg::Maps`, dropping maps from the end until it
/// fits into [`MAX_MSG_LEN`].
fn encode_listing(maps: &mut Vec<MapInfo>) -> (Arc<[u8]>, bool) {
    // Estimate per-map sizes first so that a huge repository costs one pass.
    let mut budget = MAX_MSG_LEN.saturating_sub(64);
    let mut keep = 0;
    for m in maps.iter() {
        let len = serde_json::to_vec(m).map(|v| v.len() + 1).unwrap_or(usize::MAX);
        if len > budget {
            break;
        }
        budget -= len;
        keep += 1;
    }
    let mut truncated = keep < maps.len();
    maps.truncate(keep);
    loop {
        match (ServerMsg::Maps { maps: maps.clone() }).to_json() {
            Ok(json) => return (json.into(), truncated),
            Err(_) if !maps.is_empty() => {
                maps.pop();
                truncated = true;
            }
            Err(_) => return (Arc::from(&br#"{"t":"maps","maps":[]}"#[..]), true),
        }
    }
}

#[derive(Debug, Clone)]
struct CachedHash {
    size: u64,
    mtime: Option<SystemTime>,
    blake3_hex: String,
}

/// BLAKE3 results of earlier scans, keyed by path.
#[derive(Debug, Default)]
pub struct HashCache {
    entries: HashMap<PathBuf, CachedHash>,
}

impl HashCache {
    /// Number of cached files.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Streams a file through BLAKE3.
pub fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; HASH_BUF];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(buf.get(..n).unwrap_or_default());
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Lists `dir` sorted by name; each entry with its file type (links not followed).
fn sorted_entries(dir: &Path) -> io::Result<Vec<(String, PathBuf, fs::FileType)>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        match entry.file_name().into_string() {
            Ok(name) => out.push((name, entry.path(), file_type)),
            Err(raw) => {
                debug!("skipping non-UTF-8 name {raw:?} in {}", dir.display());
                out.push((String::new(), entry.path(), file_type));
            }
        }
    }
    out.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()).then(a.0.cmp(&b.0)));
    Ok(out)
}

fn acceptable_name(name: &str) -> bool {
    !name.starts_with('.') && is_safe_file_name(name)
}

/// Scans the repository (blocking; run it on a blocking thread). A missing
/// directory yields an empty repository.
pub fn scan(dir: &Path, cache: &mut HashCache) -> MapRepo {
    let mut skipped = 0usize;
    let mut seen_paths = HashSet::new();
    let mut maps = Vec::new();
    let entries = match sorted_entries(dir) {
        Ok(e) => e,
        Err(e) => {
            if e.kind() != io::ErrorKind::NotFound {
                warn!("cannot read maps_dir {}: {e}", dir.display());
            } else {
                debug!("maps_dir {} does not exist", dir.display());
            }
            cache.entries.clear();
            return MapRepo::from_maps(Vec::new(), 0, Some(SystemTime::now()));
        }
    };
    let mut names = HashSet::new();
    for (name, path, file_type) in entries {
        if !file_type.is_dir() {
            if !name.starts_with('.') {
                skipped += 1;
            }
            continue;
        }
        if !acceptable_name(&name) || !names.insert(name.to_lowercase()) {
            warn!("skipping map folder {:?} (unsafe or duplicate name)", path);
            skipped += 1;
            continue;
        }
        if maps.len() >= MAX_MAPS {
            warn!("more than {MAX_MAPS} maps; the rest is ignored");
            skipped += 1;
            continue;
        }
        let files = scan_map(&path, cache, &mut seen_paths, &mut skipped);
        if files.is_empty() {
            debug!("skipping empty map folder {}", path.display());
            continue;
        }
        maps.push(MapInfo::new(name, files));
    }
    cache.entries.retain(|p, _| seen_paths.contains(p));
    let repo = MapRepo::from_maps(maps, skipped, Some(SystemTime::now()));
    if repo.truncated {
        warn!(
            "map listing truncated to {} maps (one message holds at most {} KiB)",
            repo.maps.len(),
            MAX_MSG_LEN / 1024
        );
    }
    repo
}

fn scan_map(
    map_dir: &Path,
    cache: &mut HashCache,
    seen_paths: &mut HashSet<PathBuf>,
    skipped: &mut usize,
) -> Vec<MapFile> {
    let mut files = Vec::new();
    let mut keys = HashSet::new();
    let mut stack: Vec<(PathBuf, String)> = vec![(map_dir.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let entries = match sorted_entries(&dir) {
            Ok(e) => e,
            Err(e) => {
                warn!("cannot read {}: {e}", dir.display());
                *skipped += 1;
                continue;
            }
        };
        for (name, path, file_type) in entries {
            if !acceptable_name(&name) {
                if !name.starts_with('.') {
                    warn!("skipping {:?} (unsafe name)", path);
                    *skipped += 1;
                }
                continue;
            }
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if file_type.is_dir() {
                if prefix.is_empty() {
                    stack.push((path, rel));
                } else {
                    warn!("skipping {:?} (maps may have one sub-folder level)", path);
                    *skipped += 1;
                }
                continue;
            }
            if !file_type.is_file() || !is_safe_rel_path(&rel) {
                // Symbolic links and special files are never served.
                warn!("skipping {:?} (not a regular file)", path);
                *skipped += 1;
                continue;
            }
            if !keys.insert(rel.to_lowercase()) || files.len() >= MAX_FILES_PER_MAP {
                warn!("skipping {:?} (duplicate name or too many files)", path);
                *skipped += 1;
                continue;
            }
            match file_entry(&path, &rel, cache) {
                Ok(Some(f)) => {
                    seen_paths.insert(path);
                    files.push(f);
                }
                Ok(None) => *skipped += 1,
                Err(e) => {
                    warn!("cannot hash {}: {e}", path.display());
                    *skipped += 1;
                }
            }
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files
}

fn file_entry(path: &Path, rel: &str, cache: &mut HashCache) -> io::Result<Option<MapFile>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return Ok(None);
    }
    let size = meta.len();
    if size > MAX_FILE_SIZE {
        warn!("skipping {} (larger than 1 GiB)", path.display());
        return Ok(None);
    }
    let mtime = meta.modified().ok();
    let cached = cache
        .entries
        .get(path)
        .filter(|c| c.size == size && c.mtime == mtime && mtime.is_some());
    let blake3_hex = match cached {
        Some(c) => c.blake3_hex.clone(),
        None => {
            let hex = hash_file(path)?;
            cache.entries.insert(
                path.to_path_buf(),
                CachedHash {
                    size,
                    mtime,
                    blake3_hex: hex.clone(),
                },
            );
            hex
        }
    };
    Ok(Some(MapFile {
        path: rel.to_owned(),
        size,
        blake3_hex,
    }))
}

/// Errors of [`read_chunk`].
#[derive(Debug)]
pub enum ChunkError {
    /// `offset` is beyond the end of the file.
    BadOffset,
    /// The file on disk no longer matches the manifest (rescan needed).
    Changed,
    /// The file could not be read.
    Io(io::Error),
}

impl std::fmt::Display for ChunkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadOffset => f.write_str("offset beyond end of file"),
            Self::Changed => f.write_str("file changed on disk"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Reads up to [`CHUNK_MAX`] bytes of a manifest file at `offset` (blocking).
/// Returns the bytes and whether they end at the end of the file.
pub fn read_chunk(
    maps_dir: &Path,
    map: &str,
    file: &MapFile,
    offset: u64,
) -> Result<(Vec<u8>, bool), ChunkError> {
    if offset > file.size {
        return Err(ChunkError::BadOffset);
    }
    // Defence in depth: the manifest only contains safe names, check anyway.
    if !is_safe_file_name(map) || !is_safe_rel_path(&file.path) {
        return Err(ChunkError::Changed);
    }
    let mut path = maps_dir.join(map);
    for part in file.path.split('/') {
        path.push(part);
    }
    let meta = fs::symlink_metadata(&path).map_err(ChunkError::Io)?;
    if !meta.is_file() || meta.len() != file.size {
        return Err(ChunkError::Changed);
    }
    let remaining = file.size - offset;
    let len = usize::try_from(remaining.min(CHUNK_MAX as u64)).unwrap_or(CHUNK_MAX);
    let mut f = fs::File::open(&path).map_err(ChunkError::Io)?;
    f.seek(SeekFrom::Start(offset)).map_err(ChunkError::Io)?;
    let mut data = vec![0u8; len];
    f.read_exact(&mut data).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            ChunkError::Changed
        } else {
            ChunkError::Io(e)
        }
    })?;
    let eof = offset.saturating_add(len as u64) >= file.size;
    Ok((data, eof))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let n = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let p = std::env::temp_dir().join(format!("beacon-maps-{tag}-{}-{n}", std::process::id()));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write(path: &Path, data: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
    }

    #[test]
    fn scan_lists_maps_with_hashes() {
        let tmp = TempDir::new("scan");
        let big: Vec<u8> = (0..CHUNK_MAX * 2 + 100).map(|i| (i % 251) as u8).collect();
        write(&tmp.0.join("Helms Deep/helms deep.map"), &big);
        write(&tmp.0.join("Helms Deep/map.str"), b"strings");
        write(&tmp.0.join("Helms Deep/art/preview.tga"), b"tga");
        write(&tmp.0.join("Helms Deep/art/deeper/x.txt"), b"too deep");
        write(&tmp.0.join("Helms Deep/.hidden"), b"h");
        write(&tmp.0.join("aaa/one.map"), b"1");
        write(&tmp.0.join("loose-file.txt"), b"not a map");
        fs::create_dir_all(tmp.0.join("Empty")).unwrap();
        let mut cache = HashCache::default();
        let repo = scan(&tmp.0, &mut cache);
        let names: Vec<_> = repo.maps.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["aaa", "Helms Deep"]);
        let helm = repo.map("Helms Deep").unwrap();
        let paths: Vec<_> = helm.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["art/preview.tga", "helms deep.map", "map.str"]);
        let f = repo.file("Helms Deep", "helms deep.map").unwrap();
        assert_eq!(f.size, big.len() as u64);
        assert_eq!(f.blake3_hex, blake3::hash(&big).to_hex().to_string());
        assert_eq!(repo.file("Helms Deep", "art\\preview.tga").unwrap().size, 3);
        assert_eq!(helm.total_size, big.len() as u64 + 7 + 3);
        assert_eq!(repo.skipped, 2, "loose file + too-deep folder");
        assert!(!repo.truncated);
        assert_eq!(cache.len(), 4);
        // The listing is a valid `maps` message.
        let msg = ServerMsg::from_json(&repo.listing).unwrap();
        assert_eq!(msg, ServerMsg::Maps { maps: repo.maps.clone() });

        // Rescan uses the cache; a changed file is re-hashed.
        write(&tmp.0.join("aaa/one.map"), b"22");
        let repo2 = scan(&tmp.0, &mut cache);
        assert_eq!(repo2.file("aaa", "one.map").unwrap().blake3_hex, blake3::hash(b"22").to_hex().to_string());
        fs::remove_dir_all(tmp.0.join("aaa")).unwrap();
        let repo3 = scan(&tmp.0, &mut cache);
        assert!(repo3.map("aaa").is_none());
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn scan_of_missing_dir_is_empty() {
        let mut cache = HashCache::default();
        let repo = scan(Path::new("/definitely/not/here/beacon"), &mut cache);
        assert!(repo.maps.is_empty());
        assert_eq!(ServerMsg::from_json(&repo.listing).unwrap(), ServerMsg::Maps { maps: vec![] });
    }

    // Case-sensitive file system with names Windows cannot even create.
    #[cfg(unix)]
    #[test]
    fn case_duplicates_and_unsafe_names_are_skipped() {
        let tmp = TempDir::new("dups");
        write(&tmp.0.join("Map/a.map"), b"1");
        write(&tmp.0.join("Map/A.MAP"), b"2");
        write(&tmp.0.join("Map/con.txt"), b"device name on Windows");
        write(&tmp.0.join("Map/bad:name"), b"stream syntax on Windows");
        write(&tmp.0.join("map/x.map"), b"folder differs only in case");
        std::os::unix::fs::symlink("/etc/hostname", tmp.0.join("Map/link.map")).unwrap();
        let repo = scan(&tmp.0, &mut HashCache::default());
        assert_eq!(repo.maps.len(), 1);
        let files: Vec<_> = repo.map("Map").unwrap().files.iter().map(|f| f.path.clone()).collect();
        // Sorted case-insensitively, then by bytes: the upper-case spelling wins.
        assert_eq!(files, ["A.MAP"]);
        assert_eq!(repo.skipped, 5);
    }

    #[test]
    fn chunks_cover_the_file_exactly() {
        let tmp = TempDir::new("chunks");
        let data: Vec<u8> = (0..CHUNK_MAX + 10).map(|i| (i * 7 % 256) as u8).collect();
        write(&tmp.0.join("M/m.map"), &data);
        write(&tmp.0.join("M/empty.ini"), b"");
        let repo = scan(&tmp.0, &mut HashCache::default());
        let f = repo.file("M", "m.map").unwrap().clone();
        let (a, eof_a) = read_chunk(&tmp.0, "M", &f, 0).unwrap();
        assert_eq!((a.len(), eof_a), (CHUNK_MAX, false));
        let (b, eof_b) = read_chunk(&tmp.0, "M", &f, CHUNK_MAX as u64).unwrap();
        assert_eq!((b.len(), eof_b), (10, true));
        assert_eq!([a, b].concat(), data);
        let (c, eof_c) = read_chunk(&tmp.0, "M", &f, f.size).unwrap();
        assert!(c.is_empty() && eof_c);
        assert!(matches!(read_chunk(&tmp.0, "M", &f, f.size + 1), Err(ChunkError::BadOffset)));
        let e = repo.file("M", "empty.ini").unwrap().clone();
        assert_eq!(read_chunk(&tmp.0, "M", &e, 0).unwrap(), (Vec::new(), true));
        // A file that changed size after the scan is reported.
        write(&tmp.0.join("M/m.map"), b"short");
        assert!(matches!(read_chunk(&tmp.0, "M", &f, 0), Err(ChunkError::Changed)));
        // Unsafe manifest entries are refused even if they slipped in.
        let evil = MapFile {
            path: "../secret".into(),
            size: 1,
            blake3_hex: String::new(),
        };
        assert!(read_chunk(&tmp.0, "M", &evil, 0).is_err());
        assert!(read_chunk(&tmp.0, "..", &f, 0).is_err());
    }

    #[test]
    fn listing_is_truncated_to_one_message() {
        let file = |i: usize| MapFile {
            path: format!("file-{i}.map"),
            size: 1,
            blake3_hex: "0".repeat(64),
        };
        let maps: Vec<MapInfo> = (0..600)
            .map(|i| MapInfo::new(format!("Map {i:04}"), vec![file(i)]))
            .collect();
        let repo = MapRepo::from_maps(maps, 0, None);
        assert!(repo.truncated);
        assert!(repo.listing.len() <= MAX_MSG_LEN);
        assert!(repo.maps.len() > 100 && repo.maps.len() < 600);
        let msg = ServerMsg::from_json(&repo.listing).unwrap();
        assert_eq!(msg, ServerMsg::Maps { maps: repo.maps.clone() });
    }
}
