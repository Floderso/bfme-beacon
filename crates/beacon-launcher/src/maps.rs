//! Map synchronisation (architecture §8): the server's map repository
//! (`maps/<MapName>/<file>`, manifest `(path, size, BLAKE3)`) is mirrored into the
//! user's BFME `Maps` folder.
//!
//! * Paths from the server are validated ([`is_safe_file_name`] for map names,
//!   [`is_safe_rel_path`] for files, depth ≤ 2) and existing folders below `Maps`
//!   must not be links or junctions.
//! * Missing files are downloaded chunk-wise into a temporary file next to the
//!   target, checked (size + BLAKE3) and renamed into place (atomic).
//! * `beacon-maps.json` (in the `Maps` folder) records what Beacon installed. A file
//!   Beacon did not install is never overwritten or deleted: if it differs from the
//!   server's version the map is reported as a conflict. A file Beacon installed and
//!   the user did not change is updated when the server has a new version.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use beacon_proto::blake3;
use beacon_proto::control::{is_safe_file_name, is_safe_rel_path, Chunk, ErrorCode, MapFile, MapInfo};
use serde::{Deserialize, Serialize};

use crate::util;

/// Record of the files Beacon installed (in the `Maps` folder).
pub const RECORD_FILE: &str = "beacon-maps.json";
/// Largest map file accepted.
pub const MAX_MAP_FILE: u64 = 256 << 20;
/// Most maps handled from one listing.
pub const MAX_MAPS: usize = 2000;
/// Most files per map.
pub const MAX_FILES_PER_MAP: usize = 256;
const MAX_RECORD_LEN: u64 = 16 << 20;
const RECORD_VERSION: u32 = 1;

/// Files Beacon installed, keyed by `<map>/<path>` (`/`-separated, as listed).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledRecord {
    /// Format version.
    pub version: u32,
    /// Installed files.
    pub files: BTreeMap<String, InstalledFile>,
}

/// One installed file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledFile {
    /// Size written.
    pub size: u64,
    /// BLAKE3 written, lowercase hex.
    pub blake3: String,
    /// When (ms since the Unix epoch).
    pub installed_at_ms: u64,
}

fn record_key(map: &str, path: &str) -> String {
    format!("{map}/{}", path.replace('\\', "/"))
}

impl InstalledRecord {
    /// Loads `<maps_dir>/beacon-maps.json` (empty if missing or unreadable).
    pub fn load(maps_dir: &Path) -> Self {
        util::read_bounded(&maps_dir.join(RECORD_FILE), MAX_RECORD_LEN)
            .ok()
            .and_then(|t| serde_json::from_slice::<Self>(&t).ok())
            .unwrap_or_default()
    }

    /// Saves it atomically.
    pub fn save(&self, maps_dir: &Path) -> io::Result<()> {
        let mut rec = self.clone();
        rec.version = RECORD_VERSION;
        let json = serde_json::to_vec_pretty(&rec).map_err(io::Error::other)?;
        util::write_atomic(&maps_dir.join(RECORD_FILE), &json)
    }
}

/// What to do with one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// The local file is identical.
    Keep,
    /// Missing: download.
    Download,
    /// Installed by Beacon, unchanged by the user, outdated: download and replace.
    Replace,
    /// A different file Beacon did not install (or the user changed): left alone.
    Conflict,
}

/// One file of a map plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePlan {
    /// The server's manifest entry.
    pub file: MapFile,
    /// Local path.
    pub target: PathBuf,
    /// Decision.
    pub action: Action,
}

/// The plan for one map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapPlan {
    /// Map name.
    pub name: String,
    /// Sum of the file sizes.
    pub total_size: u64,
    /// Files (empty if the map was rejected).
    pub files: Vec<FilePlan>,
    /// Why the map was rejected (unsafe name/path, too large, links).
    pub invalid: Option<String>,
}

/// Overall state of a map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MapState {
    /// All files present and identical.
    Installed,
    /// Files missing or outdated: a sync downloads them.
    Missing,
    /// A local file differs and was not installed by Beacon.
    Conflict,
    /// The server's entry was rejected.
    Invalid,
    /// Being downloaded.
    Downloading,
    /// The last download failed.
    Failed,
}

impl MapPlan {
    /// Bytes still to download.
    pub fn bytes_needed(&self) -> u64 {
        self.files
            .iter()
            .filter(|f| matches!(f.action, Action::Download | Action::Replace))
            .fold(0u64, |acc, f| acc.saturating_add(f.file.size))
    }

    /// The map's state according to the plan.
    pub fn state(&self) -> MapState {
        if self.invalid.is_some() {
            MapState::Invalid
        } else if self.files.iter().any(|f| f.action == Action::Conflict) {
            MapState::Conflict
        } else if self.files.iter().any(|f| f.action != Action::Keep) {
            MapState::Missing
        } else {
            MapState::Installed
        }
    }
}

/// The local path of a map file, or why it is rejected.
pub fn local_path(maps_dir: &Path, map: &str, file: &str) -> Result<PathBuf, String> {
    if !is_safe_file_name(map) {
        return Err(format!("unsafe map name {map:?}"));
    }
    if !is_safe_rel_path(file) {
        return Err(format!("unsafe file path {file:?}"));
    }
    let mut path = maps_dir.join(map);
    for part in file.split(['/', '\\']) {
        path.push(part);
    }
    Ok(path)
}

/// Refuses links/junctions (and non-directories) among the existing folders between
/// `maps_dir` and `target`.
fn check_no_links(maps_dir: &Path, target: &Path) -> Result<(), String> {
    let Ok(rel) = target.strip_prefix(maps_dir) else {
        return Err("path outside the maps folder".to_owned());
    };
    let mut cur = maps_dir.to_path_buf();
    let mut parts = rel.components().peekable();
    while let Some(part) = parts.next() {
        cur.push(part);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(format!("{} is a link", cur.display()));
            }
            Ok(m) if parts.peek().is_some() && !m.is_dir() => {
                return Err(format!("{} is not a folder", cur.display()));
            }
            _ => {}
        }
    }
    Ok(())
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// BLAKE3 (hex) and size of a local file.
pub fn hash_local(path: &Path) -> io::Result<(u64, String)> {
    let mut f = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut size = 0u64;
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.update(buf.get(..n).unwrap_or_default());
        size = size.saturating_add(u64::try_from(n).unwrap_or(0));
    }
    Ok((size, hasher.finalize().to_hex().to_string()))
}

fn plan_file(maps_dir: &Path, map: &str, file: &MapFile, record: &InstalledRecord) -> Result<FilePlan, String> {
    let target = local_path(maps_dir, map, &file.path)?;
    if file.size > MAX_MAP_FILE {
        return Err(format!("{} is too large ({} bytes)", file.path, file.size));
    }
    if !is_hex64(&file.blake3_hex) {
        return Err(format!("{} has an invalid hash", file.path));
    }
    check_no_links(maps_dir, &target)?;
    let action = match fs::symlink_metadata(&target) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Action::Download,
        Err(_) => Action::Conflict,
        Ok(m) if !m.is_file() => Action::Conflict,
        Ok(_) => match hash_local(&target) {
            Err(_) => Action::Conflict,
            Ok((size, hash)) if size == file.size && hash.eq_ignore_ascii_case(&file.blake3_hex) => Action::Keep,
            Ok((size, hash)) => match record.files.get(&record_key(map, &file.path)) {
                Some(r) if r.size == size && r.blake3.eq_ignore_ascii_case(&hash) => Action::Replace,
                _ => Action::Conflict,
            },
        },
    };
    Ok(FilePlan {
        file: file.clone(),
        target,
        action,
    })
}

/// Compares the server's listing with the local `Maps` folder (blocking: hashes
/// existing files).
pub fn plan(maps: &[MapInfo], maps_dir: &Path, record: &InstalledRecord) -> Vec<MapPlan> {
    maps.iter()
        .take(MAX_MAPS)
        .map(|m| {
            let total_size = m.files.iter().fold(0u64, |a, f| a.saturating_add(f.size));
            let files: Result<Vec<FilePlan>, String> = if m.files.len() > MAX_FILES_PER_MAP {
                Err(format!("too many files ({})", m.files.len()))
            } else if m.files.is_empty() {
                Err("no files".to_owned())
            } else {
                m.files.iter().map(|f| plan_file(maps_dir, &m.name, f, record)).collect()
            };
            match files {
                Ok(files) => MapPlan {
                    name: m.name.clone(),
                    total_size,
                    files,
                    invalid: None,
                },
                Err(why) => MapPlan {
                    name: m.name.clone(),
                    total_size,
                    files: Vec::new(),
                    invalid: Some(why),
                },
            }
        })
        .collect()
}

/// Errors of fetching chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkError {
    /// The server answered with an error.
    Server(ErrorCode, String),
    /// No answer in time.
    Timeout,
    /// Not connected (any more).
    Disconnected,
}

impl fmt::Display for ChunkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Server(code, text) => write!(f, "server error {code:?}: {text}"),
            Self::Timeout => f.write_str("no answer from the server"),
            Self::Disconnected => f.write_str("not connected"),
        }
    }
}

/// Where chunks come from (the control connection; fakes in tests).
pub trait ChunkSource {
    /// One chunk of `map`/`file` starting at `offset`.
    fn get(&mut self, map: &str, file: &str, offset: u64) -> impl Future<Output = Result<Chunk, ChunkError>> + Send;
}

/// Errors of a file download.
#[derive(Debug)]
pub enum SyncError {
    /// Fetching failed.
    Chunk(ChunkError),
    /// The server sent something inconsistent (wrong offset, too much data, bad
    /// base64, size or hash mismatch).
    Corrupt(String),
    /// The target appeared or changed meanwhile and is not Beacon's.
    Conflict(PathBuf),
    /// File system error.
    Io(PathBuf, io::Error),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chunk(e) => e.fmt(f),
            Self::Corrupt(why) => write!(f, "download corrupt: {why}"),
            Self::Conflict(p) => write!(f, "{} changed meanwhile; left alone", p.display()),
            Self::Io(p, e) => write!(f, "{}: {e}", p.display()),
        }
    }
}

impl std::error::Error for SyncError {}

/// How often a rate-limited chunk request is retried.
const RATE_LIMIT_RETRIES: u32 = 5;

async fn fetch_into<S: ChunkSource>(
    source: &mut S,
    map: &str,
    file: &MapFile,
    out: &mut File,
    on_bytes: &mut (dyn FnMut(u64) + Send),
) -> Result<String, SyncError> {
    let mut hasher = blake3::Hasher::new();
    let mut offset = 0u64;
    let mut retries = 0;
    loop {
        let chunk = match source.get(map, &file.path, offset).await {
            Ok(c) => c,
            Err(ChunkError::Server(ErrorCode::RateLimited, _)) if retries < RATE_LIMIT_RETRIES => {
                retries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(500 * u64::from(retries))).await;
                continue;
            }
            Err(e) => return Err(SyncError::Chunk(e)),
        };
        if chunk.map != map || chunk.file != file.path || chunk.offset != offset {
            return Err(SyncError::Corrupt(format!(
                "unexpected chunk {}/{}@{} (wanted @{offset})",
                chunk.map, chunk.file, chunk.offset
            )));
        }
        let data = chunk.data().map_err(|e| SyncError::Corrupt(e.to_string()))?;
        let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let end = offset.saturating_add(len);
        if end > file.size {
            return Err(SyncError::Corrupt(format!("more data than {} bytes", file.size)));
        }
        if data.is_empty() && !chunk.eof {
            return Err(SyncError::Corrupt("empty chunk".to_owned()));
        }
        out.write_all(&data).map_err(|e| SyncError::Io(PathBuf::from(&file.path), e))?;
        hasher.update(&data);
        offset = end;
        on_bytes(len);
        if chunk.eof {
            break;
        }
    }
    if offset != file.size {
        return Err(SyncError::Corrupt(format!("{offset} of {} bytes", file.size)));
    }
    let hash = hasher.finalize().to_hex().to_string();
    if !hash.eq_ignore_ascii_case(&file.blake3_hex) {
        return Err(SyncError::Corrupt(format!("{} has a wrong BLAKE3", file.path)));
    }
    Ok(hash)
}

/// Downloads one planned file (`Download` or `Replace`) and records it.
pub async fn download_file<S: ChunkSource>(
    source: &mut S,
    maps_dir: &Path,
    map: &str,
    plan: &FilePlan,
    record: &mut InstalledRecord,
    on_bytes: &mut (dyn FnMut(u64) + Send),
) -> Result<(), SyncError> {
    let target = &plan.target;
    let io_err = |e| SyncError::Io(target.clone(), e);
    let dir = target.parent().unwrap_or(maps_dir);
    fs::create_dir_all(dir).map_err(io_err)?;
    check_no_links(maps_dir, target).map_err(|_| SyncError::Conflict(target.clone()))?;
    let tmp = util::temp_sibling(target, "beacon-part");
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(io_err)?;
    let result = async {
        let hash = fetch_into(source, map, &plan.file, &mut out, on_bytes).await?;
        out.sync_all().map_err(io_err)?;
        // Re-check the target right before replacing it.
        match (plan.action, fs::symlink_metadata(target)) {
            (_, Err(e)) if e.kind() == io::ErrorKind::NotFound => {}
            (Action::Replace, Ok(m)) if m.is_file() => {
                let (size, local) = hash_local(target).map_err(io_err)?;
                let ours = record
                    .files
                    .get(&record_key(map, &plan.file.path))
                    .is_some_and(|r| r.size == size && r.blake3.eq_ignore_ascii_case(&local));
                if !ours {
                    return Err(SyncError::Conflict(target.clone()));
                }
            }
            _ => return Err(SyncError::Conflict(target.clone())),
        }
        drop(out);
        fs::rename(&tmp, target).map_err(io_err)?;
        Ok(hash)
    }
    .await;
    let hash = match result {
        Ok(h) => h,
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
    };
    record.files.insert(
        record_key(map, &plan.file.path),
        InstalledFile {
            size: plan.file.size,
            blake3: hash,
            installed_at_ms: util::unix_ms(),
        },
    );
    record.save(maps_dir).map_err(|e| SyncError::Io(maps_dir.join(RECORD_FILE), e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_proto::control::CHUNK_MAX;
    use std::collections::HashMap;

    struct FakeSource {
        files: HashMap<(String, String), Vec<u8>>,
        requests: usize,
        rate_limit_first: bool,
        corrupt: bool,
    }

    impl ChunkSource for FakeSource {
        async fn get(&mut self, map: &str, file: &str, offset: u64) -> Result<Chunk, ChunkError> {
            self.requests += 1;
            if self.rate_limit_first && self.requests == 1 {
                return Err(ChunkError::Server(ErrorCode::RateLimited, "slow".into()));
            }
            let data = self
                .files
                .get(&(map.to_owned(), file.to_owned()))
                .ok_or(ChunkError::Server(ErrorCode::UnknownFile, "?".into()))?;
            let start = usize::try_from(offset).unwrap().min(data.len());
            let end = (start + CHUNK_MAX).min(data.len());
            let mut piece = data[start..end].to_vec();
            if self.corrupt {
                if let Some(b) = piece.first_mut() {
                    *b ^= 1;
                }
            }
            Ok(Chunk::new(map, file, offset, &piece, end == data.len()).unwrap())
        }
    }

    fn info(name: &str, files: &[(&str, &[u8])]) -> MapInfo {
        MapInfo::new(
            name,
            files
                .iter()
                .map(|(p, d)| MapFile {
                    path: (*p).to_owned(),
                    size: d.len() as u64,
                    blake3_hex: blake3::hash(d).to_hex().to_string(),
                })
                .collect(),
        )
    }

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("beacon-maps-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn path_checks() {
        let m = Path::new(r"C:\Maps");
        assert!(local_path(m, "Helms Deep", "Helms Deep.map").is_ok());
        assert_eq!(
            local_path(m, "A", "art/x.tga").unwrap(),
            m.join("A").join("art").join("x.tga")
        );
        for (map, file) in [
            ("..", "x.map"),
            ("A", "../x.map"),
            ("A", "C:\\x.map"),
            ("A", "\\\\srv\\x"),
            ("CON", "x.map"),
            ("A", "a/b/c.map"),
            ("A/B", "x.map"),
            ("A", "x.map:ads"),
            ("A", ""),
        ] {
            assert!(local_path(m, map, file).is_err(), "{map:?} {file:?}");
        }
    }

    #[tokio::test]
    async fn sync_downloads_verifies_and_respects_user_files() {
        let maps_dir = temp("sync");
        let big: Vec<u8> = (0..CHUNK_MAX * 2 + 123).map(|i| (i % 251) as u8).collect();
        let listing = vec![
            info("Alpha", &[("Alpha.map", &big), ("map.ini", b"ini")]),
            info("Beta", &[("Beta.map", b"server beta")]),
            info("..", &[("x.map", b"evil")]),
        ];
        let mut src = FakeSource {
            files: HashMap::new(),
            requests: 0,
            rate_limit_first: true,
            corrupt: false,
        };
        src.files.insert(("Alpha".into(), "Alpha.map".into()), big.clone());
        src.files.insert(("Alpha".into(), "map.ini".into()), b"ini".to_vec());
        src.files.insert(("Beta".into(), "Beta.map".into()), b"server beta".to_vec());
        // The user's own Beta differs: never overwritten.
        fs::create_dir_all(maps_dir.join("Beta")).unwrap();
        fs::write(maps_dir.join("Beta").join("Beta.map"), b"user beta").unwrap();

        let mut record = InstalledRecord::load(&maps_dir);
        let plans = plan(&listing, &maps_dir, &record);
        let states: Vec<MapState> = plans.iter().map(MapPlan::state).collect();
        assert_eq!(states, [MapState::Missing, MapState::Conflict, MapState::Invalid]);
        assert_eq!(plans[0].bytes_needed(), big.len() as u64 + 3);

        let mut done = 0u64;
        for f in plans[0].files.iter().filter(|f| f.action == Action::Download) {
            download_file(&mut src, &maps_dir, "Alpha", f, &mut record, &mut |n| done += n)
                .await
                .unwrap();
        }
        assert_eq!(done, big.len() as u64 + 3);
        assert_eq!(fs::read(maps_dir.join("Alpha").join("Alpha.map")).unwrap(), big);
        assert_eq!(fs::read(maps_dir.join("Beta").join("Beta.map")).unwrap(), b"user beta");
        let reloaded = InstalledRecord::load(&maps_dir);
        assert!(reloaded.files.contains_key("Alpha/Alpha.map"));
        assert!(reloaded.files.contains_key("Alpha/map.ini"));
        assert_eq!(plan(&listing, &maps_dir, &reloaded)[0].state(), MapState::Installed);

        // A new server version of a file Beacon installed replaces it ...
        let listing2 = vec![info("Alpha", &[("Alpha.map", &big), ("map.ini", b"ini v2")])];
        src.files.insert(("Alpha".into(), "map.ini".into()), b"ini v2".to_vec());
        let plans = plan(&listing2, &maps_dir, &reloaded);
        let ini = plans[0].files.iter().find(|f| f.file.path == "map.ini").unwrap();
        assert_eq!(ini.action, Action::Replace);
        let mut record = reloaded;
        download_file(&mut src, &maps_dir, "Alpha", ini, &mut record, &mut |_| {}).await.unwrap();
        assert_eq!(fs::read(maps_dir.join("Alpha").join("map.ini")).unwrap(), b"ini v2");
        // ... but not once the user edited it.
        fs::write(maps_dir.join("Alpha").join("map.ini"), b"user edit").unwrap();
        let listing3 = vec![info("Alpha", &[("Alpha.map", &big), ("map.ini", b"ini v3")])];
        assert_eq!(plan(&listing3, &maps_dir, &record)[0].state(), MapState::Conflict);

        // A corrupt transfer is rejected and leaves nothing behind.
        src.corrupt = true;
        let gamma = info("Gamma", &[("Gamma.map", b"gamma data")]);
        src.files.insert(("Gamma".into(), "Gamma.map".into()), b"gamma data".to_vec());
        let plans = plan(&[gamma], &maps_dir, &record);
        let err = download_file(&mut src, &maps_dir, "Gamma", &plans[0].files[0], &mut record, &mut |_| {})
            .await
            .unwrap_err();
        assert!(matches!(err, SyncError::Corrupt(_)), "{err}");
        assert_eq!(fs::read_dir(maps_dir.join("Gamma")).unwrap().count(), 0);
        let _ = fs::remove_dir_all(&maps_dir);
    }

    #[test]
    fn invalid_manifests() {
        let maps_dir = temp("invalid");
        let mut m = info("A", &[("A.map", b"x")]);
        m.files[0].size = MAX_MAP_FILE + 1;
        let mut h = info("B", &[("B.map", b"x")]);
        h.files[0].blake3_hex = "zz".into();
        let empty = MapInfo::new("C", vec![]);
        let plans = plan(&[m, h, empty], &maps_dir, &InstalledRecord::default());
        assert!(plans.iter().all(|p| p.state() == MapState::Invalid));
        // A file where a folder is expected.
        fs::write(maps_dir.join("D"), b"file").unwrap();
        let plans = plan(&[info("D", &[("D.map", b"x")])], &maps_dir, &InstalledRecord::default());
        assert_eq!(plans[0].state(), MapState::Invalid);
        let _ = fs::remove_dir_all(&maps_dir);
    }
}
