//! The content-addressed store: `store\<md5>`, one file per distinct content.
//!
//! * A file enters only after its MD5 was computed over exactly the bytes written
//!   (copy into a temporary sibling while hashing, flush, rename): a store entry
//!   always has the content its name says.
//! * Entries are read-only (spec 10 R10-1) and owned by Beacon; instances link to
//!   them. Beacon never links to files it does not own.
//! * `store\index.json` records size and BLAKE3 per entry (the fingerprint of an
//!   instance can be seeded from it). An entry whose file vanished or changed size
//!   is forgotten; a file without an index entry is verified once.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

use beacon_proto::control::{is_md5_hex, MAX_CONFIG_FILE_SIZE};
use serde::{Deserialize, Serialize};

use super::fsx;
use super::hash::{self, copy_and_hash, Digests, HashError};
use super::EMPTY_MD5;
use crate::util;

const INDEX_FILE: &str = "index.json";
const INDEX_VERSION: u32 = 1;
const MAX_INDEX_BYTES: u64 = 32 << 20;

/// One stored file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFile {
    /// `store\<md5>`.
    pub path: PathBuf,
    /// Size.
    pub size: u64,
    /// BLAKE3, hex.
    pub blake3: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct IndexEntry {
    size: u64,
    blake3: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Index {
    version: u32,
    entries: BTreeMap<String, IndexEntry>,
}

/// Why a file could not be stored.
#[derive(Debug)]
pub enum StoreError {
    /// Reading or writing failed.
    Io(io::Error),
    /// The content's MD5 differs from the expected one.
    Mismatch {
        /// Expected MD5.
        expected: String,
        /// Actual MD5.
        actual: String,
    },
    /// The size differs from the expected one.
    WrongSize {
        /// Expected size.
        expected: u64,
        /// Actual size.
        actual: u64,
    },
    /// Not an MD5.
    BadMd5,
    /// Cancelled.
    Cancelled,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Mismatch { expected, actual } => write!(f, "MD5 mismatch (expected {expected}, got {actual})"),
            Self::WrongSize { expected, actual } => write!(f, "size mismatch (expected {expected}, got {actual})"),
            Self::BadMd5 => f.write_str("invalid MD5"),
            Self::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<HashError> for StoreError {
    fn from(e: HashError) -> Self {
        match e {
            HashError::Io(e) => Self::Io(e),
            HashError::Cancelled => Self::Cancelled,
            HashError::TooLarge(n) => Self::WrongSize { expected: n, actual: n.saturating_add(1) },
        }
    }
}

/// The store.
#[derive(Debug)]
pub struct Store {
    dir: PathBuf,
    index: Mutex<Index>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Store {
    /// Opens (and creates) the store folder.
    pub fn open(dir: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let index = util::read_bounded(&dir.join(INDEX_FILE), MAX_INDEX_BYTES)
            .ok()
            .and_then(|b| serde_json::from_slice::<Index>(&b).ok())
            .filter(|i| i.version == INDEX_VERSION)
            .unwrap_or_default();
        Ok(Self {
            dir: dir.to_path_buf(),
            index: Mutex::new(index),
        })
    }

    /// The store folder.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// `store\<md5>` (whether present or not).
    pub fn path_of(&self, md5: &str) -> PathBuf {
        self.dir.join(md5)
    }

    fn save_index(&self, index: &Index) {
        let mut index = index.clone();
        index.version = INDEX_VERSION;
        match serde_json::to_vec(&index) {
            Ok(json) => {
                if let Err(e) = util::write_atomic(&self.dir.join(INDEX_FILE), &json) {
                    tracing::warn!("cannot save the store index: {e}");
                }
            }
            Err(e) => tracing::warn!("cannot encode the store index: {e}"),
        }
    }

    fn record(&self, md5: &str, d: &Digests) {
        let mut index = lock(&self.index);
        index.entries.insert(
            md5.to_owned(),
            IndexEntry {
                size: d.size,
                blake3: d.blake3.clone(),
            },
        );
        self.save_index(&index);
    }

    /// The stored file with this MD5, if present and intact (size as recorded).
    /// A file without an index entry is verified once (and removed if wrong).
    pub fn get(&self, md5: &str) -> Option<StoredFile> {
        if !is_md5_hex(md5) {
            return None;
        }
        let path = self.path_of(md5);
        let meta = fs::metadata(&path).ok().filter(fs::Metadata::is_file);
        let entry = lock(&self.index).entries.get(md5).cloned();
        match (meta, entry) {
            (Some(meta), Some(e)) if meta.len() == e.size => Some(StoredFile {
                path,
                size: e.size,
                blake3: e.blake3,
            }),
            (Some(_), _) => {
                // Unknown or changed: verify (rare: a crash between rename and index).
                let ok = hash::hash_file(&path, &AtomicBool::new(false), &mut |_| {})
                    .ok()
                    .filter(|d| d.md5 == md5);
                match ok {
                    Some(d) => {
                        let _ = fsx::set_readonly(&path, true);
                        self.record(md5, &d);
                        Some(StoredFile {
                            path,
                            size: d.size,
                            blake3: d.blake3,
                        })
                    }
                    None => {
                        let _ = fsx::remove_file_force(&path);
                        self.forget(md5);
                        None
                    }
                }
            }
            (None, Some(_)) => {
                self.forget(md5);
                None
            }
            (None, None) => None,
        }
    }

    /// The size the index records (without touching the file).
    pub fn known_size(&self, md5: &str) -> Option<u64> {
        lock(&self.index).entries.get(md5).map(|e| e.size)
    }

    fn forget(&self, md5: &str) {
        let mut index = lock(&self.index);
        if index.entries.remove(md5).is_some() {
            self.save_index(&index);
        }
    }

    /// Copies `src` into the store, verifying MD5 (and the size, if known while
    /// it is not 0) on the bytes written. The source is only read.
    pub fn import_file(
        &self,
        src: &Path,
        md5: &str,
        expected_size: u64,
        cancel: &AtomicBool,
        on_bytes: &mut dyn FnMut(u64),
    ) -> Result<StoredFile, StoreError> {
        let mut input = File::open(src)?;
        self.import_reader(&mut input, md5, expected_size, cancel, on_bytes)
    }

    /// Like [`import_file`](Self::import_file) for any reader.
    pub fn import_reader(
        &self,
        input: &mut dyn io::Read,
        md5: &str,
        expected_size: u64,
        cancel: &AtomicBool,
        on_bytes: &mut dyn FnMut(u64),
    ) -> Result<StoredFile, StoreError> {
        if !is_md5_hex(md5) {
            return Err(StoreError::BadMd5);
        }
        if let Some(existing) = self.get(md5) {
            return Ok(existing);
        }
        let target = self.path_of(md5);
        let tmp = util::temp_sibling(&target, "import");
        let result = (|| {
            let file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            let mut out = BufWriter::with_capacity(hash::BUF_LEN, file);
            let limit = if expected_size > 0 { expected_size } else { MAX_CONFIG_FILE_SIZE };
            let digests = copy_and_hash(input, Some(&mut out as &mut dyn Write), limit, cancel, on_bytes)?;
            let file = out.into_inner().map_err(|e| e.into_error())?;
            file.sync_all()?;
            drop(file);
            self.adopt(&tmp, md5, expected_size, &digests)
        })();
        if result.is_err() {
            let _ = fsx::remove_file_force(&tmp);
        }
        result
    }

    /// Moves an already hashed file (same volume, e.g. a finished download) into
    /// the store if `digests` match `md5` and the expected size (0 = unknown).
    pub fn adopt(&self, file: &Path, md5: &str, expected_size: u64, digests: &Digests) -> Result<StoredFile, StoreError> {
        if digests.md5 != md5 {
            return Err(StoreError::Mismatch {
                expected: md5.to_owned(),
                actual: digests.md5.clone(),
            });
        }
        if expected_size > 0 && digests.size != expected_size {
            return Err(StoreError::WrongSize {
                expected: expected_size,
                actual: digests.size,
            });
        }
        let target = self.path_of(md5);
        if let Err(e) = fs::rename(file, &target) {
            // Another preparation stored it meanwhile: keep that one.
            if self.get(md5).is_some() {
                let _ = fsx::remove_file_force(file);
            } else {
                return Err(StoreError::Io(e));
            }
        }
        let _ = fsx::set_readonly(&target, true);
        self.record(md5, digests);
        Ok(StoredFile {
            path: target,
            size: digests.size,
            blake3: digests.blake3.clone(),
        })
    }

    /// Stores the empty file (no source needed).
    pub fn ensure_empty(&self) -> Result<StoredFile, StoreError> {
        self.import_reader(&mut io::empty(), EMPTY_MD5, 0, &AtomicBool::new(false), &mut |_| {})
    }

    /// Makes sure an entry is read-only again (a forced delete of an instance's
    /// hardlink clears the shared attribute).
    pub fn protect(&self, md5: &str) {
        let _ = fsx::set_readonly(&self.path_of(md5), true);
    }

    /// Removes an entry.
    pub fn remove(&self, md5: &str) -> io::Result<()> {
        fsx::remove_file_force(&self.path_of(md5))?;
        self.forget(md5);
        Ok(())
    }

    /// Every entry: `(md5, size)`.
    pub fn entries(&self) -> Vec<(String, u64)> {
        lock(&self.index)
            .entries
            .iter()
            .map(|(k, e)| (k.clone(), e.size))
            .collect()
    }

    /// Number of entries and their total size.
    pub fn usage(&self) -> (usize, u64) {
        let index = lock(&self.index);
        let bytes = index.entries.values().fold(0u64, |a, e| a.saturating_add(e.size));
        (index.entries.len(), bytes)
    }

    /// Removes leftover temporary files (crash during an import).
    pub fn sweep_temporaries(&self) {
        if let Ok(entries) = fs::read_dir(&self.dir) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') && name.contains(".import-") {
                    let _ = fsx::remove_file_force(&e.path());
                }
            }
        }
    }
}

/// Writes `data` to a new file (test helper and small imports).
pub fn write_new(path: &Path, data: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut f = File::create(path)?;
    f.write_all(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mods::hash::md5_hex;

    fn temp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("beacon-store-{tag}-{}", std::process::id()));
        let _ = fsx::remove_tree(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn import_verifies_and_protects() {
        let d = temp("import");
        let store = Store::open(&d.join("store")).unwrap();
        let src = d.join("src.big");
        write_new(&src, b"hello big").unwrap();
        let md5 = md5_hex(b"hello big");
        let cancel = AtomicBool::new(false);
        let mut n = 0;
        let f = store.import_file(&src, &md5, 9, &cancel, &mut |b| n += b).unwrap();
        assert_eq!((f.size, n), (9, 9));
        assert_eq!(fs::read(&f.path).unwrap(), b"hello big");
        assert!(fs::metadata(&f.path).unwrap().permissions().readonly());
        assert_eq!(fs::read(&src).unwrap(), b"hello big", "the source is untouched");
        assert!(!fs::metadata(&src).unwrap().permissions().readonly());
        // Wrong MD5 / size: nothing stored, no temporary file left.
        assert!(matches!(
            store.import_file(&src, &"0".repeat(32), 0, &cancel, &mut |_| {}),
            Err(StoreError::Mismatch { .. })
        ));
        let other = d.join("other.big");
        write_new(&other, b"other").unwrap();
        let other_md5 = md5_hex(b"other");
        assert!(matches!(
            store.import_file(&other, &other_md5, 4, &cancel, &mut |_| {}),
            Err(StoreError::WrongSize { .. })
        ));
        assert!(store.get(&other_md5).is_none());
        assert!(matches!(store.import_file(&src, "bad", 0, &cancel, &mut |_| {}), Err(StoreError::BadMd5)));
        let names: Vec<String> = fs::read_dir(store.dir()).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(names.len(), 2, "{names:?}");
        // The index survives a reopen; a damaged entry is forgotten.
        let store = Store::open(&d.join("store")).unwrap();
        assert_eq!(store.get(&md5).unwrap().blake3, beacon_proto::blake3::hash(b"hello big").to_hex().to_string());
        assert_eq!(store.usage(), (1, 9));
        assert_eq!(store.known_size(&md5), Some(9));
        fsx::set_readonly(&store.path_of(&md5), false).unwrap();
        write_new(&store.path_of(&md5), b"tampered").unwrap();
        assert!(store.get(&md5).is_none(), "changed size: verified and removed");
        assert!(!store.path_of(&md5).exists());
        // Empty content needs no source.
        let empty = store.ensure_empty().unwrap();
        assert_eq!(empty.size, 0);
        store.remove(EMPTY_MD5).unwrap();
        assert!(store.get(EMPTY_MD5).is_none());
        let _ = fsx::remove_tree(&d);
    }

    #[test]
    fn unindexed_files_are_verified_once() {
        let d = temp("unindexed");
        let store = Store::open(&d).unwrap();
        let md5 = md5_hex(b"abc");
        write_new(&store.path_of(&md5), b"abc").unwrap();
        assert_eq!(store.get(&md5).unwrap().size, 3);
        write_new(&store.path_of(&"1".repeat(32)), b"abc").unwrap();
        assert!(store.get(&"1".repeat(32)).is_none());
        assert!(!store.path_of(&"1".repeat(32)).exists());
        write_new(&d.join(".x.import-1-2"), b"junk").unwrap();
        store.sweep_temporaries();
        assert!(!d.join(".x.import-1-2").exists());
        let _ = fsx::remove_tree(&d);
    }
}
