//! Instance folders: `instances\<id>\game\` (and `mod\` for a type-1 package)
//! hold exactly a configuration's files, as NTFS hardlinks into the store, so
//! BFME can start from there with the AIO's file set and mount order while the
//! real installation stays untouched (spec 10 §6.2, R10-1).
//!
//! * Store and instances live below one root, so they share a volume; a probe
//!   link decides between hardlinks and copies ([`probe_link_mode`]). Copies are
//!   the fallback (FAT32/exFAT, network shares, another volume) and cost space.
//! * Building is incremental and in place: files that already match are kept,
//!   missing or different ones are linked again (temporary sibling + rename),
//!   anything else is removed – except Beacon's hook DLL and the game's own
//!   `UserData\` folder (user maps with `UseLocalUserMaps`).
//! * `instance.json` (beside `game\`, so the game's recursive `*.big` scan never
//!   sees it) says whether the instance is complete; it is written last.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use beacon_proto::control::{is_valid_config_id, FileDir, GameConfig, RESERVED_HOOK_NAME};
use serde::{Deserialize, Serialize};

use super::fsx;
use super::store::Store;
use super::{join_package_path, MAX_RECORD_BYTES};
use crate::util;

/// The record beside `game\`.
pub const RECORD_FILE: &str = "instance.json";
/// The game folder of an instance.
pub const GAME_DIR: &str = "game";
/// The `-mod` folder of an instance.
pub const MOD_DIR: &str = "mod";
/// A folder below `game\` the game itself writes (user maps); never removed.
pub const USERDATA_DIR: &str = "userdata";
const RECORD_VERSION: u32 = 1;

/// How the instance's files refer to the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkMode {
    /// NTFS hardlinks (no extra space).
    Hardlink,
    /// Copies (hardlinks are not possible here).
    Copy,
}

/// `instance.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceRecord {
    /// Format version.
    pub version: u32,
    /// Configuration id (= folder name).
    pub id: String,
    /// Every file is in place.
    pub complete: bool,
    /// How the files were placed.
    pub link_mode: LinkMode,
    /// Selected package (guid).
    pub guid: String,
    /// Its version.
    pub package_version: String,
    /// Display name.
    pub name: String,
    /// Language variant.
    pub language: String,
    /// Number of files.
    pub files: usize,
    /// Their total size.
    pub bytes: u64,
    /// When it was (re)built (ms since the Unix epoch).
    pub built_ms: u64,
    /// The store entries it uses (for clean-ups).
    pub md5s: Vec<String>,
}

/// A usable instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    /// `instances\<id>`.
    pub root: PathBuf,
    /// `instances\<id>\game` (start BFME here).
    pub game_dir: PathBuf,
    /// `instances\<id>\mod` for a type-1 package (pass with `-mod`).
    pub mod_dir: Option<PathBuf>,
    /// The record.
    pub record: InstanceRecord,
}

/// Why an instance could not be built.
#[derive(Debug)]
pub enum InstanceError {
    /// A file system operation failed.
    Io(PathBuf, io::Error),
    /// A file of the configuration is not in the store.
    NotInStore(String),
    /// The configuration id is malformed.
    BadId,
    /// Cancelled.
    Cancelled,
}

impl fmt::Display for InstanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(p, e) => write!(f, "{}: {e}", p.display()),
            Self::NotInStore(path) => write!(f, "{path} is not in Beacon's store"),
            Self::BadId => f.write_str("invalid configuration id"),
            Self::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for InstanceError {}

/// Progress of [`build`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BuildProgress {
    /// Files placed or checked.
    pub files_done: usize,
    /// Files in total.
    pub files_total: usize,
    /// Bytes placed or checked.
    pub bytes_done: u64,
    /// Bytes in total.
    pub bytes_total: u64,
}

/// `instances\<id>`.
pub fn root_of(instances: &Path, id: &str) -> PathBuf {
    instances.join(id)
}

/// Tries one hardlink from the store into the instances folder.
pub fn probe_link_mode(store_dir: &Path, instances_dir: &Path) -> (LinkMode, Option<String>) {
    let src = util::temp_sibling(&store_dir.join("probe"), "probe");
    let dst = util::temp_sibling(&instances_dir.join("probe"), "probe");
    let result = (|| {
        fs::create_dir_all(store_dir)?;
        fs::create_dir_all(instances_dir)?;
        fs::write(&src, b"beacon")?;
        fs::hard_link(&src, &dst)
    })();
    let _ = fsx::remove_file_force(&dst);
    let _ = fsx::remove_file_force(&src);
    match result {
        Ok(()) => (LinkMode::Hardlink, None),
        Err(e) => {
            let why = match e.raw_os_error() {
                // ERROR_NOT_SAME_DEVICE
                Some(17) => "store and instances are on different volumes".to_owned(),
                // ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED
                Some(1) | Some(50) => "the file system does not support hardlinks (FAT32/exFAT?)".to_owned(),
                _ => format!("hardlinks failed: {e}"),
            };
            (LinkMode::Copy, Some(why))
        }
    }
}

/// The record of an instance folder, if readable.
pub fn load_record(root: &Path) -> Option<InstanceRecord> {
    util::read_bounded(&root.join(RECORD_FILE), MAX_RECORD_BYTES)
        .ok()
        .and_then(|b| serde_json::from_slice::<InstanceRecord>(&b).ok())
        .filter(|r| r.version == RECORD_VERSION)
}

fn save_record(root: &Path, record: &InstanceRecord) -> Result<(), InstanceError> {
    let json = serde_json::to_vec_pretty(record).map_err(|e| InstanceError::Io(root.to_path_buf(), io::Error::other(e)))?;
    util::write_atomic(&root.join(RECORD_FILE), &json).map_err(|e| InstanceError::Io(root.join(RECORD_FILE), e))
}

fn dir_of(root: &Path, dir: FileDir) -> PathBuf {
    root.join(match dir {
        FileDir::Game => GAME_DIR,
        FileDir::Mod => MOD_DIR,
    })
}

fn instance_of(root: &Path, record: InstanceRecord, has_mod: bool) -> Instance {
    Instance {
        root: root.to_path_buf(),
        game_dir: root.join(GAME_DIR),
        mod_dir: has_mod.then(|| root.join(MOD_DIR)),
        record,
    }
}

/// The instance of `config` if it is complete: the record says so and every file
/// exists with the expected size (a quick check by metadata).
pub fn ready(instances: &Path, config: &GameConfig, store: &Store) -> Option<Instance> {
    let root = root_of(instances, &config.id);
    let record = load_record(&root).filter(|r| r.complete && r.id == config.id)?;
    for f in &config.files {
        let expected = if f.size > 0 { Some(f.size) } else { store.known_size(&f.md5) };
        let meta = fs::metadata(join_package_path(&dir_of(&root, f.dir), &f.path)).ok()?;
        if !meta.is_file() || expected.is_some_and(|s| s != meta.len()) {
            return None;
        }
    }
    Some(instance_of(&root, record, config.has_mod_dir()))
}

fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    let mtime = |m: &fs::Metadata| m.modified().ok().unwrap_or(SystemTime::UNIX_EPOCH);
    a.is_file() && a.len() == b.len() && mtime(a) == mtime(b)
}

/// Builds (or repairs) the instance of `config` from the store. Every file must
/// be in the store already. `mode` is the probed link mode; a failing hardlink
/// switches the rest to copies (the returned record says which mode was used,
/// `fallback` gets the reason).
pub fn build(
    store: &Store,
    instances: &Path,
    config: &GameConfig,
    mode: LinkMode,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&BuildProgress),
    fallback: &mut Option<String>,
) -> Result<Instance, InstanceError> {
    if !is_valid_config_id(&config.id) {
        return Err(InstanceError::BadId);
    }
    let root = root_of(instances, &config.id);
    let io_err = |p: &Path| {
        let p = p.to_path_buf();
        move |e| InstanceError::Io(p, e)
    };
    fs::create_dir_all(&root).map_err(io_err(&root))?;
    let mut sources = Vec::with_capacity(config.files.len());
    for f in &config.files {
        let stored = store.get(&f.md5).ok_or_else(|| InstanceError::NotInStore(f.path.clone()))?;
        sources.push(stored);
    }
    let mut md5s: Vec<String> = config.files.iter().map(|f| f.md5.clone()).collect();
    md5s.sort();
    md5s.dedup();
    let mut record = InstanceRecord {
        version: RECORD_VERSION,
        id: config.id.clone(),
        complete: false,
        link_mode: mode,
        guid: config.guid.clone(),
        package_version: config.version.clone(),
        name: config.name.clone(),
        language: config.language.clone(),
        files: config.files.len(),
        bytes: sources.iter().fold(0u64, |a, s| a.saturating_add(s.size)),
        built_ms: util::unix_ms(),
        md5s,
    };
    save_record(&root, &record)?;
    let mut p = BuildProgress {
        files_total: config.files.len(),
        bytes_total: record.bytes,
        ..BuildProgress::default()
    };
    progress(&p);
    let mut mode = mode;
    for (f, src) in config.files.iter().zip(&sources) {
        if cancel.load(Ordering::Relaxed) {
            return Err(InstanceError::Cancelled);
        }
        let dst = join_package_path(&dir_of(&root, f.dir), &f.path);
        let src_meta = fs::metadata(&src.path).map_err(io_err(&src.path))?;
        let current = fs::symlink_metadata(&dst).ok();
        if !current.as_ref().is_some_and(|m| same_file(m, &src_meta)) {
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent).map_err(io_err(parent))?;
            }
            let tmp = util::temp_sibling(&dst, "link");
            let placed = match mode {
                LinkMode::Hardlink => match fs::hard_link(&src.path, &tmp) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        tracing::warn!("hardlink {} failed: {e}; copying instead", dst.display());
                        *fallback = Some(format!("hardlinks failed: {e}"));
                        mode = LinkMode::Copy;
                        fs::copy(&src.path, &tmp).map(|_| ())
                    }
                },
                LinkMode::Copy => fs::copy(&src.path, &tmp).map(|_| ()),
            };
            let result = placed.and_then(|()| {
                if current.is_some() {
                    if current.as_ref().is_some_and(|m| m.is_dir() && !m.file_type().is_symlink()) {
                        fsx::remove_tree(&dst)?;
                    } else {
                        fsx::remove_file_force(&dst)?;
                    }
                }
                fs::rename(&tmp, &dst)
            });
            if let Err(e) = result {
                let _ = fsx::remove_file_force(&tmp);
                return Err(InstanceError::Io(dst, e));
            }
        }
        p.files_done += 1;
        p.bytes_done = p.bytes_done.saturating_add(src.size);
        progress(&p);
    }
    // Remove everything that is not part of the configuration.
    let mut expected: BTreeMap<FileDir, BTreeSet<&str>> = BTreeMap::new();
    for f in &config.files {
        expected.entry(f.dir).or_default().insert(f.path.as_str());
    }
    for dir in [FileDir::Game, FileDir::Mod] {
        let base = dir_of(&root, dir);
        let keep = expected.get(&dir);
        if keep.is_none() {
            fsx::remove_tree(&base).map_err(io_err(&base))?;
            continue;
        }
        let userdata = base.join(USERDATA_DIR);
        let files = fsx::walk_files(&base, fsx::MAX_WALK_DEPTH, fsx::MAX_WALK_ENTRIES, &|p| {
            dir == FileDir::Game && p.parent() == Some(base.as_path()) && fsx::is_inside(p, &userdata)
        })
        .map_err(io_err(&base))?;
        for wf in files {
            let wanted = keep.is_some_and(|k| k.contains(wf.rel.as_str()));
            let hook = dir == FileDir::Game && wf.rel == RESERVED_HOOK_NAME;
            if !wanted && !hook {
                fsx::remove_file_force(&wf.path).map_err(io_err(&wf.path))?;
            }
        }
        remove_empty_dirs(&base, &userdata);
    }
    // A forced delete of a stray hardlink may have cleared a shared attribute.
    for md5 in &record.md5s {
        store.protect(md5);
    }
    record.complete = true;
    record.link_mode = mode;
    save_record(&root, &record)?;
    Ok(instance_of(&root, record, config.has_mod_dir()))
}

/// Removes empty sub-folders of `base` (bottom-up, best effort), never `keep`.
fn remove_empty_dirs(base: &Path, keep: &Path) {
    fn walk(dir: &Path, keep: &Path, depth: usize) -> bool {
        if depth > fsx::MAX_WALK_DEPTH || fsx::is_inside(dir, keep) {
            return false;
        }
        let Ok(entries) = fs::read_dir(dir) else { return false };
        let mut empty = true;
        for e in entries.flatten() {
            let is_dir = e.file_type().is_ok_and(|t| t.is_dir() && !t.is_symlink());
            if is_dir && walk(&e.path(), keep, depth + 1) {
                let _ = fs::remove_dir(e.path());
            } else {
                empty = false;
            }
        }
        empty
    }
    walk(base, keep, 0);
}

/// Every instance folder with a readable record.
pub fn list(instances: &Path) -> Vec<(PathBuf, InstanceRecord)> {
    let Ok(entries) = fs::read_dir(instances) else {
        return Vec::new();
    };
    let mut out: Vec<(PathBuf, InstanceRecord)> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| load_record(&e.path()).map(|r| (e.path(), r)))
        .collect();
    out.sort_by(|a, b| a.1.name.cmp(&b.1.name));
    out
}

/// Deletes an instance folder (the store keeps the files).
pub fn remove(root: &Path) -> io::Result<()> {
    fsx::remove_tree(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mods::hash::md5_hex;
    use crate::mods::store::write_new;
    use beacon_proto::control::ConfigFile;

    fn temp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("beacon-inst-{tag}-{}", std::process::id()));
        let _ = fsx::remove_tree(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn config(files: &[(&str, &[u8], FileDir)]) -> GameConfig {
        GameConfig {
            id: String::new(),
            guid: "pkg".into(),
            version: "1.0".into(),
            name: "Pkg".into(),
            author: String::new(),
            language: "EN".into(),
            layers: Vec::new(),
            files: files
                .iter()
                .map(|(p, data, dir)| ConfigFile {
                    path: (*p).into(),
                    md5: md5_hex(data),
                    size: data.len() as u64,
                    dir: *dir,
                })
                .collect(),
        }
        .finalize()
        .unwrap()
    }

    fn fill(store: &Store, root: &Path, files: &[(&str, &[u8], FileDir)]) {
        for (i, (_, data, _)) in files.iter().enumerate() {
            let src = root.join(format!("src{i}"));
            write_new(&src, data).unwrap();
            store.import_file(&src, &md5_hex(data), 0, &AtomicBool::new(false), &mut |_| {}).unwrap();
        }
    }

    const FILES: &[(&str, &[u8], FileDir)] = &[
        ("lotrbfme.exe", b"exe", FileDir::Game),
        ("_patch106.big", b"patch", FileDir::Game),
        ("data\\movies\\intro.vp6", b"video", FileDir::Game),
        ("lang\\english.big", b"patch", FileDir::Game),
    ];

    fn build_with(store: &Store, inst: &Path, cfg: &GameConfig, mode: LinkMode) -> (Instance, Option<String>) {
        let mut fallback = None;
        let mut last = BuildProgress::default();
        let i = build(store, inst, cfg, mode, &AtomicBool::new(false), &mut |p| last = *p, &mut fallback).unwrap();
        assert_eq!(last.files_done, cfg.files.len());
        (i, fallback)
    }

    #[test]
    fn hardlinked_instance_mirrors_the_configuration() {
        let d = temp("hard");
        let store = Store::open(&d.join("store")).unwrap();
        fill(&store, &d, FILES);
        let inst = d.join("instances");
        let (mode, why) = probe_link_mode(store.dir(), &inst);
        assert_eq!((mode, why), (LinkMode::Hardlink, None), "temp dir is NTFS");
        let cfg = config(FILES);
        assert!(ready(&inst, &cfg, &store).is_none());
        let (i, fallback) = build_with(&store, &inst, &cfg, mode);
        assert!(fallback.is_none());
        assert_eq!(i.record.link_mode, LinkMode::Hardlink);
        assert_eq!(i.game_dir, inst.join(&cfg.id).join("game"));
        assert!(i.mod_dir.is_none());
        assert_eq!(fs::read(i.game_dir.join("data").join("movies").join("intro.vp6")).unwrap(), b"video");
        assert_eq!(fs::read(i.game_dir.join("lang").join("english.big")).unwrap(), b"patch");
        assert!(ready(&inst, &cfg, &store).is_some());
        // A hardlink shares the store file: writing is refused (read-only).
        let link = i.game_dir.join("_patch106.big");
        assert!(fs::OpenOptions::new().write(true).open(&link).is_err());
        assert_eq!(list(&inst).len(), 1);

        // Extra files are removed, except the hook DLL and UserData; a wrong
        // file is replaced; the store stays protected.
        write_new(&i.game_dir.join("wsock32.dll"), b"hook").unwrap();
        write_new(&i.game_dir.join("UserData").join("Maps").join("m").join("m.map"), b"map").unwrap();
        write_new(&i.game_dir.join("backup").join("old.big"), b"old").unwrap();
        fsx::remove_file_force(&i.game_dir.join("lotrbfme.exe")).unwrap();
        write_new(&i.game_dir.join("lotrbfme.exe"), b"bad").unwrap();
        let (i2, _) = build_with(&store, &inst, &cfg, LinkMode::Hardlink);
        assert_eq!(fs::read(i2.game_dir.join("lotrbfme.exe")).unwrap(), b"exe");
        assert!(i2.game_dir.join("wsock32.dll").exists());
        assert!(i2.game_dir.join("UserData").join("Maps").join("m").join("m.map").exists());
        assert!(!i2.game_dir.join("backup").exists());
        assert!(fs::metadata(store.path_of(&md5_hex(b"patch"))).unwrap().permissions().readonly());

        // A file missing from the instance makes it "not ready".
        fsx::remove_file_force(&i2.game_dir.join("_patch106.big")).unwrap();
        assert!(ready(&inst, &cfg, &store).is_none());
        remove(&i2.root).unwrap();
        assert!(list(&inst).is_empty());
        let _ = fsx::remove_tree(&d);
    }

    #[test]
    fn copy_mode_and_mod_folder() {
        let d = temp("copy");
        let store = Store::open(&d.join("store")).unwrap();
        let files: &[(&str, &[u8], FileDir)] = &[("lotrbfme.exe", b"exe", FileDir::Game), ("mod.big", b"mod", FileDir::Mod)];
        fill(&store, &d, files);
        let cfg = config(files);
        let inst = d.join("instances");
        let (i, _) = build_with(&store, &inst, &cfg, LinkMode::Copy);
        assert_eq!(i.record.link_mode, LinkMode::Copy);
        let modd = i.mod_dir.clone().unwrap();
        assert_eq!(fs::read(modd.join("mod.big")).unwrap(), b"mod");
        // A copy is a separate file: deleting it leaves the store intact.
        fsx::remove_file_force(&modd.join("mod.big")).unwrap();
        assert!(store.get(&md5_hex(b"mod")).is_some());
        assert!(ready(&inst, &cfg, &store).is_none());
        build_with(&store, &inst, &cfg, LinkMode::Copy);
        assert!(ready(&inst, &cfg, &store).is_some());
        let _ = fsx::remove_tree(&d);
    }

    #[test]
    fn missing_store_files_and_cancellation() {
        let d = temp("missing");
        let store = Store::open(&d.join("store")).unwrap();
        let cfg = config(FILES);
        let mut fb = None;
        let r = build(&store, &d.join("i"), &cfg, LinkMode::Hardlink, &AtomicBool::new(false), &mut |_| {}, &mut fb);
        assert!(matches!(r, Err(InstanceError::NotInStore(_))));
        fill(&store, &d, FILES);
        let r = build(&store, &d.join("i"), &cfg, LinkMode::Hardlink, &AtomicBool::new(true), &mut |_| {}, &mut fb);
        assert!(matches!(r, Err(InstanceError::Cancelled)));
        assert!(!load_record(&root_of(&d.join("i"), &cfg.id)).unwrap().complete);
        let _ = fsx::remove_tree(&d);
    }
}
