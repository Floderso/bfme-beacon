//! One preparation: from a [`GameConfig`] to a complete instance folder, or to
//! the list of files that could not be found. Blocking and cancellable (runs on
//! its own thread, see [`manager`](super::manager)).
//!
//! 1. Check the configuration again (it came over the network).
//! 2. A complete instance is reused at once.
//! 3. Free-space check for what has to be copied (imports, downloads, and the
//!    instance itself if hardlinks are not possible).
//! 4. Import from the user's own files ([`import`](super::import)).
//! 5. Download the rest from the workshop if that is enabled
//!    ([`workshop`](super::workshop)): never base-game files, never executables.
//! 6. Link the instance ([`instance`](super::instance)).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use beacon_proto::control::{ConfigError, GameConfig};
use serde::Serialize;

use super::fsx;
use super::import::{self, ImportError, ImportSources, Wanted};
use super::instance::{self, Instance, InstanceError, LinkMode};
use super::store::Store;
use super::workshop::{DownloadJob, WorkshopClient};
use super::{human_size, is_executable_path, ModPaths, BASE_GUID_PREFIX};

/// Space kept free on top of what a preparation needs.
pub const FREE_SPACE_MARGIN: u64 = 512 << 20;
/// Most missing files listed in a result.
pub const MAX_LISTED_MISSING: usize = 50;

/// What is being done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Checking the store and the instance.
    Checking,
    /// Copying files from the user's folders into the store.
    Importing,
    /// Downloading from the workshop.
    Downloading,
    /// Linking the instance folder.
    Linking,
}

/// Progress of a preparation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PrepProgress {
    /// Current phase.
    pub phase: Option<Phase>,
    /// Overall progress in percent.
    pub percent: u8,
    /// Bytes done in this phase.
    pub bytes_done: u64,
    /// Bytes of this phase (known sizes).
    pub bytes_total: u64,
    /// Files done in this phase.
    pub files_done: usize,
    /// Files of this phase.
    pub files_total: usize,
    /// File being worked on.
    pub current: Option<String>,
}

impl PrepProgress {
    fn set(&mut self, phase: Phase, done: u64, total: u64) {
        let (from, span) = match phase {
            Phase::Checking => (0u64, 5u64),
            Phase::Importing => (5, 55),
            Phase::Downloading => (60, 30),
            Phase::Linking => (90, 10),
        };
        let part = done.min(total).saturating_mul(span).checked_div(total).unwrap_or(0);
        self.phase = Some(phase);
        self.percent = u8::try_from((from + part).min(100)).unwrap_or(100);
        self.bytes_done = done;
        self.bytes_total = total;
    }
}

/// A file that could not be obtained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MissingFile {
    /// Configuration path.
    pub path: String,
    /// MD5.
    pub md5: String,
    /// Size (0 = unknown).
    pub size: u64,
}

/// The result of a preparation.
#[derive(Debug, Clone)]
pub enum PrepOutcome {
    /// The instance is complete.
    Ready {
        /// The instance.
        instance: Box<Instance>,
        /// Something the user should know (copies instead of hardlinks).
        notice: Option<String>,
    },
    /// Files are missing.
    Missing {
        /// Number of missing files.
        count: usize,
        /// The first [`MAX_LISTED_MISSING`].
        files: Vec<MissingFile>,
        /// Hints (failed downloads, executables, …).
        notes: Vec<String>,
    },
}

/// Why a preparation failed.
#[derive(Debug)]
pub enum PrepError {
    /// The configuration breaks a rule.
    Invalid(ConfigError),
    /// Not enough free space.
    NoSpace {
        /// Bytes needed (with the margin).
        needed: u64,
        /// Bytes free.
        free: u64,
    },
    /// The store failed.
    Store(String),
    /// Building the instance failed.
    Instance(String),
    /// Cancelled.
    Cancelled,
}

impl fmt::Display for PrepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(e) => write!(f, "Ungültige Spielkonfiguration: {e}"),
            Self::NoSpace { needed, free } => write!(
                f,
                "Nicht genug Speicherplatz: {} nötig, {} frei.",
                human_size(*needed),
                human_size(*free)
            ),
            Self::Store(e) => write!(f, "Beacons Dateispeicher: {e}"),
            Self::Instance(e) => write!(f, "Instanzordner: {e}"),
            Self::Cancelled => f.write_str("Abgebrochen."),
        }
    }
}

impl std::error::Error for PrepError {}

/// Everything a preparation needs.
pub struct PrepareInput<'a> {
    /// The configuration.
    pub config: &'a GameConfig,
    /// Beacon's mod folders.
    pub paths: &'a ModPaths,
    /// Where to import from.
    pub sources: &'a ImportSources,
    /// The workshop client, if downloads are enabled.
    pub workshop: Option<&'a WorkshopClient>,
}

/// `true` if a user folder has `path` with this MD5.
fn own_executable(sources: &ImportSources, path: &str, md5: &str, cancel: &AtomicBool) -> bool {
    sources.game_dir.iter().chain(sources.extra_dirs.iter()).any(|root| {
        let candidate = super::join_package_path(root, path);
        candidate.is_file()
            && super::hash::hash_file(&candidate, cancel, &mut |_| {}).is_ok_and(|d| d.md5 == md5)
    })
}

fn missing_list(config: &GameConfig, wanted: &[Wanted]) -> (usize, Vec<MissingFile>) {
    let missing: BTreeMap<&str, &Wanted> = wanted.iter().map(|w| (w.md5.as_str(), w)).collect();
    let paths: std::collections::BTreeSet<&str> = wanted.iter().flat_map(|w| w.paths.iter().map(String::as_str)).collect();
    let files: Vec<MissingFile> = config
        .files
        .iter()
        .filter(|f| missing.contains_key(f.md5.as_str()) && (paths.contains(f.path.as_str()) || !is_executable_path(&f.path)))
        .map(|f| MissingFile {
            path: f.path.clone(),
            md5: f.md5.clone(),
            size: f.size,
        })
        .collect();
    let count = files.len();
    (count, files.into_iter().take(MAX_LISTED_MISSING).collect())
}

/// Runs one preparation.
pub fn prepare(
    input: &PrepareInput<'_>,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&PrepProgress),
) -> Result<PrepOutcome, PrepError> {
    let config = input.config;
    config.validate().map_err(PrepError::Invalid)?;
    let mut p = PrepProgress::default();
    p.set(Phase::Checking, 0, 1);
    progress(&p);
    let store = Store::open(&input.paths.store()).map_err(|e| PrepError::Store(e.to_string()))?;
    store.sweep_temporaries();
    let instances = input.paths.instances();
    if let Some(instance) = instance::ready(&instances, config, &store) {
        return Ok(PrepOutcome::Ready {
            instance: Box::new(instance),
            notice: None,
        });
    }
    let wanted = import::wanted_files(config, &store);
    let (mode, why) = instance::probe_link_mode(&input.paths.store(), &instances);
    // Space: everything that will be copied.
    let to_copy = wanted.iter().fold(0u64, |a, w| a.saturating_add(w.size));
    let instance_copies = if mode == LinkMode::Copy { config.total_size() } else { 0 };
    let needed = to_copy.saturating_add(instance_copies).saturating_add(FREE_SPACE_MARGIN);
    if let Some(free) = fsx::free_space(input.paths.root()) {
        if (to_copy > 0 || instance_copies > 0) && free < needed {
            return Err(PrepError::NoSpace { needed, free });
        }
    }
    let mut notes = Vec::new();
    let mut wanted = wanted;
    if !wanted.is_empty() {
        let total = to_copy;
        p.set(Phase::Importing, 0, total);
        p.files_total = wanted.len();
        progress(&p);
        let report = import::import(&store, wanted, input.sources, cancel, &mut |ip| {
            p.set(Phase::Importing, ip.bytes_done, total);
            p.files_done = ip.files_done;
            p.current.clone_from(&ip.current);
            progress(&p);
        })
        .map_err(|e| match e {
            ImportError::Cancelled => PrepError::Cancelled,
            ImportError::Store(e) => PrepError::Store(e.to_string()),
        })?;
        if report.rejected > 0 {
            tracing::info!(rejected = report.rejected, "candidates with other content were skipped");
        }
        wanted = report.missing;
    }
    if !wanted.is_empty() {
        if let Some(client) = input.workshop {
            wanted = download(client, config, wanted, &store, input.paths, cancel, &mut p, progress, &mut notes)?;
        }
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(PrepError::Cancelled);
    }
    // Executables must be the user's own, at the same path (not just the same
    // content under another name).
    for f in config.files.iter().filter(|f| is_executable_path(&f.path)) {
        if !own_executable(input.sources, &f.path, &f.md5, cancel) && !wanted.iter().any(|w| w.md5 == f.md5) {
            wanted.push(Wanted {
                md5: f.md5.clone(),
                size: f.size,
                paths: vec![f.path.clone()],
                executable: true,
            });
        }
    }
    if !wanted.is_empty() {
        if wanted.iter().any(|w| w.executable) {
            notes.push(
                "Programmdateien (z. B. lotrbfme.exe) übernimmt Beacon nur aus deiner eigenen BFME-Installation \
                 (gleicher Pfad und gleicher Inhalt)."
                    .to_owned(),
            );
        }
        let (count, files) = missing_list(config, &wanted);
        return Ok(PrepOutcome::Missing { count, files, notes });
    }
    p.set(Phase::Linking, 0, config.total_size());
    p.files_total = config.files.len();
    p.current = None;
    progress(&p);
    let mut fallback = None;
    let instance = instance::build(
        &store,
        &instances,
        config,
        mode,
        cancel,
        &mut |bp| {
            p.set(Phase::Linking, bp.bytes_done, bp.bytes_total);
            p.files_done = bp.files_done;
            progress(&p);
        },
        &mut fallback,
    )
    .map_err(|e| match e {
        InstanceError::Cancelled => PrepError::Cancelled,
        other => PrepError::Instance(other.to_string()),
    })?;
    let notice = if instance.record.link_mode == LinkMode::Copy {
        let reason = fallback.or(why).unwrap_or_default();
        Some(format!(
            "Harte Verknüpfungen sind hier nicht möglich ({reason}). Beacon hat die Dateien in den Instanzordner \
             kopiert; das belegt zusätzlich {}.",
            human_size(instance.record.bytes)
        ))
    } else {
        None
    };
    Ok(PrepOutcome::Ready {
        instance: Box::new(instance),
        notice,
    })
}

#[allow(clippy::too_many_arguments)]
fn download(
    client: &WorkshopClient,
    config: &GameConfig,
    wanted: Vec<Wanted>,
    store: &Store,
    paths: &ModPaths,
    cancel: &AtomicBool,
    p: &mut PrepProgress,
    progress: &mut dyn FnMut(&PrepProgress),
    notes: &mut Vec<String>,
) -> Result<Vec<Wanted>, PrepError> {
    // URLs from the packages' own manifests (each guid:version fetched once).
    let mut urls: BTreeMap<String, String> = BTreeMap::new();
    for layer in config.layers.iter().filter(|l| !l.guid.starts_with(BASE_GUID_PREFIX)) {
        match client.manifest(&layer.guid, &layer.version, cancel) {
            Ok(pkg) => {
                for f in &pkg.files {
                    if let Some(url) = &f.url {
                        urls.entry(f.md5.clone()).or_insert_with(|| url.clone());
                    }
                }
            }
            Err(super::workshop::WorkshopError::Cancelled) => return Err(PrepError::Cancelled),
            Err(e) => notes.push(format!("{} {}: {e}", layer.name, layer.version)),
        }
    }
    let mut jobs = Vec::new();
    let mut rest = Vec::new();
    for w in wanted {
        let url = (!w.executable && !w.paths.iter().any(|p| is_executable_path(p)))
            .then(|| urls.get(&w.md5))
            .flatten()
            .and_then(|u| client.check_file_url(u, &w.md5).ok());
        match url {
            Some(url) => jobs.push((
                DownloadJob {
                    md5: w.md5.clone(),
                    size: w.size,
                    url,
                    label: w.paths.first().cloned().unwrap_or_default(),
                },
                w,
            )),
            None => rest.push(w),
        }
    }
    if jobs.is_empty() {
        return Ok(rest);
    }
    let total = jobs.iter().fold(0u64, |a, (j, _)| a.saturating_add(j.size));
    p.set(Phase::Downloading, 0, total);
    p.files_total = jobs.len();
    p.files_done = 0;
    progress(p);
    let snapshot = std::sync::Mutex::new(None::<super::workshop::DownloadProgress>);
    let report = client.download(
        jobs.iter().map(|(j, _)| j.clone()).collect(),
        store,
        &paths.downloads(),
        cancel,
        &|dp| {
            if let Ok(mut s) = snapshot.lock() {
                *s = Some(dp.clone());
            }
        },
    );
    // Progress is reported from the workers' snapshots after the batch (the
    // callback runs on worker threads; the UI gets the totals here).
    if let Ok(Some(dp)) = snapshot.into_inner() {
        p.set(Phase::Downloading, dp.bytes_done, total);
        p.files_done = dp.files_done;
        progress(p);
    }
    if report.cancelled {
        return Err(PrepError::Cancelled);
    }
    for (md5, why) in &report.failed {
        notes.push(format!("Download {md5}: {why}"));
    }
    for (job, w) in jobs {
        if !report.done.contains(&job.md5) {
            rest.push(w);
        }
    }
    Ok(rest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mods::hash::md5_hex;
    use crate::mods::store::write_new;
    use beacon_proto::control::{ConfigFile, FileDir};

    fn temp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("beacon-prep-{tag}-{}", std::process::id()));
        let _ = fsx::remove_tree(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn prepares_from_the_game_folder_and_reuses_the_instance() {
        let d = temp("game");
        let game = d.join("BFME1");
        let files: &[(&str, &[u8])] = &[("lotrbfme.exe", b"exe"), ("_patch106.big", b"patch"), ("lang\\english.big", b"en")];
        for (p, data) in files {
            write_new(&crate::mods::join_package_path(&game, p), data).unwrap();
        }
        let mut config = GameConfig {
            id: String::new(),
            guid: "p".into(),
            version: "1".into(),
            name: "P".into(),
            author: String::new(),
            language: "EN".into(),
            layers: Vec::new(),
            files: files
                .iter()
                .map(|(p, data)| ConfigFile { path: (*p).into(), md5: md5_hex(data), size: data.len() as u64, dir: FileDir::Game })
                .collect(),
        };
        config.files.push(ConfigFile { path: "missing.big".into(), md5: md5_hex(b"x"), size: 1, dir: FileDir::Game });
        let config = config.finalize().unwrap();
        let paths = ModPaths::new(d.join("mods"));
        let sources = ImportSources { game_dir: Some(game.clone()), ..ImportSources::default() };
        let input = PrepareInput { config: &config, paths: &paths, sources: &sources, workshop: None };
        let cancel = AtomicBool::new(false);
        let mut phases = Vec::new();
        match prepare(&input, &cancel, &mut |p| phases.push(p.phase)).unwrap() {
            PrepOutcome::Missing { count, files, .. } => {
                assert_eq!(count, 1);
                assert_eq!(files[0].path, "missing.big");
            }
            other => panic!("{other:?}"),
        }
        assert!(phases.contains(&Some(Phase::Importing)));
        write_new(&game.join("missing.big"), b"x").unwrap();
        let instance = match prepare(&input, &cancel, &mut |_| {}).unwrap() {
            PrepOutcome::Ready { instance, notice } => {
                assert!(notice.is_none());
                instance
            }
            other => panic!("{other:?}"),
        };
        assert_eq!(std::fs::read(instance.game_dir.join("lang").join("english.big")).unwrap(), b"en");
        // Second time: reused without importing.
        let mut phases = Vec::new();
        assert!(matches!(prepare(&input, &cancel, &mut |p| phases.push(p.phase)).unwrap(), PrepOutcome::Ready { .. }));
        assert_eq!(phases, [Some(Phase::Checking)]);
        // Executables are only taken from the same path in the user's folders.
        let mut exe_cfg = config.clone();
        exe_cfg.files.push(ConfigFile { path: "other.dll".into(), md5: md5_hex(b"exe"), size: 3, dir: FileDir::Game });
        let exe_cfg = exe_cfg.finalize().unwrap();
        let input = PrepareInput { config: &exe_cfg, ..input };
        match prepare(&input, &cancel, &mut |_| {}).unwrap() {
            PrepOutcome::Missing { count, files, notes } => {
                assert_eq!(count, 1, "{files:?}");
                assert_eq!(files[0].path, "other.dll", "the store has the content, but not at this path");
                assert!(notes.iter().any(|n| n.contains("Programmdateien")));
            }
            other => panic!("{other:?}"),
        }
        let mut bad = config.clone();
        bad.id = "0".repeat(32);
        let input = PrepareInput { config: &bad, ..input };
        assert!(matches!(prepare(&input, &cancel, &mut |_| {}), Err(PrepError::Invalid(_))));
        let _ = fsx::remove_tree(&d);
    }
}
