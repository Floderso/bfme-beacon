//! Logging: `tracing` events go to a log file in `<data dir>\logs\` and, in the CLI
//! modes, to stdout. Each start writes a new `beacon-<UTC stamp>-<pid>.log`
//! (rolled over to a new file after [`MAX_LOG_FILE`] bytes); only the newest
//! [`KEEP_LOGS`] files of each kind (`beacon-*`, `hook-*`) are kept.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use tracing::Level;

use crate::util;

/// Log files kept per kind.
pub const KEEP_LOGS: usize = 10;
/// Size after which a new log file is started.
pub const MAX_LOG_FILE: u64 = 16 << 20;

/// Name of a new log file of `kind` (`beacon`, `hook`).
fn new_name(kind: &str) -> String {
    format!(
        "{kind}-{}-{}.log",
        util::utc_stamp(SystemTime::now()),
        std::process::id()
    )
}

/// Deletes the oldest `<kind>-*.log` files so that at most `keep` remain.
pub fn prune(dir: &Path, kind: &str, keep: usize) {
    let prefix = format!("{kind}-");
    let Ok(entries) = fs::read_dir(dir) else { return };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with(&prefix) && n.ends_with(".log"))
        .collect();
    // The UTC stamp after the prefix sorts chronologically.
    names.sort_unstable();
    let excess = names.len().saturating_sub(keep);
    for name in names.iter().take(excess) {
        let _ = fs::remove_file(dir.join(name));
    }
}

/// A fresh path for the hook's log (`hook-<stamp>-<pid>.log`; the hook creates it).
/// Old hook logs are pruned.
pub fn hook_log_path(dir: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    prune(dir, "hook", KEEP_LOGS.saturating_sub(1));
    Ok(dir.join(new_name("hook")))
}

struct RotatingFile {
    dir: PathBuf,
    file: File,
    written: u64,
}

impl RotatingFile {
    fn open(dir: &Path) -> io::Result<(Self, PathBuf)> {
        fs::create_dir_all(dir)?;
        prune(dir, "beacon", KEEP_LOGS.saturating_sub(1));
        let path = dir.join(new_name("beacon"));
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok((
            Self {
                dir: dir.to_path_buf(),
                file,
                written: 0,
            },
            path,
        ))
    }

    fn write(&mut self, buf: &[u8]) {
        let len = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        if self.written.saturating_add(len) > MAX_LOG_FILE {
            if let Ok((next, _)) = Self::open(&self.dir) {
                *self = next;
            }
        }
        if self.file.write_all(buf).is_ok() {
            self.written = self.written.saturating_add(len);
        }
    }
}

#[derive(Clone)]
struct Sink {
    file: Option<Arc<Mutex<RotatingFile>>>,
    stdout: bool,
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.stdout {
            let mut out = io::stdout().lock();
            let _ = out.write_all(buf);
            let _ = out.flush();
        }
        if let Some(f) = &self.file {
            if let Ok(mut f) = f.lock() {
                f.write(buf);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Installs the global subscriber. Returns the log file path (if a directory was
/// given and the file could be created). Calling it twice is harmless.
pub fn init(logs_dir: Option<&Path>, stdout: bool, verbose: bool) -> Option<PathBuf> {
    let (file, path) = match logs_dir.map(RotatingFile::open) {
        Some(Ok((f, p))) => (Some(Arc::new(Mutex::new(f))), Some(p)),
        Some(Err(e)) => {
            if stdout {
                println!("cannot create the log file: {e}");
            }
            (None, None)
        }
        None => (None, None),
    };
    let sink = Sink { file, stdout };
    let level = if verbose { Level::DEBUG } else { Level::INFO };
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_writer(move || sink.clone())
        .try_init();
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pruning_keeps_the_newest() {
        let dir = std::env::temp_dir().join(format!("beacon-logs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for i in 0..5 {
            fs::write(dir.join(format!("hook-2026101{i}T000000Z-1.log")), b"x").unwrap();
        }
        fs::write(dir.join("other.txt"), b"x").unwrap();
        prune(&dir, "hook", 2);
        let mut left: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["hook-20261013T000000Z-1.log", "hook-20261014T000000Z-1.log", "other.txt"]);
        let p = hook_log_path(&dir).unwrap();
        assert!(p.file_name().unwrap().to_str().unwrap().starts_with("hook-"));
        let (mut f, path) = RotatingFile::open(&dir).unwrap();
        f.write(b"line\n");
        assert_eq!(fs::read(&path).unwrap(), b"line\n");
        let _ = fs::remove_dir_all(&dir);
    }
}
