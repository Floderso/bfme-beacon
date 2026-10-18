//! The BFME Workshop client (spec 10 §2): manifests from
//! `GET <api>/workshop/download?guid=<guid>:<version>` and files from
//! `GET <files>/<owner>/<md5>`.
//!
//! Behaviour (R10-3 … R10-6):
//!
//! * honest `User-Agent: BFME-Beacon/<version> (+https://github.com/Floderso/bfme-beacon)`;
//! * every manifest is fetched **once per `guid:version`** and kept in
//!   `workshop\manifests\` (each fetch counts as a download on the workshop);
//!   versions are always pinned;
//! * at most two file downloads at a time; `Range` resume from
//!   `downloads\<md5>.part`; exponential back-off with jitter on 429, 5xx and
//!   network errors (`Retry-After` honoured, capped); a bounded number of
//!   attempts; the expected size is enforced and nothing beyond it is read;
//! * every file is MD5-verified before it enters the store; a corrupt download
//!   is deleted and fetched again;
//! * only URLs below the files host of the form `<owner>/<md5>` with the
//!   expected MD5 are requested; files are never re-hosted.
//!
//! Nothing here runs unless the `workshop_downloads` setting is on, which this
//! build does not allow ([`WORKSHOP_DOWNLOADS_AVAILABLE`](super::WORKSHOP_DOWNLOADS_AVAILABLE)).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use beacon_proto::control::{is_md5_hex, is_valid_guid, is_valid_version, MAX_CONFIG_FILE_SIZE};

use super::hash::{self, Hashers};
use super::http::{HttpError, HttpRequest, HttpResponse, HttpTransport};
use super::manifest::{parse_manifest, ManifestError, Package, MAX_MANIFEST_BYTES};
use super::store::{Store, StoreError};
use super::fsx;
use crate::util;

/// The workshop API (only contacted with `workshop_downloads` on).
pub const API_BASE: &str = "https://bfmeladder.com/api";
/// The workshop file CDN.
pub const FILES_BASE: &str = "https://workshop-files.bfmeladder.com";
/// Longest `Retry-After` honoured.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);

/// `BFME-Beacon/<version> (+https://github.com/Floderso/bfme-beacon)`.
pub fn user_agent() -> String {
    format!("BFME-Beacon/{} (+https://github.com/Floderso/bfme-beacon)", crate::VERSION)
}

/// Where the API and the files are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    /// API base without a trailing slash (`https://bfmeladder.com/api`).
    pub api: String,
    /// Files base without a trailing slash.
    pub files: String,
}

impl Endpoints {
    /// The real BFME Workshop.
    pub fn official() -> Self {
        Self {
            api: API_BASE.to_owned(),
            files: FILES_BASE.to_owned(),
        }
    }
}

/// Exponential back-off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// First delay.
    pub base: Duration,
    /// Longest delay.
    pub max: Duration,
    /// Attempts per request or file (including the first).
    pub attempts: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(1),
            max: Duration::from_secs(60),
            attempts: 6,
        }
    }
}

impl Backoff {
    /// The delay before attempt `attempt + 1` (`attempt` ≥ 1): base · 2^(attempt−1),
    /// capped, at least `Retry-After` (capped at [`MAX_RETRY_AFTER`]), plus up to
    /// 25 % jitter.
    pub fn delay(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        let exp = attempt.saturating_sub(1).min(20);
        let base = self.base.saturating_mul(1u32 << exp).min(self.max);
        let base = base.max(retry_after.map(|r| r.min(MAX_RETRY_AFTER)).unwrap_or_default());
        let jitter = base / 4 * (util::random_u32() % 1000) / 1000;
        base.saturating_add(jitter)
    }
}

/// Client options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkshopOptions {
    /// API and files hosts.
    pub endpoints: Endpoints,
    /// Parallel file downloads (spec 10 R10-5: at most 2).
    pub max_parallel: usize,
    /// Retries.
    pub backoff: Backoff,
    /// Largest file downloaded.
    pub max_file_bytes: u64,
    /// Timeout per network step.
    pub timeout: Duration,
}

impl Default for WorkshopOptions {
    fn default() -> Self {
        Self {
            endpoints: Endpoints::official(),
            max_parallel: 2,
            backoff: Backoff::default(),
            max_file_bytes: MAX_CONFIG_FILE_SIZE,
            timeout: Duration::from_secs(60),
        }
    }
}

/// Why a workshop request failed.
#[derive(Debug)]
pub enum WorkshopError {
    /// No response (after all retries).
    Http(String),
    /// An unexpected status (after all retries for 429/5xx).
    Status(u16),
    /// The manifest is unusable or not the requested one.
    Manifest(String),
    /// The download does not have the expected content.
    Corrupt(String),
    /// A URL that is not a workshop file URL.
    BadUrl(String),
    /// The response is larger than allowed.
    TooLarge,
    /// The response is encoded in a way Beacon does not read.
    Encoding(String),
    /// Writing failed.
    Io(io::Error),
    /// Cancelled.
    Cancelled,
}

impl fmt::Display for WorkshopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(e) => write!(f, "workshop not reachable: {e}"),
            Self::Status(s) => write!(f, "workshop answered HTTP {s}"),
            Self::Manifest(e) => write!(f, "workshop manifest: {e}"),
            Self::Corrupt(e) => write!(f, "download corrupt: {e}"),
            Self::BadUrl(u) => write!(f, "not a workshop file URL: {u}"),
            Self::TooLarge => f.write_str("download larger than allowed"),
            Self::Encoding(e) => write!(f, "unsupported response encoding {e:?}"),
            Self::Io(e) => write!(f, "{e}"),
            Self::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for WorkshopError {}

impl From<ManifestError> for WorkshopError {
    fn from(e: ManifestError) -> Self {
        Self::Manifest(e.to_string())
    }
}

/// One file to download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadJob {
    /// MD5.
    pub md5: String,
    /// Expected size (0 = unknown).
    pub size: u64,
    /// URL (checked with [`WorkshopClient::check_file_url`]).
    pub url: String,
    /// What to show (the configuration path).
    pub label: String,
}

/// Progress of a download batch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DownloadProgress {
    /// Files finished.
    pub files_done: usize,
    /// Files in total.
    pub files_total: usize,
    /// Bytes received (including resumed parts).
    pub bytes_done: u64,
    /// Known bytes in total.
    pub bytes_total: u64,
    /// Files being downloaded.
    pub current: Vec<String>,
}

/// Result of a download batch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DownloadReport {
    /// MD5s now in the store.
    pub done: Vec<String>,
    /// MD5s that failed, with the reason.
    pub failed: Vec<(String, String)>,
    /// The batch was cancelled.
    pub cancelled: bool,
}

/// The client.
pub struct WorkshopClient {
    opts: WorkshopOptions,
    transport: Arc<dyn HttpTransport>,
    cache_dir: PathBuf,
    memo: Mutex<HashMap<String, Arc<Package>>>,
}

impl fmt::Debug for WorkshopClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkshopClient")
            .field("opts", &self.opts)
            .field("cache_dir", &self.cache_dir)
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Sleeps in small steps; `false` if cancelled meanwhile.
fn sleep_cancellable(d: Duration, cancel: &AtomicBool) -> bool {
    let step = Duration::from_millis(50);
    let mut left = d;
    while !left.is_zero() {
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        let s = left.min(step);
        std::thread::sleep(s);
        left = left.saturating_sub(s);
    }
    !cancel.load(Ordering::Relaxed)
}

fn retryable(status: u16) -> bool {
    status == 429 || status == 408 || (500..=599).contains(&status)
}

enum Attempt {
    Done,
    Retry(Option<Duration>, String),
}

impl WorkshopClient {
    /// A client; `cache_dir` keeps fetched manifests.
    pub fn new(opts: WorkshopOptions, transport: Arc<dyn HttpTransport>, cache_dir: PathBuf) -> Self {
        Self {
            opts,
            transport,
            cache_dir,
            memo: Mutex::new(HashMap::new()),
        }
    }

    fn request(&self, url: String, range_from: Option<u64>, json: bool) -> HttpRequest {
        let mut headers = Vec::new();
        if json {
            headers.push(("Accept".to_owned(), "application/json".to_owned()));
            // What the AIO sends for anonymous reads (spec 10 §2.1).
            headers.push(("AuthAccountUuid".to_owned(), "unauthenticated".to_owned()));
            headers.push(("AuthAccountPassword".to_owned(), String::new()));
        }
        HttpRequest {
            url,
            headers,
            range_from,
            timeout: self.opts.timeout,
        }
    }

    fn cache_path(&self, guid: &str, version: &str) -> PathBuf {
        self.cache_dir.join(format!("{guid}@{version}.json"))
    }

    /// The manifest of `guid:version`: from memory, from the cache, or fetched
    /// once from the API and cached.
    pub fn manifest(&self, guid: &str, version: &str, cancel: &AtomicBool) -> Result<Arc<Package>, WorkshopError> {
        if !is_valid_guid(guid) || !is_valid_version(version) {
            return Err(WorkshopError::Manifest(format!("invalid package {guid}:{version}")));
        }
        let key = format!("{guid}:{version}");
        if let Some(p) = lock(&self.memo).get(&key) {
            return Ok(Arc::clone(p));
        }
        let path = self.cache_path(guid, version);
        if let Ok(bytes) = util::read_bounded(&path, MAX_MANIFEST_BYTES) {
            if let Ok(p) = parse_manifest(&bytes).filter_identity(guid, version) {
                let p = Arc::new(p);
                lock(&self.memo).insert(key, Arc::clone(&p));
                return Ok(p);
            }
        }
        let url = format!("{}/workshop/download?guid={guid}:{version}", self.opts.endpoints.api);
        let bytes = self.fetch_small(&url, cancel)?;
        let package = parse_manifest(&bytes)?;
        if package.guid != guid || package.version != version {
            return Err(WorkshopError::Manifest(format!(
                "asked for {guid}:{version}, got {}:{}",
                package.guid, package.version
            )));
        }
        fs::create_dir_all(&self.cache_dir).map_err(WorkshopError::Io)?;
        util::write_atomic(&path, &bytes).map_err(WorkshopError::Io)?;
        tracing::info!(guid, version, "workshop manifest fetched and cached");
        let p = Arc::new(package);
        lock(&self.memo).insert(key, Arc::clone(&p));
        Ok(p)
    }

    /// A small JSON body with retries.
    fn fetch_small(&self, url: &str, cancel: &AtomicBool) -> Result<Vec<u8>, WorkshopError> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            if cancel.load(Ordering::Relaxed) {
                return Err(WorkshopError::Cancelled);
            }
            let outcome = match self.transport.get(&self.request(url.to_owned(), None, true)) {
                Ok(resp) if resp.status == 200 => {
                    check_encoding(&resp)?;
                    let mut body = Vec::new();
                    match resp.body.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut body) {
                        Ok(_) if u64::try_from(body.len()).unwrap_or(u64::MAX) > MAX_MANIFEST_BYTES => {
                            return Err(WorkshopError::TooLarge)
                        }
                        Ok(_) => return Ok(body),
                        Err(e) => Attempt::Retry(None, e.to_string()),
                    }
                }
                Ok(resp) if retryable(resp.status) => Attempt::Retry(resp.retry_after, format!("HTTP {}", resp.status)),
                Ok(resp) => return Err(WorkshopError::Status(resp.status)),
                Err(HttpError::BadUrl(u)) => return Err(WorkshopError::BadUrl(u)),
                Err(HttpError::Io(e)) => Attempt::Retry(None, e.to_string()),
            };
            let Attempt::Retry(after, why) = outcome else { continue };
            if attempt >= self.opts.backoff.attempts {
                return Err(WorkshopError::Http(why));
            }
            let delay = self.opts.backoff.delay(attempt, after);
            tracing::warn!(url, "{why}; retrying in {:.1} s", delay.as_secs_f32());
            if !sleep_cancellable(delay, cancel) {
                return Err(WorkshopError::Cancelled);
            }
        }
    }

    /// Checks a manifest URL for `md5`: below the files host, exactly
    /// `<owner>/<md5>`. Returns the URL to request.
    pub fn check_file_url(&self, url: &str, md5: &str) -> Result<String, WorkshopError> {
        let bad = || WorkshopError::BadUrl(url.chars().take(160).collect());
        let base = format!("{}/", self.opts.endpoints.files);
        let rest = url.strip_prefix(&base).ok_or_else(bad)?;
        let (owner, name) = rest.split_once('/').ok_or_else(bad)?;
        if !is_valid_guid(owner) || !is_md5_hex(md5) || !name.eq_ignore_ascii_case(md5) {
            return Err(bad());
        }
        Ok(format!("{base}{owner}/{name}"))
    }

    /// Downloads `jobs` into the store (at most `max_parallel` at a time).
    pub fn download(
        &self,
        jobs: Vec<DownloadJob>,
        store: &Store,
        downloads_dir: &Path,
        cancel: &AtomicBool,
        progress: &(dyn Fn(&DownloadProgress) + Sync),
    ) -> DownloadReport {
        let total_known = jobs.iter().fold(0u64, |a, j| a.saturating_add(j.size));
        let shared = Mutex::new((
            VecDeque::from(jobs.clone()),
            DownloadProgress {
                files_total: jobs.len(),
                bytes_total: total_known,
                ..DownloadProgress::default()
            },
            DownloadReport::default(),
        ));
        if let Err(e) = fs::create_dir_all(downloads_dir) {
            return DownloadReport {
                failed: jobs.iter().map(|j| (j.md5.clone(), e.to_string())).collect(),
                ..DownloadReport::default()
            };
        }
        let workers = self.opts.max_parallel.clamp(1, 2).min(jobs.len().max(1));
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    let job = {
                        let mut g = lock(&shared);
                        let Some(job) = g.0.pop_front() else { break };
                        g.1.current.push(job.label.clone());
                        progress(&g.1);
                        job
                    };
                    let result = self.download_one(&job, store, downloads_dir, cancel, &|n| {
                        let mut g = lock(&shared);
                        g.1.bytes_done = g.1.bytes_done.saturating_add(n);
                        progress(&g.1);
                    });
                    let mut g = lock(&shared);
                    g.1.current.retain(|c| *c != job.label);
                    g.1.files_done += 1;
                    match result {
                        Ok(()) => g.2.done.push(job.md5.clone()),
                        Err(WorkshopError::Cancelled) => {
                            g.2.cancelled = true;
                            g.0.clear();
                        }
                        Err(e) => {
                            tracing::warn!(file = %job.label, "download failed: {e}");
                            g.2.failed.push((job.md5.clone(), e.to_string()));
                        }
                    }
                    progress(&g.1);
                });
            }
        });
        let (_, _, report) = shared.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner);
        report
    }

    /// One file, with resume, retries and verification.
    fn download_one(
        &self,
        job: &DownloadJob,
        store: &Store,
        downloads_dir: &Path,
        cancel: &AtomicBool,
        on_bytes: &dyn Fn(u64),
    ) -> Result<(), WorkshopError> {
        if store.get(&job.md5).is_some() {
            return Ok(());
        }
        let url = self.check_file_url(&job.url, &job.md5)?;
        let limit = if job.size > 0 { job.size } else { self.opts.max_file_bytes };
        if limit > self.opts.max_file_bytes {
            return Err(WorkshopError::TooLarge);
        }
        let part = downloads_dir.join(format!("{}.part", job.md5));
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            if cancel.load(Ordering::Relaxed) {
                return Err(WorkshopError::Cancelled);
            }
            match self.attempt(&url, &part, job, limit, cancel, on_bytes)? {
                Attempt::Done => match self.finish(&part, job, store, cancel)? {
                    true => return Ok(()),
                    false => {
                        // Corrupt: start over (counts as an attempt).
                        if attempt >= self.opts.backoff.attempts {
                            return Err(WorkshopError::Corrupt(format!("{} (MD5 mismatch)", job.label)));
                        }
                    }
                },
                Attempt::Retry(after, why) => {
                    if attempt >= self.opts.backoff.attempts {
                        return Err(WorkshopError::Http(why));
                    }
                    let delay = self.opts.backoff.delay(attempt, after);
                    tracing::warn!(file = %job.label, "{why}; retrying in {:.1} s", delay.as_secs_f32());
                    if !sleep_cancellable(delay, cancel) {
                        return Err(WorkshopError::Cancelled);
                    }
                }
            }
        }
    }

    /// One request: appends to the part file. `Done` when the part has the
    /// complete length (or the server says so).
    fn attempt(
        &self,
        url: &str,
        part: &Path,
        job: &DownloadJob,
        limit: u64,
        cancel: &AtomicBool,
        on_bytes: &dyn Fn(u64),
    ) -> Result<Attempt, WorkshopError> {
        let mut have = fs::metadata(part).map(|m| m.len()).unwrap_or(0);
        if have > limit {
            fsx::remove_file_force(part).map_err(WorkshopError::Io)?;
            have = 0;
        }
        if job.size > 0 && have == job.size {
            return Ok(Attempt::Done);
        }
        let resp = match self.transport.get(&self.request(url.to_owned(), (have > 0).then_some(have), false)) {
            Ok(r) => r,
            Err(HttpError::BadUrl(u)) => return Err(WorkshopError::BadUrl(u)),
            Err(HttpError::Io(e)) => return Ok(Attempt::Retry(None, e.to_string())),
        };
        let start = match resp.status {
            200 => 0,
            206 => match resp.content_range {
                Some(r) if r.start == have => have,
                _ => {
                    // A range we did not ask for: start over.
                    fsx::remove_file_force(part).map_err(WorkshopError::Io)?;
                    return Ok(Attempt::Retry(None, "unexpected Content-Range".to_owned()));
                }
            },
            416 if have > 0 => return Ok(Attempt::Done),
            s if retryable(s) => return Ok(Attempt::Retry(resp.retry_after, format!("HTTP {s}"))),
            s => return Err(WorkshopError::Status(s)),
        };
        check_encoding(&resp)?;
        let total = resp.content_length.map(|n| n.saturating_add(start));
        if let Some(t) = total {
            if t > limit || (job.size > 0 && t != job.size) {
                fsx::remove_file_force(part).map_err(WorkshopError::Io)?;
                return Err(WorkshopError::Corrupt(format!("{}: server size {t}, expected {}", job.label, job.size)));
            }
        }
        let file = OpenOptions::new().create(true).write(true).truncate(false).open(part).map_err(WorkshopError::Io)?;
        file.set_len(start).map_err(WorkshopError::Io)?;
        let mut file = file;
        file.seek(io::SeekFrom::End(0)).map_err(WorkshopError::Io)?;
        let mut out = BufWriter::with_capacity(hash::BUF_LEN, file);
        let mut body = resp.body;
        let mut written = start;
        let mut buf = vec![0u8; 256 * 1024];
        let read_result: io::Result<()> = loop {
            if cancel.load(Ordering::Relaxed) {
                let _ = out.flush();
                return Err(WorkshopError::Cancelled);
            }
            let n = match body.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => break Err(e),
            };
            let n64 = u64::try_from(n).unwrap_or(u64::MAX);
            if written.saturating_add(n64) > limit {
                drop(out);
                fsx::remove_file_force(part).map_err(WorkshopError::Io)?;
                return Err(WorkshopError::TooLarge);
            }
            out.write_all(buf.get(..n).unwrap_or_default()).map_err(WorkshopError::Io)?;
            written = written.saturating_add(n64);
            on_bytes(n64);
        };
        out.flush().map_err(WorkshopError::Io)?;
        drop(out);
        if let Err(e) = read_result {
            // Keep what arrived: the next attempt resumes.
            return Ok(Attempt::Retry(None, format!("connection lost after {written} bytes: {e}")));
        }
        match total {
            Some(t) if written < t => Ok(Attempt::Retry(None, format!("short body ({written} of {t} bytes)"))),
            _ => Ok(Attempt::Done),
        }
    }

    /// Verifies a complete part and moves it into the store; `false` if corrupt
    /// (the part is deleted).
    fn finish(&self, part: &Path, job: &DownloadJob, store: &Store, cancel: &AtomicBool) -> Result<bool, WorkshopError> {
        let mut file = File::open(part).map_err(WorkshopError::Io)?;
        let mut hashers = Hashers::new();
        let mut buf = vec![0u8; hash::BUF_LEN];
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(WorkshopError::Cancelled);
            }
            let n = file.read(&mut buf).map_err(WorkshopError::Io)?;
            if n == 0 {
                break;
            }
            hashers.update(buf.get(..n).unwrap_or_default());
        }
        drop(file);
        let digests = hashers.finish();
        match store.adopt(part, &job.md5, job.size, &digests) {
            Ok(_) => {
                tracing::info!(file = %job.label, md5 = %job.md5, "downloaded and verified");
                Ok(true)
            }
            Err(StoreError::Mismatch { .. } | StoreError::WrongSize { .. }) => {
                tracing::warn!(file = %job.label, got = %digests.md5, "download has the wrong content; fetching again");
                fsx::remove_file_force(part).map_err(WorkshopError::Io)?;
                Ok(false)
            }
            Err(StoreError::Cancelled) => Err(WorkshopError::Cancelled),
            Err(e) => Err(WorkshopError::Io(io::Error::other(e.to_string()))),
        }
    }
}

fn check_encoding(resp: &HttpResponse) -> Result<(), WorkshopError> {
    match resp.content_encoding.as_deref() {
        None | Some("identity") => Ok(()),
        Some(other) => Err(WorkshopError::Encoding(other.to_owned())),
    }
}

trait FilterIdentity {
    fn filter_identity(self, guid: &str, version: &str) -> Result<Package, ManifestError>;
}

impl FilterIdentity for Result<Package, ManifestError> {
    fn filter_identity(self, guid: &str, version: &str) -> Result<Package, ManifestError> {
        self.and_then(|p| {
            if p.guid == guid && p.version == version {
                Ok(p)
            } else {
                Err(ManifestError::BadIdentity(format!("{}:{}", p.guid, p.version)))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_is_honest() {
        let ua = user_agent();
        assert!(ua.starts_with("BFME-Beacon/"));
        assert!(ua.ends_with("(+https://github.com/Floderso/bfme-beacon)"));
    }

    #[test]
    fn backoff_grows_and_honours_retry_after() {
        let b = Backoff {
            base: Duration::from_millis(100),
            max: Duration::from_secs(2),
            attempts: 5,
        };
        let d1 = b.delay(1, None);
        let d3 = b.delay(3, None);
        assert!(d1 >= Duration::from_millis(100) && d1 <= Duration::from_millis(125));
        assert!(d3 >= Duration::from_millis(400) && d3 <= Duration::from_millis(500));
        assert!(b.delay(30, None) <= Duration::from_millis(2500));
        assert!(b.delay(1, Some(Duration::from_secs(3))) >= Duration::from_secs(3));
        assert!(b.delay(1, Some(Duration::from_secs(9999))) <= MAX_RETRY_AFTER + MAX_RETRY_AFTER / 4);
    }

    #[test]
    fn file_urls_are_checked() {
        struct Never;
        impl HttpTransport for Never {
            fn get(&self, _req: &HttpRequest) -> Result<HttpResponse, HttpError> {
                Err(HttpError::Io(io::Error::other("no network in tests")))
            }
        }
        let c = WorkshopClient::new(WorkshopOptions::default(), Arc::new(Never), PathBuf::from("x"));
        let md5 = "57e3a89b3c5fa1023541c29fa983ed34";
        let ok = format!("{FILES_BASE}/bdc6bc60-73f9-4833-9069-3076aff26418/{md5}");
        assert_eq!(c.check_file_url(&ok, md5).unwrap(), ok);
        for bad in [
            format!("https://evil.example/bdc6bc60/{md5}"),
            format!("{FILES_BASE}/bdc6bc60/{}", "0".repeat(32)),
            format!("{FILES_BASE}/../{md5}"),
            format!("{FILES_BASE}/a/b/{md5}"),
            format!("{FILES_BASE}.evil.example/x/{md5}"),
        ] {
            assert!(c.check_file_url(&bad, md5).is_err(), "{bad}");
        }
        assert!(matches!(
            c.manifest("../x", "1.0", &AtomicBool::new(false)),
            Err(WorkshopError::Manifest(_))
        ));
    }
}
