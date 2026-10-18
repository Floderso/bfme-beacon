//! Workshop client against a local fake HTTP server (never the real BFME
//! Workshop): WinHTTP as transport, manifest caching, `Range` resume, corrupt
//! downloads, back-off, the parallel-download limit and size limits.

#![cfg(windows)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use beacon_launcher::mods::http::WinHttp;
use beacon_launcher::mods::store::Store;
use beacon_launcher::mods::workshop::{
    self, Backoff, DownloadJob, Endpoints, WorkshopClient, WorkshopError, WorkshopOptions,
};
use md5::{Digest, Md5};

const OWNER: &str = "11111111-2222-3333-4444-555555555555";

fn md5_hex(data: &[u8]) -> String {
    Md5::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// How the fake server answers requests for one file.
#[derive(Clone, Debug)]
pub enum Behaviour {
    /// Serve it (with `Range` support).
    Normal,
    /// The first `n` requests get `status` (with `Retry-After: 0`).
    FailFirst(u32, u16),
    /// The first `n` requests send the headers and only `bytes` of the body.
    CutFirst(u32, usize),
    /// The first `n` requests send other bytes of the same length.
    CorruptFirst(u32),
    /// Every request sends the body slowly (for the concurrency limit).
    Slow(Duration),
    /// The header claims more bytes than the file has, the body has them too.
    Oversized,
}

#[derive(Default)]
pub struct Fake {
    pub files: Mutex<HashMap<String, (Vec<u8>, Behaviour)>>,
    pub manifests: Mutex<HashMap<String, String>>,
    pub hits: Mutex<HashMap<String, u32>>,
    pub ranges: Mutex<Vec<(String, Option<String>)>>,
    pub user_agents: Mutex<Vec<String>>,
    pub active: AtomicUsize,
    pub max_active: AtomicUsize,
    pub requests: AtomicU32,
}

pub struct FakeServer {
    pub port: u16,
    pub state: Arc<Fake>,
}

impl FakeServer {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Fake::default());
        let s = Arc::clone(&state);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let s = Arc::clone(&s);
                std::thread::spawn(move || {
                    let _ = handle(stream, &s);
                });
            }
        });
        Self { port, state }
    }

    pub fn endpoints(&self) -> Endpoints {
        Endpoints {
            api: format!("http://127.0.0.1:{}/api", self.port),
            files: format!("http://127.0.0.1:{}/files", self.port),
        }
    }

    pub fn file_url(&self, md5: &str) -> String {
        format!("http://127.0.0.1:{}/files/{OWNER}/{md5}", self.port)
    }

    pub fn add_file(&self, data: &[u8], behaviour: Behaviour) -> String {
        let md5 = md5_hex(data);
        self.state.files.lock().unwrap().insert(md5.clone(), (data.to_vec(), behaviour));
        md5
    }

    pub fn hits(&self, key: &str) -> u32 {
        self.state.hits.lock().unwrap().get(key).copied().unwrap_or(0)
    }
}

fn respond(stream: &mut TcpStream, status: u16, headers: &[(String, String)], body: &[u8]) -> std::io::Result<()> {
    let mut head = format!("HTTP/1.1 {status} X\r\nConnection: close\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn handle(mut stream: TcpStream, s: &Fake) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
    let mut headers = HashMap::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 || h == "\r\n" {
            break;
        }
        if let Some((k, v)) = h.trim_end().split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }
    s.requests.fetch_add(1, Ordering::SeqCst);
    if let Some(ua) = headers.get("user-agent") {
        s.user_agents.lock().unwrap().push(ua.clone());
    }
    if let Some(q) = path.strip_prefix("/api/workshop/download?guid=") {
        *s.hits.lock().unwrap().entry(q.to_owned()).or_default() += 1;
        let body = s.manifests.lock().unwrap().get(q).cloned();
        return match body {
            Some(b) => respond(&mut stream, 200, &[("Content-Type".into(), "application/json".into()), ("Content-Length".into(), b.len().to_string())], b.as_bytes()),
            None => respond(&mut stream, 404, &[("Content-Length".into(), "0".into())], b""),
        };
    }
    let Some(md5) = path.strip_prefix(&format!("/files/{OWNER}/")) else {
        return respond(&mut stream, 404, &[("Content-Length".into(), "0".into())], b"");
    };
    let n = {
        let mut hits = s.hits.lock().unwrap();
        let e = hits.entry(md5.to_owned()).or_default();
        *e += 1;
        *e
    };
    s.ranges.lock().unwrap().push((md5.to_owned(), headers.get("range").cloned()));
    let Some((data, behaviour)) = s.files.lock().unwrap().get(md5).cloned() else {
        return respond(&mut stream, 404, &[("Content-Length".into(), "0".into())], b"");
    };
    let active = s.active.fetch_add(1, Ordering::SeqCst) + 1;
    s.max_active.fetch_max(active, Ordering::SeqCst);
    let result = (|| {
        if let Behaviour::FailFirst(k, status) = behaviour {
            if n <= k {
                return respond(&mut stream, status, &[("Retry-After".into(), "0".into()), ("Content-Length".into(), "0".into())], b"");
            }
        }
        let start = headers
            .get("range")
            .and_then(|r| r.strip_prefix("bytes="))
            .and_then(|r| r.strip_suffix('-'))
            .and_then(|r| r.parse::<usize>().ok())
            .unwrap_or(0);
        if start >= data.len() && start > 0 {
            return respond(&mut stream, 416, &[("Content-Length".into(), "0".into())], b"");
        }
        let mut body = data[start..].to_vec();
        if let Behaviour::CorruptFirst(k) = behaviour {
            if n <= k {
                for b in &mut body {
                    *b ^= 0x5a;
                }
            }
        }
        let mut hs = vec![("Content-Type".to_owned(), "application/octet-stream".to_owned())];
        let status = if start > 0 {
            hs.push(("Content-Range".into(), format!("bytes {start}-{}/{}", data.len() - 1, data.len())));
            206
        } else {
            200
        };
        let claimed = if matches!(behaviour, Behaviour::Oversized) { body.len() + 100 } else { body.len() };
        if matches!(behaviour, Behaviour::Oversized) {
            body.extend(std::iter::repeat_n(0u8, 100));
        }
        hs.push(("Content-Length".into(), claimed.to_string()));
        match behaviour {
            Behaviour::CutFirst(k, bytes) if n <= k => {
                let mut head = format!("HTTP/1.1 {status} X\r\nConnection: close\r\n");
                for (k, v) in &hs {
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                head.push_str("\r\n");
                stream.write_all(head.as_bytes())?;
                stream.write_all(&body[..bytes.min(body.len())])?;
                stream.flush()?;
                std::thread::sleep(Duration::from_millis(50));
                stream.shutdown(std::net::Shutdown::Both)
            }
            Behaviour::Slow(d) => {
                let mut head = format!("HTTP/1.1 {status} X\r\nConnection: close\r\n");
                for (k, v) in &hs {
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                head.push_str("\r\n");
                stream.write_all(head.as_bytes())?;
                for chunk in body.chunks(body.len().div_ceil(4).max(1)) {
                    std::thread::sleep(d);
                    stream.write_all(chunk)?;
                }
                stream.flush()
            }
            _ => respond(&mut stream, status, &hs, &body),
        }
    })();
    s.active.fetch_sub(1, Ordering::SeqCst);
    let mut rest = Vec::new();
    let _ = reader.read_to_end(&mut rest);
    result
}

struct Temp(PathBuf);

impl Temp {
    fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "beacon-mods-it-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = beacon_launcher::mods::fsx::remove_tree(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = beacon_launcher::mods::fsx::remove_tree(&self.0);
    }
}

fn client(server: &FakeServer, dir: &Temp, backoff: Backoff) -> WorkshopClient {
    WorkshopClient::new(
        WorkshopOptions {
            endpoints: server.endpoints(),
            max_parallel: 2,
            backoff,
            max_file_bytes: 1 << 20,
            timeout: Duration::from_secs(10),
        },
        Arc::new(WinHttp {
            user_agent: workshop::user_agent(),
            system_proxy: false,
        }),
        dir.0.join("manifests"),
    )
}

fn fast() -> Backoff {
    Backoff {
        base: Duration::from_millis(100),
        max: Duration::from_millis(400),
        attempts: 4,
    }
}

fn job(server: &FakeServer, md5: &str, size: u64) -> DownloadJob {
    DownloadJob {
        md5: md5.to_owned(),
        size,
        url: server.file_url(md5),
        label: format!("{md5}.big"),
    }
}

fn data(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

fn manifest(guid: &str, version: &str, files: &[(&str, &str, usize)], server: &FakeServer) -> String {
    let files: Vec<serde_json::Value> = files
        .iter()
        .map(|(name, md5, size)| {
            serde_json::json!({"Guid": md5, "Name": name, "Url": server.file_url(md5), "Md5": md5, "Language": "ALL", "Size": size})
        })
        .collect();
    serde_json::json!({
        "Guid": guid, "Name": "Fake Patch", "Version": version, "Author": "Tester", "Owner": OWNER,
        "Game": 0, "Type": 0, "Language": "EN", "Files": files, "Dependencies": [], "SocialLinks": [],
        "Maps": [], "Factions": []
    })
    .to_string()
}

#[test]
fn manifests_are_fetched_once_per_version_and_cached() {
    let server = FakeServer::start();
    let dir = Temp::new("manifest");
    server.state.manifests.lock().unwrap().insert(
        "fake-patch:1.0.0".into(),
        manifest("fake-patch", "1.0.0", &[("_fake.big", &"a".repeat(32), 10)], &server),
    );
    // A server that answers with another version is refused.
    server.state.manifests.lock().unwrap().insert(
        "fake-patch:2.0.0".into(),
        manifest("fake-patch", "1.9.9", &[], &server),
    );
    let cancel = AtomicBool::new(false);
    let c = client(&server, &dir, fast());
    let p = c.manifest("fake-patch", "1.0.0", &cancel).unwrap();
    assert_eq!(p.files[0].path, "_fake.big");
    c.manifest("fake-patch", "1.0.0", &cancel).unwrap();
    // A new client (next Beacon start) uses the cache on disk.
    let c2 = client(&server, &dir, fast());
    c2.manifest("fake-patch", "1.0.0", &cancel).unwrap();
    assert_eq!(server.hits("fake-patch:1.0.0"), 1, "each guid:version is fetched once");
    assert!(dir.0.join("manifests").join("fake-patch@1.0.0.json").is_file());
    assert!(matches!(c.manifest("fake-patch", "2.0.0", &cancel), Err(WorkshopError::Manifest(_))));
    assert!(matches!(c.manifest("missing", "1.0", &cancel), Err(WorkshopError::Status(404))));
    let ua = server.state.user_agents.lock().unwrap().clone();
    assert!(!ua.is_empty());
    assert!(ua.iter().all(|u| u == &workshop::user_agent()), "{ua:?}");
    assert!(ua[0].starts_with("BFME-Beacon/") && ua[0].contains("(+https://github.com/Floderso/bfme-beacon)"));
}

#[test]
fn an_interrupted_download_resumes_with_range() {
    let server = FakeServer::start();
    let dir = Temp::new("resume");
    let body = data(200_000, 1);
    let md5 = server.add_file(&body, Behaviour::CutFirst(1, 70_000));
    let store = Store::open(&dir.0.join("store")).unwrap();
    let c = client(&server, &dir, fast());
    let bytes = AtomicUsize::new(0);
    let report = c.download(vec![job(&server, &md5, body.len() as u64)], &store, &dir.0.join("downloads"), &AtomicBool::new(false), &|p| {
        bytes.store(p.bytes_done as usize, Ordering::SeqCst);
    });
    assert_eq!(report.done, std::slice::from_ref(&md5), "{report:?}");
    assert_eq!(std::fs::read(store.path_of(&md5)).unwrap(), body);
    let ranges = server.state.ranges.lock().unwrap().clone();
    assert_eq!(ranges.len(), 2, "{ranges:?}");
    assert_eq!(ranges[0].1, None);
    assert_eq!(ranges[1].1.as_deref(), Some("bytes=70000-"), "resumed where it stopped");
    assert_eq!(bytes.load(Ordering::SeqCst), body.len(), "no byte fetched twice");
    assert!(!dir.0.join("downloads").join(format!("{md5}.part")).exists());
}

#[test]
fn corrupt_downloads_are_detected_and_fetched_again() {
    let server = FakeServer::start();
    let dir = Temp::new("corrupt");
    let store = Store::open(&dir.0.join("store")).unwrap();
    let c = client(&server, &dir, fast());
    let once = data(50_000, 2);
    let md5_once = server.add_file(&once, Behaviour::CorruptFirst(1));
    let always = data(40_000, 3);
    let md5_always = server.add_file(&always, Behaviour::CorruptFirst(u32::MAX));
    let report = c.download(
        vec![job(&server, &md5_once, once.len() as u64), job(&server, &md5_always, always.len() as u64)],
        &store,
        &dir.0.join("downloads"),
        &AtomicBool::new(false),
        &|_| {},
    );
    assert_eq!(report.done, std::slice::from_ref(&md5_once));
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].0, md5_always);
    assert!(report.failed[0].1.contains("corrupt"), "{report:?}");
    assert_eq!(server.hits(&md5_once), 2);
    assert_eq!(server.hits(&md5_always), 4, "bounded attempts");
    assert!(store.get(&md5_always).is_none(), "never stored");
    assert_eq!(std::fs::read(store.path_of(&md5_once)).unwrap(), once);
}

#[test]
fn server_errors_back_off_and_client_errors_do_not_retry() {
    let server = FakeServer::start();
    let dir = Temp::new("backoff");
    let store = Store::open(&dir.0.join("store")).unwrap();
    let c = client(&server, &dir, fast());
    let busy = data(10_000, 4);
    let md5_busy = server.add_file(&busy, Behaviour::FailFirst(2, 503));
    let t0 = Instant::now();
    let report = c.download(vec![job(&server, &md5_busy, busy.len() as u64)], &store, &dir.0.join("downloads"), &AtomicBool::new(false), &|_| {});
    let elapsed = t0.elapsed();
    assert_eq!(report.done, std::slice::from_ref(&md5_busy), "{report:?}");
    assert_eq!(server.hits(&md5_busy), 3);
    // 100 ms then 200 ms (+ jitter) of back-off.
    assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
    let limited = data(10_000, 5);
    let md5_limited = server.add_file(&limited, Behaviour::FailFirst(u32::MAX, 429));
    let report = c.download(vec![job(&server, &md5_limited, limited.len() as u64)], &store, &dir.0.join("downloads"), &AtomicBool::new(false), &|_| {});
    assert_eq!(report.failed.len(), 1);
    assert_eq!(server.hits(&md5_limited), 4, "gives up after the attempts");
    let gone = data(10_000, 6);
    let md5_gone = server.add_file(&gone, Behaviour::FailFirst(u32::MAX, 403));
    let report = c.download(vec![job(&server, &md5_gone, gone.len() as u64)], &store, &dir.0.join("downloads"), &AtomicBool::new(false), &|_| {});
    assert!(report.failed[0].1.contains("403"), "{report:?}");
    assert_eq!(server.hits(&md5_gone), 1, "4xx is not retried");
}

#[test]
fn at_most_two_downloads_run_at_once() {
    let server = FakeServer::start();
    let dir = Temp::new("parallel");
    let store = Store::open(&dir.0.join("store")).unwrap();
    let c = client(&server, &dir, fast());
    let jobs: Vec<DownloadJob> = (0..5)
        .map(|i| {
            let d = data(20_000, 10 + i);
            let md5 = server.add_file(&d, Behaviour::Slow(Duration::from_millis(40)));
            job(&server, &md5, d.len() as u64)
        })
        .collect();
    let report = c.download(jobs, &store, &dir.0.join("downloads"), &AtomicBool::new(false), &|p| {
        assert!(p.current.len() <= 2, "{p:?}");
    });
    assert_eq!(report.done.len(), 5, "{report:?}");
    assert_eq!(server.state.max_active.load(Ordering::SeqCst), 2);
}

#[test]
fn sizes_are_enforced_and_urls_checked() {
    let server = FakeServer::start();
    let dir = Temp::new("sizes");
    let store = Store::open(&dir.0.join("store")).unwrap();
    let c = client(&server, &dir, fast());
    let d = data(5_000, 7);
    let md5 = server.add_file(&d, Behaviour::Oversized);
    let report = c.download(vec![job(&server, &md5, d.len() as u64)], &store, &dir.0.join("downloads"), &AtomicBool::new(false), &|_| {});
    assert_eq!(report.failed.len(), 1, "{report:?}");
    // Unknown size: still bounded by max_file_bytes (1 MiB here).
    let big = data(1_100_000, 8);
    let md5_big = server.add_file(&big, Behaviour::Normal);
    let report = c.download(vec![job(&server, &md5_big, 0)], &store, &dir.0.join("downloads"), &AtomicBool::new(false), &|_| {});
    assert_eq!(report.failed.len(), 1, "{report:?}");
    assert!(store.get(&md5_big).is_none());
    // A URL outside the files host is never requested.
    let before = server.state.requests.load(Ordering::SeqCst);
    let mut evil = job(&server, &md5, d.len() as u64);
    evil.url = format!("http://127.0.0.1:{}/elsewhere/{md5}", server.port);
    let report = c.download(vec![evil], &store, &dir.0.join("downloads"), &AtomicBool::new(false), &|_| {});
    assert!(report.failed[0].1.contains("not a workshop file URL"), "{report:?}");
    assert_eq!(server.state.requests.load(Ordering::SeqCst), before);
    // Cancellation stops a batch.
    let slow = data(20_000, 9);
    let md5_slow = server.add_file(&slow, Behaviour::Slow(Duration::from_millis(200)));
    let cancel = AtomicBool::new(false);
    let report = std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(150));
            cancel.store(true, Ordering::SeqCst);
        });
        c.download(vec![job(&server, &md5_slow, slow.len() as u64)], &store, &dir.0.join("downloads"), &cancel, &|_| {})
    });
    assert!(report.cancelled, "{report:?}");
    assert!(store.get(&md5_slow).is_none());
}

