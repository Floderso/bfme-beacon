//! Web UI tests over real TCP: a raw HTTP/1.1 client (so every header – `Host`,
//! `Origin`, the token – is under the test's control) against `WebServer` on
//! `127.0.0.1:0`, with temporary data folders and no BFME installation. One test
//! also runs a real `beacon_server` in-process.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use beacon_launcher::agent::AgentOptions;
use beacon_launcher::game::Registry;
use beacon_launcher::paths::DataDirs;
use beacon_launcher::web::{WebOptions, WebServer, ASSETS, MAX_EVENT_STREAMS};
use beacon_launcher::{App, AppOptions};
use beacon_proto::control::{derive_psk, KdfParams};
use beacon_server::config::Config;
use beacon_server::hexfmt;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Generous bound for anything that should happen.
const T: Duration = Duration::from_secs(20);

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "beacon-web-it-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// No BFME installation.
struct NoGame;

impl Registry for NoGame {
    fn string(&self, _value: &str) -> Option<String> {
        None
    }
    fn dword(&self, _value: &str) -> Option<u32> {
        None
    }
}

type Opened = Arc<Mutex<Vec<PathBuf>>>;

struct Ui {
    app: App,
    web: WebServer,
    opened: Opened,
    _dir: TempDir,
}

impl Ui {
    async fn start(tag: &str) -> Self {
        let dir = TempDir::new(tag);
        let mut o = AppOptions::new(DataDirs::with_base(dir.0.join("data"), 1).unwrap());
        o.registry = Arc::new(NoGame);
        o.appdata = Some(dir.0.join("appdata"));
        o.fingerprint = false;
        o.maps_dir = Some(dir.0.join("Maps"));
        o.hook_dll = Some(dir.0.join("no-hook.dll"));
        o.agent = AgentOptions {
            tick: Duration::from_millis(100),
            ..AgentOptions::default()
        };
        let app = App::start(o).await.unwrap();
        let opened: Opened = Arc::default();
        let sink = Arc::clone(&opened);
        let web = WebServer::start(
            app.clone(),
            WebOptions {
                open_folder: Arc::new(move |p: &Path| {
                    sink.lock().unwrap().push(p.to_path_buf());
                    Ok(())
                }),
            },
        )
        .await
        .unwrap();
        Self {
            app,
            web,
            opened,
            _dir: dir,
        }
    }

    fn port(&self) -> u16 {
        self.web.port()
    }

    fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port())
    }

    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port())
    }

    /// GET with the right Host and token.
    async fn get(&self, path: &str) -> Resp {
        let host = self.host();
        request(self.port(), "GET", path, &[("Host", &host), ("X-Beacon-Token", self.web.token())], None).await
    }

    /// POST (JSON) with the right Host, Origin and token, like the page does.
    async fn post(&self, path: &str, body: &Value) -> Resp {
        let (host, origin) = (self.host(), self.origin());
        let body = body.to_string();
        request(
            self.port(),
            "POST",
            path,
            &[
                ("Host", &host),
                ("Origin", &origin),
                ("Sec-Fetch-Site", "same-origin"),
                ("X-Beacon-Token", self.web.token()),
                ("Content-Type", "application/json"),
            ],
            Some(body.as_bytes()),
        )
        .await
    }

    async fn state(&self) -> Value {
        let r = self.get("/api/state").await;
        assert_eq!(r.status, 200, "{}", r.text());
        r.json()
    }

    async fn wait_state(&self, what: &str, pred: impl Fn(&Value) -> bool) -> Value {
        let deadline = tokio::time::Instant::now() + T;
        loop {
            let s = self.state().await;
            if pred(&s) {
                return s;
            }
            assert!(tokio::time::Instant::now() < deadline, "timeout waiting for {what}: {}", s["connection"]);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn stop(self) {
        self.app.quit().await;
        self.web.shutdown().await;
    }
}

#[derive(Debug)]
struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.text()))
    }

    /// `error.kind` / `error.reason` of an error answer.
    fn error(&self) -> (String, Option<String>) {
        let v = self.json();
        assert_eq!(v["ok"], false, "{v}");
        (
            v["error"]["kind"].as_str().unwrap_or_default().to_owned(),
            v["error"]["reason"].as_str().map(str::to_owned),
        )
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Splits status line + headers from `raw` (which holds at least the head).
fn parse_head(head: &[u8]) -> (u16, Vec<(String, String)>) {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("bad status line: {text}"));
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();
    (status, headers)
}

/// Decodes complete chunks of a chunked body; returns the payload and whether
/// the final chunk was seen.
fn dechunk(mut data: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    loop {
        let Some(eol) = find(data, b"\r\n") else { return (out, false) };
        let size_text = String::from_utf8_lossy(&data[..eol]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16).unwrap();
        if size == 0 {
            return (out, true);
        }
        let start = eol + 2;
        if data.len() < start + size + 2 {
            return (out, false);
        }
        out.extend_from_slice(&data[start..start + size]);
        data = &data[start + size + 2..];
    }
}

async fn request(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: Option<&[u8]>) -> Resp {
    request_raw(port, &build(method, path, "HTTP/1.1", headers, body)).await
}

fn build(method: &str, path: &str, version: &str, headers: &[(&str, &str)], body: Option<&[u8]>) -> Vec<u8> {
    let mut req = format!("{method} {path} {version}\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("Connection: close\r\n");
    if method == "POST" {
        req.push_str(&format!("Content-Length: {}\r\n", body.map_or(0, <[u8]>::len)));
    }
    req.push_str("\r\n");
    let mut bytes = req.into_bytes();
    bytes.extend_from_slice(body.unwrap_or_default());
    bytes
}

async fn request_raw(port: u16, raw_request: &[u8]) -> Resp {
    let mut s = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).await.unwrap();
    s.write_all(raw_request).await.unwrap();
    let mut raw = Vec::new();
    timeout(T, s.read_to_end(&mut raw)).await.expect("response timeout").unwrap();
    let split = find(&raw, b"\r\n\r\n").unwrap_or_else(|| panic!("no head: {}", String::from_utf8_lossy(&raw)));
    let (status, headers) = parse_head(&raw[..split]);
    let rest = &raw[split + 4..];
    let chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked"));
    let body = if chunked { dechunk(rest).0 } else { rest.to_vec() };
    Resp { status, headers, body }
}

/// An open event stream.
struct Events {
    stream: TcpStream,
    raw: Vec<u8>,
    body_start: usize,
    consumed: usize,
    status: u16,
    headers: Vec<(String, String)>,
}

impl Events {
    async fn open(ui: &Ui) -> Self {
        let host = ui.host();
        let req = build("GET", "/api/events", "HTTP/1.1", &[("Host", &host), ("X-Beacon-Token", ui.web.token())], None);
        let mut stream = TcpStream::connect(ui.web.addr()).await.unwrap();
        stream.write_all(&req).await.unwrap();
        let mut ev = Self {
            stream,
            raw: Vec::new(),
            body_start: 0,
            consumed: 0,
            status: 0,
            headers: Vec::new(),
        };
        while find(&ev.raw, b"\r\n\r\n").is_none() {
            ev.fill().await.expect("stream closed before the head");
        }
        let split = find(&ev.raw, b"\r\n\r\n").unwrap();
        let (status, headers) = parse_head(&ev.raw[..split]);
        ev.status = status;
        ev.headers = headers;
        ev.body_start = split + 4;
        ev
    }

    /// Reads more bytes; `None` at the end of the stream.
    async fn fill(&mut self) -> Option<()> {
        let mut buf = [0u8; 16 * 1024];
        let n = timeout(T, self.stream.read(&mut buf)).await.expect("event timeout").unwrap();
        if n == 0 {
            return None;
        }
        self.raw.extend_from_slice(&buf[..n]);
        Some(())
    }

    /// The next `(event, data)`; `None` when the stream ended.
    async fn next(&mut self) -> Option<(String, String)> {
        loop {
            let (payload, _) = dechunk(&self.raw[self.body_start..]);
            let text = String::from_utf8_lossy(&payload[self.consumed.min(payload.len())..]).into_owned();
            if let Some(end) = text.find("\n\n") {
                self.consumed += end + 2;
                let block = &text[..end];
                if block.lines().all(|l| l.starts_with(':')) {
                    continue; // keep-alive comment
                }
                let mut event = String::new();
                let mut data = String::new();
                for line in block.lines() {
                    if let Some(v) = line.strip_prefix("event: ") {
                        event = v.to_owned();
                    } else if let Some(v) = line.strip_prefix("data: ") {
                        data.push_str(v);
                    }
                }
                return Some((event, data));
            }
            self.fill().await?;
        }
    }

    /// The next state event (skipping nothing else).
    async fn next_state(&mut self) -> Value {
        let (event, data) = self.next().await.expect("stream ended");
        assert_eq!(event, "state");
        serde_json::from_str(&data).unwrap()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_requires_token_host_and_origin() {
    let ui = Ui::start("auth").await;
    let port = ui.port();
    let host = ui.host();
    let token = ui.web.token().to_owned();
    assert!(ui.web.addr().ip().is_loopback());
    assert_eq!(token.len(), 32);
    assert!(ui.web.url().ends_with(&format!("/#t={token}")));
    assert!(ui.web.url().starts_with(&format!("http://127.0.0.1:{port}/")));

    let forbidden = |r: &Resp, reason: &str| {
        assert_eq!(r.status, 403, "{}", r.text());
        assert_eq!(r.error(), ("forbidden".to_owned(), Some(reason.to_owned())));
    };

    // Token: missing, wrong, other length.
    let r = request(port, "GET", "/api/state", &[("Host", &host)], None).await;
    forbidden(&r, "token");
    let wrong = if token.starts_with('0') { "1" } else { "0" }.repeat(32);
    let r = request(port, "GET", "/api/state", &[("Host", &host), ("X-Beacon-Token", &wrong)], None).await;
    forbidden(&r, "token");
    let r = request(port, "GET", "/api/state", &[("Host", &host), ("X-Beacon-Token", &token[..31])], None).await;
    forbidden(&r, "token");
    let upper = token.to_uppercase();
    if upper != token {
        let r = request(port, "GET", "/api/state", &[("Host", &host), ("X-Beacon-Token", &upper)], None).await;
        forbidden(&r, "token");
    }
    // Unknown API paths need the token too.
    let r = request(port, "GET", "/api/nothing", &[("Host", &host)], None).await;
    forbidden(&r, "token");

    // Host (DNS rebinding): only 127.0.0.1:PORT and localhost:PORT.
    for bad in [
        "evil.example".to_owned(),
        format!("evil.example:{port}"),
        format!("127.0.0.1:{}", port.wrapping_add(1)),
        format!("localhost.evil.example:{port}"),
    ] {
        let r = request(port, "GET", "/api/state", &[("Host", &bad), ("X-Beacon-Token", &token)], None).await;
        forbidden(&r, "host");
        let r = request(port, "GET", "/", &[("Host", &bad)], None).await;
        forbidden(&r, "host");
    }
    let r = request_raw(port, &build("GET", "/", "HTTP/1.0", &[], None)).await;
    forbidden(&r, "host");
    // An absolute-form target must name the same authority.
    let r = request(
        port,
        "GET",
        "http://evil.example/api/state",
        &[("Host", &host), ("X-Beacon-Token", &token)],
        None,
    )
    .await;
    assert_eq!(r.status, 403);
    let localhost = format!("localhost:{port}");
    let r = request(port, "GET", "/api/state", &[("Host", &localhost), ("X-Beacon-Token", &token)], None).await;
    assert_eq!(r.status, 200, "{}", r.text());

    // Origin and Sec-Fetch-Site.
    for (name, value) in [
        ("Origin", "http://evil.example".to_owned()),
        ("Origin", "null".to_owned()),
        ("Origin", format!("https://127.0.0.1:{port}")),
        ("Origin", format!("http://localhost:{port}")),
        ("Sec-Fetch-Site", "cross-site".to_owned()),
        ("Sec-Fetch-Site", "same-site".to_owned()),
    ] {
        let r = request(
            port,
            "POST",
            "/api/chat",
            &[
                ("Host", &host),
                ("X-Beacon-Token", &token),
                (name, &value),
                ("Content-Type", "application/json"),
            ],
            Some(br#"{"text":"hi"}"#),
        )
        .await;
        let reason = if name == "Origin" { "origin" } else { "fetch_site" };
        forbidden(&r, reason);
        assert!(r.header("access-control-allow-origin").is_none());
    }
    // A CORS preflight from another site gets no CORS answer.
    let r = request(
        port,
        "OPTIONS",
        "/api/connect",
        &[
            ("Host", &host),
            ("Origin", "http://evil.example"),
            ("Access-Control-Request-Method", "POST"),
        ],
        None,
    )
    .await;
    assert_eq!(r.status, 403);
    assert!(r.header("access-control-allow-origin").is_none());
    assert!(r.header("access-control-allow-methods").is_none());

    // The page's own origin works.
    let origin = ui.origin();
    let r = request(
        port,
        "GET",
        "/api/state",
        &[("Host", &host), ("X-Beacon-Token", &token), ("Origin", &origin), ("Sec-Fetch-Site", "same-origin")],
        None,
    )
    .await;
    assert_eq!(r.status, 200);
    for (name, value) in [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
    ] {
        assert_eq!(r.header(name), Some(value), "{name}");
    }
    let csp = r.header("content-security-policy").unwrap();
    assert!(csp.contains("default-src 'none'") && csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"));
    assert!(r.header("access-control-allow-origin").is_none());
    ui.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn state_shape_and_assets() {
    let ui = Ui::start("state").await;
    let s = ui.state().await;
    assert_eq!(s["version"], beacon_launcher::VERSION);
    assert_eq!(s["instance"], 1);
    assert_eq!(s["test_mode"], false);
    assert_eq!(s["connection"], json!({"state": "disconnected"}));
    assert_eq!(s["server"], Value::Null);
    assert_eq!(s["players"], json!([]));
    assert_eq!(s["chat"], json!([]));
    assert_eq!(s["maps"]["sync"]["running"], false);
    assert_eq!(s["maps"]["listing_received"], false);
    assert!(s["agent"]["local_port"].as_u64().is_some_and(|p| p > 0));
    assert!(s["settings"]["servers"].is_array());
    assert_eq!(s["settings"]["name_sync"], true);
    assert!(s["settings"]["launch"].is_object());
    assert!(s["notices"].is_array());
    assert!(s["peer_files"].is_object());
    assert!(s["hook"]["state"].is_string());
    assert!(s["fingerprint"]["state"].is_string());
    let text = s.to_string();
    assert!(!text.contains("remembered_psk") && !text.contains(ui.web.token()), "no secrets in the state");

    // Assets: no token needed, right type, embedded content.
    let host = ui.host();
    assert!(ASSETS.len() >= 4);
    for asset in ASSETS {
        let r = request(ui.port(), "GET", asset.path, &[("Host", &host)], None).await;
        assert_eq!(r.status, 200, "{}", asset.path);
        assert_eq!(r.header("content-type"), Some(asset.content_type), "{}", asset.path);
        assert_eq!(r.text(), asset.body, "{}", asset.path);
        assert!(r.header("content-security-policy").is_some());
        assert!(!asset.body.is_empty());
    }
    let index = ASSETS.iter().find(|a| a.path == "/").unwrap().body;
    assert!(index.contains(r#"<script src="/app.js" defer></script>"#));
    assert!(index.contains(r#"href="/style.css""#));
    assert!(index.contains(r#"<html lang="de">"#));
    assert_eq!(index.matches("<script").count(), 1, "no inline scripts (CSP)");
    assert!(!index.contains("style=\""), "no inline styles (CSP)");
    for view in ["view-verbinden", "view-lobby", "view-einstellungen", "view-diagnose"] {
        assert!(index.contains(view), "{view}");
    }
    let js = ASSETS.iter().find(|a| a.path == "/app.js").unwrap().body;
    for forbidden in [".innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"] {
        assert!(!js.contains(forbidden), "app.js must not use {forbidden}");
    }
    assert!(js.contains("X-Beacon-Token"));
    // The hook answers the game's XP firewall query itself (beacon-hook f05a8dc).
    assert!(js.contains("'Firewall-Abfrage'") && js.contains("'übersprungen'"));

    let r = request(ui.port(), "GET", "/nothing-here", &[("Host", &host)], None).await;
    assert_eq!(r.status, 404);
    assert_eq!(r.error().0, "not_found");
    let r = ui.get("/api/nothing").await;
    assert_eq!(r.status, 404);
    let r = request(ui.port(), "POST", "/", &[("Host", &host)], None).await;
    assert_eq!(r.status, 405);
    ui.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_send_the_state_first_then_changes_then_quit() {
    let ui = Ui::start("events").await;
    let mut events = Events::open(&ui).await;
    assert_eq!(events.status, 200);
    assert!(events
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v.starts_with("text/event-stream")));
    let first = events.next_state().await;
    assert_eq!(first["connection"]["state"], "disconnected");
    assert_eq!(first["version"], beacon_launcher::VERSION);
    assert_eq!(first["settings"]["name_sync"], true);

    // A change arrives as a new full state (agent ticks may come first).
    let r = ui.post("/api/settings", &json!({"name_sync": false})).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let deadline = tokio::time::Instant::now() + T;
    loop {
        let s = events.next_state().await;
        if s["settings"]["name_sync"] == false {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline);
    }

    // Throttled: at most ~10 state events per second even with a flood of changes.
    let started = tokio::time::Instant::now();
    for i in 0..30 {
        let r = ui.post("/api/settings", &json!({"auto_launch_on_host_start": i % 2 == 0})).await;
        assert_eq!(r.status, 200);
    }
    let mut n = 0;
    while started.elapsed() < Duration::from_millis(1500) {
        if timeout(Duration::from_millis(300), events.next()).await.is_ok() {
            n += 1;
        }
    }
    assert!(n <= 17, "{n} events in 1.5 s");

    // Quit: the stream says so and ends.
    let r = ui.post("/api/quit", &json!({})).await;
    assert_eq!(r.status, 200);
    timeout(T, ui.app.quit_requested()).await.unwrap();
    loop {
        match events.next().await {
            Some((event, _)) if event == "quit" => break,
            Some(_) => continue,
            None => panic!("stream ended without a quit event"),
        }
    }
    assert!(events.next().await.is_none(), "the stream ends after quit");
    ui.web.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn event_streams_are_limited() {
    let ui = Ui::start("limit").await;
    let mut open = Vec::new();
    for _ in 0..MAX_EVENT_STREAMS {
        let mut e = Events::open(&ui).await;
        assert_eq!(e.status, 200);
        e.next_state().await;
        open.push(e);
    }
    let r = ui.get("/api/events").await;
    assert_eq!(r.status, 429);
    assert_eq!(r.error().0, "too_many_streams");
    // A closed tab frees its slot.
    drop(open.pop());
    let deadline = tokio::time::Instant::now() + T;
    loop {
        let mut e = Events::open(&ui).await;
        if e.status == 200 {
            e.next_state().await;
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "slot not freed");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    ui.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commands_validate_and_settings_are_saved() {
    let ui = Ui::start("commands").await;
    let check = |r: Resp, status: u16, kind: &str, reason: Option<&str>| {
        assert_eq!(r.status, status, "{}", r.text());
        assert_eq!(r.error(), (kind.to_owned(), reason.map(str::to_owned)), "{}", r.text());
    };
    let connect = |server: &str, name: &str| json!({"server": server, "name": name, "password": "pw"});
    check(ui.post("/api/connect", &connect("127.0.0.1:1", "")).await, 400, "invalid_input", Some("name_empty"));
    check(ui.post("/api/connect", &connect("127.0.0.1:1", "abcdefghijklm")).await, 400, "invalid_input", Some("name_too_long"));
    check(ui.post("/api/connect", &connect("127.0.0.1:1", "Bo  b")).await, 400, "invalid_input", Some("name_spaces"));
    check(ui.post("/api/connect", &connect("127.0.0.1:1", "<b>")).await, 400, "invalid_input", Some("name_invalid_char"));
    check(ui.post("/api/connect", &connect("bad host", "Bob")).await, 400, "invalid_input", Some("invalid_address"));
    check(
        ui.post("/api/connect", &json!({"server": "127.0.0.1:1", "name": "Bob", "use_remembered": false})).await,
        400,
        "invalid_input",
        Some("password_missing"),
    );
    check(
        ui.post("/api/connect", &json!({"server": "127.0.0.1:1", "name": "Bob", "password": "x", "extra": 1})).await,
        422,
        "bad_request",
        None,
    );
    let r = ui.get("/api/connect").await;
    assert_eq!(r.status, 405);

    check(ui.post("/api/chat", &json!({"text": "  "})).await, 400, "invalid_input", Some("chat_empty"));
    check(ui.post("/api/chat", &json!({"text": "hallo"})).await, 409, "not_connected", None);
    check(ui.post("/api/ready", &json!({"ready": true})).await, 409, "not_connected", None);
    check(ui.post("/api/launch_all", &json!({})).await, 409, "not_connected", None);
    check(ui.post("/api/kick", &json!({"name": ""})).await, 400, "invalid_input", Some("name_missing"));
    check(ui.post("/api/kick", &json!({"name": "Bob"})).await, 409, "not_connected", None);
    check(ui.post("/api/fingerprint", &json!({"name": "Bob"})).await, 409, "not_connected", None);
    check(ui.post("/api/maps/sync", &json!({})).await, 409, "not_connected", None);
    check(ui.post("/api/launch", &json!({})).await, 409, "not_connected", None);

    // Malformed bodies.
    let host = ui.host();
    let token = ui.web.token().to_owned();
    let r = request(
        ui.port(),
        "POST",
        "/api/chat",
        &[("Host", &host), ("X-Beacon-Token", &token), ("Content-Type", "application/json")],
        Some(b"{not json"),
    )
    .await;
    check(r, 400, "bad_request", None);
    let r = request(
        ui.port(),
        "POST",
        "/api/chat",
        &[("Host", &host), ("X-Beacon-Token", &token), ("Content-Type", "text/plain")],
        Some(br#"{"text":"hi"}"#),
    )
    .await;
    check(r, 415, "bad_request", None);
    let big = format!(r#"{{"text":"{}"}}"#, "x".repeat(70 * 1024));
    let r = request(
        ui.port(),
        "POST",
        "/api/chat",
        &[("Host", &host), ("X-Beacon-Token", &token), ("Content-Type", "application/json")],
        Some(big.as_bytes()),
    )
    .await;
    assert_eq!(r.status, 413, "{}", r.text());

    // Settings: validated, saved, visible in the state and in config.json.
    check(
        ui.post("/api/settings", &json!({"launch": {"windowed": true, "xres": 100, "yres": 600}})).await,
        400,
        "invalid_input",
        Some("resolution_range"),
    );
    check(
        ui.post("/api/settings", &json!({"redundancy": {"lobby": 9}})).await,
        400,
        "invalid_input",
        Some("redundancy_range"),
    );
    check(
        ui.post("/api/settings", &json!({"game_dir": "relative\\BFME"})).await,
        400,
        "invalid_input",
        Some("path_not_absolute"),
    );
    check(ui.post("/api/settings", &json!({"player_name": " x"})).await, 400, "invalid_input", Some("name_spaces"));
    let r = ui
        .post(
            "/api/settings",
            &json!({
                "player_name": "Éowyn",
                "launch": {"windowed": true, "xres": 1280, "yres": 720, "noshellmap": false},
                "name_sync": false,
                "auto_launch_on_host_start": false,
                "redundancy": {"lobby": 2, "game": null, "other": 1}
            }),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json(), json!({"ok": true}));
    let s = ui.state().await;
    let settings = &s["settings"];
    assert_eq!(settings["player_name"], "Éowyn");
    assert_eq!(settings["launch"], json!({"windowed": true, "xres": 1280, "yres": 720, "noshellmap": false}));
    assert_eq!(settings["name_sync"], false);
    assert_eq!(settings["auto_launch_on_host_start"], false);
    assert_eq!(settings["redundancy"], json!({"lobby": 2, "game": null, "other": 1}));
    let saved = std::fs::read_to_string(ui.app.data_dirs().config_file()).unwrap();
    let saved: Value = serde_json::from_str(&saved).unwrap();
    assert_eq!(saved["player_name"], "Éowyn");
    assert_eq!(saved["launch"]["xres"], 1280);

    // Pins / passwords of unknown servers: nothing to remove.
    let r = ui.post("/api/pin/reset", &json!({"server": "home.example.org"})).await;
    assert_eq!(r.json(), json!({"ok": true, "removed": false}));
    let r = ui.post("/api/password/forget", &json!({"server": "home.example.org:28086"})).await;
    assert_eq!(r.json(), json!({"ok": true, "removed": false}));
    check(ui.post("/api/pin/reset", &json!({"server": ""})).await, 400, "invalid_input", Some("invalid_address"));
    // Nothing was ever changed in Network.ini: nothing to restore.
    ui.wait_state("detection", |s| !s["game"].is_null()).await;
    let r = ui.post("/api/name/restore", &json!({})).await;
    assert_eq!(r.json(), json!({"ok": true, "restored": false}));

    // The log folder is opened through the injected opener (no Explorer window).
    let r = ui.post("/api/logs/open", &json!({})).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let opened = ui.opened.lock().unwrap().clone();
    assert_eq!(opened, vec![ui.app.data_dirs().logs_dir()]);
    assert!(opened[0].is_dir());

    let r = ui.post("/api/disconnect", &json!({})).await;
    assert_eq!(r.json(), json!({"ok": true}));
    ui.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_chat_ready_and_disconnect_through_the_api() {
    let ui = Ui::start("e2e").await;
    let dir = TempDir::new("e2e-server");
    std::fs::create_dir_all(dir.0.join("maps")).unwrap();
    let salt = *b"beacon-web-salt!";
    let psk = derive_psk("mellon-mellon", &salt, &KdfParams::DEFAULT).unwrap();
    let cfg = Config {
        server_name: "Webserver".into(),
        motd: "Willkommen <b>in</b> Mittelerde".into(),
        bind: "127.0.0.1".into(),
        port: 0,
        status_bind: String::new(),
        salt: hexfmt::encode(&salt),
        psk: hexfmt::encode(&psk),
        maps_dir: dir.0.join("maps").to_string_lossy().into_owned(),
        data_dir: dir.0.join("server-data").to_string_lossy().into_owned(),
        map_rescan_secs: 0,
        ..Config::default()
    };
    let mut settings = cfg.into_settings(&dir.0).unwrap();
    settings.lobby_refresh = Duration::from_millis(200);
    let server = beacon_server::start(settings).await.unwrap();
    let addr = format!("127.0.0.1:{}", server.control_addr().port());

    // Wrong password: the state reports auth_failed.
    let r = ui
        .post("/api/connect", &json!({"server": addr, "name": "Gandalf", "password": "falsch"}))
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let s = ui.wait_state("auth failure", |s| s["connection"]["state"] == "failed").await;
    assert_eq!(s["connection"]["error"]["kind"], "auth_failed");

    // Right password.
    let r = ui
        .post(
            "/api/connect",
            &json!({"server": addr, "name": "Gandalf", "password": "mellon-mellon", "remember": true}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let s = ui
        .wait_state("connected", |s| s["connection"]["state"] == "connected" && s["players"].as_array().is_some_and(|p| !p.is_empty()))
        .await;
    assert_eq!(s["server"]["name"], "Webserver");
    assert_eq!(s["server"]["motd"], "Willkommen <b>in</b> Mittelerde");
    assert_eq!(s["server"]["you_are_host"], true);
    assert_eq!(s["players"][0]["name"], "Gandalf");
    assert_eq!(s["players"][0]["is_host"], true);

    let r = ui.post("/api/chat", &json!({"text": "Ein Ring <script>alert(1)</script>"})).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let r = ui.post("/api/ready", &json!({"ready": true})).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let s = ui
        .wait_state("chat + ready", |s| {
            s["players"][0]["ready"] == true
                && s["chat"]
                    .as_array()
                    .is_some_and(|c| c.iter().any(|l| l["from"] == "Gandalf" && l["text"] == "Ein Ring <script>alert(1)</script>"))
        })
        .await;
    assert!(s["settings"]["servers"][0]["remembered"] == true || s["settings"]["servers"].to_string().contains("\"remembered\":true"));

    // Host-only commands work for the host; kicking an unknown player is the
    // server's business (no error from the launcher).
    let r = ui.post("/api/launch_all", &json!({})).await;
    assert_eq!(r.status, 200, "{}", r.text());

    let r = ui.post("/api/disconnect", &json!({})).await;
    assert_eq!(r.status, 200);
    ui.wait_state("disconnected", |s| s["connection"]["state"] == "disconnected").await;

    // The remembered key logs in without a password.
    let r = ui.post("/api/connect", &json!({"server": addr, "name": "Gandalf"})).await;
    assert_eq!(r.status, 200, "{}", r.text());
    ui.wait_state("connected again", |s| s["connection"]["state"] == "connected").await;
    let r = ui.post("/api/password/forget", &json!({"server": addr})).await;
    assert_eq!(r.json(), json!({"ok": true, "removed": true}));

    ui.stop().await;
    server.shutdown().await;
}
