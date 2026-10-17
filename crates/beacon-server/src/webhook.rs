//! Optional notifications ("webhook"): one HTTP/1.1 `POST` per event with a plain
//! text body and a `Title` header, which is exactly what ntfy expects
//! (`Authorization: Bearer <token>` for protected topics). Only `http://` URLs
//! are supported: TLS would need a C/asm crypto dependency. Delivery runs in its
//! own task behind a bounded queue; failures are logged, never retried.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::net::Ipv6Addr;
use std::time::Duration;

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

/// Capacity of the notification queue.
pub const QUEUE_LEN: usize = 32;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(3);
const RESPONSE_PEEK: usize = 512;

/// `[webhook]` in the config file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    /// `http://host[:port]/path`.
    pub url: String,
    /// Bearer token (`Authorization: Bearer <token>`), empty = none.
    #[serde(default)]
    pub token: String,
    /// Extra request headers (e.g. ntfy `Priority`, `Tags`).
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Events to send (`start`, `stop`, `join`, `leave`, `launch`, `kick`).
    #[serde(default = "default_events")]
    pub events: Vec<String>,
    /// Title prefix (default: the server name).
    #[serde(default)]
    pub title: String,
}

fn default_events() -> Vec<String> {
    vec!["join".to_owned(), "launch".to_owned()]
}

/// Notification events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    /// The server started.
    Start,
    /// The server is stopping.
    Stop,
    /// A player joined.
    Join,
    /// A player left.
    Leave,
    /// The host started the game.
    Launch,
    /// The host removed a player.
    Kick,
}

impl EventKind {
    /// Every event.
    pub const ALL: [Self; 6] = [
        Self::Start,
        Self::Stop,
        Self::Join,
        Self::Leave,
        Self::Launch,
        Self::Kick,
    ];

    /// Name used in the config file.
    pub fn name(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Join => "join",
            Self::Leave => "leave",
            Self::Launch => "launch",
            Self::Kick => "kick",
        }
    }

    /// Parses a config name.
    pub fn parse(name: &str) -> Option<Self> {
        let name = name.trim().to_ascii_lowercase();
        Self::ALL.into_iter().find(|k| k.name() == name)
    }

    /// Title suffix shown in the notification.
    pub fn title(self) -> &'static str {
        match self {
            Self::Start => "Server gestartet",
            Self::Stop => "Server beendet",
            Self::Join => "Spieler beigetreten",
            Self::Leave => "Spieler gegangen",
            Self::Launch => "Spielstart",
            Self::Kick => "Spieler entfernt",
        }
    }
}

/// A parsed `http://` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpUrl {
    /// Host name or IP address (IPv6 without brackets).
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Path including the query, starting with `/`.
    pub path: String,
}

impl HttpUrl {
    /// Parses `http://host[:port][/path][?query]`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let t = text.trim();
        let rest = t
            .get(..7)
            .filter(|p| p.eq_ignore_ascii_case("http://"))
            .and_then(|_| t.get(7..))
            .ok_or_else(|| {
                if t.to_ascii_lowercase().starts_with("https://") {
                    "https:// is not supported (no TLS); use http:// to a local service \
                     such as your own ntfy"
                        .to_owned()
                } else {
                    "the url must start with http://".to_owned()
                }
            })?;
        let rest = rest.split('#').next().unwrap_or("");
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) => (rest.get(..i).unwrap_or(""), rest.get(i..).unwrap_or("")),
            None => (rest, ""),
        };
        let path = if path.is_empty() {
            "/".to_owned()
        } else if path.starts_with('?') {
            format!("/{path}")
        } else {
            path.to_owned()
        };
        if path.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err("the url path must not contain spaces".to_owned());
        }
        if authority.contains('@') {
            return Err("credentials in the url are not supported; use `token`".to_owned());
        }
        let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
            let (host, after) = bracketed
                .split_once(']')
                .ok_or_else(|| "unterminated IPv6 address in the url".to_owned())?;
            host.parse::<Ipv6Addr>()
                .map_err(|_| format!("invalid IPv6 address {host:?}"))?;
            let port = match after {
                "" => 80,
                p => parse_port(p.strip_prefix(':').unwrap_or("x"))?,
            };
            (host.to_owned(), port)
        } else {
            let (host, port) = match authority.rsplit_once(':') {
                Some((h, p)) => (h, parse_port(p)?),
                None => (authority, 80),
            };
            if host.is_empty()
                || !host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
            {
                return Err(format!("invalid host {host:?} in the url"));
            }
            (host.to_owned(), port)
        };
        Ok(Self { host, port, path })
    }

    /// Value of the `Host` header.
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 80 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

fn parse_port(text: &str) -> Result<u16, String> {
    match text.parse::<u16>() {
        Ok(p) if p != 0 => Ok(p),
        _ => Err(format!("invalid port {text:?} in the url")),
    }
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

const RESERVED_HEADERS: [&str; 6] = [
    "host",
    "content-length",
    "content-type",
    "connection",
    "transfer-encoding",
    "user-agent",
];

/// Validated webhook settings.
#[derive(Clone)]
pub struct WebhookSettings {
    /// Target.
    pub url: HttpUrl,
    /// Bearer token.
    pub token: Option<String>,
    /// Extra headers.
    pub headers: Vec<(String, String)>,
    /// Enabled events.
    pub events: Vec<EventKind>,
    /// Title prefix.
    pub title: String,
}

impl fmt::Debug for WebhookSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookSettings")
            .field("url", &self.url)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("headers", &self.headers.iter().map(|(k, _)| k).collect::<Vec<_>>())
            .field("events", &self.events)
            .field("title", &self.title)
            .finish()
    }
}

impl WebhookSettings {
    /// Validates `[webhook]`; `server_name` is the default title.
    pub fn from_config(cfg: &WebhookConfig, server_name: &str) -> Result<Self, String> {
        let url = HttpUrl::parse(&cfg.url)?;
        let token = match cfg.token.trim() {
            "" => None,
            t if t.chars().all(|c| c.is_ascii_graphic()) => Some(t.to_owned()),
            _ => return Err("token must be printable ASCII without spaces".to_owned()),
        };
        let mut headers = Vec::new();
        for (name, value) in &cfg.headers {
            if name.is_empty() || !name.chars().all(is_token_char) {
                return Err(format!("invalid header name {name:?}"));
            }
            let lower = name.to_ascii_lowercase();
            if RESERVED_HEADERS.contains(&lower.as_str())
                || (token.is_some() && lower == "authorization")
                || lower == "title"
            {
                return Err(format!("header {name:?} is set by the server"));
            }
            if value.chars().any(|c| c.is_control() && c != '\t') {
                return Err(format!("header {name:?} contains control characters"));
            }
            headers.push((name.clone(), value.trim().to_owned()));
        }
        let mut events = Vec::new();
        for name in &cfg.events {
            let kind = EventKind::parse(name).ok_or_else(|| {
                format!("unknown event {name:?} (start, stop, join, leave, launch, kick)")
            })?;
            if !events.contains(&kind) {
                events.push(kind);
            }
        }
        let title: String = match cfg.title.trim() {
            "" => server_name,
            t => t,
        }
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect();
        Ok(Self {
            url,
            token,
            headers,
            events,
            title,
        })
    }

    /// Headers of a request for `kind` (Title, Authorization, extras).
    pub fn request_headers(&self, kind: EventKind) -> Vec<(String, String)> {
        let mut h = vec![(
            "Title".to_owned(),
            format!("{}: {}", self.title, kind.title()),
        )];
        if let Some(token) = &self.token {
            h.push(("Authorization".to_owned(), format!("Bearer {token}")));
        }
        h.extend(self.headers.iter().cloned());
        h
    }
}

/// One queued notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    /// Event.
    pub kind: EventKind,
    /// Text body.
    pub body: String,
}

/// Handle to queue notifications (cheap to clone; never blocks).
#[derive(Debug, Clone)]
pub struct Notifier {
    tx: mpsc::Sender<Notification>,
    events: Vec<EventKind>,
}

impl Notifier {
    /// Queues `body` if `kind` is enabled; drops it if the queue is full.
    pub fn notify(&self, kind: EventKind, body: String) {
        if self.events.contains(&kind)
            && self.tx.try_send(Notification { kind, body }).is_err()
        {
            debug!("webhook queue full, notification dropped");
        }
    }
}

/// Creates the notifier and its delivery task (the caller spawns it). The task
/// stops after `shutdown`, delivering what is already queued for at most 3 s.
pub fn start(
    settings: WebhookSettings,
    shutdown: watch::Receiver<bool>,
) -> (Notifier, impl Future<Output = ()> + Send + 'static) {
    let (tx, rx) = mpsc::channel(QUEUE_LEN);
    let notifier = Notifier {
        tx,
        events: settings.events.clone(),
    };
    (notifier, worker(settings, rx, shutdown))
}

async fn worker(
    settings: WebhookSettings,
    mut rx: mpsc::Receiver<Notification>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Some(n) => deliver(&settings, &n).await,
                None => return,
            },
            _ = shutdown.changed() => break,
        }
    }
    let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;
    while let Ok(n) = rx.try_recv() {
        if tokio::time::timeout_at(deadline, deliver(&settings, &n))
            .await
            .is_err()
        {
            break;
        }
    }
}

async fn deliver(settings: &WebhookSettings, n: &Notification) {
    let headers = settings.request_headers(n.kind);
    match post(&settings.url, &headers, &n.body).await {
        Ok(status) if (200..300).contains(&status) => {
            debug!(event = n.kind.name(), status, "webhook delivered");
        }
        Ok(status) => warn!(event = n.kind.name(), status, "webhook rejected the notification"),
        Err(e) => warn!(event = n.kind.name(), "webhook failed: {e}"),
    }
}

/// Webhook delivery errors.
#[derive(Debug)]
pub enum WebhookError {
    /// Connect, write or read failed.
    Io(std::io::Error),
    /// No answer within 5 s.
    Timeout,
    /// The answer is not an HTTP status line.
    BadResponse,
}

impl fmt::Display for WebhookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Timeout => f.write_str("timeout"),
            Self::BadResponse => f.write_str("invalid HTTP response"),
        }
    }
}

impl std::error::Error for WebhookError {}

impl From<std::io::Error> for WebhookError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Header values: plain ASCII as is, anything else as an RFC 2047 encoded word
/// (`=?UTF-8?B?…?=`, understood by ntfy).
pub fn encode_header_value(value: &str) -> String {
    if value.is_ascii() {
        value.to_owned()
    } else {
        format!(
            "=?UTF-8?B?{}?=",
            beacon_proto::control::base64_encode(value.as_bytes())
        )
    }
}

/// The complete request bytes.
pub fn build_request(url: &HttpUrl, headers: &[(String, String)], body: &str) -> Vec<u8> {
    let mut req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: beacon-server/{}\r\n\
         Content-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n",
        url.path,
        url.host_header(),
        crate::VERSION,
        body.len()
    );
    for (name, value) in headers {
        req.push_str(name);
        req.push_str(": ");
        req.push_str(&encode_header_value(value));
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    req.push_str(body);
    req.into_bytes()
}

/// The status code of an HTTP/1.x response that starts with `head`.
pub fn parse_status_line(head: &[u8]) -> Option<u16> {
    let line = head.split(|&b| b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim_end();
    let mut parts = line.split(' ');
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    parts
        .next()?
        .parse::<u16>()
        .ok()
        .filter(|c| (100..=599).contains(c))
}

/// Sends one POST and returns the response status code.
pub async fn post(url: &HttpUrl, headers: &[(String, String)], body: &str) -> Result<u16, WebhookError> {
    let request = build_request(url, headers, body);
    let exchange = async {
        let mut stream = TcpStream::connect((url.host.as_str(), url.port)).await?;
        stream.write_all(&request).await?;
        let mut head = [0u8; RESPONSE_PEEK];
        let mut len = 0usize;
        while let Some(space) = head.get_mut(len..) {
            if space.is_empty() {
                break;
            }
            let n = stream.read(space).await?;
            if n == 0 {
                break;
            }
            len = len.saturating_add(n);
            if head
                .get(..len)
                .is_some_and(|h| h.windows(2).any(|w| w == b"\r\n"))
            {
                break;
            }
        }
        parse_status_line(head.get(..len).unwrap_or_default()).ok_or(WebhookError::BadResponse)
    };
    tokio::time::timeout(REQUEST_TIMEOUT, exchange)
        .await
        .map_err(|_| WebhookError::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(url: &str) -> WebhookConfig {
        WebhookConfig {
            url: url.to_owned(),
            token: String::new(),
            headers: BTreeMap::new(),
            events: default_events(),
            title: String::new(),
        }
    }

    #[test]
    fn url_parsing() {
        let u = HttpUrl::parse("http://ntfy.lan/beacon").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("ntfy.lan", 80, "/beacon"));
        assert_eq!(u.host_header(), "ntfy.lan");
        let u = HttpUrl::parse("HTTP://127.0.0.1:8080").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("127.0.0.1", 8080, "/"));
        assert_eq!(u.host_header(), "127.0.0.1:8080");
        let u = HttpUrl::parse("http://[::1]:81/a?b=c#frag").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.path.as_str()), ("::1", 81, "/a?b=c"));
        assert_eq!(u.host_header(), "[::1]:81");
        let u = HttpUrl::parse("http://h?x=1").unwrap();
        assert_eq!(u.path, "/?x=1");
        for bad in [
            "https://ntfy.sh/x",
            "ftp://x",
            "http://",
            "http://:80/",
            "http://a b/",
            "http://h:0/",
            "http://h:99999/",
            "http://user:pw@h/",
            "http://[::1/",
            "http://[zz]/",
            "http://h/a b",
        ] {
            assert!(HttpUrl::parse(bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn settings_validation() {
        let s = WebhookSettings::from_config(&cfg("http://h/t"), "Beacon").unwrap();
        assert_eq!(s.events, vec![EventKind::Join, EventKind::Launch]);
        assert_eq!(s.title, "Beacon");
        let mut c = cfg("http://h/t");
        c.token = "tk_abc".into();
        c.headers.insert("Priority".into(), "high".into());
        c.events = vec!["kick".into(), "KICK".into(), "start".into()];
        c.title = "Mittelerde".into();
        let s = WebhookSettings::from_config(&c, "Beacon").unwrap();
        assert_eq!(s.events, vec![EventKind::Kick, EventKind::Start]);
        assert!(!format!("{s:?}").contains("tk_abc"));
        let h = s.request_headers(EventKind::Kick);
        assert_eq!(h[0], ("Title".into(), "Mittelerde: Spieler entfernt".into()));
        assert_eq!(h[1], ("Authorization".into(), "Bearer tk_abc".into()));
        assert_eq!(h[2], ("Priority".into(), "high".into()));

        for (name, value) in [("Bad Name", "x"), ("Host", "x"), ("X", "a\r\nb"), ("Title", "t")] {
            let mut c = cfg("http://h/t");
            c.headers.insert(name.into(), value.into());
            assert!(WebhookSettings::from_config(&c, "B").is_err(), "accepted {name}");
        }
        let mut c = cfg("http://h/t");
        c.events = vec!["explode".into()];
        assert!(WebhookSettings::from_config(&c, "B").is_err());
        let mut c = cfg("http://h/t");
        c.token = "has space".into();
        assert!(WebhookSettings::from_config(&c, "B").is_err());
    }

    #[test]
    fn request_format() {
        let url = HttpUrl::parse("http://h:8080/topic").unwrap();
        let req = build_request(
            &url,
            &[("Title".into(), "Größe".into()), ("Tags".into(), "x".into())],
            "Frodo ist beigetreten.",
        );
        let text = String::from_utf8(req).unwrap();
        assert!(text.starts_with("POST /topic HTTP/1.1\r\nHost: h:8080\r\n"));
        assert!(text.contains("Content-Length: 22\r\n"));
        assert!(text.contains("Title: =?UTF-8?B?R3LDtsOfZQ==?=\r\n"));
        assert!(text.contains("Tags: x\r\n"));
        assert!(text.ends_with("\r\n\r\nFrodo ist beigetreten."));
    }

    #[test]
    fn status_line() {
        assert_eq!(parse_status_line(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status_line(b"HTTP/1.0 403 Forbidden"), Some(403));
        assert_eq!(parse_status_line(b"HTTP/2 200\r\n"), None);
        assert_eq!(parse_status_line(b"garbage"), None);
        assert_eq!(parse_status_line(b"HTTP/1.1 99999 x"), None);
        assert_eq!(parse_status_line(b""), None);
        assert_eq!(parse_status_line(&[0xff, 0xfe]), None);
    }

    #[tokio::test]
    async fn post_reaches_a_local_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                req.extend_from_slice(&buf[..n]);
                if n == 0 || req.ends_with(b"hallo") {
                    break;
                }
            }
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await.unwrap();
            String::from_utf8(req).unwrap()
        });
        let url = HttpUrl::parse(&format!("http://{addr}/beacon")).unwrap();
        let status = post(&url, &[("Title".into(), "T".into())], "hallo").await.unwrap();
        assert_eq!(status, 200);
        let req = server.await.unwrap();
        assert!(req.starts_with("POST /beacon HTTP/1.1\r\n"));
        assert!(req.contains("\r\nTitle: T\r\n"));
    }

    #[tokio::test]
    async fn post_fails_cleanly() {
        // Nothing listens on the port (bind and drop to find a free one).
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let url = HttpUrl::parse(&format!("http://{addr}/")).unwrap();
        assert!(post(&url, &[], "x").await.is_err());
    }
}
