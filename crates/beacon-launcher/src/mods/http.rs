//! A minimal HTTP client interface for the workshop client: one blocking `GET`
//! with an optional `Range`, status and the few headers resumable downloads
//! need. The real transport is WinHTTP ([`WinHttp`], `sys::http_get`): the
//! system's TLS and proxy, no TLS crate in Beacon. Tests use the same transport
//! against a local plain-HTTP server.

use std::fmt;
use std::io::{self, Read};
use std::time::Duration;

/// Longest URL accepted.
pub const MAX_URL_LEN: usize = 2048;

/// A parsed `http`/`https` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// `https`.
    pub secure: bool,
    /// Host (name or IPv4 literal).
    pub host: String,
    /// Port.
    pub port: u16,
    /// Path and query, starting with `/`.
    pub path: String,
}

/// Why a request failed before a response arrived.
#[derive(Debug)]
pub enum HttpError {
    /// The URL is not acceptable.
    BadUrl(String),
    /// Connection, TLS, timeout or read failure.
    Io(io::Error),
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadUrl(u) => write!(f, "invalid URL {u:?}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for HttpError {}

fn is_url_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._~/?=&:%+!$'()*,;@".contains(c)
}

/// Parses `http://host[:port]/path?query` (no user info, no fragment, only
/// unreserved and reserved URL characters, at most [`MAX_URL_LEN`] bytes).
pub fn parse_url(url: &str) -> Result<Url, HttpError> {
    let bad = || HttpError::BadUrl(url.chars().take(120).collect());
    if url.len() > MAX_URL_LEN {
        return Err(bad());
    }
    let (secure, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(bad());
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (rest.get(..i).ok_or_else(bad)?, rest.get(i..).ok_or_else(bad)?),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok().filter(|&p| p != 0).ok_or_else(bad)?),
        None => (authority, if secure { 443 } else { 80 }),
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|l| {
            !l.is_empty() && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !host_ok || !path.chars().all(is_url_char) || path.contains("..") {
        return Err(bad());
    }
    Ok(Url {
        secure,
        host: host.to_ascii_lowercase(),
        port,
        path: path.to_owned(),
    })
}

/// A `GET`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// URL.
    pub url: String,
    /// Extra headers.
    pub headers: Vec<(String, String)>,
    /// `Range: bytes=<n>-`.
    pub range_from: Option<u64>,
    /// Timeout per step (connect, send, each receive).
    pub timeout: Duration,
}

/// `Content-Range: bytes start-end/total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentRange {
    /// First byte.
    pub start: u64,
    /// Last byte (inclusive).
    pub end: u64,
    /// Total size, if given.
    pub total: Option<u64>,
}

impl ContentRange {
    /// Parses `bytes 100-199/1000` (or `/*`).
    pub fn parse(text: &str) -> Option<Self> {
        let rest = text.trim().strip_prefix("bytes ")?;
        let (range, total) = rest.split_once('/')?;
        let (start, end) = range.split_once('-')?;
        let start = start.trim().parse().ok()?;
        let end = end.trim().parse().ok()?;
        let total = match total.trim() {
            "*" => None,
            t => Some(t.parse().ok()?),
        };
        (start <= end).then_some(Self { start, end, total })
    }
}

/// A response.
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// `Content-Length`.
    pub content_length: Option<u64>,
    /// `Content-Range`.
    pub content_range: Option<ContentRange>,
    /// `Retry-After` in seconds (the date form is ignored).
    pub retry_after: Option<Duration>,
    /// `Content-Encoding` (Beacon accepts only none or `identity`).
    pub content_encoding: Option<String>,
    /// The body.
    pub body: Box<dyn Read + Send>,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("content_length", &self.content_length)
            .field("content_range", &self.content_range)
            .finish_non_exhaustive()
    }
}

/// Something that performs `GET`s.
pub trait HttpTransport: Send + Sync {
    /// Performs the request.
    fn get(&self, req: &HttpRequest) -> Result<HttpResponse, HttpError>;
}

/// WinHTTP (Windows only; elsewhere every request fails with `Unsupported`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinHttp {
    /// `User-Agent`.
    pub user_agent: String,
    /// Use the system proxy settings (off for loopback tests).
    pub system_proxy: bool,
}

impl HttpTransport for WinHttp {
    fn get(&self, req: &HttpRequest) -> Result<HttpResponse, HttpError> {
        let url = parse_url(&req.url)?;
        let mut headers = req.headers.clone();
        if let Some(from) = req.range_from {
            headers.push(("Range".to_owned(), format!("bytes={from}-")));
        }
        let timeout_ms = i32::try_from(req.timeout.as_millis()).unwrap_or(i32::MAX).max(1000);
        let raw = crate::sys::http_get(&crate::sys::HttpRequestSpec {
            secure: url.secure,
            host: &url.host,
            port: url.port,
            path: &url.path,
            user_agent: &self.user_agent,
            headers: &headers,
            system_proxy: self.system_proxy,
            timeout_ms,
        })
        .map_err(HttpError::Io)?;
        Ok(HttpResponse {
            status: raw.status,
            content_length: raw.content_length.and_then(|v| v.trim().parse().ok()),
            content_range: raw.content_range.as_deref().and_then(ContentRange::parse),
            retry_after: raw
                .retry_after
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(Duration::from_secs),
            content_encoding: raw.content_encoding.map(|e| e.trim().to_ascii_lowercase()).filter(|e| !e.is_empty()),
            body: raw.body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_url("https://workshop-files.bfmeladder.com/1c32-x/57e3a89b3c5fa1023541c29fa983ed34").unwrap();
        assert!(u.secure);
        assert_eq!((u.host.as_str(), u.port), ("workshop-files.bfmeladder.com", 443));
        assert_eq!(u.path, "/1c32-x/57e3a89b3c5fa1023541c29fa983ed34");
        let u = parse_url("http://127.0.0.1:8080/api/workshop/download?guid=official-0:7.0.5").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.secure), ("127.0.0.1", 8080, false));
        assert_eq!(parse_url("http://Example.ORG").unwrap().path, "/");
        for bad in [
            "ftp://x/",
            "https://user@host/",
            "https://host:0/",
            "https://host:99999/",
            "https:///x",
            "https://ho st/",
            "https://host/a b",
            "https://host/a#frag",
            "https://host/a\\b",
            "https://host/../etc",
            "https://-host/",
            "https://[::1]/",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
        assert!(parse_url(&format!("https://h/{}", "a".repeat(MAX_URL_LEN))).is_err());
    }

    #[test]
    fn content_ranges() {
        assert_eq!(
            ContentRange::parse("bytes 100-199/1000"),
            Some(ContentRange { start: 100, end: 199, total: Some(1000) })
        );
        assert_eq!(ContentRange::parse("bytes 0-0/*").unwrap().total, None);
        assert_eq!(ContentRange::parse("bytes 9-1/10"), None);
        assert_eq!(ContentRange::parse("items 0-1/2"), None);
    }
}
