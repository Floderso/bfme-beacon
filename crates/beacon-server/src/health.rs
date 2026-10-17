//! `beacon-server health`: a minimal blocking HTTP probe of `GET /health`
//! (used as the Docker healthcheck; the image has no shell or curl).

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::webhook::parse_status_line;

/// Address used when neither `--addr` nor a config file is available.
pub const DEFAULT_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 28087);
const MAX_RESPONSE: u64 = 4096;

/// Why the probe failed.
#[derive(Debug)]
pub enum HealthError {
    /// Address could not be resolved.
    Resolve(String),
    /// Connect/read/write failed.
    Io(io::Error),
    /// Not an HTTP response.
    BadResponse,
    /// The endpoint answered, but not `200 ok`.
    Unhealthy {
        /// HTTP status.
        status: u16,
        /// Body (truncated).
        body: String,
    },
}

impl fmt::Display for HealthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve(a) => write!(f, "cannot resolve {a}"),
            Self::Io(e) => write!(f, "{e}"),
            Self::BadResponse => f.write_str("invalid HTTP response"),
            Self::Unhealthy { status, body } => write!(f, "HTTP {status}: {body}"),
        }
    }
}

impl std::error::Error for HealthError {}

impl From<io::Error> for HealthError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// The address to probe for a status endpoint bound to `bind` (an unspecified
/// address becomes loopback).
pub fn probe_addr(bind: SocketAddr) -> SocketAddr {
    match bind.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => SocketAddr::new(Ipv4Addr::LOCALHOST.into(), bind.port()),
        IpAddr::V6(ip) if ip.is_unspecified() => SocketAddr::new(Ipv6Addr::LOCALHOST.into(), bind.port()),
        _ => bind,
    }
}

/// Resolves `HOST:PORT`.
pub fn resolve(addr: &str) -> Result<SocketAddr, HealthError> {
    addr.to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .ok_or_else(|| HealthError::Resolve(addr.to_owned()))
}

/// Probes `GET /health`; `Ok` only for HTTP 200 with body `ok`.
pub fn check(addr: SocketAddr, timeout: Duration) -> Result<(), HealthError> {
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    // One write: the request must not trickle out in pieces.
    let request = format!(
        "GET /health HTTP/1.1\r\nHost: {addr}\r\nUser-Agent: beacon-server-health\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    stream.take(MAX_RESPONSE).read_to_end(&mut response)?;
    let status = parse_status_line(&response).ok_or(HealthError::BadResponse)?;
    let body = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .and_then(|i| response.get(i + 4..))
        .map(|b| String::from_utf8_lossy(b).trim().to_owned())
        .unwrap_or_default();
    if status == 200 && body == "ok" {
        Ok(())
    } else {
        Err(HealthError::Unhealthy {
            status,
            body: body.chars().take(200).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn probe_addr_maps_unspecified_to_loopback() {
        assert_eq!(probe_addr("0.0.0.0:28087".parse().unwrap()), "127.0.0.1:28087".parse().unwrap());
        assert_eq!(probe_addr("[::]:1".parse().unwrap()), "[::1]:1".parse().unwrap());
        assert_eq!(probe_addr("10.0.0.1:5".parse().unwrap()), "10.0.0.1:5".parse().unwrap());
    }

    fn serve_once(reply: &'static [u8]) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
            }
            let _ = s.write_all(reply);
        });
        addr
    }

    #[test]
    fn check_accepts_only_ok() {
        let t = Duration::from_secs(3);
        let ok = serve_once(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
        assert!(check(ok, t).is_ok());
        let bad = serve_once(b"HTTP/1.1 503 Service Unavailable\r\n\r\nrelay stalled");
        assert!(matches!(check(bad, t), Err(HealthError::Unhealthy { status: 503, .. })));
        let junk = serve_once(b"SSH-2.0-OpenSSH\r\n");
        assert!(matches!(check(junk, t), Err(HealthError::BadResponse)));
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = l.local_addr().unwrap();
        drop(l);
        assert!(check(closed, t).is_err());
        assert!(resolve("127.0.0.1:1").is_ok());
        assert!(resolve("no port").is_err());
    }
}
