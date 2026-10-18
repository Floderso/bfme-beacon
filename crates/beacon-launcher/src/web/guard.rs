//! Request guard of the web UI: `Host` check for every request (DNS rebinding),
//! token + `Origin` + `Sec-Fetch-Site` checks for `/api`, security headers on
//! every response.

use axum::extract::{Request, State};
use axum::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tracing::debug;

use super::api::ApiError;
use super::Shared;
use crate::util;

/// Header that carries the access token (lowercase, as HTTP/1 normalises it).
pub const TOKEN_HEADER: &str = "x-beacon-token";

/// Content-Security-Policy of every response: only this origin's own script and
/// style files, no inline code, no framing, no form submissions, no plugins.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
                   connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// `true` if `host` (a `Host` header or URI authority) is `127.0.0.1:port` or
/// `localhost:port` (case-insensitive name, exact decimal port).
pub fn host_allowed(host: &str, port: u16) -> bool {
    let Some((name, p)) = host.rsplit_once(':') else {
        return false;
    };
    p == port.to_string() && (name == "127.0.0.1" || name.eq_ignore_ascii_case("localhost"))
}

/// `true` if the request has no `Origin` header or it is this page's own origin
/// (`http://` + the already validated `Host`). `null` and foreign origins fail.
pub fn origin_allowed(origin: Option<&str>, host: &str) -> bool {
    match origin {
        None => true,
        Some(o) => o
            .strip_prefix("http://")
            .is_some_and(|authority| authority.eq_ignore_ascii_case(host)),
    }
}

/// `Sec-Fetch-Site` (sent by modern browsers): only our own page (`same-origin`)
/// or a user navigation (`none`) may reach the API.
fn fetch_site_allowed(value: Option<&str>) -> bool {
    matches!(value, None | Some("same-origin" | "none"))
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ()> {
    match headers.get(name) {
        None => Ok(None),
        Some(v) => v.to_str().map(Some).map_err(|_| ()),
    }
}

/// Why a request is refused (also the `reason` of the 403 answer).
fn check(req: &Request, shared: &Shared) -> Result<(), &'static str> {
    let headers = req.headers();
    let host = header_str(headers, header::HOST.as_str())
        .ok()
        .flatten()
        .filter(|h| host_allowed(h, shared.port))
        .ok_or("host")?;
    if let Some(authority) = req.uri().authority() {
        if !authority.as_str().eq_ignore_ascii_case(host) {
            return Err("host");
        }
    }
    let path = req.uri().path();
    if path == "/api" || path.starts_with("/api/") {
        let origin = header_str(headers, header::ORIGIN.as_str()).map_err(|()| "origin")?;
        if !origin_allowed(origin, host) {
            return Err("origin");
        }
        let site = header_str(headers, "sec-fetch-site").map_err(|()| "fetch_site")?;
        if !fetch_site_allowed(site) {
            return Err("fetch_site");
        }
        let token = headers.get(TOKEN_HEADER).map(HeaderValue::as_bytes).unwrap_or_default();
        if !util::ct_eq(token, shared.token.as_bytes()) {
            return Err("token");
        }
    }
    Ok(())
}

/// The middleware: refuses with `403` or runs the handler; adds the security
/// headers either way.
pub(super) async fn guard(State(shared): State<Shared>, req: Request, next: Next) -> Response {
    let mut res = match check(&req, &shared) {
        Ok(()) => next.run(req).await,
        Err(reason) => {
            debug!(path = %req.uri().path(), reason, "web UI request refused");
            ApiError::forbidden(reason).into_response()
        }
    };
    let h = res.headers_mut();
    let fixed: [(HeaderName, &'static str); 7] = [
        (header::CONTENT_SECURITY_POLICY, CSP),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::CACHE_CONTROL, "no-store"),
        (HeaderName::from_static("cross-origin-opener-policy"), "same-origin"),
        (HeaderName::from_static("cross-origin-resource-policy"), "same-origin"),
    ];
    for (name, value) in fixed {
        h.insert(name, HeaderValue::from_static(value));
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert!(host_allowed("127.0.0.1:4711", 4711));
        assert!(host_allowed("localhost:4711", 4711));
        assert!(host_allowed("LocalHost:4711", 4711));
        for bad in [
            "127.0.0.1",
            "127.0.0.1:4712",
            "127.0.0.1:04711",
            "127.0.0.1:+4711",
            "evil.example:4711",
            "localhost.evil.example:4711",
            "127.0.0.2:4711",
            "[::1]:4711",
            "",
            ":4711",
            "127.0.0.1:4711:4711",
        ] {
            assert!(!host_allowed(bad, 4711), "{bad}");
        }
    }

    #[test]
    fn origins() {
        assert!(origin_allowed(None, "127.0.0.1:80"));
        assert!(origin_allowed(Some("http://127.0.0.1:80"), "127.0.0.1:80"));
        assert!(origin_allowed(Some("http://LOCALHOST:80"), "localhost:80"));
        for bad in [
            "null",
            "https://127.0.0.1:80",
            "http://127.0.0.1:81",
            "http://localhost:80",
            "http://evil.example",
            "http://127.0.0.1:80/",
            "",
        ] {
            assert!(!origin_allowed(Some(bad), "127.0.0.1:80"), "{bad}");
        }
    }

    #[test]
    fn fetch_sites() {
        assert!(fetch_site_allowed(None));
        assert!(fetch_site_allowed(Some("same-origin")));
        assert!(fetch_site_allowed(Some("none")));
        assert!(!fetch_site_allowed(Some("cross-site")));
        assert!(!fetch_site_allowed(Some("same-site")));
    }
}
