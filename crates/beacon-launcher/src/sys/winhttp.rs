//! A synchronous HTTP(S) `GET` over WinHTTP for the BFME Workshop client
//! (`mods::http`). WinHTTP brings the system's TLS stack, certificate store and
//! proxy settings, so the launcher needs no TLS crate (no `ring`, no OpenSSL).
//!
//! One call = one request on its own session (no connection reuse, no cookies,
//! no automatic redirects, no decompression). The body is read in the caller's
//! pieces through [`std::io::Read`]; the handles are closed on drop.

#![allow(unsafe_code)]

use std::io::{self, Read};
use std::ptr;

use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};
use windows_sys::Win32::Networking::WinHttp::{
    WinHttpAddRequestHeaders, WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest,
    WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption,
    WinHttpSetTimeouts, ERROR_WINHTTP_HEADER_NOT_FOUND, ERROR_WINHTTP_TIMEOUT, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_ADDREQ_FLAG_ADD, WINHTTP_DISABLE_COOKIES, WINHTTP_FLAG_ESCAPE_DISABLE,
    WINHTTP_FLAG_SECURE, WINHTTP_OPTION_DISABLE_FEATURE, WINHTTP_OPTION_REDIRECT_POLICY,
    WINHTTP_OPTION_REDIRECT_POLICY_NEVER, WINHTTP_QUERY_CONTENT_ENCODING, WINHTTP_QUERY_CONTENT_LENGTH,
    WINHTTP_QUERY_CONTENT_RANGE, WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_RETRY_AFTER, WINHTTP_QUERY_STATUS_CODE,
};

use super::windows::wide;
use super::{HttpRequestSpec, RawHttpResponse};

/// Longest response header value read.
const MAX_HEADER_UNITS: usize = 4096;

/// An open WinHTTP handle, closed on drop.
struct Handle(*mut core::ffi::c_void);

// SAFETY: WinHTTP handles may be used from any thread; Beacon uses each one from
// one thread at a time (the reader owns it).
unsafe impl Send for Handle {}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle came from a successful WinHttpOpen/Connect/OpenRequest
            // and is closed exactly once.
            unsafe {
                WinHttpCloseHandle(self.0);
            }
        }
    }
}

fn last_error(op: &str) -> io::Error {
    // SAFETY: plain thread-local read.
    let code = unsafe { GetLastError() };
    if code == ERROR_WINHTTP_TIMEOUT {
        io::Error::new(io::ErrorKind::TimedOut, format!("{op}: timeout"))
    } else {
        io::Error::other(format!("{op}: WinHTTP error {code}"))
    }
}

fn open(handle: *mut core::ffi::c_void, op: &str) -> io::Result<Handle> {
    if handle.is_null() {
        Err(last_error(op))
    } else {
        Ok(Handle(handle))
    }
}

fn set_u32_option(handle: &Handle, option: u32, value: u32) -> io::Result<()> {
    // SAFETY: `value` is a live u32 for the duration of the call; the handle is open.
    let ok = unsafe {
        WinHttpSetOption(
            handle.0,
            option,
            (&value as *const u32).cast(),
            std::mem::size_of::<u32>() as u32,
        )
    };
    if ok == 0 {
        Err(last_error("WinHttpSetOption"))
    } else {
        Ok(())
    }
}

/// A response header as text (`None` if absent or unreadable).
fn query_text(request: &Handle, info: u32) -> Option<String> {
    let mut buf: Vec<u16> = vec![0; 128];
    loop {
        let mut len = u32::try_from(buf.len() * 2).ok()?;
        // SAFETY: `buf` has `len` writable bytes; null name/index select a standard
        // header by `info`.
        let ok = unsafe {
            WinHttpQueryHeaders(
                request.0,
                info,
                ptr::null(),
                buf.as_mut_ptr().cast(),
                &mut len,
                ptr::null_mut(),
            )
        };
        if ok != 0 {
            let units = usize::try_from(len / 2).ok()?;
            return Some(String::from_utf16_lossy(buf.get(..units)?));
        }
        // SAFETY: plain thread-local read.
        let err = unsafe { GetLastError() };
        if err == ERROR_WINHTTP_HEADER_NOT_FOUND {
            return None;
        }
        let needed = usize::try_from(len / 2).ok()?.saturating_add(1);
        if err != ERROR_INSUFFICIENT_BUFFER || needed > MAX_HEADER_UNITS || needed <= buf.len() {
            return None;
        }
        buf.resize(needed, 0);
    }
}

fn query_status(request: &Handle) -> io::Result<u16> {
    let mut status: u32 = 0;
    let mut len = std::mem::size_of::<u32>() as u32;
    // SAFETY: `status` is a live u32 of `len` bytes; the number flag makes WinHTTP
    // write a DWORD.
    let ok = unsafe {
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            ptr::null(),
            (&mut status as *mut u32).cast(),
            &mut len,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_error("WinHttpQueryHeaders(status)"));
    }
    u16::try_from(status).map_err(|_| io::Error::other(format!("bad HTTP status {status}")))
}

/// The open request whose body is read.
struct Body {
    request: Handle,
    // Kept open until the body is dropped (the request depends on them).
    _connect: Handle,
    _session: Handle,
}

impl Read for Body {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let mut got: u32 = 0;
        // SAFETY: `buf` has at least `want` writable bytes; `got` is a live u32.
        let ok = unsafe { WinHttpReadData(self.request.0, buf.as_mut_ptr().cast(), want, &mut got) };
        if ok == 0 {
            return Err(last_error("WinHttpReadData"));
        }
        Ok(usize::try_from(got).unwrap_or(0).min(buf.len()))
    }
}

/// Performs a `GET` and returns the status, the headers Beacon uses and the body.
pub fn http_get(spec: &HttpRequestSpec<'_>) -> io::Result<RawHttpResponse> {
    let agent = wide(spec.user_agent);
    let access = if spec.system_proxy {
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
    } else {
        WINHTTP_ACCESS_TYPE_NO_PROXY
    };
    // SAFETY: `agent` is NUL-terminated UTF-16 that outlives the call; null proxy
    // name and bypass list are allowed; flags 0 = synchronous.
    let session = open(
        unsafe { WinHttpOpen(agent.as_ptr(), access, ptr::null(), ptr::null(), 0) },
        "WinHttpOpen",
    )?;
    let t = spec.timeout_ms;
    // SAFETY: the session handle is open.
    if unsafe { WinHttpSetTimeouts(session.0, t, t, t, t) } == 0 {
        return Err(last_error("WinHttpSetTimeouts"));
    }
    set_u32_option(&session, WINHTTP_OPTION_REDIRECT_POLICY, WINHTTP_OPTION_REDIRECT_POLICY_NEVER)?;
    let host = wide(spec.host);
    // SAFETY: `host` is NUL-terminated UTF-16 that outlives the call.
    let connect = open(
        unsafe { WinHttpConnect(session.0, host.as_ptr(), spec.port, 0) },
        "WinHttpConnect",
    )?;
    let verb = wide("GET");
    let path = wide(spec.path);
    let flags = WINHTTP_FLAG_ESCAPE_DISABLE | if spec.secure { WINHTTP_FLAG_SECURE } else { 0 };
    // SAFETY: verb and path are NUL-terminated UTF-16 that outlive the call; null
    // version (HTTP/1.1), referrer and accept types are allowed.
    let request = open(
        unsafe {
            WinHttpOpenRequest(
                connect.0,
                verb.as_ptr(),
                path.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                flags,
            )
        },
        "WinHttpOpenRequest",
    )?;
    set_u32_option(&request, WINHTTP_OPTION_DISABLE_FEATURE, WINHTTP_DISABLE_COOKIES)?;
    let mut header_text = String::new();
    for (name, value) in spec.headers {
        header_text.push_str(name);
        header_text.push_str(": ");
        header_text.push_str(value);
        header_text.push_str("\r\n");
    }
    if !header_text.is_empty() {
        let units: Vec<u16> = header_text.encode_utf16().collect();
        let len = u32::try_from(units.len()).map_err(|_| io::Error::other("headers too long"))?;
        // SAFETY: `units` holds `len` UTF-16 units that outlive the call.
        let ok = unsafe { WinHttpAddRequestHeaders(request.0, units.as_ptr(), len, WINHTTP_ADDREQ_FLAG_ADD) };
        if ok == 0 {
            return Err(last_error("WinHttpAddRequestHeaders"));
        }
    }
    // SAFETY: no extra headers or body; the request handle is open.
    let sent = unsafe { WinHttpSendRequest(request.0, ptr::null(), 0, ptr::null(), 0, 0, 0) };
    if sent == 0 {
        return Err(last_error("WinHttpSendRequest"));
    }
    // SAFETY: reserved pointer must be null.
    if unsafe { WinHttpReceiveResponse(request.0, ptr::null_mut()) } == 0 {
        return Err(last_error("WinHttpReceiveResponse"));
    }
    let status = query_status(&request)?;
    let content_length = query_text(&request, WINHTTP_QUERY_CONTENT_LENGTH);
    let content_range = query_text(&request, WINHTTP_QUERY_CONTENT_RANGE);
    let retry_after = query_text(&request, WINHTTP_QUERY_RETRY_AFTER);
    let content_encoding = query_text(&request, WINHTTP_QUERY_CONTENT_ENCODING);
    Ok(RawHttpResponse {
        status,
        content_length,
        content_range,
        retry_after,
        content_encoding,
        body: Box::new(Body {
            request,
            _connect: connect,
            _session: session,
        }),
    })
}
