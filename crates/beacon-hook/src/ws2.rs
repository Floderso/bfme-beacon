//! Replacements for the exe's five `WS2_32.dll` IAT slots (spec 03 §3.2/§8.4;
//! WS2_32 is a KnownDLL, so these imports cannot be proxied by a file).
//!
//! `recvfrom` and `recv` virtualise VIRTUAL sockets like the wsock32 exports do
//! (the lobby/in-game read path `UDP::Read` uses `WS2_32!recvfrom`). `getsockopt`,
//! `setsockopt` and `WSAIoctl` act on the real socket (architecture §4.2) and
//! chain to the original pointer. These are WinSock 2 functions: no WinSock 1.1
//! option renumbering here.

use core::ffi::{c_char, c_void};
use std::sync::atomic::AtomicUsize;

use crate::ffi::{self, SOCKET};
use crate::{state, vsock};

/// The patched imports in descriptor order (identity-checked layout).
pub const NAMES: [&str; 5] = crate::pe::BFME_WS2_32_IMPORTS;
/// Index of `WSAIoctl` in [`NAMES`] / [`ORIG`].
pub const WSAIOCTL: usize = 0;
/// Index of `getsockopt`.
pub const GETSOCKOPT: usize = 1;
/// Index of `recv`.
pub const RECV: usize = 2;
/// Index of `recvfrom`.
pub const RECVFROM: usize = 3;
/// Index of `setsockopt`.
pub const SETSOCKOPT: usize = 4;

/// Original slot values (what the loader resolved), chained to.
pub static ORIG: [AtomicUsize; 5] = [const { AtomicUsize::new(0) }; 5];

type WsaIoctlFn = unsafe extern "system" fn(
    SOCKET,
    u32,
    *mut c_void,
    u32,
    *mut c_void,
    u32,
    *mut u32,
    *mut c_void,
    *mut c_void,
) -> i32;
type GetSockOptFn = unsafe extern "system" fn(SOCKET, i32, i32, *mut c_char, *mut i32) -> i32;
type RecvFn = unsafe extern "system" fn(SOCKET, *mut c_char, i32, i32) -> i32;
type RecvFromFn = unsafe extern "system" fn(SOCKET, *mut c_char, i32, i32, *mut c_void, *mut i32) -> i32;
type SetSockOptFn = unsafe extern "system" fn(SOCKET, i32, i32, *const c_char, i32) -> i32;

/// Hook addresses in [`NAMES`] order.
pub fn hooks() -> [usize; 5] {
    [
        hook_wsaioctl as WsaIoctlFn as usize,
        hook_getsockopt as GetSockOptFn as usize,
        hook_recv as RecvFn as usize,
        hook_recvfrom as RecvFromFn as usize,
        hook_setsockopt as SetSockOptFn as usize,
    ]
}

/// The saved original of slot `index`.
///
/// # Safety
/// `F` must be the fn-pointer type of import `NAMES[index]`.
unsafe fn original<F: Copy>(index: usize) -> Option<F> {
    // SAFETY: forwarded caller contract.
    ORIG.get(index).and_then(|slot| unsafe { crate::iat::load_fn::<F>(slot) })
}

unsafe extern "system" fn hook_wsaioctl(
    s: SOCKET,
    code: u32,
    inbuf: *mut c_void,
    inlen: u32,
    outbuf: *mut c_void,
    outlen: u32,
    returned: *mut u32,
    overlapped: *mut c_void,
    completion: *mut c_void,
) -> i32 {
    // SAFETY: `WsaIoctlFn` is the signature of import `WSAIOCTL`.
    match unsafe { original::<WsaIoctlFn>(WSAIOCTL) } {
        // SAFETY: original function with the caller's arguments.
        Some(f) => unsafe { f(s, code, inbuf, inlen, outbuf, outlen, returned, overlapped, completion) },
        // SAFETY: arguments passed through.
        None => unsafe { ffi::WSAIoctl(s, code, inbuf, inlen, outbuf, outlen, returned, overlapped, completion) },
    }
}

unsafe extern "system" fn hook_getsockopt(
    s: SOCKET,
    level: i32,
    optname: i32,
    optval: *mut c_char,
    optlen: *mut i32,
) -> i32 {
    // SAFETY: `GetSockOptFn` is the signature of import `GETSOCKOPT`.
    match unsafe { original::<GetSockOptFn>(GETSOCKOPT) } {
        // SAFETY: original function with the caller's arguments.
        Some(f) => unsafe { f(s, level, optname, optval, optlen) },
        // SAFETY: arguments passed through.
        None => unsafe { ffi::getsockopt(s, level, optname, optval, optlen) },
    }
}

unsafe extern "system" fn hook_setsockopt(
    s: SOCKET,
    level: i32,
    optname: i32,
    optval: *const c_char,
    optlen: i32,
) -> i32 {
    // SAFETY: `SetSockOptFn` is the signature of import `SETSOCKOPT`.
    match unsafe { original::<SetSockOptFn>(SETSOCKOPT) } {
        // SAFETY: original function with the caller's arguments.
        Some(f) => unsafe { f(s, level, optname, optval, optlen) },
        // SAFETY: arguments passed through.
        None => unsafe { ffi::setsockopt(s, level, optname, optval, optlen) },
    }
}

unsafe extern "system" fn hook_recv(s: SOCKET, buf: *mut c_char, len: i32, flags: i32) -> i32 {
    if let Some(st) = state::get() {
        // SAFETY: arguments passed through (no `from`).
        if let Some(r) = unsafe { vsock::recvfrom(st, s, buf, len, flags, core::ptr::null_mut(), core::ptr::null_mut()) } {
            return r;
        }
    }
    // SAFETY: `RecvFn` is the signature of import `RECV`.
    match unsafe { original::<RecvFn>(RECV) } {
        // SAFETY: original function with the caller's arguments.
        Some(f) => unsafe { f(s, buf, len, flags) },
        // SAFETY: arguments passed through.
        None => unsafe { ffi::recv(s, buf, len, flags) },
    }
}

unsafe extern "system" fn hook_recvfrom(
    s: SOCKET,
    buf: *mut c_char,
    len: i32,
    flags: i32,
    from: *mut c_void,
    fromlen: *mut i32,
) -> i32 {
    if let Some(st) = state::get() {
        // SAFETY: arguments passed through.
        if let Some(r) = unsafe { vsock::recvfrom(st, s, buf, len, flags, from, fromlen) } {
            return r;
        }
    }
    // SAFETY: `RecvFromFn` is the signature of import `RECVFROM`.
    match unsafe { original::<RecvFromFn>(RECVFROM) } {
        // SAFETY: original function with the caller's arguments.
        Some(f) => unsafe { f(s, buf, len, flags, from, fromlen) },
        // SAFETY: arguments passed through.
        None => unsafe { ffi::recvfrom(s, buf, len, flags, from, fromlen) },
    }
}
