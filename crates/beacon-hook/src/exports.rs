//! The 27 functions implemented in Rust and exported under wsock32's names and
//! ordinals by `wsock32.def` (internal symbol `bh_<lowercase name>`; i686 stdcall
//! decoration `_bh_x@N` is resolved by lld). Every other wsock32 export is a `.def`
//! forwarder.
//!
//! Passive mode (`state::get() == None`): each function calls ws2_32 directly — the
//! system wsock32 forwards these 23 names to ws2_32 — and the four WinSock 1.1
//! code exports use `compat`, an exact copy of the system code. Armed mode adds
//! the virtual-socket handling of `vsock` and the first-call duties of
//! `WSAStartup`.

use core::ffi::{c_char, c_void};

use crate::ffi::{self, Hostent, SOCKET};
use crate::{compat, init, state, vsock};

/// `WSAStartup` (#115). First call: deferred start-up work (log report, IAT
/// re-verification).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_wsastartup(version: u16, data: *mut c_void) -> i32 {
    init::on_wsastartup();
    // SAFETY: arguments passed through.
    unsafe { ffi::WSAStartup(version, data) }
}

/// `WSACleanup` (#116).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_wsacleanup() -> i32 {
    // SAFETY: no arguments.
    unsafe { ffi::WSACleanup() }
}

/// `WSAGetLastError` (#111).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_wsagetlasterror() -> i32 {
    // SAFETY: no arguments.
    unsafe { ffi::WSAGetLastError() }
}

/// `__WSAFDIsSet` (#151).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn bh___wsafdisset(s: SOCKET, set: *mut c_void) -> i32 {
    // SAFETY: arguments passed through.
    unsafe { ffi::__WSAFDIsSet(s, set) }
}

/// `accept` (#1).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_accept(s: SOCKET, addr: *mut c_void, addrlen: *mut i32) -> SOCKET {
    // SAFETY: arguments passed through.
    let accepted = unsafe { ffi::accept(s, addr, addrlen) };
    if accepted != ffi::INVALID_SOCKET && state::get().is_some() {
        vsock::forget_stale(accepted);
    }
    accepted
}

/// `bind` (#2).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_bind(s: SOCKET, name: *const c_void, namelen: i32) -> i32 {
    match state::get() {
        // SAFETY: arguments passed through.
        Some(st) => unsafe { vsock::bind(st, s, name, namelen) },
        // SAFETY: arguments passed through.
        None => unsafe { ffi::bind(s, name, namelen) },
    }
}

/// `closesocket` (#3).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_closesocket(s: SOCKET) -> i32 {
    match state::get() {
        // SAFETY: argument passed through.
        Some(st) => unsafe { vsock::closesocket(st, s) },
        // SAFETY: argument passed through.
        None => unsafe { ffi::closesocket(s) },
    }
}

/// `connect` (#4).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_connect(s: SOCKET, name: *const c_void, namelen: i32) -> i32 {
    // SAFETY: arguments passed through.
    unsafe { ffi::connect(s, name, namelen) }
}

/// `getpeername` (#5).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_getpeername(s: SOCKET, name: *mut c_void, namelen: *mut i32) -> i32 {
    // SAFETY: arguments passed through.
    unsafe { ffi::getpeername(s, name, namelen) }
}

/// `getsockname` (#6).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_getsockname(s: SOCKET, name: *mut c_void, namelen: *mut i32) -> i32 {
    if let Some(st) = state::get() {
        // SAFETY: arguments passed through.
        if let Some(r) = unsafe { vsock::getsockname(st, s, name, namelen) } {
            return r;
        }
    }
    // SAFETY: arguments passed through.
    unsafe { ffi::getsockname(s, name, namelen) }
}

/// `getsockopt` (#7, WinSock 1.1 code export).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_getsockopt(
    s: SOCKET,
    level: i32,
    optname: i32,
    optval: *mut c_char,
    optlen: *mut i32,
) -> i32 {
    // SAFETY: arguments passed through.
    unsafe { compat::getsockopt(s, level, optname, optval, optlen) }
}

/// `htonl` (#8).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_htonl(v: u32) -> u32 {
    // SAFETY: plain value.
    unsafe { ffi::htonl(v) }
}

/// `inet_addr` (#10).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_inet_addr(cp: *const c_char) -> u32 {
    // SAFETY: argument passed through.
    unsafe { ffi::inet_addr(cp) }
}

/// `inet_ntoa` (#11); `in_addr` by value.
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_inet_ntoa(addr: u32) -> *mut c_char {
    // SAFETY: plain value.
    unsafe { ffi::inet_ntoa(addr) }
}

/// `ioctlsocket` (#12).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_ioctlsocket(s: SOCKET, cmd: i32, argp: *mut u32) -> i32 {
    // SAFETY: arguments passed through.
    unsafe { ffi::ioctlsocket(s, cmd, argp) }
}

/// `listen` (#13).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_listen(s: SOCKET, backlog: i32) -> i32 {
    // SAFETY: arguments passed through.
    unsafe { ffi::listen(s, backlog) }
}

/// `ntohs` (#15). Returns the value zero-extended in `EAX` like ws2_32.
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_ntohs(v: u16) -> u32 {
    // SAFETY: plain value.
    u32::from(unsafe { ffi::ntohs(v) })
}

/// `recv` (#16, WinSock 1.1 code export).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_recv(s: SOCKET, buf: *mut c_char, len: i32, flags: i32) -> i32 {
    if let Some(st) = state::get() {
        // SAFETY: arguments passed through (no `from`).
        if let Some(r) = unsafe { vsock::recvfrom(st, s, buf, len, flags, core::ptr::null_mut(), core::ptr::null_mut()) } {
            return r;
        }
    }
    // SAFETY: arguments passed through.
    unsafe { compat::recv(s, buf, len, flags) }
}

/// `recvfrom` (#17, WinSock 1.1 code export).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_recvfrom(
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
    // SAFETY: arguments passed through.
    unsafe { compat::recvfrom(s, buf, len, flags, from, fromlen) }
}

/// `select` (#18).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_select(
    nfds: i32,
    readfds: *mut c_void,
    writefds: *mut c_void,
    exceptfds: *mut c_void,
    timeout: *const c_void,
) -> i32 {
    // SAFETY: arguments passed through.
    unsafe { ffi::select(nfds, readfds, writefds, exceptfds, timeout) }
}

/// `send` (#19).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_send(s: SOCKET, buf: *const c_char, len: i32, flags: i32) -> i32 {
    // SAFETY: arguments passed through.
    unsafe { ffi::send(s, buf, len, flags) }
}

/// `sendto` (#20).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_sendto(
    s: SOCKET,
    buf: *const c_char,
    len: i32,
    flags: i32,
    to: *const c_void,
    tolen: i32,
) -> i32 {
    match state::get() {
        // SAFETY: arguments passed through.
        Some(st) => unsafe { vsock::sendto(st, s, buf, len, flags, to, tolen) },
        // SAFETY: arguments passed through.
        None => unsafe { ffi::sendto(s, buf, len, flags, to, tolen) },
    }
}

/// `setsockopt` (#21, WinSock 1.1 code export).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_setsockopt(
    s: SOCKET,
    level: i32,
    optname: i32,
    optval: *const c_char,
    optlen: i32,
) -> i32 {
    // SAFETY: arguments passed through.
    unsafe { compat::setsockopt(s, level, optname, optval, optlen) }
}

/// `shutdown` (#22).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_shutdown(s: SOCKET, how: i32) -> i32 {
    match state::get() {
        // SAFETY: arguments passed through.
        Some(st) => unsafe { vsock::shutdown(st, s, how) },
        // SAFETY: arguments passed through.
        None => unsafe { ffi::shutdown(s, how) },
    }
}

/// `socket` (#23).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_socket(af: i32, ty: i32, protocol: i32) -> SOCKET {
    match state::get() {
        // SAFETY: arguments passed through.
        Some(_) => unsafe { vsock::socket(af, ty, protocol) },
        // SAFETY: arguments passed through.
        None => unsafe { ffi::socket(af, ty, protocol) },
    }
}

/// `gethostbyname` (#52).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_gethostbyname(name: *const c_char) -> *mut Hostent {
    match state::get() {
        // SAFETY: argument passed through.
        Some(st) => unsafe { vsock::gethostbyname(st, name) },
        // SAFETY: argument passed through.
        None => unsafe { ffi::gethostbyname(name) },
    }
}

/// `gethostname` (#57).
///
/// # Safety
/// Winsock's contract.
#[no_mangle]
pub unsafe extern "system" fn bh_gethostname(name: *mut c_char, namelen: i32) -> i32 {
    match state::get() {
        // SAFETY: arguments passed through.
        Some(st) => unsafe { vsock::gethostname(st, name, namelen) },
        // SAFETY: arguments passed through.
        None => unsafe { ffi::gethostname(name, namelen) },
    }
}
