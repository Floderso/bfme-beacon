//! Replacements for the exe's five `WS2_32.dll` IAT slots (spec 03 §3.2/§8.4;
//! WS2_32 is a KnownDLL, so these imports cannot be proxied by a file).
//!
//! `recvfrom` and `recv` virtualise VIRTUAL sockets like the wsock32 exports do
//! (the lobby/in-game read path `UDP::Read` uses `WS2_32!recvfrom`). `getsockopt`,
//! `setsockopt` and `WSAIoctl` act on the real socket (architecture §4.2) and
//! chain to the original pointer. These are WinSock 2 functions: no WinSock 1.1
//! option renumbering here.

use core::ffi::{c_char, c_void};
use core::ptr::{self, null_mut};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use crate::ffi::{self, SockAddrIn, SOCKADDR_IN_LEN, SOCKET, SOCKET_ERROR};
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

/// Socket value of a reachability probe (see [`reaches_hook`]): `INVALID_SOCKET`,
/// never a socket (ws2_32 answers `WSAENOTSOCK` if a probe never reaches our hook)
/// and, as a kernel handle, the current-process pseudo-handle, so no call down the
/// chain can trip an invalid-handle check. A hit also requires the probing thread
/// and the probed import, so the game's own calls are never mistaken for a probe.
pub const PROBE_SOCKET: SOCKET = ffi::INVALID_SOCKET;
/// Thread running a probe (0 = none; no thread has id 0).
static PROBE_THREAD: AtomicU32 = AtomicU32::new(0);
/// Index (in [`NAMES`]) of the hook the running probe is looking for.
static PROBE_INDEX: AtomicUsize = AtomicUsize::new(usize::MAX);
/// Set by the hook when the running probe reached it.
static PROBE_HIT: AtomicBool = AtomicBool::new(false);

/// `true` if this call is the running reachability probe for hook `index` (then the
/// hit is recorded and the caller must return `SOCKET_ERROR` at once). One compare
/// on the hot path.
#[inline]
fn is_probe(s: SOCKET, index: usize) -> bool {
    if s != PROBE_SOCKET || PROBE_INDEX.load(Ordering::Acquire) != index {
        return false;
    }
    // SAFETY: no arguments.
    let me = unsafe { ffi::GetCurrentThreadId() };
    if PROBE_THREAD.load(Ordering::Acquire) != me {
        return false;
    }
    PROBE_HIT.store(true, Ordering::Release);
    // SAFETY: no pointer arguments.
    unsafe { ffi::WSASetLastError(ffi::WSAENOTSOCK) };
    true
}

/// Calls the function at address `f` — the current value of the IAT slot of import
/// `NAMES[index]` — with [`PROBE_SOCKET`] and reports whether the call reached our
/// hook for that import (directly, or through another module's hook chained in
/// front of ours). Used by the first-`WSAStartup` re-verification: a slot whose
/// function never reaches the hook means the game would bypass the virtualisation.
/// The thread's last-error value is preserved. Not reentrant (one probe at a time).
///
/// # Safety
/// `f` must be the address of a function with the signature of import
/// `NAMES[index]` (what the slot of that import holds).
pub unsafe fn reaches_hook(index: usize, f: usize) -> bool {
    if f == 0 || index >= NAMES.len() {
        return false;
    }
    // SAFETY: no arguments.
    let (saved, me) = unsafe { (ffi::GetLastError(), ffi::GetCurrentThreadId()) };
    PROBE_HIT.store(false, Ordering::Release);
    PROBE_INDEX.store(index, Ordering::Release);
    PROBE_THREAD.store(me, Ordering::Release);
    let mut word = [0u8; 4];
    let mut int_len = 4i32;
    let mut from = SockAddrIn::default();
    let mut from_len = SOCKADDR_IN_LEN;
    let mut returned = 0u32;
    // SAFETY: `f` has the import's signature (caller contract); every pointer
    // argument is a valid local buffer of the stated size.
    unsafe {
        match index {
            WSAIOCTL => {
                if let Some(func) = crate::iat::fn_from_addr::<WsaIoctlFn>(f) {
                    func(PROBE_SOCKET, 0, null_mut(), 0, null_mut(), 0, &mut returned, null_mut(), null_mut());
                }
            }
            GETSOCKOPT => {
                if let Some(func) = crate::iat::fn_from_addr::<GetSockOptFn>(f) {
                    func(PROBE_SOCKET, ffi::SOL_SOCKET, ffi::SO_TYPE, word.as_mut_ptr().cast(), &mut int_len);
                }
            }
            RECV => {
                if let Some(func) = crate::iat::fn_from_addr::<RecvFn>(f) {
                    func(PROBE_SOCKET, word.as_mut_ptr().cast(), 4, 0);
                }
            }
            RECVFROM => {
                if let Some(func) = crate::iat::fn_from_addr::<RecvFromFn>(f) {
                    func(PROBE_SOCKET, word.as_mut_ptr().cast(), 4, 0, ptr::addr_of_mut!(from).cast(), &mut from_len);
                }
            }
            _ => {
                if let Some(func) = crate::iat::fn_from_addr::<SetSockOptFn>(f) {
                    func(PROBE_SOCKET, ffi::SOL_SOCKET, ffi::SO_BROADCAST, word.as_ptr().cast(), 4);
                }
            }
        }
    }
    PROBE_THREAD.store(0, Ordering::Release);
    PROBE_INDEX.store(usize::MAX, Ordering::Release);
    // SAFETY: restores the caller's last-error value.
    unsafe { ffi::SetLastError(saved) };
    PROBE_HIT.load(Ordering::Acquire)
}

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
    if is_probe(s, WSAIOCTL) {
        return SOCKET_ERROR;
    }
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
    if is_probe(s, GETSOCKOPT) {
        return SOCKET_ERROR;
    }
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
    if is_probe(s, SETSOCKOPT) {
        return SOCKET_ERROR;
    }
    // SAFETY: `SetSockOptFn` is the signature of import `SETSOCKOPT`.
    match unsafe { original::<SetSockOptFn>(SETSOCKOPT) } {
        // SAFETY: original function with the caller's arguments.
        Some(f) => unsafe { f(s, level, optname, optval, optlen) },
        // SAFETY: arguments passed through.
        None => unsafe { ffi::setsockopt(s, level, optname, optval, optlen) },
    }
}

unsafe extern "system" fn hook_recv(s: SOCKET, buf: *mut c_char, len: i32, flags: i32) -> i32 {
    if is_probe(s, RECV) {
        return SOCKET_ERROR;
    }
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
    if is_probe(s, RECVFROM) {
        return SOCKET_ERROR;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, PoisonError};

    /// Probes use process-wide state: one test at a time.
    static ONE_PROBE: Mutex<()> = Mutex::new(());

    /// Another module's `recvfrom` hook that calls ws2_32 directly (bypasses ours).
    unsafe extern "system" fn bypassing_recvfrom(
        s: SOCKET,
        buf: *mut c_char,
        len: i32,
        flags: i32,
        from: *mut c_void,
        fromlen: *mut i32,
    ) -> i32 {
        // SAFETY: arguments passed through.
        unsafe { ffi::recvfrom(s, buf, len, flags, from, fromlen) }
    }

    /// Another module's `recvfrom` hook chained in front of ours.
    unsafe extern "system" fn chained_recvfrom(
        s: SOCKET,
        buf: *mut c_char,
        len: i32,
        flags: i32,
        from: *mut c_void,
        fromlen: *mut i32,
    ) -> i32 {
        // SAFETY: arguments passed through.
        unsafe { hook_recvfrom(s, buf, len, flags, from, fromlen) }
    }

    /// Chained in front of our `setsockopt` hook.
    unsafe extern "system" fn chained_setsockopt(
        s: SOCKET,
        level: i32,
        optname: i32,
        optval: *const c_char,
        optlen: i32,
    ) -> i32 {
        // SAFETY: arguments passed through.
        unsafe { hook_setsockopt(s, level, optname, optval, optlen) }
    }

    /// A `getsockopt` replacement that reaches a *different* hook of ours.
    unsafe extern "system" fn getsockopt_calling_recv(
        s: SOCKET,
        _level: i32,
        _optname: i32,
        optval: *mut c_char,
        _optlen: *mut i32,
    ) -> i32 {
        // SAFETY: `optval` is the probe's 4-byte buffer.
        unsafe { hook_recv(s, optval, 4, 0) }
    }

    /// A `recvfrom` replacement that reaches our hook, but on another thread.
    unsafe extern "system" fn recvfrom_on_other_thread(
        s: SOCKET,
        _buf: *mut c_char,
        _len: i32,
        _flags: i32,
        _from: *mut c_void,
        _fromlen: *mut i32,
    ) -> i32 {
        let other = std::thread::spawn(move || {
            let mut b = [0u8; 4];
            // SAFETY: valid 4-byte buffer, no `from`.
            unsafe { hook_recvfrom(s, b.as_mut_ptr().cast(), 4, 0, null_mut(), null_mut()) }
        });
        other.join().unwrap_or(SOCKET_ERROR)
    }

    #[test]
    fn probe_tells_chained_from_bypassed() {
        let _one = ONE_PROBE.lock().unwrap_or_else(PoisonError::into_inner);
        // SAFETY: every function has the probed import's signature.
        unsafe {
            for (i, hook) in hooks().into_iter().enumerate() {
                assert!(reaches_hook(i, hook), "{} reaches itself", NAMES[i]);
            }
            assert!(reaches_hook(RECVFROM, chained_recvfrom as RecvFromFn as usize));
            assert!(reaches_hook(SETSOCKOPT, chained_setsockopt as SetSockOptFn as usize));
            assert!(!reaches_hook(RECVFROM, bypassing_recvfrom as RecvFromFn as usize));
            assert!(!reaches_hook(RECVFROM, ffi::recvfrom as RecvFromFn as usize));
            assert!(!reaches_hook(SETSOCKOPT, ffi::setsockopt as SetSockOptFn as usize));
            assert!(!reaches_hook(WSAIOCTL, ffi::WSAIoctl as WsaIoctlFn as usize));
            // Reaching another of our hooks, or ours on another thread, is no hit.
            assert!(!reaches_hook(GETSOCKOPT, getsockopt_calling_recv as GetSockOptFn as usize));
            assert!(!reaches_hook(RECVFROM, recvfrom_on_other_thread as RecvFromFn as usize));
            assert!(!reaches_hook(RECV, 0), "null slot");
            assert!(!reaches_hook(NAMES.len(), hooks()[0]), "bad index");
            // The caller's last-error value survives a probe.
            ffi::SetLastError(1234);
            let _ = reaches_hook(RECVFROM, bypassing_recvfrom as RecvFromFn as usize);
            assert_eq!(ffi::GetLastError(), 1234);
        }
        // No probe running afterwards: the sentinel is an ordinary invalid socket.
        assert_eq!(PROBE_THREAD.load(Ordering::Acquire), 0);
        assert!(!is_probe(PROBE_SOCKET, RECVFROM));
    }
}
