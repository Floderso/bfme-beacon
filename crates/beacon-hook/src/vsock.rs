//! Socket virtualisation (architecture §4.2, local frames §5).
//!
//! A VIRTUAL socket is the game's own UDP socket, really bound to
//! `127.0.0.1:ephemeral`; it talks only to the agent at `127.0.0.1:BEACON_AGENT_PORT`
//! (`REG`/`SEND`/`CLOSE` out, `DELIVER` in). Everything the game can observe —
//! `getsockname`, `recvfrom`'s `from`, `gethostname`/`gethostbyname` — shows the
//! virtual addresses. Non-blocking mode, `select`, `shutdown` and socket options
//! act on the real socket and stay native.
//!
//! Hot path (`sendto`/`recvfrom`): one table lookup under a short lock, stack
//! buffers only, no allocation, no lock held across a system call.

use core::ffi::{c_char, c_void};
use core::ptr::{self, null_mut};
use std::net::Ipv4Addr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use beacon_proto::local::{self, HookFrame};
use beacon_proto::net;

use crate::ffi::{self, Hostent, SockAddrIn, SOCKADDR_IN_LEN, SOCKET, SOCKET_ERROR};
use crate::log::{debug, info};
use crate::state::{self, Armed};
use crate::vtable::{self, BeginBind, Entry, State, Table, MAX_SOCKETS};
use crate::wide;

static TABLE: Mutex<Table> = Mutex::new(Table::new());

/// Receive scratch buffer: larger than any valid `DELIVER` frame (492 bytes) so
/// oversize frames are recognised as such instead of being truncated.
const RECV_SCRATCH: usize = 2048;
/// Foreign/invalid datagrams discarded in one `recvfrom` call before giving up
/// with `WSAEWOULDBLOCK` (bounds the time spent if something floods the socket).
const MAX_DISCARDS: usize = 1024;
const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
const WSAENOBUFS: i32 = 10055;

fn table() -> MutexGuard<'static, Table> {
    TABLE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Restores the thread's last-error value (= `WSAGetLastError`) when dropped.
struct PreserveError(u32);

impl PreserveError {
    fn new() -> Self {
        // SAFETY: no arguments.
        Self(unsafe { ffi::GetLastError() })
    }
}

impl Drop for PreserveError {
    fn drop(&mut self) {
        // SAFETY: no pointer arguments.
        unsafe { ffi::SetLastError(self.0) };
    }
}

/// Sets `code` as the Winsock error and returns `SOCKET_ERROR`.
fn fail(code: i32) -> i32 {
    // SAFETY: no pointer arguments.
    unsafe { ffi::WSASetLastError(code) };
    SOCKET_ERROR
}

fn last_error() -> i32 {
    // SAFETY: no arguments.
    unsafe { ffi::WSAGetLastError() }
}

/// Reads an `AF_INET` socket address supplied by the caller.
///
/// # Safety
/// `ptr` must be null or valid for `len` bytes (Winsock's own contract).
unsafe fn read_sockaddr_in(ptr: *const c_void, len: i32) -> Option<SockAddrIn> {
    if ptr.is_null() || len < SOCKADDR_IN_LEN {
        return None;
    }
    // SAFETY: at least 16 readable bytes (caller contract); unaligned read.
    let sa = unsafe { ptr.cast::<SockAddrIn>().read_unaligned() };
    (sa.family == ffi::AF_INET).then_some(sa)
}

fn ip_of(sa: &SockAddrIn) -> Ipv4Addr {
    Ipv4Addr::from(sa.addr)
}

/// Real local port of `s` if it is bound to `127.0.0.1`.
fn loopback_port(s: SOCKET) -> Option<u16> {
    let mut sa = SockAddrIn::default();
    let mut len = SOCKADDR_IN_LEN;
    // SAFETY: `sa`/`len` are valid out-parameters.
    let r = unsafe { ffi::getsockname(s, ptr::addr_of_mut!(sa).cast(), &mut len) };
    (r == 0 && sa.addr == LOOPBACK).then(|| sa.port())
}

/// `true` unless the entry's socket is provably gone (closed behind our back,
/// e.g. by the last `WSACleanup`, and possibly reused by a non-virtual socket).
fn is_alive(e: &Entry) -> bool {
    let _keep = PreserveError::new();
    match e.state {
        State::Virtual => loopback_port(e.sock) == Some(e.loop_port),
        State::Candidate => {
            let mut ty = 0i32;
            let mut len = 4i32;
            // SAFETY: valid out-parameters.
            let r = unsafe {
                ffi::getsockopt(e.sock, ffi::SOL_SOCKET, ffi::SO_TYPE, ptr::addr_of_mut!(ty).cast(), &mut len)
            };
            r == 0 && ty == ffi::SOCK_DGRAM
        }
        State::Binding | State::Free => true,
    }
}

/// Evicts dead entries (only needed when the table is full).
fn sweep_dead() -> usize {
    let snapshot = table().snapshot();
    let mut evicted = 0;
    for e in snapshot.iter().filter(|e| matches!(e.state, State::Candidate | State::Virtual)) {
        if !is_alive(e) && table().evict_if_unchanged(e) {
            evicted += 1;
        }
    }
    evicted
}

/// Sends one hook → agent frame from `s` (the virtual socket itself, so the agent
/// learns its loopback endpoint). Returns the Winsock error on failure.
fn send_frame(st: &Armed, s: SOCKET, header: &HookFrame, payload: &[u8]) -> Result<(), i32> {
    let mut frame = [0u8; local::MAX_HOOK_FRAME_LEN];
    let n = local::encode_hook_frame(header, payload, &mut frame).map_err(|_| ffi::WSAEMSGSIZE)?;
    let len = i32::try_from(n).map_err(|_| ffi::WSAEMSGSIZE)?;
    // SAFETY: `frame` holds `len` bytes, `st.agent` is a valid sockaddr_in.
    let r = unsafe {
        ffi::sendto(s, frame.as_ptr().cast(), len, 0, ptr::addr_of!(st.agent).cast(), SOCKADDR_IN_LEN)
    };
    if r == SOCKET_ERROR {
        Err(last_error())
    } else {
        Ok(())
    }
}

/// Turns off `WSAECONNRESET` reports for ICMP port-unreachable on `s`: if the agent
/// is gone, the game must see silence, not socket errors.
fn disable_connreset(s: SOCKET) {
    let mut off: u32 = 0;
    let mut returned = 0u32;
    // SAFETY: valid in-buffer of 4 bytes, valid out-parameter, no overlapped I/O.
    unsafe {
        ffi::WSAIoctl(
            s,
            ffi::SIO_UDP_CONNRESET,
            ptr::addr_of_mut!(off).cast(),
            4,
            null_mut(),
            0,
            &mut returned,
            null_mut(),
            null_mut(),
        )
    };
}

/// `socket`: remembers `AF_INET`/`SOCK_DGRAM` sockets as candidates.
///
/// # Safety
/// Winsock's contract for `socket`.
pub unsafe fn socket(af: i32, ty: i32, protocol: i32) -> SOCKET {
    // SAFETY: arguments passed through.
    let s = unsafe { ffi::socket(af, ty, protocol) };
    let udp = af == i32::from(ffi::AF_INET)
        && ty == ffi::SOCK_DGRAM
        && (protocol == 0 || protocol == ffi::IPPROTO_UDP);
    if s != ffi::INVALID_SOCKET && udp && !table().add_candidate(s) {
        let evicted = sweep_dead();
        if !table().add_candidate(s) {
            info!("socket {s:#x}: table full ({MAX_SOCKETS} entries, {evicted} evicted); stays real");
        }
    }
    s
}

/// `bind`: VIP (any port) or ANY:8086…8101 → VIRTUAL (`bind(127.0.0.1:0)` + `REG`);
/// a vport already held by this process → `WSAEADDRINUSE`; anything else is real.
///
/// # Safety
/// Winsock's contract for `bind`.
pub unsafe fn bind(st: &Armed, s: SOCKET, name: *const c_void, namelen: i32) -> i32 {
    // SAFETY: caller contract.
    let Some(req) = (unsafe { read_sockaddr_in(name, namelen) }) else {
        // SAFETY: arguments passed through.
        return unsafe { ffi::bind(s, name, namelen) };
    };
    let class = vtable::classify_bind(ip_of(&req), req.port(), st.vip);
    let mut decision = table().begin_bind(s, class);
    if let BeginBind::InUse(other) = decision {
        if !is_alive(&other) && table().evict_if_unchanged(&other) {
            info!("evicted stale socket {:#x} holding vport {}", other.sock, other.vport);
            decision = table().begin_bind(s, class);
        }
    }
    match decision {
        BeginBind::Untracked | BeginBind::Real => {
            // SAFETY: arguments passed through.
            unsafe { ffi::bind(s, name, namelen) }
        }
        BeginBind::InUse(other) => {
            info!("bind {s:#x} {}:{}: vport in use by {:#x}", ip_of(&req), req.port(), other.sock);
            fail(ffi::WSAEADDRINUSE)
        }
        BeginBind::NoEphemeral => fail(WSAENOBUFS),
        BeginBind::Proceed { vport, bound_any } => bind_loopback(st, s, vport, bound_any),
    }
}

fn bind_loopback(st: &Armed, s: SOCKET, vport: u16, bound_any: bool) -> i32 {
    let lo = SockAddrIn::new(LOOPBACK, 0);
    // SAFETY: `lo` is a valid sockaddr_in.
    let r = unsafe { ffi::bind(s, ptr::addr_of!(lo).cast(), SOCKADDR_IN_LEN) };
    if r != 0 {
        let err = last_error();
        table().abort_bind(s);
        info!("bind {s:#x} vport {vport}: loopback bind failed ({err})");
        return fail(err);
    }
    let _keep = PreserveError::new();
    let loop_port = loopback_port(s).unwrap_or(0);
    disable_connreset(s);
    if table().commit_bind(s, loop_port).is_none() {
        // Closed by another thread meanwhile; nothing to register.
        return 0;
    }
    let shown = if bound_any { Ipv4Addr::UNSPECIFIED } else { st.vip };
    match send_frame(st, s, &HookFrame::reg(vport, st.token), &[]) {
        Ok(()) => info!("bind {s:#x} {shown}:{vport} -> 127.0.0.1:{loop_port}, REG sent"),
        Err(e) => info!("bind {s:#x} {shown}:{vport} -> 127.0.0.1:{loop_port}, REG failed ({e})"),
    }
    0
}

/// `sendto` on a VIRTUAL socket: virtual/broadcast destinations → one `SEND` frame
/// to the agent; any other destination is dropped silently (returns `len`).
///
/// # Safety
/// Winsock's contract for `sendto`.
pub unsafe fn sendto(
    st: &Armed,
    s: SOCKET,
    buf: *const c_char,
    len: i32,
    flags: i32,
    to: *const c_void,
    tolen: i32,
) -> i32 {
    let entry = {
        let mut t = table();
        match t.get(s) {
            Some(e) if e.state == State::Virtual => Some(e),
            Some(e) if e.state == State::Candidate => {
                t.implicit_bind(s);
                None
            }
            _ => None,
        }
    };
    let Some(entry) = entry else {
        // SAFETY: arguments passed through.
        return unsafe { ffi::sendto(s, buf, len, flags, to, tolen) };
    };
    if to.is_null() || tolen < SOCKADDR_IN_LEN {
        return fail(ffi::WSAEFAULT);
    }
    // SAFETY: `to` is valid for `tolen >= 16` bytes (caller contract).
    let dst = unsafe { to.cast::<SockAddrIn>().read_unaligned() };
    if dst.family != ffi::AF_INET {
        return fail(ffi::WSAEAFNOSUPPORT);
    }
    let Ok(n) = usize::try_from(len) else {
        return fail(ffi::WSAEFAULT);
    };
    if buf.is_null() && n > 0 {
        return fail(ffi::WSAEFAULT);
    }
    if n > local::MAX_SEND_PAYLOAD {
        return fail(ffi::WSAEMSGSIZE);
    }
    let (dst_ip, dst_port) = (ip_of(&dst), dst.port());
    if dst_port == 0 {
        return fail(ffi::WSAEADDRNOTAVAIL);
    }
    if !net::is_virtual_destination(dst_ip) {
        debug!("tx {s:#x} vport {}: {n} B to {dst_ip}:{dst_port} dropped (not virtual)", entry.vport);
        return len;
    }
    if net::is_broadcast(dst_ip) && !broadcast_allowed(s) {
        return fail(ffi::WSAEACCES);
    }
    let payload: &[u8] = if n == 0 {
        &[]
    } else {
        // SAFETY: `buf` is valid for `len` bytes (caller contract).
        unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), n) }
    };
    match send_frame(st, s, &HookFrame::send(entry.vport, dst_ip, dst_port, st.token), payload) {
        Ok(()) => {
            debug!("tx {s:#x} vport {} -> {dst_ip}:{dst_port} {n} B", entry.vport);
            len
        }
        Err(e) => {
            debug!("tx {s:#x} vport {} -> {dst_ip}:{dst_port} {n} B failed ({e})", entry.vport);
            fail(e)
        }
    }
}

/// Native semantics: a broadcast needs `SO_BROADCAST` (`WSAEACCES` otherwise). The
/// option lives on the real socket (setsockopt is pass-through). Fails open.
fn broadcast_allowed(s: SOCKET) -> bool {
    let _keep = PreserveError::new();
    let mut v: i32 = 0;
    let mut len = 4i32;
    // SAFETY: valid out-parameters.
    let r = unsafe {
        ffi::getsockopt(s, ffi::SOL_SOCKET, ffi::SO_BROADCAST, ptr::addr_of_mut!(v).cast(), &mut len)
    };
    r != 0 || v != 0
}

/// Consumes the next datagram (after a `MSG_PEEK` that showed a foreign one).
fn consume_one(s: SOCKET) {
    let mut tmp = [0u8; 1];
    // SAFETY: 1-byte buffer; larger datagrams are truncated and consumed.
    unsafe { ffi::recvfrom(s, tmp.as_mut_ptr().cast(), 1, 0, null_mut(), null_mut()) };
}

/// `recvfrom`/`recv` on a VIRTUAL socket; `None` if `s` is not virtual.
///
/// Only `DELIVER` frames from `127.0.0.1:BEACON_AGENT_PORT` are accepted: the
/// payload is copied to the caller's buffer (truncation → `WSAEMSGSIZE`, like
/// Winsock) and `from` = the true virtual source. Anything else is discarded; if
/// nothing valid is queued the real call's result (`WSAEWOULDBLOCK` on a
/// non-blocking socket) is returned.
///
/// # Safety
/// Winsock's contract for `recvfrom`.
pub unsafe fn recvfrom(
    st: &Armed,
    s: SOCKET,
    buf: *mut c_char,
    len: i32,
    flags: i32,
    from: *mut c_void,
    fromlen: *mut i32,
) -> Option<i32> {
    let entry = table().virtual_entry(s)?;
    // SAFETY: caller contract.
    Some(unsafe { recvfrom_virtual(st, &entry, buf, len, flags, from, fromlen) })
}

/// # Safety
/// Winsock's contract for `recvfrom`.
unsafe fn recvfrom_virtual(
    st: &Armed,
    entry: &Entry,
    buf: *mut c_char,
    len: i32,
    flags: i32,
    from: *mut c_void,
    fromlen: *mut i32,
) -> i32 {
    let s = entry.sock;
    // SAFETY: `fromlen` is checked for null before the read.
    if !from.is_null() && (fromlen.is_null() || unsafe { fromlen.read_unaligned() } < SOCKADDR_IN_LEN) {
        return fail(ffi::WSAEFAULT);
    }
    let Ok(cap) = usize::try_from(len) else {
        return fail(ffi::WSAEFAULT);
    };
    if buf.is_null() && cap > 0 {
        return fail(ffi::WSAEFAULT);
    }
    let peek = flags & ffi::MSG_PEEK != 0;
    let mut scratch = [0u8; RECV_SCRATCH];
    for _ in 0..MAX_DISCARDS {
        let mut src = SockAddrIn::default();
        let mut srclen = SOCKADDR_IN_LEN;
        // SAFETY: `scratch`, `src`, `srclen` are valid for the given sizes.
        let r = unsafe {
            ffi::recvfrom(
                s,
                scratch.as_mut_ptr().cast(),
                RECV_SCRATCH as i32,
                flags,
                ptr::addr_of_mut!(src).cast(),
                &mut srclen,
            )
        };
        if r == SOCKET_ERROR {
            match last_error() {
                ffi::WSAEMSGSIZE => {
                    debug!("rx {s:#x} vport {}: oversize datagram discarded", entry.vport);
                    if peek {
                        consume_one(s);
                    }
                    continue;
                }
                // ICMP noise from earlier loopback sends: never surfaces (silence).
                ffi::WSAECONNRESET | ffi::WSAENETRESET => continue,
                // WSAEWOULDBLOCK, WSAESHUTDOWN, …: native, error already set.
                _ => return SOCKET_ERROR,
            }
        }
        let n = usize::try_from(r).unwrap_or(0).min(RECV_SCRATCH);
        let datagram = scratch.get(..n).unwrap_or(&[]);
        let from_agent = src.family == ffi::AF_INET && src.addr == LOOPBACK && src.port == st.agent.port;
        let parsed = if from_agent { local::parse_deliver(datagram).ok() } else { None };
        let Some((hdr, range)) = parsed else {
            debug!(
                "rx {s:#x} vport {}: {n} B from {}:{} discarded ({})",
                entry.vport,
                ip_of(&src),
                src.port(),
                if from_agent { "invalid DELIVER" } else { "not the agent" }
            );
            if peek {
                consume_one(s);
            }
            continue;
        };
        let payload = datagram.get(range).unwrap_or(&[]);
        let copy = payload.len().min(cap);
        if copy > 0 {
            // SAFETY: `buf` is valid for `len >= copy` bytes (caller contract) and
            // does not overlap our stack buffer.
            unsafe { ptr::copy_nonoverlapping(payload.as_ptr(), buf.cast::<u8>(), copy) };
        }
        if !from.is_null() {
            let sa = SockAddrIn::new(hdr.src_vip.octets(), hdr.src_vport);
            // SAFETY: `from` has room for 16 bytes and `fromlen` is valid (checked).
            unsafe {
                from.cast::<SockAddrIn>().write_unaligned(sa);
                fromlen.write_unaligned(SOCKADDR_IN_LEN);
            }
        }
        debug!("rx {s:#x} vport {} <- {}:{} {} B", entry.vport, hdr.src_vip, hdr.src_vport, payload.len());
        if copy < payload.len() {
            return fail(ffi::WSAEMSGSIZE);
        }
        return i32::try_from(payload.len()).unwrap_or(i32::MAX);
    }
    info!("rx {s:#x} vport {}: {MAX_DISCARDS} foreign datagrams in one call", entry.vport);
    fail(ffi::WSAEWOULDBLOCK)
}

/// `getsockname` on a VIRTUAL socket → `{VIP or 0.0.0.0, vport}`; `None` otherwise.
///
/// # Safety
/// Winsock's contract for `getsockname`.
pub unsafe fn getsockname(st: &Armed, s: SOCKET, name: *mut c_void, namelen: *mut i32) -> Option<i32> {
    let entry = table().virtual_entry(s)?;
    // SAFETY: `namelen` is checked for null before the read.
    if name.is_null() || namelen.is_null() || unsafe { namelen.read_unaligned() } < SOCKADDR_IN_LEN {
        return Some(fail(ffi::WSAEFAULT));
    }
    let ip = if entry.bound_any { [0; 4] } else { st.vip.octets() };
    // SAFETY: `name` has room for 16 bytes, `namelen` is valid (checked above).
    unsafe {
        name.cast::<SockAddrIn>().write_unaligned(SockAddrIn::new(ip, entry.vport));
        namelen.write_unaligned(SOCKADDR_IN_LEN);
    }
    Some(0)
}

/// `closesocket`: VIRTUAL → `CLOSE` frame (unless sent at `shutdown`); the entry is
/// forgotten before the real close (the handle may be reused right after).
///
/// # Safety
/// Winsock's contract for `closesocket`.
pub unsafe fn closesocket(st: &Armed, s: SOCKET) -> i32 {
    let removed = table().remove(s);
    if let Some(e) = removed.filter(|e| e.state == State::Virtual) {
        if e.close_sent {
            info!("close {s:#x} vport {}", e.vport);
        } else {
            let _keep = PreserveError::new();
            let sent = send_frame(st, s, &HookFrame::close(e.vport, st.token), &[]);
            info!("close {s:#x} vport {}, CLOSE {}", e.vport, if sent.is_ok() { "sent" } else { "failed" });
        }
    }
    // SAFETY: argument passed through.
    unsafe { ffi::closesocket(s) }
}

/// `shutdown(SD_SEND | SD_BOTH)` on a VIRTUAL socket sends `CLOSE` first: after it
/// the socket cannot send any more (BFME's `UDP` destructor does
/// `shutdown(SD_BOTH)` → drain → `closesocket`).
///
/// # Safety
/// Winsock's contract for `shutdown`.
pub unsafe fn shutdown(st: &Armed, s: SOCKET, how: i32) -> i32 {
    if how == ffi::SD_SEND || how == ffi::SD_BOTH {
        let vport = table().take_close(s);
        if let Some(vport) = vport {
            let _keep = PreserveError::new();
            let sent = send_frame(st, s, &HookFrame::close(vport, st.token), &[]);
            info!("shutdown {s:#x} vport {vport}, CLOSE {}", if sent.is_ok() { "sent" } else { "failed" });
        }
    }
    // SAFETY: arguments passed through.
    unsafe { ffi::shutdown(s, how) }
}

/// `gethostname` → `BEACON-<last octet>`.
///
/// # Safety
/// Winsock's contract for `gethostname`.
pub unsafe fn gethostname(st: &Armed, name: *mut c_char, namelen: i32) -> i32 {
    let value = st.hostname_with_nul();
    if name.is_null() || usize::try_from(namelen).map_or(true, |n| n < value.len()) {
        return fail(ffi::WSAEFAULT);
    }
    // SAFETY: `name` is valid for `namelen >= value.len()` bytes.
    unsafe { ptr::copy_nonoverlapping(value.as_ptr(), name.cast::<u8>(), value.len()) };
    0
}

/// `gethostbyname`: the own name (`BEACON-n`, the real host name, `""` or NULL) →
/// static `hostent` with exactly one address, the VIP. Other names → real.
///
/// # Safety
/// Winsock's contract for `gethostbyname`.
pub unsafe fn gethostbyname(st: &Armed, name: *const c_char) -> *mut Hostent {
    // SAFETY: caller contract (NUL-terminated string or NULL).
    if unsafe { is_own_name(st, name) } {
        info!("gethostbyname(own name) -> {}", st.vip);
        return state::hostent_ptr();
    }
    // SAFETY: argument passed through.
    unsafe { ffi::gethostbyname(name) }
}

/// # Safety
/// `name` must be NULL or a NUL-terminated string.
unsafe fn is_own_name(st: &Armed, name: *const c_char) -> bool {
    if name.is_null() {
        return true;
    }
    let mut buf = [0u8; 256];
    // SAFETY: caller contract.
    let Some(asked) = (unsafe { wide::read_cstr(name.cast(), &mut buf) }) else {
        return false;
    };
    if asked.is_empty() || asked.eq_ignore_ascii_case(st.hostname()) {
        return true;
    }
    let _keep = PreserveError::new();
    let mut real = [0u8; 257];
    // SAFETY: `real` is writable for 256 bytes (+1 spare for the terminator).
    if unsafe { ffi::gethostname(real.as_mut_ptr().cast(), 256) } != 0 {
        return false;
    }
    let end = real.iter().position(|&b| b == 0).unwrap_or(0);
    real.get(..end).is_some_and(|real| !real.is_empty() && asked.eq_ignore_ascii_case(real))
}
