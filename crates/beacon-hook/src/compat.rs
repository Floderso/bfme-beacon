//! Exact re-implementation of the four *code* exports of the system
//! `SysWOW64\wsock32.dll` 10.0.26100 (`getsockopt` #7, `recv` #16, `recvfrom` #17,
//! `setsockopt` #21); every other system export is a plain forwarder to ws2_32 /
//! mswsock. `worldbuilder.exe` imports these four from WSOCK32, so passive mode
//! must keep their WinSock 1.1 semantics (disassembled with capstone, see README):
//!
//! * `IPPROTO_IP` option numbers are renumbered from WinSock 1.1 to 2
//!   (`IP_MULTICAST_IF` 2→9 … `IP_DONTFRAGMENT` 9→14, [`ws1_ip_option`]).
//! * `IPPROTO_TCP`/`TCP_BSDURGENT` (0x7000) is mapped to `TCP_EXPEDITED_1122` (2)
//!   with the boolean inverted.
//! * `getsockopt` normalises the result to 0 / -1.
//! * `recv`/`recvfrom` go through `WSARecv`/`WSARecvFrom`; a partial message
//!   (`MSG_PARTIAL`) returns the *negated* byte count with `WSAEMSGSIZE` set.

use core::ffi::{c_char, c_void};
use core::ptr;

use crate::ffi::{self, SOCKET, SOCKET_ERROR};

/// WinSock 1.1 `TCP_BSDURGENT`.
pub const TCP_BSDURGENT: i32 = 0x7000;
/// WinSock 2 `TCP_EXPEDITED_1122`.
pub const TCP_EXPEDITED_1122: i32 = 2;
/// `WSAEMSGSIZE` as set by the system code (via `SetLastError`).
const WSAEMSGSIZE: u32 = 10040;

/// WinSock 1.1 → 2 renumbering of `IPPROTO_IP` options (system wsock32 jump
/// table at RVA 0x1539); other values are unchanged.
pub const fn ws1_ip_option(optname: i32) -> i32 {
    match optname {
        2 => 9,   // IP_MULTICAST_IF
        3 => 10,  // IP_MULTICAST_TTL
        4 => 11,  // IP_MULTICAST_LOOP
        5 => 12,  // IP_ADD_MEMBERSHIP
        6 => 13,  // IP_DROP_MEMBERSHIP
        7 => 4,   // IP_TTL
        8 => 3,   // IP_TOS
        9 => 14,  // IP_DONTFRAGMENT
        other => other,
    }
}

/// wsock32 `setsockopt`.
///
/// # Safety
/// Winsock's contract for `setsockopt`.
pub unsafe fn setsockopt(s: SOCKET, level: i32, optname: i32, optval: *const c_char, optlen: i32) -> i32 {
    if level == ffi::IPPROTO_IP {
        // SAFETY: arguments passed through (option renumbered).
        return unsafe { ffi::setsockopt(s, level, ws1_ip_option(optname), optval, optlen) };
    }
    if level == ffi::IPPROTO_TCP && optname == TCP_BSDURGENT {
        // System code: `cmp optlen, 4; jb` (unsigned) keeps the caller's buffer.
        if (optlen as u32) < 4 || optval.is_null() {
            // SAFETY: arguments passed through (option renumbered).
            return unsafe { ffi::setsockopt(s, level, TCP_EXPEDITED_1122, optval, optlen) };
        }
        // SAFETY: `optval` is non-null and readable (optlen >= 4, caller contract).
        let urgent = unsafe { optval.cast::<u8>().read() };
        let value: i32 = i32::from(urgent == 0);
        // SAFETY: `value` is a valid 4-byte option buffer.
        return unsafe { ffi::setsockopt(s, level, TCP_EXPEDITED_1122, ptr::addr_of!(value).cast(), 4) };
    }
    // SAFETY: arguments passed through.
    unsafe { ffi::setsockopt(s, level, optname, optval, optlen) }
}

/// wsock32 `getsockopt`.
///
/// # Safety
/// Winsock's contract for `getsockopt`.
pub unsafe fn getsockopt(s: SOCKET, level: i32, optname: i32, optval: *mut c_char, optlen: *mut i32) -> i32 {
    let mut optname = optname;
    if level == ffi::IPPROTO_IP {
        optname = ws1_ip_option(optname);
    } else if level == ffi::IPPROTO_TCP && optname == TCP_BSDURGENT {
        // SAFETY: arguments passed through (option renumbered).
        if unsafe { ffi::getsockopt(s, level, TCP_EXPEDITED_1122, optval, optlen) } == SOCKET_ERROR {
            return SOCKET_ERROR;
        }
        if !optval.is_null() {
            // SAFETY: ws2_32 just wrote the option into `optval`.
            unsafe {
                let b = optval.cast::<u8>();
                b.write(u8::from(b.read() == 0));
            }
        }
        return 0;
    }
    // SAFETY: arguments passed through.
    let r = unsafe { ffi::getsockopt(s, level, optname, optval, optlen) };
    if r == SOCKET_ERROR {
        SOCKET_ERROR
    } else {
        0
    }
}

/// wsock32 `recv`.
///
/// # Safety
/// Winsock's contract for `recv`.
pub unsafe fn recv(s: SOCKET, buf: *mut c_char, len: i32, flags: i32) -> i32 {
    let mut wsabuf = ffi::WsaBuf { len: len as u32, buf };
    let mut io_flags = flags as u32;
    let mut received = 0u32;
    // SAFETY: valid WSABUF/out-parameters; the buffer is the caller's.
    let r = unsafe {
        ffi::WSARecv(s, &mut wsabuf, 1, &mut received, &mut io_flags, ptr::null_mut(), ptr::null_mut())
    };
    // SAFETY: plain value arguments.
    unsafe { finish_recv(r, received, io_flags) }
}

/// wsock32 `recvfrom`.
///
/// # Safety
/// Winsock's contract for `recvfrom`.
pub unsafe fn recvfrom(
    s: SOCKET,
    buf: *mut c_char,
    len: i32,
    flags: i32,
    from: *mut c_void,
    fromlen: *mut i32,
) -> i32 {
    let mut wsabuf = ffi::WsaBuf { len: len as u32, buf };
    let mut io_flags = flags as u32;
    let mut received = 0u32;
    // SAFETY: valid WSABUF/out-parameters; buffers are the caller's.
    let r = unsafe {
        ffi::WSARecvFrom(
            s,
            &mut wsabuf,
            1,
            &mut received,
            &mut io_flags,
            from,
            fromlen,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    // SAFETY: plain value arguments.
    unsafe { finish_recv(r, received, io_flags) }
}

/// Shared tail of `recv`/`recvfrom` (system code at RVA 0x1595 / 0x160B).
///
/// # Safety
/// Only calls `SetLastError`.
unsafe fn finish_recv(result: i32, received: u32, io_flags: u32) -> i32 {
    if result == SOCKET_ERROR {
        return SOCKET_ERROR;
    }
    let mut received = received;
    if io_flags & ffi::MSG_PARTIAL != 0 {
        received = received.wrapping_neg();
        // SAFETY: no pointer arguments.
        unsafe { ffi::SetLastError(WSAEMSGSIZE) };
    }
    received as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_option_table_matches_system_jump_table() {
        let expected = [(2, 9), (3, 10), (4, 11), (5, 12), (6, 13), (7, 4), (8, 3), (9, 14)];
        for (ws1, ws2) in expected {
            assert_eq!(ws1_ip_option(ws1), ws2);
        }
        for unchanged in [-1, 0, 1, 10, 11, 12, 14, 0x7000, i32::MIN, i32::MAX] {
            assert_eq!(ws1_ip_option(unchanged), unchanged);
        }
    }

    #[test]
    fn partial_message_negates() {
        // SAFETY: only SetLastError.
        unsafe {
            assert_eq!(finish_recv(SOCKET_ERROR, 5, 0), SOCKET_ERROR);
            assert_eq!(finish_recv(0, 5, 0), 5);
            assert_eq!(finish_recv(0, 5, ffi::MSG_PARTIAL), -5);
            assert_eq!(ffi::GetLastError(), WSAEMSGSIZE);
        }
    }
}
