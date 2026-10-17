//! Minimal Win32 / Winsock declarations. `extern "system"` is `__stdcall` on i686,
//! which is what WinSock (`WSAAPI`) and every API used here expect.
//!
//! Only what the hook needs is declared; the hook statically imports `ws2_32`,
//! `kernel32` and `ntdll` (never `wsock32` itself, never through the game's IAT).

#![allow(non_snake_case, clippy::upper_case_acronyms)]

use core::ffi::{c_char, c_void};

/// Winsock socket handle (`UINT_PTR`).
pub type SOCKET = usize;
/// Win32 `BOOL`.
pub type BOOL = i32;
/// Generic kernel handle.
pub type HANDLE = *mut c_void;
/// Module handle.
pub type HMODULE = *mut c_void;

/// `INVALID_SOCKET`.
pub const INVALID_SOCKET: SOCKET = !0;
/// `SOCKET_ERROR`.
pub const SOCKET_ERROR: i32 = -1;

/// `AF_INET`.
pub const AF_INET: u16 = 2;
/// `SOCK_DGRAM`.
pub const SOCK_DGRAM: i32 = 2;
/// `IPPROTO_IP` (option level 0).
pub const IPPROTO_IP: i32 = 0;
/// `IPPROTO_TCP`.
pub const IPPROTO_TCP: i32 = 6;
/// `IPPROTO_UDP`.
pub const IPPROTO_UDP: i32 = 17;
/// `SOL_SOCKET`.
pub const SOL_SOCKET: i32 = 0xFFFF;
/// `SO_BROADCAST`.
pub const SO_BROADCAST: i32 = 0x20;
/// `SO_TYPE`.
pub const SO_TYPE: i32 = 0x1008;
/// `MSG_PEEK`.
pub const MSG_PEEK: i32 = 0x2;
/// `MSG_PARTIAL` (returned in `WSARecv` flags).
pub const MSG_PARTIAL: u32 = 0x8000;
/// `SD_SEND`.
pub const SD_SEND: i32 = 1;
/// `SD_BOTH`.
pub const SD_BOTH: i32 = 2;
/// `SIO_UDP_CONNRESET`: report ICMP port-unreachable as `WSAECONNRESET` (we turn it off).
pub const SIO_UDP_CONNRESET: u32 = 0x9800_000C;

/// `WSAEACCES`.
pub const WSAEACCES: i32 = 10013;
/// `WSAEFAULT`.
pub const WSAEFAULT: i32 = 10014;
/// `WSAEWOULDBLOCK`.
pub const WSAEWOULDBLOCK: i32 = 10035;
/// `WSAENOTSOCK`.
pub const WSAENOTSOCK: i32 = 10038;
/// `WSAEMSGSIZE`.
pub const WSAEMSGSIZE: i32 = 10040;
/// `WSAEAFNOSUPPORT`.
pub const WSAEAFNOSUPPORT: i32 = 10047;
/// `WSAEADDRINUSE`.
pub const WSAEADDRINUSE: i32 = 10048;
/// `WSAEADDRNOTAVAIL`.
pub const WSAEADDRNOTAVAIL: i32 = 10049;
/// `WSAENETRESET`.
pub const WSAENETRESET: i32 = 10052;
/// `WSAECONNRESET`.
pub const WSAECONNRESET: i32 = 10054;

/// `DLL_PROCESS_ATTACH`.
pub const DLL_PROCESS_ATTACH: u32 = 1;
/// `PAGE_READWRITE`.
pub const PAGE_READWRITE: u32 = 0x04;
/// `FILE_APPEND_DATA`.
pub const FILE_APPEND_DATA: u32 = 0x0004;
/// `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`.
pub const FILE_SHARE_ALL: u32 = 0x7;
/// `OPEN_ALWAYS`.
pub const OPEN_ALWAYS: u32 = 4;
/// `FILE_ATTRIBUTE_NORMAL`.
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
/// `INVALID_HANDLE_VALUE`.
pub const INVALID_HANDLE_VALUE: isize = -1;
/// `CP_ACP`.
pub const CP_ACP: u32 = 0;
/// `WC_NO_BEST_FIT_CHARS`.
pub const WC_NO_BEST_FIT_CHARS: u32 = 0x400;
/// `CP_UTF8` (the ANSI code page when "Use Unicode UTF-8 for worldwide language
/// support" is enabled).
pub const CP_UTF8: u32 = 65001;
/// `WC_ERR_INVALID_CHARS` (the only flag `WideCharToMultiByte` accepts for UTF-8).
pub const WC_ERR_INVALID_CHARS: u32 = 0x80;

/// `KeyNameInformation` (`KEY_INFORMATION_CLASS`).
pub const KEY_NAME_INFORMATION: u32 = 3;

/// `REG_SZ`.
pub const REG_SZ: u32 = 1;
/// `ERROR_SUCCESS`.
pub const ERROR_SUCCESS: i32 = 0;
/// `ERROR_INVALID_PARAMETER`.
pub const ERROR_INVALID_PARAMETER: i32 = 87;
/// `ERROR_MORE_DATA`.
pub const ERROR_MORE_DATA: i32 = 234;
/// `ERROR_INVALID_FUNCTION` (returned if a hook is reached without its original).
pub const ERROR_INVALID_FUNCTION: i32 = 1;

/// `sockaddr_in` with explicit network-order byte fields (16 bytes).
#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SockAddrIn {
    /// `sin_family`.
    pub family: u16,
    /// `sin_port`, network order.
    pub port: [u8; 2],
    /// `sin_addr`, network order.
    pub addr: [u8; 4],
    /// `sin_zero`.
    pub zero: [u8; 8],
}

/// Size of [`SockAddrIn`] as Winsock expects it in `namelen` arguments.
pub const SOCKADDR_IN_LEN: i32 = 16;

impl SockAddrIn {
    /// An `AF_INET` address.
    pub const fn new(addr: [u8; 4], port: u16) -> Self {
        Self { family: AF_INET, port: port.to_be_bytes(), addr, zero: [0; 8] }
    }

    /// Port in host order.
    pub const fn port(&self) -> u16 {
        u16::from_be_bytes(self.port)
    }
}

/// `hostent` (32-bit layout on i686: 4 + 4 + 2 + 2 + 4 bytes).
#[repr(C)]
pub struct Hostent {
    /// `h_name`.
    pub h_name: *mut c_char,
    /// `h_aliases`.
    pub h_aliases: *mut *mut c_char,
    /// `h_addrtype`.
    pub h_addrtype: i16,
    /// `h_length`.
    pub h_length: i16,
    /// `h_addr_list`.
    pub h_addr_list: *mut *mut c_char,
}

/// `WSABUF`.
#[repr(C)]
pub struct WsaBuf {
    /// Buffer length.
    pub len: u32,
    /// Buffer.
    pub buf: *mut c_char,
}

/// `SYSTEMTIME`.
#[repr(C)]
#[derive(Default)]
pub struct SystemTime {
    /// Year.
    pub year: u16,
    /// Month.
    pub month: u16,
    /// Day of week.
    pub day_of_week: u16,
    /// Day.
    pub day: u16,
    /// Hour.
    pub hour: u16,
    /// Minute.
    pub minute: u16,
    /// Second.
    pub second: u16,
    /// Milliseconds.
    pub milliseconds: u16,
}

#[link(name = "ws2_32")]
extern "system" {
    pub fn WSAStartup(version: u16, data: *mut c_void) -> i32;
    pub fn WSACleanup() -> i32;
    pub fn WSAGetLastError() -> i32;
    pub fn WSASetLastError(err: i32);
    pub fn __WSAFDIsSet(s: SOCKET, set: *mut c_void) -> i32;
    pub fn accept(s: SOCKET, addr: *mut c_void, addrlen: *mut i32) -> SOCKET;
    pub fn bind(s: SOCKET, name: *const c_void, namelen: i32) -> i32;
    pub fn closesocket(s: SOCKET) -> i32;
    pub fn connect(s: SOCKET, name: *const c_void, namelen: i32) -> i32;
    pub fn gethostbyname(name: *const c_char) -> *mut Hostent;
    pub fn gethostname(name: *mut c_char, namelen: i32) -> i32;
    pub fn getpeername(s: SOCKET, name: *mut c_void, namelen: *mut i32) -> i32;
    pub fn getsockname(s: SOCKET, name: *mut c_void, namelen: *mut i32) -> i32;
    pub fn getsockopt(s: SOCKET, level: i32, optname: i32, optval: *mut c_char, optlen: *mut i32)
        -> i32;
    pub fn htonl(v: u32) -> u32;
    pub fn inet_addr(cp: *const c_char) -> u32;
    /// `in_addr` is a 4-byte struct passed by value (one stack slot).
    pub fn inet_ntoa(addr: u32) -> *mut c_char;
    pub fn ioctlsocket(s: SOCKET, cmd: i32, argp: *mut u32) -> i32;
    pub fn listen(s: SOCKET, backlog: i32) -> i32;
    pub fn ntohs(v: u16) -> u16;
    pub fn recv(s: SOCKET, buf: *mut c_char, len: i32, flags: i32) -> i32;
    pub fn recvfrom(
        s: SOCKET,
        buf: *mut c_char,
        len: i32,
        flags: i32,
        from: *mut c_void,
        fromlen: *mut i32,
    ) -> i32;
    pub fn select(
        nfds: i32,
        readfds: *mut c_void,
        writefds: *mut c_void,
        exceptfds: *mut c_void,
        timeout: *const c_void,
    ) -> i32;
    pub fn send(s: SOCKET, buf: *const c_char, len: i32, flags: i32) -> i32;
    pub fn sendto(
        s: SOCKET,
        buf: *const c_char,
        len: i32,
        flags: i32,
        to: *const c_void,
        tolen: i32,
    ) -> i32;
    pub fn setsockopt(s: SOCKET, level: i32, optname: i32, optval: *const c_char, optlen: i32)
        -> i32;
    pub fn shutdown(s: SOCKET, how: i32) -> i32;
    pub fn socket(af: i32, ty: i32, protocol: i32) -> SOCKET;
    pub fn WSARecv(
        s: SOCKET,
        buffers: *mut WsaBuf,
        count: u32,
        received: *mut u32,
        flags: *mut u32,
        overlapped: *mut c_void,
        completion: *mut c_void,
    ) -> i32;
    pub fn WSARecvFrom(
        s: SOCKET,
        buffers: *mut WsaBuf,
        count: u32,
        received: *mut u32,
        flags: *mut u32,
        from: *mut c_void,
        fromlen: *mut i32,
        overlapped: *mut c_void,
        completion: *mut c_void,
    ) -> i32;
    pub fn WSAIoctl(
        s: SOCKET,
        code: u32,
        inbuf: *mut c_void,
        inlen: u32,
        outbuf: *mut c_void,
        outlen: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
        completion: *mut c_void,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    pub fn GetModuleHandleW(name: *const u16) -> HMODULE;
    pub fn VirtualProtect(addr: *mut c_void, size: usize, new: u32, old: *mut u32) -> BOOL;
    pub fn GetEnvironmentVariableW(name: *const u16, buf: *mut u16, size: u32) -> u32;
    pub fn GetCurrentProcessId() -> u32;
    pub fn GetCurrentThreadId() -> u32;
    pub fn GetACP() -> u32;
    pub fn GetLastError() -> u32;
    pub fn SetLastError(err: u32);
    pub fn GetTickCount() -> u32;
    pub fn GetLocalTime(st: *mut SystemTime);
    pub fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *mut c_void,
        disposition: u32,
        flags: u32,
        template: HANDLE,
    ) -> HANDLE;
    pub fn WriteFile(
        file: HANDLE,
        buf: *const c_void,
        len: u32,
        written: *mut u32,
        overlapped: *mut c_void,
    ) -> BOOL;
    pub fn CloseHandle(h: HANDLE) -> BOOL;
    pub fn CreateDirectoryW(path: *const u16, security: *mut c_void) -> BOOL;
    pub fn WideCharToMultiByte(
        code_page: u32,
        flags: u32,
        wide: *const u16,
        wide_len: i32,
        out: *mut u8,
        out_len: i32,
        default_char: *const u8,
        used_default: *mut BOOL,
    ) -> i32;
}

#[link(name = "ntdll")]
extern "system" {
    pub fn NtQueryKey(
        key: HANDLE,
        class: u32,
        info: *mut c_void,
        len: u32,
        result_len: *mut u32,
    ) -> i32;
}
