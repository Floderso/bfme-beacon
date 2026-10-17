//! Loading a DLL by full path and calling its Winsock exports through typed
//! function pointers (32-bit `__stdcall`).

use core::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn GetLastError() -> u32;
}

#[link(name = "ws2_32")]
extern "system" {
    #[link_name = "gethostname"]
    fn ws2_gethostname(name: *mut u8, len: i32) -> i32;
    #[link_name = "getsockname"]
    fn ws2_getsockname(s: usize, name: *mut SockAddrIn, len: *mut i32) -> i32;
    #[link_name = "closesocket"]
    fn ws2_closesocket(s: usize) -> i32;
}

pub const AF_INET: u16 = 2;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const IPPROTO_IP: i32 = 0;
pub const IPPROTO_UDP: i32 = 17;
pub const SOL_SOCKET: i32 = 0xFFFF;
pub const SO_BROADCAST: i32 = 0x20;
pub const FIONBIO: i32 = 0x8004_667Eu32 as i32;
pub const MSG_PEEK: i32 = 2;
pub const SD_BOTH: i32 = 2;
pub const INVALID_SOCKET: usize = !0;

pub const WSAEACCES: i32 = 10013;
pub const WSAEFAULT: i32 = 10014;
pub const WSAEINVAL: i32 = 10022;
pub const WSAEWOULDBLOCK: i32 = 10035;
pub const WSAENOTSOCK: i32 = 10038;
pub const WSAEMSGSIZE: i32 = 10040;
pub const WSAEADDRINUSE: i32 = 10048;
pub const WSAEADDRNOTAVAIL: i32 = 10049;
pub const WSAENOTCONN: i32 = 10057;

/// `sockaddr_in` with network-order byte fields.
#[repr(C, align(4))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SockAddrIn {
    pub family: u16,
    pub port: [u8; 2],
    pub addr: [u8; 4],
    pub zero: [u8; 8],
}

impl SockAddrIn {
    pub const fn new(addr: [u8; 4], port: u16) -> Self {
        Self { family: AF_INET, port: port.to_be_bytes(), addr, zero: [0; 8] }
    }

    pub const fn port(&self) -> u16 {
        u16::from_be_bytes(self.port)
    }
}

/// 32-bit `hostent`.
#[repr(C)]
pub struct Hostent {
    pub h_name: *const u8,
    pub h_aliases: *const *const u8,
    pub h_addrtype: i16,
    pub h_length: i16,
    pub h_addr_list: *const *const u8,
}

/// A loaded module.
pub struct Module(*mut c_void);

impl Module {
    pub fn load(path: &Path) -> Result<Self, String> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: NUL-terminated wide path.
        let h = unsafe { LoadLibraryW(wide.as_ptr()) };
        if h.is_null() {
            // SAFETY: no arguments.
            let err = unsafe { GetLastError() };
            return Err(format!("LoadLibraryW({}) failed: error {err}", path.display()));
        }
        Ok(Self(h))
    }

    pub fn handle(&self) -> usize {
        self.0 as usize
    }

    pub fn proc(&self, name: &str) -> Option<*mut c_void> {
        let cname: Vec<u8> = name.bytes().chain([0]).collect();
        // SAFETY: valid module handle and NUL-terminated name.
        let p = unsafe { GetProcAddress(self.0, cname.as_ptr()) };
        (!p.is_null()).then_some(p)
    }
}

type StartupFn = unsafe extern "system" fn(u16, *mut c_void) -> i32;
type CleanupFn = unsafe extern "system" fn() -> i32;
type LastErrorFn = unsafe extern "system" fn() -> i32;
type SocketFn = unsafe extern "system" fn(i32, i32, i32) -> usize;
type BindFn = unsafe extern "system" fn(usize, *const SockAddrIn, i32) -> i32;
type SockNameFn = unsafe extern "system" fn(usize, *mut SockAddrIn, *mut i32) -> i32;
type SendToFn = unsafe extern "system" fn(usize, *const u8, i32, i32, *const SockAddrIn, i32) -> i32;
type RecvFromFn = unsafe extern "system" fn(usize, *mut u8, i32, i32, *mut SockAddrIn, *mut i32) -> i32;
type RecvFn = unsafe extern "system" fn(usize, *mut u8, i32, i32) -> i32;
type SetOptFn = unsafe extern "system" fn(usize, i32, i32, *const u8, i32) -> i32;
type GetOptFn = unsafe extern "system" fn(usize, i32, i32, *mut u8, *mut i32) -> i32;
type IoctlFn = unsafe extern "system" fn(usize, i32, *mut u32) -> i32;
type CloseFn = unsafe extern "system" fn(usize) -> i32;
type ShutdownFn = unsafe extern "system" fn(usize, i32) -> i32;
type HostNameFn = unsafe extern "system" fn(*mut u8, i32) -> i32;
type HostByNameFn = unsafe extern "system" fn(*const u8) -> *const Hostent;
type HtonlFn = unsafe extern "system" fn(u32) -> u32;
type NtohsFn = unsafe extern "system" fn(u16) -> u32;

/// The Winsock exports of one module (ours or the system wsock32).
pub struct Ws {
    startup: StartupFn,
    cleanup: CleanupFn,
    last_error: LastErrorFn,
    socket: SocketFn,
    bind: BindFn,
    getsockname: SockNameFn,
    sendto: SendToFn,
    recvfrom: RecvFromFn,
    recv: RecvFn,
    setsockopt: SetOptFn,
    getsockopt: GetOptFn,
    ioctlsocket: IoctlFn,
    closesocket: CloseFn,
    shutdown: ShutdownFn,
    gethostname: HostNameFn,
    gethostbyname: HostByNameFn,
    htonl: HtonlFn,
    ntohs: NtohsFn,
}

macro_rules! export {
    ($m:expr, $name:literal, $ty:ty) => {{
        let p = $m.proc($name).ok_or_else(|| format!("export {} missing", $name))?;
        // SAFETY: the export has this signature (wsock32 API, __stdcall).
        unsafe { core::mem::transmute::<*mut c_void, $ty>(p) }
    }};
}

impl Ws {
    pub fn load(m: &Module) -> Result<Self, String> {
        Ok(Self {
            startup: export!(m, "WSAStartup", StartupFn),
            cleanup: export!(m, "WSACleanup", CleanupFn),
            last_error: export!(m, "WSAGetLastError", LastErrorFn),
            socket: export!(m, "socket", SocketFn),
            bind: export!(m, "bind", BindFn),
            getsockname: export!(m, "getsockname", SockNameFn),
            sendto: export!(m, "sendto", SendToFn),
            recvfrom: export!(m, "recvfrom", RecvFromFn),
            recv: export!(m, "recv", RecvFn),
            setsockopt: export!(m, "setsockopt", SetOptFn),
            getsockopt: export!(m, "getsockopt", GetOptFn),
            ioctlsocket: export!(m, "ioctlsocket", IoctlFn),
            closesocket: export!(m, "closesocket", CloseFn),
            shutdown: export!(m, "shutdown", ShutdownFn),
            gethostname: export!(m, "gethostname", HostNameFn),
            gethostbyname: export!(m, "gethostbyname", HostByNameFn),
            htonl: export!(m, "htonl", HtonlFn),
            ntohs: export!(m, "ntohs", NtohsFn),
        })
    }

    pub fn startup(&self) -> i32 {
        #[repr(C, align(8))]
        struct WsaData([u8; 512]);
        let mut data = WsaData([0; 512]);
        // SAFETY: WSADATA is 400 bytes on i686; the buffer is larger.
        unsafe { (self.startup)(0x0202, data.0.as_mut_ptr().cast()) }
    }

    pub fn cleanup(&self) -> i32 {
        // SAFETY: no arguments.
        unsafe { (self.cleanup)() }
    }

    pub fn err(&self) -> i32 {
        // SAFETY: no arguments.
        unsafe { (self.last_error)() }
    }

    pub fn socket(&self, protocol: i32) -> usize {
        // SAFETY: plain values.
        unsafe { (self.socket)(i32::from(AF_INET), SOCK_DGRAM, protocol) }
    }

    /// `socket(AF_INET, SOCK_STREAM, 0)`.
    pub fn socket_stream(&self) -> usize {
        // SAFETY: plain values.
        unsafe { (self.socket)(i32::from(AF_INET), SOCK_STREAM, 0) }
    }

    pub fn bind(&self, s: usize, ip: [u8; 4], port: u16) -> i32 {
        let sa = SockAddrIn::new(ip, port);
        // SAFETY: valid sockaddr_in.
        unsafe { (self.bind)(s, &sa, 16) }
    }

    pub fn sockname(&self, s: usize) -> Result<(SockAddrIn, i32), i32> {
        let mut sa = SockAddrIn::default();
        let mut len = 16;
        // SAFETY: valid out-parameters.
        match unsafe { (self.getsockname)(s, &mut sa, &mut len) } {
            0 => Ok((sa, len)),
            _ => Err(self.err()),
        }
    }

    pub fn sockname_short_buffer(&self, s: usize) -> (i32, i32) {
        let mut sa = SockAddrIn::default();
        let mut len = 8;
        // SAFETY: valid out-parameters (deliberately short length).
        let r = unsafe { (self.getsockname)(s, &mut sa, &mut len) };
        (r, self.err())
    }

    pub fn send_to(&self, s: usize, data: &[u8], ip: [u8; 4], port: u16) -> i32 {
        let sa = SockAddrIn::new(ip, port);
        let len = i32::try_from(data.len()).unwrap_or(i32::MAX);
        // SAFETY: `data` valid for `len` bytes, valid sockaddr_in.
        unsafe { (self.sendto)(s, data.as_ptr(), len, 0, &sa, 16) }
    }

    /// `recvfrom`; returns (result, from, fromlen).
    pub fn recv_from(&self, s: usize, buf: &mut [u8], flags: i32) -> (i32, SockAddrIn, i32) {
        let mut from = SockAddrIn::default();
        let mut fromlen = 16;
        let len = i32::try_from(buf.len()).unwrap_or(i32::MAX);
        // SAFETY: `buf` valid for `len` bytes, valid out-parameters.
        let r = unsafe { (self.recvfrom)(s, buf.as_mut_ptr(), len, flags, &mut from, &mut fromlen) };
        (r, from, fromlen)
    }

    pub fn recv(&self, s: usize, buf: &mut [u8]) -> i32 {
        let len = i32::try_from(buf.len()).unwrap_or(i32::MAX);
        // SAFETY: `buf` valid for `len` bytes.
        unsafe { (self.recv)(s, buf.as_mut_ptr(), len, 0) }
    }

    pub fn set_int_opt(&self, s: usize, level: i32, name: i32, value: i32) -> i32 {
        let v = value.to_ne_bytes();
        // SAFETY: 4-byte option buffer.
        unsafe { (self.setsockopt)(s, level, name, v.as_ptr(), 4) }
    }

    pub fn get_int_opt(&self, s: usize, level: i32, name: i32) -> Result<i32, i32> {
        let mut v = [0u8; 4];
        let mut len = 4;
        // SAFETY: 4-byte option buffer and length.
        match unsafe { (self.getsockopt)(s, level, name, v.as_mut_ptr(), &mut len) } {
            0 => Ok(i32::from_ne_bytes(v)),
            _ => Err(self.err()),
        }
    }

    pub fn set_nonblocking(&self, s: usize) -> i32 {
        let mut one: u32 = 1;
        // SAFETY: valid argument pointer.
        unsafe { (self.ioctlsocket)(s, FIONBIO, &mut one) }
    }

    pub fn close(&self, s: usize) -> i32 {
        // SAFETY: plain value.
        unsafe { (self.closesocket)(s) }
    }

    pub fn shutdown(&self, s: usize, how: i32) -> i32 {
        // SAFETY: plain values.
        unsafe { (self.shutdown)(s, how) }
    }

    pub fn hostname(&self) -> Result<String, i32> {
        let mut buf = [0u8; 256];
        // SAFETY: 256-byte buffer.
        if unsafe { (self.gethostname)(buf.as_mut_ptr(), 256) } != 0 {
            return Err(self.err());
        }
        Ok(c_string(&buf))
    }

    pub fn hostname_into(&self, buf: &mut [u8]) -> i32 {
        let len = i32::try_from(buf.len()).unwrap_or(i32::MAX);
        // SAFETY: `buf` valid for `len` bytes.
        unsafe { (self.gethostname)(buf.as_mut_ptr(), len) }
    }

    /// `gethostbyname`: (h_addrtype, h_length, addresses) or None for NULL.
    pub fn host_by_name(&self, name: Option<&str>) -> Option<(i16, i16, Vec<[u8; 4]>)> {
        let cname: Option<Vec<u8>> = name.map(|n| n.bytes().chain([0]).collect());
        let ptr = cname.as_ref().map_or(core::ptr::null(), |c| c.as_ptr());
        // SAFETY: NUL-terminated name or NULL.
        let he = unsafe { (self.gethostbyname)(ptr) };
        if he.is_null() {
            return None;
        }
        // SAFETY: Winsock returned a valid hostent; we read at most 16 entries.
        unsafe {
            let he = &*he;
            let mut addrs = Vec::new();
            if he.h_length == 4 && !he.h_addr_list.is_null() {
                for i in 0..16 {
                    let a = *he.h_addr_list.add(i);
                    if a.is_null() {
                        break;
                    }
                    addrs.push([*a, *a.add(1), *a.add(2), *a.add(3)]);
                }
            }
            Some((he.h_addrtype, he.h_length, addrs))
        }
    }

    pub fn htonl(&self, v: u32) -> u32 {
        // SAFETY: plain value.
        unsafe { (self.htonl)(v) }
    }

    pub fn ntohs(&self, v: u16) -> u16 {
        // SAFETY: plain value.
        (unsafe { (self.ntohs)(v) }) as u16
    }
}

/// The real host name (ws2_32 directly).
pub fn real_hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: 256-byte buffer.
    (unsafe { ws2_gethostname(buf.as_mut_ptr(), 256) } == 0).then(|| c_string(&buf))
}

/// The real local address of a socket (ws2_32 directly, bypassing the hook).
pub fn real_sockname(s: usize) -> Option<SockAddrIn> {
    let mut sa = SockAddrIn::default();
    let mut len = 16;
    // SAFETY: valid out-parameters.
    (unsafe { ws2_getsockname(s, &mut sa, &mut len) } == 0).then_some(sa)
}

/// Closes a socket with ws2_32 directly, behind the hook's back (like another
/// module or a last `WSACleanup` would).
pub fn real_closesocket(s: usize) -> i32 {
    // SAFETY: plain value.
    unsafe { ws2_closesocket(s) }
}

fn c_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(buf.get(..end).unwrap_or(&[])).into_owned()
}
