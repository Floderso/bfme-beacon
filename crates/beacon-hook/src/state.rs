//! Armed state: set once in `DllMain` (before any hooked call can observe it) and
//! read-only afterwards. Passive mode never sets it, so every export's fast path is
//! a single atomic load.

use core::cell::UnsafeCell;
use core::ffi::c_char;
use core::ptr::{addr_of_mut, null_mut};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use crate::ffi::{self, Hostent, SockAddrIn};
use crate::wide::format_decimal;

/// Capacity of the fake host name `BEACON-<octet>` incl. NUL.
pub const HOSTNAME_CAP: usize = 16;

/// Configuration of an armed hook.
pub struct Armed {
    /// `127.0.0.1:BEACON_AGENT_PORT`.
    pub agent: SockAddrIn,
    /// `BEACON_LOCAL_TOKEN`.
    pub token: u32,
    /// `BEACON_VIP`.
    pub vip: Ipv4Addr,
    /// NUL-terminated `BEACON-<last octet>`.
    hostname: [u8; HOSTNAME_CAP],
    hostname_len: usize,
}

impl Armed {
    /// The fake host name without NUL.
    pub fn hostname(&self) -> &[u8] {
        self.hostname.get(..self.hostname_len).unwrap_or(&[])
    }

    /// The fake host name including its NUL terminator.
    pub fn hostname_with_nul(&self) -> &[u8] {
        self.hostname.get(..=self.hostname_len).unwrap_or(&[])
    }
}

static ARMED: OnceLock<Armed> = OnceLock::new();
/// Set when a mandatory IAT hook turned out to be bypassed (first-`WSAStartup`
/// re-verification): virtualisation is off for good, every export is passive.
static DISARMED: AtomicBool = AtomicBool::new(false);

/// The armed state, `None` in passive mode (never armed, or disarmed).
#[inline]
pub fn get() -> Option<&'static Armed> {
    if DISARMED.load(Ordering::Acquire) {
        return None;
    }
    ARMED.get()
}

/// Turns the socket virtualisation off for the rest of the process (fail safe:
/// the game then uses the real network as without Beacon, not half-virtualised
/// sockets).
pub fn disarm() {
    DISARMED.store(true, Ordering::Release);
}

/// `BEACON-<last octet of vip>` (NUL-terminated) and its length.
pub fn hostname_for(vip: Ipv4Addr) -> ([u8; HOSTNAME_CAP], usize) {
    let mut out = [0u8; HOSTNAME_CAP];
    let prefix = b"BEACON-";
    let mut digits = [0u8; 10];
    let [_, _, _, host] = vip.octets();
    let num = format_decimal(u32::from(host), &mut digits);
    let len = prefix.len() + num.len();
    if let Some(dst) = out.get_mut(..prefix.len()) {
        dst.copy_from_slice(prefix);
    }
    if let Some(dst) = out.get_mut(prefix.len()..len) {
        dst.copy_from_slice(num);
    }
    (out, len)
}

/// Publishes the armed state (and the static `hostent`). Returns `false` if it was
/// already set.
pub fn arm(agent_port: u16, token: u32, vip: Ipv4Addr) -> bool {
    let (hostname, hostname_len) = hostname_for(vip);
    init_hostent(vip, &hostname);
    ARMED
        .set(Armed {
            agent: SockAddrIn::new([127, 0, 0, 1], agent_port),
            token,
            vip,
            hostname,
            hostname_len,
        })
        .is_ok()
}

/// Static storage behind the `hostent` returned for the own host name: exactly one
/// address, the VIP (architecture §4.2).
#[repr(C)]
struct HostentStorage {
    he: Hostent,
    aliases: [*mut c_char; 1],
    addr_list: [*mut c_char; 2],
    addr: [u8; 4],
    name: [u8; HOSTNAME_CAP],
}

struct HostentCell(UnsafeCell<HostentStorage>);

// SAFETY: written exactly once by `init_hostent` before `ARMED` is published (the
// `OnceLock` gives release/acquire ordering); afterwards it is only read.
unsafe impl Sync for HostentCell {}

static HOSTENT: HostentCell = HostentCell(UnsafeCell::new(HostentStorage {
    he: Hostent {
        h_name: null_mut(),
        h_aliases: null_mut(),
        h_addrtype: 0,
        h_length: 0,
        h_addr_list: null_mut(),
    },
    aliases: [null_mut()],
    addr_list: [null_mut(); 2],
    addr: [0; 4],
    name: [0; HOSTNAME_CAP],
}));

fn init_hostent(vip: Ipv4Addr, name: &[u8; HOSTNAME_CAP]) {
    if ARMED.get().is_some() {
        return;
    }
    let p = HOSTENT.0.get();
    // SAFETY: called once from `DllMain` before the state is published; nobody
    // reads the storage before `ARMED` is set. All pointers point into the static.
    unsafe {
        (*p).addr = vip.octets();
        (*p).name = *name;
        (*p).aliases = [null_mut()];
        (*p).addr_list = [addr_of_mut!((*p).addr).cast(), null_mut()];
        (*p).he = Hostent {
            h_name: addr_of_mut!((*p).name).cast(),
            h_aliases: addr_of_mut!((*p).aliases).cast(),
            h_addrtype: ffi::AF_INET as i16,
            h_length: 4,
            h_addr_list: addr_of_mut!((*p).addr_list).cast(),
        };
    }
}

/// The static `hostent` (valid once armed).
pub fn hostent_ptr() -> *mut Hostent {
    // `he` is the first field of the `repr(C)` storage.
    HOSTENT.0.get().cast()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames() {
        let (n, len) = hostname_for(Ipv4Addr::new(198, 18, 0, 7));
        assert_eq!(&n[..len + 1], b"BEACON-7\0");
        let (n, len) = hostname_for(Ipv4Addr::new(198, 18, 0, 254));
        assert_eq!(&n[..len + 1], b"BEACON-254\0");
        let (n, len) = hostname_for(Ipv4Addr::new(198, 18, 0, 0));
        assert_eq!(&n[..len], b"BEACON-0");
    }

    #[test]
    fn hostent_layout() {
        // i686 layout the game reads: h_length at +0x0A, h_addr_list at +0x0C.
        if cfg!(target_pointer_width = "32") {
            assert_eq!(core::mem::size_of::<Hostent>(), 16);
            assert_eq!(core::mem::offset_of!(Hostent, h_length), 0x0A);
            assert_eq!(core::mem::offset_of!(Hostent, h_addr_list), 0x0C);
        }
        assert_eq!(core::mem::size_of::<SockAddrIn>(), 16);
    }
}
