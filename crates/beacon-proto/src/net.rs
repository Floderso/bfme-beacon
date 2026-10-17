//! Virtual LAN addressing (architecture §4.1).
//!
//! All Beacon players share the virtual subnet `198.18.0.0/24` (RFC 2544 benchmark
//! range: never routed, does not collide with home LANs or VPNs). `198.18.0.1` is
//! the server; players get a vIP from `198.18.0.2..=198.18.0.254`. The game binds
//! the virtual ports 8086…8093 (LAN lobby) and 8094…8101 (in-game).

use core::ops::RangeInclusive;
use std::net::Ipv4Addr;

/// First three octets of the virtual subnet.
const PREFIX: [u8; 3] = [198, 18, 0];

/// Network address of the virtual subnet (`198.18.0.0`).
pub const VSUBNET: Ipv4Addr = Ipv4Addr::new(PREFIX[0], PREFIX[1], PREFIX[2], 0);

/// Prefix length of the virtual subnet (`/24`).
pub const VSUBNET_PREFIX_LEN: u8 = 24;

/// Netmask of the virtual subnet (`255.255.255.0`).
pub const VSUBNET_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

/// Directed broadcast address of the virtual subnet (`198.18.0.255`).
pub const VSUBNET_BROADCAST: Ipv4Addr = Ipv4Addr::new(PREFIX[0], PREFIX[1], PREFIX[2], 255);

/// Limited broadcast address (`255.255.255.255`).
pub const LIMITED_BROADCAST: Ipv4Addr = Ipv4Addr::BROADCAST;

/// The server's own virtual address (`198.18.0.1`, reserved, never assigned to a player).
pub const SERVER_VIP: Ipv4Addr = Ipv4Addr::new(PREFIX[0], PREFIX[1], PREFIX[2], 1);

/// Lowest host octet that can be assigned to a player (`198.18.0.2`).
pub const VIP_HOST_MIN: u8 = 2;

/// Highest host octet that can be assigned to a player (`198.18.0.254`).
pub const VIP_HOST_MAX: u8 = 254;

/// Number of assignable player vIPs (253).
pub const VIP_POOL_SIZE: usize = (VIP_HOST_MAX - VIP_HOST_MIN) as usize + 1;

/// Virtual ports of BFME's LAN lobby socket (first free one is used; broadcasts go
/// to all eight).
pub const LOBBY_PORTS: RangeInclusive<u16> = 8086..=8093;

/// Virtual ports of BFME's in-game socket (lobby port + 8).
pub const GAME_PORTS: RangeInclusive<u16> = 8094..=8101;

/// All virtual ports BFME uses (lobby and in-game).
pub const VIRTUAL_PORTS: RangeInclusive<u16> = 8086..=8101;

/// `true` if `ip` lies inside the virtual subnet `198.18.0.0/24` (any of its 256
/// addresses, including network, server and broadcast address).
pub const fn is_virtual(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    a == PREFIX[0] && b == PREFIX[1] && c == PREFIX[2]
}

/// `true` if `ip` is a broadcast destination for the virtual LAN:
/// `255.255.255.255` or `198.18.0.255`.
pub const fn is_broadcast(ip: Ipv4Addr) -> bool {
    matches!(ip.octets(), [255, 255, 255, 255] | [198, 18, 0, 255])
}

/// `true` if `ip` is a destination the hook must virtualise, i.e. inside the
/// virtual subnet or a broadcast address (architecture §4.2, `sendto`).
pub const fn is_virtual_destination(ip: Ipv4Addr) -> bool {
    is_virtual(ip) || is_broadcast(ip)
}

/// `true` if `ip` is a player vIP (`198.18.0.2..=198.18.0.254`).
pub const fn is_assignable(ip: Ipv4Addr) -> bool {
    vip_host(ip).is_some()
}

/// The player vIP `198.18.0.<host>`, or `None` if `host` is outside `2..=254`.
pub const fn vip_from_host(host: u8) -> Option<Ipv4Addr> {
    if host >= VIP_HOST_MIN && host <= VIP_HOST_MAX {
        Some(Ipv4Addr::new(PREFIX[0], PREFIX[1], PREFIX[2], host))
    } else {
        None
    }
}

/// The host octet of a player vIP, or `None` if `ip` is not in
/// `198.18.0.2..=198.18.0.254`.
pub const fn vip_host(ip: Ipv4Addr) -> Option<u8> {
    let [_, _, _, d] = ip.octets();
    if is_virtual(ip) && d >= VIP_HOST_MIN && d <= VIP_HOST_MAX {
        Some(d)
    } else {
        None
    }
}

/// `true` for BFME's LAN lobby ports 8086…8093.
pub const fn is_lobby_port(port: u16) -> bool {
    port >= *LOBBY_PORTS.start() && port <= *LOBBY_PORTS.end()
}

/// `true` for BFME's in-game ports 8094…8101.
pub const fn is_game_port(port: u16) -> bool {
    port >= *GAME_PORTS.start() && port <= *GAME_PORTS.end()
}

/// `true` for every port BFME binds for LAN play (8086…8101).
pub const fn is_virtual_port(port: u16) -> bool {
    is_lobby_port(port) || is_game_port(port)
}

/// Bookkeeping for the player vIP pool `198.18.0.2..=198.18.0.254`.
///
/// Stickiness per player name (architecture §4.1) is the server's job: remember the
/// name → vIP mapping, try [`claim`](Self::claim) with the remembered address first
/// and fall back to [`allocate`](Self::allocate).
#[derive(Clone, PartialEq, Eq)]
pub struct VipAllocator {
    used: [bool; 256],
}

impl VipAllocator {
    /// An allocator with every player vIP free.
    pub const fn new() -> Self {
        Self { used: [false; 256] }
    }

    /// Allocates the lowest free player vIP, or `None` if the pool is exhausted.
    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        let host = (VIP_HOST_MIN..=VIP_HOST_MAX).find(|&h| !self.is_host_used(h))?;
        self.set_host(host, true);
        vip_from_host(host)
    }

    /// Claims a specific vIP. Returns `true` if it was free and assignable and is now
    /// allocated; `false` if it is already taken or not a player vIP.
    pub fn claim(&mut self, ip: Ipv4Addr) -> bool {
        match vip_host(ip) {
            Some(host) if !self.is_host_used(host) => {
                self.set_host(host, true);
                true
            }
            _ => false,
        }
    }

    /// Returns a vIP to the pool. Returns `true` if it was allocated.
    pub fn release(&mut self, ip: Ipv4Addr) -> bool {
        match vip_host(ip) {
            Some(host) if self.is_host_used(host) => {
                self.set_host(host, false);
                true
            }
            _ => false,
        }
    }

    /// `true` if `ip` is a player vIP that is currently allocated.
    pub fn is_allocated(&self, ip: Ipv4Addr) -> bool {
        vip_host(ip).is_some_and(|h| self.is_host_used(h))
    }

    /// Number of allocated player vIPs.
    pub fn allocated(&self) -> usize {
        (VIP_HOST_MIN..=VIP_HOST_MAX)
            .filter(|&h| self.is_host_used(h))
            .count()
    }

    /// Number of free player vIPs.
    pub fn available(&self) -> usize {
        VIP_POOL_SIZE - self.allocated()
    }

    fn is_host_used(&self, host: u8) -> bool {
        self.used.get(usize::from(host)).copied().unwrap_or(true)
    }

    fn set_host(&mut self, host: u8, used: bool) {
        if let Some(slot) = self.used.get_mut(usize::from(host)) {
            *slot = used;
        }
    }
}

impl Default for VipAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for VipAllocator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VipAllocator")
            .field("allocated", &self.allocated())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(d: u8) -> Ipv4Addr {
        Ipv4Addr::new(198, 18, 0, d)
    }

    #[test]
    fn constants() {
        assert_eq!(VSUBNET.octets(), [198, 18, 0, 0]);
        assert_eq!(SERVER_VIP.octets(), [198, 18, 0, 1]);
        assert_eq!(VSUBNET_BROADCAST.octets(), [198, 18, 0, 255]);
        assert_eq!(VSUBNET_MASK.octets(), [255, 255, 255, 0]);
        assert_eq!(VIP_POOL_SIZE, 253);
        assert_eq!(u32::from(VSUBNET_MASK).count_ones(), u32::from(VSUBNET_PREFIX_LEN));
        // Inside the RFC 2544 benchmarking block 198.18.0.0/15.
        let [a, b, _, _] = VSUBNET.octets();
        assert!(a == 198 && b & 0xfe == 18);
    }

    #[test]
    fn classification() {
        for d in 0..=255u8 {
            let ip = v(d);
            assert!(is_virtual(ip));
            assert!(is_virtual_destination(ip));
            assert_eq!(is_broadcast(ip), d == 255);
            assert_eq!(is_assignable(ip), (2..=254).contains(&d));
        }
        for ip in [
            Ipv4Addr::new(198, 18, 1, 1),
            Ipv4Addr::new(198, 19, 0, 1),
            Ipv4Addr::new(199, 18, 0, 1),
            Ipv4Addr::new(10, 88, 0, 255),
            Ipv4Addr::new(192, 168, 0, 255),
            Ipv4Addr::new(198, 18, 255, 255),
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
        ] {
            assert!(!is_virtual(ip), "{ip}");
            assert!(!is_broadcast(ip), "{ip}");
            assert!(!is_assignable(ip), "{ip}");
        }
        assert!(is_broadcast(Ipv4Addr::BROADCAST));
        assert!(!is_virtual(Ipv4Addr::BROADCAST));
        assert!(is_virtual_destination(Ipv4Addr::BROADCAST));
        assert!(is_virtual(SERVER_VIP) && !is_assignable(SERVER_VIP));
    }

    #[test]
    fn ports() {
        for p in 0..=u16::MAX {
            assert_eq!(is_lobby_port(p), (8086..=8093).contains(&p));
            assert_eq!(is_game_port(p), (8094..=8101).contains(&p));
            assert_eq!(is_virtual_port(p), VIRTUAL_PORTS.contains(&p));
        }
        // In-game port = lobby port + 8.
        for p in LOBBY_PORTS {
            assert!(is_game_port(p + 8));
        }
    }

    #[test]
    fn host_conversions() {
        assert_eq!(vip_from_host(0), None);
        assert_eq!(vip_from_host(1), None);
        assert_eq!(vip_from_host(2), Some(v(2)));
        assert_eq!(vip_from_host(254), Some(v(254)));
        assert_eq!(vip_from_host(255), None);
        for h in 0..=255u8 {
            if let Some(ip) = vip_from_host(h) {
                assert_eq!(vip_host(ip), Some(h));
            }
        }
        assert_eq!(vip_host(SERVER_VIP), None);
        assert_eq!(vip_host(Ipv4Addr::new(198, 18, 1, 5)), None);
    }

    #[test]
    fn allocator_exhaustion_and_reuse() {
        let mut a = VipAllocator::new();
        assert_eq!(a.available(), 253);
        let mut got = Vec::new();
        while let Some(ip) = a.allocate() {
            assert!(is_assignable(ip));
            got.push(ip);
        }
        assert_eq!(got.len(), 253);
        assert_eq!(got.first(), Some(&v(2)));
        assert_eq!(got.last(), Some(&v(254)));
        assert_eq!(a.available(), 0);
        assert_eq!(a.allocate(), None);

        let ip = v(77);
        assert!(a.release(ip));
        assert!(!a.release(ip));
        assert!(!a.is_allocated(ip));
        assert_eq!(a.allocate(), Some(ip));
        assert!(a.is_allocated(ip));
    }

    #[test]
    fn allocator_claim() {
        let mut a = VipAllocator::new();
        let sticky = v(9);
        assert!(a.claim(sticky));
        assert!(!a.claim(sticky));
        assert!(!a.claim(SERVER_VIP));
        assert!(!a.claim(VSUBNET_BROADCAST));
        assert!(!a.claim(VSUBNET));
        assert!(!a.claim(Ipv4Addr::new(192, 168, 1, 9)));
        assert!(!a.release(SERVER_VIP));
        assert_eq!(a.allocated(), 1);
        assert_eq!(a.allocate(), Some(v(2)));
        assert_eq!(a.allocated(), 2);
        assert_eq!(format!("{a:?}"), "VipAllocator { allocated: 2 }");
    }
}
