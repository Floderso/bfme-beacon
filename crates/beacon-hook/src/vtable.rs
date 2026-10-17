//! Bookkeeping of virtual sockets (architecture §4.2): a fixed table of at most
//! [`MAX_SOCKETS`] entries, no allocation. Pure logic; the Winsock side lives in
//! `vsock.rs` and keeps the table behind a short-held lock.
//!
//! States: `Candidate` (an `AF_INET`/`SOCK_DGRAM` socket that is not bound yet),
//! `Binding` (a virtual bind in progress; its vport is reserved), `Virtual` (bound
//! to `127.0.0.1:loop_port`, the game sees `{VIP or ANY}:vport`). Everything else
//! is REAL and has no entry.

use std::net::Ipv4Addr;

use beacon_proto::net;

/// Maximum number of tracked sockets (candidates and virtual sockets).
pub const MAX_SOCKETS: usize = 64;
/// Virtual ports handed out for `bind(VIP:0)` (never used by BFME's LAN code).
pub const EPHEMERAL_FIRST: u16 = 49152;

/// Lifecycle state of a tracked socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Unused slot.
    Free,
    /// Created as `AF_INET`/`SOCK_DGRAM`, not bound yet.
    Candidate,
    /// Virtual bind in progress (vport reserved).
    Binding,
    /// Bound virtually.
    Virtual,
}

/// One tracked socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The real socket handle (what the game holds).
    pub sock: usize,
    /// State.
    pub state: State,
    /// Virtual port (host order).
    pub vport: u16,
    /// Bound to `0.0.0.0` (getsockname reports ANY) instead of the VIP.
    pub bound_any: bool,
    /// Real loopback port of the socket (`127.0.0.1:loop_port`).
    pub loop_port: u16,
    /// `CLOSE` was already sent (at `shutdown`).
    pub close_sent: bool,
}

impl Entry {
    const FREE: Self =
        Self { sock: 0, state: State::Free, vport: 0, bound_any: false, loop_port: 0, close_sent: false };

    const fn holds_vport(&self) -> bool {
        matches!(self.state, State::Binding | State::Virtual)
    }
}

/// How a `bind` request is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindClass {
    /// Virtualise: `port` 0 means "allocate an ephemeral vport".
    Virtual {
        /// Requested port (host order).
        port: u16,
        /// Bound to ANY rather than the VIP.
        bound_any: bool,
    },
    /// Real bind, no virtualisation.
    Real,
}

/// Classifies `bind(ip:port)` (architecture §4.2): the VIP (any port) or ANY on a
/// BFME port 8086…8101 is virtual; everything else is real.
pub fn classify_bind(ip: Ipv4Addr, port: u16, vip: Ipv4Addr) -> BindClass {
    if ip == vip {
        BindClass::Virtual { port, bound_any: false }
    } else if ip.is_unspecified() && net::is_virtual_port(port) {
        BindClass::Virtual { port, bound_any: true }
    } else {
        BindClass::Real
    }
}

/// Outcome of [`Table::begin_bind`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BeginBind {
    /// The socket is not a candidate: call the real `bind` unchanged.
    Untracked,
    /// Real bind; the candidate entry was dropped.
    Real,
    /// Another tracked socket holds the vport (`WSAEADDRINUSE`, unless it is stale).
    InUse(Entry),
    /// No free ephemeral vport.
    NoEphemeral,
    /// Proceed with the real loopback bind; the vport is reserved.
    Proceed {
        /// The reserved virtual port.
        vport: u16,
        /// Bound to ANY.
        bound_any: bool,
    },
}

/// The socket table.
pub struct Table {
    entries: [Entry; MAX_SOCKETS],
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

impl Table {
    /// An empty table.
    pub const fn new() -> Self {
        Self { entries: [Entry::FREE; MAX_SOCKETS] }
    }

    fn find(&self, sock: usize) -> Option<&Entry> {
        self.entries.iter().find(|e| e.state != State::Free && e.sock == sock)
    }

    fn find_mut(&mut self, sock: usize) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.state != State::Free && e.sock == sock)
    }

    /// The entry of `sock`, if tracked.
    pub fn get(&self, sock: usize) -> Option<Entry> {
        self.find(sock).copied()
    }

    /// The entry of `sock` if it is virtual.
    pub fn virtual_entry(&self, sock: usize) -> Option<Entry> {
        self.find(sock).filter(|e| e.state == State::Virtual).copied()
    }

    /// Number of tracked sockets.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|e| e.state != State::Free).count()
    }

    /// Copy of all entries (for liveness sweeps outside the lock).
    pub fn snapshot(&self) -> [Entry; MAX_SOCKETS] {
        self.entries
    }

    /// Tracks a new candidate. A stale entry with the same handle (the handle was
    /// closed behind our back and reused) is replaced. `false` if the table is full.
    pub fn add_candidate(&mut self, sock: usize) -> bool {
        let fresh = Entry { sock, state: State::Candidate, ..Entry::FREE };
        if let Some(e) = self.find_mut(sock) {
            *e = fresh;
            return true;
        }
        match self.entries.iter_mut().find(|e| e.state == State::Free) {
            Some(e) => {
                *e = fresh;
                true
            }
            None => false,
        }
    }

    /// Forgets `sock`; returns its last entry.
    pub fn remove(&mut self, sock: usize) -> Option<Entry> {
        let e = self.find_mut(sock)?;
        let old = *e;
        *e = Entry::FREE;
        Some(old)
    }

    /// Removes `expected` only if its entry is still exactly the same (used after a
    /// liveness check done without the lock).
    pub fn evict_if_unchanged(&mut self, expected: &Entry) -> bool {
        match self.find_mut(expected.sock) {
            Some(e) if e == expected => {
                *e = Entry::FREE;
                true
            }
            _ => false,
        }
    }

    fn vport_in_use(&self, vport: u16, except: usize) -> Option<Entry> {
        self.entries.iter().find(|e| e.holds_vport() && e.vport == vport && e.sock != except).copied()
    }

    /// First step of a `bind` on `sock`.
    pub fn begin_bind(&mut self, sock: usize, class: BindClass) -> BeginBind {
        if self.find(sock).is_none_or(|e| e.state != State::Candidate) {
            return BeginBind::Untracked;
        }
        let (port, bound_any) = match class {
            BindClass::Real => {
                self.remove(sock);
                return BeginBind::Real;
            }
            BindClass::Virtual { port, bound_any } => (port, bound_any),
        };
        let vport = if port == 0 {
            match (EPHEMERAL_FIRST..=u16::MAX).find(|&p| self.vport_in_use(p, sock).is_none()) {
                Some(p) => p,
                None => return BeginBind::NoEphemeral,
            }
        } else {
            if let Some(other) = self.vport_in_use(port, sock) {
                return BeginBind::InUse(other);
            }
            port
        };
        if let Some(e) = self.find_mut(sock) {
            e.state = State::Binding;
            e.vport = vport;
            e.bound_any = bound_any;
        }
        BeginBind::Proceed { vport, bound_any }
    }

    /// The loopback bind succeeded: `Binding` → `Virtual`.
    pub fn commit_bind(&mut self, sock: usize, loop_port: u16) -> Option<Entry> {
        let e = self.find_mut(sock).filter(|e| e.state == State::Binding)?;
        e.state = State::Virtual;
        e.loop_port = loop_port;
        Some(*e)
    }

    /// The loopback bind failed: `Binding` → `Candidate` (vport released).
    pub fn abort_bind(&mut self, sock: usize) {
        if let Some(e) = self.find_mut(sock).filter(|e| e.state == State::Binding) {
            e.state = State::Candidate;
            e.vport = 0;
            e.bound_any = false;
        }
    }

    /// An unbound candidate is used by `sendto` (Winsock binds it implicitly to
    /// ANY:ephemeral): it is REAL from now on.
    pub fn implicit_bind(&mut self, sock: usize) {
        if self.find(sock).is_some_and(|e| e.state == State::Candidate) {
            self.remove(sock);
        }
    }

    /// Marks `CLOSE` as sent; returns the vport if the socket is virtual and the
    /// frame was not sent before.
    pub fn take_close(&mut self, sock: usize) -> Option<u16> {
        let e = self.find_mut(sock).filter(|e| e.state == State::Virtual && !e.close_sent)?;
        e.close_sent = true;
        Some(e.vport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VIP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 5);

    fn bind_virtual(t: &mut Table, sock: usize, port: u16) -> BeginBind {
        let r = t.begin_bind(sock, BindClass::Virtual { port, bound_any: false });
        if let BeginBind::Proceed { .. } = r {
            assert!(t.commit_bind(sock, 40_000 + (sock as u16)).is_some());
        }
        r
    }

    #[test]
    fn classification() {
        let any = Ipv4Addr::UNSPECIFIED;
        assert_eq!(classify_bind(VIP, 8086, VIP), BindClass::Virtual { port: 8086, bound_any: false });
        assert_eq!(classify_bind(VIP, 0, VIP), BindClass::Virtual { port: 0, bound_any: false });
        assert_eq!(classify_bind(VIP, 31337, VIP), BindClass::Virtual { port: 31337, bound_any: false });
        assert_eq!(classify_bind(any, 8086, VIP), BindClass::Virtual { port: 8086, bound_any: true });
        assert_eq!(classify_bind(any, 8101, VIP), BindClass::Virtual { port: 8101, bound_any: true });
        assert_eq!(classify_bind(any, 8085, VIP), BindClass::Real);
        assert_eq!(classify_bind(any, 8102, VIP), BindClass::Real);
        assert_eq!(classify_bind(any, 0, VIP), BindClass::Real);
        assert_eq!(classify_bind(Ipv4Addr::LOCALHOST, 8086, VIP), BindClass::Real);
        assert_eq!(classify_bind(Ipv4Addr::new(198, 18, 0, 6), 8086, VIP), BindClass::Real);
        assert_eq!(classify_bind(Ipv4Addr::new(192, 168, 1, 5), 8086, VIP), BindClass::Real);
    }

    #[test]
    fn port_probing_like_bfme() {
        // Two game instances in one process (or one probing): 8086 taken -> next.
        let mut t = Table::new();
        assert!(t.add_candidate(100) && t.add_candidate(200));
        assert_eq!(bind_virtual(&mut t, 100, 8086), BeginBind::Proceed { vport: 8086, bound_any: false });
        let first = t.get(100).unwrap();
        assert_eq!(bind_virtual(&mut t, 200, 8086), BeginBind::InUse(first));
        assert_eq!(t.get(200).unwrap().state, State::Candidate);
        assert_eq!(bind_virtual(&mut t, 200, 8087), BeginBind::Proceed { vport: 8087, bound_any: false });
        // ANY:8086 conflicts with VIP:8086 as well.
        assert!(t.add_candidate(300));
        let r = t.begin_bind(300, BindClass::Virtual { port: 8086, bound_any: true });
        assert_eq!(r, BeginBind::InUse(first));
        // Closing frees the vport.
        assert_eq!(t.remove(100).unwrap().vport, 8086);
        assert_eq!(
            t.begin_bind(300, BindClass::Virtual { port: 8086, bound_any: true }),
            BeginBind::Proceed { vport: 8086, bound_any: true }
        );
    }

    #[test]
    fn binding_reserves_and_abort_releases() {
        let mut t = Table::new();
        t.add_candidate(1);
        t.add_candidate(2);
        assert!(matches!(t.begin_bind(1, BindClass::Virtual { port: 8094, bound_any: true }), BeginBind::Proceed { .. }));
        assert!(matches!(t.begin_bind(2, BindClass::Virtual { port: 8094, bound_any: true }), BeginBind::InUse(_)));
        t.abort_bind(1);
        assert_eq!(t.get(1).unwrap().state, State::Candidate);
        assert!(matches!(t.begin_bind(2, BindClass::Virtual { port: 8094, bound_any: true }), BeginBind::Proceed { .. }));
        // Second bind on a virtual/binding socket is not ours to handle.
        assert_eq!(t.begin_bind(2, BindClass::Virtual { port: 8095, bound_any: true }), BeginBind::Untracked);
        assert!(t.commit_bind(2, 5555).is_some());
        assert_eq!(t.begin_bind(2, BindClass::Real), BeginBind::Untracked);
        assert_eq!(t.begin_bind(99, BindClass::Real), BeginBind::Untracked);
        assert!(t.commit_bind(2, 1).is_none(), "already virtual");
    }

    #[test]
    fn real_bind_drops_candidate() {
        let mut t = Table::new();
        t.add_candidate(7);
        assert_eq!(t.begin_bind(7, BindClass::Real), BeginBind::Real);
        assert!(t.get(7).is_none());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn ephemeral_allocation() {
        let mut t = Table::new();
        t.add_candidate(1);
        t.add_candidate(2);
        assert_eq!(bind_virtual(&mut t, 1, 0), BeginBind::Proceed { vport: EPHEMERAL_FIRST, bound_any: false });
        assert_eq!(bind_virtual(&mut t, 2, 0), BeginBind::Proceed { vport: EPHEMERAL_FIRST + 1, bound_any: false });
    }

    #[test]
    fn capacity_and_handle_reuse() {
        let mut t = Table::new();
        for s in 0..MAX_SOCKETS {
            assert!(t.add_candidate(1000 + s));
        }
        assert!(!t.add_candidate(5000), "full");
        // A handle that is already tracked (stale) is replaced, even when full.
        assert_eq!(bind_virtual(&mut t, 1000, 8086), BeginBind::Proceed { vport: 8086, bound_any: false });
        assert!(t.add_candidate(1000));
        assert_eq!(t.get(1000).unwrap().state, State::Candidate);
        assert_eq!(t.len(), MAX_SOCKETS);
        t.remove(1001);
        assert!(t.add_candidate(5000));
    }

    #[test]
    fn eviction_requires_unchanged_entry() {
        let mut t = Table::new();
        t.add_candidate(1);
        bind_virtual(&mut t, 1, 8086);
        let snapshot = t.get(1).unwrap();
        // Changed in between (close flag) -> not evicted.
        assert_eq!(t.take_close(1), Some(8086));
        assert!(!t.evict_if_unchanged(&snapshot));
        let now = t.get(1).unwrap();
        assert!(t.evict_if_unchanged(&now));
        assert!(t.get(1).is_none());
    }

    #[test]
    fn close_once_and_implicit_bind() {
        let mut t = Table::new();
        t.add_candidate(1);
        assert_eq!(t.take_close(1), None, "candidates send no CLOSE");
        bind_virtual(&mut t, 1, 8086);
        assert_eq!(t.take_close(1), Some(8086));
        assert_eq!(t.take_close(1), None);
        assert!(t.virtual_entry(1).unwrap().close_sent);
        t.add_candidate(2);
        t.implicit_bind(2);
        assert!(t.get(2).is_none());
        t.implicit_bind(1);
        assert!(t.get(1).is_some(), "virtual sockets stay");
    }
}
