//! The agent's table of virtual ports: `vport → loopback endpoint` of the hook's
//! socket, learned from `REG` and refreshed by every `SEND` (architecture §5).
//! Bounded; entries not refreshed for the expiry time are dropped (the hook sends no
//! `CLOSE` when the game exits without closing its sockets).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Most registrations (the hook's own table has 64 entries).
pub const MAX_REGISTRATIONS: usize = 64;

/// One registered virtual port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registration {
    /// The hook socket's loopback endpoint.
    pub endpoint: SocketAddr,
    /// Last `REG`/`SEND` from it.
    pub last_seen: Instant,
    /// The server confirmed the relay `REG` of the current session.
    pub acked: bool,
    /// When the relay `REG` was last sent.
    pub reg_sent: Option<Instant>,
}

/// What [`Registrations::learn`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Learned {
    /// A new vport.
    New,
    /// Known vport, new endpoint (a new socket took the port).
    Moved,
    /// Known vport and endpoint; refreshed.
    Refreshed,
    /// Ignored: vport 0 or table full.
    Rejected,
}

/// The table.
#[derive(Debug, Default)]
pub struct Registrations {
    map: BTreeMap<u16, Registration>,
}

impl Registrations {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Learns or refreshes `vport → endpoint`.
    pub fn learn(&mut self, vport: u16, endpoint: SocketAddr, now: Instant) -> Learned {
        if vport == 0 {
            return Learned::Rejected;
        }
        let full = self.map.len() >= MAX_REGISTRATIONS;
        match self.map.get_mut(&vport) {
            Some(r) if r.endpoint == endpoint => {
                r.last_seen = now;
                Learned::Refreshed
            }
            Some(r) => {
                *r = Registration {
                    endpoint,
                    last_seen: now,
                    acked: false,
                    reg_sent: None,
                };
                Learned::Moved
            }
            None if full => Learned::Rejected,
            None => {
                self.map.insert(
                    vport,
                    Registration {
                        endpoint,
                        last_seen: now,
                        acked: false,
                        reg_sent: None,
                    },
                );
                Learned::New
            }
        }
    }

    /// Removes `vport` if it is registered from `endpoint` (a late `CLOSE` of an old
    /// socket must not remove its successor). Returns `true` if removed.
    pub fn close(&mut self, vport: u16, endpoint: SocketAddr) -> bool {
        if self.map.get(&vport).is_some_and(|r| r.endpoint == endpoint) {
            self.map.remove(&vport);
            true
        } else {
            false
        }
    }

    /// The endpoint of `vport`.
    pub fn endpoint(&self, vport: u16) -> Option<SocketAddr> {
        self.map.get(&vport).map(|r| r.endpoint)
    }

    /// Drops entries older than `max_age`; returns their vports.
    pub fn expire(&mut self, now: Instant, max_age: Duration) -> Vec<u16> {
        let old: Vec<u16> = self
            .map
            .iter()
            .filter(|(_, r)| now.saturating_duration_since(r.last_seen) >= max_age)
            .map(|(&v, _)| v)
            .collect();
        for v in &old {
            self.map.remove(v);
        }
        old
    }

    /// Removes everything; returns the vports.
    pub fn clear(&mut self) -> Vec<u16> {
        std::mem::take(&mut self.map).into_keys().collect()
    }

    /// The server confirmed `vport`.
    pub fn ack(&mut self, vport: u16) {
        if let Some(r) = self.map.get_mut(&vport) {
            r.acked = true;
        }
    }

    /// Marks every entry unconfirmed (new session, server lost them).
    pub fn unack_all(&mut self) {
        for r in self.map.values_mut() {
            r.acked = false;
            r.reg_sent = None;
        }
    }

    /// Unconfirmed vports whose relay `REG` is due (never sent or older than
    /// `retry`).
    pub fn reg_due(&self, now: Instant, retry: Duration) -> Vec<u16> {
        self.map
            .iter()
            .filter(|(_, r)| {
                !r.acked && r.reg_sent.is_none_or(|t| now.saturating_duration_since(t) >= retry)
            })
            .map(|(&v, _)| v)
            .collect()
    }

    /// Records that a relay `REG` for `vport` was sent.
    pub fn reg_sent(&mut self, vport: u16, now: Instant) {
        if let Some(r) = self.map.get_mut(&vport) {
            r.reg_sent = Some(now);
        }
    }

    /// Iterates `(vport, registration)` in vport order.
    pub fn iter(&self) -> impl Iterator<Item = (u16, &Registration)> {
        self.map.iter().map(|(&v, r)| (v, r))
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn learn_refresh_move_close() {
        let t0 = Instant::now();
        let mut r = Registrations::new();
        assert_eq!(r.learn(0, ep(1), t0), Learned::Rejected);
        assert_eq!(r.learn(8086, ep(1000), t0), Learned::New);
        assert_eq!(r.learn(8086, ep(1000), t0), Learned::Refreshed);
        r.ack(8086);
        assert!(r.reg_due(t0, Duration::from_secs(1)).is_empty());
        assert_eq!(r.learn(8086, ep(1001), t0), Learned::Moved);
        assert_eq!(r.endpoint(8086), Some(ep(1001)));
        assert_eq!(r.reg_due(t0, Duration::from_secs(1)), [8086], "a moved port is re-registered");
        assert!(!r.close(8086, ep(1000)), "stale CLOSE ignored");
        assert!(r.close(8086, ep(1001)));
        assert!(r.is_empty());
    }

    #[test]
    fn expiry_and_bounds() {
        let t0 = Instant::now();
        let mut r = Registrations::new();
        r.learn(8086, ep(1), t0);
        r.learn(8094, ep(2), t0 + Duration::from_secs(30));
        assert!(r.expire(t0 + Duration::from_secs(59), Duration::from_secs(60)).is_empty());
        assert_eq!(r.expire(t0 + Duration::from_secs(60), Duration::from_secs(60)), [8086]);
        // A SEND refreshes the entry.
        r.learn(8094, ep(2), t0 + Duration::from_secs(80));
        assert!(r.expire(t0 + Duration::from_secs(100), Duration::from_secs(60)).is_empty());
        assert_eq!(r.clear(), [8094]);
        for p in 0..MAX_REGISTRATIONS as u16 {
            assert_eq!(r.learn(10_000 + p, ep(p), t0), Learned::New);
        }
        assert_eq!(r.learn(9, ep(9), t0), Learned::Rejected);
        assert_eq!(r.len(), MAX_REGISTRATIONS);
    }

    #[test]
    fn reg_retry_schedule() {
        let t0 = Instant::now();
        let mut r = Registrations::new();
        r.learn(8086, ep(1), t0);
        assert_eq!(r.reg_due(t0, Duration::from_secs(1)), [8086]);
        r.reg_sent(8086, t0);
        assert!(r.reg_due(t0 + Duration::from_millis(999), Duration::from_secs(1)).is_empty());
        assert_eq!(r.reg_due(t0 + Duration::from_secs(1), Duration::from_secs(1)), [8086]);
        r.ack(8086);
        r.unack_all();
        assert_eq!(r.reg_due(t0, Duration::from_secs(1)), [8086]);
    }
}
