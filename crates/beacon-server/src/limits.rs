//! Rate limiting and abuse protection: token buckets, the per-IP handshake guard
//! (connection limits, failed-handshake backoff) and the UDP pre-authentication
//! limiter. All tables are bounded.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Canonical form of a peer address for per-IP bookkeeping: IPv4-mapped IPv6
/// addresses (`::ffff:a.b.c.d`, seen on dual-stack sockets) become plain IPv4.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

/// Classic token bucket: `rate` tokens per second, at most `burst` tokens.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket. `burst` is at least 1.
    pub fn new(rate_per_sec: f64, burst: f64, now: Instant) -> Self {
        let burst = if burst.is_finite() { burst.max(1.0) } else { 1.0 };
        let rate = if rate_per_sec.is_finite() { rate_per_sec.max(0.0) } else { 0.0 };
        Self {
            rate,
            burst,
            tokens: burst,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if now > self.last {
            self.last = now;
        }
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
    }

    /// Takes one token if available.
    pub fn try_take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// `true` if at least one token is available (nothing is taken).
    pub fn has_token(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= 1.0
    }

    /// Takes one token even if that drives the bucket negative (bounded at
    /// `-burst`), so that repeated failures keep an offender blocked longer.
    pub fn charge(&mut self, now: Instant) {
        self.refill(now);
        self.tokens = (self.tokens - 1.0).max(-self.burst);
    }

    /// `true` if the bucket is full again (the entry can be forgotten).
    pub fn is_full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= self.burst
    }
}

/// Settings of the [`HandshakeGuard`].
#[derive(Debug, Clone)]
pub struct GuardConfig {
    /// Failed handshakes (within `forget_after` of each other) that trigger a ban.
    pub max_failures: u32,
    /// Length of the first ban; every further ban doubles it.
    pub ban: Duration,
    /// Upper bound of a ban.
    pub max_ban: Duration,
    /// Failures and ban escalation older than this are forgotten.
    pub forget_after: Duration,
    /// Concurrent connections per IP (players behind one NAT share an IP).
    pub max_conns_per_ip: u32,
    /// Concurrent unfinished handshakes per IP.
    pub max_pending_per_ip: u32,
    /// Concurrent unfinished handshakes in total.
    pub max_pending_total: usize,
    /// Size bound of the per-IP table.
    pub max_entries: usize,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            max_failures: 5,
            ban: Duration::from_secs(60),
            max_ban: Duration::from_secs(15 * 60),
            forget_after: Duration::from_secs(10 * 60),
            max_conns_per_ip: 16,
            max_pending_per_ip: 8,
            max_pending_total: 64,
            max_entries: 4096,
        }
    }
}

/// Why a connection was refused before the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// The IP failed too many handshakes; try again after `remaining`.
    Banned {
        /// Time left on the ban.
        remaining: Duration,
    },
    /// The IP has too many open connections.
    TooManyConnections,
    /// The IP has too many unfinished handshakes.
    TooManyPending,
    /// Too many unfinished handshakes overall.
    Busy,
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Banned { remaining } => write!(f, "banned for {} s", remaining.as_secs()),
            Self::TooManyConnections => f.write_str("too many connections from this IP"),
            Self::TooManyPending => f.write_str("too many pending handshakes from this IP"),
            Self::Busy => f.write_str("too many pending handshakes"),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct IpEntry {
    conns: u32,
    pending: u32,
    failures: u32,
    last_failure: Option<Instant>,
    banned_until: Option<Instant>,
    ban_level: u32,
}

impl IpEntry {
    fn is_idle(&self, now: Instant, forget_after: Duration) -> bool {
        self.conns == 0
            && self.pending == 0
            && self.banned_until.is_none_or(|t| t <= now)
            && self
                .last_failure
                .is_none_or(|t| now.saturating_duration_since(t) >= forget_after)
    }
}

/// Per-IP admission control for the TCP control port: connection limits and an
/// exponential ban after repeated failed handshakes (wrong password, garbage,
/// timeouts). Bounded: idle entries are evicted first, then the least recently
/// failed idle entry.
#[derive(Debug)]
pub struct HandshakeGuard {
    cfg: GuardConfig,
    entries: HashMap<IpAddr, IpEntry>,
    pending_total: usize,
    failures_total: u64,
    bans_total: u64,
}

impl HandshakeGuard {
    /// An empty guard.
    pub fn new(cfg: GuardConfig) -> Self {
        Self {
            cfg,
            entries: HashMap::new(),
            pending_total: 0,
            failures_total: 0,
            bans_total: 0,
        }
    }

    /// Admits a new connection from `ip` (counts it as connected and pending).
    pub fn admit(&mut self, ip: IpAddr, now: Instant) -> Result<(), Denied> {
        if !self.entries.contains_key(&ip) {
            self.make_room(now);
        }
        let pending_total = self.pending_total;
        let entry = self.entries.entry(ip).or_default();
        if let Some(until) = entry.banned_until {
            if until > now {
                return Err(Denied::Banned {
                    remaining: until.saturating_duration_since(now),
                });
            }
            entry.banned_until = None;
        }
        if entry.conns >= self.cfg.max_conns_per_ip {
            return Err(Denied::TooManyConnections);
        }
        if entry.pending >= self.cfg.max_pending_per_ip {
            return Err(Denied::TooManyPending);
        }
        if pending_total >= self.cfg.max_pending_total {
            return Err(Denied::Busy);
        }
        entry.conns = entry.conns.saturating_add(1);
        entry.pending = entry.pending.saturating_add(1);
        self.pending_total = self.pending_total.saturating_add(1);
        Ok(())
    }

    /// Records the outcome of a handshake admitted with [`admit`](Self::admit).
    /// Returns the ban length if this failure triggered a ban.
    pub fn handshake_done(&mut self, ip: IpAddr, ok: bool, now: Instant) -> Option<Duration> {
        let cfg = &self.cfg;
        let entry = self.entries.get_mut(&ip)?;
        if entry.pending > 0 {
            entry.pending -= 1;
            self.pending_total = self.pending_total.saturating_sub(1);
        }
        if ok {
            entry.failures = 0;
            entry.ban_level = 0;
            return None;
        }
        self.failures_total = self.failures_total.saturating_add(1);
        if entry
            .last_failure
            .is_some_and(|t| now.saturating_duration_since(t) >= cfg.forget_after)
        {
            entry.failures = 0;
            entry.ban_level = 0;
        }
        entry.failures = entry.failures.saturating_add(1);
        entry.last_failure = Some(now);
        if entry.failures < cfg.max_failures.max(1) {
            return None;
        }
        let factor = 1u32.checked_shl(entry.ban_level.min(16)).unwrap_or(u32::MAX);
        let ban = cfg.ban.saturating_mul(factor).min(cfg.max_ban);
        entry.banned_until = Some(now + ban);
        entry.ban_level = entry.ban_level.saturating_add(1);
        entry.failures = 0;
        self.bans_total = self.bans_total.saturating_add(1);
        Some(ban)
    }

    /// Records that a connection admitted with [`admit`](Self::admit) closed;
    /// `still_pending` if it never reported a handshake outcome.
    pub fn disconnected(&mut self, ip: IpAddr, still_pending: bool, now: Instant) {
        let forget_after = self.cfg.forget_after;
        let Some(entry) = self.entries.get_mut(&ip) else {
            return;
        };
        entry.conns = entry.conns.saturating_sub(1);
        if still_pending && entry.pending > 0 {
            entry.pending -= 1;
            self.pending_total = self.pending_total.saturating_sub(1);
        }
        if entry.is_idle(now, forget_after) && entry.ban_level == 0 {
            self.entries.remove(&ip);
        }
    }

    /// Number of IPs currently banned.
    pub fn banned(&self, now: Instant) -> usize {
        self.entries
            .values()
            .filter(|e| e.banned_until.is_some_and(|t| t > now))
            .count()
    }

    /// Failed handshakes since start.
    pub fn failures_total(&self) -> u64 {
        self.failures_total
    }

    /// Bans since start.
    pub fn bans_total(&self) -> u64 {
        self.bans_total
    }

    /// Number of tracked IPs.
    pub fn tracked(&self) -> usize {
        self.entries.len()
    }

    fn make_room(&mut self, now: Instant) {
        if self.entries.len() < self.cfg.max_entries {
            return;
        }
        let forget_after = self.cfg.forget_after;
        self.entries.retain(|_, e| !e.is_idle(now, forget_after));
        if self.entries.len() < self.cfg.max_entries {
            return;
        }
        // Still full: drop the idle (no connection) entry that failed longest ago.
        let victim = self
            .entries
            .iter()
            .filter(|(_, e)| e.conns == 0 && e.pending == 0)
            .min_by_key(|(_, e)| e.last_failure)
            .map(|(ip, _)| *ip);
        if let Some(ip) = victim {
            self.entries.remove(&ip);
        }
    }
}

/// Per-source-IP budget for UDP datagrams that fail before authentication
/// (malformed, unknown session, bad tag). An IP whose budget is exhausted is
/// ignored without parsing until it recovers. Bounded table.
#[derive(Debug)]
pub struct PreAuthLimiter {
    rate: f64,
    burst: f64,
    max_entries: usize,
    buckets: HashMap<IpAddr, TokenBucket>,
}

impl PreAuthLimiter {
    /// `rate` failures per second with bursts of `burst` per IP.
    pub fn new(rate: f64, burst: f64, max_entries: usize) -> Self {
        Self {
            rate,
            burst,
            max_entries: max_entries.max(1),
            buckets: HashMap::new(),
        }
    }

    /// `false` if datagrams from `ip` should be dropped unparsed.
    pub fn allowed(&mut self, ip: IpAddr, now: Instant) -> bool {
        match self.buckets.get_mut(&ip) {
            Some(bucket) => bucket.has_token(now),
            None => true,
        }
    }

    /// Charges one failure to `ip`.
    pub fn record_failure(&mut self, ip: IpAddr, now: Instant) {
        if !self.buckets.contains_key(&ip) && self.buckets.len() >= self.max_entries {
            self.prune(now);
            if self.buckets.len() >= self.max_entries {
                // A flood from many sources: forget everybody rather than grow.
                self.buckets.clear();
            }
        }
        let (rate, burst) = (self.rate, self.burst);
        self.buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(rate, burst, now))
            .charge(now);
    }

    /// Forgets IPs whose budget has fully recovered.
    pub fn prune(&mut self, now: Instant) {
        self.buckets.retain(|_, b| !b.is_full(now));
    }

    /// Number of IPs currently tracked.
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }

    /// Number of IPs currently blocked.
    pub fn blocked(&mut self, now: Instant) -> usize {
        self.buckets
            .values_mut()
            .map(|b| b.has_token(now))
            .filter(|has| !has)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn bucket_refills_and_caps() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(10.0, 3.0, t0);
        assert!(b.try_take(t0));
        assert!(b.try_take(t0));
        assert!(b.try_take(t0));
        assert!(!b.try_take(t0));
        // 100 ms at 10/s = one token.
        assert!(b.try_take(t0 + Duration::from_millis(100)));
        assert!(!b.try_take(t0 + Duration::from_millis(100)));
        // Long pause: capped at burst.
        let later = t0 + Duration::from_secs(60);
        assert!(b.is_full(later));
        for _ in 0..3 {
            assert!(b.try_take(later));
        }
        assert!(!b.try_take(later));
        // Time going backwards does not add tokens.
        assert!(!b.try_take(t0));
    }

    #[test]
    fn bucket_charge_goes_negative() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(1.0, 2.0, t0);
        for _ in 0..10 {
            b.charge(t0);
        }
        // Bounded at -burst: needs 3 s to reach one token again.
        assert!(!b.has_token(t0 + Duration::from_millis(2900)));
        assert!(b.has_token(t0 + Duration::from_millis(3050)));
    }

    #[test]
    fn bucket_handles_silly_values() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(f64::NAN, f64::INFINITY, t0);
        assert!(b.try_take(t0));
        assert!(!b.try_take(t0 + Duration::from_secs(100)));
    }

    #[test]
    fn guard_bans_after_failures_and_escalates() {
        let cfg = GuardConfig {
            max_failures: 3,
            ban: Duration::from_secs(10),
            max_ban: Duration::from_secs(25),
            ..GuardConfig::default()
        };
        let mut g = HandshakeGuard::new(cfg);
        let t0 = Instant::now();
        for i in 0..3 {
            g.admit(ip(1), t0).unwrap();
            let ban = g.handshake_done(ip(1), false, t0);
            g.disconnected(ip(1), false, t0);
            assert_eq!(ban.is_some(), i == 2);
        }
        assert!(matches!(g.admit(ip(1), t0), Err(Denied::Banned { .. })));
        // Other IPs are unaffected.
        assert!(g.admit(ip(2), t0).is_ok());
        assert_eq!(g.banned(t0), 1);
        // After the ban the next round bans for twice as long (capped at 25 s).
        let t1 = t0 + Duration::from_secs(11);
        for _ in 0..3 {
            g.admit(ip(1), t1).unwrap();
            g.handshake_done(ip(1), false, t1);
            g.disconnected(ip(1), false, t1);
        }
        assert!(g.admit(ip(1), t1 + Duration::from_secs(19)).is_err());
        let t2 = t1 + Duration::from_secs(21);
        g.admit(ip(1), t2).unwrap();
        // Success resets the failure count.
        assert_eq!(g.handshake_done(ip(1), true, t2), None);
        g.disconnected(ip(1), false, t2);
        assert_eq!(g.failures_total(), 6);
        assert_eq!(g.bans_total(), 2);
    }

    #[test]
    fn guard_limits_connections_and_pending() {
        let cfg = GuardConfig {
            max_conns_per_ip: 3,
            max_pending_per_ip: 2,
            max_pending_total: 3,
            ..GuardConfig::default()
        };
        let mut g = HandshakeGuard::new(cfg);
        let t = Instant::now();
        g.admit(ip(1), t).unwrap();
        g.admit(ip(1), t).unwrap();
        assert_eq!(g.admit(ip(1), t), Err(Denied::TooManyPending));
        g.handshake_done(ip(1), true, t);
        g.admit(ip(1), t).unwrap();
        assert_eq!(g.admit(ip(1), t), Err(Denied::TooManyConnections));
        g.admit(ip(2), t).unwrap();
        assert_eq!(g.admit(ip(3), t), Err(Denied::Busy));
        // A connection dropped mid-handshake releases its pending slot.
        g.disconnected(ip(2), true, t);
        g.admit(ip(3), t).unwrap();
    }

    #[test]
    fn guard_table_is_bounded() {
        let cfg = GuardConfig {
            max_entries: 4,
            max_failures: 100,
            ..GuardConfig::default()
        };
        let mut g = HandshakeGuard::new(cfg);
        let t = Instant::now();
        for n in 0..50u8 {
            g.admit(ip(n), t).unwrap();
            g.handshake_done(ip(n), false, t);
            g.disconnected(ip(n), false, t);
            assert!(g.tracked() <= 4);
        }
    }

    #[test]
    fn preauth_blocks_and_recovers() {
        let mut l = PreAuthLimiter::new(10.0, 5.0, 2);
        let t = Instant::now();
        assert!(l.allowed(ip(1), t));
        for _ in 0..5 {
            l.record_failure(ip(1), t);
        }
        assert!(!l.allowed(ip(1), t));
        assert!(l.allowed(ip(2), t));
        assert_eq!(l.blocked(t), 1);
        assert!(l.allowed(ip(1), t + Duration::from_millis(150)));
        // Bounded table.
        l.record_failure(ip(2), t);
        l.record_failure(ip(3), t);
        assert!(l.tracked() <= 2);
        l.prune(t + Duration::from_secs(10));
        assert_eq!(l.tracked(), 0);
    }

    #[test]
    fn canonical_maps_v4_in_v6() {
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(canonical_ip(mapped), "192.0.2.1".parse::<IpAddr>().unwrap());
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(canonical_ip(v6), v6);
    }
}
