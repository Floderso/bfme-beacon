//! UDP relay (architecture §6): one socket, one task owning every session.
//!
//! Per session: key, vIP, receive [`ReplayWindow`], [`SendCounter`], registered
//! virtual ports, the last authenticated endpoint (updated only after a valid tag,
//! which makes NAT rebinding work), a token bucket and statistics.
//!
//! Forwarding of an authenticated DATA packet: unicast to the owner of the
//! destination vIP if it registered the destination vport; broadcast
//! (`255.255.255.255`, `198.18.0.255`) to every *other* session that registered
//! it; never back to the sender; anything else is dropped and counted (no
//! ICMP-like errors, spec 02 A8). Each forwarded packet is sealed once per
//! receiver and sent [`RedundancyConfig::for_port`] times (identical bytes, copies
//! after [`REDUNDANCY_DELAYS`]); the receiver's replay window drops the copies.
//!
//! Every datagram that fails before authentication (malformed, unknown session,
//! bad tag) is charged to its source IP; datagrams from an IP over budget are
//! ignored, except from the endpoint a session last authenticated from.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use beacon_proto::net::{self, SERVER_VIP};
use beacon_proto::relay::{
    self as wire, error_code, Direction, Header, PacketType, RelayKey, ReplayWindow, SendCounter,
    MAX_PACKET_LEN, MAX_REDUNDANCY, REDUNDANCY_DELAYS,
};
use serde::Serialize;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, MissedTickBehavior};
use tracing::{debug, info, warn};

use crate::config::RedundancyConfig;
use crate::limits::{canonical_ip, PreAuthLimiter, TokenBucket};

/// Maximum number of virtual ports one session may register.
pub const MAX_VPORTS_PER_SESSION: usize = 32;
/// Maximum number of redundant copies waiting to be sent.
pub const MAX_PENDING_COPIES: usize = 16_384;
/// Capacity of the command channel.
pub const CMD_QUEUE_LEN: usize = 1024;
// Any UDP datagram fits, so oversize junk is read whole and rejected by length
// (Windows would report a truncated datagram as an error).
const RECV_BUF_LEN: usize = 65_536;
const ERROR_INTERVAL: Duration = Duration::from_secs(1);
const STATS_INTERVAL: Duration = Duration::from_secs(1);
const SEND_STALL: Duration = Duration::from_millis(2);
const PREAUTH_TABLE: usize = 4096;
const LOSS_MIN_SAMPLE: u64 = 10;
const SOCKET_BUFFER: usize = 4 << 20;

/// Relay limits and redundancy.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Copies per port class.
    pub redundancy: RedundancyConfig,
    /// Packets per second per session.
    pub session_pps: u32,
    /// Burst per session.
    pub session_burst: u32,
    /// Pre-authentication failures per second per source IP.
    pub preauth_pps: u32,
    /// Pre-authentication burst per source IP.
    pub preauth_burst: u32,
}

/// Commands from the control side.
#[derive(Debug)]
pub enum RelayCmd {
    /// Create a session; `ack` fires once it can receive packets.
    Add {
        /// Session id (relay header).
        session: u32,
        /// Session key.
        key: RelayKey,
        /// The player's vIP.
        vip: Ipv4Addr,
        /// Completion signal.
        ack: oneshot::Sender<()>,
    },
    /// Remove a session (sends BYE to its endpoint).
    Remove {
        /// Session id.
        session: u32,
    },
}

/// Handle for the control side.
#[derive(Debug, Clone)]
pub struct RelayHandle {
    tx: mpsc::Sender<RelayCmd>,
}

impl RelayHandle {
    /// Creates a session and waits until the relay knows it. `false` if the relay
    /// has stopped.
    pub async fn add(&self, session: u32, key: RelayKey, vip: Ipv4Addr) -> bool {
        let (ack, done) = oneshot::channel();
        if self
            .tx
            .send(RelayCmd::Add {
                session,
                key,
                vip,
                ack,
            })
            .await
            .is_err()
        {
            return false;
        }
        done.await.is_ok()
    }

    /// Removes a session without waiting (usable from `Drop`).
    pub fn remove(&self, session: u32) {
        match self.tx.try_send(RelayCmd::Remove { session }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(cmd)) => {
                if let Ok(rt) = tokio::runtime::Handle::try_current() {
                    let tx = self.tx.clone();
                    rt.spawn(async move {
                        let _ = tx.send(cmd).await;
                    });
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

/// Statistics of one session (also part of `/status`).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SessionStats {
    /// Last authenticated endpoint.
    pub endpoint: Option<String>,
    /// Registered virtual ports.
    pub vports: Vec<u16>,
    /// Authenticated packets received.
    pub rx_pkts: u64,
    /// Bytes of authenticated packets received.
    pub rx_bytes: u64,
    /// Packets sent to this session (first copies).
    pub tx_pkts: u64,
    /// Bytes sent to this session (first copies).
    pub tx_bytes: u64,
    /// DATA packets from this session that were forwarded.
    pub forwarded: u64,
    /// Redundant copies and replays dropped by the replay window.
    pub duplicates: u64,
    /// Packets dropped by the rate limit.
    pub rate_limited: u64,
    /// DATA packets without a receiver.
    pub no_route: u64,
    /// Packets dropped otherwise (bad payload, vport table full, …).
    pub dropped: u64,
    /// Server-measured loss on the agent → server path (counter gaps), percent.
    pub upstream_loss_pct: Option<u8>,
    /// Milliseconds since the last authenticated packet.
    pub last_rx_ms_ago: Option<u64>,
}

/// Relay-wide counters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RelayTotals {
    /// Datagrams received.
    pub rx_datagrams: u64,
    /// Bytes received.
    pub rx_bytes: u64,
    /// Datagrams sent (including redundant copies).
    pub tx_datagrams: u64,
    /// Bytes sent.
    pub tx_bytes: u64,
    /// Redundant copies sent.
    pub copies_sent: u64,
    /// Redundant copies skipped (queue full or send failure).
    pub copies_skipped: u64,
    /// Malformed datagrams (length, magic, version, type, payload).
    pub malformed: u64,
    /// Datagrams naming an unknown session.
    pub unknown_session: u64,
    /// Datagrams with an invalid tag (wrong key, forged, modified).
    pub auth_failed: u64,
    /// Duplicates/replays dropped.
    pub duplicates: u64,
    /// Datagrams ignored because their source IP exceeded the failure budget.
    pub preauth_dropped: u64,
    /// DATA packets without a receiver.
    pub no_route: u64,
    /// Packets dropped by per-session rate limits.
    pub rate_limited: u64,
    /// Send errors.
    pub send_errors: u64,
    /// Receive errors (e.g. ICMP reports on Windows).
    pub recv_errors: u64,
}

/// A snapshot published once per second.
#[derive(Debug, Clone, Default)]
pub struct RelayStats {
    /// Per session id.
    pub sessions: HashMap<u32, SessionStats>,
    /// Totals.
    pub totals: RelayTotals,
    /// Source IPs currently ignored.
    pub blocked_ips: usize,
    /// When this snapshot was taken.
    pub taken_at: Option<Instant>,
}

/// Loss estimate from gaps in the received counters (the agent's counter grows by
/// one per distinct packet; redundant copies share a counter).
#[derive(Debug, Default, Clone)]
pub struct LossEstimator {
    first: Option<u64>,
    highest: u64,
    received: u64,
    last_expected: u64,
    last_received: u64,
    ewma: Option<f64>,
}

impl LossEstimator {
    /// Records an accepted (authenticated, non-duplicate) counter.
    pub fn observe(&mut self, counter: u64) {
        match self.first {
            None => {
                self.first = Some(counter);
                self.highest = counter;
            }
            Some(first) => {
                self.first = Some(first.min(counter));
                self.highest = self.highest.max(counter);
            }
        }
        self.received = self.received.saturating_add(1);
    }

    /// Folds the packets since the last update into the estimate once at least
    /// 10 packets were expected.
    pub fn update(&mut self) {
        let Some(first) = self.first else {
            return;
        };
        let expected = self.highest.saturating_sub(first).saturating_add(1);
        let interval_expected = expected.saturating_sub(self.last_expected);
        if interval_expected < LOSS_MIN_SAMPLE {
            return;
        }
        let interval_received = self.received.saturating_sub(self.last_received);
        let lost = interval_expected.saturating_sub(interval_received);
        // Precision loss in u64→f64 is irrelevant for a percentage.
        let sample = lost as f64 / interval_expected as f64;
        self.ewma = Some(match self.ewma {
            None => sample,
            Some(prev) => prev * 0.7 + sample * 0.3,
        });
        self.last_expected = expected;
        self.last_received = self.received;
    }

    /// The smoothed loss in percent.
    pub fn percent(&self) -> Option<u8> {
        self.ewma
            .map(|l| (l * 100.0).round().clamp(0.0, 100.0) as u8)
    }
}

struct Session {
    key: RelayKey,
    vip: Ipv4Addr,
    window: ReplayWindow,
    send: SendCounter,
    vports: Vec<u16>,
    endpoint: Option<SocketAddr>,
    bucket: TokenBucket,
    loss: LossEstimator,
    stats: SessionStats,
    last_rx: Option<Instant>,
    last_error: Option<Instant>,
}

impl Session {
    fn has_vport(&self, vport: u16) -> bool {
        self.vports.contains(&vport)
    }

    /// Registers `vport`; `false` if the table is full.
    fn register(&mut self, vport: u16) -> bool {
        if self.has_vport(vport) {
            return true;
        }
        if self.vports.len() >= MAX_VPORTS_PER_SESSION {
            return false;
        }
        self.vports.push(vport);
        self.vports.sort_unstable();
        true
    }

    fn error_due(&mut self, now: Instant) -> bool {
        let due = self
            .last_error
            .is_none_or(|t| now.saturating_duration_since(t) >= ERROR_INTERVAL);
        if due {
            self.last_error = Some(now);
        }
        due
    }

    /// Seals a server→agent packet into `out`.
    fn seal(
        &self,
        kind: PacketType,
        src_vip: Ipv4Addr,
        src_vport: u16,
        dst_vport: u16,
        payload: &[u8],
        out: &mut [u8; MAX_PACKET_LEN],
    ) -> Option<usize> {
        let counter = self.send.next()?;
        let header = Header::server(kind, counter, src_vip, src_vport, dst_vport);
        wire::seal(&self.key, Direction::ServerToClient, &header, payload, out).ok()
    }
}

struct PendingCopy {
    due: Instant,
    dst: SocketAddr,
    packet: Arc<[u8]>,
}

/// One FIFO per redundancy delay (each FIFO is ordered by due time).
struct CopyQueues {
    queues: Vec<(Duration, VecDeque<PendingCopy>)>,
    len: usize,
}

impl CopyQueues {
    fn new() -> Self {
        Self {
            queues: REDUNDANCY_DELAYS
                .iter()
                .map(|d| (*d, VecDeque::new()))
                .collect(),
            len: 0,
        }
    }

    /// Schedules `extra` copies of `packet` (at most one per delay).
    fn schedule(&mut self, now: Instant, dst: SocketAddr, packet: &[u8], extra: u8, totals: &mut RelayTotals) {
        if extra == 0 {
            return;
        }
        let shared: Arc<[u8]> = Arc::from(packet);
        for (delay, queue) in self.queues.iter_mut().take(usize::from(extra)) {
            if self.len >= MAX_PENDING_COPIES {
                totals.copies_skipped = totals.copies_skipped.saturating_add(1);
                continue;
            }
            queue.push_back(PendingCopy {
                due: now + *delay,
                dst,
                packet: Arc::clone(&shared),
            });
            self.len += 1;
        }
    }

    fn next_due(&self) -> Option<Instant> {
        self.queues
            .iter()
            .filter_map(|(_, q)| q.front().map(|c| c.due))
            .min()
    }

    /// Sends every copy that is due (non-blocking; a full socket buffer drops it).
    fn flush(&mut self, now: Instant, socket: &UdpSocket, totals: &mut RelayTotals) {
        for (_, queue) in &mut self.queues {
            while queue.front().is_some_and(|c| c.due <= now) {
                let Some(copy) = queue.pop_front() else {
                    break;
                };
                self.len = self.len.saturating_sub(1);
                match socket.try_send_to(&copy.packet, copy.dst) {
                    Ok(n) => {
                        totals.tx_datagrams = totals.tx_datagrams.saturating_add(1);
                        totals.tx_bytes = totals.tx_bytes.saturating_add(n as u64);
                        totals.copies_sent = totals.copies_sent.saturating_add(1);
                    }
                    Err(_) => totals.copies_skipped = totals.copies_skipped.saturating_add(1),
                }
            }
        }
    }
}

/// Sends one datagram; waits at most a few ms for socket buffer space.
async fn send_datagram(socket: &UdpSocket, totals: &mut RelayTotals, bytes: &[u8], dst: SocketAddr) -> bool {
    let result = match socket.try_send_to(bytes, dst) {
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            match tokio::time::timeout(SEND_STALL, socket.send_to(bytes, dst)).await {
                Ok(r) => r,
                Err(_) => Err(io::ErrorKind::WouldBlock.into()),
            }
        }
        other => other,
    };
    match result {
        Ok(n) => {
            totals.tx_datagrams = totals.tx_datagrams.saturating_add(1);
            totals.tx_bytes = totals.tx_bytes.saturating_add(n as u64);
            true
        }
        Err(e) => {
            totals.send_errors = totals.send_errors.saturating_add(1);
            debug!(%dst, "relay send failed: {e}");
            false
        }
    }
}

/// Creates a UDP socket for the relay with large buffers (best effort) and, for
/// an unspecified IPv6 address, dual-stack enabled.
pub fn bind_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    let _ = socket.set_recv_buffer_size(SOCKET_BUFFER);
    let _ = socket.set_send_buffer_size(SOCKET_BUFFER);
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

/// Creates the relay on `socket`; the returned future is the relay task (the
/// caller spawns and supervises it).
pub fn start(
    socket: UdpSocket,
    cfg: RelayConfig,
    shutdown: watch::Receiver<bool>,
) -> (
    RelayHandle,
    watch::Receiver<Arc<RelayStats>>,
    impl Future<Output = ()> + Send + 'static,
) {
    let (tx, rx) = mpsc::channel(CMD_QUEUE_LEN);
    let (stats_tx, stats_rx) = watch::channel(Arc::new(RelayStats {
        taken_at: Some(Instant::now()),
        ..RelayStats::default()
    }));
    let relay = Relay {
        preauth: PreAuthLimiter::new(
            f64::from(cfg.preauth_pps),
            f64::from(cfg.preauth_burst),
            PREAUTH_TABLE,
        ),
        socket,
        cfg,
        sessions: HashMap::new(),
        by_vip: HashMap::new(),
        copies: CopyQueues::new(),
        totals: RelayTotals::default(),
        targets: Vec::new(),
        stats_tx,
    };
    (RelayHandle { tx }, stats_rx, relay.run(rx, shutdown))
}

struct Relay {
    socket: UdpSocket,
    cfg: RelayConfig,
    sessions: HashMap<u32, Session>,
    by_vip: HashMap<Ipv4Addr, u32>,
    copies: CopyQueues,
    preauth: PreAuthLimiter,
    totals: RelayTotals,
    targets: Vec<(SocketAddr, u32)>,
    stats_tx: watch::Sender<Arc<RelayStats>>,
}

impl Relay {
    async fn run(mut self, mut cmds: mpsc::Receiver<RelayCmd>, mut shutdown: watch::Receiver<bool>) {
        if let Ok(addr) = self.socket.local_addr() {
            info!(%addr, "relay listening (UDP)");
        }
        let mut buf = vec![0u8; RECV_BUF_LEN];
        let mut consecutive_errors = 0u32;
        let mut tick = tokio::time::interval(STATS_INTERVAL);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let sleep = tokio::time::sleep(Duration::from_secs(3600));
        tokio::pin!(sleep);
        loop {
            let next_due = self.copies.next_due();
            if let Some(due) = next_due {
                if sleep.deadline() != due {
                    sleep.as_mut().reset(due);
                }
            }
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                cmd = cmds.recv() => match cmd {
                    Some(cmd) => self.handle_cmd(cmd),
                    None => break,
                },
                () = &mut sleep, if next_due.is_some() => {
                    self.copies.flush(Instant::now(), &self.socket, &mut self.totals);
                }
                // Before the socket: with `biased` a busy socket must not starve it.
                _ = tick.tick() => self.publish_stats(Instant::now()),
                res = self.socket.recv_from(&mut buf) => match res {
                    Ok((len, src)) => {
                        consecutive_errors = 0;
                        let now = Instant::now();
                        if let Some(packet) = buf.get_mut(..len) {
                            self.handle_datagram(packet, src, now).await;
                        }
                        self.copies.flush(now, &self.socket, &mut self.totals);
                    }
                    Err(e) => {
                        // Windows reports ICMP "port unreachable" for an earlier
                        // send as a receive error (WSAECONNRESET); harmless.
                        self.totals.recv_errors = self.totals.recv_errors.saturating_add(1);
                        consecutive_errors = consecutive_errors.saturating_add(1);
                        if e.kind() != io::ErrorKind::ConnectionReset {
                            debug!("relay receive error: {e}");
                        }
                        if consecutive_errors > 1000 {
                            // A persistently failing socket must not spin the CPU.
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    }
                },
            }
        }
        self.say_goodbye();
        debug!("relay stopped");
    }

    fn handle_cmd(&mut self, cmd: RelayCmd) {
        match cmd {
            RelayCmd::Add {
                session,
                key,
                vip,
                ack,
            } => {
                let now = Instant::now();
                if let Some(old) = self.by_vip.insert(vip, session) {
                    if old != session {
                        warn!("relay: vIP {vip} moved from session {old:08x} to {session:08x}");
                    }
                }
                self.sessions.insert(
                    session,
                    Session {
                        key,
                        vip,
                        window: ReplayWindow::new(),
                        send: SendCounter::new(),
                        vports: Vec::new(),
                        endpoint: None,
                        bucket: TokenBucket::new(
                            f64::from(self.cfg.session_pps),
                            f64::from(self.cfg.session_burst),
                            now.into_std(),
                        ),
                        loss: LossEstimator::default(),
                        stats: SessionStats::default(),
                        last_rx: None,
                        last_error: None,
                    },
                );
                let _ = ack.send(());
            }
            RelayCmd::Remove { session } => {
                if let Some(s) = self.sessions.remove(&session) {
                    if self.by_vip.get(&s.vip) == Some(&session) {
                        self.by_vip.remove(&s.vip);
                    }
                    if let Some(endpoint) = s.endpoint {
                        let mut out = [0u8; MAX_PACKET_LEN];
                        if let Some(n) = s.seal(PacketType::Bye, SERVER_VIP, 0, 0, &[], &mut out) {
                            if let Some(bytes) = out.get(..n) {
                                let _ = self.socket.try_send_to(bytes, endpoint);
                            }
                        }
                    }
                }
            }
        }
    }

    fn reject(&mut self, src: SocketAddr, now: Instant, counter: fn(&mut RelayTotals) -> &mut u64) {
        let c = counter(&mut self.totals);
        *c = c.saturating_add(1);
        self.preauth.record_failure(canonical_ip(src.ip()), now.into_std());
    }

    async fn handle_datagram(&mut self, packet: &mut [u8], src: SocketAddr, now: Instant) {
        let len = packet.len() as u64;
        self.totals.rx_datagrams = self.totals.rx_datagrams.saturating_add(1);
        self.totals.rx_bytes = self.totals.rx_bytes.saturating_add(len);
        // Parsing the 24-byte header is as cheap as the budget lookup. A datagram
        // from the endpoint a session last authenticated from is never dropped by
        // the per-IP budget: junk with a spoofed source IP, or a stale agent behind
        // the same NAT, must not black-hole a player's game traffic. Its tag is
        // still checked below; failures are still charged.
        let peeked = wire::peek_header(packet);
        let known_endpoint = peeked.as_ref().is_ok_and(|h| {
            self.sessions
                .get(&h.session)
                .is_some_and(|s| s.endpoint == Some(src))
        });
        if !known_endpoint && !self.preauth.allowed(canonical_ip(src.ip()), now.into_std()) {
            self.totals.preauth_dropped = self.totals.preauth_dropped.saturating_add(1);
            return;
        }
        let Ok(header) = peeked else {
            self.reject(src, now, |t| &mut t.malformed);
            return;
        };
        if !matches!(
            header.kind,
            PacketType::Reg | PacketType::Data | PacketType::Ping | PacketType::Bye | PacketType::Unreg
        ) {
            self.reject(src, now, |t| &mut t.malformed);
            return;
        }
        let Some(sess) = self.sessions.get_mut(&header.session) else {
            self.reject(src, now, |t| &mut t.unknown_session);
            return;
        };
        let range = match wire::open_with_window(&sess.key, Direction::ClientToServer, packet, &mut sess.window) {
            Ok((_, range)) => range,
            Err(wire::Error::Replayed { .. } | wire::Error::TooOld { .. }) => {
                // Redundant copies land here; normal, not a failure.
                sess.stats.duplicates = sess.stats.duplicates.saturating_add(1);
                self.totals.duplicates = self.totals.duplicates.saturating_add(1);
                return;
            }
            Err(wire::Error::AuthFailed) => {
                self.reject(src, now, |t| &mut t.auth_failed);
                return;
            }
            Err(_) => {
                self.reject(src, now, |t| &mut t.malformed);
                return;
            }
        };
        // Authenticated from here on.
        sess.loss.observe(header.counter);
        sess.last_rx = Some(now);
        sess.stats.rx_pkts = sess.stats.rx_pkts.saturating_add(1);
        sess.stats.rx_bytes = sess.stats.rx_bytes.saturating_add(len);
        if sess.endpoint != Some(src) {
            if let Some(old) = sess.endpoint {
                debug!(session = format_args!("{:08x}", header.session), %old, new = %src, "relay endpoint changed");
            }
            sess.endpoint = Some(src);
        }
        let payload = packet.get(range).unwrap_or_default();
        let mut out = [0u8; MAX_PACKET_LEN];
        if !sess.bucket.try_take(now.into_std()) {
            sess.stats.rate_limited = sess.stats.rate_limited.saturating_add(1);
            self.totals.rate_limited = self.totals.rate_limited.saturating_add(1);
            if sess.error_due(now) {
                let code = wire::encode_error(error_code::RATE_LIMITED);
                if let Some(n) = sess.seal(PacketType::Error, SERVER_VIP, 0, 0, &code, &mut out) {
                    if let Some(bytes) = out.get(..n) {
                        send_datagram(&self.socket, &mut self.totals, bytes, src).await;
                    }
                }
            }
            return;
        }
        let reply = match header.kind {
            PacketType::Reg => {
                if sess.register(header.src_vport) {
                    sess.seal(PacketType::RegAck, SERVER_VIP, header.src_vport, header.src_vport, &[], &mut out)
                } else {
                    sess.stats.dropped = sess.stats.dropped.saturating_add(1);
                    let code = wire::encode_error(error_code::NOT_REGISTERED);
                    if sess.error_due(now) {
                        sess.seal(PacketType::Error, SERVER_VIP, header.src_vport, 0, &code, &mut out)
                    } else {
                        None
                    }
                }
            }
            PacketType::Unreg => {
                sess.vports.retain(|&p| p != header.src_vport);
                None
            }
            PacketType::Ping => match wire::decode_timestamp(payload) {
                Ok(ts) => {
                    let echo = wire::encode_timestamp(ts);
                    sess.seal(PacketType::Pong, SERVER_VIP, 0, 0, &echo, &mut out)
                }
                Err(_) => {
                    sess.stats.dropped = sess.stats.dropped.saturating_add(1);
                    None
                }
            },
            PacketType::Bye => {
                sess.vports.clear();
                sess.endpoint = None;
                None
            }
            PacketType::Data => {
                // Implicit registration: the source vport is authenticated.
                if !sess.register(header.src_vport) {
                    sess.stats.dropped = sess.stats.dropped.saturating_add(1);
                    let code = wire::encode_error(error_code::NOT_REGISTERED);
                    if sess.error_due(now) {
                        sess.seal(PacketType::Error, SERVER_VIP, header.src_vport, 0, &code, &mut out)
                    } else {
                        None
                    }
                } else {
                    let src_vip = sess.vip;
                    self.forward(header.session, src_vip, &header, payload, now).await;
                    None
                }
            }
            PacketType::Pong | PacketType::RegAck | PacketType::Error => None,
        };
        if let Some(bytes) = reply.and_then(|n| out.get(..n)) {
            send_datagram(&self.socket, &mut self.totals, bytes, src).await;
        }
    }

    async fn forward(&mut self, sender: u32, src_vip: Ipv4Addr, header: &Header, payload: &[u8], now: Instant) {
        let dst = header.vip;
        let dport = header.dst_vport;
        let mut targets = std::mem::take(&mut self.targets);
        targets.clear();
        if net::is_broadcast(dst) {
            for (&id, s) in &self.sessions {
                if id != sender && s.has_vport(dport) {
                    if let Some(ep) = s.endpoint {
                        targets.push((ep, id));
                    }
                }
            }
        } else if let Some(&id) = self.by_vip.get(&dst) {
            if id != sender {
                if let Some(ep) = self
                    .sessions
                    .get(&id)
                    .filter(|s| s.has_vport(dport))
                    .and_then(|s| s.endpoint)
                {
                    targets.push((ep, id));
                }
            }
        }
        if let Some(s) = self.sessions.get_mut(&sender) {
            if targets.is_empty() {
                s.stats.no_route = s.stats.no_route.saturating_add(1);
            } else {
                s.stats.forwarded = s.stats.forwarded.saturating_add(1);
            }
        }
        if targets.is_empty() {
            self.totals.no_route = self.totals.no_route.saturating_add(1);
            self.targets = targets;
            return;
        }
        let extra = self.cfg.redundancy.for_port(dport).clamp(1, MAX_REDUNDANCY) - 1;
        let mut out = [0u8; MAX_PACKET_LEN];
        for &(endpoint, id) in &targets {
            let Some(target) = self.sessions.get_mut(&id) else {
                continue;
            };
            let Some(n) = target.seal(PacketType::Data, src_vip, header.src_vport, dport, payload, &mut out) else {
                continue;
            };
            target.stats.tx_pkts = target.stats.tx_pkts.saturating_add(1);
            target.stats.tx_bytes = target.stats.tx_bytes.saturating_add(n as u64);
            let Some(bytes) = out.get(..n) else {
                continue;
            };
            send_datagram(&self.socket, &mut self.totals, bytes, endpoint).await;
            self.copies.schedule(now, endpoint, bytes, extra, &mut self.totals);
        }
        self.targets = targets;
    }

    fn publish_stats(&mut self, now: Instant) {
        let std_now = now.into_std();
        self.preauth.prune(std_now);
        let mut sessions = HashMap::with_capacity(self.sessions.len());
        for (&id, s) in &mut self.sessions {
            s.loss.update();
            let mut stats = s.stats.clone();
            stats.endpoint = s.endpoint.map(|e| e.to_string());
            stats.vports = s.vports.clone();
            stats.upstream_loss_pct = s.loss.percent();
            stats.last_rx_ms_ago = s
                .last_rx
                .map(|t| u64::try_from(now.saturating_duration_since(t).as_millis()).unwrap_or(u64::MAX));
            sessions.insert(id, stats);
        }
        let blocked_ips = self.preauth.blocked(std_now);
        self.stats_tx.send_replace(Arc::new(RelayStats {
            sessions,
            totals: self.totals.clone(),
            blocked_ips,
            taken_at: Some(now),
        }));
    }

    fn say_goodbye(&mut self) {
        let mut out = [0u8; MAX_PACKET_LEN];
        for s in self.sessions.values() {
            let Some(endpoint) = s.endpoint else {
                continue;
            };
            if let Some(n) = s.seal(PacketType::Bye, SERVER_VIP, 0, 0, &[], &mut out) {
                if let Some(bytes) = out.get(..n) {
                    let _ = self.socket.try_send_to(bytes, endpoint);
                }
            }
        }
        self.publish_stats(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_estimator_counts_gaps() {
        let mut l = LossEstimator::default();
        l.update();
        assert_eq!(l.percent(), None);
        // 20 expected (100..=119), 18 received.
        for c in 100..120u64 {
            if c != 105 && c != 110 {
                l.observe(c);
            }
        }
        l.update();
        assert_eq!(l.percent(), Some(10));
        // Next interval without loss pulls the average down.
        for c in 120..140u64 {
            l.observe(c);
        }
        l.update();
        assert_eq!(l.percent(), Some(7));
        // Fewer than 10 new packets: no update.
        for c in 140..145u64 {
            l.observe(c);
        }
        l.update();
        assert_eq!(l.percent(), Some(7));
    }

    #[test]
    fn loss_estimator_tolerates_reordering() {
        let mut l = LossEstimator::default();
        for c in (0..30u64).rev() {
            l.observe(c);
        }
        l.update();
        assert_eq!(l.percent(), Some(0));
        // A late packet of an earlier interval does not produce negative loss.
        let mut l = LossEstimator::default();
        for c in 0..10u64 {
            if c != 5 {
                l.observe(c);
            }
        }
        l.observe(10);
        l.update();
        l.observe(5);
        for c in 11..21u64 {
            l.observe(c);
        }
        l.update();
        assert!(l.percent().unwrap() <= 10);
    }

    #[test]
    fn copy_queue_orders_and_bounds() {
        let mut q = CopyQueues::new();
        let mut totals = RelayTotals::default();
        let t0 = Instant::now();
        let dst: SocketAddr = "127.0.0.1:9".parse().unwrap();
        q.schedule(t0, dst, b"abc", 2, &mut totals);
        assert_eq!(q.len, 2);
        assert_eq!(q.next_due(), Some(t0 + REDUNDANCY_DELAYS[0]));
        q.schedule(t0, dst, b"abc", 0, &mut totals);
        q.schedule(t0, dst, b"abc", 9, &mut totals);
        assert_eq!(q.len, 4, "at most one copy per delay");
        for _ in 0..MAX_PENDING_COPIES {
            q.schedule(t0, dst, b"x", 1, &mut totals);
        }
        assert_eq!(q.len, MAX_PENDING_COPIES);
        assert!(totals.copies_skipped > 0);
    }

    #[test]
    fn session_vport_table_is_bounded() {
        let now = std::time::Instant::now();
        let mut s = Session {
            key: RelayKey::from_bytes([1; 32]),
            vip: Ipv4Addr::new(198, 18, 0, 2),
            window: ReplayWindow::new(),
            send: SendCounter::new(),
            vports: Vec::new(),
            endpoint: None,
            bucket: TokenBucket::new(1.0, 1.0, now),
            loss: LossEstimator::default(),
            stats: SessionStats::default(),
            last_rx: None,
            last_error: None,
        };
        for p in 0..MAX_VPORTS_PER_SESSION as u16 {
            assert!(s.register(8000 + p));
        }
        assert!(s.register(8000), "already registered");
        assert!(!s.register(9999));
        assert!(s.has_vport(8005) && !s.has_vport(9999));
        let t = Instant::now();
        assert!(s.error_due(t));
        assert!(!s.error_due(t));
        assert!(s.error_due(t + ERROR_INTERVAL));
    }
}
