//! The agent: the data plane between the hook (loopback `BCN1` frames,
//! architecture §5) and the relay (sealed UDP packets, §6).
//!
//! * Hook `REG` → relay `REG` (repeated until `REG_ACK`); `SEND` → relay `DATA`,
//!   sealed once and sent `R` times with the same counter (copies after 3 ms and
//!   10 ms; `R` from [`RedundancyOverrides`], default by destination port); `CLOSE` →
//!   relay `UNREG`. Every `REG`/`SEND` refreshes `vport → loopback endpoint`;
//!   entries not refreshed for 60 s, and all entries when the game exits, are
//!   dropped with `UNREG` (the hook sends no `CLOSE` when the game just exits).
//! * Relay `DATA` → replay window (drops the redundant copies and replays) →
//!   `DELIVER` to the endpoint registered for the destination vport (dropped if
//!   there is none).
//! * Unicast to the own vIP is delivered locally, never via the server;
//!   broadcasts are never delivered back to the sender.
//! * `PING` every second → RTT (EWMA) and loss; garbage on either socket is counted
//!   and dropped. Sends never block (`try_send_to`; a full socket buffer drops
//!   the datagram like the network would).

pub mod stats;
pub mod table;

use std::collections::VecDeque;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use beacon_proto::local::{self, Deliver, FrameType};
use beacon_proto::net::{self, SERVER_VIP};
use beacon_proto::relay::{
    self, decode_error, decode_timestamp, encode_timestamp, error_code, Direction, Header, PacketType,
    RelayKey, ReplayWindow, SendCounter, MAX_PACKET_LEN, MAX_PAYLOAD, REDUNDANCY_DELAYS,
};
use serde::Serialize;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior};
use tracing::{debug, info, warn};

use self::stats::{LossWindow, RttEstimator};
use self::table::{Learned, Registrations};
use crate::config::RedundancyOverrides;

/// Registrations not refreshed for this long are dropped.
pub const REGISTRATION_EXPIRY: Duration = Duration::from_secs(60);
/// Unconfirmed relay `REG`s are repeated this often.
pub const REG_RETRY: Duration = Duration::from_secs(1);
/// Pending redundant copies per delay slot.
const MAX_PENDING_COPIES: usize = 512;
/// Receive buffers (hook frames ≤ 1044 bytes, relay packets ≤ 520 bytes).
const BUF_LEN: usize = 2048;
/// After this many consecutive socket errors the loop pauses briefly.
const ERROR_BURST: u32 = 64;

/// Credentials of the current relay session (from `welcome`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySession {
    /// Server relay endpoint (control host + `relay_port`).
    pub relay_addr: SocketAddr,
    /// Session id.
    pub session: u32,
    /// Session key.
    pub key: RelayKey,
    /// The player's vIP.
    pub vip: Ipv4Addr,
}

/// Agent options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentOptions {
    /// Copies per DATA packet.
    pub redundancy: RedundancyOverrides,
    /// Registration expiry.
    pub expiry: Duration,
    /// Housekeeping interval (PING, REG retries, expiry, stats).
    pub tick: Duration,
}

impl Default for AgentOptions {
    fn default() -> Self {
        Self {
            redundancy: RedundancyOverrides::default(),
            expiry: REGISTRATION_EXPIRY,
            tick: relay::PING_INTERVAL,
        }
    }
}

/// One registered vport (stats view).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistrationView {
    /// Virtual port.
    pub vport: u16,
    /// Loopback port of the hook socket.
    pub local_port: u16,
    /// Confirmed by the server.
    pub acked: bool,
    /// Milliseconds since the last frame from it.
    pub idle_ms: u64,
}

/// Live statistics of the agent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AgentStats {
    /// Loopback port for the hook (`BEACON_AGENT_PORT`).
    pub local_port: u16,
    /// A relay session is active.
    pub session_active: bool,
    /// The session's vIP.
    pub vip: Option<Ipv4Addr>,
    /// Registered vports.
    pub registrations: Vec<RegistrationView>,
    /// Smoothed relay RTT.
    pub rtt_ms: Option<u32>,
    /// Relay loss over the last 30 pings.
    pub loss_pct: Option<u8>,
    /// Frames from the hook.
    pub hook_frames: u64,
    /// Malformed hook frames.
    pub hook_malformed: u64,
    /// Hook frames with a wrong token or from a non-loopback address.
    pub hook_rejected: u64,
    /// DATA packets sent to the relay (each counted once).
    pub data_sent: u64,
    /// Redundant copies sent.
    pub copies_sent: u64,
    /// Payload bytes sent to the relay.
    pub bytes_sent: u64,
    /// DATA packets accepted from the relay.
    pub data_received: u64,
    /// DELIVER frames to the hook (from the relay).
    pub delivered: u64,
    /// DELIVER frames to the hook for unicast to the own vIP.
    pub delivered_local: u64,
    /// Dropped: no registration for the destination vport.
    pub dropped_no_route: u64,
    /// Dropped: payload larger than 480 bytes.
    pub dropped_oversize: u64,
    /// Dropped: no relay session.
    pub dropped_no_session: u64,
    /// Dropped: destination outside the virtual LAN or port 0.
    pub dropped_bad_destination: u64,
    /// Dropped: socket buffer full / send error.
    pub dropped_send: u64,
    /// Redundant copies discarded by the replay window.
    pub duplicates: u64,
    /// Relay packets that failed authentication or parsing.
    pub relay_rejected: u64,
    /// Datagrams on the relay socket from other addresses.
    pub relay_foreign: u64,
    /// Registrations dropped by expiry or game exit.
    pub expired: u64,
    /// PINGs sent.
    pub pings: u64,
    /// PONGs received.
    pub pongs: u64,
    /// ERROR packets from the server.
    pub server_errors: u64,
}

enum Cmd {
    Session(Option<RelaySession>),
    GameExited,
    Redundancy(RedundancyOverrides),
    Shutdown,
}

/// Handle to the running agent.
#[derive(Debug, Clone)]
pub struct AgentHandle {
    tx: mpsc::Sender<Cmd>,
    port: u16,
    token: u32,
    stats: watch::Receiver<AgentStats>,
}

impl std::fmt::Debug for Cmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Session(_) => "Session",
            Self::GameExited => "GameExited",
            Self::Redundancy(_) => "Redundancy",
            Self::Shutdown => "Shutdown",
        })
    }
}

impl AgentHandle {
    /// Binds `127.0.0.1:0`, draws a random local token and starts the agent task.
    pub async fn start(opts: AgentOptions) -> io::Result<(Self, tokio::task::JoinHandle<()>)> {
        let local = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let port = local.local_addr()?.port();
        let token = crate::util::random_u32();
        let (tx, rx) = mpsc::channel(32);
        let stats = AgentStats {
            local_port: port,
            ..AgentStats::default()
        };
        let (stats_tx, stats_rx) = watch::channel(stats.clone());
        let agent = Agent {
            local,
            token,
            regs: Registrations::new(),
            relay: None,
            copies: [VecDeque::new(), VecDeque::new()],
            rtt: RttEstimator::default(),
            loss: LossWindow::default(),
            stats,
            stats_tx,
            opts,
            epoch: Instant::now(),
            errors: 0,
        };
        let task = tokio::spawn(agent.run(rx));
        info!(port, "agent listening for the hook on 127.0.0.1:{port}");
        Ok((
            Self {
                tx,
                port,
                token,
                stats: stats_rx,
            },
            task,
        ))
    }

    /// The loopback port (`BEACON_AGENT_PORT`).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The local token (`BEACON_LOCAL_TOKEN`).
    pub fn token(&self) -> u32 {
        self.token
    }

    /// Installs (or with `None` ends) the relay session.
    pub async fn set_session(&self, session: Option<RelaySession>) {
        let _ = self.tx.send(Cmd::Session(session)).await;
    }

    /// The game process ended: drop every registration (`UNREG`).
    pub async fn game_exited(&self) {
        let _ = self.tx.send(Cmd::GameExited).await;
    }

    /// Changes the redundancy.
    pub async fn set_redundancy(&self, r: RedundancyOverrides) {
        let _ = self.tx.send(Cmd::Redundancy(r)).await;
    }

    /// Stops the agent (UNREG + BYE).
    pub async fn shutdown(&self) {
        let _ = self.tx.send(Cmd::Shutdown).await;
    }

    /// Current statistics.
    pub fn stats(&self) -> AgentStats {
        self.stats.borrow().clone()
    }

    /// Statistics updates (about once per tick).
    pub fn watch_stats(&self) -> watch::Receiver<AgentStats> {
        self.stats.clone()
    }
}

struct Relay {
    sock: UdpSocket,
    session: RelaySession,
    counter: SendCounter,
    window: ReplayWindow,
}

struct PendingCopy {
    due: Instant,
    session: u32,
    packet: Vec<u8>,
}

struct Agent {
    local: UdpSocket,
    token: u32,
    regs: Registrations,
    relay: Option<Relay>,
    copies: [VecDeque<PendingCopy>; 2],
    rtt: RttEstimator,
    loss: LossWindow,
    stats: AgentStats,
    stats_tx: watch::Sender<AgentStats>,
    opts: AgentOptions,
    epoch: Instant,
    errors: u32,
}

async fn recv_relay(relay: &Option<Relay>, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    match relay {
        Some(r) => r.sock.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

async fn sleep_until_opt(due: Option<Instant>) {
    match due {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

impl Agent {
    async fn run(mut self, mut rx: mpsc::Receiver<Cmd>) {
        let mut tick = tokio::time::interval(self.opts.tick);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut lbuf = vec![0u8; BUF_LEN];
        let mut rbuf = vec![0u8; BUF_LEN];
        loop {
            let next_copy = self.next_copy_due();
            tokio::select! {
                cmd = rx.recv() => match cmd {
                    Some(Cmd::Session(s)) => self.set_session(s).await,
                    Some(Cmd::GameExited) => self.drop_all("game exited"),
                    Some(Cmd::Redundancy(r)) => self.opts.redundancy = r,
                    Some(Cmd::Shutdown) | None => {
                        self.drop_all("shutdown");
                        self.set_session(None).await;
                        self.publish();
                        return;
                    }
                },
                r = self.local.recv_from(&mut lbuf) => match r {
                    Ok((n, from)) => {
                        self.errors = 0;
                        if let Some(frame) = lbuf.get(..n) {
                            self.on_hook(frame, from);
                        }
                    }
                    Err(e) => self.socket_error("hook socket", &e).await,
                },
                r = recv_relay(&self.relay, &mut rbuf) => match r {
                    Ok((n, from)) => {
                        self.errors = 0;
                        if let Some(packet) = rbuf.get_mut(..n) {
                            self.on_relay(packet, from);
                        }
                    }
                    Err(e) => self.socket_error("relay socket", &e).await,
                },
                () = sleep_until_opt(next_copy) => self.flush_copies(),
                _ = tick.tick() => self.on_tick(),
            }
        }
    }

    /// Windows reports ICMP "port unreachable" for earlier sends as an error on the
    /// next receive (`WSAECONNRESET`); such errors are counted and ignored.
    async fn socket_error(&mut self, which: &str, e: &io::Error) {
        self.errors = self.errors.saturating_add(1);
        debug!("{which}: {e}");
        if self.errors >= ERROR_BURST {
            warn!("{which}: repeated errors ({e}); pausing briefly");
            self.errors = 0;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    // ---- hook side -------------------------------------------------------

    fn on_hook(&mut self, frame: &[u8], from: SocketAddr) {
        self.stats.hook_frames += 1;
        if !from.ip().is_loopback() {
            self.stats.hook_rejected += 1;
            return;
        }
        let Ok((h, payload)) = local::parse_hook_frame(frame) else {
            self.stats.hook_malformed += 1;
            return;
        };
        if h.token != self.token {
            self.stats.hook_rejected += 1;
            return;
        }
        match h.kind {
            FrameType::Reg => self.learn(h.src_vport, from),
            FrameType::Send => {
                self.learn(h.src_vport, from);
                self.forward(h.src_vport, h.dst_vip, h.dst_vport, payload);
            }
            FrameType::Close => {
                if self.regs.close(h.src_vport, from) {
                    debug!(vport = h.src_vport, "hook closed vport");
                    self.send_control(PacketType::Unreg, h.src_vport);
                }
            }
        }
    }

    fn learn(&mut self, vport: u16, from: SocketAddr) {
        match self.regs.learn(vport, from, Instant::now().into_std()) {
            Learned::New | Learned::Moved => {
                debug!(vport, %from, "hook registered vport");
                self.send_reg(vport);
            }
            Learned::Refreshed => {}
            Learned::Rejected => self.stats.hook_rejected += 1,
        }
    }

    fn forward(&mut self, src_vport: u16, dst: Ipv4Addr, dst_vport: u16, payload: &[u8]) {
        if payload.len() > MAX_PAYLOAD {
            self.stats.dropped_oversize += 1;
            return;
        }
        if dst_vport == 0 || !(net::is_broadcast(dst) || net::is_assignable(dst)) {
            self.stats.dropped_bad_destination += 1;
            return;
        }
        let Some(relay) = &self.relay else {
            self.stats.dropped_no_session += 1;
            return;
        };
        let own_vip = relay.session.vip;
        if dst == own_vip {
            // Unicast to ourselves: loop back locally, never via the server.
            if self.deliver(own_vip, src_vport, dst_vport, payload) {
                self.stats.delivered_local += 1;
            }
            return;
        }
        let Some(counter) = relay.counter.next() else {
            self.stats.dropped_send += 1;
            return;
        };
        let header = Header::client(
            PacketType::Data,
            relay.session.session,
            counter,
            dst,
            src_vport,
            dst_vport,
        );
        let mut buf = [0u8; MAX_PACKET_LEN];
        let Ok(len) = relay::seal(&relay.session.key, Direction::ClientToServer, &header, payload, &mut buf) else {
            self.stats.dropped_oversize += 1;
            return;
        };
        let packet = buf.get(..len).unwrap_or_default();
        let session = relay.session.session;
        if self.send_relay(packet) {
            self.stats.data_sent += 1;
            self.stats.bytes_sent += u64::try_from(payload.len()).unwrap_or(0);
        }
        let copies = usize::from(self.opts.redundancy.for_port(dst_vport).saturating_sub(1));
        let now = Instant::now();
        for (slot, delay) in REDUNDANCY_DELAYS.iter().enumerate().take(copies) {
            if let Some(queue) = self.copies.get_mut(slot) {
                if queue.len() >= MAX_PENDING_COPIES {
                    queue.pop_front();
                    self.stats.dropped_send += 1;
                }
                queue.push_back(PendingCopy {
                    due: now + *delay,
                    session,
                    packet: packet.to_vec(),
                });
            }
        }
    }

    /// Sends a DELIVER frame to the hook socket registered for `dst_vport`.
    fn deliver(&mut self, src_vip: Ipv4Addr, src_vport: u16, dst_vport: u16, payload: &[u8]) -> bool {
        let Some(endpoint) = self.regs.endpoint(dst_vport) else {
            self.stats.dropped_no_route += 1;
            return false;
        };
        let mut buf = [0u8; local::MAX_DELIVER_FRAME_LEN];
        let Ok(n) = local::encode_deliver(&Deliver { src_vip, src_vport }, payload, &mut buf) else {
            self.stats.dropped_oversize += 1;
            return false;
        };
        match self.local.try_send_to(buf.get(..n).unwrap_or_default(), endpoint) {
            Ok(_) => true,
            Err(e) => {
                debug!("deliver to {endpoint}: {e}");
                self.stats.dropped_send += 1;
                false
            }
        }
    }

    // ---- relay side ------------------------------------------------------

    fn send_relay(&mut self, packet: &[u8]) -> bool {
        let Some(relay) = &self.relay else {
            return false;
        };
        match relay.sock.try_send_to(packet, relay.session.relay_addr) {
            Ok(_) => true,
            Err(e) => {
                debug!("relay send: {e}");
                self.stats.dropped_send += 1;
                false
            }
        }
    }

    /// Sends REG/UNREG/BYE/PING (vport in `src_vport`, destination = server vIP).
    fn send_control_with(&mut self, kind: PacketType, vport: u16, payload: &[u8]) -> bool {
        let Some(relay) = &self.relay else {
            return false;
        };
        let Some(counter) = relay.counter.next() else {
            return false;
        };
        let header = Header::client(kind, relay.session.session, counter, SERVER_VIP, vport, 0);
        let mut buf = [0u8; MAX_PACKET_LEN];
        match relay::seal(&relay.session.key, Direction::ClientToServer, &header, payload, &mut buf) {
            Ok(len) => {
                let packet = buf.get(..len).unwrap_or_default().to_vec();
                self.send_relay(&packet)
            }
            Err(_) => false,
        }
    }

    fn send_control(&mut self, kind: PacketType, vport: u16) -> bool {
        self.send_control_with(kind, vport, &[])
    }

    fn send_reg(&mut self, vport: u16) {
        if self.send_control(PacketType::Reg, vport) {
            self.regs.reg_sent(vport, Instant::now().into_std());
        }
    }

    fn on_relay(&mut self, packet: &mut [u8], from: SocketAddr) {
        let Some(relay) = &mut self.relay else {
            return;
        };
        if from != relay.session.relay_addr {
            self.stats.relay_foreign += 1;
            return;
        }
        let (header, range) =
            match relay::open_with_window(&relay.session.key, Direction::ServerToClient, packet, &mut relay.window) {
                Ok(opened) => opened,
                Err(relay::Error::Replayed { .. }) => {
                    self.stats.duplicates += 1;
                    return;
                }
                Err(_) => {
                    self.stats.relay_rejected += 1;
                    return;
                }
            };
        let own_vip = relay.session.vip;
        let payload = packet.get(range).unwrap_or_default();
        match header.kind {
            PacketType::Data => {
                self.stats.data_received += 1;
                if !net::is_assignable(header.vip) || header.vip == own_vip {
                    // Never deliver our own packets back to us.
                    self.stats.dropped_bad_destination += 1;
                    return;
                }
                if self.deliver(header.vip, header.src_vport, header.dst_vport, payload) {
                    self.stats.delivered += 1;
                }
            }
            PacketType::Pong => {
                if let Ok(ts) = decode_timestamp(payload) {
                    let now = self.now_ms();
                    if let Some(rtt) = self.loss.answered(ts, now) {
                        self.stats.pongs += 1;
                        self.rtt.sample(rtt);
                    }
                }
            }
            PacketType::RegAck => self.regs.ack(header.src_vport),
            PacketType::Error => {
                self.stats.server_errors += 1;
                match decode_error(payload) {
                    Ok(error_code::NOT_REGISTERED) => {
                        debug!("server lost our registrations; re-registering");
                        self.regs.unack_all();
                        for v in self.regs.reg_due(Instant::now().into_std(), REG_RETRY) {
                            self.send_reg(v);
                        }
                    }
                    Ok(error_code::RATE_LIMITED) => debug!("relay rate limit reached"),
                    other => debug!("relay error {other:?}"),
                }
            }
            PacketType::Bye => {
                info!("relay session ended by the server");
                self.relay = None;
                self.stats.session_active = false;
            }
            PacketType::Reg | PacketType::Ping | PacketType::Unreg => {}
        }
    }

    // ---- timers ----------------------------------------------------------

    fn next_copy_due(&self) -> Option<Instant> {
        self.copies.iter().filter_map(|q| q.front().map(|c| c.due)).min()
    }

    fn flush_copies(&mut self) {
        let now = Instant::now();
        let session = self.relay.as_ref().map(|r| r.session.session);
        let mut due = Vec::new();
        for queue in &mut self.copies {
            while queue.front().is_some_and(|c| c.due <= now) {
                due.extend(queue.pop_front());
            }
        }
        for copy in due {
            if Some(copy.session) == session && self.send_relay(&copy.packet) {
                self.stats.copies_sent += 1;
            }
        }
    }

    fn on_tick(&mut self) {
        let now = Instant::now().into_std();
        for v in self.regs.expire(now, self.opts.expiry) {
            debug!(vport = v, "registration expired");
            self.stats.expired += 1;
            self.send_control(PacketType::Unreg, v);
        }
        if self.relay.is_some() {
            for v in self.regs.reg_due(now, REG_RETRY) {
                self.send_reg(v);
            }
            self.ping();
        }
        self.publish();
    }

    fn ping(&mut self) {
        let ts = self.now_ms();
        if self.send_control_with(PacketType::Ping, 0, &encode_timestamp(ts)) {
            self.loss.sent(ts);
            self.stats.pings += 1;
        }
    }

    fn drop_all(&mut self, why: &str) {
        let vports = self.regs.clear();
        if !vports.is_empty() {
            info!(count = vports.len(), "dropping registrations ({why})");
        }
        for v in vports {
            self.stats.expired += 1;
            self.send_control(PacketType::Unreg, v);
        }
        self.publish();
    }

    async fn set_session(&mut self, session: Option<RelaySession>) {
        if self.relay.is_some() {
            self.send_control(PacketType::Bye, 0);
        }
        self.relay = None;
        self.rtt.reset();
        self.loss.reset();
        for q in &mut self.copies {
            q.clear();
        }
        self.regs.unack_all();
        if let Some(session) = session {
            let bind: SocketAddr = if session.relay_addr.is_ipv4() {
                SocketAddr::from(([0, 0, 0, 0], 0))
            } else {
                SocketAddr::from(([0u16; 8], 0))
            };
            match UdpSocket::bind(bind).await {
                Ok(sock) => {
                    info!(relay = %session.relay_addr, vip = %session.vip, "relay session active");
                    self.relay = Some(Relay {
                        sock,
                        session,
                        counter: SendCounter::new(),
                        window: ReplayWindow::new(),
                    });
                    for v in self.regs.reg_due(Instant::now().into_std(), REG_RETRY) {
                        self.send_reg(v);
                    }
                    self.ping();
                }
                Err(e) => warn!("cannot open the relay socket: {e}"),
            }
        }
        self.publish();
    }

    fn publish(&mut self) {
        let now = Instant::now().into_std();
        self.stats.session_active = self.relay.is_some();
        self.stats.vip = self.relay.as_ref().map(|r| r.session.vip);
        self.stats.rtt_ms = self.rtt.rtt_ms();
        self.stats.loss_pct = self.loss.loss_pct(self.now_ms());
        self.stats.registrations = self
            .regs
            .iter()
            .map(|(vport, r)| RegistrationView {
                vport,
                local_port: r.endpoint.port(),
                acked: r.acked,
                idle_ms: u64::try_from(now.saturating_duration_since(r.last_seen).as_millis()).unwrap_or(u64::MAX),
            })
            .collect();
        self.stats_tx.send_replace(self.stats.clone());
    }
}

#[cfg(test)]
mod tests;
