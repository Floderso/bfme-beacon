//! Agent tests: a fake hook (loopback UDP socket speaking `BCN1`) and a fake relay
//! (UDP socket sealing/opening relay packets with the session key).

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use beacon_proto::local::{self, HookFrame};
use beacon_proto::relay::{self, Direction, Header, PacketType, RelayKey, SendCounter, MAX_PACKET_LEN};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use super::*;

const KEY: [u8; 32] = [0x42; 32];
const SESSION: u32 = 0x0BEA_C0FF;
const VIP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 5);
const PEER: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 9);
const QUIET: Duration = Duration::from_millis(250);
const T: Duration = Duration::from_secs(3);

struct FakeHook {
    sock: UdpSocket,
    agent: SocketAddr,
    token: u32,
}

impl FakeHook {
    async fn new(agent: &AgentHandle) -> Self {
        Self {
            sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            agent: SocketAddr::from(([127, 0, 0, 1], agent.port())),
            token: agent.token(),
        }
    }

    async fn frame(&self, h: HookFrame, payload: &[u8]) {
        let mut buf = [0u8; local::MAX_HOOK_FRAME_LEN];
        let n = local::encode_hook_frame(&h, payload, &mut buf).unwrap();
        self.sock.send_to(&buf[..n], self.agent).await.unwrap();
    }

    async fn reg(&self, vport: u16) {
        self.frame(HookFrame::reg(vport, self.token), &[]).await;
    }

    async fn send(&self, src: u16, dst: Ipv4Addr, dport: u16, payload: &[u8]) {
        self.frame(HookFrame::send(src, dst, dport, self.token), payload).await;
    }

    async fn deliver(&self, within: Duration) -> Option<(Ipv4Addr, u16, Vec<u8>)> {
        let mut buf = [0u8; 2048];
        let (n, from) = timeout(within, self.sock.recv_from(&mut buf)).await.ok()?.ok()?;
        assert_eq!(from, self.agent, "DELIVER must come from the agent port");
        let (d, range) = local::parse_deliver(&buf[..n]).unwrap();
        Some((d.src_vip, d.src_vport, buf[range].to_vec()))
    }
}

struct FakeRelay {
    sock: UdpSocket,
    key: RelayKey,
    counter: SendCounter,
    agent: Option<SocketAddr>,
}

impl FakeRelay {
    async fn new() -> Self {
        Self {
            sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            key: RelayKey::from_bytes(KEY),
            counter: SendCounter::new(),
            agent: None,
        }
    }

    fn session(&self) -> RelaySession {
        RelaySession {
            relay_addr: self.sock.local_addr().unwrap(),
            session: SESSION,
            key: self.key.clone(),
            vip: VIP,
        }
    }

    /// Next packet (raw bytes + opened header/payload).
    async fn recv(&mut self, within: Duration) -> Option<(Vec<u8>, Header, Vec<u8>)> {
        let mut buf = [0u8; 2048];
        let (n, from) = timeout(within, self.sock.recv_from(&mut buf)).await.ok()?.ok()?;
        self.agent = Some(from);
        let raw = buf[..n].to_vec();
        let mut copy = raw.clone();
        let (h, range) = relay::open(&self.key, Direction::ClientToServer, &mut copy).unwrap();
        assert_eq!(h.session, SESSION);
        Some((raw, h, copy[range].to_vec()))
    }

    /// Next packet of `kind`, answering PINGs on the way.
    async fn expect(&mut self, kind: PacketType) -> (Vec<u8>, Header, Vec<u8>) {
        let deadline = tokio::time::Instant::now() + T;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let (raw, h, p) = self.recv(left).await.unwrap_or_else(|| panic!("no {kind:?}"));
            if h.kind == kind {
                return (raw, h, p);
            }
        }
    }

    /// Asserts that no DATA arrives (control packets are ignored).
    async fn no_data(&mut self) {
        let deadline = tokio::time::Instant::now() + QUIET;
        while let Some((_, h, _)) = self
            .recv(deadline.saturating_duration_since(tokio::time::Instant::now()))
            .await
        {
            assert_ne!(h.kind, PacketType::Data, "unexpected DATA {h:?}");
        }
    }

    fn seal(&self, kind: PacketType, src_vip: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let h = Header::server(kind, self.counter.next().unwrap(), src_vip, sport, dport);
        let mut buf = [0u8; MAX_PACKET_LEN];
        let n = relay::seal(&self.key, Direction::ServerToClient, &h, payload, &mut buf).unwrap();
        buf[..n].to_vec()
    }

    async fn send_raw(&self, bytes: &[u8]) {
        self.sock.send_to(bytes, self.agent.unwrap()).await.unwrap();
    }
}

/// Fast ticks; the default 60 s expiry.
fn opts() -> AgentOptions {
    AgentOptions {
        tick: Duration::from_millis(50),
        ..AgentOptions::default()
    }
}

/// Fast ticks and a short expiry.
fn quick_expiry() -> AgentOptions {
    AgentOptions {
        expiry: Duration::from_millis(400),
        ..opts()
    }
}

async fn wait_stats(agent: &AgentHandle, what: &str, pred: impl Fn(&AgentStats) -> bool) -> AgentStats {
    let mut rx = agent.watch_stats();
    let deadline = tokio::time::Instant::now() + T;
    loop {
        let s = rx.borrow_and_update().clone();
        if pred(&s) {
            return s;
        }
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if timeout(left, rx.changed()).await.is_err() {
            panic!("timeout waiting for {what}: {s:#?}");
        }
    }
}

#[tokio::test]
async fn translates_frames_with_redundancy_and_dedupe() {
    let (agent, task) = AgentHandle::start(opts()).await.unwrap();
    let mut relay = FakeRelay::new().await;
    agent.set_session(Some(relay.session())).await;
    let hook = FakeHook::new(&agent).await;

    // REG → relay REG until REG_ACK.
    hook.reg(8086).await;
    let (_, h, p) = relay.expect(PacketType::Reg).await;
    assert_eq!((h.vip, h.src_vport, h.dst_vport, p.len()), (beacon_proto::net::SERVER_VIP, 8086, 0, 0));
    let ack = relay.seal(PacketType::RegAck, beacon_proto::net::SERVER_VIP, 8086, 8086, &[]);
    relay.send_raw(&ack).await;
    wait_stats(&agent, "ack", |s| s.registrations.iter().any(|r| r.vport == 8086 && r.acked)).await;

    // Lobby unicast: three identical copies with one counter.
    hook.send(8086, PEER, 8086, b"hello").await;
    let (first, h, p) = relay.expect(PacketType::Data).await;
    assert_eq!((h.vip, h.src_vport, h.dst_vport), (PEER, 8086, 8086));
    assert_eq!(p, b"hello");
    for _ in 0..2 {
        let (copy, hc, _) = relay.expect(PacketType::Data).await;
        assert_eq!(copy, first, "copies are byte-identical");
        assert_eq!(hc.counter, h.counter);
    }
    // Game port: two copies; broadcast keeps its destination.
    hook.send(8094, PEER, 8095, b"game").await;
    let (a, ..) = relay.expect(PacketType::Data).await;
    let (b, ..) = relay.expect(PacketType::Data).await;
    assert_eq!(a, b);
    relay.no_data().await;
    hook.send(8086, Ipv4Addr::BROADCAST, 8087, b"bcast").await;
    let (_, h, _) = relay.expect(PacketType::Data).await;
    assert_eq!((h.vip, h.dst_vport), (Ipv4Addr::BROADCAST, 8087));

    // Relay DATA → exactly one DELIVER, even when the copy arrives too.
    let data = relay.seal(PacketType::Data, PEER, 8090, 8086, b"from peer");
    relay.send_raw(&data).await;
    relay.send_raw(&data).await;
    relay.send_raw(&data).await;
    assert_eq!(hook.deliver(T).await, Some((PEER, 8090, b"from peer".to_vec())));
    assert_eq!(hook.deliver(QUIET).await, None, "redundant copies are dropped");
    let s = wait_stats(&agent, "duplicates", |s| s.duplicates >= 2).await;
    assert_eq!(s.delivered, 1);

    // No registration for the destination port → dropped.
    relay.send_raw(&relay.seal(PacketType::Data, PEER, 8090, 8099, b"x")).await;
    // Our own vIP as source (an echo) is never delivered.
    relay.send_raw(&relay.seal(PacketType::Data, VIP, 8086, 8086, b"echo")).await;
    assert_eq!(hook.deliver(QUIET).await, None);
    wait_stats(&agent, "drops", |s| s.dropped_no_route >= 1 && s.dropped_bad_destination >= 1).await;

    task.abort();
}

#[tokio::test]
async fn garbage_and_bad_frames_are_dropped() {
    let (agent, task) = AgentHandle::start(opts()).await.unwrap();
    let mut relay = FakeRelay::new().await;
    agent.set_session(Some(relay.session())).await;
    let hook = FakeHook::new(&agent).await;
    hook.reg(8086).await;
    relay.expect(PacketType::Reg).await;

    // Hook side: garbage, wrong token, oversize, bad destinations.
    hook.sock.send_to(b"garbage", hook.agent).await.unwrap();
    hook.sock.send_to(&[0u8; 3000][..1500], hook.agent).await.unwrap();
    hook.frame(HookFrame::send(8086, PEER, 8086, hook.token ^ 1), b"x").await;
    hook.send(8086, PEER, 8086, &[0u8; 481]).await;
    hook.send(8086, Ipv4Addr::new(10, 0, 0, 1), 8086, b"internet").await;
    hook.send(8086, beacon_proto::net::SERVER_VIP, 8086, b"server").await;
    hook.send(8086, PEER, 0, b"port 0").await;
    relay.no_data().await;
    let s = wait_stats(&agent, "hook drops", |s| {
        s.hook_malformed >= 2 && s.hook_rejected >= 1 && s.dropped_oversize >= 1 && s.dropped_bad_destination >= 3
    })
    .await;
    assert_eq!(s.data_sent, 0);

    // Relay side: garbage, wrong key, foreign source.
    relay.send_raw(b"junk").await;
    relay.send_raw(&[0xBE; 600]).await;
    let mut forged = relay.seal(PacketType::Data, PEER, 8086, 8086, b"x");
    let last = forged.len() - 1;
    forged[last] ^= 1;
    relay.send_raw(&forged).await;
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    other
        .send_to(&relay.seal(PacketType::Data, PEER, 8086, 8086, b"x"), relay.agent.unwrap())
        .await
        .unwrap();
    assert_eq!(hook.deliver(QUIET).await, None);
    wait_stats(&agent, "relay drops", |s| s.relay_rejected >= 3 && s.relay_foreign >= 1).await;

    // Still working afterwards.
    relay.send_raw(&relay.seal(PacketType::Data, PEER, 8086, 8086, b"ok")).await;
    assert_eq!(hook.deliver(T).await, Some((PEER, 8086, b"ok".to_vec())));
    task.abort();
}

#[tokio::test]
async fn unicast_to_self_stays_local_and_broadcast_is_not_echoed() {
    let (agent, task) = AgentHandle::start(opts()).await.unwrap();
    let mut relay = FakeRelay::new().await;
    agent.set_session(Some(relay.session())).await;
    let lobby = FakeHook::new(&agent).await;
    let other = FakeHook::new(&agent).await;
    lobby.reg(8086).await;
    other.reg(8087).await;
    relay.expect(PacketType::Reg).await;
    relay.expect(PacketType::Reg).await;

    other.send(8087, VIP, 8086, b"to myself").await;
    assert_eq!(lobby.deliver(T).await, Some((VIP, 8087, b"to myself".to_vec())));
    relay.no_data().await;
    wait_stats(&agent, "local", |s| s.delivered_local == 1).await;

    other.send(8087, beacon_proto::net::VSUBNET_BROADCAST, 8086, b"bcast").await;
    let (_, h, _) = relay.expect(PacketType::Data).await;
    assert_eq!(h.vip, beacon_proto::net::VSUBNET_BROADCAST);
    assert_eq!(lobby.deliver(QUIET).await, None, "broadcast not delivered locally");
    task.abort();
}

#[tokio::test]
async fn registrations_expire_and_end_with_the_game() {
    let (agent, task) = AgentHandle::start(quick_expiry()).await.unwrap();
    let mut relay = FakeRelay::new().await;
    // REG before the session: sent once the session starts.
    let hook = FakeHook::new(&agent).await;
    hook.reg(8086).await;
    hook.send(8086, PEER, 8086, b"too early").await;
    wait_stats(&agent, "no session", |s| s.dropped_no_session == 1).await;
    agent.set_session(Some(relay.session())).await;
    let (_, h, _) = relay.expect(PacketType::Reg).await;
    assert_eq!(h.src_vport, 8086);

    // Not refreshed → UNREG after the expiry.
    let (_, h, _) = relay.expect(PacketType::Unreg).await;
    assert_eq!(h.src_vport, 8086);
    wait_stats(&agent, "expired", |s| s.expired == 1 && s.registrations.is_empty()).await;

    // SENDs refresh; the game's exit drops everything.
    hook.reg(8094).await;
    relay.expect(PacketType::Reg).await;
    for _ in 0..6 {
        hook.send(8094, PEER, 8094, b"keep").await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(agent.stats().registrations.len(), 1, "refreshed by SEND");
    agent.game_exited().await;
    let (_, h, _) = relay.expect(PacketType::Unreg).await;
    assert_eq!(h.src_vport, 8094);

    // CLOSE → UNREG at once.
    hook.reg(8087).await;
    relay.expect(PacketType::Reg).await;
    hook.frame(HookFrame::close(8087, hook.token), &[]).await;
    let (_, h, _) = relay.expect(PacketType::Unreg).await;
    assert_eq!(h.src_vport, 8087);
    task.abort();
}

#[tokio::test]
async fn ping_pong_measures_rtt_and_session_changes_reregister() {
    let (agent, task) = AgentHandle::start(opts()).await.unwrap();
    let mut relay = FakeRelay::new().await;
    agent.set_session(Some(relay.session())).await;
    let hook = FakeHook::new(&agent).await;
    hook.reg(8086).await;
    for _ in 0..3 {
        let (_, h, p) = relay.expect(PacketType::Ping).await;
        assert_eq!(h.vip, beacon_proto::net::SERVER_VIP);
        let pong = relay.seal(PacketType::Pong, beacon_proto::net::SERVER_VIP, 0, 0, &p);
        relay.send_raw(&pong).await;
    }
    let s = wait_stats(&agent, "rtt", |s| s.rtt_ms.is_some() && s.pongs >= 3).await;
    assert!(s.rtt_ms.unwrap() < 1000);

    // ERROR(not registered) → REG again.
    relay.expect(PacketType::Reg).await;
    let err = relay.seal(
        PacketType::Error,
        beacon_proto::net::SERVER_VIP,
        0,
        0,
        &relay::encode_error(relay::error_code::NOT_REGISTERED),
    );
    relay.send_raw(&err).await;
    relay.expect(PacketType::Reg).await;

    // A new session (reconnect) re-registers on a new relay socket.
    let mut relay2 = FakeRelay::new().await;
    agent.set_session(Some(relay2.session())).await;
    let (_, h, _) = relay2.expect(PacketType::Reg).await;
    assert_eq!(h.src_vport, 8086);
    // BYE on the old session.
    relay.expect(PacketType::Bye).await;
    agent.set_session(None).await;
    relay2.expect(PacketType::Bye).await;
    wait_stats(&agent, "inactive", |s| !s.session_active).await;
    task.abort();
}

/// Regression: the relay socket is fresh when a session starts, and tokio's
/// `try_send_to` reports `WouldBlock` until the reactor has seen it writable. The
/// REGs of ports the game already holds (a reconnect mid-game) and the first PING
/// must still go out at once, not one housekeeping tick later.
#[tokio::test]
async fn session_start_sends_reg_and_ping_at_once() {
    let slow = AgentOptions {
        tick: Duration::from_secs(30),
        ..AgentOptions::default()
    };
    let (agent, task) = AgentHandle::start(slow).await.unwrap();
    let hook = FakeHook::new(&agent).await;
    hook.reg(8086).await;
    hook.reg(8094).await;
    // (`learn` does not publish stats; give the agent a moment to read both.)
    tokio::time::sleep(Duration::from_millis(100)).await;
    for round in 0..3 {
        let mut relay = FakeRelay::new().await;
        agent.set_session(Some(relay.session())).await;
        let mut seen = Vec::new();
        while seen.len() < 3 {
            let (_, h, _) = relay
                .recv(Duration::from_millis(500))
                .await
                .unwrap_or_else(|| panic!("round {round}: only {seen:?} at session start"));
            seen.push((h.kind, h.src_vport));
        }
        seen.sort_by_key(|&(k, p)| (k as u8, p));
        assert_eq!(
            seen,
            [(PacketType::Reg, 8086), (PacketType::Reg, 8094), (PacketType::Ping, 0)],
            "round {round}"
        );
    }
    assert_eq!(agent.stats().dropped_send, 0);
    task.abort();
}
