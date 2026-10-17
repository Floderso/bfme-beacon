//! Integration tests: the real server on 127.0.0.1 (ephemeral ports) with fake
//! clients built from beacon-proto only (hello line → Argon2id PSK → Noise
//! NNpsk0 → JSON control messages; sealed relay packets over UDP).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use beacon_proto::blake3;
use beacon_proto::control::{
    derive_psk, encode_frame, hello_line_len, noise_builder, ClientMsg, ErrorCode, FrameDecoder,
    KdfParams, MapInfo, Player, ServerHello, ServerMsg, CHUNK_MAX, NOISE_MAX_MSG_LEN, PSK_LEN,
};
use beacon_proto::fingerprint::{self, FileEntry};
use beacon_proto::net::{SERVER_VIP, VSUBNET_BROADCAST};
use beacon_proto::relay::{
    self, Direction, Header, PacketType, RelayKey, ReplayWindow, SendCounter, MAX_PACKET_LEN,
};
use beacon_proto::snow::TransportState;
use beacon_server::config::{Config, Settings};
use beacon_server::{hexfmt, RunningServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, Instant};

const PASSWORD: &str = "mellon-mellon";
const SALT: [u8; 16] = *b"beacon-test-salt";
/// Generous upper bound for anything that should happen.
const T: Duration = Duration::from_secs(5);
/// How long to wait for something that must NOT happen.
const QUIET: Duration = Duration::from_millis(300);

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

fn init_logging() {
    if std::env::var_os("BEACON_TEST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();
    }
}

/// Argon2id is slow in debug builds: derive each password once per test binary.
fn psk_for(password: &str) -> [u8; PSK_LEN] {
    static CACHE: OnceLock<Mutex<HashMap<String, [u8; PSK_LEN]>>> = OnceLock::new();
    let mut cache = CACHE.get_or_init(Default::default).lock().unwrap();
    *cache
        .entry(password.to_owned())
        .or_insert_with(|| derive_psk(password, &SALT, &KdfParams::DEFAULT).unwrap())
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "beacon-server-it-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(p.join("maps")).unwrap();
        Self(p)
    }

    fn maps(&self) -> PathBuf {
        self.0.join("maps")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct TestServer {
    server: Option<RunningServer>,
    dir: TempDir,
}

impl TestServer {
    async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    async fn start_with(tweak: impl FnOnce(&mut Settings)) -> Self {
        Self::start_in(TempDir::new(), tweak).await
    }

    async fn start_in(dir: TempDir, tweak: impl FnOnce(&mut Settings)) -> Self {
        init_logging();
        let cfg = Config {
            server_name: "Testserver".into(),
            motd: "Hallo Mittelerde".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            status_bind: "127.0.0.1:0".into(),
            salt: hexfmt::encode(&SALT),
            psk: hexfmt::encode(&psk_for(PASSWORD)),
            maps_dir: dir.maps().to_string_lossy().into_owned(),
            data_dir: dir.0.join("data").to_string_lossy().into_owned(),
            map_rescan_secs: 0,
            ..Config::default()
        };
        let mut settings = cfg.into_settings(&dir.0).unwrap();
        settings.lobby_refresh = Duration::from_millis(200);
        tweak(&mut settings);
        let server = beacon_server::start(settings).await.unwrap();
        Self {
            server: Some(server),
            dir,
        }
    }

    fn srv(&self) -> &RunningServer {
        self.server.as_ref().unwrap()
    }

    fn addr(&self) -> SocketAddr {
        self.srv().control_addr()
    }

    async fn login(&self, name: &str) -> Client {
        Client::login(self.addr(), self.srv().relay_addr(), name, None)
            .await
            .unwrap_or_else(|e| panic!("login {name}: {e:?}"))
    }

    async fn status(&self) -> serde_json::Value {
        let (code, body) = http_get(self.srv().status_addr().unwrap(), "/status").await;
        assert_eq!(code, 200);
        serde_json::from_str(&body).unwrap()
    }

    /// Polls `/status` until `pred` holds (relay statistics are published once
    /// per second).
    async fn status_until(&self, what: &str, pred: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
        let deadline = Instant::now() + T;
        loop {
            let status = self.status().await;
            if pred(&status) {
                return status;
            }
            assert!(Instant::now() < deadline, "status never showed {what}: {status}");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    async fn shutdown(&mut self) {
        if let Some(s) = self.server.take() {
            s.shutdown().await;
        }
    }
}

async fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    timeout(T, s.read_to_end(&mut buf)).await.unwrap().unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let code = text.get(9..12).unwrap().parse().unwrap();
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (code, body)
}

/// Connects and reads the plaintext hello line.
async fn raw_connect(addr: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.last() != Some(&b'\n') {
        let n = timeout(T, s.read(&mut byte)).await.unwrap().unwrap();
        assert_eq!(n, 1, "hello line expected");
        line.push(byte[0]);
    }
    assert!(line.starts_with(b"{\"beacon\":1"));
    s
}

/// `true` if the server closes `s` within `T` without sending anything.
async fn closed_silently(mut s: TcpStream) -> bool {
    let mut sink = Vec::new();
    match timeout(T, s.read_to_end(&mut sink)).await {
        Ok(Ok(_)) => sink.is_empty(),
        Ok(Err(_)) => true, // reset: also closed
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Fake client
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum LoginError {
    /// The server closed the connection during the handshake.
    Handshake(String),
    /// The server answered `hello` with an error.
    Refused(ErrorCode, String),
}

async fn read_frame(stream: &mut TcpStream, dec: &mut FrameDecoder) -> Option<Vec<u8>> {
    loop {
        if let Some(frame) = dec.pop().ok()? {
            return Some(frame);
        }
        let mut buf = [0u8; 16 * 1024];
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        dec.push(&buf[..n]);
    }
}

/// Connects, reads the hello line and runs the Noise handshake as initiator.
async fn handshake(
    addr: SocketAddr,
    password: &str,
) -> Result<(TcpStream, TransportState, FrameDecoder), String> {
    let mut stream = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let mut received = Vec::new();
    let line_len = loop {
        if let Some(n) = hello_line_len(&received).map_err(|e| e.to_string())? {
            break n;
        }
        let mut buf = [0u8; 1024];
        let n = timeout(T, stream.read(&mut buf))
            .await
            .map_err(|_| "no hello line".to_owned())?
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("closed before the hello line".into());
        }
        received.extend_from_slice(&buf[..n]);
    };
    let hello = ServerHello::from_line(&received[..line_len]).map_err(|e| e.to_string())?;
    assert_eq!(hello.name, "Testserver");
    assert_eq!(hello.salt, SALT);
    assert_eq!(hello.kdf, KdfParams::DEFAULT);
    let psk = psk_for(password);
    let mut hs = noise_builder(&psk).unwrap().build_initiator().unwrap();
    let mut dec = FrameDecoder::new();
    dec.push(&received[line_len..]);
    let mut buf = vec![0u8; NOISE_MAX_MSG_LEN];
    let n = hs.write_message(&[], &mut buf).unwrap();
    let mut wire = Vec::new();
    encode_frame(&buf[..n], &mut wire).unwrap();
    stream.write_all(&wire).await.map_err(|e| e.to_string())?;
    let frame = timeout(T, read_frame(&mut stream, &mut dec))
        .await
        .map_err(|_| "no handshake answer".to_owned())?
        .ok_or_else(|| "closed during the handshake".to_owned())?;
    hs.read_message(&frame, &mut buf).map_err(|e| e.to_string())?;
    Ok((stream, hs.into_transport_mode().unwrap(), dec))
}

struct Client {
    name: String,
    stream: TcpStream,
    transport: TransportState,
    decoder: FrameDecoder,
    session: u32,
    key: RelayKey,
    vip: Ipv4Addr,
    is_host: bool,
    motd: String,
    relay_port: u16,
    udp: UdpSocket,
    relay_addr: SocketAddr,
    counter: SendCounter,
    window: ReplayWindow,
}

impl Client {
    async fn login(
        addr: SocketAddr,
        relay_addr: SocketAddr,
        name: &str,
        fingerprint: Option<String>,
    ) -> Result<Self, LoginError> {
        Self::login_with(addr, relay_addr, name, fingerprint, PASSWORD).await
    }

    async fn login_with(
        addr: SocketAddr,
        relay_addr: SocketAddr,
        name: &str,
        fingerprint: Option<String>,
        password: &str,
    ) -> Result<Self, LoginError> {
        let (mut stream, mut transport, mut decoder) = handshake(addr, password)
            .await
            .map_err(LoginError::Handshake)?;
        let hello = ClientMsg::Hello {
            name: name.into(),
            version: "0.1.0-test".into(),
            fingerprint,
        };
        send_msg(&mut stream, &mut transport, &hello).await;
        let first = recv_msg(&mut stream, &mut transport, &mut decoder, T)
            .await
            .ok_or_else(|| LoginError::Handshake("no answer to hello".into()))?;
        match first {
            ServerMsg::Welcome {
                session,
                key,
                vip,
                relay_port,
                motd,
                you_are_host,
            } => Ok(Self {
                name: name.into(),
                stream,
                transport,
                decoder,
                session,
                key,
                vip,
                is_host: you_are_host,
                motd,
                relay_port,
                udp: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
                relay_addr,
                counter: SendCounter::new(),
                window: ReplayWindow::new(),
            }),
            ServerMsg::Error { code, text } => Err(LoginError::Refused(code, text)),
            other => panic!("unexpected answer to hello: {other:?}"),
        }
    }

    async fn send(&mut self, msg: &ClientMsg) {
        send_msg(&mut self.stream, &mut self.transport, msg).await;
    }

    async fn recv_within(&mut self, d: Duration) -> Option<ServerMsg> {
        recv_msg(&mut self.stream, &mut self.transport, &mut self.decoder, d).await
    }

    /// The next message matching `pred`, skipping others.
    async fn expect(&mut self, what: &str, pred: impl Fn(&ServerMsg) -> bool) -> ServerMsg {
        let deadline = Instant::now() + T;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.recv_within(left).await {
                Some(msg) if pred(&msg) => return msg,
                Some(_) => {}
                None => panic!("{}: timed out waiting for {what}", self.name),
            }
        }
    }

    /// Waits until both predicates matched a message (in any order).
    async fn expect_both(&mut self, what: &str, p1: impl Fn(&ServerMsg) -> bool, p2: impl Fn(&ServerMsg) -> bool) {
        let deadline = Instant::now() + T;
        let (mut seen1, mut seen2) = (false, false);
        while !(seen1 && seen2) {
            let left = deadline.saturating_duration_since(Instant::now());
            let msg = self
                .recv_within(left)
                .await
                .unwrap_or_else(|| panic!("{}: timed out waiting for {what}", self.name));
            seen1 |= p1(&msg);
            seen2 |= p2(&msg);
        }
    }

    async fn expect_lobby(&mut self, what: &str, pred: impl Fn(&[Player]) -> bool) -> Vec<Player> {
        match self
            .expect(what, |m| matches!(m, ServerMsg::Lobby { players } if pred(players)))
            .await
        {
            ServerMsg::Lobby { players } => players,
            _ => unreachable!(),
        }
    }

    async fn expect_error(&mut self, code: ErrorCode) -> String {
        match self
            .expect(&format!("error {code:?}"), |m| matches!(m, ServerMsg::Error { code: c, .. } if *c == code))
            .await
        {
            ServerMsg::Error { text, .. } => text,
            _ => unreachable!(),
        }
    }

    async fn expect_chat(&mut self, from: &str, text_part: &str) {
        self.expect(&format!("chat from {from:?} with {text_part:?}"), |m| {
            matches!(m, ServerMsg::Chat { from: f, text, .. } if f == from && text.contains(text_part))
        })
        .await;
    }

    /// `true` if the server closes the connection within `d` (messages skipped).
    async fn closed_within(&mut self, d: Duration) -> bool {
        let deadline = Instant::now() + d;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            let mut buf = [0u8; 4096];
            match timeout(left, self.stream.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                Ok(Ok(n)) => self.decoder.push(&buf[..n]),
                Err(_) => return false,
            }
        }
    }

    // --- relay ---

    fn seal(&self, kind: PacketType, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        seal_as(&self.key, self.session, &self.counter, kind, dst, sport, dport, payload)
    }

    async fn send_raw(&self, bytes: &[u8]) {
        self.udp.send_to(bytes, self.relay_addr).await.unwrap();
    }

    async fn data(&self, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let p = self.seal(PacketType::Data, dst, sport, dport, payload);
        self.send_raw(&p).await;
        p
    }

    async fn reg(&mut self, vport: u16) {
        let p = self.seal(PacketType::Reg, SERVER_VIP, vport, 0, &[]);
        self.send_raw(&p).await;
        let (h, _) = self
            .recv_relay(T, |h| h.kind == PacketType::RegAck)
            .await
            .unwrap_or_else(|| panic!("{}: no REG_ACK for {vport}", self.name));
        assert_eq!((h.src_vport, h.dst_vport, h.vip), (vport, vport, SERVER_VIP));
    }

    async fn recv_raw(&self, d: Duration) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 2048];
        let (n, from) = timeout(d, self.udp.recv_from(&mut buf)).await.ok()?.ok()?;
        assert_eq!(from, self.relay_addr);
        buf.truncate(n);
        Some(buf)
    }

    /// The next authenticated, non-duplicate packet matching `pred`.
    async fn recv_relay(&mut self, d: Duration, pred: impl Fn(&Header) -> bool) -> Option<(Header, Vec<u8>)> {
        let deadline = Instant::now() + d;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let mut raw = self.recv_raw(left).await?;
            if let Ok((h, range)) =
                relay::open_with_window(&self.key, Direction::ServerToClient, &mut raw, &mut self.window)
            {
                if pred(&h) {
                    return Some((h, raw[range].to_vec()));
                }
            }
        }
    }

    async fn recv_data(&mut self, d: Duration) -> Option<(Header, Vec<u8>)> {
        self.recv_relay(d, |h| h.kind == PacketType::Data).await
    }
}

#[allow(clippy::too_many_arguments)]
fn seal_as(
    key: &RelayKey,
    session: u32,
    counter: &SendCounter,
    kind: PacketType,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let h = Header::client(kind, session, counter.next().unwrap(), dst, sport, dport);
    let mut out = [0u8; MAX_PACKET_LEN];
    let n = relay::seal(key, Direction::ClientToServer, &h, payload, &mut out).unwrap();
    out[..n].to_vec()
}

async fn send_msg(stream: &mut TcpStream, transport: &mut TransportState, msg: &ClientMsg) {
    let json = msg.to_json().unwrap();
    let mut buf = vec![0u8; NOISE_MAX_MSG_LEN];
    let n = transport.write_message(&json, &mut buf).unwrap();
    let mut wire = Vec::new();
    encode_frame(&buf[..n], &mut wire).unwrap();
    stream.write_all(&wire).await.unwrap();
}

async fn recv_msg(
    stream: &mut TcpStream,
    transport: &mut TransportState,
    decoder: &mut FrameDecoder,
    d: Duration,
) -> Option<ServerMsg> {
    let frame = timeout(d, read_frame(stream, decoder)).await.ok()??;
    let mut buf = vec![0u8; NOISE_MAX_MSG_LEN];
    let n = transport.read_message(&frame, &mut buf).ok()?;
    Some(ServerMsg::from_json(&buf[..n]).unwrap())
}

fn player<'a>(status: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    status["players"]
        .as_array()
        .and_then(|a| a.iter().find(|p| p["name"] == name))
        .unwrap_or(&serde_json::Value::Null)
}

fn vip(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(198, 18, 0, last)
}

// ---------------------------------------------------------------------------
// Control channel
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_fails_and_repeated_failures_ban_the_ip() {
    let mut srv = TestServer::start_with(|s| s.limits.handshake_failures = 2).await;
    for _ in 0..2 {
        let err = Client::login_with(srv.addr(), srv.srv().relay_addr(), "Frodo", None, "melon")
            .await
            .err()
            .expect("wrong password must fail");
        assert!(matches!(&err, LoginError::Handshake(m) if !m.is_empty()), "{err:?}");
    }
    // Banned now: even the right password is refused before the hello line.
    assert!(handshake(srv.addr(), PASSWORD).await.is_err(), "banned");
    let status = srv.status().await;
    assert_eq!(status["control"]["banned_ips"], 1);
    assert!(status["control"]["handshake_failures"].as_u64().unwrap() >= 2);
    assert!(status["control"]["connections_refused"].as_u64().unwrap() >= 1);
    srv.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_assigns_distinct_vips_keys_and_sessions() {
    let mut srv = TestServer::start().await;
    let mut a = srv.login("Frodo").await;
    let mut b = srv.login("Sam").await;
    assert_eq!((a.vip, b.vip), (vip(2), vip(3)));
    assert_ne!(a.key, b.key);
    assert_ne!(a.session, b.session);
    assert_ne!(a.session, 0);
    assert!(a.is_host && !b.is_host);
    assert_eq!(a.motd, "Hallo Mittelerde");
    assert_eq!(a.relay_port, srv.srv().relay_addr().port());
    assert_eq!(a.relay_port, srv.addr().port(), "one port number for TCP and UDP");

    // Duplicate names (any case) and invalid names are refused.
    let relay_addr = srv.srv().relay_addr();
    match Client::login(srv.addr(), relay_addr, "FRODO", None).await {
        Err(LoginError::Refused(ErrorCode::NameTaken, _)) => {}
        other => panic!("expected name_taken, got {:?}", other.err()),
    }
    match Client::login(srv.addr(), relay_addr, "Thirteen-Char", None).await {
        Err(LoginError::Refused(ErrorCode::BadName, _)) => {}
        other => panic!("expected bad_name, got {:?}", other.err()),
    }
    match Client::login(srv.addr(), relay_addr, "Frodo2", Some("not-hex".into())).await {
        Err(LoginError::Refused(ErrorCode::BadRequest, _)) => {}
        other => panic!("expected bad_request, got {:?}", other.err()),
    }

    // The vIP sticks to the name: Sam leaves, Merry gets a new address, Sam
    // comes back to his old one.
    drop(b.stream);
    a.expect_chat("", "Sam hat die Lobby verlassen").await;
    b = srv.login("Merry").await;
    assert_eq!(b.vip, vip(4));
    let sam = srv.login("sam").await;
    assert_eq!(sam.vip, vip(3));
    srv.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lobby_updates_ready_status_and_host_transfer() {
    let mut srv = TestServer::start().await;
    let mut a = srv.login("Frodo").await;
    a.expect_lobby("own entry", |p| p.len() == 1 && p[0].is_host).await;
    let mut b = srv.login("Sam").await;
    let players = a.expect_lobby("Sam joined", |p| p.len() == 2).await;
    assert_eq!(players[1].name, "Sam");
    assert_eq!(players[1].vip, vip(3));
    assert!(players[0].is_host && !players[1].is_host);
    a.expect_chat("", "Sam ist beigetreten").await;
    b.expect_lobby("full list", |p| p.len() == 2).await;

    b.send(&ClientMsg::Ready { ready: true }).await;
    a.expect_lobby("Sam ready", |p| p.len() == 2 && p[1].ready).await;
    b.send(&ClientMsg::Status {
        in_game: true,
        rtt_ms: Some(25),
        loss_pct: Some(1),
    })
    .await;
    let players = a
        .expect_lobby("Sam status", |p| p.len() == 2 && p[1].rtt_ms == Some(25))
        .await;
    assert!(players[1].in_game);
    assert_eq!(players[1].loss_pct, Some(1));

    // Unknown message types are ignored (forward compatibility).
    let mut buf = vec![0u8; NOISE_MAX_MSG_LEN];
    let n = b.transport.write_message(br#"{"t":"from_the_future","x":1}"#, &mut buf).unwrap();
    let mut wire = Vec::new();
    encode_frame(&buf[..n], &mut wire).unwrap();
    b.stream.write_all(&wire).await.unwrap();
    b.send(&ClientMsg::Ping { ts: 7 }).await;
    b.expect("pong", |m| matches!(m, ServerMsg::Pong { ts: 7 })).await;

    // The host leaves: Sam becomes host.
    drop(a);
    let players = b
        .expect_lobby("Frodo left", |p| p.len() == 1 && p[0].is_host)
        .await;
    assert_eq!(players[0].name, "Sam");
    b.expect_chat("", "Sam ist jetzt Host").await;
    srv.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chat_is_broadcast_sanitised_limited_and_replayed() {
    let mut srv = TestServer::start().await;
    let mut a = srv.login("Frodo").await;
    let mut b = srv.login("Sam").await;
    a.send(&ClientMsg::Chat {
        text: "  Hallo\nSam  ".into(),
    })
    .await;
    for c in [&mut a, &mut b] {
        let msg = c
            .expect("chat", |m| matches!(m, ServerMsg::Chat { from, .. } if from == "Frodo"))
            .await;
        let ServerMsg::Chat { text, ts, .. } = msg else { unreachable!() };
        assert_eq!(text, "Hallo Sam");
        assert!(ts > 1_600_000_000_000);
    }
    a.send(&ClientMsg::Chat { text: "x".repeat(301) }).await;
    a.expect_error(ErrorCode::BadRequest).await;
    a.send(&ClientMsg::Chat { text: " \t ".into() }).await;
    a.expect_error(ErrorCode::BadRequest).await;
    // Burst of 5, then rate limited (the over-long line above used one token).
    for i in 0..6 {
        a.send(&ClientMsg::Chat {
            text: format!("spam {i}"),
        })
        .await;
    }
    a.expect_error(ErrorCode::RateLimited).await;
    // A new player sees the recent chat.
    let mut c = srv.login("Merry").await;
    c.expect_chat("Frodo", "Hallo Sam").await;
    srv.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_actions_launch_and_kick() {
    let mut srv = TestServer::start().await;
    let mut a = srv.login("Frodo").await;
    let mut b = srv.login("Sam").await;
    b.send(&ClientMsg::LaunchAll).await;
    b.expect_error(ErrorCode::NotHost).await;
    b.send(&ClientMsg::Kick { name: "Frodo".into() }).await;
    b.expect_error(ErrorCode::NotHost).await;

    a.send(&ClientMsg::LaunchAll).await;
    a.expect("launch", |m| matches!(m, ServerMsg::Launch)).await;
    b.expect("launch", |m| matches!(m, ServerMsg::Launch)).await;
    a.send(&ClientMsg::LaunchAll).await;
    a.expect_error(ErrorCode::RateLimited).await;

    a.send(&ClientMsg::Kick { name: "Frodo".into() }).await;
    a.expect_error(ErrorCode::BadRequest).await;
    a.send(&ClientMsg::Kick { name: "Gollum".into() }).await;
    a.expect_error(ErrorCode::UnknownPlayer).await;

    a.send(&ClientMsg::Kick { name: "sam".into() }).await;
    let reason = match b.expect("kick", |m| matches!(m, ServerMsg::Kick { .. })).await {
        ServerMsg::Kick { reason } => reason,
        _ => unreachable!(),
    };
    assert!(reason.contains("Frodo"), "{reason}");
    assert!(b.closed_within(T).await, "kicked connection closes");
    a.expect_both(
        "kick notice and lobby update",
        |m| matches!(m, ServerMsg::Chat { from, text, .. } if from.is_empty() && text.contains("Sam wurde von Frodo entfernt")),
        |m| matches!(m, ServerMsg::Lobby { players } if players.len() == 1),
    )
    .await;
    // A kicked name cannot rejoin right away.
    match Client::login(srv.addr(), srv.srv().relay_addr(), "Sam", None).await {
        Err(LoginError::Refused(ErrorCode::BadRequest, text)) => assert!(text.contains("entfernt")),
        other => panic!("expected refusal, got {:?}", other.err()),
    }
    srv.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_names_take_the_host_role() {
    let mut srv = TestServer::start_with(|s| s.admin_names = vec!["Gandalf".into()]).await;
    let mut a = srv.login("Frodo").await;
    assert!(a.is_host);
    let g = srv.login("gandalf").await;
    assert!(g.is_host);
    a.expect_lobby("Gandalf host", |p| p.len() == 2 && p[1].is_host && !p[0].is_host)
        .await;
    a.expect_chat("", "gandalf ist jetzt Host").await;
    srv.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fingerprint_exchange() {
    let mut srv = TestServer::start().await;
    let fp = "ab".repeat(32);
    let mut a = Client::login(srv.addr(), srv.srv().relay_addr(), "Frodo", Some(fp.to_uppercase()))
        .await
        .unwrap();
    let players = a.expect_lobby("fingerprint", |p| p.len() == 1).await;
    assert_eq!(players[0].fingerprint.as_deref(), Some(fp.as_str()));
    let files = vec![
        FileEntry::from_content("lotrbfme.exe", b"exe"),
        FileEntry::from_content("BIG/ini.big", b"ini"),
    ];
    a.send(&ClientMsg::FingerprintFiles {
        files: files.clone(),
        complete: true,
    })
    .await;
    let combined = fingerprint::combine(&files);
    a.expect_lobby("combined fingerprint", |p| {
        p[0].fingerprint.as_deref() == Some(combined.as_str())
    })
    .await;
    let mut b = srv.login("Sam").await;
    b.send(&ClientMsg::FingerprintGet { name: "frodo".into() }).await;
    match b
        .expect("fingerprint_files", |m| matches!(m, ServerMsg::FingerprintFiles { .. }))
        .await
    {
        ServerMsg::FingerprintFiles {
            name,
            files: got,
            complete,
        } => {
            assert_eq!(name, "Frodo");
            assert_eq!(got, files);
            assert!(complete);
        }
        _ => unreachable!(),
    }
    b.send(&ClientMsg::FingerprintGet { name: "Sam".into() }).await;
    b.expect_error(ErrorCode::UnknownPlayer).await;
    b.send(&ClientMsg::FingerprintGet { name: "Nobody".into() }).await;
    b.expect_error(ErrorCode::UnknownPlayer).await;
    srv.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_and_silent_connections_are_dropped() {
    let mut srv = TestServer::start_with(|s| {
        s.idle_timeout = Duration::from_millis(800);
        s.handshake_timeout = Duration::from_millis(800);
    })
    .await;
    // Logged in but silent: dropped after the idle timeout.
    let mut a = srv.login("Frodo").await;
    let mut b = srv.login("Sam").await;
    // Sam keeps pinging (and stays) while Frodo is silent.
    let pinger = async {
        let mut frodo_gone = false;
        for i in 0..8 {
            b.send(&ClientMsg::Ping { ts: i }).await;
            loop {
                match b.recv_within(T).await.expect("Sam must stay connected") {
                    ServerMsg::Pong { ts } => {
                        assert_eq!(ts, i);
                        break;
                    }
                    ServerMsg::Lobby { players } => {
                        frodo_gone |= players.len() == 1 && players[0].name == "Sam";
                    }
                    _ => {}
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        frodo_gone
    };
    let (closed, frodo_gone) = tokio::join!(a.closed_within(T), pinger);
    assert!(closed, "idle session dropped");
    assert!(frodo_gone, "Sam saw Frodo leave");
    // Connected but no handshake at all: dropped after the handshake timeout.
    let mut s = TcpStream::connect(srv.addr()).await.unwrap();
    let mut buf = vec![0u8; 2048];
    let mut total = 0;
    let closed = timeout(T, async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return true,
                Ok(n) => total += n,
            }
        }
    })
    .await
    .unwrap();
    assert!(closed && total > 0, "hello line, then closed");
    srv.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn garbage_on_tcp_and_udp_is_ignored() {
    let mut srv = TestServer::start().await;
    // TCP: an HTTP request instead of a Noise frame.
    let mut s = raw_connect(srv.addr()).await;
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    assert!(closed_silently(s).await, "HTTP garbage: closed without an answer");
    // TCP: a frame announcing 60 000 bytes during the handshake.
    let mut s = raw_connect(srv.addr()).await;
    s.write_all(&[0xEA, 0x60, 1, 2, 3]).await.unwrap();
    assert!(closed_silently(s).await, "oversized frame: closed");
    // TCP: a well-sized frame of random bytes.
    let mut s = raw_connect(srv.addr()).await;
    let mut frame = vec![0, 48];
    frame.extend((0..48u8).map(|i| i.wrapping_mul(37)));
    s.write_all(&frame).await.unwrap();
    assert!(closed_silently(s).await, "random handshake: closed");

    // UDP garbage of every length class.
    let junk = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = srv.srv().relay_addr();
    let mut valid_header = Header::client(PacketType::Data, 0xdead_beef, 1, vip(2), 8086, 8086)
        .encode()
        .to_vec();
    valid_header.extend_from_slice(&[0u8; 16]);
    let mut wrong_type = valid_header.clone();
    wrong_type[3] = PacketType::Pong.as_u8();
    let samples: Vec<Vec<u8>> = vec![
        vec![],
        vec![0xBE],
        vec![0u8; 39],
        vec![0u8; 40],
        (0..520u32).map(|i| (i * 31 % 251) as u8).collect(),
        vec![0xAB; 1400],
        vec![0xCD; 9000],
        valid_header,
        wrong_type,
    ];
    for sample in &samples {
        junk.send_to(sample, relay_addr).await.unwrap();
    }
    // The server still works for real clients.
    let mut a = srv.login("Frodo").await;
    let mut b = srv.login("Sam").await;
    a.reg(8086).await;
    b.reg(8086).await;
    a.data(b.vip, 8086, 8086, b"still alive").await;
    let (_, payload) = b.recv_data(T).await.expect("relay works after garbage");
    assert_eq!(payload, b"still alive");
    let mut buf = [0u8; 64];
    assert!(
        timeout(QUIET, junk.recv_from(&mut buf)).await.is_err(),
        "garbage is never answered"
    );
    let status = srv
        .status_until("garbage counters", |s| {
            s["relay"]["malformed"].as_u64().unwrap() >= 7
                && s["relay"]["unknown_session"].as_u64().unwrap() >= 1
        })
        .await;
    assert!(status["control"]["handshake_failures"].as_u64().unwrap() >= 3);
    srv.shutdown().await;
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_unicast_reaches_only_the_destination() {
    let mut srv = TestServer::start().await;
    let mut a = srv.login("Frodo").await;
    let mut b = srv.login("Sam").await;
    let mut c = srv.login("Merry").await;
    for client in [&mut a, &mut b, &mut c] {
        client.reg(8086).await;
    }
    a.data(b.vip, 8086, 8086, b"hello sam").await;
    let (h, payload) = b.recv_data(T).await.expect("unicast delivered");
    assert_eq!(payload, b"hello sam");
    assert_eq!(h.vip, a.vip, "true source vIP");
    assert_eq!((h.src_vport, h.dst_vport, h.session), (8086, 8086, 0));
    assert!(a.recv_data(QUIET).await.is_none(), "no echo");
    assert!(c.recv_data(QUIET).await.is_none(), "not to bystanders");

    // A vport the destination did not register: dropped silently.
    a.data(b.vip, 8086, 8094, b"not registered").await;
    // To a vIP nobody has, and to the sender's own vIP: dropped.
    a.data(vip(77), 8086, 8086, b"nobody").await;
    a.data(a.vip, 8086, 8086, b"myself").await;
    assert!(b.recv_data(QUIET).await.is_none());
    assert!(a.recv_data(QUIET).await.is_none());
    // In-game port after registration: delivered with two copies.
    b.reg(8094).await;
    a.data(b.vip, 8094, 8094, b"in game").await;
    let (h, payload) = b.recv_data(T).await.unwrap();
    assert_eq!((payload.as_slice(), h.dst_vport), (&b"in game"[..], 8094));
    srv.status_until("no_route >= 3", |s| s["relay"]["no_route"].as_u64().unwrap() >= 3)
        .await;
    srv.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broadcast_reaches_everybody_else_and_is_never_echoed() {
    let mut srv = TestServer::start().await;
    let mut a = srv.login("Frodo").await;
    let mut b = srv.login("Sam").await;
    let mut c = srv.login("Merry").await;
    let mut d = srv.login("Pippin").await;
    for client in [&mut a, &mut b, &mut c] {
        client.reg(8086).await;
    }
    d.reg(8087).await;
    for (i, dst) in [Ipv4Addr::BROADCAST, VSUBNET_BROADCAST].into_iter().enumerate() {
        let payload = format!("announce {i}");
        a.data(dst, 8086, 8086, payload.as_bytes()).await;
        for client in [&mut b, &mut c] {
            let (h, got) = client.recv_data(T).await.expect("broadcast delivered");
            assert_eq!(got, payload.as_bytes());
            assert_eq!(h.vip, a.vip);
        }
        assert!(a.recv_data(QUIET).await.is_none(), "never echoed to the sender");
        assert!(d.recv_data(Duration::from_millis(50)).await.is_none(), "port not registered");
    }
    // After UNREG, Merry no longer gets broadcasts on that port.
    let unreg = c.seal(PacketType::Unreg, SERVER_VIP, 8086, 0, &[]);
    c.send_raw(&unreg).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    a.data(Ipv4Addr::BROADCAST, 8086, 8086, b"after unreg").await;
    assert!(b.recv_data(T).await.is_some());
    assert!(c.recv_data(QUIET).await.is_none());
    srv.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redundant_copies_are_identical_and_deduplicated() {
    let mut srv = TestServer::start().await;
    let mut a = srv.login("Frodo").await;
    let mut b = srv.login("Sam").await;
    a.reg(8086).await;
    b.reg(8086).await;
    b.reg(8094).await;
    // The agent sends its own redundant copies: one sealed packet, three times.
    let packet = a.seal(PacketType::Data, b.vip, 8086, 8086, b"lobby message");
    for _ in 0..3 {
        a.send_raw(&packet).await;
    }
    // The server forwards it once, with its own redundancy: 3 copies on lobby
    // ports, all byte-identical (same counter).
    let mut copies = Vec::new();
    let deadline = Instant::now() + Duration::from_millis(400);
    while let Some(raw) = b.recv_raw(deadline.saturating_duration_since(Instant::now())).await {
        copies.push(raw);
    }
    assert_eq!(copies.len(), 3, "3 copies for a lobby port");
    assert!(copies.iter().all(|c| *c == copies[0]));
    let mut delivered = 0;
    let mut duplicates = 0;
    for mut raw in copies {
        match relay::open_with_window(&b.key, Direction::ServerToClient, &mut raw, &mut b.window) {
            Ok((_, range)) => {
                assert_eq!(&raw[range], b"lobby message");
                delivered += 1;
            }
            Err(relay::Error::Replayed { .. }) => duplicates += 1,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert_eq!((delivered, duplicates), (1, 2));

    // In-game port: 2 copies.
    a.data(b.vip, 8094, 8094, b"game").await;
    let mut n = 0;
    let deadline = Instant::now() + Duration::from_millis(400);
    while b.recv_raw(deadline.saturating_duration_since(Instant::now())).await.is_some() {
        n += 1;
    }
    assert_eq!(n, 2, "2 copies for a game port");
    let status = srv
        .status_until("Frodo forwarded 2", |s| player(s, "Frodo")["relay"]["forwarded"] == 2)
        .await;
    let frodo = player(&status, "Frodo");
    assert_eq!(frodo["relay"]["duplicates"], 2, "{frodo}");
    assert!(status["relay"]["copies_sent"].as_u64().unwrap() >= 3);
    srv.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replayed_packets_are_rejected() {
    let mut srv = TestServer::start().await;
    let mut a = srv.login("Frodo").await;
    let mut b = srv.login("Sam").await;
    a.reg(8086).await;
    b.reg(8086).await;
    let packet = a.data(b.vip, 8086, 8086, b"once").await;
    assert_eq!(b.recv_data(T).await.unwrap().1, b"once");
    // Drain the server's redundant copies.
    while b.recv_raw(Duration::from_millis(100)).await.is_some() {}
    tokio::time::sleep(Duration::from_millis(50)).await;
    // An attacker (any source address) replays the captured packet.
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    attacker.send_to(&packet, srv.srv().relay_addr()).await.unwrap();
    a.send_raw(&packet).await;
    assert!(b.recv_raw(QUIET).await.is_none(), "replay not forwarded");
    // A packet far older than the 256-entry window is rejected as well.
    for _ in 0..300 {
        a.counter.next();
    }
    a.data(b.vip, 8086, 8086, b"newer").await;
    assert_eq!(b.recv_data(T).await.unwrap().1, b"newer");
    a.send_raw(&packet).await;
    while b.recv_raw(Duration::from_millis(100)).await.is_some() {}
    assert!(b.recv_raw(QUIET).await.is_none());
    srv.status_until("3 duplicates", |s| s["relay"]["duplicates"].as_u64().unwrap() >= 3)
        .await;
    srv.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spoofed_sources_are_rejected_and_endpoints_follow_authenticated_packets() {
    let mut srv = TestServer::start().await;
    let mut a = srv.login("Frodo").await;
    let mut b = srv.login("Sam").await;
    let mut c = srv.login("Merry").await;
    for client in [&mut a, &mut b, &mut c] {
        client.reg(8086).await;
    }
    // Frodo pretends to be Sam: Sam's session id, but Frodo's key.
    let forged = seal_as(&a.key, b.session, &SendCounter::starting_at(1000), PacketType::Data, c.vip, 8086, 8086, b"I am Sam");
    a.send_raw(&forged).await;
    // ... or with a guessed key.
    let guessed = seal_as(&RelayKey::from_bytes([0x42; 32]), b.session, &SendCounter::starting_at(2000), PacketType::Data, c.vip, 8086, 8086, b"I am Sam");
    a.send_raw(&guessed).await;
    // ... or flips bits in a genuine packet of Sam's.
    let mut tampered = b.seal(PacketType::Data, c.vip, 8086, 8086, b"genuine");
    let last = tampered.len() - 20;
    tampered[last] ^= 0x01;
    a.send_raw(&tampered).await;
    assert!(c.recv_data(QUIET).await.is_none(), "forged packets are not forwarded");

    // Sam's endpoint was not hijacked by the forgeries.
    b.data(c.vip, 8086, 8086, b"real sam").await;
    let (h, payload) = c.recv_data(T).await.expect("Sam still reaches Merry");
    assert_eq!((h.vip, payload.as_slice()), (b.vip, &b"real sam"[..]));
    a.data(c.vip, 8086, 8086, b"real frodo").await;
    let (h, _) = c.recv_data(T).await.unwrap();
    assert_eq!(h.vip, a.vip, "the source vIP is always the session's own");
    while c.recv_raw(Duration::from_millis(50)).await.is_some() {}

    // NAT rebinding: Merry continues from a new UDP port; the next authenticated
    // packet moves her endpoint.
    c.udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ping = c.seal(PacketType::Ping, SERVER_VIP, 0, 0, &relay::encode_timestamp(99));
    c.send_raw(&ping).await;
    let (h, payload) = c.recv_relay(T, |h| h.kind == PacketType::Pong).await.expect("pong");
    assert_eq!(relay::decode_timestamp(&payload).unwrap(), 99);
    assert_eq!(h.vip, SERVER_VIP);
    a.data(c.vip, 8086, 8086, b"after rebinding").await;
    assert_eq!(c.recv_data(T).await.unwrap().1, b"after rebinding");

    srv.status_until("3 auth failures", |s| s["relay"]["auth_failed"].as_u64().unwrap() >= 3)
        .await;
    srv.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_rate_limit_and_stats() {
    let mut srv = TestServer::start_with(|s| {
        s.limits.relay_pps = 50;
        s.limits.relay_burst = 20;
    })
    .await;
    let mut a = srv.login("Frodo").await;
    let mut b = srv.login("Sam").await;
    a.reg(8086).await;
    b.reg(8090).await;
    for i in 0..60u32 {
        a.data(b.vip, 8086, 8090, &i.to_le_bytes()).await;
    }
    // An ERROR(RATE_LIMITED) comes back to the sender.
    let (_, payload) = a
        .recv_relay(T, |h| h.kind == PacketType::Error)
        .await
        .expect("rate limit error");
    assert_eq!(relay::decode_error(&payload).unwrap(), relay::error_code::RATE_LIMITED);
    let mut got = 0;
    while b.recv_data(Duration::from_millis(200)).await.is_some() {
        got += 1;
    }
    assert!((15..60).contains(&got), "got {got}");
    let status = srv
        .status_until("rate limit stats", |s| {
            let f = player(s, "Frodo");
            f["relay"]["rate_limited"].as_u64().unwrap_or(0) > 0 && f["relay"]["upstream_loss_pct"].is_number()
        })
        .await;
    let frodo = player(&status, "Frodo");
    assert!(frodo["relay"]["rx_pkts"].as_u64().unwrap() >= 60, "{frodo}");
    assert_eq!(frodo["relay"]["vports"], serde_json::json!([8086]));
    assert!(frodo["relay"]["endpoint"].as_str().unwrap().starts_with("127.0.0.1:"));
    assert_eq!(frodo["relay"]["upstream_loss_pct"], 0, "{frodo}");
    srv.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_loss_is_estimated_from_counter_gaps() {
    let mut srv = TestServer::start().await;
    let mut a = srv.login("Frodo").await;
    let mut b = srv.login("Sam").await;
    a.reg(8086).await;
    // 40 packets, every 4th "lost" (counter consumed but never sent): 25 %.
    for i in 0..40u32 {
        let p = a.seal(PacketType::Data, b.vip, 8086, 8086, &i.to_le_bytes());
        if i % 4 != 3 {
            a.send_raw(&p).await;
        }
    }
    let players = b
        .expect_lobby("loss shown", |p| p.iter().any(|x| x.name == "Frodo" && x.loss_pct.is_some()))
        .await;
    let loss = players.iter().find(|p| p.name == "Frodo").unwrap().loss_pct.unwrap();
    // 9 of 40 expected counters are missing; a stats tick in the middle of the
    // burst shifts the smoothed value a little.
    assert!((15..=30).contains(&loss), "loss {loss}");
    srv.shutdown().await;
}

// ---------------------------------------------------------------------------
// Maps, status, shutdown
// ---------------------------------------------------------------------------

fn write_file(path: &Path, data: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, data).unwrap();
}

async fn download(c: &mut Client, map: &str, file: &str) -> Vec<u8> {
    let mut data = Vec::new();
    loop {
        c.send(&ClientMsg::MapGet {
            map: map.into(),
            file: file.into(),
            offset: data.len() as u64,
        })
        .await;
        let chunk = match c.expect("chunk", |m| matches!(m, ServerMsg::Chunk(_))).await {
            ServerMsg::Chunk(chunk) => chunk,
            _ => unreachable!(),
        };
        assert_eq!((chunk.map.as_str(), chunk.file.as_str()), (map, file));
        assert_eq!(chunk.offset, data.len() as u64);
        let bytes = chunk.data().unwrap();
        assert!(bytes.len() <= CHUNK_MAX);
        data.extend_from_slice(&bytes);
        if chunk.eof {
            return data;
        }
        assert_eq!(bytes.len(), CHUNK_MAX, "only the last chunk may be short");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn map_list_and_download_with_integrity_check() {
    let dir = TempDir::new();
    let big: Vec<u8> = (0..CHUNK_MAX * 2 + 123).map(|i| (i * 7 % 253) as u8).collect();
    write_file(&dir.maps().join("Helms Deep/helms deep.map"), &big);
    write_file(&dir.maps().join("Helms Deep/map.ini"), b"; ini");
    write_file(&dir.maps().join("Helms Deep/art/preview.tga"), &[1, 2, 3, 4]);
    write_file(&dir.maps().join("Empty Map/zero.str"), b"");
    let mut srv = TestServer::start_in(dir, |_| {}).await;
    let mut c = srv.login("Frodo").await;
    c.send(&ClientMsg::MapList).await;
    let maps: Vec<MapInfo> = match c.expect("maps", |m| matches!(m, ServerMsg::Maps { .. })).await {
        ServerMsg::Maps { maps } => maps,
        _ => unreachable!(),
    };
    let names: Vec<_> = maps.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, ["Empty Map", "Helms Deep"]);
    for map in &maps {
        for file in &map.files {
            let data = download(&mut c, &map.name, &file.path).await;
            assert_eq!(data.len() as u64, file.size);
            assert_eq!(blake3::hash(&data).to_hex().to_string(), file.blake3_hex, "{}", file.path);
        }
    }
    let helm = maps.iter().find(|m| m.name == "Helms Deep").unwrap();
    assert_eq!(helm.files.len(), 3);
    assert_eq!(helm.total_size, big.len() as u64 + 5 + 4);

    // Path tricks and bad requests.
    let cases: [(&str, &str, u64, ErrorCode); 8] = [
        ("..", "x", 0, ErrorCode::UnknownMap),
        ("Mordor", "x.map", 0, ErrorCode::UnknownMap),
        ("Helms Deep", "../../config.toml", 0, ErrorCode::UnknownFile),
        ("Helms Deep", "/etc/passwd", 0, ErrorCode::UnknownFile),
        ("Helms Deep", "C:\\Windows\\win.ini", 0, ErrorCode::UnknownFile),
        ("Helms Deep", "art/../map.ini", 0, ErrorCode::UnknownFile),
        ("Helms Deep", "nope.map", 0, ErrorCode::UnknownFile),
        ("Helms Deep", "map.ini", 6, ErrorCode::BadOffset),
    ];
    for (map, file, offset, code) in cases {
        c.send(&ClientMsg::MapGet {
            map: map.into(),
            file: file.into(),
            offset,
        })
        .await;
        c.expect_error(code).await;
    }
    // A backslash path to a listed file works as well (answered with the
    // canonical path).
    c.send(&ClientMsg::MapGet {
        map: "Helms Deep".into(),
        file: "art\\preview.tga".into(),
        offset: 0,
    })
    .await;
    match c.expect("chunk", |m| matches!(m, ServerMsg::Chunk(_))).await {
        ServerMsg::Chunk(chunk) => {
            assert_eq!(chunk.file, "art/preview.tga");
            assert_eq!(chunk.data().unwrap(), [1, 2, 3, 4]);
            assert!(chunk.eof);
        }
        _ => unreachable!(),
    }

    // A new map appears after a rescan (SIGHUP / periodic in production).
    write_file(&srv.dir.maps().join("Isengard/isengard.map"), b"orthanc");
    srv.srv().rescan_maps();
    let deadline = Instant::now() + T;
    loop {
        c.send(&ClientMsg::MapList).await;
        let maps = match c.expect("maps", |m| matches!(m, ServerMsg::Maps { .. })).await {
            ServerMsg::Maps { maps } => maps,
            _ => unreachable!(),
        };
        if maps.iter().any(|m| m.name == "Isengard") {
            break;
        }
        assert!(Instant::now() < deadline, "rescan did not pick up the new map");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let status = srv.status().await;
    assert_eq!(status["maps"]["count"], 3);
    assert!(status["control"]["chunks_served"].as_u64().unwrap() >= 5);
    srv.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_endpoint_and_health() {
    let mut srv = TestServer::start().await;
    let status_addr = srv.srv().status_addr().unwrap();
    assert_eq!(http_get(status_addr, "/health").await, (200, "ok".to_owned()));
    assert_eq!(http_get(status_addr, "/nope").await.0, 404);
    // The CLI probe agrees.
    let probe = tokio::task::spawn_blocking(move || beacon_server::health::check(status_addr, T));
    assert!(probe.await.unwrap().is_ok());
    let mut a = srv.login("Frodo").await;
    a.reg(8086).await;
    let status = srv.status().await;
    assert_eq!(status["server"]["name"], "Testserver");
    assert_eq!(status["server"]["players"], 1);
    assert_eq!(status["server"]["host"], "Frodo");
    assert_eq!(status["server"]["port"], srv.addr().port());
    let p = &status["players"][0];
    assert_eq!(p["name"], "Frodo");
    assert_eq!(p["vip"], "198.18.0.2");
    assert_eq!(p["is_host"], true);
    assert_eq!(p["session"], format!("{:08x}", a.session));
    // Relay statistics are published once per second.
    srv.status_until("vports", |s| s["players"][0]["relay"]["vports"] == serde_json::json!([8086]))
        .await;
    srv.shutdown().await;
    // After shutdown the status endpoint is gone.
    assert!(TcpStream::connect(status_addr).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_kicks_players_and_says_bye_on_the_relay() {
    let mut srv = TestServer::start().await;
    let mut a = srv.login("Frodo").await;
    a.reg(8086).await;
    srv.shutdown().await;
    a.expect("kick", |m| matches!(m, ServerMsg::Kick { .. })).await;
    let bye = a.recv_relay(T, |h| h.kind == PacketType::Bye).await;
    assert!(bye.is_some(), "BYE on the relay");
    assert!(a.closed_within(T).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sticky_vips_survive_a_restart() {
    let dir = TempDir::new();
    let data_dir = dir.0.join("data");
    let mut srv = TestServer::start_in(dir, |_| {}).await;
    let a = srv.login("Frodo").await;
    let b = srv.login("Sam").await;
    assert_eq!((a.vip, b.vip), (vip(2), vip(3)));
    drop(a);
    // The table is written asynchronously.
    let file = data_dir.join(beacon_server::server::VIPS_FILE);
    let deadline = Instant::now() + T;
    while beacon_server::server::load_vips(&file).len() < 2 {
        assert!(Instant::now() < deadline, "vips.json not written");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    srv.shutdown().await;
    let dir = srv.dir;
    let mut srv = TestServer::start_in(dir, |_| {}).await;
    let s = srv.login("Sam").await;
    assert_eq!(s.vip, vip(3), "Sam keeps his address across restarts");
    let m = srv.login("Merry").await;
    assert_eq!(m.vip, vip(4));
    srv.shutdown().await;
    drop(b);
}
