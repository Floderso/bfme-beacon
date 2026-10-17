//! One control connection: [`connect_once`] (TCP, hello line, pin check, PSK,
//! Noise `NNpsk0` initiator, `hello` → `welcome`) and [`run`] (the lobby session).

use std::net::{Ipv4Addr, SocketAddr};

use beacon_proto::control::{
    self as pc, ClientMsg, FrameDecoder, KdfParams, ServerHello, ServerMsg, HANDSHAKE_TIMEOUT, HELLO_MAX_LEN,
    IDLE_TIMEOUT, MAX_FRAME_LEN, NOISE_MAX_MSG_LEN, PING_INTERVAL, PSK_LEN, SALT_LEN,
};
use beacon_proto::fingerprint::{FileEntry, Fingerprint};
use beacon_proto::net;
use beacon_proto::relay::RelayKey;
use beacon_proto::snow::TransportState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{timeout, Instant};
use tracing::{debug, warn};

use super::{
    Connected, ControlCmd, ControlError, ControlEvent, Credentials, ConnectParams, Deps, StatusReport,
    CONNECT_TIMEOUT, STATUS_INTERVAL, WRITE_TIMEOUT,
};
use crate::agent::RelaySession;
use crate::config::{check_pin, PinCheck, SecretError, ServerAddr};
use crate::util;

/// Largest Noise handshake frame accepted (the responder's message is 48 bytes).
const HANDSHAKE_FRAME_MAX: usize = 1024;
/// Addresses tried per connection attempt.
const MAX_ADDRS: usize = 4;

/// The PSK derived for one `(salt, kdf)`; reused for reconnects. Wiped on drop.
pub struct PskCache {
    salt: [u8; SALT_LEN],
    kdf: KdfParams,
    psk: [u8; PSK_LEN],
}

impl Drop for PskCache {
    fn drop(&mut self) {
        util::wipe(&mut self.psk);
    }
}

/// The `welcome` of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Welcome {
    /// Relay session id.
    pub session: u32,
    /// Relay key.
    pub key: RelayKey,
    /// Our vIP.
    pub vip: Ipv4Addr,
    /// Relay UDP port.
    pub relay_port: u16,
    /// Message of the day.
    pub motd: String,
    /// We are the host.
    pub you_are_host: bool,
}

/// An authenticated connection.
struct Conn {
    stream: TcpStream,
    transport: TransportState,
    decoder: FrameDecoder,
    noise: Vec<u8>,
    plain: Vec<u8>,
    out: Vec<u8>,
    rbuf: Vec<u8>,
}

impl Conn {
    fn new(stream: TcpStream, transport: TransportState, decoder: FrameDecoder) -> Self {
        Self {
            stream,
            transport,
            decoder,
            noise: vec![0u8; NOISE_MAX_MSG_LEN],
            plain: vec![0u8; NOISE_MAX_MSG_LEN],
            out: Vec::with_capacity(NOISE_MAX_MSG_LEN + 2),
            rbuf: vec![0u8; 16 * 1024],
        }
    }

    async fn send(&mut self, msg: &ClientMsg) -> Result<(), ControlError> {
        let json = msg.to_json().map_err(|e| ControlError::Protocol {
            message: format!("cannot encode a message: {e}"),
        })?;
        let n = self
            .transport
            .write_message(&json, &mut self.noise)
            .map_err(|e| ControlError::Protocol {
                message: format!("encryption failed: {e}"),
            })?;
        self.out.clear();
        pc::encode_frame(self.noise.get(..n).unwrap_or_default(), &mut self.out).map_err(|e| {
            ControlError::Protocol {
                message: e.to_string(),
            }
        })?;
        match timeout(WRITE_TIMEOUT, self.stream.write_all(&self.out)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(ControlError::io(&e)),
            Err(_) => Err(ControlError::Timeout { stage: "send".into() }),
        }
    }

    /// The next complete message already received, if any. Undecodable JSON is
    /// skipped (logged); a frame that fails to decrypt ends the session.
    fn next_msg(&mut self) -> Result<Option<ServerMsg>, ControlError> {
        loop {
            let frame = match self.decoder.pop() {
                Ok(Some(f)) => f,
                Ok(None) => return Ok(None),
                Err(e) => {
                    return Err(ControlError::Protocol {
                        message: e.to_string(),
                    })
                }
            };
            let n = self
                .transport
                .read_message(&frame, &mut self.plain)
                .map_err(|_| ControlError::Protocol {
                    message: "a message failed to decrypt".into(),
                })?;
            match ServerMsg::from_json(self.plain.get(..n).unwrap_or_default()) {
                Ok(ServerMsg::Unknown) => debug!("ignoring an unknown server message"),
                Ok(msg) => return Ok(Some(msg)),
                Err(e) => warn!("ignoring an invalid server message: {e}"),
            }
        }
    }

    async fn fill(&mut self, stage: &str) -> Result<(), ControlError> {
        match self.stream.read(&mut self.rbuf).await {
            Ok(0) => Err(ControlError::Closed { stage: stage.into() }),
            Ok(n) => {
                self.decoder.push(self.rbuf.get(..n).unwrap_or_default());
                Ok(())
            }
            Err(e) => Err(ControlError::io(&e)),
        }
    }

    async fn recv(&mut self, stage: &str) -> Result<ServerMsg, ControlError> {
        loop {
            if let Some(m) = self.next_msg()? {
                return Ok(m);
            }
            self.fill(stage).await?;
        }
    }
}

/// A logged-in connection, ready for [`run`].
pub struct Established {
    conn: Conn,
    /// The welcome.
    pub welcome: Welcome,
    /// Server name from the hello.
    pub server_name: String,
    /// Server address actually connected to.
    pub peer: SocketAddr,
    /// The identity was pinned by this login.
    pub newly_pinned: bool,
}

impl Established {
    /// The relay credentials for the agent.
    pub fn relay_session(&self) -> RelaySession {
        RelaySession {
            relay_addr: SocketAddr::new(self.peer.ip(), self.welcome.relay_port),
            session: self.welcome.session,
            key: self.welcome.key.clone(),
            vip: self.welcome.vip,
        }
    }

    /// Details for the app.
    pub fn connected(&self, addr: &ServerAddr) -> Connected {
        Connected {
            address: addr.key(),
            server_name: self.server_name.clone(),
            motd: self.welcome.motd.clone(),
            vip: self.welcome.vip,
            you_are_host: self.welcome.you_are_host,
            relay_addr: SocketAddr::new(self.peer.ip(), self.welcome.relay_port),
            newly_pinned: self.newly_pinned,
        }
    }
}

async fn read_hello(stream: &mut TcpStream) -> Result<(ServerHello, Vec<u8>), ControlError> {
    let mut buf = Vec::with_capacity(HELLO_MAX_LEN);
    let mut tmp = [0u8; 512];
    loop {
        match pc::hello_line_len(&buf) {
            Ok(Some(n)) => {
                let line = buf.get(..n).unwrap_or_default();
                let hello = ServerHello::from_line(line).map_err(|e| match e {
                    pc::Error::UnsupportedVersion(v) => ControlError::UnsupportedServer { version: v },
                    other => ControlError::NotBeacon {
                        message: other.to_string(),
                    },
                })?;
                return Ok((hello, buf.get(n..).unwrap_or_default().to_vec()));
            }
            Ok(None) => {}
            Err(_) => {
                return Err(ControlError::NotBeacon {
                    message: "no hello line".into(),
                })
            }
        }
        let n = stream.read(&mut tmp).await.map_err(|e| ControlError::io(&e))?;
        if n == 0 {
            return Err(ControlError::Closed { stage: "hello".into() });
        }
        buf.extend_from_slice(tmp.get(..n).unwrap_or_default());
    }
}

async fn read_frame(stream: &mut TcpStream, decoder: &mut FrameDecoder) -> Result<Vec<u8>, ControlError> {
    let mut tmp = [0u8; 1024];
    loop {
        match decoder.pop() {
            Ok(Some(f)) => return Ok(f),
            Ok(None) => {}
            Err(e) => {
                return Err(ControlError::Protocol {
                    message: e.to_string(),
                })
            }
        }
        let n = stream.read(&mut tmp).await.map_err(|e| ControlError::io(&e))?;
        if n == 0 {
            return Err(ControlError::Closed {
                stage: "handshake".into(),
            });
        }
        decoder.push(tmp.get(..n).unwrap_or_default());
    }
}

async fn connect_tcp(addr: &ServerAddr) -> Result<TcpStream, ControlError> {
    let lookup = timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((addr.host(), addr.port())))
        .await
        .map_err(|_| ControlError::Timeout {
            stage: "DNS lookup".into(),
        })?
        .map_err(|e| ControlError::Resolve {
            host: addr.host().to_owned(),
            message: e.to_string(),
        })?;
    let mut last = ControlError::Resolve {
        host: addr.host().to_owned(),
        message: "no address".into(),
    };
    for a in lookup.take(MAX_ADDRS) {
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(a)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Ok(Err(e)) => {
                last = ControlError::Connect {
                    address: a.to_string(),
                    message: e.to_string(),
                }
            }
            Err(_) => {
                last = ControlError::Timeout {
                    stage: format!("connect to {a}"),
                }
            }
        }
    }
    Err(last)
}

async fn obtain_psk(
    params: &ConnectParams,
    deps: &Deps,
    cache: &mut Option<PskCache>,
    hello: &ServerHello,
) -> Result<[u8; PSK_LEN], ControlError> {
    if let Some(c) = cache.as_ref().filter(|c| c.salt == hello.salt && c.kdf == hello.kdf) {
        return Ok(c.psk);
    }
    let psk = match &params.credentials {
        Credentials::Remembered => deps.config.remembered_psk(&params.addr).map_err(|e| match e {
            SecretError::NotRemembered => ControlError::NoRememberedPassword,
            other => ControlError::RememberedPasswordUnusable {
                message: other.to_string(),
            },
        })?,
        Credentials::Password(pw) => {
            let mut password = pw.clone();
            let (salt, kdf) = (hello.salt, hello.kdf);
            let derived = tokio::task::spawn_blocking(move || {
                let r = pc::derive_psk(&password, &salt, &kdf);
                util::wipe_string(&mut password);
                r
            })
            .await
            .map_err(|e| ControlError::Io {
                message: format!("key derivation task failed: {e}"),
            })?;
            derived.map_err(|e| match e {
                pc::Error::KdfParams(_) => ControlError::InsecureKdf,
                other => ControlError::Io {
                    message: other.to_string(),
                },
            })?
        }
        Credentials::Consumed => return Err(ControlError::AuthFailed),
    };
    *cache = Some(PskCache {
        salt: hello.salt,
        kdf: hello.kdf,
        psk,
    });
    Ok(psk)
}

/// One login attempt (see the module docs). On success the pin is stored (first
/// login) and, if requested, the key remembered; the plaintext password is wiped.
pub async fn connect_once(
    params: &mut ConnectParams,
    deps: &Deps,
    psk_cache: &mut Option<PskCache>,
) -> Result<Established, ControlError> {
    let mut stream = connect_tcp(&params.addr).await?;
    let peer = stream.peer_addr().map_err(|e| ControlError::io(&e))?;
    let (hello, leftover) = timeout(HANDSHAKE_TIMEOUT, read_hello(&mut stream))
        .await
        .map_err(|_| ControlError::Timeout { stage: "hello".into() })??;
    hello.kdf.validate().map_err(|_| ControlError::InsecureKdf)?;
    let newly_pinned = match check_pin(deps.config.pin(&params.addr).as_ref(), &hello) {
        PinCheck::Changed { pinned } => {
            return Err(ControlError::IdentityChanged {
                address: params.addr.key(),
                pinned_name: pinned.server_name,
                pinned_at_ms: pinned.pinned_at_ms,
                server_name: hello.name,
            })
        }
        PinCheck::Unpinned => true,
        PinCheck::Matches => false,
    };
    let _ = deps.emit(ControlEvent::Authenticating).await;
    let mut psk = obtain_psk(params, deps, psk_cache, &hello).await?;

    let handshake = async {
        let mut hs = pc::noise_builder(&psk)
            .and_then(|b| b.build_initiator())
            .map_err(|e| ControlError::Protocol {
                message: format!("noise setup: {e}"),
            })?;
        let mut noise = vec![0u8; HANDSHAKE_FRAME_MAX];
        let n = hs.write_message(&[], &mut noise).map_err(|e| ControlError::Protocol {
            message: format!("noise: {e}"),
        })?;
        let mut out = Vec::new();
        pc::encode_frame(noise.get(..n).unwrap_or_default(), &mut out).map_err(|e| ControlError::Protocol {
            message: e.to_string(),
        })?;
        stream.write_all(&out).await.map_err(|e| ControlError::io(&e))?;
        let mut decoder = FrameDecoder::with_max_len(HANDSHAKE_FRAME_MAX);
        decoder.push(&leftover);
        // A wrong PSK makes the server drop the connection instead of answering.
        let frame = read_frame(&mut stream, &mut decoder).await.map_err(|e| match e {
            ControlError::Closed { .. } | ControlError::Io { .. } => ControlError::AuthFailed,
            other => other,
        })?;
        hs.read_message(&frame, &mut noise).map_err(|_| ControlError::AuthFailed)?;
        let transport = hs.into_transport_mode().map_err(|e| ControlError::Protocol {
            message: format!("noise: {e}"),
        })?;
        decoder.set_max_len(MAX_FRAME_LEN);
        Ok::<_, ControlError>((transport, decoder))
    };
    let handshake = timeout(HANDSHAKE_TIMEOUT, handshake).await;
    let (transport, decoder) = match handshake {
        Ok(r) => r?,
        Err(_) => return Err(ControlError::Timeout { stage: "handshake".into() }),
    };
    let mut conn = Conn::new(stream, transport, decoder);
    let fingerprint = deps.fingerprint.borrow().as_ref().map(|f| f.digest_hex.clone());
    conn.send(&ClientMsg::Hello {
        name: params.name.clone(),
        version: crate::VERSION.to_owned(),
        fingerprint,
    })
    .await?;
    let first = timeout(HANDSHAKE_TIMEOUT, conn.recv("welcome"))
        .await
        .map_err(|_| ControlError::Timeout { stage: "welcome".into() })??;
    let welcome = match first {
        ServerMsg::Welcome {
            session,
            key,
            vip,
            relay_port,
            motd,
            you_are_host,
        } => Welcome {
            session,
            key,
            vip,
            relay_port,
            motd,
            you_are_host,
        },
        ServerMsg::Error { code, text } => return Err(ControlError::Rejected { code, text }),
        ServerMsg::Kick { reason } => return Err(ControlError::Kicked { reason }),
        _ => {
            return Err(ControlError::Protocol {
                message: "expected welcome".into(),
            })
        }
    };
    if !net::is_assignable(welcome.vip) || welcome.relay_port == 0 {
        return Err(ControlError::Protocol {
            message: format!("invalid welcome (vip {}, relay port {})", welcome.vip, welcome.relay_port),
        });
    }
    if let Err(e) = deps.config.store_pin(&params.addr, &hello) {
        warn!("cannot save the server pin: {e}");
    }
    if params.remember {
        params.remember = false;
        if let Err(e) = deps.config.remember_psk(&params.addr, &psk) {
            warn!("cannot remember the password: {e}");
        }
    }
    util::wipe(&mut psk);
    // The cached key serves reconnects; the plaintext password is not needed again.
    if matches!(params.credentials, Credentials::Password(_)) {
        params.credentials = Credentials::Consumed;
    }
    Ok(Established {
        conn,
        welcome,
        server_name: hello.name,
        peer,
        newly_pinned,
    })
}

/// The `fingerprint_files` message for `fp`, cut to fit into one message
/// (`complete: false` then).
pub fn fingerprint_files_msg(entries: &[FileEntry]) -> ClientMsg {
    let make = |n: usize, complete: bool| ClientMsg::FingerprintFiles {
        files: entries.get(..n).unwrap_or_default().to_vec(),
        complete,
    };
    let full = make(entries.len(), true);
    if full.to_json().is_ok() {
        return full;
    }
    let (mut lo, mut hi) = (0usize, entries.len());
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if make(mid, false).to_json().is_ok() {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    make(lo, false)
}

/// Paces `status` reports: an `in_game` change goes out at once, measurement
/// updates at most every [`STATUS_INTERVAL`].
#[derive(Debug, Default)]
pub struct StatusPacer {
    last: Option<(StatusReport, Instant)>,
    pending: Option<StatusReport>,
}

impl StatusPacer {
    /// A new report; returns it if it should be sent now.
    pub fn offer(&mut self, r: StatusReport, now: Instant) -> Option<StatusReport> {
        match self.last {
            None => Some(r),
            Some((prev, _)) if prev.in_game != r.in_game => Some(r),
            Some((prev, _)) if prev == r => {
                self.pending = None;
                None
            }
            Some((_, at)) if now.saturating_duration_since(at) >= STATUS_INTERVAL => Some(r),
            Some(_) => {
                self.pending = Some(r);
                None
            }
        }
    }

    /// A pending report whose interval has passed.
    pub fn due(&mut self, now: Instant) -> Option<StatusReport> {
        match (self.pending, self.last) {
            (Some(r), Some((_, at))) if now.saturating_duration_since(at) >= STATUS_INTERVAL => Some(r),
            _ => None,
        }
    }

    /// Records a sent report.
    pub fn sent(&mut self, r: StatusReport, now: Instant) {
        self.last = Some((r, now));
        self.pending = None;
    }
}

fn status_msg(r: StatusReport) -> ClientMsg {
    ClientMsg::Status {
        in_game: r.in_game,
        rtt_ms: r.rtt_ms,
        loss_pct: r.loss_pct,
    }
}

fn fingerprint_of(fp: &Fingerprint) -> ClientMsg {
    // All entries, including the build id: the server recomputes the digest from them.
    fingerprint_files_msg(&fp.entries)
}

/// Runs the session until the user disconnects (`Ok`) or the connection fails.
pub async fn run(est: Established, rx: &mut mpsc::Receiver<ControlCmd>, deps: &Deps) -> Result<(), ControlError> {
    let mut conn = est.conn;
    let mut status_rx = deps.status.clone();
    let mut fp_rx = deps.fingerprint.clone();
    let (mut status_open, mut fp_open) = (true, true);
    let epoch = Instant::now();
    let mut pacer = StatusPacer::default();

    let fp = fp_rx.borrow_and_update().clone();
    if let Some(fp) = fp {
        conn.send(&fingerprint_of(&fp)).await?;
    }
    let report = *status_rx.borrow_and_update();
    conn.send(&status_msg(report)).await?;
    pacer.sent(report, Instant::now());
    conn.send(&ClientMsg::MapList).await?;

    let mut ping = tokio::time::interval_at(epoch + PING_INTERVAL, PING_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_rx = Instant::now();
    loop {
        while let Some(msg) = conn.next_msg()? {
            last_rx = Instant::now();
            match msg {
                ServerMsg::Pong { .. } => {}
                ServerMsg::Kick { reason } => return Err(ControlError::Kicked { reason }),
                other => {
                    if !deps.emit(ControlEvent::Message(other)).await {
                        return Ok(());
                    }
                }
            }
        }
        tokio::select! {
            cmd = rx.recv() => match cmd {
                None | Some(ControlCmd::Disconnect) => return Ok(()),
                Some(ControlCmd::Send(msg)) => conn.send(&msg).await?,
            },
            r = conn.stream.read(&mut conn.rbuf) => match r {
                Ok(0) => return Err(ControlError::Closed { stage: "session".into() }),
                Ok(n) => conn.decoder.push(conn.rbuf.get(..n).unwrap_or_default()),
                Err(e) => return Err(ControlError::io(&e)),
            },
            _ = ping.tick() => {
                if last_rx.elapsed() > IDLE_TIMEOUT {
                    return Err(ControlError::IdleTimeout);
                }
                let ts = u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX);
                conn.send(&ClientMsg::Ping { ts }).await?;
                let now = Instant::now();
                if let Some(r) = pacer.due(now) {
                    conn.send(&status_msg(r)).await?;
                    pacer.sent(r, now);
                }
            },
            changed = status_rx.changed(), if status_open => {
                if changed.is_err() {
                    status_open = false;
                    continue;
                }
                let report = *status_rx.borrow_and_update();
                let now = Instant::now();
                if let Some(r) = pacer.offer(report, now) {
                    conn.send(&status_msg(r)).await?;
                    pacer.sent(r, now);
                }
            },
            changed = fp_rx.changed(), if fp_open => {
                if changed.is_err() {
                    fp_open = false;
                    continue;
                }
                let fp = fp_rx.borrow_and_update().clone();
                if let Some(fp) = fp {
                    conn.send(&fingerprint_of(&fp)).await?;
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn fingerprint_list_is_cut_to_fit() {
        let small: Vec<FileEntry> = (0..10)
            .map(|i| FileEntry::new(&format!("f{i}.big"), i, &"a".repeat(64)))
            .collect();
        assert!(matches!(
            fingerprint_files_msg(&small),
            ClientMsg::FingerprintFiles { ref files, complete: true } if files.len() == 10
        ));
        let huge: Vec<FileEntry> = (0..5000)
            .map(|i| FileEntry::new(&format!("data/some/long/path/file{i:05}.ini"), i, &"b".repeat(64)))
            .collect();
        let msg = fingerprint_files_msg(&huge);
        let ClientMsg::FingerprintFiles { files, complete } = &msg else {
            panic!("wrong message");
        };
        assert!(!complete);
        assert!(files.len() > 100 && files.len() < 5000);
        assert!(msg.to_json().is_ok());
        let one_more = ClientMsg::FingerprintFiles {
            files: huge[..files.len() + 1].to_vec(),
            complete: false,
        };
        assert!(one_more.to_json().is_err(), "the cut is maximal");
    }

    #[test]
    fn status_pacing() {
        let t0 = Instant::now();
        let r = |in_game, rtt| StatusReport {
            in_game,
            rtt_ms: Some(rtt),
            loss_pct: None,
        };
        let mut p = StatusPacer::default();
        assert_eq!(p.offer(r(false, 10), t0), Some(r(false, 10)));
        p.sent(r(false, 10), t0);
        assert_eq!(p.offer(r(false, 10), t0 + Duration::from_secs(9)), None, "unchanged");
        assert_eq!(p.offer(r(false, 12), t0 + Duration::from_secs(1)), None, "paced");
        assert_eq!(p.due(t0 + Duration::from_secs(4)), None);
        assert_eq!(p.due(t0 + STATUS_INTERVAL), Some(r(false, 12)));
        assert_eq!(p.offer(r(true, 12), t0 + Duration::from_secs(1)), Some(r(true, 12)), "in_game at once");
        p.sent(r(true, 12), t0 + Duration::from_secs(1));
        assert_eq!(p.due(t0 + Duration::from_secs(100)), None);
        assert_eq!(p.offer(r(true, 20), t0 + Duration::from_secs(7)), Some(r(true, 20)));
    }
}
