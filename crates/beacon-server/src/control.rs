//! TCP control channel (architecture §7).
//!
//! Per connection: admission (per-IP limits, failed-handshake ban) → plaintext
//! hello line → Noise `NNpsk0` responder handshake within the handshake timeout →
//! first message must be `hello` (same timeout) → `welcome`, lobby, recent chat →
//! message loop with idle timeout, per-connection rate limits and write timeouts.
//! A wrong password makes the first handshake message fail to decrypt; the
//! connection is closed silently and counted as a failure for the source IP.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use beacon_proto::control::{
    encode_frame, noise_builder, ClientMsg, ErrorCode, FrameDecoder, ServerMsg, MAX_FRAME_LEN,
    NOISE_MAX_MSG_LEN,
};
use beacon_proto::snow::TransportState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, watch};
use tokio::task::JoinSet;
use tokio::time::{timeout, Instant};
use tracing::{debug, info, warn};

use crate::hub::{Admission, Hub};
use crate::limits::TokenBucket;

/// Largest handshake frame accepted (NNpsk0 message 1 is 48 bytes).
pub const HANDSHAKE_FRAME_MAX: usize = 256;
/// A write that takes longer closes the connection.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Time granted to connections to say goodbye at shutdown.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
const READ_BUF: usize = 16 * 1024;
/// Rate-limited messages tolerated in a row before the connection is closed.
const MAX_STRIKES: u32 = 200;

/// Errors that end a connection.
#[derive(Debug)]
pub enum ConnError {
    /// Socket error.
    Io(std::io::Error),
    /// The peer closed the connection.
    Closed,
    /// A frame exceeded the limit (stream cannot be resynchronised).
    Frame,
    /// Noise failure (wrong password, tampering).
    Noise,
    /// A write did not finish in time.
    WriteTimeout,
    /// A message could not be encoded.
    Encode,
}

impl std::fmt::Display for ConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Closed => f.write_str("connection closed"),
            Self::Frame => f.write_str("oversized frame"),
            Self::Noise => f.write_str("decryption failed"),
            Self::WriteTimeout => f.write_str("write timeout"),
            Self::Encode => f.write_str("message too large"),
        }
    }
}

impl From<std::io::Error> for ConnError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Accepts connections until shutdown, then gives open connections
/// [`SHUTDOWN_GRACE`] to finish.
pub async fn accept_loop(listener: TcpListener, hub: Arc<Hub>, mut shutdown: watch::Receiver<bool>) {
    if let Ok(addr) = listener.local_addr() {
        info!(%addr, "control channel listening (TCP)");
    }
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => match hub.admit(peer) {
                    Ok(admission) => {
                        conns.spawn(handle_connection(
                            Arc::clone(&hub),
                            stream,
                            peer,
                            admission,
                            shutdown.clone(),
                        ));
                    }
                    Err(denied) => debug!(%peer, "connection refused: {denied}"),
                },
                Err(e) => {
                    // E.g. out of file descriptors: back off briefly.
                    warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
    drop(listener);
    let deadline = Instant::now() + SHUTDOWN_GRACE;
    while !conns.is_empty() {
        match tokio::time::timeout_at(deadline, conns.join_next()).await {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                conns.abort_all();
                while conns.join_next().await.is_some() {}
                break;
            }
        }
    }
}

/// Writes the hello line and runs the responder side of the Noise handshake.
async fn handshake(hub: &Hub, stream: &mut TcpStream) -> Result<(TransportState, FrameDecoder), ConnError> {
    stream.write_all(hub.hello_line()).await?;
    let mut hs = noise_builder(&hub.settings().psk.0)
        .and_then(|b| b.build_responder())
        .map_err(|_| ConnError::Noise)?;
    let mut decoder = FrameDecoder::with_max_len(HANDSHAKE_FRAME_MAX);
    let mut rbuf = [0u8; 512];
    let frame = loop {
        match decoder.pop() {
            Ok(Some(frame)) => break frame,
            Ok(None) => {}
            Err(_) => return Err(ConnError::Frame),
        }
        let n = stream.read(&mut rbuf).await?;
        if n == 0 {
            return Err(ConnError::Closed);
        }
        decoder.push(rbuf.get(..n).unwrap_or_default());
    };
    let mut buf = [0u8; 1024];
    hs.read_message(&frame, &mut buf)
        .map_err(|_| ConnError::Noise)?;
    let n = hs.write_message(&[], &mut buf).map_err(|_| ConnError::Noise)?;
    let mut out = Vec::with_capacity(n + 2);
    encode_frame(buf.get(..n).unwrap_or_default(), &mut out).map_err(|_| ConnError::Encode)?;
    stream.write_all(&out).await?;
    let transport = hs.into_transport_mode().map_err(|_| ConnError::Noise)?;
    decoder.set_max_len(MAX_FRAME_LEN);
    Ok((transport, decoder))
}

/// One authenticated connection.
struct Conn {
    stream: TcpStream,
    transport: TransportState,
    decoder: FrameDecoder,
    rbuf: Vec<u8>,
    noise: Vec<u8>,
    wbuf: Vec<u8>,
}

/// What [`Conn::next_msg`] found.
enum Incoming {
    /// A message.
    Msg(ClientMsg),
    /// A frame that decrypted but is not a valid message.
    Invalid(String),
}

impl Conn {
    fn new(stream: TcpStream, transport: TransportState, decoder: FrameDecoder) -> Self {
        Self {
            stream,
            transport,
            decoder,
            rbuf: vec![0u8; READ_BUF],
            noise: vec![0u8; NOISE_MAX_MSG_LEN],
            wbuf: Vec::new(),
        }
    }

    async fn send_json(&mut self, json: &[u8]) -> Result<(), ConnError> {
        let n = self
            .transport
            .write_message(json, &mut self.noise)
            .map_err(|_| ConnError::Encode)?;
        self.wbuf.clear();
        encode_frame(self.noise.get(..n).unwrap_or_default(), &mut self.wbuf)
            .map_err(|_| ConnError::Encode)?;
        match timeout(WRITE_TIMEOUT, self.stream.write_all(&self.wbuf)).await {
            Ok(result) => Ok(result?),
            Err(_) => Err(ConnError::WriteTimeout),
        }
    }

    async fn send(&mut self, msg: &ServerMsg) -> Result<(), ConnError> {
        let json = msg.to_json().map_err(|_| ConnError::Encode)?;
        self.send_json(&json).await
    }

    async fn send_error(&mut self, code: ErrorCode, text: &str) -> Result<(), ConnError> {
        self.send(&ServerMsg::Error {
            code,
            text: text.to_owned(),
        })
        .await
    }

    /// The next complete message from the buffered bytes, if any.
    fn next_msg(&mut self) -> Result<Option<Incoming>, ConnError> {
        let frame = match self.decoder.pop() {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(None),
            Err(_) => return Err(ConnError::Frame),
        };
        let n = self
            .transport
            .read_message(&frame, &mut self.noise)
            .map_err(|_| ConnError::Noise)?;
        let json = self.noise.get(..n).unwrap_or_default();
        Ok(Some(match ClientMsg::from_json(json) {
            Ok(msg) => Incoming::Msg(msg),
            Err(e) => Incoming::Invalid(e.to_string()),
        }))
    }

    /// Reads more bytes into the frame decoder.
    async fn fill(&mut self) -> Result<(), ConnError> {
        let n = self.stream.read(&mut self.rbuf).await?;
        if n == 0 {
            return Err(ConnError::Closed);
        }
        self.decoder.push(self.rbuf.get(..n).unwrap_or_default());
        Ok(())
    }

    /// Waits for the next message (used for `hello`).
    async fn recv(&mut self) -> Result<Incoming, ConnError> {
        loop {
            if let Some(incoming) = self.next_msg()? {
                return Ok(incoming);
            }
            self.fill().await?;
        }
    }
}

/// Removes the player from the lobby however the connection task ends
/// (including cancellation at shutdown).
struct LeaveGuard {
    hub: Arc<Hub>,
    id: u64,
}

impl Drop for LeaveGuard {
    fn drop(&mut self) {
        self.hub.leave(self.id);
    }
}

/// Per-connection rate limits.
struct Limiter {
    general: TokenBucket,
    chunks: TokenBucket,
    chat: TokenBucket,
    strikes: u32,
}

impl Limiter {
    fn new(hub: &Hub) -> Self {
        let l = &hub.settings().limits;
        let now = std::time::Instant::now();
        Self {
            general: TokenBucket::new(f64::from(l.control_msgs_per_s), f64::from(l.control_burst), now),
            chunks: TokenBucket::new(f64::from(l.map_chunks_per_s), f64::from(l.map_chunks_per_s), now),
            chat: TokenBucket::new(f64::from(l.chat_per_minute) / 60.0, f64::from(l.chat_burst), now),
            strikes: 0,
        }
    }

    /// Charges one received frame (valid or not) to its bucket: `None` if it may
    /// be handled, otherwise what to do instead (the first refusal in a row is
    /// answered with `rate_limited`; too many in a row close the connection).
    async fn charge(&mut self, conn: &mut Conn, map_chunk: bool) -> Result<Option<Flow>, ConnError> {
        let now = std::time::Instant::now();
        let allowed = if map_chunk {
            self.chunks.try_take(now)
        } else {
            self.general.try_take(now)
        };
        if allowed {
            self.strikes = 0;
            return Ok(None);
        }
        self.strikes = self.strikes.saturating_add(1);
        if self.strikes > MAX_STRIKES {
            debug!("closing a connection that keeps exceeding the rate limit");
            return Ok(Some(Flow::Close));
        }
        if self.strikes == 1 {
            conn.send_error(ErrorCode::RateLimited, "Zu viele Anfragen.").await?;
        }
        Ok(Some(Flow::Continue))
    }
}

enum Flow {
    Continue,
    Close,
}

async fn handle_connection(
    hub: Arc<Hub>,
    mut stream: TcpStream,
    peer: SocketAddr,
    mut admission: Admission,
    mut shutdown: watch::Receiver<bool>,
) {
    let _ = stream.set_nodelay(true);
    let settings_timeout = hub.settings().handshake_timeout;
    let (transport, decoder) = match timeout(settings_timeout, handshake(&hub, &mut stream)).await {
        Ok(Ok(t)) => {
            admission.handshake_done(true);
            t
        }
        Ok(Err(e)) => {
            admission.handshake_done(false);
            debug!(%peer, "handshake failed: {e}");
            return;
        }
        Err(_) => {
            admission.handshake_done(false);
            debug!(%peer, "handshake timeout");
            return;
        }
    };
    let mut conn = Conn::new(stream, transport, decoder);

    let hello = match timeout(settings_timeout, conn.recv()).await {
        Ok(Ok(Incoming::Msg(msg))) => msg,
        Ok(Ok(Incoming::Invalid(e))) => {
            debug!(%peer, "invalid first message: {e}");
            let _ = conn.send_error(ErrorCode::BadRequest, "Ungültige Nachricht.").await;
            return;
        }
        Ok(Err(e)) => {
            debug!(%peer, "connection ended before hello: {e}");
            return;
        }
        Err(_) => {
            debug!(%peer, "no hello in time");
            return;
        }
    };
    let ClientMsg::Hello {
        name,
        version,
        fingerprint,
    } = hello
    else {
        let _ = conn
            .send_error(ErrorCode::BadRequest, "Als Erstes wird `hello` erwartet.")
            .await;
        return;
    };
    let joined = match hub.join(&name, &version, fingerprint, peer) {
        Ok(j) => j,
        Err((code, text)) => {
            debug!(%peer, name, "login refused: {text}");
            let _ = conn.send_error(code, &text).await;
            return;
        }
    };
    let _leave = LeaveGuard {
        hub: Arc::clone(&hub),
        id: joined.id,
    };
    if !hub.activate_relay(&joined).await {
        let _ = conn.send_error(ErrorCode::Internal, "Relay nicht verfügbar.").await;
        return;
    }
    let welcome = ServerMsg::Welcome {
        session: joined.session,
        key: joined.key.clone(),
        vip: joined.vip,
        relay_port: hub.relay_port(),
        motd: hub.settings().motd.clone(),
        you_are_host: joined.is_host,
        features: Vec::new(),
    };
    let crate::hub::Joined {
        id,
        mut kick_rx,
        mut lobby_rx,
        mut events_rx,
        history,
        ..
    } = joined;
    let lobby_json = Arc::clone(&lobby_rx.borrow_and_update().json);
    let greeting = async {
        conn.send(&welcome).await?;
        conn.send_json(&lobby_json).await?;
        for line in &history {
            conn.send_json(line).await?;
        }
        Ok::<(), ConnError>(())
    };
    if let Err(e) = greeting.await {
        debug!(%peer, "welcome failed: {e}");
        return;
    }

    let idle_timeout = hub.settings().idle_timeout;
    let idle = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle);
    let mut limiter = Limiter::new(&hub);
    loop {
        // Handle everything already buffered before waiting again.
        loop {
            match conn.next_msg() {
                Ok(Some(incoming)) => {
                    idle.as_mut().reset(Instant::now() + idle_timeout);
                    let flow = match incoming {
                        Incoming::Msg(msg) => handle_msg(&hub, &mut conn, id, msg, &mut limiter).await,
                        Incoming::Invalid(e) => match limiter.charge(&mut conn, false).await {
                            Ok(None) => {
                                debug!(%peer, "invalid message: {e}");
                                conn.send_error(ErrorCode::BadRequest, "Ungültige Nachricht.")
                                    .await
                                    .map(|()| Flow::Continue)
                            }
                            Ok(Some(flow)) => Ok(flow),
                            Err(e) => Err(e),
                        },
                    };
                    match flow {
                        Ok(Flow::Continue) => {}
                        Ok(Flow::Close) => return,
                        Err(e) => {
                            debug!(%peer, "connection error: {e}");
                            return;
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    debug!(%peer, "connection error: {e}");
                    return;
                }
            }
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                let _ = conn.send(&ServerMsg::Kick { reason: "Der Server wird beendet.".to_owned() }).await;
                return;
            }
            changed = kick_rx.changed() => {
                let reason = kick_rx.borrow_and_update().clone();
                match (changed, reason) {
                    (_, Some(reason)) => {
                        let _ = conn.send(&ServerMsg::Kick { reason }).await;
                        return;
                    }
                    (Err(_), None) => return,
                    (Ok(()), None) => {}
                }
            }
            read = conn.stream.read(&mut conn.rbuf) => match read {
                Ok(0) => {
                    debug!(%peer, "connection closed by peer");
                    return;
                }
                Ok(n) => conn.decoder.push(conn.rbuf.get(..n).unwrap_or_default()),
                Err(e) => {
                    debug!(%peer, "read error: {e}");
                    return;
                }
            },
            changed = lobby_rx.changed() => {
                if changed.is_err() {
                    return;
                }
                let json = Arc::clone(&lobby_rx.borrow_and_update().json);
                if conn.send_json(&json).await.is_err() {
                    return;
                }
            }
            event = events_rx.recv() => match event {
                Ok(json) => {
                    if conn.send_json(&json).await.is_err() {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    debug!(%peer, "connection lagged, {n} events skipped");
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
            () = &mut idle => {
                debug!(%peer, "idle timeout");
                return;
            }
        }
    }
}

async fn handle_msg(
    hub: &Hub,
    conn: &mut Conn,
    id: u64,
    msg: ClientMsg,
    limiter: &mut Limiter,
) -> Result<Flow, ConnError> {
    if let Some(flow) = limiter
        .charge(conn, matches!(msg, ClientMsg::MapGet { .. }))
        .await?
    {
        return Ok(flow);
    }
    let now = std::time::Instant::now();
    let result: Result<(), (ErrorCode, String)> = match msg {
        ClientMsg::Hello { .. } => Err((ErrorCode::BadRequest, "Bereits angemeldet.".to_owned())),
        ClientMsg::FingerprintFiles { files, complete } => {
            hub.set_fingerprint_files(id, files, complete);
            Ok(())
        }
        ClientMsg::FingerprintGet { name } => match hub.fingerprint_files(&name) {
            Ok(answer) => {
                conn.send(&answer).await?;
                Ok(())
            }
            Err(e) => Err(e),
        },
        ClientMsg::Chat { text } => {
            if limiter.chat.try_take(now) {
                hub.chat(id, &text)
            } else {
                Err((
                    ErrorCode::RateLimited,
                    "Zu viele Nachrichten; bitte kurz warten.".to_owned(),
                ))
            }
        }
        ClientMsg::Ready { ready } => {
            hub.set_ready(id, ready);
            Ok(())
        }
        ClientMsg::LaunchAll => hub.launch_all(id),
        ClientMsg::Kick { name } => hub.kick(id, &name),
        ClientMsg::MapList => {
            let listing = hub.maps_listing();
            conn.send_json(&listing).await?;
            Ok(())
        }
        ClientMsg::MapGet { map, file, offset } => match hub.map_chunk(&map, &file, offset).await {
            Ok(chunk) => {
                conn.send(&ServerMsg::Chunk(chunk)).await?;
                Ok(())
            }
            Err(e) => Err(e),
        },
        ClientMsg::Ping { ts } => {
            conn.send(&ServerMsg::Pong { ts }).await?;
            Ok(())
        }
        ClientMsg::Status {
            in_game,
            rtt_ms,
            loss_pct,
            ..
        } => {
            hub.set_status(id, in_game, rtt_ms, loss_pct);
            Ok(())
        }
        ClientMsg::SetGameConfig { .. } | ClientMsg::Unknown => {
            debug!("ignoring an unknown message type");
            Ok(())
        }
    };
    if let Err((code, text)) = result {
        conn.send_error(code, &text).await?;
    }
    Ok(Flow::Continue)
}
