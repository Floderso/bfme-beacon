//! Control client (architecture §7): TCP to `host:port` (default 28086), plaintext
//! hello line, TOFU pin check, Argon2id PSK, Noise `NNpsk0` initiator, `hello`
//! → `welcome`, then the lobby session (ping every 5 s, status reports, every
//! [`ServerMsg`]). A supervisor task reconnects with exponential backoff while the
//! user wants to be connected; permanent errors (changed identity, wrong
//! password, refused name, kick) stop it.
//!
//! * [`session`] – one connection: [`session::connect_once`] and [`session::run`].
//! * [`spawn`] – the supervisor; it drives the agent's relay session and reports
//!   [`ControlEvent`]s to the app.

pub mod session;

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use beacon_proto::control::{ClientMsg, ErrorCode, ServerMsg};
use beacon_proto::fingerprint::Fingerprint;
use serde::Serialize;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::agent::AgentHandle;
use crate::config::{ConfigStore, ServerAddr};
use crate::util;

/// TCP connect timeout per address.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// Write timeout for control messages.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// First reconnect delay.
pub const BACKOFF_MIN: Duration = Duration::from_secs(1);
/// Longest reconnect delay.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Longest reconnect delay while BFME runs: the game raises its disconnect screen
/// after 8 s without a packet from a peer and drops the peer about 20 s later
/// (spec 02 §6), so a restarted server must be found again within seconds.
pub const BACKOFF_MAX_IN_GAME: Duration = Duration::from_secs(2);
/// Status reports with unchanged `in_game` are sent at most this often.
pub const STATUS_INTERVAL: Duration = Duration::from_secs(5);
/// `AuthFailed` after the key already worked in this connection is retried this
/// often before it counts as a wrong password: the server answers a wrong key by
/// closing the connection, which a connection reset during the handshake of a
/// reconnect looks exactly like. (Each failure counts towards the server's ban of
/// the IP after 5, which players behind the same NAT share.)
pub const AUTH_RETRIES_AFTER_LOGIN: u32 = 2;
/// The `kick` reason beacon-server sends to every player when it stops (restart,
/// update; `beacon-server/src/control.rs`). That is no removal: the supervisor
/// reconnects once the server is back (`tests/app.rs` keeps the text in sync).
pub const SERVER_STOPPING_REASON: &str = "Der Server wird beendet.";

/// How the user authenticates.
pub enum Credentials {
    /// The server password (wiped once the key is derived).
    Password(String),
    /// The DPAPI-protected key remembered for this server.
    Remembered,
    /// The password was used and wiped; reconnects use the cached key.
    Consumed,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Password(_) => "Password(<redacted>)",
            Self::Remembered => "Remembered",
            Self::Consumed => "Consumed",
        })
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        if let Self::Password(p) = self {
            util::wipe_string(p);
        }
    }
}

/// What to connect to.
#[derive(Debug)]
pub struct ConnectParams {
    /// Server address.
    pub addr: ServerAddr,
    /// Player name.
    pub name: String,
    /// Password or remembered key.
    pub credentials: Credentials,
    /// Store the derived key (DPAPI) after a successful login.
    pub remember: bool,
}

/// Typed control-channel errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ControlError {
    /// DNS lookup failed.
    Resolve {
        /// Host name.
        host: String,
        /// Reason.
        message: String,
    },
    /// TCP connect failed.
    Connect {
        /// Address.
        address: String,
        /// Reason.
        message: String,
    },
    /// No answer in time.
    Timeout {
        /// What was awaited.
        stage: String,
    },
    /// The server closed the connection.
    Closed {
        /// During what.
        stage: String,
    },
    /// The peer does not speak the Beacon protocol.
    NotBeacon {
        /// Reason.
        message: String,
    },
    /// The server uses another protocol version.
    UnsupportedServer {
        /// Its version.
        version: u32,
    },
    /// The hello announces KDF parameters outside the accepted bounds.
    InsecureKdf,
    /// Salt or KDF differ from the pinned identity: no login until the pin is reset.
    IdentityChanged {
        /// Server address.
        address: String,
        /// Name stored with the pin.
        pinned_name: String,
        /// When the pin was stored.
        pinned_at_ms: u64,
        /// Name the server announces now.
        server_name: String,
    },
    /// "Remembered" was requested but nothing is stored.
    NoRememberedPassword,
    /// The remembered key cannot be decrypted.
    RememberedPasswordUnusable {
        /// Reason.
        message: String,
    },
    /// The Noise handshake failed: wrong password (or the IP is banned for a while).
    AuthFailed,
    /// The server refused the login or a request.
    Rejected {
        /// Machine-readable reason.
        code: ErrorCode,
        /// Text from the server.
        text: String,
    },
    /// The host (or the server) removed us.
    Kicked {
        /// Reason.
        reason: String,
    },
    /// The server is stopping (restart, update): reconnect.
    ServerStopped {
        /// Text from the server.
        reason: String,
    },
    /// Malformed data from the server.
    Protocol {
        /// Reason.
        message: String,
    },
    /// I/O error.
    Io {
        /// Reason.
        message: String,
    },
    /// Nothing received for longer than the idle timeout.
    IdleTimeout,
}

impl ControlError {
    /// Errors that end the reconnect loop.
    pub fn is_permanent(&self) -> bool {
        match self {
            Self::NotBeacon { .. }
            | Self::UnsupportedServer { .. }
            | Self::InsecureKdf
            | Self::IdentityChanged { .. }
            | Self::NoRememberedPassword
            | Self::RememberedPasswordUnusable { .. }
            | Self::AuthFailed
            | Self::Kicked { .. } => true,
            Self::Rejected { code, .. } => !matches!(
                code,
                ErrorCode::NameTaken | ErrorCode::ServerFull | ErrorCode::RateLimited | ErrorCode::Internal
            ),
            _ => false,
        }
    }

    /// The error for a `kick` with `reason`: a stopping server is not a removal.
    pub fn kicked(reason: String) -> Self {
        if reason == SERVER_STOPPING_REASON {
            Self::ServerStopped { reason }
        } else {
            Self::Kicked { reason }
        }
    }

    pub(crate) fn io(e: &std::io::Error) -> Self {
        Self::Io {
            message: e.to_string(),
        }
    }
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve { host, message } => write!(f, "cannot resolve {host}: {message}"),
            Self::Connect { address, message } => write!(f, "cannot connect to {address}: {message}"),
            Self::Timeout { stage } => write!(f, "timeout ({stage})"),
            Self::Closed { stage } => write!(f, "the server closed the connection ({stage})"),
            Self::NotBeacon { message } => write!(f, "not a Beacon server: {message}"),
            Self::UnsupportedServer { version } => {
                write!(f, "the server speaks protocol version {version}; update Beacon")
            }
            Self::InsecureKdf => f.write_str("the server announces insecure key-derivation parameters"),
            Self::IdentityChanged {
                address,
                pinned_name,
                server_name,
                ..
            } => write!(
                f,
                "the identity of {address} changed (pinned: {pinned_name:?}, now: {server_name:?}). \
                 If the server's password was changed on purpose, reset the pin; otherwise someone \
                 may be impersonating the server"
            ),
            Self::NoRememberedPassword => f.write_str("no password remembered for this server"),
            Self::RememberedPasswordUnusable { message } => write!(f, "{message}"),
            Self::AuthFailed => f.write_str("login failed: wrong password (or this IP is temporarily blocked)"),
            Self::Rejected { code, text } => write!(f, "refused by the server ({code:?}): {text}"),
            Self::Kicked { reason } => write!(f, "removed from the server: {reason}"),
            Self::ServerStopped { reason } => write!(f, "the server is stopping ({reason})"),
            Self::Protocol { message } => write!(f, "protocol error: {message}"),
            Self::Io { message } => write!(f, "connection error: {message}"),
            Self::IdleTimeout => f.write_str("the server stopped answering"),
        }
    }
}

impl std::error::Error for ControlError {}

/// What the agent measures, reported to the server via `status`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatusReport {
    /// The game is running.
    pub in_game: bool,
    /// Relay RTT.
    pub rtt_ms: Option<u32>,
    /// Relay loss.
    pub loss_pct: Option<u8>,
}

/// Details of an established session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connected {
    /// Server address.
    pub address: String,
    /// Server name (hello).
    pub server_name: String,
    /// Message of the day.
    pub motd: String,
    /// Our vIP.
    pub vip: Ipv4Addr,
    /// We are the host.
    pub you_are_host: bool,
    /// Relay endpoint.
    pub relay_addr: SocketAddr,
    /// The identity was pinned now (first login).
    pub newly_pinned: bool,
}

/// Events from the supervisor.
#[derive(Debug, Clone)]
pub enum ControlEvent {
    /// Connecting (attempt number, 1-based).
    Connecting {
        /// Attempt.
        attempt: u32,
    },
    /// Hello received, authenticating.
    Authenticating,
    /// Logged in.
    Connected(Connected),
    /// A server message (everything except `pong` and `kick`).
    Message(ServerMsg),
    /// Disconnected; `retry_in` = `None` when the supervisor stopped.
    Disconnected {
        /// Why (`None` = the user disconnected).
        error: Option<ControlError>,
        /// Next attempt.
        retry_in: Option<Duration>,
    },
}

/// Commands to the supervisor.
#[derive(Debug)]
pub enum ControlCmd {
    /// Send a message (dropped while not connected).
    Send(ClientMsg),
    /// Disconnect and stop.
    Disconnect,
}

/// What the supervisor needs from the app.
#[derive(Debug, Clone)]
pub struct Deps {
    /// Pins and remembered keys.
    pub config: Arc<ConfigStore>,
    /// The data plane.
    pub agent: AgentHandle,
    /// Event sink; every event carries [`generation`](Self::generation).
    pub events: mpsc::Sender<(u64, ControlEvent)>,
    /// Identifies this supervisor's events (the app ignores older generations).
    pub generation: u64,
    /// Status to report.
    pub status: watch::Receiver<StatusReport>,
    /// The game-data fingerprint once computed.
    pub fingerprint: watch::Receiver<Option<Arc<Fingerprint>>>,
}

/// Handle to a running supervisor.
#[derive(Debug)]
pub struct ControlHandle {
    cmd: mpsc::Sender<ControlCmd>,
    task: JoinHandle<()>,
}

impl ControlHandle {
    /// Queues a message; `false` if the supervisor is gone or the queue is full.
    pub fn send(&self, msg: ClientMsg) -> bool {
        self.cmd.try_send(ControlCmd::Send(msg)).is_ok()
    }

    /// Queues a message, waiting for queue space.
    pub async fn send_wait(&self, msg: ClientMsg) -> bool {
        self.cmd.send(ControlCmd::Send(msg)).await.is_ok()
    }

    /// Disconnects and waits (bounded) for the supervisor to finish.
    pub async fn disconnect(self) {
        let _ = self.cmd.send(ControlCmd::Disconnect).await;
        let mut task = self.task;
        if tokio::time::timeout(Duration::from_secs(5), &mut task).await.is_err() {
            warn!("control task did not stop in time");
            task.abort();
        }
    }

    /// `true` once the supervisor has stopped.
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

/// Reconnect delay for attempt `n` (1-based): 1 s, 2 s, 4 s … 30 s, + up to 25 %
/// jitter.
pub fn backoff(attempt: u32, jitter: u32) -> Duration {
    backoff_capped(attempt, jitter, BACKOFF_MAX)
}

/// Reconnect delay while BFME runs: 1 s, then [`BACKOFF_MAX_IN_GAME`], + jitter.
pub fn backoff_in_game(attempt: u32, jitter: u32) -> Duration {
    backoff_capped(attempt, jitter, BACKOFF_MAX_IN_GAME)
}

fn backoff_capped(attempt: u32, jitter: u32, max: Duration) -> Duration {
    let exp = attempt.saturating_sub(1).min(5);
    let base = BACKOFF_MIN.saturating_mul(1 << exp).min(max);
    let extra = base / 4 * (jitter % 1000) / 1000;
    (base + extra).min(max + max / 4)
}

/// Decides which failed attempts end the supervisor.
#[derive(Debug, Default)]
pub struct RetryPolicy {
    logged_in: bool,
    auth_failures: u32,
}

impl RetryPolicy {
    /// A login succeeded (the key is right).
    pub fn logged_in(&mut self) {
        self.logged_in = true;
        self.auth_failures = 0;
    }

    /// `true` if `error` ends the reconnect loop.
    pub fn gives_up(&mut self, error: &ControlError) -> bool {
        if matches!(error, ControlError::AuthFailed) && self.logged_in {
            self.auth_failures = self.auth_failures.saturating_add(1);
            return self.auth_failures > AUTH_RETRIES_AFTER_LOGIN;
        }
        error.is_permanent()
    }
}

/// Starts the supervisor for `params`.
pub fn spawn(params: ConnectParams, deps: Deps) -> ControlHandle {
    let (cmd, rx) = mpsc::channel(64);
    let task = tokio::spawn(supervise(params, deps, rx));
    ControlHandle { cmd, task }
}

impl Deps {
    /// Sends an event tagged with the generation; `false` if the app is gone.
    pub async fn emit(&self, ev: ControlEvent) -> bool {
        self.events.send((self.generation, ev)).await.is_ok()
    }
}

async fn emit(deps: &Deps, ev: ControlEvent) -> bool {
    deps.emit(ev).await
}

/// Waits for a `Disconnect` (or the handle being dropped), discarding sends.
async fn wait_for_disconnect(rx: &mut mpsc::Receiver<ControlCmd>) {
    loop {
        match rx.recv().await {
            None | Some(ControlCmd::Disconnect) => return,
            Some(ControlCmd::Send(msg)) => {
                tracing::debug!("not connected; dropping {:?}", std::mem::discriminant(&msg));
            }
        }
    }
}

/// The supervisor. The agent's relay session outlives a failed control connection
/// until the next login replaces it, the server ends it (relay `BYE`) or the
/// supervisor stops: a control connection can break while the server still holds
/// the player (half-open TCP after a new public IP, a reset by a middlebox), and
/// then the relay, which follows NAT rebinding, keeps the running game going while
/// the reconnect waits for the server to release the name (`name_taken`).
async fn supervise(params: ConnectParams, deps: Deps, mut rx: mpsc::Receiver<ControlCmd>) {
    supervise_loop(params, &deps, &mut rx).await;
    deps.agent.set_session(None).await;
}

async fn supervise_loop(mut params: ConnectParams, deps: &Deps, rx: &mut mpsc::Receiver<ControlCmd>) {
    let mut psk_cache = None;
    let mut attempt: u32 = 0;
    let mut policy = RetryPolicy::default();
    loop {
        attempt = attempt.saturating_add(1);
        if !emit(deps, ControlEvent::Connecting { attempt }).await {
            return;
        }
        let result = tokio::select! {
            r = session::connect_once(&mut params, deps, &mut psk_cache) => r,
            () = wait_for_disconnect(rx) => {
                emit(deps, ControlEvent::Disconnected { error: None, retry_in: None }).await;
                return;
            }
        };
        let error = match result {
            Ok(est) => {
                attempt = 0;
                policy.logged_in();
                let session = est.relay_session();
                info!(server = %params.addr, vip = %est.welcome.vip, "logged in");
                deps.agent.set_session(Some(session)).await;
                if !emit(deps, ControlEvent::Connected(est.connected(&params.addr))).await {
                    return;
                }
                match session::run(est, rx, deps).await {
                    Ok(()) => {
                        emit(deps, ControlEvent::Disconnected { error: None, retry_in: None }).await;
                        return;
                    }
                    Err(e) => e,
                }
            }
            Err(e) => e,
        };
        if policy.gives_up(&error) {
            warn!(server = %params.addr, "{error}");
            emit(deps, ControlEvent::Disconnected { error: Some(error), retry_in: None }).await;
            return;
        }
        let delay = if deps.status.borrow().in_game {
            backoff_in_game(attempt, util::random_u32())
        } else {
            backoff(attempt, util::random_u32())
        };
        warn!(server = %params.addr, "{error}; retrying in {:.1} s", delay.as_secs_f32());
        if !emit(
            deps,
            ControlEvent::Disconnected {
                error: Some(error),
                retry_in: Some(delay),
            },
        )
        .await
        {
            return;
        }
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = wait_for_disconnect(rx) => {
                emit(deps, ControlEvent::Disconnected { error: None, retry_in: None }).await;
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_caps() {
        let secs = |a| backoff(a, 0).as_secs();
        assert_eq!([secs(1), secs(2), secs(3), secs(4), secs(5), secs(6), secs(50)], [1, 2, 4, 8, 16, 30, 30]);
        assert_eq!(backoff(1, 999), Duration::from_micros(1_249_750));
        assert!(backoff(u32::MAX, u32::MAX) <= BACKOFF_MAX + BACKOFF_MAX / 4);
    }

    #[test]
    fn in_game_backoff_stays_short() {
        let ms = |a| backoff_in_game(a, 0).as_millis();
        assert_eq!([ms(1), ms(2), ms(3), ms(50)], [1000, 2000, 2000, 2000]);
        assert!(backoff_in_game(u32::MAX, 999) <= BACKOFF_MAX_IN_GAME + BACKOFF_MAX_IN_GAME / 4);
    }

    #[test]
    fn auth_failure_after_a_login_is_retried_a_little() {
        let mut p = RetryPolicy::default();
        assert!(p.gives_up(&ControlError::AuthFailed), "never logged in: wrong password");
        let mut p = RetryPolicy::default();
        p.logged_in();
        for _ in 0..AUTH_RETRIES_AFTER_LOGIN {
            assert!(!p.gives_up(&ControlError::AuthFailed));
            assert!(!p.gives_up(&ControlError::Closed { stage: "hello".into() }));
        }
        assert!(p.gives_up(&ControlError::AuthFailed), "the key really is wrong now");
        p.logged_in();
        assert!(!p.gives_up(&ControlError::AuthFailed), "a new login resets the count");
        assert!(p.gives_up(&ControlError::Kicked { reason: String::new() }));
        assert!(!p.gives_up(&ControlError::Rejected { code: ErrorCode::NameTaken, text: String::new() }));
    }

    #[test]
    fn permanent_errors() {
        assert!(ControlError::AuthFailed.is_permanent());
        assert!(ControlError::Kicked { reason: String::new() }.is_permanent());
        // A server restart kicks everybody with a fixed text: reconnect, do not give up.
        assert!(!ControlError::kicked(SERVER_STOPPING_REASON.into()).is_permanent());
        assert!(ControlError::kicked("Du wurdest von Host entfernt.".into()).is_permanent());
        assert!(ControlError::Rejected { code: ErrorCode::BadName, text: String::new() }.is_permanent());
        assert!(!ControlError::Rejected { code: ErrorCode::NameTaken, text: String::new() }.is_permanent());
        assert!(!ControlError::IdleTimeout.is_permanent());
        assert!(!ControlError::Closed { stage: "x".into() }.is_permanent());
        let json = serde_json::to_value(ControlError::Rejected {
            code: ErrorCode::NameTaken,
            text: "t".into(),
        })
        .unwrap();
        assert_eq!(json["kind"], "rejected");
        assert_eq!(json["code"], "name_taken");
    }

    #[test]
    fn credentials_are_redacted() {
        let c = Credentials::Password("geheim".into());
        assert!(!format!("{c:?}").contains("geheim"));
    }
}
