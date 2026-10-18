//! Status endpoint: `GET /health` → `ok` (503 if the relay loop stalled) and
//! `GET /status` → JSON with players, relay statistics, control counters and the
//! map repository. Meant for localhost / the Docker host only (it shows player
//! endpoints).

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use beacon_proto::control::ConfigStatus;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::hub::Hub;
use crate::relay::{RelayTotals, SessionStats};
use crate::{lock, unix_ms};

/// The relay publishes statistics every second; older than this = stalled.
const RELAY_STALE: Duration = Duration::from_secs(5);

/// `GET /status`.
#[derive(Debug, Serialize)]
pub struct StatusDoc {
    /// Server facts.
    pub server: ServerStatus,
    /// Connected players in join order.
    pub players: Vec<PlayerStatus>,
    /// Relay totals.
    pub relay: RelayTotals,
    /// Source IPs the relay currently ignores.
    pub relay_blocked_ips: usize,
    /// Control channel counters.
    pub control: ControlStatus,
    /// Map repository.
    pub maps: MapsStatus,
}

/// Server facts.
#[derive(Debug, Serialize)]
pub struct ServerStatus {
    /// Server name.
    pub name: String,
    /// Version.
    pub version: &'static str,
    /// Seconds since start.
    pub uptime_s: u64,
    /// Start time (ms since the Unix epoch).
    pub started_unix_ms: u64,
    /// Current time (ms since the Unix epoch).
    pub now_unix_ms: u64,
    /// TCP/UDP port.
    pub port: u16,
    /// Player limit.
    pub max_players: usize,
    /// Connected players.
    pub players: usize,
    /// Current host.
    pub host: Option<String>,
    /// The lobby's game configuration (`None` = vanilla).
    pub game_config: Option<GameConfigStatus>,
}

/// The lobby's game configuration (summary).
#[derive(Debug, Serialize)]
pub struct GameConfigStatus {
    /// Configuration id.
    pub id: String,
    /// Package guid.
    pub guid: String,
    /// Package version.
    pub version: String,
    /// Display name.
    pub name: String,
    /// Language variant.
    pub language: String,
    /// Number of files.
    pub files: usize,
    /// Sum of the known file sizes.
    pub total_size: u64,
    /// Who set it.
    pub set_by: String,
}

/// One player.
#[derive(Debug, Serialize)]
pub struct PlayerStatus {
    /// Name.
    pub name: String,
    /// Virtual IP.
    pub vip: String,
    /// Host flag.
    pub is_host: bool,
    /// Ready flag.
    pub ready: bool,
    /// BFME running.
    pub in_game: bool,
    /// Combined fingerprint.
    pub fingerprint: Option<String>,
    /// Launcher version.
    pub version: String,
    /// RTT reported by the agent.
    pub rtt_ms: Option<u32>,
    /// Loss shown in the lobby (agent-reported and server-measured combined).
    pub loss_pct: Option<u8>,
    /// Loss reported by the agent (server → agent).
    pub reported_loss_pct: Option<u8>,
    /// Seconds since login.
    pub connected_s: u64,
    /// TCP peer address.
    pub peer: Option<String>,
    /// Relay session id (hex).
    pub session: String,
    /// Relay statistics of the session.
    pub relay: Option<SessionStats>,
    /// Readiness for the game configuration.
    pub config: Option<ConfigStatus>,
}

/// Control channel counters.
#[derive(Debug, Serialize)]
pub struct ControlStatus {
    /// Accepted connections.
    pub connections_total: u64,
    /// Open connections.
    pub connections_active: u64,
    /// Refused before the handshake.
    pub connections_refused: u64,
    /// Failed handshakes.
    pub handshake_failures: u64,
    /// Logins.
    pub logins: u64,
    /// IPs currently banned.
    pub banned_ips: usize,
    /// Chat lines.
    pub chat_lines: u64,
    /// Map chunks served.
    pub chunks_served: u64,
    /// Map bytes served.
    pub chunk_bytes: u64,
}

/// Map repository facts.
#[derive(Debug, Serialize)]
pub struct MapsStatus {
    /// Number of maps listed.
    pub count: usize,
    /// Number of files.
    pub files: usize,
    /// Sum of file sizes.
    pub total_size: u64,
    /// The listing was cut to fit into one message.
    pub truncated: bool,
    /// Skipped entries.
    pub skipped: usize,
    /// Last scan (ms since the Unix epoch).
    pub scanned_unix_ms: Option<u64>,
}

/// Builds the status document.
pub fn status_doc(hub: &Hub) -> StatusDoc {
    let relay = Arc::clone(&hub.relay_stats.borrow());
    let repo = hub.map_repo();
    let lobby = hub.lobby_view();
    let config = hub.game_config();
    let settings = hub.settings();
    let now = Instant::now();
    let (players, host) = {
        let st = lock(&hub.state);
        let host = st
            .lobby
            .host()
            .and_then(|h| st.lobby.member(h))
            .map(|m| m.name.clone());
        let players = st
            .lobby
            .members()
            .map(|(id, m)| PlayerStatus {
                name: m.name.clone(),
                vip: m.vip.to_string(),
                is_host: st.lobby.is_host(id),
                ready: m.ready,
                in_game: m.in_game,
                fingerprint: m.fingerprint.clone(),
                version: m.version.clone(),
                rtt_ms: m.reported_rtt_ms,
                loss_pct: lobby
                    .players
                    .iter()
                    .find(|p| p.name == m.name)
                    .and_then(|p| p.loss_pct),
                reported_loss_pct: m.reported_loss_pct,
                connected_s: now.saturating_duration_since(m.joined_at).as_secs(),
                peer: st.conns.get(&id).map(|c| c.peer.to_string()),
                session: format!("{:08x}", m.session),
                relay: relay.sessions.get(&m.session).cloned(),
                config: m.config.clone(),
            })
            .collect::<Vec<_>>();
        (players, host)
    };
    let (banned_ips, guard_failures) = {
        let guard = lock(&hub.guard);
        (guard.banned(now), guard.failures_total())
    };
    let c = &hub.counters;
    StatusDoc {
        server: ServerStatus {
            name: settings.server_name.clone(),
            version: crate::VERSION,
            uptime_s: hub.started.elapsed().as_secs(),
            started_unix_ms: hub.started_unix_ms,
            now_unix_ms: unix_ms(),
            port: hub.relay_port(),
            max_players: settings.max_players,
            players: players.len(),
            host,
            game_config: config.config.as_ref().map(|c| GameConfigStatus {
                id: c.id.clone(),
                guid: c.guid.clone(),
                version: c.version.clone(),
                name: c.name.clone(),
                language: c.language.clone(),
                files: c.files.len(),
                total_size: c.total_size(),
                set_by: config.by.clone(),
            }),
        },
        players,
        relay: relay.totals.clone(),
        relay_blocked_ips: relay.blocked_ips,
        control: ControlStatus {
            connections_total: c.connections_total.load(Ordering::Relaxed),
            connections_active: c.connections_active.load(Ordering::Relaxed),
            connections_refused: c.connections_refused.load(Ordering::Relaxed),
            handshake_failures: c
                .handshake_failures
                .load(Ordering::Relaxed)
                .max(guard_failures),
            logins: c.logins.load(Ordering::Relaxed),
            banned_ips,
            chat_lines: c.chat_lines.load(Ordering::Relaxed),
            chunks_served: c.chunks_served.load(Ordering::Relaxed),
            chunk_bytes: c.chunk_bytes.load(Ordering::Relaxed),
        },
        maps: MapsStatus {
            count: repo.maps.len(),
            files: repo.maps.iter().map(|m| m.files.len()).sum(),
            total_size: repo.total_size(),
            truncated: repo.truncated,
            skipped: repo.skipped,
            scanned_unix_ms: repo.scanned_at.and_then(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .and_then(|d| u64::try_from(d.as_millis()).ok())
            }),
        },
    }
}

/// `true` while the relay loop publishes statistics.
pub fn relay_alive(hub: &Hub) -> bool {
    hub.relay_stats
        .borrow()
        .taken_at
        .is_some_and(|t| t.elapsed() < RELAY_STALE)
}

async fn health(State(hub): State<Arc<Hub>>) -> Response {
    if relay_alive(&hub) {
        (StatusCode::OK, "ok").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "relay stalled").into_response()
    }
}

async fn status(State(hub): State<Arc<Hub>>) -> Json<StatusDoc> {
    Json(status_doc(&hub))
}

/// The status router.
pub fn router(hub: Arc<Hub>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .with_state(hub)
}

/// Serves the status endpoint until shutdown.
pub async fn serve(listener: TcpListener, hub: Arc<Hub>, mut shutdown: watch::Receiver<bool>) {
    if let Ok(addr) = listener.local_addr() {
        info!(%addr, "status endpoint listening (HTTP)");
    }
    let stop = async move {
        let _ = shutdown.changed().await;
    };
    if let Err(e) = axum::serve(listener, router(hub))
        .with_graceful_shutdown(stop)
        .await
    {
        warn!("status endpoint failed: {e}");
    }
}
