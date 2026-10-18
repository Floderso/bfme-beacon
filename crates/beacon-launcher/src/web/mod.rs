//! The browser UI of `Beacon.exe` (architecture §1): an axum server on
//! `127.0.0.1:0` that serves the embedded page (`ui/index.html`, `app.js`,
//! `style.css`, `favicon.svg`) and a small JSON + server-sent-events API over the
//! [`App`] handle.
//!
//! Security (the server is reachable by every local process and, through DNS
//! rebinding or cross-site requests, by web pages):
//!
//! * bound to `127.0.0.1` only, a fresh random 128-bit token per run;
//! * every request must carry `Host: 127.0.0.1:PORT` or `localhost:PORT`
//!   (DNS rebinding), absolute-form request targets must name the same authority;
//! * every `/api` request must carry `X-Beacon-Token` (constant-time compare), an
//!   `Origin` header (if present) must be this origin, `Sec-Fetch-Site` (if
//!   present) must be `same-origin` or `none`; failures answer `403`;
//! * no CORS headers, JSON bodies only (`Content-Type: application/json`, at most
//!   [`MAX_BODY`] bytes), a strict Content-Security-Policy (`script-src 'self'`, no
//!   inline code), `nosniff`, `frame-ancestors 'none'`, `no-store`;
//! * the token reaches the page in the URL fragment (`#t=…`, never sent over the
//!   network); the page keeps it in `sessionStorage` and removes it from the URL.
//!
//! See the crate README for the API.

mod api;
mod assets;
mod guard;
mod sse;

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::app::App;
use crate::util;

pub use self::assets::{Asset, ASSETS};
pub use self::guard::{host_allowed, origin_allowed, TOKEN_HEADER};
pub use self::sse::{KEEP_ALIVE, MIN_INTERVAL};

/// Concurrently open event streams (browser tabs).
pub const MAX_EVENT_STREAMS: usize = 8;
/// Largest request body (bytes).
pub const MAX_BODY: usize = 64 * 1024;
/// How long [`WebServer::shutdown`] waits for open connections.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

/// Opens a folder in the file manager (`/api/logs/open`).
pub type FolderOpener = Arc<dyn Fn(&Path) -> io::Result<()> + Send + Sync>;

/// Options of the web server.
#[derive(Clone)]
pub struct WebOptions {
    /// Opens a folder in Explorer; tests inject a fake so no window appears.
    pub open_folder: FolderOpener,
}

impl Default for WebOptions {
    fn default() -> Self {
        Self {
            open_folder: Arc::new(crate::sys::open_folder),
        }
    }
}

impl fmt::Debug for WebOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebOptions").finish_non_exhaustive()
    }
}

/// What every handler gets.
#[derive(Clone)]
struct Shared {
    app: App,
    port: u16,
    token: Arc<str>,
    streams: Arc<Semaphore>,
    stop: watch::Receiver<bool>,
    open_folder: FolderOpener,
}

/// The running web server (stops when dropped; prefer [`shutdown`](Self::shutdown)).
pub struct WebServer {
    addr: SocketAddr,
    token: String,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl fmt::Debug for WebServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebServer")
            .field("addr", &self.addr)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl WebServer {
    /// Binds `127.0.0.1:0` and starts serving (needs a tokio runtime).
    pub async fn start(app: App, opts: WebOptions) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let addr = listener.local_addr()?;
        let token = util::random_hex_token()?;
        let (stop, stop_rx) = watch::channel(false);
        let shared = Shared {
            app,
            port: addr.port(),
            token: Arc::from(token.as_str()),
            streams: Arc::new(Semaphore::new(MAX_EVENT_STREAMS)),
            stop: stop_rx.clone(),
            open_folder: opts.open_folder,
        };
        let router = router(shared);
        let mut stop_signal = stop_rx;
        let task = tokio::spawn(async move {
            let shutdown = async move {
                let _ = stop_signal.wait_for(|stopped| *stopped).await;
            };
            if let Err(e) = axum::serve(listener, router).with_graceful_shutdown(shutdown).await {
                warn!("web UI server failed: {e}");
            }
            debug!("web UI server stopped");
        });
        Ok(Self {
            addr,
            token,
            stop,
            task: Some(task),
        })
    }

    /// The bound address (`127.0.0.1:PORT`).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The port.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// The access token of this run.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The page without the token (for logs).
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.addr.port())
    }

    /// The URL the browser opens: the page with the token in the fragment.
    pub fn url(&self) -> String {
        format!("{}#t={}", self.base_url(), self.token)
    }

    /// Stops accepting connections, ends the event streams and waits (bounded)
    /// for open requests.
    pub async fn shutdown(mut self) {
        self.stop.send_replace(true);
        if let Some(task) = self.task.take() {
            let abort = task.abort_handle();
            if tokio::time::timeout(SHUTDOWN_GRACE, task).await.is_err() {
                debug!("web UI connections did not close in time");
                abort.abort();
            }
        }
    }
}

impl Drop for WebServer {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn router(shared: Shared) -> Router {
    let api = Router::new()
        .route("/state", get(api::state))
        .route("/events", get(sse::events))
        .route("/connect", post(api::connect))
        .route("/disconnect", post(api::disconnect))
        .route("/chat", post(api::chat))
        .route("/ready", post(api::ready))
        .route("/launch", post(api::launch))
        .route("/launch_all", post(api::launch_all))
        .route("/kick", post(api::kick))
        .route("/fingerprint", post(api::fingerprint))
        .route("/settings", post(api::settings))
        .route("/maps/sync", post(api::maps_sync))
        .route("/pin/reset", post(api::pin_reset))
        .route("/password/forget", post(api::password_forget))
        .route("/name/restore", post(api::name_restore))
        .route("/logs/open", post(api::logs_open))
        .route("/mods/select", post(api::mods_select))
        .route("/mods/retry", post(api::mods_retry))
        .route("/mods/cancel", post(api::mods_cancel))
        .route("/mods/reload", post(api::mods_reload))
        .route("/mods/import", post(api::mods_import))
        .route("/mods/cleanup", post(api::mods_cleanup))
        .route("/quit", post(api::quit))
        .fallback(api::not_found);
    let mut site = Router::new();
    for asset in ASSETS {
        site = site.route(asset.path, get(move || assets::serve(asset)));
    }
    site.nest("/api", api)
        .fallback(api::not_found)
        .layer(axum::middleware::from_fn_with_state(shared.clone(), guard::guard))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(shared)
}
