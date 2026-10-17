//! Server assembly: binds TCP and UDP on the same port number, scans the map
//! repository, starts every task (relay, control, status, map scanner, lobby
//! refresher, vIP persistence, webhook), handles signals and shuts down
//! gracefully.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::task::{Id, JoinSet};
use tokio::time::{Instant, Interval, MissedTickBehavior};
use tracing::{debug, info, warn};

use crate::config::{self, Settings};
use crate::hub::{Hub, HubInit};
use crate::maps::{self, HashCache, MapRepo};
use crate::relay::{self, RelayConfig};
use crate::webhook::{self, EventKind};
use crate::{control, status};

/// File in `data_dir` holding the sticky vIP table.
pub const VIPS_FILE: &str = "vips.json";
const TASK_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_VIPS_FILE: u64 = 1 << 20;

/// Errors of [`start`].
#[derive(Debug)]
pub enum ServerError {
    /// A socket could not be bound.
    Bind {
        /// Which socket.
        what: &'static str,
        /// Address.
        addr: SocketAddr,
        /// Cause.
        source: io::Error,
    },
    /// Anything else during start-up.
    Setup(String),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind { what, addr, source } => write!(f, "cannot bind {what} on {addr}: {source}"),
            Self::Setup(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for ServerError {}

/// The server's tasks, supervised: none of them may end before shutdown.
#[derive(Default)]
struct Tasks {
    set: JoinSet<()>,
    names: HashMap<Id, &'static str>,
}

impl Tasks {
    fn spawn(&mut self, name: &'static str, task: impl Future<Output = ()> + Send + 'static) {
        let handle = self.set.spawn(task);
        self.names.insert(handle.id(), name);
    }

    fn name(&self, id: Id) -> &'static str {
        self.names.get(&id).copied().unwrap_or("unknown")
    }
}

/// A started server. Dropping it aborts every task; [`shutdown`](Self::shutdown)
/// stops them gracefully and waits.
pub struct RunningServer {
    hub: Arc<Hub>,
    control_addr: SocketAddr,
    relay_addr: SocketAddr,
    status_addr: Option<SocketAddr>,
    shutdown: watch::Sender<bool>,
    tasks: Tasks,
}

impl RunningServer {
    /// Address of the TCP control listener.
    pub fn control_addr(&self) -> SocketAddr {
        self.control_addr
    }

    /// Address of the UDP relay socket (same port number).
    pub fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    /// Address of the status endpoint, if enabled.
    pub fn status_addr(&self) -> Option<SocketAddr> {
        self.status_addr
    }

    /// Shared state.
    pub fn hub(&self) -> &Arc<Hub> {
        &self.hub
    }

    /// Triggers a map rescan.
    pub fn rescan_maps(&self) {
        self.hub.request_rescan();
    }

    /// Resolves when a task ends (or panics) although no shutdown was requested;
    /// returns its name. The caller should then shut down and exit with an error
    /// so that the container restart policy brings the server back.
    pub async fn task_failed(&mut self) -> &'static str {
        match self.tasks.set.join_next_with_id().await {
            Some(Ok((id, ()))) => self.tasks.name(id),
            Some(Err(e)) => self.tasks.name(e.id()),
            None => std::future::pending().await,
        }
    }

    /// Stops all tasks: players get `kick` ("server stopping"), relay sessions get
    /// BYE, queued notifications are delivered (max 3 s).
    pub async fn shutdown(mut self) {
        info!("shutting down");
        self.hub.notify(
            EventKind::Stop,
            format!("{} wird beendet.", self.hub.settings().server_name),
        );
        let _ = self.shutdown.send(true);
        let deadline = Instant::now() + TASK_STOP_TIMEOUT;
        loop {
            match tokio::time::timeout_at(deadline, self.tasks.set.join_next_with_id()).await {
                Ok(None) => break,
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(e))) => {
                    warn!(task = self.tasks.name(e.id()), "task ended abnormally: {e}");
                }
                Err(_) => {
                    warn!("{} task(s) did not stop in time", self.tasks.set.len());
                    self.tasks.set.abort_all();
                    break;
                }
            }
        }
        info!("stopped");
    }
}

/// Binds the sockets and starts the server.
pub async fn start(settings: Settings) -> Result<RunningServer, ServerError> {
    let settings = Arc::new(settings);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (udp, tcp) = bind_pair(settings.bind_ip, settings.port)?;
    let relay_addr = udp
        .local_addr()
        .map_err(|e| ServerError::Setup(format!("relay socket: {e}")))?;
    let control_addr = tcp
        .local_addr()
        .map_err(|e| ServerError::Setup(format!("control socket: {e}")))?;
    let status_listener = match settings.status_bind {
        Some(addr) => Some(TcpListener::bind(addr).await.map_err(|source| ServerError::Bind {
            what: "status endpoint",
            addr,
            source,
        })?),
        None => None,
    };
    let status_addr = status_listener.as_ref().and_then(|l| l.local_addr().ok());

    // First map scan before players can ask for the listing.
    let (repo, cache) = scan_maps(settings.maps_dir.clone(), HashCache::default()).await;
    info!(
        maps = repo.maps.len(),
        dir = %settings.maps_dir.display(),
        "map repository scanned"
    );
    let (maps_tx, maps_rx) = watch::channel(Arc::new(repo));
    let (rescan_tx, rescan_rx) = mpsc::channel(1);

    let mut tasks = Tasks::default();
    let (relay, relay_stats, relay_task) = relay::start(
        udp,
        RelayConfig {
            redundancy: settings.redundancy,
            session_pps: settings.limits.relay_pps,
            session_burst: settings.limits.relay_burst,
            preauth_pps: settings.limits.preauth_pps,
            preauth_burst: settings.limits.preauth_burst,
        },
        shutdown_rx.clone(),
    );
    tasks.spawn("relay", relay_task);

    let notifier = match settings.webhook.clone() {
        Some(w) => {
            info!(host = %w.url.host, port = w.url.port, "webhook enabled");
            let (notifier, task) = webhook::start(w, shutdown_rx.clone());
            tasks.spawn("webhook", task);
            Some(notifier)
        }
        None => None,
    };

    let vips_path = settings.data_dir.as_ref().map(|dir| dir.join(VIPS_FILE));
    let restored = vips_path.as_deref().map(load_vips).unwrap_or_default();
    let (vips_tx, vips_rx) = watch::channel(Arc::new(restored.clone()));

    let hub = Hub::new(HubInit {
        settings: Arc::clone(&settings),
        relay,
        relay_stats,
        maps: maps_rx,
        rescan: rescan_tx,
        notifier,
        vips: vips_tx,
        restored_vips: restored,
        relay_port: relay_addr.port(),
    })
    .map_err(ServerError::Setup)?;

    tasks.spawn(
        "maps",
        map_scanner(
            settings.maps_dir.clone(),
            cache.unwrap_or_default(),
            maps_tx,
            rescan_rx,
            settings.map_rescan,
            shutdown_rx.clone(),
        ),
    );
    tasks.spawn(
        "lobby",
        lobby_refresher(Arc::clone(&hub), settings.lobby_refresh, shutdown_rx.clone()),
    );
    if let Some(path) = vips_path {
        tasks.spawn("vips", vip_persister(path, vips_rx, shutdown_rx.clone()));
    }
    if let Some(listener) = status_listener {
        tasks.spawn(
            "status",
            status::serve(listener, Arc::clone(&hub), shutdown_rx.clone()),
        );
    }
    tasks.spawn(
        "control",
        control::accept_loop(tcp, Arc::clone(&hub), shutdown_rx),
    );

    info!(
        name = %settings.server_name,
        %control_addr,
        %relay_addr,
        status = ?status_addr,
        max_players = settings.max_players,
        "beacon-server {} ready",
        crate::VERSION
    );
    hub.notify(
        EventKind::Start,
        format!(
            "{} läuft (Port {}).",
            settings.server_name,
            control_addr.port()
        ),
    );
    Ok(RunningServer {
        hub,
        control_addr,
        relay_addr,
        status_addr,
        shutdown: shutdown_tx,
        tasks,
    })
}

/// Runs until SIGTERM/SIGINT (Ctrl-C); SIGHUP rescans the maps. Fails if a
/// server task stops on its own (the process then exits with an error).
pub async fn run_until_signal(settings: Settings) -> Result<(), ServerError> {
    let mut server = start(settings).await?;
    let hub = Arc::clone(server.hub());
    let failed = tokio::select! {
        () = wait_for_signal(&hub) => None,
        name = server.task_failed() => Some(name),
    };
    if let Some(name) = failed {
        tracing::error!(task = name, "a server task stopped unexpectedly; shutting down");
    }
    server.shutdown().await;
    match failed {
        Some(name) => Err(ServerError::Setup(format!(
            "server task `{name}` stopped unexpectedly"
        ))),
        None => Ok(()),
    }
}

#[cfg(unix)]
async fn wait_for_signal(hub: &Hub) {
    use tokio::signal::unix::{signal, Signal, SignalKind};

    async fn next(sig: &mut Option<Signal>) {
        match sig {
            Some(s) => {
                if s.recv().await.is_none() {
                    std::future::pending::<()>().await;
                }
            }
            None => std::future::pending::<()>().await,
        }
    }

    let mut term = signal(SignalKind::terminate()).ok();
    let mut int = signal(SignalKind::interrupt()).ok();
    let mut hup = signal(SignalKind::hangup()).ok();
    loop {
        tokio::select! {
            () = next(&mut term) => {
                info!("SIGTERM received");
                return;
            }
            () = next(&mut int) => {
                info!("SIGINT received");
                return;
            }
            () = next(&mut hup) => {
                info!("SIGHUP received: rescanning maps");
                hub.request_rescan();
            }
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_signal(_hub: &Hub) {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
    info!("Ctrl-C received");
}

fn bind_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    // Fast restarts while old connections linger in TIME_WAIT. Not on Windows,
    // where SO_REUSEADDR would allow port stealing.
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(256)?;
    TcpListener::from_std(socket.into())
}

/// Binds UDP and TCP on the same port number. With port 0 a free UDP port is
/// picked and TCP tries the same number (a few attempts).
fn bind_pair(ip: IpAddr, port: u16) -> Result<(UdpSocket, TcpListener), ServerError> {
    let attempts = if port == 0 { 20 } else { 1 };
    let mut last = None;
    for _ in 0..attempts {
        let udp_addr = SocketAddr::new(ip, port);
        let udp = relay::bind_socket(udp_addr).map_err(|source| ServerError::Bind {
            what: "relay (UDP)",
            addr: udp_addr,
            source,
        })?;
        let actual = udp
            .local_addr()
            .map_err(|e| ServerError::Setup(format!("relay socket: {e}")))?
            .port();
        let tcp_addr = SocketAddr::new(ip, actual);
        match bind_tcp(tcp_addr) {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(source) => last = Some((tcp_addr, source)),
        }
    }
    match last {
        Some((addr, source)) => Err(ServerError::Bind {
            what: "control (TCP)",
            addr,
            source,
        }),
        None => Err(ServerError::Setup("no bind attempt".to_owned())),
    }
}

async fn scan_maps(dir: PathBuf, cache: HashCache) -> (MapRepo, Option<HashCache>) {
    let result = tokio::task::spawn_blocking(move || {
        let mut cache = cache;
        let repo = maps::scan(&dir, &mut cache);
        (repo, cache)
    })
    .await;
    match result {
        Ok((repo, cache)) => (repo, Some(cache)),
        Err(e) => {
            warn!("map scan failed: {e}");
            (MapRepo::default(), None)
        }
    }
}

async fn tick(interval: &mut Option<Interval>) {
    match interval {
        Some(i) => {
            i.tick().await;
        }
        None => std::future::pending::<()>().await,
    }
}

async fn map_scanner(
    dir: PathBuf,
    mut cache: HashCache,
    maps_tx: watch::Sender<Arc<MapRepo>>,
    mut rescan: mpsc::Receiver<()>,
    every: Option<Duration>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = every.and_then(|d| {
        let Some(first) = Instant::now().checked_add(d) else {
            warn!("map rescan interval too long; periodic rescans disabled");
            return None;
        };
        let mut i = tokio::time::interval_at(first, d);
        i.set_missed_tick_behavior(MissedTickBehavior::Skip);
        Some(i)
    });
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            request = rescan.recv() => if request.is_none() { return },
            () = tick(&mut ticker) => {}
        }
        let (repo, new_cache) = scan_maps(dir.clone(), std::mem::take(&mut cache)).await;
        let Some(new_cache) = new_cache else {
            continue;
        };
        cache = new_cache;
        let count = repo.maps.len();
        // Always store the fresh scan; notify only on content changes.
        let changed = maps_tx.send_if_modified(|current| {
            let changed = current.maps != repo.maps;
            *current = Arc::new(repo);
            changed
        });
        if changed {
            info!(maps = count, "map repository changed");
        } else {
            debug!(maps = count, "map repository unchanged");
        }
    }
}

async fn lobby_refresher(hub: Arc<Hub>, every: Duration, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(every);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = interval.tick() => hub.publish_lobby(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct VipFile {
    version: u32,
    vips: BTreeMap<String, Ipv4Addr>,
}

/// Loads the persisted sticky vIP table (empty if missing or invalid).
pub fn load_vips(path: &Path) -> BTreeMap<String, Ipv4Addr> {
    let bytes = match std::fs::metadata(path) {
        Ok(meta) if meta.len() > MAX_VIPS_FILE => {
            warn!("ignoring {}: too large", path.display());
            return BTreeMap::new();
        }
        Ok(_) => match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                warn!("cannot read {}: {e}", path.display());
                return BTreeMap::new();
            }
        },
        Err(e) => {
            if e.kind() != io::ErrorKind::NotFound {
                warn!("cannot read {}: {e}", path.display());
            }
            return BTreeMap::new();
        }
    };
    match serde_json::from_slice::<VipFile>(&bytes) {
        Ok(file) if file.version == 1 => file.vips,
        Ok(file) => {
            warn!("ignoring {}: unknown version {}", path.display(), file.version);
            BTreeMap::new()
        }
        Err(e) => {
            warn!("ignoring {}: {e}", path.display());
            BTreeMap::new()
        }
    }
}

/// Writes the sticky vIP table.
pub fn save_vips(path: &Path, vips: &BTreeMap<String, Ipv4Addr>) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_vec_pretty(&VipFile {
        version: 1,
        vips: vips.clone(),
    })
    .map_err(io::Error::other)?;
    config::write_file_replacing(path, &json)
}

async fn vip_persister(
    path: PathBuf,
    mut table: watch::Receiver<Arc<BTreeMap<String, Ipv4Addr>>>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            changed = table.changed() => {
                if changed.is_err() {
                    return;
                }
                let snapshot = Arc::clone(&table.borrow_and_update());
                let p = path.clone();
                match tokio::task::spawn_blocking(move || save_vips(&p, &snapshot)).await {
                    Ok(Ok(())) => debug!("saved {}", path.display()),
                    Ok(Err(e)) => warn!("cannot save {}: {e}", path.display()),
                    Err(e) => warn!("cannot save {}: {e}", path.display()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vip_file_round_trip() {
        let dir = std::env::temp_dir().join(format!("beacon-vips-{}", std::process::id()));
        let path = dir.join("sub").join(VIPS_FILE);
        let mut table = BTreeMap::new();
        table.insert("frodo".to_owned(), Ipv4Addr::new(198, 18, 0, 7));
        save_vips(&path, &table).unwrap();
        assert_eq!(load_vips(&path), table);
        // Overwrite works (rename over an existing file).
        table.insert("sam".to_owned(), Ipv4Addr::new(198, 18, 0, 8));
        save_vips(&path, &table).unwrap();
        assert_eq!(load_vips(&path), table);
        std::fs::write(&path, b"{not json").unwrap();
        assert!(load_vips(&path).is_empty());
        std::fs::write(&path, br#"{"version":2,"vips":{}}"#).unwrap();
        assert!(load_vips(&path).is_empty());
        assert!(load_vips(&dir.join("missing.json")).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // Regression: `Instant::now() + map_rescan` panicked for a huge interval and
    // took the whole server down (supervised task ended).
    #[tokio::test]
    async fn map_scanner_survives_a_huge_interval() {
        let (maps_tx, _maps_rx) = watch::channel(Arc::new(MapRepo::default()));
        let (_rescan_tx, rescan_rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(map_scanner(
            PathBuf::from("beacon-test-no-such-dir"),
            HashCache::default(),
            maps_tx,
            rescan_rx,
            Some(Duration::MAX),
            shutdown_rx,
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown_tx.send(true).unwrap();
        task.await.expect("map scanner must not panic");
    }

    #[tokio::test]
    async fn bind_pair_uses_one_port_number() {
        let (udp, tcp) = bind_pair("127.0.0.1".parse().unwrap(), 0).unwrap();
        assert_eq!(udp.local_addr().unwrap().port(), tcp.local_addr().unwrap().port());
        // The same fixed port cannot be bound twice.
        let port = udp.local_addr().unwrap().port();
        assert!(bind_pair("127.0.0.1".parse().unwrap(), port).is_err());
    }
}
