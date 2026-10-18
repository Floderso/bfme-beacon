//! Integration tests: real `beacon_server` instances started in-process on
//! 127.0.0.1 and `App` instances with temporary data folders. The game is not
//! involved: fake hooks (loopback UDP sockets speaking `BCN1`) stand in for it.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use beacon_launcher::agent::AgentOptions;
use beacon_launcher::control::ControlError;
use beacon_launcher::game::Registry;
use beacon_launcher::maps::MapState;
use beacon_launcher::paths::DataDirs;
use beacon_launcher::state::{AppState, ConnectionState};
use beacon_launcher::{App, AppOptions, ConnectRequest};
use beacon_proto::control::{derive_psk, KdfParams, PSK_LEN};
use beacon_proto::local::{self, HookFrame};
use beacon_server::config::Config;
use beacon_server::{hexfmt, RunningServer};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const PASSWORD: &str = "mellon-mellon";
const SALT_A: [u8; 16] = *b"beacon-test-salt";
const SALT_B: [u8; 16] = *b"another-salt-xyz";
/// Generous bound for anything that should happen.
const T: Duration = Duration::from_secs(20);
/// How long to wait for something that must not happen.
const QUIET: Duration = Duration::from_millis(400);

fn init_logging() {
    if std::env::var_os("BEACON_TEST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();
    }
}

type PskCache = Mutex<HashMap<(String, [u8; 16]), [u8; PSK_LEN]>>;

/// Argon2id is slow in debug builds: derive each (password, salt) once.
fn psk_for(password: &str, salt: [u8; 16]) -> [u8; PSK_LEN] {
    static CACHE: OnceLock<PskCache> = OnceLock::new();
    let mut cache = CACHE.get_or_init(Default::default).lock().unwrap();
    *cache
        .entry((password.to_owned(), salt))
        .or_insert_with(|| derive_psk(password, &salt, &KdfParams::DEFAULT).unwrap())
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "beacon-launcher-it-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(p.join("maps")).unwrap();
        Self(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn start_server(dir: &Path, port: u16, salt: [u8; 16]) -> RunningServer {
    start_server_with(dir, port, salt, |_| {}).await
}

async fn start_server_with(
    dir: &Path,
    port: u16,
    salt: [u8; 16],
    tune: impl Fn(&mut beacon_server::config::Settings),
) -> RunningServer {
    init_logging();
    let cfg = Config {
        server_name: "Testserver".into(),
        motd: "Hallo Mittelerde".into(),
        bind: "127.0.0.1".into(),
        port,
        status_bind: String::new(),
        salt: hexfmt::encode(&salt),
        psk: hexfmt::encode(&psk_for(PASSWORD, salt)),
        maps_dir: dir.join("maps").to_string_lossy().into_owned(),
        data_dir: dir.join("server-data").to_string_lossy().into_owned(),
        map_rescan_secs: 0,
        ..Config::default()
    };
    let mut settings = cfg.into_settings(dir).unwrap();
    settings.lobby_refresh = Duration::from_millis(200);
    tune(&mut settings);
    // A restarted server may need a moment until the port is free again.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match beacon_server::start(settings.clone()).await {
            Ok(s) => return s,
            Err(e) if tokio::time::Instant::now() < deadline => {
                eprintln!("server start: {e}; retrying");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => panic!("server start: {e}"),
        }
    }
}

/// No BFME installation.
struct NoGame;

impl Registry for NoGame {
    fn string(&self, _value: &str) -> Option<String> {
        None
    }
    fn dword(&self, _value: &str) -> Option<u32> {
        None
    }
}

async fn start_app(dir: &Path, who: &str) -> App {
    let base = dir.join(who);
    let mut o = AppOptions::new(DataDirs::with_base(base.clone(), 1).unwrap());
    o.registry = Arc::new(NoGame);
    o.appdata = Some(base.join("appdata"));
    o.fingerprint = false;
    o.maps_dir = Some(base.join("Maps"));
    o.hook_dll = Some(dir.join("no-hook.dll"));
    o.agent = AgentOptions {
        tick: Duration::from_millis(100),
        ..AgentOptions::default()
    };
    App::start(o).await.unwrap()
}

fn request(port: u16, name: &str) -> ConnectRequest {
    ConnectRequest {
        server: format!("127.0.0.1:{port}"),
        name: name.to_owned(),
        password: Some(PASSWORD.to_owned()),
        use_remembered: false,
        remember: false,
    }
}

async fn wait_state(app: &App, what: &str, pred: impl Fn(&AppState) -> bool) -> AppState {
    let mut rx = app.subscribe();
    let deadline = tokio::time::Instant::now() + T;
    loop {
        let s = app.snapshot();
        if pred(&s) {
            return s;
        }
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Ok(_)) | Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(_)) | Err(_) => panic!("timeout waiting for {what}: {:#?}", s.connection),
        }
    }
}

async fn connected(app: &App) -> AppState {
    wait_state(app, "connected", |s| s.is_connected() && s.server.is_some()).await
}

fn vip(s: &AppState) -> Ipv4Addr {
    s.server.as_ref().unwrap().vip.parse().unwrap()
}

/// Stands in for the hook inside one game instance.
struct FakeHook {
    sock: UdpSocket,
    agent: SocketAddr,
    token: u32,
}

impl FakeHook {
    async fn new(app: &App) -> Self {
        let (port, token) = app.agent_endpoint();
        Self::at(port, token).await
    }

    async fn at(port: u16, token: u32) -> Self {
        Self {
            sock: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            agent: SocketAddr::from(([127, 0, 0, 1], port)),
            token,
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
        assert_eq!(from, self.agent);
        let (d, range) = local::parse_deliver(&buf[..n]).unwrap();
        Some((d.src_vip, d.src_vport, buf[range].to_vec()))
    }
}

async fn wait_acked(app: &App, vport: u16) {
    wait_state(app, "relay REG_ACK", |s| {
        s.agent.registrations.iter().any(|r| r.vport == vport && r.acked)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_players_share_lobby_chat_and_the_virtual_lan() {
    let dir = TempDir::new("lan");
    let server = start_server(&dir.0, 0, SALT_A).await;
    let port = server.control_addr().port();
    let alice = start_app(&dir.0, "alice").await;
    let bob = start_app(&dir.0, "bob").await;
    // Alice joins first and becomes host.
    alice.connect(request(port, "Alice")).await.unwrap();
    let a = connected(&alice).await;
    bob.connect(request(port, "Bob")).await.unwrap();
    let b = connected(&bob).await;
    let (vip_a, vip_b) = (vip(&a), vip(&b));
    assert_ne!(vip_a, vip_b, "distinct vIPs");
    assert!(beacon_proto::net::is_assignable(vip_a) && beacon_proto::net::is_assignable(vip_b));
    assert_eq!(a.server.as_ref().unwrap().name, "Testserver");
    assert_eq!(a.server.as_ref().unwrap().motd, "Hallo Mittelerde");
    assert!(a.server.as_ref().unwrap().newly_pinned);

    // Lobby: both see both; the first player is host.
    for app in [&alice, &bob] {
        wait_state(app, "both players", |s| {
            let names: Vec<&str> = s.players.iter().map(|p| p.name.as_str()).collect();
            names.contains(&"Alice") && names.contains(&"Bob")
        })
        .await;
    }
    assert!(alice.snapshot().server.unwrap().you_are_host);
    assert!(!bob.snapshot().server.unwrap().you_are_host);
    assert!(bob.launch_all().await.is_err(), "only the host may launch");

    // Chat.
    alice.send_chat("Hallo Bob").await.unwrap();
    wait_state(&bob, "chat line", |s| {
        s.chat.iter().any(|l| l.from == "Alice" && l.text == "Hallo Bob")
    })
    .await;

    // Ready flag and measured RTT reach the lobby.
    bob.set_ready(true).await.unwrap();
    wait_state(&alice, "Bob ready", |s| s.players.iter().any(|p| p.name == "Bob" && p.ready)).await;
    wait_state(&alice, "rtt measured", |s| s.agent.rtt_ms.is_some()).await;

    // Data plane: fake hooks on both sides.
    let hook_a = FakeHook::new(&alice).await;
    let hook_b = FakeHook::new(&bob).await;
    hook_a.reg(8086).await;
    hook_b.reg(8086).await;
    wait_acked(&alice, 8086).await;
    wait_acked(&bob, 8086).await;

    // Unicast A → B: delivered once with A's true source (the redundant copies are
    // dropped by B's replay window).
    hook_a.send(8086, vip_b, 8086, b"unicast to bob").await;
    assert_eq!(hook_b.deliver(T).await, Some((vip_a, 8086, b"unicast to bob".to_vec())));
    assert_eq!(hook_b.deliver(QUIET).await, None, "exactly once");

    // Broadcast A → everybody else, never echoed to A.
    hook_a.send(8086, Ipv4Addr::BROADCAST, 8086, b"lan broadcast").await;
    assert_eq!(hook_b.deliver(T).await, Some((vip_a, 8086, b"lan broadcast".to_vec())));
    assert_eq!(hook_b.deliver(QUIET).await, None, "exactly once");
    assert_eq!(hook_a.deliver(QUIET).await, None, "no echo to the sender");

    // And back: B → A on the subnet broadcast address.
    hook_b.send(8086, beacon_proto::net::VSUBNET_BROADCAST, 8086, b"hi alice").await;
    assert_eq!(hook_a.deliver(T).await, Some((vip_b, 8086, b"hi alice".to_vec())));

    let stats = bob.agent_stats();
    assert!(stats.duplicates >= 2, "redundant copies seen and dropped: {stats:#?}");
    assert_eq!(stats.delivered, 2);

    alice.quit().await;
    bob.quit().await;
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn map_sync_downloads_a_test_map() {
    let dir = TempDir::new("maps");
    let map_dir = dir.0.join("maps").join("Testkarte");
    std::fs::create_dir_all(&map_dir).unwrap();
    let big: Vec<u8> = (0..100_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect();
    std::fs::write(map_dir.join("Testkarte.map"), &big).unwrap();
    std::fs::write(map_dir.join("map.ini"), b"; test map\r\n").unwrap();
    let server = start_server(&dir.0, 0, SALT_A).await;
    let port = server.control_addr().port();
    let alice = start_app(&dir.0, "alice").await;
    alice.connect(request(port, "Alice")).await.unwrap();
    connected(&alice).await;
    let s = wait_state(&alice, "map listing", |s| s.maps.listing_received && !s.maps.maps.is_empty()).await;
    assert_eq!(s.maps.maps[0].name, "Testkarte");
    assert_eq!(s.maps.maps[0].state, MapState::Missing);

    alice.sync_maps().await.unwrap();
    let s = wait_state(&alice, "sync finished", |s| {
        !s.maps.sync.running && s.maps.maps.iter().all(|m| m.state == MapState::Installed)
    })
    .await;
    assert_eq!(s.maps.sync.downloaded, ["Testkarte"]);
    assert_eq!(s.maps.sync.last_error, None);
    let local = dir.0.join("alice").join("Maps").join("Testkarte");
    assert_eq!(std::fs::read(local.join("Testkarte.map")).unwrap(), big);
    assert_eq!(std::fs::read(local.join("map.ini")).unwrap(), b"; test map\r\n");
    let record = std::fs::read_to_string(dir.0.join("alice").join("Maps").join("beacon-maps.json")).unwrap();
    assert!(record.contains("Testkarte/Testkarte.map"));

    // Nothing left to do on a second run.
    alice.sync_maps().await.unwrap();
    let s = wait_state(&alice, "second sync", |s| !s.maps.sync.running && s.maps.listing_received).await;
    assert!(s.maps.sync.downloaded.is_empty());
    alice.quit().await;
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changed_salt_is_rejected_by_the_pin() {
    let dir = TempDir::new("pin");
    let server = start_server(&dir.0, 0, SALT_A).await;
    let port = server.control_addr().port();
    let alice = start_app(&dir.0, "alice").await;

    // Wrong password: permanent failure, no retries.
    let mut wrong = request(port, "Alice");
    wrong.password = Some("wrong-password".into());
    alice.connect(wrong).await.unwrap();
    let s = wait_state(&alice, "auth failure", |s| matches!(s.connection, ConnectionState::Failed { .. })).await;
    assert!(matches!(
        s.connection,
        ConnectionState::Failed { error: ControlError::AuthFailed, .. }
    ));

    // First successful login pins the identity and remembers the key.
    let mut first = request(port, "Alice");
    first.remember = true;
    alice.connect(first).await.unwrap();
    connected(&alice).await;
    let s = alice.snapshot();
    let entry = &s.settings.servers[0];
    assert_eq!(entry.pinned_name.as_deref(), Some("Testserver"));
    assert!(entry.remembered);

    // The remembered key works.
    alice.disconnect().await;
    alice
        .connect(ConnectRequest {
            password: None,
            use_remembered: true,
            ..request(port, "Alice")
        })
        .await
        .unwrap();
    let s = connected(&alice).await;
    assert!(!s.server.unwrap().newly_pinned);
    alice.disconnect().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    server.shutdown().await;

    // Same address, new salt: refused before any key is derived.
    let server2 = start_server(&dir.0, port, SALT_B).await;
    assert_eq!(server2.control_addr().port(), port);
    alice.connect(request(port, "Alice")).await.unwrap();
    let s = wait_state(&alice, "identity change", |s| matches!(s.connection, ConnectionState::Failed { .. })).await;
    let ConnectionState::Failed { error, message, .. } = &s.connection else {
        unreachable!()
    };
    assert!(
        matches!(error, ControlError::IdentityChanged { pinned_name, .. } if pinned_name == "Testserver"),
        "{error:?}"
    );
    assert!(message.contains("reset the pin"));
    assert!(server2.hub().lobby_view().players.is_empty(), "no login happened");

    // After resetting the pin the new identity is accepted (and pinned).
    assert!(alice.reset_server_pin(&format!("127.0.0.1:{port}")).await.unwrap());
    assert!(!alice.snapshot().settings.servers[0].remembered, "the old key is forgotten too");
    alice.connect(request(port, "Alice")).await.unwrap();
    let s = connected(&alice).await;
    assert!(s.server.unwrap().newly_pinned);
    alice.quit().await;
    server2.shutdown().await;
}

const LEAF: &str = "My Battle for Middle-earth Files";

/// Registry of an installation with the usual user-folder values.
struct FakeRegistry;

impl Registry for FakeRegistry {
    fn string(&self, value: &str) -> Option<String> {
        (value == "UserDataLeafName").then(|| LEAF.to_owned())
    }
    fn dword(&self, value: &str) -> Option<u32> {
        (value == "UseLocalUserMaps").then_some(0)
    }
}

/// The full launch path without BFME: the "game" is a byte-identical copy of
/// `cmd.exe` named `lotrbfme.exe` (it exits at once on its null stdin).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn launch_installs_the_hook_syncs_the_name_and_tracks_the_game() {
    let dir = TempDir::new("launch");
    let game = dir.0.join("game");
    std::fs::create_dir_all(&game).unwrap();
    std::fs::copy(r"C:\Windows\System32\cmd.exe", game.join("lotrbfme.exe")).unwrap();
    let hook = dir.0.join("wsock32.dll");
    std::fs::write(&hook, b"MZ fake hook BFME-BEACON-HOOK/9.9.9\0rest").unwrap();
    let appdata = dir.0.join("appdata");
    let prefs = appdata.join(LEAF);
    std::fs::create_dir_all(&prefs).unwrap();
    let original = b"Color = 3\r\nUserName = O_00l_00d_00\r\n".to_vec();
    std::fs::write(prefs.join("Network.ini"), &original).unwrap();

    let server = start_server(&dir.0, 0, SALT_A).await;
    let port = server.control_addr().port();
    let mut o = AppOptions::new(DataDirs::with_base(dir.0.join("data"), 1).unwrap());
    o.registry = Arc::new(FakeRegistry);
    o.appdata = Some(appdata.clone());
    o.game_dir = Some(game.clone());
    o.hook_dll = Some(hook.clone());
    o.fingerprint = false;
    let app = App::start(o).await.unwrap();
    assert_eq!(
        app.launch_game().await.unwrap_err().kind,
        beacon_launcher::CommandErrorKind::NotConnected
    );
    app.connect(request(port, "Alice")).await.unwrap();
    connected(&app).await;
    let s = wait_state(&app, "detection", |s| s.game.is_some()).await;
    assert_eq!(s.game.unwrap().user.unwrap().prefs_dir, prefs);

    app.launch_game().await.unwrap();
    // Hook copied next to the exe.
    assert_eq!(std::fs::read(game.join("wsock32.dll")).unwrap(), std::fs::read(&hook).unwrap());
    // BFME's LAN name follows the player name; other keys stay.
    let net = String::from_utf8(std::fs::read(prefs.join("Network.ini")).unwrap()).unwrap();
    assert_eq!(net, "Color = 3\r\nUserName = A_00l_00i_00c_00e_00\r\n");
    // The process is tracked until it exits.
    let s = wait_state(&app, "game exit", |s| s.game_process.as_ref().is_some_and(|g| !g.running)).await;
    let proc_ = s.game_process.unwrap();
    assert_eq!(proc_.exit_code, Some(0));
    let log = proc_.hook_log.unwrap();
    assert!(log.starts_with(dir.0.join("data").join("logs")), "{}", log.display());
    assert!(matches!(
        s.hook,
        beacon_launcher::game::hook::HookStatus::UpToDate { ref version } if version == "9.9.9"
    ));

    // The original name comes back.
    assert!(app.restore_user_name().await.unwrap());
    assert_eq!(std::fs::read(prefs.join("Network.ini")).unwrap(), original);

    // A foreign wsock32.dll is never replaced and blocks the start.
    std::fs::write(game.join("wsock32.dll"), b"MZ someone else's proxy").unwrap();
    let err = app.launch_game().await.unwrap_err();
    assert_eq!(err.kind, beacon_launcher::CommandErrorKind::HookForeign);
    assert_eq!(std::fs::read(game.join("wsock32.dll")).unwrap(), b"MZ someone else's proxy");
    app.quit().await;
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commands_validate_their_input_and_settings_are_saved() {
    use beacon_launcher::config::{LaunchOptions, RedundancyOverrides};
    use beacon_launcher::{CommandErrorKind as K, SettingsPatch};
    let dir = TempDir::new("cmds");
    let app = start_app(&dir.0, "alice").await;
    assert_eq!(app.send_chat("hi").await.unwrap_err().kind, K::NotConnected);
    assert_eq!(app.sync_maps().await.unwrap_err().kind, K::NotConnected);
    assert_eq!(app.launch_all().await.unwrap_err().kind, K::NotConnected);
    for (server, name, password) in [
        ("bad host:1", "Alice", Some("pw")),
        ("example.org", "a/b", Some("pw")),
        ("example.org", "Alice", None),
    ] {
        let req = ConnectRequest {
            server: server.into(),
            name: name.into(),
            password: password.map(str::to_owned),
            use_remembered: false,
            remember: false,
        };
        assert_eq!(app.connect(req).await.unwrap_err().kind, K::InvalidInput, "{server} {name}");
    }
    let bad = [
        SettingsPatch { player_name: Some("bad/name".into()), ..Default::default() },
        SettingsPatch { game_dir: Some("relative/dir".into()), ..Default::default() },
        SettingsPatch {
            launch: Some(LaunchOptions { xres: Some(5), ..Default::default() }),
            ..Default::default()
        },
        SettingsPatch {
            redundancy: Some(RedundancyOverrides { lobby: Some(9), ..Default::default() }),
            ..Default::default()
        },
    ];
    for patch in bad {
        assert_eq!(app.update_settings(patch.clone()).await.unwrap_err().kind, K::InvalidInput, "{patch:?}");
    }
    app.update_settings(SettingsPatch {
        player_name: Some("Gandalf".into()),
        launch: Some(LaunchOptions {
            windowed: true,
            xres: Some(1280),
            yres: Some(720),
            noshellmap: false,
        }),
        name_sync: Some(false),
        redundancy: Some(RedundancyOverrides { game: Some(3), ..Default::default() }),
        ..Default::default()
    })
    .await
    .unwrap();
    let s = app.snapshot().settings;
    assert_eq!(s.player_name.as_deref(), Some("Gandalf"));
    assert!(s.launch.windowed && !s.name_sync);
    assert_eq!(s.redundancy.game, Some(3));
    let saved = std::fs::read_to_string(dir.0.join("alice").join("config.json")).unwrap();
    assert!(saved.contains("Gandalf") && saved.contains("1280"));
    app.quit().await;
}

// ---- reconnects while BFME runs ---------------------------------------------

use beacon_launcher::agent::{AgentHandle, AgentStats};
use beacon_launcher::config::{ConfigStore, ServerAddr};
use beacon_launcher::control::{
    self, ConnectParams, Connected, ControlEvent, ControlHandle, Credentials, Deps, StatusReport,
};
use beacon_proto::fingerprint::Fingerprint;
use tokio::sync::{mpsc, watch};

/// A control supervisor + agent outside an `App`, so that the test can report a
/// running game (`in_game`), which `App` only does for a real launch.
struct InGamePlayer {
    agent: AgentHandle,
    control: Option<ControlHandle>,
    events: mpsc::UnboundedReceiver<ControlEvent>,
    _status: watch::Sender<StatusReport>,
    _fingerprint: watch::Sender<Option<Arc<Fingerprint>>>,
}

impl InGamePlayer {
    async fn connect(dir: &Path, who: &str, server: SocketAddr, name: &str) -> Self {
        let base = dir.join(who);
        std::fs::create_dir_all(&base).unwrap();
        let (config, _) = ConfigStore::load(&base.join("config.json"));
        let (agent, _task) = AgentHandle::start(AgentOptions {
            tick: Duration::from_millis(100),
            ..AgentOptions::default()
        })
        .await
        .unwrap();
        let status = watch::channel(StatusReport {
            in_game: true,
            ..StatusReport::default()
        })
        .0;
        let fingerprint = watch::channel(None).0;
        let (events_tx, mut events_rx) = mpsc::channel::<(u64, ControlEvent)>(64);
        let (tx, events) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some((_, ev)) = events_rx.recv().await {
                if !matches!(ev, ControlEvent::Message(_)) && tx.send(ev).is_err() {
                    return;
                }
            }
        });
        let deps = Deps {
            config: Arc::new(config),
            agent: agent.clone(),
            events: events_tx,
            generation: 1,
            status: status.subscribe(),
            fingerprint: fingerprint.subscribe(),
        };
        let control = control::spawn(
            ConnectParams {
                addr: ServerAddr::parse(&server.to_string()).unwrap(),
                name: name.to_owned(),
                credentials: Credentials::Password(PASSWORD.to_owned()),
                remember: false,
            },
            deps,
        );
        Self {
            agent,
            control: Some(control),
            events,
            _status: status,
            _fingerprint: fingerprint,
        }
    }

    /// The next login; panics on a permanent failure.
    async fn connected(&mut self, within: Duration) -> Connected {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            match tokio::time::timeout_at(deadline, self.events.recv()).await {
                Ok(Some(ControlEvent::Connected(c))) => return c,
                Ok(Some(ControlEvent::Disconnected { error, retry_in: None })) => {
                    panic!("the supervisor gave up: {error:?}")
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => panic!("no login within {within:?}"),
            }
        }
    }

    /// Logs in again; returns the login and the retry delays announced before it.
    async fn reconnected(&mut self, within: Duration) -> (Connected, Vec<Duration>) {
        let deadline = tokio::time::Instant::now() + within;
        let mut delays = Vec::new();
        loop {
            match tokio::time::timeout_at(deadline, self.events.recv()).await {
                Ok(Some(ControlEvent::Connected(c))) => return (c, delays),
                Ok(Some(ControlEvent::Disconnected { retry_in: Some(d), .. })) => delays.push(d),
                Ok(Some(ControlEvent::Disconnected { error, retry_in: None })) => {
                    panic!("the supervisor gave up: {error:?}")
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => panic!("no login within {within:?}"),
            }
        }
    }

    /// `true` if a login happened since the last look (events are consumed).
    fn logged_in_meanwhile(&mut self) -> bool {
        let mut seen = false;
        while let Ok(ev) = self.events.try_recv() {
            seen |= matches!(ev, ControlEvent::Connected(_));
        }
        seen
    }

    /// The next connection loss (with a retry scheduled).
    async fn lost(&mut self) -> ControlError {
        loop {
            match timeout(T, self.events.recv()).await {
                Ok(Some(ControlEvent::Disconnected { error: Some(e), retry_in: Some(_) })) => return e,
                Ok(Some(ControlEvent::Disconnected { error, retry_in: None })) => {
                    panic!("the supervisor gave up: {error:?}")
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => panic!("no disconnect"),
            }
        }
    }

    async fn hook(&self) -> FakeHook {
        FakeHook::at(self.agent.port(), self.agent.token()).await
    }

    async fn acked(&self, vport: u16) {
        let mut rx = self.agent.watch_stats();
        let deadline = tokio::time::Instant::now() + T;
        let done = |s: &AgentStats| s.registrations.iter().any(|r| r.vport == vport && r.acked);
        while !done(&rx.borrow_and_update()) {
            if tokio::time::timeout_at(deadline, rx.changed()).await.is_err() {
                panic!("no REG_ACK for {vport}: {:#?}", self.agent.stats());
            }
        }
    }

    async fn stop(mut self) {
        if let Some(c) = self.control.take() {
            c.disconnect().await;
        }
        self.agent.shutdown().await;
    }
}

/// Sends `payload` from `from` to `to` until it arrives (the receiving side may
/// still be re-registering) within `within` and checks its source.
async fn flows(
    from: &FakeHook,
    to: &FakeHook,
    (src_vip, dst_vip): (Ipv4Addr, Ipv4Addr),
    payload: &[u8],
    within: Duration,
) {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        from.send(8094, dst_vip, 8094, payload).await;
        if let Some(got) = to.deliver(Duration::from_millis(300)).await {
            assert_eq!(got, (src_vip, 8094, payload.to_vec()));
            // Drain stragglers of earlier attempts.
            while to.deliver(Duration::from_millis(50)).await.is_some() {}
            return;
        }
        assert!(tokio::time::Instant::now() < deadline, "{payload:?} did not arrive within {within:?}");
    }
}

/// Regression: a server restart (update, `docker restart`) kicked every player
/// with "Der Server wird beendet." and the launcher took that `kick` for a
/// removal: no reconnect, relay closed, the running match lost all its players.
/// Also: while BFME runs, the reconnect delay must stay short (BFME drops a
/// silent player after 8 s + 20 s), the vIP must survive the restart and the
/// relay ports must be registered again at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_restart_mid_game_reconnects_quickly_with_the_same_vip() {
    let dir = TempDir::new("restart");
    let server = start_server(&dir.0, 0, SALT_A).await;
    let addr = server.control_addr();
    let mut alice = InGamePlayer::connect(&dir.0, "alice", addr, "Alice").await;
    let mut bob = InGamePlayer::connect(&dir.0, "bob", addr, "Bob").await;
    let (vip_a, vip_b) = (alice.connected(T).await.vip, bob.connected(T).await.vip);
    let alice_port = alice.agent.port();
    let (hook_a, hook_b) = (alice.hook().await, bob.hook().await);
    hook_a.reg(8094).await;
    hook_b.reg(8094).await;
    alice.acked(8094).await;
    bob.acked(8094).await;
    flows(&hook_a, &hook_b, (vip_a, vip_b), b"before", T).await;

    server.shutdown().await;
    for p in [&mut alice, &mut bob] {
        let e = p.lost().await;
        assert!(matches!(e, ControlError::ServerStopped { .. }), "{e:?}");
    }
    // A restart that takes a while: the exponential backoff (1, 1, 2, 4, 8 s; on
    // Windows a refused connect itself takes about 2 s) would be at 4 s by now.
    tokio::time::sleep(Duration::from_secs(12)).await;
    let server = start_server(&dir.0, addr.port(), SALT_A).await;
    for p in [&mut alice, &mut bob] {
        let (c, delays) = p.reconnected(T).await;
        assert!(delays.len() >= 2, "{delays:?}");
        let max = control::BACKOFF_MAX_IN_GAME + control::BACKOFF_MAX_IN_GAME / 4;
        assert!(delays.iter().all(|d| *d <= max), "in-game retry delays {delays:?}");
        assert_eq!(c.vip, if p.agent.port() == alice_port { vip_a } else { vip_b }, "vIPs survive the restart");
    }
    flows(&hook_a, &hook_b, (vip_a, vip_b), b"after", T).await;
    flows(&hook_b, &hook_a, (vip_b, vip_a), b"and back", T).await;
    alice.stop().await;
    bob.stop().await;
    server.shutdown().await;
}

/// A TCP forwarder for one player's control connection. `cut` closes the
/// player's side of the current connections but keeps the server's side open
/// and silent: what the server sees when the player's public IP changes
/// (DSL reconnect) - it holds the player until its idle timeout.
struct CutProxy {
    addr: SocketAddr,
    cut: watch::Sender<u32>,
}

impl CutProxy {
    async fn start(server: SocketAddr) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (cut, _) = watch::channel(0u32);
        let cut_tx = cut.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let Ok(upstream) = tokio::net::TcpStream::connect(server).await else {
                    continue;
                };
                let mut cut_rx = cut_tx.subscribe();
                cut_rx.borrow_and_update();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let (mut cr, mut cw) = client.into_split();
                    let (mut ur, mut uw) = upstream.into_split();
                    let (mut a, mut b) = ([0u8; 4096], [0u8; 4096]);
                    loop {
                        tokio::select! {
                            r = cr.read(&mut a) => match r {
                                Ok(n) if n > 0 => {
                                    if uw.write_all(&a[..n]).await.is_err() {
                                        return;
                                    }
                                }
                                _ => return,
                            },
                            r = ur.read(&mut b) => match r {
                                Ok(n) if n > 0 => {
                                    if cw.write_all(&b[..n]).await.is_err() {
                                        return;
                                    }
                                }
                                _ => return,
                            },
                            _ = cut_rx.changed() => {
                                drop((cr, cw));
                                // Keep the server's side open; swallow what it sends.
                                let _keep = uw;
                                while matches!(ur.read(&mut b).await, Ok(n) if n > 0) {}
                                return;
                            }
                        }
                    }
                });
            }
        });
        Self { addr, cut }
    }

    fn cut(&self) {
        self.cut.send_modify(|n| *n += 1);
    }
}

/// Regression: when the control connection broke while the server still held the
/// player, the launcher closed the relay at once. The game then lost its peers
/// until the server's idle timeout released the name (reconnects are refused with
/// `name_taken` until then) - BFME drops a player after 28 s. The relay session
/// must stay usable until the server ends it, and the reconnect must follow.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn broken_control_connection_keeps_the_relay_until_the_server_lets_go() {
    let dir = TempDir::new("halfopen");
    let server = start_server_with(&dir.0, 0, SALT_A, |s| s.idle_timeout = Duration::from_secs(15)).await;
    let proxy = CutProxy::start(server.control_addr()).await;
    let mut alice = InGamePlayer::connect(&dir.0, "alice", proxy.addr, "Alice").await;
    let mut bob = InGamePlayer::connect(&dir.0, "bob", server.control_addr(), "Bob").await;
    let (vip_a, vip_b) = (alice.connected(T).await.vip, bob.connected(T).await.vip);
    let (hook_a, hook_b) = (alice.hook().await, bob.hook().await);
    hook_a.reg(8094).await;
    hook_b.reg(8094).await;
    alice.acked(8094).await;
    bob.acked(8094).await;
    flows(&hook_b, &hook_a, (vip_b, vip_a), b"before", T).await;

    // Alice's control connection breaks; the server does not notice (yet: it last
    // heard from her at most 5 s ago and holds her for 15 s).
    proxy.cut();
    let e = alice.lost().await;
    assert!(matches!(e, ControlError::Closed { .. }), "{e:?}");
    // The game keeps talking through the relay in both directions.
    let quick = Duration::from_secs(2);
    flows(&hook_b, &hook_a, (vip_b, vip_a), b"during", quick).await;
    flows(&hook_a, &hook_b, (vip_a, vip_b), b"during, back", quick).await;
    assert!(alice.agent.stats().session_active);
    assert!(!alice.logged_in_meanwhile(), "that went through the old relay session");

    // Once the server drops the silent connection, Alice gets back in with the
    // same vIP (after `name_taken` refusals) and her ports are registered again.
    let (a, _) = alice.reconnected(Duration::from_secs(30)).await;
    assert_eq!(a.vip, vip_a);
    flows(&hook_b, &hook_a, (vip_b, vip_a), b"after", T).await;
    alice.stop().await;
    bob.stop().await;
    server.shutdown().await;
}
