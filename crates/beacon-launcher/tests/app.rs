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
