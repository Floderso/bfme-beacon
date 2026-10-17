//! The harness scenarios. Each runs in its own child process (the hook reads its
//! environment once, in `DllMain`), sets its `BEACON_*` variables, loads the DLL
//! by full path and checks the observable behaviour.

use std::fmt::{Debug, Display};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use beacon_proto::local::{FrameType, HookFrame, MAX_DELIVER_PAYLOAD};

use crate::agent::{Agent, Frame};
use crate::win::{self, Module, SockAddrIn, Ws};

const VIP: [u8; 4] = [198, 18, 0, 5];
const TOKEN: u32 = 0xC0FF_EE42;
const TOKEN_TEXT: &str = "c0ffee42";
const SERIAL: &str = "ABCDEFGHIJ0123456789";
const ANY: [u8; 4] = [0, 0, 0, 0];
const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
const FRAME_WAIT: Duration = Duration::from_secs(2);
const SILENCE: Duration = Duration::from_millis(150);

/// Every name the hook implements (gen_def.IMPLEMENTED) plus a few forwarders.
const EXPORTS: [&str; 32] = [
    "WSACleanup", "WSAGetLastError", "WSAStartup", "__WSAFDIsSet", "accept", "bind",
    "closesocket", "connect", "gethostbyname", "gethostname", "getpeername", "getsockname",
    "getsockopt", "htonl", "inet_addr", "inet_ntoa", "ioctlsocket", "listen", "ntohs", "recv",
    "recvfrom", "select", "send", "sendto", "setsockopt", "shutdown", "socket",
    // forwarders
    "htons", "ntohl", "WSASetLastError", "gethostbyaddr", "AcceptEx",
];

/// Pass/fail bookkeeping of one scenario (no panics: every check is recorded).
pub struct Checks {
    scenario: &'static str,
    passed: u32,
    failed: u32,
}

impl Checks {
    pub fn new(scenario: &'static str) -> Self {
        Self { scenario, passed: 0, failed: 0 }
    }

    pub fn ok(&mut self, cond: bool, what: impl Display) -> bool {
        if cond {
            self.passed += 1;
        } else {
            self.failed += 1;
            println!("  FAIL [{}] {what}", self.scenario);
        }
        cond
    }

    pub fn eq<T: PartialEq + Debug>(&mut self, got: T, want: T, what: &str) -> bool {
        let ok = got == want;
        self.ok(ok, format_args!("{what}: got {got:?}, want {want:?}"))
    }

    pub fn summary(&self) -> bool {
        println!("  [{}] {} checks passed, {} failed", self.scenario, self.passed, self.failed);
        self.failed == 0
    }
}

/// Scratch directory of one scenario (removed on drop unless keeping logs).
struct Scratch(PathBuf);

impl Scratch {
    fn new(scenario: &str) -> Result<Self, String> {
        let dir = std::env::temp_dir().join(format!("beacon-hook-harness-{}-{scenario}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        Ok(Self(dir))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if std::env::var_os("BEACON_HARNESS_KEEP").is_none() {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn set(name: &str, value: impl AsRef<std::ffi::OsStr>) {
    std::env::set_var(name, value);
}

fn arm_env(agent: &Agent, vip: &str, log: &Path) {
    set("BEACON_AGENT_PORT", agent.port().to_string());
    set("BEACON_LOCAL_TOKEN", TOKEN_TEXT);
    set("BEACON_VIP", vip);
    set("BEACON_LOG", log);
    set("BEACON_LOG_LEVEL", "debug");
}

fn read_log(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn sockaddr(sa: &SockAddrIn) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(sa.addr), sa.port()))
}

/// `recvfrom` until something other than `WSAEWOULDBLOCK` (non-blocking socket).
fn recv_poll(ws: &Ws, s: usize, buf: &mut [u8], flags: i32) -> (i32, SockAddrIn, i32, i32) {
    for _ in 0..1000 {
        let (r, from, len) = ws.recv_from(s, buf, flags);
        let err = if r == -1 { ws.err() } else { 0 };
        if err != win::WSAEWOULDBLOCK {
            return (r, from, len, err);
        }
        sleep(Duration::from_millis(2));
    }
    (-1, SockAddrIn::default(), 0, win::WSAEWOULDBLOCK)
}

fn expect_frame(c: &mut Checks, agent: &Agent, kind: FrameType, what: &str) -> Option<Frame> {
    match agent.next(FRAME_WAIT) {
        Ok(f) => {
            c.eq(f.header.kind, kind, &format!("{what}: frame type"));
            c.eq(f.header.token, TOKEN, &format!("{what}: token"));
            c.eq(f.header.flags, 0, &format!("{what}: flags"));
            Some(f)
        }
        Err(e) => {
            c.ok(false, format_args!("{what}: {e}"));
            None
        }
    }
}

fn check_send(c: &mut Checks, f: &Frame, src_vport: u16, dst: [u8; 4], dst_vport: u16, payload: &[u8], what: &str) {
    let want = HookFrame::send(src_vport, Ipv4Addr::from(dst), dst_vport, TOKEN);
    c.eq(f.header, want, &format!("{what}: SEND header"));
    c.ok(f.payload == payload, format_args!("{what}: payload ({} B)", f.payload.len()));
}

fn load(c: &mut Checks, dll: &Path) -> Result<(Module, Ws), String> {
    let module = Module::load(dll)?;
    let ws = Ws::load(&module)?;
    c.eq(ws.startup(), 0, "WSAStartup(2.2)");
    Ok((module, ws))
}

/// (a) Passive: no `BEACON_AGENT_PORT` — real loopback traffic works, WinSock 1.1
/// semantics equal the system wsock32, nothing is logged.
pub fn passive(c: &mut Checks, dll: &Path) -> Result<(), String> {
    let scratch = Scratch::new("passive")?;
    let log = scratch.path("hook.log");
    set("BEACON_LOG", &log); // must stay unused: passive mode never logs
    set("BEACON_VIP", "198.18.0.5"); // ignored without BEACON_AGENT_PORT

    let module = Module::load(dll)?;
    for name in EXPORTS {
        c.ok(module.proc(name).is_some(), format_args!("GetProcAddress({name})"));
    }
    let ws = Ws::load(&module)?;
    c.eq(ws.startup(), 0, "WSAStartup(2.2)");
    c.eq(ws.htonl(0x0102_0304), 0x0403_0201, "htonl");
    c.eq(ws.ntohs(0x1F96), 0x961F, "ntohs");

    let a = ws.socket(0);
    let b = ws.socket(win::IPPROTO_UDP);
    c.ok(a != win::INVALID_SOCKET && b != win::INVALID_SOCKET, "socket(AF_INET, SOCK_DGRAM)");
    c.eq(ws.bind(a, LOOPBACK, 0), 0, "bind a 127.0.0.1:0");
    c.eq(ws.bind(b, LOOPBACK, 0), 0, "bind b 127.0.0.1:0");
    let (sa, sb) = match (ws.sockname(a), ws.sockname(b)) {
        (Ok((sa, _)), Ok((sb, _))) => (sa, sb),
        other => return Err(format!("getsockname failed: {other:?}")),
    };
    c.ok(sa.addr == LOOPBACK && sa.port() != 0, format_args!("getsockname a = {:?}", sockaddr(&sa)));
    let msg = b"passive hello";
    c.eq(ws.send_to(a, msg, LOOPBACK, sb.port()), msg.len() as i32, "sendto a -> b");
    let mut buf = [0u8; 1038];
    let (r, from, fromlen) = ws.recv_from(b, &mut buf, 0); // blocking
    c.eq(r, msg.len() as i32, "recvfrom b length");
    c.ok(buf.get(..msg.len()) == Some(&msg[..]), "recvfrom b payload");
    c.eq(sockaddr(&from), sockaddr(&sa), "recvfrom from = a");
    c.eq(fromlen, 16, "recvfrom fromlen");
    c.eq(ws.hostname().ok(), win::real_hostname(), "gethostname is the real name");
    if let Some(real) = win::real_hostname() {
        c.ok(ws.host_by_name(Some(&real)).is_some_and(|(t, l, a)| t == 2 && l == 4 && !a.is_empty()), "gethostbyname(real)");
    }

    // Exactly the system wsock32's WinSock 1.1 behaviour (option renumbering etc.).
    match Module::load(Path::new(r"C:\Windows\SysWOW64\wsock32.dll")) {
        Ok(sys_module) if sys_module.handle() != module.handle() => {
            let sys = Ws::load(&sys_module)?;
            // WinSock 1.1 IP_TTL (7) -> ws2 IP_TTL (4): set via ours, read via system.
            c.eq(ws.set_int_opt(a, win::IPPROTO_IP, 7, 77), 0, "ours setsockopt(IP_TTL ws1)");
            c.eq(sys.get_int_opt(a, win::IPPROTO_IP, 7), Ok(77), "system getsockopt(IP_TTL ws1)");
            c.eq(ws.get_int_opt(a, win::IPPROTO_IP, 7), Ok(77), "ours getsockopt(IP_TTL ws1)");
            // WinSock 1.1 IP_MULTICAST_TTL (3 -> 10): set via system, read via ours.
            c.eq(sys.set_int_opt(a, win::IPPROTO_IP, 3, 5), 0, "system setsockopt(IP_MULTICAST_TTL ws1)");
            c.eq(ws.get_int_opt(a, win::IPPROTO_IP, 3), sys.get_int_opt(a, win::IPPROTO_IP, 3), "IP_MULTICAST_TTL ws1 equal");
            c.eq(ws.get_int_opt(a, win::SOL_SOCKET, win::SO_BROADCAST), sys.get_int_opt(a, win::SOL_SOCKET, win::SO_BROADCAST), "SO_BROADCAST equal");
            // Error paths equal.
            let bogus = 0xDEAD_BEE0usize;
            c.eq(ws.get_int_opt(bogus, win::SOL_SOCKET, win::SO_BROADCAST), Err(win::WSAENOTSOCK), "ours getsockopt(bad socket)");
            c.eq(sys.get_int_opt(bogus, win::SOL_SOCKET, win::SO_BROADCAST), Err(win::WSAENOTSOCK), "system getsockopt(bad socket)");
            // Empty non-blocking socket: both report WSAEWOULDBLOCK.
            c.eq(ws.set_nonblocking(b), 0, "ioctlsocket(FIONBIO)");
            let (r1, _, _) = ws.recv_from(b, &mut buf, 0);
            let e1 = ws.err();
            let (r2, _, _) = sys.recv_from(b, &mut buf, 0);
            let e2 = sys.err();
            c.eq((r1, e1), (-1, win::WSAEWOULDBLOCK), "ours recvfrom(empty)");
            c.eq((r2, e2), (-1, win::WSAEWOULDBLOCK), "system recvfrom(empty)");
            let r3 = ws.recv(b, &mut buf);
            c.eq((r3, ws.err()), (-1, win::WSAEWOULDBLOCK), "ours recv(empty)");
        }
        Ok(_) => println!("  note: system wsock32 resolved to the proxy module; comparison skipped"),
        Err(e) => println!("  note: {e}; comparison skipped"),
    }
    c.eq(ws.close(a), 0, "closesocket a");
    c.eq(ws.close(b), 0, "closesocket b");
    c.eq(ws.cleanup(), 0, "WSACleanup");
    c.ok(!log.exists(), "passive mode wrote no log");
    Ok(())
}

/// (b) Armed without exe: the full virtual-socket contract (architecture §4.2/§5).
pub fn armed(c: &mut Checks, dll: &Path) -> Result<(), String> {
    let scratch = Scratch::new("armed")?;
    let log = scratch.path("hook.log");
    let agent = Agent::new().map_err(|e| format!("fake agent: {e}"))?;
    arm_env(&agent, "198.18.0.5", &log);
    set("BEACON_TEST_ARMED_WITHOUT_EXE", "1");
    let (_module, ws) = load(c, dll)?;

    // Local address discovery: VIP only.
    c.eq(ws.hostname(), Ok("BEACON-5".to_string()), "gethostname");
    let mut small = [0u8; 8];
    c.eq((ws.hostname_into(&mut small), ws.err()), (-1, win::WSAEFAULT), "gethostname(short buffer)");
    let vip_only = Some((2i16, 4i16, vec![VIP]));
    c.eq(ws.host_by_name(Some("BEACON-5")), vip_only.clone(), "gethostbyname(BEACON-5)");
    c.eq(ws.host_by_name(Some("beacon-5")), vip_only.clone(), "gethostbyname(beacon-5)");
    if let Some(real) = win::real_hostname() {
        c.eq(ws.host_by_name(Some(&real)), vip_only.clone(), "gethostbyname(real host name)");
    }
    c.eq(ws.host_by_name(Some("")), vip_only.clone(), "gethostbyname(\"\")");
    c.eq(ws.host_by_name(None), vip_only, "gethostbyname(NULL)");
    let localhost = ws.host_by_name(Some("localhost"));
    c.ok(localhost.as_ref().is_some_and(|(_, _, a)| a.contains(&LOOPBACK)), format_args!("gethostbyname(localhost) is real: {localhost:?}"));

    // Lobby socket: bind VIP:8086 -> REG.
    let s1 = ws.socket(0);
    c.eq(ws.bind(s1, VIP, 8086), 0, "bind VIP:8086");
    let reg = expect_frame(c, &agent, FrameType::Reg, "REG 8086").ok_or("no REG for 8086")?;
    c.eq(reg.header, HookFrame::reg(8086, TOKEN), "REG 8086 header");
    c.ok(reg.payload.is_empty(), "REG has no payload");
    let s1_loop = reg.src;
    c.eq(win::real_sockname(s1).map(|sa| sockaddr(&sa)), Some(s1_loop), "REG sent from the socket's loopback endpoint");
    c.eq(ws.sockname(s1), Ok((SockAddrIn::new(VIP, 8086), 16)), "getsockname VIP:8086");
    c.eq(ws.sockname_short_buffer(s1), (-1, win::WSAEFAULT), "getsockname(short namelen)");

    // Port probing: second VIP:8086 -> WSAEADDRINUSE, then 8087.
    let s2 = ws.socket(win::IPPROTO_UDP);
    c.eq((ws.bind(s2, VIP, 8086), ws.err()), (-1, win::WSAEADDRINUSE), "second bind VIP:8086");
    c.ok(agent.unexpected(SILENCE).is_none(), "no REG for a refused bind");
    c.eq(ws.bind(s2, VIP, 8087), 0, "bind VIP:8087");
    if let Some(f) = expect_frame(c, &agent, FrameType::Reg, "REG 8087") {
        c.eq(f.header.src_vport, 8087, "REG 8087 vport");
    }

    // In-game socket bound to ANY:8094 -> virtual.
    let s3 = ws.socket(0);
    c.eq(ws.bind(s3, ANY, 8094), 0, "bind ANY:8094");
    let s3_loop = expect_frame(c, &agent, FrameType::Reg, "REG 8094").map(|f| {
        c.eq(f.header.src_vport, 8094, "REG 8094 vport");
        f.src
    });
    c.eq(ws.sockname(s3), Ok((SockAddrIn::new(ANY, 8094), 16)), "getsockname 0.0.0.0:8094");

    // Socket options act on the real socket.
    c.eq(ws.set_int_opt(s1, win::SOL_SOCKET, win::SO_BROADCAST, 1), 0, "setsockopt(SO_BROADCAST)");
    c.eq(ws.get_int_opt(s1, win::SOL_SOCKET, win::SO_BROADCAST), Ok(1), "getsockopt(SO_BROADCAST)");
    c.eq(ws.set_nonblocking(s1), 0, "ioctlsocket(s1, FIONBIO)");
    c.eq(ws.set_nonblocking(s3), 0, "ioctlsocket(s3, FIONBIO)");

    // Lobby broadcast: 8 datagrams to 255.255.255.255:8086..8093 -> 8 SEND frames.
    let announce = b"\x11\x22\x33\x44 lobby announce";
    for port in 8086..=8093u16 {
        c.eq(ws.send_to(s1, announce, [255; 4], port), announce.len() as i32, &format!("sendto 255.255.255.255:{port}"));
    }
    for port in 8086..=8093u16 {
        if let Some(f) = expect_frame(c, &agent, FrameType::Send, &format!("broadcast SEND {port}")) {
            check_send(c, &f, 8086, [255; 4], port, announce, &format!("broadcast {port}"));
            c.eq(f.src, s1_loop, "SEND from the virtual socket");
        }
    }
    // Directed subnet broadcast.
    c.eq(ws.send_to(s1, b"x", [198, 18, 0, 255], 8086), 1, "sendto 198.18.0.255:8086");
    if let Some(f) = expect_frame(c, &agent, FrameType::Send, "subnet broadcast") {
        check_send(c, &f, 8086, [198, 18, 0, 255], 8086, b"x", "subnet broadcast");
    }
    // Broadcast without SO_BROADCAST is refused like on real Winsock.
    c.eq((ws.send_to(s3, b"y", [255; 4], 8094), ws.err()), (-1, win::WSAEACCES), "broadcast without SO_BROADCAST");

    // In-game unicast.
    let cmd = b"in-game command";
    c.eq(ws.send_to(s3, cmd, [198, 18, 0, 7], 8094), cmd.len() as i32, "sendto 198.18.0.7:8094");
    if let Some(f) = expect_frame(c, &agent, FrameType::Send, "unicast SEND") {
        check_send(c, &f, 8094, [198, 18, 0, 7], 8094, cmd, "unicast");
        c.eq(Some(f.src), s3_loop, "unicast SEND from s3");
    }
    // Non-virtual destination: dropped, but returns len; nothing reaches the agent.
    c.eq(ws.send_to(s1, b"internet", [8, 8, 8, 8], 8086), 8, "sendto 8.8.8.8 returns len");
    c.eq(ws.send_to(s1, b"lan", [192, 168, 1, 20], 8086), 3, "sendto 192.168.1.20 returns len");
    c.eq(ws.send_to(s1, b"marker", [198, 18, 0, 9], 8086), 6, "sendto marker");
    if let Some(f) = expect_frame(c, &agent, FrameType::Send, "marker after drops") {
        check_send(c, &f, 8086, [198, 18, 0, 9], 8086, b"marker", "only the marker arrives");
    }
    // Argument errors.
    let big = vec![0u8; 1025];
    c.eq((ws.send_to(s1, &big, [198, 18, 0, 9], 8086), ws.err()), (-1, win::WSAEMSGSIZE), "sendto 1025 B");
    c.eq((ws.send_to(s1, b"p", [198, 18, 0, 9], 0), ws.err()), (-1, win::WSAEADDRNOTAVAIL), "sendto port 0");
    c.ok(agent.unexpected(SILENCE).is_none(), "no frame for refused sends");

    // DELIVER -> recvfrom returns exactly the payload, from = src VIP:port.
    let mut buf = [0u8; 1038];
    let hello = b"lobby hello from .9";
    agent.deliver(s1_loop, Ipv4Addr::new(198, 18, 0, 9), 8086, hello).map_err(|e| e.to_string())?;
    let (r, from, fromlen, _) = recv_poll(&ws, s1, &mut buf, 0);
    c.eq(r, hello.len() as i32, "recvfrom DELIVER length");
    c.ok(buf.get(..hello.len()) == Some(&hello[..]), "recvfrom DELIVER payload");
    c.eq(from, SockAddrIn::new([198, 18, 0, 9], 8086), "recvfrom from = src VIP:port");
    c.eq(fromlen, 16, "recvfrom fromlen");
    // Empty non-blocking socket.
    let (r, _, _) = ws.recv_from(s1, &mut buf, 0);
    c.eq((r, ws.err()), (-1, win::WSAEWOULDBLOCK), "empty recvfrom -> WSAEWOULDBLOCK");

    // Foreign datagrams to the loopback socket are discarded.
    let intruder = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    intruder.send_to(b"evil", s1_loop).map_err(|e| e.to_string())?;
    sleep(Duration::from_millis(50));
    let (r, _, _) = ws.recv_from(s1, &mut buf, 0);
    c.eq((r, ws.err()), (-1, win::WSAEWOULDBLOCK), "foreign datagram discarded");
    // A DELIVER-looking datagram from another port is foreign too.
    let mut fake = Vec::from(&b"BCN1"[..]);
    fake.extend_from_slice(&[198, 18, 0, 66, 0x1F, 0x96, 0, 0]);
    fake.extend_from_slice(b"spoofed");
    intruder.send_to(&fake, s1_loop).map_err(|e| e.to_string())?;
    agent.deliver(s1_loop, Ipv4Addr::new(198, 18, 0, 10), 8086, b"genuine").map_err(|e| e.to_string())?;
    let (r, from, _, _) = recv_poll(&ws, s1, &mut buf, 0);
    c.eq(r, 7, "spoofed DELIVER skipped, genuine returned");
    c.eq(from, SockAddrIn::new([198, 18, 0, 10], 8086), "genuine from");

    // Garbage and oversize DELIVERs from the agent never crash and are skipped.
    let mut oversize = Vec::from(&b"BCN1"[..]);
    oversize.extend_from_slice(&[198, 18, 0, 9, 0x1F, 0x96, 0, 0]);
    oversize.resize(12 + MAX_DELIVER_PAYLOAD + 1, 0xAB);
    let garbage: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x42],
        b"BCN1".to_vec(),
        b"BCN1\xc6\x12\x00\x09\x1f".to_vec(),
        b"XXXX\xc6\x12\x00\x09\x1f\x96\x00\x00payload".to_vec(),
        b"bcn1\xc6\x12\x00\x09\x1f\x96\x00\x00payload".to_vec(),
        oversize,
        vec![0xFF; 2000],
        vec![0x00; 4000],
    ];
    // A near-maximum datagram on its own (together with the others it could exceed
    // the default 64 KiB receive buffer and push out the valid frame below).
    agent.send_raw(s1_loop, &vec![0x5A; 65_000]).map_err(|e| format!("send 65000 B: {e}"))?;
    sleep(Duration::from_millis(50));
    let (r, _, _) = ws.recv_from(s1, &mut buf, 0);
    c.eq((r, ws.err()), (-1, win::WSAEWOULDBLOCK), "65000-byte datagram discarded");
    for g in &garbage {
        agent.send_raw(s1_loop, g).map_err(|e| format!("send garbage ({} B): {e}", g.len()))?;
    }
    agent.deliver(s1_loop, Ipv4Addr::new(198, 18, 0, 11), 8087, b"after garbage").map_err(|e| e.to_string())?;
    let (r, from, _, _) = recv_poll(&ws, s1, &mut buf, 0);
    c.eq(r, 13, "garbage skipped, valid DELIVER returned");
    c.ok(buf.get(..13) == Some(&b"after garbage"[..]), "payload after garbage");
    c.eq(from, SockAddrIn::new([198, 18, 0, 11], 8087), "from after garbage");
    let (r, _, _) = ws.recv_from(s1, &mut buf, 0);
    c.eq((r, ws.err()), (-1, win::WSAEWOULDBLOCK), "queue empty after garbage");

    // Header-only DELIVER = empty datagram; maximum payload passes.
    agent.deliver(s1_loop, Ipv4Addr::new(198, 18, 0, 12), 8086, b"").map_err(|e| e.to_string())?;
    let (r, from, _, _) = recv_poll(&ws, s1, &mut buf, 0);
    c.eq((r, from), (0, SockAddrIn::new([198, 18, 0, 12], 8086)), "empty DELIVER");
    let max = vec![0x77u8; MAX_DELIVER_PAYLOAD];
    agent.deliver(s1_loop, Ipv4Addr::new(198, 18, 0, 12), 8086, &max).map_err(|e| e.to_string())?;
    let (r, _, _, _) = recv_poll(&ws, s1, &mut buf, 0);
    c.eq(r, MAX_DELIVER_PAYLOAD as i32, "480-byte DELIVER");

    // Truncation semantics: small buffer -> WSAEMSGSIZE with the first bytes.
    let long: Vec<u8> = (0..100u8).collect();
    agent.deliver(s1_loop, Ipv4Addr::new(198, 18, 0, 13), 8086, &long).map_err(|e| e.to_string())?;
    let mut tiny = [0u8; 10];
    let (r, from, _, err) = recv_poll(&ws, s1, &mut tiny, 0);
    c.eq((r, err), (-1, win::WSAEMSGSIZE), "truncated recvfrom");
    c.eq(&tiny[..], &long[..10], "truncated payload prefix");
    c.eq(from, SockAddrIn::new([198, 18, 0, 13], 8086), "truncated from");
    let (r, _, _) = ws.recv_from(s1, &mut buf, 0);
    c.eq((r, ws.err()), (-1, win::WSAEWOULDBLOCK), "truncated datagram consumed");

    // MSG_PEEK leaves the datagram queued; a foreign one in front is consumed.
    intruder.send_to(b"evil again", s1_loop).map_err(|e| e.to_string())?;
    agent.deliver(s1_loop, Ipv4Addr::new(198, 18, 0, 14), 8086, b"peek me").map_err(|e| e.to_string())?;
    let (r, from, _, _) = recv_poll(&ws, s1, &mut buf, win::MSG_PEEK);
    c.eq((r, from), (7, SockAddrIn::new([198, 18, 0, 14], 8086)), "MSG_PEEK");
    let (r, _, _) = ws.recv_from(s1, &mut buf, 0);
    c.eq(r, 7, "recvfrom after MSG_PEEK");
    c.ok(buf.get(..7) == Some(&b"peek me"[..]), "payload after MSG_PEEK");

    // recv() strips the header too.
    agent.deliver(s1_loop, Ipv4Addr::new(198, 18, 0, 15), 8086, b"via recv").map_err(|e| e.to_string())?;
    let mut got = -1;
    for _ in 0..500 {
        got = ws.recv(s1, &mut buf);
        if got != -1 || ws.err() != win::WSAEWOULDBLOCK {
            break;
        }
        sleep(Duration::from_millis(2));
    }
    c.eq(got, 8, "recv DELIVER length");
    c.ok(buf.get(..8) == Some(&b"via recv"[..]), "recv DELIVER payload");

    // REAL sockets are untouched: 127.0.0.1 bind, plain traffic.
    let receiver = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    receiver.set_read_timeout(Some(FRAME_WAIT)).map_err(|e| e.to_string())?;
    let rport = receiver.local_addr().map_err(|e| e.to_string())?.port();
    let s4 = ws.socket(0);
    c.eq(ws.bind(s4, LOOPBACK, 0), 0, "bind 127.0.0.1:0 (real)");
    c.ok(ws.sockname(s4).is_ok_and(|(sa, _)| sa.addr == LOOPBACK && sa.port() != 0), "real getsockname");
    c.eq(ws.send_to(s4, b"real traffic", LOOPBACK, rport), 12, "real sendto");
    let mut rbuf = [0u8; 64];
    let real = receiver.recv_from(&mut rbuf).map(|(n, _)| rbuf.get(..n).map(<[u8]>::to_vec));
    c.ok(matches!(&real, Ok(Some(v)) if v == b"real traffic"), format_args!("real datagram arrives: {real:?}"));
    let s5 = ws.socket(0);
    c.eq(ws.bind(s5, ANY, 0), 0, "bind 0.0.0.0:0 (real)");
    c.ok(ws.sockname(s5).is_ok_and(|(sa, _)| sa.addr == ANY && sa.port() != 0), "real ANY getsockname");
    // An unbound candidate used by sendto becomes real (implicit bind).
    let s6 = ws.socket(0);
    c.eq(ws.send_to(s6, b"implicit", LOOPBACK, rport), 8, "sendto on unbound socket (real)");
    let real = receiver.recv_from(&mut rbuf).map(|(n, _)| n);
    c.ok(matches!(real, Ok(8)), "implicitly bound datagram arrives");
    c.ok(ws.bind(s6, VIP, 8090) == -1, "bind after implicit bind fails natively");
    c.ok(agent.unexpected(SILENCE).is_none(), "real sockets send no frames");

    // bind(VIP:0) -> ephemeral vport.
    let s7 = ws.socket(0);
    c.eq(ws.bind(s7, VIP, 0), 0, "bind VIP:0");
    if let Some(f) = expect_frame(c, &agent, FrameType::Reg, "REG ephemeral") {
        c.eq(f.header.src_vport, 49152, "ephemeral vport");
    }
    c.eq(ws.sockname(s7), Ok((SockAddrIn::new(VIP, 49152), 16)), "getsockname VIP:49152");

    // closesocket -> CLOSE; shutdown(SD_BOTH) sends it before the close.
    c.eq(ws.close(s2), 0, "closesocket s2");
    if let Some(f) = expect_frame(c, &agent, FrameType::Close, "CLOSE 8087") {
        c.eq(f.header, HookFrame::close(8087, TOKEN), "CLOSE 8087 header");
    }
    c.eq(ws.shutdown(s1, win::SD_BOTH), 0, "shutdown s1");
    if let Some(f) = expect_frame(c, &agent, FrameType::Close, "CLOSE 8086 at shutdown") {
        c.eq(f.header.src_vport, 8086, "CLOSE 8086 vport");
        c.eq(f.src, s1_loop, "CLOSE from s1");
    }
    let (r, _, _) = ws.recv_from(s1, &mut buf, 0);
    c.ok(r == -1, "recvfrom after shutdown fails (drain loop ends)");
    c.eq(ws.close(s1), 0, "closesocket s1");
    c.ok(agent.unexpected(SILENCE).is_none(), "no second CLOSE for s1");
    // The vport is free again.
    let s8 = ws.socket(0);
    c.eq(ws.bind(s8, VIP, 8086), 0, "re-bind VIP:8086 after close");
    let _ = expect_frame(c, &agent, FrameType::Reg, "REG 8086 again");
    for s in [s3, s4, s5, s6, s7, s8] {
        ws.close(s);
    }
    for _ in 0..3 {
        let _ = agent.next(SILENCE);
    }
    c.eq(ws.cleanup(), 0, "WSACleanup");

    let text = read_log(&log);
    c.ok(text.contains("armed (BEACON_TEST_ARMED_WITHOUT_EXE)"), "log: armed line");
    c.ok(text.contains("REG sent"), "log: bind line");
    c.ok(text.contains("rx ") && text.contains("discarded"), "log: debug datagram lines");
    c.ok(text.contains("oversize datagram discarded"), "log: oversize datagram line");
    c.ok(!text.contains(TOKEN_TEXT), "log never contains the token");
    Ok(())
}

/// (c) `BEACON_MULTI=1` in armed-without-exe mode: loads and works (no IAT
/// patches happen without the exe).
pub fn multi(c: &mut Checks, dll: &Path) -> Result<(), String> {
    let scratch = Scratch::new("multi")?;
    let log = scratch.path("hook.log");
    let userdir = scratch.path("userdir");
    let agent = Agent::new().map_err(|e| format!("fake agent: {e}"))?;
    arm_env(&agent, "198.18.0.77", &log);
    set("BEACON_TEST_ARMED_WITHOUT_EXE", "1");
    set("BEACON_MULTI", "1");
    set("BEACON_USERDIR", &userdir);
    set("BEACON_SERIAL", SERIAL);
    let (_module, ws) = load(c, dll)?;
    c.eq(ws.hostname(), Ok("BEACON-77".to_string()), "gethostname");
    let s = ws.socket(0);
    c.eq(ws.bind(s, [198, 18, 0, 77], 8086), 0, "bind VIP:8086");
    if let Some(f) = expect_frame(c, &agent, FrameType::Reg, "REG") {
        c.eq(f.header.src_vport, 8086, "REG vport");
    }
    c.eq(ws.close(s), 0, "closesocket");
    let _ = expect_frame(c, &agent, FrameType::Close, "CLOSE");
    c.eq(ws.cleanup(), 0, "WSACleanup");
    let text = read_log(&log);
    c.ok(text.contains("armed (BEACON_TEST_ARMED_WITHOUT_EXE)"), "log: armed line");
    c.ok(!text.contains("IAT:"), "log: no IAT patching without the exe");
    Ok(())
}

/// Identity check: armed environment, but the host is not lotrbfme.exe 1.03 (like
/// worldbuilder.exe) -> passive, silent.
pub fn not_the_game(c: &mut Checks, dll: &Path) -> Result<(), String> {
    let scratch = Scratch::new("not-the-game")?;
    let log = scratch.path("hook.log");
    let agent = Agent::new().map_err(|e| format!("fake agent: {e}"))?;
    arm_env(&agent, "198.18.0.5", &log);
    let (_module, ws) = load(c, dll)?;
    c.eq(ws.hostname().ok(), win::real_hostname(), "gethostname is the real name");
    let s = ws.socket(0);
    c.eq((ws.bind(s, VIP, 8086), ws.err()), (-1, win::WSAEADDRNOTAVAIL), "bind VIP fails natively");
    c.ok(agent.unexpected(SILENCE).is_none(), "no frames");
    ws.close(s);
    c.eq(ws.cleanup(), 0, "WSACleanup");
    c.ok(!log.exists(), "no log written");
    Ok(())
}

/// Bad configuration (VIP outside the virtual subnet): passive + one log line.
pub fn bad_config(c: &mut Checks, dll: &Path) -> Result<(), String> {
    let scratch = Scratch::new("bad-config")?;
    let log = scratch.path("hook.log");
    let agent = Agent::new().map_err(|e| format!("fake agent: {e}"))?;
    arm_env(&agent, "10.1.2.3", &log);
    set("BEACON_TEST_ARMED_WITHOUT_EXE", "1");
    let (_module, ws) = load(c, dll)?;
    c.eq(ws.hostname().ok(), win::real_hostname(), "gethostname is the real name");
    let s = ws.socket(0);
    c.eq((ws.bind(s, VIP, 8086), ws.err()), (-1, win::WSAEADDRNOTAVAIL), "bind VIP fails natively");
    c.ok(agent.unexpected(SILENCE).is_none(), "no frames");
    ws.close(s);
    c.eq(ws.cleanup(), 0, "WSACleanup");
    let text = read_log(&log);
    c.ok(text.contains("configuration error: BEACON_VIP"), format_args!("log explains the error: {text:?}"));
    Ok(())
}
