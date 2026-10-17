# BFME Beacon — architecture and protocol (engineering contract)

Status: v0.3 (2026-10-17). Facts about BFME come from `D:/BFME-RE/specs/*.md`
(Open-BFME sources + retail disassembly, cited there). If this document and a spec
disagree, the spec's cited evidence wins; fix this document.

## 1. Goals and non-goals

1. A friend starts `Beacon.exe`; a page opens in the browser: server address, name,
   password → lobby (players, ping, data check, chat, map pool). "Spielen" starts
   BFME; in BFME's own *Multiplayer → Network (LAN)* screen every Beacon player sees
   and joins the same games as on one LAN.
2. `beacon-server` runs on the user's Linux home server (static musl binary in
   Docker), needs one port number forwarded for TCP **and** UDP, never becomes the
   bottleneck, never panics on hostile input.
3. Lowest possible lag: one relay hop, per-packet redundancy against loss (one lost
   BFME packet on the critical path = ~2 s freeze in retail), Open-BFME latency
   fixes applied in memory.
4. No crashes caused by Beacon: if anything fails, the game just sees an empty LAN.
5. Identical game data enforced (BFME refuses joins on exe/INI CRC mismatch; Beacon
   shows it earlier and explains it).
6. Ship only our own code (GPL-3.0-or-later). Never ship EA files or a patched exe.

Non-goals v1: replacing BFME's LAN lobby, dedicated/headless hosting, P2P hole
punching, anti-cheat, LAA (opt-in later, see §10).

## 2. Components

| Crate | Target | Role |
|---|---|---|
| `beacon-proto` | all incl. i686 | relay wire format + crypto, control messages, fingerprint types, local (hook↔agent) frame format |
| `beacon-server` | x86_64 musl (+Windows) | TCP control (Noise), UDP relay, lobby, chat, map repository, BFME packet inspection (lag/desync), status |
| `beacon-launcher` | x86_64 Windows `Beacon.exe` | browser UI on 127.0.0.1, control client, **agent** (bridges hook ↔ relay), game detection, map sync, fingerprint, hook install, game start |
| `beacon-hook` | i686 Windows `wsock32.dll` | wsock32 proxy in the game folder; socket virtualisation only; inert unless armed |
| `beacon-mod` | x86_64 Windows/Linux | modding CLI (BIG, INI lint, CSF, map packs) — later phase |

Dependency rule (Smart App Control on the dev PC blocks some unsigned cargo build
scripts): keep dependency graphs small. Known-good: tokio, axum, serde/serde_json,
snow, argon2, chacha20poly1305, blake3 ("pure"), tracing. Known-blocked build
scripts: ahash, num-traits (both via eframe) → no eframe/egui.

## 3. BFME facts that drive the design (from specs 01–04)

* LAN lobby socket: UDP, bound to the chosen **local IP** (not ANY), first free port
  8086…8093, non-blocking, `SO_BROADCAST`. A broadcast = 8 datagrams to
  `255.255.255.255` on ports 8086…8093. Poll 200 ms, announce/keep-alive 2 s,
  timeouts 20 s, join/leave 5 s. Many lobby messages (GAME_START, …) are sent once.
* In-game socket: UDP bound to `localIP : lobbyPort+8` (8094…8101), unicast only.
  Topology = star via the packet router (slot 0 = host) **plus** direct
  guest↔guest keep-alives/chat/resends → the relay must forward every pair.
* Every datagram ≤ 480 bytes (4-byte checksum + ≤ 476 payload, XOR-obfuscated,
  not encrypted). Game receive buffer 1038 bytes.
* Peer identity = **(IPv4, port)**, also embedded inside lobby payloads; the ACK
  return path matches the exact source endpoint. ⇒ every player gets one stable
  virtual IPv4, the game's own ports are preserved end-to-end, and every delivered
  datagram carries the sender's true virtual source. No payload rewriting.
* Local IP: `gethostname` + `gethostbyname` at **engine start** (cached in
  GlobalData) ⇒ the virtual IP must be known before the game process starts.
* The LAN path uses only: `socket, bind, getsockname, ioctlsocket(FIONBIO),
  setsockopt(SO_BROADCAST), sendto, recvfrom, WSAGetLastError, shutdown,
  closesocket, htonl/ntohs, gethostname, gethostbyname` — never `select`,
  `FIONREAD`, `WSAIoctl`, TCP. `recvfrom`/`setsockopt` are imported from WS2_32
  (KnownDLL ⇒ IAT patch at RVA 0x00F58CB0…0x00F58CC0); the rest from WSOCK32
  (not a KnownDLL ⇒ proxy DLL in the game folder is loaded).
* Join admission: byte-identical exe (CRC of the exe **file**), identical INI CRC,
  **different CD key** (`HKLM\…\The Battle for Middle-earth\ergc` default value) and
  unique player name.
* Single-instance guard (for 2-instance tests only): `CreateMutexW(L"E99E8455-CC9B-
  488a-BA22-0E8A8F74F9FA")`, plus `CreateMutexA("LOTRMilesAudioManagerMutex")`;
  per-instance user dir via `SHGetSpecialFolderPath(CSIDL_APPDATA)` or the
  `UserDataLeafName` registry value.
* Failure timing (patch 1.05/1.06 data): disconnect screen after 8 s of silence,
  kick after +20 s; router stalls everyone if a guest is > 2 s behind; ACK resend
  2000 ms (400 ms with Open-BFME `033-retrytime`); desync CRC every 100 frames.

## 4. Data path

```
lotrbfme.exe ── hook (wsock32.dll) ── loopback UDP ── Beacon.exe agent ── UDP (encrypted) ── beacon-server
 game sockets are real UDP sockets      "BCN1" frames        redundancy, dedupe,        relay + lobby
 bound to 127.0.0.1:ephemeral           (§5)                 stats (§6)
```

### 4.1 Addressing
* Virtual subnet **198.18.0.0/24** (RFC 2544 benchmark range: never routed, will not
  collide with home LANs/VPNs). `198.18.0.1` = server (reserved), clients
  `.2 … .254`, sticky per player name while the server runs. Broadcast forms:
  `255.255.255.255` and `198.18.0.255`.
* Virtual ports = the ports the game binds (8086…8101 in practice).

### 4.2 Hook (in `lotrbfme.exe`)
Armed only if `BEACON_AGENT_PORT` is set; otherwise every export is a pure
pass-through to the real `%SystemRoot%\SysWOW64\wsock32.dll` and nothing is patched.

When armed, in `DllMain(PROCESS_ATTACH)` (no threads, no blocking): load the real
wsock32, IAT-patch the main module's WS2_32 imports (`recvfrom`, `setsockopt`,
`getsockopt`, `recv`, `WSAIoctl`), and patch `kernel32/advapi32` imports needed for
§4.4. The hook has **no threads, no crypto, no allocation on the hot path**.

* `socket(AF_INET, SOCK_DGRAM, 0|IPPROTO_UDP)` → real socket, remembered as candidate.
* `bind(s, {VIP or ANY, port})` with `port` in 8086…8101 (or addr == VIP) →
  VIRTUAL: real `bind(127.0.0.1:0)`; if this process already has a VIRTUAL socket
  on the same vport → fail `WSAEADDRINUSE` (keeps BFME's port probing working);
  send `REG` (§5) from the socket to the agent. Other binds → REAL (untouched).
* `sendto(VIRTUAL, buf, len, dst)` with dst in 198.18.0.0/24 or broadcast → one
  `SEND` frame to `127.0.0.1:BEACON_AGENT_PORT` from the same socket; return `len`.
  Other destinations: drop silently, return `len` (no internet traffic from the
  LAN sockets).
* `recvfrom(VIRTUAL, buf, len, flags, from, fromlen)` → loop: real `recvfrom`; accept
  only datagrams from `127.0.0.1:BEACON_AGENT_PORT` with a valid `DELIVER` header;
  strip the header in place (`memmove`), fill `from = {src vIP, src vport}`,
  return the payload length. Anything else is discarded; if nothing valid is left
  return what the real call returned (`WSAEWOULDBLOCK` on a non-blocking socket).
* `getsockname(VIRTUAL)` → `{VIP, vport}` (or `{0.0.0.0, vport}` if bound to ANY).
* `gethostname` → `BEACON-<last octet>`; `gethostbyname(that name | real hostname)` →
  hostent with exactly one address, the VIP (static storage). Other names → real.
* `closesocket(VIRTUAL)` → `CLOSE` frame, real close, forget the entry.
* `setsockopt/getsockopt/ioctlsocket/shutdown/select/WSAGetLastError` → real
  (they act on the real loopback socket; semantics stay native).
* Errors inside the hook ⇒ fall back to pass-through for that call; never panic
  (`panic = "abort"` profile, no `unwrap` on runtime data). Log (rate-limited) to
  `BEACON_LOG` if set.

### 4.3 Environment contract (launcher → hook)
| Variable | Meaning |
|---|---|
| `BEACON_AGENT_PORT` | agent's loopback UDP port (arms the hook) |
| `BEACON_LOCAL_TOKEN` | u32 hex; must appear in every hook→agent frame |
| `BEACON_VIP` | dotted virtual IPv4 |
| `BEACON_SERIAL` | 20-char `[A-Z0-9]` value returned for the `ergc` registry read (unique per player) |
| `BEACON_PATCHES` | comma list of in-memory patch ids to apply (§10), optional |
| `BEACON_MULTI` | `1` = test mode: bypass single-instance + Miles mutex; requires `BEACON_USERDIR` |
| `BEACON_USERDIR` | absolute user-data base dir for this instance (test mode) |
| `BEACON_LOG` | optional log path |

### 4.4 Other hooks (armed mode)
* `RegQueryValueExA/W` on the `ergc` key's default value → `BEACON_SERIAL`.
* Test mode only: `CreateMutexW(GUID)` / `CreateMutexA("LOTRMilesAudioManagerMutex")`
  → PID-suffixed names; `SHGetSpecialFolderPathA/W(CSIDL_APPDATA)` → `BEACON_USERDIR`.

## 5. Local frames (hook ↔ agent, loopback UDP, big-endian)

Hook → agent, sent **from the virtual socket's real loopback socket**:
```
0  4  magic "BCN1"
4  1  type: 1 REG, 2 SEND, 3 CLOSE
5  1  flags = 0
6  2  src vport
8  4  dst vIP (network order; 255.255.255.255 / 198.18.0.255 = broadcast)
12 2  dst vport
14 2  reserved = 0
16 4  local token (BEACON_LOCAL_TOKEN)
20 .. payload (SEND only, ≤ 1024 bytes)
```
Agent → hook (`DELIVER`), sent from the agent socket to the registered loopback port:
```
0  4  magic "BCN1"
4  4  src vIP (network order)
8  2  src vport
10 2  reserved = 0
12 .. payload (≤ 480 bytes; larger payloads are dropped by the agent)
```
The agent learns `vport → loopback endpoint` from `REG` (and from every `SEND`'s
source). Self-addressed datagrams (dst = own VIP or broadcast including self? —
broadcasts are **not** delivered back to the sender) are looped back locally.

## 6. Relay protocol (agent ↔ server, UDP, one port)

Header 24 bytes + payload + 16-byte Poly1305 tag (ChaCha20-Poly1305, AAD = header):
```
0  2  magic 0xBE 0xAC
2  1  version 1
3  1  type: 1 REG, 2 DATA, 3 PING, 4 PONG, 5 REG_ACK, 6 ERROR, 7 BYE, 8 UNREG
4  4  session id, u32 LE (agent→server) | 0 (server→agent)
8  8  counter, u64 LE (per sender per direction, strictly increasing; also nonce + dedupe key)
16 4  vIP (agent→server: destination; server→agent: source), network order
20 2  src vport (BE)
22 2  dst vport (BE)
```
Nonce = direction (1 = agent→server, 2 = server→agent) ‖ 3 zero bytes ‖ counter (u64 LE).
* Key + session id + VIP are issued in `welcome` over the control channel.
* Every packet is authenticated; the server rejects a source vIP other than the
  session's own (spec 02 A6).
* **Redundancy**: DATA is sent `R` times with the **same counter** (copies 2…R
  delayed by 3 ms and 10 ms). Default R = 3 for lobby ports (8086…8093) and 2 for
  game ports (8094…8101); configurable. The receiver's 256-entry sliding replay
  window discards the copies (spec 02 A5: never deliver twice).
* Forwarding: unicast → the session owning dst vIP (if it has `dst vport`
  registered); broadcast → every other session that registered `dst vport`.
  Unknown destination → drop + count. No ICMP-like errors (spec 02 A8).
* Agent sends `REG`/`UNREG` (vport in `src vport`) when the hook registers/closes vports, `PING` every 1 s
  (RTT, loss estimate, NAT keep-alive). Server rate limit: 800 pkts/s/session,
  burst 1600; per-IP pre-auth limits.
* Max payload 480 (BFME never sends more); oversize → drop.

## 7. Control protocol (agent ↔ server, TCP, same port number)

1. Server sends a plaintext hello line (JSON, ≤ 1 KiB, `\n`-terminated):
   `{"beacon":1,"name":"…","salt":"<b64 16B>","kdf":{"m":19456,"t":2,"p":1}}`.
2. Client derives `psk = Argon2id(password, salt, m, t, p) → 32 bytes`.
3. Noise `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s` with that PSK. Wrong password ⇒
   handshake fails (server counts failures per IP, backs off).
4. Frames: u16 BE length + Noise message; payload = one JSON message tagged `"t"`.
   Messages and fields: see `beacon-proto::control` (authoritative).
5. Liveness: client `ping` every 5 s; server drops idle sessions after 30 s.

Lobby: players `{name, vip, rtt_ms, loss_pct, fingerprint, ready, in_game,
is_host}`, chat, MOTD, map pool, host actions (`launch_all`, `kick`). The first
player (or `admin_names` from config) is host.

## 8. Game data fingerprint, CD key, names, maps

* Fingerprint = BLAKE3 over sorted `(relative lowercase path, size, blake3)` of:
  the exe that will be launched, every `.big` the engine mounts (game dir rules
  from spec 04 §6), loose `Data\` overrides, plus the Beacon build id. Cached by
  `(path, size, mtime)`. The lobby groups players by fingerprint; mismatch ⇒
  warning with the differing files' names (exchanged on request).
* `BEACON_SERIAL` = first 20 chars of base32(BLAKE3("beacon-serial:" + player
  name)) — unique per name, stable.
* The launcher sets BFME's LAN player name (Network.ini `UserName`, spec 04 §4.5)
  to the Beacon name before launch (setting, default on; original value backed up).
* Maps: server dir `maps/<MapName>/…`; manifest `(path, size, blake3)`; launcher
  syncs into the user's BFME `Maps` folder; path sanitising (no `..`, absolute
  paths, `:`, reserved names, max depth 2); `beacon-maps.json` records what Beacon
  installed so user maps are never deleted.

## 9. Server observability (BFME packet inspection, optional but planned)

The relay sees plaintext BFME datagrams (only XOR-obfuscated, spec 02 §2.1). It can
decode FRAMEINFO (per-guest frame lag), disconnect commands and `MSG_LOGIC_CRC`
(desync detection: compare `(frame, crc)` across players) and show live
"Spieler X hängt 1,4 s hinterher" / "Desync erkannt" in the lobby. Never modify
packets.

## 10. Game patches (later phases)

* In-memory application of Open-BFME bundle features (031 earlysend, 033
  retrytime, 042 tracksfix, …) from the hook after verifying original bytes; only
  when the server's lobby policy says all players use the same patch set (the exe
  file on disk stays original ⇒ exe CRC unchanged, Smart App Control unaffected).
* LAA: optional locally-made copy `lotrbfme_laa.exe`; all-or-nothing per lobby.
* DXVK d3d9 (BFME1 is Direct3D 9, spec 08) as opt-in.

## 11. Robustness requirements (all crates)

No `unwrap/expect` on runtime input; fuzz-style tests for every parser; bounded
queues; timeouts (handshake 10 s, idle 30 s); server survives malformed packets,
floods, mid-transfer disconnects; Docker restart policy; hook never blocks or
allocates on the hot path.

## 12. Testing

1. Unit tests per crate. 2. Loopback integration: server + two agents.
3. Hook harness: 32-bit test exe loads `wsock32.dll` and replays the game's socket
sequence (bind VIP:8086 → probe, broadcast to 8086…8093, recvfrom with `from`
check, in-game bind 8094). 4. Real game: two BFME instances on one PC
(`BEACON_MULTI=1`), host + join over the relay, start a match.
