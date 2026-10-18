# beacon-launcher — `Beacon.exe`

The player-side program of BFME Beacon (contract: `docs/dev/architecture.md` §1,
§4.3, §5–§8): control client, **agent** (hook ↔ relay data plane), game detection,
hook install, Network.ini name, map sync, game-data fingerprint, game start, a
headless CLI and the **web UI** (German, in the default browser) on top of the
internal API below.

```sh
. /d/BFME-RE/env.sh
export CARGO_TARGET_DIR=/d/BFME-RE/build/target-launcher
export CARGO_PROFILE_DEV_BUILD_OVERRIDE_DEBUG=false   # see "Smart App Control" below
cargo build -p beacon-launcher [--release]            # -> $CARGO_TARGET_DIR/{debug,release}/Beacon.exe
cargo test -p beacon-launcher                         # unit + tests/app.rs + tests/web.rs
cargo clippy -p beacon-launcher --all-targets -- -D warnings
cargo hook                                            # the wsock32.dll that ships next to Beacon.exe
```

Ship `Beacon.exe` together with `wsock32.dll` (`cargo hook` output) in one folder.
Dependencies: `beacon-proto` (its `snow`/`blake3` re-exports), `tokio`, `serde`,
`serde_json`, `tracing(-subscriber)`, `getrandom`, `windows-sys`, `axum` (same
features as beacon-server) and `futures-core` (the `Stream` trait for the event
stream) – all already in the workspace graph, none with a build script of its own;
`beacon-server` only as a dev-dependency.

## Command line

```text
Beacon.exe [OPTIONS] [--no-browser] [--no-tray]
                                           default mode: app + web UI in the browser + tray icon
Beacon.exe connect --server HOST[:PORT] --name NAME (--password-stdin | --remembered)
           [--remember] [--launch] [--windowed] [--xres W] [--yres H] [OPTIONS]
Beacon.exe detect [OPTIONS]                JSON: game folder, exe identity, user folders, hook status (exit 1 = not found)
Beacon.exe fingerprint [OPTIONS]           JSON: digest + file list (uses the hash cache)
Beacon.exe restore-name [OPTIONS]          restore BFME's original LAN name (Network.ini UserName)
Beacon.exe stop [OPTIONS]                  ask the running instance to quit gracefully, wait until it has
Beacon.exe version | help
OPTIONS: --instance N (1..=8)  --multi  --data-dir DIR  --game-dir DIR  --hook-dll PATH  -v/--verbose
```

* `connect` is the headless session used by the end-to-end game test: logs go to
  stdout (and the log file) until Ctrl+C/Ctrl+Break, console close or `Beacon.exe
  stop` (same `--instance`/`--data-dir`). `--password-stdin` reads one line;
  `--remember` stores the derived key (DPAPI) after login, `--remembered` uses it.
  `--launch` starts BFME once connected (exit code 3 if that fails). Exit codes:
  0 ok, 1 failure (e.g. wrong password, changed server identity), 2 usage error.
* Release builds use the GUI subsystem. The CLI commands attach to the parent
  console (output appears in `cmd`/PowerShell, Ctrl+C reaches the process) and keep
  pipe/file handles that already work (Git Bash/mintty, redirection).
  **Scripts in Git Bash** cannot deliver SIGINT to native Windows processes
  (`kill -INT` has no effect on them): stop a background session with
  `Beacon.exe stop --instance N`.
* Test mode (two BFME instances on one PC): `--instance 2` (or `--multi`).
* Default mode: see [Web UI](#web-ui). `--no-browser` only logs the URL (with the
  token), `--no-tray` shows no notification-area icon. Fatal start-up errors
  (data folder, instance check, start of the app or the web server) appear in a
  German message box in release builds (no console there); debug builds log them.

## Data folder

`%APPDATA%\Beacon` (or `--data-dir`); `--instance N ≥ 2` uses `…\instance-N`.

| Path | Content |
|---|---|
| `config.json` | player name, last server, servers (`address`, `pin` = server name + salt + KDF, `remembered_psk` = DPAPI blob), `game_dir`, `launch {windowed, xres, yres, noshellmap}`, `name_sync` (true), `auto_launch_on_host_start` (true), `redundancy {lobby, game, other}` overrides. Written atomically; a damaged file is moved aside. |
| `cache.json` | fingerprint hash cache `(path, size, mtime) → BLAKE3` |
| `name-backup.json` | original Network.ini `UserName` per file (for `restore-name`) |
| `running.json` | pid, port, token of the running instance (handover; removed on exit) |
| `logs\beacon-<UTC>-<pid>.log`, `logs\hook-<UTC>-<pid>.log` | launcher and hook logs; the newest 10 of each kind are kept, a launcher log rolls over after 16 MiB |
| `userdata\` | test mode: the instance's `BEACON_USERDIR` (BFME appends its leaf folder) |

The maps folder gets `beacon-maps.json` (files Beacon installed).

## Behaviour

**Control client** (`control`): `host[:port]` (default 28086; IPv6 as `[addr]:port`),
connect timeout 8 s per address, hello line (≤ 1 KiB, 10 s). **TOFU pin**: the first
successful login stores `(server name, salt, kdf)` per canonical address; a later
hello with another salt or KDF fails with `IdentityChanged` *before* any key is
derived or sent, until `reset_server_pin`. KDF parameters outside beacon-proto's
bounds are refused (`InsecureKdf`). PSK = Argon2id (blocking pool), Noise `NNpsk0`
initiator, `hello{name, version, fingerprint}`, `welcome` → relay session for the
agent. Session: `fingerprint_files` (whenever the fingerprint is known/changes),
`status{in_game, rtt_ms, loss_pct}` (in_game changes at once, measurements at most
every 5 s), `map_list`, ping every 5 s, idle timeout 30 s. Reconnect with
exponential backoff 1 s … 30 s (+ jitter) while connected is wanted – at most 2 s
(+ jitter) while BFME runs (the game drops a silent player after 8 s + 20 s);
permanent errors (wrong password = `AuthFailed`, `IdentityChanged`, `BadName`,
`UnsupportedVersion`, kick, not a Beacon server) stop it. Exceptions: the `kick`
a stopping server sends to everybody ("Der Server wird beendet.") is
`ServerStopped` and reconnects; `AuthFailed` after the key already worked in this
connection is retried twice (a reset during the handshake looks the same). The
agent's relay session outlives a broken control connection until a new login
replaces it, the server ends it (relay `BYE`) or the user disconnects: while the
server still holds the player (half-open TCP after a new public IP; reconnects get
`name_taken`) the relay, which follows NAT rebinding, keeps the game going. The
password is wiped after the first derivation (the key is cached for reconnects);
"remember" stores only the 32-byte PSK, DPAPI-encrypted for the current user.

**Agent** (`agent`): UDP `127.0.0.1:0` for the hook (random u32 local token) and one
UDP socket per relay session. Hook `REG` → relay `REG` (repeated every 1 s until
`REG_ACK`, again after `ERROR(not registered)` or a new session); `SEND` → `DATA`
sealed once, sent R times with the same counter (R = `default_redundancy(dst_vport)`
or the `redundancy` setting; copies after 3/10 ms); `CLOSE` → `UNREG`. Every
`REG`/`SEND` refreshes `vport → loopback endpoint`; entries idle for 60 s and all
entries when the game exits are dropped with `UNREG`. Relay `DATA` →
`open_with_window` (drops redundant copies and replays) → `DELIVER` to the endpoint
of the destination vport (dropped without one). Unicast to the own vIP is
delivered locally; broadcasts never come back to the sender (packets with the own
vIP as source are dropped). `PING` every 1 s → RTT EWMA (α = 1/8) and loss over the
last 30 pings. Payloads > 480 bytes, foreign destinations, wrong tokens, garbage and
foreign datagrams are counted and dropped; sends never block (`try_send_to`);
queues are bounded (64 registrations, 512 pending copies per delay slot).

**Game** (`game`): BFME folder = setting/`--game-dir`, else registry `InstallPath`
(`HKLM\SOFTWARE\WOW6432Node\Electronic Arts\EA Games\The Battle for Middle-earth`,
HKCU fallback). `lotrbfme.exe` identity = SHA-256 (CNG); known:
`c1a907c4…` = "Vanilla 1.03 (BFME Workshop / All-in-One)", unknown = warning. User
folders per spec 04 §4.1/§4.8 (preferences use the *registry* leaf only; maps in
`<user dir>\Maps` if `UseLocalUserMaps` = 0, else `<install>\UserData\Maps`).
Hook install before each launch: the `wsock32.dll` next to `Beacon.exe` (or
`--hook-dll`) is copied if missing or different (temp file + rename); a DLL is
recognised as Beacon's by the marker `BFME-BEACON-HOOK/<version>` (beacon-hook
`BEACON_HOOK_MARKER`); a foreign `wsock32.dll` is never overwritten (`HookForeign`),
a DLL loaded by a running game reports `HookInUse`. Network.ini `UserName` (spec 04
§4.5, quoted-printable UTF-16LE as the game writes it) is set to the player name
(`name_sync`), keeping every other byte; the original value is backed up once.
Launch = `CreateProcessW` (via `std::process::Command`) of `<game>\lotrbfme.exe`,
cwd = game folder, arguments from the launch options (`-win -xres W -yres H
-noshellmap`), environment = inherited minus stale `BEACON_*` + `BEACON_AGENT_PORT`,
`BEACON_LOCAL_TOKEN`, `BEACON_VIP`, `BEACON_SERIAL` (`beacon_serial(name)`),
`BEACON_LOG`; test mode adds `BEACON_MULTI=1` and `BEACON_USERDIR=<data>\userdata`
(first use copies `Options.ini`/`Network.ini` from the real user folder and sets
the instance's name). os error 4551 → `SmartAppControlBlocked`. The process is
tracked (`in_game`); its exit drops the agent's registrations.

**Fingerprint** (`fingerprint`, background thread): `lotrbfme.exe`, every `*.big`
below the game folder (recursively, like the engine), loose files below `Data\`
except `Data\Movies`, the hook DLL and the build id; cached in `cache.json`.

**Map sync** (`maps`): listing from the server; per file missing → download,
identical → keep, installed by Beacon and unchanged → replace with the new version,
anything else → conflict (never touched). Names/paths checked with
`is_safe_file_name`/`is_safe_rel_path`, no links/junctions below `Maps`, ≤ 256 MiB
per file; chunks (≤ 32 KiB, paced below the server's limit) go to a temporary file,
size + BLAKE3 are verified, then it is renamed into place and recorded.

**Single instance** (`instance`): named mutex per data folder + `running.json`; a
second start hands over to the running one (`Activate` → `Change::Activate`: the
running default-mode instance opens the browser with its UI URL again; `Quit` =
`Beacon.exe stop`) and ends with exit code 0. If the running instance does not
answer, the second start shows an error box and exits 1.

## Internal API (for the UI)

```rust
use beacon_launcher::{App, AppOptions, AppState, Change, ConnectRequest, SettingsPatch};
use beacon_launcher::paths::DataDirs;

let app = App::start(AppOptions::new(DataDirs::resolve(None, 1)?)).await?; // inside tokio
let state: AppState = app.snapshot();            // serde::Serialize, cheap clone
let mut changes = app.subscribe();              // broadcast::Receiver<Change>
```

`App` is `Clone` (an `Arc`); all methods may be called from any task of the runtime.
State changes are published as [`Change`] values (`connection`, `lobby`, `chat`,
`maps`, `game`, `hook`, `agent` ≈ 1/s, `fingerprint`, `peer_files`, `settings`,
`notice`, `activate`, `quit`); a lagging receiver should simply re-read the snapshot.

| Command | Effect / errors |
|---|---|
| `connect(ConnectRequest { server, name, password: Option<String>, use_remembered, remember })` | validates address and name, replaces any session, starts the supervisor; progress in `connection` |
| `disconnect()` | ends the session (no reconnect) |
| `send_chat(&str)` / `set_ready(bool)` | `NotConnected` |
| `launch_game()` | hook install, test-mode folder, name sync, start; `NotConnected`, `GameNotFound`, `GameRunning`, `HookForeign`, `HookInUse`, `HookMissing`, `SmartAppControlBlocked`, `LaunchFailed`, `Busy` |
| `launch_all()` / `kick(&str)` | host only (`NotHost`) |
| `request_fingerprint(&str)` | another player's file list → `peer_files[name]` (`files`, `complete`, `differs` = paths that differ from ours) |
| `update_settings(SettingsPatch { player_name, game_dir ("" = registry), launch, name_sync, auto_launch_on_host_start, redundancy })` | validated, saved; a new game folder re-runs detection + fingerprint |
| `sync_maps()` | background download; progress in `maps.sync`; `Busy`, `NotConnected`, `GameNotFound` (no maps folder) |
| `reset_server_pin(&str)` / `forget_password(&str)` | `Ok(true)` if something was removed; resetting the pin also forgets the remembered key |
| `restore_user_name()` | restores the backed-up Network.ini `UserName` |
| `activate()` / `quit()` / `request_quit()` / `quit_requested()` | handover, shutdown (the game keeps running), wait for shutdown |
| `agent_endpoint()` / `agent_stats()` | `(port, token)` for the hook, live counters |

Errors are `CommandError { kind: CommandErrorKind, message }` (serde, snake_case
kinds). Connection problems appear in `state.connection`:

```jsonc
{ "state": "disconnected" }
{ "state": "connecting", "server": "home.example.org:28086", "attempt": 1 }
{ "state": "authenticating", "server": "…" }
{ "state": "connected", "server": "…" }
{ "state": "reconnecting", "server": "…", "retry_in_ms": 4000, "error": { "kind": "closed", "stage": "session" }, "message": "…" }
{ "state": "failed", "server": "…", "error": { "kind": "identity_changed", "address": "…", "pinned_name": "…", "pinned_at_ms": 0, "server_name": "…" }, "message": "…" }
```

`AppState` fields: `version`, `instance`, `test_mode`, `data_dir`, `connection`,
`server {address, name, motd, vip, you_are_host, relay_addr, newly_pinned}`,
`players` (beacon-proto `Player`), `chat` (last 200 `{from, text, ts}`; `from` = ""
for server notices), `maps {maps_dir, listing_received, maps [{name, total_size,
files, state: installed|missing|conflict|invalid|downloading|failed, problem}],
sync {running, current, bytes_done, bytes_total, downloaded, last_error}}`, `game`
(detection: `game_dir`, `source`, `exe {path, size, sha256, known}`, `user
{prefs_dir, data_dir, maps_dir, leaf, …}`, `warnings`; `null` while it runs),
`hook` (`{state: unknown|source_missing|not_installed|up_to_date|outdated|foreign|error, …}`),
`game_process {pid, started_at_ms, running, exit_code, hook_log}`, `agent`
(`AgentStats`: `local_port`, `session_active`, `vip`, `registrations`, `rtt_ms`,
`loss_pct`, packet counters), `fingerprint` (`{state: unavailable|computing|ready|failed, …}`),
`peer_files`, `settings` (config without secrets: servers with `pinned_name`,
`pinned_at_ms`, `remembered`), `notices` (last 50 `{id, ts_ms, level, text}`).

## Web UI

`web::WebServer::start(app, WebOptions)` (default mode) serves the page and a JSON +
server-sent-events API on `127.0.0.1:0`; `Beacon.exe` then opens
`http://127.0.0.1:PORT/#t=<token>` with `ShellExecuteW` (a fresh random 128-bit
token per run). The page moves the token into `sessionStorage` (per tab) and removes
it from the address bar; `#t=<token>&v=diagnose` opens another view first
(`verbinden`, `lobby`, `einstellungen`, `diagnose`).

**Security** (`web/guard.rs`): bound to `127.0.0.1` only; every request needs
`Host: 127.0.0.1:PORT` or `localhost:PORT` (DNS rebinding; an absolute-form target
must name the same authority); every `/api` request needs `X-Beacon-Token`
(constant-time compare), an `Origin` header – if present – must be this origin and
`Sec-Fetch-Site` – if present – `same-origin`/`none`. Failures answer `403
{"ok":false,"error":{"kind":"forbidden","reason":"host|origin|fetch_site|token"}}`.
No CORS headers; JSON bodies only (`Content-Type: application/json`, ≤ 64 KiB);
every response carries a strict CSP (`default-src 'none'; script-src 'self'; …;
frame-ancestors 'none'`), `nosniff`, `X-Frame-Options: DENY`, `no-store`,
`no-referrer`. The page puts server and player data (names, chat, MOTD, map names,
paths, error texts) into the DOM only with `textContent`/`createElement`, never
`innerHTML`; player text is bidi-isolated (`<bdi>`, `dir="auto"`).

**API** (success `{"ok":true,…}`, failure: HTTP status + `{"ok":false,"error":{kind,
field?, reason?, message}}` with `kind` = a `CommandErrorKind` or `forbidden`,
`bad_request`, `not_found`, `too_many_streams`, `internal`; `reason` names a broken
input rule such as `name_too_long`, `invalid_address`, `resolution_range`):

| Route | Body | |
|---|---|---|
| `GET /api/state` | | `AppState` |
| `GET /api/events` | | SSE: `event: state` (full state) at once and after changes, coalesced to ≤ 10/s; `event: quit` when Beacon ends; keep-alive comments every 15 s; ≤ 8 streams (`429`), a client stalled for 30 s is dropped |
| `POST /api/connect` | `{server, name, password?, remember?, use_remembered?}` | no password = use the remembered key |
| `POST /api/disconnect`, `/api/launch`, `/api/launch_all`, `/api/maps/sync`, `/api/quit` | `{}` | |
| `POST /api/chat` / `/api/ready` / `/api/kick` | `{text}` / `{ready}` / `{name}` | |
| `POST /api/fingerprint` | `{name}` | that player's file list → `peer_files` |
| `POST /api/settings` | `SettingsPatch` (`player_name`, `game_dir`, `launch {windowed, xres, yres, noshellmap}`, `name_sync`, `auto_launch_on_host_start`, `redundancy {lobby, game, other}`) | |
| `POST /api/pin/reset`, `/api/password/forget` | `{server}` | `{removed}` |
| `POST /api/name/restore` | `{}` | `{restored}`: BFME's original LAN name |
| `POST /api/logs/open` | `{}` | shows the log folder in Explorer |

**Page** (`ui/index.html`, `app.js`, `style.css`, `favicon.svg`, embedded with
`include_str!`; plain JS, no CDN, no build step; German; dark with gold/bronze
accents; responsive; labels, focus rings, `prefers-reduced-motion`,
`forced-colors`). The event stream is read with `fetch` (EventSource cannot send
the token header) and reconnects with backoff; an unknown token shows "Sitzung
ungültig", the end of Beacon "Beacon wurde beendet". Views:

* **Verbinden** – server address (port 28086 by default), player name (checked like
  Beacon checks it), password, "Passwort merken", recently used servers (pinned
  name, "Passwort vergessen", "Identität zurücksetzen"), connection status with
  reconnect countdown; a changed server identity is explained with a reset button.
* **Lobby** – server name, MOTD, own vIP; players with host crown, ping + loss,
  game data vs. the host (`✓ wie Host` / `✗ weicht ab` with the differing files
  on request, own data "wird geprüft …" while fingerprinting), ready, "im Spiel",
  host-only Kick; chat with timestamps; map pool with state and sync progress;
  buttons Bereit, "BFME starten", host-only "Alle starten".
* **Einstellungen** – detected game folder and override, Fenstermodus +
  Auflösung, Shellmap aus, Name ins Spiel übernehmen, automatisch starten wenn der
  Host startet, Erweitert: Redundanz; restore the original LAN name.
* **Diagnose** – game detection and exe identity, hook state/version (and
  "Firewall-Abfrage: übersprungen": the hook answers BFME's XP firewall query
  itself), game process, agent RTT/loss/packet counters/registered ports,
  fingerprint, Beacon version and data folder, notices, "Log-Ordner öffnen",
  "Beacon beenden".

Every typed error has a German text (wrong password, server unreachable, identity
changed, game not found, foreign `wsock32.dll`, Smart App Control with an
explanation, "Als Administrator ausführen", …); Beacon's English detail is shown
below it. Known core notices are translated, unknown ones are shown as they are.

**Tray** (`sys/tray.rs`): a hidden window on its own thread with
`Shell_NotifyIconW` (version 4), an icon drawn at run time (gold beacon fire on a
dark disc), click/Enter = "Öffnen", context menu "Öffnen" / "Beenden"; it is added
again after an Explorer restart and removed on exit.

## Tests

* Unit tests: config + pinning + DPAPI, addresses and names, CLI, path checks and map
  sync with a fake chunk source (corrupt data, user files, updates), fingerprint
  collection/ordering/cache, Network.ini encoding and edits, hook install (marker,
  foreign DLL, locked file), launch environment and error mapping, agent with a
  fake hook + fake relay (redundancy, dedupe, garbage, expiry, self-unicast,
  RTT/loss, re-registration), single instance + handover, logging.
* `tests/app.rs`: real `beacon_server` instances in-process: two apps (distinct
  vIPs, lobby, host, chat, ready, RTT), fake hooks exchange unicast and broadcast
  `SEND`/`DELIVER` with the correct source exactly once and no echo, map sync of a
  test map, wrong password, remembered key, and a changed salt on the same address
  refused by the pin until it is reset.
* `tests/web.rs`: `WebServer` over real TCP with a raw HTTP/1.1 client: missing,
  wrong, truncated and upper-case tokens, foreign `Host` (incl. absolute-form
  targets, HTTP/1.0 without `Host`), foreign/`null` `Origin`, cross-site
  `Sec-Fetch-Site`, CORS preflight → `403` without CORS headers; security headers;
  state shape without secrets; embedded assets (types, no inline script/style, no
  `innerHTML` in `app.js`); SSE: full state first, changes, throttling, `quit`,
  stream limit and freed slots; input validation reasons and saved settings; a
  real in-process server: connect, chat, ready, remembered password, disconnect
  through the API. Unit tests: Host/Origin/fetch-site rules, error kinds, input
  rules, tray icon pixels.
* Manually checked (not automated): the release `Beacon.exe` in default mode with
  tray, handover of a second start, two instances in one lobby against a local
  `beacon-server`, all four views rendered by headless Edge.

## Smart App Control

On the dev PC Smart App Control blocked the default (debug-info) build script of
`serde` in this target folder (os error 4551). Build scripts compiled with
`CARGO_PROFILE_DEV_BUILD_OVERRIDE_DEBUG=false` were allowed, so builds and tests in
`target-launcher` set that variable (it is not put into the workspace profile:
verdicts differ per binary and target folder, and changing the shared profile
would rebuild other folders' build scripts). The release `Beacon.exe` ran; the
hook harness exe was blocked when rebuilt here, the identical harness from
`target-hook` passes all scenarios against the new DLL.

## Limitations

* Web UI: Beacon's own notices and error details are English strings; the page
  translates the known ones and shows others unchanged. The page's JavaScript has
  no automated tests (only the HTTP side is tested); kick, quit and pin reset ask
  with the browser's `confirm()`. A tab of an earlier run cannot reconnect (new
  port and token): reopen the UI from `Beacon.exe` or the tray.
* The tray icon's colours were checked as pixels only (`icon_pixels`), not on screen.
* Interactive Ctrl+C in mintty depends on Git for Windows forwarding it to native
  processes; scripts use `Beacon.exe stop`.
* Map/file writes in the map sync are small blocking writes on a runtime thread.
* A vIP change after a server restart without `data_dir` cannot reach a running game
  (BFME caches its IP at start); the server persists vIPs by default.
* No in-memory game patches (`BEACON_PATCHES`) yet (architecture §10).
