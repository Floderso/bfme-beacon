# beacon-launcher — `Beacon.exe`

The player-side program of BFME Beacon (contract: `docs/dev/architecture.md` §1,
§4.3, §5–§8): control client, **agent** (hook ↔ relay data plane), game detection,
hook install, Network.ini name, map sync, game-data fingerprint, game start and a
headless CLI. The web UI is added on top of the internal API below (part 2).

```sh
. /d/BFME-RE/env.sh
export CARGO_TARGET_DIR=/d/BFME-RE/build/target-launcher
export CARGO_PROFILE_DEV_BUILD_OVERRIDE_DEBUG=false   # see "Smart App Control" below
cargo build -p beacon-launcher [--release]            # -> $CARGO_TARGET_DIR/{debug,release}/Beacon.exe
cargo test -p beacon-launcher                         # unit + tests/app.rs (in-process server)
cargo clippy -p beacon-launcher --all-targets -- -D warnings
cargo hook                                            # the wsock32.dll that ships next to Beacon.exe
```

Ship `Beacon.exe` together with `wsock32.dll` (`cargo hook` output) in one folder.
Dependencies: `beacon-proto` (its `snow`/`blake3` re-exports), `tokio`, `serde`,
`serde_json`, `tracing(-subscriber)`, `getrandom`, `windows-sys` (all already in the
workspace graph); `beacon-server` only as a dev-dependency.

## Command line

```text
Beacon.exe [OPTIONS]                       default mode: starts the app (UI not built yet: headless, Ctrl+C quits)
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
exponential backoff 1 s … 30 s (+ jitter) while connected is wanted; permanent
errors (wrong password = `AuthFailed`, `IdentityChanged`, `BadName`,
`UnsupportedVersion`, kick, not a Beacon server) stop it. The password is wiped after
the first derivation (the key is cached for reconnects); "remember" stores only the
32-byte PSK, DPAPI-encrypted for the current user.

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
second start hands over to the running one (`Activate` → `Change::Activate`, the
UI will open the browser; `Quit` = `Beacon.exe stop`).

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

* The web UI is not part of this crate yet; the default mode runs headless.
* Interactive Ctrl+C in mintty depends on Git for Windows forwarding it to native
  processes; scripts use `Beacon.exe stop`.
* Map/file writes in the map sync are small blocking writes on a runtime thread.
* A vIP change after a server restart without `data_dir` cannot reach a running game
  (BFME caches its IP at start); the server persists vIPs by default.
* No in-memory game patches (`BEACON_PATCHES`) yet (architecture §10).
