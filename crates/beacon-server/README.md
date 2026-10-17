# beacon-server

Home server of BFME Beacon (contract: `docs/dev/architecture.md` §6, §7, §8 maps,
§11). One port number, TCP and UDP (default 28086):

* **Control (TCP)** – plaintext hello line, Noise `NNpsk0` (PSK = Argon2id of the
  server password), JSON `ClientMsg`/`ServerMsg` from `beacon-proto`. Lobby with
  sticky vIPs per name (`198.18.0.2–254`, persisted in `data_dir/vips.json`), host
  election (first player or `admin_names`, moves on when the host leaves), chat
  (sanitised, rate limited, last 20 lines replayed), `launch_all`, `kick` (with a
  rejoin ban), fingerprint lists, map list and 32 KiB chunk downloads, ping/pong.
  Timeouts: handshake 10 s, idle 30 s, writes 10 s. Failed handshakes ban the IP
  with exponential backoff.
* **Relay (UDP)** – one task owns every session (key, replay window, send counter,
  registered vports, endpoint updated only after a valid tag). Unicast to the
  owner of the destination vIP, broadcast to every other session with that vport,
  never echoed. Each forwarded packet is sealed once per receiver and sent 1–3 times
  (3 ms / 10 ms copies; lobby 3, game 2). Per-session token bucket, per-IP budget
  for unauthenticated junk, per-session stats (packets, bytes, drops, duplicates,
  upstream loss from counter gaps).
* **Maps** – `maps_dir/<Map>/<file>` (one sub-folder level), BLAKE3 manifest cached
  by `(path, size, mtime)`, rescanned on SIGHUP and every `map_rescan_secs`.
* **Status** – `GET /health` (`ok`, 503 if the relay loop stalls) and
  `GET /status` (JSON) on `status_bind` (default `127.0.0.1:28087`).
* **Webhook** – optional plain-HTTP POST per event (ntfy format: body + `Title`).

Lobby `rtt_ms` is the agent's measurement (relay PING/PONG, reported via `status`);
`loss_pct` combines the agent-reported loss with the server-measured upstream loss.

## Usage

```sh
beacon-server init-config config.toml          # commented example
beacon-server set-password --config config.toml # or --password-stdin
beacon-server run --config config.toml          # default command
beacon-server health                            # exit 0 if /health answers "ok"
beacon-server version
```

The config path defaults to `$BEACON_CONFIG`, else `./config.toml`; relative paths
inside it are resolved against its directory. SIGTERM/Ctrl-C shut down gracefully
(players get `kick`, relay sessions `BYE`). Docker deployment: `deploy/`.

## Build and test

```sh
cargo build -p beacon-server --release
cargo build -p beacon-server --release --target x86_64-unknown-linux-musl   # static
cargo test -p beacon-server            # unit tests + tests/server.rs (fake clients)
cargo clippy -p beacon-server --all-targets -- -D warnings
```

`tests/server.rs` starts the real server on `127.0.0.1:0` and drives it with fake
clients built from `beacon-proto` (login, lobby, chat, host actions, relay unicast,
broadcast, redundancy, replay, spoofing, NAT rebinding, rate limits, garbage
input, maps with BLAKE3 check, status, shutdown, vIP persistence). Set
`BEACON_TEST_LOG=1` for server logs.
