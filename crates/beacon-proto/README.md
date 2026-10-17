# beacon-proto

Wire formats, crypto helpers and shared constants of BFME Beacon
(contract: `docs/dev/architecture.md` §4–§8). `#![forbid(unsafe_code)]`, no async
runtime, no panics on untrusted input (every parser returns a typed error).

| Feature | Modules | Dependencies |
|---|---|---|
| *(none)* — `--no-default-features`, used by the 32-bit hook | `net`, `env`, `local`, `relay` | `chacha20poly1305` (pure Rust) |
| `control` (default) | + `control`, `fingerprint` | + `serde`, `serde_json`, `snow` (25519/ChaChaPoly/BLAKE2s only, no `ring`), `argon2`, `base64`, `blake3` (`pure`) |

Builds for the host, `i686-pc-windows-gnullvm` and `x86_64-unknown-linux-musl`.
`beacon_proto::snow` and `beacon_proto::blake3` are re-exported; use them instead of
direct dependencies so every component uses the same versions and pure-Rust
feature set.

## Modules

* **`net`** (§4.1) — virtual subnet `198.18.0.0/24`: `SERVER_VIP`, `VSUBNET_BROADCAST`,
  `is_virtual`, `is_broadcast` (`255.255.255.255`, `198.18.0.255`),
  `is_virtual_destination`, `vip_from_host`/`vip_host`, BFME port ranges
  (`LOBBY_PORTS` 8086–8093, `GAME_PORTS` 8094–8101, `is_virtual_port`), and
  `VipAllocator` (`allocate`, `claim`, `release`) for `.2..=.254`.
* **`env`** (§4.3) — `BEACON_*` variable names and allocation-free parsers:
  `parse_agent_port`, `format_token`/`parse_token`, `parse_vip`, `is_valid_serial`,
  `patch_ids`, `is_enabled`.
* **`local`** (§5) — hook ↔ agent loopback frames (`BCN1`, big-endian), zero
  allocation: `HookFrame::{reg, send, close}`, `encode_hook_frame`,
  `parse_hook_frame`, `Deliver`, `encode_deliver`, `parse_deliver`,
  `strip_deliver_in_place` (the hook's `recvfrom` path).
* **`relay`** (§6) — agent ↔ server packets: `Header` (24 bytes, `Header::client` /
  `Header::server`), `PacketType` (REG … UNREG), `seal(key, dir, &header, payload,
  out) -> usize`, `open(key, dir, &mut packet) -> (Header, Range)` (in place),
  `peek_header` (unauthenticated, for the session lookup), `open_with_window`,
  `nonce`, `ReplayWindow` (256 entries, also drops redundant copies), `SendCounter`,
  `default_redundancy(dst_vport)` (3 lobby / 2 game / 1 other) with
  `REDUNDANCY_DELAYS` (3 ms, 10 ms), `RelayKey` (hex), PING/ERROR payload helpers.
  `MAX_PAYLOAD` = 480. Every packet type is sealed (ChaCha20-Poly1305, AAD = header).
* **`control`** (§7, feature `control`) — `ServerHello` (`to_line`, `from_line`,
  `hello_line_len`), `KdfParams` (bounds-checked) and `derive_psk` (Argon2id),
  `NOISE_PARAMS` + `noise_builder(psk)`, framing (`encode_frame`, `FrameDecoder`),
  JSON messages `ClientMsg` / `ServerMsg` (`#[serde(tag = "t")]`, snake_case; the
  authoritative message list), `encode_msg`/`decode_msg` (60 KiB limit), `Chunk`
  (32 KiB raw), `ErrorCode`, path validation (`is_safe_rel_path`, depth ≤ 2;
  `is_safe_file_name`), liveness constants.
* **`fingerprint`** (§8, feature `control`) — `FileEntry`, `Fingerprint`,
  deterministic `combine` (BLAKE3 derive-key mode, documented byte layout),
  `FileEntry::build_id`, `normalize_path`, `hash_hex`, and `beacon_serial(name)`
  (`BEACON_SERIAL`: first 20 chars of base32(BLAKE3("beacon-serial:" + name))).

## Examples and tests

* `tests/noise_handshake.rs` — complete control-channel setup: hello line →
  Argon2id PSK → Noise NNpsk0 over frames → JSON messages; a wrong password fails.
* `tests/fuzz.rs` — deterministic pseudo-random garbage/mutation tests for every
  parser; replay window checked against a reference model.
* Known-answer vectors were cross-checked with independent implementations:
  relay packets with a pure-Python RFC 8439 ChaCha20-Poly1305, the PSK with the
  Argon2 reference C implementation (argon2-cffi), fingerprints and serials with
  blake3-py + Python's base32.

```sh
cargo test -p beacon-proto
cargo test -p beacon-proto --no-default-features
cargo build -p beacon-proto --target i686-pc-windows-gnullvm --no-default-features
```
