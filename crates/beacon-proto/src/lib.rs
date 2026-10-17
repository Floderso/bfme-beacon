//! Wire formats, crypto helpers and shared constants of BFME Beacon
//! (see `docs/dev/architecture.md`, sections 4–8).
//!
//! * [`net`] – the virtual LAN `198.18.0.0/24` and BFME's ports: constants,
//!   classification, vIP allocation (§4.1).
//! * [`env`](mod@env) – the launcher → hook environment contract (`BEACON_*`, §4.3).
//! * [`local`] – the hook ↔ agent loopback frames (`BCN1`, §5), zero allocation.
//! * [`relay`] – the agent ↔ server UDP packet format (§6): 24-byte header,
//!   ChaCha20-Poly1305 sealing on caller buffers (zero allocation), 256-entry replay
//!   window, send counter, redundancy defaults.
//! * `control` (feature `control`) – the TCP control channel (§7): server hello,
//!   Argon2id PSK derivation, Noise parameters, length-prefixed framing and the
//!   JSON message enums (authoritative list of messages and fields).
//! * `fingerprint` (feature `control`) – game-data fingerprint types, the
//!   deterministic `fingerprint::combine` function and the `BEACON_SERIAL`
//!   derivation (§8).
//!
//! The crate never panics on untrusted input: every parser returns a typed error.
//! It contains no `unsafe` code and does not depend on an async runtime. With
//! `--no-default-features` (the 32-bit hook, `i686-pc-windows-gnullvm`) only `net`,
//! `env`, `local` and `relay` remain.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod env;
pub mod local;
pub mod net;
pub mod relay;

#[cfg(feature = "control")]
pub mod control;
#[cfg(feature = "control")]
pub mod fingerprint;

/// Re-export of the BLAKE3 implementation (built with its `pure` feature) used for
/// fingerprints and map manifests, so all components hash identically.
#[cfg(feature = "control")]
pub use blake3;

/// Re-export of the Noise implementation used by [`control::noise_builder`]. Use this
/// instead of a direct `snow` dependency so the version and feature set (pure Rust,
/// no `ring`) stay identical across components.
#[cfg(feature = "control")]
pub use snow;
