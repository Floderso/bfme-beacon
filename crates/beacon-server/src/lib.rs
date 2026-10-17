//! BFME Beacon home server (architecture §6, §7, §8 maps, §11).
//!
//! * [`control`] – TCP control channel: plaintext hello line, Noise `NNpsk0`
//!   responder, JSON [`ClientMsg`](beacon_proto::control::ClientMsg) /
//!   [`ServerMsg`](beacon_proto::control::ServerMsg) messages, lobby, chat, host
//!   actions, map downloads, fingerprint exchange.
//! * [`relay`] – UDP relay on the same port number: per-session keys, replay windows
//!   and send counters, unicast/broadcast forwarding, redundancy, rate limits, stats.
//! * [`maps`] – map repository (`maps/<MapName>/…`) with a BLAKE3 manifest.
//! * [`status`] – `GET /health` and `GET /status` (JSON) for monitoring.
//! * [`webhook`] – optional notifications (plain HTTP POST, ntfy compatible).
//! * [`server`] – binds the sockets, starts every task, graceful shutdown.
//!
//! The server never panics on network input: every parser returns an error that
//! is counted and dropped, all queues are bounded and every connection has
//! handshake/idle/write timeouts.

#![forbid(unsafe_code)]
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

pub mod cli;
pub mod config;
pub mod control;
pub mod health;
pub mod hexfmt;
pub mod hub;
pub mod limits;
pub mod lobby;
pub mod maps;
pub mod relay;
pub mod server;
pub mod status;
pub mod webhook;

pub use config::{Config, Settings};
pub use server::{start, RunningServer, ServerError};

/// Version of this crate (shown by `beacon-server version` and in `/status`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Milliseconds since the Unix epoch (0 if the clock is before 1970).
pub fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Locks a mutex, ignoring poisoning (a panicking holder cannot leave our state
/// half-updated in a way that matters more than stopping the server would).
pub(crate) fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
