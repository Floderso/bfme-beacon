//! BFME Beacon launcher (`Beacon.exe`, architecture §1, §4.3, §5–§8).
//!
//! * [`app`] – the [`App`] handle: state snapshot + change notifications and the
//!   commands of the UI (see the crate README for the API).
//! * [`control`] – control client: hello, TOFU pin, Argon2id PSK, Noise `NNpsk0`,
//!   lobby session, reconnect with backoff.
//! * [`agent`] – data plane between the hook (loopback `BCN1` frames) and the relay
//!   (sealed UDP packets with redundancy, replay window, PING/PONG statistics).
//! * [`game`] – BFME detection, exe identity, hook DLL install, Network.ini name,
//!   test-mode user folders, starting the game.
//! * [`fingerprint`], [`maps`] – game-data fingerprint and map sync.
//! * [`config`], [`paths`], [`instance`], [`logging`], [`cli`] – settings and pins,
//!   data folder layout, single instance + handover, logs, command line.
//! * [`sys`] – the Win32 calls (all `unsafe` code of the crate).

#![deny(unsafe_code)]
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

pub mod agent;
pub mod app;
pub mod cli;
pub mod config;
pub mod control;
pub mod fingerprint;
pub mod game;
pub mod instance;
pub mod logging;
pub mod maps;
pub mod paths;
pub mod state;
pub mod sys;
pub mod util;

pub use app::{App, AppOptions, CommandError, CommandErrorKind, ConnectRequest, SettingsPatch};
pub use state::{AppState, Change};

/// Launcher version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build id that enters the game-data fingerprint (players with different Beacon
/// builds are shown as mismatching).
pub const BUILD_ID: &str = concat!("beacon-launcher/", env!("CARGO_PKG_VERSION"));
