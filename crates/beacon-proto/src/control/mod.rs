//! TCP control channel between the launcher (agent) and the server (architecture
//! §7). Feature `control`. The message enums here are the authoritative list of
//! control messages and fields.
//!
//! Connection sequence:
//!
//! 1. The server sends one plaintext [`ServerHello`] line (JSON + `\n`, at most
//!    [`HELLO_MAX_LEN`] bytes). The client finds its end with [`hello_line_len`] and
//!    parses it with [`ServerHello::from_line`].
//! 2. Both sides derive the PSK: [`derive_psk`] (Argon2id over the server password,
//!    salt and KDF parameters from the hello). The server can do this once at start.
//! 3. Noise handshake [`NOISE_PARAMS`] (`NNpsk0`, PSK at position 0); both sides build
//!    their handshake state with [`noise_builder`]. Client = initiator. A wrong
//!    password makes the responder's first `read_message` fail.
//! 4. Every Noise message travels in a frame: u16 big-endian length + message
//!    ([`encode_frame`], [`FrameDecoder`]). After the handshake each transport
//!    message carries exactly one JSON message ([`ClientMsg`] / [`ServerMsg`], at most
//!    [`MAX_MSG_LEN`] bytes, see [`encode_msg`] / [`decode_msg`]).
//! 5. Liveness: the client sends `ping` every [`PING_INTERVAL`]; the server drops
//!    sessions idle for [`IDLE_TIMEOUT`] and handshakes slower than
//!    [`HANDSHAKE_TIMEOUT`].
//!
//! Map download: the client sends `map_get{map, file, offset}`; the server answers
//! with one `chunk` holding at most [`CHUNK_MAX`] bytes starting at `offset`
//! (`eof` = the chunk ends at the end of the file). The client requests the next
//! offset until `eof`.
//!
//! Fingerprint details (§8, "exchanged on request"): after `hello` the client
//! uploads its file list with `fingerprint_files{files, complete}`; any client can
//! ask for another player's list with `fingerprint_get{name}` and receives
//! `fingerprint_files{name, files, complete}` (or `error{unknown_player}`).
//! `complete` is `false` if the list had to be cut to fit into one message.
//!
//! Game configuration (`docs/dev/mods.md`): servers that announce
//! [`FEATURE_GAME_CONFIG`] in `welcome.features` accept the host's
//! `set_game_config{config}` ([`GameConfig`], `null` = vanilla), send
//! `game_config{config, by}` after the login and after every change, take each
//! player's readiness ([`ConfigStatus`]) from `status.config`, show it in
//! `lobby.players[].config` and refuse `launch_all` (`not_ready`) until every player
//! is ready for the current configuration.
//!
//! The `tests/noise_handshake.rs` integration test shows the complete sequence with
//! `snow`.

mod game_config;
mod msg;
mod path;

pub use game_config::{
    is_md5_hex, is_valid_config_id, is_valid_guid, is_valid_language, is_valid_version, ConfigError,
    ConfigFile, ConfigState, ConfigStatus, FileDir, GameConfig, PackageRef, CONFIG_ID_LEN,
    FEATURE_GAME_CONFIG, ID_CONTEXT, MAX_CONFIG_FILES, MAX_CONFIG_FILE_SIZE, MAX_CONFIG_LAYERS,
    MAX_CONFIG_TEXT_CHARS, MAX_CONFIG_TOTAL_SIZE, MAX_GUID_LEN, MAX_STATUS_TEXT_CHARS,
    MAX_VERSION_LEN, RESERVED_HOOK_NAME, VANILLA_CONFIG_ID,
};
pub use msg::{Chunk, ClientMsg, ErrorCode, MapFile, MapInfo, Player, ServerMsg};
pub use path::{
    is_safe_file_name, is_safe_package_path, is_safe_rel_path, normalize_package_path,
    MAX_PACKAGE_PATH_DEPTH, MAX_PATH_DEPTH,
};

use std::fmt;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Control protocol version, sent as `"beacon"` in the [`ServerHello`].
pub const PROTOCOL_VERSION: u32 = 1;

/// Interval of the client's `ping`.
pub const PING_INTERVAL: Duration = Duration::from_secs(5);

/// The server drops a session that sent nothing for this long.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum time from TCP accept to a completed Noise handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum length of the hello line including the trailing `\n`.
pub const HELLO_MAX_LEN: usize = 1024;

/// Length of the Argon2id salt in the hello.
pub const SALT_LEN: usize = 16;

/// Length of the derived Noise PSK.
pub const PSK_LEN: usize = 32;

/// Noise protocol name of the control channel.
pub const NOISE_PARAMS: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";

/// Maximum Noise message length (handshake or transport), equal to the frame limit.
pub const NOISE_MAX_MSG_LEN: usize = 65_535;

/// Length of the authentication tag Noise appends to every encrypted payload.
pub const NOISE_TAG_LEN: usize = 16;

/// Length of the frame header (u16 BE length).
pub const FRAME_HEADER_LEN: usize = 2;

/// Maximum frame payload: what a u16 length can express.
pub const MAX_FRAME_LEN: usize = u16::MAX as usize;

/// Maximum length of one JSON message (60 KiB) – fits into one Noise transport
/// message together with its tag.
pub const MAX_MSG_LEN: usize = 60 * 1024;

/// Maximum raw bytes in one `chunk` message (32 KiB). Base64 inflates this to
/// 43 692 characters, which leaves room for the rest of the message within
/// [`MAX_MSG_LEN`].
pub const CHUNK_MAX: usize = 32 * 1024;

/// Errors of the control-channel helpers.
#[derive(Debug)]
pub enum Error {
    /// A frame, message, hello line or chunk exceeds its limit.
    TooLarge {
        /// Offending length.
        len: usize,
        /// Applicable limit.
        max: usize,
    },
    /// JSON (de)serialisation failed (malformed or unexpected message).
    Json(serde_json::Error),
    /// Invalid base64 data.
    Base64,
    /// The server hello announces an unsupported protocol version.
    UnsupportedVersion(u32),
    /// KDF parameters outside the accepted range (see [`KdfParams::validate`]).
    KdfParams(KdfParams),
    /// Argon2 failed or its memory could not be allocated.
    Kdf,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { len, max } => write!(f, "control data too large ({len} > {max} bytes)"),
            Self::Json(e) => write!(f, "invalid control message: {e}"),
            Self::Base64 => f.write_str("invalid base64 data"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported control protocol version {v}"),
            Self::KdfParams(p) => write!(
                f,
                "KDF parameters out of range (m={} KiB, t={}, p={})",
                p.m, p.t, p.p
            ),
            Self::Kdf => f.write_str("Argon2id key derivation failed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

// ---------------------------------------------------------------------------
// Hello + KDF
// ---------------------------------------------------------------------------

/// Argon2id cost parameters as sent in the hello (`"kdf":{"m":…,"t":…,"p":…}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m: u32,
    /// Number of passes.
    pub t: u32,
    /// Degree of parallelism (lanes).
    pub p: u32,
}

impl KdfParams {
    /// The default and minimum cost: 19 MiB, 2 passes, 1 lane (`m=19456, t=2, p=1`).
    pub const DEFAULT: Self = Self {
        m: 19_456,
        t: 2,
        p: 1,
    };
    /// Lowest accepted memory cost (KiB). Clients refuse cheaper parameters so a
    /// man in the middle cannot downgrade the KDF to speed up offline guessing.
    pub const MIN_M: u32 = 19_456;
    /// Highest accepted memory cost (KiB, 256 MiB): a hostile server cannot make
    /// clients allocate arbitrary amounts of memory.
    pub const MAX_M: u32 = 256 * 1024;
    /// Lowest accepted number of passes.
    pub const MIN_T: u32 = 2;
    /// Highest accepted number of passes.
    pub const MAX_T: u32 = 16;
    /// Lowest accepted parallelism.
    pub const MIN_P: u32 = 1;
    /// Highest accepted parallelism.
    pub const MAX_P: u32 = 8;

    /// Checks the parameters against the accepted bounds.
    pub fn validate(&self) -> Result<(), Error> {
        let ok = (Self::MIN_M..=Self::MAX_M).contains(&self.m)
            && (Self::MIN_T..=Self::MAX_T).contains(&self.t)
            && (Self::MIN_P..=Self::MAX_P).contains(&self.p);
        if ok {
            Ok(())
        } else {
            Err(Error::KdfParams(*self))
        }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Derives the 32-byte Noise PSK: `Argon2id(password, salt, m, t, p)`, version 0x13,
/// no secret, no associated data. The password is used as its UTF-8 bytes, without
/// normalisation. Fails if `params` are outside [`KdfParams::validate`]'s bounds.
pub fn derive_psk(
    password: &str,
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<[u8; PSK_LEN], Error> {
    params.validate()?;
    let argon_params = argon2::Params::new(params.m, params.t, params.p, Some(PSK_LEN))
        .map_err(|_| Error::KdfParams(*params))?;
    let block_count = argon_params.block_count();
    let mut blocks: Vec<argon2::Block> = Vec::new();
    blocks
        .try_reserve_exact(block_count)
        .map_err(|_| Error::Kdf)?;
    blocks.resize(block_count, argon2::Block::default());
    let mut psk = [0u8; PSK_LEN];
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    )
    .hash_password_into_with_memory(password.as_bytes(), salt, &mut psk, blocks.as_mut_slice())
    .map_err(|_| Error::Kdf)?;
    Ok(psk)
}

/// The plaintext hello line the server sends first:
/// `{"beacon":1,"name":"…","salt":"<b64 16B>","kdf":{"m":19456,"t":2,"p":1}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerHello {
    /// Control protocol version ([`PROTOCOL_VERSION`]).
    pub beacon: u32,
    /// Server display name.
    pub name: String,
    /// Argon2id salt, standard base64 (with padding) in JSON.
    #[serde(with = "salt_base64")]
    pub salt: [u8; SALT_LEN],
    /// Argon2id parameters.
    pub kdf: KdfParams,
}

impl ServerHello {
    /// A hello for the current protocol version with default KDF parameters.
    pub fn new(name: impl Into<String>, salt: [u8; SALT_LEN]) -> Self {
        Self {
            beacon: PROTOCOL_VERSION,
            name: name.into(),
            salt,
            kdf: KdfParams::DEFAULT,
        }
    }

    /// Serialises the hello as one line (JSON + `\n`). Fails if longer than
    /// [`HELLO_MAX_LEN`] (e.g. an overly long server name).
    pub fn to_line(&self) -> Result<Vec<u8>, Error> {
        let mut line = serde_json::to_vec(self)?;
        line.push(b'\n');
        if line.len() > HELLO_MAX_LEN {
            return Err(Error::TooLarge {
                len: line.len(),
                max: HELLO_MAX_LEN,
            });
        }
        Ok(line)
    }

    /// Parses a hello line (with or without the trailing `\n` / `\r\n`) and checks
    /// the protocol version. KDF bounds are checked by [`derive_psk`].
    pub fn from_line(line: &[u8]) -> Result<Self, Error> {
        if line.len() > HELLO_MAX_LEN {
            return Err(Error::TooLarge {
                len: line.len(),
                max: HELLO_MAX_LEN,
            });
        }
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let hello: Self = serde_json::from_slice(line)?;
        if hello.beacon != PROTOCOL_VERSION {
            return Err(Error::UnsupportedVersion(hello.beacon));
        }
        Ok(hello)
    }

    /// [`derive_psk`] with this hello's salt and parameters.
    pub fn derive_psk(&self, password: &str) -> Result<[u8; PSK_LEN], Error> {
        derive_psk(password, &self.salt, &self.kdf)
    }
}

/// Length of the hello line (including its `\n`) at the start of the bytes received
/// so far: `Ok(Some(n))` once complete, `Ok(None)` if more data is needed, and an
/// error if no `\n` appears within [`HELLO_MAX_LEN`] bytes. Bytes after the line
/// already belong to the Noise frame stream.
pub fn hello_line_len(received: &[u8]) -> Result<Option<usize>, Error> {
    let head = received.get(..HELLO_MAX_LEN).unwrap_or(received);
    match head.iter().position(|&b| b == b'\n') {
        Some(i) => Ok(Some(i + 1)),
        None if received.len() >= HELLO_MAX_LEN => Err(Error::TooLarge {
            len: received.len(),
            max: HELLO_MAX_LEN,
        }),
        None => Ok(None),
    }
}

mod salt_base64 {
    use super::{BASE64, SALT_LEN};
    use base64::Engine as _;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(salt: &[u8; SALT_LEN], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(salt))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; SALT_LEN], D::Error> {
        let text = String::deserialize(d)?;
        if text.len() > 64 {
            return Err(D::Error::custom("salt too long"));
        }
        let bytes = BASE64
            .decode(text.as_bytes())
            .map_err(|_| D::Error::custom("salt is not valid base64"))?;
        <[u8; SALT_LEN]>::try_from(bytes.as_slice())
            .map_err(|_| D::Error::invalid_length(bytes.len(), &"16 bytes"))
    }
}

// ---------------------------------------------------------------------------
// Noise
// ---------------------------------------------------------------------------

/// A `snow` builder for [`NOISE_PARAMS`] with `psk` at position 0. Call
/// `build_initiator()` (client) or `build_responder()` (server) on it.
pub fn noise_builder(psk: &[u8; PSK_LEN]) -> Result<snow::Builder<'_>, snow::Error> {
    let params: snow::params::NoiseParams = NOISE_PARAMS.parse()?;
    snow::Builder::new(params).psk(0, psk)
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// Appends one frame (u16 big-endian length + `payload`) to `out`. Fails without
/// touching `out` if `payload` is longer than [`MAX_FRAME_LEN`].
pub fn encode_frame(payload: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    let len = u16::try_from(payload.len()).map_err(|_| Error::TooLarge {
        len: payload.len(),
        max: MAX_FRAME_LEN,
    })?;
    out.reserve(FRAME_HEADER_LEN + payload.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Incremental decoder for the u16-BE-length-prefixed frame stream: push received
/// bytes in arbitrary pieces, pop complete frames.
///
/// A frame header announcing more than the configured maximum is reported as soon
/// as the two length bytes have arrived (the body is never buffered); the error is
/// sticky because the stream cannot be resynchronised – close the connection.
#[derive(Debug, Clone)]
pub struct FrameDecoder {
    buf: Vec<u8>,
    start: usize,
    max_len: usize,
}

impl FrameDecoder {
    /// A decoder accepting frames up to [`MAX_FRAME_LEN`] bytes.
    pub fn new() -> Self {
        Self::with_max_len(MAX_FRAME_LEN)
    }

    /// A decoder accepting frames up to `max_len` bytes (capped at
    /// [`MAX_FRAME_LEN`]); e.g. a small limit during the handshake.
    pub fn with_max_len(max_len: usize) -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            max_len: max_len.min(MAX_FRAME_LEN),
        }
    }

    /// Changes the frame size limit (capped at [`MAX_FRAME_LEN`]).
    pub fn set_max_len(&mut self, max_len: usize) {
        self.max_len = max_len.min(MAX_FRAME_LEN);
    }

    /// The current frame size limit.
    pub fn max_len(&self) -> usize {
        self.max_len
    }

    /// Appends received bytes.
    pub fn push(&mut self, data: &[u8]) {
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// The next complete frame, `Ok(None)` if more bytes are needed, or an error if
    /// the next frame exceeds the limit.
    pub fn pop(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let pending = self.buf.get(self.start..).unwrap_or_default();
        let Some(&len_bytes) = pending.first_chunk::<FRAME_HEADER_LEN>() else {
            return Ok(None);
        };
        let len = usize::from(u16::from_be_bytes(len_bytes));
        if len > self.max_len {
            return Err(Error::TooLarge {
                len,
                max: self.max_len,
            });
        }
        let end = FRAME_HEADER_LEN + len;
        let Some(frame) = pending.get(FRAME_HEADER_LEN..end) else {
            return Ok(None);
        };
        let frame = frame.to_vec();
        self.start += end;
        if self.start >= self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
        Ok(Some(frame))
    }

    /// Number of received bytes not yet returned as frames.
    pub fn buffered(&self) -> usize {
        self.buf.len().saturating_sub(self.start)
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// JSON messages
// ---------------------------------------------------------------------------

/// Serialises a control message to JSON, enforcing [`MAX_MSG_LEN`].
pub fn encode_msg<T: Serialize>(msg: &T) -> Result<Vec<u8>, Error> {
    let json = serde_json::to_vec(msg)?;
    if json.len() > MAX_MSG_LEN {
        return Err(Error::TooLarge {
            len: json.len(),
            max: MAX_MSG_LEN,
        });
    }
    Ok(json)
}

/// Parses a control message from JSON, enforcing [`MAX_MSG_LEN`]. Unknown fields
/// are ignored; an unknown `"t"` yields the enum's `Unknown` variant.
pub fn decode_msg<T: DeserializeOwned>(json: &[u8]) -> Result<T, Error> {
    if json.len() > MAX_MSG_LEN {
        return Err(Error::TooLarge {
            len: json.len(),
            max: MAX_MSG_LEN,
        });
    }
    Ok(serde_json::from_slice(json)?)
}

/// Standard base64 (with padding) as used in the control protocol.
pub fn base64_encode(data: &[u8]) -> String {
    BASE64.encode(data)
}

/// Decodes standard base64 (with padding).
pub fn base64_decode(text: &str) -> Result<Vec<u8>, Error> {
    BASE64.decode(text.as_bytes()).map_err(|_| Error::Base64)
}

#[cfg(test)]
mod tests;
