//! JSON messages of the control channel (one per Noise transport message).

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use super::game_config::{ConfigStatus, GameConfig};
use super::{base64_decode, base64_encode, decode_msg, encode_msg, Error, CHUNK_MAX};
use crate::fingerprint::FileEntry;
use crate::relay::RelayKey;

/// Launcher → server messages: `{"t":"<variant in snake_case>", …fields}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ClientMsg {
    /// First message after the handshake; the server answers with `welcome`
    /// (or `error` + close).
    Hello {
        /// Player name (unique among connected players; the vIP sticks to it).
        name: String,
        /// Launcher version (informational, e.g. `"0.1.0"`).
        version: String,
        /// Combined game-data fingerprint (64 hex digits, see
        /// [`crate::fingerprint`]); `null` if the game was not found.
        fingerprint: Option<String>,
    },
    /// The client's fingerprint file list, sent after `hello` (and whenever the
    /// fingerprint changes) so that other players can ask for it.
    FingerprintFiles {
        /// Normalised, sorted entries ([`crate::fingerprint::Fingerprint::entries`]).
        files: Vec<FileEntry>,
        /// `false` if the list was cut to fit into one message.
        complete: bool,
    },
    /// Asks for another player's fingerprint file list (answer:
    /// `fingerprint_files`, or `error` with `unknown_player`).
    FingerprintGet {
        /// Name of the player.
        name: String,
    },
    /// A lobby chat line.
    Chat {
        /// Message text.
        text: String,
    },
    /// Sets the player's ready flag.
    Ready {
        /// Ready or not.
        ready: bool,
    },
    /// Host only: every launcher starts BFME (server broadcasts `launch`).
    LaunchAll,
    /// Host only: removes a player (the server sends that player `kick`).
    Kick {
        /// Name of the player to remove.
        name: String,
    },
    /// Requests the map repository listing (answer: `maps`).
    MapList,
    /// Requests one chunk of a map file (answer: `chunk`).
    MapGet {
        /// Map name ([`MapInfo::name`]).
        map: String,
        /// File path inside the map ([`MapFile::path`]).
        file: String,
        /// Byte offset to start at.
        offset: u64,
    },
    /// Liveness probe every [`PING_INTERVAL`](super::PING_INTERVAL) (answer: `pong`
    /// with the same `ts`).
    Ping {
        /// Client timestamp (ms, opaque to the server).
        ts: u64,
    },
    /// Status update shown in the lobby (the agent measures the relay path).
    Status {
        /// The game is running.
        in_game: bool,
        /// Last measured relay round-trip time, if any.
        rtt_ms: Option<u32>,
        /// Relay packet loss in percent (0–100), if measured.
        loss_pct: Option<u8>,
        /// Readiness for the lobby's game configuration (omitted by launchers
        /// without mod support).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        config: Option<ConfigStatus>,
    },
    /// Host only: sets the lobby's game configuration (`null` = vanilla). Servers
    /// without [`FEATURE_GAME_CONFIG`](super::FEATURE_GAME_CONFIG) ignore it.
    SetGameConfig {
        /// The configuration ([`GameConfig::finalize`]d by the host).
        config: Option<Box<GameConfig>>,
    },
    /// Any message type this version does not know. Never sent; produced by
    /// decoding an unknown `"t"` so that newer peers stay compatible.
    #[serde(other)]
    Unknown,
}

/// Server → launcher messages: `{"t":"<variant in snake_case>", …fields}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ServerMsg {
    /// Answer to `hello`: relay credentials of this session (used by the agent).
    Welcome {
        /// Relay session id (relay header field).
        session: u32,
        /// Relay key, 64 hex digits in JSON.
        key: RelayKey,
        /// The player's vIP, dotted quad in JSON (passed to the hook as `BEACON_VIP`).
        vip: Ipv4Addr,
        /// UDP port of the relay (same host as the control connection).
        relay_port: u16,
        /// Message of the day.
        motd: String,
        /// This player is the host.
        you_are_host: bool,
        /// Optional protocol features of this server (e.g.
        /// [`FEATURE_GAME_CONFIG`](super::FEATURE_GAME_CONFIG)); missing from older
        /// servers.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        features: Vec<String>,
    },
    /// The complete current player list (sent on every change).
    Lobby {
        /// All connected players.
        players: Vec<Player>,
    },
    /// A player's fingerprint file list (answer to `fingerprint_get`).
    FingerprintFiles {
        /// Name of the player.
        name: String,
        /// The player's entries as uploaded.
        files: Vec<FileEntry>,
        /// `false` if the list is incomplete.
        complete: bool,
    },
    /// A chat line.
    Chat {
        /// Sender name (empty for server notices).
        from: String,
        /// Message text.
        text: String,
        /// Server timestamp (ms since the Unix epoch).
        ts: u64,
    },
    /// The map repository listing.
    Maps {
        /// Every map the server offers.
        maps: Vec<MapInfo>,
    },
    /// One piece of a map file.
    Chunk(Chunk),
    /// The lobby's game configuration: after the login and after every change.
    GameConfig {
        /// The configuration; `null` = vanilla (everybody's own installation).
        config: Option<Box<GameConfig>>,
        /// Name of the host who set it (empty after a server start).
        #[serde(default)]
        by: String,
    },
    /// Start BFME now.
    Launch,
    /// Answer to `ping`.
    Pong {
        /// The `ts` of the `ping`.
        ts: u64,
    },
    /// A request failed.
    Error {
        /// Machine-readable reason.
        code: ErrorCode,
        /// Human-readable text.
        text: String,
    },
    /// The player was removed; the server closes the connection.
    Kick {
        /// Reason shown to the player.
        reason: String,
    },
    /// Any message type this version does not know. Never sent; produced by
    /// decoding an unknown `"t"` so that newer peers stay compatible.
    #[serde(other)]
    Unknown,
}

impl ClientMsg {
    /// JSON encoding (see [`encode_msg`](super::encode_msg)).
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        encode_msg(self)
    }

    /// JSON decoding (see [`decode_msg`](super::decode_msg)).
    pub fn from_json(json: &[u8]) -> Result<Self, Error> {
        decode_msg(json)
    }
}

impl ServerMsg {
    /// JSON encoding (see [`encode_msg`](super::encode_msg)).
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        encode_msg(self)
    }

    /// JSON decoding (see [`decode_msg`](super::decode_msg)).
    pub fn from_json(json: &[u8]) -> Result<Self, Error> {
        decode_msg(json)
    }
}

/// One entry of the `lobby` player list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Player {
    /// Player name.
    pub name: String,
    /// The player's vIP.
    pub vip: Ipv4Addr,
    /// Relay round-trip time, if measured.
    pub rtt_ms: Option<u32>,
    /// Relay packet loss in percent (0–100), if measured.
    pub loss_pct: Option<u8>,
    /// Combined game-data fingerprint, if known (players are grouped by it).
    pub fingerprint: Option<String>,
    /// Ready flag.
    pub ready: bool,
    /// The game is running.
    pub in_game: bool,
    /// This player is the host.
    pub is_host: bool,
    /// The player's readiness for the game configuration (`None`: not reported,
    /// e.g. a launcher without mod support).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<ConfigStatus>,
}

/// One file of a map in the repository manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MapFile {
    /// Path relative to the map folder, `/`-separated (validate with
    /// [`is_safe_rel_path`](super::is_safe_rel_path) before touching the disk).
    pub path: String,
    /// File size in bytes.
    pub size: u64,
    /// BLAKE3 of the content, 64 lowercase hex digits.
    pub blake3_hex: String,
}

/// A map in the repository (`maps/<MapName>/…` on the server).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapInfo {
    /// Map folder name (validate with [`is_safe_file_name`](super::is_safe_file_name)).
    pub name: String,
    /// Every file of the map.
    pub files: Vec<MapFile>,
    /// Sum of all file sizes.
    pub total_size: u64,
}

impl MapInfo {
    /// A map entry with `total_size` computed from `files`.
    pub fn new(name: impl Into<String>, files: Vec<MapFile>) -> Self {
        let total_size = files.iter().fold(0u64, |acc, f| acc.saturating_add(f.size));
        Self {
            name: name.into(),
            files,
            total_size,
        }
    }
}

/// One piece of a map file: `{"t":"chunk","map":…,"file":…,"offset":…,"data":"<b64>","eof":…}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunk {
    /// Map name.
    pub map: String,
    /// File path inside the map.
    pub file: String,
    /// Offset of the first byte of this chunk within the file.
    pub offset: u64,
    /// The bytes, standard base64 (JSON field `"data"`); at most [`CHUNK_MAX`] raw bytes.
    #[serde(rename = "data")]
    pub data_b64: String,
    /// This chunk ends at the end of the file.
    pub eof: bool,
}

impl Chunk {
    /// Builds a chunk from raw bytes; fails if `data` exceeds [`CHUNK_MAX`].
    pub fn new(
        map: impl Into<String>,
        file: impl Into<String>,
        offset: u64,
        data: &[u8],
        eof: bool,
    ) -> Result<Self, Error> {
        if data.len() > CHUNK_MAX {
            return Err(Error::TooLarge {
                len: data.len(),
                max: CHUNK_MAX,
            });
        }
        Ok(Self {
            map: map.into(),
            file: file.into(),
            offset,
            data_b64: base64_encode(data),
            eof,
        })
    }

    /// Decodes the payload; fails on invalid base64 or more than [`CHUNK_MAX`] bytes.
    pub fn data(&self) -> Result<Vec<u8>, Error> {
        let max_encoded = CHUNK_MAX.div_ceil(3) * 4;
        if self.data_b64.len() > max_encoded {
            return Err(Error::TooLarge {
                len: self.data_b64.len(),
                max: max_encoded,
            });
        }
        let data = base64_decode(&self.data_b64)?;
        if data.len() > CHUNK_MAX {
            return Err(Error::TooLarge {
                len: data.len(),
                max: CHUNK_MAX,
            });
        }
        Ok(data)
    }
}

/// Machine-readable error reason of `error{code, text}`; snake_case strings in JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Malformed, unexpected or out-of-order message.
    BadRequest,
    /// The launcher version is not supported.
    UnsupportedVersion,
    /// The name is empty, too long or contains invalid characters.
    BadName,
    /// Another connected player uses this name.
    NameTaken,
    /// The server is full (player limit or vIP pool exhausted).
    ServerFull,
    /// A host-only command was sent by a non-host.
    NotHost,
    /// The named player does not exist (or has no fingerprint list).
    UnknownPlayer,
    /// The requested map does not exist.
    UnknownMap,
    /// The requested file is not part of the map.
    UnknownFile,
    /// The requested offset is beyond the end of the file.
    BadOffset,
    /// Too many requests.
    RateLimited,
    /// Internal server error.
    Internal,
    /// Not every player is ready for the lobby's game configuration.
    NotReady,
    /// A code this version does not know.
    #[serde(other)]
    Unknown,
}
