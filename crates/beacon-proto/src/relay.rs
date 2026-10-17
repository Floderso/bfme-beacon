//! UDP relay protocol between the launcher's agent and the server (architecture §6).
//! "Client" in this module means the agent.
//!
//! ```text
//! offset size field
//! 0      2    magic 0xBE 0xAC
//! 2      1    version = 1
//! 3      1    type: 1 REG, 2 DATA, 3 PING, 4 PONG, 5 REG_ACK, 6 ERROR, 7 BYE, 8 UNREG
//! 4      4    session id, u32 LE (agent→server) | 0 (server→agent)
//! 8      8    counter, u64 LE (per sender per direction, strictly increasing)
//! 16     4    vIP, network order (agent→server: destination; server→agent: source)
//! 20     2    src vport, big-endian
//! 22     2    dst vport, big-endian
//! 24     n    payload, ChaCha20-Poly1305 ciphertext (n ≤ 480)
//! 24+n   16   Poly1305 tag (AAD = bytes 0..24)
//! ```
//!
//! * **Every** packet type is sealed (the payload may be empty), so every packet that
//!   [`open`] accepts is authenticated. Datagrams that fail to open, or that name an
//!   unknown session, are dropped silently and never answered.
//! * Nonce = direction (1 = agent→server, 2 = server→agent) ‖ 3 zero bytes ‖
//!   counter (u64 LE), see [`nonce`]. The key is the per-session [`RelayKey`] issued
//!   in `welcome`; it is used for both directions, the direction byte keeps the
//!   nonces apart.
//! * Senders draw counters from a [`SendCounter`]; receivers keep one 256-entry
//!   [`ReplayWindow`] per session and direction.
//! * Redundancy: DATA is sent [`default_redundancy`] times with the **same counter**,
//!   copies delayed by [`REDUNDANCY_DELAYS`]. Copies must be byte-identical
//!   retransmissions of the one sealed packet (never seal different data under a
//!   counter twice); the receiver's window drops them as [`Error::Replayed`].
//!
//! The API works on caller-provided buffers and never allocates.
//!
//! ```
//! use beacon_proto::relay::*;
//! use beacon_proto::net::SERVER_VIP;
//!
//! let key = RelayKey::from_bytes([7; 32]);
//! let counter = SendCounter::new();
//!
//! // Agent: wrap a game datagram for vIP 198.18.0.3, port 8086 -> 8086.
//! let header = Header::client(
//!     PacketType::Data, 0x1234, counter.next().unwrap(),
//!     "198.18.0.3".parse().unwrap(), 8086, 8086,
//! );
//! assert_eq!(default_redundancy(header.dst_vport), 3);
//! let mut packet = [0u8; MAX_PACKET_LEN];
//! let len = seal(&key, Direction::ClientToServer, &header, b"hello", &mut packet).unwrap();
//!
//! // Server: look up the session by the unauthenticated header, then open in place.
//! let peeked = peek_header(&packet[..len]).unwrap();
//! assert_eq!(peeked.session, 0x1234);
//! let mut window = ReplayWindow::new();
//! let (opened, payload) =
//!     open_with_window(&key, Direction::ClientToServer, &mut packet[..len], &mut window).unwrap();
//! assert_eq!(opened, header);
//! assert_eq!(&packet[payload], b"hello");
//! # let _ = SERVER_VIP;
//! ```

use core::fmt;
use core::ops::Range;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::net::Ipv4Addr;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};

use crate::net;

/// Magic bytes at offset 0.
pub const MAGIC: [u8; 2] = [0xBE, 0xAC];
/// Protocol version at offset 2.
pub const VERSION: u8 = 1;
/// Length of the header, which is also the AEAD associated data.
pub const HEADER_LEN: usize = 24;
/// Length of the Poly1305 tag at the end of every packet.
pub const TAG_LEN: usize = 16;
/// Maximum payload length (BFME never sends datagrams larger than 480 bytes;
/// larger payloads are dropped).
pub const MAX_PAYLOAD: usize = 480;
/// Length of the smallest valid packet (empty payload).
pub const MIN_PACKET_LEN: usize = HEADER_LEN + TAG_LEN;
/// Length of the largest valid packet; a receive buffer of this size always suffices.
pub const MAX_PACKET_LEN: usize = HEADER_LEN + MAX_PAYLOAD + TAG_LEN;
/// Length of a relay key.
pub const KEY_LEN: usize = 32;
/// Length of the ChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 12;
/// Length of the PING/PONG payload (client timestamp, u64 LE).
pub const TIMESTAMP_LEN: usize = 8;

/// Errors of the relay codec. Every malformed input maps to one of these; nothing panics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Error {
    /// The datagram is shorter than header + tag ([`MIN_PACKET_LEN`]).
    Truncated {
        /// Length of the rejected datagram.
        len: usize,
    },
    /// Payload longer than [`MAX_PAYLOAD`] (seal) or datagram longer than
    /// [`MAX_PACKET_LEN`] (peek/open).
    TooLarge {
        /// Offending payload or datagram length.
        len: usize,
    },
    /// The output buffer passed to [`seal`] is too small.
    BufferTooSmall {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        available: usize,
    },
    /// The magic bytes are not `0xBE 0xAC`.
    BadMagic,
    /// Unsupported protocol version.
    BadVersion(u8),
    /// Unknown packet type.
    BadType(u8),
    /// Tag verification failed: wrong key, wrong direction or modified packet.
    AuthFailed,
    /// The counter was already accepted (duplicate or replay).
    Replayed {
        /// Rejected counter.
        counter: u64,
    },
    /// The counter is older than the replay window.
    TooOld {
        /// Rejected counter.
        counter: u64,
    },
    /// The payload does not have the size its packet type requires.
    BadPayload,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { len } => write!(f, "relay packet truncated ({len} bytes)"),
            Self::TooLarge { len } => write!(f, "relay packet or payload too large ({len} bytes)"),
            Self::BufferTooSmall { needed, available } => {
                write!(f, "output buffer too small ({available} < {needed} bytes)")
            }
            Self::BadMagic => f.write_str("bad relay magic"),
            Self::BadVersion(v) => write!(f, "unsupported relay version {v}"),
            Self::BadType(t) => write!(f, "unknown relay packet type {t}"),
            Self::AuthFailed => f.write_str("relay packet authentication failed"),
            Self::Replayed { counter } => write!(f, "replayed relay counter {counter}"),
            Self::TooOld { counter } => write!(f, "relay counter {counter} outside replay window"),
            Self::BadPayload => f.write_str("malformed relay payload"),
        }
    }
}

impl std::error::Error for Error {}

/// Packet type (header offset 3). The doc of each variant gives the field
/// conventions shared by server and agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketType {
    /// Agent→server: the hook registered virtual port `src_vport` for this session
    /// (the agent's UDP endpoint is the packet source). `vip` =
    /// [`SERVER_VIP`](crate::net::SERVER_VIP), `dst_vport` = 0, empty payload.
    /// Answered with [`RegAck`](Self::RegAck).
    Reg = 1,
    /// A game datagram. Agent→server: `vip` = destination vIP (unicast or
    /// broadcast); server→agent: `vip` = source vIP. Ports are the virtual ports.
    /// Sent [`default_redundancy`] times with the same counter.
    Data = 2,
    /// Agent→server probe every [`PING_INTERVAL`] (RTT, loss estimate, NAT
    /// keep-alive): payload = 8-byte agent timestamp ([`encode_timestamp`]);
    /// `vip` = server vIP.
    Ping = 3,
    /// Server→agent answer to [`Ping`](Self::Ping): echoes the 8-byte timestamp;
    /// `vip` = server vIP.
    Pong = 4,
    /// Server→agent registration confirmation: echoes the registered vport in
    /// `src_vport` (and `dst_vport`); `vip` = server vIP; empty payload.
    RegAck = 5,
    /// Server→agent notification about the session: payload = u16 LE code from
    /// [`error_code`] ([`encode_error`]). Never sent for unknown destinations.
    Error = 6,
    /// End of the session (agent leaving, or server→agent: stop sending). Empty
    /// payload.
    Bye = 7,
    /// Agent→server: the hook closed the socket bound to `src_vport`. `vip` =
    /// server vIP, `dst_vport` = 0, empty payload.
    Unreg = 8,
}

impl PacketType {
    /// Every packet type, in wire order.
    pub const ALL: [Self; 8] = [
        Self::Reg,
        Self::Data,
        Self::Ping,
        Self::Pong,
        Self::RegAck,
        Self::Error,
        Self::Bye,
        Self::Unreg,
    ];

    /// The packet type for a wire value, or `None` if unknown.
    pub const fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Reg,
            2 => Self::Data,
            3 => Self::Ping,
            4 => Self::Pong,
            5 => Self::RegAck,
            6 => Self::Error,
            7 => Self::Bye,
            8 => Self::Unreg,
            _ => return None,
        })
    }

    /// The wire value.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for PacketType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Error> {
        Self::from_u8(value).ok_or(Error::BadType(value))
    }
}

/// Direction of a packet; selects the first nonce byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Direction {
    /// Agent (in `Beacon.exe`) → server.
    ClientToServer = 1,
    /// Server → agent.
    ServerToClient = 2,
}

impl Direction {
    /// The opposite direction.
    pub const fn reverse(self) -> Self {
        match self {
            Self::ClientToServer => Self::ServerToClient,
            Self::ServerToClient => Self::ClientToServer,
        }
    }
}

/// A per-session 32-byte relay key. `Debug` does not print the key material.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayKey([u8; KEY_LEN]);

impl RelayKey {
    /// Wraps raw key bytes.
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw key bytes.
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Parses exactly 64 hex digits (either case; surrounding whitespace ignored),
    /// the format of the `key` field of `welcome`.
    pub fn from_hex(s: &str) -> Option<Self> {
        let digits = s.trim().as_bytes();
        if digits.len() != KEY_LEN * 2 {
            return None;
        }
        let mut key = [0u8; KEY_LEN];
        for (out, &[hi, lo]) in key.iter_mut().zip(digits.as_chunks::<2>().0) {
            *out = (hex_value(hi)? << 4) | hex_value(lo)?;
        }
        Some(Self(key))
    }

    /// The key as 64 lowercase hex digits.
    pub fn to_hex(&self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(KEY_LEN * 2);
        for b in self.0 {
            for nibble in [b >> 4, b & 0x0f] {
                if let Some(&d) = DIGITS.get(usize::from(nibble)) {
                    s.push(char::from(d));
                }
            }
        }
        s
    }
}

impl From<[u8; KEY_LEN]> for RelayKey {
    fn from(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for RelayKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelayKey(<redacted>)")
    }
}

#[cfg(feature = "control")]
impl serde::Serialize for RelayKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

#[cfg(feature = "control")]
impl<'de> serde::Deserialize<'de> for RelayKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s)
            .ok_or_else(|| serde::de::Error::custom("relay key must be 64 hex digits"))
    }
}

const fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// The 24-byte packet header (everything except magic and version, which are fixed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Header {
    /// Packet type.
    pub kind: PacketType,
    /// Session id (client→server); always 0 server→client.
    pub session: u32,
    /// Sender's counter for this direction; also the nonce.
    pub counter: u64,
    /// Client→server: destination vIP. Server→client: source vIP.
    pub vip: Ipv4Addr,
    /// Virtual source port.
    pub src_vport: u16,
    /// Virtual destination port.
    pub dst_vport: u16,
}

impl Header {
    /// A client→server header for `session`; `dst_vip` is the destination vIP
    /// (the server vIP for REG/PING/BYE).
    pub const fn client(
        kind: PacketType,
        session: u32,
        counter: u64,
        dst_vip: Ipv4Addr,
        src_vport: u16,
        dst_vport: u16,
    ) -> Self {
        Self {
            kind,
            session,
            counter,
            vip: dst_vip,
            src_vport,
            dst_vport,
        }
    }

    /// A server→client header (session id 0); `src_vip` is the source vIP
    /// (the server vIP for PONG/REG_ACK/ERROR/BYE).
    pub const fn server(
        kind: PacketType,
        counter: u64,
        src_vip: Ipv4Addr,
        src_vport: u16,
        dst_vport: u16,
    ) -> Self {
        Self {
            kind,
            session: 0,
            counter,
            vip: src_vip,
            src_vport,
            dst_vport,
        }
    }

    /// Encodes the header into its 24 wire bytes.
    pub const fn encode(&self) -> [u8; HEADER_LEN] {
        let [m0, m1] = MAGIC;
        let [s0, s1, s2, s3] = self.session.to_le_bytes();
        let [c0, c1, c2, c3, c4, c5, c6, c7] = self.counter.to_le_bytes();
        let [v0, v1, v2, v3] = self.vip.octets();
        let [sp0, sp1] = self.src_vport.to_be_bytes();
        let [dp0, dp1] = self.dst_vport.to_be_bytes();
        [
            m0,
            m1,
            VERSION,
            self.kind.as_u8(),
            s0,
            s1,
            s2,
            s3,
            c0,
            c1,
            c2,
            c3,
            c4,
            c5,
            c6,
            c7,
            v0,
            v1,
            v2,
            v3,
            sp0,
            sp1,
            dp0,
            dp1,
        ]
    }

    /// Decodes 24 header bytes, checking magic, version and type (not authenticity).
    pub const fn decode(bytes: &[u8; HEADER_LEN]) -> Result<Self, Error> {
        let [m0, m1, version, kind, s0, s1, s2, s3, c0, c1, c2, c3, c4, c5, c6, c7, v0, v1, v2, v3, sp0, sp1, dp0, dp1] =
            *bytes;
        let [magic0, magic1] = MAGIC;
        if m0 != magic0 || m1 != magic1 {
            return Err(Error::BadMagic);
        }
        if version != VERSION {
            return Err(Error::BadVersion(version));
        }
        let Some(kind) = PacketType::from_u8(kind) else {
            return Err(Error::BadType(kind));
        };
        Ok(Self {
            kind,
            session: u32::from_le_bytes([s0, s1, s2, s3]),
            counter: u64::from_le_bytes([c0, c1, c2, c3, c4, c5, c6, c7]),
            vip: Ipv4Addr::new(v0, v1, v2, v3),
            src_vport: u16::from_be_bytes([sp0, sp1]),
            dst_vport: u16::from_be_bytes([dp0, dp1]),
        })
    }
}

/// The 12-byte nonce: direction byte ‖ 3 zero bytes ‖ counter (u64 LE).
pub const fn nonce(dir: Direction, counter: u64) -> [u8; NONCE_LEN] {
    let [c0, c1, c2, c3, c4, c5, c6, c7] = counter.to_le_bytes();
    [dir as u8, 0, 0, 0, c0, c1, c2, c3, c4, c5, c6, c7]
}

/// Validates the framing of a received datagram (length bounds, magic, version,
/// type) and returns its header **without** authenticating it. Use it only to find
/// the session (and thus the key); then call [`open`] or [`open_with_window`].
pub fn peek_header(packet: &[u8]) -> Result<Header, Error> {
    let len = packet.len();
    if len < MIN_PACKET_LEN {
        return Err(Error::Truncated { len });
    }
    if len > MAX_PACKET_LEN {
        return Err(Error::TooLarge { len });
    }
    let header = packet
        .first_chunk::<HEADER_LEN>()
        .ok_or(Error::Truncated { len })?;
    Header::decode(header)
}

/// Seals `payload` under `header` into `out` and returns the packet length
/// (`24 + payload.len() + 16`). The payload is encrypted, the header is
/// authenticated as associated data. `out` beyond the returned length is untouched.
pub fn seal(
    key: &RelayKey,
    dir: Direction,
    header: &Header,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let n = payload.len();
    if n > MAX_PAYLOAD {
        return Err(Error::TooLarge { len: n });
    }
    let total = MIN_PACKET_LEN + n;
    let available = out.len();
    let too_small = Error::BufferTooSmall {
        needed: total,
        available,
    };
    let packet = out.get_mut(..total).ok_or(too_small)?;
    let (aad, rest) = packet
        .split_first_chunk_mut::<HEADER_LEN>()
        .ok_or(too_small)?;
    *aad = header.encode();
    let (body, tag_out) = rest.split_at_mut_checked(n).ok_or(too_small)?;
    let tag_out = <&mut [u8; TAG_LEN]>::try_from(tag_out).map_err(|_| too_small)?;
    body.copy_from_slice(payload);
    let tag = cipher(key)
        .encrypt_in_place_detached(&Nonce::from(nonce(dir, header.counter)), aad, body)
        .map_err(|_| Error::TooLarge { len: n })?;
    tag_out.copy_from_slice(&tag);
    Ok(total)
}

/// Authenticates and decrypts `packet` in place. On success returns the header and
/// the byte range of the plaintext payload inside `packet`. Fails with
/// [`Error::AuthFailed`] for a wrong key, the wrong direction or any modification;
/// on failure the payload bytes are left as received.
///
/// This does not check for replays; see [`open_with_window`].
pub fn open(
    key: &RelayKey,
    dir: Direction,
    packet: &mut [u8],
) -> Result<(Header, Range<usize>), Error> {
    let header = peek_header(packet)?;
    let len = packet.len();
    let truncated = Error::Truncated { len };
    let n = len.checked_sub(MIN_PACKET_LEN).ok_or(truncated)?;
    let (aad, rest) = packet
        .split_first_chunk_mut::<HEADER_LEN>()
        .ok_or(truncated)?;
    let (body, tag) = rest.split_at_mut_checked(n).ok_or(truncated)?;
    let tag = <[u8; TAG_LEN]>::try_from(&*tag).map_err(|_| truncated)?;
    cipher(key)
        .decrypt_in_place_detached(
            &Nonce::from(nonce(dir, header.counter)),
            aad.as_slice(),
            body,
            &Tag::from(tag),
        )
        .map_err(|_| Error::AuthFailed)?;
    Ok((header, HEADER_LEN..HEADER_LEN + n))
}

/// [`open`] with replay protection: rejects counters the window has already seen
/// or that are too old *before* decrypting, and records the counter only *after*
/// successful authentication (so forged packets cannot move the window).
pub fn open_with_window(
    key: &RelayKey,
    dir: Direction,
    packet: &mut [u8],
    window: &mut ReplayWindow,
) -> Result<(Header, Range<usize>), Error> {
    let header = peek_header(packet)?;
    window.check(header.counter)?;
    let opened = open(key, dir, packet)?;
    window.accept(header.counter)?;
    Ok(opened)
}

fn cipher(key: &RelayKey) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(&Key::from(key.0))
}

/// Encodes the PING/PONG payload (client timestamp, u64 LE).
pub const fn encode_timestamp(ts: u64) -> [u8; TIMESTAMP_LEN] {
    ts.to_le_bytes()
}

/// Decodes a PING/PONG payload; it must be exactly 8 bytes.
pub fn decode_timestamp(payload: &[u8]) -> Result<u64, Error> {
    <[u8; TIMESTAMP_LEN]>::try_from(payload)
        .map(u64::from_le_bytes)
        .map_err(|_| Error::BadPayload)
}

/// Codes carried by [`PacketType::Error`] packets (u16 LE payload).
pub mod error_code {
    /// The sending endpoint/vport is not registered; send REG first.
    pub const NOT_REGISTERED: u16 = 1;
    /// The session exceeded its rate limit; packets are being dropped.
    pub const RATE_LIMITED: u16 = 2;
}

/// Encodes an ERROR payload.
pub const fn encode_error(code: u16) -> [u8; 2] {
    code.to_le_bytes()
}

/// Decodes an ERROR payload: the first two bytes (u16 LE) are the code; any further
/// bytes are reserved and ignored.
pub fn decode_error(payload: &[u8]) -> Result<u16, Error> {
    payload
        .first_chunk::<2>()
        .map(|b| u16::from_le_bytes(*b))
        .ok_or(Error::BadPayload)
}

/// Interval of the agent's PING (RTT, loss estimate, NAT keep-alive).
pub const PING_INTERVAL: Duration = Duration::from_millis(1000);

/// Delays of the redundant DATA copies 2 and 3 after the original.
pub const REDUNDANCY_DELAYS: [Duration; 2] = [Duration::from_millis(3), Duration::from_millis(10)];

/// Highest number of DATA copies with a defined delay (original + [`REDUNDANCY_DELAYS`]).
pub const MAX_REDUNDANCY: u8 = 1 + REDUNDANCY_DELAYS.len() as u8;

/// Default number of times a DATA packet to virtual port `dst_vport` is sent (with
/// the same counter): 3 for BFME's lobby ports 8086…8093 (many lobby messages are
/// sent only once), 2 for the in-game ports 8094…8101, 1 for anything else.
/// Configurable by the caller; at most [`MAX_REDUNDANCY`].
pub const fn default_redundancy(dst_vport: u16) -> u8 {
    if net::is_lobby_port(dst_vport) {
        3
    } else if net::is_game_port(dst_vport) {
        2
    } else {
        1
    }
}

const WINDOW_WORDS: usize = 4;

/// Sliding anti-replay window over the last 256 counters of one sender and
/// direction (also the dedupe filter for redundant copies).
///
/// Accepts every counter newer than the highest one seen, accepts older counters
/// within the window exactly once (out-of-order delivery), and rejects duplicates
/// and counters 256 or more below the highest one. The first counter is always
/// accepted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayWindow {
    /// Highest accepted counter (meaningful once `seen` is set).
    top: u64,
    /// Bit `c % 256` is set if counter `c` (within the window) has been accepted.
    bitmap: [u64; WINDOW_WORDS],
    seen: bool,
}

impl ReplayWindow {
    /// Number of counters tracked (the highest one and the 255 below it).
    pub const SIZE: u64 = 64 * WINDOW_WORDS as u64;

    /// An empty window.
    pub const fn new() -> Self {
        Self {
            top: 0,
            bitmap: [0; WINDOW_WORDS],
            seen: false,
        }
    }

    /// Checks whether `counter` would be accepted, without recording it.
    pub fn check(&self, counter: u64) -> Result<(), Error> {
        if !self.seen || counter > self.top {
            return Ok(());
        }
        if self.top - counter >= Self::SIZE {
            Err(Error::TooOld { counter })
        } else if self.is_set(counter) {
            Err(Error::Replayed { counter })
        } else {
            Ok(())
        }
    }

    /// Checks `counter` and records it if acceptable. Call this only after the
    /// packet has been authenticated.
    pub fn accept(&mut self, counter: u64) -> Result<(), Error> {
        self.check(counter)?;
        if !self.seen {
            self.seen = true;
            self.bitmap = [0; WINDOW_WORDS];
            self.top = counter;
        } else if counter > self.top {
            if counter - self.top >= Self::SIZE {
                self.bitmap = [0; WINDOW_WORDS];
            } else {
                // The slots of top+1..counter still hold counters that are now
                // outside the window; clear them.
                for c in self.top + 1..counter {
                    self.set(c, false);
                }
            }
            self.top = counter;
        }
        self.set(counter, true);
        Ok(())
    }

    fn slot(counter: u64) -> (usize, u64) {
        let bit = counter % Self::SIZE;
        ((bit / 64) as usize, 1u64 << (bit % 64))
    }

    fn is_set(&self, counter: u64) -> bool {
        let (word, mask) = Self::slot(counter);
        self.bitmap.get(word).is_some_and(|w| w & mask != 0)
    }

    fn set(&mut self, counter: u64, value: bool) {
        let (word, mask) = Self::slot(counter);
        if let Some(w) = self.bitmap.get_mut(word) {
            if value {
                *w |= mask;
            } else {
                *w &= !mask;
            }
        }
    }

    /// The highest accepted counter, if any.
    pub const fn highest(&self) -> Option<u64> {
        if self.seen {
            Some(self.top)
        } else {
            None
        }
    }

    /// Forgets everything (e.g. when a session is re-keyed).
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

/// Source of strictly increasing counters for one sender and direction (one per
/// session in the agent, one per session in the server). Atomic, so several tasks
/// can share it. Never wraps: after `u64::MAX - 1` it returns `None` (re-key the
/// session then).
#[derive(Debug, Default)]
pub struct SendCounter(AtomicU64);

impl SendCounter {
    /// A counter whose first value is 0.
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// A counter whose first value is `first`.
    pub const fn starting_at(first: u64) -> Self {
        Self(AtomicU64::new(first))
    }

    /// The next counter, or `None` once the counter space is exhausted.
    pub fn next(&self) -> Option<u64> {
        let mut current = self.0.load(Ordering::Relaxed);
        loop {
            let next = current.checked_add(1)?;
            match self.0.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return Some(current),
                Err(actual) => current = actual,
            }
        }
    }

    /// The value the next call to [`next`](Self::next) would return.
    pub fn peek(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests;
