//! Local frames between the game hook and the launcher's agent (architecture §5):
//! loopback UDP, all fields big-endian / network order. Zero allocation: frames are
//! encoded into and parsed from caller buffers.
//!
//! Hook → agent ([`HookFrame`], sent from the virtual socket's real loopback socket):
//!
//! ```text
//! 0  4  magic "BCN1"
//! 4  1  type: 1 REG, 2 SEND, 3 CLOSE
//! 5  1  flags = 0
//! 6  2  src vport
//! 8  4  dst vIP (255.255.255.255 / 198.18.0.255 = broadcast)
//! 12 2  dst vport
//! 14 2  reserved = 0
//! 16 4  local token (BEACON_LOCAL_TOKEN)
//! 20 .. payload (SEND only, ≤ 1024 bytes)
//! ```
//!
//! Agent → hook ([`Deliver`]):
//!
//! ```text
//! 0  4  magic "BCN1"
//! 4  4  src vIP
//! 8  2  src vport
//! 10 2  reserved = 0
//! 12 .. payload (≤ 480 bytes)
//! ```
//!
//! Reserved fields are written as 0 and ignored when parsing; `flags` is passed
//! through. The agent must compare [`HookFrame::token`] with its local token.

use core::fmt;
use core::ops::Range;
use std::net::Ipv4Addr;

/// Magic of every local frame.
pub const MAGIC: [u8; 4] = *b"BCN1";
/// Header length of hook → agent frames.
pub const HOOK_HEADER_LEN: usize = 20;
/// Header length of agent → hook `DELIVER` frames.
pub const DELIVER_HEADER_LEN: usize = 12;
/// Maximum payload of a `SEND` frame.
pub const MAX_SEND_PAYLOAD: usize = 1024;
/// Maximum payload of a `DELIVER` frame (equals the relay's maximum payload).
pub const MAX_DELIVER_PAYLOAD: usize = 480;
/// Largest hook → agent frame.
pub const MAX_HOOK_FRAME_LEN: usize = HOOK_HEADER_LEN + MAX_SEND_PAYLOAD;
/// Largest `DELIVER` frame.
pub const MAX_DELIVER_FRAME_LEN: usize = DELIVER_HEADER_LEN + MAX_DELIVER_PAYLOAD;

/// Errors of the local frame codec; nothing panics on any input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Error {
    /// The frame is shorter than its header.
    Truncated {
        /// Length of the rejected frame.
        len: usize,
    },
    /// The magic is not `BCN1`.
    BadMagic,
    /// Unknown hook frame type.
    BadType(u8),
    /// The payload exceeds the limit of its frame type.
    TooLarge {
        /// Offending payload length.
        len: usize,
    },
    /// A `REG` or `CLOSE` frame carries a payload.
    UnexpectedPayload,
    /// The output buffer is too small.
    BufferTooSmall {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        available: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { len } => write!(f, "local frame truncated ({len} bytes)"),
            Self::BadMagic => f.write_str("bad local frame magic"),
            Self::BadType(t) => write!(f, "unknown local frame type {t}"),
            Self::TooLarge { len } => write!(f, "local frame payload too large ({len} bytes)"),
            Self::UnexpectedPayload => f.write_str("REG/CLOSE frame with payload"),
            Self::BufferTooSmall { needed, available } => {
                write!(f, "output buffer too small ({available} < {needed} bytes)")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Type of a hook → agent frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    /// The game bound virtual port `src_vport` (sent after `bind`); no payload.
    Reg = 1,
    /// A game datagram from `src_vport` to `dst_vip:dst_vport`.
    Send = 2,
    /// The game closed the socket bound to `src_vport`; no payload.
    Close = 3,
}

impl FrameType {
    /// The frame type for a wire value, or `None` if unknown.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Reg),
            2 => Some(Self::Send),
            3 => Some(Self::Close),
            _ => None,
        }
    }
}

/// Header of a hook → agent frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HookFrame {
    /// Frame type.
    pub kind: FrameType,
    /// Flags (0 in this version).
    pub flags: u8,
    /// The virtual port the sending socket is bound to.
    pub src_vport: u16,
    /// Destination vIP (`SEND`; unspecified for `REG`/`CLOSE`).
    pub dst_vip: Ipv4Addr,
    /// Destination virtual port (`SEND`; 0 for `REG`/`CLOSE`).
    pub dst_vport: u16,
    /// The local token from `BEACON_LOCAL_TOKEN`.
    pub token: u32,
}

impl HookFrame {
    /// A `REG` header for `src_vport`.
    pub const fn reg(src_vport: u16, token: u32) -> Self {
        Self::new(FrameType::Reg, src_vport, Ipv4Addr::UNSPECIFIED, 0, token)
    }

    /// A `SEND` header.
    pub const fn send(src_vport: u16, dst_vip: Ipv4Addr, dst_vport: u16, token: u32) -> Self {
        Self::new(FrameType::Send, src_vport, dst_vip, dst_vport, token)
    }

    /// A `CLOSE` header for `src_vport`.
    pub const fn close(src_vport: u16, token: u32) -> Self {
        Self::new(FrameType::Close, src_vport, Ipv4Addr::UNSPECIFIED, 0, token)
    }

    const fn new(
        kind: FrameType,
        src_vport: u16,
        dst_vip: Ipv4Addr,
        dst_vport: u16,
        token: u32,
    ) -> Self {
        Self {
            kind,
            flags: 0,
            src_vport,
            dst_vip,
            dst_vport,
            token,
        }
    }

    /// The 20 header bytes.
    pub const fn encode(&self) -> [u8; HOOK_HEADER_LEN] {
        let [m0, m1, m2, m3] = MAGIC;
        let [s0, s1] = self.src_vport.to_be_bytes();
        let [v0, v1, v2, v3] = self.dst_vip.octets();
        let [d0, d1] = self.dst_vport.to_be_bytes();
        let [t0, t1, t2, t3] = self.token.to_be_bytes();
        [
            m0,
            m1,
            m2,
            m3,
            self.kind as u8,
            self.flags,
            s0,
            s1,
            v0,
            v1,
            v2,
            v3,
            d0,
            d1,
            0,
            0,
            t0,
            t1,
            t2,
            t3,
        ]
    }
}

/// Encodes a hook → agent frame into `out` and returns its length. `payload` must be
/// empty for `REG`/`CLOSE` and at most [`MAX_SEND_PAYLOAD`] bytes for `SEND`.
pub fn encode_hook_frame(header: &HookFrame, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    check_hook_payload(header.kind, payload.len())?;
    let total = HOOK_HEADER_LEN + payload.len();
    let too_small = Error::BufferTooSmall {
        needed: total,
        available: out.len(),
    };
    let (head, rest) = out
        .split_first_chunk_mut::<HOOK_HEADER_LEN>()
        .ok_or(too_small)?;
    let body = rest.get_mut(..payload.len()).ok_or(too_small)?;
    *head = header.encode();
    body.copy_from_slice(payload);
    Ok(total)
}

/// Parses a hook → agent frame; returns the header and the payload.
pub fn parse_hook_frame(frame: &[u8]) -> Result<(HookFrame, &[u8]), Error> {
    let (head, payload) = frame
        .split_first_chunk::<HOOK_HEADER_LEN>()
        .ok_or(Error::Truncated { len: frame.len() })?;
    let [m0, m1, m2, m3, kind, flags, s0, s1, v0, v1, v2, v3, d0, d1, _r0, _r1, t0, t1, t2, t3] =
        *head;
    if [m0, m1, m2, m3] != MAGIC {
        return Err(Error::BadMagic);
    }
    let kind = FrameType::from_u8(kind).ok_or(Error::BadType(kind))?;
    check_hook_payload(kind, payload.len())?;
    let header = HookFrame {
        kind,
        flags,
        src_vport: u16::from_be_bytes([s0, s1]),
        dst_vip: Ipv4Addr::new(v0, v1, v2, v3),
        dst_vport: u16::from_be_bytes([d0, d1]),
        token: u32::from_be_bytes([t0, t1, t2, t3]),
    };
    Ok((header, payload))
}

fn check_hook_payload(kind: FrameType, len: usize) -> Result<(), Error> {
    match kind {
        FrameType::Send if len > MAX_SEND_PAYLOAD => Err(Error::TooLarge { len }),
        FrameType::Reg | FrameType::Close if len != 0 => Err(Error::UnexpectedPayload),
        _ => Ok(()),
    }
}

/// Header of an agent → hook `DELIVER` frame: the true virtual source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Deliver {
    /// Source vIP.
    pub src_vip: Ipv4Addr,
    /// Source virtual port.
    pub src_vport: u16,
}

impl Deliver {
    /// The 12 header bytes.
    pub const fn encode(&self) -> [u8; DELIVER_HEADER_LEN] {
        let [m0, m1, m2, m3] = MAGIC;
        let [v0, v1, v2, v3] = self.src_vip.octets();
        let [p0, p1] = self.src_vport.to_be_bytes();
        [m0, m1, m2, m3, v0, v1, v2, v3, p0, p1, 0, 0]
    }
}

/// Encodes a `DELIVER` frame into `out` and returns its length; `payload` must not
/// exceed [`MAX_DELIVER_PAYLOAD`].
pub fn encode_deliver(header: &Deliver, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if payload.len() > MAX_DELIVER_PAYLOAD {
        return Err(Error::TooLarge { len: payload.len() });
    }
    let total = DELIVER_HEADER_LEN + payload.len();
    let too_small = Error::BufferTooSmall {
        needed: total,
        available: out.len(),
    };
    let (head, rest) = out
        .split_first_chunk_mut::<DELIVER_HEADER_LEN>()
        .ok_or(too_small)?;
    let body = rest.get_mut(..payload.len()).ok_or(too_small)?;
    *head = header.encode();
    body.copy_from_slice(payload);
    Ok(total)
}

/// Parses a `DELIVER` frame; returns the header and the byte range of the payload.
pub fn parse_deliver(frame: &[u8]) -> Result<(Deliver, Range<usize>), Error> {
    let len = frame.len();
    let head = frame
        .first_chunk::<DELIVER_HEADER_LEN>()
        .ok_or(Error::Truncated { len })?;
    let [m0, m1, m2, m3, v0, v1, v2, v3, p0, p1, _r0, _r1] = *head;
    if [m0, m1, m2, m3] != MAGIC {
        return Err(Error::BadMagic);
    }
    let payload_len = len - DELIVER_HEADER_LEN;
    if payload_len > MAX_DELIVER_PAYLOAD {
        return Err(Error::TooLarge { len: payload_len });
    }
    let header = Deliver {
        src_vip: Ipv4Addr::new(v0, v1, v2, v3),
        src_vport: u16::from_be_bytes([p0, p1]),
    };
    Ok((header, DELIVER_HEADER_LEN..len))
}

/// The hook's `recvfrom` path: validates the `DELIVER` frame in `datagram` (exactly
/// the received bytes), moves the payload to the start of the buffer and returns
/// the header and the payload length. On error the buffer is unchanged.
pub fn strip_deliver_in_place(datagram: &mut [u8]) -> Result<(Deliver, usize), Error> {
    let (header, payload) = parse_deliver(datagram)?;
    let payload_len = payload.len();
    datagram.copy_within(payload, 0);
    Ok((header, payload_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: u32 = 0xA1B2_C3D4;

    fn encode_hook(header: &HookFrame, payload: &[u8]) -> Vec<u8> {
        let mut buf = [0u8; MAX_HOOK_FRAME_LEN];
        let n = encode_hook_frame(header, payload, &mut buf).unwrap();
        buf[..n].to_vec()
    }

    #[test]
    fn constants() {
        assert_eq!(&MAGIC, b"BCN1");
        assert_eq!(MAX_HOOK_FRAME_LEN, 1044);
        assert_eq!(MAX_DELIVER_FRAME_LEN, 492);
        assert_eq!(MAX_DELIVER_PAYLOAD, crate::relay::MAX_PAYLOAD);
    }

    #[test]
    fn hook_frame_layout_golden() {
        let h = HookFrame::send(8086, Ipv4Addr::BROADCAST, 8093, TOKEN);
        let f = encode_hook(&h, b"hi");
        assert_eq!(
            f,
            [
                b'B', b'C', b'N', b'1', 2, 0, 0x1F, 0x96, 255, 255, 255, 255, 0x1F, 0x9D, 0, 0,
                0xA1, 0xB2, 0xC3, 0xD4, b'h', b'i'
            ]
        );
        assert_eq!(
            HookFrame::reg(8094, 1).encode(),
            [b'B', b'C', b'N', b'1', 1, 0, 0x1F, 0x9E, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn hook_frame_round_trips() {
        let payload: Vec<u8> = (0..MAX_SEND_PAYLOAD).map(|i| i as u8).collect();
        let cases = [
            (HookFrame::reg(8086, TOKEN), 0usize),
            (HookFrame::close(8101, TOKEN), 0),
            (HookFrame::send(8094, Ipv4Addr::new(198, 18, 0, 7), 8095, TOKEN), 0),
            (HookFrame::send(8094, Ipv4Addr::new(198, 18, 0, 7), 8095, 0), 1),
            (HookFrame::send(8086, Ipv4Addr::new(198, 18, 0, 255), 8090, u32::MAX), 476),
            (HookFrame::send(8086, Ipv4Addr::BROADCAST, 8086, TOKEN), MAX_SEND_PAYLOAD),
        ];
        for (h, len) in cases {
            let f = encode_hook(&h, &payload[..len]);
            assert_eq!(f.len(), HOOK_HEADER_LEN + len);
            let (got, p) = parse_hook_frame(&f).unwrap();
            assert_eq!(got, h);
            assert_eq!(p, &payload[..len]);
        }
    }

    #[test]
    fn hook_frame_errors() {
        let good = encode_hook(&HookFrame::send(8086, Ipv4Addr::BROADCAST, 8086, TOKEN), b"x");
        for len in 0..HOOK_HEADER_LEN {
            assert_eq!(parse_hook_frame(&good[..len]), Err(Error::Truncated { len }));
        }
        let mut f = good.clone();
        f[3] = b'2';
        assert_eq!(parse_hook_frame(&f), Err(Error::BadMagic));
        for t in [0u8, 4, 255] {
            let mut f = good.clone();
            f[4] = t;
            assert_eq!(parse_hook_frame(&f), Err(Error::BadType(t)));
        }
        // Oversize SEND, payload on REG/CLOSE.
        let mut big = good[..HOOK_HEADER_LEN].to_vec();
        big.extend(std::iter::repeat_n(0u8, MAX_SEND_PAYLOAD + 1));
        assert_eq!(
            parse_hook_frame(&big),
            Err(Error::TooLarge { len: MAX_SEND_PAYLOAD + 1 })
        );
        let mut reg = encode_hook(&HookFrame::reg(8086, TOKEN), &[]);
        reg.push(0);
        assert_eq!(parse_hook_frame(&reg), Err(Error::UnexpectedPayload));
        let mut buf = [0u8; MAX_HOOK_FRAME_LEN + 10];
        assert_eq!(
            encode_hook_frame(&HookFrame::close(1, 2), b"x", &mut buf),
            Err(Error::UnexpectedPayload)
        );
        assert_eq!(
            encode_hook_frame(
                &HookFrame::send(1, Ipv4Addr::BROADCAST, 2, 3),
                &[0; MAX_SEND_PAYLOAD + 1],
                &mut buf
            ),
            Err(Error::TooLarge { len: MAX_SEND_PAYLOAD + 1 })
        );
        for avail in [0usize, 19, 20, 22] {
            let mut small = vec![0u8; avail];
            assert_eq!(
                encode_hook_frame(&HookFrame::send(1, Ipv4Addr::BROADCAST, 2, 3), b"abc", &mut small),
                Err(Error::BufferTooSmall {
                    needed: 23,
                    available: avail
                })
            );
        }
        // Reserved bytes are ignored, flags are passed through.
        let mut f = good;
        f[5] = 0x80;
        f[14] = 0xFF;
        f[15] = 0xFF;
        let (h, _) = parse_hook_frame(&f).unwrap();
        assert_eq!(h.flags, 0x80);
    }

    #[test]
    fn deliver_round_trip_and_layout() {
        let d = Deliver {
            src_vip: Ipv4Addr::new(198, 18, 0, 3),
            src_vport: 8086,
        };
        let mut buf = [0u8; MAX_DELIVER_FRAME_LEN];
        let n = encode_deliver(&d, b"payload", &mut buf).unwrap();
        assert_eq!(
            &buf[..n],
            b"BCN1\xC6\x12\x00\x03\x1F\x96\x00\x00payload".as_slice()
        );
        let (got, r) = parse_deliver(&buf[..n]).unwrap();
        assert_eq!(got, d);
        assert_eq!(&buf[r], b"payload");

        for len in [0usize, 1, 476, MAX_DELIVER_PAYLOAD] {
            let payload = vec![0x5A; len];
            let n = encode_deliver(&d, &payload, &mut buf).unwrap();
            let (got, r) = parse_deliver(&buf[..n]).unwrap();
            assert_eq!(got, d);
            assert_eq!(&buf[r], payload.as_slice());
        }
    }

    #[test]
    fn deliver_errors() {
        let d = Deliver {
            src_vip: Ipv4Addr::new(198, 18, 0, 3),
            src_vport: 8086,
        };
        let mut buf = [0u8; 2 * MAX_DELIVER_FRAME_LEN];
        assert_eq!(
            encode_deliver(&d, &[0; MAX_DELIVER_PAYLOAD + 1], &mut buf),
            Err(Error::TooLarge { len: MAX_DELIVER_PAYLOAD + 1 })
        );
        assert_eq!(
            encode_deliver(&d, b"abc", &mut [0u8; 14]),
            Err(Error::BufferTooSmall {
                needed: 15,
                available: 14
            })
        );
        let n = encode_deliver(&d, b"abc", &mut buf).unwrap();
        for len in 0..DELIVER_HEADER_LEN {
            assert_eq!(parse_deliver(&buf[..len]), Err(Error::Truncated { len }));
        }
        let mut bad = buf[..n].to_vec();
        bad[0] = b'X';
        assert_eq!(parse_deliver(&bad), Err(Error::BadMagic));
        let oversize = DELIVER_HEADER_LEN + MAX_DELIVER_PAYLOAD + 1;
        let mut big = buf[..oversize].to_vec();
        big[..DELIVER_HEADER_LEN].copy_from_slice(&d.encode());
        assert_eq!(
            parse_deliver(&big),
            Err(Error::TooLarge { len: MAX_DELIVER_PAYLOAD + 1 })
        );
    }

    #[test]
    fn strip_in_place() {
        let d = Deliver {
            src_vip: Ipv4Addr::new(198, 18, 0, 9),
            src_vport: 8094,
        };
        let mut game_buf = [0u8; 1038];
        let n = encode_deliver(&d, b"game datagram", &mut game_buf).unwrap();
        let (got, len) = strip_deliver_in_place(&mut game_buf[..n]).unwrap();
        assert_eq!(got, d);
        assert_eq!(&game_buf[..len], b"game datagram");

        let mut junk = *b"BCN0\x00\x00\x00\x00\x00\x00\x00\x00data";
        let before = junk;
        assert_eq!(strip_deliver_in_place(&mut junk), Err(Error::BadMagic));
        assert_eq!(junk, before);
        let mut empty = *b"BCN1\xC6\x12\x00\x03\x1F\x96\x00\x00";
        assert_eq!(strip_deliver_in_place(&mut empty).map(|(_, l)| l), Ok(0));
    }

    #[test]
    fn garbage_never_panics() {
        let mut x: u64 = 0x1234_5678_9ABC_DEF0;
        let mut buf = [0u8; 1200];
        for i in 0..20_000usize {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = (x % 1200) as usize;
            for (j, b) in buf[..len].iter_mut().enumerate() {
                *b = (x >> (j % 57)) as u8 ^ j as u8;
            }
            if i % 2 == 0 && len >= 5 {
                buf[..4].copy_from_slice(&MAGIC);
                buf[4] = (i % 5) as u8;
            }
            let _ = parse_hook_frame(&buf[..len]);
            let _ = parse_deliver(&buf[..len]);
            let _ = strip_deliver_in_place(&mut buf[..len]);
        }
    }

    #[test]
    fn error_display() {
        for e in [
            Error::Truncated { len: 1 },
            Error::BadMagic,
            Error::BadType(9),
            Error::TooLarge { len: 2000 },
            Error::UnexpectedPayload,
            Error::BufferTooSmall {
                needed: 2,
                available: 1,
            },
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}
