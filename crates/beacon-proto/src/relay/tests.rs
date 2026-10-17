use super::*;
use crate::net::SERVER_VIP;

const W: u64 = ReplayWindow::SIZE;

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn test_key() -> RelayKey {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    RelayKey::from_bytes(k)
}

fn data_header() -> Header {
    Header::client(
        PacketType::Data,
        0x1234_5678,
        0x0102_0304_0506_0708,
        Ipv4Addr::new(198, 18, 0, 5),
        0x1234,
        0xABCD,
    )
}

fn sealed(key: &RelayKey, dir: Direction, header: &Header, payload: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; MAX_PACKET_LEN];
    let n = seal(key, dir, header, payload, &mut buf).unwrap();
    buf[..n].to_vec()
}

#[test]
fn constants_match_architecture() {
    assert_eq!(MAGIC, [0xBE, 0xAC]);
    assert_eq!(VERSION, 1);
    assert_eq!(HEADER_LEN, 24);
    assert_eq!(TAG_LEN, 16);
    assert_eq!(MAX_PAYLOAD, 480);
    assert_eq!(MIN_PACKET_LEN, 40);
    assert_eq!(MAX_PACKET_LEN, 520);
    assert_eq!(W, 256);
    let wire: Vec<u8> = PacketType::ALL.iter().map(|t| t.as_u8()).collect();
    assert_eq!(wire, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(Direction::ClientToServer as u8, 1);
    assert_eq!(Direction::ServerToClient as u8, 2);
    assert_eq!(Direction::ClientToServer.reverse(), Direction::ServerToClient);
    assert_eq!(PING_INTERVAL, Duration::from_secs(1));
}

#[test]
fn redundancy_defaults() {
    for p in 8086..=8093 {
        assert_eq!(default_redundancy(p), 3, "lobby port {p}");
    }
    for p in 8094..=8101 {
        assert_eq!(default_redundancy(p), 2, "game port {p}");
    }
    for p in [0, 1, 8085, 8102, 6500, u16::MAX] {
        assert_eq!(default_redundancy(p), 1, "port {p}");
    }
    assert_eq!(MAX_REDUNDANCY, 3);
    assert_eq!(
        REDUNDANCY_DELAYS,
        [Duration::from_millis(3), Duration::from_millis(10)]
    );
}

#[test]
fn redundant_copies_are_delivered_once() {
    let key = test_key();
    let mut window = ReplayWindow::new();
    let mut delivered = 0;
    for counter in 0..50u64 {
        let h = Header::client(PacketType::Data, 1, counter, SERVER_VIP, 8086, 8086);
        let packet = sealed(&key, Direction::ClientToServer, &h, b"lobby msg");
        for _copy in 0..default_redundancy(8086) {
            let mut p = packet.clone();
            match open_with_window(&key, Direction::ClientToServer, &mut p, &mut window) {
                Ok(_) => delivered += 1,
                Err(e) => assert_eq!(e, Error::Replayed { counter }),
            }
        }
    }
    assert_eq!(delivered, 50);
}

#[test]
fn header_layout_golden() {
    let h = data_header();
    let bytes = h.encode();
    assert_eq!(
        bytes.to_vec(),
        hex("beac0102785634120807060504030201c61200051234abcd")
    );
    assert_eq!(Header::decode(&bytes), Ok(h));

    let s = Header::server(PacketType::Pong, 42, SERVER_VIP, 0, 8086);
    assert_eq!(s.session, 0);
    assert_eq!(
        s.encode().to_vec(),
        hex("beac0104000000002a00000000000000c612000100001f96")
    );
}

#[test]
fn packet_type_conversions() {
    for t in PacketType::ALL {
        assert_eq!(PacketType::from_u8(t.as_u8()), Some(t));
        assert_eq!(PacketType::try_from(t.as_u8()), Ok(t));
    }
    for v in [0u8, 9, 10, 0x7f, 0xff] {
        assert_eq!(PacketType::from_u8(v), None);
        assert_eq!(PacketType::try_from(v), Err(Error::BadType(v)));
    }
}

#[test]
fn nonce_layout() {
    assert_eq!(
        nonce(Direction::ClientToServer, 0x0102_0304_0506_0708),
        [1, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1]
    );
    assert_eq!(
        nonce(Direction::ServerToClient, u64::MAX),
        [2, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
}

/// Vectors produced by an independent pure-Python RFC 8439 implementation
/// (validated against the RFC 8439 §2.8.2 test vector).
#[test]
fn known_answer_vectors() {
    let key = test_key();
    let check = |dir: Direction, header: Header, payload: &[u8], expected: &str| {
        let expected = hex(expected);
        assert_eq!(sealed(&key, dir, &header, payload), expected);
        let mut p = expected;
        let (h, r) = open(&key, dir, &mut p).unwrap();
        assert_eq!(h, header);
        assert_eq!(&p[r], payload);
    };
    check(
        Direction::ClientToServer,
        data_header(),
        b"BFME Beacon relay KAT",
        "beac0102785634120807060504030201c61200051234abcd394040dc314968bcd16080366d22\
         92aaee43def9eedb7409ab6f4f67588d02e2b7051302ae",
    );
    check(
        Direction::ServerToClient,
        Header::server(PacketType::Pong, 42, SERVER_VIP, 0, 8086),
        &encode_timestamp(1_700_000_000_123),
        "beac0104000000002a00000000000000c612000100001f96dd0971077357dbb2024c39bf99b8\
         2c895cca45c15d77aaec",
    );
    check(
        Direction::ClientToServer,
        Header::client(PacketType::Reg, 0xDEAD_BEEF, 0, SERVER_VIP, 8086, 0),
        &[],
        "beac0101efbeadde0000000000000000c61200011f960000decbdd0c9e05b8241e008882d52cf92e",
    );
    check(
        Direction::ClientToServer,
        Header::client(PacketType::Unreg, 7, 1, SERVER_VIP, 8094, 0),
        &[],
        "beac0108070000000100000000000000c61200011f9e0000904511b48bcf6b4bc614485b2f4f411b",
    );
}

#[test]
fn round_trip_all_types_and_sizes() {
    let key = RelayKey::from_bytes([0x5a; 32]);
    let payload: Vec<u8> = (0..MAX_PAYLOAD).map(|i| (i * 7 + 3) as u8).collect();
    for (i, kind) in PacketType::ALL.into_iter().enumerate() {
        for &len in &[0usize, 1, 8, 15, 16, 17, 63, 64, 65, 476, 479, 480] {
            for dir in [Direction::ClientToServer, Direction::ServerToClient] {
                let header = Header {
                    kind,
                    session: if dir == Direction::ClientToServer { 77 } else { 0 },
                    counter: (i * 1000 + len) as u64,
                    vip: Ipv4Addr::new(198, 18, 0, (len % 250) as u8 + 2),
                    src_vport: 8086,
                    dst_vport: 8094,
                };
                let mut buf = [0u8; MAX_PACKET_LEN];
                let n = seal(&key, dir, &header, &payload[..len], &mut buf).unwrap();
                assert_eq!(n, HEADER_LEN + len + TAG_LEN);
                if len > 0 {
                    assert_ne!(&buf[HEADER_LEN..HEADER_LEN + len], &payload[..len]);
                }
                assert_eq!(peek_header(&buf[..n]), Ok(header));
                let (h, r) = open(&key, dir, &mut buf[..n]).unwrap();
                assert_eq!(h, header);
                assert_eq!(r, HEADER_LEN..HEADER_LEN + len);
                assert_eq!(&buf[r], &payload[..len]);
            }
        }
    }
}

#[test]
fn seal_into_exact_and_larger_buffers() {
    let key = test_key();
    let h = data_header();
    let mut exact = [0u8; MIN_PACKET_LEN + 5];
    assert_eq!(seal(&key, Direction::ClientToServer, &h, b"12345", &mut exact), Ok(45));
    let mut larger = [0xEEu8; 100];
    assert_eq!(seal(&key, Direction::ClientToServer, &h, b"12345", &mut larger), Ok(45));
    assert_eq!(&larger[..45], &exact[..]);
    assert!(larger[45..].iter().all(|&b| b == 0xEE), "bytes beyond the packet untouched");
}

#[test]
fn seal_errors() {
    let key = test_key();
    let h = data_header();
    let big = [0u8; MAX_PAYLOAD + 1];
    let mut buf = [0u8; MAX_PACKET_LEN + 100];
    assert_eq!(
        seal(&key, Direction::ClientToServer, &h, &big, &mut buf),
        Err(Error::TooLarge { len: MAX_PAYLOAD + 1 })
    );
    for avail in [0usize, 1, 23, 24, 39, 44] {
        let mut small = vec![0u8; avail];
        assert_eq!(
            seal(&key, Direction::ClientToServer, &h, b"12345", &mut small),
            Err(Error::BufferTooSmall {
                needed: 45,
                available: avail
            })
        );
    }
}

#[test]
fn every_single_byte_modification_is_detected() {
    let key = test_key();
    let original = sealed(&key, Direction::ClientToServer, &data_header(), b"tamper me please");
    for i in 0..original.len() {
        for mask in [0x01u8, 0x02, 0x10, 0x80, 0xff] {
            let mut p = original.clone();
            p[i] ^= mask;
            let res = open(&key, Direction::ClientToServer, &mut p);
            assert!(res.is_err(), "byte {i} mask {mask:#x} accepted");
            match i {
                0 | 1 => assert_eq!(res, Err(Error::BadMagic)),
                2 => assert_eq!(res, Err(Error::BadVersion(original[2] ^ mask))),
                // A modified type byte either becomes unknown or fails authentication.
                3 => assert!(matches!(res, Err(Error::BadType(_) | Error::AuthFailed))),
                _ => assert_eq!(res, Err(Error::AuthFailed), "byte {i}"),
            }
        }
    }
}

#[test]
fn failed_open_leaves_ciphertext_untouched() {
    let key = test_key();
    let original = sealed(&key, Direction::ClientToServer, &data_header(), b"payload");
    let mut p = original.clone();
    let last = p.len() - 1;
    p[last] ^= 1;
    let tampered = p.clone();
    assert_eq!(open(&key, Direction::ClientToServer, &mut p), Err(Error::AuthFailed));
    assert_eq!(p, tampered);
}

#[test]
fn wrong_key_or_direction_fails() {
    let key = test_key();
    let original = sealed(&key, Direction::ClientToServer, &data_header(), b"secret");

    let mut wrong = *key.as_bytes();
    wrong[31] ^= 1;
    let mut p = original.clone();
    assert_eq!(
        open(&RelayKey::from_bytes(wrong), Direction::ClientToServer, &mut p),
        Err(Error::AuthFailed)
    );
    let mut p = original.clone();
    assert_eq!(open(&key, Direction::ServerToClient, &mut p), Err(Error::AuthFailed));
    let mut p = original;
    assert!(open(&key, Direction::ClientToServer, &mut p).is_ok());
}

#[test]
fn truncated_and_extended_packets_fail() {
    let key = test_key();
    let original = sealed(&key, Direction::ClientToServer, &data_header(), b"0123456789");
    for len in 0..original.len() {
        let mut p = original[..len].to_vec();
        let res = open(&key, Direction::ClientToServer, &mut p);
        if len < MIN_PACKET_LEN {
            assert_eq!(res, Err(Error::Truncated { len }));
        } else {
            assert_eq!(res, Err(Error::AuthFailed), "len {len}");
        }
    }
    let mut p = original.clone();
    p.push(0);
    assert_eq!(open(&key, Direction::ClientToServer, &mut p), Err(Error::AuthFailed));
}

#[test]
fn peek_header_framing_errors() {
    let key = test_key();
    let good = sealed(&key, Direction::ClientToServer, &data_header(), b"x");
    assert_eq!(peek_header(&good), Ok(data_header()));
    assert_eq!(peek_header(&[]), Err(Error::Truncated { len: 0 }));
    assert_eq!(peek_header(&good[..39]), Err(Error::Truncated { len: 39 }));

    let big = vec![0u8; MAX_PACKET_LEN + 1];
    assert_eq!(peek_header(&big), Err(Error::TooLarge { len: MAX_PACKET_LEN + 1 }));
    let mut max = vec![0u8; MAX_PACKET_LEN];
    max[..HEADER_LEN].copy_from_slice(&data_header().encode());
    assert_eq!(peek_header(&max), Ok(data_header()));

    let mut p = good.clone();
    p[0] = 0xBF;
    assert_eq!(peek_header(&p), Err(Error::BadMagic));
    let mut p = good.clone();
    p[2] = 2;
    assert_eq!(peek_header(&p), Err(Error::BadVersion(2)));
    let mut p = good.clone();
    p[3] = 0;
    assert_eq!(peek_header(&p), Err(Error::BadType(0)));
    let mut p = good;
    p[3] = 9;
    assert_eq!(peek_header(&p), Err(Error::BadType(9)));
}

#[test]
fn every_packet_type_is_authenticated() {
    let key = test_key();
    for kind in PacketType::ALL {
        let h = Header::server(kind, 9, SERVER_VIP, 0, 8086);
        let p = sealed(&key, Direction::ServerToClient, &h, &[]);
        assert_eq!(p.len(), MIN_PACKET_LEN);
        // Forge a different type without the key: must fail.
        for other in PacketType::ALL {
            if other == kind {
                continue;
            }
            let mut forged = p.clone();
            forged[3] = other.as_u8();
            assert_eq!(
                open(&key, Direction::ServerToClient, &mut forged),
                Err(Error::AuthFailed)
            );
        }
    }
}

#[test]
fn open_with_window_rejects_replays_but_not_forgeries_moving_the_window() {
    let key = test_key();
    let mut window = ReplayWindow::new();
    let mk = |counter: u64| {
        let h = Header::client(PacketType::Data, 1, counter, SERVER_VIP, 1, 2);
        sealed(&key, Direction::ClientToServer, &h, b"data")
    };

    let mut p = mk(10);
    assert!(open_with_window(&key, Direction::ClientToServer, &mut p, &mut window).is_ok());
    let mut p = mk(10);
    assert_eq!(
        open_with_window(&key, Direction::ClientToServer, &mut p, &mut window),
        Err(Error::Replayed { counter: 10 })
    );

    // A forged packet with a huge counter fails authentication and does not move the window.
    let mut forged = mk(11);
    forged[8..16].copy_from_slice(&1_000_000u64.to_le_bytes());
    assert_eq!(
        open_with_window(&key, Direction::ClientToServer, &mut forged, &mut window),
        Err(Error::AuthFailed)
    );
    assert_eq!(window.highest(), Some(10));
    let mut p = mk(11);
    assert!(open_with_window(&key, Direction::ClientToServer, &mut p, &mut window).is_ok());
    assert_eq!(window.highest(), Some(11));
}

#[test]
fn replay_window_in_order() {
    let mut w = ReplayWindow::new();
    assert_eq!(w.highest(), None);
    for c in 0..2000u64 {
        assert_eq!(w.check(c), Ok(()));
        assert_eq!(w.accept(c), Ok(()));
        assert_eq!(w.highest(), Some(c));
    }
    let top = 1999;
    assert_eq!(w.accept(top), Err(Error::Replayed { counter: top }));
    assert_eq!(w.accept(top - (W - 1)), Err(Error::Replayed { counter: top - (W - 1) }));
    assert_eq!(w.accept(top - W), Err(Error::TooOld { counter: top - W }));
    assert_eq!(w.accept(0), Err(Error::TooOld { counter: 0 }));
}

#[test]
fn replay_window_out_of_order_within_window() {
    let mut w = ReplayWindow::new();
    let top = 1000u64;
    assert_eq!(w.accept(top), Ok(()));
    // Everything in top-255..top is still inside the window, once.
    for c in (top - (W - 1)..top).rev() {
        assert_eq!(w.accept(c), Ok(()), "{c}");
        assert_eq!(w.accept(c), Err(Error::Replayed { counter: c }));
    }
    assert_eq!(w.accept(top - W), Err(Error::TooOld { counter: top - W }));
    assert_eq!(w.accept(top), Err(Error::Replayed { counter: top }));
    // Newer is always fine; small gaps stay fillable.
    assert_eq!(w.accept(top + 5), Ok(()));
    assert_eq!(w.accept(top + 3), Ok(()));
    assert_eq!(w.accept(top + 4), Ok(()));
    assert_eq!(w.accept(top + 1), Ok(()));
    assert_eq!(w.accept(top + 2), Ok(()));
    for c in top + 1..=top + 5 {
        assert_eq!(w.accept(c), Err(Error::Replayed { counter: c }));
    }
    // The window is now top+5-255 ..= top+5.
    let oldest = top + 5 - (W - 1);
    assert_eq!(w.accept(oldest - 1), Err(Error::TooOld { counter: oldest - 1 }));
    assert_eq!(w.accept(oldest), Err(Error::Replayed { counter: oldest }));
}

#[test]
fn replay_window_slots_are_recycled_correctly() {
    // A counter whose ring slot was used by an older counter must be accepted, and
    // the older counter must not be mistaken for the new one.
    let mut w = ReplayWindow::new();
    assert_eq!(w.accept(5), Ok(()));
    assert_eq!(w.accept(5 + W - 1), Ok(()));
    assert_eq!(w.accept(5), Err(Error::Replayed { counter: 5 }));
    // Advancing by one pushes 5 out; 5 + W reuses its slot.
    assert_eq!(w.accept(5 + W), Ok(()));
    assert_eq!(w.accept(5), Err(Error::TooOld { counter: 5 }));
    assert_eq!(w.accept(5 + W), Err(Error::Replayed { counter: 5 + W }));
    // Slots between the old and the new top are cleared on a jump.
    let mut w = ReplayWindow::new();
    for c in 0..W {
        assert_eq!(w.accept(c), Ok(()));
    }
    assert_eq!(w.accept(W + 100), Ok(()));
    for c in W..W + 100 {
        assert_eq!(w.accept(c), Ok(()), "{c} must be fresh");
    }
    for c in 101..W {
        assert_eq!(w.accept(c), Err(Error::Replayed { counter: c }));
    }
    assert_eq!(w.accept(100), Err(Error::TooOld { counter: 100 }));
}

#[test]
fn replay_window_edges() {
    let mut w = ReplayWindow::new();
    assert_eq!(w.accept(5000), Ok(()));
    assert_eq!(w.check(5000 - (W - 1)), Ok(()));
    assert_eq!(w.check(5000 - W), Err(Error::TooOld { counter: 5000 - W }));
    // A jump of exactly W clears the whole window except the new top.
    assert_eq!(w.accept(5000 + W), Ok(()));
    assert_eq!(w.accept(5001), Ok(()));
    assert_eq!(w.accept(5000), Err(Error::TooOld { counter: 5000 }));
    // A jump of W - 1 keeps the old top as the oldest entry.
    let mut w = ReplayWindow::new();
    assert_eq!(w.accept(10), Ok(()));
    assert_eq!(w.accept(10 + W - 1), Ok(()));
    assert_eq!(w.accept(10), Err(Error::Replayed { counter: 10 }));
    assert_eq!(w.accept(11), Ok(()));
    // Huge jumps and extreme values.
    let mut w = ReplayWindow::new();
    assert_eq!(w.accept(0), Ok(()));
    assert_eq!(w.accept(u64::MAX), Ok(()));
    assert_eq!(w.accept(u64::MAX), Err(Error::Replayed { counter: u64::MAX }));
    assert_eq!(w.accept(u64::MAX - (W - 1)), Ok(()));
    assert_eq!(
        w.accept(u64::MAX - W),
        Err(Error::TooOld {
            counter: u64::MAX - W
        })
    );
    assert_eq!(w.accept(0), Err(Error::TooOld { counter: 0 }));
    // check() never records.
    let mut w = ReplayWindow::new();
    assert_eq!(w.check(5), Ok(()));
    assert_eq!(w.check(5), Ok(()));
    assert_eq!(w.highest(), None);
    assert_eq!(w.accept(5), Ok(()));
    w.reset();
    assert_eq!(w, ReplayWindow::default());
    assert_eq!(w.accept(5), Ok(()));
}

#[test]
fn send_counter() {
    let c = SendCounter::new();
    assert_eq!(c.peek(), 0);
    assert_eq!(c.next(), Some(0));
    assert_eq!(c.next(), Some(1));
    assert_eq!(c.peek(), 2);

    let c = SendCounter::starting_at(u64::MAX - 2);
    assert_eq!(c.next(), Some(u64::MAX - 2));
    assert_eq!(c.next(), Some(u64::MAX - 1));
    assert_eq!(c.next(), None);
    assert_eq!(c.next(), None);
}

#[test]
fn send_counter_is_shared_across_threads() {
    let c = std::sync::Arc::new(SendCounter::new());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let c = c.clone();
            std::thread::spawn(move || (0..1000).map(|_| c.next().unwrap()).collect::<Vec<_>>())
        })
        .collect();
    let mut all: Vec<u64> = handles.into_iter().flat_map(|h| h.join().unwrap()).collect();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), 4000);
    assert_eq!(c.peek(), 4000);
}

#[test]
fn payload_helpers() {
    assert_eq!(decode_timestamp(&encode_timestamp(123_456_789)), Ok(123_456_789));
    assert_eq!(decode_timestamp(&[0; 7]), Err(Error::BadPayload));
    assert_eq!(decode_timestamp(&[0; 9]), Err(Error::BadPayload));
    assert_eq!(decode_timestamp(&[]), Err(Error::BadPayload));
    assert_eq!(encode_error(error_code::RATE_LIMITED), [2, 0]);
    assert_eq!(decode_error(&encode_error(0xBEEF)), Ok(0xBEEF));
    assert_eq!(decode_error(&[1, 0, 9, 9]), Ok(error_code::NOT_REGISTERED));
    assert_eq!(decode_error(&[1]), Err(Error::BadPayload));
}

#[test]
fn relay_key_hex() {
    let key = test_key();
    let h = key.to_hex();
    assert_eq!(h, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    assert_eq!(RelayKey::from_hex(&h), Some(key.clone()));
    assert_eq!(RelayKey::from_hex(&h.to_uppercase()), Some(key.clone()));
    assert_eq!(RelayKey::from_hex(&format!(" {h}\n")), Some(key.clone()));
    assert_eq!(RelayKey::from_hex(&h[..62]), None);
    assert_eq!(RelayKey::from_hex(&format!("{h}00")), None);
    assert_eq!(RelayKey::from_hex(&h.replace('a', "g")), None);
    assert_eq!(RelayKey::from_hex(""), None);
    // Multi-byte UTF-8 of the right byte length must not be accepted or panic.
    assert_eq!(RelayKey::from_hex(&"é".repeat(32)), None);
    assert_eq!(format!("{key:?}"), "RelayKey(<redacted>)");
    assert_eq!(RelayKey::from([1u8; 32]).as_bytes(), &[1u8; 32]);
}

#[test]
fn error_display() {
    let all = [
        Error::Truncated { len: 3 },
        Error::TooLarge { len: 5000 },
        Error::BufferTooSmall {
            needed: 45,
            available: 10,
        },
        Error::BadMagic,
        Error::BadVersion(9),
        Error::BadType(99),
        Error::AuthFailed,
        Error::Replayed { counter: 1 },
        Error::TooOld { counter: 2 },
        Error::BadPayload,
    ];
    for e in all {
        assert!(!e.to_string().is_empty());
        let _: &dyn std::error::Error = &e;
    }
}
