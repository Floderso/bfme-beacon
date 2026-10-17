//! Deterministic pseudo-random robustness tests: every parser must return an error
//! (never panic) for garbage, truncated, oversized and mutated inputs.

use beacon_proto::relay::{
    decode_error, decode_timestamp, open, open_with_window, peek_header, seal, Direction, Error,
    Header, PacketType, RelayKey, ReplayWindow, MAX_PACKET_LEN, MAX_PAYLOAD,
};

/// SplitMix64: tiny, deterministic, good enough to generate test inputs.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }
}

fn random_header(rng: &mut Rng) -> Header {
    Header {
        kind: PacketType::ALL[rng.below(PacketType::ALL.len())],
        session: rng.next_u64() as u32,
        counter: rng.next_u64(),
        vip: std::net::Ipv4Addr::from(rng.next_u64() as u32),
        src_vport: rng.next_u64() as u16,
        dst_vport: rng.next_u64() as u16,
    }
}

#[test]
fn relay_garbage_never_panics() {
    let mut rng = Rng(1);
    let key = RelayKey::from_bytes([0x42; 32]);
    let mut window = ReplayWindow::new();
    for i in 0..60_000 {
        let len = rng.below(MAX_PACKET_LEN + 200);
        let mut buf = rng.bytes(len);
        // Make half of the inputs pass the cheap framing checks to reach the AEAD.
        if i % 2 == 0 && len >= 4 {
            buf[..4].copy_from_slice(&[0xBE, 0xAC, 1, 1 + rng.below(8) as u8]);
        }
        let peeked = peek_header(&buf);
        let dir = if i % 3 == 0 {
            Direction::ServerToClient
        } else {
            Direction::ClientToServer
        };
        let opened = open(&key, dir, &mut buf.clone());
        assert!(opened.is_err(), "random bytes authenticated (iteration {i})");
        if peeked.is_ok() {
            assert_eq!(opened, Err(Error::AuthFailed));
        }
        let _ = open_with_window(&key, dir, &mut buf, &mut window);
        let _ = decode_timestamp(&buf[..len.min(10)]);
        let _ = decode_error(&buf[..len.min(3)]);
    }
    assert_eq!(window.highest(), None, "nothing forged reached the window");
}

#[test]
fn relay_mutations_of_valid_packets_are_rejected() {
    let mut rng = Rng(2);
    let key = RelayKey::from_bytes([0x17; 32]);
    let mut buf = [0u8; MAX_PACKET_LEN];
    for i in 0..4_000 {
        let header = random_header(&mut rng);
        let len = rng.below(MAX_PAYLOAD + 1);
        let payload = rng.bytes(len);
        let dir = if i % 2 == 0 {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };
        let n = seal(&key, dir, &header, &payload, &mut buf).unwrap();
        let packet = buf[..n].to_vec();

        // Unmodified: opens.
        let mut p = packet.clone();
        let (h, r) = open(&key, dir, &mut p).unwrap();
        assert_eq!(h, header);
        assert_eq!(&p[r], &payload[..]);

        // 1–3 random byte modifications: always rejected.
        let mut p = packet.clone();
        for _ in 0..1 + rng.below(3) {
            let at = rng.below(p.len());
            p[at] ^= 1 + rng.below(255) as u8;
        }
        if p != packet {
            assert!(open(&key, dir, &mut p).is_err(), "iteration {i}");
        }

        // Truncation and extension: always rejected.
        let cut = rng.below(packet.len());
        assert!(open(&key, dir, &mut packet[..cut].to_vec()).is_err());
        let mut longer = packet.clone();
        let extra = 1 + rng.below(32);
        longer.extend(rng.bytes(extra));
        assert!(open(&key, dir, &mut longer).is_err());

        // Wrong direction: rejected.
        let mut p = packet.clone();
        assert_eq!(open(&key, dir.reverse(), &mut p), Err(Error::AuthFailed));
    }
}

/// Compares the replay window with a straightforward reference model.
#[test]
fn replay_window_matches_reference_model() {
    let mut rng = Rng(3);
    for round in 0..200 {
        let mut window = ReplayWindow::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut top: Option<u64> = None;
        let mut next = rng.next_u64() % 1000;
        for _ in 0..2_000 {
            // Mostly increasing with jitter, some duplicates, some old ones, some jumps.
            let counter = match rng.below(10) {
                0 => next.saturating_sub(rng.below(300) as u64),
                1 if !seen.is_empty() => *seen.iter().nth(rng.below(seen.len())).unwrap(),
                2 => {
                    next += rng.below(600) as u64;
                    next
                }
                _ => {
                    next += 1 + rng.below(3) as u64;
                    next.saturating_sub(rng.below(4) as u64)
                }
            };
            let expected = match top {
                None => true,
                Some(t) if counter > t => true,
                Some(t) => t - counter < ReplayWindow::SIZE && !seen.contains(&counter),
            };
            let got = window.accept(counter);
            assert_eq!(got.is_ok(), expected, "round {round}, counter {counter}, top {top:?}");
            if expected {
                seen.insert(counter);
                top = Some(top.map_or(counter, |t| t.max(counter)));
            }
            assert_eq!(window.highest(), top);
        }
    }
}

#[cfg(feature = "control")]
mod control {
    use super::Rng;
    use beacon_proto::control::{
        base64_decode, decode_msg, encode_frame, hello_line_len, is_safe_file_name,
        is_safe_rel_path, Chunk, ClientMsg, FrameDecoder, ServerHello, ServerMsg,
    };
    use beacon_proto::fingerprint::{combine, normalize_path, FileEntry};

    const SAMPLES: &[&str] = &[
        r#"{"t":"hello","name":"Frodo","version":"0.1.0","fingerprint":"ab12"}"#,
        r#"{"t":"map_get","map":"Helms Deep","file":"map.map","offset":65536}"#,
        r#"{"t":"status","in_game":false,"rtt_ms":42}"#,
        r#"{"t":"welcome","session":305419896,"key":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","vip":"198.18.0.2","relay_port":24800,"motd":"Hi","you_are_host":true}"#,
        r#"{"t":"lobby","players":[{"name":"Frodo","vip":"198.18.0.2","rtt_ms":12,"fingerprint":"ab","ready":true,"in_game":false,"is_host":true}]}"#,
        r#"{"t":"chunk","map":"m","file":"f","offset":0,"data":"aGVsbG8=","eof":true}"#,
        r#"{"beacon":1,"name":"Home","salt":"AAECAwQFBgcICQoLDA0ODw==","kdf":{"m":19456,"t":2,"p":1}}"#,
    ];

    #[test]
    fn json_and_hello_garbage_never_panics() {
        let mut rng = Rng(4);
        for i in 0..30_000 {
            let input = if i % 2 == 0 {
                // Mutated valid sample.
                let mut s = SAMPLES[rng.below(SAMPLES.len())].as_bytes().to_vec();
                for _ in 0..1 + rng.below(4) {
                    match rng.below(3) {
                        0 if !s.is_empty() => {
                            let at = rng.below(s.len());
                            s[at] = rng.next_u64() as u8;
                        }
                        1 if !s.is_empty() => {
                            let at = rng.below(s.len());
                            s.truncate(at);
                        }
                        _ => {
                            let at = rng.below(s.len() + 1);
                            s.insert(at, b"{}[]\":,0x\\"[rng.below(10)]);
                        }
                    }
                }
                s
            } else {
                {
                    let len = rng.below(300);
                    rng.bytes(len)
                }
            };
            let _ = ClientMsg::from_json(&input);
            if let Ok(ServerMsg::Chunk(c)) = ServerMsg::from_json(&input) {
                let _ = c.data();
            }
            let _ = decode_msg::<serde_json::Value>(&input);
            let _ = ServerHello::from_line(&input);
            let _ = hello_line_len(&input);
            if let Ok(text) = std::str::from_utf8(&input) {
                let _ = base64_decode(text);
                let _ = is_safe_rel_path(text);
                let _ = is_safe_file_name(text);
                let _ = normalize_path(text);
                let _ = combine(&[FileEntry::new(text, input.len() as u64, text)]);
            }
        }
    }

    #[test]
    fn chunk_garbage_never_panics() {
        let mut rng = Rng(5);
        for _ in 0..5_000 {
            let len = rng.below(200);
            let text: String = (0..len)
                .map(|_| b"ABCabc019+/=-_ \n\xc3"[rng.below(16)] as char)
                .collect();
            let c = Chunk {
                map: "m".into(),
                file: "f".into(),
                offset: rng.next_u64(),
                data_b64: text,
                eof: rng.below(2) == 0,
            };
            let _ = c.data();
        }
    }

    #[test]
    fn frame_decoder_random_split_and_garbage() {
        let mut rng = Rng(6);
        for round in 0..300 {
            // A random stream of frames, fed in random pieces.
            let frames: Vec<Vec<u8>> = (0..1 + rng.below(20))
                .map(|_| {
                    let len = if rng.below(10) == 0 { rng.below(65_536) } else { rng.below(300) };
                    rng.bytes(len)
                })
                .collect();
            let mut stream = Vec::new();
            for f in &frames {
                encode_frame(f, &mut stream).unwrap();
            }
            let mut dec = FrameDecoder::new();
            let mut got = Vec::new();
            let mut pos = 0;
            while pos < stream.len() {
                let max_piece = if rng.below(2) == 0 { 16 } else { 70_000 };
                let piece = 1 + rng.below(max_piece);
                let end = (pos + piece).min(stream.len());
                dec.push(&stream[pos..end]);
                pos = end;
                while let Some(f) = dec.pop().unwrap() {
                    got.push(f);
                }
            }
            assert_eq!(got, frames, "round {round}");
            assert_eq!(dec.buffered(), 0);

            // Garbage with a small limit: either frames or a clean error, never a panic.
            let mut dec = FrameDecoder::with_max_len(rng.below(512));
            let len = rng.below(2_000);
            dec.push(&rng.bytes(len));
            for _ in 0..100 {
                match dec.pop() {
                    Ok(Some(f)) => assert!(f.len() <= dec.max_len()),
                    Ok(None) | Err(_) => break,
                }
            }
        }
    }
}
