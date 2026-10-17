use std::net::Ipv4Addr;

use super::*;
use crate::fingerprint::FileEntry;
use crate::relay::RelayKey;

fn salt() -> [u8; SALT_LEN] {
    let mut s = [0u8; SALT_LEN];
    for (i, b) in s.iter_mut().enumerate() {
        *b = i as u8;
    }
    s
}

fn key() -> RelayKey {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    RelayKey::from_bytes(k)
}

fn client_json(m: &ClientMsg) -> String {
    String::from_utf8(m.to_json().unwrap()).unwrap()
}

fn server_json(m: &ServerMsg) -> String {
    String::from_utf8(m.to_json().unwrap()).unwrap()
}

// ---------------------------------------------------------------------------
// Exact JSON shapes other components rely on
// ---------------------------------------------------------------------------

#[test]
fn server_hello_exact_json() {
    let hello = ServerHello::new("Home", salt());
    let line = hello.to_line().unwrap();
    assert_eq!(
        String::from_utf8(line.clone()).unwrap(),
        "{\"beacon\":1,\"name\":\"Home\",\"salt\":\"AAECAwQFBgcICQoLDA0ODw==\",\
         \"kdf\":{\"m\":19456,\"t\":2,\"p\":1}}\n"
    );
    assert_eq!(ServerHello::from_line(&line).unwrap(), hello);
}

#[test]
fn client_messages_exact_json() {
    let cases = [
        (
            ClientMsg::Hello {
                name: "Frodo".into(),
                version: "0.1.0".into(),
                fingerprint: Some("ab12".into()),
            },
            r#"{"t":"hello","name":"Frodo","version":"0.1.0","fingerprint":"ab12"}"#,
        ),
        (
            ClientMsg::Hello {
                name: "Sam".into(),
                version: "0.1.0".into(),
                fingerprint: None,
            },
            r#"{"t":"hello","name":"Sam","version":"0.1.0","fingerprint":null}"#,
        ),
        (
            ClientMsg::Chat {
                text: "gl hf".into(),
            },
            r#"{"t":"chat","text":"gl hf"}"#,
        ),
        (ClientMsg::Ready { ready: true }, r#"{"t":"ready","ready":true}"#),
        (ClientMsg::LaunchAll, r#"{"t":"launch_all"}"#),
        (
            ClientMsg::Kick {
                name: "Gollum".into(),
            },
            r#"{"t":"kick","name":"Gollum"}"#,
        ),
        (ClientMsg::MapList, r#"{"t":"map_list"}"#),
        (
            ClientMsg::MapGet {
                map: "Helms Deep".into(),
                file: "map.map".into(),
                offset: 65_536,
            },
            r#"{"t":"map_get","map":"Helms Deep","file":"map.map","offset":65536}"#,
        ),
        (ClientMsg::Ping { ts: 1234 }, r#"{"t":"ping","ts":1234}"#),
        (
            ClientMsg::Status {
                in_game: false,
                rtt_ms: Some(42),
                loss_pct: Some(3),
            },
            r#"{"t":"status","in_game":false,"rtt_ms":42,"loss_pct":3}"#,
        ),
        (
            ClientMsg::FingerprintFiles {
                files: vec![FileEntry::new("INI.big", 5, "AB")],
                complete: true,
            },
            r#"{"t":"fingerprint_files","files":[{"path":"ini.big","size":5,"blake3_hex":"ab"}],"complete":true}"#,
        ),
        (
            ClientMsg::FingerprintGet {
                name: "Sam".into(),
            },
            r#"{"t":"fingerprint_get","name":"Sam"}"#,
        ),
    ];
    for (msg, json) in cases {
        assert_eq!(client_json(&msg), json);
        assert_eq!(ClientMsg::from_json(json.as_bytes()).unwrap(), msg);
    }
}

#[test]
fn liveness_constants() {
    assert_eq!(PING_INTERVAL.as_secs(), 5);
    assert_eq!(IDLE_TIMEOUT.as_secs(), 30);
    assert_eq!(HANDSHAKE_TIMEOUT.as_secs(), 10);
}

#[test]
fn server_messages_exact_json() {
    let welcome = ServerMsg::Welcome {
        session: 0x1234_5678,
        key: key(),
        vip: Ipv4Addr::new(198, 18, 0, 2),
        relay_port: 24800,
        motd: "Hi".into(),
        you_are_host: true,
    };
    let player = Player {
        name: "Frodo".into(),
        vip: Ipv4Addr::new(198, 18, 0, 2),
        rtt_ms: Some(12),
        loss_pct: Some(0),
        fingerprint: Some("ab".into()),
        ready: true,
        in_game: false,
        is_host: true,
    };
    let map = MapInfo::new(
        "Helms Deep",
        vec![
            MapFile {
                path: "map.map".into(),
                size: 3,
                blake3_hex: "aa".into(),
            },
            MapFile {
                path: "map.tga".into(),
                size: 4,
                blake3_hex: "bb".into(),
            },
        ],
    );
    let cases = [
        (
            welcome,
            "{\"t\":\"welcome\",\"session\":305419896,\
             \"key\":\"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\",\
             \"vip\":\"198.18.0.2\",\"relay_port\":24800,\"motd\":\"Hi\",\"you_are_host\":true}"
                .to_string(),
        ),
        (
            ServerMsg::Lobby {
                players: vec![player],
            },
            r#"{"t":"lobby","players":[{"name":"Frodo","vip":"198.18.0.2","rtt_ms":12,"loss_pct":0,"fingerprint":"ab","ready":true,"in_game":false,"is_host":true}]}"#
                .to_string(),
        ),
        (
            ServerMsg::FingerprintFiles {
                name: "Frodo".into(),
                files: vec![FileEntry::new("lotrbfme.exe", 7, "cd")],
                complete: false,
            },
            r#"{"t":"fingerprint_files","name":"Frodo","files":[{"path":"lotrbfme.exe","size":7,"blake3_hex":"cd"}],"complete":false}"#
                .to_string(),
        ),
        (
            ServerMsg::Chat {
                from: "Frodo".into(),
                text: "hi".into(),
                ts: 1_700_000_000_000,
            },
            r#"{"t":"chat","from":"Frodo","text":"hi","ts":1700000000000}"#.to_string(),
        ),
        (
            ServerMsg::Maps { maps: vec![map] },
            r#"{"t":"maps","maps":[{"name":"Helms Deep","files":[{"path":"map.map","size":3,"blake3_hex":"aa"},{"path":"map.tga","size":4,"blake3_hex":"bb"}],"total_size":7}]}"#
                .to_string(),
        ),
        (
            ServerMsg::Chunk(Chunk::new("Helms Deep", "map.map", 0, b"hello", true).unwrap()),
            r#"{"t":"chunk","map":"Helms Deep","file":"map.map","offset":0,"data":"aGVsbG8=","eof":true}"#
                .to_string(),
        ),
        (ServerMsg::Launch, r#"{"t":"launch"}"#.to_string()),
        (ServerMsg::Pong { ts: 99 }, r#"{"t":"pong","ts":99}"#.to_string()),
        (
            ServerMsg::Error {
                code: ErrorCode::NotHost,
                text: "only the host can launch".into(),
            },
            r#"{"t":"error","code":"not_host","text":"only the host can launch"}"#.to_string(),
        ),
        (
            ServerMsg::Kick {
                reason: "bye".into(),
            },
            r#"{"t":"kick","reason":"bye"}"#.to_string(),
        ),
    ];
    for (msg, json) in cases {
        assert_eq!(server_json(&msg), json);
        assert_eq!(ServerMsg::from_json(json.as_bytes()).unwrap(), msg);
    }
}

#[test]
fn error_codes_json() {
    let all = [
        (ErrorCode::BadRequest, "bad_request"),
        (ErrorCode::UnsupportedVersion, "unsupported_version"),
        (ErrorCode::BadName, "bad_name"),
        (ErrorCode::NameTaken, "name_taken"),
        (ErrorCode::ServerFull, "server_full"),
        (ErrorCode::NotHost, "not_host"),
        (ErrorCode::UnknownPlayer, "unknown_player"),
        (ErrorCode::UnknownMap, "unknown_map"),
        (ErrorCode::UnknownFile, "unknown_file"),
        (ErrorCode::BadOffset, "bad_offset"),
        (ErrorCode::RateLimited, "rate_limited"),
        (ErrorCode::Internal, "internal"),
    ];
    for (code, s) in all {
        assert_eq!(serde_json::to_string(&code).unwrap(), format!("\"{s}\""));
        assert_eq!(serde_json::from_str::<ErrorCode>(&format!("\"{s}\"")).unwrap(), code);
    }
    assert_eq!(
        serde_json::from_str::<ErrorCode>("\"some_future_code\"").unwrap(),
        ErrorCode::Unknown
    );
    let m = ServerMsg::from_json(br#"{"t":"error","code":"brand_new","text":"x"}"#).unwrap();
    assert_eq!(
        m,
        ServerMsg::Error {
            code: ErrorCode::Unknown,
            text: "x".into()
        }
    );
}

#[test]
fn forward_compatibility() {
    // Unknown message types decode to Unknown instead of failing.
    assert_eq!(
        ClientMsg::from_json(br#"{"t":"teleport","x":1}"#).unwrap(),
        ClientMsg::Unknown
    );
    assert_eq!(
        ServerMsg::from_json(br#"{"t":"weather","rain":true}"#).unwrap(),
        ServerMsg::Unknown
    );
    // Unknown fields are ignored.
    assert_eq!(
        ClientMsg::from_json(br#"{"t":"ping","ts":5,"extra":[1,2,3]}"#).unwrap(),
        ClientMsg::Ping { ts: 5 }
    );
    // Missing optional fields are None.
    assert_eq!(
        ClientMsg::from_json(br#"{"t":"hello","name":"a","version":"1"}"#).unwrap(),
        ClientMsg::Hello {
            name: "a".into(),
            version: "1".into(),
            fingerprint: None
        }
    );
    assert_eq!(
        ClientMsg::from_json(br#"{"t":"status","in_game":true}"#).unwrap(),
        ClientMsg::Status {
            in_game: true,
            rtt_ms: None,
            loss_pct: None
        }
    );
    // Field order does not matter, the tag may come last.
    assert_eq!(
        ClientMsg::from_json(br#"{"ts":7,"t":"ping"}"#).unwrap(),
        ClientMsg::Ping { ts: 7 }
    );
}

#[test]
fn malformed_messages_are_errors() {
    for bad in [
        &b""[..],
        b"null",
        b"[]",
        b"{}",
        b"{\"t\":5}",
        b"{\"t\":\"chat\"}",
        b"{\"t\":\"chat\",\"text\":5}",
        b"{\"t\":\"ping\",\"ts\":-1}",
        b"{\"t\":\"ping\",\"ts\":18446744073709551616}",
        b"{\"t\":\"ready\",\"ready\":\"yes\"}",
        b"{\"t\":\"map_get\",\"map\":\"a\",\"file\":\"b\"}",
        b"\xff\xfe",
        b"{\"t\":\"chat\",\"text\":\"\xff\"}",
    ] {
        assert!(
            matches!(ClientMsg::from_json(bad), Err(Error::Json(_))),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    for bad in [
        &br#"{"t":"welcome","session":1,"key":"zz","vip":"198.18.0.2","relay_port":1,"motd":"","you_are_host":false}"#[..],
        br#"{"t":"welcome","session":1,"key":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","vip":"198.18.0","relay_port":1,"motd":"","you_are_host":false}"#,
        br#"{"t":"welcome","session":1,"key":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","vip":"198.18.0.2","relay_port":70000,"motd":"","you_are_host":false}"#,
        br#"{"t":"lobby","players":{}}"#,
    ] {
        assert!(matches!(ServerMsg::from_json(bad), Err(Error::Json(_))));
    }
    // Deeply nested input is rejected without overflowing the stack.
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    assert!(ClientMsg::from_json(deep.as_bytes()).is_err());
}

#[test]
fn message_size_limits() {
    let big_text = "x".repeat(MAX_MSG_LEN);
    let msg = ClientMsg::Chat { text: big_text };
    assert!(matches!(
        msg.to_json(),
        Err(Error::TooLarge { max: MAX_MSG_LEN, .. })
    ));
    let json = vec![b' '; MAX_MSG_LEN + 1];
    assert!(matches!(
        ClientMsg::from_json(&json),
        Err(Error::TooLarge { max: MAX_MSG_LEN, .. })
    ));
    // A maximal chunk with long names fits into one message and one Noise frame.
    let name = "n".repeat(255);
    let chunk = Chunk::new(name.clone(), name, u64::MAX, &[0xff; CHUNK_MAX], false).unwrap();
    let json = ServerMsg::Chunk(chunk).to_json().unwrap();
    assert!(json.len() <= MAX_MSG_LEN);
    const { assert!(MAX_MSG_LEN + NOISE_TAG_LEN <= NOISE_MAX_MSG_LEN) };
    const { assert!(NOISE_MAX_MSG_LEN <= MAX_FRAME_LEN) };
}

#[test]
fn chunk_data() {
    let data: Vec<u8> = (0..1000u32).map(|i| (i * 31) as u8).collect();
    let c = Chunk::new("m", "f", 7, &data, false).unwrap();
    assert_eq!(c.data().unwrap(), data);
    assert!(matches!(
        Chunk::new("m", "f", 0, &[0; CHUNK_MAX + 1], true),
        Err(Error::TooLarge { max: CHUNK_MAX, .. })
    ));
    assert_eq!(
        Chunk::new("m", "f", 0, &[0; CHUNK_MAX], true)
            .unwrap()
            .data()
            .unwrap()
            .len(),
        CHUNK_MAX
    );
    let mut bad = c.clone();
    bad.data_b64 = "not base64!".into();
    assert!(matches!(bad.data(), Err(Error::Base64)));
    bad.data_b64 = "aGVsbG8".into(); // missing padding
    assert!(matches!(bad.data(), Err(Error::Base64)));
    bad.data_b64 = "A".repeat(CHUNK_MAX / 3 * 4 + 8);
    assert!(matches!(bad.data(), Err(Error::TooLarge { .. })));
    let empty = Chunk::new("m", "f", 0, &[], true).unwrap();
    assert_eq!(empty.data_b64, "");
    assert_eq!(empty.data().unwrap(), Vec::<u8>::new());
}

#[test]
fn map_info_total_size_saturates() {
    let f = |size| MapFile {
        path: "a".into(),
        size,
        blake3_hex: String::new(),
    };
    assert_eq!(MapInfo::new("m", vec![]).total_size, 0);
    assert_eq!(MapInfo::new("m", vec![f(1), f(2)]).total_size, 3);
    assert_eq!(MapInfo::new("m", vec![f(u64::MAX), f(2)]).total_size, u64::MAX);
}

// ---------------------------------------------------------------------------
// Hello line
// ---------------------------------------------------------------------------

#[test]
fn hello_line_parsing() {
    let hello = ServerHello::new("Beacon @ home", salt());
    let mut line = hello.to_line().unwrap();
    assert_eq!(line.iter().filter(|&&b| b == b'\n').count(), 1);
    assert_eq!(ServerHello::from_line(&line).unwrap(), hello);
    // Without newline and with CRLF.
    assert_eq!(ServerHello::from_line(&line[..line.len() - 1]).unwrap(), hello);
    line.pop();
    line.extend_from_slice(b"\r\n");
    assert_eq!(ServerHello::from_line(&line).unwrap(), hello);

    let v2 = br#"{"beacon":2,"name":"x","salt":"AAECAwQFBgcICQoLDA0ODw==","kdf":{"m":19456,"t":2,"p":1}}"#;
    assert!(matches!(
        ServerHello::from_line(v2),
        Err(Error::UnsupportedVersion(2))
    ));
    for bad_salt in ["AAECAwQFBgcICQoLDA0O", "AAECAwQFBgcICQoLDA0ODxA=", "!!!!", ""] {
        let line = format!(
            r#"{{"beacon":1,"name":"x","salt":"{bad_salt}","kdf":{{"m":19456,"t":2,"p":1}}}}"#
        );
        assert!(
            matches!(ServerHello::from_line(line.as_bytes()), Err(Error::Json(_))),
            "{bad_salt}"
        );
    }
    let missing_kdf = br#"{"beacon":1,"name":"x","salt":"AAECAwQFBgcICQoLDA0ODw=="}"#;
    assert!(matches!(ServerHello::from_line(missing_kdf), Err(Error::Json(_))));
    let too_long = vec![b' '; HELLO_MAX_LEN + 1];
    assert!(matches!(
        ServerHello::from_line(&too_long),
        Err(Error::TooLarge { .. })
    ));
    let long_name = ServerHello::new("n".repeat(HELLO_MAX_LEN), salt());
    assert!(matches!(long_name.to_line(), Err(Error::TooLarge { .. })));
    // A name with a newline is escaped, so the line stays one line.
    let tricky = ServerHello::new("a\nb", salt());
    let line = tricky.to_line().unwrap();
    assert_eq!(hello_line_len(&line).unwrap(), Some(line.len()));
    assert_eq!(ServerHello::from_line(&line).unwrap(), tricky);
}

#[test]
fn hello_line_len_in_stream() {
    let line = ServerHello::new("x", salt()).to_line().unwrap();
    let mut stream = line.clone();
    stream.extend_from_slice(&[0, 48, 1, 2, 3]);
    assert_eq!(hello_line_len(&stream).unwrap(), Some(line.len()));
    for cut in 0..line.len() {
        assert_eq!(hello_line_len(&line[..cut]).unwrap(), None);
    }
    assert!(hello_line_len(&vec![b'a'; HELLO_MAX_LEN]).is_err());
    let mut exact = vec![b'a'; HELLO_MAX_LEN - 1];
    exact.push(b'\n');
    assert_eq!(hello_line_len(&exact).unwrap(), Some(HELLO_MAX_LEN));
    exact.extend_from_slice(b"more");
    assert_eq!(hello_line_len(&exact).unwrap(), Some(HELLO_MAX_LEN));
    let mut late = vec![b'a'; HELLO_MAX_LEN];
    late.push(b'\n');
    assert!(hello_line_len(&late).is_err());
}

// ---------------------------------------------------------------------------
// KDF
// ---------------------------------------------------------------------------

#[test]
fn kdf_params_bounds() {
    assert!(KdfParams::DEFAULT.validate().is_ok());
    assert_eq!(KdfParams::default(), KdfParams::DEFAULT);
    let ok = [
        KdfParams { m: 19_456, t: 2, p: 1 },
        KdfParams { m: 262_144, t: 16, p: 8 },
        KdfParams { m: 65_536, t: 3, p: 4 },
    ];
    for p in ok {
        assert!(p.validate().is_ok(), "{p:?}");
    }
    let bad = [
        KdfParams { m: 19_455, t: 2, p: 1 },
        KdfParams { m: 262_145, t: 2, p: 1 },
        KdfParams { m: 19_456, t: 1, p: 1 },
        KdfParams { m: 19_456, t: 17, p: 1 },
        KdfParams { m: 19_456, t: 2, p: 0 },
        KdfParams { m: 19_456, t: 2, p: 9 },
        KdfParams { m: 0, t: 0, p: 0 },
        KdfParams { m: u32::MAX, t: u32::MAX, p: u32::MAX },
    ];
    for p in bad {
        assert!(matches!(p.validate(), Err(Error::KdfParams(q)) if q == p), "{p:?}");
        assert!(matches!(derive_psk("pw", &salt(), &p), Err(Error::KdfParams(_))));
    }
}

#[test]
fn derive_psk_properties() {
    let p = KdfParams::DEFAULT;
    let a = derive_psk("correct horse", &salt(), &p).unwrap();
    assert_eq!(a, derive_psk("correct horse", &salt(), &p).unwrap());
    // Golden value (Argon2id v0x13, m=19456, t=2, p=1, 32 bytes, no secret/AD);
    // cross-checked against the reference C implementation (argon2-cffi).
    assert_eq!(
        RelayKey::from_bytes(a).to_hex(),
        "d00b90c40f918cf889780d7d3a9ec3c2b1719df87dc5e4d4d93ea6163db04e17"
    );
    let mut other_salt = salt();
    other_salt[0] ^= 1;
    assert_ne!(a, derive_psk("correct horse", &other_salt, &p).unwrap());
    assert_ne!(a, derive_psk("correct horsf", &salt(), &p).unwrap());
    let hello = ServerHello::new("x", salt());
    assert_eq!(hello.derive_psk("correct horse").unwrap(), a);
    // Empty and non-ASCII passwords work.
    assert_ne!(derive_psk("", &salt(), &p).unwrap(), a);
    assert_ne!(derive_psk("pässwörd", &salt(), &p).unwrap(), a);
}

// ---------------------------------------------------------------------------
// Noise
// ---------------------------------------------------------------------------

#[test]
fn noise_params_parse_and_build() {
    let params: snow::params::NoiseParams = NOISE_PARAMS.parse().unwrap();
    assert_eq!(params.name, NOISE_PARAMS);
    let psk = [9u8; PSK_LEN];
    assert!(noise_builder(&psk).unwrap().build_initiator().is_ok());
    assert!(noise_builder(&psk).unwrap().build_responder().is_ok());
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

fn frames() -> Vec<Vec<u8>> {
    vec![
        b"first".to_vec(),
        Vec::new(),
        vec![0xAB; 300],
        (0..=255u8).collect(),
        vec![7; MAX_FRAME_LEN],
        b"last".to_vec(),
    ]
}

fn stream() -> Vec<u8> {
    let mut out = Vec::new();
    for f in frames() {
        encode_frame(&f, &mut out).unwrap();
    }
    out
}

fn drain(dec: &mut FrameDecoder) -> Vec<Vec<u8>> {
    let mut got = Vec::new();
    while let Some(f) = dec.pop().unwrap() {
        got.push(f);
    }
    got
}

#[test]
fn encode_frame_layout() {
    let mut out = vec![0xEE];
    encode_frame(b"abc", &mut out).unwrap();
    assert_eq!(out, [0xEE, 0, 3, b'a', b'b', b'c']);
    let mut out = Vec::new();
    encode_frame(&vec![1; 0x1234], &mut out).unwrap();
    assert_eq!(&out[..2], &[0x12, 0x34]);
    assert_eq!(out.len(), 0x1234 + 2);
    let mut out = vec![1, 2];
    assert!(matches!(
        encode_frame(&vec![0; MAX_FRAME_LEN + 1], &mut out),
        Err(Error::TooLarge { .. })
    ));
    assert_eq!(out, [1, 2], "output untouched on error");
}

#[test]
fn frame_decoder_whole_stream() {
    let mut dec = FrameDecoder::new();
    dec.push(&stream());
    assert_eq!(drain(&mut dec), frames());
    assert_eq!(dec.buffered(), 0);
    assert_eq!(dec.pop().unwrap(), None);
}

#[test]
fn frame_decoder_byte_by_byte() {
    let mut dec = FrameDecoder::new();
    let mut got = Vec::new();
    for b in stream() {
        dec.push(&[b]);
        got.extend(drain(&mut dec));
    }
    assert_eq!(got, frames());
    assert_eq!(dec.buffered(), 0);
}

#[test]
fn frame_decoder_irregular_pieces() {
    let s = stream();
    for piece in [2usize, 3, 7, 64, 1000, 65_536, 70_000] {
        let mut dec = FrameDecoder::new();
        let mut got = Vec::new();
        for chunk in s.chunks(piece) {
            dec.push(chunk);
            got.extend(drain(&mut dec));
        }
        assert_eq!(got, frames(), "piece size {piece}");
    }
    // Pushing everything first, popping later, in two halves.
    let mut dec = FrameDecoder::new();
    let (a, b) = s.split_at(s.len() / 2);
    dec.push(a);
    let mut got = drain(&mut dec);
    assert!(dec.buffered() > 0);
    dec.push(b);
    got.extend(drain(&mut dec));
    assert_eq!(got, frames());
}

#[test]
fn frame_decoder_limits() {
    let mut dec = FrameDecoder::with_max_len(100);
    assert_eq!(dec.max_len(), 100);
    let mut s = Vec::new();
    encode_frame(&[1; 100], &mut s).unwrap();
    encode_frame(&[2; 101], &mut s).unwrap();
    dec.push(&s);
    assert_eq!(dec.pop().unwrap(), Some(vec![1; 100]));
    // Reported as soon as the length is known, and sticky.
    assert!(matches!(dec.pop(), Err(Error::TooLarge { len: 101, max: 100 })));
    assert!(matches!(dec.pop(), Err(Error::TooLarge { len: 101, max: 100 })));

    let mut dec = FrameDecoder::with_max_len(10);
    dec.push(&[0xFF]);
    assert_eq!(dec.pop().unwrap(), None);
    dec.push(&[0xFF]);
    assert!(matches!(dec.pop(), Err(Error::TooLarge { len: 65_535, max: 10 })));

    // The limit can be raised after the handshake and is capped at 65535.
    let mut dec = FrameDecoder::with_max_len(1_000_000);
    assert_eq!(dec.max_len(), MAX_FRAME_LEN);
    dec.set_max_len(16);
    assert_eq!(dec.max_len(), 16);
    dec.set_max_len(usize::MAX);
    assert_eq!(dec.max_len(), MAX_FRAME_LEN);
    assert_eq!(FrameDecoder::default().max_len(), MAX_FRAME_LEN);
}

#[test]
fn frame_decoder_partial_header_and_body() {
    let mut dec = FrameDecoder::new();
    dec.push(&[0]);
    assert_eq!(dec.pop().unwrap(), None);
    assert_eq!(dec.buffered(), 1);
    dec.push(&[5, b'a', b'b']);
    assert_eq!(dec.pop().unwrap(), None);
    assert_eq!(dec.buffered(), 4);
    dec.push(b"cde");
    assert_eq!(dec.pop().unwrap(), Some(b"abcde".to_vec()));
    assert_eq!(dec.buffered(), 0);
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

#[test]
fn base64_helpers() {
    assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
    assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
    assert!(matches!(base64_decode("aGVsbG8"), Err(Error::Base64)));
    assert!(matches!(base64_decode("a b"), Err(Error::Base64)));
}

#[test]
fn error_display_and_source() {
    let json_err = ClientMsg::from_json(b"{").unwrap_err();
    assert!(std::error::Error::source(&json_err).is_some());
    let errs = [
        json_err,
        Error::TooLarge { len: 2, max: 1 },
        Error::Base64,
        Error::UnsupportedVersion(3),
        Error::KdfParams(KdfParams { m: 1, t: 1, p: 1 }),
        Error::Kdf,
    ];
    for e in errs {
        assert!(!e.to_string().is_empty());
    }
}
