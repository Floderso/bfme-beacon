//! End-to-end example of the control-channel setup (architecture §5):
//! hello line → Argon2id PSK → Noise NNpsk0 handshake over u16-BE frames →
//! JSON messages in Noise transport messages. Also shows that a wrong password
//! makes the handshake fail.
#![cfg(feature = "control")]

use beacon_proto::control::{
    encode_frame, hello_line_len, noise_builder, ClientMsg, FrameDecoder, ServerHello, ServerMsg,
    NOISE_MAX_MSG_LEN, PSK_LEN,
};
use beacon_proto::relay::RelayKey;
use beacon_proto::snow::{HandshakeState, TransportState};

const PASSWORD: &str = "mellon";
const SALT: [u8; 16] = *b"0123456789abcdef";

/// The server derives its PSK once at start-up.
fn server_psk() -> [u8; PSK_LEN] {
    ServerHello::new("Home", SALT).derive_psk(PASSWORD).unwrap()
}

/// Writes one handshake message into a frame.
fn send_handshake(hs: &mut HandshakeState, wire: &mut Vec<u8>) {
    let mut buf = vec![0u8; NOISE_MAX_MSG_LEN];
    let n = hs.write_message(&[], &mut buf).unwrap();
    encode_frame(&buf[..n], wire).unwrap();
}

/// Reads one handshake message from the frame stream.
fn recv_handshake(
    hs: &mut HandshakeState,
    dec: &mut FrameDecoder,
    wire: &mut Vec<u8>,
) -> Result<(), beacon_proto::snow::Error> {
    dec.push(wire);
    wire.clear();
    let frame = dec.pop().unwrap().expect("complete frame");
    let mut payload = vec![0u8; NOISE_MAX_MSG_LEN];
    hs.read_message(&frame, &mut payload).map(|_| ())
}

fn send_json(t: &mut TransportState, json: &[u8], wire: &mut Vec<u8>) {
    let mut buf = vec![0u8; NOISE_MAX_MSG_LEN];
    let n = t.write_message(json, &mut buf).unwrap();
    encode_frame(&buf[..n], wire).unwrap();
}

fn recv_json(t: &mut TransportState, dec: &mut FrameDecoder, wire: &mut Vec<u8>) -> Vec<u8> {
    dec.push(wire);
    wire.clear();
    let frame = dec.pop().unwrap().expect("complete frame");
    let mut buf = vec![0u8; NOISE_MAX_MSG_LEN];
    let n = t.read_message(&frame, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

/// Runs the client side of the handshake with `password`; returns the transports
/// if the handshake succeeded.
fn connect(password: &str, server_psk: &[u8; PSK_LEN]) -> Option<(TransportState, TransportState)> {
    // Server -> client: the plaintext hello line, followed by nothing yet.
    let mut to_client = ServerHello::new("Home", SALT).to_line().unwrap();
    let mut to_server = Vec::new();

    // Client: find and parse the hello line, derive the PSK.
    let line_len = hello_line_len(&to_client).unwrap().unwrap();
    let hello = ServerHello::from_line(&to_client[..line_len]).unwrap();
    to_client.drain(..line_len);
    assert_eq!(hello.name, "Home");
    let client_psk = hello.derive_psk(password).unwrap();

    let mut client = noise_builder(&client_psk).unwrap().build_initiator().unwrap();
    let mut server = noise_builder(server_psk).unwrap().build_responder().unwrap();
    // Small frame limit until the handshake is done.
    let mut client_dec = FrameDecoder::with_max_len(256);
    let mut server_dec = FrameDecoder::with_max_len(256);

    // -> psk, e
    send_handshake(&mut client, &mut to_server);
    if recv_handshake(&mut server, &mut server_dec, &mut to_server).is_err() {
        return None; // wrong password: the server closes the connection
    }
    // <- e, ee
    send_handshake(&mut server, &mut to_client);
    recv_handshake(&mut client, &mut client_dec, &mut to_client).unwrap();

    assert!(client.is_handshake_finished() && server.is_handshake_finished());
    Some((
        client.into_transport_mode().unwrap(),
        server.into_transport_mode().unwrap(),
    ))
}

#[test]
fn full_handshake_and_json_exchange() {
    let psk = server_psk();
    let (mut client, mut server) = connect(PASSWORD, &psk).expect("handshake succeeds");
    let mut client_dec = FrameDecoder::new();
    let mut server_dec = FrameDecoder::new();
    let mut wire = Vec::new();

    // Client hello.
    let hello = ClientMsg::Hello {
        name: "Frodo".into(),
        version: "0.1.0".into(),
        fingerprint: None,
    };
    send_json(&mut client, &hello.to_json().unwrap(), &mut wire);
    assert!(!wire.windows(5).any(|w| w == b"Frodo"), "encrypted on the wire");
    let got = ClientMsg::from_json(&recv_json(&mut server, &mut server_dec, &mut wire)).unwrap();
    assert_eq!(got, hello);

    // Server welcome.
    let welcome = ServerMsg::Welcome {
        session: 7,
        key: RelayKey::from_bytes([3; 32]),
        vip: "198.18.0.2".parse().unwrap(),
        relay_port: 24800,
        motd: "Welcome to Middle-earth".into(),
        you_are_host: true,
    };
    send_json(&mut server, &welcome.to_json().unwrap(), &mut wire);
    let got = ServerMsg::from_json(&recv_json(&mut client, &mut client_dec, &mut wire)).unwrap();
    assert_eq!(got, welcome);

    // A tampered transport frame is rejected.
    send_json(&mut client, &ClientMsg::MapList.to_json().unwrap(), &mut wire);
    let last = wire.len() - 1;
    wire[last] ^= 1;
    server_dec.push(&wire);
    let frame = server_dec.pop().unwrap().unwrap();
    let mut buf = vec![0u8; NOISE_MAX_MSG_LEN];
    assert!(server.read_message(&frame, &mut buf).is_err());
}

#[test]
fn wrong_password_fails_the_handshake() {
    let psk = server_psk();
    assert!(connect("melon", &psk).is_none());
}

#[test]
fn wrong_psk_on_the_server_side_fails_too() {
    let mut other = server_psk();
    other[0] ^= 0x80;
    assert!(connect(PASSWORD, &other).is_none());
}
