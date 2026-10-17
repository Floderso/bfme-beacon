//! A fake Beacon agent: the loopback UDP socket the hook sends `REG`/`SEND`/`CLOSE`
//! frames to and that sends `DELIVER` frames back (architecture §5).

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use beacon_proto::local::{self, Deliver, HookFrame};

/// One received hook → agent frame.
#[derive(Debug)]
pub struct Frame {
    pub header: HookFrame,
    pub payload: Vec<u8>,
    pub src: SocketAddr,
}

pub struct Agent {
    sock: UdpSocket,
}

impl Agent {
    pub fn new() -> io::Result<Self> {
        let sock = UdpSocket::bind("127.0.0.1:0")?;
        Ok(Self { sock })
    }

    pub fn port(&self) -> u16 {
        self.sock.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    /// Next frame within `timeout`; parse errors are reported as `Err`.
    pub fn next(&self, timeout: Duration) -> Result<Frame, String> {
        self.sock.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
        let mut buf = [0u8; 2048];
        let (n, src) = self.sock.recv_from(&mut buf).map_err(|e| format!("no frame: {e}"))?;
        let datagram = buf.get(..n).ok_or("bad length")?;
        let (header, payload) = local::parse_hook_frame(datagram).map_err(|e| format!("bad frame: {e}"))?;
        Ok(Frame { header, payload: payload.to_vec(), src })
    }

    /// `Some(frame)` if anything arrives within `wait` (used to assert silence).
    pub fn unexpected(&self, wait: Duration) -> Option<Frame> {
        self.next(wait).ok()
    }

    pub fn deliver(&self, to: SocketAddr, src_vip: Ipv4Addr, src_vport: u16, payload: &[u8]) -> io::Result<()> {
        let mut buf = [0u8; local::MAX_DELIVER_FRAME_LEN];
        let n = local::encode_deliver(&Deliver { src_vip, src_vport }, payload, &mut buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        self.sock.send_to(buf.get(..n).unwrap_or(&[]), to)?;
        Ok(())
    }

    pub fn send_raw(&self, to: SocketAddr, bytes: &[u8]) -> io::Result<usize> {
        self.sock.send_to(bytes, to)
    }
}
