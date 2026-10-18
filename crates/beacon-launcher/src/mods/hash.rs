//! MD5 (the BFME Workshop's content address) and BLAKE3 (Beacon's fingerprint)
//! in one pass over a file or a stream.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use beacon_proto::blake3;
use md5::{Digest, Md5};

/// Read buffer for hashing and copying.
pub const BUF_LEN: usize = 1 << 20;

/// Both digests of some content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digests {
    /// MD5, 32 lowercase hex digits.
    pub md5: String,
    /// BLAKE3, 64 lowercase hex digits.
    pub blake3: String,
    /// Number of bytes.
    pub size: u64,
}

/// Why hashing or copying stopped.
#[derive(Debug)]
pub enum HashError {
    /// Reading or writing failed.
    Io(io::Error),
    /// The cancel flag was set.
    Cancelled,
    /// More than the allowed number of bytes.
    TooLarge(u64),
}

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Cancelled => f.write_str("cancelled"),
            Self::TooLarge(n) => write!(f, "more than {n} bytes"),
        }
    }
}

impl std::error::Error for HashError {}

impl From<io::Error> for HashError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Incremental MD5 + BLAKE3.
pub struct Hashers {
    md5: Md5,
    blake3: blake3::Hasher,
    size: u64,
}

impl Default for Hashers {
    fn default() -> Self {
        Self::new()
    }
}

impl Hashers {
    /// Empty state.
    pub fn new() -> Self {
        Self {
            md5: Md5::new(),
            blake3: blake3::Hasher::new(),
            size: 0,
        }
    }

    /// Adds bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.md5.update(data);
        self.blake3.update(data);
        self.size = self.size.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
    }

    /// Bytes seen so far.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The digests.
    pub fn finish(self) -> Digests {
        Digests {
            md5: crate::sys::hex(&self.md5.finalize()),
            blake3: self.blake3.finalize().to_hex().to_string(),
            size: self.size,
        }
    }
}

/// MD5 of a byte slice as hex.
pub fn md5_hex(data: &[u8]) -> String {
    crate::sys::hex(&Md5::digest(data))
}

/// Copies `src` to `dst` (if given) while hashing it; stops at `limit` bytes,
/// on cancellation and on errors. `on_bytes` gets every piece's length.
pub fn copy_and_hash(
    src: &mut dyn Read,
    mut dst: Option<&mut dyn Write>,
    limit: u64,
    cancel: &AtomicBool,
    on_bytes: &mut dyn FnMut(u64),
) -> Result<Digests, HashError> {
    let mut hashers = Hashers::new();
    let mut buf = vec![0u8; BUF_LEN];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(HashError::Cancelled);
        }
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(HashError::Io(e)),
        };
        let chunk = buf.get(..n).unwrap_or_default();
        if hashers.size().saturating_add(u64::try_from(n).unwrap_or(u64::MAX)) > limit {
            return Err(HashError::TooLarge(limit));
        }
        hashers.update(chunk);
        if let Some(w) = dst.as_deref_mut() {
            w.write_all(chunk)?;
        }
        on_bytes(u64::try_from(n).unwrap_or(0));
    }
    Ok(hashers.finish())
}

/// The digests of a file.
pub fn hash_file(path: &Path, cancel: &AtomicBool, on_bytes: &mut dyn FnMut(u64)) -> Result<Digests, HashError> {
    let mut file = File::open(path)?;
    copy_and_hash(&mut file, None, u64::MAX, cancel, on_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        assert_eq!(md5_hex(b""), crate::mods::EMPTY_MD5);
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        let mut h = Hashers::new();
        h.update(b"a");
        h.update(b"bc");
        let d = h.finish();
        assert_eq!(d.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(d.blake3, blake3::hash(b"abc").to_hex().to_string());
        assert_eq!(d.size, 3);
    }

    #[test]
    fn copy_limits_and_cancel() {
        let data = vec![7u8; 3 * BUF_LEN + 5];
        let cancel = AtomicBool::new(false);
        let mut out = Vec::new();
        let mut seen = 0u64;
        let d = copy_and_hash(&mut data.as_slice(), Some(&mut out), u64::MAX, &cancel, &mut |n| seen += n).unwrap();
        assert_eq!(out, data);
        assert_eq!(seen, data.len() as u64);
        assert_eq!(d.md5, md5_hex(&data));
        assert!(matches!(
            copy_and_hash(&mut data.as_slice(), None, 10, &cancel, &mut |_| {}),
            Err(HashError::TooLarge(10))
        ));
        cancel.store(true, Ordering::Relaxed);
        assert!(matches!(
            copy_and_hash(&mut data.as_slice(), None, u64::MAX, &cancel, &mut |_| {}),
            Err(HashError::Cancelled)
        ));
    }
}
