//! Stubs for non-Windows hosts: the launcher only runs on Windows, but its portable
//! logic (and those tests) also build elsewhere.

use std::io;
use std::path::Path;

use super::{Hive, SHA256_LEN};

fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "only available on Windows")
}

/// Not available: DPAPI is Windows-only.
pub fn dpapi_protect(_data: &[u8]) -> io::Result<Vec<u8>> {
    Err(unsupported())
}

/// Not available: DPAPI is Windows-only.
pub fn dpapi_unprotect(_blob: &[u8]) -> io::Result<Vec<u8>> {
    Err(unsupported())
}

/// Not available (CNG); the exe identity is reported as unknown.
pub fn sha256_file(_path: &Path) -> io::Result<[u8; SHA256_LEN]> {
    Err(unsupported())
}

/// No registry: always `None`.
pub fn reg_string(_hive: Hive, _subkey: &str, _value: &str) -> Option<String> {
    None
}

/// No registry: always `None`.
pub fn reg_dword(_hive: Hive, _subkey: &str, _value: &str) -> Option<u32> {
    None
}

/// Without named mutexes the single-instance check relies on the instance file.
#[derive(Debug)]
pub struct NamedMutex;

impl NamedMutex {
    /// Always "not existing".
    pub fn create(_name: &str) -> io::Result<(Self, bool)> {
        Ok((Self, false))
    }
}

/// Nothing to attach to.
pub fn attach_parent_console() -> bool {
    false
}
