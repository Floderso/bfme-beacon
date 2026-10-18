//! Stubs for non-Windows hosts: the launcher only runs on Windows, but its portable
//! logic (and those tests) also build elsewhere.

use std::io;
use std::path::Path;

use super::{Hive, HttpRequestSpec, RawHttpResponse, TrayCommand, SHA256_LEN};

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

/// Not available: there is no shell to hand the URL to.
pub fn open_url(_url: &str) -> io::Result<()> {
    Err(unsupported())
}

/// Not available: the text goes to stderr instead.
pub fn message_box(title: &str, text: &str) {
    eprintln!("{title}: {text}");
}

/// Not available: there is no Explorer.
pub fn open_folder(_path: &Path) -> io::Result<()> {
    Err(unsupported())
}

/// No notification area: [`Tray::start`] always fails.
#[derive(Debug)]
pub struct Tray;

impl Tray {
    /// Not available.
    pub fn start(_tooltip: &str, _callback: impl Fn(TrayCommand) + Send + 'static) -> io::Result<Self> {
        Err(unsupported())
    }
}

/// Not available: the free-space check is skipped.
pub fn free_space(_path: &Path) -> io::Result<u64> {
    Err(unsupported())
}

/// Not available: the BFME Workshop client uses WinHTTP.
pub fn http_get(_spec: &HttpRequestSpec<'_>) -> io::Result<RawHttpResponse> {
    Err(unsupported())
}
