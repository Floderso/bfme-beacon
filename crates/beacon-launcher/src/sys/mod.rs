//! Platform layer: every Win32 call of the launcher – and with it every `unsafe`
//! block – lives in this module (`windows.rs`). Other platforms get stubs
//! (`other.rs`) so the portable logic still builds and its tests run there.
//!
//! * DPAPI (`CryptProtectData`, user scope) for the remembered PSK.
//! * SHA-256 through CNG (`BCryptHashData`) for the exe identity.
//! * Registry reads (32-bit view, like the 32-bit game).
//! * Named mutex (single instance per data directory).
//! * Attaching to the parent console for the CLI modes of the GUI-subsystem exe.

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use self::windows::*;

#[cfg(not(windows))]
mod other;
#[cfg(not(windows))]
pub use self::other::*;

/// A registry hive the launcher reads from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    /// `HKEY_LOCAL_MACHINE` (read through the 32-bit view, `WOW6432Node`).
    LocalMachine,
    /// `HKEY_CURRENT_USER`.
    CurrentUser,
}

/// Length of a SHA-256 digest.
pub const SHA256_LEN: usize = 32;

/// Lowercase hex of a byte slice.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            if let Some(&d) = DIGITS.get(usize::from(nibble)) {
                s.push(char::from(d));
            }
        }
    }
    s
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answers() {
        let dir = std::env::temp_dir().join(format!("beacon-sha-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cases: [(&[u8], &str); 3] = [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ];
        for (i, (data, want)) in cases.iter().enumerate() {
            let p = dir.join(format!("f{i}"));
            std::fs::write(&p, data).unwrap();
            assert_eq!(hex(&sha256_file(&p).unwrap()), *want);
        }
        // One million 'a' (crosses the 1 MiB read buffer boundary).
        let p = dir.join("million");
        std::fs::write(&p, vec![b'a'; 1_000_000]).unwrap();
        assert_eq!(
            hex(&sha256_file(&p).unwrap()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dpapi_round_trip_and_tamper() {
        let secret = [7u8; 32];
        let blob = dpapi_protect(&secret).unwrap();
        assert!(blob.len() > secret.len());
        assert!(!blob.windows(secret.len()).any(|w| w == secret));
        assert_eq!(dpapi_unprotect(&blob).unwrap(), secret);
        let mut bad = blob.clone();
        if let Some(last) = bad.last_mut() {
            *last ^= 0xff;
        }
        assert!(dpapi_unprotect(&bad).is_err());
        assert!(dpapi_unprotect(&[]).is_err());
    }

    #[test]
    fn named_mutex_reports_existing() {
        let name = format!("Local\\beacon-test-mutex-{}", std::process::id());
        let (first, existed) = NamedMutex::create(&name).unwrap();
        assert!(!existed);
        let (_second, existed) = NamedMutex::create(&name).unwrap();
        assert!(existed);
        drop(first);
    }

    #[test]
    fn registry_missing_values_are_none() {
        assert_eq!(
            reg_string(Hive::CurrentUser, "Software\\BeaconTestDoesNotExist", "x"),
            None
        );
        assert_eq!(reg_dword(Hive::LocalMachine, "SOFTWARE\\BeaconTestDoesNotExist", "x"), None);
    }

    #[test]
    fn hex_formats_lowercase() {
        assert_eq!(hex(&[0x00, 0xab, 0x7f]), "00ab7f");
    }
}
