//! `RegQueryValueExA/W` hook (architecture §4.4, spec 04 §5.2): the default value
//! of the `ergc` key — the CD key BFME compares on LAN join (`RET_SERIAL_DUPE`) —
//! reads as `BEACON_SERIAL`. Everything else passes through to the original.
//!
//! The game reads it with `RegOpenKeyExA(HKLM, "SOFTWARE\Electronic Arts\EA
//! Games\The Battle for Middle-earth\ergc", KEY_READ)` + `RegQueryValueExA(h, "")`,
//! falling back to HKCU. The key is identified by its kernel name
//! (`NtQueryKey(KeyNameInformation)`), so no `RegOpenKeyEx`/`RegCloseKey` tracking
//! is needed; the lookup only happens for default-value reads.

use core::ffi::c_void;
use std::sync::atomic::AtomicUsize;
use std::sync::OnceLock;

use beacon_proto::env::SERIAL_LEN;

use crate::ffi;
use crate::wide::wide_eq_ignore_ascii_case;

/// Original `ADVAPI32!RegQueryValueExA` (from the exe's IAT).
pub static ORIG_A: AtomicUsize = AtomicUsize::new(0);
/// Original `ADVAPI32!RegQueryValueExW`.
pub static ORIG_W: AtomicUsize = AtomicUsize::new(0);

static SERIAL: OnceLock<[u8; SERIAL_LEN]> = OnceLock::new();

/// `RegQueryValueExA`.
pub type RegQueryValueExAFn =
    unsafe extern "system" fn(*mut c_void, *const u8, *mut u32, *mut u32, *mut u8, *mut u32) -> i32;
/// `RegQueryValueExW`.
pub type RegQueryValueExWFn =
    unsafe extern "system" fn(*mut c_void, *const u16, *mut u32, *mut u32, *mut u8, *mut u32) -> i32;

/// Path of the key below `HKLM\` / `HKCU\` (spec 04 §5.1 + `"\\ergc"`).
const ERGC_PATH: &str = r"SOFTWARE\Electronic Arts\EA Games\The Battle for Middle-earth\ergc";
/// The same key as seen by a 32-bit process under HKLM (WOW64 redirection).
const ERGC_PATH_WOW64: &str = r"SOFTWARE\WOW6432Node\Electronic Arts\EA Games\The Battle for Middle-earth\ergc";

/// Sets the serial the hooks return (once, before the hooks are installed).
pub fn set_serial(serial: [u8; SERIAL_LEN]) {
    let _ = SERIAL.set(serial);
}

/// `true` if a kernel key name (`\REGISTRY\…`) is the `ergc` key: under
/// `\REGISTRY\MACHINE`, `\REGISTRY\USER\<sid>` or a UAC VirtualStore copy
/// `\REGISTRY\USER\<sid>_Classes\VirtualStore\MACHINE`, at `ERGC_PATH` or its
/// `WOW6432Node` form. Case-insensitive like the registry.
pub fn is_ergc_key_name(name: &[u16]) -> bool {
    let Some(rest) = strip_prefix_ci(name, r"\REGISTRY\") else {
        return false;
    };
    let root_len = if let Some(r) = strip_prefix_ci(rest, "MACHINE") {
        rest.len() - r.len()
    } else if let Some(r) = strip_prefix_ci(rest, r"USER\") {
        // One component (the SID or `<sid>_Classes`), optionally followed by the
        // VirtualStore mirror of HKLM.
        let sid_len = r.iter().position(|&c| c == u16::from(b'\\')).unwrap_or(r.len());
        if sid_len == 0 {
            return false;
        }
        let after_sid = r.get(sid_len..).unwrap_or(&[]);
        let virtual_store = strip_prefix_ci(after_sid, r"\VirtualStore\MACHINE").map_or(0, |v| after_sid.len() - v.len());
        rest.len() - r.len() + sid_len + virtual_store
    } else {
        return false;
    };
    let Some(path) = rest.get(root_len..).and_then(|p| strip_prefix_ci(p, r"\")) else {
        return false;
    };
    wide_eq_ignore_ascii_case(path, ERGC_PATH) || wide_eq_ignore_ascii_case(path, ERGC_PATH_WOW64)
}

fn strip_prefix_ci<'a>(s: &'a [u16], prefix: &str) -> Option<&'a [u16]> {
    let head = s.get(..prefix.len())?;
    wide_eq_ignore_ascii_case(head, prefix).then(|| s.get(prefix.len()..).unwrap_or(&[]))
}

/// `true` if `key` is an open handle to the `ergc` key.
fn is_ergc_key(key: *mut c_void) -> bool {
    // KEY_NAME_INFORMATION { ULONG NameLength (bytes); WCHAR Name[] }.
    let mut info = [0u32; 256];
    let mut needed = 0u32;
    let len = u32::try_from(core::mem::size_of_val(&info)).unwrap_or(0);
    // SAFETY: `info` is writable for `len` bytes and 4-byte aligned; NtQueryKey
    // validates the handle (pseudo-handles like HKEY_LOCAL_MACHINE simply fail).
    let status =
        unsafe { ffi::NtQueryKey(key, ffi::KEY_NAME_INFORMATION, info.as_mut_ptr().cast(), len, &mut needed) };
    if status < 0 {
        return false;
    }
    let [name_bytes, rest @ ..] = &info;
    let chars = (*name_bytes as usize / 2).min(rest.len() * 2);
    let mut name = [0u16; 510];
    for (i, dst) in name.iter_mut().enumerate().take(chars) {
        let word = rest.get(i / 2).copied().unwrap_or(0);
        *dst = if i % 2 == 0 { word as u16 } else { (word >> 16) as u16 };
    }
    name.get(..chars).is_some_and(is_ergc_key_name)
}

/// Fills a `RegQueryValueEx` reply with `value` (`REG_SZ`, terminator included) and
/// returns the status, with the documented buffer semantics: size query with
/// `data == NULL`, `ERROR_MORE_DATA` + required size if the buffer is too small.
///
/// # Safety
/// Non-null pointers must be valid (`data` for `*cb` bytes).
pub unsafe fn fill_reply(value: &[u8], ty: *mut u32, data: *mut u8, cb: *mut u32) -> i32 {
    let needed = u32::try_from(value.len()).unwrap_or(u32::MAX);
    if !ty.is_null() {
        // SAFETY: valid out-parameter (caller contract).
        unsafe { ty.write_unaligned(ffi::REG_SZ) };
    }
    if cb.is_null() {
        return if data.is_null() { ffi::ERROR_SUCCESS } else { ffi::ERROR_INVALID_PARAMETER };
    }
    // SAFETY: valid in/out parameter.
    let available = unsafe { cb.read_unaligned() };
    // SAFETY: valid in/out parameter.
    unsafe { cb.write_unaligned(needed) };
    if data.is_null() {
        return ffi::ERROR_SUCCESS;
    }
    if available < needed {
        return ffi::ERROR_MORE_DATA;
    }
    // SAFETY: `data` is writable for `available >= needed` bytes.
    unsafe { core::ptr::copy_nonoverlapping(value.as_ptr(), data, value.len()) };
    ffi::ERROR_SUCCESS
}

fn serial_a(serial: &[u8; SERIAL_LEN]) -> [u8; SERIAL_LEN + 1] {
    let mut out = [0u8; SERIAL_LEN + 1];
    for (dst, &b) in out.iter_mut().zip(serial) {
        *dst = b;
    }
    out
}

fn serial_w(serial: &[u8; SERIAL_LEN]) -> [u8; 2 * (SERIAL_LEN + 1)] {
    let mut out = [0u8; 2 * (SERIAL_LEN + 1)];
    for (dst, &b) in out.as_chunks_mut::<2>().0.iter_mut().zip(serial) {
        dst.copy_from_slice(&u16::from(b).to_le_bytes());
    }
    out
}


/// Hook for `ADVAPI32!RegQueryValueExA`.
///
/// # Safety
/// Called by the game with `RegQueryValueExA`'s contract.
pub unsafe extern "system" fn hook_reg_query_value_ex_a(
    key: *mut c_void,
    name: *const u8,
    reserved: *mut u32,
    ty: *mut u32,
    data: *mut u8,
    cb: *mut u32,
) -> i32 {
    if let Some(serial) = SERIAL.get() {
        // SAFETY: `name` is NULL or a NUL-terminated string (API contract).
        let default_value = name.is_null() || unsafe { name.read() } == 0;
        if default_value && reserved.is_null() && is_ergc_key(key) {
            crate::log::info!("RegQueryValueExA(ergc) -> BEACON_SERIAL");
            // SAFETY: API contract for the out-parameters.
            return unsafe { fill_reply(&serial_a(serial), ty, data, cb) };
        }
    }
    // SAFETY: `RegQueryValueExAFn` is the signature of the import saved in `ORIG_A`.
    match unsafe { crate::iat::load_fn::<RegQueryValueExAFn>(&ORIG_A) } {
        // SAFETY: the original function with the caller's arguments.
        Some(f) => unsafe { f(key, name, reserved, ty, data, cb) },
        None => ffi::ERROR_INVALID_FUNCTION,
    }
}

/// Hook for `ADVAPI32!RegQueryValueExW`.
///
/// # Safety
/// Called by the game with `RegQueryValueExW`'s contract.
pub unsafe extern "system" fn hook_reg_query_value_ex_w(
    key: *mut c_void,
    name: *const u16,
    reserved: *mut u32,
    ty: *mut u32,
    data: *mut u8,
    cb: *mut u32,
) -> i32 {
    if let Some(serial) = SERIAL.get() {
        // SAFETY: `name` is NULL or a NUL-terminated string (API contract).
        let default_value = name.is_null() || unsafe { name.read() } == 0;
        if default_value && reserved.is_null() && is_ergc_key(key) {
            crate::log::info!("RegQueryValueExW(ergc) -> BEACON_SERIAL");
            // SAFETY: API contract for the out-parameters.
            return unsafe { fill_reply(&serial_w(serial), ty, data, cb) };
        }
    }
    // SAFETY: `RegQueryValueExWFn` is the signature of the import saved in `ORIG_W`.
    match unsafe { crate::iat::load_fn::<RegQueryValueExWFn>(&ORIG_W) } {
        // SAFETY: the original function with the caller's arguments.
        Some(f) => unsafe { f(key, name, reserved, ty, data, cb) },
        None => ffi::ERROR_INVALID_FUNCTION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn key_name_matching() {
        let yes = [
            r"\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Electronic Arts\EA Games\The Battle for Middle-earth\ergc",
            r"\REGISTRY\MACHINE\SOFTWARE\Electronic Arts\EA Games\The Battle for Middle-earth\ergc",
            r"\Registry\Machine\Software\electronic arts\ea games\the battle for middle-earth\ERGC",
            r"\REGISTRY\USER\S-1-5-21-1-2-3-1001\SOFTWARE\Electronic Arts\EA Games\The Battle for Middle-earth\ergc",
            r"\REGISTRY\USER\S-1-5-21-1-2-3-1001_Classes\VirtualStore\MACHINE\SOFTWARE\WOW6432Node\Electronic Arts\EA Games\The Battle for Middle-earth\ergc",
        ];
        for name in yes {
            assert!(is_ergc_key_name(&w(name)), "{name}");
        }
        let no = [
            "",
            r"\REGISTRY\MACHINE",
            r"\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Electronic Arts\EA Games\The Battle for Middle-earth",
            r"\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Electronic Arts\EA Games\The Battle for Middle-earth\ergc\sub",
            r"\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Electronic Arts\EA Games\The Battle for Middle-earth II\ergc",
            r"\REGISTRY\MACHINE\X\SOFTWARE\Electronic Arts\EA Games\The Battle for Middle-earth\ergc",
            r"\REGISTRY\USER\\SOFTWARE\Electronic Arts\EA Games\The Battle for Middle-earth\ergc",
            r"\REGISTRY\USER\S-1\X\SOFTWARE\Electronic Arts\EA Games\The Battle for Middle-earth\ergc",
            r"REGISTRY\MACHINE\SOFTWARE\Electronic Arts\EA Games\The Battle for Middle-earth\ergc",
            r"\REGISTRY\MACHINESOFTWARE\Electronic Arts\EA Games\The Battle for Middle-earth\ergc",
        ];
        for name in no {
            assert!(!is_ergc_key_name(&w(name)), "{name}");
        }
    }

    #[test]
    fn reply_buffer_semantics() {
        let value = b"ABCDEFGHIJ0123456789\0";
        let mut ty = 0u32;
        let mut cb = 0u32;
        let mut data = [0xEEu8; 64];
        // SAFETY: valid local buffers.
        unsafe {
            // Size query.
            assert_eq!(fill_reply(value, &mut ty, core::ptr::null_mut(), &mut cb), ffi::ERROR_SUCCESS);
            assert_eq!((ty, cb), (ffi::REG_SZ, 21));
            // Too small.
            cb = 20;
            assert_eq!(fill_reply(value, &mut ty, data.as_mut_ptr(), &mut cb), ffi::ERROR_MORE_DATA);
            assert_eq!(cb, 21);
            assert_eq!(data[0], 0xEE);
            // Exact and larger buffers.
            cb = 256;
            assert_eq!(fill_reply(value, core::ptr::null_mut(), data.as_mut_ptr(), &mut cb), ffi::ERROR_SUCCESS);
            assert_eq!(cb, 21);
            assert_eq!(&data[..21], value);
            assert_eq!(data[21], 0xEE);
            // Data without size pointer is invalid; nothing at all is fine.
            assert_eq!(fill_reply(value, &mut ty, data.as_mut_ptr(), core::ptr::null_mut()), ffi::ERROR_INVALID_PARAMETER);
            assert_eq!(fill_reply(value, &mut ty, core::ptr::null_mut(), core::ptr::null_mut()), ffi::ERROR_SUCCESS);
        }
        let s = *b"ABCDEFGHIJ0123456789";
        assert_eq!(&serial_a(&s), value);
        let wide = serial_w(&s);
        assert_eq!(wide.len(), 42);
        assert_eq!(&wide[..4], &[b'A', 0, b'B', 0]);
        assert_eq!(&wide[40..], &[0, 0]);
    }

    #[test]
    fn nt_query_key_on_real_keys() {
        // Read-only: a key that exists on every Windows, and BFME's ergc key if
        // the game is installed (its value is never read or printed here).
        #[link(name = "advapi32")]
        extern "system" {
            fn RegOpenKeyExW(root: isize, sub: *const u16, opts: u32, sam: u32, out: *mut *mut c_void) -> i32;
            fn RegCloseKey(key: *mut c_void) -> i32;
        }
        const HKLM: isize = 0x8000_0002u32 as i32 as isize;
        const KEY_READ: u32 = 0x20019;
        const KEY_WOW64_32KEY: u32 = 0x0200;
        let open = |path: &str| {
            let p: Vec<u16> = path.encode_utf16().chain([0]).collect();
            let mut key = core::ptr::null_mut();
            // SAFETY: valid NUL-terminated path and out-parameter.
            let r = unsafe { RegOpenKeyExW(HKLM, p.as_ptr(), 0, KEY_READ | KEY_WOW64_32KEY, &mut key) };
            (r == 0).then_some(key)
        };
        let key = open(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion").expect("CurrentVersion key");
        assert!(!is_ergc_key(key));
        // SAFETY: open key handle.
        unsafe { RegCloseKey(key) };
        assert!(!is_ergc_key(HKLM as *mut c_void), "pseudo handles never match");
        assert!(!is_ergc_key(core::ptr::null_mut()));
        match open(ERGC_PATH) {
            Some(key) => {
                assert!(is_ergc_key(key));
                // SAFETY: open key handle.
                unsafe { RegCloseKey(key) };
            }
            None => eprintln!("BFME ergc key not present; skipped"),
        }
    }
}
