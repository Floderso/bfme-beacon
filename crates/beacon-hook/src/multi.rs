//! Test mode (`BEACON_MULTI=1`, architecture §4.4, spec 04 §3.2): two game
//! instances on one PC.
//!
//! * `CreateMutexW(L"E99E8455-CC9B-488a-BA22-0E8A8F74F9FA")` (single-instance guard)
//!   and `CreateMutexA("LOTRMilesAudioManagerMutex")` (Miles audio, shared
//!   system-wide) get a `-<PID>` suffix; every other mutex passes through.
//! * `SHGetSpecialFolderPathA/W(CSIDL_APPDATA)` returns `BEACON_USERDIR`, so each
//!   instance has its own `My Battle for Middle-earth Files` (Options.ini,
//!   Network.ini, replays, …). Other folders pass through.

use core::ffi::c_void;
use std::sync::atomic::AtomicUsize;
use std::sync::OnceLock;

use crate::config::{PATH_CAP, USERDIR_MAX};
use crate::ffi;
use crate::log::info;
use crate::wide::{self, WideBuf};

/// Original `KERNEL32!CreateMutexA`.
pub static ORIG_MUTEX_A: AtomicUsize = AtomicUsize::new(0);
/// Original `KERNEL32!CreateMutexW`.
pub static ORIG_MUTEX_W: AtomicUsize = AtomicUsize::new(0);
/// Original `SHELL32!SHGetSpecialFolderPathA`.
pub static ORIG_FOLDER_A: AtomicUsize = AtomicUsize::new(0);
/// Original `SHELL32!SHGetSpecialFolderPathW`.
pub static ORIG_FOLDER_W: AtomicUsize = AtomicUsize::new(0);

/// `CreateMutexA`.
pub type CreateMutexAFn = unsafe extern "system" fn(*mut c_void, ffi::BOOL, *const u8) -> ffi::HANDLE;
/// `CreateMutexW`.
pub type CreateMutexWFn = unsafe extern "system" fn(*mut c_void, ffi::BOOL, *const u16) -> ffi::HANDLE;
/// `SHGetSpecialFolderPathA`.
pub type FolderPathAFn = unsafe extern "system" fn(*mut c_void, *mut u8, i32, ffi::BOOL) -> ffi::BOOL;
/// `SHGetSpecialFolderPathW`.
pub type FolderPathWFn = unsafe extern "system" fn(*mut c_void, *mut u16, i32, ffi::BOOL) -> ffi::BOOL;

/// The game's single-instance mutex / window class name (spec 04 §3.1).
pub const APP_GUID: &str = "E99E8455-CC9B-488a-BA22-0E8A8F74F9FA";
const APP_GUID_W: [u16; 36] = wide::ascii_to_utf16(APP_GUID);
/// The Miles audio manager mutex (spec 04 §3.2 #2).
pub const MILES_MUTEX: &[u8] = b"LOTRMilesAudioManagerMutex";

const CSIDL_APPDATA: i32 = 0x001A;
const CSIDL_FLAG_MASK: i32 = 0xFF00;

/// The per-instance user-data base in both encodings.
struct UserDir {
    wide: WideBuf<PATH_CAP>,
    /// ANSI (`CP_ACP`) form, NUL-terminated; `None` if not representable.
    ansi: Option<([u8; PATH_CAP], usize)>,
}

static USERDIR: OnceLock<UserDir> = OnceLock::new();

/// Stores the user-data base (called from `DllMain` before the hooks are
/// installed). Returns `false` if the ANSI form is not representable (the A hook
/// then passes through).
pub fn set_userdir(dir: WideBuf<PATH_CAP>) -> bool {
    let ansi = to_ansi(&dir);
    let ok = ansi.is_some();
    let _ = USERDIR.set(UserDir { wide: dir, ansi });
    ok
}

fn to_ansi(dir: &WideBuf<PATH_CAP>) -> Option<([u8; PATH_CAP], usize)> {
    let mut out = [0u8; PATH_CAP];
    let mut lossy: ffi::BOOL = 0;
    let wide_len = i32::try_from(dir.len()).ok()?;
    let cap = i32::try_from(PATH_CAP - 1).ok()?;
    // SAFETY: `dir` is valid for `wide_len` units, `out` writable for `cap` bytes.
    let n = unsafe {
        ffi::WideCharToMultiByte(
            ffi::CP_ACP,
            ffi::WC_NO_BEST_FIT_CHARS,
            dir.as_ptr(),
            wide_len,
            out.as_mut_ptr(),
            cap,
            core::ptr::null(),
            &mut lossy,
        )
    };
    // Same bound as the wide form: the game appends its leaf folder and file
    // names to this in MAX_PATH buffers.
    let n = usize::try_from(n).ok().filter(|&n| n > 0 && n <= USERDIR_MAX)?;
    (lossy == 0).then_some((out, n))
}

/// `name` + `-` + PID, NUL-terminated (wide).
fn suffixed_w(name: &[u16]) -> Option<WideBuf<64>> {
    let mut out = WideBuf::<64>::from_slice(name)?;
    // SAFETY: no arguments.
    let pid = unsafe { ffi::GetCurrentProcessId() };
    (out.push_ascii("-") && out.push_decimal(pid)).then_some(out)
}

/// `name` + `-` + PID, NUL-terminated (ANSI).
fn suffixed_a(name: &[u8], pid: u32) -> Option<([u8; 64], usize)> {
    let mut out = [0u8; 64];
    let mut digits = [0u8; 10];
    let num = wide::format_decimal(pid, &mut digits);
    let len = name.len() + 1 + num.len();
    if len >= out.len() {
        return None;
    }
    out.get_mut(..name.len())?.copy_from_slice(name);
    *out.get_mut(name.len())? = b'-';
    out.get_mut(name.len() + 1..len)?.copy_from_slice(num);
    Some((out, len))
}


/// Hook for `KERNEL32!CreateMutexW`.
///
/// # Safety
/// `CreateMutexW`'s contract.
pub unsafe extern "system" fn hook_create_mutex_w(
    attrs: *mut c_void,
    initial_owner: ffi::BOOL,
    name: *const u16,
) -> ffi::HANDLE {
    // SAFETY: `CreateMutexWFn` is the signature of the import saved in `ORIG_MUTEX_W`.
    let Some(f) = (unsafe { crate::iat::load_fn::<CreateMutexWFn>(&ORIG_MUTEX_W) }) else {
        return core::ptr::null_mut();
    };
    // SAFETY: `name` is NULL or a NUL-terminated string (API contract).
    if unsafe { wide::wide_cstr_eq(name, &APP_GUID_W) } {
        if let Some(unique) = suffixed_w(&APP_GUID_W) {
            info!("CreateMutexW(single-instance guard) -> PID-suffixed name");
            // SAFETY: original function, valid NUL-terminated name.
            return unsafe { f(attrs, initial_owner, unique.as_ptr()) };
        }
    }
    // SAFETY: original function with the caller's arguments.
    unsafe { f(attrs, initial_owner, name) }
}

/// Hook for `KERNEL32!CreateMutexA`.
///
/// # Safety
/// `CreateMutexA`'s contract.
pub unsafe extern "system" fn hook_create_mutex_a(
    attrs: *mut c_void,
    initial_owner: ffi::BOOL,
    name: *const u8,
) -> ffi::HANDLE {
    // SAFETY: `CreateMutexAFn` is the signature of the import saved in `ORIG_MUTEX_A`.
    let Some(f) = (unsafe { crate::iat::load_fn::<CreateMutexAFn>(&ORIG_MUTEX_A) }) else {
        return core::ptr::null_mut();
    };
    // SAFETY: `name` is NULL or a NUL-terminated string (API contract).
    if unsafe { wide::ansi_cstr_eq(name, MILES_MUTEX) } {
        // SAFETY: no arguments.
        let pid = unsafe { ffi::GetCurrentProcessId() };
        if let Some((unique, _)) = suffixed_a(MILES_MUTEX, pid) {
            info!("CreateMutexA(LOTRMilesAudioManagerMutex) -> PID-suffixed name");
            // SAFETY: original function, valid NUL-terminated name.
            return unsafe { f(attrs, initial_owner, unique.as_ptr()) };
        }
    }
    // SAFETY: original function with the caller's arguments.
    unsafe { f(attrs, initial_owner, name) }
}

fn is_appdata(csidl: i32) -> bool {
    csidl & !CSIDL_FLAG_MASK == CSIDL_APPDATA
}

/// Hook for `SHELL32!SHGetSpecialFolderPathW`.
///
/// # Safety
/// `SHGetSpecialFolderPathW`'s contract (`path` holds `MAX_PATH` characters).
pub unsafe extern "system" fn hook_folder_path_w(
    hwnd: *mut c_void,
    path: *mut u16,
    csidl: i32,
    create: ffi::BOOL,
) -> ffi::BOOL {
    if let (Some(dir), false, true) = (USERDIR.get(), path.is_null(), is_appdata(csidl)) {
        // SAFETY: `path` holds MAX_PATH (260) characters; the validated dir is at
        // most USERDIR_MAX (200) characters plus terminator.
        unsafe { core::ptr::copy_nonoverlapping(dir.wide.as_ptr(), path, dir.wide.len() + 1) };
        if create != 0 {
            // SAFETY: NUL-terminated path; failure (already exists) is fine.
            unsafe { ffi::CreateDirectoryW(dir.wide.as_ptr(), core::ptr::null_mut()) };
        }
        info!("SHGetSpecialFolderPathW(CSIDL_APPDATA) -> BEACON_USERDIR");
        return 1;
    }
    // SAFETY: `FolderPathWFn` is the signature of the import saved in `ORIG_FOLDER_W`.
    match unsafe { crate::iat::load_fn::<FolderPathWFn>(&ORIG_FOLDER_W) } {
        // SAFETY: original function with the caller's arguments.
        Some(f) => unsafe { f(hwnd, path, csidl, create) },
        None => 0,
    }
}

/// Hook for `SHELL32!SHGetSpecialFolderPathA`.
///
/// # Safety
/// `SHGetSpecialFolderPathA`'s contract (`path` holds `MAX_PATH` bytes).
pub unsafe extern "system" fn hook_folder_path_a(
    hwnd: *mut c_void,
    path: *mut u8,
    csidl: i32,
    create: ffi::BOOL,
) -> ffi::BOOL {
    if let (Some(dir), false, true) = (USERDIR.get(), path.is_null(), is_appdata(csidl)) {
        if let Some((ansi, len)) = &dir.ansi {
            // SAFETY: `path` holds MAX_PATH bytes; `len <= USERDIR_MAX` (200), so the
            // string and its terminator fit.
            unsafe { core::ptr::copy_nonoverlapping(ansi.as_ptr(), path, *len + 1) };
            if create != 0 {
                // SAFETY: NUL-terminated path.
                unsafe { ffi::CreateDirectoryW(dir.wide.as_ptr(), core::ptr::null_mut()) };
            }
            info!("SHGetSpecialFolderPathA(CSIDL_APPDATA) -> BEACON_USERDIR");
            return 1;
        }
    }
    // SAFETY: `FolderPathAFn` is the signature of the import saved in `ORIG_FOLDER_A`.
    match unsafe { crate::iat::load_fn::<FolderPathAFn>(&ORIG_FOLDER_A) } {
        // SAFETY: original function with the caller's arguments.
        Some(f) => unsafe { f(hwnd, path, csidl, create) },
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutex_names() {
        let (n, len) = suffixed_a(MILES_MUTEX, 4242).unwrap();
        assert_eq!(&n[..=len], b"LOTRMilesAudioManagerMutex-4242\0");
        let (_, len) = suffixed_a(MILES_MUTEX, u32::MAX).unwrap();
        assert_eq!(len, MILES_MUTEX.len() + 11);
        let w = suffixed_w(&APP_GUID_W).unwrap();
        let s = String::from_utf16(w.as_slice()).unwrap();
        assert!(s.starts_with("E99E8455-CC9B-488a-BA22-0E8A8F74F9FA-"));
        assert!(s.len() > APP_GUID.len() + 1);
        assert_eq!(String::from_utf16(&APP_GUID_W).unwrap(), APP_GUID);
    }

    #[test]
    fn appdata_matching() {
        assert!(is_appdata(0x1A));
        assert!(is_appdata(0x801A)); // CSIDL_FLAG_CREATE
        assert!(!is_appdata(0x1C)); // CSIDL_LOCAL_APPDATA
        assert!(!is_appdata(0x05)); // CSIDL_PERSONAL
    }

    #[test]
    fn ansi_conversion() {
        let dir: Vec<u16> = r"C:\Beacon\instance-2".encode_utf16().collect();
        let (out, n) = to_ansi(&WideBuf::from_slice(&dir).unwrap()).unwrap();
        assert_eq!(&out[..=n], b"C:\\Beacon\\instance-2\0");
        // A character no ANSI code page has (U+4E2D with Latin code pages; on CJK
        // systems it converts, so only check it does not panic).
        let odd: Vec<u16> = "C:\\x\u{4E2D}\u{0300}".encode_utf16().collect();
        let _ = to_ansi(&WideBuf::from_slice(&odd).unwrap());
    }
}
