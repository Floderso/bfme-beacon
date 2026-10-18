//! Win32 implementation of the platform layer. Every `unsafe` block of the launcher
//! is in this file or in `tray.rs`; each one documents why its pointers are valid.

#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash, BCryptHashData, CryptProtectData,
    CryptUnprotectData, BCRYPT_HASH_HANDLE, BCRYPT_SHA256_ALG_HANDLE, CRYPTPROTECT_UI_FORBIDDEN,
    CRYPT_INTEGER_BLOB,
};
use windows_sys::Win32::Storage::FileSystem::{GetFileType, FILE_TYPE_UNKNOWN};
use windows_sys::Win32::System::Console::{
    AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Com::{
    CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
};
use windows_sys::Win32::System::Registry::{
    RegGetValueW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
    RRF_SUBKEY_WOW6432KEY,
};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, MB_ICONERROR, MB_OK, MB_SETFOREGROUND, SW_SHOWNORMAL,
};

use super::{Hive, SHA256_LEN};

/// Description stored (unencrypted) inside DPAPI blobs.
const DPAPI_DESCRIPTION: &str = "BFME Beacon server key";
/// Largest registry string the launcher reads (bytes).
const REG_STRING_MAX: u32 = 64 * 1024;

/// NUL-terminated UTF-16 of `s`.
pub(super) fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn too_large() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "data too large")
}

/// Copies a blob returned by DPAPI, wipes and frees the system buffer.
fn take_blob(blob: &CRYPT_INTEGER_BLOB) -> Vec<u8> {
    if blob.pbData.is_null() {
        return Vec::new();
    }
    let len = usize::try_from(blob.cbData).unwrap_or(0);
    // SAFETY: on success `CryptProtectData`/`CryptUnprotectData` return `cbData`
    // readable bytes at `pbData`, allocated with `LocalAlloc`; the buffer is not
    // used after `LocalFree`.
    unsafe {
        let data = std::slice::from_raw_parts(blob.pbData, len).to_vec();
        ptr::write_bytes(blob.pbData, 0, len);
        LocalFree(blob.pbData.cast());
        data
    }
}

/// Encrypts `data` with DPAPI for the current user (`CryptProtectData`, no UI).
pub fn dpapi_protect(data: &[u8]) -> io::Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| too_large())?,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let description = wide(DPAPI_DESCRIPTION);
    // SAFETY: `input` describes `data` (only read by the call), `description` is
    // NUL-terminated, the optional pointers are null, `output` is writable.
    let ok = unsafe {
        CryptProtectData(
            &input,
            description.as_ptr(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(take_blob(&output))
}

/// Decrypts a DPAPI blob of the current user. Fails for blobs of other users or
/// machines and for modified blobs.
pub fn dpapi_unprotect(blob: &[u8]) -> io::Result<Vec<u8>> {
    if blob.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty DPAPI blob"));
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(blob.len()).map_err(|_| too_large())?,
        pbData: blob.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    // SAFETY: `input` describes `blob` (only read), no description is requested,
    // the optional pointers are null, `output` is writable.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(take_blob(&output))
}

fn nt_check(status: i32, what: &str) -> io::Result<()> {
    if status >= 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!("{what} failed (NTSTATUS {status:#010x})")))
    }
}

/// A CNG SHA-256 hash object, destroyed on drop.
struct HashHandle(BCRYPT_HASH_HANDLE);

impl Drop for HashHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful `BCryptCreateHash` and is
        // destroyed exactly once.
        unsafe {
            BCryptDestroyHash(self.0);
        }
    }
}

/// SHA-256 of a file's content (CNG, streamed in 1 MiB pieces).
pub fn sha256_file(path: &Path) -> io::Result<[u8; SHA256_LEN]> {
    let mut file = File::open(path)?;
    let mut handle: BCRYPT_HASH_HANDLE = ptr::null_mut();
    // SAFETY: the SHA-256 pseudo handle is valid on Windows 10+; CNG allocates the
    // hash object itself (null buffer, length 0); no secret.
    let status = unsafe {
        BCryptCreateHash(
            BCRYPT_SHA256_ALG_HANDLE,
            &mut handle,
            ptr::null_mut(),
            0,
            ptr::null(),
            0,
            0,
        )
    };
    nt_check(status, "BCryptCreateHash")?;
    let hash = HashHandle(handle);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let chunk = buf.get(..n).unwrap_or_default();
        let len = u32::try_from(chunk.len()).map_err(|_| too_large())?;
        // SAFETY: `chunk` is `len` readable bytes; `hash.0` is a live hash handle.
        let status = unsafe { BCryptHashData(hash.0, chunk.as_ptr(), len, 0) };
        nt_check(status, "BCryptHashData")?;
    }
    let mut digest = [0u8; SHA256_LEN];
    // SAFETY: `digest` is exactly the SHA-256 output length; `hash.0` is live.
    let status = unsafe { BCryptFinishHash(hash.0, digest.as_mut_ptr(), SHA256_LEN as u32, 0) };
    nt_check(status, "BCryptFinishHash")?;
    Ok(digest)
}

fn hive_key(hive: Hive) -> HKEY {
    match hive {
        Hive::LocalMachine => HKEY_LOCAL_MACHINE,
        Hive::CurrentUser => HKEY_CURRENT_USER,
    }
}

/// A `REG_SZ` value (`value` = `""` for the default value), read through the 32-bit
/// registry view like the 32-bit game does. `None` if absent, of another type or
/// unreadable.
pub fn reg_string(hive: Hive, subkey: &str, value: &str) -> Option<String> {
    let subkey_w = wide(subkey);
    let value_w = wide(value);
    let flags = RRF_RT_REG_SZ | RRF_SUBKEY_WOW6432KEY;
    let mut size: u32 = 0;
    // SAFETY: both names are NUL-terminated; a null data pointer asks for the size.
    let rc = unsafe {
        RegGetValueW(
            hive_key(hive),
            subkey_w.as_ptr(),
            value_w.as_ptr(),
            flags,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut size,
        )
    };
    if rc != 0 || size == 0 || size > REG_STRING_MAX {
        return None;
    }
    // Room for a value that grows between the two calls is not needed: a larger
    // value fails the second call (ERROR_MORE_DATA) and reads as absent.
    let mut buf = vec![0u16; usize::try_from(size.div_ceil(2)).ok()?];
    let mut len_bytes = u32::try_from(buf.len() * 2).ok()?;
    // SAFETY: `buf` has `len_bytes` writable bytes; names are NUL-terminated.
    let rc = unsafe {
        RegGetValueW(
            hive_key(hive),
            subkey_w.as_ptr(),
            value_w.as_ptr(),
            flags,
            ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len_bytes,
        )
    };
    if rc != 0 {
        return None;
    }
    let units = usize::try_from(len_bytes / 2).ok()?.min(buf.len());
    let text = buf.get(..units)?;
    let end = text.iter().position(|&c| c == 0).unwrap_or(text.len());
    Some(String::from_utf16_lossy(text.get(..end)?))
}

/// A `REG_DWORD` value through the 32-bit registry view; `None` if absent.
pub fn reg_dword(hive: Hive, subkey: &str, value: &str) -> Option<u32> {
    let subkey_w = wide(subkey);
    let value_w = wide(value);
    let mut data: u32 = 0;
    let mut size: u32 = 4;
    // SAFETY: `data` is 4 writable bytes; names are NUL-terminated.
    let rc = unsafe {
        RegGetValueW(
            hive_key(hive),
            subkey_w.as_ptr(),
            value_w.as_ptr(),
            RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6432KEY,
            ptr::null_mut(),
            (&mut data as *mut u32).cast(),
            &mut size,
        )
    };
    (rc == 0 && size == 4).then_some(data)
}

/// A named Win32 mutex (only used as an existence marker; never waited on).
#[derive(Debug)]
pub struct NamedMutex(HANDLE);

// SAFETY: a kernel object handle may be used and closed from any thread.
unsafe impl Send for NamedMutex {}
// SAFETY: the handle is never mutated after creation.
unsafe impl Sync for NamedMutex {}

impl NamedMutex {
    /// Creates (or opens) the mutex; the flag is `true` if it already existed,
    /// i.e. another process holds it.
    pub fn create(name: &str) -> io::Result<(Self, bool)> {
        let name_w = wide(name);
        // SAFETY: default security, not initially owned, NUL-terminated name.
        let handle = unsafe { CreateMutexW(ptr::null(), 0, name_w.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: reads the calling thread's last-error value set by CreateMutexW.
        let existed = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        Ok((Self(handle), existed))
    }
}

impl Drop for NamedMutex {
    fn drop(&mut self) {
        // SAFETY: the handle came from CreateMutexW and is closed exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// `true` for a standard handle that can be used (pipe, file or console).
fn usable(handle: HANDLE) -> bool {
    // SAFETY: GetFileType accepts any handle value and only reads its type.
    !handle.is_null() && handle != INVALID_HANDLE_VALUE && unsafe { GetFileType(handle) } != FILE_TYPE_UNKNOWN
}

/// For the CLI modes of the GUI-subsystem release build: attaches to the parent
/// process's console (if it has one), so that output appears in `cmd`/PowerShell
/// and Ctrl+C in that console reaches the process. Standard handles that were
/// already usable (pipes or files, e.g. started from Git Bash/mintty or with
/// redirected output) are kept. Returns `true` if it attached.
pub fn attach_parent_console() -> bool {
    const IDS: [u32; 3] = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];
    // SAFETY: plain calls with handle values and constants; no pointers.
    unsafe {
        let saved = IDS.map(|id| (id, GetStdHandle(id)));
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            return false;
        }
        for (id, handle) in saved {
            if usable(handle) {
                SetStdHandle(id, handle);
            }
        }
        true
    }
}

/// Opens `target` with its default handler (`ShellExecuteW`, verb "open") on a
/// short-lived thread that initialises COM as the shell requires; returns once the
/// shell has handed it over (the browser or Explorer may still be starting).
fn shell_open(target: &OsStr) -> io::Result<()> {
    if target.is_empty() || target.encode_wide().any(|c| c == 0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty target or NUL in it"));
    }
    let file: Vec<u16> = target.encode_wide().chain(Some(0)).collect();
    let verb = wide("open");
    let worker = std::thread::Builder::new()
        .name("beacon-shell".into())
        .spawn(move || {
            // SAFETY: COM is initialised for this thread only and released below;
            // `verb` and `file` are NUL-terminated UTF-16 strings that live across
            // the call; null window/parameters/directory are allowed.
            unsafe {
                let hr = CoInitializeEx(ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32);
                let result = ShellExecuteW(
                    ptr::null_mut(),
                    verb.as_ptr(),
                    file.as_ptr(),
                    ptr::null(),
                    ptr::null(),
                    SW_SHOWNORMAL,
                );
                if hr >= 0 {
                    CoUninitialize();
                }
                result as isize
            }
        })?;
    let code = worker
        .join()
        .map_err(|_| io::Error::other("the shell thread failed"))?;
    // ShellExecuteW: values above 32 mean success.
    if code > 32 {
        Ok(())
    } else {
        Err(io::Error::other(format!("ShellExecuteW failed (code {code})")))
    }
}

/// Opens an `http://` or `https://` URL in the default browser.
pub fn open_url(url: &str) -> io::Result<()> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "only http(s) URLs are opened"));
    }
    shell_open(OsStr::new(url))
}

/// Shows a folder in Explorer.
pub fn open_folder(path: &Path) -> io::Result<()> {
    if !path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} is not a folder", path.display()),
        ));
    }
    shell_open(path.as_os_str())
}

/// Shows a modal error box (for fatal start-up errors of the GUI-subsystem exe,
/// which has no console). Blocks until the user closes it.
pub fn message_box(title: &str, text: &str) {
    let title = wide(&title.replace('\0', " "));
    let text = wide(&text.replace('\0', " "));
    // SAFETY: both strings are NUL-terminated UTF-16 without inner NULs that live
    // across the call; a null owner window is allowed.
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND,
        );
    }
}
