//! Exe mode in a live process, without the game. The `exe-mode` scenario starts an
//! identical copy of this harness exe **suspended**, next to a copy of the hook DLL
//! named `wsock32.dll`, and — before the child's loader runs — gives its in-memory
//! image the identity the hook checks for `lotrbfme.exe` 1.03 (spec 03 §8.4,
//! `beacon-hook/src/pe.rs`):
//!
//! * two committed pages at RVA 0x00F58000 hold a new import directory: `WS2_32.dll`
//!   with `FirstThunk` 0x00F58CB0 importing exactly `WSAIoctl, getsockopt, recv,
//!   recvfrom, setsockopt` (in this order), `WSOCK32.dll` (`WSAStartup`, so the
//!   loader loads the proxy from the exe folder like in the game folder),
//!   `ADVAPI32.dll` (`RegQueryValueExA/W`), `KERNEL32.dll` (`CreateMutexA/W`),
//!   `SHELL32.dll` (`SHGetSpecialFolderPathA/W`), then the original descriptors;
//!   the IATs hold hint/name RVAs like in a file;
//! * the header's `TimeDateStamp`, `SizeOfImage` and import directory entry are
//!   patched.
//!
//! When resumed, the real loader snaps those IATs, loads the proxy and runs its
//! `DllMain` at process start — the game's situation — and `exe-inner` then calls
//! through the patched IAT slots exactly like the game: the WS2_32 hooks
//! (`recvfrom`/`recv` virtualisation, `getsockopt`/`setsockopt`/`WSAIoctl`
//! chaining), `RegQueryValueExA/W` (ergc → `BEACON_SERIAL`), `CreateMutexA/W` (PID
//! suffix) and `SHGetSpecialFolderPathA/W` (`BEACON_USERDIR`). (A rewritten exe
//! file would be simpler, but Smart App Control blocks generated executables; an
//! identical copy runs.)
//!
//! Variants exercise the first-`WSAStartup` re-verification by changing the
//! `recvfrom` slot before the first `WSAStartup`: `resnap` (the loader's original
//! again → patched again), `chained` (another module's hook in front of ours → left
//! alone, still virtualised) and `bypass` (another module's hook that never reaches
//! ours → the hook disarms and stays passive).

use core::ffi::c_void;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::sleep;
use std::time::Duration;

use beacon_proto::local::{FrameType, HookFrame};

use crate::agent::Agent;
use crate::scenarios::{expect_frame, read_log, Checks, Scratch, SERIAL, TOKEN, TOKEN_TEXT, VIP};
use crate::win::{self, Module, SockAddrIn, Ws};

/// `IMAGE_FILE_HEADER.TimeDateStamp` of `lotrbfme.exe` 1.03.
const TIMESTAMP: u32 = 0x438B_ABC8;
/// `SizeOfImage` of `lotrbfme.exe` 1.03.
const SIZE_OF_IMAGE: u32 = 0x0101_6000;
/// RVA of the import block (two committed pages).
const IMPORT_RVA: u32 = 0x00F5_8000;
const IMPORT_BLOCK: usize = 0x2000;
/// `FirstThunk` of the `WS2_32.dll` descriptor (as in the game).
const WS2_FT: u32 = 0x00F5_8CB0;
/// IAT of `ADVAPI32.dll`: `RegQueryValueExA`, `RegQueryValueExW`.
const ADVAPI_FT: u32 = 0x00F5_8D00;
/// IAT of `KERNEL32.dll`: `CreateMutexA`, `CreateMutexW`.
const KERNEL_FT: u32 = 0x00F5_8D10;
/// IAT of `SHELL32.dll`: `SHGetSpecialFolderPathA`, `SHGetSpecialFolderPathW`.
const SHELL_FT: u32 = 0x00F5_8D20;
/// IAT of `WSOCK32.dll`: `WSAStartup`.
const WSOCK_FT: u32 = 0x00F5_8D30;
/// Start of the names and lookup tables (after the fixed IATs).
const DATA_START: u32 = 0x00F5_8D80;
const WS2_NAMES: [&str; 5] = ["WSAIoctl", "getsockopt", "recv", "recvfrom", "setsockopt"];

struct Import {
    dll: &'static str,
    ft: u32,
    names: &'static [&'static str],
}

const IMPORTS: [Import; 5] = [
    Import { dll: "WS2_32.dll", ft: WS2_FT, names: &WS2_NAMES },
    Import { dll: "WSOCK32.dll", ft: WSOCK_FT, names: &["WSAStartup"] },
    Import { dll: "ADVAPI32.dll", ft: ADVAPI_FT, names: &["RegQueryValueExA", "RegQueryValueExW"] },
    Import { dll: "KERNEL32.dll", ft: KERNEL_FT, names: &["CreateMutexA", "CreateMutexW"] },
    Import { dll: "SHELL32.dll", ft: SHELL_FT, names: &["SHGetSpecialFolderPathA", "SHGetSpecialFolderPathW"] },
];

const HKEY_LOCAL_MACHINE: usize = 0x8000_0002;
const KEY_READ: u32 = 0x0002_0019;
const SYNCHRONIZE: u32 = 0x0010_0000;
const ERROR_MORE_DATA: i32 = 234;
const ERROR_ALREADY_EXISTS: u32 = 183;
const REG_SZ: u32 = 1;
const CSIDL_APPDATA: i32 = 0x1A;
const CSIDL_FLAG_CREATE: i32 = 0x8000;
const CSIDL_LOCAL_APPDATA: i32 = 0x1C;
const PAGE_READWRITE: u32 = 0x04;
const MEM_COMMIT_RESERVE: u32 = 0x3000;
const CREATE_SUSPENDED: u32 = 0x4;
const STARTF_USESTDHANDLES: u32 = 0x100;
const HANDLE_FLAG_INHERIT: u32 = 0x1;
const STD_INPUT_HANDLE: u32 = -10i32 as u32;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
const STD_ERROR_HANDLE: u32 = -12i32 as u32;
const WAIT_TIMEOUT: u32 = 0x102;
/// Smart App Control / WDAC: "An Application Control policy has blocked this file".
const ERROR_APP_CONTROL_BLOCKED: u32 = 4551;
const ERGC: &str = "SOFTWARE\\Electronic Arts\\EA Games\\The Battle for Middle-earth\\ergc";
const APP_GUID: &str = "E99E8455-CC9B-488a-BA22-0E8A8F74F9FA";
const MILES_MUTEX: &str = "LOTRMilesAudioManagerMutex";
const VARIANTS: [&str; 4] = ["plain", "resnap", "chained", "bypass"];

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    reserved2_len: u16,
    reserved2: *mut u8,
    std_input: *mut c_void,
    std_output: *mut c_void,
    std_error: *mut c_void,
}

#[repr(C)]
struct ProcessInformation {
    process: *mut c_void,
    thread: *mut c_void,
    process_id: u32,
    thread_id: u32,
}

#[repr(C)]
#[derive(Default)]
struct ProcessBasicInformation {
    exit_status: i32,
    peb: usize,
    affinity: usize,
    base_priority: i32,
    pid: usize,
    parent_pid: usize,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    fn GetModuleFileNameW(module: *mut c_void, buf: *mut u16, len: u32) -> u32;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn VirtualProtect(addr: *mut c_void, size: usize, new: u32, old: *mut u32) -> i32;
    fn OpenMutexA(access: u32, inherit: i32, name: *const u8) -> *mut c_void;
    fn OpenMutexW(access: u32, inherit: i32, name: *const u16) -> *mut c_void;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn GetLastError() -> u32;
    fn GetStdHandle(which: u32) -> *mut c_void;
    fn SetHandleInformation(h: *mut c_void, mask: u32, flags: u32) -> i32;
    fn CreateProcessW(
        app: *const u16,
        cmdline: *mut u16,
        process_attrs: *mut c_void,
        thread_attrs: *mut c_void,
        inherit: i32,
        flags: u32,
        env: *mut c_void,
        cwd: *const u16,
        startup: *const StartupInfoW,
        info: *mut ProcessInformation,
    ) -> i32;
    fn ResumeThread(thread: *mut c_void) -> u32;
    fn WaitForSingleObject(h: *mut c_void, ms: u32) -> u32;
    fn GetExitCodeProcess(h: *mut c_void, code: *mut u32) -> i32;
    fn TerminateProcess(h: *mut c_void, code: u32) -> i32;
    fn VirtualAllocEx(process: *mut c_void, addr: *mut c_void, size: usize, kind: u32, protect: u32) -> *mut c_void;
    fn VirtualProtectEx(process: *mut c_void, addr: *mut c_void, size: usize, new: u32, old: *mut u32) -> i32;
    fn ReadProcessMemory(process: *mut c_void, addr: *const c_void, buf: *mut c_void, len: usize, done: *mut usize)
        -> i32;
    fn WriteProcessMemory(process: *mut c_void, addr: *mut c_void, buf: *const c_void, len: usize, done: *mut usize)
        -> i32;
}

#[repr(C)]
#[derive(Default)]
struct MemoryBasicInformation {
    base: usize,
    allocation_base: usize,
    allocation_protect: u32,
    region_size: usize,
    state: u32,
    protect: u32,
    kind: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn VirtualQueryEx(process: *mut c_void, addr: *const c_void, info: *mut c_void, len: usize) -> usize;
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(process: *mut c_void, class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
}

#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExA(key: usize, sub: *const u8, options: u32, sam: u32, out: *mut usize) -> i32;
    fn RegCloseKey(key: usize) -> i32;
}

#[link(name = "ws2_32")]
extern "system" {
    #[link_name = "recvfrom"]
    fn ws2_recvfrom(s: usize, buf: *mut u8, len: i32, flags: i32, from: *mut SockAddrIn, fromlen: *mut i32) -> i32;
}

type StartupFn = unsafe extern "system" fn(u16, *mut c_void) -> i32;
type WsaIoctlFn =
    unsafe extern "system" fn(usize, u32, *mut c_void, u32, *mut c_void, u32, *mut u32, *mut c_void, *mut c_void) -> i32;
type GetOptFn = unsafe extern "system" fn(usize, i32, i32, *mut u8, *mut i32) -> i32;
type RecvFn = unsafe extern "system" fn(usize, *mut u8, i32, i32) -> i32;
type RecvFromFn = unsafe extern "system" fn(usize, *mut u8, i32, i32, *mut SockAddrIn, *mut i32) -> i32;
type SetOptFn = unsafe extern "system" fn(usize, i32, i32, *const u8, i32) -> i32;
type RegQueryAFn = unsafe extern "system" fn(usize, *const u8, *mut u32, *mut u32, *mut u8, *mut u32) -> i32;
type RegQueryWFn = unsafe extern "system" fn(usize, *const u16, *mut u32, *mut u32, *mut u8, *mut u32) -> i32;
type CreateMutexAFn = unsafe extern "system" fn(*mut c_void, i32, *const u8) -> *mut c_void;
type CreateMutexWFn = unsafe extern "system" fn(*mut c_void, i32, *const u16) -> *mut c_void;
type FolderAFn = unsafe extern "system" fn(*mut c_void, *mut u8, i32, i32) -> i32;
type FolderWFn = unsafe extern "system" fn(*mut c_void, *mut u16, i32, i32) -> i32;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn cstr(s: &str) -> Vec<u8> {
    s.bytes().chain([0]).collect()
}

fn le32(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| format!("header read at {at:#x} out of bounds"))
}

/// The import block placed at [`IMPORT_RVA`]: our descriptors, then `original`;
/// the IATs hold hint/name RVAs (unsnapped, as in a file). Returns the block and
/// the size of the descriptor array.
fn import_block(original: &[[u8; 20]]) -> Result<(Vec<u8>, u32), String> {
    let mut sec = vec![0u8; (DATA_START - IMPORT_RVA) as usize];
    let push = |sec: &mut Vec<u8>, bytes: &[u8]| -> u32 {
        while !sec.len().is_multiple_of(4) {
            sec.push(0);
        }
        let rva = IMPORT_RVA + sec.len() as u32;
        sec.extend_from_slice(bytes);
        rva
    };
    let mut descriptors = Vec::new();
    for imp in &IMPORTS {
        let dll_rva = push(&mut sec, &cstr(imp.dll));
        let mut table = Vec::new();
        for name in imp.names {
            let mut entry = vec![0u8, 0u8];
            entry.extend_from_slice(&cstr(name));
            table.extend_from_slice(&push(&mut sec, &entry).to_le_bytes());
        }
        table.extend_from_slice(&[0; 4]);
        let oft = push(&mut sec, &table);
        let ft = (imp.ft - IMPORT_RVA) as usize;
        sec.get_mut(ft..ft + table.len()).ok_or("IAT outside the block")?.copy_from_slice(&table);
        let mut d = [0u8; 20];
        d[0..4].copy_from_slice(&oft.to_le_bytes());
        d[12..16].copy_from_slice(&dll_rva.to_le_bytes());
        d[16..20].copy_from_slice(&imp.ft.to_le_bytes());
        descriptors.push(d);
    }
    descriptors.extend_from_slice(original);
    descriptors.push([0; 20]);
    if descriptors.len() * 20 > (WS2_FT - IMPORT_RVA) as usize || sec.len() > IMPORT_BLOCK {
        return Err("import block does not fit".into());
    }
    for (i, d) in descriptors.iter().enumerate() {
        sec[i * 20..(i + 1) * 20].copy_from_slice(d);
    }
    Ok((sec, (descriptors.len() * 20) as u32))
}

/// A child process created suspended; terminated on drop unless it finished.
struct Child {
    info: ProcessInformation,
    finished: bool,
}

impl Drop for Child {
    fn drop(&mut self) {
        // SAFETY: handles from CreateProcessW, closed once.
        unsafe {
            if !self.finished {
                TerminateProcess(self.info.process, 1);
            }
            CloseHandle(self.info.thread);
            CloseHandle(self.info.process);
        }
    }
}

impl Child {
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<(), String> {
        let mut done = 0usize;
        // SAFETY: `buf` is writable for its length.
        let ok = unsafe {
            ReadProcessMemory(self.info.process, addr as *const c_void, buf.as_mut_ptr().cast(), buf.len(), &mut done)
        };
        (ok != 0 && done == buf.len()).then_some(()).ok_or_else(|| format!("ReadProcessMemory({addr:#x}) failed"))
    }

    fn write(&self, addr: usize, buf: &[u8]) -> Result<(), String> {
        let mut done = 0usize;
        // SAFETY: `buf` is readable for its length.
        let ok = unsafe {
            WriteProcessMemory(self.info.process, addr as *mut c_void, buf.as_ptr().cast(), buf.len(), &mut done)
        };
        (ok != 0 && done == buf.len()).then_some(()).ok_or_else(|| format!("WriteProcessMemory({addr:#x}) failed"))
    }

    /// `ImageBaseAddress` from the child's (32-bit) PEB.
    fn image_base(&self) -> Result<usize, String> {
        let mut pbi = ProcessBasicInformation::default();
        let len = core::mem::size_of::<ProcessBasicInformation>() as u32;
        // SAFETY: valid out-buffer of `len` bytes.
        let status = unsafe {
            NtQueryInformationProcess(self.info.process, 0, core::ptr::addr_of_mut!(pbi).cast(), len, core::ptr::null_mut())
        };
        if status < 0 || pbi.peb == 0 {
            return Err(format!("NtQueryInformationProcess: {status:#x}"));
        }
        let mut base = [0u8; 4];
        self.read(pbi.peb + 8, &mut base)?;
        Ok(u32::from_le_bytes(base) as usize)
    }

    /// Gives the not-yet-initialised image the game's identity (module docs).
    fn give_identity(&self) -> Result<(), String> {
        let base = self.image_base()?;
        let mut hdr = vec![0u8; 0x1000];
        self.read(base, &mut hdr)?;
        let nt = le32(&hdr, 0x3C)? as usize;
        let fh = nt + 4;
        let opt = fh + 20;
        let import_rva = le32(&hdr, opt + 104)? as usize;
        let mut raw = vec![0u8; 64 * 20];
        self.read(base + import_rva, &mut raw)?;
        let original: Vec<[u8; 20]> = raw
            .as_chunks::<20>()
            .0
            .iter()
            .copied()
            .take_while(|d| *d != [0u8; 20])
            .collect();
        let (block, dir_len) = import_block(&original)?;
        let at = base + IMPORT_RVA as usize;
        // Reservations start on the 64 KiB allocation granularity.
        let start = at & !0xFFFF;
        let size = at + IMPORT_BLOCK - start;
        // SAFETY: allocation request in the child at a fixed address.
        let got =
            unsafe { VirtualAllocEx(self.info.process, start as *mut c_void, size, MEM_COMMIT_RESERVE, PAGE_READWRITE) };
        if got as usize != start {
            let mut mbi = MemoryBasicInformation::default();
            // SAFETY: valid out-buffer.
            unsafe {
                VirtualQueryEx(
                    self.info.process,
                    at as *const c_void,
                    core::ptr::addr_of_mut!(mbi).cast(),
                    core::mem::size_of::<MemoryBasicInformation>(),
                )
            };
            return Err(format!(
                "address {at:#x} (image + {IMPORT_RVA:#x}) is not free in the child: allocation base {:#x}, \
                 region {:#x}+{:#x}, state {:#x}, type {:#x}",
                mbi.allocation_base, mbi.base, mbi.region_size, mbi.state, mbi.kind
            ));
        }
        self.write(at, &block)?;
        let mut old = 0u32;
        // SAFETY: the child's header page.
        if unsafe { VirtualProtectEx(self.info.process, base as *mut c_void, 0x1000, PAGE_READWRITE, &mut old) } == 0 {
            return Err("VirtualProtectEx(headers)".into());
        }
        self.write(base + fh + 4, &TIMESTAMP.to_le_bytes())?;
        self.write(base + opt + 56, &SIZE_OF_IMAGE.to_le_bytes())?;
        self.write(base + opt + 104, &IMPORT_RVA.to_le_bytes())?;
        self.write(base + opt + 108, &dir_len.to_le_bytes())?;
        if le32(&hdr, opt + 92)? > 11 {
            self.write(base + opt + 184, &[0; 8])?; // no bound imports
        }
        // SAFETY: as above.
        unsafe { VirtualProtectEx(self.info.process, base as *mut c_void, 0x1000, old, &mut old) };
        Ok(())
    }
}

enum Launch {
    /// Exit code of the child.
    Exited(u32),
    /// Smart App Control refused to start the copy.
    Blocked,
    /// The identity could not be prepared (environmental, e.g. address in use).
    NoIdentity(String),
}

/// Starts `exe` suspended, prepares its identity, runs it to completion.
fn launch(exe: &Path, dll: &Path) -> Result<Launch, String> {
    let mut cmdline = wide(&format!("\"{}\" --child exe-inner --dll \"{}\"", exe.display(), dll.display()));
    // SAFETY: plain values; the std handles are handed down to the child.
    let handles = unsafe { [GetStdHandle(STD_INPUT_HANDLE), GetStdHandle(STD_OUTPUT_HANDLE), GetStdHandle(STD_ERROR_HANDLE)] };
    for h in handles {
        // SAFETY: one of our std handles (or null, which simply fails).
        unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) };
    }
    let [std_input, std_output, std_error] = handles;
    let startup = StartupInfoW {
        cb: core::mem::size_of::<StartupInfoW>() as u32,
        reserved: core::ptr::null_mut(),
        desktop: core::ptr::null_mut(),
        title: core::ptr::null_mut(),
        x: 0,
        y: 0,
        x_size: 0,
        y_size: 0,
        x_count_chars: 0,
        y_count_chars: 0,
        fill_attribute: 0,
        flags: STARTF_USESTDHANDLES,
        show_window: 0,
        reserved2_len: 0,
        reserved2: core::ptr::null_mut(),
        std_input,
        std_output,
        std_error,
    };
    let mut info =
        ProcessInformation { process: core::ptr::null_mut(), thread: core::ptr::null_mut(), process_id: 0, thread_id: 0 };
    // SAFETY: mutable NUL-terminated command line and valid structures; the
    // environment (with the BEACON_* variables) is inherited.
    let ok = unsafe {
        CreateProcessW(
            core::ptr::null(),
            cmdline.as_mut_ptr(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            1,
            CREATE_SUSPENDED,
            core::ptr::null_mut(),
            core::ptr::null(),
            &startup,
            &mut info,
        )
    };
    if ok == 0 {
        // SAFETY: no arguments.
        let err = unsafe { GetLastError() };
        return if err == ERROR_APP_CONTROL_BLOCKED { Ok(Launch::Blocked) } else { Err(format!("CreateProcessW: error {err}")) };
    }
    let mut child = Child { info, finished: false };
    if let Err(e) = child.give_identity() {
        return Ok(Launch::NoIdentity(e));
    }
    // SAFETY: the child's main thread.
    unsafe { ResumeThread(child.info.thread) };
    // SAFETY: the child's process handle.
    if unsafe { WaitForSingleObject(child.info.process, 120_000) } == WAIT_TIMEOUT {
        return Err("child did not finish within 120 s".into());
    }
    let mut code = 0u32;
    // SAFETY: as above.
    unsafe { GetExitCodeProcess(child.info.process, &mut code) };
    child.finished = true;
    Ok(Launch::Exited(code))
}

/// `exe-mode`: runs `exe-inner` in an identity copy, once per variant.
pub fn exe_mode(c: &mut Checks, dll: &Path) -> Result<(), String> {
    let scratch = Scratch::new("exe-mode")?;
    let me = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let exe = scratch.path("identity-copy.exe");
    std::fs::copy(&me, &exe).map_err(|e| format!("copy the harness exe: {e}"))?;
    let dll_copy = scratch.path("wsock32.dll");
    std::fs::copy(dll, &dll_copy).map_err(|e| format!("copy the DLL: {e}"))?;
    for variant in VARIANTS {
        let agent_port = UdpSocket::bind("127.0.0.1:0")
            .and_then(|s| s.local_addr())
            .map(|a| a.port())
            .map_err(|e| e.to_string())?;
        for (name, value) in [
            ("BEACON_AGENT_PORT", agent_port.to_string()),
            ("BEACON_LOCAL_TOKEN", TOKEN_TEXT.to_owned()),
            ("BEACON_VIP", "198.18.0.5".to_owned()),
            ("BEACON_LOG_LEVEL", "debug".to_owned()),
            ("BEACON_SERIAL", SERIAL.to_owned()),
            ("BEACON_MULTI", "1".to_owned()),
            ("BEACON_HARNESS_VARIANT", variant.to_owned()),
        ] {
            std::env::set_var(name, value);
        }
        std::env::set_var("BEACON_LOG", scratch.path(&format!("hook-{variant}.log")));
        std::env::set_var("BEACON_USERDIR", scratch.path(&format!("userdir-{variant}")));
        std::env::remove_var("BEACON_TEST_ARMED_WITHOUT_EXE");
        // The child's image base is randomised (ASLR); now and then its initial
        // reservations cover image + 0x00F58000. A new child gets a new layout.
        let mut attempt = 1;
        loop {
            match launch(&exe, &dll_copy)? {
                Launch::Exited(code) => {
                    c.eq(code, 0, &format!("exe-mode variant {variant} (exit code; its checks are listed above)"));
                }
                Launch::Blocked => println!("  note: Smart App Control blocked the exe copy; variant {variant} skipped"),
                Launch::NoIdentity(_) if attempt < IDENTITY_ATTEMPTS => {
                    attempt += 1;
                    continue;
                }
                Launch::NoIdentity(e) => {
                    c.ok(false, format_args!("variant {variant}: no identity after {attempt} children: {e}"));
                }
            }
            break;
        }
    }
    Ok(())
}

/// Children started per variant before giving up on a free import-block address.
const IDENTITY_ATTEMPTS: u32 = 10;

/// Previous `recvfrom` slot value, chained to by [`chained_recvfrom`].
static PREVIOUS_RECVFROM: AtomicUsize = AtomicUsize::new(0);

/// Another module's `recvfrom` hook in front of ours (calls the previous slot value).
unsafe extern "system" fn chained_recvfrom(
    s: usize,
    buf: *mut u8,
    len: i32,
    flags: i32,
    from: *mut SockAddrIn,
    fromlen: *mut i32,
) -> i32 {
    let prev = PREVIOUS_RECVFROM.load(Ordering::Acquire);
    if prev == 0 {
        return -1;
    }
    // SAFETY: `prev` is the `recvfrom` this function replaced in the slot.
    let f = unsafe { core::mem::transmute::<usize, RecvFromFn>(prev) };
    // SAFETY: arguments passed through.
    unsafe { f(s, buf, len, flags, from, fromlen) }
}

/// Another module's `recvfrom` hook that calls ws2_32 directly (bypasses ours).
unsafe extern "system" fn bypassing_recvfrom(
    s: usize,
    buf: *mut u8,
    len: i32,
    flags: i32,
    from: *mut SockAddrIn,
    fromlen: *mut i32,
) -> i32 {
    // SAFETY: arguments passed through.
    unsafe { ws2_recvfrom(s, buf, len, flags, from, fromlen) }
}

/// The main module's IAT, read and written by RVA.
struct Iat(usize);

impl Iat {
    fn get(&self, rva: u32) -> usize {
        // SAFETY: `rva` is an IAT slot in the committed import block.
        unsafe { ((self.0 + rva as usize) as *const usize).read_volatile() }
    }

    fn set(&self, rva: u32, value: usize) -> bool {
        let p = (self.0 + rva as usize) as *mut usize;
        let mut old = 0u32;
        // SAFETY: `p` is an IAT slot in the import block.
        unsafe {
            if VirtualProtect(p.cast(), 4, PAGE_READWRITE, &mut old) == 0 {
                return false;
            }
            p.write_volatile(value);
            VirtualProtect(p.cast(), 4, old, &mut old);
        }
        true
    }

    /// The function in slot `rva` as `F`.
    ///
    /// # Safety
    /// `F` must be the slot's function type.
    unsafe fn func<F: Copy>(&self, rva: u32) -> F {
        let v = self.get(rva);
        // SAFETY: caller contract; every slot holds a resolved address.
        unsafe { core::mem::transmute_copy::<usize, F>(&v) }
    }
}

/// `[base, base + SizeOfImage)` of a loaded module.
fn module_range(base: usize) -> (usize, usize) {
    // SAFETY: the headers of a loaded module are mapped.
    let size = unsafe {
        let opt = base + ((base + 0x3C) as *const u32).read_unaligned() as usize + 24;
        ((opt + 56) as *const u32).read_unaligned() as usize
    };
    (base, base + size)
}

fn module_path(h: *mut c_void) -> PathBuf {
    let mut buf = [0u16; 1024];
    // SAFETY: valid buffer of 1024 units.
    let n = unsafe { GetModuleFileNameW(h, buf.as_mut_ptr(), 1024) } as usize;
    PathBuf::from(String::from_utf16_lossy(buf.get(..n).unwrap_or(&[])))
}

fn same_file(a: &Path, b: &Path) -> bool {
    matches!((std::fs::canonicalize(a), std::fs::canonicalize(b)), (Ok(x), Ok(y)) if x == y)
}

/// `recvfrom` through `f` until something other than `WSAEWOULDBLOCK`.
fn poll_recvfrom(f: RecvFromFn, ws: &Ws, s: usize, buf: &mut [u8]) -> (i32, SockAddrIn) {
    for _ in 0..1000 {
        let mut from = SockAddrIn::default();
        let mut fromlen = 16;
        let len = i32::try_from(buf.len()).unwrap_or(i32::MAX);
        // SAFETY: valid buffers and out-parameters.
        let r = unsafe { f(s, buf.as_mut_ptr(), len, 0, &mut from, &mut fromlen) };
        if r != -1 || ws.err() != win::WSAEWOULDBLOCK {
            return (r, from);
        }
        sleep(Duration::from_millis(2));
    }
    (-1, SockAddrIn::default())
}

/// `exe-inner`: runs inside the identity copy (started by `exe-mode`).
pub fn exe_inner(c: &mut Checks, dll: &Path) -> Result<(), String> {
    let variant = std::env::var("BEACON_HARNESS_VARIANT").unwrap_or_default();
    let port: u16 =
        std::env::var("BEACON_AGENT_PORT").ok().and_then(|p| p.parse().ok()).ok_or("BEACON_AGENT_PORT")?;
    let log = PathBuf::from(std::env::var_os("BEACON_LOG").ok_or("BEACON_LOG")?);
    let userdir = std::env::var("BEACON_USERDIR").map_err(|_| "BEACON_USERDIR")?;
    println!("  exe-mode variant {variant}");

    // SAFETY: NUL-terminated name.
    let hook = unsafe { GetModuleHandleW(wide("wsock32.dll").as_ptr()) };
    if hook.is_null() {
        return Err("wsock32.dll was not loaded at process start".into());
    }
    let path = module_path(hook);
    c.ok(same_file(&path, dll), format_args!("the loader took wsock32.dll from the exe folder: {}", path.display()));
    let (lo, hi) = module_range(hook as usize);
    let in_hook = |v: usize| v >= lo && v < hi;
    // SAFETY: NULL = the main module.
    let iat = Iat(unsafe { GetModuleHandleW(core::ptr::null()) } as usize);

    for (i, name) in WS2_NAMES.iter().enumerate() {
        c.ok(in_hook(iat.get(WS2_FT + 4 * i as u32)), format_args!("DllMain patched IAT WS2_32!{name}"));
    }
    for (rva, name) in [
        (ADVAPI_FT, "RegQueryValueExA"),
        (ADVAPI_FT + 4, "RegQueryValueExW"),
        (KERNEL_FT, "CreateMutexA"),
        (KERNEL_FT + 4, "CreateMutexW"),
        (SHELL_FT, "SHGetSpecialFolderPathA"),
        (SHELL_FT + 4, "SHGetSpecialFolderPathW"),
        (WSOCK_FT, "WSOCK32!WSAStartup (the proxy export)"),
    ] {
        c.ok(in_hook(iat.get(rva)), format_args!("IAT {name} points into the hook"));
    }

    // Another module changes the recvfrom slot before the first WSAStartup.
    let recvfrom_rva = WS2_FT + 12;
    // SAFETY: NUL-terminated names.
    let real_recvfrom =
        unsafe { GetProcAddress(GetModuleHandleW(wide("ws2_32.dll").as_ptr()), cstr("recvfrom").as_ptr()) } as usize;
    match variant.as_str() {
        "resnap" => {
            c.ok(iat.set(recvfrom_rva, real_recvfrom), "re-snap the recvfrom slot");
        }
        "chained" => {
            PREVIOUS_RECVFROM.store(iat.get(recvfrom_rva), Ordering::Release);
            c.ok(iat.set(recvfrom_rva, chained_recvfrom as RecvFromFn as usize), "chain a hook in front");
        }
        "bypass" => {
            c.ok(iat.set(recvfrom_rva, bypassing_recvfrom as RecvFromFn as usize), "install a bypassing hook");
        }
        _ => {}
    }

    #[repr(C, align(8))]
    struct WsaData([u8; 512]);
    let mut data = WsaData([0; 512]);
    // SAFETY: the WSOCK32!WSAStartup slot (the proxy's export).
    let startup: StartupFn = unsafe { iat.func(WSOCK_FT) };
    // SAFETY: WSADATA buffer (400 bytes on i686).
    c.eq(unsafe { startup(0x0202, data.0.as_mut_ptr().cast()) }, 0, "first WSAStartup through the WSOCK32 IAT");
    let module = Module::load(dll)?; // the already loaded proxy
    let ws = Ws::load(&module)?;
    let text = read_log(&log);
    let agent = Agent::bind(port).map_err(|e| format!("fake agent on port {port}: {e}"))?;

    if variant == "bypass" {
        c.ok(text.contains("WS2_32!recvfrom no longer reaches the hook"), format_args!("log: bypass detected: {text:?}"));
        c.ok(!text.contains("armed (lotrbfme.exe 1.03)"), "log: no armed line");
        c.eq(iat.get(recvfrom_rva), bypassing_recvfrom as RecvFromFn as usize, "bypassing slot left alone");
        c.eq(ws.hostname().ok(), win::real_hostname(), "disarmed: gethostname is the real name");
        let s = ws.socket(0);
        c.eq((ws.bind(s, VIP, 8086), ws.err()), (-1, win::WSAEADDRNOTAVAIL), "disarmed: bind VIP fails natively");
        ws.close(s);
        c.ok(agent.unexpected(Duration::from_millis(150)).is_none(), "disarmed: no frames");
        c.eq(ws.cleanup(), 0, "WSACleanup");
        return Ok(());
    }
    match variant.as_str() {
        "resnap" => {
            c.ok(in_hook(iat.get(recvfrom_rva)), "re-snapped slot patched again");
            c.ok(text.contains("(re-patched after re-snap)"), "log: re-patched");
        }
        "chained" => {
            c.eq(iat.get(recvfrom_rva), chained_recvfrom as RecvFromFn as usize, "chained slot left alone");
            c.ok(text.contains("still reaches ours"), "log: chained hook detected");
        }
        _ => {}
    }
    c.ok(text.contains("armed (lotrbfme.exe 1.03)"), format_args!("log: armed in exe mode: {text:?}"));
    c.ok(text.contains("RegQueryValueExA patched, RegQueryValueExW patched"), "log: registry hooks");
    c.ok(
        text.contains(
            "CreateMutexA patched, CreateMutexW patched, SHGetSpecialFolderPathA patched, SHGetSpecialFolderPathW patched",
        ),
        "log: test-mode hooks",
    );
    c.eq(ws.hostname(), Ok("BEACON-5".to_string()), "gethostname");

    sockets_through_iat(c, &iat, &ws, &agent)?;
    if variant == "plain" {
        registry_through_iat(c, &iat);
        mutexes_through_iat(c, &iat);
        folders_through_iat(c, &iat, &userdir);
    }
    c.eq(ws.cleanup(), 0, "WSACleanup");
    Ok(())
}

/// Virtual and real sockets, read through the patched WS2_32 slots like
/// `UDP::Read` does.
fn sockets_through_iat(c: &mut Checks, iat: &Iat, ws: &Ws, agent: &Agent) -> Result<(), String> {
    // SAFETY: the slots hold functions with these signatures.
    let (ioctl, getopt, recv, recvfrom, setopt): (WsaIoctlFn, GetOptFn, RecvFn, RecvFromFn, SetOptFn) = unsafe {
        (iat.func(WS2_FT), iat.func(WS2_FT + 4), iat.func(WS2_FT + 8), iat.func(WS2_FT + 12), iat.func(WS2_FT + 16))
    };

    let s = ws.socket(0);
    c.eq(ws.bind(s, VIP, 8086), 0, "bind VIP:8086");
    let reg = expect_frame(c, agent, FrameType::Reg, "REG 8086").ok_or("no REG")?;
    c.eq(reg.header, HookFrame::reg(8086, TOKEN), "REG header");
    let one = 1i32.to_ne_bytes();
    // SAFETY: 4-byte option buffer.
    c.eq(unsafe { setopt(s, win::SOL_SOCKET, win::SO_BROADCAST, one.as_ptr(), 4) }, 0, "setsockopt(SO_BROADCAST) via IAT");
    let mut v = [0u8; 4];
    let mut vlen = 4;
    // SAFETY: 4-byte option buffer and length.
    let r = unsafe { getopt(s, win::SOL_SOCKET, win::SO_BROADCAST, v.as_mut_ptr(), &mut vlen) };
    c.eq((r, i32::from_ne_bytes(v)), (0, 1), "getsockopt(SO_BROADCAST) via IAT");
    let mut nonblocking: u32 = 1;
    let mut returned = 0u32;
    // SAFETY: 4-byte in-buffer, valid out-parameter, no overlapped I/O.
    let r = unsafe {
        ioctl(
            s,
            win::FIONBIO as u32,
            core::ptr::addr_of_mut!(nonblocking).cast(),
            4,
            core::ptr::null_mut(),
            0,
            &mut returned,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    c.eq(r, 0, "WSAIoctl(FIONBIO) via IAT");
    let mut buf = [0u8; 1038];
    let mut from = SockAddrIn::default();
    let mut fromlen = 16;
    // SAFETY: valid buffers.
    let r = unsafe { recvfrom(s, buf.as_mut_ptr(), 1038, 0, &mut from, &mut fromlen) };
    c.eq((r, ws.err()), (-1, win::WSAEWOULDBLOCK), "empty recvfrom via IAT (non-blocking)");

    agent.deliver(reg.src, Ipv4Addr::new(198, 18, 0, 9), 8086, b"through the IAT").map_err(|e| e.to_string())?;
    let (r, from) = poll_recvfrom(recvfrom, ws, s, &mut buf);
    c.eq(r, 15, "recvfrom via IAT: DELIVER payload length");
    c.ok(buf.get(..15) == Some(&b"through the IAT"[..]), "recvfrom via IAT: payload");
    c.eq(from, SockAddrIn::new([198, 18, 0, 9], 8086), "recvfrom via IAT: from = src VIP:port");
    agent.deliver(reg.src, Ipv4Addr::new(198, 18, 0, 9), 8086, b"recv").map_err(|e| e.to_string())?;
    let mut got = -1;
    for _ in 0..500 {
        // SAFETY: valid buffer.
        got = unsafe { recv(s, buf.as_mut_ptr(), 1038, 0) };
        if got != -1 || ws.err() != win::WSAEWOULDBLOCK {
            break;
        }
        sleep(Duration::from_millis(2));
    }
    c.eq(got, 4, "recv via IAT: header stripped");
    c.eq(ws.send_to(s, b"bcast", [255; 4], 8087), 5, "broadcast sendto");
    if let Some(f) = expect_frame(c, agent, FrameType::Send, "broadcast SEND") {
        c.eq(f.header, HookFrame::send(8086, Ipv4Addr::BROADCAST, 8087, TOKEN), "SEND header");
    }

    // A REAL socket read through the same slot: chained to ws2_32 unchanged.
    let real = ws.socket(0);
    c.eq(ws.bind(real, [127, 0, 0, 1], 0), 0, "bind 127.0.0.1:0 (real)");
    let real_port = ws.sockname(real).map(|(sa, _)| sa.port()).unwrap_or(0);
    let sender = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let sender_port = sender.local_addr().map(|a| a.port()).unwrap_or(0);
    sender.send_to(b"plain", ("127.0.0.1", real_port)).map_err(|e| e.to_string())?;
    let mut rbuf = [0u8; 64];
    let mut rfrom = SockAddrIn::default();
    let mut rlen = 16;
    // SAFETY: valid buffers (blocking socket; the datagram is already queued).
    let r = unsafe { recvfrom(real, rbuf.as_mut_ptr(), 64, 0, &mut rfrom, &mut rlen) };
    c.eq((r, rfrom), (5, SockAddrIn::new([127, 0, 0, 1], sender_port)), "real socket via IAT recvfrom");

    c.eq(ws.close(real), 0, "closesocket real");
    c.eq(ws.close(s), 0, "closesocket virtual");
    if let Some(f) = expect_frame(c, agent, FrameType::Close, "CLOSE") {
        c.eq(f.header, HookFrame::close(8086, TOKEN), "CLOSE header");
    }
    Ok(())
}

/// `RegQueryValueExA/W` through the patched ADVAPI32 slots. Read-only; the real CD
/// key is never printed (a failing check only says that the value differs).
fn registry_through_iat(c: &mut Checks, iat: &Iat) {
    // SAFETY: the slots hold these functions.
    let (query_a, query_w): (RegQueryAFn, RegQueryWFn) = unsafe { (iat.func(ADVAPI_FT), iat.func(ADVAPI_FT + 4)) };
    let mut key = 0usize;
    // SAFETY: NUL-terminated subkey, valid out-parameter. Read-only access.
    let opened = unsafe { RegOpenKeyExA(HKEY_LOCAL_MACHINE, cstr(ERGC).as_ptr(), 0, KEY_READ, &mut key) };
    if opened != 0 {
        println!("  note: HKLM ergc key not present (error {opened}); registry substitution check skipped");
    } else {
        let expected_a = cstr(SERIAL);
        let mut ty = 0u32;
        let mut buf = [0u8; 256];
        let mut cb = 256u32;
        // SAFETY: valid key, empty value name, buffers of the stated sizes.
        let r = unsafe { query_a(key, cstr("").as_ptr(), core::ptr::null_mut(), &mut ty, buf.as_mut_ptr(), &mut cb) };
        c.eq((r, ty, cb), (0, REG_SZ, 21), "RegQueryValueExA(ergc) via IAT: status/type/size");
        c.ok(buf.get(..21) == Some(&expected_a[..]), "RegQueryValueExA(ergc) returns BEACON_SERIAL");
        let mut cb = 0u32;
        // SAFETY: size query (NULL data; NULL name = default value).
        let r = unsafe {
            query_a(key, core::ptr::null(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), &mut cb)
        };
        c.eq((r, cb), (0, 21), "RegQueryValueExA(ergc) size query");
        let mut small = [0u8; 5];
        let mut cb = 5u32;
        // SAFETY: 5-byte buffer.
        let r = unsafe {
            query_a(key, cstr("").as_ptr(), core::ptr::null_mut(), core::ptr::null_mut(), small.as_mut_ptr(), &mut cb)
        };
        c.eq((r, cb), (ERROR_MORE_DATA, 21), "RegQueryValueExA(ergc) small buffer");
        let expected_w: Vec<u8> = SERIAL.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
        let mut wbuf = [0u8; 256];
        let mut cb = 256u32;
        // SAFETY: empty wide value name, 256-byte buffer.
        let r = unsafe { query_w(key, wide("").as_ptr(), core::ptr::null_mut(), &mut ty, wbuf.as_mut_ptr(), &mut cb) };
        c.eq((r, ty, cb), (0, REG_SZ, 42), "RegQueryValueExW(ergc) via IAT: status/type/size");
        c.ok(wbuf.get(..42) == Some(&expected_w[..]), "RegQueryValueExW(ergc) returns BEACON_SERIAL");
        // SAFETY: key opened above.
        unsafe { RegCloseKey(key) };
    }
    // Any other key passes through.
    let mut other = 0usize;
    let sub = cstr("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    // SAFETY: read-only open of a standard key.
    if unsafe { RegOpenKeyExA(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ, &mut other) } == 0 {
        let mut buf = [0u8; 256];
        let mut cb = 256u32;
        // SAFETY: valid key and buffers.
        let r = unsafe {
            query_a(other, cstr("ProductName").as_ptr(), core::ptr::null_mut(), core::ptr::null_mut(), buf.as_mut_ptr(), &mut cb)
        };
        c.ok(r == 0 && cb > 1 && !buf.starts_with(SERIAL.as_bytes()), "RegQueryValueExA(other key) passes through");
        let mut cb = 256u32;
        // SAFETY: as above (default value).
        let r = unsafe {
            query_a(other, cstr("").as_ptr(), core::ptr::null_mut(), core::ptr::null_mut(), buf.as_mut_ptr(), &mut cb)
        };
        c.ok(r != 0 || !buf.starts_with(SERIAL.as_bytes()), "default value of another key is not the serial");
        // SAFETY: key opened above.
        unsafe { RegCloseKey(other) };
    }
}

/// `CreateMutexA/W` through the patched KERNEL32 slots.
fn mutexes_through_iat(c: &mut Checks, iat: &Iat) {
    // SAFETY: the slots hold these functions.
    let (create_a, create_w): (CreateMutexAFn, CreateMutexWFn) = unsafe { (iat.func(KERNEL_FT), iat.func(KERNEL_FT + 4)) };
    let pid = std::process::id();
    // SAFETY: NUL-terminated names; every handle is closed below.
    unsafe {
        let guard = create_w(core::ptr::null_mut(), 0, wide(APP_GUID).as_ptr());
        let already = GetLastError() == ERROR_ALREADY_EXISTS;
        c.ok(!guard.is_null() && !already, "CreateMutexW(single-instance GUID) via IAT: a new mutex");
        let suffixed = OpenMutexW(SYNCHRONIZE, 0, wide(&format!("{APP_GUID}-{pid}")).as_ptr());
        c.ok(!suffixed.is_null(), "the GUID mutex got the -<PID> suffix");
        let miles = create_a(core::ptr::null_mut(), 0, cstr(MILES_MUTEX).as_ptr());
        let miles_suffixed = OpenMutexA(SYNCHRONIZE, 0, cstr(&format!("{MILES_MUTEX}-{pid}")).as_ptr());
        c.ok(!miles.is_null() && !miles_suffixed.is_null(), "CreateMutexA(Miles) via IAT got the -<PID> suffix");
        let name = format!("BeaconHarness-{pid}");
        let plain = create_a(core::ptr::null_mut(), 0, cstr(&name).as_ptr());
        let plain_open = OpenMutexA(SYNCHRONIZE, 0, cstr(&name).as_ptr());
        c.ok(!plain.is_null() && !plain_open.is_null(), "other mutex names pass through unchanged");
        for h in [guard, suffixed, miles, miles_suffixed, plain, plain_open] {
            if !h.is_null() {
                CloseHandle(h);
            }
        }
    }
}

/// `SHGetSpecialFolderPathA/W` through the patched SHELL32 slots.
fn folders_through_iat(c: &mut Checks, iat: &Iat, userdir: &str) {
    // SAFETY: the slots hold these functions.
    let (folder_a, folder_w): (FolderAFn, FolderWFn) = unsafe { (iat.func(SHELL_FT), iat.func(SHELL_FT + 4)) };
    let text_w = |w: &[u16]| String::from_utf16_lossy(w.split(|&x| x == 0).next().unwrap_or(&[]));
    let mut w = [0u16; 260];
    // SAFETY: MAX_PATH buffer.
    let r = unsafe { folder_w(core::ptr::null_mut(), w.as_mut_ptr(), CSIDL_APPDATA, 1) };
    c.eq((r, text_w(&w).as_str()), (1, userdir), "SHGetSpecialFolderPathW(APPDATA) via IAT = BEACON_USERDIR");
    c.ok(Path::new(userdir).is_dir(), "fCreate created BEACON_USERDIR");
    // SAFETY: as above.
    let r = unsafe { folder_w(core::ptr::null_mut(), w.as_mut_ptr(), CSIDL_APPDATA | CSIDL_FLAG_CREATE, 0) };
    c.eq((r, text_w(&w).as_str()), (1, userdir), "CSIDL_APPDATA | CSIDL_FLAG_CREATE");
    // SAFETY: as above.
    let r = unsafe { folder_w(core::ptr::null_mut(), w.as_mut_ptr(), CSIDL_LOCAL_APPDATA, 0) };
    let local = text_w(&w);
    c.ok(r == 1 && !local.is_empty() && local != userdir, format_args!("CSIDL_LOCAL_APPDATA passes through: {local}"));
    let mut a = [0u8; 260];
    // SAFETY: MAX_PATH buffer.
    let r = unsafe { folder_a(core::ptr::null_mut(), a.as_mut_ptr(), CSIDL_APPDATA, 1) };
    let got = String::from_utf8_lossy(a.split(|&x| x == 0).next().unwrap_or(&[])).into_owned();
    c.eq((r, got.as_str()), (1, userdir), "SHGetSpecialFolderPathA(APPDATA) via IAT = BEACON_USERDIR");
}
