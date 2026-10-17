//! `DllMain(PROCESS_ATTACH)` and the deferred start-up work.
//!
//! Under the loader lock only: read the environment (`GetEnvironmentVariableW`),
//! check the exe identity (in-memory headers), patch IAT slots (`VirtualProtect`)
//! and publish the armed state. No threads, no sockets, no `LoadLibrary`, no file
//! I/O. The start-up report is written to the log by the first `WSAStartup`, which
//! also re-verifies the IAT patches (spec 03 §8.4).

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;

use crate::config::{self, Config, ConfigError, MultiProblem, ProcessEnv};
use crate::iat::{PatchError, Slot};
use crate::log::info;
use crate::pe::{self, Headers, Image, LiveImage, PeError};
use crate::{ffi, log, multi, reg, state, ws2};

/// Maximum number of patched slots (5 WS2_32 + 2 registry + 4 test mode).
const MAX_PATCHES: usize = 11;

/// One installed IAT patch.
#[derive(Clone, Copy)]
struct Patch {
    name: &'static str,
    slot: Slot,
    hook: usize,
    orig: &'static AtomicUsize,
}

/// Fixed list of installed patches.
#[derive(Clone, Copy)]
struct PatchList {
    items: [Option<Patch>; MAX_PATCHES],
}

impl PatchList {
    const fn new() -> Self {
        Self { items: [None; MAX_PATCHES] }
    }

    fn push(&mut self, p: Patch) {
        if let Some(free) = self.items.iter_mut().find(|i| i.is_none()) {
            *free = Some(p);
        }
    }

    fn iter(&self) -> impl Iterator<Item = &Patch> {
        self.items.iter().flatten()
    }
}

static PATCHES: OnceLock<PatchList> = OnceLock::new();

/// Status of one optional patch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Optional {
    /// Not requested (feature off).
    Off,
    /// The exe does not import the function.
    NotImported,
    /// Installed.
    Patched,
    /// Patch refused.
    Failed(PatchError),
    /// Import table unreadable.
    Unreadable(PeError),
}

/// Why the mandatory WS2_32 patch set failed.
#[derive(Clone, Copy, Debug)]
enum Ws2Failure {
    Pe(PeError),
    Missing(&'static str),
    Patch(&'static str, PatchError),
}

impl core::fmt::Display for Ws2Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Pe(e) => write!(f, "import table unreadable: {e:?}"),
            Self::Missing(name) => write!(f, "{name} not imported"),
            Self::Patch(name, e) => write!(f, "{name}: {e:?}"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Outcome {
    Armed,
    Config(ConfigError),
    Ws2(Ws2Failure),
}

/// What `DllMain` did; logged by the first `WSAStartup`.
#[derive(Clone, Copy)]
struct Report {
    outcome: Outcome,
    exe_mode: bool,
    config: Option<Config>,
    reg_a: Optional,
    reg_w: Optional,
    mutex_a: Optional,
    mutex_w: Optional,
    folder_a: Optional,
    folder_w: Optional,
    ansi_userdir: bool,
}

impl Report {
    const fn new(outcome: Outcome, exe_mode: bool) -> Self {
        Self {
            outcome,
            exe_mode,
            config: None,
            reg_a: Optional::Off,
            reg_w: Optional::Off,
            mutex_a: Optional::Off,
            mutex_w: Optional::Off,
            folder_a: Optional::Off,
            folder_w: Optional::Off,
            ansi_userdir: true,
        }
    }
}

static REPORT: OnceLock<Report> = OnceLock::new();
static REPORT_PENDING: AtomicBool = AtomicBool::new(false);

fn set_report(r: Report) {
    if REPORT.set(r).is_ok() {
        REPORT_PENDING.store(true, Ordering::Release);
    }
}

/// `DLL_PROCESS_ATTACH`.
pub fn process_attach() {
    let env = ProcessEnv;
    // Passive unless the launcher armed us: no further work, nothing logged.
    if !config::agent_port_set(&env) {
        return;
    }
    let test_mode = config::test_armed_without_exe(&env);
    let image = if test_mode {
        None
    } else {
        // SAFETY: NULL = the main executable, mapped by the loader.
        let base = unsafe { ffi::GetModuleHandleW(core::ptr::null()) }.cast::<u8>().cast_const();
        // SAFETY: `base` is the loaded main module.
        match unsafe { LiveImage::from_module(base) } {
            // Not BFME 1.03 (e.g. worldbuilder.exe): passive and silent.
            Some(img) if pe::is_bfme_103(&img) => Some(img),
            _ => return,
        }
    };
    let exe_mode = image.is_some();

    if let Some(settings) = config::log_settings(&env) {
        log::configure(settings);
    }
    let cfg = match config::parse(&env) {
        Ok(cfg) => cfg,
        Err(e) => {
            set_report(Report::new(Outcome::Config(e), exe_mode));
            return;
        }
    };
    let mut report = Report::new(Outcome::Armed, exe_mode);
    report.config = Some(cfg);

    if let Some(img) = &image {
        let mut list = PatchList::new();
        let headers = match install_ws2(img, &mut list) {
            Ok(h) => h,
            Err(failure) => {
                report.outcome = Outcome::Ws2(failure);
                set_report(report);
                return;
            }
        };
        if let Some(serial) = cfg.serial {
            reg::set_serial(serial);
            let a = reg::hook_reg_query_value_ex_a as reg::RegQueryValueExAFn as usize;
            let w = reg::hook_reg_query_value_ex_w as reg::RegQueryValueExWFn as usize;
            report.reg_a = install_optional(img, &headers, &mut list, "ADVAPI32.dll", "RegQueryValueExA", a, &reg::ORIG_A);
            report.reg_w = install_optional(img, &headers, &mut list, "ADVAPI32.dll", "RegQueryValueExW", w, &reg::ORIG_W);
        }
        if let (true, Some(dir)) = (cfg.multi, cfg.userdir) {
            report.ansi_userdir = multi::set_userdir(dir);
            let ma = multi::hook_create_mutex_a as multi::CreateMutexAFn as usize;
            let mw = multi::hook_create_mutex_w as multi::CreateMutexWFn as usize;
            let fa = multi::hook_folder_path_a as multi::FolderPathAFn as usize;
            let fw = multi::hook_folder_path_w as multi::FolderPathWFn as usize;
            report.mutex_a = install_optional(img, &headers, &mut list, "KERNEL32.dll", "CreateMutexA", ma, &multi::ORIG_MUTEX_A);
            report.mutex_w = install_optional(img, &headers, &mut list, "KERNEL32.dll", "CreateMutexW", mw, &multi::ORIG_MUTEX_W);
            report.folder_a =
                install_optional(img, &headers, &mut list, "SHELL32.dll", "SHGetSpecialFolderPathA", fa, &multi::ORIG_FOLDER_A);
            report.folder_w =
                install_optional(img, &headers, &mut list, "SHELL32.dll", "SHGetSpecialFolderPathW", fw, &multi::ORIG_FOLDER_W);
        }
        let _ = PATCHES.set(list);
    }

    state::arm(cfg.agent_port, cfg.token, cfg.vip);
    set_report(report);
}

/// Patches all five WS2_32 slots or none (spec 03 §9.11: virtualising without the
/// `recvfrom` hook would deliver wrong `from` addresses).
fn install_ws2(img: &LiveImage, list: &mut PatchList) -> Result<Headers, Ws2Failure> {
    let headers = pe::parse_headers(img).map_err(Ws2Failure::Pe)?;
    let desc = pe::find_descriptor(img, &headers, "WS2_32.dll")
        .map_err(Ws2Failure::Pe)?
        .ok_or(Ws2Failure::Missing("WS2_32.dll"))?;
    let hooks = ws2::hooks();
    let mut done: [Option<Patch>; 5] = [None; 5];
    let mut result = Ok(());
    for (i, ((name, hook), orig)) in ws2::NAMES.into_iter().zip(hooks).zip(&ws2::ORIG).enumerate() {
        let rva = match pe::find_slot(img, &desc, name) {
            Ok(Some(rva)) => rva,
            Ok(None) => {
                result = Err(Ws2Failure::Missing(name));
                break;
            }
            Err(e) => {
                result = Err(Ws2Failure::Pe(e));
                break;
            }
        };
        let slot = Slot::new(img.base() as usize, img.size(), rva);
        // SAFETY: the slot lies in the main module's IAT; we run under the loader
        // lock before any game code.
        if let Err(e) = unsafe { slot.patch(hook, orig) } {
            result = Err(Ws2Failure::Patch(name, e));
            break;
        }
        if let Some(d) = done.get_mut(i) {
            *d = Some(Patch { name, slot, hook, orig });
        }
    }
    if let Err(failure) = result {
        for p in done.iter().flatten() {
            // SAFETY: as above; puts back the value saved by `patch`.
            let _ = unsafe { p.slot.restore(p.hook, p.orig) };
        }
        return Err(failure);
    }
    for p in done.into_iter().flatten() {
        list.push(p);
    }
    Ok(headers)
}

/// Patches one optional slot if the exe imports the function.
fn install_optional(
    img: &LiveImage,
    headers: &Headers,
    list: &mut PatchList,
    dll: &'static str,
    name: &'static str,
    hook: usize,
    orig: &'static AtomicUsize,
) -> Optional {
    let rva = match pe::find_descriptor(img, headers, dll) {
        Ok(Some(desc)) => match pe::find_slot(img, &desc, name) {
            Ok(Some(rva)) => rva,
            Ok(None) => return Optional::NotImported,
            Err(e) => return Optional::Unreadable(e),
        },
        Ok(None) => return Optional::NotImported,
        Err(e) => return Optional::Unreadable(e),
    };
    let slot = Slot::new(img.base() as usize, img.size(), rva);
    // SAFETY: the slot lies in the main module's IAT; loader lock held.
    match unsafe { slot.patch(hook, orig) } {
        Ok(()) => {
            list.push(Patch { name, slot, hook, orig });
            Optional::Patched
        }
        Err(e) => Optional::Failed(e),
    }
}

/// Called at the top of every `WSAStartup`; does its work once.
pub fn on_wsastartup() {
    if !REPORT_PENDING.load(Ordering::Acquire) || !REPORT_PENDING.swap(false, Ordering::AcqRel) {
        return;
    }
    let reverified = reverify_patches();
    if let Some(report) = REPORT.get() {
        write_report(report, reverified);
    }
}

/// Re-checks every patched slot. A slot that holds the original pointer again
/// (re-snapped) is patched again; a slot holding a third value (another hooking
/// module) is left alone — chaining to it could loop back into us.
fn reverify_patches() -> (usize, usize) {
    let Some(list) = PATCHES.get() else {
        return (0, 0);
    };
    let (mut repatched, mut foreign) = (0, 0);
    for p in list.iter() {
        // SAFETY: slots of the main module's IAT (validated when patched).
        let Ok(current) = (unsafe { p.slot.load() }) else {
            continue;
        };
        if current == p.hook {
            continue;
        }
        if current == p.orig.load(Ordering::Acquire) {
            // SAFETY: as above; the original is unchanged, so chaining is safe.
            if unsafe { p.slot.patch(p.hook, p.orig) }.is_ok() {
                repatched += 1;
            }
        } else {
            foreign += 1;
            info!("IAT slot {} (rva {:#x}) was replaced by another module; left alone", p.name, p.slot.rva());
        }
    }
    (repatched, foreign)
}

fn optional_text(o: Optional) -> &'static str {
    match o {
        Optional::Off => "off",
        Optional::NotImported => "not imported",
        Optional::Patched => "patched",
        Optional::Failed(PatchError::BadSlot) => "FAILED (bad slot)",
        Optional::Failed(PatchError::NotChainable) => "FAILED (slot not resolved)",
        Optional::Failed(PatchError::Protect) => "FAILED (VirtualProtect)",
        Optional::Unreadable(_) => "FAILED (import table unreadable)",
    }
}

fn write_report(r: &Report, (repatched, foreign): (usize, usize)) {
    let version = env!("CARGO_PKG_VERSION");
    let mode = if r.exe_mode { "lotrbfme.exe 1.03" } else { "BEACON_TEST_ARMED_WITHOUT_EXE" };
    match r.outcome {
        Outcome::Config(e) => {
            info!("beacon-hook {version}: configuration error: {} - staying passive", e.describe());
            return;
        }
        Outcome::Ws2(f) => {
            info!("beacon-hook {version}: WS2_32 IAT patch failed ({f}) - staying passive");
            return;
        }
        Outcome::Armed => {}
    }
    let Some(cfg) = r.config else {
        return;
    };
    let host = state::get().map(|s| core::str::from_utf8(s.hostname()).unwrap_or("?")).unwrap_or("?");
    info!(
        "beacon-hook {version}: armed ({mode}); vip {} host {host}, agent 127.0.0.1:{}",
        cfg.vip, cfg.agent_port
    );
    if r.exe_mode {
        info!(
            "IAT: WS2_32 WSAIoctl/getsockopt/recv/recvfrom/setsockopt patched{}; RegQueryValueExA {}, RegQueryValueExW {}",
            if repatched > 0 { " (re-patched after re-snap)" } else { "" },
            optional_text(r.reg_a),
            optional_text(r.reg_w)
        );
        if cfg.multi {
            info!(
                "test mode: CreateMutexA {}, CreateMutexW {}, SHGetSpecialFolderPathA {}{}, SHGetSpecialFolderPathW {}",
                optional_text(r.mutex_a),
                optional_text(r.mutex_w),
                optional_text(r.folder_a),
                if r.ansi_userdir { "" } else { " (BEACON_USERDIR not representable in ANSI: passes through)" },
                optional_text(r.folder_w)
            );
        }
        if foreign > 0 {
            info!("{foreign} IAT slot(s) replaced by another module before the first WSAStartup");
        }
    }
    if cfg.serial.is_none() {
        info!(
            "BEACON_SERIAL {} - the ergc CD key passes through",
            if cfg.serial_invalid { "malformed (need 20 x [A-Z0-9])" } else { "not set" }
        );
    }
    match cfg.multi_problem {
        Some(MultiProblem::UserdirMissing) => info!("BEACON_MULTI=1 without BEACON_USERDIR - test mode off"),
        Some(MultiProblem::UserdirInvalid) => {
            info!("BEACON_MULTI=1 but BEACON_USERDIR is not an absolute path <= 200 chars - test mode off");
        }
        None => {}
    }
}
