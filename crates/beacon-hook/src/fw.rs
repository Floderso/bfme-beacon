//! Windows Firewall check (armed mode only).
//!
//! On *Multiplayer* the main menu (`0x0051DB30`) asks its XP SP2 firewall helper
//! (`BfmeThingTTD`, created with the menu at `0x0051FFE3`) whether the exe is an
//! authorised application. If not, it offers to add itself (`0x00690CB0`); without
//! admin rights that fails with "GUI:FirewallNoAdmin" and the game stays in the
//! main menu. That is what happens for every install path that has no firewall
//! rule yet (e.g. a copied or moved game folder).
//!
//! With Beacon the game never receives inbound traffic from the network: all of
//! its datagrams arrive over loopback from the launcher. So the hook answers
//! `CoCreateInstance(CLSID_NetFwMgr)` with `REGDB_E_CLASSNOTREG`, exactly what
//! Windows before XP SP2 answers. `BfmeThingTTD::initialize` (`0x006909B0`) then
//! leaves `m_initialized` false and `0x0051DB30` goes straight to the multiplayer
//! menu. Every other class passes through unchanged.

use core::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::log::info;

/// Original `ole32!CoCreateInstance`.
pub static ORIG_CO_CREATE: AtomicUsize = AtomicUsize::new(0);

/// A COM GUID in memory layout.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// `CoCreateInstance`.
pub type CoCreateInstanceFn =
    unsafe extern "system" fn(*const Guid, *mut c_void, u32, *const Guid, *mut *mut c_void) -> i32;

/// `CLSID_NetFwMgr` {304CE942-6E39-40D8-943A-B913C40C9CD4} (exe copy at VA 0x0111B8F4).
pub const CLSID_NET_FW_MGR: Guid = Guid {
    data1: 0x304C_E942,
    data2: 0x6E39,
    data3: 0x40D8,
    data4: [0x94, 0x3A, 0xB9, 0x13, 0xC4, 0x0C, 0x9C, 0xD4],
};

/// `REGDB_E_CLASSNOTREG`: what pre-SP2 Windows returns for `CLSID_NetFwMgr`.
pub const REGDB_E_CLASSNOTREG: i32 = 0x8004_0154_u32 as i32;
/// `E_FAIL` (returned if the hook is reached without its original).
const E_FAIL: i32 = 0x8000_4005_u32 as i32;

static LOGGED: AtomicBool = AtomicBool::new(false);

/// Whether a `CoCreateInstance` call for `rclsid` is answered by the hook.
pub fn is_hidden_class(rclsid: &Guid) -> bool {
    *rclsid == CLSID_NET_FW_MGR
}

/// Hook for `ole32!CoCreateInstance`.
///
/// # Safety
/// Called by the game with `CoCreateInstance`'s contract.
pub unsafe extern "system" fn hook_co_create_instance(
    rclsid: *const Guid,
    outer: *mut c_void,
    context: u32,
    riid: *const Guid,
    out: *mut *mut c_void,
) -> i32 {
    // SAFETY: `rclsid` is NULL or points to a GUID (API contract); read unaligned
    // because callers are not required to align it.
    let hidden = !rclsid.is_null() && is_hidden_class(&unsafe { rclsid.read_unaligned() });
    if hidden {
        if !out.is_null() {
            // SAFETY: `out` is the caller's interface pointer slot (API contract).
            unsafe { out.write(core::ptr::null_mut()) };
        }
        if !LOGGED.swap(true, Ordering::Relaxed) {
            info!("CoCreateInstance(CLSID_NetFwMgr) -> REGDB_E_CLASSNOTREG (no firewall prompt; Beacon traffic is loopback only)");
        }
        return REGDB_E_CLASSNOTREG;
    }
    // SAFETY: `CoCreateInstanceFn` is the signature of the import saved in `ORIG_CO_CREATE`.
    match unsafe { crate::iat::load_fn::<CoCreateInstanceFn>(&ORIG_CO_CREATE) } {
        // SAFETY: original function with the caller's arguments.
        Some(f) => unsafe { f(rclsid, outer, context, riid, out) },
        None => E_FAIL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exe's own copy of the CLSID (VA 0x0111B8F4) in memory layout.
    const EXE_BYTES: [u8; 16] = [
        0x42, 0xE9, 0x4C, 0x30, 0x39, 0x6E, 0xD8, 0x40, 0x94, 0x3A, 0xB9, 0x13, 0xC4, 0x0C, 0x9C, 0xD4,
    ];

    #[test]
    fn clsid_matches_exe_layout() {
        assert_eq!(core::mem::size_of::<Guid>(), 16);
        // SAFETY: 16 bytes, `Guid` is repr(C) plain data; unaligned read.
        let g = unsafe { EXE_BYTES.as_ptr().cast::<Guid>().read_unaligned() };
        assert!(is_hidden_class(&g));
    }

    #[test]
    fn other_classes_pass() {
        // CLSID_NetFwAuthorizedApplication {EC9846B3-2762-4A6B-A214-6ACB603462D2}
        let app = Guid { data1: 0xEC98_46B3, data2: 0x2762, data3: 0x4A6B, data4: [0xA2, 0x14, 0x6A, 0xCB, 0x60, 0x34, 0x62, 0xD2] };
        assert!(!is_hidden_class(&app));
        let mut near = CLSID_NET_FW_MGR;
        near.data4[7] ^= 1;
        assert!(!is_hidden_class(&near));
    }

    #[test]
    fn hidden_class_clears_out_pointer_and_fails() {
        let mut out: *mut c_void = 8 as *mut c_void;
        // SAFETY: valid GUID and out pointer; the hidden path never calls the original.
        let hr = unsafe {
            hook_co_create_instance(&CLSID_NET_FW_MGR, core::ptr::null_mut(), 1, &CLSID_NET_FW_MGR, &mut out)
        };
        assert_eq!(hr, REGDB_E_CLASSNOTREG);
        assert!(out.is_null());
    }

    #[test]
    fn missing_original_fails_cleanly() {
        let other = Guid { data1: 1, data2: 2, data3: 3, data4: [0; 8] };
        let mut out: *mut c_void = core::ptr::null_mut();
        // SAFETY: valid pointers; with no original saved the hook returns E_FAIL.
        let hr = unsafe { hook_co_create_instance(&other, core::ptr::null_mut(), 1, &other, &mut out) };
        assert_eq!(hr, E_FAIL);
    }
}
