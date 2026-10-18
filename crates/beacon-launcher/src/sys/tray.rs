//! Notification-area icon ("tray") with the menu *Öffnen* / *Beenden*: a hidden
//! window with its own message loop on a dedicated thread (Win32 only). A left
//! click or Enter opens the UI, the context menu offers both commands. The icon
//! (a gold beacon fire) is drawn at run time; no resource file is needed.

#![allow(unsafe_code)]

use std::cell::{Cell, OnceCell};
use std::io;
use std::ptr;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{GetLastError, ERROR_CLASS_ALREADY_EXISTS, HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{CreateBitmap, DeleteObject};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_SETVERSION, NINF_KEY,
    NIN_SELECT, NOTIFYICONDATAW, NOTIFYICON_VERSION_4,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreateIconIndirect, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyIcon, DestroyMenu,
    DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW, LoadIconW, PostMessageW, PostQuitMessage,
    RegisterClassW, RegisterWindowMessageW, SetForegroundWindow, SetMenuDefaultItem, TrackPopupMenu,
    TranslateMessage, HICON, ICONINFO, IDI_APPLICATION, MF_SEPARATOR, MF_STRING, MSG, TPM_BOTTOMALIGN,
    TPM_NONOTIFY, TPM_RETURNCMD, TPM_RIGHTBUTTON, WM_APP, WM_CLOSE, WM_CONTEXTMENU, WM_DESTROY, WM_NULL,
    WNDCLASSW, WS_OVERLAPPED,
};

use super::windows::wide;
use super::TrayCommand;

const WM_TRAY: u32 = WM_APP + 1;
const NIN_KEYSELECT: u32 = NIN_SELECT | NINF_KEY;
const ID_OPEN: usize = 1;
const ID_QUIT: usize = 2;
const ICON_ID: u32 = 1;
const CLASS_NAME: &str = "BFMEBeaconTray";
/// Clicks closer together than this open the UI only once (double clicks).
const OPEN_DEBOUNCE: Duration = Duration::from_millis(1500);
/// How long dropping the tray waits for its thread.
const STOP_WAIT: Duration = Duration::from_secs(2);
/// Icon edge in pixels.
pub const ICON_SIZE: usize = 32;

type Callback = Box<dyn Fn(TrayCommand) + Send>;

/// Per-thread state of the tray window (only touched on its own thread).
struct TrayState {
    callback: Callback,
    nid: NOTIFYICONDATAW,
    icon: HICON,
    own_icon: bool,
    taskbar_created: u32,
    last_open: Cell<Option<Instant>>,
}

thread_local! {
    static STATE: OnceCell<TrayState> = const { OnceCell::new() };
}

/// The tray icon; removed when dropped.
#[derive(Debug)]
pub struct Tray {
    hwnd: HWND,
    thread: Option<JoinHandle<()>>,
}

// SAFETY: the window handle is only used with PostMessageW, which may be called
// from any thread for any window handle.
unsafe impl Send for Tray {}
// SAFETY: as above; `&Tray` exposes nothing else.
unsafe impl Sync for Tray {}

impl Tray {
    /// Shows the icon with `tooltip`; `callback` runs on the tray thread for every
    /// menu choice or click.
    pub fn start(tooltip: &str, callback: impl Fn(TrayCommand) + Send + 'static) -> io::Result<Self> {
        struct SendHwnd(HWND);
        // SAFETY: the handle value is only passed back to the creating thread's
        // owner, which uses it with PostMessageW (thread-safe).
        unsafe impl Send for SendHwnd {}

        let (tx, rx) = mpsc::sync_channel::<io::Result<SendHwnd>>(1);
        let tip = tooltip.to_owned();
        let callback: Callback = Box::new(callback);
        let thread = std::thread::Builder::new()
            .name("beacon-tray".into())
            .spawn(move || match create(&tip, callback) {
                Ok(hwnd) => {
                    let _ = tx.send(Ok(SendHwnd(hwnd)));
                    run_message_loop();
                }
                Err(e) => {
                    let _ = tx.send(Err(e));
                }
            })?;
        match rx.recv() {
            Ok(Ok(SendHwnd(hwnd))) => Ok(Self {
                hwnd,
                thread: Some(thread),
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(io::Error::other("the tray thread ended"))
            }
        }
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        // SAFETY: posting to a window of another thread is allowed; if the window
        // is already gone the call fails harmlessly.
        unsafe {
            PostMessageW(self.hwnd, WM_CLOSE, 0, 0);
        }
        if let Some(thread) = self.thread.take() {
            let deadline = Instant::now() + STOP_WAIT;
            while !thread.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if thread.is_finished() {
                let _ = thread.join();
            }
        }
    }
}

/// Creates the window, the icon and the notification-area entry (tray thread).
fn create(tip: &str, callback: Callback) -> io::Result<HWND> {
    let class = wide(CLASS_NAME);
    let title = wide("BFME Beacon");
    // SAFETY: all strings are NUL-terminated UTF-16 that outlive the calls; the
    // class registers a valid window procedure; null parent/menu/param are allowed.
    let hwnd = unsafe {
        let hinstance = GetModuleHandleW(ptr::null());
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: hinstance,
            lpszClassName: class.as_ptr(),
            ..WNDCLASSW::default()
        };
        if RegisterClassW(&wc) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS {
            return Err(io::Error::last_os_error());
        }
        CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            hinstance,
            ptr::null(),
        )
    };
    if hwnd.is_null() {
        return Err(io::Error::last_os_error());
    }
    let taskbar = wide("TaskbarCreated");
    // SAFETY: NUL-terminated string.
    let taskbar_created = unsafe { RegisterWindowMessageW(taskbar.as_ptr()) };
    let (icon, own_icon) = match make_icon() {
        Some(icon) => (icon, true),
        // SAFETY: loads a shared system icon (null instance + predefined id).
        None => (unsafe { LoadIconW(ptr::null_mut(), IDI_APPLICATION) }, false),
    };
    // SAFETY: NOTIFYICONDATAW is plain data; all-zero is a valid initial value.
    let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    nid.cbSize = u32::try_from(std::mem::size_of::<NOTIFYICONDATAW>()).unwrap_or(0);
    nid.hWnd = hwnd;
    nid.uID = ICON_ID;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = icon;
    for (dst, src) in nid.szTip.iter_mut().zip(tip.encode_utf16().take(127)) {
        *dst = src;
    }
    nid.Anonymous.uVersion = NOTIFYICON_VERSION_4;
    let state = TrayState {
        callback,
        nid,
        icon,
        own_icon,
        taskbar_created,
        last_open: Cell::new(None),
    };
    STATE.with(|s| {
        let _ = s.set(state);
    });
    if !add_icon() {
        // SAFETY: our own window, destroyed on its own thread.
        unsafe {
            DestroyWindow(hwnd);
        }
        return Err(io::Error::other("Shell_NotifyIconW(NIM_ADD) failed"));
    }
    Ok(hwnd)
}

/// Adds the icon (again after an Explorer restart) and selects the modern
/// notification behaviour (`NIN_SELECT`, `WM_CONTEXTMENU`).
fn add_icon() -> bool {
    STATE.with(|s| {
        s.get().is_some_and(|st| {
            // SAFETY: `nid` is fully initialised and lives in the thread-local state.
            unsafe {
                let added = Shell_NotifyIconW(NIM_ADD, &st.nid) != 0;
                if added {
                    Shell_NotifyIconW(NIM_SETVERSION, &st.nid);
                }
                added
            }
        })
    })
}

fn fire(command: TrayCommand) {
    STATE.with(|s| {
        if let Some(st) = s.get() {
            if command == TrayCommand::Open {
                let now = Instant::now();
                if st.last_open.get().is_some_and(|t| now.duration_since(t) < OPEN_DEBOUNCE) {
                    return;
                }
                st.last_open.set(Some(now));
            }
            (st.callback)(command);
        }
    });
}

/// Shows the context menu at `at` (screen coordinates) or the cursor.
fn show_menu(hwnd: HWND, at: Option<POINT>) {
    let open = wide("Öffnen");
    let quit = wide("Beenden");
    // SAFETY: the menu is created, used and destroyed here; the strings outlive
    // the AppendMenuW calls (the menu copies them); `hwnd` is our window.
    let chosen = unsafe {
        let menu = CreatePopupMenu();
        if menu.is_null() {
            return;
        }
        AppendMenuW(menu, MF_STRING, ID_OPEN, open.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, ptr::null());
        AppendMenuW(menu, MF_STRING, ID_QUIT, quit.as_ptr());
        SetMenuDefaultItem(menu, ID_OPEN as u32, 0);
        let mut pt = POINT { x: 0, y: 0 };
        match at {
            Some(p) => pt = p,
            None => {
                GetCursorPos(&mut pt);
            }
        }
        // Required so that the menu closes when the user clicks elsewhere.
        SetForegroundWindow(hwnd);
        let chosen = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN,
            pt.x,
            pt.y,
            0,
            hwnd,
            ptr::null(),
        );
        PostMessageW(hwnd, WM_NULL, 0, 0);
        DestroyMenu(menu);
        chosen
    };
    match usize::try_from(chosen) {
        Ok(ID_OPEN) => fire(TrayCommand::Open),
        Ok(ID_QUIT) => fire(TrayCommand::Quit),
        _ => {}
    }
}

/// Signed 16-bit halves of a packed coordinate pair (`GET_X_LPARAM`/`GET_Y_LPARAM`).
fn point_from(packed: usize) -> POINT {
    let x = i32::from((packed & 0xFFFF) as u16 as i16);
    let y = i32::from(((packed >> 16) & 0xFFFF) as u16 as i16);
    POINT { x, y }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_TRAY => {
            // NOTIFYICON_VERSION_4: LOWORD(lParam) = event, wParam = anchor point.
            match (lparam as usize & 0xFFFF) as u32 {
                NIN_SELECT | NIN_KEYSELECT => fire(TrayCommand::Open),
                WM_CONTEXTMENU => show_menu(hwnd, Some(point_from(wparam))),
                _ => {}
            }
            0
        }
        WM_CLOSE => {
            // SAFETY: our own window, on its own thread.
            unsafe {
                DestroyWindow(hwnd);
            }
            0
        }
        WM_DESTROY => {
            STATE.with(|s| {
                if let Some(st) = s.get() {
                    // SAFETY: removes our icon; destroys the icon handle we created.
                    unsafe {
                        Shell_NotifyIconW(NIM_DELETE, &st.nid);
                        if st.own_icon {
                            DestroyIcon(st.icon);
                        }
                    }
                }
            });
            // SAFETY: ends this thread's message loop.
            unsafe { PostQuitMessage(0) };
            0
        }
        _ => {
            let restarted = STATE.with(|s| s.get().is_some_and(|st| st.taskbar_created != 0 && msg == st.taskbar_created));
            if restarted {
                add_icon();
            }
            // SAFETY: default handling with the unchanged arguments.
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
    }
}

fn run_message_loop() {
    // SAFETY: MSG is plain data; GetMessageW fills it; standard loop of this thread.
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

/// The icon as an `HICON` (32×32, alpha), `None` if GDI refuses.
fn make_icon() -> Option<HICON> {
    let pixels = icon_pixels();
    let mut color = Vec::with_capacity(pixels.len() * 4);
    for p in pixels {
        color.extend_from_slice(&p.to_le_bytes());
    }
    // 1 bpp mask, rows padded to 16 bits: all zero = use the colour image.
    let mask = [0u8; ICON_SIZE * ICON_SIZE / 8];
    let size = i32::try_from(ICON_SIZE).ok()?;
    // SAFETY: the buffers hold exactly size×size pixels in the stated formats;
    // CreateIconIndirect copies the bitmaps, which are deleted afterwards.
    unsafe {
        let hbm_color = CreateBitmap(size, size, 1, 32, color.as_ptr().cast());
        let hbm_mask = CreateBitmap(size, size, 1, 1, mask.as_ptr().cast());
        let icon = if hbm_color.is_null() || hbm_mask.is_null() {
            ptr::null_mut()
        } else {
            let info = ICONINFO {
                fIcon: 1,
                xHotspot: 0,
                yHotspot: 0,
                hbmMask: hbm_mask,
                hbmColor: hbm_color,
            };
            CreateIconIndirect(&info)
        };
        if !hbm_color.is_null() {
            DeleteObject(hbm_color);
        }
        if !hbm_mask.is_null() {
            DeleteObject(hbm_mask);
        }
        (!icon.is_null()).then_some(icon)
    }
}

/// Straight-alpha colour `0xAARRGGBB`.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Rgba {
    r: f32,
    g: f32,
    b: f32,
    a: f32,
}

impl Rgba {
    const CLEAR: Self = Self { r: 0.0, g: 0.0, b: 0.0, a: 0.0 };

    fn hex(rgb: u32) -> Self {
        let c = |shift: u32| ((rgb >> shift) & 0xFF) as f32 / 255.0;
        Self { r: c(16), g: c(8), b: c(0), a: 1.0 }
    }

    /// `self` painted over `below` with coverage `cov`.
    fn over(self, below: Self, cov: f32) -> Self {
        let a = (self.a * cov.clamp(0.0, 1.0)).clamp(0.0, 1.0);
        let out_a = a + below.a * (1.0 - a);
        if out_a <= 0.0 {
            return Self::CLEAR;
        }
        let mix = |top: f32, bottom: f32| (top * a + bottom * below.a * (1.0 - a)) / out_a;
        Self {
            r: mix(self.r, below.r),
            g: mix(self.g, below.g),
            b: mix(self.b, below.b),
            a: out_a,
        }
    }

    fn packed(self) -> u32 {
        let q = |v: f32| (v.clamp(0.0, 1.0) * 255.0).round() as u32;
        (q(self.a) << 24) | (q(self.r) << 16) | (q(self.g) << 8) | q(self.b)
    }
}

/// Half width of a flame at height `y`: a point at `top` widening into a circle
/// of radius `r` around `(16, cy)`.
fn flame_half_width(y: f32, top: f32, cy: f32, r: f32) -> f32 {
    if y < top {
        0.0
    } else if y <= cy {
        r * ((y - top) / (cy - top)).powf(0.75)
    } else {
        (r * r - (y - cy) * (y - cy)).max(0.0).sqrt()
    }
}

/// The tray icon, row by row from the top, `0xAARRGGBB`: a dark disc with a
/// bronze rim and a gold flame (the beacon fire).
pub fn icon_pixels() -> Vec<u32> {
    let disc = Rgba::hex(0x1E1812);
    let rim = Rgba::hex(0xB08D57);
    let flame = Rgba::hex(0xE8A93A);
    let core = Rgba::hex(0xFFF0B8);
    let mut out = Vec::with_capacity(ICON_SIZE * ICON_SIZE);
    for py in 0..ICON_SIZE {
        for px in 0..ICON_SIZE {
            let (x, y) = (px as f32 + 0.5, py as f32 + 0.5);
            let d = ((x - 16.0).powi(2) + (y - 16.0).powi(2)).sqrt();
            let mut c = disc.over(Rgba::CLEAR, 15.6 - d);
            c = rim.over(c, (15.6 - d).min(d - 13.4));
            let dx = (x - 16.0).abs();
            c = flame.over(c, flame_half_width(y, 4.5, 19.0, 7.0) - dx + 0.5);
            c = core.over(c, flame_half_width(y, 11.5, 21.0, 3.4) - dx + 0.5);
            out.push(c.packed());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_is_a_round_beacon() {
        let px = icon_pixels();
        assert_eq!(px.len(), ICON_SIZE * ICON_SIZE);
        let at = |x: usize, y: usize| px[y * ICON_SIZE + x];
        let alpha = |p: u32| p >> 24;
        // Corners are transparent, the disc is opaque.
        assert_eq!(alpha(at(0, 0)), 0);
        assert_eq!(alpha(at(31, 31)), 0);
        assert_eq!(alpha(at(16, 30)), 255);
        // The flame core near the centre is bright, the rim is bronze.
        let core = at(16, 20);
        assert!((core >> 16 & 0xFF) > 0xF0 && (core >> 8 & 0xFF) > 0xE0, "{core:08x}");
        assert_eq!(at(16, 1) & 0x00FF_FFFF, 0x00B0_8D57);
    }

    #[test]
    fn packed_points() {
        let p = point_from(0xFFFF_0010);
        assert_eq!((p.x, p.y), (16, -1));
    }
}
