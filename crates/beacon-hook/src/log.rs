//! Optional, rate-limited logging to `BEACON_LOG` (architecture §4.2).
//!
//! * Off unless `BEACON_LOG` is set **and** the hook got past the "is this the
//!   game, does the launcher want us" checks (passive mode never logs).
//! * Lines are formatted into a stack buffer (no allocation) and appended with one
//!   `WriteFile` each; the file is opened lazily on the first line (never under the
//!   loader lock, because nothing is logged from `DllMain`).
//! * At most [`LINES_PER_SECOND`] lines per second (excess counted and reported on
//!   the next line) and [`MAX_LINES`] per process; with `BEACON_LOG_LEVEL=debug`
//!   [`DEBUG_LINES_PER_SECOND`] / [`DEBUG_MAX_LINES`] (≈ 20 MB worst case).
//! * The thread's last-error value (= `WSAGetLastError`) is preserved.

use core::fmt::{self, Write as _};
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, Ordering};
use std::sync::OnceLock;

use crate::config::LogSettings;
use crate::ffi;

/// Lines allowed per one-second window.
pub const LINES_PER_SECOND: u32 = 40;
/// Lines allowed per process.
pub const MAX_LINES: u32 = 20_000;
/// Lines per second with `BEACON_LOG_LEVEL=debug` (in-game traffic is ~70/s).
pub const DEBUG_LINES_PER_SECOND: u32 = 500;
/// Lines per process with `BEACON_LOG_LEVEL=debug`.
pub const DEBUG_MAX_LINES: u32 = 200_000;
/// Longest line (longer ones are truncated).
const LINE_CAP: usize = 400;

static SETTINGS: OnceLock<LogSettings> = OnceLock::new();
static DEBUG: AtomicBool = AtomicBool::new(false);
/// 0 = not opened yet, -1 = open failed, else the file handle.
static HANDLE: AtomicIsize = AtomicIsize::new(0);
static LIMITER: RateLimiter = RateLimiter::new(LINES_PER_SECOND, MAX_LINES);

/// Enables logging (called once, from `DllMain`, before anything is logged).
pub fn configure(settings: LogSettings) {
    DEBUG.store(settings.debug, Ordering::Relaxed);
    if settings.debug {
        LIMITER.set_limits(DEBUG_LINES_PER_SECOND, DEBUG_MAX_LINES);
    }
    let _ = SETTINGS.set(settings);
}

/// `true` if logging is on.
pub fn enabled() -> bool {
    SETTINGS.get().is_some()
}

/// `true` if per-datagram lines are wanted.
pub fn debug_enabled() -> bool {
    DEBUG.load(Ordering::Relaxed) && enabled()
}

/// Logs one line (use the `info!` / `debug!` macros).
pub fn write(args: fmt::Arguments<'_>) {
    let Some(settings) = SETTINGS.get() else {
        return;
    };
    // SAFETY: plain Win32 calls without pointer arguments.
    let (saved, now) = unsafe { (ffi::GetLastError(), ffi::GetTickCount()) };
    let admitted = LIMITER.admit(now);
    if let Admit::Write { suppressed, last } = admitted {
        let mut line = LineBuf::new();
        let mut t = ffi::SystemTime::default();
        // SAFETY: `t` is a valid SYSTEMTIME out-parameter.
        unsafe { ffi::GetLocalTime(&mut t) };
        // SAFETY: no arguments.
        let pid = unsafe { ffi::GetCurrentProcessId() };
        let _ = write!(
            line,
            "{:02}:{:02}:{:02}.{:03} [{pid}] ",
            t.hour, t.minute, t.second, t.milliseconds
        );
        if suppressed > 0 {
            let _ = write!(line, "({suppressed} lines suppressed) ");
        }
        let _ = line.write_fmt(args);
        if last {
            let _ = line.write_str(" (log limit reached, further lines dropped)");
        }
        line.end_line();
        if let Some(h) = handle(settings) {
            let mut written = 0u32;
            let bytes = line.as_bytes();
            let len = u32::try_from(bytes.len()).unwrap_or(0);
            // SAFETY: `h` is an open file handle, `bytes` is valid for `len` bytes.
            unsafe {
                ffi::WriteFile(h, bytes.as_ptr().cast(), len, &mut written, core::ptr::null_mut())
            };
        }
    }
    // SAFETY: restores the caller's last-error value.
    unsafe { ffi::SetLastError(saved) };
}

fn handle(settings: &LogSettings) -> Option<ffi::HANDLE> {
    match HANDLE.load(Ordering::Acquire) {
        -1 => return None,
        0 => {}
        h => return Some(h as ffi::HANDLE),
    }
    // SAFETY: the path is NUL-terminated; all other arguments are plain values.
    let new = unsafe {
        ffi::CreateFileW(
            settings.path.as_ptr(),
            ffi::FILE_APPEND_DATA,
            ffi::FILE_SHARE_ALL,
            core::ptr::null_mut(),
            ffi::OPEN_ALWAYS,
            ffi::FILE_ATTRIBUTE_NORMAL,
            core::ptr::null_mut(),
        )
    } as isize;
    let store = if new == ffi::INVALID_HANDLE_VALUE || new == 0 { -1 } else { new };
    match HANDLE.compare_exchange(0, store, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => (store != -1).then_some(store as ffi::HANDLE),
        Err(existing) => {
            if store != -1 {
                // SAFETY: we own `new` and lost the race; close our duplicate.
                unsafe { ffi::CloseHandle(new as ffi::HANDLE) };
            }
            (existing != -1).then_some(existing as ffi::HANDLE)
        }
    }
}

/// Decision of the [`RateLimiter`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    /// Drop this line.
    Drop,
    /// Write it; report `suppressed` dropped lines; `last` = the per-process cap is
    /// reached with this line.
    Write {
        /// Lines dropped since the last written one.
        suppressed: u32,
        /// This is the last line ever written.
        last: bool,
    },
}

/// Lock-free token window: `per_window` lines per 1000 ms, `max_total` overall.
/// Races between threads only make the counts slightly approximate.
pub struct RateLimiter {
    per_window: AtomicU32,
    max_total: AtomicU32,
    window_start: AtomicU32,
    in_window: AtomicU32,
    suppressed: AtomicU32,
    total: AtomicU32,
}

impl RateLimiter {
    /// A limiter.
    pub const fn new(per_window: u32, max_total: u32) -> Self {
        Self {
            per_window: AtomicU32::new(per_window),
            max_total: AtomicU32::new(max_total),
            window_start: AtomicU32::new(0),
            in_window: AtomicU32::new(0),
            suppressed: AtomicU32::new(0),
            total: AtomicU32::new(0),
        }
    }

    /// Changes the limits (before the first line is logged).
    pub fn set_limits(&self, per_window: u32, max_total: u32) {
        self.per_window.store(per_window, Ordering::Relaxed);
        self.max_total.store(max_total, Ordering::Relaxed);
    }

    /// Decides about one line at time `now_ms` (`GetTickCount`, wraps).
    pub fn admit(&self, now_ms: u32) -> Admit {
        let per_window = self.per_window.load(Ordering::Relaxed);
        let max_total = self.max_total.load(Ordering::Relaxed);
        if self.total.load(Ordering::Relaxed) >= max_total {
            return Admit::Drop;
        }
        let start = self.window_start.load(Ordering::Relaxed);
        if now_ms.wrapping_sub(start) >= 1000
            && self
                .window_start
                .compare_exchange(start, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.in_window.store(0, Ordering::Relaxed);
        }
        if self.in_window.fetch_add(1, Ordering::Relaxed) >= per_window {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            return Admit::Drop;
        }
        let n = self.total.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if n > max_total {
            return Admit::Drop;
        }
        Admit::Write { suppressed: self.suppressed.swap(0, Ordering::Relaxed), last: n == max_total }
    }
}

/// Truncating line buffer (`\r\n` always fits).
struct LineBuf {
    buf: [u8; LINE_CAP + 2],
    len: usize,
}

impl LineBuf {
    const fn new() -> Self {
        Self { buf: [0; LINE_CAP + 2], len: 0 }
    }

    fn end_line(&mut self) {
        if let Some(dst) = self.buf.get_mut(self.len..self.len + 2) {
            dst.copy_from_slice(b"\r\n");
            self.len += 2;
        }
    }

    fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }
}

impl fmt::Write for LineBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = LINE_CAP.saturating_sub(self.len);
        let take = s.len().min(room);
        if let (Some(dst), Some(src)) =
            (self.buf.get_mut(self.len..self.len + take), s.as_bytes().get(..take))
        {
            dst.copy_from_slice(src);
            self.len += take;
        }
        Ok(())
    }
}

/// Logs a line if logging is enabled.
macro_rules! info {
    ($($arg:tt)*) => {
        if $crate::log::enabled() {
            $crate::log::write(format_args!($($arg)*));
        }
    };
}

/// Logs a per-datagram line if `BEACON_LOG_LEVEL=debug`.
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::log::debug_enabled() {
            $crate::log::write(format_args!($($arg)*));
        }
    };
}

pub(crate) use {debug, info};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_limits_and_reports_suppressed() {
        let l = RateLimiter::new(3, 100);
        let t0 = 5_000;
        assert_eq!(l.admit(t0), Admit::Write { suppressed: 0, last: false });
        assert_eq!(l.admit(t0 + 1), Admit::Write { suppressed: 0, last: false });
        assert_eq!(l.admit(t0 + 2), Admit::Write { suppressed: 0, last: false });
        assert_eq!(l.admit(t0 + 3), Admit::Drop);
        assert_eq!(l.admit(t0 + 999), Admit::Drop);
        // New window: the two dropped lines are reported.
        assert_eq!(l.admit(t0 + 1000), Admit::Write { suppressed: 2, last: false });
    }

    #[test]
    fn window_survives_tick_wraparound() {
        let l = RateLimiter::new(1, 100);
        assert!(matches!(l.admit(u32::MAX - 10), Admit::Write { .. }));
        assert_eq!(l.admit(u32::MAX - 5), Admit::Drop);
        assert!(matches!(l.admit(2_000), Admit::Write { suppressed: 1, .. }));
    }

    #[test]
    fn limits_can_be_raised() {
        let l = RateLimiter::new(1, 100);
        l.set_limits(3, 100);
        for t in 0..3 {
            assert!(matches!(l.admit(5_000 + t), Admit::Write { .. }));
        }
        assert_eq!(l.admit(5_010), Admit::Drop);
    }

    #[test]
    fn total_cap() {
        let l = RateLimiter::new(1000, 3);
        assert_eq!(l.admit(1), Admit::Write { suppressed: 0, last: false });
        assert_eq!(l.admit(2), Admit::Write { suppressed: 0, last: false });
        assert_eq!(l.admit(3), Admit::Write { suppressed: 0, last: true });
        assert_eq!(l.admit(4), Admit::Drop);
        assert_eq!(l.admit(50_000), Admit::Drop);
    }

    #[test]
    fn line_buffer_truncates() {
        let mut b = LineBuf::new();
        let long = "x".repeat(LINE_CAP + 50);
        let _ = b.write_str(&long);
        b.end_line();
        assert_eq!(b.as_bytes().len(), LINE_CAP + 2);
        assert!(b.as_bytes().ends_with(b"x\r\n"));
    }
}
