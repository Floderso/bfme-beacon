//! Fixed-capacity strings and bounded C-string comparisons (no allocation).

/// A NUL-terminated UTF-16 string with fixed capacity `N` (including the NUL).
#[derive(Clone, Copy)]
pub struct WideBuf<const N: usize> {
    buf: [u16; N],
    len: usize,
}

impl<const N: usize> WideBuf<N> {
    /// An empty string.
    pub const fn new() -> Self {
        Self { buf: [0; N], len: 0 }
    }

    /// Copies `s` (must not contain NUL and must leave room for the terminator).
    pub fn from_slice(s: &[u16]) -> Option<Self> {
        let mut out = Self::new();
        out.push_slice(s).then_some(out)
    }

    /// The characters without the terminator.
    #[cfg(test)]
    pub fn as_slice(&self) -> &[u16] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    /// Pointer to the NUL-terminated string.
    pub fn as_ptr(&self) -> *const u16 {
        self.buf.as_ptr()
    }

    /// Number of characters (without the terminator).
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Appends `s`; `false` (unchanged) if it does not fit or contains NUL.
    pub fn push_slice(&mut self, s: &[u16]) -> bool {
        if s.contains(&0) {
            return false;
        }
        let end = self.len + s.len();
        // `end < N` keeps one slot for the terminator.
        match self.buf.get_mut(self.len..end) {
            Some(dst) if end < N => {
                dst.copy_from_slice(s);
                self.len = end;
                if let Some(nul) = self.buf.get_mut(end) {
                    *nul = 0;
                }
                true
            }
            _ => false,
        }
    }

    /// Appends an ASCII string.
    pub fn push_ascii(&mut self, s: &str) -> bool {
        let start = self.len;
        for b in s.bytes() {
            if !b.is_ascii() || !self.push_slice(&[u16::from(b)]) {
                self.truncate(start);
                return false;
            }
        }
        true
    }

    /// Appends `v` in decimal.
    pub fn push_decimal(&mut self, v: u32) -> bool {
        let mut digits = [0u8; 10];
        let text = format_decimal(v, &mut digits);
        let start = self.len;
        for &d in text {
            if !self.push_slice(&[u16::from(d)]) {
                self.truncate(start);
                return false;
            }
        }
        true
    }

    fn truncate(&mut self, len: usize) {
        if len <= self.len {
            self.len = len;
            if let Some(nul) = self.buf.get_mut(len) {
                *nul = 0;
            }
        }
    }
}

/// Formats `v` in decimal into `buf`, returning the used tail.
pub fn format_decimal(mut v: u32, buf: &mut [u8; 10]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        if let Some(slot) = buf.get_mut(i) {
            // `v % 10 < 10`, the cast cannot truncate.
            *slot = b'0' + (v % 10) as u8;
        }
        v /= 10;
        if v == 0 || i == 0 {
            break;
        }
    }
    buf.get(i..).unwrap_or(&[])
}

/// Case-insensitive (ASCII) comparison of UTF-16 text with an ASCII string.
pub fn wide_eq_ignore_ascii_case(wide: &[u16], ascii: &str) -> bool {
    wide.len() == ascii.len()
        && wide.iter().zip(ascii.bytes()).all(|(&w, a)| {
            u8::try_from(w).is_ok_and(|w| w.is_ascii() && w.eq_ignore_ascii_case(&a))
        })
}

/// Reads a NUL-terminated byte string of at most `max` bytes (without NUL) into
/// `out`; `None` if `ptr` is null or the string is longer.
///
/// # Safety
/// `ptr` must be null or point to a readable NUL-terminated string (or at least
/// `out.len() + 1` readable bytes).
pub unsafe fn read_cstr(ptr: *const u8, out: &mut [u8]) -> Option<&[u8]> {
    if ptr.is_null() {
        return None;
    }
    for i in 0..out.len() {
        // SAFETY: the caller guarantees readability up to the terminator, and we stop
        // at the first NUL.
        let b = unsafe { ptr.add(i).read() };
        if b == 0 {
            return out.get(..i);
        }
        *out.get_mut(i)? = b;
    }
    None
}

/// `true` if the NUL-terminated UTF-16 string at `ptr` equals `expected` exactly.
///
/// # Safety
/// `ptr` must be null or point to a readable NUL-terminated UTF-16 string.
pub unsafe fn wide_cstr_eq(ptr: *const u16, expected: &[u16]) -> bool {
    if ptr.is_null() {
        return false;
    }
    for (i, &e) in expected.iter().enumerate() {
        // SAFETY: we read at most up to the first mismatch or NUL; every earlier
        // character was non-NUL, so the string extends at least to index `i`.
        let c = unsafe { ptr.add(i).read() };
        if c != e {
            return false;
        }
    }
    // SAFETY: all `expected.len()` characters matched non-NUL characters, so the
    // terminator (or another character) is readable at this index.
    unsafe { ptr.add(expected.len()).read() == 0 }
}

/// `true` if the NUL-terminated byte string at `ptr` equals `expected` exactly.
///
/// # Safety
/// `ptr` must be null or point to a readable NUL-terminated string.
pub unsafe fn ansi_cstr_eq(ptr: *const u8, expected: &[u8]) -> bool {
    if ptr.is_null() {
        return false;
    }
    for (i, &e) in expected.iter().enumerate() {
        // SAFETY: see `wide_cstr_eq`.
        let c = unsafe { ptr.add(i).read() };
        if c != e {
            return false;
        }
    }
    // SAFETY: see `wide_cstr_eq`.
    unsafe { ptr.add(expected.len()).read() == 0 }
}

/// Compile-time ASCII → UTF-16 conversion for constants (only used in `const`
/// items, where an out-of-bounds index would be a compile error; the loop bound
/// keeps both indices in range anyway).
#[allow(clippy::indexing_slicing)]
pub const fn ascii_to_utf16<const N: usize>(s: &str) -> [u16; N] {
    let bytes = s.as_bytes();
    let mut out = [0u16; N];
    let mut i = 0;
    while i < N && i < bytes.len() {
        out[i] = bytes[i] as u16;
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn widebuf_push_and_terminate() {
        let mut b = WideBuf::<8>::new();
        assert!(b.push_ascii("abc"));
        assert!(b.push_decimal(42));
        assert_eq!(b.as_slice(), w("abc42").as_slice());
        // 5 chars + NUL used; 2 more fit, a third does not.
        assert!(!b.push_ascii("xyz"));
        assert_eq!(b.as_slice(), w("abc42").as_slice());
        assert!(b.push_ascii("xy"));
        assert_eq!(b.len(), 7);
        // SAFETY: the buffer is NUL-terminated.
        assert_eq!(unsafe { b.as_ptr().add(7).read() }, 0);
        assert!(!b.push_decimal(1));
        assert!(WideBuf::<4>::from_slice(&w("abcd")).is_none());
        assert!(WideBuf::<5>::from_slice(&w("abcd")).is_some());
        assert!(WideBuf::<8>::from_slice(&[0x61, 0, 0x62]).is_none());
        assert!(!WideBuf::<8>::new().push_ascii("é"));
    }

    #[test]
    fn decimal() {
        let mut buf = [0u8; 10];
        assert_eq!(format_decimal(0, &mut buf), b"0");
        assert_eq!(format_decimal(7, &mut buf), b"7");
        assert_eq!(format_decimal(254, &mut buf), b"254");
        assert_eq!(format_decimal(u32::MAX, &mut buf), b"4294967295");
    }

    #[test]
    fn comparisons() {
        assert!(wide_eq_ignore_ascii_case(&w("Ergc"), "ERGC"));
        assert!(!wide_eq_ignore_ascii_case(&w("ergcx"), "ergc"));
        assert!(!wide_eq_ignore_ascii_case(&[0x0130], "I"));
        let s = w("LOTR\0");
        // SAFETY: NUL-terminated test strings.
        unsafe {
            assert!(wide_cstr_eq(s.as_ptr(), &w("LOTR")));
            assert!(!wide_cstr_eq(s.as_ptr(), &w("LOT")));
            assert!(!wide_cstr_eq(s.as_ptr(), &w("LOTRX")));
            assert!(!wide_cstr_eq(core::ptr::null(), &w("LOTR")));
            assert!(ansi_cstr_eq(c"abc".as_ptr().cast(), b"abc"));
            assert!(!ansi_cstr_eq(c"abcd".as_ptr().cast(), b"abc"));
            assert!(!ansi_cstr_eq(c"ab".as_ptr().cast(), b"abc"));
            let mut out = [0u8; 4];
            assert_eq!(read_cstr(c"abc".as_ptr().cast(), &mut out), Some(&b"abc"[..]));
            assert_eq!(read_cstr(c"abcd".as_ptr().cast(), &mut out), None);
            assert_eq!(read_cstr(core::ptr::null(), &mut out), None);
        }
        assert_eq!(ascii_to_utf16::<3>("ab"), [0x61, 0x62, 0]);
    }
}
