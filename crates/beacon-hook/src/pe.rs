//! Bounds-checked PE32 reading: the identity check of spec 03 §8.4 and import
//! table walking by name (IAT slots are found by import name, never hardcoded).
//!
//! Works on any [`Image`]: the live main module (`LiveImage`) or a byte buffer laid
//! out like a loaded image (unit tests).

/// `IMAGE_FILE_HEADER.TimeDateStamp` of `lotrbfme.exe` 1.03 (retail and workshop).
pub const BFME_TIMESTAMP: u32 = 0x438B_ABC8;
/// `IMAGE_OPTIONAL_HEADER32.SizeOfImage` of `lotrbfme.exe` 1.03.
pub const BFME_SIZE_OF_IMAGE: u32 = 0x0101_6000;
/// `FirstThunk` (IAT RVA) of the exe's `WS2_32.dll` import descriptor.
pub const BFME_WS2_32_FIRST_THUNK: u32 = 0x00F5_8CB0;
/// The exe's `WS2_32.dll` imports, in descriptor order (spec 03 §3.2).
pub const BFME_WS2_32_IMPORTS: [&str; 5] = ["WSAIoctl", "getsockopt", "recv", "recvfrom", "setsockopt"];

const MAX_DESCRIPTORS: usize = 1024;
const MAX_THUNKS: usize = 8192;
const MAX_NAME: usize = 256;
const ORDINAL_FLAG: u32 = 0x8000_0000;

/// Read access to a mapped image by RVA.
pub trait Image {
    /// Mapped size (`SizeOfImage`).
    fn size(&self) -> usize;

    /// Copies `out.len()` bytes at `rva`; `false` if the range is outside the image.
    fn read(&self, rva: usize, out: &mut [u8]) -> bool;

    /// Little-endian `u16` at `rva`.
    fn u16_at(&self, rva: usize) -> Option<u16> {
        let mut b = [0u8; 2];
        self.read(rva, &mut b).then(|| u16::from_le_bytes(b))
    }

    /// Little-endian `u32` at `rva`.
    fn u32_at(&self, rva: usize) -> Option<u32> {
        let mut b = [0u8; 4];
        self.read(rva, &mut b).then(|| u32::from_le_bytes(b))
    }
}

impl Image for [u8] {
    fn size(&self) -> usize {
        self.len()
    }

    fn read(&self, rva: usize, out: &mut [u8]) -> bool {
        match rva.checked_add(out.len()).and_then(|end| self.get(rva..end)) {
            Some(src) => {
                out.copy_from_slice(src);
                true
            }
            None => false,
        }
    }
}

/// The live image of a loaded module.
pub struct LiveImage {
    base: *const u8,
    size: usize,
}

impl LiveImage {
    /// Size assumed for the header page before `SizeOfImage` is known.
    const HEADER_PAGE: usize = 0x1000;

    /// Wraps a loaded module: reads `SizeOfImage` from its (validated) headers.
    ///
    /// # Safety
    /// `base` must be the base address of a module mapped by the loader (its header
    /// page and `SizeOfImage` bytes are mapped and readable).
    pub unsafe fn from_module(base: *const u8) -> Option<Self> {
        if base.is_null() {
            return None;
        }
        let header = Self { base, size: Self::HEADER_PAGE };
        let info = parse_headers(&header).ok()?;
        let size = usize::try_from(info.size_of_image).ok()?;
        (size >= Self::HEADER_PAGE).then_some(Self { base, size })
    }

    /// Base address.
    pub const fn base(&self) -> *const u8 {
        self.base
    }
}

impl Image for LiveImage {
    fn size(&self) -> usize {
        self.size
    }

    fn read(&self, rva: usize, out: &mut [u8]) -> bool {
        if rva.checked_add(out.len()).is_none_or(|end| end > self.size) {
            return false;
        }
        for (i, dst) in out.iter_mut().enumerate() {
            // SAFETY: `rva + i < size` and the whole image is mapped (constructor
            // contract). Volatile because other threads may write IAT slots.
            *dst = unsafe { self.base.add(rva + i).read_volatile() };
        }
        true
    }
}

/// Malformed or unexpected image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeError {
    /// No `MZ` signature.
    NoDosHeader,
    /// No `PE\0\0` signature.
    NoPeHeader,
    /// Not a PE32 i386 image.
    NotPe32,
    /// A header, descriptor, thunk or name lies outside the image.
    OutOfBounds,
    /// Unterminated import table or name (beyond the safety limits).
    Unterminated,
}

/// The header fields the hook needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Headers {
    /// `IMAGE_FILE_HEADER.TimeDateStamp`.
    pub time_date_stamp: u32,
    /// `IMAGE_OPTIONAL_HEADER32.SizeOfImage`.
    pub size_of_image: u32,
    /// Import directory RVA (0 if none).
    pub import_rva: u32,
}

/// `base + offset` without wrap-around.
fn at(base: usize, offset: usize) -> Result<usize, PeError> {
    base.checked_add(offset).ok_or(PeError::OutOfBounds)
}

fn u16_at(img: &(impl Image + ?Sized), base: usize, offset: usize) -> Result<u16, PeError> {
    img.u16_at(at(base, offset)?).ok_or(PeError::OutOfBounds)
}

fn u32_at(img: &(impl Image + ?Sized), base: usize, offset: usize) -> Result<u32, PeError> {
    img.u32_at(at(base, offset)?).ok_or(PeError::OutOfBounds)
}

/// Parses DOS, file and optional headers of a PE32 i386 image.
pub fn parse_headers(img: &(impl Image + ?Sized)) -> Result<Headers, PeError> {
    if img.u16_at(0) != Some(0x5A4D) {
        return Err(PeError::NoDosHeader);
    }
    let nt = u32_at(img, 0x3C, 0)? as usize;
    if img.u32_at(nt) != Some(0x0000_4550) {
        return Err(PeError::NoPeHeader);
    }
    let machine = u16_at(img, nt, 4)?;
    let time_date_stamp = u32_at(img, nt, 8)?;
    let opt = at(nt, 24)?;
    let magic = u16_at(img, opt, 0)?;
    if machine != 0x014C || magic != 0x010B {
        return Err(PeError::NotPe32);
    }
    let size_of_image = u32_at(img, opt, 56)?;
    let dirs = u32_at(img, opt, 92)?;
    let import_rva = if dirs >= 2 { u32_at(img, opt, 104)? } else { 0 };
    Ok(Headers { time_date_stamp, size_of_image, import_rva })
}

/// One `IMAGE_IMPORT_DESCRIPTOR`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportDescriptor {
    /// `OriginalFirstThunk` (import lookup table), 0 if absent.
    pub original_first_thunk: u32,
    /// `FirstThunk` (the IAT).
    pub first_thunk: u32,
}

impl ImportDescriptor {
    /// The table holding the names (the lookup table, or the IAT for old linkers).
    const fn lookup(&self) -> u32 {
        if self.original_first_thunk != 0 {
            self.original_first_thunk
        } else {
            self.first_thunk
        }
    }
}

/// Compares the NUL-terminated string at `rva` with `expected`.
fn name_eq(img: &(impl Image + ?Sized), rva: usize, expected: &str, ignore_case: bool) -> Result<bool, PeError> {
    let expected = expected.as_bytes();
    for i in 0..MAX_NAME {
        let mut b = [0u8; 1];
        if !img.read(at(rva, i)?, &mut b) {
            return Err(PeError::OutOfBounds);
        }
        let [c] = b;
        match expected.get(i) {
            None => return Ok(c == 0),
            Some(&e) if c == e || (ignore_case && c.eq_ignore_ascii_case(&e)) => {}
            Some(_) => return Ok(false),
        }
    }
    Err(PeError::Unterminated)
}

/// Finds the import descriptor of `dll` (case-insensitive, e.g. `"WS2_32.dll"`).
pub fn find_descriptor(
    img: &(impl Image + ?Sized),
    headers: &Headers,
    dll: &str,
) -> Result<Option<ImportDescriptor>, PeError> {
    if headers.import_rva == 0 {
        return Ok(None);
    }
    let table = headers.import_rva as usize;
    for i in 0..MAX_DESCRIPTORS {
        let desc = at(table, i * 20)?;
        let oft = u32_at(img, desc, 0)?;
        let name = u32_at(img, desc, 12)?;
        let ft = u32_at(img, desc, 16)?;
        if oft == 0 && name == 0 && ft == 0 {
            return Ok(None);
        }
        if name != 0 && name_eq(img, name as usize, dll, true)? {
            return Ok(Some(ImportDescriptor { original_first_thunk: oft, first_thunk: ft }));
        }
    }
    Err(PeError::Unterminated)
}

/// The import names of a descriptor, visited in order (`None` for ordinal imports).
fn for_each_import(
    img: &(impl Image + ?Sized),
    desc: &ImportDescriptor,
    mut f: impl FnMut(usize, Option<usize>) -> Result<bool, PeError>,
) -> Result<usize, PeError> {
    let lookup = desc.lookup() as usize;
    for i in 0..MAX_THUNKS {
        let thunk = u32_at(img, lookup, 4 * i)?;
        if thunk == 0 {
            return Ok(i);
        }
        // Hint/name entry: u16 hint, then the name.
        let name = if thunk & ORDINAL_FLAG == 0 { Some(at(thunk as usize, 2)?) } else { None };
        if !f(i, name)? {
            return Ok(i);
        }
    }
    Err(PeError::Unterminated)
}

/// RVA of the IAT slot importing `func` (exact, case-sensitive name) from `desc`.
pub fn find_slot(img: &(impl Image + ?Sized), desc: &ImportDescriptor, func: &str) -> Result<Option<u32>, PeError> {
    let mut found = None;
    for_each_import(img, desc, |i, name| match name {
        Some(name) if name_eq(img, name, func, false)? => {
            found = Some(i);
            Ok(false)
        }
        _ => Ok(true),
    })?;
    match found {
        Some(i) => {
            let i = u32::try_from(i).map_err(|_| PeError::OutOfBounds)?;
            Ok(Some(desc.first_thunk.wrapping_add(4 * i)))
        }
        None => Ok(None),
    }
}

/// `true` if `desc` imports exactly `names`, in this order, and nothing else.
pub fn imports_exactly(img: &(impl Image + ?Sized), desc: &ImportDescriptor, names: &[&str]) -> Result<bool, PeError> {
    let mut all_match = true;
    let count = for_each_import(img, desc, |i, name| {
        let ok = match (names.get(i), name) {
            (Some(expected), Some(name)) => name_eq(img, name, expected, false)?,
            _ => false,
        };
        all_match &= ok;
        Ok(ok)
    })?;
    Ok(all_match && count == names.len())
}

/// Identity check of spec 03 §8.4: `lotrbfme.exe` 1.03 (TimeDateStamp, SizeOfImage
/// and the exact `WS2_32.dll` descriptor layout). Anything else (e.g.
/// `worldbuilder.exe`) keeps the hook passive.
pub fn is_bfme_103(img: &(impl Image + ?Sized)) -> bool {
    let Ok(headers) = parse_headers(img) else {
        return false;
    };
    if headers.time_date_stamp != BFME_TIMESTAMP || headers.size_of_image != BFME_SIZE_OF_IMAGE {
        return false;
    }
    match find_descriptor(img, &headers, "WS2_32.dll") {
        Ok(Some(desc)) => {
            desc.first_thunk == BFME_WS2_32_FIRST_THUNK
                && imports_exactly(img, &desc, &BFME_WS2_32_IMPORTS) == Ok(true)
        }
        _ => false,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds a minimal PE32 image (already "mapped": RVA = offset).
    pub(crate) struct Builder {
        pub img: Vec<u8>,
        imports: Vec<(String, Vec<Result<String, u16>>)>,
        pub timestamp: u32,
        pub size_override: Option<u32>,
    }

    pub(crate) const NT: usize = 0x80;
    const IMPORT_DIR: usize = 0x400;

    impl Builder {
        pub(crate) fn new() -> Self {
            Self { img: vec![0; 0x4000], imports: Vec::new(), timestamp: BFME_TIMESTAMP, size_override: None }
        }

        pub(crate) fn import(mut self, dll: &str, funcs: &[&str]) -> Self {
            self.imports.push((dll.into(), funcs.iter().map(|f| Ok(f.to_string())).collect()));
            self
        }

        pub(crate) fn import_ordinal(mut self, dll: &str, ordinal: u16) -> Self {
            self.imports.push((dll.into(), vec![Err(ordinal)]));
            self
        }

        fn put16(&mut self, at: usize, v: u16) {
            self.img[at..at + 2].copy_from_slice(&v.to_le_bytes());
        }

        pub(crate) fn put32(&mut self, at: usize, v: u32) {
            self.img[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }

        fn put_str(&mut self, at: usize, s: &str) -> usize {
            self.img[at..at + s.len()].copy_from_slice(s.as_bytes());
            self.img[at + s.len()] = 0;
            at + s.len() + 1
        }

        /// Returns the image and, per import (in order), the IAT RVA of its first slot.
        pub(crate) fn build(mut self) -> (Vec<u8>, Vec<u32>) {
            self.put16(0, 0x5A4D);
            self.put32(0x3C, NT as u32);
            self.put32(NT, 0x4550);
            self.put16(NT + 4, 0x014C);
            self.put32(NT + 8, self.timestamp);
            let opt = NT + 24;
            self.put16(opt, 0x010B);
            let size = self.size_override.unwrap_or(self.img.len() as u32);
            self.put32(opt + 56, size);
            self.put32(opt + 92, 16);
            self.put32(opt + 104, IMPORT_DIR as u32);
            let imports = std::mem::take(&mut self.imports);
            let mut data = 0x1000usize; // names and thunk tables
            let mut firsts = Vec::new();
            for (i, (dll, funcs)) in imports.iter().enumerate() {
                let desc = IMPORT_DIR + 20 * i;
                let name_rva = data;
                data = self.put_str(data, dll);
                data = (data + 3) & !3;
                let oft = data;
                data += 4 * (funcs.len() + 1);
                let ft = data;
                data += 4 * (funcs.len() + 1);
                for (j, f) in funcs.iter().enumerate() {
                    let thunk = match f {
                        Ok(name) => {
                            let hint = data;
                            data = self.put_str(hint + 2, name);
                            data = (data + 1) & !1;
                            hint as u32
                        }
                        Err(ordinal) => ORDINAL_FLAG | u32::from(*ordinal),
                    };
                    self.put32(oft + 4 * j, thunk);
                    self.put32(ft + 4 * j, thunk);
                }
                self.put32(desc, oft as u32);
                self.put32(desc + 12, name_rva as u32);
                self.put32(desc + 16, ft as u32);
                firsts.push(ft as u32);
            }
            (self.img, firsts)
        }
    }

    #[test]
    fn headers_and_import_walk() {
        let (img, firsts) = Builder::new()
            .import("KERNEL32.dll", &["CreateMutexA", "CreateMutexW"])
            .import("ws2_32.DLL", &["recv", "recvfrom"])
            .import_ordinal("WSOCK32.dll", 23)
            .build();
        let img = img.as_slice();
        let h = parse_headers(img).unwrap();
        assert_eq!(h.time_date_stamp, BFME_TIMESTAMP);
        assert_eq!(h.size_of_image as usize, img.len());
        let k32 = find_descriptor(img, &h, "kernel32.dll").unwrap().unwrap();
        assert_eq!(k32.first_thunk, firsts[0]);
        assert_eq!(find_slot(img, &k32, "CreateMutexW").unwrap(), Some(firsts[0] + 4));
        assert_eq!(find_slot(img, &k32, "CreateMutexA").unwrap(), Some(firsts[0]));
        // Function names are case-sensitive.
        assert_eq!(find_slot(img, &k32, "createmutexa").unwrap(), None);
        assert_eq!(find_slot(img, &k32, "CreateMutex").unwrap(), None);
        let ws2 = find_descriptor(img, &h, "WS2_32.dll").unwrap().unwrap();
        assert_eq!(find_slot(img, &ws2, "recvfrom").unwrap(), Some(firsts[1] + 4));
        assert!(imports_exactly(img, &ws2, &["recv", "recvfrom"]).unwrap());
        assert!(!imports_exactly(img, &ws2, &["recvfrom", "recv"]).unwrap());
        assert!(!imports_exactly(img, &ws2, &["recv"]).unwrap());
        assert!(!imports_exactly(img, &ws2, &["recv", "recvfrom", "x"]).unwrap());
        let ws1 = find_descriptor(img, &h, "WSOCK32.dll").unwrap().unwrap();
        assert_eq!(find_slot(img, &ws1, "socket").unwrap(), None);
        assert_eq!(find_descriptor(img, &h, "SHELL32.dll").unwrap(), None);
        assert!(!is_bfme_103(img), "size and WS2_32 layout differ");
    }

    #[test]
    fn identity_requires_every_property() {
        let ok = || Builder::new().import("WS2_32.dll", &BFME_WS2_32_IMPORTS);
        // The IAT RVA is not 0x00F58CB0 in a small synthetic image.
        let (img, _) = ok().build();
        assert!(!is_bfme_103(img.as_slice()));
        // Patch FirstThunk and SizeOfImage to the real values: identity holds.
        let mut b = ok();
        b.size_override = Some(BFME_SIZE_OF_IMAGE);
        let (mut img, _) = b.build();
        img[IMPORT_DIR + 16..IMPORT_DIR + 20].copy_from_slice(&BFME_WS2_32_FIRST_THUNK.to_le_bytes());
        assert!(is_bfme_103(img.as_slice()));
        // Wrong timestamp.
        let mut t = img.clone();
        t[NT + 8] ^= 1;
        assert!(!is_bfme_103(t.as_slice()));
        // Wrong size.
        let mut s = img.clone();
        s[NT + 24 + 56] ^= 0x10;
        assert!(!is_bfme_103(s.as_slice()));
        // Wrong import order.
        let mut b = Builder::new().import("WS2_32.dll", &["getsockopt", "WSAIoctl", "recv", "recvfrom", "setsockopt"]);
        b.size_override = Some(BFME_SIZE_OF_IMAGE);
        let (mut o, _) = b.build();
        o[IMPORT_DIR + 16..IMPORT_DIR + 20].copy_from_slice(&BFME_WS2_32_FIRST_THUNK.to_le_bytes());
        assert!(!is_bfme_103(o.as_slice()));
    }

    #[test]
    fn malformed_images_are_rejected_without_panicking() {
        assert_eq!(parse_headers(&[][..]), Err(PeError::NoDosHeader));
        let (img, _) = Builder::new().import("WS2_32.dll", &["recv"]).build();
        let mut bad = img.clone();
        bad[0x3C..0x40].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        assert_eq!(parse_headers(bad.as_slice()), Err(PeError::NoPeHeader));
        // NT headers cut off right after the signature.
        let mut cut = img[..NT + 6].to_vec();
        cut[0x3C..0x40].copy_from_slice(&(NT as u32).to_le_bytes());
        assert_eq!(parse_headers(cut.as_slice()), Err(PeError::OutOfBounds));
        let mut bad = img.clone();
        bad[NT] = 0;
        assert_eq!(parse_headers(bad.as_slice()), Err(PeError::NoPeHeader));
        let mut bad = img.clone();
        bad[NT + 4] = 0x64; // AMD64
        assert_eq!(parse_headers(bad.as_slice()), Err(PeError::NotPe32));
        // Import directory pointing outside the image.
        let mut bad = img.clone();
        bad[NT + 24 + 104..NT + 24 + 108].copy_from_slice(&0x7FFF_0000u32.to_le_bytes());
        let h = parse_headers(bad.as_slice()).unwrap();
        assert_eq!(find_descriptor(bad.as_slice(), &h, "WS2_32.dll"), Err(PeError::OutOfBounds));
        // Thunk pointing outside the image.
        let h = parse_headers(img.as_slice()).unwrap();
        let d = find_descriptor(img.as_slice(), &h, "WS2_32.dll").unwrap().unwrap();
        let mut bad = img.clone();
        let oft = d.original_first_thunk as usize;
        bad[oft..oft + 4].copy_from_slice(&0x7FFF_0000u32.to_le_bytes());
        assert_eq!(find_slot(bad.as_slice(), &d, "recv"), Err(PeError::OutOfBounds));
        // Truncated buffers of every length never panic.
        for len in 0..img.len().min(0x1400) {
            let cut = &img[..len];
            let _ = is_bfme_103(cut);
            if let Ok(h) = parse_headers(cut) {
                if let Ok(Some(d)) = find_descriptor(cut, &h, "WS2_32.dll") {
                    let _ = find_slot(cut, &d, "recv");
                }
            }
        }
        // Random garbage.
        let mut x: u32 = 0x1234_5678;
        let mut junk = img.clone();
        for _ in 0..2000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let at = x as usize % junk.len();
            junk[at] = (x >> 24) as u8;
            let _ = is_bfme_103(junk.as_slice());
        }
    }

    /// Maps a PE file like the loader does (headers + sections at their RVAs).
    pub(crate) fn map_file(path: &str) -> Option<Vec<u8>> {
        let file = std::fs::read(path).ok()?;
        let u16_at = |at: usize| u16::from_le_bytes([file[at], file[at + 1]]) as usize;
        let u32_at = |at: usize| u32::from_le_bytes(file[at..at + 4].try_into().unwrap()) as usize;
        let nt = u32_at(0x3C);
        let opt = nt + 24;
        let size = u32_at(opt + 56);
        let headers = u32_at(opt + 60);
        let sections = u16_at(nt + 6);
        let table = opt + u16_at(nt + 20);
        let mut img = vec![0u8; size];
        img[..headers].copy_from_slice(&file[..headers]);
        for s in 0..sections {
            let at = table + 40 * s;
            let (va, raw_size, raw_ptr) = (u32_at(at + 12), u32_at(at + 16), u32_at(at + 20));
            let n = raw_size.min(size - va).min(file.len() - raw_ptr);
            img[va..va + n].copy_from_slice(&file[raw_ptr..raw_ptr + n]);
        }
        Some(img)
    }

    #[test]
    fn real_game_executables_if_installed() {
        // Read-only use of the user's install; skipped where BFME is not installed.
        let Some(exe) = map_file(r"C:\BFME1\lotrbfme.exe") else {
            eprintln!("C:\\BFME1\\lotrbfme.exe not found; skipped");
            return;
        };
        let img = exe.as_slice();
        assert!(is_bfme_103(img));
        let h = parse_headers(img).unwrap();
        let ws2 = find_descriptor(img, &h, "WS2_32.dll").unwrap().unwrap();
        let expected = [0x00F5_8CB0, 0x00F5_8CB4, 0x00F5_8CB8, 0x00F5_8CBC, 0x00F5_8CC0];
        for (name, rva) in BFME_WS2_32_IMPORTS.iter().zip(expected) {
            assert_eq!(find_slot(img, &ws2, name).unwrap(), Some(rva), "{name}");
        }
        let slot = |dll: &str, f: &str| {
            let d = find_descriptor(img, &h, dll).unwrap().unwrap();
            find_slot(img, &d, f).unwrap()
        };
        // The slots the hook patches besides WS2_32 (pefile listing in the README).
        assert_eq!(slot("ADVAPI32.dll", "RegQueryValueExA"), Some(0x00F5_9154));
        assert_eq!(slot("ADVAPI32.dll", "RegQueryValueExW"), Some(0x00F5_9158));
        assert_eq!(slot("KERNEL32.dll", "CreateMutexA"), Some(0x00F5_8CF4));
        assert_eq!(slot("KERNEL32.dll", "CreateMutexW"), Some(0x00F5_8CF8));
        assert_eq!(slot("SHELL32.dll", "SHGetSpecialFolderPathA"), Some(0x00F5_9170));
        assert_eq!(slot("SHELL32.dll", "SHGetSpecialFolderPathW"), Some(0x00F5_9174));
        assert_eq!(slot("WSOCK32.dll", "socket"), Some(0x00F5_9740));

        if let Some(wb) = map_file(r"C:\BFME1\worldbuilder.exe") {
            assert!(!is_bfme_103(wb.as_slice()), "worldbuilder.exe must stay passive");
        }
    }
}
