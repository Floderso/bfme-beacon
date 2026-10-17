//! IAT slot patching inside the main module (spec 03 §8.4).
//!
//! Every use of an import reads its slot at call time (`call [slot]`, `jmp [slot]`
//! thunks, `mov reg,[slot]` at function entry), so replacing the pointer is enough.
//! The previous value is stored first and is what the hook chains to.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::ffi;

/// The function pointer saved in `slot` (an original stored by [`Slot::patch`]),
/// `None` while nothing is stored.
///
/// # Safety
/// `F` must be the fn-pointer type of the function whose address is stored in
/// `slot` (the signature of the patched import).
pub unsafe fn load_fn<F: Copy>(slot: &AtomicUsize) -> Option<F> {
    const { assert!(core::mem::size_of::<F>() == core::mem::size_of::<usize>()) };
    let v = slot.load(Ordering::Acquire);
    // SAFETY: `F` is a pointer-sized fn-pointer type matching the stored function
    // (caller contract) and `v` is non-null.
    (v != 0).then(|| unsafe { core::mem::transmute_copy::<usize, F>(&v) })
}

/// The function at address `addr` (e.g. the current value of an IAT slot) as `F`,
/// `None` for a null address.
///
/// # Safety
/// `F` must be the fn-pointer type of the function at `addr`.
pub unsafe fn fn_from_addr<F: Copy>(addr: usize) -> Option<F> {
    const { assert!(core::mem::size_of::<F>() == core::mem::size_of::<usize>()) };
    // SAFETY: `F` is a pointer-sized fn-pointer type of the function at `addr`
    // (caller contract) and `addr` is non-null.
    (addr != 0).then(|| unsafe { core::mem::transmute_copy::<usize, F>(&addr) })
}

/// Why a slot could not be patched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatchError {
    /// Slot outside the image or misaligned.
    BadSlot,
    /// The slot does not hold a resolved import (null or pointing into the exe
    /// itself, e.g. an unsnapped hint/name RVA): nothing safe to chain to.
    NotChainable,
    /// `VirtualProtect` failed.
    Protect,
}

/// One import slot of the main module.
#[derive(Clone, Copy)]
pub struct Slot {
    base: usize,
    size: usize,
    rva: u32,
}

impl Slot {
    /// A slot at `rva` inside the image `[base, base + size)`.
    pub const fn new(base: usize, size: usize, rva: u32) -> Self {
        Self { base, size, rva }
    }

    /// RVA of the slot.
    pub const fn rva(&self) -> u32 {
        self.rva
    }

    fn ptr(&self) -> Result<*mut usize, PatchError> {
        let rva = self.rva as usize;
        let width = core::mem::size_of::<usize>();
        let fits = rva.checked_add(width).is_some_and(|end| end <= self.size);
        if !fits || !rva.is_multiple_of(width) {
            return Err(PatchError::BadSlot);
        }
        Ok(self.base.wrapping_add(rva) as *mut usize)
    }

    fn chainable(&self, value: usize) -> bool {
        value != 0 && !(self.base..self.base.wrapping_add(self.size)).contains(&value)
    }

    /// Current slot value.
    ///
    /// # Safety
    /// The slot must lie in a mapped, readable image.
    pub unsafe fn load(&self) -> Result<usize, PatchError> {
        let ptr = self.ptr()?;
        // SAFETY: in-bounds and aligned (checked by `ptr`), mapped (caller contract).
        Ok(unsafe { AtomicUsize::from_ptr(ptr) }.load(Ordering::SeqCst))
    }

    /// Stores `hook` in the slot after saving the current pointer in `orig`.
    /// Idempotent: a slot that already holds `hook` is left alone.
    ///
    /// # Safety
    /// The slot must lie in a mapped image whose IAT nobody else rewrites
    /// concurrently (true under the loader lock / in the first `WSAStartup`).
    pub unsafe fn patch(&self, hook: usize, orig: &AtomicUsize) -> Result<(), PatchError> {
        let ptr = self.ptr()?;
        // SAFETY: as in `load`.
        let current = unsafe { self.load()? };
        if current == hook {
            return Ok(());
        }
        if !self.chainable(current) {
            return Err(PatchError::NotChainable);
        }
        orig.store(current, Ordering::SeqCst);
        // SAFETY: `ptr` is valid for writes once made writable.
        unsafe { write_protected(ptr, hook) }
    }

    /// Puts the saved original back (used when a mandatory patch set fails halfway).
    ///
    /// # Safety
    /// As for [`Slot::patch`].
    pub unsafe fn restore(&self, hook: usize, orig: &AtomicUsize) -> Result<(), PatchError> {
        let ptr = self.ptr()?;
        let original = orig.load(Ordering::SeqCst);
        // SAFETY: as in `load`.
        if original == 0 || unsafe { self.load()? } != hook {
            return Ok(());
        }
        // SAFETY: as in `patch`.
        unsafe { write_protected(ptr, original) }
    }
}

/// Writes one pointer, making the page writable for the duration.
///
/// # Safety
/// `ptr` must be aligned and inside a mapped image.
unsafe fn write_protected(ptr: *mut usize, value: usize) -> Result<(), PatchError> {
    let len = core::mem::size_of::<usize>();
    let mut old = 0u32;
    // SAFETY: `ptr` lies in a mapped image; VirtualProtect validates the range.
    if unsafe { ffi::VirtualProtect(ptr.cast(), len, ffi::PAGE_READWRITE, &mut old) } == 0 {
        return Err(PatchError::Protect);
    }
    // SAFETY: aligned, in-bounds and now writable.
    unsafe { AtomicUsize::from_ptr(ptr) }.store(value, Ordering::SeqCst);
    let mut ignored = 0u32;
    // SAFETY: restores the previous protection of the same range.
    unsafe { ffi::VirtualProtect(ptr.cast(), len, old, &mut ignored) };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_chain_restore() {
        // A fake "image" of 16 pointer slots; slot 2 holds a resolved import that
        // points outside the image.
        let mut image = vec![0usize; 16];
        let base = image.as_mut_ptr() as usize;
        let size = image.len() * core::mem::size_of::<usize>();
        let outside = base.wrapping_add(size + 0x1000);
        image[2] = outside;
        let width = core::mem::size_of::<usize>() as u32;
        let slot = Slot::new(base, size, 2 * width);
        let orig = AtomicUsize::new(0);
        // SAFETY: the slots lie inside `image`, which outlives the calls.
        unsafe {
            assert_eq!(slot.load(), Ok(outside));
            slot.patch(0x1234, &orig).unwrap();
            assert_eq!(slot.load(), Ok(0x1234));
            assert_eq!(orig.load(Ordering::SeqCst), outside);
            // Idempotent.
            slot.patch(0x1234, &orig).unwrap();
            assert_eq!(orig.load(Ordering::SeqCst), outside);
            slot.restore(0x1234, &orig).unwrap();
            assert_eq!(slot.load(), Ok(outside));
        }
        // SAFETY: as above.
        unsafe {
            // Unsnapped (null) and self-pointing slots are refused.
            let null_slot = Slot::new(base, size, 3 * width);
            assert_eq!(null_slot.patch(0x1234, &orig), Err(PatchError::NotChainable));
            image[4] = base + 8;
            let inside = Slot::new(base, size, 4 * width);
            assert_eq!(inside.patch(0x1234, &orig), Err(PatchError::NotChainable));
            // Out of bounds / misaligned.
            assert_eq!(Slot::new(base, size, size as u32).load(), Err(PatchError::BadSlot));
            assert_eq!(Slot::new(base, size, 1).load(), Err(PatchError::BadSlot));
            assert_eq!(Slot::new(base, size, u32::MAX).load(), Err(PatchError::BadSlot));
        }
        drop(image);
    }
}
