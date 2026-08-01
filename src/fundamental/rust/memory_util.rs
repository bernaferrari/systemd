// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/memory-util.h,
//            src/fundamental/memory-util.c
//
// Memory utilities: alignment, zeroing, uniform-byte checks, and pointer
// alignment validation.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use crate::macro_fundamental::is_power_of_2;
use core::ffi::c_void;

// ── Alignment helpers ────────────────────────────────────────────────────

#[inline]
pub fn align_to(l: usize, ali: usize) -> usize {
    debug_assert!(is_power_of_2(ali as u64));
    if l > usize::MAX - (ali - 1) {
        return usize::MAX;
    }
    (l + (ali - 1)) & !(ali - 1)
}

#[inline]
pub fn align_to_u64(l: u64, ali: u64) -> u64 {
    debug_assert!(is_power_of_2(ali));
    if l > u64::MAX - (ali - 1) {
        return u64::MAX;
    }
    (l + (ali - 1)) & !(ali - 1)
}

#[inline]
pub fn align_down(l: usize, ali: usize) -> usize {
    debug_assert!(is_power_of_2(ali as u64));
    l & !(ali - 1)
}

#[inline]
pub fn align_down_u64(l: u64, ali: u64) -> u64 {
    debug_assert!(is_power_of_2(ali));
    l & !(ali - 1)
}

#[inline]
pub fn align_offset(l: usize, ali: usize) -> usize {
    debug_assert!(is_power_of_2(ali as u64));
    l & (ali - 1)
}

#[inline]
pub fn align_offset_u64(l: u64, ali: u64) -> u64 {
    debug_assert!(is_power_of_2(ali));
    l & (ali - 1)
}

// ── Convenience alignment functions ───────────────────────────────────────

#[inline]
pub fn align2(l: usize) -> usize {
    align_to(l, 2)
}

#[inline]
pub fn align4(l: usize) -> usize {
    align_to(l, 4)
}

#[inline]
pub fn align8(l: usize) -> usize {
    align_to(l, 8)
}

#[inline]
pub fn align_ptr_size(l: usize) -> usize {
    align_to(l, core::mem::size_of::<usize>())
}

// ── Pointer alignment ────────────────────────────────────────────────────

#[inline]
pub fn is_aligned16(p: *const c_void) -> bool {
    (p as usize).is_multiple_of(core::mem::align_of::<u16>())
}

#[inline]
pub fn is_aligned32(p: *const c_void) -> bool {
    (p as usize).is_multiple_of(core::mem::align_of::<u32>())
}

#[inline]
pub fn is_aligned64(p: *const c_void) -> bool {
    (p as usize).is_multiple_of(core::mem::align_of::<u64>())
}

// ── Pointer alignment casting ────────────────────────────────────────────

#[inline]
pub fn align2_ptr(p: *const c_void) -> *const c_void {
    align2(p as usize) as *const c_void
}

#[inline]
pub fn align4_ptr(p: *const c_void) -> *const c_void {
    align4(p as usize) as *const c_void
}

#[inline]
pub fn align8_ptr(p: *const c_void) -> *const c_void {
    align8(p as usize) as *const c_void
}

#[inline]
pub fn align_ptr(p: *const c_void) -> *const c_void {
    align_ptr_size(p as usize) as *const c_void
}

// ── memeqbyte ────────────────────────────────────────────────────────────

pub fn memeqbyte(byte: u8, data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }

    let check = 16.min(data.len());
    for item in data.iter().take(check) {
        if *item != byte {
            return false;
        }
    }

    if data.len() <= 16 {
        return true;
    }

    data[..data.len() - 16] == data[16..]
}

#[inline]
pub fn memeqzero(data: &[u8]) -> bool {
    memeqbyte(0x00, data)
}

// ── eqzero ───────────────────────────────────────────────────────────────

/// Check if a fixed-size array is all zeros.
pub fn eqzero<T: AsRef<[u8]>>(val: &T) -> bool {
    memeqzero(val.as_ref())
}

// ── explicit_bzero_safe ──────────────────────────────────────────────────

/// Overwrite a caller-owned memory region with zero bytes.
///
/// # Safety
///
/// If `len` is nonzero, `p` must be non-null, properly allocated, and valid
/// for writes of `len` consecutive bytes. No live reference may be used to
/// access the region during the overwrite.
pub unsafe fn explicit_bzero_safe(p: *mut c_void, len: usize) {
    if !p.is_null() && len > 0 {
        // SAFETY: the caller guarantees that the complete region is writable.
        unsafe_ffi!({
            core::ptr::write_bytes(p.cast::<u8>(), 0, len);
        });
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

// ── memzero ──────────────────────────────────────────────────────────────

pub fn memzero(data: &mut [u8]) {
    for b in data.iter_mut() {
        *b = 0;
    }
}

// ── VarEraser ────────────────────────────────────────────────────────────

pub struct VarEraser<'a> {
    data: &'a mut [u8],
}

impl<'a> VarEraser<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    pub fn erase(&mut self) {
        // SAFETY: the exclusive slice proves that its pointer is writable for
        // exactly its length and remains alive for this call.
        unsafe {
            explicit_bzero_safe(self.data.as_mut_ptr().cast(), self.data.len());
        }
    }
}

impl Drop for VarEraser<'_> {
    fn drop(&mut self) {
        self.erase();
    }
}

// ── Const-time alignment ─────────────────────────────────────────────────

pub const fn const_align_to(l: usize, ali: usize) -> usize {
    if l > usize::MAX - (ali - 1) {
        usize::MAX
    } else {
        (l + (ali - 1)) & !(ali - 1)
    }
}

// ── Cast-align pointer ───────────────────────────────────────────────────

/// Check if a pointer is aligned for a given type `T`, then cast.
pub fn cast_align_ptr<T>(p: *const c_void) -> *const T {
    assert_eq!(
        (p as usize) % core::mem::align_of::<T>(),
        0,
        "Pointer is not aligned for type"
    );
    p as *const T
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_to_basic() {
        assert_eq!(align_to(0, 8), 0);
        assert_eq!(align_to(1, 8), 8);
        assert_eq!(align_to(7, 8), 8);
        assert_eq!(align_to(8, 8), 8);
        assert_eq!(align_to(9, 8), 16);
    }

    #[test]
    fn test_align_to_power_of_two() {
        assert_eq!(align_to(15, 16), 16);
        assert_eq!(align_to(16, 16), 16);
        assert_eq!(align_to(17, 16), 32);
    }

    #[test]
    fn test_align_to_overflow() {
        assert_eq!(align_to(usize::MAX, 2), usize::MAX);
        assert_eq!(align_to(usize::MAX - 1, 4), usize::MAX);
    }

    #[test]
    fn test_align_down() {
        assert_eq!(align_down(0, 8), 0);
        assert_eq!(align_down(7, 8), 0);
        assert_eq!(align_down(8, 8), 8);
        assert_eq!(align_down(15, 8), 8);
        assert_eq!(align_down(16, 8), 16);
    }

    #[test]
    fn test_align_offset() {
        assert_eq!(align_offset(0, 8), 0);
        assert_eq!(align_offset(1, 8), 1);
        assert_eq!(align_offset(7, 8), 7);
        assert_eq!(align_offset(8, 8), 0);
        assert_eq!(align_offset(9, 8), 1);
    }

    #[test]
    fn test_align_to_u64() {
        assert_eq!(align_to_u64(1, 8), 8);
        assert_eq!(align_to_u64(7, 8), 8);
        assert_eq!(align_to_u64(8, 8), 8);
        assert_eq!(align_to_u64(9, 8), 16);
    }

    #[test]
    fn test_align_down_u64() {
        assert_eq!(align_down_u64(7, 8), 0);
        assert_eq!(align_down_u64(8, 8), 8);
        assert_eq!(align_down_u64(15, 8), 8);
    }

    #[test]
    fn test_align_offset_u64() {
        assert_eq!(align_offset_u64(0, 8), 0);
        assert_eq!(align_offset_u64(5, 8), 5);
        assert_eq!(align_offset_u64(8, 8), 0);
    }

    #[test]
    fn test_align2_4_8() {
        assert_eq!(align2(1), 2);
        assert_eq!(align4(3), 4);
        assert_eq!(align8(5), 8);
    }

    #[test]
    fn test_memeqbyte_uniform() {
        let buf = [0x42u8; 32];
        assert!(memeqbyte(0x42, &buf));
    }

    #[test]
    fn test_memeqbyte_mismatch() {
        let mut buf = [0x42u8; 32];
        buf[10] = 0x43;
        assert!(!memeqbyte(0x42, &buf));
    }

    #[test]
    fn test_memeqbyte_empty() {
        assert!(memeqbyte(0x00, &[]));
    }

    #[test]
    fn test_memeqbyte_short() {
        assert!(memeqbyte(0xFF, &[0xFF, 0xFF, 0xFF]));
        assert!(!memeqbyte(0xFF, &[0xFF, 0xFE, 0xFF]));
    }

    #[test]
    fn test_memeqbyte_long() {
        let buf = [0xABu8; 256];
        assert!(memeqbyte(0xAB, &buf));
        assert!(!memeqbyte(0xAC, &buf));
    }

    #[test]
    fn test_memeqzero() {
        assert!(memeqzero(&[0u8; 128]));
        let mut non_zero = [0u8; 128];
        non_zero[127] = 1;
        assert!(!memeqzero(&non_zero));
    }

    #[test]
    fn test_eqzero() {
        assert!(eqzero(&[0u8; 16]));
        assert!(!eqzero(&[0u8, 1u8]));
    }

    #[test]
    fn test_explicit_bzero_safe() {
        let mut buf = [0xABu8; 16];
        // SAFETY: `buf.as_mut_ptr()` is valid for 16 bytes and the call writes exactly those bytes.
        unsafe_ffi!({
            explicit_bzero_safe(buf.as_mut_ptr() as *mut c_void, 16);
        });
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn test_explicit_bzero_safe_null() {
        // SAFETY: helper is defined to no-op for null pointers, so this does not dereference memory.
        unsafe_ffi!({
            explicit_bzero_safe(core::ptr::null_mut(), 16);
        })
    }

    #[test]
    fn test_explicit_bzero_safe_zero_len() {
        let mut buf = [0xABu8; 4];
        // SAFETY: pointer is valid and `len == 0`, so the call is a no-op.
        unsafe_ffi!({
            explicit_bzero_safe(buf.as_mut_ptr() as *mut c_void, 0);
        });
        assert_eq!(buf, [0xABu8; 4]);
    }

    #[test]
    fn test_memzero() {
        let mut buf = [0xFFu8; 8];
        memzero(&mut buf);
        assert_eq!(buf, [0u8; 8]);
    }

    #[test]
    fn test_is_aligned() {
        let p16 = core::ptr::dangling::<u16>();
        assert!(is_aligned16(p16 as *const c_void));
    }

    #[test]
    fn test_const_align_to() {
        assert_eq!(const_align_to(7, 8), 8);
        assert_eq!(const_align_to(8, 8), 8);
        assert_eq!(const_align_to(9, 8), 16);
    }

    #[test]
    fn test_var_eraser() {
        let mut buf = [0xFFu8; 8];
        {
            let mut eraser = VarEraser::new(&mut buf);
            eraser.erase();
        }
        assert_eq!(buf, [0u8; 8]);
    }

    #[test]
    fn test_align_ptr_functions() {
        let p = 3usize as *const c_void;
        assert_eq!(align2_ptr(p) as usize, 4);
        assert_eq!(align4_ptr(p) as usize, 4);
        assert_eq!(align8_ptr(p) as usize, 8);
    }
}
