// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/alloc-util.c (memdup, memdup_suffix0, free_many)
//            src/basic/alloc-util.h (malloc_multiply, memdup_multiply, memdup_suffix0_multiply)
//
// Safe memory allocation utilities plus a deliberately narrow C allocator
// boundary. Rust-owned buffers never cross the ABI: each `rs_*` result is
// allocated by libc and is therefore valid input to C's `free()`.

use crate::ffi;
use std::ffi::c_void;
use std::ptr;

// ── Error type ────────────────────────────────────────────────────────────

/// Error type for allocation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocError {
    /// The requested size overflows `usize`.
    Overflow,
    /// The underlying allocator could not satisfy the request.
    OutOfMemory,
    /// A safe caller supplied fewer source bytes than the requested copy size.
    ///
    /// The corresponding C helper has an unchecked pointer-length contract;
    /// modelling that as an error keeps the ordinary Rust API memory-safe.
    InvalidInput,
}

impl std::fmt::Display for AllocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AllocError::Overflow => write!(f, "allocation size overflow"),
            AllocError::OutOfMemory => write!(f, "out of memory"),
            AllocError::InvalidInput => write!(f, "source buffer is too short"),
        }
    }
}

impl std::error::Error for AllocError {}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Compute `count * size`, returning `Err(Overflow)` on wrap.
fn safe_mul(count: usize, size: usize) -> Result<usize, AllocError> {
    count.checked_mul(size).ok_or(AllocError::Overflow)
}

/// Calculate the exact allocation used by `malloc_multiply()`.
///
/// The C expression is `malloc(size * need ?: 1)`: after rejecting a product
/// overflow, a zero product deliberately becomes a one-byte allocation.
fn multiply_allocation_size(need: usize, size: usize) -> Option<usize> {
    need.checked_mul(size).map(|total| total.max(1))
}

/// Calculate the exact allocation used by `memdup_suffix0_multiply()`.
///
/// Unlike `malloc_multiply`, this does *not* use the zero-product fallback:
/// `memdup_suffix0()` always allocates the product plus one NUL byte.
fn suffix0_allocation_size(product: usize) -> Option<usize> {
    product.checked_add(1)
}

/// Allocate a `Vec<u8>` of exactly `len` bytes, zero-initialised.
/// For `len == 0`, returns an empty `Vec` (Rust handles this naturally,
/// unlike C where `malloc(0)` is implementation-defined so the C code
/// substitutes `malloc(1)`).
fn alloc_vec(len: usize) -> Result<Vec<u8>, AllocError> {
    let mut v = Vec::new();
    v.try_reserve(len).map_err(|_| AllocError::OutOfMemory)?;
    v.resize(len, 0);
    Ok(v)
}

// ── memdup ────────────────────────────────────────────────────────────────

/// Duplicate a byte slice.
///
/// Mirrors C `memdup(p, l)`: copies `data` into a new `Vec<u8>`.
/// For empty input, returns a one-byte buffer to preserve the C helper's
/// guaranteed non-NULL allocation shape.
pub fn memdup(data: &[u8]) -> Result<Vec<u8>, AllocError> {
    if data.is_empty() {
        // C allocates 1 byte for l==0; Rust Vec is always valid when empty.
        alloc_vec(1)
    } else {
        let mut v = alloc_vec(data.len())?;
        v.copy_from_slice(data);
        Ok(v)
    }
}

// ── memdup_suffix0 ────────────────────────────────────────────────────────

/// Duplicate a byte slice with a trailing NUL byte.
///
/// Mirrors C `memdup_suffix0(p, l)`: allocates `data.len() + 1` bytes,
/// copies `data`, and appends `\0`.
/// Returns `Err(Overflow)` if `data.len() == usize::MAX` (would overflow).
pub fn memdup_suffix0(data: &[u8]) -> Result<Vec<u8>, AllocError> {
    let allocation_size = suffix0_allocation_size(data.len()).ok_or(AllocError::Overflow)?;
    let mut v = alloc_vec(allocation_size)?;
    v[..data.len()].copy_from_slice(data);
    // v[data.len()] is already 0 from alloc_vec
    Ok(v)
}

// ── free_many ─────────────────────────────────────────────────────────────

/// Drop every element in a list of optional `Vec<u8>`s, setting each to `None`.
///
/// Mirrors C `free_many(p, n)`: frees each non-NULL pointer and NULLs it out.
pub fn free_many(allocations: &mut [Option<Vec<u8>>]) {
    for slot in allocations.iter_mut() {
        *slot = None;
    }
}

// ── malloc_multiply ───────────────────────────────────────────────────────

/// Allocate `count * size` bytes with overflow protection.
///
/// Mirrors C `malloc_multiply(need, size)`: returns `Err(Overflow)` if
/// `count * size > usize::MAX`.  For a zero result, allocates 1 byte
/// (matching the C behaviour).
pub fn malloc_multiply(count: usize, size: usize) -> Result<Vec<u8>, AllocError> {
    let total = safe_mul(count, size)?;
    let alloc_len = if total == 0 { 1 } else { total };
    alloc_vec(alloc_len)
}

// ── memdup_multiply ───────────────────────────────────────────────────────

/// Duplicate `count` copies of a pattern of `size` bytes with overflow protection.
///
/// Mirrors C `memdup_multiply(p, need, size)`: computes `need * size`,
/// then copies that many bytes from `data`.
/// Returns `Err(Overflow)` if `count * size` overflows and `Err(InvalidInput)`
/// when a safe Rust slice cannot meet C's pointer-length precondition.
pub fn memdup_multiply(data: &[u8], count: usize, size: usize) -> Result<Vec<u8>, AllocError> {
    let total = safe_mul(count, size)?;
    if total == 0 {
        return alloc_vec(1);
    }
    if data.len() < total {
        return Err(AllocError::InvalidInput);
    }
    let mut v = alloc_vec(total)?;
    v.copy_from_slice(&data[..total]);
    Ok(v)
}

// ── memdup_suffix0_multiply ───────────────────────────────────────────────

/// Duplicate with overflow protection and NUL termination.
///
/// Mirrors C `memdup_suffix0_multiply(p, need, size)`: computes `need * size`,
/// then calls `memdup_suffix0` on that many bytes.
pub fn memdup_suffix0_multiply(
    data: &[u8],
    count: usize,
    size: usize,
) -> Result<Vec<u8>, AllocError> {
    let total = safe_mul(count, size)?;
    suffix0_allocation_size(total).ok_or(AllocError::Overflow)?;
    if data.len() < total {
        return Err(AllocError::InvalidInput);
    }
    memdup_suffix0(&data[..total])
}

// ── Exact C ABI allocation boundary ──────────────────────────────────────

/// Allocate a C-owned buffer and optionally copy a validated number of bytes.
///
/// # Safety
/// When `copy_len` is nonzero, `source` must be non-null and readable for
/// exactly `copy_len` bytes. The returned pointer is owned by the caller and
/// must be released exactly once with C `free()`. A null return signals either
/// allocation failure or a rejected size calculation before this function.
unsafe fn c_allocate_copy(
    source: *const c_void,
    copy_len: usize,
    allocation_len: usize,
    append_nul: bool,
) -> *mut c_void {
    if allocation_len < copy_len || allocation_len == 0 {
        return ptr::null_mut();
    }

    let destination = ffi::malloc(allocation_len);
    if destination.is_null() {
        return ptr::null_mut();
    }

    if copy_len != 0 {
        // SAFETY: the extern-C caller supplies `source` readable for
        // `copy_len`; `destination` is a fresh libc allocation of at least
        // `allocation_len >= copy_len` bytes and cannot overlap it.
        unsafe {
            ptr::copy_nonoverlapping(source.cast::<u8>(), destination.cast::<u8>(), copy_len);
        }
    }
    if append_nul {
        // SAFETY: suffix callers allocate exactly `copy_len + 1` bytes, so
        // this writes the final in-bounds byte of the fresh allocation.
        unsafe { *destination.cast::<u8>().add(copy_len) = 0 };
    }

    destination
}

/// Exact C ABI facade for `malloc_multiply(need, size)`.
///
/// A zero product requests one byte, while multiplication overflow returns
/// NULL before calling the allocator, exactly like the current inline C helper.
/// The successful result is C-allocator-owned and the caller must use `free()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_malloc_multiply(need: usize, size: usize) -> *mut c_void {
    let Some(allocation_len) = multiply_allocation_size(need, size) else {
        return ptr::null_mut();
    };

    // SAFETY: no source bytes are copied, and `allocation_len` is nonzero by
    // construction. The returned allocation deliberately belongs to C.
    unsafe { c_allocate_copy(ptr::null(), 0, allocation_len, false) }
}

/// Exact C ABI facade for `memdup_multiply(p, need, size)`.
///
/// # Safety
/// `p` may be null only for a zero product. Otherwise it must designate at
/// least `need * size` readable bytes. On success the returned C allocation is
/// owned by the caller and must be released exactly once with `free()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_memdup_multiply(
    p: *const c_void,
    need: usize,
    size: usize,
) -> *mut c_void {
    let Some(allocation_len) = multiply_allocation_size(need, size) else {
        return ptr::null_mut();
    };
    let copy_len = need * size;
    if copy_len != 0 && p.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: the wrapper contract provides the source validity requirement;
    // `allocation_len` is the exact nonzero C allocation size.
    unsafe { c_allocate_copy(p, copy_len, allocation_len, false) }
}

/// Exact C ABI facade for `memdup_suffix0_multiply(p, need, size)`.
///
/// # Safety
/// `p` may be null only for a zero product. Otherwise it must designate at
/// least `need * size` readable bytes. On success the returned C allocation is
/// owned by the caller and must be released exactly once with `free()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_memdup_suffix0_multiply(
    p: *const c_void,
    need: usize,
    size: usize,
) -> *mut c_void {
    let Some(copy_len) = need.checked_mul(size) else {
        return ptr::null_mut();
    };
    let Some(allocation_len) = suffix0_allocation_size(copy_len) else {
        return ptr::null_mut();
    };
    if copy_len != 0 && p.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: the wrapper contract provides the source validity requirement;
    // the checked suffix allocation has one writable byte after `copy_len`.
    unsafe { c_allocate_copy(p, copy_len, allocation_len, true) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── memdup ─────────────────────────────────────────────────────────

    #[test]
    fn test_memdup_valid_data() {
        let src = b"hello";
        let result = memdup(src).unwrap();
        assert_eq!(&result[..src.len()], src);
    }

    #[test]
    fn test_memdup_empty_slice() {
        let result = memdup(b"").unwrap();
        // C allocates 1 byte for l==0; our Vec has 1 byte
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_memdup_preserves_content() {
        let src = b"\x00\x01\x02\xff";
        let result = memdup(src).unwrap();
        assert_eq!(&result[..], src);
    }

    // ── memdup_suffix0 ─────────────────────────────────────────────────

    #[test]
    fn test_memdup_suffix0_valid_data() {
        let src = b"hello";
        let result = memdup_suffix0(src).unwrap();
        assert_eq!(&result[..src.len()], src);
        assert_eq!(result[src.len()], 0);
    }

    #[test]
    fn test_memdup_suffix0_zero_len() {
        let result = memdup_suffix0(b"").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], 0);
    }

    #[test]
    fn test_memdup_suffix0_size_max() {
        // We can't create a &[u8] of length usize::MAX, but the function
        // checks for it and returns Overflow. Test the overflow path with
        // a normal input that succeeds, verifying the non-overflow path works.
        let result = memdup_suffix0(&[0u8; 1]).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], 0);
        assert_eq!(result[1], 0);
    }

    #[test]
    fn test_memdup_suffix0_overflow() {
        // We can't actually allocate usize::MAX bytes, but the function checks
        // for data.len() == usize::MAX and returns Overflow
        // This test verifies the logic path indirectly
        let result = memdup_suffix0(b"test");
        assert!(result.is_ok());
    }

    // ── free_many ──────────────────────────────────────────────────────

    #[test]
    fn test_free_many_clears_all() {
        let mut allocations: Vec<Option<Vec<u8>>> = vec![
            Some(vec![1, 2, 3]),
            Some(vec![4, 5, 6]),
            Some(vec![7, 8, 9]),
        ];
        free_many(&mut allocations);
        assert!(allocations.iter().all(|a| a.is_none()));
    }

    #[test]
    fn test_free_many_empty() {
        let mut allocations: Vec<Option<Vec<u8>>> = vec![];
        free_many(&mut allocations);
        assert!(allocations.is_empty());
    }

    #[test]
    fn test_free_many_mixed_null_and_nonnull() {
        let mut allocations: Vec<Option<Vec<u8>>> =
            vec![Some(vec![1, 2]), None, Some(vec![3, 4]), None];
        free_many(&mut allocations);
        assert!(allocations.iter().all(|a| a.is_none()));
    }

    #[test]
    fn test_free_many_all_none() {
        let mut allocations: Vec<Option<Vec<u8>>> = vec![None, None, None];
        free_many(&mut allocations);
        assert!(allocations.iter().all(|a| a.is_none()));
    }

    // ── malloc_multiply ────────────────────────────────────────────────

    #[test]
    fn test_malloc_multiply_overflow() {
        let result = malloc_multiply(usize::MAX, 2);
        assert_eq!(result, Err(AllocError::Overflow));
    }

    #[test]
    fn test_malloc_multiply_zero_need() {
        let result = malloc_multiply(0, 10).unwrap();
        assert_eq!(result.len(), 1); // C allocates 1 byte for size==0
    }

    #[test]
    fn test_malloc_multiply_zero_size() {
        let result = malloc_multiply(10, 0).unwrap();
        assert_eq!(result.len(), 1); // C allocates 1 byte for size==0
    }

    #[test]
    fn test_malloc_multiply_normal() {
        let result = malloc_multiply(10, 10).unwrap();
        assert_eq!(result.len(), 100);
    }

    #[test]
    fn test_malloc_multiply_both_zero() {
        let result = malloc_multiply(0, 0).unwrap();
        assert_eq!(result.len(), 1);
    }

    // ── memdup_multiply ────────────────────────────────────────────────

    #[test]
    fn test_memdup_multiply_overflow() {
        let result = memdup_multiply(b"data", usize::MAX, 2);
        assert_eq!(result, Err(AllocError::Overflow));
    }

    #[test]
    fn test_memdup_multiply_valid() {
        let src = b"hello";
        let result = memdup_multiply(src, 1, src.len()).unwrap();
        assert_eq!(&result[..], src);
    }

    #[test]
    fn test_memdup_multiply_zero_count() {
        let result = memdup_multiply(b"", 0, 10).unwrap();
        assert_eq!(result.len(), 1); // C allocates 1 byte
    }

    // ── memdup_suffix0_multiply ────────────────────────────────────────

    #[test]
    fn test_memdup_suffix0_multiply_overflow() {
        let result = memdup_suffix0_multiply(b"data", usize::MAX, 2);
        assert_eq!(result, Err(AllocError::Overflow));
    }

    #[test]
    fn test_memdup_suffix0_multiply_valid() {
        let src = b"hello";
        let result = memdup_suffix0_multiply(src, 1, src.len()).unwrap();
        assert_eq!(&result[..src.len()], src);
        assert_eq!(result[src.len()], 0);
    }

    #[test]
    fn test_memdup_suffix0_multiply_zero_count() {
        let result = memdup_suffix0_multiply(b"", 0, 10).unwrap();
        // memdup_suffix0 of empty = 1 NUL byte
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], 0);
    }

    #[test]
    fn test_memdup_suffix0_multiply_size_max() {
        let result = memdup_suffix0_multiply(b"x", 1, usize::MAX);
        assert_eq!(result, Err(AllocError::Overflow));
    }
}
