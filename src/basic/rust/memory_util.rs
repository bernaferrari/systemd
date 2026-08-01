// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.memory-util; authority=src/basic/memory-util.c,src/basic/memory-util.h,src/fundamental/memory-util.c,src/fundamental/memory-util.h
//
// Memory utility functions.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::cmp::Ordering;
use std::ffi::{c_int, c_void};
use std::sync::OnceLock;

use crate::ffi;

// ── Errors ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    InvalidLength,
    SystemPageSizeUnavailable,
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "invalid slice length"),
            Self::SystemPageSizeUnavailable => write!(f, "system page size unavailable"),
        }
    }
}

impl std::error::Error for MemoryError {}

// ── page_size ─────────────────────────────────────────────────────────────

static PAGE_SIZE: OnceLock<usize> = OnceLock::new();

fn cached_page_size() -> Result<usize, MemoryError> {
    if let Some(page_size) = PAGE_SIZE.get() {
        return Ok(*page_size);
    }

    // SAFETY: `_SC_PAGESIZE` is the exact C authority query and has no
    // caller-provided memory contract.
    let queried = unsafe_ffi!(libc::sysconf(libc::_SC_PAGESIZE));
    if queried <= 0 {
        return Err(MemoryError::SystemPageSizeUnavailable);
    }

    let _ = PAGE_SIZE.set(queried as usize);
    Ok(*PAGE_SIZE
        .get()
        .expect("a successful page-size query initializes the cache"))
}

pub fn page_size() -> Result<usize, MemoryError> {
    cached_page_size()
}

// ── Basic operations ──────────────────────────────────────────────────────

pub fn memcpy_safe(dst: &mut [u8], src: &[u8], n: usize) -> Result<(), MemoryError> {
    if n == 0 {
        return Ok(());
    }
    if dst.len() < n || src.len() < n {
        return Err(MemoryError::InvalidLength);
    }

    dst[..n].copy_from_slice(&src[..n]);
    Ok(())
}

pub fn mempcpy_safe(dst: &mut [u8], src: &[u8], n: usize) -> Result<usize, MemoryError> {
    memcpy_safe(dst, src, n)?;
    Ok(n)
}

pub fn memcmp_safe(s1: &[u8], s2: &[u8], n: usize) -> Result<i32, MemoryError> {
    if n == 0 {
        return Ok(0);
    }
    if s1.len() < n || s2.len() < n {
        return Err(MemoryError::InvalidLength);
    }

    for (a, b) in s1[..n].iter().zip(&s2[..n]) {
        if a != b {
            return Ok(i32::from(*a) - i32::from(*b));
        }
    }

    Ok(0)
}

pub fn memcmp_nn(s1: &[u8], s2: &[u8]) -> i32 {
    let common = s1.len().min(s2.len());
    let cmp = memcmp_safe(s1, s2, common).expect("common prefix length is valid");
    if cmp != 0 {
        return cmp;
    }

    match s1.len().cmp(&s2.len()) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

pub fn mempset(buf: &mut [u8], byte: u8, n: usize) -> Result<usize, MemoryError> {
    if buf.len() < n {
        return Err(MemoryError::InvalidLength);
    }

    buf[..n].fill(byte);
    Ok(n)
}

pub fn memmem_safe(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }

    haystack.windows(needle.len()).position(|w| w == needle)
}

pub fn mempmem_safe(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memmem_safe(haystack, needle).map(|i| i + needle.len())
}

pub fn memeqbyte(byte: u8, data: &[u8]) -> bool {
    let checked = data.len().min(16);
    if data[..checked].iter().any(|b| *b != byte) {
        return false;
    }

    let remaining = data.len() - checked;
    remaining == 0 || data[..remaining] == data[16..]
}

// ── C ABI ────────────────────────────────────────────────────────────────

/// Return the system page size, matching `page_size()` in `memory-util.c`.
///
/// The C authority asserts if `_SC_PAGESIZE` cannot be read. This process-wide
/// query has no caller-provided pointer contract.
#[unsafe(no_mangle)]
pub extern "C" fn rs_page_size() -> usize {
    cached_page_size().expect("sysconf(_SC_PAGESIZE) failed")
}

/// Copy `n` bytes with the exact null-for-zero-length exception of
/// `memcpy_safe()`.
///
/// # Safety
/// For `n > 0`, `dst` must be writable and `src` readable for `n` bytes; the
/// ranges must not overlap. `src` must be non-null, as asserted by the C
/// helper. `dst` has the same validity requirement as `memcpy(3)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_memcpy_safe(
    dst: *mut c_void,
    src: *const c_void,
    n: usize,
) -> *mut c_void {
    if n == 0 {
        return dst;
    }

    assert!(!src.is_null(), "memcpy_safe source must be non-null");
    // SAFETY: documented C ABI preconditions match `memcpy_safe()` and the
    // lower-level wrapper's requirements.
    unsafe_ffi!(ffi::memcpy(dst, src, n))
}

/// Copy `n` bytes and return the one-past-end destination pointer, matching
/// `mempcpy_safe()`.
///
/// # Safety
/// This has the same storage, non-overlap, and non-null-for-`n > 0` source
/// requirements as [`rs_memcpy_safe`]. The returned one-past-end pointer is
/// valid only under the caller's original destination-object contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_mempcpy_safe(
    dst: *mut c_void,
    src: *const c_void,
    n: usize,
) -> *mut c_void {
    if n == 0 {
        return dst;
    }

    // SAFETY: forwarded unchanged to the documented `rs_memcpy_safe` ABI.
    unsafe_ffi!(rs_memcpy_safe(dst, src, n));
    // SAFETY: the caller's destination range is valid for `n` bytes, so its
    // one-past-end pointer is valid under the same C object contract.
    unsafe_ffi!(dst.cast::<u8>().add(n).cast())
}

/// Compare `n` bytes with the null-for-zero-length exception of
/// `memcmp_safe()`.
///
/// # Safety
/// For `n > 0`, both inputs must be non-null and readable for `n` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_memcmp_safe(s1: *const c_void, s2: *const c_void, n: usize) -> c_int {
    if n == 0 {
        return 0;
    }

    assert!(!s1.is_null(), "memcmp_safe first input must be non-null");
    assert!(!s2.is_null(), "memcmp_safe second input must be non-null");
    // SAFETY: documented C ABI preconditions match the wrapper's requirements.
    unsafe_ffi!(ffi::memcmp(s1, s2, n))
}

/// Compare two counted byte sequences lexicographically, matching
/// `memcmp_nn()`.
///
/// # Safety
/// Both inputs must be non-null and readable for `min(n1, n2)` bytes. As in C,
/// an input beyond that shared prefix is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_memcmp_nn(
    s1: *const c_void,
    n1: usize,
    s2: *const c_void,
    n2: usize,
) -> c_int {
    let shared_length = n1.min(n2);
    // SAFETY: `shared_length` is within both caller-provided readable ranges.
    let comparison = unsafe_ffi!(rs_memcmp_safe(s1, s2, shared_length));
    if comparison != 0 {
        return comparison;
    }

    match n1.cmp(&n2) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

/// Fill `n` bytes and return the one-past-end pointer, matching `mempset()`.
///
/// # Safety
/// `s` must meet `memset(3)`'s writable-storage contract for `n` bytes. The
/// returned one-past-end pointer is valid only under that same object contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_mempset(s: *mut c_void, c: c_int, n: usize) -> *mut c_void {
    // SAFETY: documented C ABI preconditions match the wrapper's requirements.
    unsafe_ffi!(ffi::memset(s, c, n));
    if n == 0 {
        return s;
    }

    // SAFETY: the caller's writable range is valid for `n` bytes, so its
    // one-past-end pointer is valid under the same C object contract.
    unsafe_ffi!(s.cast::<u8>().add(n).cast())
}

/// Find the first `needle` occurrence in a counted byte range, matching
/// `memmem_safe()`.
///
/// # Safety
/// For a non-empty needle when `haystacklen >= needlelen`, `haystack` must be
/// readable for `haystacklen` bytes and `needle` readable for `needlelen`
/// bytes. A zero-length needle returns `haystack` without dereferencing either
/// pointer; a too-short haystack returns NULL without dereferencing either.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_memmem_safe(
    haystack: *const c_void,
    haystacklen: usize,
    needle: *const c_void,
    needlelen: usize,
) -> *mut c_void {
    if needlelen == 0 {
        return haystack.cast_mut();
    }
    if haystacklen < needlelen {
        return std::ptr::null_mut();
    }

    assert!(!haystack.is_null(), "memmem_safe haystack must be non-null");
    assert!(!needle.is_null(), "memmem_safe needle must be non-null");

    let haystack = haystack.cast::<u8>();
    let needle = needle.cast::<u8>();
    for offset in 0..=haystacklen - needlelen {
        let mut index = 0;
        while index < needlelen {
            // SAFETY: the documented input ranges cover every compared byte.
            if unsafe_ffi!(*haystack.add(offset + index) != *needle.add(index)) {
                break;
            }
            index += 1;
        }
        if index == needlelen {
            // SAFETY: the matching start lies within the caller's readable
            // haystack range, so converting it to the C-compatible result
            // pointer does not dereference or advance beyond that range.
            return unsafe_ffi!(haystack.add(offset).cast_mut().cast());
        }
    }

    std::ptr::null_mut()
}

/// Find a counted-byte match and return the pointer after it, matching
/// `mempmem_safe()`.
///
/// # Safety
/// This has the same input-range requirements and no-dereference early-return
/// cases as [`rs_memmem_safe`]. The returned pointer is within or one past the
/// caller's haystack range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_mempmem_safe(
    haystack: *const c_void,
    haystacklen: usize,
    needle: *const c_void,
    needlelen: usize,
) -> *mut c_void {
    // SAFETY: forwarded unchanged to the documented `rs_memmem_safe` ABI.
    let match_start = unsafe_ffi!(rs_memmem_safe(haystack, haystacklen, needle, needlelen));
    if match_start.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: a non-null match is within the caller's haystack range and
    // `needlelen` advances at most to its one-past-end pointer.
    unsafe_ffi!(match_start.cast::<u8>().add(needlelen).cast())
}

/// Match the fundamental `memeqbyte()` implementation, including its
/// first-sixteen-byte check followed by its self-comparison fast path.
///
/// # Safety
/// If `length` is non-zero, `data` must be non-null and readable for `length`
/// bytes. A null pointer is permitted only with zero length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_memeqbyte(byte: u8, data: *const c_void, length: usize) -> bool {
    assert!(!data.is_null() || length == 0, "memeqbyte requires data");

    let data = data.cast::<u8>();
    let checked = length.min(16);
    for index in 0..checked {
        // SAFETY: the documented input range covers every inspected byte.
        if unsafe_ffi!(*data.add(index)) != byte {
            return false;
        }
    }

    let remaining = length - checked;
    if remaining == 0 {
        return true;
    }

    // SAFETY: `length > 16`, so the documented input range covers both the
    // original prefix and the offset-by-sixteen range used by the C fast path.
    unsafe_ffi!(ffi::memcmp(data.cast(), data.add(16).cast(), remaining) == 0)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_is_cached_and_positive() {
        let a = page_size().unwrap();
        let b = page_size().unwrap();
        assert!(a > 0);
        assert_eq!(a, b);
    }

    #[test]
    fn memcpy_safe_copies_prefix() {
        let mut dst = [0u8; 4];
        memcpy_safe(&mut dst, &[9, 8, 7, 6], 3).unwrap();
        assert_eq!(dst, [9, 8, 7, 0]);
    }

    #[test]
    fn mempcpy_safe_returns_end_offset() {
        let mut dst = [0u8; 3];
        assert_eq!(mempcpy_safe(&mut dst, &[1, 2, 3], 3).unwrap(), 3);
        assert_eq!(dst, [1, 2, 3]);
    }

    #[test]
    fn memcmp_safe_matches_c_ordering() {
        assert_eq!(memcmp_safe(b"abc", b"abc", 3).unwrap(), 0);
        assert!(memcmp_safe(b"abc", b"abd", 3).unwrap() < 0);
        assert!(memcmp_safe(b"abd", b"abc", 3).unwrap() > 0);
    }

    #[test]
    fn memcmp_nn_uses_length_when_prefix_matches() {
        assert_eq!(memcmp_nn(b"abc", b"abc"), 0);
        assert!(memcmp_nn(b"abc", b"abcd") < 0);
        assert!(memcmp_nn(b"abcd", b"abc") > 0);
    }

    #[test]
    fn mempset_sets_bytes_and_returns_past_end() {
        let mut buf = [0u8; 5];
        assert_eq!(mempset(&mut buf, 0x7f, 4).unwrap(), 4);
        assert_eq!(buf, [0x7f, 0x7f, 0x7f, 0x7f, 0]);
    }

    #[test]
    fn memmem_safe_handles_empty_and_miss() {
        assert_eq!(memmem_safe(b"abcdef", b""), Some(0));
        assert_eq!(memmem_safe(b"abcdef", b"cd"), Some(2));
        assert_eq!(memmem_safe(b"abcdef", b"xy"), None);
    }

    #[test]
    fn mempmem_safe_returns_end_of_match() {
        assert_eq!(mempmem_safe(b"abcdef", b"cd"), Some(4));
        assert_eq!(mempmem_safe(b"abcdef", b"xy"), None);
    }

    #[test]
    fn memeqbyte_checks_uniform_buffers() {
        assert!(memeqbyte(0x42, &[0x42; 32]));
        assert!(!memeqbyte(0x42, &[0x42, 0x42, 0x41]));
        assert!(memeqbyte(0, &[]));
    }
}
