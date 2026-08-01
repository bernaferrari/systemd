// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.strxcpyx; authority=src/basic/strxcpyx.c,src/basic/strxcpyx.h
//
// Safe string concatenation/copying utilities.

use std::ffi::CStr;

use libc::c_char;

// ── Result type ─────────────────────────────────────────────────────────────

/// Result of a string copy/concatenation operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyResult {
    /// Remaining bytes in the destination buffer.
    pub remaining: usize,
    /// Whether the source string was truncated.
    pub truncated: bool,
}

// ── Internal ───────────────────────────────────────────────────────────────

/// Core implementation matching C's strnpcpy_full.
/// Copies up to `len` bytes from `src` into `buf` starting at `pos`.
/// NUL-terminates. Updates `pos` to point at the NUL byte.
fn strnpcpy_full_impl(buf: &mut [u8], pos: &mut usize, src: &[u8], len: usize) -> CopyResult {
    let size = buf.len().saturating_sub(*pos);
    if size == 0 {
        return CopyResult {
            remaining: 0,
            truncated: len > 0,
        };
    }

    let copy_len = len.min(src.len());
    let truncated;
    let actual;

    if copy_len >= size {
        actual = size.saturating_sub(1);
        truncated = true;
    } else if copy_len > 0 {
        actual = copy_len;
        truncated = false;
    } else {
        actual = 0;
        truncated = false;
    }

    if actual > 0 {
        buf[*pos..*pos + actual].copy_from_slice(&src[..actual]);
        *pos += actual;
    }

    buf[*pos] = 0;

    let remaining = if truncated { 0 } else { size - actual };
    CopyResult {
        remaining,
        truncated,
    }
}

// ── Public API: pointer-advancing variants ──────────────────────────────────

/// Copy at most `len` bytes from `src` into `buf` starting at `pos`.
/// NUL-terminates. Updates `pos` to the NUL byte position.
/// Equivalent to C strnpcpy_full().
pub fn strnpcpy_full(buf: &mut [u8], pos: &mut usize, src: &[u8], len: usize) -> CopyResult {
    strnpcpy_full_impl(buf, pos, src, len)
}

/// Copy `src` into `buf` starting at `pos`.
/// NUL-terminates. Updates `pos` to the NUL byte position.
/// Equivalent to C strpcpy_full().
pub fn strpcpy_full(buf: &mut [u8], pos: &mut usize, src: &[u8]) -> CopyResult {
    strnpcpy_full_impl(buf, pos, src, src.len())
}

// ── Public API: static-destination variants ─────────────────────────────────

/// Copy at most `len` bytes from `src` into `dest` from the beginning.
/// NUL-terminates. Equivalent to C strnscpy_full().
pub fn strnscpy_full(dest: &mut [u8], src: &[u8], len: usize) -> CopyResult {
    let mut pos = 0;
    strnpcpy_full_impl(dest, &mut pos, src, len)
}

/// Copy `src` into `dest` from the beginning.
/// NUL-terminates. Equivalent to C strscpy_full().
pub fn strscpy_full(dest: &mut [u8], src: &[u8]) -> CopyResult {
    let mut pos = 0;
    strnpcpy_full_impl(dest, &mut pos, src, src.len())
}

// ── C ABI ─────────────────────────────────────────────────────────────────

/// Implement C's `strnpcpy_full()` pointer and remaining-size semantics.
///
/// `size == 0` deliberately does not inspect or modify `*dest`, matching the
/// C helper's loop-friendly no-op behavior. For non-zero sizes, C requires a
/// writable `size`-byte range at `*dest` and a readable `len`-byte range at
/// `src`; like `mempcpy(3)`, source and destination must not overlap.
///
/// # Safety
///
/// The caller must uphold the raw-pointer and non-overlap requirements above.
/// `ret_truncated`, when non-null, must be writable for one `bool`.
unsafe fn strnpcpy_full_raw(
    dest: *mut *mut c_char,
    size: usize,
    src: *const c_char,
    len: usize,
    ret_truncated: *mut bool,
) -> usize {
    if dest.is_null() || src.is_null() {
        return 0;
    }

    if size == 0 {
        if !ret_truncated.is_null() {
            // SAFETY: the caller supplied writable storage for the optional
            // result flag. This is the only C-visible output for size zero.
            unsafe_ffi!(*ret_truncated = len > 0);
        }
        return 0;
    }

    // SAFETY: for non-zero sizes the documented ABI contract requires `dest`
    // to point to writable pointer storage and `*dest` to head a writable
    // `size` byte range.
    let destination = unsafe_ffi!(*dest);
    if destination.is_null() {
        return 0;
    }

    let (copied, remaining, truncated) = if len >= size {
        (size - 1, 0, true)
    } else {
        (len, size - len, false)
    };

    if copied > 0 {
        // SAFETY: the ABI contract provides readable source and writable,
        // non-overlapping destination ranges for the bytes C's mempcpy()
        // would access.
        unsafe_ffi!({
            std::ptr::copy_nonoverlapping(src.cast::<u8>(), destination.cast::<u8>(), copied)
        });
    }

    // SAFETY: `copied < size`, so this remains within the caller-provided
    // writable range. C advances the destination to this terminating NUL.
    let advanced = unsafe_ffi!(destination.add(copied));
    // SAFETY: `advanced` points at the final byte written by the C helper.
    unsafe_ffi!(*advanced = 0);
    // SAFETY: the ABI contract provides writable outer pointer storage.
    unsafe_ffi!(*dest = advanced);

    if !ret_truncated.is_null() {
        // SAFETY: the caller supplied writable storage for the optional flag.
        unsafe_ffi!(*ret_truncated = truncated);
    }

    remaining
}

/// C ABI facade for `strnpcpy_full()`.
///
/// # Safety
///
/// `dest` and `src` must be non-NULL. If `size != 0`, `dest` must point to
/// writable pointer storage, `*dest` must point to `size` writable bytes, and
/// `src` must point to at least `min(len, size - 1)` readable bytes when a
/// copy occurs. As in C's `mempcpy()`, the input and output byte ranges must
/// not overlap. `ret_truncated`, when non-NULL, must point to writable `bool`
/// storage. `size == 0` reads neither `*dest` nor `src` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strnpcpy_full(
    dest: *mut *mut c_char,
    size: usize,
    src: *const c_char,
    len: usize,
    ret_truncated: *mut bool,
) -> usize {
    // SAFETY: this ABI entry point forwards its documented pointer contract.
    unsafe_ffi!(strnpcpy_full_raw(dest, size, src, len, ret_truncated))
}

/// C ABI facade for `strpcpy_full()`.
///
/// # Safety
///
/// `src` must be a readable, NUL-terminated C string. The remaining pointer,
/// destination-range, non-overlap, and optional-flag requirements are the
/// same as [`rs_strnpcpy_full`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strpcpy_full(
    dest: *mut *mut c_char,
    size: usize,
    src: *const c_char,
    ret_truncated: *mut bool,
) -> usize {
    if dest.is_null() || src.is_null() {
        return 0;
    }

    // SAFETY: this entry point's C-string contract guarantees a terminating
    // NUL readable from `src` for the duration of the call.
    let length = unsafe_ffi!(CStr::from_ptr(src).to_bytes().len());
    // SAFETY: this forwards the same destination and optional-output contract.
    unsafe_ffi!(strnpcpy_full_raw(dest, size, src, length, ret_truncated))
}

/// C ABI facade for `strnscpy_full()`.
///
/// # Safety
///
/// `dest` and `src` must be non-NULL. If `size != 0`, `dest` must point to
/// `size` writable bytes and `src` must meet `rs_strnpcpy_full`'s explicit
/// length-readability and non-overlap requirements. `ret_truncated`, when
/// non-NULL, must point to writable `bool` storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strnscpy_full(
    dest: *mut c_char,
    size: usize,
    src: *const c_char,
    len: usize,
    ret_truncated: *mut bool,
) -> usize {
    if dest.is_null() || src.is_null() {
        return 0;
    }

    let mut cursor = dest;
    // SAFETY: `cursor` is local writable outer-pointer storage, while the
    // remaining raw-pointer requirements are exactly this function's contract.
    unsafe_ffi!(strnpcpy_full_raw(
        &mut cursor,
        size,
        src,
        len,
        ret_truncated
    ))
}

/// C ABI facade for `strscpy_full()`.
///
/// # Safety
///
/// `src` must be a readable, NUL-terminated C string. `dest` must point to
/// `size` writable bytes when `size != 0`; the source and destination ranges
/// must not overlap. `ret_truncated`, when non-NULL, must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strscpy_full(
    dest: *mut c_char,
    size: usize,
    src: *const c_char,
    ret_truncated: *mut bool,
) -> usize {
    if dest.is_null() || src.is_null() {
        return 0;
    }

    // SAFETY: this entry point's C-string contract guarantees a readable NUL.
    let length = unsafe_ffi!(CStr::from_ptr(src).to_bytes().len());
    let mut cursor = dest;
    // SAFETY: `cursor` is local writable outer-pointer storage; the rest of
    // the raw-pointer contract is forwarded from this function's documentation.
    unsafe_ffi!(strnpcpy_full_raw(
        &mut cursor,
        size,
        src,
        length,
        ret_truncated
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── strnpcpy_full tests ──────────────────────────────────────────────

    #[test]
    fn test_strnpcpy_full_basic() {
        let mut buf = [0u8; 16];
        let mut pos = 0;
        let result = strnpcpy_full(&mut buf, &mut pos, b"hello", 5);
        assert_eq!(result.remaining, 11);
        assert!(!result.truncated);
        assert_eq!(&buf[..6], b"hello\0");
        assert_eq!(pos, 5);
    }

    #[test]
    fn test_strnpcpy_full_truncated() {
        let mut buf = [0u8; 8];
        let mut pos = 0;
        let result = strnpcpy_full(&mut buf, &mut pos, b"hello world", 11);
        assert_eq!(result.remaining, 0);
        assert!(result.truncated);
        assert_eq!(&buf[..8], b"hello w\0");
    }

    #[test]
    fn test_strnpcpy_full_zero_size() {
        let mut buf = [0u8; 1];
        let mut pos = 1;
        let result = strnpcpy_full(&mut buf, &mut pos, b"hello", 5);
        assert_eq!(result.remaining, 0);
        assert!(result.truncated);
    }

    #[test]
    fn test_strnpcpy_full_zero_len() {
        let mut buf = [0u8; 16];
        let mut pos = 0;
        let result = strnpcpy_full(&mut buf, &mut pos, b"hello", 0);
        assert_eq!(result.remaining, 16);
        assert!(!result.truncated);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn test_strnpcpy_full_exact_fit() {
        let mut buf = [0u8; 6];
        let mut pos = 0;
        let result = strnpcpy_full(&mut buf, &mut pos, b"hello", 5);
        assert_eq!(result.remaining, 1);
        assert!(!result.truncated);
        assert_eq!(&buf[..6], b"hello\0");
    }

    #[test]
    fn test_strnpcpy_full_size_one() {
        let mut buf = [0u8; 1];
        let mut pos = 0;
        let result = strnpcpy_full(&mut buf, &mut pos, b"hello", 5);
        assert_eq!(result.remaining, 0);
        assert!(result.truncated);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn test_strnpcpy_full_empty_src() {
        let mut buf = [0u8; 16];
        let mut pos = 0;
        let result = strnpcpy_full(&mut buf, &mut pos, b"", 0);
        assert_eq!(result.remaining, 16);
        assert!(!result.truncated);
        assert_eq!(buf[0], 0);
    }

    // ── strpcpy_full tests ───────────────────────────────────────────────

    #[test]
    fn test_strpcpy_full_basic() {
        let mut buf = [0u8; 16];
        let mut pos = 0;
        let result = strpcpy_full(&mut buf, &mut pos, b"hello");
        assert_eq!(result.remaining, 11);
        assert!(!result.truncated);
        assert_eq!(&buf[..6], b"hello\0");
    }

    #[test]
    fn test_strpcpy_full_truncated() {
        let mut buf = [0u8; 4];
        let mut pos = 0;
        let result = strpcpy_full(&mut buf, &mut pos, b"hello");
        assert_eq!(result.remaining, 0);
        assert!(result.truncated);
        assert_eq!(&buf[..4], b"hel\0");
    }

    #[test]
    fn test_strpcpy_full_empty() {
        let mut buf = [0u8; 16];
        let mut pos = 0;
        let result = strpcpy_full(&mut buf, &mut pos, b"");
        assert_eq!(result.remaining, 16);
        assert!(!result.truncated);
    }

    // ── strnscpy_full tests ──────────────────────────────────────────────

    #[test]
    fn test_strnscpy_full_basic() {
        let mut buf = [0u8; 16];
        let result = strnscpy_full(&mut buf, b"hello", 5);
        assert_eq!(result.remaining, 11);
        assert!(!result.truncated);
        assert_eq!(&buf[..6], b"hello\0");
    }

    #[test]
    fn test_strnscpy_full_truncated() {
        let mut buf = [0u8; 6];
        let result = strnscpy_full(&mut buf, b"hello world", 11);
        assert_eq!(result.remaining, 0);
        assert!(result.truncated);
        assert_eq!(&buf[..6], b"hello\0");
    }

    // ── strscpy_full tests ───────────────────────────────────────────────

    #[test]
    fn test_strscpy_full_basic() {
        let mut buf = [0u8; 16];
        let result = strscpy_full(&mut buf, b"hello");
        assert_eq!(result.remaining, 11);
        assert!(!result.truncated);
        assert_eq!(&buf[..6], b"hello\0");
    }

    #[test]
    fn test_strscpy_full_truncated() {
        let mut buf = [0u8; 6];
        let result = strscpy_full(&mut buf, b"hello world");
        assert_eq!(result.remaining, 0);
        assert!(result.truncated);
        assert_eq!(&buf[..6], b"hello\0");
    }

    #[test]
    fn test_strscpy_full_empty_string() {
        let mut buf = [0u8; 16];
        let result = strscpy_full(&mut buf, b"");
        assert_eq!(result.remaining, 16);
        assert!(!result.truncated);
        assert_eq!(buf[0], 0);
    }

    // ── Concatenation test ───────────────────────────────────────────────

    #[test]
    fn test_concatenation() {
        let mut buf = [0u8; 20];
        let mut pos = 0;
        let r1 = strnpcpy_full(&mut buf, &mut pos, b"hello", 5);
        assert!(!r1.truncated);
        let r2 = strnpcpy_full(&mut buf, &mut pos, b" world", 6);
        assert!(!r2.truncated);
        assert_eq!(&buf[..12], b"hello world\0");
    }
}
