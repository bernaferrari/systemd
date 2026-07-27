// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/strxcpyx.c, src/basic/strxcpyx.h
//
// Safe string concatenation/copying utilities.

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
