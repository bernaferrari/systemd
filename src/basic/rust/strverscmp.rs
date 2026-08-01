// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.strverscmp; authority=src/fundamental/string-util.c,src/fundamental/string-util.h
//
// Version string comparison utility (rpm-like version ordering).
// Handles '~' (pre-release), '-' (version/release separator),
// '^' (patch release), '.' (point release) markers.

use std::ffi::{CStr, c_char};

// ── Internal helpers ────────────────────────────────────────────────────

fn is_valid_version_byte(a: u8) -> bool {
    a.is_ascii_digit() || a.is_ascii_alphabetic() || matches!(a, b'~' | b'-' | b'^' | b'.')
}

#[inline(always)]
fn cmp<T: Ord>(a: T, b: T) -> std::cmp::Ordering {
    a.cmp(&b)
}

#[inline(always)]
fn byte_at(bytes: &[u8], index: usize) -> u8 {
    bytes.get(index).copied().unwrap_or(0)
}

// ── Public API ──────────────────────────────────────────────────────────

/// Compare two version strings using rpm-like version ordering.
///
/// Returns an ordering where `Ordering::Less` means `a < b`,
/// `Ordering::Greater` means `a > b`, and `Ordering::Equal` means equal.
///
/// # Version ordering (older to newer)
///
/// ```text
/// 122.1 < 123~rc1-1 < 123 < 123-a < 123-a.1 < 123-1 < 123-1.1
/// < 123^post1 < 123.a-1 < 123.1-1 < 123a-1 < 124-1
/// ```
pub fn strverscmp_improved(a: &str, b: &str) -> std::cmp::Ordering {
    strverscmp_improved_bytes(a.as_bytes(), b.as_bytes())
}

/// Byte-oriented comparison core shared by C ABI facades that must preserve
/// systemd's opaque C-string semantics without requiring UTF-8.
pub(crate) fn strverscmp_improved_bytes(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let mut ai = 0usize;
    let mut bi = 0usize;

    loop {
        // Drop leading invalid bytes. C operates on opaque bytes rather than
        // requiring UTF-8, so the core deliberately does the same.
        while byte_at(a, ai) != 0 && !is_valid_version_byte(byte_at(a, ai)) {
            ai += 1;
        }
        while byte_at(b, bi) != 0 && !is_valid_version_byte(byte_at(b, bi)) {
            bi += 1;
        }

        // Handle '~': pre-release marker, oldest
        if byte_at(a, ai) == b'~' || byte_at(b, bi) == b'~' {
            let r = cmp(byte_at(a, ai) != b'~', byte_at(b, bi) != b'~');
            if r != std::cmp::Ordering::Equal {
                return r;
            }
            ai += 1;
            bi += 1;
        }

        // End of one or both strings: longer string is newer
        if byte_at(a, ai) == 0 || byte_at(b, bi) == 0 {
            return cmp(byte_at(a, ai), byte_at(b, bi));
        }

        // Handle '-': separator between version and release
        if byte_at(a, ai) == b'-' || byte_at(b, bi) == b'-' {
            let r = cmp(byte_at(a, ai) != b'-', byte_at(b, bi) != b'-');
            if r != std::cmp::Ordering::Equal {
                return r;
            }
            ai += 1;
            bi += 1;
        }

        // Handle '^': patched release marker
        if byte_at(a, ai) == b'^' || byte_at(b, bi) == b'^' {
            let r = cmp(byte_at(a, ai) != b'^', byte_at(b, bi) != b'^');
            if r != std::cmp::Ordering::Equal {
                return r;
            }
            ai += 1;
            bi += 1;
        }

        // Handle '.': point release separator
        if byte_at(a, ai) == b'.' || byte_at(b, bi) == b'.' {
            let r = cmp(byte_at(a, ai) != b'.', byte_at(b, bi) != b'.');
            if r != std::cmp::Ordering::Equal {
                return r;
            }
            ai += 1;
            bi += 1;
        }

        let a_is_digit = byte_at(a, ai).is_ascii_digit();
        let b_is_digit = byte_at(b, bi).is_ascii_digit();

        if a_is_digit || b_is_digit {
            // Numeric segment: find end of digits
            let mut aa = ai;
            while byte_at(a, aa).is_ascii_digit() {
                aa += 1;
            }
            let mut bb = bi;
            while byte_at(b, bb).is_ascii_digit() {
                bb += 1;
            }

            // If one was empty, the non-empty numeric is newer
            let r = cmp(ai != aa, bi != bb);
            if r != std::cmp::Ordering::Equal {
                return r;
            }

            // Skip leading zeros
            while byte_at(a, ai) == b'0' {
                ai += 1;
            }
            while byte_at(b, bi) == b'0' {
                bi += 1;
            }

            // Longer number is newer
            let r = cmp(aa - ai, bb - bi);
            if r != std::cmp::Ordering::Equal {
                return r;
            }

            // Then compare equal-length numeric segments as byte strings.
            let r = a[ai..aa].cmp(&b[bi..bb]);
            if r != std::cmp::Ordering::Equal {
                return r;
            }

            ai = aa;
            bi = bb;
        } else {
            // Alpha segment: find end of alpha chars
            let mut aa = ai;
            while byte_at(a, aa).is_ascii_alphabetic() {
                aa += 1;
            }
            let mut bb = bi;
            while byte_at(b, bb).is_ascii_alphabetic() {
                bb += 1;
            }

            // Compare the common prefix as opaque bytes.
            let min_len = std::cmp::min(aa - ai, bb - bi);
            let r = a[ai..ai + min_len].cmp(&b[bi..bi + min_len]);
            if r != std::cmp::Ordering::Equal {
                return r;
            }

            // Longer alpha segment is newer
            let r = cmp(aa - ai, bb - bi);
            if r != std::cmp::Ordering::Equal {
                return r;
            }

            ai = aa;
            bi = bb;
        }
    }
}

/// Exact C ABI shadow of `strverscmp_improved()`.
///
/// NULL inputs are treated as empty strings, and non-UTF-8 bytes are compared
/// with the same ASCII-only segment rules as the C implementation.
///
/// # Safety
/// Each non-null argument must point to a live NUL-terminated byte string for
/// the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strverscmp_improved(a: *const c_char, b: *const c_char) -> i32 {
    // SAFETY: the caller guarantees each non-null pointer is a live C string.
    let (a, b): (&[u8], &[u8]) = unsafe_ffi!({
        (
            if a.is_null() {
                &[]
            } else {
                CStr::from_ptr(a).to_bytes()
            },
            if b.is_null() {
                &[]
            } else {
                CStr::from_ptr(b).to_bytes()
            },
        )
    });

    match strverscmp_improved_bytes(a, b) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equal_strings() {
        assert_eq!(strverscmp_improved("1.0", "1.0"), std::cmp::Ordering::Equal);
        assert_eq!(strverscmp_improved("abc", "abc"), std::cmp::Ordering::Equal);
        assert_eq!(strverscmp_improved("", ""), std::cmp::Ordering::Equal);
        assert_eq!(
            strverscmp_improved("2.3.1", "2.3.1"),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn test_empty_vs_nonempty() {
        assert_eq!(strverscmp_improved("", "1"), std::cmp::Ordering::Less);
        assert_eq!(strverscmp_improved("1", ""), std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_numeric_comparison() {
        assert!(strverscmp_improved("2", "1") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("1", "2") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("10", "2") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("9", "10") == std::cmp::Ordering::Less);
    }

    #[test]
    fn test_leading_zeros() {
        assert_eq!(strverscmp_improved("01", "1"), std::cmp::Ordering::Equal);
        assert_eq!(strverscmp_improved("007", "7"), std::cmp::Ordering::Equal);
        assert!(strverscmp_improved("0010", "09") == std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_tilde_pre_release() {
        assert!(strverscmp_improved("1.0~rc1", "1.0") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("1.0", "1.0~rc1") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("1.0~alpha", "1.0~beta") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("1.0~~", "1.0~") == std::cmp::Ordering::Less);
    }

    #[test]
    fn test_dash_separator() {
        assert!(strverscmp_improved("1.0-1", "1.0") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("1.0", "1.0-1") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("1.0-2", "1.0-1") == std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_dot_separator() {
        assert!(strverscmp_improved("1.1", "1.0") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("1.0", "1.1") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("1.2.3", "1.2.2") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("2.0", "1.9") == std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_caret_patch() {
        assert!(strverscmp_improved("1.0^1", "1.0") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("1.0", "1.0^1") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("1.0^2", "1.0^1") == std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_alpha_comparison() {
        assert!(strverscmp_improved("abc", "abd") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("abd", "abc") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("beta", "alpha") == std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_alpha_longer_is_newer() {
        assert!(strverscmp_improved("abc", "ab") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("ab", "abc") == std::cmp::Ordering::Less);
    }

    #[test]
    fn test_numeric_longer_is_newer() {
        assert!(strverscmp_improved("1.0.1", "1.0") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("1.0", "1.0.1") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("1.0.0", "1.0") == std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_numeric_vs_alpha() {
        assert!(strverscmp_improved("1", "a") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("a", "1") == std::cmp::Ordering::Less);
    }

    #[test]
    fn test_complex_versions() {
        assert!(strverscmp_improved("2.31.0-1", "2.30.0-1") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("1.0.0-1", "1.0.0-2") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("3.14.159", "3.14.15") == std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_same_prefix_different_suffix() {
        assert!(strverscmp_improved("foo1", "foo2") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("foo10", "foo2") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("foo9", "foo10") == std::cmp::Ordering::Less);
    }

    #[test]
    fn test_large_numbers() {
        assert!(strverscmp_improved("999", "1000") == std::cmp::Ordering::Less);
        assert!(strverscmp_improved("1000", "999") == std::cmp::Ordering::Greater);
        assert!(strverscmp_improved("100000", "99999") == std::cmp::Ordering::Greater);
    }

    #[test]
    fn test_full_ordering_chain() {
        // From C source documentation
        let versions = [
            "122.1",
            "123~rc1-1",
            "123",
            "123-a",
            "123-a.1",
            "123-1",
            "123-1.1",
            "123^post1",
            "123.a-1",
            "123.1-1",
            "123a-1",
            "124-1",
        ];
        for i in 0..versions.len() - 1 {
            assert!(
                strverscmp_improved(versions[i], versions[i + 1]) == std::cmp::Ordering::Less,
                "Expected {} < {}",
                versions[i],
                versions[i + 1]
            );
        }
    }
}
