// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.user-shell-util; authority=src/basic/user-util.c,src/basic/user-util.h,src/basic/parse-util.c,src/basic/parse-util.h
//
// Pure user/shell classification and fractional parsing utilities.

use std::ffi::CStr;

use libc::c_char;

use crate::ffi::Errno;

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FractionalParseError {
    NoDigits,
}

// ── Shell classification ──────────────────────────────────────────────────

/// Check if the given shell path is a nologin/false/true binary.
/// Port of C `is_nologin_shell()`.
pub fn is_nologin_shell(shell: &str) -> bool {
    matches!(
        shell,
        "/bin/nologin"
            | "/sbin/nologin"
            | "/usr/bin/nologin"
            | "/usr/sbin/nologin"
            | "/bin/false"
            | "/usr/bin/false"
            | "/bin/true"
            | "/usr/bin/true"
    )
}

/// Check if the shell is empty or a nologin shell.
/// Port of C `shell_is_placeholder()`.
pub fn shell_is_placeholder(shell: &str) -> bool {
    shell.is_empty() || is_nologin_shell(shell)
}

// ── Fractional parsing ────────────────────────────────────────────────────

/// Parse a fractional part from a string slice.
///
/// Reads up to `digits` decimal digits, producing a fixed-point value.
/// If fewer digits are available, pads with trailing zeros.
/// Rounds up if the next digit is >= 5.
/// Skips any remaining trailing digits after the requested precision.
///
/// Returns `(remaining_str, value)` on success.
/// Port of C `parse_fractional_part_u()`.
pub fn parse_fractional_part_u(
    s: &str,
    digits: usize,
) -> Result<(&str, u32), FractionalParseError> {
    let bytes = s.as_bytes();
    let mut val: u32 = 0;
    let mut i: usize = 0;

    while i < digits {
        if i >= bytes.len() {
            if i == 0 {
                return Err(FractionalParseError::NoDigits);
            }
            for _ in i..digits {
                val = val.wrapping_mul(10);
            }
            return Ok((&s[i..], val));
        }

        let c = bytes[i];
        if !c.is_ascii_digit() {
            if i == 0 {
                return Err(FractionalParseError::NoDigits);
            }
            for _ in i..digits {
                val = val.wrapping_mul(10);
            }
            break;
        }

        val = val.wrapping_mul(10).wrapping_add((c - b'0') as u32);
        i += 1;
    }

    let remaining = &s[i..];
    let next_bytes = remaining.as_bytes();
    let rounding = !next_bytes.is_empty() && next_bytes[0] >= b'5' && next_bytes[0] <= b'9';
    if rounding {
        val = val.wrapping_add(1);
    }

    let extra_digits = next_bytes
        .iter()
        .take_while(|&&c| c.is_ascii_digit())
        .count();

    let skip = if i == 0 {
        0
    } else if rounding {
        extra_digits.min(digits.saturating_sub(extra_digits))
    } else {
        extra_digits
    };

    Ok((&remaining[skip..], val))
}

// ── C ABI facades ────────────────────────────────────────────────────────

const NOLOGIN_SHELLS: [&[u8]; 8] = [
    b"/bin/nologin",
    b"/sbin/nologin",
    b"/usr/bin/nologin",
    b"/usr/sbin/nologin",
    b"/bin/false",
    b"/usr/bin/false",
    b"/bin/true",
    b"/usr/bin/true",
];

/// C ABI facade for `is_nologin_shell()` that compares opaque C-string bytes.
///
/// # Safety
///
/// A non-null `shell` must designate a live NUL-terminated C string.  A null
/// pointer is rejected as false instead of relying on C's asserted precondition.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_nologin_shell(shell: *const c_char) -> bool {
    if shell.is_null() {
        return false;
    }
    // SAFETY: upheld by this export's C-string contract.
    let bytes = unsafe { CStr::from_ptr(shell) }.to_bytes();
    NOLOGIN_SHELLS.iter().any(|candidate| bytes == *candidate)
}

/// C ABI facade for `shell_is_placeholder()`.
///
/// # Safety
///
/// A non-null `shell` must designate a live NUL-terminated C string.  The null
/// case matches C `isempty(NULL)` and is therefore a placeholder.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_shell_is_placeholder(shell: *const c_char) -> bool {
    if shell.is_null() {
        return true;
    }
    // SAFETY: upheld by this export's C-string contract.
    if unsafe { *shell } == 0 {
        return true;
    }
    // SAFETY: `shell` is non-null and satisfies rs_is_nologin_shell's contract.
    unsafe { rs_is_nologin_shell(shell) }
}

/// C ABI facade for `parse_fractional_part_u()`.
///
/// The output pointer and input cursor are published only on success.  The
/// arithmetic intentionally wraps as C's unsigned arithmetic does.
///
/// # Safety
///
/// `p` and `res` must be writable. `*p` must be a non-null, live
/// NUL-terminated C string. Pointer ranges must not overlap in a way that
/// makes the cursor update invalidate the read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_fractional_part_u(
    p: *mut *const c_char,
    digits: usize,
    res: *mut u32,
) -> i32 {
    if p.is_null() || res.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: `p` is writable under this export's contract.
    let mut cursor = unsafe { *p };
    if cursor.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut value = 0u32;
    for index in 0..digits {
        // SAFETY: `cursor` starts in a live C string and advances only after
        // reading a non-NUL decimal byte, so it remains in that allocation.
        let byte = unsafe { *cursor } as u8;
        if !byte.is_ascii_digit() {
            if index == 0 {
                return Errno::EINVAL.to_neg_errno();
            }
            for _ in index..digits {
                value = value.wrapping_mul(10);
            }
            break;
        }
        value = value.wrapping_mul(10).wrapping_add((byte - b'0') as u32);
        // SAFETY: the byte was non-NUL, so its successor remains in the C string.
        cursor = unsafe { cursor.add(1) };
    }

    // SAFETY: `cursor` remains within the live C string by the loop invariant.
    let round = unsafe { *cursor } as u8;
    if (b'5'..=b'9').contains(&round) {
        value = value.wrapping_add(1);
    }
    // C uses strspn(s, DIGITS), preserving opaque non-digit bytes and stopping
    // exactly at the first one.
    loop {
        // SAFETY: `cursor` is within the live NUL-terminated C string.
        let byte = unsafe { *cursor } as u8;
        if !byte.is_ascii_digit() {
            break;
        }
        // SAFETY: the byte was non-NUL, so the successor stays in range.
        cursor = unsafe { cursor.add(1) };
    }

    // SAFETY: both output locations are writable by this export's contract.
    unsafe {
        *p = cursor;
        *res = value;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_nologin_shell_nologin_variants() {
        assert!(is_nologin_shell("/bin/nologin"));
        assert!(is_nologin_shell("/sbin/nologin"));
        assert!(is_nologin_shell("/usr/bin/nologin"));
        assert!(is_nologin_shell("/usr/sbin/nologin"));
    }

    #[test]
    fn test_is_nologin_shell_false_true() {
        assert!(is_nologin_shell("/bin/false"));
        assert!(is_nologin_shell("/usr/bin/false"));
        assert!(is_nologin_shell("/bin/true"));
        assert!(is_nologin_shell("/usr/bin/true"));
    }

    #[test]
    fn test_is_nologin_shell_normal_shells() {
        assert!(!is_nologin_shell("/bin/bash"));
        assert!(!is_nologin_shell("/bin/sh"));
        assert!(!is_nologin_shell("/bin/zsh"));
        assert!(!is_nologin_shell("/usr/bin/fish"));
    }

    #[test]
    fn test_is_nologin_shell_empty_and_partial() {
        assert!(!is_nologin_shell(""));
        assert!(!is_nologin_shell("/bin/nologi"));
        assert!(!is_nologin_shell("nologin"));
    }

    #[test]
    fn test_shell_is_placeholder_empty() {
        assert!(shell_is_placeholder(""));
    }

    #[test]
    fn test_shell_is_placeholder_nologin() {
        assert!(shell_is_placeholder("/usr/sbin/nologin"));
        assert!(shell_is_placeholder("/bin/false"));
    }

    #[test]
    fn test_shell_is_placeholder_normal() {
        assert!(!shell_is_placeholder("/bin/bash"));
        assert!(!shell_is_placeholder("/bin/sh"));
    }

    #[test]
    fn test_parse_fractional_basic() {
        let (rem, val) = parse_fractional_part_u("1299ms", 2).unwrap();
        assert_eq!(val, 13);
        assert_eq!(rem, "99ms");
    }

    #[test]
    fn test_parse_fractional_exact_digits() {
        let (rem, val) = parse_fractional_part_u("42abc", 2).unwrap();
        assert_eq!(val, 42);
        assert_eq!(rem, "abc");
    }

    #[test]
    fn test_parse_fractional_no_digits() {
        assert_eq!(
            parse_fractional_part_u("x5", 3),
            Err(FractionalParseError::NoDigits)
        );
        assert_eq!(
            parse_fractional_part_u("abc", 2),
            Err(FractionalParseError::NoDigits)
        );
        assert_eq!(
            parse_fractional_part_u("", 2),
            Err(FractionalParseError::NoDigits)
        );
    }

    #[test]
    fn test_parse_fractional_padding() {
        let (rem, val) = parse_fractional_part_u("1abc", 3).unwrap();
        assert_eq!(val, 100);
        assert_eq!(rem, "abc");
    }

    #[test]
    fn test_parse_fractional_round_up() {
        let (rem, val) = parse_fractional_part_u("125rest", 2).unwrap();
        assert_eq!(val, 13);
        assert_eq!(rem, "rest");
    }

    #[test]
    fn test_parse_fractional_no_round_on_4() {
        let (rem, val) = parse_fractional_part_u("124rest", 2).unwrap();
        assert_eq!(val, 12);
        assert_eq!(rem, "rest");
    }

    #[test]
    fn test_parse_fractional_skip_extra_digits() {
        let (rem, val) = parse_fractional_part_u("12345abc", 2).unwrap();
        assert_eq!(val, 12);
        assert_eq!(rem, "abc");
    }

    #[test]
    fn test_parse_fractional_zero_digits_requested() {
        let (rem, val) = parse_fractional_part_u("123", 0).unwrap();
        assert_eq!(val, 0);
        assert_eq!(rem, "123");
    }
}
