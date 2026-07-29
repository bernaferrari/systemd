// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/macro.h
//
// Fundamental macros and constants ported to Rust.
// C preprocessor macros become const fns, inline fns, and const exprs.

use core::cmp::Ordering;

// ── Constants ───────────────────────────────────────────────────────────

pub const U64_KB: u64 = 1024;
pub const U64_MB: u64 = 1024 * U64_KB;
pub const U64_GB: u64 = 1024 * U64_MB;

// ── String constants ────────────────────────────────────────────────────

pub const WHITESPACE: &str = " \t\n\r";
pub const NEWLINE: &str = "\n\r";
pub const QUOTES: &str = "\"\'";
pub const COMMENTS: &str = "#;";
pub const GLOB_CHARS: &str = "*?[";
pub const DIGITS: &str = "0123456789";
pub const LOWERCASE_LETTERS: &str = "abcdefghijklmnopqrstuvwxyz";
pub const UPPERCASE_LETTERS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const LETTERS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const ALPHANUMERICAL: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
pub const HEXDIGITS: &str = "0123456789abcdefABCDEF";
pub const LOWERCASE_HEXDIGITS: &str = "0123456789abcdef";
pub const UPPERCASE_HEXDIGITS: &str = "0123456789ABCDEF";

// ── Math helpers ────────────────────────────────────────────────────────

#[inline]
pub fn max<T: Ord>(a: T, b: T) -> T {
    if a > b { a } else { b }
}

#[inline]
pub fn min<T: Ord>(a: T, b: T) -> T {
    if a < b { a } else { b }
}

#[inline]
pub fn max3<T: Ord>(a: T, b: T, c: T) -> T {
    max(max(a, b), c)
}

#[inline]
pub fn min3<T: Ord>(a: T, b: T, c: T) -> T {
    min(min(a, b), c)
}

#[inline]
pub fn clamp<T: Ord>(x: T, low: T, high: T) -> T {
    if x > high {
        high
    } else if x < low {
        low
    } else {
        x
    }
}

#[inline]
pub const fn div_round_up(x: u64, y: u64) -> u64 {
    x.div_ceil(y)
}

#[inline]
pub const fn round_up(x: u64, y: u64) -> u64 {
    let d = div_round_up(x, y);
    match d.checked_mul(y) {
        Some(v) => v,
        None => u64::MAX,
    }
}

#[inline]
pub const fn less_by(a: u64, b: u64) -> u64 {
    a.saturating_sub(b)
}

#[inline]
pub fn cmp<T: Ord>(a: T, b: T) -> i32 {
    match a.cmp(&b) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

#[inline]
pub const fn is_power_of_2(x: u64) -> bool {
    x > 0 && (x & (x - 1)) == 0
}

// ── Safe arithmetic ─────────────────────────────────────────────────────

#[inline]
pub fn add_safe(a: u64, b: u64) -> Option<u64> {
    a.checked_add(b)
}

#[inline]
pub fn sub_safe(a: u64, b: u64) -> Option<u64> {
    a.checked_sub(b)
}

#[inline]
pub fn mul_safe(a: u64, b: u64) -> Option<u64> {
    a.checked_mul(b)
}

// ── TAKE_PTR equivalent ─────────────────────────────────────────────────

/// Takes ownership of an Option<T>, leaving None in its place.
/// PORT-SYNC: mirrors TAKE_GENERIC/TAKE_PTR from macro.h
#[inline]
pub fn take<T>(opt: &mut Option<T>) -> Option<T> {
    opt.take()
}

// ── FLAGS helpers ───────────────────────────────────────────────────────

#[inline]
pub const fn update_flag(orig: u64, flag: u64, b: bool) -> u64 {
    if b { orig | flag } else { orig & !flag }
}

#[inline]
pub const fn flags_set(v: u64, flags: u64) -> bool {
    (v & flags) == flags
}

// ── STRLEN equivalent ───────────────────────────────────────────────────

#[inline]
pub const fn strlen_lit(s: &str) -> usize {
    s.len()
}

// ── ELEMENTSOF equivalent ───────────────────────────────────────────────

#[inline]
pub const fn elements_of<T>(slice: &[T]) -> usize {
    slice.len()
}

// ── IN_SET equivalent ───────────────────────────────────────────────────

#[inline]
pub fn in_set<T: PartialEq>(x: &T, set: &[T]) -> bool {
    set.iter().any(|v| v == x)
}

// ── yes_no / on_off ─────────────────────────────────────────────────────

#[inline]
pub const fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

#[inline]
pub const fn on_off(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

// ── comparison_operator ─────────────────────────────────────────────────

#[inline]
pub const fn comparison_operator(result: i32) -> &'static str {
    if result < 0 {
        "<"
    } else if result > 0 {
        ">"
    } else {
        "=="
    }
}

// ── ASCII character classification ──────────────────────────────────────

#[inline]
pub const fn ascii_isdigit(c: u8) -> bool {
    c >= b'0' && c <= b'9'
}

#[inline]
pub const fn ascii_ishex(c: u8) -> bool {
    ascii_isdigit(c) || (c >= b'a' && c <= b'f') || (c >= b'A' && c <= b'F')
}

#[inline]
pub const fn ascii_isalpha(c: u8) -> bool {
    (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z')
}

#[inline]
pub const fn ascii_isalnum(c: u8) -> bool {
    ascii_isalpha(c) || ascii_isdigit(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_min() {
        assert_eq!(max(1u64, 2), 2);
        assert_eq!(min(1u64, 2), 1);
        assert_eq!(max3(1u64, 3, 2), 3);
        assert_eq!(min3(1u64, 3, 2), 1);
    }

    #[test]
    fn test_clamp() {
        assert_eq!(clamp(5u64, 0, 10), 5);
        assert_eq!(clamp(15u64, 0, 10), 10);
        assert_eq!(clamp(0u64, 5, 10), 5);
    }

    #[test]
    fn test_div_round_up() {
        assert_eq!(div_round_up(10, 3), 4);
        assert_eq!(div_round_up(9, 3), 3);
        assert_eq!(div_round_up(0, 5), 0);
    }

    #[test]
    fn test_is_power_of_2() {
        assert!(!is_power_of_2(0));
        assert!(is_power_of_2(1));
        assert!(is_power_of_2(2));
        assert!(is_power_of_2(4));
        assert!(is_power_of_2(8));
        assert!(!is_power_of_2(3));
        assert!(!is_power_of_2(6));
    }

    #[test]
    fn test_safe_arithmetic() {
        assert_eq!(add_safe(1, 2), Some(3));
        assert_eq!(add_safe(u64::MAX, 1), None);
        assert_eq!(sub_safe(5, 3), Some(2));
        assert_eq!(sub_safe(3, 5), None);
        assert_eq!(mul_safe(3, 4), Some(12));
        assert_eq!(mul_safe(u64::MAX, 2), None);
    }

    #[test]
    fn test_cmp() {
        assert_eq!(cmp(1, 2), -1);
        assert_eq!(cmp(2, 2), 0);
        assert_eq!(cmp(3, 2), 1);
    }

    #[test]
    fn test_flags() {
        assert_eq!(update_flag(0, 1, true), 1);
        assert_eq!(update_flag(1, 1, false), 0);
        assert!(flags_set(0b101, 0b101));
        assert!(!flags_set(0b100, 0b101));
    }

    #[test]
    fn test_ascii_classify() {
        assert!(ascii_isdigit(b'5'));
        assert!(!ascii_isdigit(b'a'));
        assert!(ascii_ishex(b'a'));
        assert!(ascii_ishex(b'F'));
        assert!(ascii_isalpha(b'z'));
        assert!(!ascii_isalpha(b'3'));
        assert!(ascii_isalnum(b'7'));
        assert!(ascii_isalnum(b'X'));
    }

    #[test]
    fn test_yes_no() {
        assert_eq!(yes_no(true), "yes");
        assert_eq!(yes_no(false), "no");
        assert_eq!(on_off(true), "on");
        assert_eq!(on_off(false), "off");
    }

    #[test]
    fn test_in_set() {
        assert!(in_set(&3, &[1, 2, 3, 4]));
        assert!(!in_set(&5, &[1, 2, 3, 4]));
    }

    #[test]
    fn test_take() {
        let mut opt = Some(42);
        assert_eq!(take(&mut opt), Some(42));
        assert_eq!(opt, None);
    }
}
