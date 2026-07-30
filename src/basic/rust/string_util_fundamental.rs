// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/string-util.h
//
// Allocation-free, byte-oriented semantics for the small inline string
// helpers. Raw C pointers deliberately do not enter this module: callers
// first establish a borrowed byte view at the ABI boundary.

/// C's `CMP(a, b)` ordering for nullable pointers.
#[inline]
pub fn nullable_order<T: ?Sized>(a: Option<&T>, b: Option<&T>) -> Option<i32> {
    match (a, b) {
        (None, None) => Some(0),
        (None, Some(_)) => Some(-1),
        (Some(_), None) => Some(1),
        (Some(_), Some(_)) => None,
    }
}

#[inline]
fn byte_order(left: u8, right: u8) -> i32 {
    match left.cmp(&right) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// Byte-string comparison with C `strcmp()`'s unsigned-byte ordering.
#[inline]
pub fn strcmp_bytes(a: &[u8], b: &[u8]) -> i32 {
    for (&left, &right) in a.iter().zip(b) {
        let order = byte_order(left, right);
        if order != 0 {
            return order;
        }
    }
    match a.len().cmp(&b.len()) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// Bounded C-string comparison. A missing byte is the terminating NUL.
#[inline]
pub fn strncmp_bytes(a: &[u8], b: &[u8], limit: usize) -> i32 {
    for index in 0..limit {
        let left = a.get(index).copied().unwrap_or(0);
        let right = b.get(index).copied().unwrap_or(0);
        let order = byte_order(left, right);
        if order != 0 {
            return order;
        }
        if left == 0 {
            return 0;
        }
    }
    0
}

#[inline]
fn ascii_tolower(byte: u8) -> u8 {
    if byte.is_ascii_uppercase() {
        byte + (b'a' - b'A')
    } else {
        byte
    }
}

/// Locale-independent ASCII comparison matching the fundamental helper's
/// documented ASCII case rules.
#[inline]
pub fn strcasecmp_bytes(a: &[u8], b: &[u8]) -> i32 {
    for (&left, &right) in a.iter().zip(b) {
        let order = byte_order(ascii_tolower(left), ascii_tolower(right));
        if order != 0 {
            return order;
        }
    }
    match a.len().cmp(&b.len()) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// Returns whether a nullable C-string's first byte is absent or NUL.
#[inline]
pub fn isempty(byte: Option<u8>) -> bool {
    byte.is_none_or(|value| value == 0)
}

/// Returns the byte offset immediately after `token` when it prefixes `input`.
#[inline]
pub fn memory_startswith(input: &[u8], token: &[u8]) -> Option<usize> {
    input.starts_with(token).then_some(token.len())
}

/// Returns whether `byte` is an ASCII decimal digit.
#[inline]
pub fn ascii_isdigit(byte: u8) -> bool {
    byte.is_ascii_digit()
}

/// Returns whether `byte` is an ASCII hexadecimal digit.
#[inline]
pub fn ascii_ishex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

/// Returns whether `byte` is an ASCII alphabetic character.
#[inline]
pub fn ascii_isalpha(byte: u8) -> bool {
    byte.is_ascii_alphabetic()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparisons_keep_null_and_nul_sentinel_semantics() {
        assert_eq!(nullable_order::<[u8]>(None, Some(b"x")), Some(-1));
        assert_eq!(strcmp_bytes(b"abc", b"abd"), -1);
        assert_eq!(strncmp_bytes(b"abc", b"abd", 2), 0);
        assert_eq!(strncmp_bytes(b"abc", b"abd", 3), -1);
        assert_eq!(strncmp_bytes(b"", b"x", 0), 0);
        assert_eq!(strcasecmp_bytes(b"Hello", b"hELLo"), 0);
    }

    #[test]
    fn isempty_accepts_null_and_nul_sentinel_values() {
        assert!(isempty(None));
        assert!(isempty(Some(0)));
        assert!(!isempty(Some(b'x')));
    }

    #[test]
    fn ascii_rules_do_not_depend_on_signed_char_or_locale() {
        assert!(ascii_isalpha(b'Z'));
        assert!(ascii_ishex(b'F'));
        assert!(ascii_isdigit(b'9'));
        assert!(!ascii_isalpha(0xff));
    }
}
