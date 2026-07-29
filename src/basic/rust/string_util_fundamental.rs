// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/string-util.h
//
// Allocation-free, byte-oriented semantics for the small inline string
// helpers. Raw C pointers deliberately do not enter this module: callers
// first establish a borrowed byte view at the ABI boundary.

#[inline]
pub fn isempty(byte: Option<u8>) -> bool {
    byte.is_none_or(|value| value == 0)
}

#[inline]
pub fn memory_startswith(input: &[u8], token: &[u8]) -> Option<usize> {
    input.starts_with(token).then_some(token.len())
}

#[inline]
pub fn ascii_isdigit(byte: u8) -> bool {
    byte.is_ascii_digit()
}

#[inline]
pub fn ascii_ishex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

#[inline]
pub fn ascii_isalpha(byte: u8) -> bool {
    byte.is_ascii_alphabetic()
}

#[cfg(test)]
mod tests {
    use super::*;

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
