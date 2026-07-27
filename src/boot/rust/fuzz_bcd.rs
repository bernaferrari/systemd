// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/fuzz-bcd.c
//
// Fuzzer-side exercise of the canonical BCD parser.
//
// This module intentionally contains no second parser.  The C harness only
// bounds-checks the input, duplicates it because `get_bcd_title()` may
// terminate the title in place, then exercises that parser.  The Rust parser
// returns an owned title and never mutates its input, so its equivalent is a
// direct call to `crate::bcd::get_bcd_title`.

/// Maximum input size accepted by the fuzzer (100 KiB, matching C).
pub const BCD_FUZZ_MAX_SIZE: usize = 100 * 1024;

/// Check whether `size` is within the C fuzzer's accepted range.
pub const fn is_valid_size(size: usize) -> bool {
    size <= BCD_FUZZ_MAX_SIZE
}

/// Exercise the production BCD parser for one fuzzer input.
///
/// `None` has the same meaning as the C harness's ignored input: either it
/// exceeded the size cap or it was not a BCD store from which a title could be
/// extracted. An empty but valid title remains `Some(vec![0])`.
pub fn fuzz_bcd(data: &[u8]) -> Option<Vec<u16>> {
    if !is_valid_size(data.len()) {
        return None;
    }

    crate::bcd::get_bcd_title(data).ok()
}

/// Compute the length of a NUL-terminated UTF-16 slice.
///
/// This is the safe equivalent of the value consumed by C's
/// `DO_NOT_OPTIMIZE(title && char16_strlen(title))` expression.
pub fn char16_strlen(s: &[u16]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_limit_matches_the_c_harness() {
        assert!(is_valid_size(0));
        assert!(is_valid_size(BCD_FUZZ_MAX_SIZE));
        assert!(!is_valid_size(BCD_FUZZ_MAX_SIZE + 1));
    }

    #[test]
    fn malformed_input_is_exercised_by_the_canonical_parser() {
        assert_eq!(fuzz_bcd(&[]), None);
        assert_eq!(fuzz_bcd(&[0; 16]), None);
    }

    #[test]
    fn char16_strlen_accepts_an_empty_title() {
        assert_eq!(char16_strlen(&[0]), 0);
        assert_eq!(char16_strlen(&[b'H' as u16, b'i' as u16, 0]), 2);
    }
}
