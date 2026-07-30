// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-internal.c, src/libsystemd/sd-bus/bus-internal.h,
//            src/basic/alloc-util.h, src/basic/hexdecoct.c, src/fundamental/string-util.h
//
// Percent-escaping for sd-bus address fragments.

use std::ffi::CStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusAddressEscapeError {
    /// The C allocation-size expression cannot be represented safely.
    CapacityOverflow,
    /// The allocation corresponding to C's `NULL` result could not be made.
    AllocationFailed,
}

impl std::fmt::Display for BusAddressEscapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapacityOverflow => f.write_str("escaped address would overflow"),
            Self::AllocationFailed => f.write_str("could not allocate escaped address"),
        }
    }
}

impl std::error::Error for BusAddressEscapeError {}

const SAFE_CHARS: &[u8] = b"_-/.";

fn hex_char(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        10..=15 => b'a' + (nibble - 10),
        _ => unreachable!("nibble must be in 0..=15"),
    }
}

/// Escape a non-NULL, NUL-terminated sd-bus address fragment.
///
/// This matches the C helper's byte-string boundary: `CStr` excludes the
/// terminating NUL and cannot contain an interior NUL. Passing a `NULL` input
/// to the C helper is unsupported because it is first dereferenced by
/// `strlen()`. Its `NULL` result reports allocation failure, not an errno
/// return contract.
/// `CapacityOverflow` is the Rust guard for a size the C `strlen(v) * 3 + 1`
/// allocation expression cannot represent safely, while `AllocationFailed`
/// maps the C `NULL` result.
pub fn bus_address_escape(input: &CStr) -> Result<String, BusAddressEscapeError> {
    let c_capacity = input
        .to_bytes()
        .len()
        .checked_mul(3)
        .and_then(|capacity| capacity.checked_add(1))
        .ok_or(BusAddressEscapeError::CapacityOverflow)?;
    // Rust strings do not need the C terminator, but preserve the C allocation
    // arithmetic above so its overflow boundary is explicit.
    let capacity = c_capacity - 1;

    if capacity > isize::MAX as usize {
        return Err(BusAddressEscapeError::CapacityOverflow);
    }

    let mut out = String::new();
    out.try_reserve_exact(capacity)
        .map_err(|_| BusAddressEscapeError::AllocationFailed)?;
    for &byte in input.to_bytes() {
        if byte.is_ascii_alphanumeric() || SAFE_CHARS.contains(&byte) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex_char(byte >> 4) as char);
            out.push(hex_char(byte & 0x0f) as char);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn escape(input: &[u8]) -> String {
        bus_address_escape(CStr::from_bytes_with_nul(input).unwrap()).unwrap()
    }

    #[test]
    fn keeps_ascii_alnum() {
        assert_eq!(escape(b"abcXYZ019\0"), "abcXYZ019");
    }

    #[test]
    fn keeps_c_safe_punctuation() {
        assert_eq!(escape(b"a_b-c/d.e\0"), "a_b-c/d.e");
    }

    #[test]
    fn escapes_space() {
        assert_eq!(escape(b"hello world\0"), "hello%20world");
    }

    #[test]
    fn escapes_percent() {
        assert_eq!(escape(b"100%\0"), "100%25");
    }

    #[test]
    fn escapes_colon() {
        assert_eq!(escape(b"unix:path\0"), "unix%3apath");
    }

    #[test]
    fn escapes_non_utf8_bytes_individually() {
        assert_eq!(escape(b"\xff\x80\0"), "%ff%80");
    }

    #[test]
    fn empty_input_stays_empty() {
        assert_eq!(escape(b"\0"), "");
    }

    #[test]
    fn hex_char_matches_c_lowercase_output() {
        assert_eq!(hex_char(0), b'0');
        assert_eq!(hex_char(9), b'9');
        assert_eq!(hex_char(10), b'a');
        assert_eq!(hex_char(15), b'f');
    }

    #[test]
    fn escapes_multiple_special_bytes() {
        assert_eq!(escape(b" !@\0"), "%20%21%40");
    }

    #[test]
    fn c_string_input_rejects_interior_nul() {
        let interior_nul = [b'a', 0, b'b', 0];
        assert!(CStr::from_bytes_with_nul(&interior_nul).is_err());
    }
}
