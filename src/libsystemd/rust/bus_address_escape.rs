// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-internal.c
//
// Percent-escaping for sd-bus address fragments.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusAddressEscapeError {
    CapacityOverflow,
}

impl std::fmt::Display for BusAddressEscapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapacityOverflow => f.write_str("escaped address would overflow"),
        }
    }
}

impl std::error::Error for BusAddressEscapeError {}

const SAFE_CHARS: &[u8] = b"_-/.";

fn hex_char(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        10..=15 => b'A' + (nibble - 10),
        _ => unreachable!("nibble must be in 0..=15"),
    }
}

pub fn bus_address_escape(input: &str) -> Result<String, BusAddressEscapeError> {
    let capacity = input
        .len()
        .checked_mul(3)
        .and_then(|n| n.checked_add(1))
        .ok_or(BusAddressEscapeError::CapacityOverflow)?;

    let mut out = Vec::with_capacity(capacity);
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || SAFE_CHARS.contains(&byte) {
            out.push(byte);
        } else {
            out.push(b'%');
            out.push(hex_char(byte >> 4));
            out.push(hex_char(byte & 0x0f));
        }
    }

    String::from_utf8(out).map_err(|_| BusAddressEscapeError::CapacityOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_ascii_alnum() {
        assert_eq!(bus_address_escape("abcXYZ019").unwrap(), "abcXYZ019");
    }

    #[test]
    fn keeps_c_safe_punctuation() {
        assert_eq!(bus_address_escape("a_b-c/d.e").unwrap(), "a_b-c/d.e");
    }

    #[test]
    fn escapes_space() {
        assert_eq!(bus_address_escape("hello world").unwrap(), "hello%20world");
    }

    #[test]
    fn escapes_percent() {
        assert_eq!(bus_address_escape("100%").unwrap(), "100%25");
    }

    #[test]
    fn escapes_colon() {
        assert_eq!(bus_address_escape("unix:path").unwrap(), "unix%3Apath");
    }

    #[test]
    fn escapes_utf8_bytes_individually() {
        assert_eq!(bus_address_escape("ÿ").unwrap(), "%C3%BF");
    }

    #[test]
    fn empty_input_stays_empty() {
        assert_eq!(bus_address_escape("").unwrap(), "");
    }

    #[test]
    fn hex_char_matches_c_uppercase_output() {
        assert_eq!(hex_char(0), b'0');
        assert_eq!(hex_char(9), b'9');
        assert_eq!(hex_char(10), b'A');
        assert_eq!(hex_char(15), b'F');
    }

    #[test]
    fn escapes_multiple_special_bytes() {
        assert_eq!(bus_address_escape(" !@").unwrap(), "%20%21%40");
    }
}
