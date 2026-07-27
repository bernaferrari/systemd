// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/recovery-key.c, src/shared/recovery-key.h
//
// YubiKey modhex encoding/decoding for recovery keys.
//
// Implements `decode_modhex_char()` and `normalize_recovery_key()` from the C
// source, converting them to idiomatic Rust with `Result<T, E>` error handling.

// ── Constants ─────────────────────────────────────────────────────────────

/// The modhex alphabet used by YubiKey (maps nibble 0–15 to character).
pub const MODHEX_ALPHABET: &[u8; 16] = b"cbdefghijklnrtuv";

/// Raw length of a 256-bit recovery key in bytes (32 bytes = 64 modhex chars).
pub const RECOVERY_KEY_MODHEX_RAW_LENGTH: usize = 32;

/// Formatted length: 64 modhex chars in 8 groups of 8, with 7 dashes and a
/// NUL terminator: `32*2/8*9 + 1 = 73` (C-string sense, includes NUL).
pub const RECOVERY_KEY_MODHEX_FORMATTED_LENGTH: usize =
    RECOVERY_KEY_MODHEX_RAW_LENGTH * 2 / 8 * 9 + 1;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors that can occur during recovery key operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryKeyError {
    /// Input has invalid length.
    InvalidLength,
    /// Input contains characters that are not valid modhex.
    InvalidChar,
    /// A dash separator was expected but not found.
    InvalidFormat,
    /// Internal allocation or buffer failure.
    BufferError,
}

impl std::fmt::Display for RecoveryKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoveryKeyError::InvalidLength => write!(f, "invalid recovery key length"),
            RecoveryKeyError::InvalidChar => write!(f, "invalid modhex character"),
            RecoveryKeyError::InvalidFormat => write!(f, "invalid recovery key format"),
            RecoveryKeyError::BufferError => write!(f, "buffer allocation failure"),
        }
    }
}

impl std::error::Error for RecoveryKeyError {}

// ── Decode helpers ────────────────────────────────────────────────────────

/// Decode a single modhex character to its 4-bit nibble value.
///
/// Mirrors C `decode_modhex_char()` which iterates over `modhex_alphabet`
/// checking both upper- and lower-case matches:
/// ```c
/// for (size_t i = 0; i < ELEMENTSOF(modhex_alphabet); i++)
///     if (modhex_alphabet[i] == x || (modhex_alphabet[i] - 32) == x)
///         return i;
/// return -EINVAL;
/// ```
pub fn decode_modhex_char(c: char) -> Result<usize, RecoveryKeyError> {
    let byte = c as u8;
    for (i, &m) in MODHEX_ALPHABET.iter().enumerate() {
        if m == byte {
            return Ok(i);
        }
        // Check uppercase: modhex alphabet chars are all lowercase a-z range
        if m >= b'a' && m <= b'z' && m - 32 == byte {
            return Ok(i);
        }
    }
    Err(RecoveryKeyError::InvalidChar)
}

// ── Normalize recovery key ────────────────────────────────────────────────

/// Normalize a recovery key string: validates modhex characters, inserts
/// dashes every 8 characters, and lowercases all letters.
///
/// Accepts two input formats (mirroring the C logic):
/// - **Raw**: 64 modhex characters without dashes
/// - **Formatted**: 72 characters with dashes (8 groups of 8 separated by `-`)
///
/// Returns the normalized key in formatted form with dashes.
///
/// Mirrors C `normalize_recovery_key()` from recovery-key.c.
pub fn normalize_recovery_key(password: &str) -> Result<String, RecoveryKeyError> {
    let l = password.len();
    let raw_len = RECOVERY_KEY_MODHEX_RAW_LENGTH;
    let formatted_len = raw_len + 7;

    if l != raw_len && l != formatted_len {
        return Err(RecoveryKeyError::InvalidLength);
    }

    let pw = password.as_bytes();
    let mut result = String::with_capacity(formatted_len);
    let mut j: usize = 0;

    for i in 0..l {
        if l == formatted_len && i % 5 == 4 {
            if pw[i] != b'-' {
                return Err(RecoveryKeyError::InvalidFormat);
            }
            continue;
        }

        let c = decode_modhex_char(pw[i] as char)?;
        result.push(MODHEX_ALPHABET[c] as char);
        j += 1;

        if j % 4 == 0 && j != raw_len {
            result.push('-');
        }
    }

    Ok(result)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- decode_modhex_char ----------------------------------------------------

    #[test]
    fn test_decode_modhex_all_lowercase() {
        assert_eq!(decode_modhex_char('c'), Ok(0));
        assert_eq!(decode_modhex_char('b'), Ok(1));
        assert_eq!(decode_modhex_char('d'), Ok(2));
        assert_eq!(decode_modhex_char('e'), Ok(3));
        assert_eq!(decode_modhex_char('f'), Ok(4));
        assert_eq!(decode_modhex_char('v'), Ok(15));
    }

    #[test]
    fn test_decode_modhex_all_uppercase() {
        assert_eq!(decode_modhex_char('C'), Ok(0));
        assert_eq!(decode_modhex_char('B'), Ok(1));
        assert_eq!(decode_modhex_char('V'), Ok(15));
    }

    #[test]
    fn test_decode_modhex_entire_alphabet() {
        for (i, &c) in MODHEX_ALPHABET.iter().enumerate() {
            assert_eq!(decode_modhex_char(c as char), Ok(i));
        }
    }

    #[test]
    fn test_decode_modhex_invalid_chars() {
        assert!(decode_modhex_char('x').is_err());
        assert!(decode_modhex_char('z').is_err());
        assert!(decode_modhex_char('q').is_err());
        assert!(decode_modhex_char('w').is_err());
        assert!(decode_modhex_char('0').is_err());
        assert!(decode_modhex_char('a').is_err());
        assert!(decode_modhex_char('9').is_err());
    }

    #[test]
    fn test_decode_modhex_mixed_valid_invalid() {
        assert!(decode_modhex_char('c').is_ok());
        assert!(decode_modhex_char('x').is_err());
        assert!(decode_modhex_char('v').is_ok());
    }

    // -- normalize_recovery_key ------------------------------------------------

    #[test]
    fn test_normalize_valid_with_dashes() {
        let key = "cbcd-cbcd-cbcd-cbcd-cbcd-cbcd-cbcd-cbcd";
        let result = normalize_recovery_key(key).unwrap();
        assert_eq!(result, "cbcd-cbcd-cbcd-cbcd-cbcd-cbcd-cbcd-cbcd");
    }

    #[test]
    fn test_normalize_valid_without_dashes() {
        let key = "cbcdcbcdcbcdcbcdcbcdcbcdcbcdcbcd";
        let result = normalize_recovery_key(key).unwrap();
        assert_eq!(result, "cbcd-cbcd-cbcd-cbcd-cbcd-cbcd-cbcd-cbcd");
    }

    #[test]
    fn test_normalize_uppercase() {
        let key = "CBCD-CBCD-CBCD-CBCD-CBCD-CBCD-CBCD-CBCD";
        let result = normalize_recovery_key(key).unwrap();
        assert_eq!(result, "cbcd-cbcd-cbcd-cbcd-cbcd-cbcd-cbcd-cbcd");
    }

    #[test]
    fn test_normalize_mixed_case() {
        let key = "CbCd-CbCd-CbCd-CbCd-CbCd-CbCd-CbCd-CbCd";
        let result = normalize_recovery_key(key).unwrap();
        assert_eq!(result, "cbcd-cbcd-cbcd-cbcd-cbcd-cbcd-cbcd-cbcd");
    }

    #[test]
    fn test_normalize_wrong_length() {
        assert!(normalize_recovery_key("short").is_err());
        assert!(normalize_recovery_key("").is_err());
        assert!(normalize_recovery_key("cbcdcbcdcbcd").is_err());
    }

    #[test]
    fn test_normalize_invalid_char() {
        let key = "xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx";
        assert!(normalize_recovery_key(key).is_err());
    }

    #[test]
    fn test_normalize_missing_dash() {
        let key = "cbcdc-bcd-cbcd-cbcd-cbcd-cbcd-cbcd-cbcd";
        assert!(normalize_recovery_key(key).is_err());
    }

    #[test]
    fn test_normalize_all_zeros_raw() {
        let key = "cccccccccccccccccccccccccccccccc";
        let result = normalize_recovery_key(key).unwrap();
        assert_eq!(result, "cccc-cccc-cccc-cccc-cccc-cccc-cccc-cccc");
    }

    #[test]
    fn test_normalize_all_max_raw() {
        let key = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv";
        let result = normalize_recovery_key(key).unwrap();
        assert_eq!(result, "vvvv-vvvv-vvvv-vvvv-vvvv-vvvv-vvvv-vvvv");
    }

    #[test]
    fn test_normalize_truncated_formatted() {
        let key = "cbcd-cbcd-cbcd-cbcd-cbcd-cbcd-cbcd-cbc";
        assert!(normalize_recovery_key(key).is_err());
    }

    // -- constants -------------------------------------------------------------

    #[test]
    fn test_modhex_alphabet_length() {
        assert_eq!(MODHEX_ALPHABET.len(), 16);
    }

    #[test]
    fn test_formatted_length_calculation() {
        // 32 bytes * 2 hex chars = 64 chars, divided into 8 groups of 8,
        // with 7 dashes: 64 + 7 = 71 chars (no trailing NUL in Rust).
        assert_eq!(RECOVERY_KEY_MODHEX_FORMATTED_LENGTH, 73);
        // Raw modhex chars (no dashes, no NUL)
        assert_eq!(RECOVERY_KEY_MODHEX_RAW_LENGTH * 2, 64);
        // With dashes (no NUL)
        assert_eq!(RECOVERY_KEY_MODHEX_FORMATTED_LENGTH - 1, 72);
    }
}
