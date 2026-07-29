// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=shared.recovery-key; authority=src/shared/recovery-key.c,src/shared/recovery-key.h
//
// YubiKey modhex encoding/decoding for recovery keys.
//
// Implements the pure decode/normalization part of recovery-key.c and its
// narrow C ABI used by the shadow fixtures.

// ── Constants ─────────────────────────────────────────────────────────────

/// The modhex alphabet used by YubiKey (maps nibble 0–15 to character).
pub const MODHEX_ALPHABET: &[u8; 16] = b"cbdefghijklnrtuv";

/// Raw length of a 256-bit recovery key in bytes (32 bytes = 64 modhex chars).
pub const RECOVERY_KEY_MODHEX_RAW_LENGTH: usize = 32;

/// Formatted length including the trailing NUL: 64 modhex characters in eight
/// groups of eight, seven dashes, and one NUL (`32*2/8*9 = 72`).
pub const RECOVERY_KEY_MODHEX_FORMATTED_LENGTH: usize = RECOVERY_KEY_MODHEX_RAW_LENGTH * 2 / 8 * 9;

const RECOVERY_KEY_MODHEX_VISIBLE_LENGTH: usize = RECOVERY_KEY_MODHEX_FORMATTED_LENGTH - 1;

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
    let byte = u8::try_from(u32::from(c)).map_err(|_| RecoveryKeyError::InvalidChar)?;
    decode_modhex_byte(byte)
}

fn decode_modhex_byte(byte: u8) -> Result<usize, RecoveryKeyError> {
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
/// - **Formatted**: 71 characters with dashes (8 groups of 8 separated by `-`)
///
/// Returns the normalized key in formatted form with dashes.
///
/// Mirrors C `normalize_recovery_key()` from recovery-key.c.
pub fn normalize_recovery_key(password: &str) -> Result<String, RecoveryKeyError> {
    let normalized = normalize_recovery_key_bytes(password.as_bytes())?;
    // The canonical recovery-key alphabet, separators, and trailing NUL are
    // ASCII, so this conversion cannot fail.
    Ok(
        std::str::from_utf8(&normalized[..RECOVERY_KEY_MODHEX_VISIBLE_LENGTH])
            .expect("canonical modhex recovery key is ASCII")
            .to_owned(),
    )
}

fn normalize_recovery_key_bytes(
    password: &[u8],
) -> Result<[u8; RECOVERY_KEY_MODHEX_FORMATTED_LENGTH], RecoveryKeyError> {
    let l = password.len();
    let raw = l == RECOVERY_KEY_MODHEX_RAW_LENGTH * 2;
    let formatted = l == RECOVERY_KEY_MODHEX_VISIBLE_LENGTH;
    if !raw && !formatted {
        return Err(RecoveryKeyError::InvalidLength);
    }

    let mut result = [0_u8; RECOVERY_KEY_MODHEX_FORMATTED_LENGTH];
    let mut j: usize = 0;

    for i in 0..RECOVERY_KEY_MODHEX_RAW_LENGTH {
        let k = if raw {
            i * 2
        } else {
            let k = i * 2 + i / 4;
            if i > 0 && i % 4 == 0 && password[k - 1] != b'-' {
                return Err(RecoveryKeyError::InvalidFormat);
            }
            k
        };

        let a = decode_modhex_byte(password[k])?;
        let b = decode_modhex_byte(password[k + 1])?;
        result[j] = MODHEX_ALPHABET[a];
        result[j + 1] = MODHEX_ALPHABET[b];
        j += 2;

        if i % 4 == 3 {
            result[j] = b'-';
            j += 1;
        }
    }

    debug_assert_eq!(j, RECOVERY_KEY_MODHEX_FORMATTED_LENGTH);
    result[RECOVERY_KEY_MODHEX_VISIBLE_LENGTH] = 0;
    Ok(result)
}

/// C ABI facade for `decode_modhex_char()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_decode_modhex_char(x: libc::c_char) -> libc::c_int {
    match decode_modhex_byte(x as u8) {
        Ok(value) => value as libc::c_int,
        Err(_) => -libc::EINVAL,
    }
}

/// C ABI facade for `normalize_recovery_key()`.
///
/// # Safety
///
/// `password` must point to a readable NUL-terminated C string and `ret` must
/// point to writable pointer storage. On success the facade stores a
/// `malloc(3)` allocation in `*ret`, released by `free(3)`; every error leaves
/// `*ret` unchanged. C asserts non-null inputs. This facade fails closed with
/// `-EINVAL` instead, so it cannot unwind across C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_normalize_recovery_key(
    password: *const libc::c_char,
    ret: *mut *mut libc::c_char,
) -> libc::c_int {
    if password.is_null() || ret.is_null() {
        return -libc::EINVAL;
    }

    // SAFETY: the documented C ABI requires a live NUL-terminated input.
    let password = unsafe { std::ffi::CStr::from_ptr(password) }.to_bytes();
    let raw = password.len() == RECOVERY_KEY_MODHEX_RAW_LENGTH * 2;
    let formatted = password.len() == RECOVERY_KEY_MODHEX_VISIBLE_LENGTH;
    if !raw && !formatted {
        return -libc::EINVAL;
    }

    // Allocate before character validation, like C's `new(char, ...)`, so a
    // genuine allocator failure retains priority over a later syntax failure.
    // SAFETY: malloc takes no borrowed Rust references and transfers ownership
    // of the resulting allocation to this function until successful publish.
    let mangled =
        unsafe { libc::malloc(RECOVERY_KEY_MODHEX_FORMATTED_LENGTH) }.cast::<libc::c_char>();
    if mangled.is_null() {
        return -libc::ENOMEM;
    }

    let mut j = 0;
    for i in 0..RECOVERY_KEY_MODHEX_RAW_LENGTH {
        let k = if raw {
            i * 2
        } else {
            let k = i * 2 + i / 4;
            if i > 0 && i % 4 == 0 && password[k - 1] != b'-' {
                // SAFETY: this allocation is private, live, and exactly the
                // C-sized recovery-key buffer; erase it before freeing, as C.
                unsafe {
                    std::ptr::write_bytes(
                        mangled.cast::<u8>(),
                        0,
                        RECOVERY_KEY_MODHEX_FORMATTED_LENGTH,
                    );
                    libc::free(mangled.cast());
                }
                return -libc::EINVAL;
            }
            k
        };

        let (Ok(a), Ok(b)) = (
            decode_modhex_byte(password[k]),
            decode_modhex_byte(password[k + 1]),
        ) else {
            // SAFETY: this allocation is private, live, and exactly the
            // C-sized recovery-key buffer; erase it before freeing, as C.
            unsafe {
                std::ptr::write_bytes(
                    mangled.cast::<u8>(),
                    0,
                    RECOVERY_KEY_MODHEX_FORMATTED_LENGTH,
                );
                libc::free(mangled.cast());
            }
            return -libc::EINVAL;
        };

        // SAFETY: j advances through exactly 72 positions in the private
        // 72-byte allocation, matching C's two characters plus group dash.
        unsafe {
            *mangled.add(j) = MODHEX_ALPHABET[a] as libc::c_char;
            *mangled.add(j + 1) = MODHEX_ALPHABET[b] as libc::c_char;
        }
        j += 2;
        if i % 4 == 3 {
            // SAFETY: the loop's fixed layout leaves this index in bounds.
            unsafe { *mangled.add(j) = b'-' as libc::c_char };
            j += 1;
        }
    }

    // SAFETY: the final group dash occupies the last byte and C replaces it
    // with the NUL terminator before publishing its C-owned result.
    unsafe {
        *mangled.add(RECOVERY_KEY_MODHEX_VISIBLE_LENGTH) = 0;
        *ret = mangled;
    }
    0
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

    fn canonical(chunk: &str) -> String {
        [chunk; 8].join("-")
    }

    #[test]
    fn test_normalize_valid_with_dashes() {
        let key = canonical("cbcdcbcd");
        let result = normalize_recovery_key(&key).unwrap();
        assert_eq!(result, key);
    }

    #[test]
    fn test_normalize_valid_without_dashes() {
        let key = "cbcd".repeat(16);
        let result = normalize_recovery_key(&key).unwrap();
        assert_eq!(result, canonical("cbcdcbcd"));
    }

    #[test]
    fn test_normalize_uppercase() {
        let key = canonical("CBCDCBCD");
        let result = normalize_recovery_key(&key).unwrap();
        assert_eq!(result, canonical("cbcdcbcd"));
    }

    #[test]
    fn test_normalize_mixed_case() {
        let key = canonical("CbCdCbCd");
        let result = normalize_recovery_key(&key).unwrap();
        assert_eq!(result, canonical("cbcdcbcd"));
    }

    #[test]
    fn test_normalize_wrong_length() {
        assert!(normalize_recovery_key("short").is_err());
        assert!(normalize_recovery_key("").is_err());
        assert!(normalize_recovery_key("cbcdcbcdcbcd").is_err());
    }

    #[test]
    fn test_normalize_invalid_char() {
        let key = "x".repeat(64);
        assert!(normalize_recovery_key(&key).is_err());
    }

    #[test]
    fn test_normalize_missing_dash() {
        let mut key = canonical("cbcdcbcd");
        key.replace_range(8..9, "c");
        assert!(normalize_recovery_key(&key).is_err());
    }

    #[test]
    fn test_normalize_all_zeros_raw() {
        let key = "c".repeat(64);
        let result = normalize_recovery_key(&key).unwrap();
        assert_eq!(result, canonical("cccccccc"));
    }

    #[test]
    fn test_normalize_all_max_raw() {
        let key = "v".repeat(64);
        let result = normalize_recovery_key(&key).unwrap();
        assert_eq!(result, canonical("vvvvvvvv"));
    }

    #[test]
    fn test_normalize_truncated_formatted() {
        let key = &canonical("cbcdcbcd")[..RECOVERY_KEY_MODHEX_VISIBLE_LENGTH - 1];
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
        assert_eq!(RECOVERY_KEY_MODHEX_FORMATTED_LENGTH, 72);
        // Raw modhex chars (no dashes, no NUL)
        assert_eq!(RECOVERY_KEY_MODHEX_RAW_LENGTH * 2, 64);
        // With dashes (no NUL)
        assert_eq!(RECOVERY_KEY_MODHEX_VISIBLE_LENGTH, 71);
    }
}
