// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/recovery-key.c, src/shared/recovery-key.h
//

use std::io;

use crate::ffi::Errno;

pub const MODHEX_ALPHABET: [u8; 16] = *b"cbdefghijklnrtuv";
pub const RECOVERY_KEY_MODHEX_RAW_LENGTH: usize = 32;
pub const RECOVERY_KEY_MODHEX_FORMATTED_LENGTH: usize = RECOVERY_KEY_MODHEX_RAW_LENGTH * 2 / 8 * 9;

const RECOVERY_KEY_MODHEX_VISIBLE_LENGTH: usize = RECOVERY_KEY_MODHEX_FORMATTED_LENGTH - 1;

#[derive(Debug)]
pub enum RecoveryKeyError {
    InvalidLength(usize),
    InvalidCharacter(char),
    InvalidSeparator { expected_at: usize },
    Random(io::Error),
    ShortRandomRead,
}

impl RecoveryKeyError {
    pub fn as_errno(&self) -> i32 {
        match self {
            Self::InvalidLength(_) | Self::InvalidCharacter(_) | Self::InvalidSeparator { .. } => {
                Errno::EINVAL.to_neg_errno()
            }
            Self::Random(err) => {
                -(match err.raw_os_error() {
                    Some(errno) if errno > 0 => errno,
                    _ => Errno::EIO as i32,
                })
            }
            Self::ShortRandomRead => Errno::EIO.to_neg_errno(),
        }
    }
}

impl std::fmt::Display for RecoveryKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength(length) => write!(f, "invalid recovery key length: {length}"),
            Self::InvalidCharacter(ch) => write!(f, "invalid modhex character: {ch:?}"),
            Self::InvalidSeparator { expected_at } => {
                write!(f, "expected dash separator at offset {expected_at}")
            }
            Self::Random(err) => write!(f, "failed to read secure random bytes: {err}"),
            Self::ShortRandomRead => write!(f, "short read from getrandom()"),
        }
    }
}

impl std::error::Error for RecoveryKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Random(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for RecoveryKeyError {
    fn from(value: io::Error) -> Self {
        Self::Random(value)
    }
}

pub fn decode_modhex_char(x: char) -> Result<u8, RecoveryKeyError> {
    let byte = u8::try_from(u32::from(x)).map_err(|_| RecoveryKeyError::InvalidCharacter(x))?;
    decode_modhex_byte(byte).ok_or(RecoveryKeyError::InvalidCharacter(x))
}

pub fn normalize_recovery_key(password: &str) -> Result<String, RecoveryKeyError> {
    normalize_recovery_key_bytes(password.as_bytes())
}

pub fn make_recovery_key() -> Result<String, RecoveryKeyError> {
    let mut key = [0u8; RECOVERY_KEY_MODHEX_RAW_LENGTH];
    fill_crypto_random_bytes(&mut key)?;
    Ok(format_recovery_key(&key))
}

pub fn format_recovery_key(key: &[u8; RECOVERY_KEY_MODHEX_RAW_LENGTH]) -> String {
    let mut formatted = String::with_capacity(RECOVERY_KEY_MODHEX_VISIBLE_LENGTH);

    for (i, byte) in key.iter().copied().enumerate() {
        formatted.push(MODHEX_ALPHABET[(byte >> 4) as usize] as char);
        formatted.push(MODHEX_ALPHABET[(byte & 0x0f) as usize] as char);

        if i % 4 == 3 && i + 1 < RECOVERY_KEY_MODHEX_RAW_LENGTH {
            formatted.push('-');
        }
    }

    formatted
}

fn normalize_recovery_key_bytes(password: &[u8]) -> Result<String, RecoveryKeyError> {
    let length = password.len();
    let no_dashes = length == RECOVERY_KEY_MODHEX_RAW_LENGTH * 2;
    let with_dashes = length == RECOVERY_KEY_MODHEX_VISIBLE_LENGTH;

    if !no_dashes && !with_dashes {
        return Err(RecoveryKeyError::InvalidLength(length));
    }

    let mut mangled = String::with_capacity(RECOVERY_KEY_MODHEX_VISIBLE_LENGTH);

    for i in 0..RECOVERY_KEY_MODHEX_RAW_LENGTH {
        let k = if no_dashes {
            i * 2
        } else {
            let k = i * 2 + i / 4;
            if i > 0 && i % 4 == 0 && password[k - 1] != b'-' {
                return Err(RecoveryKeyError::InvalidSeparator { expected_at: k - 1 });
            }
            k
        };

        mangled.push(decode_nibble(password[k])?);
        mangled.push(decode_nibble(password[k + 1])?);

        if i % 4 == 3 && i + 1 < RECOVERY_KEY_MODHEX_RAW_LENGTH {
            mangled.push('-');
        }
    }

    Ok(mangled)
}

fn decode_nibble(byte: u8) -> Result<char, RecoveryKeyError> {
    decode_modhex_byte(byte)
        .map(|value| MODHEX_ALPHABET[value as usize] as char)
        .ok_or_else(|| RecoveryKeyError::InvalidCharacter(char::from(byte)))
}

fn decode_modhex_byte(x: u8) -> Option<u8> {
    MODHEX_ALPHABET
        .iter()
        .position(|candidate| *candidate == x || candidate.to_ascii_uppercase() == x)
        .map(|index| index as u8)
}

fn fill_crypto_random_bytes(buffer: &mut [u8]) -> Result<(), RecoveryKeyError> {
    let mut filled = 0;

    while filled < buffer.len() {
        let chunk = &mut buffer[filled..];
        let read = unsafe { crate::ffi::getrandom(chunk.as_mut_ptr(), chunk.len(), 0) };

        if read < 0 {
            return Err(io::Error::last_os_error().into());
        }

        if read == 0 {
            return Err(RecoveryKeyError::ShortRandomRead);
        }

        filled += read as usize;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::Errno;

    fn sequential_key() -> [u8; RECOVERY_KEY_MODHEX_RAW_LENGTH] {
        std::array::from_fn(|index| index as u8)
    }

    #[test]
    fn constants_match_header() {
        assert_eq!(RECOVERY_KEY_MODHEX_RAW_LENGTH, 32);
        assert_eq!(RECOVERY_KEY_MODHEX_FORMATTED_LENGTH, 72);
        assert_eq!(RECOVERY_KEY_MODHEX_VISIBLE_LENGTH, 71);
    }

    #[test]
    fn decode_modhex_char_accepts_lowercase() {
        assert_eq!(decode_modhex_char('c').unwrap(), 0);
        assert_eq!(decode_modhex_char('b').unwrap(), 1);
        assert_eq!(decode_modhex_char('v').unwrap(), 15);
    }

    #[test]
    fn decode_modhex_char_accepts_uppercase() {
        assert_eq!(decode_modhex_char('C').unwrap(), 0);
        assert_eq!(decode_modhex_char('V').unwrap(), 15);
        assert_eq!(decode_modhex_char('N').unwrap(), 11);
    }

    #[test]
    fn decode_modhex_char_rejects_invalid_ascii() {
        assert!(matches!(
            decode_modhex_char('a'),
            Err(RecoveryKeyError::InvalidCharacter('a'))
        ));
        assert!(matches!(
            decode_modhex_char('0'),
            Err(RecoveryKeyError::InvalidCharacter('0'))
        ));
    }

    #[test]
    fn decode_modhex_char_rejects_non_ascii() {
        assert!(matches!(
            decode_modhex_char('é'),
            Err(RecoveryKeyError::InvalidCharacter('é'))
        ));
    }

    #[test]
    fn error_to_errno_matches_c_style() {
        assert_eq!(
            RecoveryKeyError::InvalidLength(5).as_errno(),
            Errno::EINVAL.to_neg_errno()
        );
        assert_eq!(
            RecoveryKeyError::ShortRandomRead.as_errno(),
            Errno::EIO.to_neg_errno()
        );
    }

    #[test]
    fn format_recovery_key_matches_expected_output() {
        let formatted = format_recovery_key(&sequential_key());
        assert_eq!(
            formatted,
            "cccbcdce-cfcgchci-cjckclcn-crctcucv-bcbbbdbe-bfbgbhbi-bjbkblbn-brbtbubv"
        );
    }

    #[test]
    fn format_recovery_key_inserts_dashes_every_eight_chars() {
        let formatted = format_recovery_key(&[0xff; RECOVERY_KEY_MODHEX_RAW_LENGTH]);
        let dashes: Vec<_> = formatted
            .match_indices('-')
            .map(|(index, _)| index)
            .collect();
        assert_eq!(dashes, vec![8, 17, 26, 35, 44, 53, 62]);
        assert_eq!(formatted.len(), RECOVERY_KEY_MODHEX_VISIBLE_LENGTH);
    }

    #[test]
    fn normalize_accepts_canonical_form() {
        let formatted = format_recovery_key(&sequential_key());
        assert_eq!(normalize_recovery_key(&formatted).unwrap(), formatted);
    }

    #[test]
    fn normalize_accepts_form_without_dashes() {
        let formatted = format_recovery_key(&sequential_key());
        let raw: String = formatted.chars().filter(|ch| *ch != '-').collect();
        assert_eq!(raw.len(), 64);
        assert_eq!(normalize_recovery_key(&raw).unwrap(), formatted);
    }

    #[test]
    fn normalize_canonicalizes_uppercase_input() {
        let formatted = format_recovery_key(&sequential_key()).to_uppercase();
        assert_eq!(
            normalize_recovery_key(&formatted).unwrap(),
            format_recovery_key(&sequential_key())
        );
    }

    #[test]
    fn normalize_rejects_invalid_lengths() {
        assert!(matches!(
            normalize_recovery_key(""),
            Err(RecoveryKeyError::InvalidLength(0))
        ));
        assert!(matches!(
            normalize_recovery_key(&"c".repeat(63)),
            Err(RecoveryKeyError::InvalidLength(63))
        ));
        assert!(matches!(
            normalize_recovery_key(&"c".repeat(72)),
            Err(RecoveryKeyError::InvalidLength(72))
        ));
    }

    #[test]
    fn normalize_rejects_invalid_modhex_character() {
        let mut raw = format_recovery_key(&sequential_key())
            .chars()
            .filter(|ch| *ch != '-')
            .collect::<Vec<_>>();
        raw[7] = 'x';
        let raw = raw.into_iter().collect::<String>();

        assert!(matches!(
            normalize_recovery_key(&raw),
            Err(RecoveryKeyError::InvalidCharacter('x'))
        ));
    }

    #[test]
    fn normalize_rejects_missing_separator() {
        let mut formatted = format_recovery_key(&sequential_key());
        formatted.replace_range(8..9, "c");

        assert!(matches!(
            normalize_recovery_key(&formatted),
            Err(RecoveryKeyError::InvalidSeparator { expected_at: 8 })
        ));
    }

    #[test]
    fn normalize_rejects_wrong_character_where_dash_would_be_checked_later() {
        let mut formatted = format_recovery_key(&sequential_key());
        formatted.replace_range(17..18, "X");

        assert!(matches!(
            normalize_recovery_key(&formatted),
            Err(RecoveryKeyError::InvalidSeparator { expected_at: 17 })
        ));
    }

    #[test]
    fn normalize_rejects_dash_in_raw_form() {
        let mut raw: String = format_recovery_key(&sequential_key())
            .chars()
            .filter(|ch| *ch != '-')
            .collect();
        raw.replace_range(10..11, "-");

        assert!(matches!(
            normalize_recovery_key(&raw),
            Err(RecoveryKeyError::InvalidCharacter('-'))
        ));
    }

    #[test]
    fn normalize_preserves_known_reference_vector() {
        let key = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ];
        let formatted = format_recovery_key(&key);

        assert_eq!(
            formatted,
            "bdefghij-klnrtuvc-bbddeeff-gghhiijj-kkllnnrr-ttuuvvcc-cbdefghi-jklnrtuv"
        );
        assert_eq!(normalize_recovery_key(&formatted).unwrap(), formatted);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn make_recovery_key_returns_canonical_shape() {
        let key = make_recovery_key().unwrap();

        assert_eq!(key.len(), RECOVERY_KEY_MODHEX_VISIBLE_LENGTH);
        assert_eq!(normalize_recovery_key(&key).unwrap(), key);
        assert!(
            key.bytes()
                .all(|byte| byte == b'-' || decode_modhex_byte(byte).is_some())
        );
    }
}
