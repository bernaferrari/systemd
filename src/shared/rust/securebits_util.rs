// SPDX-License-Identifier: LGPL-2.1-or-later
use crate::ffi::*;
/* PORT-SYNC: src/shared/securebits-util.c, src/shared/securebits-util.h */

use std::fmt;
use std::str::FromStr;

use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SecureBits: i32 {
        const NOROOT = 1 << 0;
        const NOROOT_LOCKED = 1 << 1;
        const NO_SETUID_FIXUP = 1 << 2;
        const NO_SETUID_FIXUP_LOCKED = 1 << 3;
        const KEEP_CAPS = 1 << 4;
        const KEEP_CAPS_LOCKED = 1 << 5;
        const NO_CAP_AMBIENT_RAISE = 1 << 6;
        const NO_CAP_AMBIENT_RAISE_LOCKED = 1 << 7;
        const EXEC_RESTRICT_FILE = 1 << 8;
        const EXEC_RESTRICT_FILE_LOCKED = 1 << 9;
        const EXEC_DENY_INTERACTIVE = 1 << 10;
        const EXEC_DENY_INTERACTIVE_LOCKED = 1 << 11;

        const ALL_BITS = Self::NOROOT.bits()
            | Self::NO_SETUID_FIXUP.bits()
            | Self::KEEP_CAPS.bits()
            | Self::NO_CAP_AMBIENT_RAISE.bits()
            | Self::EXEC_RESTRICT_FILE.bits()
            | Self::EXEC_DENY_INTERACTIVE.bits();
        const ALL_LOCKS = Self::NOROOT_LOCKED.bits()
            | Self::NO_SETUID_FIXUP_LOCKED.bits()
            | Self::KEEP_CAPS_LOCKED.bits()
            | Self::NO_CAP_AMBIENT_RAISE_LOCKED.bits()
            | Self::EXEC_RESTRICT_FILE_LOCKED.bits()
            | Self::EXEC_DENY_INTERACTIVE_LOCKED.bits();
        const VALID_MASK = Self::ALL_BITS.bits() | Self::ALL_LOCKS.bits();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseSecureBitsError {
    token: String,
}

impl ParseSecureBitsError {
    pub fn token(&self) -> &str {
        &self.token
    }
}

impl fmt::Display for ParseSecureBitsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid securebits token: {}", self.token)
    }
}

impl std::error::Error for ParseSecureBitsError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SecureBitName {
    flag: SecureBits,
    name: &'static str,
}

impl SecureBitName {
    const fn new(flag: SecureBits, name: &'static str) -> Self {
        Self { flag, name }
    }
}

const DISPLAY_ORDER: [SecureBitName; 6] = [
    SecureBitName::new(SecureBits::KEEP_CAPS, "keep-caps"),
    SecureBitName::new(SecureBits::KEEP_CAPS_LOCKED, "keep-caps-locked"),
    SecureBitName::new(SecureBits::NO_SETUID_FIXUP, "no-setuid-fixup"),
    SecureBitName::new(SecureBits::NO_SETUID_FIXUP_LOCKED, "no-setuid-fixup-locked"),
    SecureBitName::new(SecureBits::NOROOT, "noroot"),
    SecureBitName::new(SecureBits::NOROOT_LOCKED, "noroot-locked"),
];

impl SecureBits {
    pub fn is_valid(self) -> bool {
        Self::is_valid_raw(self.bits())
    }

    pub const fn is_valid_raw(bits: i32) -> bool {
        bits & !Self::VALID_MASK.bits() == 0
    }

    pub fn name(self) -> Option<&'static str> {
        DISPLAY_ORDER
            .iter()
            .find_map(|entry| (entry.flag == self).then_some(entry.name))
    }

    pub fn names(self) -> Vec<&'static str> {
        DISPLAY_ORDER
            .iter()
            .filter_map(|entry| self.contains(entry.flag).then_some(entry.name))
            .collect()
    }

    pub fn from_display_name(name: &str) -> Option<Self> {
        match name {
            "keep-caps" => Some(Self::KEEP_CAPS),
            "keep-caps-locked" => Some(Self::KEEP_CAPS_LOCKED),
            "no-setuid-fixup" => Some(Self::NO_SETUID_FIXUP),
            "no-setuid-fixup-locked" => Some(Self::NO_SETUID_FIXUP_LOCKED),
            "noroot" => Some(Self::NOROOT),
            "noroot-locked" => Some(Self::NOROOT_LOCKED),
            _ => None,
        }
    }
}

impl fmt::Display for SecureBits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, name) in self.names().into_iter().enumerate() {
            if index > 0 {
                f.write_str(" ")?;
            }

            f.write_str(name)?;
        }

        Ok(())
    }
}

impl FromStr for SecureBits {
    type Err = ParseSecureBitsError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut bits = Self::empty();

        for token in tokenize_secure_bits(input) {
            let Some(flag) = Self::from_display_name(&token) else {
                return Err(ParseSecureBitsError { token });
            };

            bits |= flag;
        }

        Ok(bits)
    }
}

pub fn secure_bits_to_string(bits: i32) -> String {
    SecureBits::from_bits_truncate(bits).to_string()
}

pub fn secure_bits_to_strv(bits: i32) -> Vec<&'static str> {
    SecureBits::from_bits_truncate(bits).names()
}

pub fn secure_bits_from_string(input: &str) -> i32 {
    let mut bits = SecureBits::empty();

    for token in tokenize_secure_bits(input) {
        if let Some(flag) = SecureBits::from_display_name(&token) {
            bits |= flag;
        }
    }

    bits.bits()
}

pub const fn secure_bits_is_valid(bits: i32) -> bool {
    SecureBits::is_valid_raw(bits)
}

fn tokenize_secure_bits(input: &str) -> Vec<String> {
    let bytes = input.as_bytes();
    let mut index = 0;
    let mut tokens = Vec::new();

    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }

        if index >= bytes.len() {
            break;
        }

        let start = index;
        let token = match bytes[index] {
            b'\'' | b'"' => {
                let quote = bytes[index];
                let content_start = index + 1;
                index += 1;

                while index < bytes.len() && bytes[index] != quote {
                    index += 1;
                }

                let content_end = index;

                if index < bytes.len() {
                    index += 1;
                }

                &input[content_start..content_end]
            }
            _ => {
                while index < bytes.len() && !bytes[index].is_ascii_whitespace() {
                    index += 1;
                }

                &input[start..index]
            }
        };

        tokens.push(token.to_owned());
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_bit_constants_match_c_bit_positions() {
        assert_eq!(SecureBits::NOROOT.bits(), 1 << 0);
        assert_eq!(SecureBits::NOROOT_LOCKED.bits(), 1 << 1);
        assert_eq!(SecureBits::NO_SETUID_FIXUP.bits(), 1 << 2);
        assert_eq!(SecureBits::NO_SETUID_FIXUP_LOCKED.bits(), 1 << 3);
        assert_eq!(SecureBits::KEEP_CAPS.bits(), 1 << 4);
        assert_eq!(SecureBits::KEEP_CAPS_LOCKED.bits(), 1 << 5);
    }

    #[test]
    fn name_lookup_matches_c_string_table() {
        for entry in DISPLAY_ORDER {
            assert_eq!(entry.flag.name(), Some(entry.name));
        }
    }

    #[test]
    fn display_uses_c_output_order() {
        let bits = SecureBits::NOROOT | SecureBits::KEEP_CAPS | SecureBits::NO_SETUID_FIXUP;
        assert_eq!(bits.to_string(), "keep-caps no-setuid-fixup noroot");
    }

    #[test]
    fn display_ignores_valid_bits_without_string_mapping() {
        let bits = SecureBits::NO_CAP_AMBIENT_RAISE | SecureBits::EXEC_DENY_INTERACTIVE;
        assert_eq!(bits.to_string(), "");
    }

    #[test]
    fn from_str_parses_known_tokens() {
        let bits: SecureBits = "keep-caps noroot".parse().unwrap();
        assert_eq!(bits, SecureBits::KEEP_CAPS | SecureBits::NOROOT);
    }

    #[test]
    fn from_str_rejects_unknown_token() {
        let err = "keep-caps bogus".parse::<SecureBits>().unwrap_err();
        assert_eq!(err.token(), "bogus");
        assert_eq!(format!("{err}"), "invalid securebits token: bogus");
    }

    #[test]
    fn from_str_handles_quoted_tokens() {
        let bits: SecureBits = "\"keep-caps\" 'noroot'".parse().unwrap();
        assert_eq!(bits, SecureBits::KEEP_CAPS | SecureBits::NOROOT);
    }

    #[test]
    fn from_str_treats_unterminated_quotes_as_single_invalid_token() {
        let err = "noroot \"foo keep-caps".parse::<SecureBits>().unwrap_err();
        assert_eq!(err.token(), "foo keep-caps");
    }

    #[test]
    fn secure_bits_from_string_matches_c_mixed_cases() {
        assert_eq!(
            secure_bits_from_string("keep-caps keep-caps keep-caps"),
            SecureBits::KEEP_CAPS.bits()
        );
        assert_eq!(
            secure_bits_from_string("keep-caps noroot keep-caps"),
            (SecureBits::KEEP_CAPS | SecureBits::NOROOT).bits()
        );
        assert_eq!(
            secure_bits_from_string("noroot foo bar baz noroot"),
            SecureBits::NOROOT.bits()
        );
        assert_eq!(
            secure_bits_from_string("noroot \"foo\" \"bar keep-caps"),
            SecureBits::NOROOT.bits()
        );
        assert_eq!(
            secure_bits_from_string("\"noroot foo\" bar keep-caps"),
            SecureBits::KEEP_CAPS.bits()
        );
    }

    #[test]
    fn secure_bits_from_string_ignores_unknown_and_whitespace_only_input() {
        assert_eq!(secure_bits_from_string(""), 0);
        assert_eq!(secure_bits_from_string("     "), 0);
        assert_eq!(secure_bits_from_string("foo bar baz"), 0);
    }

    #[test]
    fn secure_bits_to_strv_matches_c_order() {
        let bits = SecureBits::NOROOT | SecureBits::KEEP_CAPS_LOCKED | SecureBits::NO_SETUID_FIXUP;
        assert_eq!(
            secure_bits_to_strv(bits.bits()),
            vec!["keep-caps-locked", "no-setuid-fixup", "noroot"]
        );
    }

    #[test]
    fn secure_bits_is_valid_accepts_full_kernel_mask() {
        assert!(secure_bits_is_valid(0));
        assert!(secure_bits_is_valid(SecureBits::ALL_BITS.bits()));
        assert!(secure_bits_is_valid(SecureBits::ALL_LOCKS.bits()));
        assert!(secure_bits_is_valid(SecureBits::VALID_MASK.bits()));
    }

    #[test]
    fn secure_bits_is_valid_rejects_unknown_bits() {
        assert!(!secure_bits_is_valid(1 << 12));
        assert!(!secure_bits_is_valid(-1));
    }

    #[test]
    fn names_returns_only_string_mapped_flags() {
        let bits = SecureBits::KEEP_CAPS | SecureBits::NO_CAP_AMBIENT_RAISE | SecureBits::NOROOT;
        assert_eq!(bits.names(), vec!["keep-caps", "noroot"]);
    }
}
