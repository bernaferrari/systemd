// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/locale-util.c, src/basic/locale-util.h
//
// Locale validation and string table lookups for locale variable names.
//
// Faithfully re-implements the locale_variable_to_string / locale_variable_from_string
// string table and locale_is_valid from locale-util.c. File I/O helpers
// (get_locales, locale_is_installed), thread-unsafe helpers (is_locale_utf8),
// and memory management helpers (locale_variables_free/simplify) are not ported.

// ── Enums ─────────────────────────────────────────────────────────────────

/// Locale variable identifiers (mirrors the C `LocaleVariable` enum).
///
/// Each variant corresponds to an environment variable used for locale
/// configuration (LANG, LC_CTYPE, etc.). The discriminants match the C ABI
/// values so that callers can interop freely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum LocaleVariable {
    Lang = 0,
    Language = 1,
    LcCtype = 2,
    LcNumeric = 3,
    LcTime = 4,
    LcCollate = 5,
    LcMonetary = 6,
    LcMessages = 7,
    LcPaper = 8,
    LcName = 9,
    LcAddress = 10,
    LcTelephone = 11,
    LcMeasurement = 12,
    LcIdentification = 13,
}

/// Sentinel for an invalid locale variable.
pub const LOCALE_VARIABLE_INVALID: i32 = -22; // -EINVAL

// ── String table ──────────────────────────────────────────────────────────

/// Mapping from `LocaleVariable` discriminant to its string name.
/// Ordered by discriminant value for direct indexing.
static LOCALE_VARIABLE_TABLE: &[(&str, LocaleVariable)] = &[
    ("LANG", LocaleVariable::Lang),
    ("LANGUAGE", LocaleVariable::Language),
    ("LC_CTYPE", LocaleVariable::LcCtype),
    ("LC_NUMERIC", LocaleVariable::LcNumeric),
    ("LC_TIME", LocaleVariable::LcTime),
    ("LC_COLLATE", LocaleVariable::LcCollate),
    ("LC_MONETARY", LocaleVariable::LcMonetary),
    ("LC_MESSAGES", LocaleVariable::LcMessages),
    ("LC_PAPER", LocaleVariable::LcPaper),
    ("LC_NAME", LocaleVariable::LcName),
    ("LC_ADDRESS", LocaleVariable::LcAddress),
    ("LC_TELEPHONE", LocaleVariable::LcTelephone),
    ("LC_MEASUREMENT", LocaleVariable::LcMeasurement),
    ("LC_IDENTIFICATION", LocaleVariable::LcIdentification),
];

// ── Lookup functions ──────────────────────────────────────────────────────

/// Convert a locale variable enum to its string name.
///
/// Mirrors `locale_variable_to_string()` from locale-util.c.
/// Returns `Ok(name)` on success or `Err(LOCALE_VARIABLE_INVALID)` for unknown values.
pub fn locale_variable_to_string(v: LocaleVariable) -> Result<&'static str, i32> {
    for &(name, var) in LOCALE_VARIABLE_TABLE {
        if var == v {
            return Ok(name);
        }
    }
    Err(LOCALE_VARIABLE_INVALID)
}

/// Parse a locale variable name string into its enum value.
///
/// Mirrors `locale_variable_from_string()` from locale-util.c.
/// Returns `Ok(variable)` on success or `Err(LOCALE_VARIABLE_INVALID)` for unknown names.
pub fn locale_variable_from_string(s: &str) -> Result<LocaleVariable, i32> {
    for &(name, var) in LOCALE_VARIABLE_TABLE {
        if name == s {
            return Ok(var);
        }
    }
    Err(LOCALE_VARIABLE_INVALID)
}

// ── Locale validation ────────────────────────────────────────────────────

/// Check if a byte is in the locale-accepted charset (alphanumeric + "_.-@").
/// Mirrors the `in_charset(name, ALPHANUMERICAL "_.-@")` check in locale-util.c.
fn in_locale_charset(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'-' || c == b'@'
}

/// Check if a byte is a valid UTF-8 continuation byte.
fn is_utf8_continuation(b: u8) -> bool {
    b & 0xC0 == 0x80
}

/// Validate that a byte slice is well-formed UTF-8.
/// Returns `true` if valid, `false` otherwise.
fn utf8_is_valid(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let following = match b {
            0x00..=0x7F => 0,
            0xC2..=0xDF => 1,
            0xE0..=0xEF => 2,
            0xF0..=0xF4 => 3,
            _ => return false, // Invalid lead byte (0x80-0xBF, 0xC0-0xC1, 0xF5-0xFF)
        };

        if i + following >= bytes.len() {
            return false;
        }

        for j in 1..=following {
            if !is_utf8_continuation(bytes[i + j]) {
                return false;
            }
        }

        // Extra validation for overlong sequences
        match following {
            1 => {
                // Already handled by range 0xC2..=0xDF
            }
            2 => {
                if b == 0xE0 && bytes[i + 1] < 0xA0 {
                    return false; // Overlong 3-byte
                }
            }
            3 => {
                if b == 0xF0 && bytes[i + 1] < 0x90 {
                    return false; // Overlong 4-byte
                }
                if b == 0xF4 && bytes[i + 1] > 0x8F {
                    return false; // > U+10FFFF
                }
            }
            _ => {}
        }

        i += 1 + following;
    }
    true
}

/// Check if a byte slice is a valid filename (non-empty, no '/' or NUL).
/// Mirrors `filename_is_valid()` from path-util.c.
fn filename_is_valid(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    for &b in name {
        if b == b'/' || b == 0 {
            return false;
        }
    }
    true
}

/// Validate a locale name.
///
/// Mirrors `locale_is_valid()` from locale-util.c:
/// - Must not be empty
/// - Must be < 128 bytes
/// - Must be valid UTF-8
/// - Must be a valid filename (no '/' or NUL)
/// - Must only contain alphanumeric characters plus "_.-@"
pub fn locale_is_valid(name: &str) -> bool {
    let bytes = name.as_bytes();

    // isempty(name)
    if bytes.is_empty() {
        return false;
    }

    // strlen(name) >= 128
    if bytes.len() >= 128 {
        return false;
    }

    // !utf8_is_valid(name)
    if !utf8_is_valid(bytes) {
        return false;
    }

    // !filename_is_valid(name) — checks for '/' and NUL
    if !filename_is_valid(bytes) {
        return false;
    }

    // in_charset(name, ALPHANUMERICAL "_.-@")
    for &b in bytes {
        if !in_locale_charset(b) {
            return false;
        }
    }

    true
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── locale_variable_to_string ──────────────────────────────────────

    #[test]
    fn test_to_string_lang() {
        assert_eq!(locale_variable_to_string(LocaleVariable::Lang), Ok("LANG"));
    }

    #[test]
    fn test_to_string_language() {
        assert_eq!(
            locale_variable_to_string(LocaleVariable::Language),
            Ok("LANGUAGE")
        );
    }

    #[test]
    fn test_to_string_lc_ctype() {
        assert_eq!(
            locale_variable_to_string(LocaleVariable::LcCtype),
            Ok("LC_CTYPE")
        );
    }

    #[test]
    fn test_to_string_lc_identification() {
        assert_eq!(
            locale_variable_to_string(LocaleVariable::LcIdentification),
            Ok("LC_IDENTIFICATION")
        );
    }

    #[test]
    fn test_to_string_all_roundtrip() {
        for &(name, var) in LOCALE_VARIABLE_TABLE {
            assert_eq!(locale_variable_to_string(var), Ok(name));
        }
    }

    // ── locale_variable_from_string ────────────────────────────────────

    #[test]
    fn test_from_string_lang() {
        assert_eq!(
            locale_variable_from_string("LANG"),
            Ok(LocaleVariable::Lang)
        );
    }

    #[test]
    fn test_from_string_language() {
        assert_eq!(
            locale_variable_from_string("LANGUAGE"),
            Ok(LocaleVariable::Language)
        );
    }

    #[test]
    fn test_from_string_lc_time() {
        assert_eq!(
            locale_variable_from_string("LC_TIME"),
            Ok(LocaleVariable::LcTime)
        );
    }

    #[test]
    fn test_from_string_lc_messages() {
        assert_eq!(
            locale_variable_from_string("LC_MESSAGES"),
            Ok(LocaleVariable::LcMessages)
        );
    }

    #[test]
    fn test_from_string_empty() {
        assert_eq!(
            locale_variable_from_string(""),
            Err(LOCALE_VARIABLE_INVALID)
        );
    }

    #[test]
    fn test_from_string_invalid() {
        assert_eq!(
            locale_variable_from_string("FOO"),
            Err(LOCALE_VARIABLE_INVALID)
        );
    }

    #[test]
    fn test_from_string_all_roundtrip() {
        for &(name, var) in LOCALE_VARIABLE_TABLE {
            assert_eq!(locale_variable_from_string(name), Ok(var));
        }
    }

    // ── locale_is_valid ────────────────────────────────────────────────

    #[test]
    fn test_locale_is_valid_empty() {
        assert!(!locale_is_valid(""));
    }

    #[test]
    fn test_locale_is_valid_simple() {
        assert!(locale_is_valid("C"));
    }

    #[test]
    fn test_locale_is_valid_utf8_locale() {
        assert!(locale_is_valid("en_US.UTF-8"));
    }

    #[test]
    fn test_locale_is_valid_with_variant() {
        assert!(locale_is_valid("sr@latin"));
    }

    #[test]
    fn test_locale_is_valid_complex() {
        assert!(locale_is_valid("pt_BR.UTF-8@valencia"));
    }

    #[test]
    fn test_locale_is_valid_invalid_space() {
        assert!(!locale_is_valid("en US"));
    }

    #[test]
    fn test_locale_is_valid_invalid_special_char() {
        assert!(!locale_is_valid("en_US!"));
    }

    #[test]
    fn test_locale_is_valid_invalid_slash() {
        assert!(!locale_is_valid("en/US"));
    }

    #[test]
    fn test_locale_is_valid_too_long() {
        let long_name = "a".repeat(128);
        assert!(!locale_is_valid(&long_name));
    }

    #[test]
    fn test_locale_is_valid_max_length() {
        // 127 chars should be OK (if valid chars)
        let name = "a".repeat(127);
        assert!(locale_is_valid(&name));
    }

    #[test]
    fn test_locale_is_valid_with_dash() {
        assert!(locale_is_valid("en-US"));
    }

    #[test]
    fn test_locale_is_valid_with_dot() {
        assert!(locale_is_valid("C.UTF-8"));
    }

    #[test]
    fn test_utf8_is_valid() {
        assert!(utf8_is_valid(b"hello"));
        assert!(utf8_is_valid(b""));
        assert!(utf8_is_valid("en_US.UTF-8".as_bytes()));
        assert!(!utf8_is_valid(&[0x80])); // Invalid lead byte
        assert!(!utf8_is_valid(&[0xC0, 0x80])); // Overlong 2-byte
        assert!(!utf8_is_valid(&[0xE0, 0x80, 0x80])); // Overlong 3-byte
    }
}
