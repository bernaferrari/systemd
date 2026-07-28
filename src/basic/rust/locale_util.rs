// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.locale-util; authority=src/basic/locale-util.c,src/basic/locale-util.h
//
// Locale validation and string table lookups for locale variable names.
//
// Faithfully re-implements the locale_variable_to_string / locale_variable_from_string
// string table and locale_is_valid from locale-util.c. File I/O helpers
// (get_locales, locale_is_installed), thread-unsafe helpers (is_locale_utf8),
// and memory management helpers (locale_variables_free/simplify) are not ported.

use crate::ffi_string_table::{self, Entry as FfiEntry};
use std::ffi::{CStr, c_char};

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

impl LocaleVariable {
    fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Lang),
            1 => Some(Self::Language),
            2 => Some(Self::LcCtype),
            3 => Some(Self::LcNumeric),
            4 => Some(Self::LcTime),
            5 => Some(Self::LcCollate),
            6 => Some(Self::LcMonetary),
            7 => Some(Self::LcMessages),
            8 => Some(Self::LcPaper),
            9 => Some(Self::LcName),
            10 => Some(Self::LcAddress),
            11 => Some(Self::LcTelephone),
            12 => Some(Self::LcMeasurement),
            13 => Some(Self::LcIdentification),
            _ => None,
        }
    }
}

// ── String table ──────────────────────────────────────────────────────────

/// The single authority for the Rust API and borrowed C ABI strings.
///
/// The C source uses a static `const char *` table. Retaining the trailing
/// NUL here gives the Rust facade the same process-lifetime pointer semantics.
static LOCALE_VARIABLE_TABLE: &[FfiEntry] = &[
    (LocaleVariable::Lang as i32, b"LANG\0"),
    (LocaleVariable::Language as i32, b"LANGUAGE\0"),
    (LocaleVariable::LcCtype as i32, b"LC_CTYPE\0"),
    (LocaleVariable::LcNumeric as i32, b"LC_NUMERIC\0"),
    (LocaleVariable::LcTime as i32, b"LC_TIME\0"),
    (LocaleVariable::LcCollate as i32, b"LC_COLLATE\0"),
    (LocaleVariable::LcMonetary as i32, b"LC_MONETARY\0"),
    (LocaleVariable::LcMessages as i32, b"LC_MESSAGES\0"),
    (LocaleVariable::LcPaper as i32, b"LC_PAPER\0"),
    (LocaleVariable::LcName as i32, b"LC_NAME\0"),
    (LocaleVariable::LcAddress as i32, b"LC_ADDRESS\0"),
    (LocaleVariable::LcTelephone as i32, b"LC_TELEPHONE\0"),
    (LocaleVariable::LcMeasurement as i32, b"LC_MEASUREMENT\0"),
    (
        LocaleVariable::LcIdentification as i32,
        b"LC_IDENTIFICATION\0",
    ),
];

// ── Lookup functions ──────────────────────────────────────────────────────

/// Convert a locale variable enum to its string name.
///
/// Mirrors `locale_variable_to_string()` from locale-util.c.
/// Returns `Ok(name)` on success or `Err(LOCALE_VARIABLE_INVALID)` for unknown values.
pub fn locale_variable_to_string(v: LocaleVariable) -> Result<&'static str, i32> {
    ffi_string_table::to_str(LOCALE_VARIABLE_TABLE, v as i32).ok_or(LOCALE_VARIABLE_INVALID)
}

/// Parse a locale variable name string into its enum value.
///
/// Mirrors `locale_variable_from_string()` from locale-util.c.
/// Returns `Ok(variable)` on success or `Err(LOCALE_VARIABLE_INVALID)` for unknown names.
pub fn locale_variable_from_string(s: &str) -> Result<LocaleVariable, i32> {
    ffi_string_table::from_str(LOCALE_VARIABLE_TABLE, s)
        .and_then(LocaleVariable::from_raw)
        .ok_or(LOCALE_VARIABLE_INVALID)
}

// ── Locale validation ────────────────────────────────────────────────────

/// Check if a byte is in the locale-accepted charset (alphanumeric + "_.-@").
/// Mirrors the `in_charset(name, ALPHANUMERICAL "_.-@")` check in locale-util.c.
fn in_locale_charset(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'-' || c == b'@'
}

/// Validate that a byte slice is well-formed UTF-8.
///
/// C's `utf8_is_valid()` also rejects Unicode noncharacters. Locale names
/// subsequently have to be ASCII, but retaining the source check here keeps
/// this helper faithful when it is used independently.
fn utf8_is_valid(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| {
        text.chars().all(|c| {
            let value = c as u32;
            !(0xFDD0..=0xFDEF).contains(&value) && value & 0xFFFE != 0xFFFE
        })
    })
}

/// Check if a byte slice is a valid filename (non-empty, not `.`/`..`, no '/').
/// Mirrors `filename_is_valid()` from path-util.c.
fn filename_is_valid(name: &[u8]) -> bool {
    if name.is_empty() || name == b"." || name == b".." {
        return false;
    }
    !name.contains(&b'/')
}

fn locale_bytes_are_valid(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes.len() < 128
        && utf8_is_valid(bytes)
        && filename_is_valid(bytes)
        && bytes.iter().copied().all(in_locale_charset)
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
    locale_bytes_are_valid(name.as_bytes())
}

/// C ABI facade for `locale_variable_to_string()`.
///
/// Returns a borrowed pointer into immutable static storage, or NULL for an
/// invalid enum value, like `DEFINE_STRING_TABLE_LOOKUP` in the C authority.
#[unsafe(no_mangle)]
pub extern "C" fn rs_locale_variable_to_string(value: i32) -> *const c_char {
    ffi_string_table::to_ptr(LOCALE_VARIABLE_TABLE, value)
}

/// C ABI facade for `locale_variable_from_string()`.
///
/// # Safety
///
/// A non-NULL `input` must point to a live NUL-terminated C string for this
/// call. NULL returns `-EINVAL`, matching the generated C lookup helper.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_locale_variable_from_string(input: *const c_char) -> i32 {
    // SAFETY: this C ABI contract is exactly the shared adapter's contract.
    unsafe { ffi_string_table::from_ptr(LOCALE_VARIABLE_TABLE, input, LOCALE_VARIABLE_INVALID) }
}

/// C ABI facade for `locale_is_valid()`.
///
/// # Safety
///
/// A non-NULL `name` must point to a live NUL-terminated C string for this
/// call. NULL is invalid, as it is for C's `isempty(name)` guard.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_locale_is_valid(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }

    // SAFETY: required by the documented C ABI contract and checked for NULL.
    let bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    locale_bytes_are_valid(bytes)
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
        for &(value, name) in LOCALE_VARIABLE_TABLE {
            let variable = LocaleVariable::from_raw(value).unwrap();
            assert_eq!(
                locale_variable_to_string(variable),
                Ok(ffi_string_table::entry_str(name))
            );
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
        for &(value, name) in LOCALE_VARIABLE_TABLE {
            assert_eq!(
                locale_variable_from_string(ffi_string_table::entry_str(name)),
                Ok(LocaleVariable::from_raw(value).unwrap())
            );
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
    fn test_locale_is_valid_rejects_dot_names() {
        assert!(!locale_is_valid("."));
        assert!(!locale_is_valid(".."));
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
