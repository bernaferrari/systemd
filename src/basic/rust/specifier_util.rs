// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/specifier.c (specifier_escape, specifier_escape_strv)
//            src/shared/efi-loader.c (efi_loader_entry_name_valid)
//
// Specifier escaping and EFI loader validation utilities.

use crate::ffi::Errno;

// ── Specifier escaping ───────────────────────────────────────────────────

/// Port of C `specifier_escape()`.
/// Replaces all "%" with "%%" in the input string.
pub fn specifier_escape(string: &str) -> String {
    string.replace('%', "%%")
}

/// Port of C `specifier_escape_strv()`.
/// Applies `specifier_escape()` to each string in the slice.
pub fn specifier_escape_strv(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| specifier_escape(v)).collect()
}

// ── EFI loader entry validation ──────────────────────────────────────────

/// Port of C `efi_loader_entry_name_valid()`.
/// Validates an EFI loader entry name: must be a valid filename and
/// only contain alphanumeric chars plus "+-_.@".
pub fn efi_loader_entry_name_valid(s: &str) -> bool {
    // filename_is_valid: non-empty, no '/', no "." or "..", len <= 255
    if s.is_empty() || s.len() > 255 {
        return false;
    }
    if s == "." || s == ".." {
        return false;
    }
    if s.contains('/') {
        return false;
    }

    // in_charset(s, ALPHANUMERICAL "+-_.@")
    s.bytes().all(|b| {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'_' || b == b'.' || b == b'@'
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── specifier_escape ──────────────────────────────────────────────

    #[test]
    fn test_specifier_escape_no_percent() {
        assert_eq!(specifier_escape("hello"), "hello");
    }

    #[test]
    fn test_specifier_escape_single_percent() {
        assert_eq!(specifier_escape("100%"), "100%%");
    }

    #[test]
    fn test_specifier_escape_multiple_percent() {
        assert_eq!(specifier_escape("%a%b%c%"), "%%a%%b%%c%%");
    }

    #[test]
    fn test_specifier_escape_all_percent() {
        assert_eq!(specifier_escape("%%%%"), "%%%%%%%%");
    }

    #[test]
    fn test_specifier_escape_empty() {
        assert_eq!(specifier_escape(""), "");
    }

    #[test]
    fn test_specifier_escape_at_start() {
        assert_eq!(specifier_escape("%test"), "%%test");
    }

    #[test]
    fn test_specifier_escape_at_end() {
        assert_eq!(specifier_escape("test%"), "test%%");
    }

    #[test]
    fn test_specifier_escape_consecutive() {
        assert_eq!(specifier_escape("a%%b"), "a%%%%b");
    }

    #[test]
    fn test_specifier_escape_long_string() {
        assert_eq!(
            specifier_escape("kernel %v initrd %i"),
            "kernel %%v initrd %%i"
        );
    }

    // ── specifier_escape_strv ─────────────────────────────────────────

    #[test]
    fn test_specifier_escape_strv_empty() {
        let result = specifier_escape_strv(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_specifier_escape_strv_single_no_percent() {
        let result = specifier_escape_strv(&["hello"]);
        assert_eq!(result, vec!["hello"]);
    }

    #[test]
    fn test_specifier_escape_strv_single_with_percent() {
        let result = specifier_escape_strv(&["100%"]);
        assert_eq!(result, vec!["100%%"]);
    }

    #[test]
    fn test_specifier_escape_strv_multiple() {
        let result = specifier_escape_strv(&["a%b", "c"]);
        assert_eq!(result, vec!["a%%b", "c"]);
    }

    #[test]
    fn test_specifier_escape_strv_all_percents() {
        let result = specifier_escape_strv(&["%", "%%"]);
        assert_eq!(result, vec!["%%", "%%%%"]);
    }

    // ── efi_loader_entry_name_valid ───────────────────────────────────

    #[test]
    fn test_efi_valid_simple() {
        assert!(efi_loader_entry_name_valid("linux"));
    }

    #[test]
    fn test_efi_valid_with_dots() {
        assert!(efi_loader_entry_name_valid("vmlinuz-6.1"));
    }

    #[test]
    fn test_efi_valid_with_plus() {
        assert!(efi_loader_entry_name_valid("arch+fallback"));
    }

    #[test]
    fn test_efi_valid_with_at() {
        assert!(efi_loader_entry_name_valid("test@entry"));
    }

    #[test]
    fn test_efi_valid_with_underscore() {
        assert!(efi_loader_entry_name_valid("my_entry"));
    }

    #[test]
    fn test_efi_valid_numeric() {
        assert!(efi_loader_entry_name_valid("12345"));
    }

    #[test]
    fn test_efi_valid_empty() {
        assert!(!efi_loader_entry_name_valid(""));
    }

    #[test]
    fn test_efi_valid_dot() {
        assert!(!efi_loader_entry_name_valid("."));
    }

    #[test]
    fn test_efi_valid_dotdot() {
        assert!(!efi_loader_entry_name_valid(".."));
    }

    #[test]
    fn test_efi_valid_with_space() {
        assert!(!efi_loader_entry_name_valid("linux old"));
    }

    #[test]
    fn test_efi_valid_with_slash() {
        assert!(!efi_loader_entry_name_valid("linux/boot"));
    }

    #[test]
    fn test_efi_valid_with_special_chars() {
        assert!(!efi_loader_entry_name_valid("linux#1"));
    }

    #[test]
    fn test_efi_valid_with_hyphen() {
        assert!(efi_loader_entry_name_valid("my-entry"));
    }

    #[test]
    fn test_efi_valid_too_long() {
        let long_name = "a".repeat(256);
        assert!(!efi_loader_entry_name_valid(&long_name));
    }

    #[test]
    fn test_efi_valid_max_length() {
        let max_name = "a".repeat(255);
        assert!(efi_loader_entry_name_valid(&max_name));
    }
}
