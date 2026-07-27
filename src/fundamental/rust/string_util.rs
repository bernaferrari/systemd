// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/string-util.h, src/fundamental/string-util.c
//
// Selected string utility helpers in safe Rust.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringUtilError {
    MissingSeparator,
    InvalidHex,
}
pub type Result<T> = core::result::Result<T, StringUtilError>;

pub fn streq_ptr(a: Option<&str>, b: Option<&str>) -> bool {
    a == b
}
pub fn isempty(value: Option<&str>) -> bool {
    value.is_none_or(str::is_empty)
}
pub fn startswith<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    s.strip_prefix(prefix)
}
pub fn endswith<'a>(s: &'a str, suffix: &str) -> Option<&'a str> {
    s.strip_suffix(suffix)
}
pub fn ascii_strlower(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_lowercase()).collect()
}
pub fn delete_chars(s: &str, bad: &str) -> String {
    s.chars().filter(|c| !bad.contains(*c)).collect()
}

pub fn split_pair(s: &str, separator: char) -> Result<(&str, &str)> {
    let index = s.find(separator).ok_or(StringUtilError::MissingSeparator)?;
    Ok((&s[..index], &s[index + separator.len_utf8()..]))
}

pub fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let filtered: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if filtered.len() % 2 != 0 {
        return Err(StringUtilError::InvalidHex);
    }
    filtered
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let hi = (chunk[0] as char)
                .to_digit(16)
                .ok_or(StringUtilError::InvalidHex)?;
            let lo = (chunk[1] as char)
                .to_digit(16)
                .ok_or(StringUtilError::InvalidHex)?;
            Ok(((hi << 4) | lo) as u8)
        })
        .collect()
}

pub fn cescape_length(s: &str) -> usize {
    s.chars()
        .map(|c| {
            if c.is_ascii_control() || c == '\\' || c == '"' {
                4
            } else {
                1
            }
        })
        .sum()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    fn option_string_comparison_matches_none_semantics() {
        assert!(streq_ptr(None, None));
        assert!(!streq_ptr(Some("a"), None));
    }
    #[test]
    fn startswith_returns_rest() {
        assert_eq!(startswith("foobar", "foo"), Some("bar"));
    }
    #[test]
    fn endswith_returns_prefix() {
        assert_eq!(endswith("foobar", "bar"), Some("foo"));
    }
    #[test]
    fn lowercases_ascii_only() {
        assert_eq!(ascii_strlower("HeLLo"), "hello");
    }
    #[test]
    fn deletes_selected_chars() {
        assert_eq!(delete_chars("a-b:c", "-:"), "abc");
    }
    #[test]
    fn split_pair_finds_separator() {
        assert_eq!(split_pair("A=B", '=').unwrap(), ("A", "B"));
    }
    #[test]
    fn parses_hex_bytes() {
        assert_eq!(parse_hex("0a ff").unwrap(), vec![0x0a, 0xff]);
    }
    #[test]
    fn rejects_invalid_hex() {
        assert_eq!(parse_hex("xyz"), Err(StringUtilError::InvalidHex));
    }
}
