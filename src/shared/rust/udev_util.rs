// SPDX-License-Identifier: LGPL-2.1-or-later
/* PORT-SYNC: src/shared/udev-util.c */

use std::fmt;

const WHITESPACE: &[u8] = b" \t\n\r";

fn is_allowed_devnode_char(c: u8) -> bool {
    c.is_ascii_digit() || c.is_ascii_alphabetic() || b"#+-.:=@_".contains(&c)
}

fn is_hex_digit(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdevReplaceWhitespaceError {
    EmptyInput,
}

impl fmt::Display for UdevReplaceWhitespaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => f.write_str("input string is empty or all whitespace"),
        }
    }
}

impl std::error::Error for UdevReplaceWhitespaceError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdevReplaceCharsError {
    InvalidUtf8,
}

impl fmt::Display for UdevReplaceCharsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 => f.write_str("input string contains invalid UTF-8"),
        }
    }
}

impl std::error::Error for UdevReplaceCharsError {}

/// Replace whitespace runs with underscores, stripping leading/trailing whitespace.
/// At most `len` characters of the result are produced.
pub fn udev_replace_whitespace(
    input: &str,
    len: usize,
) -> Result<String, UdevReplaceWhitespaceError> {
    let bytes = input.as_bytes();

    let start = bytes
        .iter()
        .position(|&b| !WHITESPACE.contains(&b))
        .unwrap_or(bytes.len());

    if start == bytes.len() {
        return Err(UdevReplaceWhitespaceError::EmptyInput);
    }

    let end = bytes
        .iter()
        .rposition(|&b| !WHITESPACE.contains(&b))
        .unwrap_or(start);

    let trimmed = &bytes[start..=end];

    let mut result = String::with_capacity(trimmed.len().min(len));
    let mut prev_space = false;

    for &b in trimmed {
        if WHITESPACE.contains(&b) {
            prev_space = true;
            continue;
        }
        if prev_space {
            if result.len() + 1 >= len {
                break;
            }
            result.push('_');
            prev_space = false;
        }
        if result.len() >= len {
            break;
        }
        result.push(b as char);
    }

    Ok(result)
}

/// Sanitize a device-node name: allowed chars pass through, `\xNN` hex escapes and
/// valid multi-byte UTF-8 are preserved, everything else becomes `'_'`.
/// If `' '` is in `allow`, whitespace becomes a space instead.
/// Returns `(sanitized_string, count_of_replacements)`.
pub fn udev_replace_chars(
    input: &str,
    allow: Option<&str>,
) -> Result<(String, usize), UdevReplaceCharsError> {
    let bytes = input.as_bytes();
    let allow_set: Option<&[u8]> = allow.map(|s| s.as_bytes());
    let mut result = String::with_capacity(bytes.len());
    let mut replaced = 0;
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];

        if is_allowed_devnode_char(b) {
            result.push(b as char);
            i += 1;
            continue;
        }

        if let Some(allow_bytes) = allow_set {
            if allow_bytes.contains(&b) {
                result.push(b as char);
                i += 1;
                continue;
            }
        }

        if b == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1] == b'x'
            && is_hex_digit(bytes[i + 2])
            && is_hex_digit(bytes[i + 3])
        {
            result.push(bytes[i] as char);
            result.push(bytes[i + 1] as char);
            result.push(bytes[i + 2] as char);
            result.push(bytes[i + 3] as char);
            i += 4;
            continue;
        }

        if b == b'\\' && i + 1 < bytes.len() && bytes[i + 1] == b'x' {
            result.push('_');
            result.push('_');
            replaced += 2;
            i += 2;
            continue;
        }

        let ch = input[i..].chars().next();
        if let Some(c) = ch {
            let utf8_len = c.len_utf8();
            if utf8_len > 1 {
                result.push(c);
                i += utf8_len;
                continue;
            }
        }

        if b.is_ascii_whitespace() && allow_set.is_some_and(|a| a.contains(&b' ')) {
            result.push(' ');
            i += 1;
            replaced += 1;
            continue;
        }

        result.push('_');
        i += 1;
        replaced += 1;
    }

    Ok((result, replaced))
}

#[inline]
pub fn allow_listed_char_for_devnode(c: char, additional: Option<&str>) -> bool {
    let b = c as u8;
    if !b.is_ascii() {
        return false;
    }
    if is_allowed_devnode_char(b) {
        return true;
    }
    if let Some(extra) = additional {
        if extra.as_bytes().contains(&b) {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyLookup {
    Found(String),
    NotFound,
}

pub fn device_get_vendor_string_from_props(
    properties: &[(impl AsRef<str>, impl AsRef<str>)],
) -> PropertyLookup {
    const VENDOR_FIELDS: &[&str] = &["ID_VENDOR_FROM_DATABASE", "ID_VENDOR"];
    lookup_property_fallback(properties, VENDOR_FIELDS)
}

pub fn device_get_model_string_from_props(
    properties: &[(impl AsRef<str>, impl AsRef<str>)],
) -> PropertyLookup {
    const MODEL_FIELDS: &[&str] = &["ID_MODEL_FROM_DATABASE", "ID_MODEL"];
    lookup_property_fallback(properties, MODEL_FIELDS)
}

pub fn lookup_property_fallback(
    properties: &[(impl AsRef<str>, impl AsRef<str>)],
    fields: &[&str],
) -> PropertyLookup {
    for field in fields {
        for (key, value) in properties {
            if key.as_ref() == *field {
                return PropertyLookup::Found(value.as_ref().to_string());
            }
        }
    }
    PropertyLookup::NotFound
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyWithFallback {
    Found(String, Source),
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Device,
    ExtraProps,
}

pub fn device_get_property_value_with_fallback(
    device_props: &[(impl AsRef<str>, impl AsRef<str>)],
    extra_props: &[(impl AsRef<str>, impl AsRef<str>)],
    prop: &str,
) -> PropertyWithFallback {
    for (key, value) in device_props {
        if key.as_ref() == prop {
            return PropertyWithFallback::Found(value.as_ref().to_string(), Source::Device);
        }
    }
    for (key, value) in extra_props {
        if key.as_ref() == prop {
            return PropertyWithFallback::Found(value.as_ref().to_string(), Source::ExtraProps);
        }
    }
    PropertyWithFallback::NotFound
}

pub fn parse_device_property_bool(value: Option<&str>) -> Option<bool> {
    match value? {
        "1" => Some(true),
        "true" => Some(true),
        "yes" => Some(true),
        "0" => Some(false),
        "false" => Some(false),
        "no" => Some(false),
        _ => None,
    }
}

pub fn device_is_renaming_from_props(properties: &[(impl AsRef<str>, impl AsRef<str>)]) -> bool {
    let value = properties
        .iter()
        .find(|(k, _)| k.as_ref() == "ID_RENAMING")
        .map(|(_, v)| v.as_ref());
    parse_device_property_bool(value).unwrap_or(false)
}

pub fn device_is_processed_from_props(
    is_initialized: bool,
    properties: &[(impl AsRef<str>, impl AsRef<str>)],
) -> bool {
    if !is_initialized {
        return false;
    }

    let processing = properties
        .iter()
        .find(|(k, _)| k.as_ref() == "ID_PROCESSING")
        .map(|(_, v)| v.as_ref());

    match parse_device_property_bool(processing) {
        None => true,
        Some(p) => !p,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_whitespace_simple() {
        assert_eq!(
            udev_replace_whitespace("hello world", 100).unwrap(),
            "hello_world"
        );
    }

    #[test]
    fn replace_whitespace_leading_trailing() {
        assert_eq!(
            udev_replace_whitespace("  foo bar  ", 100).unwrap(),
            "foo_bar"
        );
    }

    #[test]
    fn replace_whitespace_multiple_spaces() {
        assert_eq!(udev_replace_whitespace("a   b    c", 100).unwrap(), "a_b_c");
    }

    #[test]
    fn replace_whitespace_tabs_and_newlines() {
        assert_eq!(
            udev_replace_whitespace("a\tb\nc\r\n d", 100).unwrap(),
            "a_b_c_d"
        );
    }

    #[test]
    fn replace_whitespace_empty_input() {
        assert_eq!(
            udev_replace_whitespace("", 100),
            Err(UdevReplaceWhitespaceError::EmptyInput)
        );
    }

    #[test]
    fn replace_whitespace_all_whitespace() {
        assert_eq!(
            udev_replace_whitespace("   \t\n  ", 100),
            Err(UdevReplaceWhitespaceError::EmptyInput)
        );
    }

    #[test]
    fn replace_whitespace_len_truncation() {
        assert_eq!(udev_replace_whitespace("hello world", 5).unwrap(), "hello");
    }

    #[test]
    fn replace_whitespace_len_truncation_at_underscore() {
        assert_eq!(udev_replace_whitespace("a b c", 2).unwrap(), "a");
    }

    #[test]
    fn replace_whitespace_no_whitespace() {
        assert_eq!(udev_replace_whitespace("foobar", 100).unwrap(), "foobar");
    }

    #[test]
    fn replace_whitespace_single_char() {
        assert_eq!(udev_replace_whitespace("x", 100).unwrap(), "x");
    }

    #[test]
    fn replace_chars_all_allowed() {
        let input = "sda1";
        assert_eq!(
            udev_replace_chars(input, None).unwrap(),
            (input.to_string(), 0)
        );
    }

    #[test]
    fn replace_chars_special_chars_replaced() {
        assert_eq!(
            udev_replace_chars("foo!bar", None).unwrap(),
            ("foo_bar".to_string(), 1)
        );
    }

    #[test]
    fn replace_chars_hex_escape_preserved() {
        assert_eq!(
            udev_replace_chars(r"test\x20end", None).unwrap(),
            (r"test\x20end".to_string(), 0)
        );
    }

    #[test]
    fn replace_chars_allow_space() {
        assert_eq!(
            udev_replace_chars("a b\tc", Some(" ")).unwrap(),
            ("a b c".to_string(), 1)
        );
    }

    #[test]
    fn replace_chars_allow_additional() {
        assert_eq!(
            udev_replace_chars("a!b", Some("!")).unwrap(),
            ("a!b".to_string(), 0)
        );
    }

    #[test]
    fn replace_chars_utf8_preserved() {
        assert_eq!(
            udev_replace_chars("dev_ünicode", None).unwrap(),
            ("dev_ünicode".to_string(), 0)
        );
    }

    #[test]
    fn replace_chars_multiple_replacements() {
        assert_eq!(
            udev_replace_chars("a!b@c#d$e", None).unwrap(),
            ("a_b@c#d_e".to_string(), 2)
        );
    }

    #[test]
    fn replace_chars_empty_string() {
        assert_eq!(udev_replace_chars("", None).unwrap(), (String::new(), 0));
    }

    #[test]
    fn replace_chars_invalid_hex_escape_replaced() {
        assert_eq!(
            udev_replace_chars(r"test\xGG", None).unwrap(),
            ("test__GG".to_string(), 2)
        );
    }

    #[test]
    fn allow_listed_basic() {
        assert!(allow_listed_char_for_devnode('a', None));
        assert!(allow_listed_char_for_devnode('Z', None));
        assert!(allow_listed_char_for_devnode('0', None));
        assert!(allow_listed_char_for_devnode('#', None));
        assert!(allow_listed_char_for_devnode('_', None));
        assert!(!allow_listed_char_for_devnode('!', None));
        assert!(!allow_listed_char_for_devnode(' ', None));
    }

    #[test]
    fn allow_listed_with_additional() {
        assert!(allow_listed_char_for_devnode('!', Some("!")));
        assert!(allow_listed_char_for_devnode('@', Some("!")));
        assert!(!allow_listed_char_for_devnode('\0', Some("!")));
    }

    #[test]
    fn vendor_string_from_database() {
        let props = vec![
            ("ID_VENDOR_FROM_DATABASE", "Acme Corp"),
            ("ID_VENDOR", "Acme"),
        ];
        assert_eq!(
            device_get_vendor_string_from_props(&props),
            PropertyLookup::Found("Acme Corp".to_string())
        );
    }

    #[test]
    fn vendor_string_fallback() {
        let props = vec![("ID_VENDOR", "Acme")];
        assert_eq!(
            device_get_vendor_string_from_props(&props),
            PropertyLookup::Found("Acme".to_string())
        );
    }

    #[test]
    fn vendor_string_not_found() {
        let props: Vec<(&str, &str)> = vec![("ID_MODEL", "XYZ")];
        assert_eq!(
            device_get_vendor_string_from_props(&props),
            PropertyLookup::NotFound
        );
    }

    #[test]
    fn model_string_from_database() {
        let props = vec![("ID_MODEL_FROM_DATABASE", "Super Disk"), ("ID_MODEL", "SD")];
        assert_eq!(
            device_get_model_string_from_props(&props),
            PropertyLookup::Found("Super Disk".to_string())
        );
    }

    #[test]
    fn model_string_fallback() {
        let props = vec![("ID_MODEL", "SD")];
        assert_eq!(
            device_get_model_string_from_props(&props),
            PropertyLookup::Found("SD".to_string())
        );
    }

    #[test]
    fn property_with_fallback_from_device() {
        let dev = vec![("ID_SERIAL", "abc123")];
        let extra: Vec<(&str, &str)> = vec![];
        assert_eq!(
            device_get_property_value_with_fallback(&dev, &extra, "ID_SERIAL"),
            PropertyWithFallback::Found("abc123".to_string(), Source::Device)
        );
    }

    #[test]
    fn property_with_fallback_from_extra() {
        let dev: Vec<(&str, &str)> = vec![];
        let extra = vec![("ID_SERIAL", "fallback")];
        assert_eq!(
            device_get_property_value_with_fallback(&dev, &extra, "ID_SERIAL"),
            PropertyWithFallback::Found("fallback".to_string(), Source::ExtraProps)
        );
    }

    #[test]
    fn property_with_fallback_device_takes_precedence() {
        let dev = vec![("ID_SERIAL", "primary")];
        let extra = vec![("ID_SERIAL", "fallback")];
        assert_eq!(
            device_get_property_value_with_fallback(&dev, &extra, "ID_SERIAL"),
            PropertyWithFallback::Found("primary".to_string(), Source::Device)
        );
    }

    #[test]
    fn property_with_fallback_not_found() {
        let dev: Vec<(&str, &str)> = vec![];
        let extra: Vec<(&str, &str)> = vec![];
        assert_eq!(
            device_get_property_value_with_fallback(&dev, &extra, "ID_SERIAL"),
            PropertyWithFallback::NotFound
        );
    }

    #[test]
    fn parse_property_bool_variants() {
        assert_eq!(parse_device_property_bool(Some("1")), Some(true));
        assert_eq!(parse_device_property_bool(Some("true")), Some(true));
        assert_eq!(parse_device_property_bool(Some("yes")), Some(true));
        assert_eq!(parse_device_property_bool(Some("0")), Some(false));
        assert_eq!(parse_device_property_bool(Some("false")), Some(false));
        assert_eq!(parse_device_property_bool(Some("no")), Some(false));
        assert_eq!(parse_device_property_bool(Some("unknown")), None);
        assert_eq!(parse_device_property_bool(None), None);
    }

    #[test]
    fn device_is_renaming_true() {
        let props = vec![("ID_RENAMING", "1")];
        assert!(device_is_renaming_from_props(&props));
    }

    #[test]
    fn device_is_renaming_false() {
        let props = vec![("ID_RENAMING", "0")];
        assert!(!device_is_renaming_from_props(&props));
    }

    #[test]
    fn device_is_renaming_default() {
        let props: Vec<(&str, &str)> = vec![("ID_MODEL", "X")];
        assert!(!device_is_renaming_from_props(&props));
    }

    #[test]
    fn device_is_processed_not_initialized() {
        let props: Vec<(&str, &str)> = vec![];
        assert!(!device_is_processed_from_props(false, &props));
    }

    #[test]
    fn device_is_processed_no_processing_prop() {
        let props: Vec<(&str, &str)> = vec![];
        assert!(device_is_processed_from_props(true, &props));
    }

    #[test]
    fn device_is_processing_active() {
        let props = vec![("ID_PROCESSING", "1")];
        assert!(!device_is_processed_from_props(true, &props));
    }

    #[test]
    fn device_is_processed_after_done() {
        let props = vec![("ID_PROCESSING", "0")];
        assert!(device_is_processed_from_props(true, &props));
    }

    #[test]
    fn lookup_fallback_empty_fields() {
        let props = vec![("A", "1")];
        assert_eq!(
            lookup_property_fallback(&props, &[]),
            PropertyLookup::NotFound
        );
    }

    #[test]
    fn lookup_fallback_first_match() {
        let props = vec![("A", "1"), ("B", "2"), ("A", "3")];
        assert_eq!(
            lookup_property_fallback(&props, &["A", "B"]),
            PropertyLookup::Found("1".to_string())
        );
    }
}
