// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.ansi-color; authority=src/basic/ansi-color.c,src/basic/ansi-color.h
//
// ANSI color mode parsing, environment detection, and validation.
// Pure Rust — string table lookups and environment queries use safe Rust APIs.

use crate::ffi::Errno;
use std::ffi::CStr;
use std::os::raw::c_char;

// ── ColorMode enum ────────────────────────────────────────────────────────

/// ANSI color support level.
///
/// Fixed modes (0–3) are explicit colour settings.
/// Auto modes (4–6) defer to terminal capability detection.
/// True (7) forces full colour support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ColorMode {
    Off = 0,
    C16 = 1,
    C256 = 2,
    C24bit = 3,
    Auto16 = 4,
    Auto256 = 5,
    Auto24bit = 6,
    True = 7,
}

impl ColorMode {
    /// Upper bound for the fixed-mode range (Off..Auto16).
    pub const FIXED_MAX: i32 = 4;
    /// Total number of named modes in the string table.
    pub const MAX: i32 = 8;
    /// Sentinel for an invalid/unparseable mode.
    pub const INVALID: i32 = Errno::EINVAL.to_neg_errno();

    /// Convert a raw `i32` to `ColorMode`.
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Off),
            1 => Some(Self::C16),
            2 => Some(Self::C256),
            3 => Some(Self::C24bit),
            4 => Some(Self::Auto16),
            5 => Some(Self::Auto256),
            6 => Some(Self::Auto24bit),
            7 => Some(Self::True),
            _ => None,
        }
    }
}

// ── String table ──────────────────────────────────────────────────────────

const COLOR_MODE_NAMES: [&str; 8] = [
    "off",        // ColorMode::Off
    "16",         // ColorMode::C16
    "256",        // ColorMode::C256
    "24bit",      // ColorMode::C24bit
    "auto-16",    // ColorMode::Auto16
    "auto-256",   // ColorMode::Auto256
    "auto-24bit", // ColorMode::Auto24bit
    "true",       // ColorMode::True
];

// ── Boolean parsing ───────────────────────────────────────────────────────

/// Parse a boolean-like string value.
///
/// Returns `Some(true)` for the case-insensitive systemd boolean spellings
/// "1", "yes", "y", "true", "t", and "on".
/// Returns `Some(false)` for "0", "no", "n", "false", "f", and "off".
/// Returns `None` for anything else (including empty or unrecognised strings).
fn parse_boolean(s: &str) -> Option<bool> {
    (s.eq_ignore_ascii_case("1")
        || s.eq_ignore_ascii_case("yes")
        || s.eq_ignore_ascii_case("y")
        || s.eq_ignore_ascii_case("true")
        || s.eq_ignore_ascii_case("t")
        || s.eq_ignore_ascii_case("on"))
    .then_some(true)
    .or_else(|| {
        (s.eq_ignore_ascii_case("0")
            || s.eq_ignore_ascii_case("no")
            || s.eq_ignore_ascii_case("n")
            || s.eq_ignore_ascii_case("false")
            || s.eq_ignore_ascii_case("f")
            || s.eq_ignore_ascii_case("off"))
        .then_some(false)
    })
}

// ── color_mode_from_string ────────────────────────────────────────────────

/// Parse a colour mode from a string.
///
/// First tries the string table, then falls back to boolean parsing
/// (yes/true/1 → `True`, no/false/0 → `Off`).
/// Returns `Ok(mode)` on success or `Err(EINVAL)` for unrecognised strings.
///
/// Corresponds to `color_mode_from_string()` with
/// `DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(yes=COLOR_TRUE)`.
pub fn color_mode_from_string(s: &str) -> Result<ColorMode, Errno> {
    // String table lookup
    for (i, &name) in COLOR_MODE_NAMES.iter().enumerate() {
        if s == name {
            return Ok(ColorMode::from_i32(i as i32).unwrap());
        }
    }

    // Boolean fallback
    match parse_boolean(s) {
        Some(true) => Ok(ColorMode::True),
        Some(false) => Ok(ColorMode::Off),
        None => Err(Errno::EINVAL),
    }
}

// ── color_mode_to_string ──────────────────────────────────────────────────

/// Convert a `ColorMode` to its canonical string representation.
///
/// Returns `Some(name)` for valid modes in the table range, `None` otherwise.
/// Corresponds to `color_mode_to_string()`.
pub fn color_mode_to_string(mode: ColorMode) -> Option<&'static str> {
    let idx = mode as i32;
    if idx >= 0 && (idx as usize) < COLOR_MODE_NAMES.len() {
        Some(COLOR_MODE_NAMES[idx as usize])
    } else {
        None
    }
}

// ── parse_systemd_colors ──────────────────────────────────────────────────

/// Read `$SYSTEMD_COLORS` and convert to `ColorMode`.
///
/// Returns `Ok(mode)` if the variable is set and parseable, `Err(EINVAL)` if
/// unset or unparseable.
pub fn parse_systemd_colors() -> Result<ColorMode, Errno> {
    match std::env::var("SYSTEMD_COLORS") {
        Ok(val) => color_mode_from_string(&val),
        Err(_) => Err(Errno::EINVAL),
    }
}

// ── get_color_mode ────────────────────────────────────────────────────────

/// Determine the colour mode from the process environment.
///
/// Checks `$SYSTEMD_COLORS` first, then `$NO_COLOR`, terminal dumb detection,
/// auto-mode resolution, and `$COLORTERM`.
///
/// Falls back to `C256` when no explicit setting is found.
/// Corresponds to `get_color_mode()` in ansi-color.c.
pub fn get_color_mode() -> ColorMode {
    // Check $SYSTEMD_COLORS first
    let m = parse_systemd_colors();

    if let Ok(mode) = m {
        let v = mode as i32;
        if v >= 0 && v < ColorMode::FIXED_MAX {
            return mode;
        }
    }

    // If not COLOR_TRUE, check NO_COLOR and dumb terminal
    if m != Ok(ColorMode::True) {
        if std::env::var("NO_COLOR").is_ok() {
            return ColorMode::Off;
        }

        // In the C version, getpid_cached() == 1 changes which dumb-check is used.
        // For the pure-Rust version we always check TERM for dumb.
        if is_dumb_terminal() {
            return ColorMode::Off;
        }
    }

    // Resolve auto modes
    if let Ok(mode) = m {
        match mode {
            ColorMode::Auto16 => return ColorMode::C16,
            ColorMode::Auto256 => return ColorMode::C256,
            ColorMode::Auto24bit => return ColorMode::C24bit,
            _ => {}
        }
    }

    // Check $COLORTERM for 24-bit support
    if let Ok(ct) = std::env::var("COLORTERM") {
        if ct == "truecolor" || ct == "24bit" {
            return ColorMode::C24bit;
        }
    }

    ColorMode::C256
}

/// Check if the terminal is "dumb" (no colour support).
fn is_dumb_terminal() -> bool {
    match std::env::var("TERM") {
        Ok(term) => term == "dumb" || term.is_empty(),
        Err(_) => true,
    }
}

// ── underline_enabled ─────────────────────────────────────────────────────

/// Check whether underlines should be used in output.
///
/// Underlines are enabled when colour is not off and `$TERM` is not `"linux"`.
/// Corresponds to `underline_enabled()` in ansi-color.c.
pub fn underline_enabled() -> bool {
    if get_color_mode() == ColorMode::Off {
        return false;
    }
    match std::env::var("TERM") {
        Ok(term) => term != "linux",
        Err(_) => false,
    }
}

// ── looks_like_ansi_color_code ────────────────────────────────────────────

/// Validate whether a string looks like an ANSI SGR parameter sequence.
///
/// Accepts strings matching `^[0-9]+(;[0-9]+)*$`.
/// Corresponds to `looks_like_ansi_color_code()` in ansi-color.c.
pub fn looks_like_ansi_color_code(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    let mut prev_was_digit = false;

    for b in s.bytes() {
        if b.is_ascii_digit() {
            prev_was_digit = true;
        } else if prev_was_digit && b == b';' {
            prev_was_digit = false;
        } else {
            return false;
        }
    }

    prev_was_digit
}

fn color_mode_from_bytes(bytes: &[u8]) -> i32 {
    if let Some((index, _)) = COLOR_MODE_NAMES
        .iter()
        .enumerate()
        .find(|(_, name)| bytes == name.as_bytes())
    {
        return index as i32;
    }

    let is = |value: &[u8]| bytes.eq_ignore_ascii_case(value);
    if [b"1".as_slice(), b"yes", b"y", b"true", b"t", b"on"]
        .iter()
        .any(|value| is(value))
    {
        return ColorMode::True as i32;
    }
    if [b"0".as_slice(), b"no", b"n", b"false", b"f", b"off"]
        .iter()
        .any(|value| is(value))
    {
        return ColorMode::Off as i32;
    }
    Errno::EINVAL.to_neg_errno()
}

/// C ABI facade for `color_mode_from_string()`.
///
/// # Safety
/// `s` must be null or a readable NUL-terminated C string for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_color_mode_from_string(s: *const c_char) -> i32 {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: the FFI caller promises a live NUL-terminated input string.
    color_mode_from_bytes(unsafe { CStr::from_ptr(s) }.to_bytes())
}

/// C ABI facade for `color_mode_to_string()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_color_mode_to_string(mode: i32) -> *const c_char {
    match mode {
        0 => c"off".as_ptr(),
        1 => c"16".as_ptr(),
        2 => c"256".as_ptr(),
        3 => c"24bit".as_ptr(),
        4 => c"auto-16".as_ptr(),
        5 => c"auto-256".as_ptr(),
        6 => c"auto-24bit".as_ptr(),
        7 => c"true".as_ptr(),
        _ => std::ptr::null(),
    }
}

/// C ABI facade for `parse_systemd_colors()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_parse_systemd_colors() -> i32 {
    match parse_systemd_colors() {
        Ok(mode) => mode as i32,
        Err(error) => error.to_neg_errno(),
    }
}

/// C ABI facade for `looks_like_ansi_color_code()`.
///
/// # Safety
/// `str_` must be null or a readable NUL-terminated C string for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_looks_like_ansi_color_code(str_: *const c_char) -> bool {
    if str_.is_null() {
        return false;
    }
    // SAFETY: the FFI caller promises a live NUL-terminated input string.
    let bytes = unsafe { CStr::from_ptr(str_) }.to_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut previous_was_digit = false;
    for byte in bytes {
        if byte.is_ascii_digit() {
            previous_was_digit = true;
        } else if previous_was_digit && *byte == b';' {
            previous_was_digit = false;
        } else {
            return false;
        }
    }
    previous_was_digit
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── color_mode_from_string ─────────────────────────────────────────

    #[test]
    fn test_color_mode_from_string_valid() {
        assert_eq!(color_mode_from_string("off"), Ok(ColorMode::Off));
        assert_eq!(color_mode_from_string("16"), Ok(ColorMode::C16));
        assert_eq!(color_mode_from_string("256"), Ok(ColorMode::C256));
        assert_eq!(color_mode_from_string("24bit"), Ok(ColorMode::C24bit));
        assert_eq!(color_mode_from_string("auto-16"), Ok(ColorMode::Auto16));
        assert_eq!(color_mode_from_string("auto-256"), Ok(ColorMode::Auto256));
        assert_eq!(
            color_mode_from_string("auto-24bit"),
            Ok(ColorMode::Auto24bit)
        );
        assert_eq!(color_mode_from_string("true"), Ok(ColorMode::True));
    }

    #[test]
    fn test_color_mode_from_string_boolean() {
        assert_eq!(color_mode_from_string("yes"), Ok(ColorMode::True));
        assert_eq!(color_mode_from_string("no"), Ok(ColorMode::Off));
        assert_eq!(color_mode_from_string("1"), Ok(ColorMode::True));
        assert_eq!(color_mode_from_string("0"), Ok(ColorMode::Off));
    }

    #[test]
    fn test_color_mode_from_string_invalid() {
        assert_eq!(color_mode_from_string("foobar"), Err(Errno::EINVAL));
        assert_eq!(color_mode_from_string(""), Err(Errno::EINVAL));
        assert_eq!(color_mode_from_string("maybe"), Err(Errno::EINVAL));
    }

    // ── color_mode_to_string ───────────────────────────────────────────

    #[test]
    fn test_color_mode_to_string_valid() {
        assert_eq!(color_mode_to_string(ColorMode::Off), Some("off"));
        assert_eq!(color_mode_to_string(ColorMode::C256), Some("256"));
        assert_eq!(color_mode_to_string(ColorMode::True), Some("true"));
        assert_eq!(color_mode_to_string(ColorMode::C24bit), Some("24bit"));
    }

    #[test]
    fn test_roundtrip() {
        for i in 0..ColorMode::FIXED_MAX {
            let mode = ColorMode::from_i32(i).unwrap();
            let s = color_mode_to_string(mode).unwrap();
            assert_eq!(color_mode_from_string(s), Ok(mode));
        }
    }

    // ── looks_like_ansi_color_code ─────────────────────────────────────

    #[test]
    fn test_ansi_color_code_valid() {
        assert!(looks_like_ansi_color_code("0"));
        assert!(looks_like_ansi_color_code("1"));
        assert!(looks_like_ansi_color_code("31"));
        assert!(looks_like_ansi_color_code("1;31"));
        assert!(looks_like_ansi_color_code("0;1;31;42"));
        assert!(looks_like_ansi_color_code("38;5;255"));
    }

    #[test]
    fn test_ansi_color_code_invalid() {
        assert!(!looks_like_ansi_color_code(""));
        assert!(!looks_like_ansi_color_code(";1"));
        assert!(!looks_like_ansi_color_code("1;"));
        assert!(!looks_like_ansi_color_code("abc"));
        assert!(!looks_like_ansi_color_code("1a"));
        assert!(!looks_like_ansi_color_code("1;;2"));
        assert!(!looks_like_ansi_color_code("-1"));
    }

    #[test]
    fn test_ansi_color_code_single_values() {
        assert!(looks_like_ansi_color_code("7"));
        assert!(looks_like_ansi_color_code("33"));
        assert!(looks_like_ansi_color_code("44"));
        assert!(!looks_like_ansi_color_code(" 44"));
        assert!(!looks_like_ansi_color_code("44 "));
    }

    #[test]
    fn test_ansi_color_code_complex_valid() {
        assert!(looks_like_ansi_color_code("38;2;255;128;0"));
        assert!(looks_like_ansi_color_code("48;5;196"));
        assert!(looks_like_ansi_color_code("1;38;5;220;4"));
    }

    // ── parse_boolean ──────────────────────────────────────────────────

    #[test]
    fn test_parse_boolean_true() {
        assert_eq!(parse_boolean("1"), Some(true));
        assert_eq!(parse_boolean("yes"), Some(true));
        assert_eq!(parse_boolean("true"), Some(true));
        assert_eq!(parse_boolean("on"), Some(true));
    }

    #[test]
    fn test_parse_boolean_false() {
        assert_eq!(parse_boolean("0"), Some(false));
        assert_eq!(parse_boolean("no"), Some(false));
        assert_eq!(parse_boolean("false"), Some(false));
        assert_eq!(parse_boolean("off"), Some(false));
    }

    #[test]
    fn test_parse_boolean_unknown() {
        assert_eq!(parse_boolean(""), None);
        assert_eq!(parse_boolean("maybe"), None);
        assert_eq!(parse_boolean("YES"), None);
    }

    // ── ColorMode::from_i32 ────────────────────────────────────────────

    #[test]
    fn test_color_mode_from_i32() {
        assert_eq!(ColorMode::from_i32(0), Some(ColorMode::Off));
        assert_eq!(ColorMode::from_i32(7), Some(ColorMode::True));
        assert_eq!(ColorMode::from_i32(-1), None);
        assert_eq!(ColorMode::from_i32(8), None);
        assert_eq!(ColorMode::from_i32(100), None);
    }
}
