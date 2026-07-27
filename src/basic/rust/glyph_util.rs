// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/glyph-util.c
//
// Unicode glyph lookup table for systemd output decoration.
// Pure Rust — environment checks use std::env.

use std::sync::atomic::{AtomicI32, Ordering};

// ── Constants ──────────────────────────────────────────────────────────────

const GLYPH_MAX: usize = 59;
const GLYPH_FIRST_EMOJI: usize = 28;

// ── Lookup tables ──────────────────────────────────────────────────────────

static ASCII_TABLE: &[&str] = &[
    " ",     // 0
    "| ",    // 1
    "|-",    // 2
    "`-",    // 3
    "  ",    // 4
    ",-",    // 5
    ":",     // 6
    "-",     // 7
    "=",     // 8
    ">",     // 9
    "*",     // 10
    "*",     // 11
    "x",     // 12
    "*",     // 13
    "*",     // 14
    "u",     // 15
    "+",     // 16
    "-",     // 17
    "-",     // 18
    "X",     // 19
    "#",     // 20
    "S",     // 21
    "^",     // 22
    "v",     // 23
    "<-",    // 24
    "->",    // 25
    "...",   // 26
    "[LNK]", // 27
    ":-]",   // 28
    ":-}",   // 29
    ":-)",   // 30
    ":-|",   // 31
    ":-(",   // 32
    ":-{",   // 33
    ":-[",   // 34
    "o-,",   // 35
    "O=",    // 36
    "~",     // 37
    "\\",    // 38
    "*",     // 39
    "!",     // 40
    "!",     // 41
    "o",     // 42
    "W",     // 43
    "o",     // 44
    "o",     // 45
    "o",     // 46
    "o",     // 47
    "o",     // 48
    "S",     // 49
    "P",     // 50
    "@",     // 51
    "^",     // 52
    "^",     // 53
    "/",     // 54
    "K",     // 55
    "O",     // 56
    "L",     // 57
    "$",     // 58
];

static UTF8_TABLE: &[&str] = &[
    " ",                 // 0
    "\u{2502} ",         // 1 │
    "\u{251C}\u{2500}",  // 2 ├─
    "\u{2514}\u{2500}",  // 3 └─
    "  ",                // 4
    "\u{250C}\u{2500}",  // 5 ┌─
    "\u{2506}",          // 6 ┆
    "\u{2504}",          // 7 ┄
    "\u{2501}",          // 8 ━
    "\u{2023}",          // 9 ‣
    "\u{25CF}",          // 10 ●
    "\u{25CB}",          // 11 ○
    "\u{00D7}",          // 12 ×
    "\u{21BB}",          // 13 ↻
    "\u{2022}",          // 14 •
    "\u{03BC}",          // 15 μ
    "\u{2713}",          // 16 ✓
    "\u{2717}",          // 17 ✗
    "\u{2591}",          // 18 ░
    "\u{2592}",          // 19 ▒
    "\u{2588}",          // 20 █
    "\u{03A3}",          // 21 Σ
    "\u{2191}",          // 22 ↑
    "\u{2193}",          // 23 ↓
    "\u{2190}",          // 24 ←
    "\u{2192}",          // 25 →
    "\u{2026}",          // 26 …
    "[\u{1F855}]",       // 27 [🡕]
    "\u{1F607}",         // 28 😇
    "\u{1F600}",         // 29 😀
    "\u{1F642}",         // 30 🙂
    "\u{1F610}",         // 31 😐
    "\u{1F641}",         // 32 🙁
    "\u{1F628}",         // 33 😨
    "\u{1F922}",         // 34 🤢
    "\u{1F510}",         // 35 🔐
    "\u{1F446}",         // 36 👆
    "\u{267B}\u{FE0F}",  // 37 ♻️
    "\u{2935}\u{FE0F}",  // 38 ⤵️
    "\u{2728}",          // 39 ✨
    "\u{1FAAB}",         // 40 🪫
    "\u{26A0}\u{FE0F}",  // 41 ⚠️
    "\u{1F4BD}",         // 42 💽
    "\u{1F30D}",         // 43 🌍
    "\u{1F534}",         // 44 🔴
    "\u{1F7E0}",         // 45 🟠
    "\u{1F7E1}",         // 46 🟡
    "\u{1F535}",         // 47 🔵
    "\u{1F7E2}",         // 48 🟢
    "\u{1F9B8}",         // 49 🦸
    "\u{1F383}",         // 50 🎃
    "\u{1FAAA}",         // 51 🪪
    "\u{1F3E0}",         // 52 🏠
    "\u{1F680}",         // 53 🚀
    "\u{1F9F9}",         // 54 🧹
    "\u{2328}\u{FE0F}",  // 55 ⌨️
    "\u{1F557}",         // 56 🕗
    "\u{1F3F7}\u{FE0F}", // 57 🏷️
    "\u{1F41A}",         // 58 🐚
];

// ── Environment helpers ────────────────────────────────────────────────────

/// Parse a boolean env-var value.
/// Returns `Some(true/false)` for known values, `None` for unset or invalid.
pub fn parse_env_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "true" | "yes" | "on" | "True" | "Yes" | "TRUE" | "YES" | "ON" => Some(true),
        "0" | "false" | "no" | "off" | "False" | "No" | "FALSE" | "NO" | "OFF" => Some(false),
        _ => None,
    }
}

/// Check if the locale charset is UTF-8 by inspecting LC_ALL, LC_CTYPE, LANG.
pub fn is_locale_utf8() -> bool {
    let charset = std::env::var("LC_ALL")
        .or_else(|_| std::env::var("LC_CTYPE"))
        .or_else(|_| std::env::var("LANG"))
        .unwrap_or_default();
    let lower = charset.to_lowercase();
    lower.contains("utf-8") || lower.contains("utf8")
}

static CACHED_EMOJI: AtomicI32 = AtomicI32::new(-1);

/// Check if emoji output is enabled, mirroring C `emoji_enabled()`.
/// Uses atomic caching just like the C static-local pattern.
pub fn emoji_enabled() -> bool {
    let cached = CACHED_EMOJI.load(Ordering::Relaxed);
    if cached >= 0 {
        return cached != 0;
    }

    if let Ok(val) = std::env::var("SYSTEMD_EMOJI") {
        if let Some(b) = parse_env_bool(&val) {
            CACHED_EMOJI.store(if b { 1 } else { 0 }, Ordering::Relaxed);
            return b;
        }
    }

    let term = std::env::var("TERM").ok();
    match term.as_deref() {
        None | Some("dumb") | Some("linux") => {
            CACHED_EMOJI.store(0, Ordering::Relaxed);
            false
        }
        _ => {
            let utf8 = is_locale_utf8();
            CACHED_EMOJI.store(if utf8 { 1 } else { 0 }, Ordering::Relaxed);
            utf8
        }
    }
}

/// Reset the cached emoji state (for testing).
pub fn reset_emoji_cache() {
    CACHED_EMOJI.store(-1, Ordering::Relaxed);
}

// ── glyph_full ─────────────────────────────────────────────────────────────

/// Look up a glyph string by numeric code and UTF-8 preference.
/// Mirrors C `glyph_full()`.
/// Returns `None` for out-of-range codes.
pub fn glyph_full(code: i32, force_utf: bool) -> Option<&'static str> {
    if code < 0 || code as usize >= GLYPH_MAX {
        return None;
    }

    let idx = code as usize;
    let use_utf8 = force_utf;

    let table = if use_utf8 { &UTF8_TABLE } else { &ASCII_TABLE };
    Some(table[idx])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glyph_full_ascii_space() {
        assert_eq!(glyph_full(0, false), Some(" "));
    }

    #[test]
    fn test_glyph_full_ascii_tree_chars() {
        assert_eq!(glyph_full(1, false), Some("| "));
        assert_eq!(glyph_full(2, false), Some("|-"));
        assert_eq!(glyph_full(3, false), Some("`-"));
    }

    #[test]
    fn test_glyph_full_ascii_check_mark() {
        assert_eq!(glyph_full(16, false), Some("+"));
    }

    #[test]
    fn test_glyph_full_ascii_cross_mark() {
        assert_eq!(glyph_full(17, false), Some("-"));
    }

    #[test]
    fn test_glyph_full_utf8_space() {
        assert_eq!(glyph_full(0, true), Some(" "));
    }

    #[test]
    fn test_glyph_full_utf8_tree_chars() {
        assert_eq!(glyph_full(1, true), Some("\u{2502} "));
        assert_eq!(glyph_full(2, true), Some("\u{251C}\u{2500}"));
        assert_eq!(glyph_full(3, true), Some("\u{2514}\u{2500}"));
    }

    #[test]
    fn test_glyph_full_utf8_check_mark() {
        assert_eq!(glyph_full(16, true), Some("\u{2713}"));
    }

    #[test]
    fn test_glyph_full_utf8_cross_mark() {
        assert_eq!(glyph_full(17, true), Some("\u{2717}"));
    }

    #[test]
    fn test_glyph_full_utf8_ellipsis() {
        assert_eq!(glyph_full(26, true), Some("\u{2026}"));
    }

    #[test]
    fn test_glyph_full_utf8_arrows() {
        assert_eq!(glyph_full(22, true), Some("\u{2191}"));
        assert_eq!(glyph_full(23, true), Some("\u{2193}"));
        assert_eq!(glyph_full(24, true), Some("\u{2190}"));
        assert_eq!(glyph_full(25, true), Some("\u{2192}"));
    }

    #[test]
    fn test_glyph_full_negative_code() {
        assert_eq!(glyph_full(-1, false), None);
        assert_eq!(glyph_full(-100, true), None);
    }

    #[test]
    fn test_glyph_full_out_of_range_code() {
        assert_eq!(glyph_full(59, false), None);
        assert_eq!(glyph_full(1000, true), None);
    }

    #[test]
    fn test_glyph_full_boundary_last_valid() {
        assert_eq!(glyph_full(58, true), Some("\u{1F41A}"));
        assert_eq!(glyph_full(58, false), Some("$"));
    }

    #[test]
    fn test_glyph_full_all_ascii_entries_exist() {
        for i in 0..GLYPH_MAX {
            assert!(
                glyph_full(i as i32, false).is_some(),
                "missing ascii entry {i}"
            );
        }
    }

    #[test]
    fn test_glyph_full_all_utf8_entries_exist() {
        for i in 0..GLYPH_MAX {
            assert!(
                glyph_full(i as i32, true).is_some(),
                "missing utf8 entry {i}"
            );
        }
    }

    #[test]
    fn test_parse_env_bool_true_values() {
        for v in &["1", "true", "yes", "on", "True", "Yes", "TRUE", "YES", "ON"] {
            assert_eq!(parse_env_bool(v), Some(true), "expected true for {v}");
        }
    }

    #[test]
    fn test_parse_env_bool_false_values() {
        for v in &[
            "0", "false", "no", "off", "False", "No", "FALSE", "NO", "OFF",
        ] {
            assert_eq!(parse_env_bool(v), Some(false), "expected false for {v}");
        }
    }

    #[test]
    fn test_parse_env_bool_invalid_values() {
        assert_eq!(parse_env_bool("maybe"), None);
        assert_eq!(parse_env_bool("2"), None);
        assert_eq!(parse_env_bool(""), None);
    }

    #[test]
    fn test_glyph_full_utf8_emoji_range() {
        assert_eq!(glyph_full(28, true), Some("\u{1F607}"));
        assert_eq!(glyph_full(29, true), Some("\u{1F600}"));
        assert_eq!(glyph_full(30, true), Some("\u{1F642}"));
    }

    #[test]
    fn test_glyph_full_ascii_smiley() {
        assert_eq!(glyph_full(30, false), Some(":-)"));
    }

    #[test]
    fn test_glyph_full_utf8_tree_top() {
        assert_eq!(glyph_full(5, true), Some("\u{250C}\u{2500}"));
    }

    #[test]
    fn test_glyph_full_utf8_horizontal_dotted() {
        assert_eq!(glyph_full(7, true), Some("\u{2504}"));
    }

    #[test]
    fn test_glyph_full_utf8_horizontal_fat() {
        assert_eq!(glyph_full(8, true), Some("\u{2501}"));
    }

    #[test]
    fn test_glyph_full_ascii_external_link() {
        assert_eq!(glyph_full(27, false), Some("[LNK]"));
    }
}
