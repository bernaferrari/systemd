// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.glyph-util; authority=src/basic/glyph-util.c,src/basic/glyph-util.h,src/basic/locale-util.c,src/basic/locale-util.h
//
// Unicode glyph lookup table for systemd output decoration.
// The narrow libc boundary mirrors C's cached locale-selection policy.

use std::ffi::{CStr, c_char};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicI32, Ordering};

// ── Constants ──────────────────────────────────────────────────────────────

const GLYPH_MAX: usize = 59;
const GLYPH_FIRST_EMOJI: usize = 28;

// ── Lookup tables ──────────────────────────────────────────────────────────

static ASCII_TABLE: &[&CStr] = &[
    c" ",     // 0
    c"| ",    // 1
    c"|-",    // 2
    c"`-",    // 3
    c"  ",    // 4
    c",-",    // 5
    c":",     // 6
    c"-",     // 7
    c"=",     // 8
    c">",     // 9
    c"*",     // 10
    c"*",     // 11
    c"x",     // 12
    c"*",     // 13
    c"*",     // 14
    c"u",     // 15
    c"+",     // 16
    c"-",     // 17
    c"-",     // 18
    c"X",     // 19
    c"#",     // 20
    c"S",     // 21
    c"^",     // 22
    c"v",     // 23
    c"<-",    // 24
    c"->",    // 25
    c"...",   // 26
    c"[LNK]", // 27
    c":-]",   // 28
    c":-}",   // 29
    c":-)",   // 30
    c":-|",   // 31
    c":-(",   // 32
    c":-{",   // 33
    c":-[",   // 34
    c"o-,",   // 35
    c"O=",    // 36
    c"~",     // 37
    c"\\",    // 38
    c"*",     // 39
    c"!",     // 40
    c"!",     // 41
    c"o",     // 42
    c"W",     // 43
    c"o",     // 44
    c"o",     // 45
    c"o",     // 46
    c"o",     // 47
    c"o",     // 48
    c"S",     // 49
    c"P",     // 50
    c"@",     // 51
    c"^",     // 52
    c"^",     // 53
    c"/",     // 54
    c"K",     // 55
    c"O",     // 56
    c"L",     // 57
    c"$",     // 58
];

static UTF8_TABLE: &[&CStr] = &[
    c" ",                 // 0
    c"\u{2502} ",         // 1 │
    c"\u{251C}\u{2500}",  // 2 ├─
    c"\u{2514}\u{2500}",  // 3 └─
    c"  ",                // 4
    c"\u{250C}\u{2500}",  // 5 ┌─
    c"\u{2506}",          // 6 ┆
    c"\u{2504}",          // 7 ┄
    c"\u{2501}",          // 8 ━
    c"\u{2023}",          // 9 ‣
    c"\u{25CF}",          // 10 ●
    c"\u{25CB}",          // 11 ○
    c"\u{00D7}",          // 12 ×
    c"\u{21BB}",          // 13 ↻
    c"\u{2022}",          // 14 •
    c"\u{03BC}",          // 15 μ
    c"\u{2713}",          // 16 ✓
    c"\u{2717}",          // 17 ✗
    c"\u{2591}",          // 18 ░
    c"\u{2592}",          // 19 ▒
    c"\u{2588}",          // 20 █
    c"\u{03A3}",          // 21 Σ
    c"\u{2191}",          // 22 ↑
    c"\u{2193}",          // 23 ↓
    c"\u{2190}",          // 24 ←
    c"\u{2192}",          // 25 →
    c"\u{2026}",          // 26 …
    c"[\u{1F855}]",       // 27 [🡕]
    c"\u{1F607}",         // 28 😇
    c"\u{1F600}",         // 29 😀
    c"\u{1F642}",         // 30 🙂
    c"\u{1F610}",         // 31 😐
    c"\u{1F641}",         // 32 🙁
    c"\u{1F628}",         // 33 😨
    c"\u{1F922}",         // 34 🤢
    c"\u{1F510}",         // 35 🔐
    c"\u{1F446}",         // 36 👆
    c"\u{267B}\u{FE0F}",  // 37 ♻️
    c"\u{2935}\u{FE0F}",  // 38 ⤵️
    c"\u{2728}",          // 39 ✨
    c"\u{1FAAB}",         // 40 🪫
    c"\u{26A0}\u{FE0F}",  // 41 ⚠️
    c"\u{1F4BD}",         // 42 💽
    c"\u{1F30D}",         // 43 🌍
    c"\u{1F534}",         // 44 🔴
    c"\u{1F7E0}",         // 45 🟠
    c"\u{1F7E1}",         // 46 🟡
    c"\u{1F535}",         // 47 🔵
    c"\u{1F7E2}",         // 48 🟢
    c"\u{1F9B8}",         // 49 🦸
    c"\u{1F383}",         // 50 🎃
    c"\u{1FAAA}",         // 51 🪪
    c"\u{1F3E0}",         // 52 🏠
    c"\u{1F680}",         // 53 🚀
    c"\u{1F9F9}",         // 54 🧹
    c"\u{2328}\u{FE0F}",  // 55 ⌨️
    c"\u{1F557}",         // 56 🕗
    c"\u{1F3F7}\u{FE0F}", // 57 🏷️
    c"\u{1F41A}",         // 58 🐚
];

// ── Environment helpers ────────────────────────────────────────────────────

/// Parse the byte grammar accepted by C `parse_boolean()`.
///
/// C's environment is byte-oriented, so keeping this helper byte-oriented
/// preserves the behavior for non-UTF-8 values: they are simply invalid.
fn parse_env_bool_bytes(value: &[u8]) -> Option<bool> {
    const TRUE_VALUES: [&[u8]; 6] = [b"1", b"yes", b"y", b"true", b"t", b"on"];
    const FALSE_VALUES: [&[u8]; 6] = [b"0", b"no", b"n", b"false", b"f", b"off"];

    if TRUE_VALUES
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
    {
        Some(true)
    } else if FALSE_VALUES
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
    {
        Some(false)
    } else {
        None
    }
}

/// Parse a boolean env-var value.
/// Returns `Some(true/false)` for known values, `None` for unset or invalid.
pub fn parse_env_bool(value: &str) -> Option<bool> {
    parse_env_bool_bytes(value.as_bytes())
}

fn environment_bytes(name: &str) -> Option<Vec<u8>> {
    std::env::var_os(name).map(|value| value.as_bytes().to_vec())
}

/// Mirror glibc's `secure_getenv()` policy used by C systemd.
fn secure_environment_bytes(name: &str) -> Option<Vec<u8>> {
    // SAFETY: getauxval() takes no pointers and transfers no ownership.
    (unsafe { libc::getauxval(libc::AT_SECURE) } == 0)
        .then(|| environment_bytes(name))
        .flatten()
}

fn current_thread_is_main_thread() -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let pid = std::process::id() as libc::pid_t;
        // SAFETY: gettid() takes no pointers and has no ownership contract.
        let tid = unsafe { libc::gettid() };
        return pid == tid;
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        // SAFETY: pthread_main_np() takes no pointers and has no ownership contract.
        return unsafe { libc::pthread_main_np() == 1 };
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        true
    }
}

fn locale_utf8_uncached() -> bool {
    if let Some(value) = secure_environment_bytes("SYSTEMD_UTF8") {
        if let Some(enabled) = parse_env_bool_bytes(&value) {
            return enabled;
        }
    }

    // This is the same guard C uses before calling the process-global,
    // thread-unsafe setlocale(). In a non-main thread it deliberately assumes
    // UTF-8 rather than changing global locale state.
    if !current_thread_is_main_thread() {
        return true;
    }

    // SAFETY: this reproduces C's guarded, one-time setlocale()/nl_langinfo()
    // lookup. The result is copied immediately and no C pointer escapes.
    unsafe {
        if libc::setlocale(libc::LC_ALL, c"".as_ptr()).is_null() {
            return true;
        }

        let charset = libc::nl_langinfo(libc::CODESET);
        if charset.is_null() || CStr::from_ptr(charset).to_bytes() == b"UTF-8" {
            return true;
        }

        let locale = libc::setlocale(libc::LC_CTYPE, std::ptr::null());
        if locale.is_null() {
            return true;
        }

        let locale = CStr::from_ptr(locale).to_bytes();
        (locale == b"C" || locale == b"POSIX")
            && std::env::var_os("LC_ALL").is_none()
            && std::env::var_os("LC_CTYPE").is_none()
            && std::env::var_os("LANG").is_none()
    }
}

static CACHED_LOCALE_UTF8: AtomicI32 = AtomicI32::new(-1);

/// C-compatible, cached `is_locale_utf8()` selection used by `glyph_full()`.
pub fn is_locale_utf8() -> bool {
    let cached = CACHED_LOCALE_UTF8.load(Ordering::Relaxed);
    if cached >= 0 {
        return cached != 0;
    }

    let enabled = locale_utf8_uncached();
    CACHED_LOCALE_UTF8.store(i32::from(enabled), Ordering::Relaxed);
    enabled
}

static CACHED_EMOJI: AtomicI32 = AtomicI32::new(-1);

/// Check if emoji output is enabled, mirroring C `emoji_enabled()`.
/// Uses atomic caching just like the C static-local pattern.
pub fn emoji_enabled() -> bool {
    let cached = CACHED_EMOJI.load(Ordering::Relaxed);
    if cached >= 0 {
        return cached != 0;
    }

    // C uses getenv_bool() here (rather than secure_getenv_bool()), so retain
    // that deliberately different policy from SYSTEMD_UTF8 above.
    if let Some(value) = environment_bytes("SYSTEMD_EMOJI") {
        if let Some(b) = parse_env_bool_bytes(&value) {
            CACHED_EMOJI.store(if b { 1 } else { 0 }, Ordering::Relaxed);
            return b;
        }
    }

    match environment_bytes("TERM").as_deref() {
        None => {
            CACHED_EMOJI.store(0, Ordering::Relaxed);
            false
        }
        Some(term) if term == b"dumb" || term == b"linux" => {
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
///
/// The C authority treats a non-negative `Glyph` outside `_GLYPH_MAX` as a
/// caller-contract violation (it asserts before indexing its static table).
/// The safe Rust helper exposes that as `None`; the C facade below keeps the
/// original assertion for callers using the C ABI.
fn glyph_full_cstr(code: i32, force_utf: bool) -> Option<&'static CStr> {
    if code < 0 || code as usize >= GLYPH_MAX {
        return None;
    }

    let idx = code as usize;
    let use_utf8 = force_utf
        || if idx >= GLYPH_FIRST_EMOJI {
            emoji_enabled()
        } else {
            is_locale_utf8()
        };

    let table = if use_utf8 { &UTF8_TABLE } else { &ASCII_TABLE };
    Some(table[idx])
}

/// Safe view of C `glyph_full()` for a checked numeric glyph code.
pub fn glyph_full(code: i32, force_utf: bool) -> Option<&'static str> {
    glyph_full_cstr(code, force_utf).map(|glyph| {
        glyph
            .to_str()
            .expect("glyph tables contain only valid UTF-8 literals")
    })
}

/// C ABI facade for `glyph_full()`.
///
/// The returned pointer is borrowed immutable process-lifetime storage and
/// must not be freed or written through. Negative values return NULL. As in C,
/// every non-negative input must be a valid `Glyph` value below `_GLYPH_MAX`;
/// invalid positive values violate the caller contract and trigger an assert.
#[unsafe(no_mangle)]
pub extern "C" fn rs_glyph_full(code: libc::c_int, force_utf: bool) -> *const c_char {
    if code < 0 {
        return std::ptr::null();
    }

    assert!((code as usize) < GLYPH_MAX);

    glyph_full_cstr(code, force_utf)
        .expect("a C-validated glyph code must have a table entry")
        .as_ptr()
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
        assert_eq!(ASCII_TABLE[1].to_str(), Ok("| "));
        assert_eq!(ASCII_TABLE[2].to_str(), Ok("|-"));
        assert_eq!(ASCII_TABLE[3].to_str(), Ok("`-"));
    }

    #[test]
    fn test_glyph_full_ascii_check_mark() {
        assert_eq!(ASCII_TABLE[16].to_str(), Ok("+"));
    }

    #[test]
    fn test_glyph_full_ascii_cross_mark() {
        assert_eq!(ASCII_TABLE[17].to_str(), Ok("-"));
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
        assert_eq!(ASCII_TABLE[58].to_str(), Ok("$"));
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
        assert_eq!(ASCII_TABLE[30].to_str(), Ok(":-)"));
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
        assert_eq!(ASCII_TABLE[27].to_str(), Ok("[LNK]"));
    }
}
