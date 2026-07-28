// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=shared.hostname-setup; authority=src/shared/hostname-setup.c,src/shared/hostname-setup.h,src/basic/hostname-util.c,src/basic/hostname-util.h
//
// Hostname setup pure functions and the narrow C ABI used by shadow tests.

use std::ffi::CStr;

use libc::c_char;

use crate::ffi::Errno;

// ── Constants ──────────────────────────────────────────────────────────────

const LINUX_HOST_NAME_MAX: usize = 64;

// ── Result / Error types ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShortenResult {
    AlreadyValid(String),
    Shortened(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostnameSetupError {
    CannotShorten,
}

impl std::fmt::Display for HostnameSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostnameSetupError::CannotShorten => write!(f, "hostname invalid after truncation"),
        }
    }
}

impl std::error::Error for HostnameSetupError {}

// ── Internal helpers ──────────────────────────────────────────────────────

/// LDH = Letters, Digits, Hyphens (RFC 5890, Section 2.3.1)
fn valid_ldh_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-'
}

/// Hostname validation with flags=0.
///
/// Mirrors C `hostname_is_valid(s, 0)`:
/// - Not empty, not ".host"
/// - Only LDH characters (no '?' without flag)
/// - No leading dot or hyphen, no trailing dot or hyphen
/// - No consecutive dots or dots after hyphens
/// - Length <= LINUX_HOST_NAME_MAX (64)
fn hostname_is_valid(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    if s == ".host" {
        return false;
    }

    let mut dot = true;
    let mut hyphen = true;

    for &byte in s.as_bytes() {
        if byte == b'.' {
            if dot || hyphen {
                return false;
            }
            dot = true;
            hyphen = false;
        } else if byte == b'-' {
            if dot {
                return false;
            }
            dot = false;
            hyphen = true;
        } else {
            if !valid_ldh_char(byte) {
                return false;
            }
            dot = false;
            hyphen = false;
        }
    }

    if dot {
        return false;
    }
    if hyphen {
        return false;
    }

    s.len() <= LINUX_HOST_NAME_MAX
}

// ── Public API ────────────────────────────────────────────────────────────

/// Shorten an overlong hostname to LINUX_HOST_NAME_MAX or to the first dot,
/// whichever comes earlier.
///
/// Mirrors C `shorten_overlong()`:
/// - Returns `AlreadyValid` if the name was already a valid hostname
/// - Returns `Shortened` if truncated at the first dot or at max length
/// - Returns error if the hostname cannot be made valid
pub fn shorten_overlong(s: &str) -> Result<ShortenResult, HostnameSetupError> {
    if hostname_is_valid(s) {
        return Ok(ShortenResult::AlreadyValid(s.to_string()));
    }

    let after_dot_truncation = match s.find('.') {
        Some(pos) => &s[..pos],
        None => s,
    };

    let truncated = if after_dot_truncation.len() > LINUX_HOST_NAME_MAX {
        &after_dot_truncation[..LINUX_HOST_NAME_MAX]
    } else {
        after_dot_truncation
    };

    if !hostname_is_valid(truncated) {
        return Err(HostnameSetupError::CannotShorten);
    }

    Ok(ShortenResult::Shortened(truncated.to_string()))
}

/// Byte-oriented `hostname_is_valid(s, 0)` for the C ABI facade.
///
/// Host names admitted with zero flags are ASCII-only, so a byte core both
/// avoids lossy UTF-8 conversion and matches the C parser's rejection of any
/// non-ASCII byte before an allocation can be published.
fn hostname_is_valid_zero_flags(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes == b".host" {
        return false;
    }

    let mut dot = true;
    let mut hyphen = true;
    for &byte in bytes {
        match byte {
            b'.' => {
                if dot || hyphen {
                    return false;
                }
                dot = true;
                hyphen = false;
            }
            b'-' => {
                if dot {
                    return false;
                }
                dot = false;
                hyphen = true;
            }
            _ if valid_ldh_char(byte) => {
                dot = false;
                hyphen = false;
            }
            _ => return false,
        }
    }

    !hyphen && !dot && bytes.len() <= LINUX_HOST_NAME_MAX
}

/// C ABI facade for `shorten_overlong()`.
///
/// A successful result is allocated with the process C allocator and written
/// to `*ret` only after both hostname validation and allocation succeed. The
/// return is `0` for an already-valid hostname, `1` when shortening occurred,
/// or a negative errno on failure.
///
/// # Safety
///
/// `s` must point to a readable NUL-terminated C string and `ret` must point
/// to writable pointer storage for the duration of the call. On success the
/// caller owns `*ret` and releases it with `free(3)`; on error it is unchanged.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_shorten_overlong(s: *const c_char, ret: *mut *mut c_char) -> i32 {
    if s.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // C allocates first, before deciding whether the original is valid. Keep
    // that order so an allocator failure remains `-ENOMEM`, even for malformed
    // input, and so both successful paths publish the same C-owned allocation.
    // SAFETY: `s` satisfies the documented live NUL-terminated input contract.
    let allocated = unsafe { libc::strdup(s) };
    if allocated.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: `strdup()` returned a live NUL-terminated C allocation.
    let bytes = unsafe { CStr::from_ptr(allocated) }.to_bytes();
    if hostname_is_valid_zero_flags(bytes) {
        // SAFETY: `ret` was validated non-null and the caller guarantees
        // writable pointer storage; publication follows C's successful path.
        unsafe { *ret = allocated };
        return 0;
    }

    let first_label = bytes
        .iter()
        .position(|&byte| byte == b'.')
        .map_or(bytes, |offset| &bytes[..offset]);
    let shortened = &first_label[..first_label.len().min(LINUX_HOST_NAME_MAX)];
    let shortened_len = shortened.len();
    if !hostname_is_valid_zero_flags(shortened) {
        // SAFETY: `allocated` is exactly the live C allocation returned by
        // strdup() above and has not been published.
        unsafe { libc::free(allocated.cast()) };
        return Errno::EDOM.to_neg_errno();
    }

    // SAFETY: `shortened_len` is inside the allocated C string (or at its
    // original NUL terminator), so this is C's in-place dot/truncation write.
    unsafe { *allocated.cast::<u8>().add(shortened_len) = 0 };
    // SAFETY: `ret` was validated non-null and the caller guarantees writable
    // pointer storage; publication happens only after a successful allocation.
    unsafe { *ret = allocated };
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── hostname_is_valid tests ─────────────────────────────────────────

    #[test]
    fn test_hostname_valid_simple() {
        assert!(hostname_is_valid("localhost"));
        assert!(hostname_is_valid("my-host"));
        assert!(hostname_is_valid("my.host.example"));
    }

    #[test]
    fn test_hostname_valid_fqdn() {
        assert!(hostname_is_valid("host.example.com"));
        assert!(hostname_is_valid("a.b.c"));
    }

    #[test]
    fn test_hostname_valid_empty() {
        assert!(!hostname_is_valid(""));
    }

    #[test]
    fn test_hostname_valid_leading_dot() {
        assert!(!hostname_is_valid(".example"));
    }

    #[test]
    fn test_hostname_valid_leading_hyphen() {
        assert!(!hostname_is_valid("-host"));
    }

    #[test]
    fn test_hostname_valid_trailing_hyphen() {
        assert!(!hostname_is_valid("host-"));
    }

    #[test]
    fn test_hostname_valid_trailing_dot() {
        assert!(!hostname_is_valid("host."));
    }

    #[test]
    fn test_hostname_valid_consecutive_dots() {
        assert!(!hostname_is_valid("host..name"));
    }

    #[test]
    fn test_hostname_valid_too_long() {
        assert!(!hostname_is_valid(&"a".repeat(65)));
    }

    #[test]
    fn test_hostname_valid_max_length() {
        assert!(hostname_is_valid(&"a".repeat(64)));
    }

    #[test]
    fn test_hostname_valid_dot_host() {
        assert!(!hostname_is_valid(".host"));
    }

    #[test]
    fn test_hostname_valid_invalid_chars() {
        assert!(!hostname_is_valid("host name"));
        assert!(!hostname_is_valid("host?name"));
    }

    #[test]
    fn test_hostname_valid_hyphen_after_dot() {
        assert!(!hostname_is_valid("host.-name"));
    }

    #[test]
    fn test_valid_ldh_char() {
        assert!(valid_ldh_char(b'a'));
        assert!(valid_ldh_char(b'Z'));
        assert!(valid_ldh_char(b'0'));
        assert!(valid_ldh_char(b'-'));
        assert!(!valid_ldh_char(b'.'));
        assert!(!valid_ldh_char(b'_'));
        assert!(!valid_ldh_char(b'?'));
    }

    // ── shorten_overlong tests ──────────────────────────────────────────

    #[test]
    fn test_shorten_valid_short() {
        let result = shorten_overlong("localhost").unwrap();
        assert_eq!(result, ShortenResult::AlreadyValid("localhost".to_string()));
    }

    #[test]
    fn test_shorten_valid_fqdn() {
        let result = shorten_overlong("host.example.com").unwrap();
        assert_eq!(
            result,
            ShortenResult::AlreadyValid("host.example.com".to_string())
        );
    }

    #[test]
    fn test_shorten_trailing_dot() {
        let result = shorten_overlong("host.example.com.").unwrap();
        assert_eq!(result, ShortenResult::Shortened("host".to_string()));
    }

    #[test]
    fn test_shorten_overlong_no_dot() {
        let long_name = "a".repeat(100);
        let result = shorten_overlong(&long_name).unwrap();
        match result {
            ShortenResult::Shortened(s) => {
                assert!(s.len() <= LINUX_HOST_NAME_MAX);
                assert!(hostname_is_valid(&s));
            }
            _ => panic!("expected shortened"),
        }
    }

    #[test]
    fn test_shorten_exactly_max() {
        let name = "a".repeat(LINUX_HOST_NAME_MAX);
        let result = shorten_overlong(&name).unwrap();
        assert_eq!(result, ShortenResult::AlreadyValid(name.clone()));
    }

    #[test]
    fn test_shorten_empty() {
        assert_eq!(shorten_overlong(""), Err(HostnameSetupError::CannotShorten));
    }

    #[test]
    fn test_shorten_single_char() {
        let result = shorten_overlong("a").unwrap();
        assert_eq!(result, ShortenResult::AlreadyValid("a".to_string()));
    }

    #[test]
    fn test_shorten_leading_dot() {
        assert!(shorten_overlong(".example.com").is_err());
    }

    #[test]
    fn test_shorten_multiple_dots_valid() {
        let result = shorten_overlong("a.b.c.d.e").unwrap();
        assert_eq!(result, ShortenResult::AlreadyValid("a.b.c.d.e".to_string()));
    }

    #[test]
    fn test_shorten_leading_hyphen() {
        assert!(shorten_overlong("-hostname").is_err());
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            HostnameSetupError::CannotShorten.to_string(),
            "hostname invalid after truncation"
        );
    }

    #[test]
    fn test_shorten_dot_within_overlong() {
        let name = format!("{}{}", "b".repeat(70), ".example.com");
        let result = shorten_overlong(&name).unwrap();
        assert_eq!(result, ShortenResult::Shortened("b".repeat(64)));
    }
}
