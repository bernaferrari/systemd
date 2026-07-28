// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.file-classify; authority=src/basic/login-util.c,src/basic/login-util.h
//
// Session classification utilities.

use libc::c_char;
use std::ffi::CStr;

/// Returns true if the session ID is non-empty and fully alphanumeric.
///
/// Mirrors the C `session_id_valid()` which checks `isempty(id)` then
/// `in_charset(id, ALPHANUMERICAL)`.
pub fn session_id_valid(id: &str) -> bool {
    session_id_valid_bytes(id.as_bytes())
}

/// Validate the opaque bytes of a C session identifier.
///
/// C's `in_charset(..., ALPHANUMERICAL)` is an ASCII predicate, so bytes
/// outside that range are rejected without attempting UTF-8 decoding.
fn session_id_valid_bytes(id: &[u8]) -> bool {
    !id.is_empty() && id.iter().all(|byte| byte.is_ascii_alphanumeric())
}

/// Validate a C session identifier without requiring UTF-8 input.
///
/// # Safety
///
/// `id` must be null or point to a live NUL-terminated C string for the
/// duration of this call. The return value has no ownership implications.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_session_id_valid(id: *const c_char) -> bool {
    if id.is_null() {
        return false;
    }

    // SAFETY: upheld by this entry point's documented C-string contract.
    unsafe { session_id_valid_bytes(CStr::from_ptr(id).to_bytes()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_session() {
        assert!(session_id_valid("session1"));
    }

    #[test]
    fn test_single_char() {
        assert!(session_id_valid("a"));
    }

    #[test]
    fn test_all_digits() {
        assert!(session_id_valid("12345"));
    }

    #[test]
    fn test_mixed_alphanumeric() {
        assert!(session_id_valid("abc123XYZ"));
    }

    #[test]
    fn test_empty_string() {
        assert!(!session_id_valid(""));
    }

    #[test]
    fn test_hyphen_rejected() {
        assert!(!session_id_valid("session-1"));
    }

    #[test]
    fn test_space_rejected() {
        assert!(!session_id_valid("session 1"));
    }

    #[test]
    fn test_underscore_rejected() {
        assert!(!session_id_valid("session_1"));
    }

    #[test]
    fn test_dot_rejected() {
        assert!(!session_id_valid("session.1"));
    }

    #[test]
    fn test_slash_rejected() {
        assert!(!session_id_valid("session/1"));
    }

    #[test]
    fn test_uppercase_only() {
        assert!(session_id_valid("ABC"));
    }

    #[test]
    fn test_mixed_case() {
        assert!(session_id_valid("aBcDeF"));
    }

    #[test]
    fn test_single_digit() {
        assert!(session_id_valid("9"));
    }

    #[test]
    fn test_unicode_rejected() {
        assert!(!session_id_valid("sesión1"));
    }

    #[test]
    fn test_long_valid() {
        assert!(session_id_valid(&"a".repeat(100)));
    }
}
