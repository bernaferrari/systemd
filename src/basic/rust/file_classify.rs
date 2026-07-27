// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/login-util.c (session_id_valid)
//
// Session classification utilities.

/// Returns true if the session ID is non-empty and fully alphanumeric.
///
/// Mirrors the C `session_id_valid()` which checks `isempty(id)` then
/// `in_charset(id, ALPHANUMERICAL)`.
pub fn session_id_valid(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric())
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
