// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/hostname-setup.c (shorten_overlong)
//
// Hostname setup pure functions.

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
