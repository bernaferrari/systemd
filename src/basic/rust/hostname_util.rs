// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/hostname-util.c, src/basic/hostname-util.h
//
// Hostname validation, cleanup, and parsing utilities.
//
// Supports validation of LDH hostnames, localhost detection,
// synthetic hostname checks, and user@host expression splitting.

use libc::c_char;

// ── Constants ──────────────────────────────────────────────────────────────

/// Maximum hostname length on Linux (min of HOST_NAME_MAX and 64).
const LINUX_HOST_NAME_MAX: usize = 64;

// ── Flags ──────────────────────────────────────────────────────────────────

/// Flags controlling hostname validation behavior.
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ValidHostnameFlags: u32 {
        /// Accept trailing dot on multi-label names.
        const TRAILING_DOT = 1 << 0;
        /// Accept ".host" as valid hostname.
        const DOT_HOST = 1 << 1;
        /// Accept "?" as placeholder for hashed machine ID.
        const QUESTION_MARK = 1 << 2;
        /// Accept "$" as a placeholder for a word-list substitution.
        const WORD_TOKEN = 1 << 3;
    }
}

// ── Error constants ────────────────────────────────────────────────────────

const EINVAL: i32 = -22;
const ENOMEM: i32 = -12;

// ── Internal helpers ──────────────────────────────────────────────────────

/// Check if byte is ASCII letter (a-z, A-Z).
#[inline]
fn ascii_isalpha(c: u8) -> bool {
    (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z')
}

/// Check if byte is ASCII digit (0-9).
#[inline]
fn ascii_isdigit(c: u8) -> bool {
    c >= b'0' && c <= b'9'
}

/// Case-insensitive ASCII comparison.
#[inline]
fn ascii_tolower(c: u8) -> u8 {
    if c >= b'A' && c <= b'Z' { c + 32 } else { c }
}

/// Case-insensitive string equality.
fn strcaseeq(a: &str, b: &str) -> bool {
    a.bytes()
        .zip(b.bytes())
        .all(|(ca, cb)| ascii_tolower(ca) == ascii_tolower(cb))
        && a.len() == b.len()
}

/// Case-insensitive check if s equals any of the given strings.
fn strcase_in_set(s: &str, candidates: &[&str]) -> bool {
    candidates.iter().any(|c| strcaseeq(s, c))
}

/// Case-insensitive check if s ends with suffix.
fn endswith_no_case(s: &str, suffix: &str) -> bool {
    if suffix.len() > s.len() {
        return false;
    }
    if suffix.is_empty() {
        return true;
    }
    let s_tail = &s[s.len() - suffix.len()..];
    strcaseeq(s_tail, suffix)
}

// ── Simple user name validation ───────────────────────────────────────────

/// Check if a string is a valid POSIX user/group name.
///
/// Mirrors `valid_user_group_name(u, VALID_USER_RELAX | VALID_USER_ALLOW_NUMERIC)`
/// from user-util.c. Allows alphanumeric, underscore, hyphen; leading digits OK.
fn valid_user_group_name_relaxed(u: &str) -> bool {
    if u.is_empty() {
        return true; // VALID_USER_RELAX allows empty
    }
    if u.len() > 256 {
        return false;
    }
    u.bytes()
        .all(|c| ascii_isalpha(c) || ascii_isdigit(c) || c == b'_' || c == b'-')
}

// ── Public API ────────────────────────────────────────────────────────────

/// Check if a character is a valid LDH character (Letter, Digit, Hyphen).
///
/// "LDH" → "Letters, digits, hyphens", as per RFC 5890, Section 2.3.1.
pub fn valid_ldh_char(c: u8) -> bool {
    ascii_isalpha(c) || ascii_isdigit(c) || c == b'-'
}

pub fn rs_valid_ldh_char(c: c_char) -> bool {
    valid_ldh_char(c as u8)
}

/// Check if a string looks like a valid hostname or FQDN.
///
/// Returns `true` if valid, `false` otherwise.
pub fn hostname_is_valid(s: &str, flags: ValidHostnameFlags) -> bool {
    if s.is_empty() {
        return false;
    }

    if s == ".host" {
        return flags.contains(ValidHostnameFlags::DOT_HOST);
    }

    let mut n_dots: u32 = 0;
    let mut dot = true;
    let mut hyphen = true;

    for ch in s.bytes() {
        if ch == b'.' {
            if dot || hyphen {
                return false;
            }
            dot = true;
            hyphen = false;
            n_dots += 1;
        } else if ch == b'-' {
            if dot {
                return false;
            }
            dot = false;
            hyphen = true;
        } else {
            if !valid_ldh_char(ch)
                && (ch != b'?' || !flags.contains(ValidHostnameFlags::QUESTION_MARK))
                && (ch != b'$' || !flags.contains(ValidHostnameFlags::WORD_TOKEN))
            {
                return false;
            }
            dot = false;
            hyphen = false;
        }
    }

    if dot && !flags.contains(ValidHostnameFlags::TRAILING_DOT) {
        return false;
    }
    if hyphen {
        return false;
    }

    // Note that host name max is 64 on Linux, but DNS allows domain names up to 255 characters.
    if s.len() > LINUX_HOST_NAME_MAX {
        return false;
    }

    true
}

/// Clean up a hostname string.
///
/// Removes invalid characters, collapses consecutive dots/hyphens, trims
/// trailing dot/hyphen, truncates to LINUX_HOST_NAME_MAX.
pub fn hostname_cleanup(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(bytes.len().min(LINUX_HOST_NAME_MAX));
    let mut dot = true;
    let mut hyphen = true;

    for &ch in bytes.iter() {
        if result.len() >= LINUX_HOST_NAME_MAX {
            break;
        }
        if ch == b'.' {
            if dot || hyphen {
                continue;
            }
            result.push(b'.');
            dot = true;
            hyphen = false;
        } else if ch == b'-' {
            if dot {
                continue;
            }
            result.push(b'-');
            dot = false;
            hyphen = true;
        } else if valid_ldh_char(ch) || matches!(ch, b'?' | b'$') {
            result.push(ch);
            dot = false;
            hyphen = false;
        }
    }

    // Remove trailing dot or hyphen
    while result.last() == Some(&b'-') || result.last() == Some(&b'.') {
        result.pop();
    }

    String::from_utf8_lossy(&result).into_owned()
}

/// Check if a hostname matches localhost patterns (RFC 6761 + localdomain).
pub fn is_localhost(hostname: &str) -> bool {
    strcase_in_set(
        hostname,
        &[
            "localhost",
            "localhost.",
            "localhost.localdomain",
            "localhost.localdomain.",
        ],
    ) || endswith_no_case(hostname, ".localhost")
        || endswith_no_case(hostname, ".localhost.")
        || endswith_no_case(hostname, ".localhost.localdomain")
        || endswith_no_case(hostname, ".localhost.localdomain.")
}

/// Check if hostname is the synthetic "gateway" host.
pub fn is_gateway_hostname(hostname: &str) -> bool {
    strcase_in_set(hostname, &["_gateway", "_gateway."])
}

/// Check if hostname is the synthetic "outbound" host.
pub fn is_outbound_hostname(hostname: &str) -> bool {
    strcase_in_set(hostname, &["_outbound", "_outbound."])
}

/// Check if hostname is the DNS stub hostname.
pub fn is_dns_stub_hostname(hostname: &str) -> bool {
    strcase_in_set(hostname, &["_localdnsstub", "_localdnsstub."])
}

/// Check if hostname is the DNS proxy stub hostname.
pub fn is_dns_proxy_stub_hostname(hostname: &str) -> bool {
    strcase_in_set(hostname, &["_localdnsproxy", "_localdnsproxy."])
}

/// Result of splitting a user@host expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitResult {
    /// The user part (before @), if any.
    pub user: Option<String>,
    /// The host part (after @, or entire string if no @).
    pub host: Option<String>,
    /// Whether an '@' was found in the input.
    pub has_at: bool,
}

/// Split a user@host expression.
///
/// Returns a `SplitResult` on success, or a negative errno on error.
/// Sets user/host to `None` if that part was empty.
pub fn split_user_at_host(s: &str) -> Result<SplitResult, i32> {
    if let Some(at_pos) = s.find('@') {
        let user_part = if at_pos > 0 {
            Some(s[..at_pos].to_string())
        } else {
            None
        };

        let host_part = if at_pos + 1 < s.len() {
            Some(s[at_pos + 1..].to_string())
        } else {
            None
        };

        Ok(SplitResult {
            user: user_part,
            host: host_part,
            has_at: true,
        })
    } else {
        if s.is_empty() {
            return Err(EINVAL);
        }

        Ok(SplitResult {
            user: None,
            host: Some(s.to_string()),
            has_at: false,
        })
    }
}

/// Validate a machine specification (user@host format).
///
/// Returns `Ok(true)` if valid, `Ok(false)` if invalid, `Err` on error.
pub fn machine_spec_valid(s: &str) -> Result<bool, i32> {
    let split = match split_user_at_host(s) {
        Ok(r) => r,
        Err(EINVAL) => return Ok(false),
        Err(e) => return Err(e),
    };

    let mut valid = true;

    if let Some(ref u) = split.user {
        if !valid_user_group_name_relaxed(u) {
            valid = false;
        }
    }

    if valid {
        if let Some(ref h) = split.host {
            if !hostname_is_valid(h, ValidHostnameFlags::DOT_HOST) {
                valid = false;
            }
        }
    }

    Ok(valid)
}

/// Maximum number of machine tags accepted by `machine_tags_from_string`.
pub const MACHINE_TAGS_MAX: usize = 1024;

/// Validate one machine tag.
///
/// This mirrors `machine_tag_is_valid()`: tags are ASCII alphanumeric strings
/// with `-`, `.`, and `=` separators; `=` optionally separates a tag key from
/// its value.
pub fn machine_tag_is_valid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() >= 256 {
        return false;
    }

    if matches!(bytes[0], b'-' | b'.' | b'=') {
        return false;
    }

    if let Some(eq) = bytes.iter().position(|byte| *byte == b'=') {
        if matches!(bytes[eq - 1], b'-' | b'.') {
            return false;
        }
    } else if matches!(bytes[bytes.len() - 1], b'-' | b'.') {
        return false;
    }

    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'='))
}

/// Validate a complete machine-tag list, including the one-value-per-key rule.
pub fn machine_tag_list_is_valid(tags: &[String]) -> bool {
    if tags.len() > MACHINE_TAGS_MAX || tags.iter().any(|tag| !machine_tag_is_valid(tag)) {
        return false;
    }

    for (index, tag) in tags.iter().enumerate() {
        let Some(eq) = tag.find('=') else {
            continue;
        };
        let key = &tag[..=eq];
        if tags[..index]
            .iter()
            .any(|other| other != tag && other.starts_with(key))
        {
            return false;
        }
    }

    true
}

/// Parse the colon-separated `TAGS=` machine-info value.
///
/// Invalid tags either reject the input or are omitted, depending on
/// `graceful`. The returned tags are sorted and deduplicated, as in C.
pub fn machine_tags_from_string(s: &str, graceful: bool) -> Result<Vec<String>, i32> {
    if s.is_empty() {
        return Ok(Vec::new());
    }

    let mut tags: Vec<String> = s.split(':').map(str::to_owned).collect();
    tags.sort_unstable();
    tags.dedup();

    if !graceful {
        return machine_tag_list_is_valid(&tags)
            .then_some(tags)
            .ok_or(EINVAL);
    }

    let mut cleaned = Vec::new();
    let mut valid_tag_count = 0;
    for tag in tags {
        if !machine_tag_is_valid(&tag) {
            continue;
        }

        valid_tag_count += 1;
        if valid_tag_count > MACHINE_TAGS_MAX {
            return Err(-(libc::E2BIG as i32));
        }

        if let Some(eq) = tag.find('=') {
            let key = &tag[..=eq];
            if cleaned.iter().any(|other: &String| other.starts_with(key)) {
                continue;
            }
        }
        cleaned.push(tag);
    }

    Ok(cleaned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rs_valid_ldh_char_uses_c_char() {
        let valid: c_char = b'a' as c_char;
        let invalid: c_char = b'_' as c_char;

        assert!(rs_valid_ldh_char(valid));
        assert!(!rs_valid_ldh_char(invalid));
    }

    #[test]
    fn test_valid_ldh_char_letters() {
        assert!(valid_ldh_char(b'a'));
        assert!(valid_ldh_char(b'z'));
        assert!(valid_ldh_char(b'A'));
        assert!(valid_ldh_char(b'Z'));
    }

    #[test]
    fn test_valid_ldh_char_digits_and_hyphen() {
        assert!(valid_ldh_char(b'0'));
        assert!(valid_ldh_char(b'9'));
        assert!(valid_ldh_char(b'-'));
    }

    #[test]
    fn test_valid_ldh_char_invalid() {
        assert!(!valid_ldh_char(b'_'));
        assert!(!valid_ldh_char(b'.'));
        assert!(!valid_ldh_char(b' '));
        assert!(!valid_ldh_char(b'@'));
    }

    #[test]
    fn test_hostname_is_valid_simple() {
        assert!(hostname_is_valid("myhost", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid("my-host", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid("my.host", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid(
            "myhost.example.com",
            ValidHostnameFlags::empty()
        ));
    }

    #[test]
    fn test_hostname_is_valid_trailing_dot() {
        assert!(!hostname_is_valid("myhost.", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid(
            "myhost.",
            ValidHostnameFlags::TRAILING_DOT
        ));
        assert!(hostname_is_valid(
            "myhost.",
            ValidHostnameFlags::TRAILING_DOT | ValidHostnameFlags::QUESTION_MARK
        ));
    }

    #[test]
    fn test_hostname_is_valid_dot_host() {
        assert!(!hostname_is_valid(".host", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid(".host", ValidHostnameFlags::DOT_HOST));
    }

    #[test]
    fn test_hostname_is_valid_question_mark() {
        assert!(!hostname_is_valid("my?host", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid(
            "my?host",
            ValidHostnameFlags::QUESTION_MARK
        ));
    }

    #[test]
    fn test_hostname_is_valid_word_token() {
        assert!(!hostname_is_valid("my$host", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid("my$host", ValidHostnameFlags::WORD_TOKEN));
    }

    #[test]
    fn test_hostname_is_valid_empty_and_null() {
        assert!(!hostname_is_valid("", ValidHostnameFlags::empty()));
    }

    #[test]
    fn test_hostname_is_valid_starting_hyphen() {
        assert!(!hostname_is_valid("-host", ValidHostnameFlags::empty()));
    }

    #[test]
    fn test_hostname_is_valid_ending_hyphen() {
        assert!(!hostname_is_valid("host-", ValidHostnameFlags::empty()));
    }

    #[test]
    fn test_hostname_is_valid_consecutive_dots() {
        assert!(!hostname_is_valid(
            "host..name",
            ValidHostnameFlags::empty()
        ));
    }

    #[test]
    fn test_hostname_is_valid_too_long() {
        let long = "a".repeat(65);
        assert!(!hostname_is_valid(&long, ValidHostnameFlags::empty()));
    }

    #[test]
    fn test_hostname_is_valid_max_length() {
        let max = "a".repeat(64);
        assert!(hostname_is_valid(&max, ValidHostnameFlags::empty()));
    }

    #[test]
    fn test_hostname_cleanup_basic() {
        assert_eq!(hostname_cleanup("myhost"), "myhost");
    }

    #[test]
    fn test_hostname_cleanup_trailing_dot() {
        assert_eq!(hostname_cleanup("myhost."), "myhost");
    }

    #[test]
    fn test_hostname_cleanup_trailing_hyphen() {
        assert_eq!(hostname_cleanup("myhost-"), "myhost");
    }

    #[test]
    fn test_hostname_cleanup_word_token_and_multiple_trailing_separators() {
        assert_eq!(hostname_cleanup("my$host--."), "my$host");
    }

    #[test]
    fn test_hostname_cleanup_consecutive_dots() {
        assert_eq!(hostname_cleanup("my..host"), "my.host");
    }

    #[test]
    fn test_hostname_cleanup_invalid_chars() {
        assert_eq!(hostname_cleanup("my host"), "myhost");
        assert_eq!(hostname_cleanup("my_host"), "myhost");
    }

    #[test]
    fn test_is_localhost() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("LOCALHOST"));
        assert!(is_localhost("localhost."));
        assert!(is_localhost("localhost.localdomain"));
        assert!(is_localhost("foo.localhost"));
        assert!(is_localhost("foo.localhost."));
    }

    #[test]
    fn test_is_localhost_not_localhost() {
        assert!(!is_localhost("example.com"));
        assert!(!is_localhost("myhost"));
    }

    #[test]
    fn test_is_gateway_hostname() {
        assert!(is_gateway_hostname("_gateway"));
        assert!(is_gateway_hostname("_GATEWAY"));
        assert!(is_gateway_hostname("_gateway."));
    }

    #[test]
    fn test_is_gateway_hostname_not_gateway() {
        assert!(!is_gateway_hostname("gateway"));
        assert!(!is_gateway_hostname("localhost"));
    }

    #[test]
    fn test_is_outbound_hostname() {
        assert!(is_outbound_hostname("_outbound"));
        assert!(is_outbound_hostname("_outbound."));
    }

    #[test]
    fn test_is_outbound_hostname_not_outbound() {
        assert!(!is_outbound_hostname("outbound"));
    }

    #[test]
    fn test_is_dns_stub_hostname() {
        assert!(is_dns_stub_hostname("_localdnsstub"));
        assert!(is_dns_stub_hostname("_localdnsstub."));
    }

    #[test]
    fn test_is_dns_stub_hostname_not_stub() {
        assert!(!is_dns_stub_hostname("localdnsstub"));
    }

    #[test]
    fn test_is_dns_proxy_stub_hostname() {
        assert!(is_dns_proxy_stub_hostname("_localdnsproxy"));
        assert!(is_dns_proxy_stub_hostname("_localdnsproxy."));
    }

    #[test]
    fn test_is_dns_proxy_stub_hostname_not_proxy() {
        assert!(!is_dns_proxy_stub_hostname("localdnsproxy"));
    }

    #[test]
    fn test_split_user_at_host_with_user() {
        let result = split_user_at_host("user@host").unwrap();
        assert_eq!(result.user.as_deref(), Some("user"));
        assert_eq!(result.host.as_deref(), Some("host"));
        assert!(result.has_at);
    }

    #[test]
    fn test_split_user_at_host_no_user() {
        let result = split_user_at_host("@host").unwrap();
        assert!(result.user.is_none());
        assert_eq!(result.host.as_deref(), Some("host"));
        assert!(result.has_at);
    }

    #[test]
    fn test_split_user_at_host_no_at() {
        let result = split_user_at_host("host").unwrap();
        assert!(result.user.is_none());
        assert_eq!(result.host.as_deref(), Some("host"));
        assert!(!result.has_at);
    }

    #[test]
    fn test_split_user_at_host_empty() {
        assert!(split_user_at_host("").is_err());
    }

    #[test]
    fn test_machine_spec_valid() {
        assert!(machine_spec_valid("host").unwrap());
        assert!(machine_spec_valid("user@host").unwrap());
        assert!(!machine_spec_valid("").unwrap());
    }

    #[test]
    fn machine_tags_validate_canonical_forms() {
        assert!(machine_tag_is_valid("build"));
        assert!(machine_tag_is_valid("role=worker"));
        assert!(machine_tag_is_valid("release=2026.07"));
        assert!(!machine_tag_is_valid("-build"));
        assert!(!machine_tag_is_valid("role-=worker"));
        assert!(!machine_tag_is_valid("build."));
        assert!(!machine_tag_is_valid("role/worker"));
    }

    #[test]
    fn machine_tags_reject_multiple_values_for_one_key() {
        let tags = vec!["role=api".to_owned(), "role=worker".to_owned()];
        assert!(!machine_tag_list_is_valid(&tags));
        assert!(machine_tags_from_string("role=api:role=worker", false).is_err());
    }

    #[test]
    fn graceful_machine_tags_are_sorted_and_keep_first_value_per_key() {
        assert_eq!(
            machine_tags_from_string("role=worker:bad/:role=api:build", true),
            Ok(vec!["build".to_owned(), "role=api".to_owned()])
        );
    }
}
