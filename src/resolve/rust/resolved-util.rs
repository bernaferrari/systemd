// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolved-util.c
//
// System hostname resolution: retrieves the local hostname,
// extracts and normalizes the first DNS label, checks for
// "localhost" rejection, and optionally applies IDNA decoding.

use std::fmt;

// ── Constants ─────────────────────────────────────────────────────────────

pub const DNS_LABEL_MAX: usize = 63;

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostnameError {
    CannotDetermine(String),
    UnescapeFailed(String),
    EmptyHostname,
    EscapeFailed(String),
    LocalhostRejected,
}

impl fmt::Display for HostnameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostnameError::CannotDetermine(msg) => {
                write!(f, "Can't determine system hostname: {}", msg)
            }
            HostnameError::UnescapeFailed(msg) => {
                write!(f, "Failed to unescape hostname: {}", msg)
            }
            HostnameError::EmptyHostname => {
                write!(f, "Couldn't find a single label in hostname")
            }
            HostnameError::EscapeFailed(msg) => {
                write!(f, "Failed to escape hostname: {}", msg)
            }
            HostnameError::LocalhostRejected => {
                write!(f, "System hostname is 'localhost', ignoring")
            }
        }
    }
}

impl std::error::Error for HostnameError {}

// ── DNS label handling ─────────────────────────────────────────────────────

pub fn dns_label_unescape(input: &str) -> Result<(String, usize), HostnameError> {
    let mut label = String::new();
    let mut pos = 0;
    let bytes = input.as_bytes();

    while pos < bytes.len() {
        let ch = bytes[pos];

        if ch == b'.' {
            pos += 1;
            break;
        }

        if ch == b'\\' {
            pos += 1;
            if pos >= bytes.len() {
                label.push('\\');
                break;
            }

            let next = bytes[pos];
            if next.is_ascii_digit() {
                if pos + 2 < bytes.len() {
                    let d1 = (bytes[pos] - b'0') as u32;
                    let d2 = (bytes[pos + 1] - b'0') as u32;
                    let d3 = (bytes[pos + 2] - b'0') as u32;
                    let val = d1 * 100 + d2 * 10 + d3;
                    if val < 256 {
                        label.push(val as u8 as char);
                        pos += 3;
                        continue;
                    }
                }
                label.push('\\');
                label.push(next as char);
                pos += 1;
            } else {
                label.push(next as char);
                pos += 1;
            }
        } else {
            label.push(ch as char);
            pos += 1;
        }

        if label.len() >= DNS_LABEL_MAX {
            break;
        }
    }

    if label.is_empty() {
        return Err(HostnameError::EmptyHostname);
    }

    Ok((label, pos))
}

pub fn dns_label_escape(label: &str) -> Result<String, HostnameError> {
    if label.is_empty() {
        return Err(HostnameError::EscapeFailed("empty label".to_string()));
    }

    let mut escaped = String::new();
    for ch in label.bytes() {
        match ch {
            b'.' | b'\\' => {
                escaped.push('\\');
                escaped.push(ch as char);
            }
            b' '..=b'~' if ch != b'.' && ch != b'\\' => {
                escaped.push(ch as char);
            }
            _ => {
                escaped.push_str(&format!("\\{:03}", ch));
            }
        }
    }

    Ok(escaped)
}

// ── Localhost check ────────────────────────────────────────────────────────

pub fn is_localhost(name: &str) -> bool {
    name.eq_ignore_ascii_case("localhost")
}

pub fn is_gateway_hostname(name: &str) -> bool {
    name.eq_ignore_ascii_case("_gateway")
}

pub fn is_outbound_hostname(name: &str) -> bool {
    name.eq_ignore_ascii_case("_outbound")
}

// ── Hostname resolution ────────────────────────────────────────────────────

pub struct HostnameInfo {
    pub full_hostname: String,
    pub first_label: String,
}

pub fn resolve_system_hostname(hostname_input: &str) -> Result<HostnameInfo, HostnameError> {
    let h = hostname_input.trim();
    if h.is_empty() {
        return Err(HostnameError::CannotDetermine("empty hostname".to_string()));
    }

    let (label, _) = dns_label_unescape(h)?;

    let escaped = dns_label_escape(&label)?;

    if is_localhost(&escaped) {
        return Err(HostnameError::LocalhostRejected);
    }

    let full_hostname = h.to_string();
    let first_label = escaped;

    Ok(HostnameInfo {
        full_hostname,
        first_label,
    })
}

pub fn resolve_system_hostname_full(hostname_input: &str) -> Result<HostnameInfo, HostnameError> {
    resolve_system_hostname(hostname_input)
}

pub fn resolve_first_label_only(hostname_input: &str) -> Result<String, HostnameError> {
    let info = resolve_system_hostname(hostname_input)?;
    Ok(info.first_label)
}

// ── Single-label check ─────────────────────────────────────────────────────

pub fn dns_name_is_single_label(name: &str) -> bool {
    let trimmed = name.trim_end_matches('.');
    !trimmed.contains('.')
}

pub fn single_label_nonsynthetic(name: &str, system_first_label: &str) -> bool {
    if !dns_name_is_single_label(name) {
        return false;
    }

    if is_localhost(name) || is_gateway_hostname(name) || is_outbound_hostname(name) {
        return false;
    }

    !name.eq_ignore_ascii_case(system_first_label)
}

// ── IDNA-like processing ───────────────────────────────────────────────────

pub fn apply_idna(name: &str) -> Result<String, HostnameError> {
    let mut result = String::new();
    for ch in name.chars() {
        if ch.is_ascii() {
            result.push(ch.to_ascii_lowercase());
        } else {
            let encoded = format!("\\{:03}", ch as u8);
            result.push_str(&encoded);
        }
    }
    Ok(result)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_label_unescape_simple() {
        let (label, pos) = dns_label_unescape("example.").unwrap();
        assert_eq!(label, "example");
        assert_eq!(pos, 8);
    }

    #[test]
    fn test_dns_label_unescape_no_dot() {
        let (label, _pos) = dns_label_unescape("example").unwrap();
        assert_eq!(label, "example");
    }

    #[test]
    fn test_dns_label_unescape_escaped() {
        let (label, _pos) = dns_label_unescape(r"ex\097mple").unwrap();
        assert_eq!(label, "example");
    }

    #[test]
    fn test_dns_label_unescape_empty() {
        let result = dns_label_unescape(".");
        assert!(matches!(result, Err(HostnameError::EmptyHostname)));
    }

    #[test]
    fn test_dns_label_unescape_empty_string() {
        let result = dns_label_unescape("");
        assert!(matches!(result, Err(HostnameError::EmptyHostname)));
    }

    #[test]
    fn test_dns_label_escape_simple() {
        let escaped = dns_label_escape("example").unwrap();
        assert_eq!(escaped, "example");
    }

    #[test]
    fn test_dns_label_escape_dot() {
        let escaped = dns_label_escape("a.b").unwrap();
        assert_eq!(escaped, r"a\.b");
    }

    #[test]
    fn test_dns_label_escape_backslash() {
        let escaped = dns_label_escape(r"a\b").unwrap();
        assert_eq!(escaped, r"a\\b");
    }

    #[test]
    fn test_dns_label_escape_high_byte() {
        let escaped = dns_label_escape("t").unwrap();
        assert_eq!(escaped, "t");
    }

    #[test]
    fn test_dns_label_escape_empty() {
        let result = dns_label_escape("");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_localhost() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("Localhost"));
        assert!(is_localhost("LOCALHOST"));
        assert!(!is_localhost("myhost"));
    }

    #[test]
    fn test_is_gateway_hostname() {
        assert!(is_gateway_hostname("_gateway"));
        assert!(is_gateway_hostname("_Gateway"));
        assert!(!is_gateway_hostname("gateway"));
    }

    #[test]
    fn test_is_outbound_hostname() {
        assert!(is_outbound_hostname("_outbound"));
        assert!(!is_outbound_hostname("outbound"));
    }

    #[test]
    fn test_resolve_system_hostname_valid() {
        let info = resolve_system_hostname("myhost.example.com").unwrap();
        assert_eq!(info.full_hostname, "myhost.example.com");
        assert_eq!(info.first_label, "myhost");
    }

    #[test]
    fn test_resolve_system_hostname_localhost_rejected() {
        let result = resolve_system_hostname("localhost");
        assert!(matches!(result, Err(HostnameError::LocalhostRejected)));
    }

    #[test]
    fn test_resolve_system_hostname_empty_rejected() {
        let result = resolve_system_hostname("");
        assert!(matches!(result, Err(HostnameError::CannotDetermine(_))));
    }

    #[test]
    fn test_resolve_first_label_only() {
        let label = resolve_first_label_only("myhost.example.com").unwrap();
        assert_eq!(label, "myhost");
    }

    #[test]
    fn test_dns_name_is_single_label() {
        assert!(dns_name_is_single_label("myhost"));
        assert!(dns_name_is_single_label("myhost."));
        assert!(!dns_name_is_single_label("myhost.example.com"));
    }

    #[test]
    fn test_single_label_nonsynthetic() {
        assert!(single_label_nonsynthetic("myhost", "otherhost"));
        assert!(!single_label_nonsynthetic("myhost", "myhost"));
        assert!(!single_label_nonsynthetic("localhost", "otherhost"));
        assert!(!single_label_nonsynthetic("_gateway", "otherhost"));
        assert!(!single_label_nonsynthetic("multi.label", "otherhost"));
    }

    #[test]
    fn test_apply_idna_ascii() {
        let result = apply_idna("Example.COM").unwrap();
        assert_eq!(result, "example.com");
    }

    #[test]
    fn test_unescape_escape_roundtrip() {
        let original = "test-label";
        let escaped = dns_label_escape(original).unwrap();
        let (unescaped, _) = dns_label_unescape(&escaped).unwrap();
        assert_eq!(unescaped, original);
    }
}
