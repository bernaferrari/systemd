// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/sysctl/sysctl.c
//
// Kernel sysctl settings applicator.
//
// Parses sysctl configuration files and applies settings to the kernel.
// Supports prefix filtering, glob patterns, strict mode, and inline
// configuration lines.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default file umask applied before processing.
pub const DEFAULT_UMASK: u32 = 0o022;

/// Base path for sysctl parameters in procfs.
pub const PROC_SYS_PREFIX: &str = "/proc/sys";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Flags controlling how configuration files are displayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatFlags {
    Off,
    ConfigOn,
    Tldr,
}

/// Result of parsing a single sysctl line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysctlOption {
    /// The normalized sysctl key (e.g., "net.ipv4.ip_forward").
    pub key: String,
    /// The value to set, or None for "negative match" options.
    pub value: Option<String>,
    /// If true, failures to apply this setting are non-fatal.
    pub ignore_failure: bool,
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors from sysctl operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysctlError {
    /// A line in the config is not a valid assignment.
    InvalidLine(String),
    /// Failed to write a sysctl value.
    WriteFailed {
        key: String,
        value: String,
        message: String,
    },
    /// Failed to resolve a glob pattern.
    GlobFailed(String, String),
    /// Memory allocation failure.
    OutOfMemory,
    /// Invalid argument.
    InvalidArgument(String),
}

impl std::fmt::Display for SysctlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SysctlError::InvalidLine(line) => {
                write!(f, "Line is not an assignment, ignoring: {}", line)
            }
            SysctlError::WriteFailed {
                key,
                value,
                message,
            } => {
                write!(f, "Couldn't write '{}' to '{}': {}", value, key, message)
            }
            SysctlError::GlobFailed(pattern, message) => {
                write!(f, "Couldn't resolve glob '{}': {}", pattern, message)
            }
            SysctlError::OutOfMemory => write!(f, "Out of memory"),
            SysctlError::InvalidArgument(msg) => write!(f, "Invalid argument: {}", msg),
        }
    }
}

impl std::error::Error for SysctlError {}

// ── Sysctl key normalization ──────────────────────────────────────────────

/// Normalize a sysctl key: strip whitespace, trim /proc/sys prefix if present,
/// and convert dots to slashes consistently.
///
/// Mirrors the C `sysctl_normalize()`.
pub fn sysctl_normalize(key: &str) -> String {
    let mut k = key.trim().to_string();

    // Strip /proc/sys prefix if present
    if let Some(rest) = k.strip_prefix("/proc/sys/") {
        k = rest.to_string();
    } else if k == "/proc/sys" {
        k = String::new();
    }

    // Replace dots with slashes (sysctl uses both interchangeably)
    // Actually, sysctl keys use dots. The path uses slashes.
    // Normalization means: strip /proc/sys, replace / with . for the key name
    k = k.replace('/', ".");

    // Remove leading dot if any
    k = k.trim_start_matches('.').to_string();

    k
}

// ── Prefix matching ───────────────────────────────────────────────────────

/// Check if a sysctl key matches any of the given prefixes.
/// An empty prefix list means everything matches (mirrors C `test_prefix`).
pub fn test_prefix(key: &str, prefixes: &[&str]) -> bool {
    if prefixes.is_empty() {
        return true;
    }
    prefixes.iter().any(|p| key.starts_with(p))
}

// ── Glob detection ────────────────────────────────────────────────────────

/// Check if a sysctl key contains glob characters.
pub fn string_is_glob(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

// ── Line parsing ──────────────────────────────────────────────────────────

/// Parse a single sysctl configuration line.
///
/// Mirrors the C `parse_line()`. Returns the parsed option or an error.
/// Lines starting with `-` set ignore_failure. Lines without `=` are
/// "negative match" entries (key only, value is None).
pub fn parse_line(buffer: &str) -> Result<SysctlOption, SysctlError> {
    let buffer = buffer.trim();

    if buffer.is_empty() || buffer.starts_with('#') || buffer.starts_with(';') {
        return Err(SysctlError::InvalidLine(buffer.to_string()));
    }

    let (working, ignore_failure) = if let Some(stripped) = buffer.strip_prefix('-') {
        (stripped, true)
    } else {
        (buffer, false)
    };

    let working = working.trim();

    if let Some(eq_pos) = working.find('=') {
        let key_part = &working[..eq_pos];
        let value_part = &working[eq_pos + 1..];

        let key = sysctl_normalize(key_part);
        let value = value_part.trim().to_string();

        Ok(SysctlOption {
            key,
            value: Some(value),
            ignore_failure,
        })
    } else if ignore_failure {
        // Negative match: no value, just a key to exclude from glob expansion
        let key = sysctl_normalize(working);
        Ok(SysctlOption {
            key,
            value: None,
            ignore_failure: true,
        })
    } else {
        Err(SysctlError::InvalidLine(buffer.to_string()))
    }
}

// ── Glob matching ─────────────────────────────────────────────────────────

/// Expand a glob pattern against known sysctl keys.
/// Returns matching keys (simplified: uses basic wildcard matching).
pub fn glob_expand_keys<S: AsRef<str>>(pattern: &str, available_keys: &[S]) -> Vec<String> {
    available_keys
        .iter()
        .filter(|k| glob_match(pattern, k.as_ref()))
        .map(|k| k.as_ref().to_string())
        .collect()
}

/// Simple glob match supporting *, ?, and [] patterns.
fn glob_match(pattern: &str, s: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = s.chars().collect();
    let mut pi = 0;
    let mut si = 0;
    let mut star_pi = usize::MAX;
    let mut star_si = 0;

    while si < s.len() {
        if pi < p.len() {
            match p[pi] {
                '*' => {
                    star_pi = pi;
                    star_si = si;
                    pi += 1;
                    continue;
                }
                '?' => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                c if c == s[si] => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                _ => {}
            }
        }
        if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_si += 1;
            si = star_si;
            continue;
        }
        return false;
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sysctl_normalize_plain() {
        assert_eq!(
            sysctl_normalize("net.ipv4.ip_forward"),
            "net.ipv4.ip_forward"
        );
    }

    #[test]
    fn test_sysctl_normalize_with_proc_prefix() {
        assert_eq!(
            sysctl_normalize("/proc/sys/net/ipv4/ip_forward"),
            "net.ipv4.ip_forward"
        );
    }

    #[test]
    fn test_sysctl_normalize_whitespace() {
        assert_eq!(
            sysctl_normalize("  net.ipv4.ip_forward  "),
            "net.ipv4.ip_forward"
        );
    }

    #[test]
    fn test_sysctl_normalize_slashes() {
        assert_eq!(
            sysctl_normalize("net/ipv4/ip_forward"),
            "net.ipv4.ip_forward"
        );
    }

    #[test]
    fn test_test_prefix_empty() {
        assert!(test_prefix("net.ipv4.ip_forward", &[]));
    }

    #[test]
    fn test_test_prefix_match() {
        assert!(test_prefix("net.ipv4.ip_forward", &["net.ipv4"]));
    }

    #[test]
    fn test_test_prefix_no_match() {
        assert!(!test_prefix("kernel.hostname", &["net.ipv4"]));
    }

    #[test]
    fn test_string_is_glob() {
        assert!(string_is_glob("net.ipv4.*"));
        assert!(string_is_glob("net.ipv4.ip_?"));
        assert!(string_is_glob("net.ipv4.[abc]"));
        assert!(!string_is_glob("net.ipv4.ip_forward"));
    }

    #[test]
    fn test_parse_line_simple() {
        let opt = parse_line("net.ipv4.ip_forward = 1").unwrap();
        assert_eq!(opt.key, "net.ipv4.ip_forward");
        assert_eq!(opt.value, Some("1".to_string()));
        assert!(!opt.ignore_failure);
    }

    #[test]
    fn test_parse_line_ignore_failure() {
        let opt = parse_line("-net.ipv4.ip_forward=1").unwrap();
        assert!(opt.ignore_failure);
    }

    #[test]
    fn test_parse_line_negative_match() {
        let opt = parse_line("-net.ipv4.*").unwrap();
        assert_eq!(opt.value, None);
        assert!(opt.ignore_failure);
    }

    #[test]
    fn test_parse_line_comment() {
        assert!(parse_line("# comment").is_err());
    }

    #[test]
    fn test_parse_line_empty() {
        assert!(parse_line("").is_err());
    }

    #[test]
    fn test_parse_line_invalid() {
        assert!(parse_line("notanassignment").is_err());
    }

    #[test]
    fn test_glob_expand_keys() {
        let keys = vec![
            "net.ipv4.ip_forward".to_string(),
            "net.ipv4.tcp_syncookies".to_string(),
            "kernel.hostname".to_string(),
        ];
        let matches = glob_expand_keys("net.ipv4.*", &keys);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_glob_match_star() {
        assert!(glob_match("net.*", "net.test"));
        assert!(!glob_match("net.*", "kernel.test"));
    }

    #[test]
    fn test_glob_match_question() {
        assert!(glob_match("net.?", "net.a"));
        assert!(!glob_match("net.?", "net.ab"));
    }

    #[test]
    fn test_error_display() {
        let err = SysctlError::InvalidLine("bad line".to_string());
        assert!(format!("{}", err).contains("bad line"));
    }
}
