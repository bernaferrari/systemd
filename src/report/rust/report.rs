// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/report/report.c
//
// Acquires metrics from local Varlink sources.
//
// Provides constants, action types, and metric name validation utilities
// faithfully mirroring the C implementation's data types and helpers.

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum number of metrics to collect.
/// Corresponds to `METRICS_MAX` in report.c.
pub const METRICS_MAX: u32 = 1024;

/// Maximum number of Varlink link connections.
/// Corresponds to `METRICS_LINKS_MAX` in report.c.
pub const METRICS_LINKS_MAX: u32 = 128;

/// Timeout for Varlink operations in microseconds (30 seconds).
/// Corresponds to `TIMEOUT_USEC` in report.c.
pub const TIMEOUT_USEC: u64 = 30_000_000;

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

pub type Result<T> = std::result::Result<T, Errno>;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Report action type.
/// Corresponds to `Action` in report.c.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    List,
    Describe,
}

/// Metric validation verdict.
/// Corresponds to the `Verdict` enum in report.c.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Invalid,
    Match,
    Mismatch,
}

// ── Metric name validation ────────────────────────────────────────────────

/// Validate a metrics family name.
/// Corresponds to `metrics_name_valid()` in report.c.
///
/// The name must contain a dot separating the Varlink interface name prefix
/// from the field name suffix. Both parts must follow Varlink naming rules:
/// - Interface name: at least two dot-separated segments, each starting with
///   a lowercase ASCII letter and containing only lowercase letters and digits.
/// - Field name: starts with a lowercase ASCII letter, followed by lowercase
///   letters, digits, or underscores.
pub fn metrics_name_valid(name: &str) -> bool {
    let dot_pos = match name.rfind('.') {
        Some(pos) => pos,
        None => return false,
    };

    if dot_pos == 0 || dot_pos == name.len() - 1 {
        return false;
    }

    let interface = &name[..dot_pos];
    let field = &name[dot_pos + 1..];

    varlink_interface_name_valid(interface) && varlink_field_name_valid(field)
}

/// Check whether a metric name starts with a given prefix, requiring a dot
/// separator after the prefix. Corresponds to `metric_startswith_prefix()`.
pub fn metric_startswith_prefix(metric_name: &str, prefix: &str) -> bool {
    if metric_name.is_empty() || prefix.is_empty() {
        return false;
    }
    if let Some(rest) = metric_name.strip_prefix(prefix) {
        !rest.is_empty() && rest.as_bytes()[0] == b'.'
    } else {
        false
    }
}

/// Simplified Varlink interface name validation.
/// Interface names must have at least two dot-separated segments, each
/// starting with a lowercase ASCII letter.
fn varlink_interface_name_valid(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    parts.iter().all(|p| segment_valid(p))
}

/// Simplified Varlink field name validation.
/// Must start with a lowercase ASCII letter, followed by lowercase letters,
/// digits, or underscores.
fn varlink_field_name_valid(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Validate a single segment of an interface name.
fn segment_valid(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let bytes = s.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

// ── Context model ─────────────────────────────────────────────────────────

/// Report context tracking metrics collection state.
/// Corresponds to the `Context` struct in report.c.
#[derive(Debug, Clone)]
pub struct ReportContext {
    pub action: Action,
    pub n_metrics: usize,
    pub n_skipped_metrics: usize,
    pub n_invalid_metrics: usize,
}

impl ReportContext {
    pub fn new(action: Action) -> Self {
        Self {
            action,
            n_metrics: 0,
            n_skipped_metrics: 0,
            n_invalid_metrics: 0,
        }
    }

    /// Record a collected metric.
    /// Returns `false` if the maximum has been reached.
    /// Corresponds to `if (context->n_metrics >= METRICS_MAX)` check.
    pub fn try_add_metric(&mut self) -> bool {
        if self.n_metrics >= METRICS_MAX as usize {
            self.n_skipped_metrics += 1;
            return false;
        }
        self.n_metrics += 1;
        true
    }

    /// Record an invalid metric.
    pub fn record_invalid(&mut self) {
        self.n_invalid_metrics += 1;
    }
}

// ── Service matching ──────────────────────────────────────────────────────

/// Check whether a Varlink service matches any of the given match patterns.
/// Corresponds to `test_service_matches()` in report.c.
///
/// A service matches if:
/// - The pattern equals the service name exactly, or
/// - The pattern is a prefix of the service name, or
/// - The service name is a prefix of the pattern.
pub fn test_service_matches(service: &str, matches: &[&str]) -> bool {
    if matches.is_empty() {
        return true;
    }
    for pattern in matches {
        if service == *pattern {
            return true;
        }
        if metric_startswith_prefix(pattern, service) || metric_startswith_prefix(service, pattern)
        {
            return true;
        }
    }
    false
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants() {
        assert_eq!(METRICS_MAX, 1024);
        assert_eq!(METRICS_LINKS_MAX, 128);
        assert_eq!(TIMEOUT_USEC, 30_000_000);
    }

    #[test]
    fn metrics_name_valid_simple() {
        assert!(metrics_name_valid("io.systemd.foo"));
    }

    #[test]
    fn metrics_name_valid_nested() {
        assert!(metrics_name_valid("io.systemd.Metrics.UsedMemory"));
    }

    #[test]
    fn metrics_name_invalid_no_dot() {
        assert!(!metrics_name_valid("nodot"));
    }

    #[test]
    fn metrics_name_invalid_empty() {
        assert!(!metrics_name_valid(""));
    }

    #[test]
    fn metrics_name_invalid_dot_at_start() {
        assert!(!metrics_name_valid(".field"));
    }

    #[test]
    fn metrics_name_invalid_dot_at_end() {
        assert!(!metrics_name_valid("io.systemd."));
    }

    #[test]
    fn metrics_name_invalid_uppercase_interface() {
        assert!(!metrics_name_valid("Io.Systemd.Foo"));
    }

    #[test]
    fn metric_startswith_prefix_true() {
        assert!(metric_startswith_prefix("foo.bar", "foo"));
    }

    #[test]
    fn metric_startswith_prefix_exact_name_false() {
        assert!(!metric_startswith_prefix("foo", "foo"));
    }

    #[test]
    fn metric_startswith_prefix_no_dot_false() {
        assert!(!metric_startswith_prefix("foobar", "foo"));
    }

    #[test]
    fn metric_startswith_prefix_empty() {
        assert!(!metric_startswith_prefix("", "foo"));
        assert!(!metric_startswith_prefix("foo", ""));
    }

    #[test]
    fn context_new() {
        let ctx = ReportContext::new(Action::List);
        assert_eq!(ctx.n_metrics, 0);
        assert_eq!(ctx.n_skipped_metrics, 0);
        assert_eq!(ctx.n_invalid_metrics, 0);
    }

    #[test]
    fn context_add_metrics() {
        let mut ctx = ReportContext::new(Action::List);
        assert!(ctx.try_add_metric());
        assert_eq!(ctx.n_metrics, 1);
    }

    #[test]
    fn context_overflow() {
        let mut ctx = ReportContext::new(Action::List);
        ctx.n_metrics = METRICS_MAX as usize;
        assert!(!ctx.try_add_metric());
        assert_eq!(ctx.n_skipped_metrics, 1);
    }

    #[test]
    fn context_record_invalid() {
        let mut ctx = ReportContext::new(Action::Describe);
        ctx.record_invalid();
        assert_eq!(ctx.n_invalid_metrics, 1);
    }

    #[test]
    fn service_matches_exact() {
        assert!(test_service_matches("io.systemd", &["io.systemd"]));
    }

    #[test]
    fn service_matches_prefix() {
        assert!(test_service_matches("io.systemd", &["io.systemd.Foo"]));
    }

    #[test]
    fn service_matches_suffix() {
        assert!(test_service_matches("io.systemd.Foo", &["io.systemd"]));
    }

    #[test]
    fn service_no_match() {
        assert!(!test_service_matches("io.other", &["io.systemd"]));
    }

    #[test]
    fn service_empty_matches_all() {
        assert!(test_service_matches("anything", &[]));
    }
}
