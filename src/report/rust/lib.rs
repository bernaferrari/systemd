// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/report/report.c
use std::cmp::Ordering;

pub const METRICS_MAX: usize = 1024;
pub const METRICS_LINKS_MAX: usize = 128;
pub const TIMEOUT_USEC: u64 = 30_000_000;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidMetricName,
    TooManyMetrics,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMetricName => write!(f, "invalid metric name"),
            Self::TooManyMetrics => write!(f, "too many metrics"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    List,
    Describe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Invalid,
    Match,
    Mismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metric {
    pub name: String,
    pub object: Option<String>,
    pub fields: Option<String>,
}

fn interface_segment_valid(segment: &str) -> bool {
    let mut chars = segment.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn field_name_valid(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn metrics_name_valid(metric_name: &str) -> bool {
    let Some((interface, field)) = metric_name.rsplit_once('.') else {
        return false;
    };

    !interface.is_empty()
        && interface.split('.').all(interface_segment_valid)
        && field_name_valid(field)
}

pub fn metric_startswith_prefix(metric_name: &str, prefix: &str) -> bool {
    metric_name
        .strip_prefix(prefix)
        .is_some_and(|rest| rest.starts_with('.'))
}

pub fn metrics_verdict(service_name: &str, matches: &[String], metric_name: &str) -> Verdict {
    if !metrics_name_valid(metric_name) || !metric_startswith_prefix(metric_name, service_name) {
        return Verdict::Invalid;
    }

    if matches.is_empty()
        || matches.iter().any(|candidate| {
            candidate == metric_name || metric_startswith_prefix(metric_name, candidate)
        })
    {
        Verdict::Match
    } else {
        Verdict::Mismatch
    }
}

pub fn metric_compare(a: &Metric, b: &Metric) -> Ordering {
    a.name
        .cmp(&b.name)
        .then_with(|| a.object.cmp(&b.object))
        .then_with(|| a.fields.cmp(&b.fields))
}

pub fn sort_metrics(metrics: &mut [Metric]) {
    metrics.sort_by(metric_compare);
}

pub fn validate_metric_batch(metrics: &[Metric]) -> Result<()> {
    if metrics.len() > METRICS_MAX {
        return Err(Error::TooManyMetrics);
    }
    if metrics
        .iter()
        .all(|metric| metrics_name_valid(&metric.name))
    {
        Ok(())
    } else {
        Err(Error::InvalidMetricName)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_c_values() {
        assert_eq!(METRICS_MAX, 1024);
        assert_eq!(METRICS_LINKS_MAX, 128);
        assert_eq!(TIMEOUT_USEC, 30_000_000);
    }

    #[test]
    fn action_variants_are_distinct() {
        assert_ne!(Action::List, Action::Describe);
    }

    #[test]
    fn metric_name_requires_interface_and_field() {
        assert!(metrics_name_valid("io.systemd.Report.requests_total"));
        assert!(!metrics_name_valid("requests_total"));
    }

    #[test]
    fn metric_name_rejects_invalid_segments() {
        assert!(!metrics_name_valid("io.systemd.9bad"));
        assert!(!metrics_name_valid("io..systemd.field"));
    }

    #[test]
    fn prefix_check_requires_separator() {
        assert!(metric_startswith_prefix(
            "io.systemd.Report.requests_total",
            "io.systemd.Report"
        ));
        assert!(!metric_startswith_prefix(
            "io.systemd.Report",
            "io.systemd.Report"
        ));
    }

    #[test]
    fn verdict_rejects_wrong_service_name() {
        assert_eq!(
            metrics_verdict("io.systemd.Other", &[], "io.systemd.Report.requests_total"),
            Verdict::Invalid
        );
    }

    #[test]
    fn verdict_matches_exact_and_prefix_filters() {
        let filters = vec!["io.systemd.Report".to_string()];
        assert_eq!(
            metrics_verdict(
                "io.systemd.Report",
                &filters,
                "io.systemd.Report.requests_total"
            ),
            Verdict::Match
        );
    }

    #[test]
    fn verdict_reports_mismatch_when_filter_excludes_metric() {
        let filters = vec!["io.systemd.Report.errors_total".to_string()];
        assert_eq!(
            metrics_verdict(
                "io.systemd.Report",
                &filters,
                "io.systemd.Report.requests_total"
            ),
            Verdict::Mismatch
        );
    }

    #[test]
    fn metric_sort_order_matches_name_object_fields() {
        let mut metrics = vec![
            Metric {
                name: "io.systemd.Report.requests_total".into(),
                object: Some("z".into()),
                fields: None,
            },
            Metric {
                name: "io.systemd.Report.requests_total".into(),
                object: Some("a".into()),
                fields: Some("x".into()),
            },
            Metric {
                name: "io.systemd.Report.accepts_total".into(),
                object: None,
                fields: None,
            },
        ];
        sort_metrics(&mut metrics);
        assert_eq!(metrics[0].name, "io.systemd.Report.accepts_total");
        assert_eq!(metrics[1].object.as_deref(), Some("a"));
    }

    #[test]
    fn metric_batch_rejects_invalid_names() {
        let metrics = vec![Metric {
            name: "broken".into(),
            object: None,
            fields: None,
        }];
        assert_eq!(
            validate_metric_batch(&metrics),
            Err(Error::InvalidMetricName)
        );
    }
}
