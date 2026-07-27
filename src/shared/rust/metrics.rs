// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/metrics.c, src/shared/metrics.h
//
// Systemd metrics framework — metric family definitions, describe/list
// dispatch, and value helpers. Provides pure-Rust equivalents of the
// C varlink-based metrics infrastructure.
//
// A MetricFamily describes a named metric (counter, gauge, or string) and
// optionally carries a generate callback that produces metric entries.
// The describe path returns metadata for every registered family; the list
// path invokes each family's generator and collects the resulting entries.

// ── Metric family type ─────────────────────────────────────────────────────

/// The kind of metric family, mirroring the C `MetricFamilyType` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetricFamilyType {
    /// Monotonically-increasing value (e.g. bytes transferred).
    Counter,
    /// Point-in-time value that can go up or down.
    Gauge,
    /// Free-form string label.
    String,
}

impl MetricFamilyType {
    /// Returns the canonical string representation used in JSON / varlink.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::String => "string",
        }
    }

    /// Parse a metric family type from its canonical string form.
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s {
            "counter" => Some(Self::Counter),
            "gauge" => Some(Self::Gauge),
            "string" => Some(Self::String),
            _ => None,
        }
    }
}

impl std::fmt::Display for MetricFamilyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Metric value ───────────────────────────────────────────────────────────

/// The value payload of a single metric entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricValue {
    /// Unsigned integer value (counters, gauges).
    Unsigned(u64),
    /// String value (string metrics).
    String(String),
}

// ── Metric entry (produced by generators) ──────────────────────────────────

/// A single metric sample produced by a family's generate callback.
///
/// Corresponds to one varlink reply frame in the C implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricEntry {
    /// Family name this entry belongs to.
    pub name: String,
    /// Optional object label (e.g. a disk or container identifier).
    pub object: Option<String>,
    /// The metric value.
    pub value: MetricValue,
    /// Optional key-value fields attached to this sample.
    pub fields: Option<std::collections::BTreeMap<String, String>>,
}

// ── Metric family definition ───────────────────────────────────────────────

/// A metric family definition — the static descriptor that appears in the
/// metric-family table passed to `metrics_method_describe` / `metrics_method_list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricFamily {
    /// Human-readable identifier (e.g. `"io_systemd_service_memory_current"`).
    pub name: &'static str,
    /// Short description of what the metric measures.
    pub description: &'static str,
    /// Whether this is a counter, gauge, or string metric.
    pub family_type: MetricFamilyType,
}

// ── Metric description (describe output) ───────────────────────────────────

/// Serialisable description of a metric family, returned by `metrics_method_describe`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricDescription {
    pub name: String,
    pub description: String,
    pub family_type: String,
}

// ── Describe ───────────────────────────────────────────────────────────────

/// Produce a description record for every family in the table.
///
/// Equivalent to the C `metrics_method_describe` which iterates the
/// `metric_family_table` and replies with JSON objects containing
/// `name`, `description`, and `type`.
pub fn metrics_method_describe(table: &[MetricFamily]) -> Vec<MetricDescription> {
    table
        .iter()
        .map(|mf| MetricDescription {
            name: mf.name.to_owned(),
            description: mf.description.to_owned(),
            family_type: mf.family_type.as_str().to_owned(),
        })
        .collect()
}

// ── List ───────────────────────────────────────────────────────────────────

/// Generate metric entries for every family in the table.
///
/// The closure `generate` receives a `&MetricFamily` and should return an
/// iterator (or fallible iterator) of `MetricEntry`. This mirrors the C
/// `MetricFamily.generate` callback invoked from `metrics_method_list`.
pub fn metrics_method_list<F, I>(table: &[MetricFamily], generate: F) -> Vec<MetricEntry>
where
    F: Fn(&MetricFamily) -> I,
    I: IntoIterator<Item = MetricEntry>,
{
    table.iter().flat_map(generate).collect()
}

// ── Build helpers ──────────────────────────────────────────────────────────

/// Construct a `MetricEntry` with a string value.
///
/// Equivalent to the C `metric_build_send_string`.
pub fn metric_build_send_string(
    family: &MetricFamily,
    object: Option<&str>,
    value: &str,
    fields: Option<std::collections::BTreeMap<String, String>>,
) -> MetricEntry {
    MetricEntry {
        name: family.name.to_owned(),
        object: object.map(String::from),
        value: MetricValue::String(value.to_owned()),
        fields,
    }
}

/// Construct a `MetricEntry` with an unsigned integer value.
///
/// Equivalent to the C `metric_build_send_unsigned`.
pub fn metric_build_send_unsigned(
    family: &MetricFamily,
    object: Option<&str>,
    value: u64,
    fields: Option<std::collections::BTreeMap<String, String>>,
) -> MetricEntry {
    MetricEntry {
        name: family.name.to_owned(),
        object: object.map(String::from),
        value: MetricValue::Unsigned(value),
        fields,
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    static FOO_COUNTER: MetricFamily = MetricFamily {
        name: "foo_total",
        description: "Total number of foo operations",
        family_type: MetricFamilyType::Counter,
    };

    static BAR_GAUGE: MetricFamily = MetricFamily {
        name: "bar_bytes",
        description: "Current bar memory usage in bytes",
        family_type: MetricFamilyType::Gauge,
    };

    static BAZ_STRING: MetricFamily = MetricFamily {
        name: "baz_status",
        description: "Current status string",
        family_type: MetricFamilyType::String,
    };

    // ── MetricFamilyType ────────────────────────────────────────────────

    #[test]
    fn metric_family_type_as_str() {
        assert_eq!(MetricFamilyType::Counter.as_str(), "counter");
        assert_eq!(MetricFamilyType::Gauge.as_str(), "gauge");
        assert_eq!(MetricFamilyType::String.as_str(), "string");
    }

    #[test]
    fn metric_family_type_display() {
        assert_eq!(format!("{}", MetricFamilyType::Counter), "counter");
        assert_eq!(format!("{}", MetricFamilyType::Gauge), "gauge");
        assert_eq!(format!("{}", MetricFamilyType::String), "string");
    }

    #[test]
    fn metric_family_type_from_str_roundtrip() {
        for ty in [
            MetricFamilyType::Counter,
            MetricFamilyType::Gauge,
            MetricFamilyType::String,
        ] {
            assert_eq!(MetricFamilyType::from_str_lossy(ty.as_str()), Some(ty));
        }
    }

    #[test]
    fn metric_family_type_from_str_invalid() {
        assert_eq!(MetricFamilyType::from_str_lossy("bogus"), None);
        assert_eq!(MetricFamilyType::from_str_lossy(""), None);
    }

    // ── metrics_method_describe ─────────────────────────────────────────

    #[test]
    fn describe_empty_table() {
        let result = metrics_method_describe(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn describe_single_family() {
        let result = metrics_method_describe(&[FOO_COUNTER]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "foo_total");
        assert_eq!(result[0].description, "Total number of foo operations");
        assert_eq!(result[0].family_type, "counter");
    }

    #[test]
    fn describe_multiple_families() {
        let table = [FOO_COUNTER, BAR_GAUGE, BAZ_STRING];
        let result = metrics_method_describe(&table);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].family_type, "counter");
        assert_eq!(result[1].family_type, "gauge");
        assert_eq!(result[2].family_type, "string");
    }

    // ── metrics_method_list ─────────────────────────────────────────────

    #[test]
    fn list_empty_table() {
        let result: Vec<MetricEntry> = metrics_method_list(&[], |_| std::iter::empty());
        assert!(result.is_empty());
    }

    #[test]
    fn list_with_generator() {
        let table = [FOO_COUNTER, BAR_GAUGE];
        let result = metrics_method_list(&table, |mf| {
            let name = mf.name.to_owned();
            let value = match mf.family_type {
                MetricFamilyType::Counter => MetricValue::Unsigned(42),
                MetricFamilyType::Gauge => MetricValue::Unsigned(1024),
                MetricFamilyType::String => MetricValue::String("ok".to_owned()),
            };
            vec![MetricEntry {
                name,
                object: None,
                value,
                fields: None,
            }]
        });
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "foo_total");
        assert_eq!(result[0].value, MetricValue::Unsigned(42));
        assert_eq!(result[1].name, "bar_bytes");
        assert_eq!(result[1].value, MetricValue::Unsigned(1024));
    }

    #[test]
    fn list_generator_produces_multiple_entries() {
        let table = [FOO_COUNTER];
        let result = metrics_method_list(&table, |mf| {
            let name = mf.name.to_owned();
            vec![
                MetricEntry {
                    name: name.clone(),
                    object: Some("disk-a".to_owned()),
                    value: MetricValue::Unsigned(100),
                    fields: None,
                },
                MetricEntry {
                    name,
                    object: Some("disk-b".to_owned()),
                    value: MetricValue::Unsigned(200),
                    fields: None,
                },
            ]
        });
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].object.as_deref(), Some("disk-a"));
        assert_eq!(result[1].object.as_deref(), Some("disk-b"));
    }

    // ── metric_build_send_string ────────────────────────────────────────

    #[test]
    fn build_send_string_basic() {
        let entry = metric_build_send_string(&BAZ_STRING, None, "running", None);
        assert_eq!(entry.name, "baz_status");
        assert_eq!(entry.object, None);
        assert_eq!(entry.value, MetricValue::String("running".to_owned()));
        assert!(entry.fields.is_none());
    }

    #[test]
    fn build_send_string_with_object_and_fields() {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("unit".to_owned(), "ssh.service".to_owned());
        let entry =
            metric_build_send_string(&BAZ_STRING, Some("host-1"), "active", Some(fields.clone()));
        assert_eq!(entry.object.as_deref(), Some("host-1"));
        assert_eq!(entry.value, MetricValue::String("active".to_owned()));
        assert_eq!(
            entry.fields.as_ref().unwrap().get("unit").unwrap(),
            "ssh.service"
        );
    }

    // ── metric_build_send_unsigned ──────────────────────────────────────

    #[test]
    fn build_send_unsigned_basic() {
        let entry = metric_build_send_unsigned(&BAR_GAUGE, None, 2048, None);
        assert_eq!(entry.name, "bar_bytes");
        assert_eq!(entry.object, None);
        assert_eq!(entry.value, MetricValue::Unsigned(2048));
        assert!(entry.fields.is_none());
    }

    #[test]
    fn build_send_unsigned_with_fields() {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("path".to_owned(), "/dev/sda".to_owned());
        let entry = metric_build_send_unsigned(&BAR_GAUGE, Some("/dev/sda"), 99999, Some(fields));
        assert_eq!(entry.object.as_deref(), Some("/dev/sda"));
        assert_eq!(entry.value, MetricValue::Unsigned(99999));
    }

    // ── MetricEntry equality ────────────────────────────────────────────

    #[test]
    fn metric_entry_equality() {
        let a = MetricEntry {
            name: "x".to_owned(),
            object: None,
            value: MetricValue::Unsigned(1),
            fields: None,
        };
        let b = MetricEntry {
            name: "x".to_owned(),
            object: None,
            value: MetricValue::Unsigned(1),
            fields: None,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn metric_entry_inequality() {
        let a = MetricEntry {
            name: "x".to_owned(),
            object: None,
            value: MetricValue::Unsigned(1),
            fields: None,
        };
        let b = MetricEntry {
            name: "x".to_owned(),
            object: None,
            value: MetricValue::Unsigned(2),
            fields: None,
        };
        assert_ne!(a, b);
    }
}
