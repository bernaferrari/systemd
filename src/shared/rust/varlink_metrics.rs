// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Metrics.c
//
// Varlink interface definition for io.systemd.Metrics
// Metrics APIs for systemd.

// ── Constants ─────────────────────────────────────────────────────────────

/// Interface name for the Metrics service
pub const INTERFACE_NAME: &str = "io.systemd.Metrics";

/// Method: List metrics
pub const METHOD_LIST: &str = "io.systemd.Metrics.List";

/// Method: Describe metric families
pub const METHOD_DESCRIBE: &str = "io.systemd.Metrics.Describe";

/// Error: No such metric found
pub const ERROR_NO_SUCH_METRIC: &str = "io.systemd.Metrics.NoSuchMetric";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Metric family type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricFamilyType {
    /// Monotonically increasing counter
    Counter,
    /// Value that can go up and down
    Gauge,
    /// String metric
    String,
}

impl MetricFamilyType {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "counter" => Ok(MetricFamilyType::Counter),
            "gauge" => Ok(MetricFamilyType::Gauge),
            "string" => Ok(MetricFamilyType::String),
            _ => Err(-22),
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            MetricFamilyType::Counter => "counter",
            MetricFamilyType::Gauge => "gauge",
            MetricFamilyType::String => "string",
        }
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

/// A metric data point from List method
#[derive(Debug, Clone, PartialEq)]
pub enum MetricValue {
    Integer(i64),
    Float(f64),
    Text(String),
}

impl MetricValue {
    /// Try to get as integer
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            MetricValue::Integer(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as float
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            MetricValue::Float(v) => Some(*v),
            MetricValue::Integer(v) => Some(*v as f64),
            _ => None,
        }
    }

    /// Try to get as string
    pub fn as_str(&self) -> Option<&str> {
        match self {
            MetricValue::Text(v) => Some(v),
            _ => None,
        }
    }
}

/// Metric entry from List method
#[derive(Debug, Clone)]
pub struct MetricEntry {
    /// Metric family name
    pub name: String,
    /// Object name (unit name, process name, etc.)
    pub object: Option<String>,
    /// Fields for differentiating metrics in same family
    pub fields: Option<String>,
    /// Metric value
    pub value: MetricValue,
}

impl MetricEntry {
    /// Create a new MetricEntry with integer value
    pub fn new_int(name: impl Into<String>, value: i64) -> Self {
        Self {
            name: name.into(),
            object: None,
            fields: None,
            value: MetricValue::Integer(value),
        }
    }

    /// Create a new MetricEntry with float value
    pub fn new_float(name: impl Into<String>, value: f64) -> Self {
        Self {
            name: name.into(),
            object: None,
            fields: None,
            value: MetricValue::Float(value),
        }
    }

    /// Create a new MetricEntry with string value
    pub fn new_text(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            object: None,
            fields: None,
            value: MetricValue::Text(value.into()),
        }
    }

    /// Set the object name
    pub fn object(mut self, object: impl Into<String>) -> Self {
        self.object = Some(object.into());
        self
    }
}

/// Metric family description from Describe method
#[derive(Debug, Clone)]
pub struct MetricFamilyDescription {
    /// Family name
    pub name: String,
    /// Description
    pub description: String,
    /// Type
    pub metric_type: MetricFamilyType,
}

impl MetricFamilyDescription {
    /// Create a new description
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        metric_type: MetricFamilyType,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            metric_type,
        }
    }
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Get all known method names
pub fn method_names() -> &'static [&'static str] {
    &[METHOD_LIST, METHOD_DESCRIBE]
}

/// Get all known error names
pub fn error_names() -> &'static [&'static str] {
    &[ERROR_NO_SUCH_METRIC]
}

/// Check if a metric family type string is valid
pub fn is_valid_metric_type(s: &str) -> bool {
    MetricFamilyType::from_str(s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Metrics");
    }

    #[test]
    fn test_method_names() {
        assert_eq!(METHOD_LIST, "io.systemd.Metrics.List");
        assert_eq!(METHOD_DESCRIBE, "io.systemd.Metrics.Describe");
    }

    #[test]
    fn test_error_name() {
        assert_eq!(ERROR_NO_SUCH_METRIC, "io.systemd.Metrics.NoSuchMetric");
    }

    #[test]
    fn test_metric_family_type_from_str() {
        assert_eq!(
            MetricFamilyType::from_str("counter"),
            Ok(MetricFamilyType::Counter)
        );
        assert_eq!(
            MetricFamilyType::from_str("gauge"),
            Ok(MetricFamilyType::Gauge)
        );
        assert_eq!(
            MetricFamilyType::from_str("string"),
            Ok(MetricFamilyType::String)
        );
        assert!(MetricFamilyType::from_str("histogram").is_err());
    }

    #[test]
    fn test_metric_family_type_as_str() {
        assert_eq!(MetricFamilyType::Counter.as_str(), "counter");
        assert_eq!(MetricFamilyType::Gauge.as_str(), "gauge");
        assert_eq!(MetricFamilyType::String.as_str(), "string");
    }

    #[test]
    fn test_metric_value_integer() {
        let v = MetricValue::Integer(42);
        assert_eq!(v.as_i64(), Some(42));
        assert_eq!(v.as_f64(), Some(42.0));
        assert!(v.as_str().is_none());
    }

    #[test]
    fn test_metric_value_float() {
        let v = MetricValue::Float(3.14);
        assert!(v.as_i64().is_none());
        assert_eq!(v.as_f64(), Some(3.14));
    }

    #[test]
    fn test_metric_value_text() {
        let v = MetricValue::Text("active".to_string());
        assert!(v.as_i64().is_none());
        assert_eq!(v.as_str(), Some("active"));
    }

    #[test]
    fn test_metric_entry_new_int() {
        let entry = MetricEntry::new_int("units.total", 10);
        assert_eq!(entry.name, "units.total");
        assert!(entry.object.is_none());
        assert_eq!(entry.value, MetricValue::Integer(10));
    }

    #[test]
    fn test_metric_entry_new_float() {
        let entry = MetricEntry::new_float("cpu.usage", 0.75);
        assert_eq!(entry.name, "cpu.usage");
        assert_eq!(entry.value, MetricValue::Float(0.75));
    }

    #[test]
    fn test_metric_entry_with_object() {
        let entry = MetricEntry::new_int("units.active", 1).object("ssh.service");
        assert_eq!(entry.object, Some("ssh.service".to_string()));
    }

    #[test]
    fn test_metric_family_description() {
        let desc = MetricFamilyDescription::new(
            "io.systemd.Manager.unitsByTypeTotal",
            "Total units by type",
            MetricFamilyType::Counter,
        );
        assert_eq!(desc.name, "io.systemd.Manager.unitsByTypeTotal");
        assert_eq!(desc.metric_type, MetricFamilyType::Counter);
    }

    #[test]
    fn test_method_names_list() {
        let names = method_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&METHOD_LIST));
        assert!(names.contains(&METHOD_DESCRIBE));
    }

    #[test]
    fn test_error_names_list() {
        let errors = error_names();
        assert_eq!(errors.len(), 1);
        assert!(errors.contains(&ERROR_NO_SUCH_METRIC));
    }

    #[test]
    fn test_is_valid_metric_type() {
        assert!(is_valid_metric_type("counter"));
        assert!(is_valid_metric_type("gauge"));
        assert!(is_valid_metric_type("string"));
        assert!(!is_valid_metric_type("histogram"));
    }
}
