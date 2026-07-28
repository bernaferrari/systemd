// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Metrics.c
//
// Varlink interface definition for io.systemd.Metrics.
//
// Metrics APIs for listing metric families and describing their
// types (counter, gauge, string) and values.

// ── Interface metadata ─────────────────────────────────────────────────────

pub const INTERFACE_NAME: &str = "io.systemd.Metrics";

pub const METHOD_LIST: &str = "List";
pub const METHOD_DESCRIBE: &str = "Describe";

pub const METHODS: &[&str] = &[METHOD_LIST, METHOD_DESCRIBE];

// ── Enums ──────────────────────────────────────────────────────────────────

/// Metric family type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricFamilyType {
    /// A monotonically increasing counter value
    Counter,
    /// A value that can go up and down
    Gauge,
    /// A string metric value
    String,
}

impl MetricFamilyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MetricFamilyType::Counter => "counter",
            MetricFamilyType::Gauge => "gauge",
            MetricFamilyType::String => "string",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "counter" => Some(MetricFamilyType::Counter),
            "gauge" => Some(MetricFamilyType::Gauge),
            "string" => Some(MetricFamilyType::String),
            _ => None,
        }
    }

    /// Whether this metric type is numeric
    pub fn is_numeric(&self) -> bool {
        matches!(self, MetricFamilyType::Counter | MetricFamilyType::Gauge)
    }

    /// Whether this metric type can decrease
    pub fn can_decrease(&self) -> bool {
        matches!(self, MetricFamilyType::Gauge)
    }
}

// ── Structs ────────────────────────────────────────────────────────────────

/// A single metric value from the List method
#[derive(Debug, Clone, PartialEq)]
pub struct MetricValue {
    /// Metric family name (e.g. "io.systemd.Manager.unitsByTypeTotal")
    pub name: String,
    /// Metric object name (e.g. "dev-hvc0.device")
    pub object: Option<String>,
    /// Metric fields as key-value pairs
    pub fields: Vec<(String, String)>,
    /// The metric value
    pub value: MetricData,
}

impl MetricValue {
    pub fn new_counter(name: String, value: f64) -> Self {
        Self {
            name,
            object: None,
            fields: vec![],
            value: MetricData::Float(value),
        }
    }

    pub fn new_gauge(name: String, value: f64) -> Self {
        Self {
            name,
            object: None,
            fields: vec![],
            value: MetricData::Float(value),
        }
    }

    pub fn new_string(name: String, value: String) -> Self {
        Self {
            name,
            object: None,
            fields: vec![],
            value: MetricData::String(value),
        }
    }

    pub fn with_object(mut self, object: String) -> Self {
        self.object = Some(object);
        self
    }
}

/// Tagged union for metric data values
#[derive(Debug, Clone, PartialEq)]
pub enum MetricData {
    Float(f64),
    Int(i64),
    String(String),
}

impl MetricData {
    /// Try to get the value as f64
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            MetricData::Float(f) => Some(*f),
            MetricData::Int(i) => Some(*i as f64),
            MetricData::String(_) => None,
        }
    }

    /// Try to get the value as i64
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            MetricData::Int(i) => Some(*i),
            MetricData::Float(f) => Some(*f as i64),
            MetricData::String(_) => None,
        }
    }

    /// Try to get the value as a string reference
    pub fn as_str(&self) -> Option<&str> {
        match self {
            MetricData::String(s) => Some(s),
            _ => None,
        }
    }
}

/// Metric family description from the Describe method
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricFamilyDescription {
    /// Metric family name
    pub name: String,
    /// Human-readable description
    pub description: String,
    /// The type of this metric family
    pub family_type: MetricFamilyType,
}

impl MetricFamilyDescription {
    pub fn new(name: String, description: String, family_type: MetricFamilyType) -> Self {
        Self {
            name,
            description,
            family_type,
        }
    }

    /// Validate the metric family description
    pub fn validate(&self) -> Result<(), MetricsError> {
        if self.name.is_empty() {
            return Err(MetricsError::NoSuchMetric);
        }
        if self.description.is_empty() {
            return Err(MetricsError::NoSuchMetric);
        }
        Ok(())
    }
}

// ── Error types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricsError {
    /// No such metric found
    NoSuchMetric,
}

impl MetricsError {
    pub fn error_id(&self) -> &'static str {
        match self {
            MetricsError::NoSuchMetric => "io.systemd.Metrics.NoSuchMetric",
        }
    }
}

pub const ERROR_IDS: &[&str] = &["io.systemd.Metrics.NoSuchMetric"];

// ── Helper functions ───────────────────────────────────────────────────────

/// Validate a metric family name follows the expected format
pub fn is_valid_metric_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    // Must contain at least one dot for namespacing
    name.contains('.')
}

/// Extract the namespace prefix from a metric name (everything before the last dot)
pub fn metric_namespace(name: &str) -> Option<&str> {
    if !is_valid_metric_name(name) {
        return None;
    }
    name.rsplit_once('.').map(|(prefix, _)| prefix)
}

/// Validate metric data matches expected family type
pub fn validate_metric_type(data: &MetricData, family_type: MetricFamilyType) -> bool {
    match family_type {
        MetricFamilyType::Counter | MetricFamilyType::Gauge => data.is_numeric(),
        MetricFamilyType::String => matches!(data, MetricData::String(_)),
    }
}

impl MetricData {
    /// Check if this data value is numeric
    pub fn is_numeric(&self) -> bool {
        matches!(self, MetricData::Float(_) | MetricData::Int(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Metrics");
        assert_eq!(METHODS.len(), 2);
    }

    #[test]
    fn test_metric_family_type_roundtrip() {
        assert_eq!(
            MetricFamilyType::from_str("counter"),
            Some(MetricFamilyType::Counter)
        );
        assert_eq!(
            MetricFamilyType::from_str("gauge"),
            Some(MetricFamilyType::Gauge)
        );
        assert_eq!(
            MetricFamilyType::from_str("string"),
            Some(MetricFamilyType::String)
        );
        assert_eq!(MetricFamilyType::from_str("histogram"), None);
    }

    #[test]
    fn test_metric_family_type_properties() {
        assert!(MetricFamilyType::Counter.is_numeric());
        assert!(MetricFamilyType::Gauge.is_numeric());
        assert!(!MetricFamilyType::String.is_numeric());

        assert!(MetricFamilyType::Gauge.can_decrease());
        assert!(!MetricFamilyType::Counter.can_decrease());
        assert!(!MetricFamilyType::String.can_decrease());
    }

    #[test]
    fn test_metric_value_constructors() {
        let counter = MetricValue::new_counter("test.counter".into(), 42.0);
        assert_eq!(counter.name, "test.counter");
        assert!(counter.object.is_none());

        let gauge = MetricValue::new_gauge("test.gauge".into(), 3.14);
        assert_eq!(gauge.name, "test.gauge");

        let string = MetricValue::new_string("test.string".into(), "hello".into());
        assert_eq!(string.name, "test.string");
    }

    #[test]
    fn test_metric_value_with_object() {
        let mv = MetricValue::new_counter("test".into(), 1.0).with_object("dev-sda.device".into());
        assert_eq!(mv.object.as_deref(), Some("dev-sda.device"));
    }

    #[test]
    fn test_metric_data_conversions() {
        let f = MetricData::Float(3.14);
        assert_eq!(f.as_f64(), Some(3.14));
        assert!(f.as_str().is_none());

        let i = MetricData::Int(42);
        assert_eq!(i.as_i64(), Some(42));
        assert_eq!(i.as_f64(), Some(42.0));

        let s = MetricData::String("hello".into());
        assert_eq!(s.as_str(), Some("hello"));
        assert!(s.as_f64().is_none());
    }

    #[test]
    fn test_metric_family_description_validate() {
        let desc = MetricFamilyDescription::new(
            "io.systemd.test".into(),
            "A test metric".into(),
            MetricFamilyType::Counter,
        );
        assert!(desc.validate().is_ok());

        let empty_name =
            MetricFamilyDescription::new(String::new(), "desc".into(), MetricFamilyType::Counter);
        assert_eq!(empty_name.validate(), Err(MetricsError::NoSuchMetric));
    }

    #[test]
    fn test_is_valid_metric_name() {
        assert!(is_valid_metric_name("io.systemd.Manager.unitsByTypeTotal"));
        assert!(is_valid_metric_name("a.b"));
        assert!(!is_valid_metric_name("nodots"));
        assert!(!is_valid_metric_name(""));
    }

    #[test]
    fn test_metric_namespace() {
        assert_eq!(
            metric_namespace("io.systemd.Manager.unitsByTypeTotal"),
            Some("io.systemd.Manager")
        );
        assert_eq!(metric_namespace("single"), None);
        assert_eq!(metric_namespace(""), None);
    }

    #[test]
    fn test_validate_metric_type() {
        assert!(validate_metric_type(
            &MetricData::Float(1.0),
            MetricFamilyType::Counter
        ));
        assert!(validate_metric_type(
            &MetricData::Int(42),
            MetricFamilyType::Gauge
        ));
        assert!(validate_metric_type(
            &MetricData::String("s".into()),
            MetricFamilyType::String
        ));
        assert!(!validate_metric_type(
            &MetricData::String("s".into()),
            MetricFamilyType::Counter
        ));
    }

    #[test]
    fn test_error_ids() {
        assert_eq!(ERROR_IDS.len(), 1);
        assert!(
            MetricsError::NoSuchMetric
                .error_id()
                .contains("NoSuchMetric")
        );
    }

    #[test]
    fn test_metric_data_is_numeric() {
        assert!(MetricData::Float(1.0).is_numeric());
        assert!(MetricData::Int(1).is_numeric());
        assert!(!MetricData::String("x".into()).is_numeric());
    }
}
