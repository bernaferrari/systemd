// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Resolve.Hook.c
//
// Varlink interface definition for io.systemd.Resolve.Hook.
//
// Generic interface for implementing a domain name resolution hook.
// Provides methods for querying filter parameters and resolving DNS records.

// ── Constants ─────────────────────────────────────────────────────────────

/// Fully qualified varlink interface name.
pub const INTERFACE_NAME: &str = "io.systemd.Resolve.Hook";

// ── Method identifiers ────────────────────────────────────────────────────

pub const METHOD_QUERY_FILTER: &str = "QueryFilter";
pub const METHOD_RESOLVE_RECORD: &str = "ResolveRecord";

/// All method names defined by this interface.
pub fn method_names() -> &'static [&'static str] {
    &[METHOD_QUERY_FILTER, METHOD_RESOLVE_RECORD]
}

/// Check whether a method name belongs to this interface.
pub fn has_method(name: &str) -> bool {
    method_names().contains(&name)
}

/// Typed method identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveHookMethod {
    QueryFilter,
    ResolveRecord,
}

impl ResolveHookMethod {
    /// Return the varlink method name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::QueryFilter => METHOD_QUERY_FILTER,
            Self::ResolveRecord => METHOD_RESOLVE_RECORD,
        }
    }

    /// Whether the method supports the "more" flag.
    pub fn supports_more(&self) -> bool {
        matches!(self, Self::QueryFilter)
    }
}

/// Parse a method name into a typed identifier.
pub fn parse_method(name: &str) -> Result<ResolveHookMethod, String> {
    match name {
        METHOD_QUERY_FILTER => Ok(ResolveHookMethod::QueryFilter),
        METHOD_RESOLVE_RECORD => Ok(ResolveHookMethod::ResolveRecord),
        _ => Err(format!("unknown method: {name}")),
    }
}

// ── Struct types ──────────────────────────────────────────────────────────

/// A resource record key used in DNS lookups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceKey {
    /// DNS class (typically IN = 1).
    pub class: i64,
    /// DNS record type (e.g. A=1, AAAA=28, TXT=16).
    pub r#type: i64,
    /// Domain name to look up.
    pub name: String,
}

impl ResourceKey {
    /// Create a new resource key.
    pub fn new(class: i64, r#type: i64, name: &str) -> Self {
        Self {
            class,
            r#type,
            name: name.to_string(),
        }
    }
}

/// A DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    /// Resource record key.
    pub key: ResourceKey,
    /// Raw record data.
    pub data: Option<String>,
}

/// A lookup answer containing a resource record and its wire-format data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// A resource record (mostly for debugging).
    pub rr: Option<ResourceRecord>,
    /// Wire-format resource record encoded in Base64.
    pub raw: String,
}

impl Answer {
    /// Create a new Answer with raw wire-format data.
    pub fn from_raw(raw: &str) -> Self {
        Self {
            rr: None,
            raw: raw.to_string(),
        }
    }
}

/// A lookup question containing a resource key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The resource record key to look up.
    pub key: ResourceKey,
}

impl Question {
    /// Create a new Question for the given resource key.
    pub fn new(key: ResourceKey) -> Self {
        Self { key }
    }

    /// Create a new Question from class, type, and name.
    pub fn from_parts(class: i64, r#type: i64, name: &str) -> Self {
        Self {
            key: ResourceKey::new(class, r#type, name),
        }
    }
}

// ── Method I/O structs ────────────────────────────────────────────────────

/// Output from the QueryFilter method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryFilterOutput {
    /// Domains this hook is interested in.
    pub filter_domains: Option<Vec<String>>,
    /// Minimum number of labels required in a domain.
    pub filter_labels_min: Option<i64>,
    /// Maximum number of labels allowed in a domain.
    pub filter_labels_max: Option<i64>,
}

impl QueryFilterOutput {
    /// Create a new QueryFilterOutput with no filters.
    pub fn new() -> Self {
        Self {
            filter_domains: None,
            filter_labels_min: None,
            filter_labels_max: None,
        }
    }

    /// Check if a domain matches the filter.
    pub fn matches_domain(&self, domain: &str) -> bool {
        let label_count = domain.split('.').count() as i64;

        if let Some(min) = self.filter_labels_min {
            if label_count < min {
                return false;
            }
        }
        if let Some(max) = self.filter_labels_max {
            if label_count > max {
                return false;
            }
        }

        match &self.filter_domains {
            None => true,
            Some(domains) if domains.is_empty() => false,
            Some(domains) => domains.iter().any(|d| domain.ends_with(d) || domain == *d),
        }
    }
}

impl Default for QueryFilterOutput {
    fn default() -> Self {
        Self::new()
    }
}

/// Input for the ResolveRecord method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveRecordInput {
    /// The question being looked up.
    pub question: Vec<Question>,
}

impl ResolveRecordInput {
    /// Create a new input with the given questions.
    pub fn new(question: Vec<Question>) -> Self {
        Self { question }
    }

    /// Validate the input.
    pub fn validate(&self) -> Result<(), String> {
        if self.question.is_empty() {
            return Err("question must not be empty".to_string());
        }
        Ok(())
    }
}

/// Output from the ResolveRecord method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveRecordOutput {
    /// DNS response code (if set, skips normal resolution).
    pub rcode: Option<i64>,
    /// Answers matching the request.
    pub answer: Option<Vec<Answer>>,
}

impl ResolveRecordOutput {
    /// Create a success response with answers.
    pub fn with_answers(answers: Vec<Answer>) -> Self {
        Self {
            rcode: Some(0),
            answer: Some(answers),
        }
    }

    /// Create an error response with a DNS return code.
    pub fn with_rcode(rcode: i64) -> Self {
        Self {
            rcode: Some(rcode),
            answer: None,
        }
    }
}

/// Error names defined by this interface.
pub fn error_names() -> &'static [&'static str] {
    &[]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Resolve.Hook");
    }

    #[test]
    fn test_method_names() {
        assert_eq!(method_names().len(), 2);
        assert!(has_method("QueryFilter"));
        assert!(has_method("ResolveRecord"));
        assert!(!has_method("Unknown"));
    }

    #[test]
    fn test_parse_method() {
        assert_eq!(
            parse_method("QueryFilter"),
            Ok(ResolveHookMethod::QueryFilter)
        );
        assert_eq!(
            parse_method("ResolveRecord"),
            Ok(ResolveHookMethod::ResolveRecord)
        );
        assert!(parse_method("bogus").is_err());
    }

    #[test]
    fn test_method_name_roundtrip() {
        for name in method_names() {
            let m = parse_method(name).unwrap();
            assert_eq!(m.name(), *name);
        }
    }

    #[test]
    fn test_supports_more() {
        assert!(ResolveHookMethod::QueryFilter.supports_more());
        assert!(!ResolveHookMethod::ResolveRecord.supports_more());
    }

    #[test]
    fn test_resource_key() {
        let key = ResourceKey::new(1, 28, "example.com");
        assert_eq!(key.class, 1);
        assert_eq!(key.r#type, 28);
        assert_eq!(key.name, "example.com");
    }

    #[test]
    fn test_question_from_parts() {
        let q = Question::from_parts(1, 1, "test.example.com");
        assert_eq!(q.key.class, 1);
        assert_eq!(q.key.r#type, 1);
        assert_eq!(q.key.name, "test.example.com");
    }

    #[test]
    fn test_resolve_record_input_validate() {
        let input = ResolveRecordInput::new(vec![Question::from_parts(1, 1, "example.com")]);
        assert!(input.validate().is_ok());
    }

    #[test]
    fn test_resolve_record_input_validate_empty() {
        let input = ResolveRecordInput::new(vec![]);
        assert!(input.validate().is_err());
    }

    #[test]
    fn test_resolve_record_output_with_answers() {
        let output = ResolveRecordOutput::with_answers(vec![Answer::from_raw("dGVzdA==")]);
        assert_eq!(output.rcode, Some(0));
        assert!(output.answer.is_some());
    }

    #[test]
    fn test_resolve_record_output_with_rcode() {
        let output = ResolveRecordOutput::with_rcode(3);
        assert_eq!(output.rcode, Some(3));
        assert!(output.answer.is_none());
    }

    #[test]
    fn test_query_filter_matches_no_filter() {
        let filter = QueryFilterOutput::new();
        assert!(filter.matches_domain("example.com"));
    }

    #[test]
    fn test_query_filter_matches_with_domains() {
        let filter = QueryFilterOutput {
            filter_domains: Some(vec!["example.com".to_string()]),
            filter_labels_min: None,
            filter_labels_max: None,
        };
        assert!(filter.matches_domain("example.com"));
        assert!(filter.matches_domain("sub.example.com"));
        assert!(!filter.matches_domain("other.com"));
    }

    #[test]
    fn test_query_filter_matches_with_labels() {
        let filter = QueryFilterOutput {
            filter_domains: None,
            filter_labels_min: Some(2),
            filter_labels_max: Some(3),
        };
        assert!(!filter.matches_domain("com")); // 1 label
        assert!(filter.matches_domain("example.com")); // 2 labels
        assert!(filter.matches_domain("sub.example.com")); // 3 labels
        assert!(!filter.matches_domain("a.b.c.example.com")); // 4 labels
    }
}
