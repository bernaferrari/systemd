// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Resolve.Hook.c
//
// Varlink interface definition for io.systemd.Resolve.Hook
// Generic interface for implementing a domain name resolution hook.

pub const INTERFACE_NAME: &str = "io.systemd.Resolve.Hook";

pub const METHOD_QUERY_FILTER: &str = "io.systemd.Resolve.Hook.QueryFilter";
pub const METHOD_RESOLVE_RECORD: &str = "io.systemd.Resolve.Hook.ResolveRecord";

pub const TYPE_ANSWER: &str = "Answer";
pub const TYPE_QUESTION: &str = "Question";

pub const PARAM_QUESTION: &str = "question";
pub const PARAM_RCODE: &str = "rcode";
pub const PARAM_ANSWER: &str = "answer";
pub const PARAM_FILTER_DOMAINS: &str = "filterDomains";
pub const PARAM_FILTER_LABELS_MIN: &str = "filterLabelsMin";
pub const PARAM_FILTER_LABELS_MAX: &str = "filterLabelsMax";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveHookError {
    EmptyQuestionList,
    EmptyQuestionKey,
    UnknownMethod(String),
}

impl std::fmt::Display for ResolveHookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveHookError::EmptyQuestionList => write!(f, "question list must not be empty"),
            ResolveHookError::EmptyQuestionKey => write!(f, "question key must not be empty"),
            ResolveHookError::UnknownMethod(m) => write!(f, "unknown method: {m}"),
        }
    }
}

impl std::error::Error for ResolveHookError {}

pub fn get_interface_definition() -> &'static str {
    r#"{
  "types": [
    {
      "name": "Answer",
      "type": "struct",
      "fields": {
        "rr": { "type": "ResourceRecord", "nullable": true },
        "raw": { "type": "string" }
      }
    },
    {
      "name": "Question",
      "type": "struct",
      "fields": {
        "key": { "type": "ResourceKey" }
      }
    }
  ],
  "methods": {
    "QueryFilter": {
      "return": {
        "filterDomains": { "type": "[]string", "nullable": true },
        "filterLabelsMin": { "type": "int", "nullable": true },
        "filterLabelsMax": { "type": "int", "nullable": true }
      },
      "flags": ["more"]
    },
    "ResolveRecord": {
      "parameters": {
        "question": { "type": "[]Question" }
      },
      "return": {
        "rcode": { "type": "int", "nullable": true },
        "answer": { "type": "[]Answer", "nullable": true }
      }
    }
  },
  "interface": "io.systemd.Resolve.Hook",
  "description": "Generic interface for implementing a domain name resolution hook."
}"#
}

#[derive(Debug, Clone)]
pub struct Question {
    pub key: String,
}

impl Question {
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }

    pub fn validate(&self) -> Result<(), ResolveHookError> {
        if self.key.is_empty() {
            return Err(ResolveHookError::EmptyQuestionKey);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Answer {
    pub rr: Option<String>,
    pub raw: String,
}

impl Answer {
    pub fn new(raw: impl Into<String>) -> Self {
        Self {
            rr: None,
            raw: raw.into(),
        }
    }

    pub fn with_rr(mut self, rr: impl Into<String>) -> Self {
        self.rr = Some(rr.into());
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResolveRecordParams {
    pub questions: Vec<Question>,
}

impl ResolveRecordParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(mut self, q: Question) -> Self {
        self.questions.push(q);
        self
    }

    pub fn validate(&self) -> Result<(), ResolveHookError> {
        if self.questions.is_empty() {
            return Err(ResolveHookError::EmptyQuestionList);
        }
        for q in &self.questions {
            q.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct QueryFilterOutput {
    pub filter_domains: Option<Vec<String>>,
    pub filter_labels_min: Option<i64>,
    pub filter_labels_max: Option<i64>,
}

impl QueryFilterOutput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn domains(mut self, domains: Vec<String>) -> Self {
        self.filter_domains = Some(domains);
        self
    }

    pub fn labels_range(mut self, min: i64, max: i64) -> Self {
        self.filter_labels_min = Some(min);
        self.filter_labels_max = Some(max);
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResolveRecordOutput {
    pub rcode: Option<i64>,
    pub answers: Option<Vec<Answer>>,
}

impl ResolveRecordOutput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn rcode(mut self, code: i64) -> Self {
        self.rcode = Some(code);
        self
    }

    pub fn answers(mut self, ans: Vec<Answer>) -> Self {
        self.answers = Some(ans);
        self
    }

    pub fn is_success(&self) -> bool {
        self.rcode.unwrap_or(0) == 0
    }
}

pub fn validate_method_name(method: &str) -> Result<&str, ResolveHookError> {
    match method {
        METHOD_QUERY_FILTER | METHOD_RESOLVE_RECORD => Ok(method),
        _ => Err(ResolveHookError::UnknownMethod(method.to_string())),
    }
}

pub fn count_labels(domain: &str) -> usize {
    if domain.is_empty() {
        return 0;
    }
    domain.trim_end_matches('.').split('.').count()
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
        assert!(METHOD_QUERY_FILTER.contains("QueryFilter"));
        assert!(METHOD_RESOLVE_RECORD.contains("ResolveRecord"));
    }

    #[test]
    fn test_type_names() {
        assert_eq!(TYPE_ANSWER, "Answer");
        assert_eq!(TYPE_QUESTION, "Question");
    }

    #[test]
    fn test_interface_definition_valid() {
        let json = get_interface_definition();
        assert!(json.contains("io.systemd.Resolve.Hook"));
        assert!(json.contains("QueryFilter"));
        assert!(json.contains("ResolveRecord"));
        assert!(json.contains("Answer"));
        assert!(json.contains("Question"));
    }

    #[test]
    fn test_question_validate_ok() {
        let q = Question::new("example.com");
        assert!(q.validate().is_ok());
    }

    #[test]
    fn test_question_validate_empty_key() {
        let q = Question::new("");
        assert_eq!(q.validate(), Err(ResolveHookError::EmptyQuestionKey));
    }

    #[test]
    fn test_resolve_record_params_validate_empty() {
        let params = ResolveRecordParams::new();
        assert_eq!(params.validate(), Err(ResolveHookError::EmptyQuestionList));
    }

    #[test]
    fn test_resolve_record_params_validate_ok() {
        let params = ResolveRecordParams::new().add(Question::new("example.com"));
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_answer_new() {
        let a = Answer::new("base64data");
        assert_eq!(a.raw, "base64data");
        assert!(a.rr.is_none());
    }

    #[test]
    fn test_answer_with_rr() {
        let a = Answer::new("base64data").with_rr("A 1.2.3.4");
        assert_eq!(a.rr.as_deref(), Some("A 1.2.3.4"));
    }

    #[test]
    fn test_resolve_record_output_is_success() {
        let out = ResolveRecordOutput::new().rcode(0);
        assert!(out.is_success());

        let out = ResolveRecordOutput::new().rcode(3);
        assert!(!out.is_success());
    }

    #[test]
    fn test_query_filter_output_builder() {
        let out = QueryFilterOutput::new()
            .domains(vec!["example.com".to_string()])
            .labels_range(2, 5);
        assert_eq!(out.filter_domains.as_ref().map(|d| d.len()), Some(1));
        assert_eq!(out.filter_labels_min, Some(2));
        assert_eq!(out.filter_labels_max, Some(5));
    }

    #[test]
    fn test_count_labels() {
        assert_eq!(count_labels(""), 0);
        assert_eq!(count_labels("com"), 1);
        assert_eq!(count_labels("example.com"), 2);
        assert_eq!(count_labels("www.example.com."), 3);
    }

    #[test]
    fn test_validate_method_name_known() {
        assert!(validate_method_name(METHOD_QUERY_FILTER).is_ok());
        assert!(validate_method_name(METHOD_RESOLVE_RECORD).is_ok());
    }

    #[test]
    fn test_validate_method_name_unknown() {
        assert!(validate_method_name("io.systemd.Resolve.Hook.Bogus").is_err());
    }
}
