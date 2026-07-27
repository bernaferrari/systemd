// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/resolve-hook-util.c, src/shared/resolve-hook-util.h,
//            src/resolve/resolved-hook.c header

use std::collections::BTreeMap;
use std::fmt;

use crate::dns_question::{
    dns_json_dispatch_question, DnsQuestion, DnsQuestionJsonEntry, DnsResourceKey,
};
use crate::ffi::Errno;

pub const SOURCE_PATHS: &[&str] = &[
    "src/shared/resolve-hook-util.c",
    "src/shared/resolve-hook-util.h",
    "src/resolve/resolved-hook.c",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveRecordParameters {
    pub question: Option<DnsQuestion>,
}

impl ResolveRecordParameters {
    pub fn new(question: DnsQuestion) -> Self {
        Self {
            question: Some(question),
        }
    }

    pub fn parse(value: &JsonValue) -> Result<Self, ResolveHookUtilError> {
        let object = value
            .as_object()
            .ok_or(ResolveHookUtilError::unexpected_type(
                None,
                JsonValueKind::Object,
                value,
            ))?;

        let question_value = object
            .get("question")
            .ok_or(ResolveHookUtilError::MissingMandatoryField("question"))?;

        let entries = parse_question_entries(question_value)?;
        let question =
            dns_json_dispatch_question(&entries).map_err(ResolveHookUtilError::InvalidQuestion)?;

        Ok(Self::new(question))
    }

    pub fn done(&mut self) {
        self.question = None;
    }

    pub fn question(&self) -> Result<&DnsQuestion, ResolveHookUtilError> {
        self.question
            .as_ref()
            .ok_or(ResolveHookUtilError::QuestionAlreadyReleased)
    }
}

pub fn resolve_record_parameters_done(parameters: &mut ResolveRecordParameters) {
    parameters.done();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonValueKind {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
}

impl fmt::Display for JsonValueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Null => "null",
            Self::Bool => "bool",
            Self::Number => "number",
            Self::String => "string",
            Self::Array => "array",
            Self::Object => "object",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(i64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    pub fn kind(&self) -> JsonValueKind {
        match self {
            Self::Null => JsonValueKind::Null,
            Self::Bool(_) => JsonValueKind::Bool,
            Self::Number(_) => JsonValueKind::Number,
            Self::String(_) => JsonValueKind::String,
            Self::Array(_) => JsonValueKind::Array,
            Self::Object(_) => JsonValueKind::Object,
        }
    }

    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, JsonValue>> {
        match self {
            Self::Object(values) => Some(values),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }
}

impl From<&str> for JsonValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}

impl From<String> for JsonValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<i64> for JsonValue {
    fn from(value: i64) -> Self {
        Self::Number(value)
    }
}

impl From<u16> for JsonValue {
    fn from(value: u16) -> Self {
        Self::Number(i64::from(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonDispatchField {
    pub name: &'static str,
    pub expected: JsonValueKind,
    pub mandatory: bool,
}

pub const RESOLVE_RECORD_PARAMETERS_DISPATCH_TABLE: [JsonDispatchField; 1] = [JsonDispatchField {
    name: "question",
    expected: JsonValueKind::Array,
    mandatory: true,
}];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveHookUtilError {
    MissingMandatoryField(&'static str),
    UnexpectedType {
        field: Option<&'static str>,
        expected: JsonValueKind,
        actual: JsonValueKind,
    },
    IntegerOutOfRange {
        field: &'static str,
        value: i64,
    },
    InvalidDnsName(String),
    InvalidQuestion(i32),
    QuestionAlreadyReleased,
}

impl ResolveHookUtilError {
    fn unexpected_type(
        field: Option<&'static str>,
        expected: JsonValueKind,
        actual: &JsonValue,
    ) -> Self {
        Self::UnexpectedType {
            field,
            expected,
            actual: actual.kind(),
        }
    }

    pub fn errno_value(&self) -> i32 {
        match self {
            Self::MissingMandatoryField(_) => Errno::EINVAL.to_neg_errno(),
            Self::UnexpectedType { .. } => Errno::EINVAL.to_neg_errno(),
            Self::IntegerOutOfRange { .. } => Errno::ERANGE.to_neg_errno(),
            Self::InvalidDnsName(_) => Errno::EBADMSG.to_neg_errno(),
            Self::InvalidQuestion(errno) => *errno,
            Self::QuestionAlreadyReleased => Errno::EINVAL.to_neg_errno(),
        }
    }
}

impl fmt::Display for ResolveHookUtilError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMandatoryField(field) => {
                write!(f, "missing mandatory field '{field}'")
            }
            Self::UnexpectedType {
                field,
                expected,
                actual,
            } => match field {
                Some(field) => write!(
                    f,
                    "field '{field}' has wrong type: expected {expected}, got {actual}"
                ),
                None => write!(
                    f,
                    "JSON value has wrong type: expected {expected}, got {actual}"
                ),
            },
            Self::IntegerOutOfRange { field, value } => {
                write!(f, "field '{field}' value {value} is out of range")
            }
            Self::InvalidDnsName(name) => write!(f, "invalid DNS name '{name}'"),
            Self::InvalidQuestion(errno) => write!(f, "invalid DNS question ({errno})"),
            Self::QuestionAlreadyReleased => f.write_str("question was already released"),
        }
    }
}

impl std::error::Error for ResolveHookUtilError {}

fn parse_question_entries(
    value: &JsonValue,
) -> Result<Vec<DnsQuestionJsonEntry>, ResolveHookUtilError> {
    let entries = value
        .as_array()
        .ok_or(ResolveHookUtilError::unexpected_type(
            Some("question"),
            JsonValueKind::Array,
            value,
        ))?;

    entries
        .iter()
        .map(parse_question_entry)
        .collect::<Result<Vec<_>, _>>()
}

fn parse_question_entry(value: &JsonValue) -> Result<DnsQuestionJsonEntry, ResolveHookUtilError> {
    let object = value
        .as_object()
        .ok_or(ResolveHookUtilError::unexpected_type(
            Some("question"),
            JsonValueKind::Object,
            value,
        ))?;

    let key_value = object
        .get("key")
        .ok_or(ResolveHookUtilError::MissingMandatoryField("key"))?;

    Ok(DnsQuestionJsonEntry {
        key: parse_resource_key(key_value)?,
    })
}

fn parse_resource_key(value: &JsonValue) -> Result<DnsResourceKey, ResolveHookUtilError> {
    let object = value
        .as_object()
        .ok_or(ResolveHookUtilError::unexpected_type(
            Some("key"),
            JsonValueKind::Object,
            value,
        ))?;

    let dns_class = object
        .get("class")
        .map(|v| parse_u16_field("class", v))
        .transpose()?
        .unwrap_or(1);

    let rr_type = object
        .get("type")
        .ok_or(ResolveHookUtilError::MissingMandatoryField("type"))
        .and_then(|v| parse_u16_field("type", v))?;

    let name = object
        .get("name")
        .ok_or(ResolveHookUtilError::MissingMandatoryField("name"))
        .and_then(|v| parse_dns_name_field("name", v))?;

    Ok(DnsResourceKey::new(dns_class, rr_type, name))
}

fn parse_u16_field(field: &'static str, value: &JsonValue) -> Result<u16, ResolveHookUtilError> {
    let raw = value.as_i64().ok_or(ResolveHookUtilError::unexpected_type(
        Some(field),
        JsonValueKind::Number,
        value,
    ))?;

    u16::try_from(raw).map_err(|_| ResolveHookUtilError::IntegerOutOfRange { field, value: raw })
}

fn parse_dns_name_field(
    field: &'static str,
    value: &JsonValue,
) -> Result<String, ResolveHookUtilError> {
    let name = value.as_str().ok_or(ResolveHookUtilError::unexpected_type(
        Some(field),
        JsonValueKind::String,
        value,
    ))?;

    if !dns_name_is_valid(name) {
        return Err(ResolveHookUtilError::InvalidDnsName(name.to_string()));
    }

    Ok(name.to_string())
}

fn dns_name_is_valid(name: &str) -> bool {
    if name == "." {
        return true;
    }

    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return false;
    }

    trimmed.split('.').all(is_valid_dns_label)
}

fn is_valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.as_bytes().iter().any(|b| *b == 0)
        && !label.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(entries: impl IntoIterator<Item = (&'static str, JsonValue)>) -> JsonValue {
        JsonValue::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    fn question_json(name: &str, rr_type: u16) -> JsonValue {
        object([(
            "question",
            JsonValue::Array(vec![object([(
                "key",
                object([("type", rr_type.into()), ("name", name.into())]),
            )])]),
        )])
    }

    #[test]
    fn dispatch_table_matches_c_contract() {
        assert_eq!(RESOLVE_RECORD_PARAMETERS_DISPATCH_TABLE.len(), 1);
        let field = RESOLVE_RECORD_PARAMETERS_DISPATCH_TABLE[0];
        assert_eq!(field.name, "question");
        assert_eq!(field.expected, JsonValueKind::Array);
        assert!(field.mandatory);
    }

    #[test]
    fn parse_resolve_record_parameters_success() {
        let parsed = ResolveRecordParameters::parse(&question_json("example.com", 1)).unwrap();
        assert_eq!(parsed.question().unwrap().size(), 1);
        assert_eq!(parsed.question().unwrap().first_name(), Some("example.com"));
    }

    #[test]
    fn parse_defaults_class_to_in() {
        let parsed = ResolveRecordParameters::parse(&question_json("example.com", 1)).unwrap();
        assert_eq!(parsed.question().unwrap().first_key().unwrap().class, 1);
    }

    #[test]
    fn parse_accepts_explicit_class() {
        let parsed = ResolveRecordParameters::parse(&object([(
            "question",
            JsonValue::Array(vec![object([(
                "key",
                object([
                    ("class", 255u16.into()),
                    ("type", 12u16.into()),
                    ("name", "_http._tcp.local".into()),
                ]),
            )])]),
        )]))
        .unwrap();

        let key = parsed.question().unwrap().first_key().unwrap();
        assert_eq!(key.class, 255);
        assert_eq!(key.rr_type, 12);
    }

    #[test]
    fn parse_ignores_unknown_top_level_fields() {
        let parsed = ResolveRecordParameters::parse(&object([
            (
                "question",
                JsonValue::Array(vec![object([(
                    "key",
                    object([("type", 1u16.into()), ("name", "example.com".into())]),
                )])]),
            ),
            ("ignored", JsonValue::Bool(true)),
        ]))
        .unwrap();

        assert_eq!(parsed.question().unwrap().first_name(), Some("example.com"));
    }

    #[test]
    fn parse_deduplicates_question_entries_like_dns_question_parser() {
        let parsed = ResolveRecordParameters::parse(&object([(
            "question",
            JsonValue::Array(vec![
                object([(
                    "key",
                    object([("type", 1u16.into()), ("name", "example.com".into())]),
                )]),
                object([(
                    "key",
                    object([("type", 1u16.into()), ("name", "EXAMPLE.COM.".into())]),
                )]),
            ]),
        )]))
        .unwrap();

        assert_eq!(parsed.question().unwrap().size(), 1);
    }

    #[test]
    fn parse_rejects_missing_question() {
        let err = ResolveRecordParameters::parse(&object([])).unwrap_err();
        assert_eq!(err, ResolveHookUtilError::MissingMandatoryField("question"));
        assert_eq!(err.errno_value(), Errno::EINVAL.to_neg_errno());
    }

    #[test]
    fn parse_rejects_non_object_root() {
        let err = ResolveRecordParameters::parse(&JsonValue::Array(vec![])).unwrap_err();
        assert_eq!(
            err,
            ResolveHookUtilError::UnexpectedType {
                field: None,
                expected: JsonValueKind::Object,
                actual: JsonValueKind::Array,
            }
        );
    }

    #[test]
    fn parse_rejects_non_array_question() {
        let err =
            ResolveRecordParameters::parse(&object([("question", JsonValue::Null)])).unwrap_err();
        assert_eq!(
            err,
            ResolveHookUtilError::UnexpectedType {
                field: Some("question"),
                expected: JsonValueKind::Array,
                actual: JsonValueKind::Null,
            }
        );
    }

    #[test]
    fn parse_rejects_non_object_question_entry() {
        let err = ResolveRecordParameters::parse(&object([(
            "question",
            JsonValue::Array(vec![JsonValue::String("bad".into())]),
        )]))
        .unwrap_err();

        assert_eq!(
            err,
            ResolveHookUtilError::UnexpectedType {
                field: Some("question"),
                expected: JsonValueKind::Object,
                actual: JsonValueKind::String,
            }
        );
    }

    #[test]
    fn parse_rejects_missing_key() {
        let err = ResolveRecordParameters::parse(&object([(
            "question",
            JsonValue::Array(vec![object([])]),
        )]))
        .unwrap_err();

        assert_eq!(err, ResolveHookUtilError::MissingMandatoryField("key"));
    }

    #[test]
    fn parse_rejects_missing_type() {
        let err = ResolveRecordParameters::parse(&object([(
            "question",
            JsonValue::Array(vec![object([(
                "key",
                object([("name", "example.com".into())]),
            )])]),
        )]))
        .unwrap_err();

        assert_eq!(err, ResolveHookUtilError::MissingMandatoryField("type"));
    }

    #[test]
    fn parse_rejects_missing_name() {
        let err = ResolveRecordParameters::parse(&object([(
            "question",
            JsonValue::Array(vec![object([("key", object([("type", 1u16.into())]))])]),
        )]))
        .unwrap_err();

        assert_eq!(err, ResolveHookUtilError::MissingMandatoryField("name"));
    }

    #[test]
    fn parse_rejects_out_of_range_type() {
        let err = ResolveRecordParameters::parse(&object([(
            "question",
            JsonValue::Array(vec![object([(
                "key",
                object([
                    ("type", JsonValue::Number(70000)),
                    ("name", "example.com".into()),
                ]),
            )])]),
        )]))
        .unwrap_err();

        assert_eq!(
            err,
            ResolveHookUtilError::IntegerOutOfRange {
                field: "type",
                value: 70000,
            }
        );
        assert_eq!(err.errno_value(), Errno::ERANGE.to_neg_errno());
    }

    #[test]
    fn parse_rejects_invalid_dns_name() {
        let err = ResolveRecordParameters::parse(&question_json("example..com", 1)).unwrap_err();
        assert_eq!(
            err,
            ResolveHookUtilError::InvalidDnsName("example..com".to_string())
        );
        assert_eq!(err.errno_value(), Errno::EBADMSG.to_neg_errno());
    }

    #[test]
    fn done_releases_question() {
        let mut parsed = ResolveRecordParameters::parse(&question_json("example.com", 1)).unwrap();
        resolve_record_parameters_done(&mut parsed);
        assert_eq!(parsed.question, None);
        assert_eq!(
            parsed.question().unwrap_err(),
            ResolveHookUtilError::QuestionAlreadyReleased
        );
    }

    #[test]
    fn done_is_idempotent() {
        let mut parsed = ResolveRecordParameters::parse(&question_json("example.com", 1)).unwrap();
        parsed.done();
        parsed.done();
        assert!(parsed.question.is_none());
    }
}
