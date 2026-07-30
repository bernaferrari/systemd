// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-json/sd-json.c
//

use std::sync::Arc;

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EINVAL: i32 = -libc::EINVAL;
pub const DEPTH_MAX: u16 = 2 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonVariantType {
    Null,
    Boolean,
    Integer,
    Unsigned,
    Real,
    String,
    Array,
    Object,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonSource {
    pub name: String,
    pub max_line: u32,
    pub max_column: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLocation {
    pub source: Arc<JsonSource>,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Boolean(bool),
    Integer(i64),
    Unsigned(u64),
    Real(f64),
    String(String),
    Array(Vec<sd_json_variant>),
    Object(Vec<(String, sd_json_variant)>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct sd_json_variant {
    value: Arc<JsonValue>,
    source: Option<SourceLocation>,
    depth: u16,
    sensitive: bool,
    recursive_sensitive: bool,
    sorted: bool,
    normalized: bool,
}

impl JsonSource {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            max_line: 0,
            max_column: 0,
        }
    }
}

impl sd_json_variant {
    pub fn new_null() -> Self {
        Self::simple(JsonValue::Null)
    }

    pub fn new_boolean(value: bool) -> Self {
        Self::simple(JsonValue::Boolean(value))
    }

    pub fn new_integer(value: i64) -> Self {
        Self::simple(JsonValue::Integer(value))
    }

    pub fn new_unsigned(value: u64) -> Self {
        Self::simple(JsonValue::Unsigned(value))
    }

    pub fn new_real(value: f64) -> Self {
        if value.is_nan() || value.is_infinite() {
            return Self::new_null();
        }
        if value == 0.0 {
            return Self::simple(JsonValue::Real(0.0));
        }
        Self::simple(JsonValue::Real(value))
    }

    pub fn new_string(value: impl Into<String>) -> Self {
        Self::simple(JsonValue::String(value.into()))
    }

    pub fn new_array(elements: Vec<Self>) -> Result<Self> {
        Self::compound(JsonValue::Array(elements))
    }

    pub fn new_object(entries: Vec<(String, Self)>) -> Result<Self> {
        Self::compound(JsonValue::Object(entries))
    }

    pub fn with_source(mut self, source: Arc<JsonSource>, line: u32, column: u32) -> Self {
        self.source = Some(SourceLocation {
            source,
            line,
            column,
        });
        self
    }

    pub fn variant_type(&self) -> JsonVariantType {
        match self.value.as_ref() {
            JsonValue::Null => JsonVariantType::Null,
            JsonValue::Boolean(_) => JsonVariantType::Boolean,
            JsonValue::Integer(_) => JsonVariantType::Integer,
            JsonValue::Unsigned(_) => JsonVariantType::Unsigned,
            JsonValue::Real(_) => JsonVariantType::Real,
            JsonValue::String(_) => JsonVariantType::String,
            JsonValue::Array(_) => JsonVariantType::Array,
            JsonValue::Object(_) => JsonVariantType::Object,
        }
    }

    pub fn depth(&self) -> u16 {
        self.depth
    }

    pub fn has_source(&self) -> bool {
        self.source.is_some()
    }

    pub fn formalize(&self) -> Self {
        match self.value.as_ref() {
            JsonValue::Null => Self::new_null(),
            JsonValue::Boolean(v) => Self::new_boolean(*v),
            JsonValue::Integer(0) => Self::new_integer(0),
            JsonValue::Unsigned(0) => Self::new_unsigned(0),
            JsonValue::Real(v) if *v == 0.0 => Self::new_real(0.0),
            JsonValue::String(s) if s.is_empty() => Self::new_string(""),
            JsonValue::Array(v) if v.is_empty() => Self::new_array(Vec::new()).unwrap(),
            JsonValue::Object(v) if v.is_empty() => Self::new_object(Vec::new()).unwrap(),
            _ => self.clone(),
        }
    }

    pub fn conservative_formalize(&self) -> Self {
        if self.has_source() {
            self.clone()
        } else {
            self.formalize()
        }
    }

    pub fn format_compact(&self) -> String {
        match self.value.as_ref() {
            JsonValue::Null => "null".into(),
            JsonValue::Boolean(v) => v.to_string(),
            JsonValue::Integer(v) => v.to_string(),
            JsonValue::Unsigned(v) => v.to_string(),
            JsonValue::Real(v) => {
                if v.fract() == 0.0 {
                    format!("{v:.1}")
                } else {
                    v.to_string()
                }
            }
            JsonValue::String(s) => format!("\"{}\"", s.replace('"', "\\\"")),
            JsonValue::Array(v) => format!(
                "[{}]",
                v.iter()
                    .map(Self::format_compact)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            JsonValue::Object(v) => format!(
                "{{{}}}",
                v.iter()
                    .map(|(k, value)| format!(
                        "\"{}\":{}",
                        k.replace('"', "\\\""),
                        value.format_compact()
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }

    fn simple(value: JsonValue) -> Self {
        Self {
            value: Arc::new(value),
            source: None,
            depth: 0,
            sensitive: false,
            recursive_sensitive: false,
            sorted: false,
            normalized: false,
        }
    }

    fn compound(value: JsonValue) -> Result<Self> {
        let depth = match &value {
            JsonValue::Array(values) => max_child_depth(values.iter())?,
            JsonValue::Object(values) => max_child_depth(values.iter().map(|(_, v)| v))?,
            _ => 0,
        };

        Ok(Self {
            value: Arc::new(value),
            source: None,
            depth,
            sensitive: false,
            recursive_sensitive: false,
            sorted: false,
            normalized: false,
        })
    }
}

fn max_child_depth<'a>(variants: impl Iterator<Item = &'a sd_json_variant>) -> Result<u16> {
    let child = variants.map(sd_json_variant::depth).max().unwrap_or(0);
    let depth = child.checked_add(1).ok_or(NEG_EINVAL)?;
    if depth > DEPTH_MAX {
        return Err(NEG_EINVAL);
    }
    Ok(depth)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_nan_to_null() {
        assert_eq!(
            sd_json_variant::new_real(f64::NAN).variant_type(),
            JsonVariantType::Null
        );
    }

    #[test]
    fn keeps_real_zero_as_real() {
        let v = sd_json_variant::new_real(0.0);
        assert_eq!(v.variant_type(), JsonVariantType::Real);
        assert_eq!(v.format_compact(), "0.0");
    }

    #[test]
    fn computes_array_depth() {
        let leaf = sd_json_variant::new_string("x");
        let array = sd_json_variant::new_array(vec![leaf]).unwrap();
        assert_eq!(array.depth(), 1);
    }

    #[test]
    fn computes_nested_object_depth() {
        let array = sd_json_variant::new_array(vec![sd_json_variant::new_null()]).unwrap();
        let object = sd_json_variant::new_object(vec![("k".into(), array)]).unwrap();
        assert_eq!(object.depth(), 2);
    }

    #[test]
    fn conservative_formalize_preserves_sourced_values() {
        let source = Arc::new(JsonSource::new("test.json"));
        let sourced = sd_json_variant::new_string("").with_source(source, 4, 2);
        assert!(sourced.conservative_formalize().has_source());
    }

    #[test]
    fn formalize_canonicalizes_empty_array() {
        let empty = sd_json_variant::new_array(Vec::new()).unwrap();
        assert_eq!(empty.formalize().format_compact(), "[]");
    }

    #[test]
    fn formats_objects_compactly() {
        let value = sd_json_variant::new_object(vec![
            ("a".into(), sd_json_variant::new_unsigned(1)),
            ("b".into(), sd_json_variant::new_boolean(true)),
        ])
        .unwrap();
        assert_eq!(value.format_compact(), r#"{"a":1,"b":true}"#);
    }

    #[test]
    fn rejects_depth_overflow() {
        let deep = sd_json_variant {
            value: Arc::new(JsonValue::Null),
            source: None,
            depth: DEPTH_MAX,
            sensitive: false,
            recursive_sensitive: false,
            sorted: false,
            normalized: false,
        };
        assert_eq!(sd_json_variant::new_array(vec![deep]), Err(NEG_EINVAL));
    }
}
