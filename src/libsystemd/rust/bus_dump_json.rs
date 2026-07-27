// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-dump-json.c
//
// Safe JSON transformation for a simplified D-Bus message model.

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Boolean(bool),
    Integer(i64),
    Unsigned(u64),
    Real(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum MessageValue {
    Byte(u8),
    Boolean(bool),
    Int16(i16),
    Uint16(u16),
    Int32(i32),
    Uint32(u32),
    Int64(i64),
    Uint64(u64),
    Double(f64),
    String(String),
    ObjectPath(String),
    Signature(String),
    UnixFd(i32),
    Array(Vec<MessageValue>),
    Struct(Vec<MessageValue>),
    DictArray(Vec<(MessageValue, MessageValue)>),
    Variant {
        contents: String,
        value: Box<MessageValue>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageHeader {
    pub message_type: String,
    pub endian: char,
    pub flags: u8,
    pub version: u8,
    pub cookie: u64,
    pub reply_cookie: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub signature: String,
    pub body: Vec<MessageValue>,
    pub header: Option<MessageHeader>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransformError {
    InvalidFd(i32),
    InvalidDictKey,
    EmptyVariantType,
}

impl std::fmt::Display for TransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFd(fd) => write!(f, "invalid unix fd {fd}"),
            Self::InvalidDictKey => {
                f.write_str("dictionary key cannot be converted to a JSON object key")
            }
            Self::EmptyVariantType => f.write_str("variant type must not be empty"),
        }
    }
}

impl std::error::Error for TransformError {}

fn key_to_string(key: &MessageValue) -> Option<String> {
    match key {
        MessageValue::String(s) | MessageValue::ObjectPath(s) | MessageValue::Signature(s) => {
            Some(s.clone())
        }
        MessageValue::Byte(v) => Some(v.to_string()),
        MessageValue::Boolean(v) => Some(v.to_string()),
        MessageValue::Int16(v) => Some(v.to_string()),
        MessageValue::Uint16(v) => Some(v.to_string()),
        MessageValue::Int32(v) => Some(v.to_string()),
        MessageValue::Uint32(v) => Some(v.to_string()),
        MessageValue::Int64(v) => Some(v.to_string()),
        MessageValue::Uint64(v) => Some(v.to_string()),
        _ => None,
    }
}

pub fn json_transform_one(value: &MessageValue) -> Result<JsonValue, TransformError> {
    match value {
        MessageValue::Byte(v) => Ok(JsonValue::Unsigned((*v).into())),
        MessageValue::Boolean(v) => Ok(JsonValue::Boolean(*v)),
        MessageValue::Int16(v) => Ok(JsonValue::Integer((*v).into())),
        MessageValue::Uint16(v) => Ok(JsonValue::Unsigned((*v).into())),
        MessageValue::Int32(v) => Ok(JsonValue::Integer((*v).into())),
        MessageValue::Uint32(v) => Ok(JsonValue::Unsigned((*v).into())),
        MessageValue::Int64(v) => Ok(JsonValue::Integer(*v)),
        MessageValue::Uint64(v) => Ok(JsonValue::Unsigned(*v)),
        MessageValue::Double(v) => Ok(JsonValue::Real(*v)),
        MessageValue::String(v) | MessageValue::ObjectPath(v) | MessageValue::Signature(v) => {
            Ok(JsonValue::String(v.clone()))
        }
        MessageValue::UnixFd(fd) => {
            if *fd < 0 {
                return Err(TransformError::InvalidFd(*fd));
            }
            Ok(JsonValue::Object(vec![(
                "fd".into(),
                JsonValue::Integer((*fd).into()),
            )]))
        }
        MessageValue::Array(values) | MessageValue::Struct(values) => values
            .iter()
            .map(json_transform_one)
            .collect::<Result<Vec<_>, _>>()
            .map(JsonValue::Array),
        MessageValue::DictArray(entries) => {
            let mut object = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                let key = key_to_string(key).ok_or(TransformError::InvalidDictKey)?;
                object.push((key, json_transform_one(value)?));
            }
            Ok(JsonValue::Object(object))
        }
        MessageValue::Variant { contents, value } => {
            if contents.is_empty() {
                return Err(TransformError::EmptyVariantType);
            }
            Ok(JsonValue::Object(vec![
                ("type".into(), JsonValue::String(contents.clone())),
                ("data".into(), json_transform_one(value)?),
            ]))
        }
    }
}

pub fn json_transform_message(
    message: &Message,
    with_header: bool,
) -> Result<JsonValue, TransformError> {
    let payload = JsonValue::Object(vec![
        ("type".into(), JsonValue::String(message.signature.clone())),
        (
            "data".into(),
            JsonValue::Array(
                message
                    .body
                    .iter()
                    .map(json_transform_one)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        ),
    ]);

    if !with_header {
        return Ok(payload);
    }

    let Some(header) = &message.header else {
        return Ok(payload);
    };

    let mut object = vec![
        (
            "type".into(),
            JsonValue::String(header.message_type.clone()),
        ),
        (
            "endian".into(),
            JsonValue::String(header.endian.to_string()),
        ),
        ("flags".into(), JsonValue::Integer(header.flags.into())),
        ("version".into(), JsonValue::Integer(header.version.into())),
        ("cookie".into(), JsonValue::Unsigned(header.cookie)),
    ];
    if let Some(reply_cookie) = header.reply_cookie {
        object.push(("reply_cookie".into(), JsonValue::Unsigned(reply_cookie)));
    }
    object.push(("payload".into(), payload));
    Ok(JsonValue::Object(object))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transforms_basic_scalars() {
        assert_eq!(
            json_transform_one(&MessageValue::Byte(7)).unwrap(),
            JsonValue::Unsigned(7)
        );
        assert_eq!(
            json_transform_one(&MessageValue::Boolean(true)).unwrap(),
            JsonValue::Boolean(true)
        );
        assert_eq!(
            json_transform_one(&MessageValue::Int32(-2)).unwrap(),
            JsonValue::Integer(-2)
        );
    }

    #[test]
    fn transforms_strings() {
        assert_eq!(
            json_transform_one(&MessageValue::ObjectPath("/a/b".into())).unwrap(),
            JsonValue::String("/a/b".into())
        );
    }

    #[test]
    fn transforms_arrays() {
        assert_eq!(
            json_transform_one(&MessageValue::Array(vec![
                MessageValue::Uint16(1),
                MessageValue::Uint16(2)
            ]))
            .unwrap(),
            JsonValue::Array(vec![JsonValue::Unsigned(1), JsonValue::Unsigned(2)])
        );
    }

    #[test]
    fn transforms_structs_as_arrays() {
        assert_eq!(
            json_transform_one(&MessageValue::Struct(vec![
                MessageValue::String("x".into()),
                MessageValue::Int16(3)
            ]))
            .unwrap(),
            JsonValue::Array(vec![JsonValue::String("x".into()), JsonValue::Integer(3)])
        );
    }

    #[test]
    fn transforms_variants_to_type_plus_data() {
        assert_eq!(
            json_transform_one(&MessageValue::Variant {
                contents: "s".into(),
                value: Box::new(MessageValue::String("hello".into())),
            })
            .unwrap(),
            JsonValue::Object(vec![
                ("type".into(), JsonValue::String("s".into())),
                ("data".into(), JsonValue::String("hello".into())),
            ])
        );
    }

    #[test]
    fn transforms_dict_arrays_to_objects() {
        assert_eq!(
            json_transform_one(&MessageValue::DictArray(vec![(
                MessageValue::String("A".into()),
                MessageValue::Uint64(9)
            )]))
            .unwrap(),
            JsonValue::Object(vec![("A".into(), JsonValue::Unsigned(9))])
        );
    }

    #[test]
    fn rejects_non_stringifiable_dict_keys() {
        assert_eq!(
            json_transform_one(&MessageValue::DictArray(vec![(
                MessageValue::Array(vec![MessageValue::Byte(1)]),
                MessageValue::Byte(2),
            )]))
            .unwrap_err(),
            TransformError::InvalidDictKey
        );
    }

    #[test]
    fn rejects_negative_fds() {
        assert_eq!(
            json_transform_one(&MessageValue::UnixFd(-1)).unwrap_err(),
            TransformError::InvalidFd(-1)
        );
    }

    #[test]
    fn wraps_message_payload_and_header() {
        let value = json_transform_message(
            &Message {
                signature: "su".into(),
                body: vec![MessageValue::String("x".into()), MessageValue::Uint32(2)],
                header: Some(MessageHeader {
                    message_type: "signal".into(),
                    endian: 'l',
                    flags: 1,
                    version: 1,
                    cookie: 5,
                    reply_cookie: Some(8),
                }),
            },
            true,
        )
        .unwrap();

        match value {
            JsonValue::Object(fields) => assert!(fields.iter().any(|(k, _)| k == "payload")),
            other => panic!("unexpected value: {other:?}"),
        }
    }
}
