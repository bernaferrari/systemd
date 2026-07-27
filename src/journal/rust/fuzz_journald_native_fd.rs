// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/fuzz-journald-native-fd.c
//
// Native journal protocol file-descriptor message parsing.
//
// The C version creates sealed memfd and unsealed tmpfile, writes
// the fuzz data, then calls `manager_process_native_file()`.
// This Rust port provides a safe parser for the native protocol
// format that can be exercised with arbitrary byte streams.

use crate::fuzz_journald_native::{
    parse_native_message as parse_canonical_message, parse_one_entry, NativeError,
    NATIVE_FIELD_NAME_MAX,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeFdError {
    FieldNameTooLong,
    FieldValueSizeOverflow,
    InvalidFraming,
}

impl core::fmt::Display for NativeFdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NativeFdError::FieldNameTooLong => write!(f, "field name exceeds limit"),
            NativeFdError::FieldValueSizeOverflow => write!(f, "field value size overflow"),
            NativeFdError::InvalidFraming => write!(f, "invalid native journal framing"),
        }
    }
}

impl std::error::Error for NativeFdError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeField {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeMessage {
    pub fields: Vec<NativeField>,
}

/// Maximum field name length, matching `journal_field_valid()` in journal-file.c.
pub const FIELD_NAME_MAX: usize = NATIVE_FIELD_NAME_MAX;

fn map_native_error(error: NativeError) -> NativeFdError {
    match error {
        NativeError::InvalidFieldName => NativeFdError::InvalidFraming,
        NativeError::FieldTooLarge | NativeError::EntryTooLarge => {
            NativeFdError::FieldValueSizeOverflow
        }
        NativeError::TooManyFields
        | NativeError::Truncated
        | NativeError::MissingBinaryTerminator
        | NativeError::MultipleEntriesUnsupported => NativeFdError::InvalidFraming,
    }
}

fn convert_field(
    field: crate::fuzz_journald_native::NativeEntry,
) -> Result<NativeField, NativeFdError> {
    if field.name.len() > FIELD_NAME_MAX {
        return Err(NativeFdError::FieldNameTooLong);
    }
    Ok(NativeField {
        name: field.name,
        value: field.payload,
    })
}

/// Parse a single native protocol field from the start of *data*.
///
/// Native protocol format:
/// - Text field: `NAME=value\n`
/// - Binary field: `NAME\n` followed by a 64-bit little-endian
///   size, then the raw bytes, then a trailing `\n`.
///
/// Returns `(field, bytes_consumed)` on success.
pub fn parse_native_field(data: &[u8]) -> Result<Option<(NativeField, usize)>, NativeFdError> {
    let line_end = data
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(data.len());
    let name_len = data[..line_end]
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(line_end);
    if name_len > FIELD_NAME_MAX {
        return Err(NativeFdError::FieldNameTooLong);
    }
    parse_one_entry(data)
        .map_err(map_native_error)?
        .map(|(field, consumed)| Ok((convert_field(field)?, consumed)))
        .transpose()
}

/// Parse all fields from a native protocol byte stream.
pub fn parse_native_message(data: &[u8]) -> Result<NativeMessage, NativeFdError> {
    let canonical = parse_canonical_message(data).map_err(map_native_error)?;
    let fields = canonical
        .entries
        .into_iter()
        .map(convert_field)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(NativeMessage { fields })
}

/// Process native-fd data (fuzz entry point).
/// Returns `Ok(message)` with all parsed fields, or an error.
pub fn process_native_fd_data(data: &[u8]) -> Result<NativeMessage, NativeFdError> {
    parse_native_message(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_text_field() {
        let (field, consumed) = parse_native_field(b"KEY=value\n").unwrap().unwrap();
        assert_eq!(field.name, b"KEY");
        assert_eq!(field.value, b"value");
        assert_eq!(consumed, 10);
    }

    #[test]
    fn test_parse_binary_field() {
        let size = 3u64.to_le_bytes();
        let mut data = b"KEY\n".to_vec();
        data.extend_from_slice(&size);
        data.extend_from_slice(b"abc");
        data.push(b'\n');
        let (field, consumed) = parse_native_field(&data).unwrap().unwrap();
        assert_eq!(field.name, b"KEY");
        assert_eq!(field.value, b"abc");
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_parse_empty_input() {
        assert!(parse_native_field(b"").unwrap().is_none());
    }

    #[test]
    fn test_parse_incomplete_header() {
        assert_eq!(
            parse_native_field(b"KEY=value").unwrap_err(),
            NativeFdError::InvalidFraming
        );
    }

    #[test]
    fn test_parse_multiple_fields() {
        let data = b"FIELD1=val1\nFIELD2=val2\n";
        let msg = parse_native_message(data).unwrap();
        assert_eq!(msg.fields.len(), 2);
        assert_eq!(msg.fields[0].name, b"FIELD1");
        assert_eq!(msg.fields[1].name, b"FIELD2");
    }

    #[test]
    fn test_parse_field_no_equals() {
        let size = 2u64.to_le_bytes();
        let mut data = b"BINFIELD\n".to_vec();
        data.extend_from_slice(&size);
        data.extend_from_slice(b"hi");
        data.push(b'\n');
        let (field, _) = parse_native_field(&data).unwrap().unwrap();
        assert_eq!(field.name, b"BINFIELD");
        assert_eq!(field.value, b"hi");
    }

    #[test]
    fn test_process_native_fd_data() {
        let data = b"PRIORITY=6\nMESSAGE=hello\n";
        let msg = process_native_fd_data(data).unwrap();
        assert_eq!(msg.fields.len(), 2);
    }

    #[test]
    fn test_process_native_fd_data_empty() {
        let msg = process_native_fd_data(b"").unwrap();
        assert!(msg.fields.is_empty());
    }

    #[test]
    fn test_binary_field_incomplete_payload() {
        let size = 100u64.to_le_bytes();
        let mut data = b"KEY\n".to_vec();
        data.extend_from_slice(&size);
        data.extend_from_slice(b"short");
        assert_eq!(
            parse_native_field(&data).unwrap_err(),
            NativeFdError::InvalidFraming
        );
    }

    #[test]
    fn test_field_name_too_long() {
        let mut data = vec![b'X'; FIELD_NAME_MAX + 1];
        data.push(b'\n');
        assert_eq!(
            parse_native_field(&data).unwrap_err(),
            NativeFdError::FieldNameTooLong
        );
    }
}
