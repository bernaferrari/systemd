// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/fuzz-journald-native.c
//
// Native journal protocol message parsing and fuzz harness.
//
// The C version calls `fuzz_journald_processing_function(data, size,
// manager_process_native_message)`.  This Rust port provides a safe
// parser for the native journald wire format.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeError {
    InvalidFieldName,
    FieldTooLarge,
    EntryTooLarge,
    TooManyFields,
    Truncated,
    MissingBinaryTerminator,
    MultipleEntriesUnsupported,
}

impl core::fmt::Display for NativeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NativeError::InvalidFieldName => write!(f, "invalid journal field name"),
            NativeError::FieldTooLarge => write!(f, "journal field exceeds DATA_SIZE_MAX"),
            NativeError::EntryTooLarge => write!(f, "journal entry exceeds ENTRY_SIZE_MAX"),
            NativeError::TooManyFields => write!(f, "journal entry has too many fields"),
            NativeError::Truncated => write!(f, "truncated native journal record"),
            NativeError::MissingBinaryTerminator => {
                write!(f, "binary journal field is not followed by a newline")
            }
            NativeError::MultipleEntriesUnsupported => {
                write!(
                    f,
                    "multiple native journal entries in one datagram are unsupported"
                )
            }
        }
    }
}

impl std::error::Error for NativeError {}

// Keep these in sync with src/shared/journal-importer.h.
pub const NATIVE_FIELD_NAME_MAX: usize = 64;
pub const DATA_SIZE_MAX: usize = 1024 * 1024 * 768;
pub const ENTRY_SIZE_MAX: usize = 1024 * 1024 * 770;
pub const ENTRY_FIELD_COUNT_MAX: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeEntry {
    pub name: Vec<u8>,
    pub payload: Vec<u8>,
    pub is_binary: bool,
}

impl NativeEntry {
    /// Convert the native wire representation into the byte string stored in a
    /// journal DATA object: `FIELD_NAME=VALUE`.
    pub fn into_journal_field(self) -> Result<Vec<u8>, NativeError> {
        let capacity = self
            .name
            .len()
            .checked_add(1)
            .and_then(|size| size.checked_add(self.payload.len()))
            .ok_or(NativeError::EntryTooLarge)?;
        if capacity > ENTRY_SIZE_MAX {
            return Err(NativeError::EntryTooLarge);
        }

        let mut field = Vec::with_capacity(capacity);
        field.extend_from_slice(&self.name);
        field.push(b'=');
        field.extend_from_slice(&self.payload);
        Ok(field)
    }
}

#[derive(Debug, Clone)]
pub struct NativeMessage {
    pub entries: Vec<NativeEntry>,
}

fn memchr_byte(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

/// Parse one native protocol field. Returns `None` only for an empty buffer;
/// incomplete framing is rejected so callers cannot persist partial data.
pub fn parse_one_entry(data: &[u8]) -> Result<Option<(NativeEntry, usize)>, NativeError> {
    if data.is_empty() {
        return Ok(None);
    }

    let nl = memchr_byte(b'\n', data).ok_or(NativeError::Truncated)?;

    let first_line = &data[..nl];

    if let Some(eq) = memchr_byte(b'=', first_line) {
        let name_bytes = &first_line[..eq];
        if !is_valid_field_name_bytes(name_bytes) {
            return Err(NativeError::InvalidFieldName);
        }
        if first_line.len() > DATA_SIZE_MAX {
            return Err(NativeError::FieldTooLarge);
        }
        let payload = first_line[eq + 1..].to_vec();
        return Ok(Some((
            NativeEntry {
                name: name_bytes.to_vec(),
                payload,
                is_binary: false,
            },
            nl + 1,
        )));
    }

    // Binary field: name\n + 8-byte LE size + payload + \n
    if !is_valid_field_name_bytes(first_line) {
        return Err(NativeError::InvalidFieldName);
    }

    let size_start = nl.checked_add(1).ok_or(NativeError::EntryTooLarge)?;
    let payload_start = size_start
        .checked_add(core::mem::size_of::<u64>())
        .ok_or(NativeError::EntryTooLarge)?;
    let size_bytes = data
        .get(size_start..payload_start)
        .ok_or(NativeError::Truncated)?;
    let size_u64 = u64::from_le_bytes(size_bytes.try_into().map_err(|_| NativeError::Truncated)?);
    if size_u64 > DATA_SIZE_MAX as u64 {
        return Err(NativeError::FieldTooLarge);
    }
    let size = usize::try_from(size_u64).map_err(|_| NativeError::FieldTooLarge)?;
    let payload_end = payload_start
        .checked_add(size)
        .ok_or(NativeError::EntryTooLarge)?;
    let consumed = payload_end
        .checked_add(1)
        .ok_or(NativeError::EntryTooLarge)?;
    let payload = data
        .get(payload_start..payload_end)
        .ok_or(NativeError::Truncated)?
        .to_vec();
    let terminator = data.get(payload_end).ok_or(NativeError::Truncated)?;
    if *terminator != b'\n' {
        return Err(NativeError::MissingBinaryTerminator);
    }

    Ok(Some((
        NativeEntry {
            name: first_line.to_vec(),
            payload,
            is_binary: true,
        },
        consumed,
    )))
}

/// Parse one blank-line-delimited native journal entry.
///
/// The returned byte count includes the entry separator when one was present.
/// An empty entry marks the end of the datagram, matching
/// `manager_process_native_message()`'s stop condition.
fn parse_native_entry(data: &[u8]) -> Result<(NativeMessage, usize), NativeError> {
    let mut entries = Vec::new();
    let mut offset = 0;
    let mut entry_size = 0usize;

    while offset < data.len() {
        if data[offset] == b'\n' {
            offset += 1;
            break;
        }

        // journald-native.c ignores protocol control lines and comments.
        if matches!(data[offset], b'.' | b'#') {
            let line_len = memchr_byte(b'\n', &data[offset..]).ok_or(NativeError::Truncated)?;
            offset = offset
                .checked_add(line_len)
                .and_then(|next| next.checked_add(1))
                .ok_or(NativeError::EntryTooLarge)?;
            continue;
        }

        if entries.len() >= ENTRY_FIELD_COUNT_MAX {
            return Err(NativeError::TooManyFields);
        }

        let (entry, consumed) = parse_one_entry(&data[offset..])?.ok_or(NativeError::Truncated)?;
        let field_size = entry
            .name
            .len()
            .checked_add(1)
            .and_then(|size| size.checked_add(entry.payload.len()))
            .ok_or(NativeError::EntryTooLarge)?;
        entry_size = entry_size
            .checked_add(field_size)
            .ok_or(NativeError::EntryTooLarge)?;
        if entry_size > ENTRY_SIZE_MAX {
            return Err(NativeError::EntryTooLarge);
        }

        entries.push(entry);
        offset = offset
            .checked_add(consumed)
            .ok_or(NativeError::EntryTooLarge)?;
    }
    entry_size = entry_size
        .checked_add(entries.len())
        .and_then(|size| size.checked_add(1))
        .ok_or(NativeError::EntryTooLarge)?;
    if entry_size > ENTRY_SIZE_MAX {
        return Err(NativeError::EntryTooLarge);
    }

    Ok((NativeMessage { entries }, offset))
}

/// Parse a native datagram into independently framed journal entries.
///
/// Each result represents one blank-line-separated entry. A malformed entry
/// terminates the sequence after the preceding valid entries, so callers can
/// persist those earlier records without merging data from the malformed
/// entry into them.
pub fn parse_native_datagram(data: &[u8]) -> Vec<Result<NativeMessage, NativeError>> {
    let mut messages = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        match parse_native_entry(&data[offset..]) {
            Ok((message, consumed)) => {
                debug_assert!(consumed > 0);
                offset += consumed;

                if message.entries.is_empty() {
                    break;
                }

                messages.push(Ok(message));
            }
            Err(error) => {
                messages.push(Err(error));
                break;
            }
        }
    }

    messages
}

/// Parse a complete single native message.
///
/// This compatibility helper retains the old one-entry contract for the
/// native FD fuzz surface. Datagram consumers should use
/// [`parse_native_datagram`] so they can keep entries independent.
pub fn parse_native_message(data: &[u8]) -> Result<NativeMessage, NativeError> {
    let mut messages = parse_native_datagram(data).into_iter();
    let Some(first) = messages.next() else {
        return Ok(NativeMessage {
            entries: Vec::new(),
        });
    };
    let first = first?;

    if let Some(next) = messages.next() {
        return match next {
            Ok(_) => Err(NativeError::MultipleEntriesUnsupported),
            Err(error) => Err(error),
        };
    }

    Ok(first)
}

/// Fuzz entry point: parse the data and return the message.
pub fn process_native_data(data: &[u8]) -> Result<NativeMessage, NativeError> {
    parse_native_message(data)
}

/// Validate that a field name follows journald rules:
/// only uppercase ASCII alphanumerics and underscores, not starting with a digit or underscore.
pub fn is_valid_field_name(name: &str) -> bool {
    is_valid_field_name_bytes(name.as_bytes())
}

/// Match `journal_field_valid(..., false)` from journal-file.c.
pub fn is_valid_field_name_bytes(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > NATIVE_FIELD_NAME_MAX {
        return false;
    }
    if name[0] == b'_' || name[0].is_ascii_digit() {
        return false;
    }
    name.iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_text_entry() {
        let (entry, n) = parse_one_entry(b"MESSAGE=hello\n").unwrap().unwrap();
        assert_eq!(entry.name, b"MESSAGE");
        assert_eq!(entry.payload, b"hello");
        assert!(!entry.is_binary);
        assert_eq!(n, 14);
    }

    #[test]
    fn test_parse_binary_entry() {
        let mut buf = b"DATA\n".to_vec();
        buf.extend_from_slice(&4u64.to_le_bytes());
        buf.extend_from_slice(b"test");
        buf.push(b'\n');
        let (entry, n) = parse_one_entry(&buf).unwrap().unwrap();
        assert_eq!(entry.name, b"DATA");
        assert_eq!(entry.payload, b"test");
        assert!(entry.is_binary);
        assert_eq!(n, buf.len());
    }

    #[test]
    fn test_parse_empty() {
        assert!(parse_one_entry(b"").unwrap().is_none());
    }

    #[test]
    fn test_parse_incomplete() {
        assert_eq!(
            parse_one_entry(b"KEY=val").unwrap_err(),
            NativeError::Truncated
        );
    }

    #[test]
    fn test_parse_multiple_entries() {
        let data = b"A=1\nB=2\nC=3\n";
        let msg = parse_native_message(data).unwrap();
        assert_eq!(msg.entries.len(), 3);
        assert_eq!(msg.entries[0].name, "A");
        assert_eq!(msg.entries[2].payload, b"3");
    }

    #[test]
    fn test_process_native_data() {
        let data = b"SYSLOG_IDENTIFIER=test\nPRIORITY=6\n";
        let msg = process_native_data(data).unwrap();
        assert_eq!(msg.entries.len(), 2);
    }

    #[test]
    fn test_process_native_data_empty() {
        let msg = process_native_data(b"").unwrap();
        assert!(msg.entries.is_empty());
    }

    #[test]
    fn test_is_valid_field_name() {
        assert!(is_valid_field_name("MESSAGE"));
        assert!(is_valid_field_name("SYSLOG_IDENTIFIER"));
        assert!(is_valid_field_name("A1_B2"));
        assert!(!is_valid_field_name(""));
        assert!(!is_valid_field_name("_KEY"));
        assert!(!is_valid_field_name("1KEY"));
        assert!(!is_valid_field_name("key"));
        assert!(!is_valid_field_name("KEY-VAL"));
    }

    #[test]
    fn test_binary_entry_with_zero_size() {
        let mut buf = b"DATA\n".to_vec();
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.push(b'\n');
        let (entry, n) = parse_one_entry(&buf).unwrap().unwrap();
        assert!(entry.payload.is_empty());
        assert!(entry.is_binary);
        assert_eq!(n, buf.len());
    }

    #[test]
    fn test_empty_field_name_error() {
        assert_eq!(
            parse_one_entry(b"=value\n").unwrap_err(),
            NativeError::InvalidFieldName
        );
    }

    #[test]
    fn test_binary_payload_round_trips_arbitrary_bytes() {
        let payload = b"\0line one\nline two\r\t|%\xff";
        let mut buf = b"MESSAGE\n".to_vec();
        buf.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        buf.extend_from_slice(payload);
        buf.push(b'\n');

        let (entry, consumed) = parse_one_entry(&buf).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(
            entry.into_journal_field().unwrap(),
            [b"MESSAGE=".as_slice(), payload].concat()
        );
    }

    #[test]
    fn test_binary_payload_requires_newline_terminator() {
        let mut buf = b"MESSAGE\n".to_vec();
        buf.extend_from_slice(&3u64.to_le_bytes());
        buf.extend_from_slice(b"abc!");
        assert_eq!(
            parse_one_entry(&buf).unwrap_err(),
            NativeError::MissingBinaryTerminator
        );
    }

    #[test]
    fn test_binary_payload_rejects_truncation() {
        let mut buf = b"MESSAGE\n".to_vec();
        buf.extend_from_slice(&4u64.to_le_bytes());
        buf.extend_from_slice(b"abc");
        assert_eq!(parse_one_entry(&buf).unwrap_err(), NativeError::Truncated);
    }

    #[test]
    fn test_binary_payload_rejects_oversized_declared_length() {
        let mut buf = b"MESSAGE\n".to_vec();
        buf.extend_from_slice(&((DATA_SIZE_MAX as u64) + 1).to_le_bytes());
        assert_eq!(
            parse_one_entry(&buf).unwrap_err(),
            NativeError::FieldTooLarge
        );
    }

    #[test]
    fn test_invalid_field_names_fail_closed() {
        assert_eq!(
            parse_one_entry(b"_PID=1\n").unwrap_err(),
            NativeError::InvalidFieldName
        );
        assert_eq!(
            parse_one_entry(b"lower=value\n").unwrap_err(),
            NativeError::InvalidFieldName
        );
        assert_eq!(
            parse_one_entry(b"1FIELD=value\n").unwrap_err(),
            NativeError::InvalidFieldName
        );
    }

    #[test]
    fn test_field_name_length_matches_c_limit() {
        let valid_name = vec![b'A'; NATIVE_FIELD_NAME_MAX];
        assert!(is_valid_field_name_bytes(&valid_name));
        let invalid_name = vec![b'A'; NATIVE_FIELD_NAME_MAX + 1];
        assert!(!is_valid_field_name_bytes(&invalid_name));
    }

    #[test]
    fn test_field_count_limit_is_checked() {
        let mut payload = b"A=1\n".repeat(ENTRY_FIELD_COUNT_MAX);
        assert_eq!(
            parse_native_message(&payload).unwrap().entries.len(),
            ENTRY_FIELD_COUNT_MAX
        );
        payload.extend_from_slice(b"A=1\n");
        assert_eq!(
            parse_native_message(&payload).unwrap_err(),
            NativeError::TooManyFields
        );
    }

    #[test]
    fn test_control_and_comment_lines_are_ignored() {
        let message = parse_native_message(b"# comment\n.flush\nMESSAGE=hello\n").unwrap();
        assert_eq!(message.entries.len(), 1);
        assert_eq!(message.entries[0].name, b"MESSAGE");
    }

    #[test]
    fn test_trailing_entry_separator_is_accepted() {
        let message = parse_native_message(b"MESSAGE=hello\n\n").unwrap();
        assert_eq!(message.entries.len(), 1);
    }

    #[test]
    fn test_multiple_entries_remain_independent_in_a_datagram() {
        let messages = parse_native_datagram(b"MESSAGE=one\n\nMESSAGE=two\n");
        assert_eq!(messages.len(), 2);
        assert_eq!(
            messages[0].as_ref().unwrap().entries[0]
                .clone()
                .into_journal_field()
                .unwrap(),
            b"MESSAGE=one"
        );
        assert_eq!(
            messages[1].as_ref().unwrap().entries[0]
                .clone()
                .into_journal_field()
                .unwrap(),
            b"MESSAGE=two"
        );
    }

    #[test]
    fn test_malformed_later_entry_does_not_discard_earlier_entry() {
        let messages = parse_native_datagram(b"MESSAGE=one\n\nMESSAGE=two");
        assert_eq!(messages.len(), 2);
        assert_eq!(
            messages[0].as_ref().unwrap().entries[0]
                .clone()
                .into_journal_field()
                .unwrap(),
            b"MESSAGE=one"
        );
        assert_eq!(messages[1].as_ref().unwrap_err(), &NativeError::Truncated);
    }

    #[test]
    fn test_single_message_compatibility_helper_rejects_multiple_entries() {
        assert_eq!(
            parse_native_message(b"MESSAGE=one\n\nMESSAGE=two\n").unwrap_err(),
            NativeError::MultipleEntriesUnsupported
        );
    }
}
