// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/fuzz-journald-kmsg.c
//
// Kernel message (kmsg) record parsing and fuzz harness.
//
// The C version creates a dummy Manager and feeds bytes into
// `dev_kmsg_record()`.  This Rust port provides a safe parser for
// the /dev/kmsg record format.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KmsgError {
    InvalidUtf8,
    MissingHeader,
    InvalidPriority,
    InvalidSequence,
    InvalidTimestamp,
}

impl core::fmt::Display for KmsgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KmsgError::InvalidUtf8 => write!(f, "invalid UTF-8 in kmsg data"),
            KmsgError::MissingHeader => write!(f, "missing kmsg header"),
            KmsgError::InvalidPriority => write!(f, "invalid priority value"),
            KmsgError::InvalidSequence => write!(f, "invalid sequence number"),
            KmsgError::InvalidTimestamp => write!(f, "invalid timestamp"),
        }
    }
}

impl std::error::Error for KmsgError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsgRecord {
    pub priority: u32,
    pub sequence: u64,
    pub timestamp_us: u64,
    pub message: String,
}

/// Parse a single `/dev/kmsg` record line.
///
/// Format: `priority,sequence,timestamp,-;message\n`
///
/// Returns `Ok(record)` on success or an error if the header is
/// fundamentally unparseable.  Empty input returns `Ok(None)`.
pub fn parse_kmsg_record(data: &[u8]) -> Result<Option<KmsgRecord>, KmsgError> {
    if data.is_empty() {
        return Ok(None);
    }

    if !data.ends_with(b"\n") {
        return Err(KmsgError::MissingHeader);
    }

    let text = std::str::from_utf8(data).map_err(|_| KmsgError::InvalidUtf8)?;

    let semicolon_pos = match text.find(';') {
        Some(p) => p,
        None => return Err(KmsgError::MissingHeader),
    };

    let header = &text[..semicolon_pos];
    let message = text[semicolon_pos + 1..].trim_end_matches('\n').to_string();

    let mut header_parts = header.splitn(4, ',');
    let priority_str = header_parts.next().unwrap_or("");
    let sequence_str = header_parts.next().unwrap_or("");
    let timestamp_str = header_parts.next().unwrap_or("");

    let priority: u32 = priority_str
        .parse()
        .map_err(|_| KmsgError::InvalidPriority)?;

    if priority > 191 {
        return Err(KmsgError::InvalidPriority);
    }

    let sequence: u64 = sequence_str
        .parse()
        .map_err(|_| KmsgError::InvalidSequence)?;

    let timestamp_us: u64 = timestamp_str
        .parse()
        .map_err(|_| KmsgError::InvalidTimestamp)?;

    Ok(Some(KmsgRecord {
        priority,
        sequence,
        timestamp_us,
        message,
    }))
}

/// Process kmsg data (fuzz entry point).  Returns `Ok(())` when
/// parsing succeeds or the input is empty.  Malformed content
/// returns the specific error.
pub fn process_kmsg_data(data: &[u8]) -> Result<Option<KmsgRecord>, KmsgError> {
    if data.is_empty() {
        return Ok(None);
    }
    parse_kmsg_record(data)
}

/// Extract the facility from a syslog-style priority value.
/// Facility = priority / 8.
pub fn facility_from_priority(priority: u32) -> u8 {
    (priority / 8) as u8
}

/// Extract the severity from a syslog-style priority value.
/// Severity = priority % 8.
pub fn severity_from_priority(priority: u32) -> u8 {
    (priority % 8) as u8
}

/// Severity level names (RFC 5424).
pub const SEVERITY_NAMES: &[&str] = &[
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
];

/// Get the severity name for a priority value.
pub fn severity_name(priority: u32) -> &'static str {
    SEVERITY_NAMES[(priority % 8) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kmsg_record_basic() {
        let rec = parse_kmsg_record(b"6,1234,567890,-;Hello world\n")
            .unwrap()
            .unwrap();
        assert_eq!(rec.priority, 6);
        assert_eq!(rec.sequence, 1234);
        assert_eq!(rec.timestamp_us, 567890);
        assert_eq!(rec.message, "Hello world");
    }

    #[test]
    fn test_parse_kmsg_record_no_newline_is_rejected() {
        assert_eq!(
            parse_kmsg_record(b"3,99,1000,-;test").unwrap_err(),
            KmsgError::MissingHeader
        );
    }

    #[test]
    fn test_parse_kmsg_record_empty() {
        assert!(parse_kmsg_record(b"").unwrap().is_none());
    }

    #[test]
    fn test_parse_kmsg_record_invalid_utf8() {
        assert_eq!(
            parse_kmsg_record(&[0xFF, 0xFE, b'\n']).unwrap_err(),
            KmsgError::InvalidUtf8
        );
    }

    #[test]
    fn test_parse_kmsg_record_no_semicolon() {
        assert_eq!(
            parse_kmsg_record(b"6,1234,5678,-").unwrap_err(),
            KmsgError::MissingHeader
        );
    }

    #[test]
    fn test_parse_kmsg_record_bad_priority() {
        assert_eq!(
            parse_kmsg_record(b"200,1,2,-;msg\n").unwrap_err(),
            KmsgError::InvalidPriority
        );
    }

    #[test]
    fn test_parse_kmsg_record_non_numeric_priority() {
        assert_eq!(
            parse_kmsg_record(b"abc,1,2,-;msg\n").unwrap_err(),
            KmsgError::InvalidPriority
        );
    }

    #[test]
    fn test_facility_from_priority() {
        assert_eq!(facility_from_priority(0), 0);
        assert_eq!(facility_from_priority(6), 0);
        assert_eq!(facility_from_priority(8), 1);
        assert_eq!(facility_from_priority(23), 2);
        assert_eq!(facility_from_priority(191), 23);
    }

    #[test]
    fn test_severity_from_priority() {
        assert_eq!(severity_from_priority(0), 0);
        assert_eq!(severity_from_priority(7), 7);
        assert_eq!(severity_from_priority(8), 0);
        assert_eq!(severity_from_priority(14), 6);
    }

    #[test]
    fn test_severity_name() {
        assert_eq!(severity_name(0), "emerg");
        assert_eq!(severity_name(6), "info");
        assert_eq!(severity_name(7), "debug");
        assert_eq!(severity_name(8), "emerg");
    }

    #[test]
    fn test_process_kmsg_data_empty() {
        assert!(process_kmsg_data(b"").unwrap().is_none());
    }

    #[test]
    fn test_process_kmsg_data_valid() {
        let rec = process_kmsg_data(b"1,0,0,-;kernel msg\n").unwrap().unwrap();
        assert_eq!(rec.priority, 1);
    }
}
