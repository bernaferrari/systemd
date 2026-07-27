// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/fuzz-journald-syslog.c
//
// Syslog message parsing and fuzz harness.
//
// The C version calls `fuzz_journald_processing_function(data, size,
// manager_process_syslog_message)`.  This Rust port provides a safe
// parser for RFC 5424 / RFC 3164 syslog messages.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyslogError {
    InvalidUtf8,
    MissingPriority,
    BadPriorityValue,
    PriorityOverflow,
}

impl core::fmt::Display for SyslogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SyslogError::InvalidUtf8 => write!(f, "invalid UTF-8 in syslog data"),
            SyslogError::MissingPriority => write!(f, "missing PRI field"),
            SyslogError::BadPriorityValue => write!(f, "bad priority value"),
            SyslogError::PriorityOverflow => write!(f, "priority value out of range"),
        }
    }
}

impl std::error::Error for SyslogError {}

/// Maximum valid syslog priority value (RFC 5424: 0–191).
pub const SYSLOG_PRIORITY_MAX: u8 = 191;

/// Syslog severity levels (RFC 5424 Table 2).
pub const SYSLOG_SEVERITY_NAMES: &[&str] = &[
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "informational",
    "debug",
];

/// Syslog facility codes (subset from RFC 5424).
pub const SYSLOG_FACILITY_NAMES: &[&str] = &[
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4",
    "local5", "local6", "local7",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogMessage {
    pub priority: u8,
    pub facility: u8,
    pub severity: u8,
    pub content: String,
}

/// Parse a syslog PRI field: `<priority>content`.
///
/// Returns the parsed message on success.
pub fn parse_syslog_message(data: &[u8]) -> Result<SyslogMessage, SyslogError> {
    if data.is_empty() {
        return Err(SyslogError::MissingPriority);
    }

    let mut start = 0usize;
    while start < data.len() && data[start].is_ascii_whitespace() {
        start += 1;
    }
    if start >= data.len() || data[start] != b'<' {
        return Err(SyslogError::MissingPriority);
    }

    let rest = &data[start + 1..];
    let close_pos = match rest.iter().position(|b| *b == b'>') {
        Some(p) => p,
        None => return Err(SyslogError::MissingPriority),
    };

    let prio_str =
        std::str::from_utf8(&rest[..close_pos]).map_err(|_| SyslogError::BadPriorityValue)?;
    let priority: u8 = prio_str
        .parse()
        .map_err(|_| SyslogError::BadPriorityValue)?;

    if priority > SYSLOG_PRIORITY_MAX {
        return Err(SyslogError::PriorityOverflow);
    }

    let content = String::from_utf8_lossy(&rest[close_pos + 1..]).into_owned();
    let facility = priority / 8;
    let severity = priority % 8;

    Ok(SyslogMessage {
        priority,
        facility,
        severity,
        content,
    })
}

/// Get the severity name for a syslog priority value.
pub fn severity_name(priority: u8) -> &'static str {
    SYSLOG_SEVERITY_NAMES[(priority % 8) as usize]
}

/// Get the facility name for a syslog priority value.
pub fn facility_name(priority: u8) -> &'static str {
    let idx = (priority / 8) as usize;
    if idx < SYSLOG_FACILITY_NAMES.len() {
        SYSLOG_FACILITY_NAMES[idx]
    } else {
        "unknown"
    }
}

/// Process syslog data (fuzz entry point).
pub fn process_syslog_data(data: &[u8]) -> Result<SyslogMessage, SyslogError> {
    parse_syslog_message(data)
}

/// Try to parse an RFC 3164 timestamp from the start of *text*.
/// Format: `Mmm dd hh:mm:ss ` (15 characters).
/// Returns (timestamp_str, remaining_text) or None.
pub fn try_parse_rfc3164_timestamp(text: &str) -> Option<(&str, &str)> {
    if text.len() < 16 {
        return None;
    }
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month = &text[0..3];
    if !months.contains(&month) {
        return None;
    }
    let b = text.as_bytes();
    if b[3] != b' ' {
        return None;
    }

    if !(b[4].is_ascii_digit() || b[4] == b' ') || !b[5].is_ascii_digit() {
        return None;
    }
    if b[6] != b' ' {
        return None;
    }
    if !b[7].is_ascii_digit() || !b[8].is_ascii_digit() {
        return None;
    }
    if b[9] != b':' {
        return None;
    }
    if !b[10].is_ascii_digit() || !b[11].is_ascii_digit() {
        return None;
    }
    if b[12] != b':' {
        return None;
    }
    if !b[13].is_ascii_digit() || !b[14].is_ascii_digit() {
        return None;
    }
    if b[15] != b' ' {
        return None;
    }
    Some((&text[..16], &text[16..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_syslog() {
        let msg = parse_syslog_message(b"<6>hello world").unwrap();
        assert_eq!(msg.priority, 6);
        assert_eq!(msg.facility, 0);
        assert_eq!(msg.severity, 6);
        assert_eq!(msg.content, "hello world");
    }

    #[test]
    fn test_parse_user_notice() {
        let msg = parse_syslog_message(b"<13>test message").unwrap();
        assert_eq!(msg.priority, 13);
        assert_eq!(msg.facility, 1);
        assert_eq!(msg.severity, 5);
    }

    #[test]
    fn test_parse_empty_content() {
        let msg = parse_syslog_message(b"<0>").unwrap();
        assert_eq!(msg.priority, 0);
        assert_eq!(msg.content, "");
    }

    #[test]
    fn test_parse_missing_pri() {
        assert_eq!(
            parse_syslog_message(b"no priority").unwrap_err(),
            SyslogError::MissingPriority
        );
    }

    #[test]
    fn test_parse_empty_input() {
        assert_eq!(
            parse_syslog_message(b"").unwrap_err(),
            SyslogError::MissingPriority
        );
    }

    #[test]
    fn test_parse_invalid_utf8() {
        let msg = parse_syslog_message(b"<6>\xFFmsg").unwrap();
        assert_eq!(msg.priority, 6);
        assert_eq!(msg.content, "\u{FFFD}msg");
    }

    #[test]
    fn test_parse_bad_priority() {
        assert_eq!(
            parse_syslog_message(b"<abc>msg").unwrap_err(),
            SyslogError::BadPriorityValue
        );
    }

    #[test]
    fn test_parse_priority_overflow() {
        assert_eq!(
            parse_syslog_message(b"<200>msg").unwrap_err(),
            SyslogError::PriorityOverflow
        );
    }

    #[test]
    fn test_severity_name() {
        assert_eq!(severity_name(0), "emergency");
        assert_eq!(severity_name(6), "informational");
        assert_eq!(severity_name(7), "debug");
    }

    #[test]
    fn test_facility_name() {
        assert_eq!(facility_name(0), "kern");
        assert_eq!(facility_name(8), "user");
        assert_eq!(facility_name(23 * 8), "local7");
        assert_eq!(facility_name(192), "unknown");
    }

    #[test]
    fn test_rfc3164_timestamp_valid() {
        let (ts, rest) = try_parse_rfc3164_timestamp("Jan 01 12:00:00 hello").unwrap();
        assert_eq!(ts, "Jan 01 12:00:00 ");
        assert_eq!(rest, "hello");
    }

    #[test]
    fn test_rfc3164_timestamp_invalid_month() {
        assert!(try_parse_rfc3164_timestamp("Xyz 01 12:00:00 hello").is_none());
    }

    #[test]
    fn test_rfc3164_timestamp_too_short() {
        assert!(try_parse_rfc3164_timestamp("Jan").is_none());
    }

    #[test]
    fn test_process_syslog_data() {
        let msg = process_syslog_data(b"<165>program[pid]: message").unwrap();
        assert_eq!(msg.priority, 165);
        assert_eq!(msg.content, "program[pid]: message");
    }

    #[test]
    fn test_parse_priority_after_leading_whitespace() {
        let msg = parse_syslog_message(b"   <13>hello").unwrap();
        assert_eq!(msg.priority, 13);
        assert_eq!(msg.content, "hello");
    }
}
