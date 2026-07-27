// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/journal/fuzz-journald-audit.c
//
// Audit-message parsing and fuzz harness.
//
// The C version creates a dummy `Manager`, feeds the raw bytes into
// `process_audit_string()`, and returns.  This Rust port provides a
// safe parser for the same audit-string format so the logic can be
// tested without the full journald infrastructure.

// ── Error type ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    /// Input data could not be interpreted as valid UTF-8.
    InvalidUtf8,
    /// The audit header (e.g. `audit(…):`) is missing or malformed.
    MissingHeader,
    /// A key=value field could not be parsed.
    MalformedField,
}

impl core::fmt::Display for AuditError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuditError::InvalidUtf8 => write!(f, "invalid UTF-8 in audit data"),
            AuditError::MissingHeader => write!(f, "missing or malformed audit header"),
            AuditError::MalformedField => write!(f, "malformed key=value field"),
        }
    }
}

impl std::error::Error for AuditError {}

// ── Parsed audit message ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditMessage {
    /// The numeric audit type (0 if absent).
    pub audit_type: u32,
    /// Key-value pairs extracted from the message body.
    pub fields: Vec<(String, String)>,
    /// The raw message text after the header.
    pub body: String,
}

// ── Parsing ──────────────────────────────────────────────────────────────

/// Parse a kernel audit string.
///
/// Typical format:
/// ```text
/// audit(1234567890.123:456): field1=value1 field2=value2
/// ```
///
/// The function is deliberately lenient (as the C fuzz target is): it
/// tries to extract as much structure as possible without failing on
/// unexpected input.
pub fn parse_audit_string(data: &[u8]) -> Result<AuditMessage, AuditError> {
    let text = std::str::from_utf8(data).map_err(|_| AuditError::InvalidUtf8)?;

    // Try to find the audit header: audit(…):
    let body = match extract_audit_body(text) {
        Some(b) => b,
        None => {
            // No header found — treat the entire text as body.
            return Ok(AuditMessage {
                audit_type: 0,
                fields: vec![],
                body: text.to_string(),
            });
        }
    };

    let fields = parse_fields(body);
    Ok(AuditMessage {
        audit_type: 0,
        fields,
        body: body.to_string(),
    })
}

/// Locate the body text after the `audit(timestamp:serial):` header.
fn extract_audit_body(text: &str) -> Option<&str> {
    let start = text.find("audit(")?;
    let close_paren = text[start..].find("):")?;
    let body_start = start + close_paren + 2;
    Some(text[body_start..].trim_start())
}

/// Parse whitespace-separated `key=value` fields.
fn parse_fields(body: &str) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    for token in body.split_whitespace() {
        if let Some((k, v)) = token.split_once('=') {
            fields.push((k.to_string(), v.to_string()));
        }
    }
    fields
}

/// Process audit data (fuzz target entry point).
/// Returns `Ok(())` on success, or an error if the input is fundamentally
/// invalid (non-UTF-8).  Malformed audit formatting is not an error —
/// the parser is lenient, matching the C behaviour.
pub fn process_audit_data(data: &[u8]) -> Result<(), AuditError> {
    let text = std::str::from_utf8(data).map_err(|_| AuditError::InvalidUtf8)?;

    // Best-effort parse: we never fail on malformed audit content.
    if let Some(body) = extract_audit_body(text) {
        let _ = parse_fields(body);
    }

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_audit_string_basic() {
        let msg = parse_audit_string(b"audit(1234567890.123:456): uid=1000 gid=1000").unwrap();
        assert!(!msg.body.is_empty());
        assert_eq!(msg.fields.len(), 2);
        assert_eq!(msg.fields[0], ("uid".into(), "1000".into()));
        assert_eq!(msg.fields[1], ("gid".into(), "1000".into()));
    }

    #[test]
    fn test_parse_audit_string_no_header() {
        let msg = parse_audit_string(b"just some text").unwrap();
        assert_eq!(msg.body, "just some text");
        assert!(msg.fields.is_empty());
    }

    #[test]
    fn test_parse_audit_string_invalid_utf8() {
        let result = parse_audit_string(&[0xFF, 0xFE]);
        assert_eq!(result.unwrap_err(), AuditError::InvalidUtf8);
    }

    #[test]
    fn test_process_audit_data_valid() {
        assert!(process_audit_data(b"audit(1.2:3): key=val").is_ok());
    }

    #[test]
    fn test_process_audit_data_empty() {
        assert!(process_audit_data(b"").is_ok());
    }

    #[test]
    fn test_process_audit_data_invalid_utf8() {
        assert!(process_audit_data(&[0x80, 0x81]).is_err());
    }

    #[test]
    fn test_parse_fields() {
        let fields = parse_fields("a=1 b=2 c=hello");
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].1, "1");
        assert_eq!(fields[2].1, "hello");
    }

    #[test]
    fn test_parse_fields_no_equals() {
        let fields = parse_fields("nokey justtext a=1");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, "a");
    }

    #[test]
    fn test_extract_audit_body() {
        let body = extract_audit_body("audit(1:2): stuff here");
        assert_eq!(body, Some("stuff here"));
    }

    #[test]
    fn test_extract_audit_body_missing() {
        let body = extract_audit_body("no audit header");
        assert_eq!(body, None);
    }

    #[test]
    fn test_audit_message_body_with_special_chars() {
        let data = b"audit(0:0): msg='test\x01\x02\x03'";
        let result = parse_audit_string(data);
        assert!(result.is_ok());
    }
}
