// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/notify-recv.c, src/shared/notify-recv.h
//
// sd_notify() message receiving and parsing.
//
// Handles reception and parsing of service notification messages sent over
// $NOTIFY_SOCKET (AF_UNIX datagram sockets). Notifications follow the
// newline-separated KEY=VALUE format defined by sd_notify(3). This module
// provides the core receive/parse logic; socket setup (event source
// registration) is done by the C side via sd-event.

use crate::ffi::*;
use std::collections::HashMap;
use std::io;
use std::os::unix::net::UnixDatagram;

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum payload size of a single notification datagram (matches PIPE_BUF).
pub const NOTIFY_BUFFER_MAX: usize = 4096;

/// Maximum number of file descriptors that may accompany a notification.
pub const NOTIFY_FD_MAX: usize = 768;

// ── Well-known notification field names ───────────────────────────────────

/// Recognized sd_notify() variable names.
pub mod field {
    pub const READY: &str = "READY";
    pub const RELOADING: &str = "RELOADING";
    pub const STOPPING: &str = "STOPPING";
    pub const STATUS: &str = "STATUS";
    pub const ERRNO: &str = "ERRNO";
    pub const ERRNO_NAME: &str = "ERRNO_NAME";
    pub const BUS_ERROR: &str = "BUS_ERROR";
    pub const MAINPID: &str = "MAINPID";
    pub const WATCHDOG: &str = "WATCHDOG";
    pub const WATCHDOG_USEC: &str = "WATCHDOG_USEC";
    pub const FDSTORE: &str = "FDSTORE";
    pub const FDSTOREREMOVE: &str = "FDSTOREREMOVE";
    pub const FDNAME: &str = "FDNAME";
    pub const FDPID: &str = "FDPID";
    pub const LISTEN_FDS: &str = "LISTEN_FDS";
    pub const LISTEN_PID: &str = "LISTEN_PID";
    pub const MONOTONIC_USEC: &str = "MONOTONIC_USEC";
    pub const BOUNDARY: &str = "BOUNDARY";
    pub const EXTEND_TIMEOUT_USEC: &str = "EXTEND_TIMEOUT_USEC";
}

// ── Error types ───────────────────────────────────────────────────────────

/// Errors produced during notification message receiving and parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyError {
    /// The notification datagram payload is not valid UTF-8.
    InvalidUtf8,
    /// An embedded NUL byte was found in the notification text (before the trailing NUL).
    EmbeddedNul,
    /// The message payload is empty.
    EmptyPayload,
    /// I/O error receiving from the socket.
    Io(io::ErrorKind),
}

impl std::fmt::Display for NotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotifyError::InvalidUtf8 => write!(f, "notification payload is not valid UTF-8"),
            NotifyError::EmbeddedNul => {
                write!(f, "notification message contains embedded NUL byte")
            }
            NotifyError::EmptyPayload => write!(f, "notification payload is empty"),
            NotifyError::Io(kind) => write!(f, "I/O error receiving notification: {kind}"),
        }
    }
}

impl std::error::Error for NotifyError {}

impl From<io::Error> for NotifyError {
    fn from(err: io::Error) -> Self {
        NotifyError::Io(err.kind())
    }
}

// ── NotificationMessage ──────────────────────────────────────────────────

/// A parsed sd_notify() message.
///
/// Contains the raw notification text and a map of the KEY=VALUE fields
/// extracted from it. Fields are separated by newlines; each line has the
/// form `KEY=VALUE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationMessage {
    /// The full raw notification text (newline-separated fields).
    pub text: String,
    /// Parsed KEY=VALUE map extracted from the text.
    pub fields: HashMap<String, String>,
}

impl NotificationMessage {
    /// Parse a raw notification string into a [`NotificationMessage`].
    ///
    /// Splits the text on newlines and extracts `KEY=VALUE` pairs.
    /// Lines without an `=` sign are silently skipped.
    pub fn parse(text: String) -> Self {
        let mut fields = HashMap::new();
        for line in text.lines() {
            if let Some((k, v)) = line.split_once('=') {
                fields.insert(k.to_string(), v.to_string());
            }
        }
        Self { text, fields }
    }

    /// Check whether the message signals service readiness (`READY=1`).
    pub fn is_ready(&self) -> bool {
        self.fields.get(field::READY) == Some(&"1".to_string())
    }

    /// Check whether the message signals service reload (`RELOADING=1`).
    pub fn is_reloading(&self) -> bool {
        self.fields.get(field::RELOADING) == Some(&"1".to_string())
    }

    /// Check whether the message signals service stop (`STOPPING=1`).
    pub fn is_stopping(&self) -> bool {
        self.fields.get(field::STOPPING) == Some(&"1".to_string())
    }

    /// Check whether the message is a watchdog keepalive ping (`WATCHDOG=1`).
    pub fn is_watchdog(&self) -> bool {
        self.fields.get(field::WATCHDOG) == Some(&"1".to_string())
    }

    /// Return the `STATUS=` value, if present.
    pub fn status(&self) -> Option<&str> {
        self.fields.get(field::STATUS).map(String::as_str)
    }

    /// Return the `ERRNO=` value as an `i32`, if present and parseable.
    pub fn errno(&self) -> Option<i32> {
        self.fields.get(field::ERRNO).and_then(|v| v.parse().ok())
    }

    /// Return the `MAINPID=` value as a `u32`, if present and parseable.
    pub fn main_pid(&self) -> Option<u32> {
        self.fields.get(field::MAINPID).and_then(|v| v.parse().ok())
    }

    /// Return the `WATCHDOG_USEC=` value as a `u64`, if present and parseable.
    pub fn watchdog_usec(&self) -> Option<u64> {
        self.fields
            .get(field::WATCHDOG_USEC)
            .and_then(|v| v.parse().ok())
    }

    /// Return the `MONOTONIC_USEC=` value as a `u64`, if present and parseable.
    pub fn monotonic_usec(&self) -> Option<u64> {
        self.fields
            .get(field::MONOTONIC_USEC)
            .and_then(|v| v.parse().ok())
    }

    /// Return the `FDNAME=` value, if present.
    pub fn fdname(&self) -> Option<&str> {
        self.fields.get(field::FDNAME).map(String::as_str)
    }

    /// Return the `EXTEND_TIMEOUT_USEC=` value as a `u64`, if present and parseable.
    pub fn extend_timeout_usec(&self) -> Option<u64> {
        self.fields
            .get(field::EXTEND_TIMEOUT_USEC)
            .and_then(|v| v.parse().ok())
    }

    /// Return the `ERRNO_NAME=` value, if present.
    pub fn errno_name(&self) -> Option<&str> {
        self.fields.get(field::ERRNO_NAME).map(String::as_str)
    }

    /// Return the `BUS_ERROR=` value, if present.
    pub fn bus_error(&self) -> Option<&str> {
        self.fields.get(field::BUS_ERROR).map(String::as_str)
    }

    /// Return the `FDSTORE=` value as a boolean (`"1"` → true).
    pub fn is_fdstore(&self) -> bool {
        self.fields.get(field::FDSTORE) == Some(&"1".to_string())
    }

    /// Return the `FDSTOREREMOVE=` value as a boolean (`"1"` → true).
    pub fn is_fdstore_remove(&self) -> bool {
        self.fields.get(field::FDSTOREREMOVE) == Some(&"1".to_string())
    }
}

// ── Receiving ─────────────────────────────────────────────────────────────

/// Receive a single notification datagram from a bound Unix datagram socket.
///
/// Reads up to [`NOTIFY_BUFFER_MAX`] bytes, validates UTF-8, checks for
/// embedded NUL bytes (matching the C implementation's safety check), and
/// parses the result into a [`NotificationMessage`].
pub fn notify_recv(socket: &UnixDatagram) -> Result<NotificationMessage, NotifyError> {
    let mut buf = vec![0_u8; NOTIFY_BUFFER_MAX];
    let n = socket.recv(&mut buf)?;
    if n == 0 {
        return Err(NotifyError::EmptyPayload);
    }
    buf.truncate(n);

    // Reject embedded NUL bytes (a trailing NUL is tolerated — trimmed below).
    // The C code checks: memchr(buf, 0, n - 1) for n > 1.
    if n > 1 && buf[..n.saturating_sub(1)].contains(&0) {
        return Err(NotifyError::EmbeddedNul);
    }

    let text = String::from_utf8(buf).map_err(|_| NotifyError::InvalidUtf8)?;
    Ok(NotificationMessage::parse(
        text.trim_end_matches('\0').to_string(),
    ))
}

/// Parse a notification text string into a vector of `KEY=VALUE` lines.
///
/// Equivalent to `strv_split_newlines` in the C code — splits on `\n`
/// and returns a vector of the individual field strings.
pub fn notify_split_fields(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| !line.is_empty())
        .map(String::from)
        .collect()
}

// ── Validation helpers ────────────────────────────────────────────────────

/// Validate that a raw byte buffer contains no embedded NUL bytes
/// (except possibly one trailing NUL).
///
/// Returns `Ok(())` if the buffer is valid, `Err(NotifyError::EmbeddedNul)` otherwise.
pub fn validate_no_embedded_nul(buf: &[u8]) -> Result<(), NotifyError> {
    if buf.len() > 1 && buf[..buf.len() - 1].contains(&0) {
        Err(NotifyError::EmbeddedNul)
    } else {
        Ok(())
    }
}

/// Strip a single optional trailing NUL byte from a byte slice and convert to String.
///
/// Returns an error if the bytes (after trimming) are not valid UTF-8.
pub fn bytes_to_notify_string(buf: &[u8]) -> Result<String, NotifyError> {
    let trimmed = buf
        .iter()
        .copied()
        .rev()
        .skip_while(|&b| b == 0)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    String::from_utf8(trimmed).map_err(|_| NotifyError::InvalidUtf8)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse ──

    #[test]
    fn test_parse_ready() {
        let msg = NotificationMessage::parse("READY=1".to_string());
        assert!(msg.is_ready());
        assert_eq!(msg.text, "READY=1");
    }

    #[test]
    fn test_parse_multiple_fields() {
        let text = "READY=1\nSTATUS=Running\nMAINPID=1234";
        let msg = NotificationMessage::parse(text.to_string());
        assert!(msg.is_ready());
        assert_eq!(msg.status(), Some("Running"));
        assert_eq!(msg.main_pid(), Some(1234));
        assert_eq!(msg.fields.len(), 3);
    }

    #[test]
    fn test_parse_empty_string() {
        let msg = NotificationMessage::parse(String::new());
        assert!(!msg.is_ready());
        assert!(msg.fields.is_empty());
    }

    #[test]
    fn test_parse_lines_without_equals() {
        let msg = NotificationMessage::parse("bare_line\nREADY=1".to_string());
        assert!(msg.is_ready());
        // bare_line is silently skipped
        assert_eq!(msg.fields.len(), 1);
    }

    #[test]
    fn test_parse_key_with_empty_value() {
        let msg = NotificationMessage::parse("STATUS=".to_string());
        assert_eq!(msg.status(), Some(""));
        assert!(msg.fields.contains_key("STATUS"));
    }

    #[test]
    fn test_parse_value_with_equals() {
        let msg = NotificationMessage::parse("STATUS=a=b".to_string());
        assert_eq!(msg.status(), Some("a=b"));
    }

    // ── field accessors ──

    #[test]
    fn test_is_reloading() {
        let msg = NotificationMessage::parse("RELOADING=1".to_string());
        assert!(msg.is_reloading());
    }

    #[test]
    fn test_is_stopping() {
        let msg = NotificationMessage::parse("STOPPING=1".to_string());
        assert!(msg.is_stopping());
    }

    #[test]
    fn test_is_watchdog() {
        let msg = NotificationMessage::parse("WATCHDOG=1".to_string());
        assert!(msg.is_watchdog());
    }

    #[test]
    fn test_errno_parsing() {
        let msg = NotificationMessage::parse("ERRNO=2\nERRNO_NAME=ENOENT".to_string());
        assert_eq!(msg.errno(), Some(2));
        assert_eq!(msg.errno_name(), Some("ENOENT"));
    }

    #[test]
    fn test_errno_invalid() {
        let msg = NotificationMessage::parse("ERRNO=not_a_number".to_string());
        assert_eq!(msg.errno(), None);
    }

    #[test]
    fn test_watchdog_usec() {
        let msg = NotificationMessage::parse("WATCHDOG_USEC=30000000".to_string());
        assert_eq!(msg.watchdog_usec(), Some(30_000_000));
    }

    #[test]
    fn test_monotonic_usec() {
        let msg = NotificationMessage::parse("MONOTONIC_USEC=12345678".to_string());
        assert_eq!(msg.monotonic_usec(), Some(12_345_678));
    }

    #[test]
    fn test_fdname() {
        let msg = NotificationMessage::parse("FDSTORE=1\nFDNAME=my-socket".to_string());
        assert!(msg.is_fdstore());
        assert_eq!(msg.fdname(), Some("my-socket"));
    }

    #[test]
    fn test_extend_timeout_usec() {
        let msg = NotificationMessage::parse("EXTEND_TIMEOUT_USEC=5000000".to_string());
        assert_eq!(msg.extend_timeout_usec(), Some(5_000_000));
    }

    #[test]
    fn test_fdstore_remove() {
        let msg = NotificationMessage::parse("FDSTOREREMOVE=1\nFDNAME=foo".to_string());
        assert!(msg.is_fdstore_remove());
    }

    #[test]
    fn test_bus_error() {
        let msg =
            NotificationMessage::parse("ERRNO=5\nBUS_ERROR=org.freedesktop.DBus.Error".to_string());
        assert_eq!(msg.errno(), Some(5));
        assert_eq!(msg.bus_error(), Some("org.freedesktop.DBus.Error"));
    }

    // ── validation ──

    #[test]
    fn test_validate_no_embedded_nul_clean() {
        assert!(validate_no_embedded_nul(b"READY=1").is_ok());
    }

    #[test]
    fn test_validate_no_embedded_nul_trailing() {
        assert!(validate_no_embedded_nul(b"READY=1\0").is_ok());
    }

    #[test]
    fn test_validate_no_embedded_nul_embedded() {
        assert!(validate_no_embedded_nul(b"READY=\x001").is_err());
    }

    #[test]
    fn test_validate_no_embedded_nul_single_byte() {
        // Single byte is always ok (n <= 1)
        assert!(validate_no_embedded_nul(b"\0").is_ok());
    }

    #[test]
    fn test_validate_no_embedded_nul_empty() {
        assert!(validate_no_embedded_nul(b"").is_ok());
    }

    // ── bytes_to_notify_string ──

    #[test]
    fn test_bytes_to_notify_string_basic() {
        assert_eq!(bytes_to_notify_string(b"READY=1").unwrap(), "READY=1");
    }

    #[test]
    fn test_bytes_to_notify_string_trailing_nul() {
        assert_eq!(bytes_to_notify_string(b"READY=1\0").unwrap(), "READY=1");
    }

    #[test]
    fn test_bytes_to_notify_string_invalid_utf8() {
        assert!(matches!(
            bytes_to_notify_string(b"\xff\xfe"),
            Err(NotifyError::InvalidUtf8)
        ));
    }

    // ── notify_split_fields ──

    #[test]
    fn test_notify_split_fields_basic() {
        let fields = notify_split_fields("READY=1\nSTATUS=ok");
        assert_eq!(fields, vec!["READY=1", "STATUS=ok"]);
    }

    #[test]
    fn test_notify_split_fields_trailing_newline() {
        let fields = notify_split_fields("READY=1\n");
        assert_eq!(fields, vec!["READY=1"]);
    }

    #[test]
    fn test_notify_split_fields_empty() {
        let fields = notify_split_fields("");
        assert!(fields.is_empty());
    }

    #[test]
    fn test_notify_split_fields_consecutive_newlines() {
        let fields = notify_split_fields("READY=1\n\nSTATUS=ok");
        assert_eq!(fields, vec!["READY=1", "STATUS=ok"]);
    }

    // ── NotificationMessage round-trip ──

    #[test]
    fn test_notification_message_clone() {
        let msg = NotificationMessage::parse("READY=1\nSTATUS=test".to_string());
        let cloned = msg.clone();
        assert_eq!(msg, cloned);
    }

    #[test]
    fn test_notification_message_equality() {
        let a = NotificationMessage::parse("READY=1".to_string());
        let b = NotificationMessage::parse("READY=1".to_string());
        let c = NotificationMessage::parse("READY=0".to_string());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ── NotifyError display ──

    #[test]
    fn test_notify_error_display() {
        let err = NotifyError::EmbeddedNul;
        assert!(!err.to_string().is_empty());

        let err = NotifyError::InvalidUtf8;
        assert!(err.to_string().contains("UTF-8"));

        let err = NotifyError::EmptyPayload;
        assert!(err.to_string().contains("empty"));
    }
}
