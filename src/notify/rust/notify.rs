// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/notify/notify.c
//
// Service notification message parsing and formatting.
//
// Provides types and utilities for constructing and parsing the
// `sd_notify()` protocol messages sent from services to the systemd
// manager.  Supports all standard key=value pairs such as `READY=1`,
// `STATUS=...`, `MAINPID=...`, etc.

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

pub type Result<T> = std::result::Result<T, Errno>;

// ── Constants ─────────────────────────────────────────────────────────────

/// Well-known notification keys.
pub const NOTIFY_KEY_READY: &str = "READY";
pub const NOTIFY_KEY_STATUS: &str = "STATUS";
pub const NOTIFY_KEY_ERRNO: &str = "ERRNO";
pub const NOTIFY_KEY_BUSERROR: &str = "BUSERROR";
pub const NOTIFY_KEY_FDNAME: &str = "FDNAME";
pub const NOTIFY_KEY_MAINPID: &str = "MAINPID";
pub const NOTIFY_KEY_STOPPING: &str = "STOPPING";
pub const NOTIFY_KEY_RELOADING: &str = "RELOADING";
pub const NOTIFY_KEY_WATCHDOG: &str = "WATCHDOG";
pub const NOTIFY_KEY_FDSTORE: &str = "FDSTORE";
pub const NOTIFY_KEY_MONOTONIC_USEC: &str = "MONOTONIC_USEC";

// ── Notification message ──────────────────────────────────────────────────

/// Parsed notification message fields.
///
/// Each field corresponds to a key=value pair in the `sd_notify()` protocol.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NotifyMessage {
    pub status: Option<String>,
    pub errno: Option<i32>,
    pub bus_error: Option<String>,
    pub fdname: Option<String>,
    pub mainpid: Option<u32>,
    pub ready: bool,
    pub stopping: bool,
    pub reloading: bool,
    pub watchdog: bool,
    pub fdstore: bool,
    pub monotonic_usec: Option<u64>,
}

impl NotifyMessage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether the message is completely empty (no fields set).
    pub fn is_empty(&self) -> bool {
        self.status.is_none()
            && self.errno.is_none()
            && self.bus_error.is_none()
            && self.fdname.is_none()
            && self.mainpid.is_none()
            && self.monotonic_usec.is_none()
            && !self.ready
            && !self.stopping
            && !self.reloading
            && !self.watchdog
            && !self.fdstore
    }

    /// Parse a single `KEY=VALUE` line and update this message.
    ///
    /// Unknown keys are silently ignored, matching the C behaviour.
    pub fn parse_line(&mut self, line: &str) -> Result<()> {
        if let Some(value) = line.strip_prefix("STATUS=") {
            self.status = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("ERRNO=") {
            self.errno = Some(value.parse().map_err(|_| Errno(-22))?);
        } else if let Some(value) = line.strip_prefix("BUSERROR=") {
            self.bus_error = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("FDNAME=") {
            self.fdname = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("MAINPID=") {
            self.mainpid = Some(value.parse().map_err(|_| Errno(-22))?);
        } else if let Some(value) = line.strip_prefix("MONOTONIC_USEC=") {
            self.monotonic_usec = Some(value.parse().map_err(|_| Errno(-22))?);
        } else if line == "READY=1" {
            self.ready = true;
        } else if line == "STOPPING=1" {
            self.stopping = true;
        } else if line == "RELOADING=1" {
            self.reloading = true;
        } else if line == "WATCHDOG=1" {
            self.watchdog = true;
        } else if line == "FDSTORE=1" {
            self.fdstore = true;
        }
        Ok(())
    }
}

// ── Parsing ───────────────────────────────────────────────────────────────

/// Parse a multi-line notification payload into a `NotifyMessage`.
///
/// Each line is a `KEY=VALUE` pair separated by `\n`.
pub fn parse_notify_message(data: &str) -> Result<NotifyMessage> {
    let mut msg = NotifyMessage::new();
    for line in data.lines() {
        let trimmed = line.trim_end_matches('\n');
        if !trimmed.is_empty() {
            msg.parse_line(trimmed)?;
        }
    }
    Ok(msg)
}

// ── Formatting ────────────────────────────────────────────────────────────

/// Format a `READY=1` notification message.
pub fn format_ready_message() -> String {
    "READY=1\n".to_string()
}

/// Format a `STATUS=...` notification message.
pub fn format_status_message(status: &str) -> String {
    format!("STATUS={}\n", status)
}

/// Format a `WATCHDOG=1` notification message.
pub fn format_watchdog_message() -> String {
    "WATCHDOG=1\n".to_string()
}

/// Format a `STOPPING=1` notification message.
pub fn format_stopping_message() -> String {
    "STOPPING=1\n".to_string()
}

/// Format a `RELOADING=1` notification message with monotonic timestamp.
pub fn format_reloading_message(monotonic_usec: u64) -> String {
    format!("RELOADING=1\nMONOTONIC_USEC={}\n", monotonic_usec)
}

/// Format a `MAINPID=...` notification message.
pub fn format_mainpid_message(pid: u32) -> String {
    format!("MAINPID={}\n", pid)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_message_empty() {
        let msg = NotifyMessage::new();
        assert!(msg.is_empty());
    }

    #[test]
    fn parse_ready() {
        let msg = parse_notify_message("READY=1\n").unwrap();
        assert!(msg.ready);
        assert!(!msg.is_empty());
    }

    #[test]
    fn parse_status() {
        let msg = parse_notify_message("STATUS=Hello world\n").unwrap();
        assert_eq!(msg.status.as_deref(), Some("Hello world"));
        assert!(msg.is_empty() == false);
    }

    #[test]
    fn parse_multiple_lines() {
        let msg = parse_notify_message("READY=1\nSTATUS=Running\nWATCHDOG=1\n").unwrap();
        assert!(msg.ready);
        assert!(msg.watchdog);
        assert_eq!(msg.status.as_deref(), Some("Running"));
    }

    #[test]
    fn parse_errno() {
        let msg = parse_notify_message("ERRNO=22\n").unwrap();
        assert_eq!(msg.errno, Some(22));
    }

    #[test]
    fn parse_mainpid() {
        let msg = parse_notify_message("MAINPID=1234\n").unwrap();
        assert_eq!(msg.mainpid, Some(1234));
    }

    #[test]
    fn parse_stopping() {
        let msg = parse_notify_message("STOPPING=1\n").unwrap();
        assert!(msg.stopping);
    }

    #[test]
    fn parse_reloading_with_monotonic() {
        let msg = parse_notify_message("RELOADING=1\nMONOTONIC_USEC=12345678\n").unwrap();
        assert!(msg.reloading);
        assert_eq!(msg.monotonic_usec, Some(12345678));
    }

    #[test]
    fn parse_fdstore() {
        let msg = parse_notify_message("FDSTORE=1\nFDNAME=myfd\n").unwrap();
        assert!(msg.fdstore);
        assert_eq!(msg.fdname.as_deref(), Some("myfd"));
    }

    #[test]
    fn parse_invalid_mainpid() {
        let msg = parse_notify_message("MAINPID=notanumber\n");
        assert!(msg.is_err());
    }

    #[test]
    fn format_helpers() {
        assert!(format_ready_message().starts_with("READY=1"));
        assert!(format_watchdog_message().starts_with("WATCHDOG=1"));
        assert!(format_stopping_message().starts_with("STOPPING=1"));
        assert!(format_status_message("test").contains("STATUS=test"));
    }

    #[test]
    fn format_reloading() {
        let msg = format_reloading_message(999);
        assert!(msg.contains("RELOADING=1"));
        assert!(msg.contains("MONOTONIC_USEC=999"));
    }

    #[test]
    fn format_mainpid() {
        let msg = format_mainpid_message(42);
        assert!(msg.contains("MAINPID=42"));
    }

    #[test]
    fn unknown_keys_ignored() {
        let msg = parse_notify_message("UNKNOWN_KEY=value\nREADY=1\n").unwrap();
        assert!(msg.ready);
        assert!(msg.is_empty() == false); // ready is set
    }
}
