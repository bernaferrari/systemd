// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/notify/notify.c
//
// Sends sd_notify() style messages from services to the systemd manager.
//
// Supports three actions: notify (default), booted, and fork.
// Messages consist of newline-separated KEY=VALUE assignments such as
// READY=1, STATUS=…, RELOADING=1, STOPPING=1, MAINPID=…, ERRNO=…,
// BUSERROR=…, FDNAME=…, and WATCHDOG=1.

// ── Error type ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

// ── Action enum ───────────────────────────────────────────────────────────

/// Top-level action for systemd-notify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyAction {
    /// Send a notification message to the service manager.
    Notify,
    /// Check whether the system was booted with systemd.
    Booted,
    /// Fork a child and wait for READY=1.
    Fork,
}

// ── Notify message ────────────────────────────────────────────────────────

/// Parsed representation of an sd_notify() message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NotifyMessage {
    pub ready: bool,
    pub reloading: bool,
    pub stopping: bool,
    pub watchdog: bool,
    pub status: Option<String>,
    pub errno: Option<i32>,
    pub bus_error: Option<String>,
    pub fdname: Option<String>,
    pub mainpid: Option<u32>,
    pub monotonic_usec: Option<u64>,
}

impl NotifyMessage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if no fields have been set.
    pub fn is_empty(&self) -> bool {
        !self.ready
            && !self.reloading
            && !self.stopping
            && !self.watchdog
            && self.status.is_none()
            && self.errno.is_none()
            && self.bus_error.is_none()
            && self.fdname.is_none()
            && self.mainpid.is_none()
            && self.monotonic_usec.is_none()
    }

    /// Parse a single KEY=VALUE line and update this message.
    pub fn parse_line(&mut self, line: &str) -> Result<()> {
        if line.is_empty() {
            return Ok(());
        }
        if let Some(value) = line.strip_prefix("STATUS=") {
            self.status = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("ERRNO=") {
            self.errno = Some(value.parse().map_err(|_| Errno(-libc::EINVAL))?);
        } else if let Some(value) = line.strip_prefix("BUSERROR=") {
            self.bus_error = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("FDNAME=") {
            self.fdname = Some(value.to_string());
        } else if let Some(value) = line.strip_prefix("MAINPID=") {
            self.mainpid = Some(value.parse().map_err(|_| Errno(-libc::EINVAL))?);
        } else if let Some(value) = line.strip_prefix("MONOTONIC_USEC=") {
            self.monotonic_usec = Some(value.parse().map_err(|_| Errno(-libc::EINVAL))?);
        } else if line == "READY=1" {
            self.ready = true;
        } else if line == "RELOADING=1" {
            self.reloading = true;
        } else if line == "STOPPING=1" {
            self.stopping = true;
        } else if line == "WATCHDOG=1" {
            self.watchdog = true;
        }
        Ok(())
    }
}

// ── Parse helpers ─────────────────────────────────────────────────────────

/// Parse a full newline-separated notification message into a struct.
pub fn parse_notify_message(data: &str) -> Result<NotifyMessage> {
    let mut msg = NotifyMessage::new();
    for line in data.lines() {
        msg.parse_line(line)?;
    }
    Ok(msg)
}

/// Validate a file-descriptor name for FDNAME=.
/// Must be non-empty and contain only ASCII alphanumeric, dash, underscore.
pub fn is_valid_fdname(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

// ── Formatting helpers ────────────────────────────────────────────────────

/// Format a READY=1 notification line.
pub fn format_ready() -> &'static str {
    "READY=1"
}

/// Format a STATUS= notification line.
pub fn format_status(status: &str) -> String {
    format!("STATUS={}", status)
}

/// Format a RELOADING=1 with monotonic timestamp.
pub fn format_reloading(monotonic_usec: u64) -> String {
    format!("RELOADING=1\nMONOTONIC_USEC={}", monotonic_usec)
}

/// Format a STOPPING=1 notification line.
pub fn format_stopping() -> &'static str {
    "STOPPING=1"
}

/// Format a WATCHDOG=1 notification line.
pub fn format_watchdog() -> &'static str {
    "WATCHDOG=1"
}

/// Format a MAINPID= notification line.
pub fn format_mainpid(pid: u32) -> String {
    format!("MAINPID={}", pid)
}

/// Format a FDSTORE=1 notification line.
pub fn format_fdstore() -> &'static str {
    "FDSTORE=1"
}

/// Inputs for [`build_message`].
///
/// These correspond to the notification fields assembled by `src/notify/notify.c`.
/// Keeping them together prevents callers from accidentally swapping one of the
/// boolean flags or optional values in the message construction API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NotifyMessageFields<'a> {
    pub ready: bool,
    pub reloading: bool,
    pub stopping: bool,
    pub status: Option<&'a str>,
    pub mainpid: Option<u32>,
    pub fdstore: bool,
    pub fdname: Option<&'a str>,
    pub monotonic_usec: Option<u64>,
}

/// Build a complete notification message from typed fields.
pub fn build_message(fields: NotifyMessageFields<'_>) -> String {
    let mut lines = Vec::new();
    if fields.reloading {
        if let Some(usec) = fields.monotonic_usec {
            lines.push(format_reloading(usec));
        } else {
            lines.push("RELOADING=1".to_string());
        }
    }
    if fields.ready {
        lines.push(format_ready().to_string());
    }
    if fields.stopping {
        lines.push(format_stopping().to_string());
    }
    if let Some(s) = fields.status {
        lines.push(format_status(s));
    }
    if let Some(pid) = fields.mainpid {
        lines.push(format_mainpid(pid));
    }
    if fields.fdstore {
        lines.push(format_fdstore().to_string());
    }
    if let Some(name) = fields.fdname {
        lines.push(format!("FDNAME={}", name));
    }
    lines.join("\n")
}

/// Determine the notify action from command-line arguments.
pub fn determine_action(args: &[&str]) -> Result<NotifyAction> {
    for arg in args {
        match *arg {
            "--booted" => return Ok(NotifyAction::Booted),
            "--fork" => return Ok(NotifyAction::Fork),
            _ => {}
        }
    }
    Ok(NotifyAction::Notify)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_message_is_empty() {
        let msg = NotifyMessage::new();
        assert!(msg.is_empty());
    }

    #[test]
    fn parse_ready() {
        let msg = parse_notify_message("READY=1").unwrap();
        assert!(msg.ready);
        assert!(!msg.is_empty());
    }

    #[test]
    fn parse_status() {
        let msg = parse_notify_message("STATUS=Running").unwrap();
        assert_eq!(msg.status.as_deref(), Some("Running"));
    }

    #[test]
    fn parse_multiple_fields() {
        let msg = parse_notify_message("READY=1\nSTATUS=Running\nWATCHDOG=1\nMAINPID=42").unwrap();
        assert!(msg.ready);
        assert!(msg.watchdog);
        assert_eq!(msg.status.as_deref(), Some("Running"));
        assert_eq!(msg.mainpid, Some(42));
    }

    #[test]
    fn parse_errno_and_buserror() {
        let msg = parse_notify_message("ERRNO=22\nBUSERROR=org.freedesktop.DBus.Error").unwrap();
        assert_eq!(msg.errno, Some(22));
        assert_eq!(msg.bus_error.as_deref(), Some("org.freedesktop.DBus.Error"));
    }

    #[test]
    fn parse_reloading_with_monotonic() {
        let msg = parse_notify_message("RELOADING=1\nMONOTONIC_USEC=12345678").unwrap();
        assert!(msg.reloading);
        assert_eq!(msg.monotonic_usec, Some(12345678));
    }

    #[test]
    fn parse_stopping() {
        let msg = parse_notify_message("STOPPING=1").unwrap();
        assert!(msg.stopping);
    }

    #[test]
    fn parse_empty_input() {
        let msg = parse_notify_message("").unwrap();
        assert!(msg.is_empty());
    }

    #[test]
    fn parse_unknown_key_ignored() {
        let msg = parse_notify_message("UNKNOWN_KEY=foo").unwrap();
        assert!(msg.is_empty());
    }

    #[test]
    fn fdname_validation() {
        assert!(is_valid_fdname("my-fd_name"));
        assert!(is_valid_fdname("abc123"));
        assert!(!is_valid_fdname(""));
        assert!(!is_valid_fdname("has space"));
        assert!(!is_valid_fdname("has/slash"));
    }

    #[test]
    fn format_helpers_output() {
        assert_eq!(format_ready(), "READY=1");
        assert_eq!(format_status("hello"), "STATUS=hello");
        assert!(format_reloading(999).contains("MONOTONIC_USEC=999"));
        assert_eq!(format_stopping(), "STOPPING=1");
        assert_eq!(format_watchdog(), "WATCHDOG=1");
        assert_eq!(format_mainpid(1234), "MAINPID=1234");
    }

    #[test]
    fn build_full_message() {
        let msg = build_message(NotifyMessageFields {
            ready: true,
            reloading: true,
            stopping: false,
            status: Some("ready"),
            mainpid: Some(99),
            fdstore: true,
            fdname: Some("state"),
            monotonic_usec: Some(123),
        });
        assert_eq!(
            msg,
            "RELOADING=1\nMONOTONIC_USEC=123\nREADY=1\nSTATUS=ready\nMAINPID=99\nFDSTORE=1\nFDNAME=state"
        );
    }

    #[test]
    fn determine_action_defaults() {
        assert_eq!(determine_action(&[]).unwrap(), NotifyAction::Notify);
        assert_eq!(
            determine_action(&["--booted"]).unwrap(),
            NotifyAction::Booted
        );
        assert_eq!(determine_action(&["--fork"]).unwrap(), NotifyAction::Fork);
    }
}
