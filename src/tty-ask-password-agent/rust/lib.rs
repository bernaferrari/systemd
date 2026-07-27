// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/tty-ask-password-agent/tty-ask-password-agent.c
//
// TTY password request processing agent.
//
// Implements the systemd-tty-ask-password-agent tool which processes
// system password requests. Supports multiple modes: listing pending
// requests, querying passwords interactively, watching for new requests,
// and forwarding requests via wall. Handles multi-console setups by
// spawning per-console agents.

// ── Constants ─────────────────────────────────────────────────────────────

/// Directory containing password request files.
pub const ASK_PASSWORD_DIR: &str = "/run/systemd/ask-password";

/// Directory for wall pipe blocking.
pub const ASK_PASSWORD_BLOCK_DIR: &str = "/run/systemd/ask-password-block";

/// Prefix for password request files.
pub const ASK_FILE_PREFIX: &str = "ask.";

/// Default console device.
pub const DEFAULT_CONSOLE: &str = "/dev/console";

/// Default umask for the tool.
pub const DEFAULT_UMASK: u32 = 0o022;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Action modes for the password agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordAction {
    /// List pending password requests
    List,
    /// Process a single password query
    Query,
    /// Continuously watch for password requests
    Watch,
    /// Forward password requests via wall
    Wall,
}

impl Default for PasswordAction {
    fn default() -> Self {
        Self::Query
    }
}

impl PasswordAction {
    /// Parse an action from its string representation.
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "list" => Ok(Self::List),
            "query" => Ok(Self::Query),
            "watch" => Ok(Self::Watch),
            "wall" => Ok(Self::Wall),
            _ => Err(-libc::EINVAL),
        }
    }

    /// Whether this action requires continuous watching.
    pub fn is_continuous(self) -> bool {
        matches!(self, Self::Watch | Self::Wall)
    }

    pub fn is_interactive(self) -> bool {
        matches!(self, Self::Query | Self::Watch)
    }
}

// ── Password file parsing ─────────────────────────────────────────────────

/// Parsed password request file content.
#[derive(Debug, Clone, Default)]
pub struct AskPasswordFile {
    /// Socket path for sending the password response
    pub socket: Option<String>,
    /// Message to display to the user
    pub message: Option<String>,
    /// Expiry time (0 = no expiry)
    pub not_after: u64,
    /// PID of the requesting process
    pub pid: u32,
    /// Whether cached passwords are accepted
    pub accept_cached: bool,
    /// Whether to echo the password input
    pub echo: bool,
    /// Whether silent mode is requested
    pub silent: bool,
}

impl AskPasswordFile {
    /// Create a new empty password request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if the request has expired.
    pub fn is_expired(&self, now_usec: u64) -> bool {
        self.not_after > 0 && now_usec > self.not_after
    }

    /// Check if the requesting process is still alive.
    /// (This would need OS support for actual implementation)
    pub fn is_requestor_alive(&self) -> bool {
        self.pid > 0
    }

    /// Validate the parsed password file has required fields.
    pub fn is_valid(&self) -> bool {
        self.socket.is_some()
    }
}

// ── Config file key names ─────────────────────────────────────────────────

/// Configuration keys in password request files.
pub const CONF_SOCKET: &str = "Socket";
pub const CONF_NOT_AFTER: &str = "NotAfter";
pub const CONF_MESSAGE: &str = "Message";
pub const CONF_PID: &str = "PID";
pub const CONF_ACCEPT_CACHED: &str = "AcceptCached";
pub const CONF_ECHO: &str = "Echo";
pub const CONF_SILENT: &str = "Silent";
pub const CONF_SECTION: &str = "Ask";

// ── Ask password flags ────────────────────────────────────────────────────

/// Bitflags for ask-password operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AskPasswordFlags(u32);

impl AskPasswordFlags {
    /// Accept cached passwords
    pub const ACCEPT_CACHED: Self = Self(1 << 0);
    /// Use console color output
    pub const CONSOLE_COLOR: Self = Self(1 << 1);
    /// Echo the password input
    pub const ECHO: Self = Self(1 << 2);
    /// Silent mode (no output)
    pub const SILENT: Self = Self(1 << 3);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn bits(&self) -> u32 {
        self.0
    }

    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    pub fn from_bits_truncate(bits: u32) -> Self {
        Self(bits & (Self::ACCEPT_CACHED.0 | Self::CONSOLE_COLOR.0 | Self::ECHO.0 | Self::SILENT.0))
    }
}

impl std::ops::BitOr for AskPasswordFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for AskPasswordFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for AskPasswordFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::BitAndAssign for AskPasswordFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl std::ops::Not for AskPasswordFlags {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}

// ── Wall message formatting ───────────────────────────────────────────────

/// Format a wall message for a password request.
pub fn format_wall_message(message: &str, pid: u32) -> String {
    format!(
        "Password entry required for '{}' (PID {}).\r\n\
         Please enter password with the systemd-tty-ask-password-agent tool.",
        message, pid
    )
}

/// Format the list output for a password request.
pub fn format_list_output(message: &str, pid: u32) -> String {
    format!("'{}' (PID {})", message, pid)
}

// ── Argument parsing ──────────────────────────────────────────────────────

/// Parsed arguments for the tty-ask-password-agent tool.
#[derive(Debug, Clone)]
pub struct TtyAskPasswordAgentArgs {
    /// Action to perform
    pub action: PasswordAction,
    /// Use Plymouth for password input
    pub plymouth: bool,
    /// Use console (optionally specific device)
    pub console: bool,
    /// Specific console device
    pub device: Option<String>,
}

impl Default for TtyAskPasswordAgentArgs {
    fn default() -> Self {
        Self {
            action: PasswordAction::default(),
            plymouth: false,
            console: false,
            device: None,
        }
    }
}

impl TtyAskPasswordAgentArgs {
    /// Validate the argument combination.
    pub fn validate(&self) -> Result<(), i32> {
        // Plymouth and console only valid with query/watch
        if self.plymouth || self.console {
            if !self.action.is_interactive() {
                return Err(-libc::EINVAL);
            }
        }

        // Plymouth and console conflict with each other
        if self.plymouth && self.console {
            return Err(-libc::EINVAL);
        }

        Ok(())
    }

    /// Get the effective console device.
    pub fn console_device(&self) -> &str {
        self.device.as_deref().unwrap_or(DEFAULT_CONSOLE)
    }
}

// ── Password packet builder ───────────────────────────────────────────────

/// Build a password response packet for sending via Unix socket.
/// Format: '+' followed by NUL-separated passwords.
pub fn build_password_packet(passwords: &[String]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.push(b'+');
    for pwd in passwords {
        packet.extend_from_slice(pwd.as_bytes());
        packet.push(0);
    }
    packet
}

// ── Polling constants ─────────────────────────────────────────────────────

/// Poll file descriptor indices.
pub const FD_SIGNAL: usize = 0;
pub const FD_INOTIFY: usize = 1;
pub const FD_MAX: usize = 2;

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_action_from_str() {
        assert_eq!(PasswordAction::from_str("list"), Ok(PasswordAction::List));
        assert_eq!(PasswordAction::from_str("query"), Ok(PasswordAction::Query));
        assert_eq!(PasswordAction::from_str("watch"), Ok(PasswordAction::Watch));
        assert_eq!(PasswordAction::from_str("wall"), Ok(PasswordAction::Wall));
        assert!(PasswordAction::from_str("invalid").is_err());
    }

    #[test]
    fn test_password_action_is_continuous() {
        assert!(PasswordAction::Watch.is_continuous());
        assert!(PasswordAction::Wall.is_continuous());
        assert!(!PasswordAction::Query.is_continuous());
        assert!(!PasswordAction::List.is_continuous());
    }

    #[test]
    fn test_password_action_is_interactive() {
        assert!(PasswordAction::Query.is_interactive());
        assert!(PasswordAction::Watch.is_interactive());
        assert!(!PasswordAction::List.is_interactive());
        assert!(!PasswordAction::Wall.is_interactive());
    }

    #[test]
    fn test_ask_password_file_validation() {
        let valid = AskPasswordFile {
            socket: Some("/run/ask.sock".to_string()),
            message: Some("Enter password".to_string()),
            pid: 1234,
            ..Default::default()
        };
        assert!(valid.is_valid());

        let invalid = AskPasswordFile::default();
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_ask_password_file_expired() {
        let file = AskPasswordFile {
            not_after: 1000,
            ..Default::default()
        };
        assert!(file.is_expired(2000));
        assert!(!file.is_expired(500));
        assert!(!file.is_expired(1000));
    }

    #[test]
    fn test_ask_password_file_not_after_zero() {
        let file = AskPasswordFile {
            not_after: 0,
            ..Default::default()
        };
        assert!(!file.is_expired(999999999));
    }

    #[test]
    fn test_format_wall_message() {
        let msg = format_wall_message("Enter passphrase", 1234);
        assert!(msg.contains("Enter passphrase"));
        assert!(msg.contains("1234"));
        assert!(msg.contains("systemd-tty-ask-password-agent"));
    }

    #[test]
    fn test_format_list_output() {
        let output = format_list_output("Passphrase for /dev/sda1", 5678);
        assert_eq!(output, "'Passphrase for /dev/sda1' (PID 5678)");
    }

    #[test]
    fn test_build_password_packet() {
        let passwords = vec!["secret".to_string()];
        let packet = build_password_packet(&passwords);
        assert_eq!(packet[0], b'+');
        assert_eq!(&packet[1..7], b"secret");
        assert_eq!(packet[7], 0);
    }

    #[test]
    fn test_build_password_packet_multiple() {
        let passwords = vec!["pass1".to_string(), "pass2".to_string()];
        let packet = build_password_packet(&passwords);
        assert_eq!(packet[0], b'+');
        let expected: Vec<u8> = vec![
            b'+', b'p', b'a', b's', b's', b'1', 0, b'p', b'a', b's', b's', b'2', 0,
        ];
        assert_eq!(packet, expected);
    }

    #[test]
    fn test_agent_args_validate() {
        let args = TtyAskPasswordAgentArgs {
            action: PasswordAction::Query,
            plymouth: true,
            ..Default::default()
        };
        assert!(args.validate().is_ok());

        let args_conflict = TtyAskPasswordAgentArgs {
            action: PasswordAction::Query,
            plymouth: true,
            console: true,
            ..Default::default()
        };
        assert!(args_conflict.validate().is_err());

        let args_wrong_action = TtyAskPasswordAgentArgs {
            action: PasswordAction::List,
            plymouth: true,
            ..Default::default()
        };
        assert!(args_wrong_action.validate().is_err());
    }

    #[test]
    fn test_agent_args_console_device() {
        let args = TtyAskPasswordAgentArgs::default();
        assert_eq!(args.console_device(), "/dev/console");

        let args_with_device = TtyAskPasswordAgentArgs {
            device: Some("/dev/tty1".to_string()),
            ..Default::default()
        };
        assert_eq!(args_with_device.console_device(), "/dev/tty1");
    }
}
