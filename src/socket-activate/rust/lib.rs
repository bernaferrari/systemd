// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/socket-activate/socket-activate.c
//
// Socket activation helper.
//
// Listens on sockets and launches a child process on connection.
// Supports accept mode (one child per connection), inetd mode,
// datagram/seqpacket sockets, and environment variable passing.

// ── Constants ─────────────────────────────────────────────────────────────

/// SD_LISTEN_FDS_START: first fd passed via socket activation.
pub const SD_LISTEN_FDS_START: i32 = 3;

/// SOCK_STREAM socket type.
pub const SOCK_STREAM: i32 = 1;

/// SOCK_DGRAM socket type.
pub const SOCK_DGRAM: i32 = 2;

/// SOCK_SEQPACKET socket type.
pub const SOCK_SEQPACKET: i32 = 5;

/// SOCK_CLOEXEC flag.
pub const SOCK_CLOEXEC: i32 = 0o2000000;

/// Environment variables inherited by child processes.
pub const INHERIT_ENV_VARS: &[&str] = &["TERM", "COLORTERM", "NO_COLOR", "PATH", "USER", "HOME"];

// ── Enums ─────────────────────────────────────────────────────────────────

/// Socket type to listen on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    Stream,
    Datagram,
    Seqpacket,
}

impl SocketType {
    /// Convert to the libc socket type constant.
    pub fn to_libc(self) -> i32 {
        match self {
            SocketType::Stream => SOCK_STREAM,
            SocketType::Datagram => SOCK_DGRAM,
            SocketType::Seqpacket => SOCK_SEQPACKET,
        }
    }

    /// Check if this socket type supports accept().
    pub fn supports_accept(self) -> bool {
        matches!(self, SocketType::Stream | SocketType::Seqpacket)
    }
}

/// How stdio is handled for the child process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioMode {
    /// Normal: pass fds via LISTEN_FDS.
    Normal,
    /// Inetd: move fd to stdin/stdout.
    Inetd,
}

// ── Structs ───────────────────────────────────────────────────────────────

/// Parsed arguments for socket-activate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivateConfig {
    /// Addresses to listen on.
    pub listen: Vec<String>,
    /// Whether to accept per-connection (spawn multiple children).
    pub accept: bool,
    /// Socket type.
    pub socket_type: SocketType,
    /// Environment variables to set for children.
    pub setenv: Vec<String>,
    /// File descriptor names.
    pub fdnames: Vec<String>,
    /// Inetd mode.
    pub inetd: bool,
    /// Start immediately instead of waiting for connection.
    pub now: bool,
}

impl Default for ActivateConfig {
    fn default() -> Self {
        ActivateConfig {
            listen: Vec::new(),
            accept: false,
            socket_type: SocketType::Stream,
            setenv: Vec::new(),
            fdnames: Vec::new(),
            inetd: false,
            now: false,
        }
    }
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors from socket-activate operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivateError {
    /// No command specified.
    NoCommand,
    /// Datagram with accept not supported.
    DatagramWithAccept,
    /// Accept with --now not supported.
    AcceptWithNow,
    /// Incompatible socket types.
    IncompatibleSocketTypes,
    /// No sockets to listen on.
    NoSockets,
    /// Failed to open socket.
    SocketOpenFailed(String),
    /// Failed to execute child.
    ExecFailed(String),
    /// Failed to create epoll.
    EpollFailed(String),
    /// Invalid fd name.
    InvalidFdName(String),
}

impl std::fmt::Display for ActivateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActivateError::NoCommand => write!(f, "Command to execute is missing."),
            ActivateError::DatagramWithAccept => write!(
                f,
                "Datagram sockets do not accept connections. \
                 The --datagram and --accept options may not be combined."
            ),
            ActivateError::AcceptWithNow => {
                write!(f, "--now cannot be used in conjunction with --accept.")
            }
            ActivateError::IncompatibleSocketTypes => {
                write!(f, "--datagram may not be combined with --seqpacket.")
            }
            ActivateError::NoSockets => {
                write!(f, "No sockets to listen on specified or passed in.")
            }
            ActivateError::SocketOpenFailed(msg) => {
                write!(f, "Failed to open socket: {}", msg)
            }
            ActivateError::ExecFailed(msg) => {
                write!(f, "Failed to execute: {}", msg)
            }
            ActivateError::EpollFailed(msg) => {
                write!(f, "Failed to create epoll: {}", msg)
            }
            ActivateError::InvalidFdName(name) => {
                write!(f, "File descriptor name \"{}\" is not valid.", name)
            }
        }
    }
}

impl std::error::Error for ActivateError {}

// ── Helper functions ──────────────────────────────────────────────────────

/// Validate the configuration for incompatible options.
pub fn validate_config(config: &ActivateConfig) -> Result<(), ActivateError> {
    if config.socket_type == SocketType::Datagram && config.accept {
        return Err(ActivateError::DatagramWithAccept);
    }
    if config.accept && config.now {
        return Err(ActivateError::AcceptWithNow);
    }
    Ok(())
}

/// Check if a file descriptor name is valid.
/// Valid names contain only alphanumeric characters, underscore, and hyphen.
pub fn fdname_is_valid(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Build the LISTEN_FDS environment variable string.
pub fn build_listen_fds_env(n_fds: usize, pid: u32) -> Vec<String> {
    vec![
        format!("LISTEN_FDS={}", n_fds),
        format!("LISTEN_PID={}", pid),
    ]
}

/// Build the LISTEN_FDNAMES environment variable string.
pub fn build_fdnames_env(fdnames: &[String], n_fds: usize) -> Option<String> {
    if fdnames.is_empty() {
        return None;
    }
    let names: Vec<&str> = if fdnames.len() == 1 {
        (0..n_fds).map(|_| fdnames[0].as_str()).collect()
    } else {
        fdnames.iter().map(|s| s.as_str()).collect()
    };
    Some(format!("LISTEN_FDNAMES={}", names.join(":")))
}

/// Calculate total number of file descriptors (passed + opened).
pub fn calculate_total_fds(passed_fds: i32, listen_count: usize) -> i32 {
    passed_fds + listen_count as i32
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_type_to_libc() {
        assert_eq!(SocketType::Stream.to_libc(), SOCK_STREAM);
        assert_eq!(SocketType::Datagram.to_libc(), SOCK_DGRAM);
        assert_eq!(SocketType::Seqpacket.to_libc(), SOCK_SEQPACKET);
    }

    #[test]
    fn test_socket_type_supports_accept() {
        assert!(SocketType::Stream.supports_accept());
        assert!(SocketType::Seqpacket.supports_accept());
        assert!(!SocketType::Datagram.supports_accept());
    }

    #[test]
    fn test_validate_config_valid() {
        let config = ActivateConfig::default();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_validate_config_datagram_accept() {
        let config = ActivateConfig {
            socket_type: SocketType::Datagram,
            accept: true,
            ..Default::default()
        };
        assert_eq!(
            validate_config(&config),
            Err(ActivateError::DatagramWithAccept)
        );
    }

    #[test]
    fn test_validate_config_accept_now() {
        let config = ActivateConfig {
            accept: true,
            now: true,
            ..Default::default()
        };
        assert_eq!(validate_config(&config), Err(ActivateError::AcceptWithNow));
    }

    #[test]
    fn test_fdname_is_valid() {
        assert!(fdname_is_valid("valid-name"));
        assert!(fdname_is_valid("valid_name"));
        assert!(fdname_is_valid("name123"));
        assert!(!fdname_is_valid(""));
        assert!(!fdname_is_valid("invalid name"));
        assert!(!fdname_is_valid("a/b"));
    }

    #[test]
    fn test_build_listen_fds_env() {
        let env = build_listen_fds_env(3, 1234);
        assert_eq!(env[0], "LISTEN_FDS=3");
        assert_eq!(env[1], "LISTEN_PID=1234");
    }

    #[test]
    fn test_build_fdnames_env_single() {
        let names = vec!["http".to_string()];
        let env = build_fdnames_env(&names, 3);
        assert_eq!(env, Some("LISTEN_FDNAMES=http:http:http".to_string()));
    }

    #[test]
    fn test_build_fdnames_env_multiple() {
        let names = vec!["http".to_string(), "https".to_string()];
        let env = build_fdnames_env(&names, 2);
        assert_eq!(env, Some("LISTEN_FDNAMES=http:https".to_string()));
    }

    #[test]
    fn test_build_fdnames_env_empty() {
        let env = build_fdnames_env(&[], 2);
        assert!(env.is_none());
    }

    #[test]
    fn test_calculate_total_fds() {
        assert_eq!(calculate_total_fds(3, 2), 5);
        assert_eq!(calculate_total_fds(0, 1), 1);
    }

    #[test]
    fn test_error_display() {
        let err = ActivateError::NoCommand;
        assert!(format!("{}", err).contains("missing"));
    }
}
