// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/reply-password/reply-password.c
//
// Sends password replies via AF_UNIX datagram sockets.
//
// Builds a response packet ("+" + password or "-" for cancellation) and sends
// it through a Unix datagram socket to the specified path, faithfully mirroring
// the C implementation's protocol and error handling.

// ── Constants ─────────────────────────────────────────────────────────────

/// Packet prefix for a confirmed password reply.
pub const PASSWORD_CONFIRMED_PREFIX: char = '+';

/// Packet content for a cancelled/no password reply.
pub const PASSWORD_CANCELLED: &str = "-";

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyPasswordError {
    /// Invalid number of arguments (expected 2 after program name).
    InvalidArgumentCount,
    /// Invalid first argument (must be "0" or "1").
    InvalidFirstArgument,
    /// Failed to read the password from stdin.
    ReadFailed,
    /// Got EOF while reading password.
    Eof,
    /// Failed to create the AF_UNIX datagram socket.
    SocketFailed,
    /// Failed to send the packet on the socket.
    SendFailed,
    /// Invalid socket path.
    InvalidSocketPath,
}

impl std::fmt::Display for ReplyPasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplyPasswordError::InvalidArgumentCount => write!(f, "Wrong number of arguments"),
            ReplyPasswordError::InvalidFirstArgument => write!(f, "Invalid first argument"),
            ReplyPasswordError::ReadFailed => write!(f, "Failed to read password"),
            ReplyPasswordError::Eof => write!(f, "Got EOF while reading password"),
            ReplyPasswordError::SocketFailed => write!(f, "socket() failed"),
            ReplyPasswordError::SendFailed => write!(f, "Failed to send"),
            ReplyPasswordError::InvalidSocketPath => write!(f, "Invalid socket path"),
        }
    }
}

impl std::error::Error for ReplyPasswordError {}

pub type Result<T> = std::result::Result<T, ReplyPasswordError>;

// ── Packet construction ───────────────────────────────────────────────────

/// The reply packet sent over the Unix datagram socket.
/// Mirrors the `packet` variable in `run()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordPacket {
    /// Password confirmed: "+" followed by the password and a NUL terminator.
    Confirmed(String),
    /// Password cancelled: just "-".
    Cancelled,
}

impl PasswordPacket {
    /// Build a packet from the first argument and the password line read from stdin.
    /// Corresponds to the `if (streq(argv[1], "1"))` / `else if (streq(argv[1], "0"))` logic.
    pub fn from_args(arg1: &str, password_line: Option<&str>) -> Result<Self> {
        match arg1 {
            "1" => {
                let line = password_line.ok_or(ReplyPasswordError::Eof)?;
                if line.is_empty() {
                    return Err(ReplyPasswordError::Eof);
                }
                Ok(PasswordPacket::Confirmed(line.to_string()))
            }
            "0" => Ok(PasswordPacket::Cancelled),
            _ => Err(ReplyPasswordError::InvalidFirstArgument),
        }
    }

    /// Encode the packet as bytes for transmission.
    /// Corresponds to the `sendto(fd, packet, length, ...)` call.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PasswordPacket::Confirmed(password) => {
                let mut buf = Vec::with_capacity(1 + password.len() + 1);
                buf.push(PASSWORD_CONFIRMED_PREFIX as u8);
                buf.extend_from_slice(password.as_bytes());
                buf.push(0); // NUL terminator
                buf
            }
            PasswordPacket::Cancelled => {
                let mut buf = Vec::with_capacity(2);
                buf.push(b'-');
                buf.push(0); // NUL terminator
                buf
            }
        }
    }

    /// The length of the encoded packet, matching the C `length` variable.
    pub fn encoded_length(&self) -> usize {
        match self {
            PasswordPacket::Confirmed(password) => 1 + password.len() + 1,
            PasswordPacket::Cancelled => 1 + 1,
        }
    }
}

// ── Validation helpers ────────────────────────────────────────────────────

/// Validate that the argument count is correct (argc == 3 in C, i.e., 2 args after progname).
pub fn validate_argc(argc: usize) -> Result<()> {
    if argc == 2 {
        Ok(())
    } else {
        Err(ReplyPasswordError::InvalidArgumentCount)
    }
}

/// Parse the first argument, returning whether it indicates confirmation.
pub fn parse_first_arg(arg: &str) -> Result<bool> {
    match arg {
        "1" => Ok(true),
        "0" => Ok(false),
        _ => Err(ReplyPasswordError::InvalidFirstArgument),
    }
}

// ── Socket path validation ────────────────────────────────────────────────

/// Validate a socket path for AF_UNIX usage.
/// Corresponds to `sockaddr_un_set_path()` checks.
pub fn validate_socket_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(ReplyPasswordError::InvalidSocketPath);
    }
    // AF_UNIX paths have a maximum length (typically 108 bytes on Linux).
    const UNIX_PATH_MAX: usize = 108;
    if path.len() >= UNIX_PATH_MAX {
        return Err(ReplyPasswordError::InvalidSocketPath);
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_confirmed_encodes_correctly() {
        let packet = PasswordPacket::Confirmed("secret".to_string());
        let encoded = packet.encode();
        assert_eq!(encoded[0], b'+');
        assert_eq!(&encoded[1..7], b"secret");
        assert_eq!(encoded[7], 0);
        assert_eq!(encoded.len(), 8);
    }

    #[test]
    fn packet_confirmed_length() {
        let packet = PasswordPacket::Confirmed("test".to_string());
        assert_eq!(packet.encoded_length(), 6); // '+' + "test" + '\0'
        assert_eq!(packet.encode().len(), packet.encoded_length());
    }

    #[test]
    fn packet_cancelled_encodes_correctly() {
        let packet = PasswordPacket::Cancelled;
        let encoded = packet.encode();
        assert_eq!(encoded[0], b'-');
        assert_eq!(encoded[1], 0);
    }

    #[test]
    fn packet_cancelled_length() {
        let packet = PasswordPacket::Cancelled;
        assert_eq!(packet.encoded_length(), 2);
        assert_eq!(packet.encode().len(), 2);
    }

    #[test]
    fn from_args_confirmed() {
        let packet = PasswordPacket::from_args("1", Some("mypass")).unwrap();
        assert_eq!(packet, PasswordPacket::Confirmed("mypass".to_string()));
    }

    #[test]
    fn from_args_cancelled() {
        let packet = PasswordPacket::from_args("0", None).unwrap();
        assert_eq!(packet, PasswordPacket::Cancelled);
    }

    #[test]
    fn from_args_invalid() {
        assert!(PasswordPacket::from_args("2", None).is_err());
        assert!(PasswordPacket::from_args("yes", None).is_err());
    }

    #[test]
    fn from_args_missing_password() {
        assert!(PasswordPacket::from_args("1", None).is_err());
        assert!(PasswordPacket::from_args("1", Some("")).is_err());
    }

    #[test]
    fn validate_argc_correct() {
        assert!(validate_argc(2).is_ok());
    }

    #[test]
    fn validate_argc_wrong() {
        assert!(validate_argc(0).is_err());
        assert!(validate_argc(1).is_err());
        assert!(validate_argc(3).is_err());
    }

    #[test]
    fn parse_first_arg_valid() {
        assert_eq!(parse_first_arg("1").unwrap(), true);
        assert_eq!(parse_first_arg("0").unwrap(), false);
    }

    #[test]
    fn parse_first_arg_invalid() {
        assert!(parse_first_arg("2").is_err());
        assert!(parse_first_arg("").is_err());
    }

    #[test]
    fn validate_socket_path_ok() {
        assert!(validate_socket_path("/run/systemd/ask-password").is_ok());
    }

    #[test]
    fn validate_socket_path_empty() {
        assert!(validate_socket_path("").is_err());
    }

    #[test]
    fn validate_socket_path_too_long() {
        let long_path = "x".repeat(200);
        assert!(validate_socket_path(&long_path).is_err());
    }
}
