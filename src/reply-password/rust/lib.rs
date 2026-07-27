// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/reply-password/reply-password.c
pub const UNIX_PATH_MAX: usize = 107;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    WrongNumberOfArguments,
    InvalidMode(String),
    MissingPassword,
    InvalidSocketPath,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongNumberOfArguments => write!(f, "wrong number of arguments"),
            Self::InvalidMode(mode) => write!(f, "invalid first argument {mode}"),
            Self::MissingPassword => write!(f, "got EOF while reading password"),
            Self::InvalidSocketPath => write!(f, "specified socket path is invalid"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyPacket {
    Password(String),
    Cancel,
}

impl ReplyPacket {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Password(password) => {
                let mut bytes = Vec::with_capacity(password.len() + 2);
                bytes.push(b'+');
                bytes.extend_from_slice(password.as_bytes());
                bytes.push(0);
                bytes
            }
            Self::Cancel => vec![b'-'],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedSend {
    pub socket_path: String,
    pub packet: ReplyPacket,
}

pub fn validate_socket_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > UNIX_PATH_MAX || path.as_bytes().contains(&0) {
        Err(Error::InvalidSocketPath)
    } else {
        Ok(())
    }
}

pub fn build_packet(mode: &str, line: Option<&str>) -> Result<ReplyPacket> {
    match mode {
        "1" => line
            .map(|value| ReplyPacket::Password(value.to_string()))
            .ok_or(Error::MissingPassword),
        "0" => Ok(ReplyPacket::Cancel),
        other => Err(Error::InvalidMode(other.to_string())),
    }
}

pub fn parse_invocation(argv: &[&str], line: Option<&str>) -> Result<PreparedSend> {
    if argv.len() != 3 {
        return Err(Error::WrongNumberOfArguments);
    }

    validate_socket_path(argv[2])?;

    Ok(PreparedSend {
        socket_path: argv[2].to_string(),
        packet: build_packet(argv[1], line)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_socket_path_accepts_regular_unix_path() {
        assert_eq!(validate_socket_path("/run/systemd/ask-password"), Ok(()));
    }

    #[test]
    fn validate_socket_path_rejects_empty_value() {
        assert_eq!(validate_socket_path(""), Err(Error::InvalidSocketPath));
    }

    #[test]
    fn validate_socket_path_rejects_overlong_value() {
        let too_long = "x".repeat(UNIX_PATH_MAX + 1);
        assert_eq!(
            validate_socket_path(&too_long),
            Err(Error::InvalidSocketPath)
        );
    }

    #[test]
    fn password_mode_requires_stdin_line() {
        assert_eq!(build_packet("1", None), Err(Error::MissingPassword));
    }

    #[test]
    fn password_mode_prefixes_plus_and_nul_terminates() {
        let packet = build_packet("1", Some("secret")).unwrap();
        assert_eq!(packet.to_bytes(), b"+secret\0".to_vec());
    }

    #[test]
    fn cancel_mode_is_single_dash_byte() {
        let packet = build_packet("0", Some("ignored")).unwrap();
        assert_eq!(packet.to_bytes(), b"-".to_vec());
    }

    #[test]
    fn invalid_mode_is_rejected() {
        assert_eq!(
            build_packet("2", Some("pw")),
            Err(Error::InvalidMode("2".to_string()))
        );
    }

    #[test]
    fn parse_invocation_requires_exact_argument_count() {
        assert_eq!(
            parse_invocation(&["reply-password", "1"], Some("pw")),
            Err(Error::WrongNumberOfArguments)
        );
    }

    #[test]
    fn parse_invocation_returns_prepared_send() {
        let prepared = parse_invocation(
            &["reply-password", "1", "/run/systemd/ask-password"],
            Some("pw"),
        )
        .unwrap();

        assert_eq!(prepared.socket_path, "/run/systemd/ask-password");
        assert_eq!(prepared.packet.to_bytes(), b"+pw\0".to_vec());
    }
}
