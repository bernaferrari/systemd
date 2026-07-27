// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/tty-ask-password-agent/tty-ask-password-agent.c
//
pub const ASK_PASSWORD_DIR: &str = "/run/systemd/ask-password";
pub const ASK_FILE_PREFIX: &str = "ask.";
pub const DEFAULT_CONSOLE: &str = "/dev/console";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    List,
    Query,
    Watch,
    Wall,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AskPasswordFile {
    pub socket: Option<String>,
    pub message: Option<String>,
    pub not_after: u64,
    pub pid: u32,
    pub accept_cached: bool,
    pub echo: bool,
    pub silent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordError {
    InvalidFile,
    MissingSocket,
    InvalidAction,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PasswordError {}

pub fn parse_action(text: &str) -> Result<Action, PasswordError> {
    match text {
        "list" => Ok(Action::List),
        "query" => Ok(Action::Query),
        "watch" => Ok(Action::Watch),
        "wall" => Ok(Action::Wall),
        _ => Err(PasswordError::InvalidAction),
    }
}

pub fn is_request_file(name: &str) -> bool {
    name.starts_with(ASK_FILE_PREFIX)
}

pub fn parse_request(contents: &str) -> Result<AskPasswordFile, PasswordError> {
    let mut req = AskPasswordFile::default();
    for line in contents.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k.trim() {
            "Socket" => req.socket = Some(v.trim().to_string()),
            "Message" => req.message = Some(v.trim().to_string()),
            "NotAfter" => {
                req.not_after = v.trim().parse().map_err(|_| PasswordError::InvalidFile)?
            }
            "PID" => req.pid = v.trim().parse().map_err(|_| PasswordError::InvalidFile)?,
            "AcceptCached" => req.accept_cached = matches!(v.trim(), "1" | "yes" | "true" | "on"),
            "Echo" => req.echo = matches!(v.trim(), "1" | "yes" | "true" | "on"),
            "Silent" => req.silent = matches!(v.trim(), "1" | "yes" | "true" | "on"),
            _ => {}
        }
    }
    if req.socket.is_none() {
        return Err(PasswordError::MissingSocket);
    }
    Ok(req)
}

pub fn is_expired(req: &AskPasswordFile, now_usec: u64) -> bool {
    req.not_after > 0 && now_usec > req.not_after
}

pub fn build_password_packet(passwords: &[&str]) -> Vec<u8> {
    let mut packet = vec![b'+'];
    for p in passwords {
        packet.extend_from_slice(p.as_bytes());
        packet.push(0);
    }
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_query_action() {
        assert_eq!(parse_action("query").unwrap(), Action::Query);
    }

    #[test]
    fn rejects_invalid_action() {
        assert_eq!(
            parse_action("bad").unwrap_err(),
            PasswordError::InvalidAction
        );
    }

    #[test]
    fn recognizes_request_file_name() {
        assert!(is_request_file("ask.123"));
    }

    #[test]
    fn ignores_non_request_file_name() {
        assert!(!is_request_file("note.txt"));
    }

    #[test]
    fn parses_request_socket_and_message() {
        let req = parse_request("Socket=/run/x\nMessage=hello").unwrap();
        assert_eq!(req.message.as_deref(), Some("hello"));
    }

    #[test]
    fn request_requires_socket() {
        assert_eq!(
            parse_request("Message=x").unwrap_err(),
            PasswordError::MissingSocket
        );
    }

    #[test]
    fn expiry_is_checked() {
        let req = AskPasswordFile {
            not_after: 10,
            ..Default::default()
        };
        assert!(is_expired(&req, 11));
    }

    #[test]
    fn password_packet_matches_c_layout() {
        assert_eq!(
            build_password_packet(&["a", "b"]),
            vec![b'+', b'a', 0, b'b', 0]
        );
    }
}
