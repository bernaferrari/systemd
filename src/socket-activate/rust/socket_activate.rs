// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/socket-activate/socket-activate.c
//
pub const SD_LISTEN_FDS_START: i32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    Stream,
    Datagram,
    Seqpacket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen: Vec<String>,
    pub accept: bool,
    pub socket_type: SocketType,
    pub setenv: Vec<String>,
    pub fdnames: Vec<String>,
    pub inetd: bool,
    pub now: bool,
    pub command: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: Vec::new(),
            accept: false,
            socket_type: SocketType::Stream,
            setenv: Vec::new(),
            fdnames: Vec::new(),
            inetd: false,
            now: false,
            command: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivateError {
    MissingCommand,
    DatagramWithAccept,
    AcceptWithNow,
    ConflictingSocketTypes,
    InetdRequiresSingleFdWithoutAccept,
    InvalidOption(String),
}

impl std::fmt::Display for ActivateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCommand => write!(f, "command to execute is missing"),
            Self::DatagramWithAccept => write!(f, "--datagram and --accept may not be combined"),
            Self::AcceptWithNow => write!(f, "--now cannot be used in conjunction with --accept"),
            Self::ConflictingSocketTypes => {
                write!(f, "--datagram may not be combined with --seqpacket")
            }
            Self::InetdRequiresSingleFdWithoutAccept => {
                write!(f, "--inetd only supports one fd unless --accept is used")
            }
            Self::InvalidOption(s) => write!(f, "invalid option: {s}"),
        }
    }
}

impl std::error::Error for ActivateError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPlan {
    pub wait_for_connection: bool,
    pub pass_via_inetd: bool,
    pub start_fd: i32,
    pub fd_count: usize,
    pub env: Vec<String>,
}

pub fn parse_fdnames(spec: &str) -> Vec<String> {
    if spec.is_empty() {
        vec![String::new()]
    } else {
        spec.split(':').map(str::to_string).collect()
    }
}

pub fn parse_args(args: &[&str]) -> Result<Config, ActivateError> {
    let mut cfg = Config::default();
    let mut i = 0;

    while i < args.len() {
        match args[i] {
            "-l" | "--listen" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| ActivateError::InvalidOption("missing listen address".into()))?;
                cfg.listen.push((*value).to_string());
            }
            s if s.starts_with("--listen=") => cfg.listen.push(s[9..].to_string()),
            "-d" | "--datagram" => {
                if cfg.socket_type == SocketType::Seqpacket {
                    return Err(ActivateError::ConflictingSocketTypes);
                }
                cfg.socket_type = SocketType::Datagram;
            }
            "--seqpacket" => {
                if cfg.socket_type == SocketType::Datagram {
                    return Err(ActivateError::ConflictingSocketTypes);
                }
                cfg.socket_type = SocketType::Seqpacket;
            }
            "-a" | "--accept" => cfg.accept = true,
            "-E" | "--setenv" | "--environment" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| {
                    ActivateError::InvalidOption("missing environment assignment".into())
                })?;
                cfg.setenv.push((*value).to_string());
            }
            s if s.starts_with("--setenv=") => cfg.setenv.push(s[9..].to_string()),
            s if s.starts_with("--environment=") => cfg.setenv.push(s[14..].to_string()),
            "--fdname" => {
                i += 1;
                let value = args
                    .get(i)
                    .ok_or_else(|| ActivateError::InvalidOption("missing fd names".into()))?;
                cfg.fdnames.extend(parse_fdnames(value));
            }
            s if s.starts_with("--fdname=") => cfg.fdnames.extend(parse_fdnames(&s[9..])),
            "--inetd" => cfg.inetd = true,
            "--now" => cfg.now = true,
            "--" => {
                cfg.command = args[i + 1..].iter().map(|s| (*s).to_string()).collect();
                break;
            }
            s if s.starts_with('-') => return Err(ActivateError::InvalidOption(s.into())),
            _ => {
                cfg.command = args[i..].iter().map(|s| (*s).to_string()).collect();
                break;
            }
        }
        i += 1;
    }

    validate_config(&cfg)?;
    Ok(cfg)
}

pub fn validate_config(cfg: &Config) -> Result<(), ActivateError> {
    if cfg.command.is_empty() {
        return Err(ActivateError::MissingCommand);
    }
    if cfg.socket_type == SocketType::Datagram && cfg.accept {
        return Err(ActivateError::DatagramWithAccept);
    }
    if cfg.accept && cfg.now {
        return Err(ActivateError::AcceptWithNow);
    }
    Ok(())
}

pub fn extend_fdnames(mut names: Vec<String>, fd_count: usize, accept: bool) -> Vec<String> {
    if accept || names.len() != 1 || fd_count <= 1 {
        return names;
    }
    while names.len() < fd_count {
        names.push(names[0].clone());
    }
    names
}

pub fn build_child_env(
    cfg: &Config,
    start_fd: i32,
    fd_count: usize,
    listen_pid: u32,
) -> Vec<String> {
    let mut env = Vec::new();
    if !cfg.inetd {
        env.push(format!("LISTEN_FDS={fd_count}"));
        env.push(format!("LISTEN_PID={listen_pid}"));
        let names = extend_fdnames(cfg.fdnames.clone(), fd_count, cfg.accept);
        if !names.is_empty() {
            env.push(format!("LISTEN_FDNAMES={}", names.join(":")));
        }
    }
    if start_fd != SD_LISTEN_FDS_START && !cfg.inetd {
        env.push(format!("LISTEN_FDS_START={start_fd}"));
    }
    env.extend(cfg.setenv.iter().cloned());
    env
}

pub fn execution_plan(
    cfg: &Config,
    start_fd: i32,
    fd_count: usize,
    listen_pid: u32,
) -> Result<ExecutionPlan, ActivateError> {
    if cfg.inetd && !cfg.accept && fd_count != 1 {
        return Err(ActivateError::InetdRequiresSingleFdWithoutAccept);
    }
    Ok(ExecutionPlan {
        wait_for_connection: !cfg.now,
        pass_via_inetd: cfg.inetd,
        start_fd,
        fd_count,
        env: build_child_env(cfg, start_fd, fd_count, listen_pid),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_listen_and_command() {
        let cfg = parse_args(&["--listen", "127.0.0.1:80", "sh", "-c", "true"]).unwrap();
        assert_eq!(cfg.listen, vec!["127.0.0.1:80"]);
        assert_eq!(cfg.command[0], "sh");
    }

    #[test]
    fn rejects_missing_command() {
        assert_eq!(
            parse_args(&["--listen", "a"]).unwrap_err(),
            ActivateError::MissingCommand
        );
    }

    #[test]
    fn rejects_datagram_accept() {
        assert_eq!(
            parse_args(&["--datagram", "--accept", "cmd"]).unwrap_err(),
            ActivateError::DatagramWithAccept
        );
    }

    #[test]
    fn rejects_accept_now() {
        assert_eq!(
            parse_args(&["--accept", "--now", "cmd"]).unwrap_err(),
            ActivateError::AcceptWithNow
        );
    }

    #[test]
    fn parses_fdname_colon_list() {
        assert_eq!(parse_fdnames("a:b"), vec!["a", "b"]);
    }

    #[test]
    fn extends_single_fdname() {
        assert_eq!(
            extend_fdnames(vec!["http".into()], 3, false),
            vec!["http", "http", "http"]
        );
    }

    #[test]
    fn build_env_contains_activation_variables() {
        let cfg = parse_args(&["--fdname=http", "cmd"]).unwrap();
        let env = build_child_env(&cfg, 3, 2, 99);
        assert!(env.contains(&"LISTEN_FDS=2".to_string()));
        assert!(env.contains(&"LISTEN_PID=99".to_string()));
        assert!(env.contains(&"LISTEN_FDNAMES=http:http".to_string()));
    }

    #[test]
    fn inetd_requires_single_fd() {
        let cfg = parse_args(&["--inetd", "cmd"]).unwrap();
        assert_eq!(
            execution_plan(&cfg, 3, 2, 1).unwrap_err(),
            ActivateError::InetdRequiresSingleFdWithoutAccept
        );
    }
}
