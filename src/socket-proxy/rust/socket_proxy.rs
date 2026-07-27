// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/socket-proxy/socket-proxyd.c
//
pub const DEFAULT_CONNECTIONS_MAX: u32 = 256;
pub const DEFAULT_EXIT_IDLE_TIME_USEC: u64 = u64::MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteAddress {
    Unix(String),
    Tcp { host: String, port: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub connections_max: u32,
    pub exit_idle_time_usec: u64,
    pub remote_host: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyError {
    NotEnoughParameters,
    TooManyParameters,
    InvalidConnectionLimit,
    InvalidIdleTime,
    ConnectionLimitReached,
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ProxyError {}

pub fn parse_sec_to_usec(text: &str) -> Result<u64, ProxyError> {
    let secs: u64 = text.parse().map_err(|_| ProxyError::InvalidIdleTime)?;
    secs.checked_mul(1_000_000)
        .ok_or(ProxyError::InvalidIdleTime)
}

pub fn parse_remote_host(remote: &str) -> RemoteAddress {
    if remote.starts_with('/') || remote.starts_with('@') {
        return RemoteAddress::Unix(remote.to_string());
    }
    if let Some((host, port)) = remote.rsplit_once(':') {
        return RemoteAddress::Tcp {
            host: host.to_string(),
            port: port.to_string(),
        };
    }
    RemoteAddress::Tcp {
        host: remote.to_string(),
        port: "80".to_string(),
    }
}

pub fn parse_args(args: &[&str]) -> Result<Config, ProxyError> {
    let mut connections_max = DEFAULT_CONNECTIONS_MAX;
    let mut exit_idle_time_usec = DEFAULT_EXIT_IDLE_TIME_USEC;
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-c" | "--connections-max" => {
                i += 1;
                let v = args.get(i).ok_or(ProxyError::InvalidConnectionLimit)?;
                connections_max = v.parse().map_err(|_| ProxyError::InvalidConnectionLimit)?;
            }
            s if s.starts_with("--connections-max=") => {
                connections_max = s[18..]
                    .parse()
                    .map_err(|_| ProxyError::InvalidConnectionLimit)?;
            }
            "--exit-idle-time" => {
                i += 1;
                exit_idle_time_usec =
                    parse_sec_to_usec(args.get(i).ok_or(ProxyError::InvalidIdleTime)?)?;
            }
            s if s.starts_with("--exit-idle-time=") => {
                exit_idle_time_usec = parse_sec_to_usec(&s[17..])?
            }
            s if s.starts_with('-') => return Err(ProxyError::InvalidIdleTime),
            other => positional.push(other.to_string()),
        }
        i += 1;
    }
    if connections_max < 1 {
        return Err(ProxyError::InvalidConnectionLimit);
    }
    match positional.len() {
        0 => Err(ProxyError::NotEnoughParameters),
        1 => Ok(Config {
            connections_max,
            exit_idle_time_usec,
            remote_host: positional.remove(0),
        }),
        _ => Err(ProxyError::TooManyParameters),
    }
}

pub fn may_accept_connection(active: usize, limit: u32) -> Result<(), ProxyError> {
    if active as u32 > limit {
        Err(ProxyError::ConnectionLimitReached)
    } else {
        Ok(())
    }
}

pub fn should_arm_idle_timer(exit_idle_time_usec: u64, connections_empty: bool) -> bool {
    exit_idle_time_usec != DEFAULT_EXIT_IDLE_TIME_USEC && connections_empty
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_defaults() {
        let cfg = parse_args(&["example.com"]).unwrap();
        assert_eq!(cfg.connections_max, DEFAULT_CONNECTIONS_MAX);
    }

    #[test]
    fn parses_connection_limit() {
        let cfg = parse_args(&["--connections-max=5", "example.com"]).unwrap();
        assert_eq!(cfg.connections_max, 5);
    }

    #[test]
    fn parses_idle_time() {
        let cfg = parse_args(&["--exit-idle-time=3", "example.com"]).unwrap();
        assert_eq!(cfg.exit_idle_time_usec, 3_000_000);
    }

    #[test]
    fn parses_unix_destination() {
        assert_eq!(
            parse_remote_host("/run/socket"),
            RemoteAddress::Unix("/run/socket".into())
        );
    }

    #[test]
    fn parses_tcp_destination() {
        assert_eq!(
            parse_remote_host("host:99"),
            RemoteAddress::Tcp {
                host: "host".into(),
                port: "99".into()
            }
        );
    }

    #[test]
    fn defaults_port_to_80() {
        assert_eq!(
            parse_remote_host("host"),
            RemoteAddress::Tcp {
                host: "host".into(),
                port: "80".into()
            }
        );
    }

    #[test]
    fn enforces_connection_limit() {
        assert_eq!(
            may_accept_connection(6, 5).unwrap_err(),
            ProxyError::ConnectionLimitReached
        );
    }

    #[test]
    fn arms_idle_timer_only_when_empty() {
        assert!(should_arm_idle_timer(1, true));
        assert!(!should_arm_idle_timer(1, false));
    }
}
