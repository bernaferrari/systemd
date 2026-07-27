// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/socket-proxy/socket-proxyd.c
//
// Bidirectional socket proxy daemon.
//
// Proxies local sockets to another (possibly remote) socket.
// Manages connections, DNS resolution, and idle timeout.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default maximum number of simultaneous connections.
pub const DEFAULT_CONNECTIONS_MAX: u32 = 256;

/// Default exit idle time (infinity = never exit).
pub const DEFAULT_EXIT_IDLE_TIME: u64 = u64::MAX;

/// Default remote port when none specified.
pub const DEFAULT_REMOTE_PORT: &str = "80";

// ── Enums ─────────────────────────────────────────────────────────────────

/// Result of resolving a remote host address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteAddress {
    /// Unix domain socket path (starts with '/' or '@').
    Unix(String),
    /// TCP host:port.
    Tcp { host: String, port: String },
}

// ── Structs ───────────────────────────────────────────────────────────────

/// Parsed arguments for the socket proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    /// Maximum simultaneous connections.
    pub connections_max: u32,
    /// Remote host to proxy to.
    pub remote_host: String,
    /// Exit after this idle time in microseconds.
    pub exit_idle_time: u64,
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors from socket proxy operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyError {
    /// Connection limit reached.
    ConnectionLimitReached,
    /// Too many parameters.
    TooManyParameters,
    /// Not enough parameters.
    NotEnoughParameters,
    /// Invalid connection limit.
    InvalidConnectionLimit(String),
    /// Invalid idle time.
    InvalidIdleTime(String),
    /// No sockets passed in.
    NoSocketsPassed,
    /// Event loop error.
    EventLoopError(String),
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::ConnectionLimitReached => {
                write!(f, "Hit connection limit, refusing connection.")
            }
            ProxyError::TooManyParameters => write!(f, "Too many parameters."),
            ProxyError::NotEnoughParameters => write!(f, "Not enough parameters."),
            ProxyError::InvalidConnectionLimit(s) => {
                write!(f, "Failed to parse --connections-max= argument: {}", s)
            }
            ProxyError::InvalidIdleTime(s) => {
                write!(f, "Failed to parse --exit-idle-time= argument: {}", s)
            }
            ProxyError::NoSocketsPassed => {
                write!(f, "Didn't get any sockets passed in.")
            }
            ProxyError::EventLoopError(msg) => {
                write!(f, "Failed to run event loop: {}", msg)
            }
        }
    }
}

impl std::error::Error for ProxyError {}

// ── Helper functions ──────────────────────────────────────────────────────

/// Parse the remote host specification into an address.
///
/// If the host starts with '/' or '@', it's a Unix domain socket.
/// Otherwise, it's parsed as host:port (defaulting to port 80).
pub fn parse_remote_host(remote_host: &str) -> RemoteAddress {
    if remote_host.starts_with('/') || remote_host.starts_with('@') {
        RemoteAddress::Unix(remote_host.to_string())
    } else if let Some(colon_pos) = remote_host.rfind(':') {
        RemoteAddress::Tcp {
            host: remote_host[..colon_pos].to_string(),
            port: remote_host[colon_pos + 1..].to_string(),
        }
    } else {
        RemoteAddress::Tcp {
            host: remote_host.to_string(),
            port: DEFAULT_REMOTE_PORT.to_string(),
        }
    }
}

/// Validate the connection limit.
pub fn validate_connections_max(max: u32) -> Result<u32, ProxyError> {
    if max < 1 {
        Err(ProxyError::InvalidConnectionLimit(max.to_string()))
    } else {
        Ok(max)
    }
}

/// Check if connections have reached the maximum.
pub fn at_connection_limit(current: usize, max: u32) -> bool {
    current >= max as usize
}

/// Parse a systemd-style time span into microseconds.
///
/// This covers the units accepted by `--exit-idle-time=` and permits adjacent
/// or whitespace-separated components, for example `1min 30s` and `1.5s`.
pub fn parse_time_span_usec(value: &str) -> Result<u64, ProxyError> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("infinity") {
        return Ok(DEFAULT_EXIT_IDLE_TIME);
    }
    if value.is_empty() {
        return Err(ProxyError::InvalidIdleTime(value.to_string()));
    }

    let bytes = value.as_bytes();
    let mut offset = 0usize;
    let mut total = 0u64;
    let mut parsed_any = false;

    while offset < bytes.len() {
        while offset < bytes.len() && bytes[offset].is_ascii_whitespace() {
            offset += 1;
        }
        if offset == bytes.len() {
            break;
        }

        let number_start = offset;
        while offset < bytes.len() && bytes[offset].is_ascii_digit() {
            offset += 1;
        }
        if number_start == offset {
            return Err(ProxyError::InvalidIdleTime(value.to_string()));
        }

        let whole = value[number_start..offset]
            .parse::<u64>()
            .map_err(|_| ProxyError::InvalidIdleTime(value.to_string()))?;
        let mut fraction = None;
        if offset < bytes.len() && bytes[offset] == b'.' {
            offset += 1;
            let fraction_start = offset;
            while offset < bytes.len() && bytes[offset].is_ascii_digit() {
                offset += 1;
            }
            if fraction_start == offset {
                return Err(ProxyError::InvalidIdleTime(value.to_string()));
            }
            let digits = offset - fraction_start;
            let denominator = 10u64
                .checked_pow(
                    u32::try_from(digits)
                        .map_err(|_| ProxyError::InvalidIdleTime(value.to_string()))?,
                )
                .ok_or_else(|| ProxyError::InvalidIdleTime(value.to_string()))?;
            let numerator = value[fraction_start..offset]
                .parse::<u64>()
                .map_err(|_| ProxyError::InvalidIdleTime(value.to_string()))?;
            fraction = Some((numerator, denominator));
        }

        while offset < bytes.len() && bytes[offset].is_ascii_whitespace() {
            offset += 1;
        }
        let unit_start = offset;
        while offset < bytes.len() && (bytes[offset].is_ascii_alphabetic() || bytes[offset] >= 0x80)
        {
            offset += 1;
        }
        let unit = &value[unit_start..offset];
        let multiplier = match unit {
            "" | "s" | "sec" | "second" | "seconds" => 1_000_000u64,
            "us" | "usec" | "µs" | "μs" => 1,
            "ms" | "msec" => 1_000,
            "m" | "min" | "minute" | "minutes" => 60 * 1_000_000,
            "h" | "hr" | "hour" | "hours" => 60 * 60 * 1_000_000,
            "d" | "day" | "days" => 24 * 60 * 60 * 1_000_000,
            "w" | "week" | "weeks" => 7 * 24 * 60 * 60 * 1_000_000,
            "M" | "month" | "months" => 2_629_800 * 1_000_000,
            "y" | "year" | "years" => 31_557_600 * 1_000_000,
            _ => return Err(ProxyError::InvalidIdleTime(value.to_string())),
        };

        let component = whole
            .checked_mul(multiplier)
            .ok_or_else(|| ProxyError::InvalidIdleTime(value.to_string()))?;
        total = total
            .checked_add(component)
            .ok_or_else(|| ProxyError::InvalidIdleTime(value.to_string()))?;
        if let Some((numerator, denominator)) = fraction {
            let fractional = u64::try_from(
                u128::from(numerator) * u128::from(multiplier) / u128::from(denominator),
            )
            .map_err(|_| ProxyError::InvalidIdleTime(value.to_string()))?;
            total = total
                .checked_add(fractional)
                .ok_or_else(|| ProxyError::InvalidIdleTime(value.to_string()))?;
        }
        // USEC_INFINITY is a sentinel. C's parse_sec() reserves it for the
        // explicit `infinity` spelling and rejects finite values which would
        // evaluate to this bit pattern.
        if total == DEFAULT_EXIT_IDLE_TIME {
            return Err(ProxyError::InvalidIdleTime(value.to_string()));
        }
        parsed_any = true;
    }

    if parsed_any {
        Ok(total)
    } else {
        Err(ProxyError::InvalidIdleTime(value.to_string()))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_remote_host_unix_path() {
        let addr = parse_remote_host("/run/proxy.sock");
        assert!(matches!(addr, RemoteAddress::Unix(p) if p == "/run/proxy.sock"));
    }

    #[test]
    fn test_parse_remote_host_unix_abstract() {
        let addr = parse_remote_host("@abstract_socket");
        assert!(matches!(addr, RemoteAddress::Unix(p) if p == "@abstract_socket"));
    }

    #[test]
    fn test_parse_remote_host_tcp_with_port() {
        let addr = parse_remote_host("example.com:8080");
        match addr {
            RemoteAddress::Tcp { host, port } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, "8080");
            }
            _ => panic!("Expected Tcp"),
        }
    }

    #[test]
    fn test_parse_remote_host_tcp_default_port() {
        let addr = parse_remote_host("example.com");
        match addr {
            RemoteAddress::Tcp { host, port } => {
                assert_eq!(host, "example.com");
                assert_eq!(port, DEFAULT_REMOTE_PORT);
            }
            _ => panic!("Expected Tcp"),
        }
    }

    #[test]
    fn test_validate_connections_max_valid() {
        assert_eq!(validate_connections_max(256), Ok(256));
        assert_eq!(validate_connections_max(1), Ok(1));
    }

    #[test]
    fn test_validate_connections_max_zero() {
        assert!(validate_connections_max(0).is_err());
    }

    #[test]
    fn test_at_connection_limit() {
        assert!(!at_connection_limit(100, 256));
        assert!(at_connection_limit(256, 256));
        assert!(at_connection_limit(257, 256));
    }

    #[test]
    fn test_parse_time_span_usec() {
        assert_eq!(parse_time_span_usec("5").unwrap(), 5_000_000);
        assert_eq!(parse_time_span_usec("1.5s").unwrap(), 1_500_000);
        assert_eq!(parse_time_span_usec("1min 30s").unwrap(), 90_000_000);
        assert_eq!(parse_time_span_usec("2h30min").unwrap(), 9_000_000_000);
        assert_eq!(parse_time_span_usec("17μs").unwrap(), 17);
        assert_eq!(
            parse_time_span_usec("infinity").unwrap(),
            DEFAULT_EXIT_IDLE_TIME
        );
        assert!(parse_time_span_usec("18446744073709551615us").is_err());
        assert!(parse_time_span_usec("-1s").is_err());
        assert!(parse_time_span_usec("1fortnight").is_err());
    }

    #[test]
    fn test_error_display() {
        let err = ProxyError::NoSocketsPassed;
        assert!(format!("{}", err).contains("sockets"));
    }
}
