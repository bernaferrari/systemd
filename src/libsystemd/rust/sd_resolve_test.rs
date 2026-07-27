// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-resolve/test-resolve.c

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const TEST_TIMEOUT_USEC: u64 = 20_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrInfo {
    pub address: SocketAddr,
    pub canonical_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameInfo {
    pub host: Option<String>,
    pub service: Option<String>,
}

pub fn getaddrinfo_handler(ret: i32, records: &[AddrInfo]) -> Result<Vec<String>, String> {
    if ret != 0 {
        return Err(format!("getaddrinfo error {ret}"));
    }

    Ok(records
        .iter()
        .map(|record| record.address.ip().to_string())
        .collect())
}

pub fn getnameinfo_handler(ret: i32, info: &NameInfo) -> Result<String, String> {
    if ret != 0 {
        return Err(format!("getnameinfo error {ret}"));
    }

    Ok(format!(
        "Host: {} — Serv: {}",
        info.host.as_deref().unwrap_or(""),
        info.service.as_deref().unwrap_or("")
    ))
}

pub fn default_lookup_arguments(args: &[String]) -> (String, IpAddr) {
    let host = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "www.heise.de".into());
    let ip = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::new(193, 99, 144, 71)));
    (host, ip)
}

pub fn wait_result(sequence: &[i32]) -> Result<&'static str, String> {
    for item in sequence {
        match *item {
            0 => return Ok("completed"),
            -110 => return Ok("timed out"),
            negative if negative < 0 => return Err(format!("wait failed {negative}")),
            _ => continue,
        }
    }

    Err("wait loop did not finish".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(ip: [u8; 4], canon: Option<&str>) -> AddrInfo {
        AddrInfo {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), 80),
            canonical_name: canon.map(str::to_string),
        }
    }

    #[test]
    fn addrinfo_handler_formats_ips() {
        let out = getaddrinfo_handler(0, &[record([1, 2, 3, 4], None)]).unwrap();
        assert_eq!(out, vec!["1.2.3.4".to_string()]);
    }

    #[test]
    fn addrinfo_handler_returns_error() {
        assert!(getaddrinfo_handler(-1, &[]).is_err());
    }

    #[test]
    fn nameinfo_handler_formats_host_and_service() {
        let line = getnameinfo_handler(
            0,
            &NameInfo {
                host: Some("example.com".into()),
                service: Some("http".into()),
            },
        )
        .unwrap();
        assert_eq!(line, "Host: example.com — Serv: http");
    }

    #[test]
    fn nameinfo_handler_returns_error() {
        assert!(getnameinfo_handler(
            5,
            &NameInfo {
                host: None,
                service: None
            }
        )
        .is_err());
    }

    #[test]
    fn default_arguments_use_fallbacks() {
        let (host, ip) = default_lookup_arguments(&["test".into()]);
        assert_eq!(host, "www.heise.de");
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(193, 99, 144, 71)));
    }

    #[test]
    fn default_arguments_use_cli_overrides() {
        let (host, ip) =
            default_lookup_arguments(&["test".into(), "redhat.com".into(), "127.0.0.1".into()]);
        assert_eq!(host, "redhat.com");
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn wait_result_finishes_on_zero() {
        assert_eq!(wait_result(&[1, 1, 0]).unwrap(), "completed");
    }

    #[test]
    fn wait_result_accepts_timeout() {
        assert_eq!(wait_result(&[1, -110]).unwrap(), "timed out");
    }

    #[test]
    fn wait_result_surfaces_errors() {
        assert!(wait_result(&[-5]).is_err());
    }
}
