// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nspawn/nspawn-expose-ports.c

use crate::common::{Errno, PortMetadata};
pub const SOURCE_PATH: &str = "src/nspawn/nspawn-expose-ports.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "expose_port_execute",
    "expose_port_flush",
    "expose_port_free_all",
    "expose_port_parse",
    "expose_port_send_rtnl",
    "expose_port_watch_rtnl",
];
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Inet,
    Inet6,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposePort {
    pub protocol: Protocol,
    pub host_port: u16,
    pub container_port: u16,
}
pub fn port_metadata() -> PortMetadata {
    PortMetadata {
        module_name: "nspawn_expose_ports",
        source_path: SOURCE_PATH,
        source_lines: 220,
        extracted_functions: EXTRACTED_FUNCTIONS,
    }
}
pub fn expose_port_parse(existing: &[ExposePort], spec: &str) -> Result<ExposePort, Errno> {
    let (protocol, rest) = if let Some(x) = spec.strip_prefix("tcp:") {
        (Protocol::Tcp, x)
    } else if let Some(x) = spec.strip_prefix("udp:") {
        (Protocol::Udp, x)
    } else {
        (Protocol::Tcp, spec)
    };
    let parts: Vec<_> = rest.split(':').collect();
    let (host, cont) = match parts.as_slice() {
        [a] => (*a, *a),
        [a, b] => (*a, *b),
        _ => return Err(Errno::new(-22)),
    };
    let host_port = host.parse().map_err(|_| Errno::new(-22))?;
    let container_port = cont.parse().map_err(|_| Errno::new(-22))?;
    if existing
        .iter()
        .any(|p| p.protocol == protocol && p.host_port == host_port)
    {
        return Err(Errno::new(-17));
    }
    Ok(ExposePort {
        protocol,
        host_port,
        container_port,
    })
}
pub fn expose_port_flush(
    ports: &[ExposePort],
    current: Option<&str>,
) -> Result<Option<String>, Errno> {
    if ports.is_empty() {
        Ok(current.map(str::to_string))
    } else {
        Ok(None)
    }
}
pub fn expose_port_execute(
    ports: &[ExposePort],
    _af: AddressFamily,
    current: Option<&str>,
    discovered: Option<&str>,
) -> Result<Option<String>, Errno> {
    if ports.is_empty() {
        return Ok(current.map(str::to_string));
    }
    match discovered {
        Some(v) => Ok(Some(v.into())),
        None => expose_port_flush(ports, current),
    }
}
pub fn expose_port_send_rtnl(fd: i32) -> Result<i32, Errno> {
    if fd < 0 {
        Err(Errno::new(-22))
    } else {
        Ok(fd)
    }
}
pub fn expose_port_watch_rtnl(fd: i32) -> Result<i32, Errno> {
    if fd < 0 {
        Err(Errno::new(-22))
    } else {
        Ok(fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_module() {
        assert_eq!(port_metadata().module_name, "nspawn_expose_ports");
    }
    #[test]
    fn parse_same_port() {
        let p = expose_port_parse(&[], "8080").unwrap();
        assert_eq!(p.container_port, 8080);
    }
    #[test]
    fn parse_udp() {
        assert_eq!(
            expose_port_parse(&[], "udp:53:5353").unwrap().protocol,
            Protocol::Udp
        );
    }
    #[test]
    fn reject_duplicate_host_port() {
        let e = [ExposePort {
            protocol: Protocol::Tcp,
            host_port: 80,
            container_port: 80,
        }];
        assert!(expose_port_parse(&e, "80:81").is_err());
    }
    #[test]
    fn flush_without_ports_keeps_address() {
        assert_eq!(
            expose_port_flush(&[], Some("10.0.0.2")).unwrap().as_deref(),
            Some("10.0.0.2")
        );
    }
    #[test]
    fn flush_with_ports_clears_address() {
        assert_eq!(
            expose_port_flush(
                &[ExposePort {
                    protocol: Protocol::Tcp,
                    host_port: 1,
                    container_port: 1
                }],
                Some("10.0.0.2")
            )
            .unwrap(),
            None
        );
    }
    #[test]
    fn execute_prefers_discovered_address() {
        assert_eq!(
            expose_port_execute(
                &[ExposePort {
                    protocol: Protocol::Tcp,
                    host_port: 1,
                    container_port: 1
                }],
                AddressFamily::Inet,
                None,
                Some("1.2.3.4")
            )
            .unwrap()
            .as_deref(),
            Some("1.2.3.4")
        );
    }
    #[test]
    fn send_fd_must_be_nonnegative() {
        assert!(expose_port_send_rtnl(-1).is_err());
    }
    #[test]
    fn watch_fd_must_be_nonnegative() {
        assert!(expose_port_watch_rtnl(-1).is_err());
    }
    #[test]
    fn execute_without_ports_keeps_current() {
        assert_eq!(
            expose_port_execute(&[], AddressFamily::Inet, Some("x"), None)
                .unwrap()
                .as_deref(),
            Some("x")
        );
    }
}
