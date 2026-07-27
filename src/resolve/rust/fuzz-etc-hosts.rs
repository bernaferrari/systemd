// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/fuzz-etc-hosts.c
//
// /etc/hosts parser fuzzer: converts fuzz input to a file-like structure,
// then parses it as an /etc/hosts file, exercising the host lookup tables.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EtcHostsError {
    /// Failed to parse a line.
    ParseError { line: usize, reason: String },
    /// Invalid IP address.
    InvalidAddress(String),
}

impl std::fmt::Display for EtcHostsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EtcHostsError::ParseError { line, reason } => {
                write!(f, "Parse error at line {}: {}", line, reason)
            }
            EtcHostsError::InvalidAddress(addr) => {
                write!(f, "Invalid IP address: {}", addr)
            }
        }
    }
}

impl std::error::Error for EtcHostsError {}

// ── Data structures ────────────────────────────────────────────────────────

/// Represents a parsed /etc/hosts entry mapping addresses to hostnames.
#[derive(Debug, Clone, Default)]
pub struct EtcHosts {
    /// IPv4 address to hostname mappings.
    by_address_ipv4: HashMap<Ipv4Addr, Vec<String>>,
    /// IPv6 address to hostname mappings.
    by_address_ipv6: HashMap<Ipv6Addr, Vec<String>>,
    /// Hostname to address mappings (reverse lookup).
    by_name: HashMap<String, Vec<String>>,
}

impl EtcHosts {
    /// Create a new empty EtcHosts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.by_address_ipv4.clear();
        self.by_address_ipv6.clear();
        self.by_name.clear();
    }

    /// Parse /etc/hosts content from a string.
    ///
    /// Mirrors the C `etc_hosts_parse()` function. Each non-comment,
    /// non-empty line should contain an IP address followed by one or
    /// more hostnames, separated by whitespace.
    pub fn parse(&mut self, content: &str) -> Result<(), EtcHostsError> {
        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let addr_str = parts[0];
            let hostnames: Vec<String> = parts[1..].iter().map(|s| (*s).to_string()).collect();

            if hostnames.is_empty() {
                continue;
            }

            // Try parsing as IPv4
            if let Ok(ipv4) = addr_str.parse::<Ipv4Addr>() {
                self.by_address_ipv4
                    .entry(ipv4)
                    .or_default()
                    .extend(hostnames.clone());
                for hostname in &hostnames {
                    self.by_name
                        .entry(hostname.clone())
                        .or_default()
                        .push(ipv4.to_string());
                }
                continue;
            }

            // Try parsing as IPv6
            if let Ok(ipv6) = addr_str.parse::<Ipv6Addr>() {
                self.by_address_ipv6
                    .entry(ipv6)
                    .or_default()
                    .extend(hostnames.clone());
                for hostname in &hostnames {
                    self.by_name
                        .entry(hostname.clone())
                        .or_default()
                        .push(ipv6.to_string());
                }
                continue;
            }

            // Ignore lines with unparseable addresses (mirroring C's tolerant parsing)
        }

        Ok(())
    }

    /// Look up hostnames by IPv4 address.
    pub fn lookup_ipv4(&self, addr: &Ipv4Addr) -> Option<&Vec<String>> {
        self.by_address_ipv4.get(addr)
    }

    /// Look up hostnames by IPv6 address.
    pub fn lookup_ipv6(&self, addr: &Ipv6Addr) -> Option<&Vec<String>> {
        self.by_address_ipv6.get(addr)
    }

    /// Look up addresses by hostname.
    pub fn lookup_name(&self, name: &str) -> Option<&Vec<String>> {
        self.by_name.get(name)
    }

    /// Number of IPv4 entries.
    pub fn ipv4_entry_count(&self) -> usize {
        self.by_address_ipv4.len()
    }

    /// Number of IPv6 entries.
    pub fn ipv6_entry_count(&self) -> usize {
        self.by_address_ipv6.len()
    }

    /// Total number of hostname entries.
    pub fn hostname_count(&self) -> usize {
        self.by_name.len()
    }
}

// ── Fuzz entry point ───────────────────────────────────────────────────────

/// Process fuzz input as an /etc/hosts file.
///
/// Mirrors the C `LLVMFuzzerTestOneInput`:
/// 1. Convert raw bytes to a string (lossy UTF-8)
/// 2. Parse the content as /etc/hosts
pub fn fuzz_etc_hosts(data: &[u8]) -> Result<(), EtcHostsError> {
    let content = String::from_utf8_lossy(data);
    let mut hosts = EtcHosts::new();
    hosts.parse(&content)?;
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        let mut hosts = EtcHosts::new();
        hosts.parse("").unwrap();
        assert_eq!(hosts.ipv4_entry_count(), 0);
        assert_eq!(hosts.ipv6_entry_count(), 0);
    }

    #[test]
    fn test_parse_comments_and_blanks() {
        let mut hosts = EtcHosts::new();
        hosts
            .parse("# comment\n\n  \n; semicolon comment\n# another\n")
            .unwrap();
        assert_eq!(hosts.ipv4_entry_count(), 0);
    }

    #[test]
    fn test_parse_ipv4_entry() {
        let mut hosts = EtcHosts::new();
        hosts.parse("127.0.0.1 localhost\n").unwrap();
        let addr: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let names = hosts.lookup_ipv4(&addr).unwrap();
        assert_eq!(names, &vec!["localhost".to_string()]);
    }

    #[test]
    fn test_parse_ipv4_multiple_hostnames() {
        let mut hosts = EtcHosts::new();
        hosts.parse("192.168.1.1 host1 host2 host3\n").unwrap();
        let addr: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let names = hosts.lookup_ipv4(&addr).unwrap();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"host1".to_string()));
        assert!(names.contains(&"host2".to_string()));
        assert!(names.contains(&"host3".to_string()));
    }

    #[test]
    fn test_parse_ipv6_entry() {
        let mut hosts = EtcHosts::new();
        hosts.parse("::1 localhost6 ip6-localhost\n").unwrap();
        let addr: Ipv6Addr = "::1".parse().unwrap();
        let names = hosts.lookup_ipv6(&addr).unwrap();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn test_parse_reverse_lookup() {
        let mut hosts = EtcHosts::new();
        hosts.parse("10.0.0.1 myhost\n").unwrap();
        let addrs = hosts.lookup_name("myhost").unwrap();
        assert_eq!(addrs, &vec!["10.0.0.1".to_string()]);
    }

    #[test]
    fn test_parse_multiple_lines() {
        let mut hosts = EtcHosts::new();
        let content = "\
127.0.0.1 localhost
::1 localhost6
192.168.1.1 server1 server1.local
10.0.0.1 gateway gateway.local
";
        hosts.parse(content).unwrap();
        assert_eq!(hosts.ipv4_entry_count(), 3);
        assert_eq!(hosts.ipv6_entry_count(), 1);
        assert!(hosts.lookup_name("localhost").is_some());
        assert!(hosts.lookup_name("server1").is_some());
        assert!(hosts.lookup_name("gateway.local").is_some());
    }

    #[test]
    fn test_parse_invalid_address_ignored() {
        let mut hosts = EtcHosts::new();
        hosts
            .parse("not_an_ip somehost\n192.168.1.1 validhost\n")
            .unwrap();
        assert_eq!(hosts.ipv4_entry_count(), 1);
        assert!(hosts.lookup_name("somehost").is_none());
        assert!(hosts.lookup_name("validhost").is_some());
    }

    #[test]
    fn test_parse_trailing_whitespace() {
        let mut hosts = EtcHosts::new();
        hosts.parse("  127.0.0.1   localhost   \n").unwrap();
        let addr: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let names = hosts.lookup_ipv4(&addr).unwrap();
        assert_eq!(names, &vec!["localhost".to_string()]);
    }

    #[test]
    fn test_clear() {
        let mut hosts = EtcHosts::new();
        hosts.parse("127.0.0.1 localhost\n").unwrap();
        assert_eq!(hosts.ipv4_entry_count(), 1);
        hosts.clear();
        assert_eq!(hosts.ipv4_entry_count(), 0);
        assert_eq!(hosts.ipv6_entry_count(), 0);
        assert_eq!(hosts.hostname_count(), 0);
    }

    #[test]
    fn test_fuzz_etc_hosts_empty() {
        assert!(fuzz_etc_hosts(&[]).is_ok());
    }

    #[test]
    fn test_fuzz_etc_hosts_valid() {
        let data = b"127.0.0.1 localhost\n::1 ip6-localhost\n";
        assert!(fuzz_etc_hosts(data).is_ok());
    }

    #[test]
    fn test_fuzz_etc_hosts_garbage() {
        let data: Vec<u8> = (0..255).collect();
        assert!(fuzz_etc_hosts(&data).is_ok());
    }
}
