// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-resolved-etc-hosts.c
//
// /etc/hosts parser tests. Validates IPv4/IPv6 address parsing,
// hostname validation (RFC 1035), comment handling, and reverse lookups.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostsError {
    InvalidAddress(String),
    InvalidHostname(String),
    IoError(String),
}

impl fmt::Display for HostsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress(a) => write!(f, "invalid address: {}", a),
            Self::InvalidHostname(h) => write!(f, "invalid hostname: {}", h),
            Self::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for HostsError {}

pub type Result<T> = std::result::Result<T, HostsError>;

// ── Address types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

fn parse_ipv4(s: &str) -> Option<Ipv4Addr> {
    s.parse::<Ipv4Addr>().ok()
}

fn parse_ipv6(s: &str) -> Option<Ipv6Addr> {
    s.parse::<Ipv6Addr>().ok()
}

pub fn parse_ip_addr(s: &str) -> Option<IpAddr> {
    if let Some(v4) = parse_ipv4(s) {
        return Some(IpAddr::V4(v4));
    }
    if let Some(v6) = parse_ipv6(s) {
        return Some(IpAddr::V6(v6));
    }
    None
}

// ── Hostname validation (RFC 1035 Section 2.3.1) ──────────────────────────

pub fn is_valid_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    if name.starts_with('-') || name.ends_with('-') {
        return false;
    }
    for label in name.split('.') {
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        for ch in label.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '-' {
                return false;
            }
        }
    }
    true
}

// ── EtcHosts data structures ───────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct HostsItemByName {
    pub addresses: HashSet<IpAddr>,
}

#[derive(Debug)]
pub struct HostsItemByAddress {
    pub names: HashSet<String>,
    pub canonical_name: String,
}

#[derive(Debug, Default)]
pub struct EtcHosts {
    pub by_name: HashMap<String, HostsItemByName>,
    pub by_address: HashMap<IpAddr, HostsItemByAddress>,
    pub no_address: HashSet<String>,
}

impl EtcHosts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.by_name.clear();
        self.by_address.clear();
        self.no_address.clear();
    }

    pub fn parse(&mut self, content: &str) -> Result<()> {
        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let line = match line.find('#') {
                Some(pos) => &line[..pos],
                None => line,
            };
            let line = line.trim_end();
            if line.is_empty() {
                continue;
            }

            let mut parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let addr_str = parts[0];
            let addr = match parse_ip_addr(addr_str) {
                Some(a) => a,
                None => continue,
            };

            let hostnames: Vec<&str> = parts[1..]
                .iter()
                .filter(|h| is_valid_hostname(h))
                .copied()
                .collect();

            if hostnames.is_empty() {
                self.no_address.insert(addr_str.to_lowercase());
                continue;
            }

            let is_zero = match &addr {
                IpAddr::V4(v4) => v4 == &Ipv4Addr::UNSPECIFIED,
                IpAddr::V6(v6) => v6 == &Ipv6Addr::UNSPECIFIED,
            };

            if is_zero {
                for name in &hostnames {
                    self.no_address.insert(name.to_lowercase());
                }
                continue;
            }

            for (i, name) in hostnames.iter().enumerate() {
                let name_lower = name.to_lowercase();

                self.by_name
                    .entry(name_lower.clone())
                    .or_default()
                    .addresses
                    .insert(addr.clone());

                let entry =
                    self.by_address
                        .entry(addr.clone())
                        .or_insert_with(|| HostsItemByAddress {
                            names: HashSet::new(),
                            canonical_name: hostnames[0].to_lowercase(),
                        });

                entry.names.insert(name_lower);

                if i == 0 {
                    entry.canonical_name = name.to_lowercase();
                }
            }
        }

        Ok(())
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn parse_simple_hosts() {
        let mut hosts = EtcHosts::new();
        hosts
            .parse("1.2.3.4 some.where\n1.2.3.5 some.where\n")
            .unwrap();

        let bn = hosts.by_name.get("some.where").unwrap();
        assert_eq!(bn.addresses.len(), 2);
        assert!(bn.addresses.contains(&ipv4(1, 2, 3, 4)));
        assert!(bn.addresses.contains(&ipv4(1, 2, 3, 5)));
    }

    #[test]
    fn parse_multiple_names_per_address() {
        let mut hosts = EtcHosts::new();
        hosts.parse("1.2.3.6 host1 host2.example.com\n").unwrap();

        let ba = hosts.by_address.get(&ipv4(1, 2, 3, 6)).unwrap();
        assert!(ba.names.contains("host1"));
        assert!(ba.names.contains("host2.example.com"));
        assert_eq!(ba.canonical_name, "host1");
    }

    #[test]
    fn parse_comments_stripped() {
        let mut hosts = EtcHosts::new();
        hosts
            .parse(
                "1.2.3.9 before.comment # within.comment\n\
             1.2.3.10 before.comment#within.comment2\n\
             1.2.3.11 before.comment# within.comment3\n\
             1.2.3.12 before.comment#\n",
            )
            .unwrap();

        let bn = hosts.by_name.get("before.comment").unwrap();
        assert_eq!(bn.addresses.len(), 4);

        assert!(!hosts.by_name.contains_key("within.comment"));
        assert!(!hosts.by_name.contains_key("within.comment2"));
        assert!(!hosts.by_name.contains_key("within.comment3"));
        assert!(!hosts.by_name.contains_key("#"));
    }

    #[test]
    fn parse_invalid_hostnames_rejected() {
        let mut hosts = EtcHosts::new();
        hosts
            .parse("1.2.3.7 bad-dash- -bad-dash -bad-dash.bad-\n")
            .unwrap();

        assert!(!hosts.by_name.contains_key("bad-dash-"));
        assert!(!hosts.by_name.contains_key("-bad-dash"));
        assert!(!hosts.by_name.contains_key("-bad-dash.bad-"));
    }

    #[test]
    fn parse_invalid_addresses_skipped() {
        let mut hosts = EtcHosts::new();
        hosts
            .parse(
                "1.2.3 short.address\n\
             1.2.3.4.5 long.address\n\
             1::2::3 multi.colon\n",
            )
            .unwrap();

        assert!(!hosts.by_name.contains_key("short.address"));
        assert!(!hosts.by_name.contains_key("long.address"));
        assert!(!hosts.by_name.contains_key("multi.colon"));
    }

    #[test]
    fn parse_zero_address_goes_to_no_address() {
        let mut hosts = EtcHosts::new();
        hosts
            .parse("0.0.0.0 deny.listed\n::0 some.where\n")
            .unwrap();

        assert!(hosts.no_address.contains("deny.listed"));
        assert!(hosts.no_address.contains("some.where"));
        assert!(!hosts.by_name.contains_key("deny.listed"));
    }

    #[test]
    fn parse_ipv6_address() {
        let mut hosts = EtcHosts::new();
        hosts.parse("::5 some.where some.other\n").unwrap();

        let bn = hosts.by_name.get("some.where").unwrap();
        assert_eq!(bn.addresses.len(), 1);

        let ba = hosts
            .by_address
            .get(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 5)))
            .unwrap();
        assert!(ba.names.contains("some.where"));
        assert!(ba.names.contains("some.other"));
    }

    #[test]
    fn is_valid_hostname_rules() {
        assert!(is_valid_hostname("example"));
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("dash-dash.where-dash"));
        assert!(is_valid_hostname("a"));
        assert!(!is_valid_hostname(""));
        assert!(!is_valid_hostname("-leading"));
        assert!(!is_valid_hostname("trailing-"));
        assert!(!is_valid_hostname("-bad-dash"));
        assert!(!is_valid_hostname("-bad-dash.bad-"));
        assert!(!is_valid_hostname("has space"));
    }

    #[test]
    fn parse_empty_lines_and_whitespace() {
        let mut hosts = EtcHosts::new();
        hosts.parse("   \n\n1.2.3.4 valid.host\n   \n").unwrap();
        assert!(hosts.by_name.contains_key("valid.host"));
    }

    #[test]
    fn parse_address_with_no_hostnames() {
        let mut hosts = EtcHosts::new();
        hosts.parse("1.2.3.8\n").unwrap();
        assert!(hosts.by_name.is_empty());
    }
}
