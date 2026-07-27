// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/resolvectl.c
//
// DNS resolution control tool: hostname resolution, address resolution,
// service discovery, DNS record queries, TLSA/OpenPGP lookups,
// statistics display, and interface DNS configuration management.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ── Constants ─────────────────────────────────────────────────────────────

pub const DNS_QUERY_TIMEOUT_USEC: u64 = 30_000_000;

pub const SD_RESOLVED_DNS: u64 = 1 << 0;
pub const SD_RESOLVED_LLMNR_IPV4: u64 = 1 << 2;
pub const SD_RESOLVED_LLMNR_IPV6: u64 = 1 << 3;
pub const SD_RESOLVED_MDNS_IPV4: u64 = 1 << 4;
pub const SD_RESOLVED_MDNS_IPV6: u64 = 1 << 5;
pub const SD_RESOLVED_AUTHENTICATED: u64 = 1 << 12;
pub const SD_RESOLVED_CONFIDENTIAL: u64 = 1 << 13;
pub const SD_RESOLVED_SYNTHETIC: u64 = 1 << 15;
pub const SD_RESOLVED_FROM_CACHE: u64 = 1 << 16;
pub const SD_RESOLVED_FROM_ZONE: u64 = 1 << 17;
pub const SD_RESOLVED_FROM_TRUST_ANCHOR: u64 = 1 << 18;
pub const SD_RESOLVED_FROM_NETWORK: u64 = 1 << 19;
pub const SD_RESOLVED_FROM_HOOK: u64 = 1 << 20;
pub const SD_RESOLVED_FROM_MASK: u64 = SD_RESOLVED_FROM_CACHE
    | SD_RESOLVED_FROM_ZONE
    | SD_RESOLVED_FROM_TRUST_ANCHOR
    | SD_RESOLVED_FROM_NETWORK
    | SD_RESOLVED_FROM_HOOK;

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvectlError {
    NoAddressesFound(String),
    NoNamesFound(String),
    NoRecordsFound(String),
    NxDomain(String),
    ResolveFailed(String),
    BusError(String),
    InvalidArgument(String),
    NotSupported(String),
    DnsUriInvalid(String),
    ServiceFamilyInvalid(String),
}

impl fmt::Display for ResolvectlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolvectlError::NoAddressesFound(s) => write!(f, "{}: no addresses found", s),
            ResolvectlError::NoNamesFound(s) => write!(f, "{}: no names found", s),
            ResolvectlError::NoRecordsFound(s) => write!(f, "{}: no records found", s),
            ResolvectlError::NxDomain(s) => write!(f, "{}: NXDOMAIN", s),
            ResolvectlError::ResolveFailed(s) => write!(f, "resolve call failed: {}", s),
            ResolvectlError::BusError(s) => write!(f, "bus error: {}", s),
            ResolvectlError::InvalidArgument(s) => write!(f, "invalid argument: {}", s),
            ResolvectlError::NotSupported(s) => write!(f, "not supported: {}", s),
            ResolvectlError::DnsUriInvalid(s) => write!(f, "invalid DNS URI: {}", s),
            ResolvectlError::ServiceFamilyInvalid(s) => {
                write!(f, "invalid service family: {}", s)
            }
        }
    }
}

impl std::error::Error for ResolvectlError {}

// ── Address types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAddress {
    pub ifindex: i32,
    pub family: AddressFamily,
    pub address: IpAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Unspec,
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    pub fn from_af(af: i32) -> Option<Self> {
        match af {
            0 => Some(AddressFamily::Unspec),
            2 => Some(AddressFamily::Ipv4),
            10 => Some(AddressFamily::Ipv6),
            _ => None,
        }
    }
}

// ── Resolved host result ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHost {
    pub name: String,
    pub addresses: Vec<ResolvedAddress>,
    pub canonical: String,
    pub flags: u64,
    pub rtt_usec: u64,
}

// ── Resolved record result ─────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRecord {
    pub ifindex: i32,
    pub class: u16,
    pub rr_type: u16,
    pub data: Vec<u8>,
}

// ── Service family validation ──────────────────────────────────────────────

pub fn service_family_is_valid(s: &str) -> bool {
    matches!(s, "tcp" | "udp" | "sctp")
}

// ── RFC 4501 DNS URI parsing ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsUri {
    pub name: String,
    pub class: u16,
    pub rr_type: u16,
}

pub fn parse_rfc4501_uri(
    uri: &str,
    default_class: u16,
    default_type: u16,
) -> Result<DnsUri, ResolvectlError> {
    let s = uri
        .strip_prefix("dns:")
        .ok_or_else(|| ResolvectlError::DnsUriInvalid(uri.to_string()))?;

    let mut p = s;

    if p.starts_with('/') {
        let rest = p.strip_prefix('/').unwrap();
        if !rest.starts_with('/') {
            return Err(ResolvectlError::DnsUriInvalid(uri.to_string()));
        }
        let e = rest[1..].find('/').map(|i| i + 1);
        match e {
            Some(idx) => {
                p = &rest[1 + idx..];
            }
            None => return Err(ResolvectlError::DnsUriInvalid(uri.to_string())),
        }
    }

    let mut class: u16 = 0;
    let mut rr_type: u16 = 0;
    let name;

    if let Some(q_pos) = p.find('?') {
        name = p[..q_pos].to_string();
        let query = &p[q_pos + 1..];

        for param in query.split(';') {
            if let Some(val) = param.strip_prefix("class=") {
                if class != 0 {
                    return Err(ResolvectlError::InvalidArgument(
                        "DNS class specified twice".to_string(),
                    ));
                }
                class = dns_class_from_string(val);
            } else if let Some(val) = param.strip_prefix("type=") {
                if rr_type != 0 {
                    return Err(ResolvectlError::InvalidArgument(
                        "DNS type specified twice".to_string(),
                    ));
                }
                rr_type = dns_type_from_string(val);
            } else {
                return Err(ResolvectlError::DnsUriInvalid(uri.to_string()));
            }
        }
    } else {
        name = p.to_string();
    }

    if class == 0 {
        class = default_class;
    }
    if rr_type == 0 {
        rr_type = default_type;
    }

    Ok(DnsUri {
        name,
        class,
        rr_type,
    })
}

// ── DNS class/type helpers ─────────────────────────────────────────────────

pub fn dns_class_from_string(s: &str) -> u16 {
    match s.to_lowercase().as_str() {
        "in" => 1,
        "ch" | "chaos" => 3,
        "hs" | "hesiod" => 4,
        "none" => 254,
        "any" => 255,
        _ => 0,
    }
}

pub fn dns_type_from_string(s: &str) -> u16 {
    match s.to_uppercase().as_str() {
        "A" => 1,
        "NS" => 2,
        "CNAME" => 5,
        "SOA" => 6,
        "PTR" => 12,
        "MX" => 15,
        "TXT" => 16,
        "AAAA" => 28,
        "SRV" => 33,
        "TLSA" => 52,
        "ANY" => 255,
        _ => 0,
    }
}

// ── Source flag formatting ─────────────────────────────────────────────────

pub fn format_source_flags(flags: u64) -> String {
    let mut parts = Vec::new();

    if flags & SD_RESOLVED_DNS != 0 {
        parts.push("DNS");
    }
    if flags & SD_RESOLVED_LLMNR_IPV4 != 0 {
        parts.push("LLMNR/IPv4");
    }
    if flags & SD_RESOLVED_LLMNR_IPV6 != 0 {
        parts.push("LLMNR/IPv6");
    }
    if flags & SD_RESOLVED_MDNS_IPV4 != 0 {
        parts.push("mDNS/IPv4");
    }
    if flags & SD_RESOLVED_MDNS_IPV6 != 0 {
        parts.push("mDNS/IPv6");
    }

    let mut info = String::new();
    if !parts.is_empty() {
        info.push_str("protocol ");
        info.push_str(&parts.join(" "));
    }

    if flags & SD_RESOLVED_AUTHENTICATED != 0 {
        info.push_str("; authenticated");
    }
    if flags & SD_RESOLVED_CONFIDENTIAL != 0 {
        info.push_str("; encrypted transport");
    }

    info
}

pub fn format_data_source(flags: u64) -> String {
    let mut parts = Vec::new();
    if flags & SD_RESOLVED_SYNTHETIC != 0 {
        parts.push("synthetic");
    }
    if flags & SD_RESOLVED_FROM_CACHE != 0 {
        parts.push("cache");
    }
    if flags & SD_RESOLVED_FROM_ZONE != 0 {
        parts.push("zone");
    }
    if flags & SD_RESOLVED_FROM_TRUST_ANCHOR != 0 {
        parts.push("trust-anchor");
    }
    if flags & SD_RESOLVED_FROM_NETWORK != 0 {
        parts.push("network");
    }
    if flags & SD_RESOLVED_FROM_HOOK != 0 {
        parts.push("hook");
    }
    parts.join(", ")
}

// ── Address parsing ────────────────────────────────────────────────────────

pub fn parse_address_auto(input: &str) -> Option<(AddressFamily, IpAddr, i32)> {
    let input = input.trim();

    if let Ok(ipv4) = input.parse::<Ipv4Addr>() {
        return Some((AddressFamily::Ipv4, IpAddr::V4(ipv4), 0));
    }
    if let Ok(ipv6) = input.parse::<Ipv6Addr>() {
        return Some((AddressFamily::Ipv6, IpAddr::V6(ipv6), 0));
    }
    if let Some(percent_pos) = input.rfind('%') {
        let addr_part = &input[..percent_pos];
        let scope_part = &input[percent_pos + 1..];
        if let Ok(ipv6) = addr_part.parse::<Ipv6Addr>() {
            if let Ok(ifindex) = scope_part.parse::<i32>() {
                return Some((AddressFamily::Ipv6, IpAddr::V6(ipv6), ifindex));
            }
        }
    }
    None
}

// ── TLSA name construction ─────────────────────────────────────────────────

pub fn build_tlsa_name(
    family: &str,
    address: &str,
    default_port: u16,
) -> Result<String, ResolvectlError> {
    let (host, port) = if let Some(colon_pos) = address.rfind(':') {
        let host_part = &address[..colon_pos];
        let port_part = &address[colon_pos + 1..];
        let port: u16 = port_part.parse().map_err(|_| {
            ResolvectlError::InvalidArgument(format!("Invalid port: {}", port_part))
        })?;
        (host_part, port)
    } else {
        (address, default_port)
    };

    Ok(format!("_{}._{}.{}", port, family, host))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_family_is_valid() {
        assert!(service_family_is_valid("tcp"));
        assert!(service_family_is_valid("udp"));
        assert!(service_family_is_valid("sctp"));
        assert!(!service_family_is_valid("icmp"));
        assert!(!service_family_is_valid(""));
    }

    #[test]
    fn test_dns_class_from_string() {
        assert_eq!(dns_class_from_string("IN"), 1);
        assert_eq!(dns_class_from_string("in"), 1);
        assert_eq!(dns_class_from_string("CH"), 3);
        assert_eq!(dns_class_from_string("ANY"), 255);
        assert_eq!(dns_class_from_string("unknown"), 0);
    }

    #[test]
    fn test_dns_type_from_string() {
        assert_eq!(dns_type_from_string("A"), 1);
        assert_eq!(dns_type_from_string("aaaa"), 28);
        assert_eq!(dns_type_from_string("SRV"), 33);
        assert_eq!(dns_type_from_string("TLSA"), 52);
        assert_eq!(dns_type_from_string("unknown"), 0);
    }

    #[test]
    fn test_parse_rfc4501_simple() {
        let uri = parse_rfc4501_uri("dns:example.com", 1, 1).unwrap();
        assert_eq!(uri.name, "example.com");
        assert_eq!(uri.class, 1);
        assert_eq!(uri.rr_type, 1);
    }

    #[test]
    fn test_parse_rfc4501_with_type() {
        let uri = parse_rfc4501_uri("dns:example.com?type=AAAA", 1, 1).unwrap();
        assert_eq!(uri.name, "example.com");
        assert_eq!(uri.rr_type, 28);
    }

    #[test]
    fn test_parse_rfc4501_with_class_and_type() {
        let uri = parse_rfc4501_uri("dns:example.com?class=IN;type=MX", 1, 1).unwrap();
        assert_eq!(uri.name, "example.com");
        assert_eq!(uri.class, 1);
        assert_eq!(uri.rr_type, 15);
    }

    #[test]
    fn test_parse_rfc4501_with_authority() {
        let uri = parse_rfc4501_uri("dns://server/example.com", 1, 1).unwrap();
        assert_eq!(uri.name, "example.com");
    }

    #[test]
    fn test_parse_rfc4501_invalid() {
        assert!(parse_rfc4501_uri("notdns:example.com", 1, 1).is_err());
        assert!(parse_rfc4501_uri("dns:/broken", 1, 1).is_err());
    }

    #[test]
    fn test_format_source_flags() {
        let flags = SD_RESOLVED_DNS | SD_RESOLVED_AUTHENTICATED;
        let info = format_source_flags(flags);
        assert!(info.contains("DNS"));
        assert!(info.contains("authenticated"));
    }

    #[test]
    fn test_format_source_flags_empty() {
        assert!(format_source_flags(0).is_empty());
    }

    #[test]
    fn test_format_data_source() {
        let flags = SD_RESOLVED_FROM_CACHE | SD_RESOLVED_FROM_NETWORK;
        let info = format_data_source(flags);
        assert!(info.contains("cache"));
        assert!(info.contains("network"));
    }

    #[test]
    fn test_parse_address_auto_ipv4() {
        let result = parse_address_auto("192.168.1.1");
        let (family, _addr, ifindex) = result.unwrap();
        assert_eq!(family, AddressFamily::Ipv4);
        assert_eq!(ifindex, 0);
    }

    #[test]
    fn test_parse_address_auto_ipv6() {
        let result = parse_address_auto("::1");
        let (family, _addr, ifindex) = result.unwrap();
        assert_eq!(family, AddressFamily::Ipv6);
        assert_eq!(ifindex, 0);
    }

    #[test]
    fn test_parse_address_auto_ipv6_scoped() {
        let result = parse_address_auto("fe80::1%2");
        let (family, _addr, ifindex) = result.unwrap();
        assert_eq!(family, AddressFamily::Ipv6);
        assert_eq!(ifindex, 2);
    }

    #[test]
    fn test_parse_address_auto_hostname() {
        assert!(parse_address_auto("example.com").is_none());
    }

    #[test]
    fn test_build_tlsa_name_default_port() {
        let name = build_tlsa_name("tcp", "example.com", 443).unwrap();
        assert_eq!(name, "_443._tcp.example.com");
    }

    #[test]
    fn test_build_tlsa_name_custom_port() {
        let name = build_tlsa_name("tcp", "example.com:8443", 443).unwrap();
        assert_eq!(name, "_8443._tcp.example.com");
    }

    #[test]
    fn test_build_tlsa_name_invalid_port() {
        assert!(build_tlsa_name("tcp", "example.com:notaport", 443).is_err());
    }

    #[test]
    fn test_address_family_from_af() {
        assert_eq!(AddressFamily::from_af(0), Some(AddressFamily::Unspec));
        assert_eq!(AddressFamily::from_af(2), Some(AddressFamily::Ipv4));
        assert_eq!(AddressFamily::from_af(10), Some(AddressFamily::Ipv6));
        assert_eq!(AddressFamily::from_af(99), None);
    }
}
