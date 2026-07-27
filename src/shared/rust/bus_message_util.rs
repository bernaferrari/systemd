// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/bus-message-util.c
//
// D-Bus message utility functions for reading/writing DNS servers,
// IP addresses, interface indices, and other structured data.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ── Constants ─────────────────────────────────────────────────────────────

pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;

/// Standard DNS port.
pub const DNS_PORT: u16 = 53;
/// DNS-over-TLS port.
pub const DNS_OVER_TLS_PORT: u16 = 853;

/// Size of an IPv4 address in bytes.
pub const IN4ADDRSZ: usize = 4;
/// Size of an IPv6 address in bytes.
pub const IN6ADDRSZ: usize = 16;

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusMessageError {
    /// Invalid argument passed.
    InvalidArgument(String),
    /// Invalid address family (not AF_INET or AF_INET6).
    InvalidFamily(i32),
    /// Invalid address data.
    InvalidAddress(String),
    /// Invalid DNS server address (unspecified or stub).
    InvalidDnsServerAddress(String),
    /// Invalid interface index (zero or negative).
    InvalidIfindex(i32),
    /// Unexpected array size for address data.
    InvalidSize { expected: usize, actual: usize },
    /// End of container reached.
    EndOfContainer,
    /// Container type mismatch.
    ContainerTypeMismatch { expected: char, actual: char },
    /// I/O error.
    Io(String),
}

impl fmt::Display for BusMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(s) => write!(f, "invalid argument: {s}"),
            Self::InvalidFamily(fam) => write!(f, "unknown address family {fam}"),
            Self::InvalidAddress(s) => write!(f, "invalid address: {s}"),
            Self::InvalidDnsServerAddress(s) => {
                write!(f, "invalid DNS server address: {s}")
            }
            Self::InvalidIfindex(idx) => write!(f, "invalid interface index {idx}"),
            Self::InvalidSize { expected, actual } => {
                write!(f, "invalid size: expected {expected}, got {actual}")
            }
            Self::EndOfContainer => write!(f, "end of container"),
            Self::ContainerTypeMismatch { expected, actual } => {
                write!(
                    f,
                    "container type mismatch: expected '{expected}', got '{actual}'"
                )
            }
            Self::Io(s) => write!(f, "I/O error: {s}"),
        }
    }
}

impl std::error::Error for BusMessageError {}

// ── Types ────────────────────────────────────────────────────────────────

/// A full DNS server address entry.
///
/// Mirrors C `struct in_addr_full` — holds an IP address, port, interface
/// index, and optional server name (for DoT/DoH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServerAddress {
    pub family: i32,
    pub address: IpAddr,
    pub port: u16,
    pub ifindex: i32,
    pub server_name: Option<String>,
}

impl DnsServerAddress {
    /// Create a new DNS server address with full validation.
    ///
    /// The address family must match the IP address variant.
    pub fn new(
        family: i32,
        address: IpAddr,
        port: u16,
        ifindex: i32,
        server_name: Option<String>,
    ) -> Result<Self, BusMessageError> {
        let expected = match address {
            IpAddr::V4(_) => AF_INET,
            IpAddr::V6(_) => AF_INET6,
        };
        if family != expected {
            return Err(BusMessageError::InvalidFamily(family));
        }
        Ok(Self {
            family,
            address,
            port,
            ifindex,
            server_name,
        })
    }

    /// Create from an IPv4 address with default port and ifindex.
    pub fn from_v4(addr: Ipv4Addr) -> Self {
        Self {
            family: AF_INET,
            address: IpAddr::V4(addr),
            port: 0,
            ifindex: 0,
            server_name: None,
        }
    }

    /// Create from an IPv6 address with default port and ifindex.
    pub fn from_v6(addr: Ipv6Addr) -> Self {
        Self {
            family: AF_INET6,
            address: IpAddr::V6(addr),
            port: 0,
            ifindex: 0,
            server_name: None,
        }
    }

    /// Human-readable string: `addr[:port][%ifindex][#name]`.
    pub fn to_string_repr(&self) -> String {
        let addr = match self.address {
            IpAddr::V4(a) => a.to_string(),
            IpAddr::V6(a) => format!("[{a}]"),
        };
        let mut s = addr;
        if self.port != 0 {
            s.push(':');
            s.push_str(&self.port.to_string());
        }
        if self.ifindex != 0 {
            s.push('%');
            s.push_str(&self.ifindex.to_string());
        }
        if let Some(ref name) = self.server_name {
            s.push('#');
            s.push_str(name);
        }
        s
    }
}

/// Result of reading a 128-bit ID from a D-Bus message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Id128Result {
    /// The 16-byte ID value.
    pub id: [u8; 16],
    /// Whether the ID is all-zeros (null).
    pub is_null: bool,
}

/// A serialized DNS server entry for D-Bus message writing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsServerEntry {
    /// Basic entry: `(family, address_bytes)` — D-Bus signature `(iay)`.
    Basic { family: i32, address: Vec<u8> },
    /// Extended entry: `(family, address_bytes, port, server_name)` — `(iayqs)`.
    Extended {
        family: i32,
        address: Vec<u8>,
        port: u16,
        server_name: String,
    },
}

// ── ID128 reading ────────────────────────────────────────────────────────

/// Read a 128-bit ID from a byte array.
///
/// Accepts either an empty array (returns null ID) or exactly 16 bytes.
/// Returns the ID and whether it is non-null (all zeros).
pub fn bus_message_read_id128(data: &[u8]) -> Result<Id128Result, BusMessageError> {
    match data.len() {
        0 => Ok(Id128Result {
            id: [0u8; 16],
            is_null: true,
        }),
        16 => {
            let is_null = data.iter().all(|&b| b == 0);
            let mut id = [0u8; 16];
            id.copy_from_slice(data);
            Ok(Id128Result { id, is_null })
        }
        n => Err(BusMessageError::InvalidSize {
            expected: 16,
            actual: n,
        }),
    }
}

// ── Interface index validation ───────────────────────────────────────────

/// Validate and return an interface index.
///
/// The index must be a positive integer (> 0).
pub fn bus_message_read_ifindex(ifindex: i32) -> Result<i32, BusMessageError> {
    if ifindex <= 0 {
        return Err(BusMessageError::InvalidIfindex(ifindex));
    }
    Ok(ifindex)
}

// ── Address family validation ───────────────────────────────────────────

/// Validate and return an address family.
///
/// Only `AF_INET` (2) and `AF_INET6` (10) are accepted.
pub fn bus_message_read_family(family: i32) -> Result<i32, BusMessageError> {
    match family {
        AF_INET | AF_INET6 => Ok(family),
        f => Err(BusMessageError::InvalidFamily(f)),
    }
}

// ── IP address parsing ───────────────────────────────────────────────────

/// Return the byte size of an address for the given family.
pub const fn family_address_size(family: i32) -> usize {
    match family {
        AF_INET => IN4ADDRSZ,
        AF_INET6 => IN6ADDRSZ,
        _ => 0,
    }
}

/// Parse an IP address from raw bytes, auto-detecting by family.
///
/// `family` must be `AF_INET` (expects 4 bytes) or `AF_INET6` (expects 16
/// bytes).  The byte slice must match exactly.
pub fn bus_message_read_in_addr_auto(
    family: i32,
    data: &[u8],
) -> Result<(i32, IpAddr), BusMessageError> {
    let validated_family = bus_message_read_family(family)?;
    let expected_size = family_address_size(validated_family);

    if data.len() != expected_size {
        return Err(BusMessageError::InvalidSize {
            expected: expected_size,
            actual: data.len(),
        });
    }

    let address = match validated_family {
        AF_INET => {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(data);
            IpAddr::V4(Ipv4Addr::from(bytes))
        }
        AF_INET6 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(data);
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => unreachable!("bus_message_read_family already validated"),
    };

    Ok((validated_family, address))
}

// ── DNS server address validation ───────────────────────────────────────

/// Check whether an IP address is a valid DNS server address.
///
/// Rejects unspecified (0.0.0.0 / ::) and the local DNS stub/proxy
/// addresses (127.0.0.53, 127.0.0.54).
pub fn dns_server_address_valid(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(a) => {
            !a.is_unspecified()
                && a != Ipv4Addr::new(127, 0, 0, 53)
                && a != Ipv4Addr::new(127, 0, 0, 54)
        }
        IpAddr::V6(a) => !a.is_unspecified(),
    }
}

// ── DNS server reading ───────────────────────────────────────────────────

/// Parse a single DNS server entry from its components.
///
/// When `extended` is true the entry includes a port and server name
/// (D-Bus signature `(iayqs)`).  Otherwise only family + address are
/// expected (signature `(iay)`).
///
/// Well-known DNS ports (53, 853) are normalized to 0.
pub fn bus_message_read_dns_one(
    family: i32,
    address_data: &[u8],
    port: Option<u16>,
    server_name: Option<&str>,
    extended: bool,
) -> Result<DnsServerAddress, BusMessageError> {
    let (validated_family, address) = bus_message_read_in_addr_auto(family, address_data)?;

    if !dns_server_address_valid(address) {
        return Err(BusMessageError::InvalidDnsServerAddress(format!(
            "{address}"
        )));
    }

    let (effective_port, effective_name) = if extended {
        let raw_port = port.ok_or_else(|| {
            BusMessageError::InvalidArgument("extended entry missing port".into())
        })?;
        // Normalize well-known ports to 0 (same as C code).
        let normalized = if raw_port == DNS_PORT || raw_port == DNS_OVER_TLS_PORT {
            0
        } else {
            raw_port
        };
        let name = server_name.ok_or_else(|| {
            BusMessageError::InvalidArgument("extended entry missing server name".into())
        })?;
        (normalized, Some(name.to_owned()))
    } else {
        (0, None)
    };

    DnsServerAddress::new(validated_family, address, effective_port, 0, effective_name)
}

/// Parse a list of DNS server entries.
///
/// Each element is `(family, address_bytes, port, server_name)`.  When
/// `extended` is true the port and server_name fields are required.
pub fn bus_message_read_dns_servers(
    entries: &[(i32, &[u8], Option<u16>, Option<&str>)],
    extended: bool,
) -> Result<Vec<DnsServerAddress>, BusMessageError> {
    let mut servers = Vec::with_capacity(entries.len());

    for &(family, addr_data, port, name) in entries {
        let server = bus_message_read_dns_one(family, addr_data, port, name, extended)?;
        servers.push(server);
    }

    Ok(servers)
}

// ── DNS server writing ───────────────────────────────────────────────────

/// Serialize DNS server addresses into D-Bus entry tuples.
///
/// When `extended` is true each entry includes port and server name.
pub fn bus_message_append_dns_servers(
    servers: &[DnsServerAddress],
    extended: bool,
) -> Vec<DnsServerEntry> {
    servers
        .iter()
        .map(|s| {
            let addr_bytes = match s.address {
                IpAddr::V4(a) => a.octets().to_vec(),
                IpAddr::V6(a) => a.octets().to_vec(),
            };
            if extended {
                DnsServerEntry::Extended {
                    family: s.family,
                    address: addr_bytes,
                    port: s.port,
                    server_name: s.server_name.clone().unwrap_or_default(),
                }
            } else {
                DnsServerEntry::Basic {
                    family: s.family,
                    address: addr_bytes,
                }
            }
        })
        .collect()
}

// ── String set helpers ──────────────────────────────────────────────────

/// Serialize a set of unique strings.
///
/// Returns a sorted, deduplicated list suitable for writing as a D-Bus
/// array of strings (`as`).
pub fn bus_message_append_string_set(set: &[&str]) -> Vec<String> {
    let mut sorted: Vec<String> = set.iter().map(|s| s.to_string()).collect();
    sorted.sort();
    sorted.dedup();
    sorted
}

// ── Hash operations ──────────────────────────────────────────────────────

/// Bus message hash operations for use in hash sets/maps.
///
/// Provides trivial pointer-based hashing and comparison for `sd_bus_message`
/// references managed externally.
pub struct BusMessageHashOps;

impl BusMessageHashOps {
    /// Trivial hash: uses the pointer value as the hash.
    pub fn hash(ptr: usize) -> usize {
        ptr
    }

    /// Trivial comparison: pointer equality.
    pub fn compare(a: usize, b: usize) -> std::cmp::Ordering {
        a.cmp(&b)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- id128 --

    #[test]
    fn test_read_id128_empty() {
        let result = bus_message_read_id128(&[]).unwrap();
        assert!(result.is_null);
        assert_eq!(result.id, [0u8; 16]);
    }

    #[test]
    fn test_read_id128_valid() {
        let data: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let result = bus_message_read_id128(&data).unwrap();
        assert!(!result.is_null);
        assert_eq!(result.id, data);
    }

    #[test]
    fn test_read_id128_all_zeros_is_null() {
        let data = [0u8; 16];
        let result = bus_message_read_id128(&data).unwrap();
        assert!(result.is_null);
    }

    #[test]
    fn test_read_id128_invalid_size() {
        let err = bus_message_read_id128(&[0u8; 8]).unwrap_err();
        assert_eq!(
            err,
            BusMessageError::InvalidSize {
                expected: 16,
                actual: 8
            }
        );
    }

    // -- ifindex --

    #[test]
    fn test_read_ifindex_valid() {
        assert_eq!(bus_message_read_ifindex(1).unwrap(), 1);
        assert_eq!(bus_message_read_ifindex(42).unwrap(), 42);
    }

    #[test]
    fn test_read_ifindex_zero_rejected() {
        assert_eq!(
            bus_message_read_ifindex(0),
            Err(BusMessageError::InvalidIfindex(0))
        );
    }

    #[test]
    fn test_read_ifindex_negative_rejected() {
        assert_eq!(
            bus_message_read_ifindex(-1),
            Err(BusMessageError::InvalidIfindex(-1))
        );
    }

    // -- family --

    #[test]
    fn test_read_family_inet() {
        assert_eq!(bus_message_read_family(AF_INET).unwrap(), AF_INET);
        assert_eq!(bus_message_read_family(AF_INET6).unwrap(), AF_INET6);
    }

    #[test]
    fn test_read_family_invalid() {
        assert!(bus_message_read_family(0).is_err());
        assert!(bus_message_read_family(99).is_err());
        assert_eq!(
            bus_message_read_family(3),
            Err(BusMessageError::InvalidFamily(3))
        );
    }

    // -- address size --

    #[test]
    fn test_family_address_size() {
        assert_eq!(family_address_size(AF_INET), 4);
        assert_eq!(family_address_size(AF_INET6), 16);
        assert_eq!(family_address_size(0), 0);
    }

    // -- in_addr_auto --

    #[test]
    fn test_read_in_addr_auto_v4() {
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        let (family, parsed) = bus_message_read_in_addr_auto(AF_INET, &addr.octets()).unwrap();
        assert_eq!(family, AF_INET);
        assert_eq!(parsed, IpAddr::V4(addr));
    }

    #[test]
    fn test_read_in_addr_auto_v6() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let (family, parsed) = bus_message_read_in_addr_auto(AF_INET6, &addr.octets()).unwrap();
        assert_eq!(family, AF_INET6);
        assert_eq!(parsed, IpAddr::V6(addr));
    }

    #[test]
    fn test_read_in_addr_auto_wrong_size_v4() {
        let err = bus_message_read_in_addr_auto(AF_INET, &[1, 2, 3]).unwrap_err();
        assert_eq!(
            err,
            BusMessageError::InvalidSize {
                expected: 4,
                actual: 3
            }
        );
    }

    #[test]
    fn test_read_in_addr_auto_invalid_family() {
        let err = bus_message_read_in_addr_auto(0, &[]).unwrap_err();
        assert_eq!(err, BusMessageError::InvalidFamily(0));
    }

    // -- dns_server_address_valid --

    #[test]
    fn test_dns_server_valid_v4_public() {
        assert!(dns_server_address_valid(IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
        assert!(dns_server_address_valid(IpAddr::V4(Ipv4Addr::new(
            1, 1, 1, 1
        ))));
    }

    #[test]
    fn test_dns_server_invalid_v4_unspecified_and_stubs() {
        assert!(!dns_server_address_valid(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!dns_server_address_valid(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 53
        ))));
        assert!(!dns_server_address_valid(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 54
        ))));
    }

    #[test]
    fn test_dns_server_valid_v6() {
        assert!(dns_server_address_valid(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))));
    }

    #[test]
    fn test_dns_server_invalid_v6_unspecified() {
        assert!(!dns_server_address_valid(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    // -- dns_one --

    #[test]
    fn test_read_dns_one_basic_v4() {
        let addr = Ipv4Addr::new(8, 8, 8, 8);
        let server = bus_message_read_dns_one(AF_INET, &addr.octets(), None, None, false).unwrap();
        assert_eq!(server.family, AF_INET);
        assert_eq!(server.address, IpAddr::V4(addr));
        assert_eq!(server.port, 0);
        assert!(server.server_name.is_none());
    }

    #[test]
    fn test_read_dns_one_basic_v6() {
        let addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
        let server = bus_message_read_dns_one(AF_INET6, &addr.octets(), None, None, false).unwrap();
        assert_eq!(server.family, AF_INET6);
        assert_eq!(server.address, IpAddr::V6(addr));
    }

    #[test]
    fn test_read_dns_one_extended() {
        let addr = Ipv4Addr::new(8, 8, 8, 8);
        let server = bus_message_read_dns_one(
            AF_INET,
            &addr.octets(),
            Some(5353),
            Some("dns.example.com"),
            true,
        )
        .unwrap();
        assert_eq!(server.port, 5353);
        assert_eq!(server.server_name.as_deref(), Some("dns.example.com"));
    }

    #[test]
    fn test_read_dns_one_normalizes_default_ports() {
        let addr = Ipv4Addr::new(8, 8, 8, 8);
        let s53 =
            bus_message_read_dns_one(AF_INET, &addr.octets(), Some(53), Some(""), true).unwrap();
        assert_eq!(s53.port, 0, "port 53 must normalize to 0");

        let s853 =
            bus_message_read_dns_one(AF_INET, &addr.octets(), Some(853), Some(""), true).unwrap();
        assert_eq!(s853.port, 0, "port 853 must normalize to 0");
    }

    #[test]
    fn test_read_dns_one_rejects_invalid_address() {
        let addr = Ipv4Addr::UNSPECIFIED;
        let err = bus_message_read_dns_one(AF_INET, &addr.octets(), None, None, false).unwrap_err();
        assert!(matches!(err, BusMessageError::InvalidDnsServerAddress(_)));
    }

    // -- dns_servers list --

    #[test]
    fn test_read_dns_servers_multiple() {
        let octets_a = Ipv4Addr::new(8, 8, 8, 8).octets();
        let octets_b = Ipv4Addr::new(8, 8, 4, 4).octets();
        let entries: Vec<(i32, &[u8], Option<u16>, Option<&str>)> = vec![
            (AF_INET, &octets_a, None, None),
            (AF_INET, &octets_b, None, None),
        ];
        let servers = bus_message_read_dns_servers(&entries, false).unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].address, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(servers[1].address, IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)));
    }

    // -- append --

    #[test]
    fn test_append_dns_servers_basic() {
        let servers = vec![
            DnsServerAddress::from_v4(Ipv4Addr::new(8, 8, 8, 8)),
            DnsServerAddress::from_v6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
        ];
        let entries = bus_message_append_dns_servers(&servers, false);
        assert_eq!(entries.len(), 2);
        assert!(matches!(
            &entries[0],
            DnsServerEntry::Basic { family, .. } if *family == AF_INET
        ));
        assert!(matches!(
            &entries[1],
            DnsServerEntry::Basic { family, .. } if *family == AF_INET6
        ));
    }

    #[test]
    fn test_append_dns_servers_extended() {
        let server = DnsServerAddress::new(
            AF_INET,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            5353,
            1,
            Some("dns.example.com".into()),
        )
        .unwrap();
        let entries = bus_message_append_dns_servers(&[server], true);
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            DnsServerEntry::Extended {
                family,
                address,
                port,
                server_name,
            } => {
                assert_eq!(*family, AF_INET);
                assert_eq!(address.len(), 4);
                assert_eq!(*port, 5353);
                assert_eq!(server_name, "dns.example.com");
            }
            _ => panic!("expected Extended variant"),
        }
    }

    // -- roundtrip --

    #[test]
    fn test_roundtrip_dns_servers_basic() {
        let servers = vec![
            DnsServerAddress::from_v4(Ipv4Addr::new(8, 8, 8, 8)),
            DnsServerAddress::from_v4(Ipv4Addr::new(8, 8, 4, 4)),
        ];
        let entries = bus_message_append_dns_servers(&servers, false);
        let refs: Vec<(i32, &[u8], Option<u16>, Option<&str>)> = entries
            .iter()
            .map(|e| match e {
                DnsServerEntry::Basic { family, address } => {
                    (*family, address.as_slice(), None, None)
                }
                _ => unreachable!(),
            })
            .collect();
        let recovered = bus_message_read_dns_servers(&refs, false).unwrap();
        assert_eq!(recovered, servers);
    }

    // -- string set --

    #[test]
    fn test_append_string_set_dedup_and_sort() {
        let result = bus_message_append_string_set(&["charlie", "alpha", "bravo", "alpha"]);
        assert_eq!(result, vec!["alpha", "bravo", "charlie"]);
    }

    #[test]
    fn test_append_string_set_empty() {
        let result = bus_message_append_string_set(&[]);
        assert!(result.is_empty());
    }

    // -- DnsServerAddress constructors --

    #[test]
    fn test_dns_server_address_new_valid() {
        let addr =
            DnsServerAddress::new(AF_INET, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 0, 0, None)
                .unwrap();
        assert_eq!(addr.family, AF_INET);
    }

    #[test]
    fn test_dns_server_address_new_family_mismatch() {
        let err =
            DnsServerAddress::new(AF_INET6, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 0, 0, None)
                .unwrap_err();
        assert!(matches!(err, BusMessageError::InvalidFamily(_)));
    }

    // -- to_string_repr --

    #[test]
    fn test_dns_server_to_string_repr_simple() {
        let s = DnsServerAddress::from_v4(Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(s.to_string_repr(), "8.8.8.8");
    }

    #[test]
    fn test_dns_server_to_string_repr_full() {
        let s = DnsServerAddress::new(
            AF_INET,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            2,
            Some("dns.example.com".into()),
        )
        .unwrap();
        assert_eq!(s.to_string_repr(), "8.8.8.8:53%2#dns.example.com");
    }

    #[test]
    fn test_dns_server_to_string_repr_v6() {
        let s = DnsServerAddress::from_v6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(s.to_string_repr(), "[2001:db8::1]");
    }

    // -- hash ops --

    #[test]
    fn test_hash_ops_identity() {
        assert_eq!(BusMessageHashOps::hash(0x1234), 0x1234);
        assert_eq!(BusMessageHashOps::compare(1, 2), std::cmp::Ordering::Less);
        assert_eq!(BusMessageHashOps::compare(2, 2), std::cmp::Ordering::Equal);
        assert_eq!(
            BusMessageHashOps::compare(3, 2),
            std::cmp::Ordering::Greater
        );
    }

    // -- error display --

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", BusMessageError::InvalidFamily(99)),
            "unknown address family 99"
        );
        assert_eq!(
            format!("{}", BusMessageError::InvalidIfindex(-1)),
            "invalid interface index -1"
        );
        assert_eq!(
            format!(
                "{}",
                BusMessageError::InvalidSize {
                    expected: 16,
                    actual: 8
                }
            ),
            "invalid size: expected 16, got 8"
        );
        assert_eq!(
            format!("{}", BusMessageError::InvalidArgument("bad".into())),
            "invalid argument: bad"
        );
        assert_eq!(
            format!("{}", BusMessageError::EndOfContainer),
            "end of container"
        );
    }
}
