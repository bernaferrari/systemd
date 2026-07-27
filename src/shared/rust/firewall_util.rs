// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/firewall-util.c, src/shared/firewall-util.h
//
// Firewall/nftables utility functions.
//
// Provides types and pure-logic helpers for managing nftables firewall rules,
// including NAT (masquerade/DNAT), set element management, protocol lookups,
// and address family conversions. Netlink syscalls are isolated behind safe
// abstractions.

// ── Constants ─────────────────────────────────────────────────────────────

/// Default nftables table name used by systemd.
pub const NFT_SYSTEMD_TABLE_NAME: &str = "io.systemd.nat";

/// Name of the DNAT map set (protocol+port → ip+port).
pub const NFT_SYSTEMD_DNAT_MAP_NAME: &str = "map_port_ipport";

/// Name of the masquerade source-address set.
pub const NFT_SYSTEMD_MASQ_SET_NAME: &str = "masq_saddr";

/// Default timeout for netfilter netlink operations, in microseconds.
pub const NFNL_DEFAULT_TIMEOUT_USECS: u64 = 1_000_000;

/// Offset of the destination port field in a UDP/TCP header.
pub const UDP_DPORT_OFFSET: u32 = 2;

/// Number of bits used for each nft data-type in a concatenated type.
const TYPE_BITS: u32 = 6;

// ── Enums ─────────────────────────────────────────────────────────────────

/// NFT set element source type.
///
/// Maps to `NFTSetSource` in firewall-util.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NftSetSource {
    Address,
    Prefix,
    Ifindex,
    Cgroup,
    User,
    Group,
}

impl NftSetSource {
    /// Total number of valid variants (mirrors `_NFT_SET_SOURCE_MAX`).
    pub const COUNT: usize = 6;
}

/// NFT protocol family (nfproto).
///
/// Maps to the `NFPROTO_*` constants and `nfproto_table`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NftProtocol {
    Arp,
    Bridge,
    Inet,
    Ip4,
    Ip6,
    Netdev,
}

impl NftProtocol {
    /// Total number of valid variants.
    pub const COUNT: usize = 6;

    /// Check whether the value is a valid nfproto (always true for enum variants).
    pub fn is_valid(self) -> bool {
        true
    }
}

/// NFT key data types used for set/map element type identifiers.
///
/// Values are part of the `nft` userspace tool ABI and **must not** be changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NftKeyType {
    IpAddr = 7,
    Ip6Addr = 8,
    InetProtocol = 12,
    InetService = 13,
}

/// Flags controlling which NFT set sources are accepted during config parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftSetParseFlags {
    Network,
    Cgroup,
}

/// IP protocol numbers used by nftables DNAT rules.
pub mod ip_protocol {
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
}

// ── Structs ───────────────────────────────────────────────────────────────

/// A single nftables set definition.
///
/// Mirrors the C `NFTSet` struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftSet {
    pub source: NftSetSource,
    pub nfproto: NftProtocol,
    pub table: String,
    pub set: String,
}

impl NftSet {
    pub fn new(
        source: NftSetSource,
        nfproto: NftProtocol,
        table: impl Into<String>,
        set: impl Into<String>,
    ) -> Self {
        Self {
            source,
            nfproto,
            table: table.into(),
            set: set.into(),
        }
    }
}

/// Context holding zero or more nftables sets.
///
/// Mirrors the C `NFTSetContext` struct.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NftSetContext {
    sets: Vec<NftSet>,
}

impl NftSetContext {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a set to the context.
    pub fn add(&mut self, set: NftSet) {
        self.sets.push(set);
    }

    /// Remove all sets and free resources.
    pub fn clear(&mut self) {
        self.sets.clear();
    }

    /// Returns `true` if no sets are stored.
    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }

    /// Number of stored sets.
    pub fn len(&self) -> usize {
        self.sets.len()
    }

    /// Iterate over stored sets.
    pub fn iter(&self) -> impl Iterator<Item = &NftSet> {
        self.sets.iter()
    }

    /// Deep-copy this context into a new one.
    pub fn dup(&self) -> Self {
        Self {
            sets: self.sets.clone(),
        }
    }
}

/// Error type for firewall operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallError {
    InvalidAddress,
    InvalidPort,
    InvalidPrefix,
    ProtocolNotSupported,
    SetNotFound,
    InvalidIdentifier,
    UnknownSource(String),
    UnknownProtocol(String),
    NetlinkFailed(i32),
}

impl std::fmt::Display for FirewallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallError::InvalidAddress => write!(f, "Invalid IP address"),
            FirewallError::InvalidPort => write!(f, "Invalid port number"),
            FirewallError::InvalidPrefix => write!(f, "Invalid prefix length"),
            FirewallError::ProtocolNotSupported => write!(f, "Protocol not supported"),
            FirewallError::SetNotFound => write!(f, "NFT set not found"),
            FirewallError::InvalidIdentifier => write!(f, "Invalid nft identifier"),
            FirewallError::UnknownSource(s) => write!(f, "Unknown NFT source: {s}"),
            FirewallError::UnknownProtocol(s) => write!(f, "Unknown NFT protocol family: {s}"),
            FirewallError::NetlinkFailed(code) => write!(f, "Netlink operation failed: {code}"),
        }
    }
}

impl std::error::Error for FirewallError {}

// ── String lookups ────────────────────────────────────────────────────────

/// Parse an `NftProtocol` from its string representation.
///
/// Mirrors `nfproto_from_string()` / `nfproto_table`.
pub fn nfproto_from_str(s: &str) -> Option<NftProtocol> {
    match s {
        "arp" => Some(NftProtocol::Arp),
        "bridge" => Some(NftProtocol::Bridge),
        "inet" => Some(NftProtocol::Inet),
        "ip" => Some(NftProtocol::Ip4),
        "ip6" => Some(NftProtocol::Ip6),
        "netdev" => Some(NftProtocol::Netdev),
        _ => None,
    }
}

/// Convert an `NftProtocol` to its string representation.
pub fn nfproto_to_str(p: NftProtocol) -> &'static str {
    match p {
        NftProtocol::Arp => "arp",
        NftProtocol::Bridge => "bridge",
        NftProtocol::Inet => "inet",
        NftProtocol::Ip4 => "ip",
        NftProtocol::Ip6 => "ip6",
        NftProtocol::Netdev => "netdev",
    }
}

/// Parse an `NftSetSource` from its string representation.
///
/// Mirrors `nft_set_source_from_string()` / `nft_set_source_table`.
pub fn nft_set_source_from_str(s: &str) -> Option<NftSetSource> {
    match s {
        "address" => Some(NftSetSource::Address),
        "prefix" => Some(NftSetSource::Prefix),
        "ifindex" => Some(NftSetSource::Ifindex),
        "cgroup" => Some(NftSetSource::Cgroup),
        "user" => Some(NftSetSource::User),
        "group" => Some(NftSetSource::Group),
        _ => None,
    }
}

/// Convert an `NftSetSource` to its string representation.
pub fn nft_set_source_to_str(s: NftSetSource) -> &'static str {
    match s {
        NftSetSource::Address => "address",
        NftSetSource::Prefix => "prefix",
        NftSetSource::Ifindex => "ifindex",
        NftSetSource::Cgroup => "cgroup",
        NftSetSource::User => "user",
        NftSetSource::Group => "group",
    }
}

// ── Address-family helpers ────────────────────────────────────────────────

/// Convert a socket address family to the corresponding nfproto value.
///
/// Maps to `af_to_nfproto()` in the C source.
pub fn af_to_nfproto(af: AddressFamily) -> NftProtocol {
    match af {
        AddressFamily::Inet => NftProtocol::Ip4,
        AddressFamily::Inet6 => NftProtocol::Ip6,
    }
}

/// IP address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    Inet,
    Inet6,
}

// ── Type concatenation ────────────────────────────────────────────────────

/// Concatenate two nft key types into a single 32-bit type identifier.
///
/// Maps to `concat_types2()` in the C source.
pub fn concat_types2(a: NftKeyType, b: NftKeyType) -> u32 {
    ((a as u32) << TYPE_BITS) | (b as u32)
}

// ── Validation helpers ────────────────────────────────────────────────────

/// Check whether a string is a valid nftables identifier (table or set name).
///
/// Nftables identifiers must start with a letter and contain only
/// alphanumeric characters, underscores, and dots.
pub fn nft_identifier_valid(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

/// Validate that the given source is allowed for the given parse context.
pub fn nft_set_source_valid_for(source: NftSetSource, flags: NftSetParseFlags) -> bool {
    match flags {
        NftSetParseFlags::Network => matches!(
            source,
            NftSetSource::Address | NftSetSource::Prefix | NftSetSource::Ifindex
        ),
        NftSetParseFlags::Cgroup => matches!(
            source,
            NftSetSource::Cgroup | NftSetSource::User | NftSetSource::Group
        ),
    }
}

/// Validate a port number for nftables use.
///
/// Port 0 is not valid for nftables rules.
pub fn validate_port(port: u16) -> bool {
    port > 0
}

/// Validate a protocol number for DNAT rules.
///
/// Only TCP and UDP are supported.
pub fn validate_dnat_protocol(protocol: u8) -> bool {
    matches!(protocol, ip_protocol::TCP | ip_protocol::UDP)
}

/// Validate an IPv4 prefix length.
pub fn validate_ipv4_prefix(prefixlen: u8) -> bool {
    (1..=32).contains(&prefixlen)
}

/// Validate an IPv6 prefix length (minimum 8 for nftables sets).
pub fn validate_ipv6_prefix(prefixlen: u8) -> bool {
    (8..=128).contains(&prefixlen)
}

// ── IPv4 prefix-range computation ─────────────────────────────────────────

/// Compute the IPv4 prefix range start/end addresses for a given source and prefix length.
///
/// Returns `(start_host_order, end_host_order)` where both are in host byte order.
///
/// Maps to the logic in `nft_message_append_setelem_iprange()`.
pub fn ipv4_prefix_range(source: u32, prefixlen: u8) -> Option<(u32, u32)> {
    if prefixlen == 0 || prefixlen > 32 {
        return None;
    }

    let nplen = 32 - prefixlen;
    let mask = !((1u32 << nplen) - 1);
    let start = source & mask;

    let range_size = 1u32 << nplen;
    let end = start.wrapping_add(range_size);

    // Detect overflow: if end < start, wrap to 0 (covers entire space)
    let end = if end < start { 0 } else { end };

    Some((start, end))
}

// ── Config parsing ────────────────────────────────────────────────────────

/// Parse a single NFT set tuple from the config format: `source:family:table:set`.
///
/// Returns `Some(NftSet)` on success or `None` if the tuple is malformed.
pub fn parse_nft_set_tuple(tuple: &str, flags: NftSetParseFlags) -> Result<NftSet, FirewallError> {
    let parts: Vec<&str> = tuple.split(':').collect();
    if parts.len() != 4 || parts.iter().any(|p| p.is_empty()) {
        return Err(FirewallError::InvalidIdentifier);
    }

    let source = nft_set_source_from_str(parts[0])
        .ok_or_else(|| FirewallError::UnknownSource(parts[0].to_string()))?;

    if !nft_set_source_valid_for(source, flags) {
        return Err(FirewallError::UnknownSource(parts[0].to_string()));
    }

    let nfproto = nfproto_from_str(parts[1])
        .ok_or_else(|| FirewallError::UnknownProtocol(parts[1].to_string()))?;

    let table = parts[2];
    let set = parts[3];

    if !nft_identifier_valid(table) {
        return Err(FirewallError::InvalidIdentifier);
    }
    if !nft_identifier_valid(set) {
        return Err(FirewallError::InvalidIdentifier);
    }

    Ok(NftSet::new(source, nfproto, table, set))
}

// ── DNAT key/data construction ───────────────────────────────────────────

/// Construct a DNAT map key (protocol + port) as a big-endian byte array.
///
/// Returns an 8-byte array: `[protocol: 4B, port: 4B]` (concatenation rounds
/// each field up to 4 bytes per nftables convention).
pub fn dnat_map_key(protocol: u8, port: u16) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0] = protocol;
    key[4..6].copy_from_slice(&port.to_be_bytes());
    key
}

/// Construct a DNAT map data value for IPv4 (address + port).
///
/// Returns an 8-byte array: `[addr: 4B, port: 4B]`.
pub fn dnat_map_data_ipv4(addr: [u8; 4], port: u16) -> [u8; 8] {
    let mut data = [0u8; 8];
    data[0..4].copy_from_slice(&addr);
    data[4..6].copy_from_slice(&port.to_be_bytes());
    data
}

/// Construct a DNAT map data value for IPv6 (address + port).
///
/// Returns a 20-byte array: `[addr: 16B, port: 4B]`.
pub fn dnat_map_data_ipv6(addr: [u8; 16], port: u16) -> [u8; 20] {
    let mut data = [0u8; 20];
    data[0..16].copy_from_slice(&addr);
    data[16..18].copy_from_slice(&port.to_be_bytes());
    data
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nfproto_from_str() {
        assert_eq!(nfproto_from_str("inet"), Some(NftProtocol::Inet));
        assert_eq!(nfproto_from_str("ip"), Some(NftProtocol::Ip4));
        assert_eq!(nfproto_from_str("ip6"), Some(NftProtocol::Ip6));
        assert_eq!(nfproto_from_str("arp"), Some(NftProtocol::Arp));
        assert_eq!(nfproto_from_str("bridge"), Some(NftProtocol::Bridge));
        assert_eq!(nfproto_from_str("netdev"), Some(NftProtocol::Netdev));
        assert_eq!(nfproto_from_str("invalid"), None);
        assert_eq!(nfproto_from_str(""), None);
    }

    #[test]
    fn test_nfproto_to_str_roundtrip() {
        for proto in [
            NftProtocol::Arp,
            NftProtocol::Bridge,
            NftProtocol::Inet,
            NftProtocol::Ip4,
            NftProtocol::Ip6,
            NftProtocol::Netdev,
        ] {
            assert_eq!(nfproto_from_str(nfproto_to_str(proto)), Some(proto));
        }
    }

    #[test]
    fn test_nft_set_source_from_str() {
        assert_eq!(
            nft_set_source_from_str("address"),
            Some(NftSetSource::Address)
        );
        assert_eq!(
            nft_set_source_from_str("prefix"),
            Some(NftSetSource::Prefix)
        );
        assert_eq!(
            nft_set_source_from_str("ifindex"),
            Some(NftSetSource::Ifindex)
        );
        assert_eq!(
            nft_set_source_from_str("cgroup"),
            Some(NftSetSource::Cgroup)
        );
        assert_eq!(nft_set_source_from_str("user"), Some(NftSetSource::User));
        assert_eq!(nft_set_source_from_str("group"), Some(NftSetSource::Group));
        assert_eq!(nft_set_source_from_str("invalid"), None);
    }

    #[test]
    fn test_nft_set_source_to_str_roundtrip() {
        for src in [
            NftSetSource::Address,
            NftSetSource::Prefix,
            NftSetSource::Ifindex,
            NftSetSource::Cgroup,
            NftSetSource::User,
            NftSetSource::Group,
        ] {
            assert_eq!(
                nft_set_source_from_str(nft_set_source_to_str(src)),
                Some(src)
            );
        }
    }

    #[test]
    fn test_af_to_nfproto() {
        assert_eq!(af_to_nfproto(AddressFamily::Inet), NftProtocol::Ip4);
        assert_eq!(af_to_nfproto(AddressFamily::Inet6), NftProtocol::Ip6);
    }

    #[test]
    fn test_concat_types2() {
        // ipaddr . inet_service
        let t = concat_types2(NftKeyType::IpAddr, NftKeyType::InetService);
        assert_eq!(t, (7u32 << 6) | 13);

        // inet_protocol . inet_service
        let t = concat_types2(NftKeyType::InetProtocol, NftKeyType::InetService);
        assert_eq!(t, (12u32 << 6) | 13);

        // inet_protocol . inet_service for IPv6
        let t = concat_types2(NftKeyType::InetProtocol, NftKeyType::InetService);
        assert_eq!(
            t,
            concat_types2(NftKeyType::InetProtocol, NftKeyType::InetService)
        );
    }

    #[test]
    fn test_nft_identifier_valid() {
        assert!(nft_identifier_valid("io.systemd.nat"));
        assert!(nft_identifier_valid("masq_saddr"));
        assert!(nft_identifier_valid("map_port_ipport"));
        assert!(nft_identifier_valid("a"));
        assert!(nft_identifier_valid("Table1"));

        // Must start with a letter
        assert!(!nft_identifier_valid(""));
        assert!(!nft_identifier_valid("1table"));
        assert!(!nft_identifier_valid("_table"));

        // Invalid characters
        assert!(!nft_identifier_valid("tab le"));
        assert!(!nft_identifier_valid("tab:le"));
        assert!(!nft_identifier_valid("tab-le"));
    }

    #[test]
    fn test_nft_set_source_valid_for() {
        assert!(nft_set_source_valid_for(
            NftSetSource::Address,
            NftSetParseFlags::Network
        ));
        assert!(nft_set_source_valid_for(
            NftSetSource::Ifindex,
            NftSetParseFlags::Network
        ));
        assert!(!nft_set_source_valid_for(
            NftSetSource::Cgroup,
            NftSetParseFlags::Network
        ));

        assert!(nft_set_source_valid_for(
            NftSetSource::Cgroup,
            NftSetParseFlags::Cgroup
        ));
        assert!(nft_set_source_valid_for(
            NftSetSource::User,
            NftSetParseFlags::Cgroup
        ));
        assert!(!nft_set_source_valid_for(
            NftSetSource::Address,
            NftSetParseFlags::Cgroup
        ));
    }

    #[test]
    fn test_validate_port() {
        assert!(validate_port(1));
        assert!(validate_port(80));
        assert!(validate_port(65535));
        assert!(!validate_port(0));
    }

    #[test]
    fn test_validate_dnat_protocol() {
        assert!(validate_dnat_protocol(ip_protocol::TCP));
        assert!(validate_dnat_protocol(ip_protocol::UDP));
        assert!(!validate_dnat_protocol(0));
        assert!(!validate_dnat_protocol(1)); // ICMP
        assert!(!validate_dnat_protocol(132)); // SCTP
    }

    #[test]
    fn test_validate_ipv4_prefix() {
        assert!(validate_ipv4_prefix(8));
        assert!(validate_ipv4_prefix(24));
        assert!(validate_ipv4_prefix(32));
        assert!(!validate_ipv4_prefix(0));
        assert!(!validate_ipv4_prefix(33));
    }

    #[test]
    fn test_validate_ipv6_prefix() {
        assert!(validate_ipv6_prefix(8));
        assert!(validate_ipv6_prefix(64));
        assert!(validate_ipv6_prefix(128));
        assert!(!validate_ipv6_prefix(0));
        assert!(!validate_ipv6_prefix(7));
        assert!(!validate_ipv6_prefix(129));
    }

    #[test]
    fn test_ipv4_prefix_range() {
        // 192.168.1.0/24
        let source: u32 = (192u32 << 24) | (168u32 << 16) | (1u32 << 8);
        let (start, end) = ipv4_prefix_range(source, 24).unwrap();
        assert_eq!(start, source);
        assert_eq!(end, source + 256);

        // 10.0.0.0/8
        let source: u32 = 10u32 << 24;
        let (start, end) = ipv4_prefix_range(source, 8).unwrap();
        assert_eq!(start, source);
        assert_eq!(end, source + (1u32 << 24));

        // /32 is a single address
        let source: u32 = 0xC0A80101; // 192.168.1.1
        let (start, end) = ipv4_prefix_range(source, 32).unwrap();
        assert_eq!(start, source);
        assert_eq!(end, source + 1);

        // /0 is invalid
        assert!(ipv4_prefix_range(0, 0).is_none());

        // /33 is invalid
        assert!(ipv4_prefix_range(0, 33).is_none());

        // Wrapping: 0.0.0.0/0 is invalid, but test wrap behavior
        // For a /1 starting at 0x80000000, end would overflow
        let source: u32 = 0x8000_0000;
        let (start, end) = ipv4_prefix_range(source, 1).unwrap();
        assert_eq!(start, 0x8000_0000);
        assert_eq!(end, 0); // overflow wraps to 0
    }

    #[test]
    fn test_nft_set_context() {
        let mut ctx = NftSetContext::new();
        assert!(ctx.is_empty());
        assert_eq!(ctx.len(), 0);

        ctx.add(NftSet::new(
            NftSetSource::Address,
            NftProtocol::Inet,
            "io.systemd.nat",
            "my_set",
        ));
        assert!(!ctx.is_empty());
        assert_eq!(ctx.len(), 1);

        let dup = ctx.dup();
        assert_eq!(dup, ctx);
        assert_eq!(dup.len(), 1);

        ctx.clear();
        assert!(ctx.is_empty());
        assert_eq!(ctx.len(), 0);
        // dup is unaffected
        assert_eq!(dup.len(), 1);
    }

    #[test]
    fn test_parse_nft_set_tuple_network() {
        let result = parse_nft_set_tuple(
            "address:inet:io.systemd.nat:my_set",
            NftSetParseFlags::Network,
        );
        assert!(result.is_ok());
        let s = result.unwrap();
        assert_eq!(s.source, NftSetSource::Address);
        assert_eq!(s.nfproto, NftProtocol::Inet);
        assert_eq!(s.table, "io.systemd.nat");
        assert_eq!(s.set, "my_set");

        // Cgroup source not allowed for network parse
        let result = parse_nft_set_tuple(
            "cgroup:inet:io.systemd.nat:my_set",
            NftSetParseFlags::Network,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_nft_set_tuple_cgroup() {
        let result = parse_nft_set_tuple(
            "cgroup:inet:io.systemd.nat:my_set",
            NftSetParseFlags::Cgroup,
        );
        assert!(result.is_ok());
        let s = result.unwrap();
        assert_eq!(s.source, NftSetSource::Cgroup);

        // Address source not allowed for cgroup parse
        let result = parse_nft_set_tuple(
            "address:inet:io.systemd.nat:my_set",
            NftSetParseFlags::Cgroup,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_nft_set_tuple_malformed() {
        // Not enough parts
        assert!(parse_nft_set_tuple("a:b:c", NftSetParseFlags::Network).is_err());
        // Too many parts
        assert!(parse_nft_set_tuple("a:b:c:d:e", NftSetParseFlags::Network).is_err());
        // Empty part
        assert!(parse_nft_set_tuple("a::c:d", NftSetParseFlags::Network).is_err());
        // Unknown source
        assert!(parse_nft_set_tuple("bad:inet:table:set", NftSetParseFlags::Network).is_err());
        // Unknown protocol
        assert!(
            parse_nft_set_tuple("address:badproto:table:set", NftSetParseFlags::Network).is_err()
        );
        // Invalid identifier
        assert!(parse_nft_set_tuple("address:inet:123bad:set", NftSetParseFlags::Network).is_err());
    }

    #[test]
    fn test_dnat_map_key() {
        let key = dnat_map_key(ip_protocol::TCP, 80);
        assert_eq!(key[0], ip_protocol::TCP);
        assert_eq!(&key[4..6], &80u16.to_be_bytes());
        // Remaining bytes are zero
        assert_eq!(key[1], 0);
        assert_eq!(key[2], 0);
        assert_eq!(key[3], 0);
        assert_eq!(key[6], 0);
        assert_eq!(key[7], 0);
    }

    #[test]
    fn test_dnat_map_data_ipv4() {
        let addr = [192, 168, 1, 100];
        let data = dnat_map_data_ipv4(addr, 8080);
        assert_eq!(&data[0..4], &addr);
        assert_eq!(&data[4..6], &8080u16.to_be_bytes());
        assert_eq!(data[6], 0);
        assert_eq!(data[7], 0);
    }

    #[test]
    fn test_dnat_map_data_ipv6() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let data = dnat_map_data_ipv6(addr, 443);
        assert_eq!(&data[0..16], &addr);
        assert_eq!(&data[16..18], &443u16.to_be_bytes());
        assert_eq!(data[18], 0);
        assert_eq!(data[19], 0);
    }

    #[test]
    fn test_constants() {
        assert!(!NFT_SYSTEMD_TABLE_NAME.is_empty());
        assert!(!NFT_SYSTEMD_DNAT_MAP_NAME.is_empty());
        assert!(!NFT_SYSTEMD_MASQ_SET_NAME.is_empty());
        assert_eq!(NFNL_DEFAULT_TIMEOUT_USECS, 1_000_000);
        assert_eq!(UDP_DPORT_OFFSET, 2);
    }

    #[test]
    fn test_firewall_error_display() {
        let err = FirewallError::InvalidPort;
        assert!(!err.to_string().is_empty());

        let err = FirewallError::UnknownProtocol("foo".into());
        assert!(err.to_string().contains("foo"));
    }

    #[test]
    fn test_nft_set_new() {
        let s = NftSet::new(NftSetSource::Prefix, NftProtocol::Ip6, "table", "set");
        assert_eq!(s.source, NftSetSource::Prefix);
        assert_eq!(s.nfproto, NftProtocol::Ip6);
        assert_eq!(s.table, "table");
        assert_eq!(s.set, "set");
    }
}
