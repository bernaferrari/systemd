// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Resolve.c
//
// Varlink interface definition for io.systemd.Resolve
// DNS resolution APIs including hostname, address, service, and record resolution.

// ── Constants ─────────────────────────────────────────────────────────────

/// Interface name for the Resolve service
pub const INTERFACE_NAME: &str = "io.systemd.Resolve";

/// Method: Resolve a hostname to IP addresses
pub const METHOD_RESOLVE_HOSTNAME: &str = "io.systemd.Resolve.ResolveHostname";

/// Method: Resolve an IP address to hostnames
pub const METHOD_RESOLVE_ADDRESS: &str = "io.systemd.Resolve.ResolveAddress";

/// Method: Resolve a DNS-SD or SRV service
pub const METHOD_RESOLVE_SERVICE: &str = "io.systemd.Resolve.ResolveService";

/// Method: Resolve a domain name to DNS resource records
pub const METHOD_RESOLVE_RECORD: &str = "io.systemd.Resolve.ResolveRecord";

/// Method: Browse for DNS-SD services
pub const METHOD_BROWSE_SERVICES: &str = "io.systemd.Resolve.BrowseServices";

/// Method: Dump current DNS configuration
pub const METHOD_DUMP_DNS_CONFIGURATION: &str = "io.systemd.Resolve.DumpDNSConfiguration";

/// Error: No name servers available
pub const ERROR_NO_NAME_SERVERS: &str = "io.systemd.Resolve.NoNameServers";

/// Error: No such resource record
pub const ERROR_NO_SUCH_RESOURCE_RECORD: &str = "io.systemd.Resolve.NoSuchResourceRecord";

/// Error: Query timed out
pub const ERROR_QUERY_TIMED_OUT: &str = "io.systemd.Resolve.QueryTimedOut";

/// Error: Maximum attempts reached
pub const ERROR_MAX_ATTEMPTS_REACHED: &str = "io.systemd.Resolve.MaxAttemptsReached";

/// Error: Invalid reply
pub const ERROR_INVALID_REPLY: &str = "io.systemd.Resolve.InvalidReply";

/// Error: DNSSEC validation failed
pub const ERROR_DNSSEC_VALIDATION_FAILED: &str = "io.systemd.Resolve.DNSSECValidationFailed";

/// Error: Network is down
pub const ERROR_NETWORK_DOWN: &str = "io.systemd.Resolve.NetworkDown";

// ── Enums ─────────────────────────────────────────────────────────────────

/// DNS protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DNSProtocol {
    /// Standard DNS
    Dns,
    /// Multicast DNS
    Mdns,
    /// Link-Local Multicast Name Resolution
    Llmnr,
}

impl DNSProtocol {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "dns" => Ok(DNSProtocol::Dns),
            "mdns" => Ok(DNSProtocol::Mdns),
            "llmnr" => Ok(DNSProtocol::Llmnr),
            _ => Err(-22),
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            DNSProtocol::Dns => "dns",
            DNSProtocol::Mdns => "mdns",
            DNSProtocol::Llmnr => "llmnr",
        }
    }
}

/// DNS-over-TLS mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DNSOverTLSMode {
    /// DNS-over-TLS is disabled
    No,
    /// DNS-over-TLS is enabled
    Yes,
    /// Try DNS-over-TLS, fallback if not supported
    Opportunistic,
}

impl DNSOverTLSMode {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "no" => Ok(DNSOverTLSMode::No),
            "yes" => Ok(DNSOverTLSMode::Yes),
            "opportunistic" => Ok(DNSOverTLSMode::Opportunistic),
            _ => Err(-22),
        }
    }

    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            DNSOverTLSMode::No => "no",
            DNSOverTLSMode::Yes => "yes",
            DNSOverTLSMode::Opportunistic => "opportunistic",
        }
    }
}

/// Resolve support state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveSupport {
    /// Protocol is disabled
    No,
    /// Protocol is enabled
    Yes,
    /// Protocol used only for resolving
    Resolve,
}

impl ResolveSupport {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "no" => Ok(ResolveSupport::No),
            "yes" => Ok(ResolveSupport::Yes),
            "resolve" => Ok(ResolveSupport::Resolve),
            _ => Err(-22),
        }
    }
}

/// /etc/resolv.conf management mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvConfMode {
    /// Symbolic link to uplink resolv.conf
    Uplink,
    /// Symbolic link to stub resolv.conf
    Stub,
    /// Symbolic link to static resolv.conf
    Static,
    /// resolv.conf does not exist
    Missing,
    /// Not managed by systemd-resolved
    Foreign,
}

impl ResolvConfMode {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "uplink" => Ok(ResolvConfMode::Uplink),
            "stub" => Ok(ResolvConfMode::Stub),
            "static" => Ok(ResolvConfMode::Static),
            "missing" => Ok(ResolvConfMode::Missing),
            "foreign" => Ok(ResolvConfMode::Foreign),
            _ => Err(-22),
        }
    }
}

/// Browse service update flag
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowseServiceUpdateFlag {
    /// Service was added
    Added,
    /// Service was removed
    Removed,
}

impl BrowseServiceUpdateFlag {
    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self, i32> {
        match s {
            "added" => Ok(BrowseServiceUpdateFlag::Added),
            "removed" => Ok(BrowseServiceUpdateFlag::Removed),
            _ => Err(-22),
        }
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

/// DNS resource record key (name + class + type)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceKey {
    /// RR class (defaults to IN/0x01 if None)
    pub class: Option<i64>,
    /// RR type (A, AAAA, PTR, etc.)
    pub rr_type: i64,
    /// Domain name
    pub name: String,
}

impl ResourceKey {
    /// Create a new ResourceKey
    pub fn new(rr_type: i64, name: impl Into<String>) -> Self {
        Self {
            class: None,
            rr_type,
            name: name.into(),
        }
    }
}

/// Parameters for ResolveHostname method
#[derive(Debug, Clone, Default)]
pub struct ResolveHostnameParams {
    /// Network interface index (None = all interfaces)
    pub ifindex: Option<i64>,
    /// Hostname to resolve
    pub name: String,
    /// Address family (AF_INET or AF_INET6)
    pub family: Option<i64>,
    /// Search flags
    pub flags: Option<i64>,
}

/// Parameters for ResolveAddress method
#[derive(Debug, Clone, Default)]
pub struct ResolveAddressParams {
    /// Network interface index
    pub ifindex: Option<i64>,
    /// Address family
    pub family: i64,
    /// IP address as integer array
    pub address: Vec<i64>,
    /// Search flags
    pub flags: Option<i64>,
}

/// Parameters for ResolveService method
#[derive(Debug, Clone, Default)]
pub struct ResolveServiceParams {
    /// DNS-SD service name
    pub name: Option<String>,
    /// Service type (e.g., "_http._tcp")
    pub service_type: Option<String>,
    /// Domain
    pub domain: String,
    /// Interface index
    pub ifindex: Option<i64>,
    /// Address family
    pub family: Option<i64>,
    /// Search flags
    pub flags: Option<i64>,
}

/// Parameters for ResolveRecord method
#[derive(Debug, Clone, Default)]
pub struct ResolveRecordParams {
    /// Interface index
    pub ifindex: Option<i64>,
    /// Domain name
    pub name: String,
    /// RR class
    pub class: Option<i64>,
    /// RR type
    pub rr_type: i64,
    /// Search flags
    pub flags: Option<i64>,
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Validate a hostname for resolution
pub fn validate_hostname(name: &str) -> Result<(), i32> {
    if name.is_empty() {
        return Err(-22); // -EINVAL
    }
    if name.len() > 253 {
        return Err(-22);
    }
    Ok(())
}

/// Validate an address family value (AF_INET=2, AF_INET6=10)
pub fn validate_address_family(family: i64) -> Result<(), i32> {
    match family {
        2 | 10 => Ok(()),
        _ => Err(-22), // -EINVAL
    }
}

/// Get the string name for an address family
pub fn address_family_name(family: i64) -> Result<&'static str, i32> {
    match family {
        2 => Ok("AF_INET"),
        10 => Ok("AF_INET6"),
        _ => Err(-22),
    }
}

/// Validate a DNS-SD service type string (e.g. "_http._tcp")
pub fn validate_service_type(svc_type: &str) -> Result<(), i32> {
    if svc_type.is_empty() {
        return Err(-22);
    }
    // Must start with underscore
    if !svc_type.starts_with('_') {
        return Err(-22);
    }
    // Must contain at least one dot separating service and protocol
    if !svc_type.contains('.') {
        return Err(-22);
    }
    Ok(())
}

/// Count the number of known error names
pub fn error_count() -> usize {
    15
}

/// Check if an error name belongs to this interface
pub fn is_known_error(name: &str) -> bool {
    matches!(
        name,
        "io.systemd.Resolve.NoNameServers"
            | "io.systemd.Resolve.NoSuchResourceRecord"
            | "io.systemd.Resolve.QueryTimedOut"
            | "io.systemd.Resolve.MaxAttemptsReached"
            | "io.systemd.Resolve.InvalidReply"
            | "io.systemd.Resolve.QueryAborted"
            | "io.systemd.Resolve.QueryRefused"
            | "io.systemd.Resolve.DNSSECValidationFailed"
            | "io.systemd.Resolve.NoTrustAnchor"
            | "io.systemd.Resolve.ResourceRecordTypeUnsupported"
            | "io.systemd.Resolve.NetworkDown"
            | "io.systemd.Resolve.NoSource"
            | "io.systemd.Resolve.StubLoop"
            | "io.systemd.Resolve.DNSError"
            | "io.systemd.Resolve.CNAMELoop"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Resolve");
    }

    #[test]
    fn test_method_names() {
        assert!(METHOD_RESOLVE_HOSTNAME.contains("ResolveHostname"));
        assert!(METHOD_RESOLVE_ADDRESS.contains("ResolveAddress"));
        assert!(METHOD_RESOLVE_SERVICE.contains("ResolveService"));
        assert!(METHOD_RESOLVE_RECORD.contains("ResolveRecord"));
        assert!(METHOD_BROWSE_SERVICES.contains("BrowseServices"));
        assert!(METHOD_DUMP_DNS_CONFIGURATION.contains("DumpDNSConfiguration"));
    }

    #[test]
    fn test_error_names() {
        assert!(ERROR_NO_NAME_SERVERS.contains("NoNameServers"));
        assert!(ERROR_NO_SUCH_RESOURCE_RECORD.contains("NoSuchResourceRecord"));
        assert!(ERROR_QUERY_TIMED_OUT.contains("QueryTimedOut"));
        assert!(ERROR_MAX_ATTEMPTS_REACHED.contains("MaxAttemptsReached"));
        assert!(ERROR_INVALID_REPLY.contains("InvalidReply"));
        assert!(ERROR_DNSSEC_VALIDATION_FAILED.contains("DNSSECValidationFailed"));
        assert!(ERROR_NETWORK_DOWN.contains("NetworkDown"));
    }

    #[test]
    fn test_dns_protocol_from_str() {
        assert_eq!(DNSProtocol::from_str("dns"), Ok(DNSProtocol::Dns));
        assert_eq!(DNSProtocol::from_str("mdns"), Ok(DNSProtocol::Mdns));
        assert_eq!(DNSProtocol::from_str("llmnr"), Ok(DNSProtocol::Llmnr));
        assert!(DNSProtocol::from_str("unknown").is_err());
    }

    #[test]
    fn test_dns_protocol_as_str() {
        assert_eq!(DNSProtocol::Dns.as_str(), "dns");
        assert_eq!(DNSProtocol::Mdns.as_str(), "mdns");
        assert_eq!(DNSProtocol::Llmnr.as_str(), "llmnr");
    }

    #[test]
    fn test_dns_over_tls_mode() {
        assert_eq!(DNSOverTLSMode::from_str("no"), Ok(DNSOverTLSMode::No));
        assert_eq!(DNSOverTLSMode::from_str("yes"), Ok(DNSOverTLSMode::Yes));
        assert_eq!(
            DNSOverTLSMode::from_str("opportunistic"),
            Ok(DNSOverTLSMode::Opportunistic)
        );
        assert!(DNSOverTLSMode::from_str("invalid").is_err());
        assert_eq!(DNSOverTLSMode::Yes.as_str(), "yes");
    }

    #[test]
    fn test_resolve_support() {
        assert_eq!(ResolveSupport::from_str("no"), Ok(ResolveSupport::No));
        assert_eq!(ResolveSupport::from_str("yes"), Ok(ResolveSupport::Yes));
        assert_eq!(
            ResolveSupport::from_str("resolve"),
            Ok(ResolveSupport::Resolve)
        );
        assert!(ResolveSupport::from_str("maybe").is_err());
    }

    #[test]
    fn test_resolv_conf_mode() {
        assert_eq!(
            ResolvConfMode::from_str("uplink"),
            Ok(ResolvConfMode::Uplink)
        );
        assert_eq!(ResolvConfMode::from_str("stub"), Ok(ResolvConfMode::Stub));
        assert_eq!(
            ResolvConfMode::from_str("static"),
            Ok(ResolvConfMode::Static)
        );
        assert_eq!(
            ResolvConfMode::from_str("missing"),
            Ok(ResolvConfMode::Missing)
        );
        assert_eq!(
            ResolvConfMode::from_str("foreign"),
            Ok(ResolvConfMode::Foreign)
        );
        assert!(ResolvConfMode::from_str("invalid").is_err());
    }

    #[test]
    fn test_browse_service_update_flag() {
        assert_eq!(
            BrowseServiceUpdateFlag::from_str("added"),
            Ok(BrowseServiceUpdateFlag::Added)
        );
        assert_eq!(
            BrowseServiceUpdateFlag::from_str("removed"),
            Ok(BrowseServiceUpdateFlag::Removed)
        );
        assert!(BrowseServiceUpdateFlag::from_str("invalid").is_err());
    }

    #[test]
    fn test_resource_key() {
        let key = ResourceKey::new(1, "example.com");
        assert_eq!(key.class, None);
        assert_eq!(key.rr_type, 1);
        assert_eq!(key.name, "example.com");
    }

    #[test]
    fn test_validate_hostname() {
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname(&"x".repeat(254)).is_err());
    }

    #[test]
    fn test_validate_address_family() {
        assert!(validate_address_family(2).is_ok()); // AF_INET
        assert!(validate_address_family(10).is_ok()); // AF_INET6
        assert!(validate_address_family(4).is_err());
    }

    #[test]
    fn test_address_family_name() {
        assert_eq!(address_family_name(2), Ok("AF_INET"));
        assert_eq!(address_family_name(10), Ok("AF_INET6"));
        assert!(address_family_name(5).is_err());
    }

    #[test]
    fn test_validate_service_type() {
        assert!(validate_service_type("_http._tcp").is_ok());
        assert!(validate_service_type("").is_err());
        assert!(validate_service_type("http").is_err());
        assert!(validate_service_type("_http").is_err());
    }

    #[test]
    fn test_error_count_and_known() {
        assert_eq!(error_count(), 15);
        assert!(is_known_error("io.systemd.Resolve.NoNameServers"));
        assert!(is_known_error("io.systemd.Resolve.NetworkDown"));
        assert!(!is_known_error("io.systemd.Resolve.UnknownError"));
    }

    #[test]
    fn test_resolve_hostname_params_default() {
        let params = ResolveHostnameParams::default();
        assert!(params.ifindex.is_none());
        assert!(params.name.is_empty());
        assert!(params.family.is_none());
        assert!(params.flags.is_none());
    }

    #[test]
    fn test_resolve_service_params_default() {
        let params = ResolveServiceParams::default();
        assert!(params.name.is_none());
        assert!(params.service_type.is_none());
        assert!(params.domain.is_empty());
    }
}
