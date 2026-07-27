// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/varlink-io.systemd.Resolve.Monitor.c
//
// Varlink interface definition for io.systemd.Resolve.Monitor.
//
// DNS resolution monitoring interface. Provides methods to subscribe to
// query results, dump the DNS cache, dump server state, dump/reset statistics,
// and subscribe to DNS configuration changes.

// ── Constants ─────────────────────────────────────────────────────────────

/// Fully qualified varlink interface name.
pub const INTERFACE_NAME: &str = "io.systemd.Resolve.Monitor";

// ── Method identifiers ────────────────────────────────────────────────────

pub const METHOD_SUBSCRIBE_QUERY_RESULTS: &str = "SubscribeQueryResults";
pub const METHOD_DUMP_CACHE: &str = "DumpCache";
pub const METHOD_DUMP_SERVER_STATE: &str = "DumpServerState";
pub const METHOD_DUMP_STATISTICS: &str = "DumpStatistics";
pub const METHOD_RESET_STATISTICS: &str = "ResetStatistics";
pub const METHOD_SUBSCRIBE_DNS_CONFIGURATION: &str = "SubscribeDNSConfiguration";

/// All method names defined by this interface.
pub fn method_names() -> &'static [&'static str] {
    &[
        METHOD_SUBSCRIBE_QUERY_RESULTS,
        METHOD_DUMP_CACHE,
        METHOD_DUMP_SERVER_STATE,
        METHOD_DUMP_STATISTICS,
        METHOD_RESET_STATISTICS,
        METHOD_SUBSCRIBE_DNS_CONFIGURATION,
    ]
}

/// Check whether a method name belongs to this interface.
pub fn has_method(name: &str) -> bool {
    method_names().contains(&name)
}

/// Typed method identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveMonitorMethod {
    SubscribeQueryResults,
    DumpCache,
    DumpServerState,
    DumpStatistics,
    ResetStatistics,
    SubscribeDNSConfiguration,
}

impl ResolveMonitorMethod {
    /// Return the varlink method name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::SubscribeQueryResults => METHOD_SUBSCRIBE_QUERY_RESULTS,
            Self::DumpCache => METHOD_DUMP_CACHE,
            Self::DumpServerState => METHOD_DUMP_SERVER_STATE,
            Self::DumpStatistics => METHOD_DUMP_STATISTICS,
            Self::ResetStatistics => METHOD_RESET_STATISTICS,
            Self::SubscribeDNSConfiguration => METHOD_SUBSCRIBE_DNS_CONFIGURATION,
        }
    }

    /// Whether the method requires the "more" flag (streaming output).
    pub fn requires_more(&self) -> bool {
        matches!(
            self,
            Self::SubscribeQueryResults | Self::SubscribeDNSConfiguration
        )
    }
}

/// Parse a method name into a typed identifier.
pub fn parse_method(name: &str) -> Result<ResolveMonitorMethod, String> {
    match name {
        METHOD_SUBSCRIBE_QUERY_RESULTS => Ok(ResolveMonitorMethod::SubscribeQueryResults),
        METHOD_DUMP_CACHE => Ok(ResolveMonitorMethod::DumpCache),
        METHOD_DUMP_SERVER_STATE => Ok(ResolveMonitorMethod::DumpServerState),
        METHOD_DUMP_STATISTICS => Ok(ResolveMonitorMethod::DumpStatistics),
        METHOD_RESET_STATISTICS => Ok(ResolveMonitorMethod::ResetStatistics),
        METHOD_SUBSCRIBE_DNS_CONFIGURATION => Ok(ResolveMonitorMethod::SubscribeDNSConfiguration),
        _ => Err(format!("unknown method: {name}")),
    }
}

// ── Struct types ──────────────────────────────────────────────────────────

/// A resource record key used in DNS lookups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceKey {
    /// DNS class.
    pub class: i64,
    /// DNS record type.
    pub r#type: i64,
    /// Domain name.
    pub name: String,
}

impl ResourceKey {
    /// Create a new ResourceKey.
    pub fn new(class: i64, r#type: i64, name: &str) -> Self {
        Self {
            class,
            r#type,
            name: name.to_string(),
        }
    }
}

/// A DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    /// Record key.
    pub key: ResourceKey,
    /// Raw record data.
    pub data: Option<String>,
}

/// A resource record array (record + raw wire data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecordArray {
    /// The resource record.
    pub rr: Option<ResourceRecord>,
    /// Raw wire-format data encoded in Base64.
    pub raw: String,
}

/// An answer with interface information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The resource record.
    pub rr: Option<ResourceRecord>,
    /// Raw wire-format data encoded in Base64.
    pub raw: String,
    /// Interface index the answer came from.
    pub ifindex: Option<i64>,
}

/// A DNS cache entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    /// The cache key (resource record key).
    pub key: ResourceKey,
    /// Resource records in this cache entry.
    pub rrs: Option<Vec<ResourceRecordArray>>,
    /// Cache entry type.
    pub entry_type: Option<String>,
    /// Expiry timestamp.
    pub until: i64,
}

/// A scope-specific DNS cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeCache {
    /// DNS protocol used.
    pub protocol: i64,
    /// Address family.
    pub family: Option<i64>,
    /// Interface index.
    pub ifindex: Option<i64>,
    /// Interface name.
    pub ifname: Option<String>,
    /// Cache entries.
    pub cache: Vec<CacheEntry>,
    /// DNSSEC state.
    pub dnssec: Option<String>,
    /// DNS-over-TLS mode.
    pub dns_over_tls: Option<i64>,
}

/// DNS server state information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerState {
    /// Server address string.
    pub server: String,
    /// Server type string.
    pub server_type: String,
    /// Interface name.
    pub interface: Option<String>,
    /// Interface index.
    pub interface_index: Option<i64>,
    /// Verified feature level.
    pub verified_feature_level: String,
    /// Possible feature level.
    pub possible_feature_level: String,
    /// DNSSEC mode.
    pub dnssec_mode: String,
    /// Whether DNSSEC is supported.
    pub dnssec_supported: bool,
    /// Max received UDP fragment size.
    pub received_udp_fragment_max: i64,
    /// Number of failed UDP attempts.
    pub failed_udp_attempts: i64,
    /// Number of failed TCP attempts.
    pub failed_tcp_attempts: i64,
    /// Whether a packet was truncated.
    pub packet_truncated: bool,
    /// Whether a packet had a bad OPT record.
    pub packet_bad_opt: bool,
    /// Whether RRSIG was missing.
    pub packet_rrsig_missing: bool,
    /// Whether a packet was invalid.
    pub packet_invalid: bool,
    /// Whether DO bit was turned off.
    pub packet_do_off: bool,
}

/// Transaction statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionStatistics {
    /// Currently active transactions.
    pub current_transactions: i64,
    /// Total transactions since startup.
    pub total_transactions: i64,
    /// Total timeouts.
    pub total_timeouts: i64,
    /// Total timeouts served from stale cache.
    pub total_timeouts_served_stale: i64,
    /// Total failed responses.
    pub total_failed_responses: i64,
    /// Total failed responses served from stale cache.
    pub total_failed_responses_served_stale: i64,
}

/// Cache statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheStatistics {
    /// Cache size (number of entries).
    pub size: i64,
    /// Number of cache hits.
    pub hits: i64,
    /// Number of cache misses.
    pub misses: i64,
}

/// DNSSEC statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnssecStatistics {
    /// Number of secure validations.
    pub secure: i64,
    /// Number of insecure validations.
    pub insecure: i64,
    /// Number of bogus validations.
    pub bogus: i64,
    /// Number of indeterminate validations.
    pub indeterminate: i64,
}

/// Error names defined by this interface.
pub fn error_names() -> &'static [&'static str] {
    &[]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_name() {
        assert_eq!(INTERFACE_NAME, "io.systemd.Resolve.Monitor");
    }

    #[test]
    fn test_method_names_count() {
        assert_eq!(method_names().len(), 6);
    }

    #[test]
    fn test_has_method() {
        assert!(has_method("SubscribeQueryResults"));
        assert!(has_method("DumpCache"));
        assert!(has_method("DumpServerState"));
        assert!(has_method("DumpStatistics"));
        assert!(has_method("ResetStatistics"));
        assert!(has_method("SubscribeDNSConfiguration"));
        assert!(!has_method("Unknown"));
    }

    #[test]
    fn test_parse_method_all() {
        assert_eq!(
            parse_method("SubscribeQueryResults"),
            Ok(ResolveMonitorMethod::SubscribeQueryResults)
        );
        assert_eq!(
            parse_method("DumpCache"),
            Ok(ResolveMonitorMethod::DumpCache)
        );
        assert_eq!(
            parse_method("DumpServerState"),
            Ok(ResolveMonitorMethod::DumpServerState)
        );
        assert_eq!(
            parse_method("DumpStatistics"),
            Ok(ResolveMonitorMethod::DumpStatistics)
        );
        assert_eq!(
            parse_method("ResetStatistics"),
            Ok(ResolveMonitorMethod::ResetStatistics)
        );
        assert_eq!(
            parse_method("SubscribeDNSConfiguration"),
            Ok(ResolveMonitorMethod::SubscribeDNSConfiguration)
        );
    }

    #[test]
    fn test_parse_method_unknown() {
        assert!(parse_method("bogus").is_err());
    }

    #[test]
    fn test_method_name_roundtrip() {
        for name in method_names() {
            let m = parse_method(name).unwrap();
            assert_eq!(m.name(), *name);
        }
    }

    #[test]
    fn test_requires_more() {
        assert!(ResolveMonitorMethod::SubscribeQueryResults.requires_more());
        assert!(ResolveMonitorMethod::SubscribeDNSConfiguration.requires_more());
        assert!(!ResolveMonitorMethod::DumpCache.requires_more());
        assert!(!ResolveMonitorMethod::DumpServerState.requires_more());
        assert!(!ResolveMonitorMethod::DumpStatistics.requires_more());
        assert!(!ResolveMonitorMethod::ResetStatistics.requires_more());
    }

    #[test]
    fn test_resource_key() {
        let key = ResourceKey::new(1, 1, "example.com");
        assert_eq!(key.class, 1);
        assert_eq!(key.r#type, 1);
        assert_eq!(key.name, "example.com");
    }

    #[test]
    fn test_cache_statistics() {
        let stats = CacheStatistics {
            size: 128,
            hits: 1024,
            misses: 64,
        };
        assert_eq!(stats.size, 128);
        assert_eq!(stats.hits, 1024);
        assert_eq!(stats.misses, 64);
    }

    #[test]
    fn test_dnssec_statistics() {
        let stats = DnssecStatistics {
            secure: 100,
            insecure: 50,
            bogus: 2,
            indeterminate: 0,
        };
        assert_eq!(stats.secure, 100);
        assert_eq!(stats.insecure, 50);
        assert_eq!(stats.bogus, 2);
        assert_eq!(stats.indeterminate, 0);
    }

    #[test]
    fn test_transaction_statistics() {
        let stats = TransactionStatistics {
            current_transactions: 3,
            total_transactions: 500,
            total_timeouts: 10,
            total_timeouts_served_stale: 2,
            total_failed_responses: 5,
            total_failed_responses_served_stale: 1,
        };
        assert_eq!(stats.current_transactions, 3);
        assert_eq!(stats.total_transactions, 500);
    }

    #[test]
    fn test_error_names_empty() {
        assert!(error_names().is_empty());
    }
}
