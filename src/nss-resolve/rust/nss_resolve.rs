// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nss-resolve/nss-resolve.c
//
// NSS module for hostname resolution via systemd-resolved.
//
// Provides error classification for Varlink errors returned by
// `systemd-resolved`, scope-ID computation for IPv6 link-local
// addresses, and the data structures used in hostname resolution
/// replies.

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

pub type Result<T> = std::result::Result<T, Errno>;

// ── NSS status ────────────────────────────────────────────────────────────

/// NSS lookup return status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NssStatus {
    Success = 0,
    NotFound = 1,
    TryAgain = 2,
    Unavail = 3,
}

// ── Constants ─────────────────────────────────────────────────────────────

/// Varlink socket path for systemd-resolved.
pub const RESOLVED_VARLINK_ADDRESS: &str = "/run/systemd/resolve/io.systemd.Resolve";

/// Default query timeout in microseconds (5 seconds).
pub const RESOLVED_QUERY_TIMEOUT_USEC: u64 = 5_000_000;

// ── Error classification ─────────────────────────────────────────────────

/// Check whether a Varlink error should cause a fallback to the next
/// NSS module.
///
/// These are mostly transport/protocol errors indicating that
/// communication with `systemd-resolved` itself failed.
/// Mirrors `error_shall_fallback()` in the C source.
pub fn error_shall_fallback(error_id: &str) -> bool {
    matches!(
        error_id,
        "org.freedesktop.resolve1.NoNameServers"
            | "org.freedesktop.resolve1.ResourceNotSupported"
            | "io.systemd.Resolve.Disconnected"
            | "io.systemd.Resolve.Timeout"
            | "io.systemd.Resolve.Protocol"
            | "io.systemd.Resolve.InterfaceNotFound"
            | "io.systemd.Resolve.MethodNotFound"
            | "io.systemd.Resolve.MethodNotImplemented"
    )
}

/// Check whether a Varlink error should cause a TRY_AGAIN response,
/// indicating a transient failure (no DNS servers, timeout, network down).
///
/// Mirrors `error_shall_try_again()` in the C source.
pub fn error_shall_try_again(error_id: &str) -> bool {
    matches!(
        error_id,
        "io.systemd.Resolve.NoNameServers"
            | "io.systemd.Resolve.QueryTimedOut"
            | "io.systemd.Resolve.MaxAttemptsReached"
            | "io.systemd.Resolve.NetworkDown"
    )
}

/// Check whether the error indicates the resource was not found.
pub fn error_is_not_found(error_id: &str) -> bool {
    error_id == "io.systemd.Resolve.NoSuchResourceRecord"
}

// ── Scope ID computation ─────────────────────────────────────────────────

/// Convert an interface index to a scope ID for IPv6 addresses.
///
/// For link-local addresses, the interface index is used directly.
/// For other addresses, the scope ID is suppressed (0) because some
/// applications cannot handle it.
///
/// Mirrors `ifindex_to_scopeid()` in the C source.
pub fn ifindex_to_scopeid(family: i32, is_link_local_ipv6: bool, ifindex: i32) -> u32 {
    if family != 10 || ifindex == 0 {
        // Not IPv6 or no interface → no scope
        return 0;
    }
    if is_link_local_ipv6 {
        ifindex as u32
    } else {
        // Suppress scope ID for non-link-local addresses
        0
    }
}

// ── Resolve hostname reply ───────────────────────────────────────────────

/// Parsed reply from a `ResolveHostname` Varlink call.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolveHostnameReply {
    /// Resolved addresses.
    pub addresses: Vec<ResolvedAddress>,
    /// Canonical hostname, if returned.
    pub canonical: Option<String>,
    /// TTL in seconds.
    pub ttl: Option<u32>,
    /// Flags from the resolution.
    pub flags: u64,
}

impl ResolveHostnameReply {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_address(&mut self, addr: ResolvedAddress) {
        self.addresses.push(addr);
    }

    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }
}

/// A single resolved address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAddress {
    /// Address family (2 = IPv4, 10 = IPv6).
    pub family: i32,
    /// Interface index.
    pub ifindex: i32,
    /// Raw address bytes.
    pub address: Vec<u8>,
}

impl ResolvedAddress {
    pub fn new_ipv4(addr: [u8; 4], ifindex: i32) -> Self {
        Self {
            family: 2,
            ifindex,
            address: addr.to_vec(),
        }
    }

    pub fn new_ipv6(addr: [u8; 16], ifindex: i32) -> Self {
        Self {
            family: 10,
            ifindex,
            address: addr.to_vec(),
        }
    }

    pub fn is_ipv4(&self) -> bool {
        self.family == 2
    }

    pub fn is_ipv6(&self) -> bool {
        self.family == 10
    }
}

// ── Query flags ───────────────────────────────────────────────────────────

/// Build the query flags from environment variables.
///
/// Returns 0 in this pure-Rust implementation (the real implementation
/// reads `$SYSTEMD_NSS_RESOLVE_*` environment variables).
pub fn query_flags() -> u64 {
    0
}

/// Determine the interface index to restrict queries to.
///
/// Returns 0 (unrestricted) in this pure-Rust implementation.
pub fn query_ifindex() -> i32 {
    0
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_fallback_known() {
        assert!(error_shall_fallback(
            "org.freedesktop.resolve1.NoNameServers"
        ));
        assert!(error_shall_fallback(
            "org.freedesktop.resolve1.ResourceNotSupported"
        ));
    }

    #[test]
    fn error_fallback_transport() {
        assert!(error_shall_fallback("io.systemd.Resolve.Disconnected"));
        assert!(error_shall_fallback("io.systemd.Resolve.Timeout"));
        assert!(error_shall_fallback("io.systemd.Resolve.Protocol"));
    }

    #[test]
    fn error_fallback_unknown() {
        assert!(!error_shall_fallback("other.error"));
        assert!(!error_shall_fallback("io.systemd.Resolve.NoNameServers"));
    }

    #[test]
    fn error_try_again_known() {
        assert!(error_shall_try_again("io.systemd.Resolve.NoNameServers"));
        assert!(error_shall_try_again("io.systemd.Resolve.QueryTimedOut"));
        assert!(error_shall_try_again(
            "io.systemd.Resolve.MaxAttemptsReached"
        ));
        assert!(error_shall_try_again("io.systemd.Resolve.NetworkDown"));
    }

    #[test]
    fn error_try_again_unknown() {
        assert!(!error_shall_try_again("other.error"));
        assert!(!error_shall_try_again(
            "io.systemd.Resolve.NoSuchResourceRecord"
        ));
    }

    #[test]
    fn error_is_not_found() {
        assert!(error_is_not_found(
            "io.systemd.Resolve.NoSuchResourceRecord"
        ));
        assert!(!error_is_not_found("io.systemd.Resolve.NoNameServers"));
    }

    #[test]
    fn ifindex_to_scopeid_ipv4() {
        // IPv4 → always 0
        assert_eq!(ifindex_to_scopeid(2, false, 5), 0);
    }

    #[test]
    fn ifindex_to_scopeid_ipv6_link_local() {
        assert_eq!(ifindex_to_scopeid(10, true, 5), 5);
    }

    #[test]
    fn ifindex_to_scopeid_ipv6_non_link_local() {
        assert_eq!(ifindex_to_scopeid(10, false, 5), 0);
    }

    #[test]
    fn ifindex_to_scopeid_zero_ifindex() {
        assert_eq!(ifindex_to_scopeid(10, true, 0), 0);
    }

    #[test]
    fn reply_default_empty() {
        let reply = ResolveHostnameReply::new();
        assert!(reply.is_empty());
        assert!(reply.canonical.is_none());
        assert!(reply.ttl.is_none());
    }

    #[test]
    fn reply_add_address() {
        let mut reply = ResolveHostnameReply::new();
        reply.add_address(ResolvedAddress::new_ipv4([192, 168, 1, 1], 0));
        reply.add_address(ResolvedAddress::new_ipv6([0; 16], 1));
        assert!(!reply.is_empty());
        assert_eq!(reply.addresses.len(), 2);
    }

    #[test]
    fn resolved_address_ipv4() {
        let addr = ResolvedAddress::new_ipv4([10, 0, 0, 1], 2);
        assert!(addr.is_ipv4());
        assert!(!addr.is_ipv6());
        assert_eq!(addr.address.len(), 4);
        assert_eq!(addr.ifindex, 2);
    }

    #[test]
    fn resolved_address_ipv6() {
        let addr =
            ResolvedAddress::new_ipv6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 3);
        assert!(addr.is_ipv6());
        assert!(!addr.is_ipv4());
        assert_eq!(addr.address.len(), 16);
        assert_eq!(addr.ifindex, 3);
    }

    #[test]
    fn query_flags_default() {
        assert_eq!(query_flags(), 0);
    }

    #[test]
    fn query_ifindex_default() {
        assert_eq!(query_ifindex(), 0);
    }
}
