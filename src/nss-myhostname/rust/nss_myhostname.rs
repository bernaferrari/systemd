// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nss-myhostname/nss-myhostname.c
//
// NSS module for resolving local hostnames.
//
// Provides hostname classification and the well-known local addresses
// (127.0.0.2 for IPv4, ::1 for IPv6) used by `nss-myhostname`.  The
// module resolves `localhost`, `_gateway`, `_outbound`, and the system
// hostname to appropriate addresses.

// ── Constants ─────────────────────────────────────────────────────────────

use std::net::Ipv4Addr;

/// The IPv4 address assigned to the local hostname.
///
/// Corresponds to `LOCALADDRESS_IPV4` / `INADDR_LOCALADDRESS` (127.0.0.2).
/// Using 127.0.0.2 rather than 127.0.0.1 allows reverse lookups to map
/// back to the local hostname instead of "localhost".
pub const LOCALADDRESS_IPV4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// The IPv4 loopback address.
pub const LOCALADDRESS_LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

// ── NSS status ────────────────────────────────────────────────────────────

/// NSS lookup return status.
///
/// Mirrors `enum nss_status` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NssStatus {
    Success = 0,
    NotFound = 1,
    TryAgain = 2,
    Unavail = 3,
}

// ── Hostname classification ───────────────────────────────────────────────

/// Category of a hostname for NSS resolution purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostnameClass {
    /// `localhost` or `localhost.localdomain`.
    Localhost,
    /// `_gateway` – resolve to the default gateway.
    Gateway,
    /// `_outbound` – resolve to the outbound interface.
    Outbound,
    /// The system hostname or an unknown name.
    Other,
}

/// Check whether the name is `localhost` or `localhost.localdomain`
/// (case-insensitive).
///
/// Mirrors `is_localhost()` from `hostname-util.h`.
pub fn is_localhost(name: &str) -> bool {
    name.eq_ignore_ascii_case("localhost") || name.eq_ignore_ascii_case("localhost.localdomain")
}

/// Check whether the name is the special `_gateway` hostname.
pub fn is_gateway_hostname(name: &str) -> bool {
    name == "_gateway"
}

/// Check whether the name is the special `_outbound` hostname.
pub fn is_outbound_hostname(name: &str) -> bool {
    name == "_outbound"
}

/// Classify a hostname into one of the well-known categories.
///
/// Mirrors the decision tree in `_nss_myhostname_gethostbyname4_r()`.
pub fn classify_hostname(name: &str) -> HostnameClass {
    if is_localhost(name) {
        HostnameClass::Localhost
    } else if is_gateway_hostname(name) {
        HostnameClass::Gateway
    } else if is_outbound_hostname(name) {
        HostnameClass::Outbound
    } else {
        HostnameClass::Other
    }
}

/// Return the canonical name for a hostname class.
pub fn canonical_for_class(cls: HostnameClass) -> &'static str {
    match cls {
        HostnameClass::Localhost => "localhost",
        HostnameClass::Gateway => "_gateway",
        HostnameClass::Outbound => "_outbound",
        HostnameClass::Other => "",
    }
}

// ── Address helpers ───────────────────────────────────────────────────────

/// The IPv6 loopback address used for local hostname resolution.
pub fn localaddress_ipv6() -> std::net::Ipv6Addr {
    std::net::Ipv6Addr::LOCALHOST
}

/// Determine the IPv4 address to use for a given hostname class.
///
/// For `Localhost`, returns 127.0.0.1 (loopback).
/// For `Other` (the system hostname), returns 127.0.0.2 (LOCALADDRESS).
/// Gateway/Outbound use actual interface addresses.
pub fn ipv4_address_for_class(cls: HostnameClass) -> Option<Ipv4Addr> {
    match cls {
        HostnameClass::Localhost => Some(LOCALADDRESS_LOOPBACK),
        HostnameClass::Other => Some(LOCALADDRESS_IPV4),
        HostnameClass::Gateway | HostnameClass::Outbound => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_localhost_cases() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("LOCALHOST"));
        assert!(is_localhost("localhost.localdomain"));
        assert!(is_localhost("LOCALHOST.LOCALDOMAIN"));
        assert!(!is_localhost("myhost"));
        assert!(!is_localhost("localhosty"));
    }

    #[test]
    fn is_gateway() {
        assert!(is_gateway_hostname("_gateway"));
        assert!(!is_gateway_hostname("gateway"));
        assert!(!is_gateway_hostname("_GATEWAY"));
    }

    #[test]
    fn is_outbound() {
        assert!(is_outbound_hostname("_outbound"));
        assert!(!is_outbound_hostname("outbound"));
        assert!(!is_outbound_hostname("_OUTBOUND"));
    }

    #[test]
    fn classify_various() {
        assert_eq!(classify_hostname("localhost"), HostnameClass::Localhost);
        assert_eq!(classify_hostname("LOCALHOST"), HostnameClass::Localhost);
        assert_eq!(classify_hostname("_gateway"), HostnameClass::Gateway);
        assert_eq!(classify_hostname("_outbound"), HostnameClass::Outbound);
        assert_eq!(classify_hostname("myhost"), HostnameClass::Other);
        assert_eq!(classify_hostname("example.com"), HostnameClass::Other);
    }

    #[test]
    fn canonical_matches() {
        for cls in [
            HostnameClass::Localhost,
            HostnameClass::Gateway,
            HostnameClass::Outbound,
        ] {
            let canon = canonical_for_class(cls);
            assert_eq!(classify_hostname(canon), cls);
        }
        assert_eq!(canonical_for_class(HostnameClass::Other), "");
    }

    #[test]
    fn local_address_ipv4() {
        assert_eq!(LOCALADDRESS_IPV4, Ipv4Addr::new(127, 0, 0, 2));
    }

    #[test]
    fn local_address_loopback() {
        assert_eq!(LOCALADDRESS_LOOPBACK, Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn ipv4_address_for_class_localhost() {
        assert_eq!(
            ipv4_address_for_class(HostnameClass::Localhost),
            Some(LOCALADDRESS_LOOPBACK)
        );
    }

    #[test]
    fn ipv4_address_for_class_other() {
        assert_eq!(
            ipv4_address_for_class(HostnameClass::Other),
            Some(LOCALADDRESS_IPV4)
        );
    }

    #[test]
    fn ipv4_address_for_class_gateway_is_none() {
        assert!(ipv4_address_for_class(HostnameClass::Gateway).is_none());
    }

    #[test]
    fn ipv4_address_for_class_outbound_is_none() {
        assert!(ipv4_address_for_class(HostnameClass::Outbound).is_none());
    }

    #[test]
    fn localaddress_ipv6_is_loopback() {
        assert_eq!(localaddress_ipv6(), std::net::Ipv6Addr::LOCALHOST);
    }
}
