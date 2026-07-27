// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/nss-myhostname/nss-myhostname.c
//
// NSS module that resolves local hostnames to 127.0.0.2 / ::1.
//
// We use 127.0.0.2 as IPv4 address. This has the advantage over
// 127.0.0.1 that it can be translated back to the local hostname.
// For IPv6 we use ::1.

use std::net::Ipv4Addr;

// ── Error type ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

// ── Constants ─────────────────────────────────────────────────────────────

/// IPv4 address used for local hostname resolution.
/// Unlike 127.0.0.1, this can be translated back to the local hostname.
pub const LOCALADDRESS_IPV4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// IPv4 loopback address.
pub const LOOPBACK_IPV4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

// ── Enums ─────────────────────────────────────────────────────────────────

/// NSS status return values, matching `enum nss_status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NssStatus {
    Success = 0,
    NotFound = 1,
    TryAgain = 2,
    Unavail = 3,
}

/// Address family for name resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Unspec,
    Inet,
    Inet6,
}

/// Classification of a hostname for NSS lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostnameClass {
    Localhost,
    Gateway,
    Outbound,
    Other,
}

// ── Hostname classification ───────────────────────────────────────────────

/// Check whether the given name refers to "localhost".
///
/// Corresponds to `is_localhost()` in the C source which checks for
/// "localhost" and "localhost.localdomain" (case-insensitive).
pub fn is_localhost(name: &str) -> bool {
    name.eq_ignore_ascii_case("localhost") || name.eq_ignore_ascii_case("localhost.localdomain")
}

/// Check whether the given name is the special `_gateway` hostname.
pub fn is_gateway_hostname(name: &str) -> bool {
    name == "_gateway"
}

/// Check whether the given name is the special `_outbound` hostname.
pub fn is_outbound_hostname(name: &str) -> bool {
    name == "_outbound"
}

/// Classify a hostname into its resolution category.
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

/// Return the canonical hostname string for a given class.
pub fn canonical_for_class(cls: HostnameClass) -> &'static str {
    match cls {
        HostnameClass::Localhost => "localhost",
        HostnameClass::Gateway => "_gateway",
        HostnameClass::Outbound => "_outbound",
        HostnameClass::Other => "",
    }
}

// ── Address resolution helpers ────────────────────────────────────────────

/// Resolve result for a classified hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHost {
    pub canonical: String,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<[u8; 16]>,
}

/// Resolve a hostname to its canonical form and addresses.
///
/// This captures the logic from `_nss_myhostname_gethostbyname4_r`:
/// - localhost → 127.0.0.1 + ::1
/// - _gateway → no local addresses (would need local_gateways)
/// - _outbound → no local addresses (would need local_outbounds)
/// - hostname matches system → 127.0.0.2 + ::1
pub fn resolve_hostname(name: &str, system_hostname: Option<&str>) -> Result<ResolvedHost> {
    let cls = classify_hostname(name);

    match cls {
        HostnameClass::Localhost => Ok(ResolvedHost {
            canonical: "localhost".to_string(),
            ipv4: Some(LOOPBACK_IPV4),
            ipv6: Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        }),
        HostnameClass::Gateway => Ok(ResolvedHost {
            canonical: "_gateway".to_string(),
            ipv4: None,
            ipv6: None,
        }),
        HostnameClass::Outbound => Ok(ResolvedHost {
            canonical: "_outbound".to_string(),
            ipv4: None,
            ipv6: None,
        }),
        HostnameClass::Other => {
            let hn = system_hostname.ok_or(Errno(-libc::ENOENT))?;
            let matches_exact = name == hn;
            let matches_dotted = name
                .strip_prefix(hn)
                .map(|rest| rest == "." || rest.is_empty())
                .unwrap_or(false);

            if !matches_exact && !matches_dotted {
                return Err(Errno(-libc::ENOENT));
            }

            Ok(ResolvedHost {
                canonical: hn.to_string(),
                ipv4: Some(LOCALADDRESS_IPV4),
                ipv6: Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            })
        }
    }
}

/// Resolve an IPv4 address back to a hostname.
///
/// Corresponds to the reverse-lookup logic in `_nss_myhostname_gethostbyaddr2_r`.
pub fn resolve_ipv4_addr(addr: Ipv4Addr, system_hostname: Option<&str>) -> Result<ResolvedHost> {
    if addr == LOCALADDRESS_IPV4 {
        let hn = system_hostname.ok_or(Errno(-libc::ENOENT))?;
        return Ok(ResolvedHost {
            canonical: hn.to_string(),
            ipv4: Some(addr),
            ipv6: None,
        });
    }
    if addr == LOOPBACK_IPV4 {
        return Ok(ResolvedHost {
            canonical: "localhost".to_string(),
            ipv4: Some(addr),
            ipv6: None,
        });
    }
    Err(Errno(-libc::ENOENT))
}

/// Parse an address family string into the enum.
pub fn parse_address_family(af: &str) -> Result<AddressFamily> {
    match af {
        "AF_UNSPEC" | "unspec" => Ok(AddressFamily::Unspec),
        "AF_INET" | "inet" | "ipv4" => Ok(AddressFamily::Inet),
        "AF_INET6" | "inet6" | "ipv6" => Ok(AddressFamily::Inet6),
        _ => Err(Errno(-libc::EAFNOSUPPORT)),
    }
}

/// Validate a hostname for NSS lookup purposes.
/// Must be non-empty and not exceed 253 characters.
pub fn is_valid_hostname(name: &str) -> bool {
    !name.is_empty() && name.len() <= 253 && !name.contains('\0')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_detection() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("LOCALHOST"));
        assert!(is_localhost("localhost.localdomain"));
        assert!(is_localhost("Localhost.LocalDomain"));
        assert!(!is_localhost("myhost"));
        assert!(!is_localhost("localhosty"));
    }

    #[test]
    fn gateway_detection() {
        assert!(is_gateway_hostname("_gateway"));
        assert!(!is_gateway_hostname("gateway"));
        assert!(!is_gateway_hostname("_Gateway"));
    }

    #[test]
    fn outbound_detection() {
        assert!(is_outbound_hostname("_outbound"));
        assert!(!is_outbound_hostname("outbound"));
    }

    #[test]
    fn classify_all_types() {
        assert_eq!(classify_hostname("localhost"), HostnameClass::Localhost);
        assert_eq!(classify_hostname("_gateway"), HostnameClass::Gateway);
        assert_eq!(classify_hostname("_outbound"), HostnameClass::Outbound);
        assert_eq!(classify_hostname("myhost"), HostnameClass::Other);
    }

    #[test]
    fn canonical_matches_classification() {
        for cls in [
            HostnameClass::Localhost,
            HostnameClass::Gateway,
            HostnameClass::Outbound,
        ] {
            let canon = canonical_for_class(cls);
            assert_eq!(classify_hostname(canon), cls);
        }
    }

    #[test]
    fn resolve_localhost() {
        let result = resolve_hostname("localhost", None).unwrap();
        assert_eq!(result.canonical, "localhost");
        assert_eq!(result.ipv4, Some(LOOPBACK_IPV4));
        assert!(result.ipv6.is_some());
    }

    #[test]
    fn resolve_system_hostname() {
        let result = resolve_hostname("myhost", Some("myhost")).unwrap();
        assert_eq!(result.canonical, "myhost");
        assert_eq!(result.ipv4, Some(LOCALADDRESS_IPV4));
    }

    #[test]
    fn resolve_unknown_hostname_fails() {
        assert!(resolve_hostname("other", Some("myhost")).is_err());
    }

    #[test]
    fn resolve_system_hostname_dotted() {
        let result = resolve_hostname("myhost.", Some("myhost")).unwrap();
        assert_eq!(result.canonical, "myhost");
    }

    #[test]
    fn resolve_ipv4_localaddress() {
        let result = resolve_ipv4_addr(LOCALADDRESS_IPV4, Some("myhost")).unwrap();
        assert_eq!(result.canonical, "myhost");
    }

    #[test]
    fn resolve_ipv4_loopback() {
        let result = resolve_ipv4_addr(LOOPBACK_IPV4, None).unwrap();
        assert_eq!(result.canonical, "localhost");
    }

    #[test]
    fn resolve_ipv4_unknown_fails() {
        assert!(resolve_ipv4_addr(Ipv4Addr::new(10, 0, 0, 1), None).is_err());
    }

    #[test]
    fn local_address_constant() {
        assert_eq!(LOCALADDRESS_IPV4, Ipv4Addr::new(127, 0, 0, 2));
    }

    #[test]
    fn parse_address_families() {
        assert_eq!(
            parse_address_family("AF_INET").unwrap(),
            AddressFamily::Inet
        );
        assert_eq!(parse_address_family("ipv6").unwrap(), AddressFamily::Inet6);
        assert_eq!(
            parse_address_family("AF_UNSPEC").unwrap(),
            AddressFamily::Unspec
        );
        assert!(parse_address_family("unknown").is_err());
    }

    #[test]
    fn valid_hostname_checks() {
        assert!(is_valid_hostname("myhost"));
        assert!(!is_valid_hostname(""));
        assert!(is_valid_hostname(&"a".repeat(253)));
        assert!(!is_valid_hostname(&"a".repeat(254)));
    }
}
