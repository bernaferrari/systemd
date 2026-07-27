// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/resolve-util.c

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

pub const SOURCE_PATH: &str = "src/shared/resolve-util.c";
pub const SOURCE_TEXT: &str = include_str!("../resolve-util.c");

pub const INADDR_DNS_STUB: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 53);
pub const INADDR_DNS_PROXY_STUB: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 54);
pub const INADDR_LOCALADDRESS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

pub const PRIVATE_UPLINK_RESOLV_CONF: &str = "/run/systemd/resolve/resolv.conf";
pub const PRIVATE_STUB_RESOLV_CONF: &str = "/run/systemd/resolve/stub-resolv.conf";
pub const PRIVATE_STATIC_RESOLV_CONF: &str = "/usr/lib/systemd/resolv.conf";

pub const RESOLVE_SUPPORT_MAX: i32 = 3;
pub const DNSSEC_MODE_MAX: i32 = 3;
pub const DNS_OVER_TLS_MODE_MAX: i32 = 3;
pub const DNS_CACHE_MODE_MAX: i32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum AddressFamily {
    Unspec = 0,
    Inet = 2,
    Inet6 = 10,
}

impl AddressFamily {
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Unspec),
            2 => Some(Self::Inet),
            10 => Some(Self::Inet6),
            _ => None,
        }
    }

    pub fn matches(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::Inet, IpAddr::V4(_)) | (Self::Inet6, IpAddr::V6(_))
        )
    }
}

trait StringEnum: Sized + Copy + Eq
where
    Self: 'static,
{
    const TABLE: &'static [(Self, &'static str)];

    fn to_str(self) -> &'static str {
        Self::TABLE
            .iter()
            .find_map(|(value, name)| (*value == self).then_some(*name))
            .expect("string table must cover all enum variants")
    }

    fn from_str_name(name: &str) -> Option<Self> {
        Self::TABLE
            .iter()
            .find_map(|(value, candidate)| (*candidate == name).then_some(*value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ResolveSupport {
    No = 0,
    Resolve = 1,
    Yes = 2,
}

impl StringEnum for ResolveSupport {
    const TABLE: &'static [(Self, &'static str)] = &[
        (Self::No, "no"),
        (Self::Yes, "yes"),
        (Self::Resolve, "resolve"),
    ];
}

impl ResolveSupport {
    pub fn from_name(name: &str) -> Option<Self> {
        <Self as StringEnum>::from_str_name(name)
    }

    pub fn to_name(self) -> &'static str {
        <Self as StringEnum>::to_str(self)
    }

    pub fn from_name_with_boolean(name: &str) -> Option<Self> {
        match parse_boolean(name) {
            Some(false) => Some(Self::No),
            Some(true) => Some(Self::Yes),
            None => Self::from_name(name),
        }
    }
}

impl FromStr for ResolveSupport {
    type Err = ParseResolveError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name_with_boolean(s).ok_or_else(|| ParseResolveError::invalid_resolve_support(s))
    }
}

impl fmt::Display for ResolveSupport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum DnssecMode {
    No = 0,
    AllowDowngrade = 1,
    Yes = 2,
}

impl StringEnum for DnssecMode {
    const TABLE: &'static [(Self, &'static str)] = &[
        (Self::No, "no"),
        (Self::AllowDowngrade, "allow-downgrade"),
        (Self::Yes, "yes"),
    ];
}

impl DnssecMode {
    pub fn from_name(name: &str) -> Option<Self> {
        <Self as StringEnum>::from_str_name(name)
    }

    pub fn to_name(self) -> &'static str {
        <Self as StringEnum>::to_str(self)
    }

    pub fn from_name_with_boolean(name: &str) -> Option<Self> {
        match parse_boolean(name) {
            Some(false) => Some(Self::No),
            Some(true) => Some(Self::Yes),
            None => Self::from_name(name),
        }
    }
}

impl FromStr for DnssecMode {
    type Err = ParseResolveError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name_with_boolean(s).ok_or_else(|| ParseResolveError::invalid_dnssec_mode(s))
    }
}

impl fmt::Display for DnssecMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum DnsOverTlsMode {
    No = 0,
    Opportunistic = 1,
    Yes = 2,
}

impl StringEnum for DnsOverTlsMode {
    const TABLE: &'static [(Self, &'static str)] = &[
        (Self::No, "no"),
        (Self::Opportunistic, "opportunistic"),
        (Self::Yes, "yes"),
    ];
}

impl DnsOverTlsMode {
    pub fn from_name(name: &str) -> Option<Self> {
        <Self as StringEnum>::from_str_name(name)
    }

    pub fn to_name(self) -> &'static str {
        <Self as StringEnum>::to_str(self)
    }

    pub fn from_name_with_boolean(name: &str) -> Option<Self> {
        match parse_boolean(name) {
            Some(false) => Some(Self::No),
            Some(true) => Some(Self::Yes),
            None => Self::from_name(name),
        }
    }
}

impl FromStr for DnsOverTlsMode {
    type Err = ParseResolveError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name_with_boolean(s)
            .ok_or_else(|| ParseResolveError::invalid_dns_over_tls_mode(s))
    }
}

impl fmt::Display for DnsOverTlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum DnsCacheMode {
    No = 0,
    Yes = 1,
    NoNegative = 2,
}

impl StringEnum for DnsCacheMode {
    const TABLE: &'static [(Self, &'static str)] = &[
        (Self::Yes, "yes"),
        (Self::No, "no"),
        (Self::NoNegative, "no-negative"),
    ];
}

impl DnsCacheMode {
    pub fn from_name(name: &str) -> Option<Self> {
        <Self as StringEnum>::from_str_name(name)
    }

    pub fn to_name(self) -> &'static str {
        <Self as StringEnum>::to_str(self)
    }

    pub fn from_name_with_boolean(name: &str) -> Option<Self> {
        match parse_boolean(name) {
            Some(false) => Some(Self::No),
            Some(true) => Some(Self::Yes),
            None => Self::from_name(name),
        }
    }
}

impl FromStr for DnsCacheMode {
    type Err = ParseResolveError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name_with_boolean(s).ok_or_else(|| ParseResolveError::invalid_dns_cache_mode(s))
    }
}

impl fmt::Display for DnsCacheMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseResolveError {
    InvalidResolveSupport(String),
    InvalidDnssecMode(String),
    InvalidDnsOverTlsMode(String),
    InvalidDnsCacheMode(String),
}

impl ParseResolveError {
    fn invalid_resolve_support(value: &str) -> Self {
        Self::InvalidResolveSupport(value.to_owned())
    }

    fn invalid_dnssec_mode(value: &str) -> Self {
        Self::InvalidDnssecMode(value.to_owned())
    }

    fn invalid_dns_over_tls_mode(value: &str) -> Self {
        Self::InvalidDnsOverTlsMode(value.to_owned())
    }

    fn invalid_dns_cache_mode(value: &str) -> Self {
        Self::InvalidDnsCacheMode(value.to_owned())
    }
}

impl fmt::Display for ParseResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidResolveSupport(value) => write!(f, "invalid resolve support: {value}"),
            Self::InvalidDnssecMode(value) => write!(f, "invalid DNSSEC mode: {value}"),
            Self::InvalidDnsOverTlsMode(value) => write!(f, "invalid DNS-over-TLS mode: {value}"),
            Self::InvalidDnsCacheMode(value) => write!(f, "invalid DNS cache mode: {value}"),
        }
    }
}

impl std::error::Error for ParseResolveError {}

pub fn parse_boolean(value: &str) -> Option<bool> {
    if matches_ascii_case_insensitive(value, &["1", "yes", "y", "true", "t", "on"]) {
        Some(true)
    } else if matches_ascii_case_insensitive(value, &["0", "no", "n", "false", "f", "off"]) {
        Some(false)
    } else {
        None
    }
}

pub fn resolve_support_from_str_or_boolean(value: &str) -> Option<ResolveSupport> {
    ResolveSupport::from_name_with_boolean(value)
}

pub fn dnssec_mode_from_str_or_boolean(value: &str) -> Option<DnssecMode> {
    DnssecMode::from_name_with_boolean(value)
}

pub fn dns_over_tls_mode_from_str_or_boolean(value: &str) -> Option<DnsOverTlsMode> {
    DnsOverTlsMode::from_name_with_boolean(value)
}

pub fn dns_cache_mode_from_str_or_boolean(value: &str) -> Option<DnsCacheMode> {
    DnsCacheMode::from_name_with_boolean(value)
}

pub fn dns_server_address_valid(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            dns_server_address_valid_for_family(AddressFamily::Inet, address.into())
        }
        IpAddr::V6(address) => {
            dns_server_address_valid_for_family(AddressFamily::Inet6, address.into())
        }
    }
}

pub fn dns_server_address_valid_for_family(family: AddressFamily, address: IpAddr) -> bool {
    match (family, address) {
        (AddressFamily::Inet, IpAddr::V4(address)) => {
            !address.is_unspecified()
                && address != INADDR_DNS_STUB
                && address != INADDR_DNS_PROXY_STUB
        }
        (AddressFamily::Inet6, IpAddr::V6(address)) => !address.is_unspecified(),
        (AddressFamily::Unspec, _) => false,
        _ => false,
    }
}

pub fn dns_server_ipv4_address_valid(address: Ipv4Addr) -> bool {
    dns_server_address_valid_for_family(AddressFamily::Inet, address.into())
}

pub fn dns_server_ipv6_address_valid(address: Ipv6Addr) -> bool {
    dns_server_address_valid_for_family(AddressFamily::Inet6, address.into())
}

fn matches_ascii_case_insensitive(value: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_reference_constants_match_port() {
        assert_eq!(SOURCE_PATH, "src/shared/resolve-util.c");
        assert!(SOURCE_TEXT.contains("dns_server_address_valid"));
        assert!(SOURCE_TEXT.contains("dns_cache_mode_table"));
    }

    #[test]
    fn resolve_support_roundtrips_and_boolean_aliases() {
        assert_eq!(ResolveSupport::from_name("no"), Some(ResolveSupport::No));
        assert_eq!(
            ResolveSupport::from_name("resolve"),
            Some(ResolveSupport::Resolve)
        );
        assert_eq!(ResolveSupport::from_name("yes"), Some(ResolveSupport::Yes));
        assert_eq!(
            ResolveSupport::from_name_with_boolean("on"),
            Some(ResolveSupport::Yes)
        );
        assert_eq!(
            ResolveSupport::from_name_with_boolean("OFF"),
            Some(ResolveSupport::No)
        );
        assert_eq!(ResolveSupport::Yes.to_string(), "yes");
    }

    #[test]
    fn dnssec_mode_roundtrips_and_parses() {
        assert_eq!(
            DnssecMode::from_name("allow-downgrade"),
            Some(DnssecMode::AllowDowngrade)
        );
        assert_eq!(
            DnssecMode::from_name_with_boolean("true"),
            Some(DnssecMode::Yes)
        );
        assert_eq!(
            "allow-downgrade".parse::<DnssecMode>(),
            Ok(DnssecMode::AllowDowngrade)
        );
        assert_eq!(DnssecMode::AllowDowngrade.to_string(), "allow-downgrade");
    }

    #[test]
    fn dns_over_tls_mode_roundtrips_and_parses() {
        assert_eq!(
            DnsOverTlsMode::from_name("opportunistic"),
            Some(DnsOverTlsMode::Opportunistic)
        );
        assert_eq!(
            DnsOverTlsMode::from_name_with_boolean("1"),
            Some(DnsOverTlsMode::Yes)
        );
        assert_eq!("no".parse::<DnsOverTlsMode>(), Ok(DnsOverTlsMode::No));
        assert_eq!(DnsOverTlsMode::Opportunistic.to_string(), "opportunistic");
    }

    #[test]
    fn dns_cache_mode_roundtrips_and_parses() {
        assert_eq!(
            DnsCacheMode::from_name("no-negative"),
            Some(DnsCacheMode::NoNegative)
        );
        assert_eq!(
            DnsCacheMode::from_name_with_boolean("y"),
            Some(DnsCacheMode::Yes)
        );
        assert_eq!("false".parse::<DnsCacheMode>(), Ok(DnsCacheMode::No));
        assert_eq!(DnsCacheMode::NoNegative.to_string(), "no-negative");
    }

    #[test]
    fn parse_boolean_matches_systemd_aliases() {
        for value in ["1", "yes", "Y", "true", "T", "on", "ON"] {
            assert_eq!(parse_boolean(value), Some(true), "{value}");
        }

        for value in ["0", "no", "N", "false", "F", "off", "OFF"] {
            assert_eq!(parse_boolean(value), Some(false), "{value}");
        }

        assert_eq!(parse_boolean("resolve"), None);
        assert_eq!(parse_boolean(""), None);
    }

    #[test]
    fn parse_errors_preserve_invalid_input() {
        assert_eq!(
            "bogus".parse::<ResolveSupport>(),
            Err(ParseResolveError::InvalidResolveSupport("bogus".to_owned()))
        );
        assert_eq!(
            "bogus".parse::<DnssecMode>(),
            Err(ParseResolveError::InvalidDnssecMode("bogus".to_owned()))
        );
        assert_eq!(
            format!("{}", "bogus".parse::<DnsCacheMode>().unwrap_err()),
            "invalid DNS cache mode: bogus"
        );
    }

    #[test]
    fn family_values_match_c() {
        assert_eq!(AddressFamily::from_i32(0), Some(AddressFamily::Unspec));
        assert_eq!(AddressFamily::from_i32(2), Some(AddressFamily::Inet));
        assert_eq!(AddressFamily::from_i32(10), Some(AddressFamily::Inet6));
        assert_eq!(AddressFamily::from_i32(42), None);
        assert_eq!(RESOLVE_SUPPORT_MAX, 3);
        assert_eq!(DNSSEC_MODE_MAX, 3);
        assert_eq!(DNS_OVER_TLS_MODE_MAX, 3);
        assert_eq!(DNS_CACHE_MODE_MAX, 3);
    }

    #[test]
    fn dns_server_address_valid_rejects_unspecified_and_stub_addresses() {
        assert!(!dns_server_address_valid(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!dns_server_address_valid(IpAddr::V4(INADDR_DNS_STUB)));
        assert!(!dns_server_address_valid(IpAddr::V4(INADDR_DNS_PROXY_STUB)));
        assert!(dns_server_address_valid(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));
        assert!(dns_server_address_valid(IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
    }

    #[test]
    fn dns_server_address_valid_supports_ipv6() {
        assert!(!dns_server_ipv6_address_valid(Ipv6Addr::UNSPECIFIED));
        assert!(dns_server_ipv6_address_valid(Ipv6Addr::LOCALHOST));
        assert!(dns_server_address_valid(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111,
        ))));
    }

    #[test]
    fn family_specific_validation_rejects_mismatches_and_unspec() {
        assert!(!dns_server_address_valid_for_family(
            AddressFamily::Inet,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ));
        assert!(!dns_server_address_valid_for_family(
            AddressFamily::Inet6,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        ));
        assert!(!dns_server_address_valid_for_family(
            AddressFamily::Unspec,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        ));
    }

    #[test]
    fn constants_match_header_intent() {
        assert_eq!(INADDR_DNS_STUB, Ipv4Addr::new(127, 0, 0, 53));
        assert_eq!(INADDR_DNS_PROXY_STUB, Ipv4Addr::new(127, 0, 0, 54));
        assert_eq!(INADDR_LOCALADDRESS, Ipv4Addr::new(127, 0, 0, 2));
        assert_eq!(
            PRIVATE_UPLINK_RESOLV_CONF,
            "/run/systemd/resolve/resolv.conf"
        );
        assert_eq!(
            PRIVATE_STUB_RESOLV_CONF,
            "/run/systemd/resolve/stub-resolv.conf"
        );
        assert!(PRIVATE_STATIC_RESOLV_CONF.ends_with("/resolv.conf"));
    }
}
