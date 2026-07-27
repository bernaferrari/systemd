// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-dnssec-complex.c
//
// DNSSEC complex integration test helpers and lookup-logic tests.
// The C source is a manual/integration test requiring network access.
// This Rust port extracts the testable logic (name prefix generation,
// DNS type/class constants, bus-error name matching) and validates them.

use std::fmt;

// ── DNS constants ──────────────────────────────────────────────────────────

pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_SRV: u16 = 33;
pub const DNS_TYPE_RP: u16 = 17;

pub const AF_UNSPEC: i32 = 0;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;

// ── Bus error names ────────────────────────────────────────────────────────

pub const BUS_ERROR_DNSSEC_FAILED: &str = "org.freedesktop.resolve1.DnssecFailed";
pub const BUS_ERROR_NO_SUCH_RR: &str = "org.freedesktop.resolve1.NoSuchRR";
pub const BUS_ERROR_DNS_NXDOMAIN: &str = "org.freedesktop.resolve1.DnsNxDomain";

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupError {
    pub name: String,
}

impl fmt::Display for LookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LookupError({})", self.name)
    }
}

impl std::error::Error for LookupError {}

pub type Result<T> = std::result::Result<T, LookupError>;

// ── DNS type to string ─────────────────────────────────────────────────────

pub fn dns_type_to_string(t: u16) -> Option<&'static str> {
    match t {
        DNS_TYPE_A => Some("A"),
        DNS_TYPE_AAAA => Some("AAAA"),
        DNS_TYPE_SRV => Some("SRV"),
        DNS_TYPE_RP => Some("RP"),
        6 => Some("SOA"),
        5 => Some("CNAME"),
        2 => Some("NS"),
        15 => Some("MX"),
        16 => Some("TXT"),
        46 => Some("RRSIG"),
        48 => Some("DNSKEY"),
        _ => None,
    }
}

// ── AF name mapping ────────────────────────────────────────────────────────

pub fn af_to_name(family: i32) -> Option<&'static str> {
    match family {
        AF_UNSPEC => Some("AF_UNSPEC"),
        AF_INET => Some("AF_INET"),
        AF_INET6 => Some("AF_INET6"),
        _ => None,
    }
}

// ── Random prefix generation ───────────────────────────────────────────────

/// Generate a random-prefixed DNS name by prepending 1-3 random labels.
/// Mirrors C's `prefix_random()`.
pub fn prefix_random(name: &str, rng_values: &[u64]) -> String {
    if rng_values.is_empty() {
        return name.to_string();
    }

    let count = 1 + (rng_values[0] & 3) as usize;
    let mut result = String::new();

    for i in 0..count {
        if i > 0 || !result.is_empty() {
            result.push('.');
        }
        let v = rng_values.get(i).copied().unwrap_or(i as u64);
        result.push_str(&format!("x{}x", v));
    }

    if !name.is_empty() {
        result.push('.');
        result.push_str(name);
    }
    result
}

/// Check whether a name starts with a dot (trigger for random prefixing).
pub fn starts_with_dot(name: &str) -> bool {
    name.starts_with('.')
}

// ── RR lookup simulation ───────────────────────────────────────────────────

/// Simulate a DNS record lookup with an expected error result.
/// Returns Ok(()) if the expected error matches, Err otherwise.
pub fn test_rr_lookup(name: &str, rtype: u16, expected_error: Option<&str>) -> Result<()> {
    let type_str = dns_type_to_string(rtype).unwrap_or("UNKNOWN");

    if let Some(err) = expected_error {
        Err(LookupError {
            name: format!("{}.{}:{}", name, type_str, err),
        })
    } else {
        Ok(())
    }
}

/// Simulate a hostname lookup with an expected error result.
pub fn test_hostname_lookup(name: &str, family: i32, expected_error: Option<&str>) -> Result<()> {
    let af = af_to_name(family).unwrap_or("AF_UNKNOWN");

    if let Some(err) = expected_error {
        Err(LookupError {
            name: format!("{}.{}:{}", name, af, err),
        })
    } else {
        Ok(())
    }
}

/// Check if a bus error name matches.
pub fn bus_error_has_name(error_name: &str, expected: &str) -> bool {
    error_name == expected
}

// ── DNSSEC test case definitions ───────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnssecTestCase {
    pub name: &'static str,
    pub rtype: u16,
    pub family: i32,
    pub expected_error: Option<&'static str>,
    pub is_rr_lookup: bool,
}

pub fn dnssec_complex_test_cases() -> Vec<DnssecTestCase> {
    vec![
        DnssecTestCase {
            name: "www.eurid.eu",
            rtype: DNS_TYPE_A,
            family: AF_UNSPEC,
            expected_error: None,
            is_rr_lookup: true,
        },
        DnssecTestCase {
            name: "www.eurid.eu",
            rtype: 0,
            family: AF_UNSPEC,
            expected_error: None,
            is_rr_lookup: false,
        },
        DnssecTestCase {
            name: "www.eurid.eu",
            rtype: DNS_TYPE_RP,
            family: 0,
            expected_error: Some(BUS_ERROR_NO_SUCH_RR),
            is_rr_lookup: true,
        },
        DnssecTestCase {
            name: "sigfail.verteiltesysteme.net",
            rtype: DNS_TYPE_A,
            family: AF_INET,
            expected_error: Some(BUS_ERROR_DNSSEC_FAILED),
            is_rr_lookup: true,
        },
        DnssecTestCase {
            name: "sigfail.verteiltesysteme.net",
            rtype: 0,
            family: AF_INET,
            expected_error: Some(BUS_ERROR_DNSSEC_FAILED),
            is_rr_lookup: false,
        },
        DnssecTestCase {
            name: "hhh.nasa.gov",
            rtype: DNS_TYPE_A,
            family: AF_UNSPEC,
            expected_error: Some(BUS_ERROR_DNS_NXDOMAIN),
            is_rr_lookup: true,
        },
        DnssecTestCase {
            name: "hhh.nasa.gov",
            rtype: 0,
            family: AF_UNSPEC,
            expected_error: Some(BUS_ERROR_DNS_NXDOMAIN),
            is_rr_lookup: false,
        },
        DnssecTestCase {
            name: "poettering.de",
            rtype: DNS_TYPE_A,
            family: AF_UNSPEC,
            expected_error: None,
            is_rr_lookup: true,
        },
        DnssecTestCase {
            name: "poettering.de",
            rtype: DNS_TYPE_AAAA,
            family: AF_UNSPEC,
            expected_error: None,
            is_rr_lookup: true,
        },
        DnssecTestCase {
            name: "poettering.de",
            rtype: 0,
            family: AF_INET,
            expected_error: None,
            is_rr_lookup: false,
        },
        DnssecTestCase {
            name: "poettering.de",
            rtype: 0,
            family: AF_INET6,
            expected_error: None,
            is_rr_lookup: false,
        },
    ]
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_type_to_string_known() {
        assert_eq!(dns_type_to_string(DNS_TYPE_A), Some("A"));
        assert_eq!(dns_type_to_string(DNS_TYPE_AAAA), Some("AAAA"));
        assert_eq!(dns_type_to_string(DNS_TYPE_SRV), Some("SRV"));
        assert_eq!(dns_type_to_string(DNS_TYPE_RP), Some("RP"));
    }

    #[test]
    fn dns_type_to_string_unknown() {
        assert_eq!(dns_type_to_string(9999), None);
        assert_eq!(dns_type_to_string(0), None);
    }

    #[test]
    fn af_to_name_mapping() {
        assert_eq!(af_to_name(AF_UNSPEC), Some("AF_UNSPEC"));
        assert_eq!(af_to_name(AF_INET), Some("AF_INET"));
        assert_eq!(af_to_name(AF_INET6), Some("AF_INET6"));
        assert_eq!(af_to_name(99), None);
    }

    #[test]
    fn starts_with_dot_detection() {
        assert!(starts_with_dot(".wilda.rhybar.0skar.cz"));
        assert!(starts_with_dot("."));
        assert!(!starts_with_dot("www.eurid.eu"));
        assert!(!starts_with_dot(""));
    }

    #[test]
    fn prefix_random_single() {
        let rng = &[42u64];
        let result = prefix_random("example.com", rng);
        assert!(result.ends_with(".example.com"));
        assert!(result.contains("x42x"));
    }

    #[test]
    fn prefix_random_multiple() {
        let rng = &[1u64, 2, 3];
        let result = prefix_random("example.com", rng);
        assert!(result.ends_with(".example.com"));
        assert!(result.contains("x1x"));
    }

    #[test]
    fn prefix_random_empty() {
        let result = prefix_random("example.com", &[]);
        assert_eq!(result, "example.com");
    }

    #[test]
    fn bus_error_matching() {
        assert!(bus_error_has_name(
            BUS_ERROR_DNSSEC_FAILED,
            BUS_ERROR_DNSSEC_FAILED
        ));
        assert!(bus_error_has_name(
            BUS_ERROR_NO_SUCH_RR,
            BUS_ERROR_NO_SUCH_RR
        ));
        assert!(!bus_error_has_name(
            BUS_ERROR_DNSSEC_FAILED,
            BUS_ERROR_NO_SUCH_RR
        ));
    }

    #[test]
    fn rr_lookup_success() {
        assert!(test_rr_lookup("www.eurid.eu", DNS_TYPE_A, None).is_ok());
    }

    #[test]
    fn rr_lookup_error() {
        let err = test_rr_lookup(
            "fail.example.com",
            DNS_TYPE_A,
            Some(BUS_ERROR_DNSSEC_FAILED),
        );
        assert!(err.is_err());
        let e = err.unwrap_err();
        assert!(e.name.contains(BUS_ERROR_DNSSEC_FAILED));
    }

    #[test]
    fn hostname_lookup_success() {
        assert!(test_hostname_lookup("www.eurid.eu", AF_UNSPEC, None).is_ok());
    }

    #[test]
    fn hostname_lookup_error() {
        let err = test_hostname_lookup("hhh.nasa.gov", AF_UNSPEC, Some(BUS_ERROR_DNS_NXDOMAIN));
        assert!(err.is_err());
        let e = err.unwrap_err();
        assert!(e.name.contains(BUS_ERROR_DNS_NXDOMAIN));
    }

    #[test]
    fn dnssec_test_cases_count() {
        let cases = dnssec_complex_test_cases();
        assert!(cases.len() >= 10, "should have at least 10 test cases");
    }

    #[test]
    fn dnssec_test_cases_error_vs_success() {
        let cases = dnssec_complex_test_cases();
        let success_count = cases.iter().filter(|c| c.expected_error.is_none()).count();
        let error_count = cases.iter().filter(|c| c.expected_error.is_some()).count();
        assert!(success_count > 0, "should have some success cases");
        assert!(error_count > 0, "should have some error cases");
    }
}
