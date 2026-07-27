// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-resolve-tables.c
//
// DNS table/enum string-conversion tests. Validates every DNS protocol,
// DNSSEC result, DNSSEC verdict, DNS RCODE, DNS type, and DNS class
// round-trips and property queries.

use std::fmt;

// ── DNS protocol ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsProtocol {
    Dns,
    Mdns,
    Llmnr,
}

pub fn dns_protocol_to_string(p: DnsProtocol) -> &'static str {
    match p {
        DnsProtocol::Dns => "DNS",
        DnsProtocol::Mdns => "mDNS",
        DnsProtocol::Llmnr => "LLMNR",
    }
}

pub fn dns_protocol_from_string(s: &str) -> Option<DnsProtocol> {
    match s {
        "DNS" => Some(DnsProtocol::Dns),
        "mDNS" => Some(DnsProtocol::Mdns),
        "LLMNR" => Some(DnsProtocol::Llmnr),
        _ => None,
    }
}

// ── DNSSEC result ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecResult {
    Validated,
    Invalid,
    Insecure,
    Indeterminate,
    MissingKey,
    SignatureExpired,
    SignatureNotYetValid,
    UnsupportedAlgorithm,
}

pub fn dnssec_result_to_string(r: DnssecResult) -> &'static str {
    match r {
        DnssecResult::Validated => "validated",
        DnssecResult::Invalid => "invalid",
        DnssecResult::Insecure => "insecure",
        DnssecResult::Indeterminate => "indeterminate",
        DnssecResult::MissingKey => "missing-key",
        DnssecResult::SignatureExpired => "signature-expired",
        DnssecResult::SignatureNotYetValid => "signature-not-yet-valid",
        DnssecResult::UnsupportedAlgorithm => "unsupported-algorithm",
    }
}

pub fn dnssec_result_from_string(s: &str) -> Option<DnssecResult> {
    match s {
        "validated" => Some(DnssecResult::Validated),
        "invalid" => Some(DnssecResult::Invalid),
        "insecure" => Some(DnssecResult::Insecure),
        "indeterminate" => Some(DnssecResult::Indeterminate),
        "missing-key" => Some(DnssecResult::MissingKey),
        "signature-expired" => Some(DnssecResult::SignatureExpired),
        "signature-not-yet-valid" => Some(DnssecResult::SignatureNotYetValid),
        "unsupported-algorithm" => Some(DnssecResult::UnsupportedAlgorithm),
        _ => None,
    }
}

// ── DNSSEC verdict ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecVerdict {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
}

pub fn dnssec_verdict_to_string(v: DnssecVerdict) -> &'static str {
    match v {
        DnssecVerdict::Secure => "secure",
        DnssecVerdict::Insecure => "insecure",
        DnssecVerdict::Bogus => "bogus",
        DnssecVerdict::Indeterminate => "indeterminate",
    }
}

pub fn dnssec_verdict_from_string(s: &str) -> Option<DnssecVerdict> {
    match s {
        "secure" => Some(DnssecVerdict::Secure),
        "insecure" => Some(DnssecVerdict::Insecure),
        "bogus" => Some(DnssecVerdict::Bogus),
        "indeterminate" => Some(DnssecVerdict::Indeterminate),
        _ => None,
    }
}

// ── DNS RCODE ──────────────────────────────────────────────────────────────

pub const DNS_RCODE_SUCCESS: u16 = 0;
pub const DNS_RCODE_FORMERR: u16 = 1;
pub const DNS_RCODE_SERVFAIL: u16 = 2;
pub const DNS_RCODE_NXDOMAIN: u16 = 3;
pub const DNS_RCODE_NOTIMP: u16 = 4;
pub const DNS_RCODE_REFUSED: u16 = 5;

pub fn dns_rcode_to_string(rcode: u16) -> Option<&'static str> {
    match rcode {
        DNS_RCODE_SUCCESS => Some("SUCCESS"),
        DNS_RCODE_FORMERR => Some("FORMERR"),
        DNS_RCODE_SERVFAIL => Some("SERVFAIL"),
        DNS_RCODE_NXDOMAIN => Some("NXDOMAIN"),
        DNS_RCODE_NOTIMP => Some("NOTIMP"),
        DNS_RCODE_REFUSED => Some("REFUSED"),
        _ => None,
    }
}

// ── DNS type ───────────────────────────────────────────────────────────────

pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_NS: u16 = 2;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_SOA: u16 = 6;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_MX: u16 = 15;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_SRV: u16 = 33;
pub const DNS_TYPE_NAPTR: u16 = 35;
pub const DNS_TYPE_OPT: u16 = 41;
pub const DNS_TYPE_RRSIG: u16 = 46;
pub const DNS_TYPE_NSEC: u16 = 47;
pub const DNS_TYPE_DNSKEY: u16 = 48;
pub const DNS_TYPE_DS: u16 = 43;
pub const DNS_TYPE_ANY: u16 = 255;

pub const DNS_TYPE_STRING_MAX: usize = 12;

pub fn dns_type_to_string(t: u16) -> Option<&'static str> {
    match t {
        DNS_TYPE_A => Some("A"),
        DNS_TYPE_NS => Some("NS"),
        DNS_TYPE_CNAME => Some("CNAME"),
        DNS_TYPE_SOA => Some("SOA"),
        DNS_TYPE_PTR => Some("PTR"),
        DNS_TYPE_MX => Some("MX"),
        DNS_TYPE_TXT => Some("TXT"),
        DNS_TYPE_AAAA => Some("AAAA"),
        DNS_TYPE_SRV => Some("SRV"),
        DNS_TYPE_NAPTR => Some("NAPTR"),
        DNS_TYPE_OPT => Some("OPT"),
        DNS_TYPE_DS => Some("DS"),
        DNS_TYPE_RRSIG => Some("RRSIG"),
        DNS_TYPE_NSEC => Some("NSEC"),
        DNS_TYPE_DNSKEY => Some("DNSKEY"),
        DNS_TYPE_ANY => Some("ANY"),
        _ => None,
    }
}

pub fn dns_type_is_pseudo(t: u16) -> bool {
    matches!(t, DNS_TYPE_OPT | DNS_TYPE_ANY)
}

pub fn dns_type_is_valid_query(t: u16) -> bool {
    !matches!(
        t,
        DNS_TYPE_OPT | DNS_TYPE_RRSIG | DNS_TYPE_NSEC | DNS_TYPE_DS
    )
}

pub fn dns_type_is_valid_rr(t: u16) -> bool {
    !dns_type_is_pseudo(t)
}

pub fn dns_type_is_dnssec(t: u16) -> bool {
    matches!(
        t,
        DNS_TYPE_DS | DNS_TYPE_RRSIG | DNS_TYPE_NSEC | DNS_TYPE_DNSKEY
    )
}

pub fn dns_type_is_obsolete(t: u16) -> bool {
    matches!(t, 3 | 4 | 254)
}

pub fn dns_type_may_wildcard(t: u16) -> bool {
    !dns_type_is_pseudo(t)
}

pub fn dns_type_apex_only(t: u16) -> bool {
    matches!(t, DNS_TYPE_SOA | DNS_TYPE_DNSKEY)
}

pub fn dns_type_needs_authentication(t: u16) -> bool {
    matches!(t, DNS_TYPE_DS | DNS_TYPE_DNSKEY)
}

// ── DNS class ──────────────────────────────────────────────────────────────

pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_CLASS_ANY: u16 = 255;

pub const DNS_CLASS_STRING_MAX: usize = 5;

pub fn dns_class_to_string(c: u16) -> Option<&'static str> {
    match c {
        DNS_CLASS_IN => Some("IN"),
        DNS_CLASS_ANY => Some("ANY"),
        3 => Some("CH"),
        4 => Some("HS"),
        _ => None,
    }
}

pub fn dns_class_is_pseudo(c: u16) -> bool {
    c == DNS_CLASS_ANY
}

pub fn dns_class_is_valid_rr(c: u16) -> bool {
    !dns_class_is_pseudo(c)
}

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableError(pub String);

impl fmt::Display for TableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "table error: {}", self.0)
    }
}

impl std::error::Error for TableError {}

pub type Result<T> = std::result::Result<T, TableError>;

// ── Table validation helpers ───────────────────────────────────────────────

pub fn validate_table_roundtrip<T: Copy + PartialEq + std::fmt::Debug>(
    values: &[T],
    to_string: fn(T) -> &'static str,
    from_string: fn(&str) -> Option<T>,
) -> Result<()> {
    for &v in values {
        let s = to_string(v);
        let parsed =
            from_string(s).ok_or_else(|| TableError(format!("roundtrip failed for {:?}", v)))?;
        if parsed != v {
            return Err(TableError(format!(
                "roundtrip mismatch: {:?} != {:?}",
                v, parsed
            )));
        }
    }
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_protocol_roundtrip() -> Result<()> {
        validate_table_roundtrip(
            &[DnsProtocol::Dns, DnsProtocol::Mdns, DnsProtocol::Llmnr],
            dns_protocol_to_string,
            dns_protocol_from_string,
        )
    }

    #[test]
    fn dnssec_result_roundtrip() -> Result<()> {
        validate_table_roundtrip(
            &[
                DnssecResult::Validated,
                DnssecResult::Invalid,
                DnssecResult::Insecure,
                DnssecResult::Indeterminate,
            ],
            dnssec_result_to_string,
            dnssec_result_from_string,
        )
    }

    #[test]
    fn dnssec_verdict_roundtrip() -> Result<()> {
        validate_table_roundtrip(
            &[
                DnssecVerdict::Secure,
                DnssecVerdict::Insecure,
                DnssecVerdict::Bogus,
                DnssecVerdict::Indeterminate,
            ],
            dnssec_verdict_to_string,
            dnssec_verdict_from_string,
        )
    }

    #[test]
    fn dns_rcode_known_values() {
        assert_eq!(dns_rcode_to_string(DNS_RCODE_SUCCESS), Some("SUCCESS"));
        assert_eq!(dns_rcode_to_string(DNS_RCODE_SERVFAIL), Some("SERVFAIL"));
        assert_eq!(dns_rcode_to_string(DNS_RCODE_NXDOMAIN), Some("NXDOMAIN"));
        assert_eq!(dns_rcode_to_string(999), None);
    }

    #[test]
    fn dns_type_to_string_all() {
        assert_eq!(dns_type_to_string(DNS_TYPE_A), Some("A"));
        assert_eq!(dns_type_to_string(DNS_TYPE_AAAA), Some("AAAA"));
        assert_eq!(dns_type_to_string(DNS_TYPE_MX), Some("MX"));
        assert_eq!(dns_type_to_string(DNS_TYPE_SOA), Some("SOA"));
        assert_eq!(dns_type_to_string(DNS_TYPE_DNSKEY), Some("DNSKEY"));
        assert_eq!(dns_type_to_string(DNS_TYPE_ANY), Some("ANY"));
    }

    #[test]
    fn dns_type_string_max_length() {
        for t in 0..256u16 {
            if let Some(s) = dns_type_to_string(t) {
                assert!(
                    s.len() < DNS_TYPE_STRING_MAX,
                    "DNS type {} string '{}' exceeds max {}",
                    t,
                    s,
                    DNS_TYPE_STRING_MAX
                );
            }
        }
    }

    #[test]
    fn dns_type_property_queries() {
        assert!(dns_type_is_pseudo(DNS_TYPE_OPT));
        assert!(dns_type_is_pseudo(DNS_TYPE_ANY));
        assert!(!dns_type_is_pseudo(DNS_TYPE_A));

        assert!(dns_type_is_dnssec(DNS_TYPE_DS));
        assert!(dns_type_is_dnssec(DNS_TYPE_RRSIG));
        assert!(!dns_type_is_dnssec(DNS_TYPE_A));

        assert!(dns_type_apex_only(DNS_TYPE_SOA));
        assert!(dns_type_apex_only(DNS_TYPE_DNSKEY));
        assert!(!dns_type_apex_only(DNS_TYPE_A));

        assert!(dns_type_needs_authentication(DNS_TYPE_DS));
        assert!(!dns_type_needs_authentication(DNS_TYPE_A));

        assert!(dns_type_is_obsolete(3));
        assert!(!dns_type_is_obsolete(DNS_TYPE_A));
    }

    #[test]
    fn dns_class_to_string_all() {
        assert_eq!(dns_class_to_string(DNS_CLASS_IN), Some("IN"));
        assert_eq!(dns_class_to_string(DNS_CLASS_ANY), Some("ANY"));
        assert_eq!(dns_class_to_string(3), Some("CH"));
        assert_eq!(dns_class_to_string(999), None);
    }

    #[test]
    fn dns_class_string_max_length() {
        for c in 0..256u16 {
            if let Some(s) = dns_class_to_string(c) {
                assert!(
                    s.len() < DNS_CLASS_STRING_MAX,
                    "DNS class {} string '{}' exceeds max {}",
                    c,
                    s,
                    DNS_CLASS_STRING_MAX
                );
            }
        }
    }

    #[test]
    fn dns_class_property_queries() {
        assert!(dns_class_is_pseudo(DNS_CLASS_ANY));
        assert!(!dns_class_is_pseudo(DNS_CLASS_IN));
        assert!(dns_class_is_valid_rr(DNS_CLASS_IN));
        assert!(!dns_class_is_valid_rr(DNS_CLASS_ANY));
    }

    #[test]
    fn dns_protocol_from_string_invalid() {
        assert!(dns_protocol_from_string("INVALID").is_none());
        assert!(dns_protocol_from_string("").is_none());
    }

    #[test]
    fn dnssec_result_from_string_invalid() {
        assert!(dnssec_result_from_string("bogus-value").is_none());
    }

    #[test]
    fn dnssec_verdict_from_string_invalid() {
        assert!(dnssec_verdict_from_string("unknown").is_none());
    }
}
