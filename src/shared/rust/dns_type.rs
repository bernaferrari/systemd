// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/dns-type.c, src/shared/dns-type.h

use std::fmt;

pub const SOURCE_PATH: &str = "src/shared/dns-type.c";
pub const SOURCE_TEXT: &str = include_str!("../dns-type.c");

pub const DNS_CLASS_STRING_MAX: usize = 12;
pub const DNS_TYPE_STRING_MAX: usize = 12;
pub const CAA_FLAG_CRITICAL: u8 = 1 << 7;

pub const DNS_TYPE_MAX: u16 = 0x8002;
pub const DNS_TYPE_INVALID: i32 = -libc::EINVAL;
pub const DNS_CLASS_MAX: u16 = 0x0100;
pub const DNS_CLASS_INVALID: i32 = -libc::EINVAL;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsType {
    A = 0x01,
    Ns = 0x02,
    Md = 0x03,
    Mf = 0x04,
    Cname = 0x05,
    Soa = 0x06,
    Mb = 0x07,
    Mg = 0x08,
    Mr = 0x09,
    Null = 0x0a,
    Wks = 0x0b,
    Ptr = 0x0c,
    Hinfo = 0x0d,
    Minfo = 0x0e,
    Mx = 0x0f,
    Txt = 0x10,
    Rp = 0x11,
    Afsdb = 0x12,
    X25 = 0x13,
    Isdn = 0x14,
    Rt = 0x15,
    Nsap = 0x16,
    NsapPtr = 0x17,
    Sig = 0x18,
    Key = 0x19,
    Px = 0x1a,
    Gpos = 0x1b,
    Aaaa = 0x1c,
    Loc = 0x1d,
    Nxt = 0x1e,
    Eid = 0x1f,
    Nimloc = 0x20,
    Srv = 0x21,
    Atma = 0x22,
    Naptr = 0x23,
    Kx = 0x24,
    Cert = 0x25,
    A6 = 0x26,
    Dname = 0x27,
    Sink = 0x28,
    Opt = 0x29,
    Apl = 0x2a,
    Ds = 0x2b,
    Sshfp = 0x2c,
    Ipseckey = 0x2d,
    Rrsig = 0x2e,
    Nsec = 0x2f,
    Dnskey = 0x30,
    Dhcid = 0x31,
    Nsec3 = 0x32,
    Nsec3param = 0x33,
    Tlsa = 0x34,
    Smimea = 0x35,
    Hip = 0x37,
    Ninfo = 0x38,
    Rkey = 0x39,
    Talink = 0x3a,
    Cds = 0x3b,
    Cdnskey = 0x3c,
    Openpgpkey = 0x3d,
    Csync = 0x3e,
    Zonemd = 0x3f,
    Svcb = 0x40,
    Https = 0x41,
    Spf = 0x63,
    Uinfo = 0x64,
    Uid = 0x65,
    Gid = 0x66,
    Unspec = 0x67,
    Nid = 0x68,
    L32 = 0x69,
    L64 = 0x6a,
    Lp = 0x6b,
    Eui48 = 0x6c,
    Eui64 = 0x6d,
    Tkey = 0xf9,
    Tsig = 0xfa,
    Ixfr = 0xfb,
    Axfr = 0xfc,
    Mailb = 0xfd,
    Maila = 0xfe,
    Any = 0xff,
    Uri = 0x100,
    Caa = 0x101,
    Avc = 0x102,
    Doa = 0x103,
    Amtrelay = 0x104,
    Resinfo = 0x105,
    Ta = 0x8000,
    Dlv = 0x8001,
}

const DNS_TYPE_BY_NAME: &[(DnsType, &str)] = &[
    (DnsType::A, "A"),
    (DnsType::Ns, "NS"),
    (DnsType::Md, "MD"),
    (DnsType::Mf, "MF"),
    (DnsType::Cname, "CNAME"),
    (DnsType::Soa, "SOA"),
    (DnsType::Mb, "MB"),
    (DnsType::Mg, "MG"),
    (DnsType::Mr, "MR"),
    (DnsType::Null, "NULL"),
    (DnsType::Wks, "WKS"),
    (DnsType::Ptr, "PTR"),
    (DnsType::Hinfo, "HINFO"),
    (DnsType::Minfo, "MINFO"),
    (DnsType::Mx, "MX"),
    (DnsType::Txt, "TXT"),
    (DnsType::Rp, "RP"),
    (DnsType::Afsdb, "AFSDB"),
    (DnsType::X25, "X25"),
    (DnsType::Isdn, "ISDN"),
    (DnsType::Rt, "RT"),
    (DnsType::Nsap, "NSAP"),
    (DnsType::NsapPtr, "NSAP-PTR"),
    (DnsType::Sig, "SIG"),
    (DnsType::Key, "KEY"),
    (DnsType::Px, "PX"),
    (DnsType::Gpos, "GPOS"),
    (DnsType::Aaaa, "AAAA"),
    (DnsType::Loc, "LOC"),
    (DnsType::Nxt, "NXT"),
    (DnsType::Eid, "EID"),
    (DnsType::Nimloc, "NIMLOC"),
    (DnsType::Srv, "SRV"),
    (DnsType::Atma, "ATMA"),
    (DnsType::Naptr, "NAPTR"),
    (DnsType::Kx, "KX"),
    (DnsType::Cert, "CERT"),
    (DnsType::A6, "A6"),
    (DnsType::Dname, "DNAME"),
    (DnsType::Sink, "SINK"),
    (DnsType::Opt, "OPT"),
    (DnsType::Apl, "APL"),
    (DnsType::Ds, "DS"),
    (DnsType::Sshfp, "SSHFP"),
    (DnsType::Ipseckey, "IPSECKEY"),
    (DnsType::Rrsig, "RRSIG"),
    (DnsType::Nsec, "NSEC"),
    (DnsType::Dnskey, "DNSKEY"),
    (DnsType::Dhcid, "DHCID"),
    (DnsType::Nsec3, "NSEC3"),
    (DnsType::Nsec3param, "NSEC3PARAM"),
    (DnsType::Tlsa, "TLSA"),
    (DnsType::Smimea, "SMIMEA"),
    (DnsType::Hip, "HIP"),
    (DnsType::Ninfo, "NINFO"),
    (DnsType::Rkey, "RKEY"),
    (DnsType::Talink, "TALINK"),
    (DnsType::Cds, "CDS"),
    (DnsType::Cdnskey, "CDNSKEY"),
    (DnsType::Openpgpkey, "OPENPGPKEY"),
    (DnsType::Csync, "CSYNC"),
    (DnsType::Zonemd, "ZONEMD"),
    (DnsType::Svcb, "SVCB"),
    (DnsType::Https, "HTTPS"),
    (DnsType::Spf, "SPF"),
    (DnsType::Uinfo, "UINFO"),
    (DnsType::Uid, "UID"),
    (DnsType::Gid, "GID"),
    (DnsType::Unspec, "UNSPEC"),
    (DnsType::Nid, "NID"),
    (DnsType::L32, "L32"),
    (DnsType::L64, "L64"),
    (DnsType::Lp, "LP"),
    (DnsType::Eui48, "EUI48"),
    (DnsType::Eui64, "EUI64"),
    (DnsType::Tkey, "TKEY"),
    (DnsType::Tsig, "TSIG"),
    (DnsType::Ixfr, "IXFR"),
    (DnsType::Axfr, "AXFR"),
    (DnsType::Mailb, "MAILB"),
    (DnsType::Maila, "MAILA"),
    (DnsType::Any, "ANY"),
    (DnsType::Uri, "URI"),
    (DnsType::Caa, "CAA"),
    (DnsType::Avc, "AVC"),
    (DnsType::Doa, "DOA"),
    (DnsType::Amtrelay, "AMTRELAY"),
    (DnsType::Resinfo, "RESINFO"),
    (DnsType::Ta, "TA"),
    (DnsType::Dlv, "DLV"),
];

impl DnsType {
    pub fn from_u16(value: u16) -> Option<Self> {
        DNS_TYPE_BY_NAME
            .iter()
            .find_map(|(kind, _)| ((*kind as u16) == value).then_some(*kind))
    }

    pub fn to_name(self) -> &'static str {
        DNS_TYPE_BY_NAME
            .iter()
            .find_map(|(kind, name)| (*kind == self).then_some(*name))
            .expect("known DNS types must have a name")
    }

    pub fn is_pseudo(self) -> bool {
        dns_type_is_pseudo(self as u16)
    }

    pub fn is_valid_query(self) -> bool {
        dns_type_is_valid_query(self as u16)
    }

    pub fn is_zone_transfer(self) -> bool {
        dns_type_is_zone_transfer(self as u16)
    }

    pub fn is_valid_rr(self) -> bool {
        dns_type_is_valid_rr(self as u16)
    }

    pub fn may_redirect(self) -> bool {
        dns_type_may_redirect(self as u16)
    }

    pub fn may_wildcard(self) -> bool {
        dns_type_may_wildcard(self as u16)
    }

    pub fn apex_only(self) -> bool {
        dns_type_apex_only(self as u16)
    }

    pub fn is_dnssec(self) -> bool {
        dns_type_is_dnssec(self as u16)
    }

    pub fn is_obsolete(self) -> bool {
        dns_type_is_obsolete(self as u16)
    }

    pub fn needs_authentication(self) -> bool {
        dns_type_needs_authentication(self as u16)
    }

    pub fn address_family(self) -> Option<AddressFamily> {
        dns_type_to_af(self as u16)
    }
}

impl fmt::Display for DnsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsClass {
    In = 0x01,
    Any = 0xff,
}

impl DnsClass {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x01 => Some(Self::In),
            0xff => Some(Self::Any),
            _ => None,
        }
    }

    pub fn to_name(self) -> &'static str {
        match self {
            Self::In => "IN",
            Self::Any => "ANY",
        }
    }

    pub fn is_pseudo(self) -> bool {
        dns_class_is_pseudo(self as u16)
    }

    pub fn is_valid_rr(self) -> bool {
        dns_class_is_valid_rr(self as u16)
    }
}

impl fmt::Display for DnsClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum AddressFamily {
    Inet = libc::AF_INET,
    Inet6 = libc::AF_INET6,
    Unspec = libc::AF_UNSPEC,
}

fn parse_generic_type_name(name: &str) -> Option<u16> {
    let (prefix, rest) = name.split_at_checked(4)?;
    if !prefix.eq_ignore_ascii_case("TYPE") || rest.is_empty() {
        return None;
    }

    rest.chars().all(|ch| ch.is_ascii_digit()).then_some(())?;

    rest.parse::<u16>().ok()
}

pub fn dns_type_to_string(value: u16) -> Option<&'static str> {
    DnsType::from_u16(value).map(DnsType::to_name)
}

pub fn dns_type_from_string(name: &str) -> Option<u16> {
    DNS_TYPE_BY_NAME
        .iter()
        .find_map(|(kind, known_name)| {
            known_name
                .eq_ignore_ascii_case(name)
                .then_some(*kind as u16)
        })
        .or_else(|| parse_generic_type_name(name))
}

pub fn dns_type_is_pseudo(value: u16) -> bool {
    value == 0
        || value == DnsType::Any as u16
        || value == DnsType::Axfr as u16
        || value == DnsType::Ixfr as u16
        || value == DnsType::Opt as u16
        || value == DnsType::Tsig as u16
        || value == DnsType::Tkey as u16
}

pub fn dns_class_is_pseudo(value: u16) -> bool {
    value == DnsClass::Any as u16
}

pub fn dns_type_is_valid_query(value: u16) -> bool {
    value != 0
        && value != DnsType::Opt as u16
        && value != DnsType::Tsig as u16
        && value != DnsType::Tkey as u16
        && value != DnsType::Rrsig as u16
}

pub fn dns_type_is_zone_transfer(value: u16) -> bool {
    value == DnsType::Axfr as u16 || value == DnsType::Ixfr as u16
}

pub fn dns_type_is_valid_rr(value: u16) -> bool {
    value != DnsType::Any as u16 && value != DnsType::Axfr as u16 && value != DnsType::Ixfr as u16
}

pub fn dns_class_is_valid_rr(value: u16) -> bool {
    value != DnsClass::Any as u16
}

pub fn dns_type_may_redirect(value: u16) -> bool {
    if dns_type_is_pseudo(value) {
        return false;
    }

    value != DnsType::Cname as u16
        && value != DnsType::Dname as u16
        && value != DnsType::Nsec3 as u16
        && value != DnsType::Nsec as u16
        && value != DnsType::Rrsig as u16
        && value != DnsType::Nxt as u16
        && value != DnsType::Sig as u16
        && value != DnsType::Key as u16
}

pub fn dns_type_may_wildcard(value: u16) -> bool {
    if dns_type_is_pseudo(value) {
        return false;
    }

    value != DnsType::Nsec3 as u16 && value != DnsType::Soa as u16 && value != DnsType::Dname as u16
}

pub fn dns_type_apex_only(value: u16) -> bool {
    value == DnsType::Soa as u16
        || value == DnsType::Ns as u16
        || value == DnsType::Dnskey as u16
        || value == DnsType::Nsec3param as u16
}

pub fn dns_type_is_dnssec(value: u16) -> bool {
    value == DnsType::Ds as u16
        || value == DnsType::Dnskey as u16
        || value == DnsType::Rrsig as u16
        || value == DnsType::Nsec as u16
        || value == DnsType::Nsec3 as u16
        || value == DnsType::Nsec3param as u16
}

pub fn dns_type_is_obsolete(value: u16) -> bool {
    value == DnsType::Md as u16
        || value == DnsType::Mf as u16
        || value == DnsType::Maila as u16
        || value == DnsType::Mb as u16
        || value == DnsType::Mg as u16
        || value == DnsType::Mr as u16
        || value == DnsType::Minfo as u16
        || value == DnsType::Mailb as u16
        || value == DnsType::Wks as u16
        || value == DnsType::A6 as u16
        || value == DnsType::Nxt as u16
        || value == DnsType::Null as u16
}

pub fn dns_type_needs_authentication(value: u16) -> bool {
    value == DnsType::Cert as u16
        || value == DnsType::Sshfp as u16
        || value == DnsType::Ipseckey as u16
        || value == DnsType::Ds as u16
        || value == DnsType::Dnskey as u16
        || value == DnsType::Tlsa as u16
        || value == DnsType::Cdnskey as u16
        || value == DnsType::Openpgpkey as u16
        || value == DnsType::Caa as u16
}

pub fn dns_type_to_af(value: u16) -> Option<AddressFamily> {
    match value {
        x if x == DnsType::A as u16 => Some(AddressFamily::Inet),
        x if x == DnsType::Aaaa as u16 => Some(AddressFamily::Inet6),
        x if x == DnsType::Any as u16 => Some(AddressFamily::Unspec),
        _ => None,
    }
}

pub fn dns_class_to_string(value: u16) -> Option<&'static str> {
    DnsClass::from_u16(value).map(DnsClass::to_name)
}

pub fn dns_class_from_string(name: &str) -> Option<DnsClass> {
    if name.eq_ignore_ascii_case("IN") {
        Some(DnsClass::In)
    } else if name.eq_ignore_ascii_case("ANY") {
        Some(DnsClass::Any)
    } else {
        None
    }
}

pub fn tlsa_cert_usage_to_string(cert_usage: u8) -> &'static str {
    match cert_usage {
        0 => "CA constraint",
        1 => "Service certificate constraint",
        2 => "Trust anchor assertion",
        3 => "Domain-issued certificate",
        4..=254 => "Unassigned",
        255 => "Private use",
    }
}

pub fn tlsa_selector_to_string(selector: u8) -> &'static str {
    match selector {
        0 => "Full Certificate",
        1 => "SubjectPublicKeyInfo",
        2..=254 => "Unassigned",
        255 => "Private use",
    }
}

pub fn tlsa_matching_type_to_string(matching_type: u8) -> &'static str {
    match matching_type {
        0 => "No hash used",
        1 => "SHA-256",
        2 => "SHA-512",
        3..=254 => "Unassigned",
        255 => "Private use",
    }
}

trait SplitAtChecked {
    fn split_at_checked(&self, mid: usize) -> Option<(&str, &str)>;
}

impl SplitAtChecked for str {
    fn split_at_checked(&self, mid: usize) -> Option<(&str, &str)> {
        (self.len() >= mid).then(|| self.split_at(mid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_reference_constants_are_kept() {
        assert_eq!(SOURCE_PATH, "src/shared/dns-type.c");
        assert!(SOURCE_TEXT.contains("dns_type_from_string"));
    }

    #[test]
    fn header_constants_match_c() {
        assert_eq!(DNS_CLASS_STRING_MAX, 12);
        assert_eq!(DNS_TYPE_STRING_MAX, 12);
        assert_eq!(CAA_FLAG_CRITICAL, 0x80);
        assert_eq!(DNS_TYPE_MAX, 0x8002);
        assert_eq!(DNS_CLASS_MAX, 0x0100);
        assert_eq!(DNS_TYPE_INVALID, -libc::EINVAL);
        assert_eq!(DNS_CLASS_INVALID, -libc::EINVAL);
    }

    #[test]
    fn dns_type_from_u16_and_to_name_cover_known_values() {
        assert_eq!(DnsType::from_u16(1), Some(DnsType::A));
        assert_eq!(DnsType::from_u16(53), Some(DnsType::Smimea));
        assert_eq!(DnsType::from_u16(65), Some(DnsType::Https));
        assert_eq!(DnsType::from_u16(109), Some(DnsType::Eui64));
        assert_eq!(DnsType::from_u16(261), Some(DnsType::Resinfo));
        assert_eq!(DnsType::from_u16(65535), None);
        assert_eq!(DnsType::NsapPtr.to_name(), "NSAP-PTR");
        assert_eq!(DnsType::Https.to_string(), "HTTPS");
    }

    #[test]
    fn dns_class_from_u16_and_display_work() {
        assert_eq!(DnsClass::from_u16(1), Some(DnsClass::In));
        assert_eq!(DnsClass::from_u16(255), Some(DnsClass::Any));
        assert_eq!(DnsClass::from_u16(0), None);
        assert_eq!(DnsClass::Any.to_name(), "ANY");
        assert_eq!(DnsClass::In.to_string(), "IN");
    }

    #[test]
    fn dns_type_string_lookups_match_c_semantics() {
        assert_eq!(dns_type_to_string(DnsType::A as u16), Some("A"));
        assert_eq!(
            dns_type_to_string(DnsType::NsapPtr as u16),
            Some("NSAP-PTR")
        );
        assert_eq!(dns_type_to_string(54), None);

        assert_eq!(dns_type_from_string("A"), Some(1));
        assert_eq!(dns_type_from_string("aaaa"), Some(28));
        assert_eq!(dns_type_from_string("nsap-ptr"), Some(23));
        assert_eq!(dns_type_from_string("TYPE0"), Some(0));
        assert_eq!(dns_type_from_string("type65535"), Some(u16::MAX));
        assert_eq!(dns_type_from_string("TYPE65536"), None);
        assert_eq!(dns_type_from_string("TYPE"), None);
        assert_eq!(dns_type_from_string("TYPE-1"), None);
        assert_eq!(dns_type_from_string("TYPE12X"), None);
        assert_eq!(dns_type_from_string("invalid"), None);
    }

    #[test]
    fn dns_type_predicates_match_c_logic() {
        assert!(dns_type_is_pseudo(0));
        assert!(dns_type_is_pseudo(DnsType::Any as u16));
        assert!(!dns_type_is_pseudo(DnsType::A as u16));
        assert!(DnsType::Any.is_pseudo());

        assert!(!dns_type_is_valid_query(0));
        assert!(!dns_type_is_valid_query(DnsType::Rrsig as u16));
        assert!(dns_type_is_valid_query(DnsType::A as u16));
        assert!(DnsType::Mx.is_valid_query());

        assert!(dns_type_is_zone_transfer(DnsType::Axfr as u16));
        assert!(dns_type_is_zone_transfer(DnsType::Ixfr as u16));
        assert!(!dns_type_is_zone_transfer(DnsType::A as u16));
        assert!(DnsType::Axfr.is_zone_transfer());

        assert!(!dns_type_is_valid_rr(DnsType::Any as u16));
        assert!(!dns_type_is_valid_rr(DnsType::Axfr as u16));
        assert!(dns_type_is_valid_rr(DnsType::Opt as u16));
        assert!(DnsType::Opt.is_valid_rr());

        assert!(!dns_type_may_redirect(DnsType::Any as u16));
        assert!(!dns_type_may_redirect(DnsType::Cname as u16));
        assert!(dns_type_may_redirect(DnsType::A as u16));
        assert!(DnsType::A.may_redirect());

        assert!(!dns_type_may_wildcard(DnsType::Any as u16));
        assert!(!dns_type_may_wildcard(DnsType::Soa as u16));
        assert!(dns_type_may_wildcard(DnsType::Mx as u16));
        assert!(DnsType::Mx.may_wildcard());

        assert!(dns_type_apex_only(DnsType::Soa as u16));
        assert!(dns_type_apex_only(DnsType::Ns as u16));
        assert!(!dns_type_apex_only(DnsType::A as u16));
        assert!(DnsType::Dnskey.apex_only());

        assert!(dns_type_is_dnssec(DnsType::Ds as u16));
        assert!(dns_type_is_dnssec(DnsType::Nsec3param as u16));
        assert!(!dns_type_is_dnssec(DnsType::A as u16));
        assert!(DnsType::Rrsig.is_dnssec());

        assert!(dns_type_is_obsolete(DnsType::Md as u16));
        assert!(dns_type_is_obsolete(DnsType::Mailb as u16));
        assert!(!dns_type_is_obsolete(DnsType::Aaaa as u16));
        assert!(DnsType::Null.is_obsolete());

        assert!(dns_type_needs_authentication(DnsType::Cert as u16));
        assert!(dns_type_needs_authentication(DnsType::Caa as u16));
        assert!(!dns_type_needs_authentication(DnsType::Mx as u16));
        assert!(DnsType::Dnskey.needs_authentication());
    }

    #[test]
    fn dns_class_predicates_match_c_logic() {
        assert!(dns_class_is_pseudo(DnsClass::Any as u16));
        assert!(!dns_class_is_pseudo(DnsClass::In as u16));
        assert!(DnsClass::Any.is_pseudo());

        assert!(!dns_class_is_valid_rr(DnsClass::Any as u16));
        assert!(dns_class_is_valid_rr(DnsClass::In as u16));
        assert!(dns_class_is_valid_rr(0));
        assert!(DnsClass::In.is_valid_rr());
    }

    #[test]
    fn dns_type_to_af_returns_expected_families() {
        assert_eq!(dns_type_to_af(DnsType::A as u16), Some(AddressFamily::Inet));
        assert_eq!(
            dns_type_to_af(DnsType::Aaaa as u16),
            Some(AddressFamily::Inet6)
        );
        assert_eq!(
            dns_type_to_af(DnsType::Any as u16),
            Some(AddressFamily::Unspec)
        );
        assert_eq!(dns_type_to_af(DnsType::Mx as u16), None);
        assert_eq!(DnsType::A.address_family(), Some(AddressFamily::Inet));
    }

    #[test]
    fn dns_class_string_lookups_match_c_semantics() {
        assert_eq!(dns_class_to_string(DnsClass::In as u16), Some("IN"));
        assert_eq!(dns_class_to_string(DnsClass::Any as u16), Some("ANY"));
        assert_eq!(dns_class_to_string(0), None);

        assert_eq!(dns_class_from_string("IN"), Some(DnsClass::In));
        assert_eq!(dns_class_from_string("any"), Some(DnsClass::Any));
        assert_eq!(dns_class_from_string("CH"), None);
    }

    #[test]
    fn tlsa_string_lookups_cover_all_ranges() {
        assert_eq!(tlsa_cert_usage_to_string(0), "CA constraint");
        assert_eq!(tlsa_cert_usage_to_string(3), "Domain-issued certificate");
        assert_eq!(tlsa_cert_usage_to_string(100), "Unassigned");
        assert_eq!(tlsa_cert_usage_to_string(255), "Private use");

        assert_eq!(tlsa_selector_to_string(0), "Full Certificate");
        assert_eq!(tlsa_selector_to_string(1), "SubjectPublicKeyInfo");
        assert_eq!(tlsa_selector_to_string(200), "Unassigned");
        assert_eq!(tlsa_selector_to_string(255), "Private use");

        assert_eq!(tlsa_matching_type_to_string(0), "No hash used");
        assert_eq!(tlsa_matching_type_to_string(1), "SHA-256");
        assert_eq!(tlsa_matching_type_to_string(2), "SHA-512");
        assert_eq!(tlsa_matching_type_to_string(200), "Unassigned");
        assert_eq!(tlsa_matching_type_to_string(255), "Private use");
    }
}
