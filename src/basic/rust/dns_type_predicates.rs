// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/dns-type.c

use crate::ffi::Errno;
use libc::{c_char, c_int};
use std::ffi::CStr;

pub const AF_UNSPEC: c_int = libc::AF_UNSPEC;
pub const AF_INET: c_int = libc::AF_INET;
pub const AF_INET6: c_int = libc::AF_INET6;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    Null = 0x0A,
    Wks = 0x0B,
    Ptr = 0x0C,
    Minfo = 0x0E,
    Mx = 0x0F,
    Aaaa = 0x1C,
    Nxt = 0x1E,
    Srv = 0x21,
    Cert = 0x25,
    A6 = 0x26,
    Dname = 0x27,
    Opt = 0x29,
    Ds = 0x2B,
    Sshfp = 0x2C,
    Ipseckey = 0x2D,
    Rrsig = 0x2E,
    Dnskey = 0x30,
    Nsec = 0x2F,
    Nsec3 = 0x32,
    Nsec3Param = 0x33,
    Tlsa = 0x34,
    Cdnskey = 0x3C,
    Openpgpkey = 0x3D,
    Tkey = 0xF9,
    Tsig = 0xFA,
    Ixfr = 0xFB,
    Axfr = 0xFC,
    Mailb = 0xFD,
    Maila = 0xFE,
    Any = 0xFF,
    Caa = 0x101,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsClass {
    In = 0x01,
    Any = 0xFF,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPredicateError {
    InvalidAddressFamily,
}

impl DnsPredicateError {
    pub const fn errno(self) -> Errno {
        match self {
            Self::InvalidAddressFamily => Errno::EINVAL,
        }
    }
}

const fn in_set(value: u16, set: &[u16]) -> bool {
    let mut i = 0;
    while i < set.len() {
        if set[i] == value {
            return true;
        }
        i += 1;
    }
    false
}

#[inline]
pub const fn dns_type_is_pseudo(ty: u16) -> bool {
    in_set(
        ty,
        &[
            0,
            DnsType::Any as u16,
            DnsType::Axfr as u16,
            DnsType::Ixfr as u16,
            DnsType::Opt as u16,
            DnsType::Tsig as u16,
            DnsType::Tkey as u16,
        ],
    )
}

#[inline]
pub const fn dns_class_is_pseudo(class: u16) -> bool {
    class == DnsClass::Any as u16
}

#[inline]
pub const fn dns_type_is_valid_query(ty: u16) -> bool {
    !in_set(
        ty,
        &[
            0,
            DnsType::Opt as u16,
            DnsType::Tsig as u16,
            DnsType::Tkey as u16,
            DnsType::Rrsig as u16,
        ],
    )
}

#[inline]
pub const fn dns_type_is_zone_transfer(ty: u16) -> bool {
    in_set(ty, &[DnsType::Axfr as u16, DnsType::Ixfr as u16])
}

#[inline]
pub const fn dns_type_is_valid_rr(ty: u16) -> bool {
    !in_set(
        ty,
        &[
            DnsType::Any as u16,
            DnsType::Axfr as u16,
            DnsType::Ixfr as u16,
        ],
    )
}

#[inline]
pub const fn dns_class_is_valid_rr(class: u16) -> bool {
    class != DnsClass::Any as u16
}

#[inline]
pub const fn dns_type_may_redirect(ty: u16) -> bool {
    if dns_type_is_pseudo(ty) {
        return false;
    }

    !in_set(
        ty,
        &[
            DnsType::Cname as u16,
            DnsType::Dname as u16,
            DnsType::Nsec3 as u16,
            DnsType::Nsec as u16,
            DnsType::Rrsig as u16,
            DnsType::Nxt as u16,
            0x18,
            0x19,
        ],
    )
}

#[inline]
pub const fn dns_type_may_wildcard(ty: u16) -> bool {
    if dns_type_is_pseudo(ty) {
        return false;
    }

    !in_set(
        ty,
        &[
            DnsType::Nsec3 as u16,
            DnsType::Soa as u16,
            DnsType::Dname as u16,
        ],
    )
}

#[inline]
pub const fn dns_type_apex_only(ty: u16) -> bool {
    in_set(
        ty,
        &[
            DnsType::Soa as u16,
            DnsType::Ns as u16,
            DnsType::Dnskey as u16,
            DnsType::Nsec3Param as u16,
        ],
    )
}

#[inline]
pub const fn dns_type_is_dnssec(ty: u16) -> bool {
    in_set(
        ty,
        &[
            DnsType::Ds as u16,
            DnsType::Dnskey as u16,
            DnsType::Rrsig as u16,
            DnsType::Nsec as u16,
            DnsType::Nsec3 as u16,
            DnsType::Nsec3Param as u16,
        ],
    )
}

#[inline]
pub const fn dns_type_is_obsolete(ty: u16) -> bool {
    in_set(
        ty,
        &[
            DnsType::Md as u16,
            DnsType::Mf as u16,
            DnsType::Maila as u16,
            DnsType::Mb as u16,
            DnsType::Mg as u16,
            DnsType::Mr as u16,
            DnsType::Minfo as u16,
            DnsType::Mailb as u16,
            DnsType::Wks as u16,
            DnsType::A6 as u16,
            DnsType::Nxt as u16,
            DnsType::Null as u16,
        ],
    )
}

#[inline]
pub const fn dns_type_needs_authentication(ty: u16) -> bool {
    in_set(
        ty,
        &[
            DnsType::Cert as u16,
            DnsType::Sshfp as u16,
            DnsType::Ipseckey as u16,
            DnsType::Ds as u16,
            DnsType::Dnskey as u16,
            DnsType::Tlsa as u16,
            DnsType::Cdnskey as u16,
            DnsType::Openpgpkey as u16,
            DnsType::Caa as u16,
        ],
    )
}

pub const fn dns_type_to_af(ty: u16) -> Result<c_int, DnsPredicateError> {
    if ty == DnsType::A as u16 {
        Ok(AF_INET)
    } else if ty == DnsType::Aaaa as u16 {
        Ok(AF_INET6)
    } else if ty == DnsType::Any as u16 {
        Ok(AF_UNSPEC)
    } else {
        Err(DnsPredicateError::InvalidAddressFamily)
    }
}

fn tlsa_cert_usage_cstr(cert_usage: u8) -> &'static CStr {
    match cert_usage {
        0 => c"CA constraint",
        1 => c"Service certificate constraint",
        2 => c"Trust anchor assertion",
        3 => c"Domain-issued certificate",
        4..=254 => c"Unassigned",
        255 => c"Private use",
    }
}

pub fn tlsa_cert_usage_to_string(cert_usage: u8) -> &'static str {
    tlsa_cert_usage_cstr(cert_usage)
        .to_str()
        .expect("TLSA certificate-usage names are ASCII")
}

fn tlsa_selector_cstr(selector: u8) -> &'static CStr {
    match selector {
        0 => c"Full Certificate",
        1 => c"SubjectPublicKeyInfo",
        2..=254 => c"Unassigned",
        255 => c"Private use",
    }
}

pub fn tlsa_selector_to_string(selector: u8) -> &'static str {
    tlsa_selector_cstr(selector)
        .to_str()
        .expect("TLSA selector names are ASCII")
}

fn tlsa_matching_type_cstr(selector: u8) -> &'static CStr {
    match selector {
        0 => c"No hash used",
        1 => c"SHA-256",
        2 => c"SHA-512",
        3..=254 => c"Unassigned",
        255 => c"Private use",
    }
}

pub fn tlsa_matching_type_to_string(selector: u8) -> &'static str {
    tlsa_matching_type_cstr(selector)
        .to_str()
        .expect("TLSA matching-type names are ASCII")
}

// C ABI facades. All arguments and predicate results are fixed-width values;
// no caller-owned storage crosses this boundary.

#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_type_is_pseudo(ty: u16) -> bool {
    dns_type_is_pseudo(ty)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_class_is_pseudo(class: u16) -> bool {
    dns_class_is_pseudo(class)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_type_is_valid_query(ty: u16) -> bool {
    dns_type_is_valid_query(ty)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_type_is_zone_transfer(ty: u16) -> bool {
    dns_type_is_zone_transfer(ty)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_type_is_valid_rr(ty: u16) -> bool {
    dns_type_is_valid_rr(ty)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_class_is_valid_rr(class: u16) -> bool {
    dns_class_is_valid_rr(class)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_type_may_redirect(ty: u16) -> bool {
    dns_type_may_redirect(ty)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_type_may_wildcard(ty: u16) -> bool {
    dns_type_may_wildcard(ty)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_type_apex_only(ty: u16) -> bool {
    dns_type_apex_only(ty)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_type_is_dnssec(ty: u16) -> bool {
    dns_type_is_dnssec(ty)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_type_is_obsolete(ty: u16) -> bool {
    dns_type_is_obsolete(ty)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_type_needs_authentication(ty: u16) -> bool {
    dns_type_needs_authentication(ty)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_type_to_af(ty: u16) -> c_int {
    match dns_type_to_af(ty) {
        Ok(af) => af,
        Err(error) => error.errno().to_neg_errno(),
    }
}

/// Return a borrowed NUL-terminated name in static storage.
///
/// The returned pointer is never null and must not be freed.
#[unsafe(no_mangle)]
pub extern "C" fn rs_tlsa_cert_usage_to_string(cert_usage: u8) -> *const c_char {
    tlsa_cert_usage_cstr(cert_usage).as_ptr()
}

/// Return a borrowed NUL-terminated name in static storage.
///
/// The returned pointer is never null and must not be freed.
#[unsafe(no_mangle)]
pub extern "C" fn rs_tlsa_selector_to_string(selector: u8) -> *const c_char {
    tlsa_selector_cstr(selector).as_ptr()
}

/// Return a borrowed NUL-terminated name in static storage.
///
/// The returned pointer is never null and must not be freed.
#[unsafe(no_mangle)]
pub extern "C" fn rs_tlsa_matching_type_to_string(selector: u8) -> *const c_char {
    tlsa_matching_type_cstr(selector).as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudo_types_match_c_list() {
        assert!(dns_type_is_pseudo(0));
        assert!(dns_type_is_pseudo(DnsType::Any as u16));
        assert!(dns_type_is_pseudo(DnsType::Axfr as u16));
        assert!(!dns_type_is_pseudo(DnsType::A as u16));
        assert!(!dns_type_is_pseudo(DnsType::Mx as u16));
    }

    #[test]
    fn pseudo_classes_match_c_list() {
        assert!(dns_class_is_pseudo(DnsClass::Any as u16));
        assert!(!dns_class_is_pseudo(DnsClass::In as u16));
        assert!(!dns_class_is_pseudo(0));
    }

    #[test]
    fn valid_query_rejects_special_cases() {
        assert!(!dns_type_is_valid_query(0));
        assert!(!dns_type_is_valid_query(DnsType::Opt as u16));
        assert!(!dns_type_is_valid_query(DnsType::Rrsig as u16));
        assert!(dns_type_is_valid_query(DnsType::Any as u16));
        assert!(dns_type_is_valid_query(DnsType::Axfr as u16));
    }

    #[test]
    fn rr_validity_matches_c() {
        assert!(!dns_type_is_valid_rr(DnsType::Any as u16));
        assert!(!dns_type_is_valid_rr(DnsType::Axfr as u16));
        assert!(dns_type_is_valid_rr(DnsType::A as u16));
        assert!(dns_class_is_valid_rr(DnsClass::In as u16));
        assert!(!dns_class_is_valid_rr(DnsClass::Any as u16));
    }

    #[test]
    fn redirect_and_wildcard_rules_match_c() {
        assert!(!dns_type_may_redirect(DnsType::Cname as u16));
        assert!(!dns_type_may_redirect(DnsType::Opt as u16));
        assert!(dns_type_may_redirect(DnsType::A as u16));
        assert!(!dns_type_may_wildcard(DnsType::Soa as u16));
        assert!(!dns_type_may_wildcard(DnsType::Nsec3 as u16));
        assert!(dns_type_may_wildcard(DnsType::Mx as u16));
    }

    #[test]
    fn apex_and_dnssec_sets_match_c() {
        assert!(dns_type_apex_only(DnsType::Soa as u16));
        assert!(dns_type_apex_only(DnsType::Dnskey as u16));
        assert!(!dns_type_apex_only(DnsType::A as u16));
        assert!(dns_type_is_dnssec(DnsType::Nsec3 as u16));
        assert!(!dns_type_is_dnssec(DnsType::Srv as u16));
    }

    #[test]
    fn obsolete_and_authenticated_sets_match_c() {
        assert!(dns_type_is_obsolete(DnsType::Md as u16));
        assert!(dns_type_is_obsolete(DnsType::Null as u16));
        assert!(!dns_type_is_obsolete(DnsType::A as u16));
        assert!(dns_type_needs_authentication(DnsType::Tlsa as u16));
        assert!(dns_type_needs_authentication(DnsType::Caa as u16));
        assert!(!dns_type_needs_authentication(DnsType::Mx as u16));
    }

    #[test]
    fn address_family_mapping_matches_c() {
        assert_eq!(dns_type_to_af(DnsType::A as u16), Ok(AF_INET));
        assert_eq!(dns_type_to_af(DnsType::Aaaa as u16), Ok(AF_INET6));
        assert_eq!(dns_type_to_af(DnsType::Any as u16), Ok(AF_UNSPEC));
        assert_eq!(
            dns_type_to_af(DnsType::Mx as u16),
            Err(DnsPredicateError::InvalidAddressFamily)
        );
    }

    #[test]
    fn tlsa_usage_strings_match_c() {
        assert_eq!(tlsa_cert_usage_to_string(0), "CA constraint");
        assert_eq!(tlsa_cert_usage_to_string(3), "Domain-issued certificate");
        assert_eq!(tlsa_cert_usage_to_string(200), "Unassigned");
        assert_eq!(tlsa_cert_usage_to_string(255), "Private use");
    }

    #[test]
    fn tlsa_selector_strings_match_c() {
        assert_eq!(tlsa_selector_to_string(0), "Full Certificate");
        assert_eq!(tlsa_selector_to_string(1), "SubjectPublicKeyInfo");
        assert_eq!(tlsa_selector_to_string(2), "Unassigned");
        assert_eq!(tlsa_selector_to_string(255), "Private use");
    }

    #[test]
    fn tlsa_matching_strings_match_c() {
        assert_eq!(tlsa_matching_type_to_string(0), "No hash used");
        assert_eq!(tlsa_matching_type_to_string(1), "SHA-256");
        assert_eq!(tlsa_matching_type_to_string(2), "SHA-512");
        assert_eq!(tlsa_matching_type_to_string(4), "Unassigned");
        assert_eq!(tlsa_matching_type_to_string(255), "Private use");
    }
}
