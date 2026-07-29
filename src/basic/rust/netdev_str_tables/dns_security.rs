// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/dns-packet.c, dns-type.c, dns-rr.c

use super::*;

// ── dns-packet: dns_rcode (SUCCESS=0..BADCOOKIE=23, gap at 12-15) ──

static DNS_RCODE_TABLE: &[(i32, &[u8])] = &[
    (0, b"SUCCESS\0"),
    (1, b"FORMERR\0"),
    (2, b"SERVFAIL\0"),
    (3, b"NXDOMAIN\0"),
    (4, b"NOTIMP\0"),
    (5, b"REFUSED\0"),
    (6, b"YXDOMAIN\0"),
    (7, b"YRRSET\0"),
    (8, b"NXRRSET\0"),
    (9, b"NOTAUTH\0"),
    (10, b"NOTZONE\0"),
    (11, b"DSOTYPENI\0"),
    (16, b"BADVERS\0"),
    (17, b"BADKEY\0"),
    (18, b"BADTIME\0"),
    (19, b"BADMODE\0"),
    (20, b"BADNAME\0"),
    (21, b"BADALG\0"),
    (22, b"BADTRUNC\0"),
    (23, b"BADCOOKIE\0"),
];

string_table!(
    rs_dns_rcode_to_string,
    rs_dns_rcode_from_string,
    DNS_RCODE_TABLE
);

// ── dns-packet: dns_protocol (DNS=0, MDNS=1, LLMNR=2) ──

static DNS_PROTOCOL_TABLE: &[(i32, &[u8])] = &[(0, b"dns\0"), (1, b"mdns\0"), (2, b"llmnr\0")];

string_table!(
    rs_dns_protocol_to_string,
    rs_dns_protocol_from_string,
    DNS_PROTOCOL_TABLE
);

// ── dns-packet: dns_svc_param_key (MANDATORY=0..OHTTP=8, to_string only) ──

static DNS_SVC_PARAM_KEY_TABLE: &[(i32, &[u8])] = &[
    (0, b"mandatory\0"),
    (1, b"alpn\0"),
    (2, b"no-default-alpn\0"),
    (3, b"port\0"),
    (4, b"ipv4hint\0"),
    (5, b"ech\0"),
    (6, b"ipv6hint\0"),
    (7, b"dohpath\0"),
    (8, b"ohttp\0"),
];

/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_svc_param_key_to_string(v: i32) -> *const c_char {
    for &(idx, name) in DNS_SVC_PARAM_KEY_TABLE {
        if idx == v {
            return static_cstr_ptr(name);
        }
    }
    std::ptr::null()
}

// ── dns-packet: dns_ede_rcode (OTHER=0..SYNTHESIZED=29, to_string only) ──

static DNS_EDE_RCODE_TABLE: &[(i32, &[u8])] = &[
    (0, b"Other\0"),
    (1, b"Unsupported DNSKEY Algorithm\0"),
    (2, b"Unsupported DS Digest Type\0"),
    (3, b"Stale Answer\0"),
    (4, b"Forged Answer\0"),
    (5, b"DNSSEC Indeterminate\0"),
    (6, b"DNSSEC Bogus\0"),
    (7, b"Signature Expired\0"),
    (8, b"Signature Not Yet Valid\0"),
    (9, b"DNSKEY Missing\0"),
    (10, b"RRSIG Missing\0"),
    (11, b"No Zone Key Bit Set\0"),
    (12, b"NSEC Missing\0"),
    (13, b"Cached Error\0"),
    (14, b"Not Ready\0"),
    (15, b"Blocked\0"),
    (16, b"Censored\0"),
    (17, b"Filtered\0"),
    (18, b"Prohibited\0"),
    (19, b"Stale NXDOMAIN Answer\0"),
    (20, b"Not Authoritative\0"),
    (21, b"Not Supported\0"),
    (22, b"No Reachable Authority\0"),
    (23, b"Network Error\0"),
    (24, b"Invalid Data\0"),
    (25, b"Signature Never Valid\0"),
    (26, b"Too Early\0"),
    (27, b"Unsupported NSEC3 Iterations\0"),
    (28, b"Impossible Transport Policy\0"),
    (29, b"Synthesized\0"),
];

/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_ede_rcode_to_string(v: i32) -> *const c_char {
    for &(idx, name) in DNS_EDE_RCODE_TABLE {
        if idx == v {
            return static_cstr_ptr(name);
        }
    }
    std::ptr::null()
}

// ── DNS EDE RCODE DNSSEC-related constants ────────────────────────────────

const DNS_EDE_RCODE_UNSUPPORTED_DNSKEY_ALG: i32 = 1;
const DNS_EDE_RCODE_UNSUPPORTED_DS_DIGEST: i32 = 2;
const DNS_EDE_RCODE_DNSSEC_INDETERMINATE: i32 = 5;
const DNS_EDE_RCODE_DNSSEC_BOGUS: i32 = 6;
const DNS_EDE_RCODE_SIG_EXPIRED: i32 = 7;
const DNS_EDE_RCODE_SIG_NOT_YET_VALID: i32 = 8;
const DNS_EDE_RCODE_DNSKEY_MISSING: i32 = 9;
const DNS_EDE_RCODE_RRSIG_MISSING: i32 = 10;
const DNS_EDE_RCODE_NO_ZONE_KEY_BIT: i32 = 11;
const DNS_EDE_RCODE_NSEC_MISSING: i32 = 12;

// ── dns_ede_rcode_is_dnssec ─────────────────────────────────────────────

/// Shadow of C dns_ede_rcode_is_dnssec() from shared/dns-packet.c
/// C ABI facade. Accepts any integer DNS EDE code.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_ede_rcode_is_dnssec(ede_rcode: i32) -> bool {
    matches!(
        ede_rcode,
        DNS_EDE_RCODE_UNSUPPORTED_DNSKEY_ALG
            | DNS_EDE_RCODE_UNSUPPORTED_DS_DIGEST
            | DNS_EDE_RCODE_DNSSEC_INDETERMINATE
            | DNS_EDE_RCODE_DNSSEC_BOGUS
            | DNS_EDE_RCODE_SIG_EXPIRED
            | DNS_EDE_RCODE_SIG_NOT_YET_VALID
            | DNS_EDE_RCODE_DNSKEY_MISSING
            | DNS_EDE_RCODE_RRSIG_MISSING
            | DNS_EDE_RCODE_NO_ZONE_KEY_BIT
            | DNS_EDE_RCODE_NSEC_MISSING
    )
}

// ── dns-type: dns_class (IN=1, ANY=255, case-insensitive from_string) ──

static DNS_CLASS_TABLE: &[(i32, &[u8])] = &[(1, b"IN\0"), (255, b"ANY\0")];

/// C ABI facade. Returns a borrowed static string or NULL for an unknown value.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub extern "C" fn rs_dns_class_to_string(v: i32) -> *const c_char {
    for &(idx, name) in DNS_CLASS_TABLE {
        if idx == v {
            return static_cstr_ptr(name);
        }
    }
    std::ptr::null()
}

/// C ABI facade. `s` must be null or a valid NUL-terminated C string.
/// # Safety
/// The caller must satisfy the pointer validity, lifetime, and ownership contract documented by the corresponding C header.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_class_from_string(s: *const c_char) -> i32 {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    for &(idx, name) in DNS_CLASS_TABLE {
        // SAFETY: the caller guarantees s is a live NUL-terminated C string.
        if unsafe { cstr_eq_ignore_ascii_case_static(s, name) } {
            return idx;
        }
    }
    Errno::EINVAL.to_neg_errno()
}

// ── dnssec_algorithm: RSAMD5=1..PRIVATEOID=254 (WITH_FALLBACK max=255) ──

static DNSSEC_ALGORITHM_TABLE: &[(i32, &[u8])] = &[
    (1, b"RSAMD5\0"),
    (2, b"DH\0"),
    (3, b"DSA\0"),
    (4, b"ECC\0"),
    (5, b"RSASHA1\0"),
    (6, b"DSA-NSEC3-SHA1\0"),
    (7, b"RSASHA1-NSEC3-SHA1\0"),
    (8, b"RSASHA256\0"),
    (10, b"RSASHA512\0"),
    (12, b"ECC-GOST\0"),
    (13, b"ECDSAP256SHA256\0"),
    (14, b"ECDSAP384SHA384\0"),
    (15, b"ED25519\0"),
    (16, b"ED448\0"),
    (252, b"INDIRECT\0"),
    (253, b"PRIVATEDNS\0"),
    (254, b"PRIVATEOID\0"),
];

string_table_fallback!(
    rs_dnssec_algorithm_to_string_alloc,
    rs_dnssec_algorithm_from_string,
    DNSSEC_ALGORITHM_TABLE,
    255
);

// ── dnssec_digest: SHA1=1..SHA384=4 (WITH_FALLBACK max=255) ──

static DNSSEC_DIGEST_TABLE: &[(i32, &[u8])] = &[
    (1, b"SHA-1\0"),
    (2, b"SHA-256\0"),
    (3, b"GOST_R_34.11-94\0"),
    (4, b"SHA-384\0"),
];

string_table_fallback!(
    rs_dnssec_digest_to_string_alloc,
    rs_dnssec_digest_from_string,
    DNSSEC_DIGEST_TABLE,
    255
);

// ── sshfp_algorithm: RSA=1..ED448=6, gap at 5 (WITH_FALLBACK max=255) ──

static SSHFP_ALGORITHM_TABLE: &[(i32, &[u8])] = &[
    (1, b"RSA\0"),
    (2, b"DSA\0"),
    (3, b"ECDSA\0"),
    (4, b"Ed25519\0"),
    (6, b"Ed448\0"),
];

string_table_fallback!(
    rs_sshfp_algorithm_to_string_alloc,
    rs_sshfp_algorithm_from_string,
    SSHFP_ALGORITHM_TABLE,
    255
);

// ── sshfp_key_type: SHA1=1, SHA256=2 (WITH_FALLBACK max=255) ──

static SSHFP_KEY_TYPE_TABLE: &[(i32, &[u8])] = &[(1, b"SHA-1\0"), (2, b"SHA-256\0")];

string_table_fallback!(
    rs_sshfp_key_type_to_string_alloc,
    rs_sshfp_key_type_from_string,
    SSHFP_KEY_TYPE_TABLE,
    255
);
