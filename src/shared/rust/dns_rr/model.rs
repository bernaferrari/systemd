// SPDX-License-Identifier: LGPL-2.1-or-later
//
// DNS resource-record data model mirrored from src/shared/dns-rr.h.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const DNS_HOSTNAME_MAX: usize = 253;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;
pub const CAA_FLAG_CRITICAL: u8 = 1 << 7;

pub const DNSKEY_FLAG_SEP: u16 = 1 << 0;
pub const DNSKEY_FLAG_REVOKE: u16 = 1 << 7;
pub const DNSKEY_FLAG_ZONE_KEY: u16 = 1 << 8;
pub const MDNS_RR_CACHE_FLUSH_OR_QU: u16 = 1 << 15;

pub const DNS_RESOURCE_KEY_STRING_MAX: usize = 12 + 12 + DNS_HOSTNAME_MAX + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsClass {
    In = 0x01,
    Any = 0xff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsType {
    A = 0x01,
    Ns = 0x02,
    Cname = 0x05,
    Soa = 0x06,
    Ptr = 0x0c,
    Hinfo = 0x0d,
    Mx = 0x0f,
    Txt = 0x10,
    Aaaa = 0x1c,
    Loc = 0x1d,
    Srv = 0x21,
    Naptr = 0x23,
    Opt = 0x29,
    Ds = 0x2b,
    Sshfp = 0x2c,
    Rrsig = 0x2e,
    Nsec = 0x2f,
    Dnskey = 0x30,
    Nsec3 = 0x32,
    Tlsa = 0x34,
    Openpgpkey = 0x3d,
    Svcb = 0x40,
    Https = 0x41,
    Spf = 0x63,
    Any = 0xff,
    Caa = 0x101,
    Dname = 0x27,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsSvcParamKey {
    Mandatory = 0,
    Alpn = 1,
    NoDefaultAlpn = 2,
    Port = 3,
    Ipv4Hint = 4,
    Ech = 5,
    Ipv6Hint = 6,
    DohPath = 7,
    Ohttp = 8,
}

pub enum DnssecAlgorithm {
    RsaMd5 = 1,
    Dh = 2,
    Dsa = 3,
    Ecc = 4,
    RsaSha1 = 5,
    DsaNsec3Sha1 = 6,
    RsaSha1Nsec3Sha1 = 7,
    RsaSha256 = 8,
    RsaSha512 = 10,
    EccGost = 12,
    EcdsaP256Sha256 = 13,
    EcdsaP384Sha384 = 14,
    Ed25519 = 15,
    Ed448 = 16,
    Indirect = 252,
    PrivateDns = 253,
    PrivateOid = 254,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum DnssecDigest {
    Sha1 = 1,
    Sha256 = 2,
    GostR341194 = 3,
    Sha384 = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Nsec3Algorithm {
    Sha1 = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SshfpAlgorithm {
    Rsa = 1,
    Dsa = 2,
    Ecdsa = 3,
    Ed25519 = 4,
    Ed448 = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SshfpKeyType {
    Sha1 = 1,
    Sha256 = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    UnexpectedEof,
    InvalidName,
    InvalidLabel,
    CompressionUnsupported,
    InvalidRdata(&'static str),
    InvalidType(u16),
    InvalidClass(u16),
    InvalidAddressFamily(i32),
    Mismatch(&'static str),
    Overflow,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => f.write_str("unexpected EOF"),
            Self::InvalidName => f.write_str("invalid DNS name"),
            Self::InvalidLabel => f.write_str("invalid DNS label"),
            Self::CompressionUnsupported => f.write_str("DNS compression pointers are unsupported"),
            Self::InvalidRdata(msg) => write!(f, "invalid rdata: {msg}"),
            Self::InvalidType(t) => write!(f, "invalid type {t}"),
            Self::InvalidClass(c) => write!(f, "invalid class {c}"),
            Self::InvalidAddressFamily(fam) => write!(f, "invalid address family {fam}"),
            Self::Mismatch(msg) => write!(f, "mismatch: {msg}"),
            Self::Overflow => f.write_str("integer overflow"),
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsTxtItem {
    pub data: Vec<u8>,
}

impl DnsTxtItem {
    pub fn new_empty() -> Self {
        Self { data: Vec::new() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsSvcParam {
    pub key: u16,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum Rdata {
    Generic(Vec<u8>),
    Opt(Vec<u8>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        name: String,
    },
    Ptr {
        name: String,
    },
    Ns {
        name: String,
    },
    Cname {
        name: String,
    },
    Dname {
        name: String,
    },
    Hinfo {
        cpu: String,
        os: String,
    },
    Txt {
        items: Vec<DnsTxtItem>,
    },
    Spf {
        items: Vec<DnsTxtItem>,
    },
    A {
        address: Ipv4Addr,
    },
    Aaaa {
        address: Ipv6Addr,
    },
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Mx {
        priority: u16,
        exchange: String,
    },
    Loc {
        version: u8,
        size: u8,
        horiz_pre: u8,
        vert_pre: u8,
        latitude: u32,
        longitude: u32,
        altitude: u32,
    },
    Sshfp {
        fingerprint: Vec<u8>,
        algorithm: u8,
        fptype: u8,
    },
    Dnskey {
        key: Vec<u8>,
        flags: u16,
        protocol: u8,
        algorithm: u8,
    },
    Rrsig {
        signer: String,
        signature: Vec<u8>,
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
    },
    Nsec {
        next_domain_name: String,
        types: BTreeSet<u16>,
    },
    Ds {
        digest: Vec<u8>,
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
    },
    Nsec3 {
        types: BTreeSet<u16>,
        salt: Vec<u8>,
        next_hashed_name: Vec<u8>,
        algorithm: u8,
        flags: u8,
        iterations: u16,
    },
    Tlsa {
        data: Vec<u8>,
        cert_usage: u8,
        selector: u8,
        matching_type: u8,
    },
    Svcb {
        priority: u16,
        target_name: String,
        params: Vec<DnsSvcParam>,
    },
    Https {
        priority: u16,
        target_name: String,
        params: Vec<DnsSvcParam>,
    },
    Caa {
        tag: String,
        value: Vec<u8>,
        flags: u8,
    },
    Naptr {
        order: u16,
        preference: u16,
        flags: String,
        services: String,
        regexp: String,
        replacement: String,
    },
}
