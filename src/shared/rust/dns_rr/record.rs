// SPDX-License-Identifier: LGPL-2.1-or-later
//
// DNS resource-record lifecycle, matching, equality, and hashing.

use std::cmp::Ordering;
use std::fmt::Write as _;
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr};

use super::key::{
    dns_name_change_suffix, dns_name_startswith, dns_type_may_redirect, eq_name, skip_labels,
    DnsResourceKey,
};
use super::model::{
    DnsClass, DnsSvcParam, DnsTxtItem, DnsType, ParseError, Rdata, AF_INET, AF_INET6,
    DNSKEY_FLAG_REVOKE,
};

#[derive(Debug, Clone)]
pub struct DnsResourceRecord {
    pub key: DnsResourceKey,
    pub ttl: u32,
    pub expiry: Option<u64>,
    pub signer_skip_labels: Option<u8>,
    pub source_skip_labels: Option<u8>,
    pub unparsable: bool,
    pub wire_format_canonical: bool,
    pub wire_format: Option<Vec<u8>>,
    pub wire_format_rdata_offset: usize,
    pub rdata: Rdata,
}

impl DnsResourceKey {
    pub fn new_redirect(key: &Self, cname: &DnsResourceRecord) -> Result<Self, ParseError> {
        match cname.key.rr_type {
            x if x == DnsType::Cname as u16 => Self::new(
                key.dns_class,
                key.rr_type,
                cname
                    .target_name()
                    .ok_or(ParseError::Mismatch("CNAME missing target"))?,
            ),
            x if x == DnsType::Dname as u16 => {
                let changed = dns_name_change_suffix(
                    &key.name,
                    &cname.key.name,
                    cname
                        .target_name()
                        .ok_or(ParseError::Mismatch("DNAME missing target"))?,
                )?;
                match changed {
                    Some(name) => Self::new(key.dns_class, key.rr_type, name),
                    None => Ok(key.clone()),
                }
            }
            _ => Err(ParseError::Mismatch("record is not CNAME/DNAME")),
        }
    }
}

impl DnsResourceRecord {
    pub fn new(key: DnsResourceKey, rdata: Rdata) -> Self {
        Self {
            key,
            ttl: 0,
            expiry: None,
            signer_skip_labels: None,
            source_skip_labels: None,
            unparsable: false,
            wire_format_canonical: false,
            wire_format: None,
            wire_format_rdata_offset: 0,
            rdata,
        }
    }

    pub fn new_full(
        dns_class: u16,
        rr_type: u16,
        name: impl AsRef<str>,
        rdata: Rdata,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(
            DnsResourceKey::new(dns_class, rr_type, name)?,
            rdata,
        ))
    }

    pub fn new_reverse(
        family: i32,
        address: &[u8],
        hostname: impl AsRef<str>,
    ) -> Result<Self, ParseError> {
        let reverse = match family {
            AF_INET => {
                if address.len() != 4 {
                    return Err(ParseError::InvalidRdata("invalid IPv4 address size"));
                }
                let octets = [address[0], address[1], address[2], address[3]];
                format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[3], octets[2], octets[1], octets[0]
                )
            }
            AF_INET6 => {
                if address.len() != 16 {
                    return Err(ParseError::InvalidRdata("invalid IPv6 address size"));
                }
                let mut out = String::new();
                for byte in address.iter().rev() {
                    let lo = byte & 0x0f;
                    let hi = byte >> 4;
                    write!(&mut out, "{:x}.{:x}.", lo, hi).map_err(|_| ParseError::Overflow)?;
                }
                out.push_str("ip6.arpa");
                out
            }
            _ => return Err(ParseError::InvalidAddressFamily(family)),
        };

        Self::new_full(
            DnsClass::In as u16,
            DnsType::Ptr as u16,
            reverse,
            Rdata::Ptr {
                name: normalize_name(hostname.as_ref())?,
            },
        )
    }

    pub fn new_address(
        family: i32,
        address: &[u8],
        name: impl AsRef<str>,
    ) -> Result<Self, ParseError> {
        match family {
            AF_INET => {
                let octets: [u8; 4] = address
                    .try_into()
                    .map_err(|_| ParseError::InvalidRdata("invalid IPv4 address size"))?;
                Self::new_full(
                    DnsClass::In as u16,
                    DnsType::A as u16,
                    name,
                    Rdata::A {
                        address: Ipv4Addr::from(octets),
                    },
                )
            }
            AF_INET6 => {
                let octets: [u8; 16] = address
                    .try_into()
                    .map_err(|_| ParseError::InvalidRdata("invalid IPv6 address size"))?;
                Self::new_full(
                    DnsClass::In as u16,
                    DnsType::Aaaa as u16,
                    name,
                    Rdata::Aaaa {
                        address: Ipv6Addr::from(octets),
                    },
                )
            }
            _ => Err(ParseError::InvalidAddressFamily(family)),
        }
    }

    pub fn payload_equal(&self, other: &Self) -> bool {
        self.rdata_equal(&other.rdata)
    }

    pub fn equal(&self, other: &Self) -> bool {
        self.key == other.key && self.payload_equal(other)
    }

    pub fn signer(&self) -> Result<Option<&str>, ParseError> {
        Ok(self
            .signer_skip_labels
            .map(|n| skip_labels(&self.key.name, n))
            .transpose()?)
    }

    pub fn source(&self) -> Result<Option<&str>, ParseError> {
        Ok(self
            .source_skip_labels
            .map(|n| skip_labels(&self.key.name, n))
            .transpose()?)
    }

    pub fn is_signer(&self, zone: &str) -> Result<Option<bool>, ParseError> {
        Ok(self.signer()?.map(|signer| eq_name(signer, zone)))
    }

    pub fn is_synthetic(&self) -> Result<Option<bool>, ParseError> {
        let Some(skip) = self.source_skip_labels else {
            return Ok(None);
        };
        if skip == 0 {
            return Ok(Some(false));
        }
        if skip > 1 {
            return Ok(Some(true));
        }
        Ok(Some(!dns_name_startswith(&self.key.name, "*")))
    }

    pub fn clamp_ttl(&mut self, max_ttl: u32) -> Result<bool, ParseError> {
        if self.key.rr_type == DnsType::Opt as u16 {
            return Err(ParseError::Mismatch("OPT TTL cannot be clamped"));
        }
        let new_ttl = self.ttl.min(max_ttl);
        if new_ttl == self.ttl {
            return Ok(false);
        }
        self.ttl = new_ttl;
        Ok(true)
    }

    pub fn is_link_local_address(&self) -> bool {
        if self.key.dns_class != DnsClass::In as u16 {
            return false;
        }
        match &self.rdata {
            Rdata::A { address } => address.octets()[0] == 169 && address.octets()[1] == 254,
            Rdata::Aaaa { address } => address.segments()[0] & 0xffc0 == 0xfe80,
            _ => false,
        }
    }

    pub fn get_cname_target(
        key: &DnsResourceKey,
        cname: &DnsResourceRecord,
    ) -> Result<String, ParseError> {
        if key.dns_class != cname.key.dns_class && key.dns_class != DnsClass::Any as u16 {
            return Err(ParseError::Mismatch("class mismatch"));
        }
        if !dns_type_may_redirect(key.rr_type) {
            return Err(ParseError::Mismatch("type may not redirect"));
        }
        match cname.key.rr_type {
            x if x == DnsType::Cname as u16 => {
                if !eq_name(&key.name, &cname.key.name) {
                    return Err(ParseError::Mismatch("CNAME key mismatch"));
                }
                Ok(cname
                    .target_name()
                    .ok_or(ParseError::Mismatch("missing CNAME target"))?
                    .to_owned())
            }
            x if x == DnsType::Dname as u16 => dns_name_change_suffix(
                &key.name,
                &cname.key.name,
                cname
                    .target_name()
                    .ok_or(ParseError::Mismatch("missing DNAME target"))?,
            )?
            .ok_or(ParseError::Mismatch("DNAME key mismatch")),
            _ => Err(ParseError::Mismatch("record is not CNAME/DNAME")),
        }
    }

    pub fn payload(&self) -> Option<Vec<u8>> {
        match &self.rdata {
            Rdata::A { address } => Some(address.octets().to_vec()),
            Rdata::Aaaa { address } => Some(address.octets().to_vec()),
            Rdata::Sshfp { fingerprint, .. } => Some(fingerprint.clone()),
            Rdata::Tlsa { data, .. } => Some(data.clone()),
            Rdata::Generic(data) | Rdata::Opt(data) => Some(data.clone()),
            _ => None,
        }
    }

    pub fn copy(&self) -> Self {
        self.clone()
    }

    pub fn compare_func(&self, other: &Self) -> Ordering {
        self.key
            .compare_func(&other.key)
            .then_with(|| self.to_hash_bytes().cmp(&other.to_hash_bytes()))
    }

    pub fn hash_func<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
        self.to_hash_bytes().hash(state);
    }

    pub fn target_name(&self) -> Option<&str> {
        match &self.rdata {
            Rdata::Ptr { name }
            | Rdata::Ns { name }
            | Rdata::Cname { name }
            | Rdata::Dname { name } => Some(name),
            _ => None,
        }
    }

    fn rdata_equal(&self, other: &Rdata) -> bool {
        match (&self.rdata, other) {
            (Rdata::Generic(a), Rdata::Generic(b)) | (Rdata::Opt(a), Rdata::Opt(b)) => a == b,
            (
                Rdata::Srv {
                    priority: ap,
                    weight: aw,
                    port: apo,
                    name: an,
                },
                Rdata::Srv {
                    priority: bp,
                    weight: bw,
                    port: bpo,
                    name: bn,
                },
            ) => ap == bp && aw == bw && apo == bpo && eq_name(an, bn),
            (Rdata::Ptr { name: a }, Rdata::Ptr { name: b })
            | (Rdata::Ns { name: a }, Rdata::Ns { name: b })
            | (Rdata::Cname { name: a }, Rdata::Cname { name: b })
            | (Rdata::Dname { name: a }, Rdata::Dname { name: b }) => eq_name(a, b),
            (Rdata::Hinfo { cpu: ac, os: ao }, Rdata::Hinfo { cpu: bc, os: bo }) => {
                ac.eq_ignore_ascii_case(bc) && ao.eq_ignore_ascii_case(bo)
            }
            (Rdata::Txt { items: a }, Rdata::Txt { items: b })
            | (Rdata::Spf { items: a }, Rdata::Spf { items: b }) => a == b,
            (Rdata::A { address: a }, Rdata::A { address: b }) => a == b,
            (Rdata::Aaaa { address: a }, Rdata::Aaaa { address: b }) => a == b,
            (
                Rdata::Soa {
                    mname: am,
                    rname: ar,
                    serial: aser,
                    refresh: aref,
                    retry: aret,
                    expire: aexp,
                    minimum: amin,
                },
                Rdata::Soa {
                    mname: bm,
                    rname: br,
                    serial: bser,
                    refresh: bref,
                    retry: bret,
                    expire: bexp,
                    minimum: bmin,
                },
            ) => {
                eq_name(am, bm)
                    && eq_name(ar, br)
                    && aser == bser
                    && aref == bref
                    && aret == bret
                    && aexp == bexp
                    && amin == bmin
            }
            (
                Rdata::Mx {
                    priority: ap,
                    exchange: ae,
                },
                Rdata::Mx {
                    priority: bp,
                    exchange: be,
                },
            ) => ap == bp && eq_name(ae, be),
            (
                Rdata::Loc {
                    version: av,
                    size: asz,
                    horiz_pre: ah,
                    vert_pre: avp,
                    latitude: alat,
                    longitude: alon,
                    altitude: aalt,
                },
                Rdata::Loc {
                    version: bv,
                    size: bsz,
                    horiz_pre: bh,
                    vert_pre: bvp,
                    latitude: blat,
                    longitude: blon,
                    altitude: balt,
                },
            ) => {
                av == bv
                    && asz == bsz
                    && ah == bh
                    && avp == bvp
                    && alat == blat
                    && alon == blon
                    && aalt == balt
            }
            (
                Rdata::Sshfp {
                    fingerprint: af,
                    algorithm: aa,
                    fptype: at,
                },
                Rdata::Sshfp {
                    fingerprint: bf,
                    algorithm: ba,
                    fptype: bt,
                },
            ) => af == bf && aa == ba && at == bt,
            (
                Rdata::Dnskey {
                    key: ak,
                    flags: af,
                    protocol: ap,
                    algorithm: aa,
                },
                Rdata::Dnskey {
                    key: bk,
                    flags: bf,
                    protocol: bp,
                    algorithm: ba,
                },
            ) => ak == bk && af == bf && ap == bp && aa == ba,
            (
                Rdata::Rrsig {
                    signer: asg,
                    signature: asi,
                    type_covered: at,
                    algorithm: aa,
                    labels: al,
                    original_ttl: ao,
                    expiration: ae,
                    inception: ai,
                    key_tag: ak,
                },
                Rdata::Rrsig {
                    signer: bsg,
                    signature: bsi,
                    type_covered: bt,
                    algorithm: ba,
                    labels: bl,
                    original_ttl: bo,
                    expiration: be,
                    inception: bi,
                    key_tag: bk,
                },
            ) => {
                eq_name(asg, bsg)
                    && asi == bsi
                    && at == bt
                    && aa == ba
                    && al == bl
                    && ao == bo
                    && ae == be
                    && ai == bi
                    && ak == bk
            }
            (
                Rdata::Nsec {
                    next_domain_name: an,
                    types: at,
                },
                Rdata::Nsec {
                    next_domain_name: bn,
                    types: bt,
                },
            ) => eq_name(an, bn) && at == bt,
            (
                Rdata::Ds {
                    digest: ad,
                    key_tag: ak,
                    algorithm: aa,
                    digest_type: at,
                },
                Rdata::Ds {
                    digest: bd,
                    key_tag: bk,
                    algorithm: ba,
                    digest_type: bt,
                },
            ) => ad == bd && ak == bk && aa == ba && at == bt,
            (
                Rdata::Nsec3 {
                    types: at,
                    salt: asalt,
                    next_hashed_name: an,
                    algorithm: aa,
                    flags: af,
                    iterations: ai,
                },
                Rdata::Nsec3 {
                    types: bt,
                    salt: bsalt,
                    next_hashed_name: bn,
                    algorithm: ba,
                    flags: bf,
                    iterations: bi,
                },
            ) => at == bt && asalt == bsalt && an == bn && aa == ba && af == bf && ai == bi,
            (
                Rdata::Tlsa {
                    data: ad,
                    cert_usage: au,
                    selector: asel,
                    matching_type: am,
                },
                Rdata::Tlsa {
                    data: bd,
                    cert_usage: bu,
                    selector: bsel,
                    matching_type: bm,
                },
            ) => ad == bd && au == bu && asel == bsel && am == bm,
            (
                Rdata::Svcb {
                    priority: ap,
                    target_name: at,
                    params: apar,
                },
                Rdata::Svcb {
                    priority: bp,
                    target_name: bt,
                    params: bpar,
                },
            )
            | (
                Rdata::Https {
                    priority: ap,
                    target_name: at,
                    params: apar,
                },
                Rdata::Https {
                    priority: bp,
                    target_name: bt,
                    params: bpar,
                },
            ) => ap == bp && eq_name(at, bt) && apar == bpar,
            (
                Rdata::Caa {
                    tag: at,
                    value: av,
                    flags: af,
                },
                Rdata::Caa {
                    tag: bt,
                    value: bv,
                    flags: bf,
                },
            ) => at == bt && av == bv && af == bf,
            (
                Rdata::Naptr {
                    order: ao,
                    preference: ap,
                    flags: af,
                    services: asv,
                    regexp: ar,
                    replacement: arep,
                },
                Rdata::Naptr {
                    order: bo,
                    preference: bp,
                    flags: bf,
                    services: bsv,
                    regexp: br,
                    replacement: brep,
                },
            ) => ao == bo && ap == bp && af == bf && asv == bsv && ar == br && eq_name(arep, brep),
            _ => false,
        }
    }

    fn to_hash_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let _ = self
            .clone()
            .to_wire(true)
            .map(|wire| out.extend_from_slice(wire));
        out
    }
}

pub fn dnssec_keytag(dnskey: &DnsResourceRecord, mask_revoke: bool) -> Result<u16, ParseError> {
    let Rdata::Dnskey {
        key,
        flags,
        protocol,
        algorithm,
    } = &dnskey.rdata
    else {
        return Err(ParseError::Mismatch("record is not DNSKEY"));
    };
    let mut f = u32::from(*flags);
    if mask_revoke {
        f &= !u32::from(DNSKEY_FLAG_REVOKE);
    }
    let mut sum = f + ((u32::from(*protocol) << 8) + u32::from(*algorithm));
    for (i, b) in key.iter().enumerate() {
        sum += if i % 2 == 0 {
            u32::from(*b) << 8
        } else {
            u32::from(*b)
        };
    }
    sum += (sum >> 16) & 0xffff;
    Ok((sum & 0xffff) as u16)
}

pub fn dns_resource_key_hash_func<H: Hasher>(key: &DnsResourceKey, state: &mut H) {
    key.hash(state);
}

pub fn dns_resource_record_hash_func<H: Hasher>(rr: &DnsResourceRecord, state: &mut H) {
    rr.hash_func(state);
}

pub fn dns_resource_key_compare_func(x: &DnsResourceKey, y: &DnsResourceKey) -> Ordering {
    x.compare_func(y)
}

pub fn dns_resource_record_compare_func(x: &DnsResourceRecord, y: &DnsResourceRecord) -> Ordering {
    x.compare_func(y)
}

pub fn dns_resource_record_payload(rr: &DnsResourceRecord) -> Option<Vec<u8>> {
    rr.payload()
}

pub fn dns_txt_item_equal(a: &[DnsTxtItem], b: &[DnsTxtItem]) -> bool {
    a == b
}

pub fn dns_txt_item_copy(first: &[DnsTxtItem]) -> Vec<DnsTxtItem> {
    first.to_vec()
}

pub fn dns_txt_item_new_empty() -> DnsTxtItem {
    DnsTxtItem::new_empty()
}

pub fn dns_svc_params_equal(a: &[DnsSvcParam], b: &[DnsSvcParam]) -> bool {
    a == b
}

pub fn dns_svc_params_copy(first: &[DnsSvcParam]) -> Vec<DnsSvcParam> {
    first.to_vec()
}
