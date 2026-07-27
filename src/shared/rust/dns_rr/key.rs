// SPDX-License-Identifier: LGPL-2.1-or-later
//
// DNS resource-key construction, matching, and name canonicalization.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use super::model::{DnsClass, DnsType, ParseError};

fn dns_class_to_string(value: u16) -> Option<&'static str> {
    match value {
        x if x == DnsClass::In as u16 => Some("IN"),
        x if x == DnsClass::Any as u16 => Some("ANY"),
        _ => None,
    }
}

fn dns_type_to_string(value: u16) -> Option<&'static str> {
    match value {
        x if x == DnsType::A as u16 => Some("A"),
        x if x == DnsType::Ns as u16 => Some("NS"),
        x if x == DnsType::Cname as u16 => Some("CNAME"),
        x if x == DnsType::Soa as u16 => Some("SOA"),
        x if x == DnsType::Ptr as u16 => Some("PTR"),
        x if x == DnsType::Hinfo as u16 => Some("HINFO"),
        x if x == DnsType::Mx as u16 => Some("MX"),
        x if x == DnsType::Txt as u16 => Some("TXT"),
        x if x == DnsType::Aaaa as u16 => Some("AAAA"),
        x if x == DnsType::Loc as u16 => Some("LOC"),
        x if x == DnsType::Srv as u16 => Some("SRV"),
        x if x == DnsType::Naptr as u16 => Some("NAPTR"),
        x if x == DnsType::Opt as u16 => Some("OPT"),
        x if x == DnsType::Ds as u16 => Some("DS"),
        x if x == DnsType::Sshfp as u16 => Some("SSHFP"),
        x if x == DnsType::Rrsig as u16 => Some("RRSIG"),
        x if x == DnsType::Nsec as u16 => Some("NSEC"),
        x if x == DnsType::Dnskey as u16 => Some("DNSKEY"),
        x if x == DnsType::Nsec3 as u16 => Some("NSEC3"),
        x if x == DnsType::Tlsa as u16 => Some("TLSA"),
        x if x == DnsType::Openpgpkey as u16 => Some("OPENPGPKEY"),
        x if x == DnsType::Svcb as u16 => Some("SVCB"),
        x if x == DnsType::Https as u16 => Some("HTTPS"),
        x if x == DnsType::Spf as u16 => Some("SPF"),
        x if x == DnsType::Caa as u16 => Some("CAA"),
        x if x == DnsType::Dname as u16 => Some("DNAME"),
        x if x == DnsType::Any as u16 => Some("ANY"),
        _ => None,
    }
}

pub(super) fn dns_type_may_redirect(value: u16) -> bool {
    !matches!(
        value,
        x if x == DnsType::Cname as u16
            || x == DnsType::Dname as u16
            || x == DnsType::Nsec3 as u16
            || x == DnsType::Nsec as u16
            || x == DnsType::Rrsig as u16
            || x == DnsType::Opt as u16
            || x == DnsType::Any as u16
    )
}

pub(super) fn dns_name_is_root(name: &str) -> bool {
    name.is_empty() || name == "."
}

pub(super) fn dns_name_parent(name: &str) -> Option<&str> {
    let name = name.trim_end_matches('.');
    name.find('.').map(|idx| &name[idx + 1..])
}

pub(super) fn dns_name_endswith(name: &str, suffix: &str) -> bool {
    let name = lower_name(name);
    let suffix = lower_name(suffix);
    name == suffix || name.ends_with(&format!(".{suffix}"))
}

pub(super) fn dns_name_startswith(name: &str, prefix: &str) -> bool {
    lower_name(name).starts_with(&lower_name(prefix))
}

pub(super) fn dns_name_count_labels(name: &str) -> usize {
    if dns_name_is_root(name) {
        0
    } else {
        name.trim_end_matches('.').split('.').count()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DnsResourceKey {
    pub dns_class: u16,
    pub rr_type: u16,
    pub name: String,
}

impl DnsResourceKey {
    pub fn new(dns_class: u16, rr_type: u16, name: impl AsRef<str>) -> Result<Self, ParseError> {
        Ok(Self {
            dns_class,
            rr_type,
            name: normalize_name(name.as_ref())?,
        })
    }

    pub fn new_consume(dns_class: u16, rr_type: u16, name: String) -> Result<Self, ParseError> {
        Self::new(dns_class, rr_type, name)
    }

    pub fn new_append_suffix(key: &Self, suffix: impl AsRef<str>) -> Result<Self, ParseError> {
        let suffix = normalize_name(suffix.as_ref())?;
        if dns_name_is_root(&suffix) {
            return Ok(key.clone());
        }
        let joined = dns_name_concat(&key.name, &suffix)?;
        Self::new(key.dns_class, key.rr_type, joined)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_address(&self) -> bool {
        self.dns_class == DnsClass::In as u16
            && matches!(self.rr_type, x if x == DnsType::A as u16 || x == DnsType::Aaaa as u16)
    }

    pub fn is_dnssd_ptr(&self) -> bool {
        self.rr_type == DnsType::Ptr as u16
            && (dns_name_endswith(&self.name, "_tcp.local")
                || dns_name_endswith(&self.name, "_udp.local"))
    }

    pub fn is_dnssd_two_label_ptr(&self) -> bool {
        if self.rr_type != DnsType::Ptr as u16 {
            return false;
        }
        let Some(parent) = dns_name_parent(&self.name) else {
            return false;
        };
        eq_name(parent, "_tcp.local") || eq_name(parent, "_udp.local")
    }

    pub fn equal(&self, other: &Self) -> bool {
        self == other
    }

    pub fn match_rr(
        &self,
        rr: &DnsResourceRecord,
        search_domain: Option<&str>,
    ) -> Result<bool, ParseError> {
        if (rr.key.dns_class != self.dns_class && self.dns_class != DnsClass::Any as u16)
            || (rr.key.rr_type != self.rr_type && self.rr_type != DnsType::Any as u16)
        {
            return Ok(false);
        }
        if eq_name(&rr.key.name, &self.name) {
            return Ok(true);
        }
        match search_domain {
            Some(domain) => Ok(eq_name(&rr.key.name, &dns_name_concat(&self.name, domain)?)),
            None => Ok(false),
        }
    }

    pub fn match_cname_or_dname(
        &self,
        cname: &Self,
        search_domain: Option<&str>,
    ) -> Result<bool, ParseError> {
        if cname.dns_class != self.dns_class && self.dns_class != DnsClass::Any as u16 {
            return Ok(false);
        }
        if !dns_type_may_redirect(self.rr_type) {
            return Ok(false);
        }
        let direct = match cname.rr_type {
            x if x == DnsType::Cname as u16 => eq_name(&self.name, &cname.name),
            x if x == DnsType::Dname as u16 => dns_name_endswith(&self.name, &cname.name),
            _ => false,
        };
        if direct {
            return Ok(true);
        }
        let Some(search_domain) = search_domain else {
            return Ok(false);
        };
        let joined = dns_name_concat(&self.name, search_domain)?;
        Ok(match cname.rr_type {
            x if x == DnsType::Cname as u16 => eq_name(&joined, &cname.name),
            x if x == DnsType::Dname as u16 => dns_name_endswith(&joined, &cname.name),
            _ => false,
        })
    }

    pub fn match_soa(&self, soa: &Self) -> bool {
        soa.dns_class == self.dns_class
            && soa.rr_type == DnsType::Soa as u16
            && dns_name_endswith(&self.name, &soa.name)
    }

    pub fn to_rr_string(&self) -> String {
        let class = dns_class_to_string(self.dns_class)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("CLASS{}", self.dns_class));
        let rr_type = dns_type_to_string(self.rr_type)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("TYPE{}", self.rr_type));
        format!("{} {} {}", self.name(), class, rr_type)
    }

    pub fn reduce(a: &mut Self, b: &mut Self) -> bool {
        if a == b {
            *b = a.clone();
            true
        } else {
            false
        }
    }

    pub fn compare_func(&self, other: &Self) -> Ordering {
        cmp_name(&self.name, &other.name)
            .then_with(|| self.rr_type.cmp(&other.rr_type))
            .then_with(|| self.dns_class.cmp(&other.dns_class))
    }
}

impl PartialEq for DnsResourceKey {
    fn eq(&self, other: &Self) -> bool {
        self.dns_class == other.dns_class
            && self.rr_type == other.rr_type
            && eq_name(&self.name, &other.name)
    }
}

impl Hash for DnsResourceKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        lower_name(&self.name).hash(state);
        self.dns_class.hash(state);
        self.rr_type.hash(state);
    }
}

impl fmt::Display for DnsResourceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rr_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) fn normalize_name(name: &str) -> Result<String, ParseError> {
    if dns_name_is_root(name) {
        return Ok(".".to_owned());
    }
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return Ok(".".to_owned());
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ParseError::InvalidLabel);
        }
    }
    Ok(trimmed.to_owned())
}

pub(super) fn lower_name(name: &str) -> String {
    if dns_name_is_root(name) {
        ".".into()
    } else {
        name.to_ascii_lowercase()
    }
}

pub(super) fn eq_name(a: &str, b: &str) -> bool {
    lower_name(a) == lower_name(b)
}

pub(super) fn cmp_name(a: &str, b: &str) -> Ordering {
    lower_name(a).cmp(&lower_name(b))
}

pub(super) fn dns_name_concat(a: &str, b: &str) -> Result<String, ParseError> {
    let a = normalize_name(a)?;
    let b = normalize_name(b)?;
    if dns_name_is_root(&a) {
        return Ok(b);
    }
    if dns_name_is_root(&b) {
        return Ok(a);
    }
    Ok(format!("{a}.{b}"))
}

pub(super) fn dns_name_change_suffix(
    name: &str,
    old_suffix: &str,
    new_suffix: &str,
) -> Result<Option<String>, ParseError> {
    let name = normalize_name(name)?;
    let old_suffix = normalize_name(old_suffix)?;
    let new_suffix = normalize_name(new_suffix)?;
    if !dns_name_endswith(&name, &old_suffix) {
        return Ok(None);
    }
    let prefix = if eq_name(&name, &old_suffix) {
        String::new()
    } else {
        let lowered_name = lower_name(&name);
        let lowered_suffix = lower_name(&old_suffix);
        let idx = lowered_name.len() - lowered_suffix.len() - 1;
        name[..idx].to_owned()
    };
    let destination = if prefix.is_empty() {
        new_suffix
    } else if dns_name_is_root(&new_suffix) {
        prefix
    } else {
        format!("{prefix}.{new_suffix}")
    };
    Ok(Some(destination))
}

pub(super) fn skip_labels(name: &str, n: u8) -> Result<&str, ParseError> {
    let mut current = name;
    for _ in 0..n {
        current = dns_name_parent(current).ok_or(ParseError::InvalidName)?;
    }
    Ok(current)
}
