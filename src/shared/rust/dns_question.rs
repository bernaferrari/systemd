// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/dns-question.c, src/shared/dns-question.h

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::dns_type::{DnsClass, DnsType, dns_type_is_valid_query, dns_type_may_redirect};
use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/shared/dns-question.c";
pub const SOURCE_TEXT: &str = include_str!("../dns-question.c");

pub const AF_UNSPEC: i32 = libc::AF_UNSPEC;
pub const AF_INET: i32 = libc::AF_INET;
pub const AF_INET6: i32 = libc::AF_INET6;
pub const DNS_CLASS_IN: u16 = DnsClass::In as u16;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct DnsQuestionFlags: u32 {
        const WANTS_UNICAST_REPLY = 1 << 0;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsResourceKey {
    pub class: u16,
    pub rr_type: u16,
    pub name: String,
}

impl DnsResourceKey {
    pub fn new(class: u16, rr_type: u16, name: impl Into<String>) -> Self {
        Self {
            class,
            rr_type,
            name: canonical_name(&name.into()),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn equal(&self, other: &Self) -> i32 {
        dns_name_equal(self.name(), other.name()) as i32
            * i32::from(self.class == other.class && self.rr_type == other.rr_type)
    }

    pub fn match_rr(&self, rr: &DnsResourceRecord, search_domain: Option<&str>) -> i32 {
        if self.class != rr.key.class && self.class != DnsClass::Any as u16 {
            return 0;
        }
        if self.rr_type != rr.key.rr_type && self.rr_type != DnsType::Any as u16 {
            return 0;
        }
        if dns_name_equal(self.name(), rr.key.name()) {
            return 1;
        }

        search_domain
            .map(|domain| dns_name_concat(self.name(), domain))
            .filter(|joined| dns_name_equal(joined, rr.key.name()))
            .map(|_| 1)
            .unwrap_or(0)
    }

    pub fn match_cname_or_dname(&self, cname: &DnsResourceKey, search_domain: Option<&str>) -> i32 {
        if cname.class != self.class && self.class != DnsClass::Any as u16 {
            return 0;
        }
        if !dns_type_may_redirect(self.rr_type) {
            return 0;
        }

        let direct = match cname.rr_type {
            x if x == DnsType::Cname as u16 => dns_name_equal(self.name(), cname.name()),
            x if x == DnsType::Dname as u16 => dns_name_endswith(self.name(), cname.name()),
            _ => false,
        };
        if direct {
            return 1;
        }

        let Some(search_domain) = search_domain else {
            return 0;
        };
        let joined = dns_name_concat(self.name(), search_domain);
        match cname.rr_type {
            x if x == DnsType::Cname as u16 => dns_name_equal(&joined, cname.name()) as i32,
            x if x == DnsType::Dname as u16 => dns_name_endswith(&joined, cname.name()) as i32,
            _ => 0,
        }
    }

    pub fn new_redirect(&self, cname: &DnsResourceRecord) -> Option<Self> {
        match &cname.data {
            DnsRecordData::Cname { name } => Some(Self::new(self.class, self.rr_type, name)),
            DnsRecordData::Dname { name } => {
                match dns_name_change_suffix(self.name(), cname.key.name(), name) {
                    Some(destination) => Some(Self::new(self.class, self.rr_type, destination)),
                    None => Some(self.clone()),
                }
            }
            _ => None,
        }
    }
}

impl fmt::Display for DnsResourceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            dns_class_name(self.class),
            dns_type_name(self.rr_type),
            self.name()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsQuestionItem {
    pub key: DnsResourceKey,
    pub flags: DnsQuestionFlags,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRecordData {
    Empty,
    Cname { name: String },
    Dname { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResourceRecord {
    pub key: DnsResourceKey,
    pub data: DnsRecordData,
}

impl DnsResourceRecord {
    pub fn new(key: DnsResourceKey) -> Self {
        Self {
            key,
            data: DnsRecordData::Empty,
        }
    }

    pub fn cname(owner: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            key: DnsResourceKey::new(DNS_CLASS_IN, DnsType::Cname as u16, owner),
            data: DnsRecordData::Cname {
                name: canonical_name(&target.into()),
            },
        }
    }

    pub fn dname(owner: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            key: DnsResourceKey::new(DNS_CLASS_IN, DnsType::Dname as u16, owner),
            data: DnsRecordData::Dname {
                name: canonical_name(&target.into()),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    allocated: usize,
    items: Vec<DnsQuestionItem>,
}

impl DnsQuestion {
    pub fn new(n: usize) -> Self {
        let allocated = n.min(u16::MAX as usize);
        Self {
            allocated,
            items: Vec::with_capacity(allocated),
        }
    }

    pub fn size(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn first_key(&self) -> Option<&DnsResourceKey> {
        self.items.first().map(|item| &item.key)
    }

    pub fn first_name(&self) -> Option<&str> {
        self.first_key().map(DnsResourceKey::name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &DnsQuestionItem> {
        self.items.iter()
    }

    pub fn add_raw(&mut self, key: DnsResourceKey, flags: DnsQuestionFlags) -> Result<(), i32> {
        if self.items.len() >= self.allocated {
            return Err(Errno::ENOSPC.to_neg_errno());
        }

        self.items.push(DnsQuestionItem { key, flags });
        Ok(())
    }

    pub fn add(&mut self, key: DnsResourceKey, flags: DnsQuestionFlags) -> Result<(), i32> {
        if self
            .items
            .iter()
            .any(|item| item.flags == flags && item.key.equal(&key) > 0)
        {
            return Ok(());
        }

        self.add_raw(key, flags)
    }

    pub fn add_raw_all(&mut self, other: &Self) -> Result<(), i32> {
        for item in &other.items {
            self.add_raw(item.key.clone(), item.flags)?;
        }
        Ok(())
    }

    pub fn add_all(&mut self, other: &Self) -> Result<(), i32> {
        for item in &other.items {
            self.add(item.key.clone(), item.flags)?;
        }
        Ok(())
    }

    pub fn matches_rr(&self, rr: &DnsResourceRecord, search_domain: Option<&str>) -> i32 {
        self.items
            .iter()
            .map(|item| item.key.match_rr(rr, search_domain))
            .find(|r| *r != 0)
            .unwrap_or(0)
    }

    pub fn matches_cname_or_dname(
        &self,
        rr: &DnsResourceRecord,
        search_domain: Option<&str>,
    ) -> i32 {
        if rr.key.rr_type != DnsType::Cname as u16 && rr.key.rr_type != DnsType::Dname as u16 {
            return 0;
        }

        for item in &self.items {
            if !dns_type_may_redirect(item.key.rr_type) {
                return 0;
            }

            let r = item.key.match_cname_or_dname(&rr.key, search_domain);
            if r != 0 {
                return r;
            }
        }

        0
    }

    pub fn is_valid_for_query(&self) -> bool {
        if self.items.is_empty() || self.items.len() > u16::MAX as usize {
            return false;
        }

        let Some(name) = self.first_name() else {
            return false;
        };

        self.items.iter().all(|item| {
            dns_name_equal(item.key.name(), name) && dns_type_is_valid_query(item.key.rr_type)
        })
    }

    pub fn contains_key(&self, key: &DnsResourceKey) -> i32 {
        self.items
            .iter()
            .map(|item| item.key.equal(key))
            .find(|r| *r != 0)
            .unwrap_or(0)
    }

    pub fn contains_item(&self, needle: &DnsQuestionItem) -> bool {
        self.items
            .iter()
            .any(|item| item.flags == needle.flags && item.key.equal(&needle.key) > 0)
    }

    pub fn is_equal(&self, other: &Self) -> i32 {
        if std::ptr::eq(self, other) {
            return 1;
        }

        if self.items.iter().any(|item| !other.contains_item(item)) {
            return 0;
        }
        if other.items.iter().any(|item| !self.contains_item(item)) {
            return 0;
        }

        1
    }

    pub fn cname_redirect(&self, cname: &DnsResourceRecord) -> Result<Option<Self>, i32> {
        if self.is_empty() {
            return Ok(None);
        }

        if cname.key.rr_type != DnsType::Cname as u16 && cname.key.rr_type != DnsType::Dname as u16
        {
            return Err(Errno::EINVAL.to_neg_errno());
        }

        let same = self.items.iter().all(|item| {
            let destination = match &cname.data {
                DnsRecordData::Cname { name } => name.as_str(),
                DnsRecordData::Dname { name } => {
                    return dns_name_change_suffix(item.key.name(), cname.key.name(), name)
                        .map(|n| dns_name_equal(item.key.name(), &n))
                        .unwrap_or(true);
                }
                DnsRecordData::Empty => return true,
            };

            dns_name_equal(item.key.name(), destination)
        });
        if same {
            return Ok(None);
        }

        let mut redirected = Self::new(self.size());
        for item in &self.items {
            let key = item
                .key
                .new_redirect(cname)
                .ok_or_else(|| Errno::EINVAL.to_neg_errno())?;
            redirected.add(key, DnsQuestionFlags::empty())?;
        }

        Ok(Some(redirected))
    }

    pub fn new_address(family: i32, name: &str, convert_idna: bool) -> Result<Self, i32> {
        if !matches!(family, AF_INET | AF_INET6 | AF_UNSPEC) {
            return Err(Errno::EAFNOSUPPORT.to_neg_errno());
        }

        let effective_name = if convert_idna {
            match dns_name_apply_idna(name) {
                Some(converted) if !dns_name_equal(name, &converted) => converted,
                _ => return Err(Errno::EALREADY.to_neg_errno()),
            }
        } else {
            canonical_name(name)
        };

        let mut question = Self::new(if family == AF_UNSPEC { 2 } else { 1 });
        if family != AF_INET6 {
            question.add(
                DnsResourceKey::new(DNS_CLASS_IN, DnsType::A as u16, effective_name.clone()),
                DnsQuestionFlags::empty(),
            )?;
        }
        if family != AF_INET {
            question.add(
                DnsResourceKey::new(DNS_CLASS_IN, DnsType::Aaaa as u16, effective_name),
                DnsQuestionFlags::empty(),
            )?;
        }

        Ok(question)
    }

    pub fn new_reverse(address: IpAddr) -> Result<Self, i32> {
        let reverse = dns_name_reverse(address);
        let mut question = Self::new(1);
        question.add(
            DnsResourceKey::new(DNS_CLASS_IN, DnsType::Ptr as u16, reverse),
            DnsQuestionFlags::empty(),
        )?;
        Ok(question)
    }

    pub fn new_service_pointer(
        service_type: Option<&str>,
        domain: &str,
        convert_idna: bool,
    ) -> Result<Self, i32> {
        if domain.is_empty() {
            return Err(Errno::EINVAL.to_neg_errno());
        }

        let normalized_domain = if convert_idna {
            dns_name_apply_idna(domain).unwrap_or_else(|| canonical_name(domain))
        } else {
            canonical_name(domain)
        };

        let name = match service_type {
            Some(service_type) => dns_service_join(None, service_type, &normalized_domain)?,
            None => normalized_domain,
        };

        let mut question = Self::new(1);
        question.add(
            DnsResourceKey::new(DNS_CLASS_IN, DnsType::Ptr as u16, name),
            DnsQuestionFlags::empty(),
        )?;
        Ok(question)
    }

    pub fn new_service(
        service: Option<&str>,
        service_type: Option<&str>,
        domain: &str,
        with_txt: bool,
        convert_idna: bool,
    ) -> Result<Self, i32> {
        if domain.is_empty() {
            return Err(Errno::EINVAL.to_neg_errno());
        }

        let name = match service_type {
            Some(service_type) => {
                let domain = if convert_idna {
                    dns_name_apply_idna(domain).unwrap_or_else(|| canonical_name(domain))
                } else {
                    canonical_name(domain)
                };
                dns_service_join(service, service_type, &domain)?
            }
            None => {
                if service.is_some() {
                    return Err(Errno::EINVAL.to_neg_errno());
                }
                canonical_name(domain)
            }
        };

        let mut question = Self::new(1 + usize::from(with_txt));
        question.add(
            DnsResourceKey::new(DNS_CLASS_IN, DnsType::Srv as u16, name.clone()),
            DnsQuestionFlags::empty(),
        )?;
        if with_txt {
            question.add(
                DnsResourceKey::new(DNS_CLASS_IN, DnsType::Txt as u16, name),
                DnsQuestionFlags::empty(),
            )?;
        }
        Ok(question)
    }

    pub fn dump(&self) -> String {
        let mut out = String::new();
        for item in &self.items {
            out.push('\t');
            out.push_str(&item.key.to_string());
            out.push('\n');
        }
        out
    }

    pub fn merge(a: &Self, b: &Self) -> Result<Self, i32> {
        if std::ptr::eq(a, b) || b.is_empty() {
            return Ok(a.clone());
        }
        if a.is_empty() {
            return Ok(b.clone());
        }

        let mut merged = Self::new(a.size() + b.size());
        merged.add_raw_all(a)?;
        merged.add_all(b)?;
        Ok(merged)
    }

    pub fn from_json_entries(entries: &[DnsQuestionJsonEntry]) -> Result<Self, i32> {
        let mut question = Self::new(entries.len());
        for entry in entries {
            question.add(entry.key.clone(), DnsQuestionFlags::empty())?;
        }
        Ok(question)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestionJsonEntry {
    pub key: DnsResourceKey,
}

pub fn dns_question_new(n: usize) -> DnsQuestion {
    DnsQuestion::new(n)
}

pub fn dns_question_new_address(
    family: i32,
    name: &str,
    convert_idna: bool,
) -> Result<DnsQuestion, i32> {
    DnsQuestion::new_address(family, name, convert_idna)
}

pub fn dns_question_new_reverse(address: IpAddr) -> Result<DnsQuestion, i32> {
    DnsQuestion::new_reverse(address)
}

pub fn dns_question_new_service_pointer(
    service_type: Option<&str>,
    domain: &str,
    convert_idna: bool,
) -> Result<DnsQuestion, i32> {
    DnsQuestion::new_service_pointer(service_type, domain, convert_idna)
}

pub fn dns_question_new_service(
    service: Option<&str>,
    service_type: Option<&str>,
    domain: &str,
    with_txt: bool,
    convert_idna: bool,
) -> Result<DnsQuestion, i32> {
    DnsQuestion::new_service(service, service_type, domain, with_txt, convert_idna)
}

pub fn dns_question_merge(a: &DnsQuestion, b: &DnsQuestion) -> Result<DnsQuestion, i32> {
    DnsQuestion::merge(a, b)
}

pub fn dns_json_dispatch_question(entries: &[DnsQuestionJsonEntry]) -> Result<DnsQuestion, i32> {
    DnsQuestion::from_json_entries(entries)
}

fn canonical_name(name: &str) -> String {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        ".".to_string()
    } else {
        trimmed.to_string()
    }
}

fn parse_labels(name: &str) -> Vec<String> {
    if name.is_empty() || name == "." {
        return Vec::new();
    }

    let mut labels = Vec::new();
    let mut current = String::new();
    let mut chars = name.trim_end_matches('.').chars();

    while let Some(ch) = chars.next() {
        match ch {
            '.' => {
                labels.push(current);
                current = String::new();
            }
            '\\' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                } else {
                    current.push('\\');
                }
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() || labels.is_empty() {
        labels.push(current);
    }

    labels
}

fn dns_name_equal(a: &str, b: &str) -> bool {
    let a = parse_labels(&canonical_name(a));
    let b = parse_labels(&canonical_name(b));
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn dns_name_endswith(name: &str, suffix: &str) -> bool {
    let name_labels = parse_labels(&canonical_name(name));
    let suffix_labels = parse_labels(&canonical_name(suffix));
    if suffix_labels.len() > name_labels.len() {
        return false;
    }
    name_labels[name_labels.len().saturating_sub(suffix_labels.len())..]
        .iter()
        .zip(suffix_labels.iter())
        .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn dns_name_concat(left: &str, right: &str) -> String {
    let left = canonical_name(left);
    let right = canonical_name(right);
    if left == "." {
        return right;
    }
    if right == "." {
        return left;
    }
    format!("{left}.{right}")
}

fn dns_name_change_suffix(name: &str, old_suffix: &str, new_suffix: &str) -> Option<String> {
    let name_labels = parse_labels(&canonical_name(name));
    let old_labels = parse_labels(&canonical_name(old_suffix));
    if old_labels.len() > name_labels.len() {
        return None;
    }
    if !name_labels[name_labels.len().saturating_sub(old_labels.len())..]
        .iter()
        .zip(old_labels.iter())
        .all(|(x, y)| x.eq_ignore_ascii_case(y))
    {
        return None;
    }

    let mut labels = name_labels[..name_labels.len() - old_labels.len()].to_vec();
    labels.extend(parse_labels(&canonical_name(new_suffix)));
    if labels.is_empty() {
        Some(".".to_string())
    } else {
        Some(labels.join("."))
    }
}

fn dns_name_reverse(address: IpAddr) -> String {
    match address {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(v6) => {
            let bytes = v6.octets();
            let mut labels = Vec::with_capacity(32);
            for byte in bytes.iter().rev() {
                labels.push(format!("{:x}", byte & 0x0f));
                labels.push(format!("{:x}", byte >> 4));
            }
            format!("{}.ip6.arpa", labels.join("."))
        }
    }
}

fn dns_name_apply_idna(_name: &str) -> Option<String> {
    None
}

fn dns_service_name_is_valid(name: &str) -> bool {
    !name.is_empty() && name.len() <= 63 && !name.chars().any(char::is_control)
}

fn srv_type_label_is_valid(label: &str) -> bool {
    let mut chars = label.chars();
    matches!(chars.next(), Some('_'))
        && matches!(chars.next(), Some(ch) if ch.is_ascii_alphabetic())
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

fn dns_srv_type_is_valid(name: &str) -> bool {
    let labels = parse_labels(name);
    labels.len() == 2 && labels.iter().all(|label| srv_type_label_is_valid(label))
}

fn dns_service_join(name: Option<&str>, service_type: &str, domain: &str) -> Result<String, i32> {
    if !dns_srv_type_is_valid(service_type) {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    let base = dns_name_concat(service_type, domain);
    match name {
        None => Ok(base),
        Some(name) => {
            if !dns_service_name_is_valid(name) {
                return Err(Errno::EINVAL.to_neg_errno());
            }

            let escaped = name.replace('\\', "\\\\").replace('.', "\\.");
            Ok(dns_name_concat(&escaped, &base))
        }
    }
}

fn dns_class_name(class: u16) -> &'static str {
    match DnsClass::from_u16(class) {
        Some(class) => class.to_name(),
        None => "CLASS?",
    }
}

fn dns_type_name(rr_type: u16) -> String {
    crate::dns_type::dns_type_to_string(rr_type)
        .map(str::to_string)
        .unwrap_or_else(|| format!("TYPE{rr_type}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(rr_type: DnsType, name: &str) -> DnsResourceKey {
        DnsResourceKey::new(DNS_CLASS_IN, rr_type as u16, name)
    }

    #[test]
    fn new_caps_allocation_at_u16_max() {
        let q = DnsQuestion::new(usize::MAX);
        assert_eq!(q.allocated, u16::MAX as usize);
        assert!(q.is_empty());
    }

    #[test]
    fn add_raw_honors_capacity() {
        let mut q = DnsQuestion::new(1);
        q.add_raw(key(DnsType::A, "example.com"), DnsQuestionFlags::empty())
            .unwrap();
        let err = q
            .add_raw(key(DnsType::Aaaa, "example.com"), DnsQuestionFlags::empty())
            .unwrap_err();
        assert_eq!(err, Errno::ENOSPC.to_neg_errno());
    }

    #[test]
    fn add_deduplicates_only_same_flags() {
        let mut q = DnsQuestion::new(4);
        q.add(key(DnsType::A, "example.com"), DnsQuestionFlags::empty())
            .unwrap();
        q.add(key(DnsType::A, "EXAMPLE.COM."), DnsQuestionFlags::empty())
            .unwrap();
        q.add(
            key(DnsType::A, "example.com"),
            DnsQuestionFlags::WANTS_UNICAST_REPLY,
        )
        .unwrap();
        assert_eq!(q.size(), 2);
    }

    #[test]
    fn matches_rr_and_search_domain_follow_c_logic() {
        let mut q = DnsQuestion::new(2);
        q.add(key(DnsType::A, "host"), DnsQuestionFlags::empty())
            .unwrap();
        let rr = DnsResourceRecord::new(key(DnsType::A, "host.example.com"));
        assert_eq!(q.matches_rr(&rr, None), 0);
        assert_eq!(q.matches_rr(&rr, Some("example.com")), 1);
    }

    #[test]
    fn matches_cname_or_dname() {
        let mut q = DnsQuestion::new(2);
        q.add(
            key(DnsType::A, "www.example.com"),
            DnsQuestionFlags::empty(),
        )
        .unwrap();

        let cname = DnsResourceRecord::cname("www.example.com", "alias.example.com");
        assert_eq!(q.matches_cname_or_dname(&cname, None), 1);

        let dname = DnsResourceRecord::dname("example.com", "example.net");
        assert_eq!(q.matches_cname_or_dname(&dname, None), 1);
    }

    #[test]
    fn valid_for_query_requires_same_name_and_valid_type() {
        let mut q = DnsQuestion::new(2);
        q.add(key(DnsType::A, "example.com"), DnsQuestionFlags::empty())
            .unwrap();
        q.add(
            key(DnsType::Aaaa, "example.com."),
            DnsQuestionFlags::empty(),
        )
        .unwrap();
        assert!(q.is_valid_for_query());

        let mut invalid = DnsQuestion::new(2);
        invalid
            .add(key(DnsType::A, "example.com"), DnsQuestionFlags::empty())
            .unwrap();
        invalid
            .add(key(DnsType::Opt, "example.com"), DnsQuestionFlags::empty())
            .unwrap();
        assert!(!invalid.is_valid_for_query());
    }

    #[test]
    fn contains_and_equality_are_order_insensitive() {
        let mut a = DnsQuestion::new(2);
        let mut b = DnsQuestion::new(2);
        let a_key = key(DnsType::A, "example.com");
        let aaaa_key = key(DnsType::Aaaa, "example.com");

        a.add(a_key.clone(), DnsQuestionFlags::empty()).unwrap();
        a.add(aaaa_key.clone(), DnsQuestionFlags::empty()).unwrap();
        b.add(aaaa_key, DnsQuestionFlags::empty()).unwrap();
        b.add(a_key.clone(), DnsQuestionFlags::empty()).unwrap();

        assert_eq!(a.contains_key(&a_key), 1);
        assert_eq!(a.is_equal(&b), 1);
    }

    #[test]
    fn cname_redirect_returns_none_when_unchanged() {
        let mut q = DnsQuestion::new(1);
        q.add(
            key(DnsType::A, "alias.example.com"),
            DnsQuestionFlags::empty(),
        )
        .unwrap();

        let cname = DnsResourceRecord::cname("www.example.com", "alias.example.com");
        assert_eq!(q.cname_redirect(&cname).unwrap(), None);
    }

    #[test]
    fn cname_redirect_rewrites_all_names() {
        let mut q = DnsQuestion::new(2);
        q.add(
            key(DnsType::A, "www.example.com"),
            DnsQuestionFlags::empty(),
        )
        .unwrap();
        q.add(
            key(DnsType::Aaaa, "www.example.com"),
            DnsQuestionFlags::empty(),
        )
        .unwrap();

        let cname = DnsResourceRecord::cname("www.example.com", "alias.example.com");
        let redirected = q.cname_redirect(&cname).unwrap().unwrap();
        assert_eq!(redirected.first_name(), Some("alias.example.com"));
        assert!(
            redirected
                .iter()
                .all(|item| item.flags == DnsQuestionFlags::empty())
        );
    }

    #[test]
    fn dname_redirect_changes_suffix() {
        let mut q = DnsQuestion::new(1);
        q.add(
            key(DnsType::A, "www.sub.example.com"),
            DnsQuestionFlags::empty(),
        )
        .unwrap();

        let dname = DnsResourceRecord::dname("example.com", "example.net");
        let redirected = q.cname_redirect(&dname).unwrap().unwrap();
        assert_eq!(redirected.first_name(), Some("www.sub.example.net"));
    }

    #[test]
    fn new_address_supports_families_and_idna_short_circuit() {
        assert_eq!(
            DnsQuestion::new_address(AF_INET, "example.com", false)
                .unwrap()
                .size(),
            1
        );
        assert_eq!(
            DnsQuestion::new_address(AF_UNSPEC, "example.com", false)
                .unwrap()
                .size(),
            2
        );
        assert_eq!(
            DnsQuestion::new_address(AF_INET, "example.com", true).unwrap_err(),
            Errno::EALREADY.to_neg_errno()
        );
    }

    #[test]
    fn new_reverse_supports_ipv4_and_ipv6() {
        let ipv4 = DnsQuestion::new_reverse(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))).unwrap();
        assert_eq!(ipv4.first_name(), Some("4.3.2.1.in-addr.arpa"));

        let ipv6 = DnsQuestion::new_reverse(IpAddr::V6(Ipv6Addr::LOCALHOST)).unwrap();
        assert!(ipv6.first_name().unwrap().ends_with("ip6.arpa"));
    }

    #[test]
    fn service_builders_follow_c_modes() {
        let ptr =
            DnsQuestion::new_service_pointer(Some("_http._tcp"), "example.com", false).unwrap();
        assert_eq!(ptr.first_name(), Some("_http._tcp.example.com"));

        let srv = DnsQuestion::new_service(
            Some("My Service"),
            Some("_http._tcp"),
            "example.com",
            true,
            false,
        )
        .unwrap();
        assert_eq!(srv.size(), 2);
        assert_eq!(srv.first_name(), Some("My Service._http._tcp.example.com"));

        let raw =
            DnsQuestion::new_service(None, None, "_ssh._tcp.example.com", false, false).unwrap();
        assert_eq!(raw.first_name(), Some("_ssh._tcp.example.com"));

        assert_eq!(
            DnsQuestion::new_service(Some("oops"), None, "example.com", false, false).unwrap_err(),
            Errno::EINVAL.to_neg_errno()
        );
    }

    #[test]
    fn merge_preserves_a_then_deduplicates_b() {
        let mut a = DnsQuestion::new(2);
        let mut b = DnsQuestion::new(2);
        a.add(key(DnsType::A, "example.com"), DnsQuestionFlags::empty())
            .unwrap();
        b.add(key(DnsType::A, "example.com"), DnsQuestionFlags::empty())
            .unwrap();
        b.add(key(DnsType::Aaaa, "example.com"), DnsQuestionFlags::empty())
            .unwrap();

        let merged = DnsQuestion::merge(&a, &b).unwrap();
        assert_eq!(merged.size(), 2);
        assert_eq!(merged.iter().next().unwrap().key.rr_type, DnsType::A as u16);
    }

    #[test]
    fn dump_and_json_dispatch_are_stable() {
        let entries = vec![
            DnsQuestionJsonEntry {
                key: key(DnsType::A, "example.com"),
            },
            DnsQuestionJsonEntry {
                key: key(DnsType::A, "EXAMPLE.COM"),
            },
        ];

        let q = dns_json_dispatch_question(&entries).unwrap();
        assert_eq!(q.size(), 1);
        assert!(q.dump().contains("\tIN A example.com\n"));
    }

    #[test]
    fn escaped_service_name_round_trips_in_comparisons() {
        let joined = dns_service_join(Some("A.B\\C"), "_http._tcp", "local").unwrap();
        assert_eq!(joined, "A\\.B\\\\C._http._tcp.local");
        assert!(dns_name_equal(&joined, "A\\.B\\\\C._http._tcp.local."));
    }
}
