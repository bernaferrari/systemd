// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-dns-rr.c
//
// DNS resource records: key creation, equality, matching (CNAME/DNAME/SOA),
// record comparison, wire format, TTL clamping, and string representation.

use std::cmp::Ordering;

// ── DNS type and class constants ────────────────────────────────────────────

const DNS_CLASS_IN: u16 = 1;
const DNS_CLASS_ANY: u16 = 255;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_NS: u16 = 2;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_SOA: u16 = 6;
const DNS_TYPE_PTR: u16 = 12;
const DNS_TYPE_HINFO: u16 = 13;
const DNS_TYPE_MX: u16 = 15;
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_SRV: u16 = 33;
const DNS_TYPE_NAPTR: u16 = 35;
const DNS_TYPE_A6: u16 = 38;
const DNS_TYPE_DNAME: u16 = 39;
const DNS_TYPE_OPT: u16 = 41;
const DNS_TYPE_RRSIG: u16 = 46;
const DNS_TYPE_SVCB: u16 = 64;
const DNS_TYPE_ANY: u16 = 255;
const DNS_TYPE_NSEC: u16 = 47;

const MANAGER_SEARCH_DOMAINS_MAX: usize = 256;

// ── Helpers ─────────────────────────────────────────────────────────────────

fn normalize_name(name: &str) -> String {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        ".".to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

fn name_labels(name: &str) -> Vec<&str> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return vec![];
    }
    trimmed.split('.').collect()
}

// ── DnsResourceKey ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DnsResourceKey {
    class: u16,
    rtype: u16,
    name: String,
}

impl DnsResourceKey {
    fn new(class: u16, rtype: u16, name: &str) -> Self {
        Self {
            class,
            rtype,
            name: name.to_string(),
        }
    }

    fn normalized_name(&self) -> String {
        normalize_name(&self.name)
    }

    fn is_address(&self) -> bool {
        self.class == DNS_CLASS_IN
            && (self.rtype == DNS_TYPE_A
                || self.rtype == DNS_TYPE_AAAA
                || self.rtype == DNS_TYPE_A6)
    }

    fn is_dnssd_ptr(&self) -> bool {
        if self.rtype != DNS_TYPE_PTR {
            return false;
        }
        let labels = name_labels(&self.name);
        let last = labels.last().map(|l| *l);
        if last != Some("local") {
            return false;
        }
        if labels.len() >= 2 {
            let proto = labels[labels.len() - 2];
            return proto == "_tcp" || proto == "_udp";
        }
        false
    }

    fn is_dnssd_two_label_ptr(&self) -> bool {
        self.is_dnssd_ptr() && name_labels(&self.name).len() >= 3
    }

    fn to_string_repr(&self) -> String {
        let type_str = match self.rtype {
            DNS_TYPE_A => "A",
            DNS_TYPE_NS => "NS",
            DNS_TYPE_CNAME => "CNAME",
            DNS_TYPE_SOA => "SOA",
            DNS_TYPE_PTR => "PTR",
            DNS_TYPE_MX => "MX",
            DNS_TYPE_AAAA => "AAAA",
            DNS_TYPE_SRV => "SRV",
            DNS_TYPE_DNAME => "DNAME",
            DNS_TYPE_TXT => "TXT",
            DNS_TYPE_ANY => "ANY",
            DNS_TYPE_OPT => "OPT",
            DNS_TYPE_HINFO => "HINFO",
            DNS_TYPE_SVCB => "SVCB",
            _ => "UNKNOWN",
        };
        format!(
            "{} {} {}",
            self.name,
            if self.class == DNS_CLASS_IN {
                "IN"
            } else {
                "ANY"
            },
            type_str
        )
    }

    fn equal(&self, other: &Self) -> bool {
        self.class == other.class
            && self.rtype == other.rtype
            && self.normalized_name() == other.normalized_name()
    }

    fn match_rr(&self, rr: &DnsResourceRecord, search_domain: Option<&str>) -> bool {
        if !self.match_class(rr.key.class) || !self.match_type(rr.key.rtype) {
            return false;
        }
        let key_name = self.normalized_name();
        let rr_name = rr.key.normalized_name();
        if key_name == rr_name {
            return true;
        }
        if let Some(sd) = search_domain {
            let combined = format!("{}.{}", key_name, sd);
            if normalize_name(&combined) == rr_name {
                return true;
            }
        }
        false
    }

    fn match_class(&self, other_class: u16) -> bool {
        self.class == DNS_CLASS_ANY || other_class == DNS_CLASS_ANY || self.class == other_class
    }

    fn match_type(&self, other_type: u16) -> bool {
        self.rtype == DNS_TYPE_ANY || other_type == DNS_TYPE_ANY || self.rtype == other_type
    }

    fn match_cname_or_dname(&self, cname_key: &Self, search_domain: Option<&str>) -> bool {
        if !self.match_class(cname_key.class) {
            return false;
        }
        if cname_key.rtype == DNS_TYPE_CNAME {
            let compatible = self.rtype != DNS_TYPE_CNAME
                && self.rtype != DNS_TYPE_DNAME
                && self.rtype != DNS_TYPE_NSEC;
            if !compatible {
                return false;
            }
            return names_match_with_domain(
                &self.normalized_name(),
                &cname_key.normalized_name(),
                search_domain,
            );
        }
        if cname_key.rtype == DNS_TYPE_DNAME {
            let compatible = self.rtype != DNS_TYPE_CNAME
                && self.rtype != DNS_TYPE_DNAME
                && self.rtype != DNS_TYPE_NSEC;
            if !compatible {
                return false;
            }
            let self_name = self.normalized_name();
            let dname_name = cname_key.normalized_name();
            if let Some(sd) = search_domain {
                if let Some(pos) = self_name.find('.').or_else(|| {
                    if self_name.len() < dname_name.len() {
                        None
                    } else {
                        Some(self_name.len())
                    }
                }) {
                    let combined = format!("{}.{}", &self_name[..pos], sd);
                    if normalize_name(&combined) == dname_name {
                        return true;
                    }
                }
            }
            let self_labels = name_labels(&self_name);
            let dname_labels = name_labels(&dname_name);
            if self_labels.len() <= dname_labels.len() {
                return false;
            }
            let suffix_start = self_labels.len() - dname_labels.len();
            let suffix: Vec<&str> = self_labels[suffix_start..].to_vec();
            return suffix == dname_labels
                && names_match_with_domain(
                    &self_name,
                    &format!("{}.{}", &self_labels[..suffix_start].join("."), dname_name),
                    search_domain,
                );
        }
        false
    }

    fn match_soa(&self, soa_key: &Self) -> bool {
        if self.class == DNS_CLASS_ANY || soa_key.class == DNS_CLASS_ANY {
            return false;
        }
        if soa_key.rtype != DNS_TYPE_SOA {
            return false;
        }
        if self.class != soa_key.class {
            return false;
        }
        let self_name = self.normalized_name();
        let self_labels = name_labels(&self_name);
        let soa_name = soa_key.normalized_name();
        let soa_labels = name_labels(&soa_name);
        if self_labels.len() < soa_labels.len() {
            return false;
        }
        let suffix_start = self_labels.len() - soa_labels.len();
        self_labels[suffix_start..] == soa_labels[..]
    }

    fn new_redirect(&self, rr: &DnsResourceRecord) -> Option<Self> {
        if rr.key.rtype == DNS_TYPE_CNAME {
            if let Some(ref cname) = rr.cname {
                Some(Self::new(self.class, self.rtype, cname))
            } else {
                None
            }
        } else if rr.key.rtype == DNS_TYPE_DNAME {
            if let Some(ref dname) = rr.dname {
                let self_name = self.normalized_name();
                let self_labels = name_labels(&self_name);
                let rr_name = rr.key.normalized_name();
                let rr_labels = name_labels(&rr_name);
                if self_labels.len() > rr_labels.len() {
                    let suffix_start = self_labels.len() - rr_labels.len();
                    let prefix: Vec<&str> = self_labels[..suffix_start].to_vec();
                    let new_name = format!("{}.{}", prefix.join("."), dname);
                    Some(Self::new(self.class, self.rtype, &new_name))
                } else {
                    Some(Self::new(self.class, self.rtype, &self.name))
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    fn append_suffix(&self, suffix: &str) -> Self {
        let s = suffix.trim_end_matches('.');
        if s.is_empty() {
            return self.clone();
        }
        if self.name.ends_with(s) {
            return self.clone();
        }
        let my_name = self.name.trim_end_matches('.');
        if my_name.is_empty() {
            return self.clone();
        }
        Self::new(self.class, self.rtype, &format!("{}.{}", my_name, s))
    }
}

fn names_match_with_domain(name1: &str, name2: &str, search_domain: Option<&str>) -> bool {
    if name1 == name2 {
        return true;
    }
    if let Some(sd) = search_domain {
        let combined = format!("{}.{}", name1, sd);
        if normalize_name(&combined) == name2 {
            return true;
        }
    }
    false
}

// ── DNS Resource Record ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DnsResourceRecord {
    key: DnsResourceKey,
    ttl: u32,
    a_addr: Option<u32>,
    aaaa_addr: Option<[u8; 16]>,
    ns: Option<String>,
    cname: Option<String>,
    dname: Option<String>,
    ptr: Option<String>,
    soa: Option<SoaData>,
    mx: Option<MxData>,
    srv: Option<SrvData>,
    txt: Option<String>,
    hinfo: Option<HinfoData>,
    wire_format: Option<Vec<u8>>,
    wire_format_rdata_offset: usize,
}

#[derive(Debug, Clone, PartialEq)]
struct SoaData {
    mname: String,
    rname: String,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}

#[derive(Debug, Clone)]
struct MxData {
    priority: u16,
    exchange: String,
}

#[derive(Debug, Clone)]
struct SrvData {
    priority: u16,
    weight: u16,
    port: u16,
    target: String,
}

#[derive(Debug, Clone)]
struct HinfoData {
    cpu: String,
    os: String,
}

impl DnsResourceRecord {
    fn new(class: u16, rtype: u16, name: &str) -> Self {
        Self {
            key: DnsResourceKey::new(class, rtype, name),
            ttl: 0,
            a_addr: None,
            aaaa_addr: None,
            ns: None,
            cname: None,
            dname: None,
            ptr: None,
            soa: None,
            mx: None,
            srv: None,
            txt: None,
            hinfo: None,
            wire_format: None,
            wire_format_rdata_offset: 0,
        }
    }

    fn record_equal(&self, other: &Self) -> bool {
        if !self.key.equal(&other.key) {
            return false;
        }
        if self.ttl != other.ttl {
            return false;
        }
        if self.a_addr != other.a_addr {
            return false;
        }
        if self.aaaa_addr != other.aaaa_addr {
            return false;
        }
        if self.ns.as_ref().map(|s| s.to_ascii_lowercase())
            != other.ns.as_ref().map(|s| s.to_ascii_lowercase())
        {
            return false;
        }
        if self.cname.as_ref().map(|s| s.to_ascii_lowercase())
            != other.cname.as_ref().map(|s| s.to_ascii_lowercase())
        {
            return false;
        }
        if self.dname.as_ref().map(|s| s.to_ascii_lowercase())
            != other.dname.as_ref().map(|s| s.to_ascii_lowercase())
        {
            return false;
        }
        if self.ptr.as_ref().map(|s| s.to_ascii_lowercase())
            != other.ptr.as_ref().map(|s| s.to_ascii_lowercase())
        {
            return false;
        }
        if self.soa != other.soa {
            return false;
        }
        if let (Some(a), Some(b)) = (&self.mx, &other.mx) {
            if a.priority != b.priority {
                return false;
            }
            if a.exchange.to_ascii_lowercase() != b.exchange.to_ascii_lowercase() {
                return false;
            }
        } else if self.mx.is_some() || other.mx.is_some() {
            return false;
        }
        if let (Some(a), Some(b)) = (&self.srv, &other.srv) {
            if a.priority != b.priority || a.weight != b.weight || a.port != b.port {
                return false;
            }
            if a.target.to_ascii_lowercase() != b.target.to_ascii_lowercase() {
                return false;
            }
        } else if self.srv.is_some() || other.srv.is_some() {
            return false;
        }
        if self.txt != other.txt {
            return false;
        }
        if let (Some(a), Some(b)) = (&self.hinfo, &other.hinfo) {
            if a.cpu.to_ascii_lowercase() != b.cpu.to_ascii_lowercase()
                || a.os.to_ascii_lowercase() != b.os.to_ascii_lowercase()
            {
                return false;
            }
        } else if self.hinfo.is_some() || other.hinfo.is_some() {
            return false;
        }
        if self.wire_format != other.wire_format {
            return false;
        }
        true
    }

    fn to_string_repr(&self) -> String {
        let key_str = self.key.to_string_repr();
        match self.key.rtype {
            DNS_TYPE_A => {
                if let Some(addr) = self.a_addr {
                    let a = (addr >> 24) as u8;
                    let b = (addr >> 16) as u8;
                    let c = (addr >> 8) as u8;
                    let d = addr as u8;
                    format!("{} {}.{}.{}.{}", key_str, a, b, c, d)
                } else {
                    key_str
                }
            }
            DNS_TYPE_AAAA => key_str,
            DNS_TYPE_NS | DNS_TYPE_CNAME | DNS_TYPE_PTR => {
                let name = self
                    .ns
                    .as_ref()
                    .or(self.cname.as_ref())
                    .or(self.ptr.as_ref());
                if let Some(n) = name {
                    format!("{} {}", key_str, n)
                } else {
                    key_str
                }
            }
            DNS_TYPE_SOA => {
                if let Some(ref soa) = self.soa {
                    format!(
                        "{} {} {} {} {} {} {} {}",
                        key_str,
                        soa.mname,
                        soa.rname,
                        soa.serial,
                        soa.refresh,
                        soa.retry,
                        soa.expire,
                        soa.minimum
                    )
                } else {
                    key_str
                }
            }
            DNS_TYPE_MX => {
                if let Some(ref mx) = self.mx {
                    format!("{} {} {}", key_str, mx.priority, mx.exchange)
                } else {
                    key_str
                }
            }
            DNS_TYPE_SRV => {
                if let Some(ref srv) = self.srv {
                    format!(
                        "{} {} {} {} {}",
                        key_str, srv.priority, srv.weight, srv.port, srv.target
                    )
                } else {
                    key_str
                }
            }
            DNS_TYPE_HINFO => {
                if let Some(ref hinfo) = self.hinfo {
                    format!("{} {} {}", key_str, hinfo.cpu, hinfo.os)
                } else {
                    key_str
                }
            }
            _ => key_str,
        }
    }

    fn clamp_max_ttl(&mut self, max_ttl: u32) -> bool {
        if self.ttl <= max_ttl {
            return false;
        }
        self.ttl = max_ttl;
        true
    }
}

// ── DnsResourceKey reduce ───────────────────────────────────────────────────

fn key_reduce(a: &mut DnsResourceKey, b: &mut DnsResourceKey) -> bool {
    if a.equal(b) {
        *b = a.clone();
        true
    } else {
        false
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_key_new_and_accessors() {
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        assert_eq!(key.class, DNS_CLASS_IN);
        assert_eq!(key.rtype, DNS_TYPE_A);
        assert_eq!(key.name, "www.example.com");
        assert_eq!(key.normalized_name(), "www.example.com");
    }

    #[test]
    fn test_resource_key_equal_case_insensitive() {
        let a = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        let b = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.EXAMPLE.com");
        assert!(a.equal(&b));

        let c = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com.");
        assert!(a.equal(&c));

        let d = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.org");
        assert!(!a.equal(&d));

        let e = DnsResourceKey::new(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com");
        assert!(!a.equal(&e));

        let f = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");
        assert!(!a.equal(&f));
    }

    #[test]
    fn test_resource_key_match_rr() {
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        let mut rr = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        assert!(key.match_rr(&rr, None));

        let key_any_class = DnsResourceKey::new(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com");
        assert!(key_any_class.match_rr(&rr, None));

        let key_any_type = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com");
        assert!(key_any_type.match_rr(&rr, None));

        let key_diff_type = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");
        assert!(!key_diff_type.match_rr(&rr, None));

        let key_case = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.EXAMPLE.com");
        assert!(key_case.match_rr(&rr, None));

        let key_short = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example");
        assert!(!key_short.match_rr(&rr, None));
        assert!(key_short.match_rr(&rr, Some("com")));
        assert!(!key_short.match_rr(&rr, Some("org")));
    }

    #[test]
    fn test_resource_key_redirect() {
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        let mut cname_rr = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        cname_rr.cname = Some("example.com".to_string());
        let redirected = key.new_redirect(&cname_rr).unwrap();
        assert_eq!(redirected.class, DNS_CLASS_IN);
        assert_eq!(redirected.rtype, DNS_TYPE_A);
        assert_eq!(redirected.normalized_name(), "example.com");

        let mut dname_rr = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_DNAME, "example.com");
        dname_rr.dname = Some("v2.example.com".to_string());
        let redirected = key.new_redirect(&dname_rr).unwrap();
        assert_eq!(redirected.normalized_name(), "www.v2.example.com");
    }

    #[test]
    fn test_resource_key_match_soa() {
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        let soa = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_SOA, "example.com");
        assert!(key.match_soa(&soa));

        let soa_same = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_SOA, "www.example.com");
        assert!(key.match_soa(&soa_same));

        let soa_parent = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_SOA, "www.example.com");
        let key_parent = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert!(!key_parent.match_soa(&soa_parent));

        let key_any = DnsResourceKey::new(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com");
        assert!(!key_any.match_soa(&soa));
    }

    #[test]
    fn test_resource_key_reduce() {
        let mut a = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        let mut b = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        assert!(key_reduce(&mut a, &mut b));
        assert!(a.equal(&b));

        let mut c = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        let mut d = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        assert!(!key_reduce(&mut c, &mut d));
    }

    #[test]
    fn test_resource_key_is_address_and_dnssd() {
        let a_key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        assert!(a_key.is_address());

        let aaaa_key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");
        assert!(aaaa_key.is_address());

        let cname_key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        assert!(!cname_key.is_address());

        let ptr_tcp = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_PTR, "_tcp.local");
        assert!(ptr_tcp.is_dnssd_ptr());
        assert!(!ptr_tcp.is_dnssd_two_label_ptr());

        let ptr_two = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_PTR, "foo._tcp.local");
        assert!(ptr_two.is_dnssd_ptr());
        assert!(ptr_two.is_dnssd_two_label_ptr());

        let ptr_bad = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_PTR, "_abc.local");
        assert!(!ptr_bad.is_dnssd_ptr());
    }

    #[test]
    fn test_resource_key_to_string_and_append_suffix() {
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        assert_eq!(key.to_string_repr(), "www.example.com IN CNAME");

        let key_root_suffix = key.append_suffix("");
        assert_eq!(key_root_suffix.name, "www.example.com");

        let key_dot_suffix = key.append_suffix(".");
        assert_eq!(key_dot_suffix.name, "www.example.com");

        let key_com = key.append_suffix("com");
        assert_eq!(key_com.name, "www.example.com");
    }

    #[test]
    fn test_resource_record_equal_a() {
        let mut a = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        a.a_addr = Some(0xc0a8017f_u32.to_be());

        let mut b = a.clone();
        assert!(a.record_equal(&b));

        b.a_addr = Some(0xc0a80180_u32.to_be());
        assert!(!a.record_equal(&b));
    }

    #[test]
    fn test_resource_record_equal_ns_cname_case_insensitive() {
        let mut a = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_NS, "www.example.com");
        a.ns = Some("ns1.example.com".to_string());

        let mut b = a.clone();
        assert!(a.record_equal(&b));

        b.ns = Some("ns2.example.com".to_string());
        assert!(!a.record_equal(&b));

        let mut c = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        c.cname = Some("example.com".to_string());
        let mut d = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.EXAMPLE.com");
        d.cname = Some("EXAMPLE.com".to_string());
        assert!(c.record_equal(&d));
    }

    #[test]
    fn test_resource_record_equal_soa() {
        let mut a = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_SOA, "www.example.com");
        a.soa = Some(SoaData {
            mname: "ns.example.com".to_string(),
            rname: "admin.example.com".to_string(),
            serial: 1111111111,
            refresh: 86400,
            retry: 7200,
            expire: 4000000,
            minimum: 3600,
        });

        let mut b = a.clone();
        assert!(a.record_equal(&b));

        b.soa.as_mut().unwrap().serial = 1111111112;
        assert!(!a.record_equal(&b));

        let mut c = a.clone();
        c.soa.as_mut().unwrap().mname = "ns.example.org".to_string();
        assert!(!a.record_equal(&c));
    }

    #[test]
    fn test_resource_record_equal_mx_srv() {
        let mut a = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_MX, "www.example.com");
        a.mx = Some(MxData {
            priority: 10,
            exchange: "mail.example.com".to_string(),
        });

        let mut b = a.clone();
        assert!(a.record_equal(&b));

        b.mx.as_mut().unwrap().priority = 9;
        assert!(!a.record_equal(&b));

        let mut c = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_SRV, "www.example.com");
        c.srv = Some(SrvData {
            priority: 10,
            weight: 5,
            port: 587,
            target: "mail.example.com".to_string(),
        });

        let mut d = c.clone();
        assert!(c.record_equal(&d));

        d.srv.as_mut().unwrap().port = 588;
        assert!(!c.record_equal(&d));
    }

    #[test]
    fn test_resource_record_to_string() {
        let mut rr = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        rr.a_addr = Some(u32::from_be_bytes([192, 168, 1, 127]));
        assert_eq!(rr.to_string_repr(), "www.example.com IN A 192.168.1.127");

        let mut rr_ns = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_NS, "www.example.com");
        rr_ns.ns = Some("ns1.example.com".to_string());
        assert_eq!(
            rr_ns.to_string_repr(),
            "www.example.com IN NS ns1.example.com"
        );

        let mut rr_mx = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_MX, "mail.example.com");
        rr_mx.mx = Some(MxData {
            priority: 6,
            exchange: "exchange.example.com".to_string(),
        });
        assert_eq!(
            rr_mx.to_string_repr(),
            "mail.example.com IN MX 6 exchange.example.com"
        );
    }

    #[test]
    fn test_resource_record_clamp_ttl() {
        let mut rr = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        rr.ttl = 3600;

        assert!(!rr.clamp_max_ttl(4800));
        assert_eq!(rr.ttl, 3600);

        assert!(rr.clamp_max_ttl(2400));
        assert_eq!(rr.ttl, 2400);
    }

    #[test]
    fn test_resource_record_different_names_not_equal() {
        let a = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        let b = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.org");
        assert!(!a.record_equal(&b));

        let c = DnsResourceRecord::new(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com");
        assert!(!a.record_equal(&c));

        let d = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com");
        assert!(!a.record_equal(&d));
    }

    #[test]
    fn test_resource_record_equal_hinfo_case_insensitive() {
        let mut a = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_HINFO, "www.example.com");
        a.hinfo = Some(HinfoData {
            cpu: "intel x64".to_string(),
            os: "linux".to_string(),
        });

        let mut b = DnsResourceRecord::new(DNS_CLASS_IN, DNS_TYPE_HINFO, "www.example.com");
        b.hinfo = Some(HinfoData {
            cpu: "INTEL x64".to_string(),
            os: "LINUX".to_string(),
        });
        assert!(a.record_equal(&b));

        b.hinfo.as_mut().unwrap().cpu = "arm64".to_string();
        assert!(!a.record_equal(&b));
    }
}
