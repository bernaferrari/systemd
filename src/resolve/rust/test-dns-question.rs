// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-dns-question.c
//
// DNS question container: add, new_address, new_reverse, new_service,
// matches_rr, matches_cname_or_dname, is_valid_for_query, is_equal,
// cname_redirect, dump, first_name, and merge.

use std::io::Write;

// ── Constants ───────────────────────────────────────────────────────────────

const DNS_CLASS_IN: u16 = 1;
const DNS_CLASS_ANY: u16 = 255;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_SRV: u16 = 33;
const DNS_TYPE_PTR: u16 = 12;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_DNAME: u16 = 39;
const DNS_TYPE_OPT: u16 = 41;
const DNS_TYPE_ANY: u16 = 255;

// ── Resource key ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
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
            name: name.trim_end_matches('.').to_ascii_lowercase(),
        }
    }
}

// ── Resource record ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DnsResourceRecord {
    key: DnsResourceKey,
    cname_target: Option<String>,
    dname_target: Option<String>,
}

impl DnsResourceRecord {
    fn new(key: DnsResourceKey) -> Self {
        Self {
            key,
            cname_target: None,
            dname_target: None,
        }
    }
}

// ── Question ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DnsQuestion {
    keys: Vec<DnsResourceKey>,
    capacity: usize,
}

impl DnsQuestion {
    fn new(capacity: usize) -> Self {
        Self {
            keys: Vec::with_capacity(capacity),
            capacity,
        }
    }

    fn size(&self) -> usize {
        self.keys.len()
    }
    fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn add(&mut self, key: DnsResourceKey) -> Result<(), i32> {
        if self.keys.len() >= self.capacity {
            return Err(-28); // ENOSPC
        }
        self.keys.push(key);
        Ok(())
    }

    fn contains_key(&self, key: &DnsResourceKey) -> bool {
        self.keys
            .iter()
            .any(|k| k.class == key.class && k.rtype == key.rtype && k.name == key.name)
    }

    fn new_address(family: i32, name: &str) -> Self {
        let rtype = if family == 10 {
            DNS_TYPE_AAAA
        } else {
            DNS_TYPE_A
        };
        Self {
            keys: vec![DnsResourceKey::new(DNS_CLASS_IN, rtype, name)],
            capacity: 1,
        }
    }

    fn new_reverse(family: i32, addr: u32) -> Self {
        let ptr_name = format!(
            "{}.{}.{}.{}.in-addr.arpa",
            addr & 0xFF,
            (addr >> 8) & 0xFF,
            (addr >> 16) & 0xFF,
            (addr >> 24) & 0xFF
        );
        Self {
            keys: vec![DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_PTR, &ptr_name)],
            capacity: 1,
        }
    }

    fn new_service(
        service: Option<&str>,
        stype: Option<&str>,
        domain: &str,
        with_txt: bool,
    ) -> Result<Self, i32> {
        let domain = domain.trim_end_matches('.');

        let full_name = match (service, stype) {
            (Some(_), None) => return Err(-22), // EINVAL: service without type
            (Some(s), Some(t)) => {
                // Validate type format: _proto._tcp or _proto._udp
                let parts: Vec<&str> = t.split('.').collect();
                if parts.len() != 2 {
                    return Err(-22);
                }
                if !parts[0].starts_with('_') || !parts[1].starts_with('_') {
                    return Err(-22);
                }
                if parts[1] != "_tcp" && parts[1] != "_udp" {
                    return Err(-22);
                }
                format!("{}.{}.{}", s, t, domain)
            }
            (None, Some(t)) => {
                let parts: Vec<&str> = t.split('.').collect();
                if parts.len() != 2 || !parts[0].starts_with('_') || !parts[1].starts_with('_') {
                    return Err(-22);
                }
                format!("{}.{}", t, domain)
            }
            (None, None) => domain.to_string(),
        };

        let capacity = if with_txt { 2 } else { 1 };
        let mut keys = vec![DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_SRV, &full_name)];
        if with_txt {
            keys.push(DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_TXT, &full_name));
        }
        Ok(Self { keys, capacity })
    }

    fn matches_rr(&self, rr: &DnsResourceRecord) -> bool {
        self.keys.iter().any(|k| {
            (k.class == DNS_CLASS_ANY || k.class == rr.key.class)
                && (k.rtype == DNS_TYPE_ANY || k.rtype == rr.key.rtype)
                && k.name == rr.key.name
        })
    }

    fn matches_cname_or_dname(&self, rr: &DnsResourceRecord) -> bool {
        if rr.key.rtype != DNS_TYPE_CNAME && rr.key.rtype != DNS_TYPE_DNAME {
            return false;
        }
        // If question already has a CNAME key, refuse
        if rr.key.rtype == DNS_TYPE_CNAME && self.keys.iter().any(|k| k.rtype == DNS_TYPE_CNAME) {
            return false;
        }
        if rr.key.rtype == DNS_TYPE_CNAME {
            self.keys
                .iter()
                .any(|k| k.name.eq_ignore_ascii_case(&rr.key.name))
        } else {
            // DNAME: question name must be a subdomain of the DNAME name
            let dname_lower = rr.key.name.to_ascii_lowercase();
            let suffix = format!(".{}", dname_lower);
            self.keys.iter().any(|k| {
                let k_lower = k.name.to_ascii_lowercase();
                k_lower != dname_lower && k_lower.ends_with(&suffix)
            })
        }
    }

    fn is_valid_for_query(&self) -> bool {
        if self.keys.is_empty() {
            return false;
        }
        // No OPT type
        if self.keys.iter().any(|k| k.rtype == DNS_TYPE_OPT) {
            return false;
        }
        // All keys must share the same name
        let first_name = &self.keys[0].name;
        if !self.keys.iter().all(|k| &k.name == first_name) {
            return false;
        }
        true
    }

    fn is_equal(&self, other: &Self) -> bool {
        if self.keys.len() != other.keys.len() {
            return false;
        }
        for k in &self.keys {
            if !other.contains_key(k) {
                return false;
            }
        }
        true
    }

    fn cname_redirect(&self, rr: &DnsResourceRecord) -> Option<Self> {
        let target = if rr.key.rtype == DNS_TYPE_CNAME {
            rr.cname_target.as_ref()?
        } else if rr.key.rtype == DNS_TYPE_DNAME {
            rr.dname_target.as_ref()?
        } else {
            return None;
        };

        let mut new_keys = vec![];
        for k in &self.keys {
            let new_name = if rr.key.rtype == DNS_TYPE_CNAME {
                target.clone()
            } else {
                // DNAME: replace suffix
                if k.name.ends_with(&format!(".{}", rr.key.name)) {
                    let prefix = &k.name[..k.name.len() - rr.key.name.len() - 1];
                    format!("{}.{}", prefix, target)
                } else {
                    k.name.clone()
                }
            };
            new_keys.push(DnsResourceKey::new(k.class, k.rtype, &new_name));
        }
        let capacity = new_keys.len();
        Some(Self {
            keys: new_keys,
            capacity,
        })
    }

    fn first_name(&self) -> Option<&str> {
        self.keys.first().map(|k| k.name.as_str())
    }

    fn merge(&self, other: &Self) -> Self {
        let mut keys = self.keys.clone();
        for k in &other.keys {
            if !keys.iter().any(|existing| existing == k) {
                keys.push(k.clone());
            }
        }
        let capacity = keys.len();
        Self { keys, capacity }
    }

    fn dump(&self) -> String {
        let mut buf = String::new();
        for k in &self.keys {
            let type_str = match k.rtype {
                DNS_TYPE_A => "A",
                DNS_TYPE_AAAA => "AAAA",
                DNS_TYPE_TXT => "TXT",
                DNS_TYPE_SRV => "SRV",
                DNS_TYPE_PTR => "PTR",
                _ => "UNKNOWN",
            };
            buf.push_str(&format!("\t{} IN {}\n", k.name, type_str));
        }
        buf
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_question_add() -> Result<(), i32> {
        let mut q = DnsQuestion::new(1);
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        q.add(key)?;
        assert_eq!(q.size(), 1);
        assert!(!q.is_empty());
        Ok(())
    }

    #[test]
    fn test_dns_question_add_full() -> Result<(), i32> {
        let mut q = DnsQuestion::new(0);
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        assert!(q.add(key).is_err());
        Ok(())
    }

    #[test]
    fn test_dns_question_new_address_ipv4() {
        let q = DnsQuestion::new_address(2, "www.example.com"); // AF_INET=2
        assert_eq!(q.size(), 1);
        assert!(q.contains_key(&DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "www.example.com"
        )));
        assert!(!q.contains_key(&DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_AAAA,
            "www.example.com"
        )));
    }

    #[test]
    fn test_dns_question_new_address_ipv6() {
        let q = DnsQuestion::new_address(10, "www.example.com"); // AF_INET6=10
        assert_eq!(q.size(), 1);
        assert!(q.contains_key(&DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_AAAA,
            "www.example.com"
        )));
    }

    #[test]
    fn test_dns_question_new_reverse() {
        let addr = 0xc0a8017f; // 192.168.1.127
        let q = DnsQuestion::new_reverse(2, addr);
        assert_eq!(q.size(), 1);
        assert!(q.contains_key(&DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_PTR,
            "127.1.168.192.in-addr.arpa"
        )));
    }

    #[test]
    fn test_dns_question_new_service_domain_only() -> Result<(), i32> {
        let q = DnsQuestion::new_service(None, None, "www.example.com", false)?;
        assert_eq!(q.size(), 1);
        assert!(q.contains_key(&DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_SRV,
            "www.example.com"
        )));
        Ok(())
    }

    #[test]
    fn test_dns_question_new_service_with_type() -> Result<(), i32> {
        let q = DnsQuestion::new_service(None, Some("_xmpp._tcp"), "example.com", false)?;
        assert_eq!(q.size(), 1);
        assert!(q.contains_key(&DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_SRV,
            "_xmpp._tcp.example.com"
        )));
        Ok(())
    }

    #[test]
    fn test_dns_question_new_service_with_txt() -> Result<(), i32> {
        let q = DnsQuestion::new_service(None, Some("_xmpp._tcp"), "example.com", true)?;
        assert_eq!(q.size(), 2);
        assert!(q.contains_key(&DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_SRV,
            "_xmpp._tcp.example.com"
        )));
        assert!(q.contains_key(&DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_TXT,
            "_xmpp._tcp.example.com"
        )));
        Ok(())
    }

    #[test]
    fn test_dns_question_new_service_invalid_type() {
        assert!(DnsQuestion::new_service(None, Some("_xmpp.tcp"), "example.com", false).is_err());
        assert!(DnsQuestion::new_service(None, Some("_xmpp"), "example.com", false).is_err());
        assert!(
            DnsQuestion::new_service(None, Some("_xmpp._tcp._extra"), "example.com", false)
                .is_err()
        );
    }

    #[test]
    fn test_dns_question_new_service_without_type_with_service() {
        assert!(DnsQuestion::new_service(Some("service"), None, "example.com", false).is_err());
    }

    #[test]
    fn test_matches_rr() {
        let mut q = DnsQuestion::new(2);
        q.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "www.example.com",
        ))
        .unwrap();
        q.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "mail.example.com",
        ))
        .unwrap();

        let rr1 = DnsResourceRecord::new(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "www.example.com",
        ));
        assert!(q.matches_rr(&rr1));

        let rr2 = DnsResourceRecord::new(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "mail.example.com",
        ));
        assert!(q.matches_rr(&rr2));

        let rr3 = DnsResourceRecord::new(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_CNAME,
            "mail.example.com",
        ));
        assert!(!q.matches_rr(&rr3));
    }

    #[test]
    fn test_matches_cname_or_dname() {
        let mut q = DnsQuestion::new(1);
        q.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "www.example.com",
        ))
        .unwrap();

        let cname = DnsResourceRecord::new(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_CNAME,
            "www.example.com",
        ));
        assert!(q.matches_cname_or_dname(&cname));

        let dname = DnsResourceRecord::new(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_DNAME,
            "example.com",
        ));
        assert!(q.matches_cname_or_dname(&dname));

        let a_rr = DnsResourceRecord::new(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "www.example.com",
        ));
        assert!(!q.matches_cname_or_dname(&a_rr));
    }

    #[test]
    fn test_is_valid_for_query() {
        let mut q = DnsQuestion::new(1);
        q.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "www.example.com",
        ))
        .unwrap();
        assert!(q.is_valid_for_query());

        let mut q_bad = DnsQuestion::new(1);
        q_bad
            .add(DnsResourceKey::new(
                DNS_CLASS_IN,
                DNS_TYPE_OPT,
                "www.example.com",
            ))
            .unwrap();
        assert!(!q_bad.is_valid_for_query());
    }

    #[test]
    fn test_is_valid_different_names() {
        let mut q = DnsQuestion::new(2);
        q.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "www.example.com",
        ))
        .unwrap();
        q.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_AAAA,
            "www.example.org",
        ))
        .unwrap();
        assert!(!q.is_valid_for_query());
    }

    #[test]
    fn test_is_equal() {
        let q1 = DnsQuestion::new_address(2, "www.example.com");
        let q2 = DnsQuestion::new_address(2, "www.EXAMPLE.com");
        assert!(q1.is_equal(&q2));

        let q3 = DnsQuestion::new_address(2, "www.example.org");
        assert!(!q1.is_equal(&q3));
    }

    #[test]
    fn test_is_equal_different_count() {
        let q1 = DnsQuestion::new_address(2, "www.example.com");
        let mut q2 = DnsQuestion::new(2);
        q2.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "www.example.com",
        ))
        .unwrap();
        q2.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_AAAA,
            "www.example.com",
        ))
        .unwrap();
        assert!(!q1.is_equal(&q2));
    }

    #[test]
    fn test_cname_redirect() {
        let q = DnsQuestion::new_address(2, "www.example.com");
        let mut rr = DnsResourceRecord::new(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_CNAME,
            "www.example.com",
        ));
        rr.cname_target = Some("example.com".to_string());
        let redirected = q.cname_redirect(&rr).unwrap();
        assert!(redirected.contains_key(&DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "example.com"
        )));
    }

    #[test]
    fn test_dname_redirect() {
        let q = DnsQuestion::new_address(2, "www.example.com");
        let mut rr = DnsResourceRecord::new(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_DNAME,
            "example.com",
        ));
        rr.dname_target = Some("v2.example.com".to_string());
        let redirected = q.cname_redirect(&rr).unwrap();
        assert!(redirected.contains_key(&DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "www.v2.example.com"
        )));
    }

    #[test]
    fn test_first_name() {
        let mut q = DnsQuestion::new(2);
        q.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "www.example.com",
        ))
        .unwrap();
        q.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "mail.example.com",
        ))
        .unwrap();
        assert_eq!(q.first_name(), Some("www.example.com"));
    }

    #[test]
    fn test_merge() {
        let mut a = DnsQuestion::new(2);
        a.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "www.example.com",
        ))
        .unwrap();
        let mut b = DnsQuestion::new(2);
        b.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_AAAA,
            "www.example.com",
        ))
        .unwrap();
        b.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_TXT,
            "www.example.com",
        ))
        .unwrap();
        let merged = a.merge(&b);
        assert_eq!(merged.size(), 3);
    }

    #[test]
    fn test_dump() {
        let mut q = DnsQuestion::new(3);
        q.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_A,
            "www.example.com",
        ))
        .unwrap();
        q.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_AAAA,
            "www.example.com",
        ))
        .unwrap();
        q.add(DnsResourceKey::new(
            DNS_CLASS_IN,
            DNS_TYPE_TXT,
            "www.example.com",
        ))
        .unwrap();
        let dump = q.dump();
        assert!(dump.contains("www.example.com IN A"));
        assert!(dump.contains("www.example.com IN AAAA"));
        assert!(dump.contains("www.example.com IN TXT"));
    }
}
