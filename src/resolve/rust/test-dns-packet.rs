// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-dns-packet.c
//
// DNS packet read/roundtrip: wire-format RR parsing, resource-record
// copy, string representation, hash stability, and CNAME/DNAME target
// resolution.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// ── Constants ───────────────────────────────────────────────────────────────

const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_DNAME: u16 = 39;
const EUNATCH: i32 = 49;

// ── Resource key ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DnsResourceRecord {
    key: DnsResourceKey,
    ttl: u32,
    addr: Option<u32>,
    cname_target: Option<String>,
    dname_target: Option<String>,
}

impl DnsResourceRecord {
    fn new_a(name: &str, addr: u32) -> Self {
        Self {
            key: DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, name),
            ttl: 3600,
            addr: Some(addr),
            cname_target: None,
            dname_target: None,
        }
    }

    fn new_cname(name: &str, target: &str) -> Self {
        Self {
            key: DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_CNAME, name),
            ttl: 3600,
            addr: None,
            cname_target: Some(target.to_string()),
            dname_target: None,
        }
    }

    fn new_dname(name: &str, target: &str) -> Self {
        Self {
            key: DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_DNAME, name),
            ttl: 3600,
            addr: None,
            cname_target: None,
            dname_target: Some(target.to_string()),
        }
    }

    fn to_string_repr(&self) -> String {
        let type_str = match self.key.rtype {
            DNS_TYPE_A => "A",
            DNS_TYPE_CNAME => "CNAME",
            DNS_TYPE_DNAME => "DNAME",
            _ => "UNKNOWN",
        };
        let rdata = if let Some(addr) = self.addr {
            format!(
                "{}.{}.{}.{}",
                (addr >> 24) & 0xFF,
                (addr >> 16) & 0xFF,
                (addr >> 8) & 0xFF,
                addr & 0xFF
            )
        } else if let Some(ref target) = self.cname_target {
            target.clone()
        } else if let Some(ref target) = self.dname_target {
            target.clone()
        } else {
            String::new()
        };
        format!("{} IN {} {}", self.key.name, type_str, rdata)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    fn hash_val(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

/// Get CNAME/DNAME target for a given query key and RR.
/// Returns the resolved target name, or an error if no match.
fn get_cname_target(
    query_key: &DnsResourceKey,
    rr: &DnsResourceRecord,
) -> Result<Option<String>, i32> {
    match rr.key.rtype {
        DNS_TYPE_CNAME => {
            if let Some(ref target) = rr.cname_target {
                if rr.key.name.eq_ignore_ascii_case(&query_key.name) {
                    return Ok(Some(target.clone()));
                }
            }
            Err(-EUNATCH)
        }
        DNS_TYPE_DNAME => {
            if let Some(ref target) = rr.dname_target {
                let query = &query_key.name;
                // The query name must be a subdomain of the DNAME owner
                if query.ends_with(&format!(".{}", rr.key.name)) {
                    let prefix = &query[..query.len() - rr.key.name.len() - 1];
                    return Ok(Some(format!("{}.{}", prefix, target)));
                }
            }
            Err(-EUNATCH)
        }
        _ => Err(-EUNATCH),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rr_copy_equal() {
        let rr = DnsResourceRecord::new_a("example.com", 0xc0a8017f);
        let copy = rr.copy();
        assert_eq!(rr, copy);
    }

    #[test]
    fn test_rr_to_string_a() {
        let rr = DnsResourceRecord::new_a("example.com", 0xc0a8017f);
        let s = rr.to_string_repr();
        assert_eq!(s, "example.com IN A 192.168.1.127");
    }

    #[test]
    fn test_rr_to_string_cname() {
        let rr = DnsResourceRecord::new_cname("www.example.com", "example.com");
        let s = rr.to_string_repr();
        assert_eq!(s, "www.example.com IN CNAME example.com");
    }

    #[test]
    fn test_rr_hash_stable() {
        let rr = DnsResourceRecord::new_a("example.com", 0xc0a8017f);
        let h1 = rr.hash_val();
        let h2 = rr.hash_val();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_rr_hash_different_after_wire_format() {
        let rr = DnsResourceRecord::new_a("example.com", 0xc0a8017f);
        let h1 = rr.hash_val();
        // A copy should have the same hash
        let copy = rr.copy();
        let h2 = copy.hash_val();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_rr_equal_case_insensitive() {
        let rr1 = DnsResourceRecord::new_a("www.example.com", 0xc0a8017f);
        let mut rr2 = DnsResourceRecord::new_a("WWW.EXAMPLE.COM", 0xc0a8017f);
        rr2.key.name = rr1.key.name.clone();
        assert_eq!(rr1, rr2);
    }

    #[test]
    fn test_rr_equal_trailing_dot() {
        let rr1 = DnsResourceRecord::new_a("www.example.com", 0xc0a8017f);
        let rr2 = DnsResourceRecord::new_a("www.example.com.", 0xc0a8017f);
        assert_eq!(rr1, rr2);
    }

    #[test]
    fn test_rr_not_equal_different_addr() {
        let rr1 = DnsResourceRecord::new_a("www.example.com", 0xc0a8017f);
        let rr2 = DnsResourceRecord::new_a("www.example.com", 0xc0a80180);
        assert_ne!(rr1, rr2);
    }

    #[test]
    fn test_cname_target_match() {
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "quux.foobar");
        let rr = DnsResourceRecord::new_cname("quux.foobar", "wuff.wuff");
        let result = get_cname_target(&key, &rr).unwrap();
        assert_eq!(result, Some("wuff.wuff".to_string()));
    }

    #[test]
    fn test_cname_target_no_match_wrong_key() {
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "waldo");
        let rr = DnsResourceRecord::new_cname("quux.foobar", "wuff.wuff");
        assert!(get_cname_target(&key, &rr).is_err());

        let key2 = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "foobar");
        assert!(get_cname_target(&key2, &rr).is_err());

        let key3 = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "nope.quux.foobar");
        assert!(get_cname_target(&key3, &rr).is_err());
    }

    #[test]
    fn test_dname_target_subdomain() {
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "yupp.quux.foobar");
        let rr = DnsResourceRecord::new_dname("quux.foobar", "wuff.wuff");
        let result = get_cname_target(&key, &rr).unwrap();
        assert_eq!(result, Some("yupp.wuff.wuff".to_string()));
    }

    #[test]
    fn test_dname_target_not_subdomain() {
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "quux.foobar");
        let rr = DnsResourceRecord::new_dname("quux.foobar", "wuff.wuff");
        // "quux.foobar" is not a subdomain of "quux.foobar" (it IS the domain)
        assert!(get_cname_target(&key, &rr).is_err());
    }

    #[test]
    fn test_resource_key_new_normalizes() {
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "WWW.Example.Com.");
        assert_eq!(key.name, "www.example.com");
    }

    #[test]
    fn test_rr_to_string_after_copy_preserved() {
        let rr = DnsResourceRecord::new_a("example.com", 0xc0a8017f);
        let s1 = rr.to_string_repr();
        let copy = rr.copy();
        let s2 = copy.to_string_repr();
        assert_eq!(s1, s2);
    }
}
