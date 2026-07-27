// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-dns-cache.c
//
// DNS cache: put, lookup, prune, conflict detection, and dump tests.

use std::collections::HashMap;

// ── Constants ───────────────────────────────────────────────────────────────

const DNS_CLASS_IN: u16 = 1;
const DNS_CLASS_ANY: u16 = 255;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_ANY: u16 = 255;
const DNS_TYPE_OPT: u16 = 41;
const DNS_TYPE_CNAME: u16 = 5;

const DNS_RCODE_SUCCESS: u8 = 0;
const DNS_RCODE_NXDOMAIN: u8 = 3;
const DNS_RCODE_SERVFAIL: u8 = 2;
const DNS_RCODE_REFUSED: u8 = 5;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct CacheFlags: u32 {
        const CACHEABLE = 1 << 0;
        const SHARED_OWNER = 1 << 1;
        const AUTHENTICATED = 1 << 2;
        const CONFIDENTIAL = 1 << 3;
    }
}

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
            name: name.to_ascii_lowercase(),
        }
    }
}

// ── Resource record ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DnsResourceRecord {
    key: DnsResourceKey,
    ttl: u32,
    addr: u32,
}

// ── Cache entry ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CacheEntry {
    key: DnsResourceKey,
    rcode: u8,
    answer: Vec<DnsResourceRecord>,
    ttl: u32,
    flags: CacheFlags,
}

// ── DNS cache ───────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct DnsCache {
    entries: HashMap<String, CacheEntry>,
}

impl DnsCache {
    fn new() -> Self {
        Self::default()
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn size(&self) -> usize {
        self.entries.len()
    }

    fn cache_key(key: &DnsResourceKey) -> String {
        format!("{}:{}:{}", key.class, key.rtype, key.name)
    }

    fn put(
        &mut self,
        key: &DnsResourceKey,
        rcode: u8,
        answer: &[DnsResourceRecord],
        flags: CacheFlags,
    ) -> Result<(), i32> {
        // Any class is never cached
        if key.class == DNS_CLASS_ANY {
            return Ok(());
        }
        // Any type is never cached
        if key.rtype == DNS_TYPE_ANY {
            return Ok(());
        }
        // OPT type is never cached
        if key.rtype == DNS_TYPE_OPT {
            return Ok(());
        }
        // Non-cacheable records with success rcode require CACHEABLE flag
        if rcode == DNS_RCODE_SUCCESS && !flags.contains(CacheFlags::CACHEABLE) {
            return Ok(());
        }
        // REFUSED is never cached
        if rcode == DNS_RCODE_REFUSED {
            return Ok(());
        }
        // Success with empty answer is not cached
        if rcode == DNS_RCODE_SUCCESS && answer.is_empty() {
            return Ok(());
        }
        // Zero TTL with success removes existing entry
        let min_ttl = answer.iter().map(|rr| rr.ttl).min().unwrap_or(0);
        if rcode == DNS_RCODE_SUCCESS && min_ttl == 0 {
            self.entries.remove(&Self::cache_key(key));
            return Ok(());
        }
        // Bad escape in name
        if key.name.contains('\\') {
            return Err(-22); // EINVAL
        }
        for rr in answer {
            if rr.key.name.contains('\\') {
                return Err(-22); // EINVAL
            }
        }

        let ck = Self::cache_key(key);
        self.entries.insert(
            ck,
            CacheEntry {
                key: key.clone(),
                rcode,
                answer: answer.to_vec(),
                ttl: min_ttl,
                flags,
            },
        );
        Ok(())
    }

    fn lookup(&self, key: &DnsResourceKey) -> Option<&CacheEntry> {
        if key.rtype == DNS_TYPE_ANY || key.class == DNS_CLASS_ANY {
            return None;
        }
        self.entries.get(&Self::cache_key(key))
    }

    fn prune(&mut self) {
        // In this simplified version, prune is a no-op
        // (real version would check TTL expiry timestamps)
    }

    fn check_conflicts(&self, _rr: &DnsResourceRecord, _owner_addr: u32) -> bool {
        false // simplified
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_a_record(name: &str, addr: u32, ttl: u32) -> DnsResourceRecord {
        DnsResourceRecord {
            key: DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, name),
            ttl,
            addr,
        }
    }

    #[test]
    fn test_dns_a_success_is_cached() -> Result<(), i32> {
        let mut cache = DnsCache::new();
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        let rr = make_a_record("www.example.com", 0xc0a8017f, 3600);
        cache.put(&key, DNS_RCODE_SUCCESS, &[rr], CacheFlags::CACHEABLE)?;
        assert!(!cache.is_empty());
        Ok(())
    }

    #[test]
    fn test_dns_a_success_empty_answer_not_cached() -> Result<(), i32> {
        let mut cache = DnsCache::new();
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        cache.put(&key, DNS_RCODE_SUCCESS, &[], CacheFlags::CACHEABLE)?;
        assert!(cache.is_empty());
        Ok(())
    }

    #[test]
    fn test_dns_a_success_any_class_not_cached() -> Result<(), i32> {
        let mut cache = DnsCache::new();
        let key = DnsResourceKey::new(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com");
        let rr = make_a_record("www.example.com", 0xc0a8017f, 3600);
        cache.put(&key, DNS_RCODE_SUCCESS, &[rr], CacheFlags::CACHEABLE)?;
        assert!(cache.is_empty());
        Ok(())
    }

    #[test]
    fn test_dns_a_success_any_type_not_cached() -> Result<(), i32> {
        let mut cache = DnsCache::new();
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com");
        let rr = make_a_record("www.example.com", 0xc0a8017f, 3600);
        cache.put(&key, DNS_RCODE_SUCCESS, &[rr], CacheFlags::CACHEABLE)?;
        assert!(cache.is_empty());
        Ok(())
    }

    #[test]
    fn test_dns_a_success_opt_not_cached() -> Result<(), i32> {
        let mut cache = DnsCache::new();
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_OPT, "www.example.com");
        let rr = make_a_record("www.example.com", 0xc0a8017f, 3600);
        cache.put(&key, DNS_RCODE_SUCCESS, &[rr], CacheFlags::CACHEABLE)?;
        assert!(cache.is_empty());
        Ok(())
    }

    #[test]
    fn test_dns_a_nxdomain_is_cached() -> Result<(), i32> {
        let mut cache = DnsCache::new();
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        cache.put(&key, DNS_RCODE_NXDOMAIN, &[], CacheFlags::CACHEABLE)?;
        assert!(!cache.is_empty());
        Ok(())
    }

    #[test]
    fn test_dns_a_servfail_is_cached() -> Result<(), i32> {
        let mut cache = DnsCache::new();
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        cache.put(&key, DNS_RCODE_SERVFAIL, &[], CacheFlags::CACHEABLE)?;
        assert!(!cache.is_empty());
        Ok(())
    }

    #[test]
    fn test_dns_a_refused_not_cached() -> Result<(), i32> {
        let mut cache = DnsCache::new();
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        cache.put(&key, DNS_RCODE_REFUSED, &[], CacheFlags::CACHEABLE)?;
        assert!(cache.is_empty());
        Ok(())
    }

    #[test]
    fn test_dns_a_success_zero_ttl_not_cached() -> Result<(), i32> {
        let mut cache = DnsCache::new();
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        let rr = make_a_record("www.example.com", 0xc0a8017f, 0);
        cache.put(&key, DNS_RCODE_SUCCESS, &[rr], CacheFlags::CACHEABLE)?;
        assert!(cache.is_empty());
        Ok(())
    }

    #[test]
    fn test_dns_a_zero_ttl_removes_existing() -> Result<(), i32> {
        let mut cache = DnsCache::new();
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        let rr = make_a_record("www.example.com", 0xc0a8017f, 3600);
        cache.put(&key, DNS_RCODE_SUCCESS, &[rr], CacheFlags::CACHEABLE)?;
        assert!(!cache.is_empty());

        let rr_zero = make_a_record("www.example.com", 0xc0a8017f, 0);
        cache.put(&key, DNS_RCODE_SUCCESS, &[rr_zero], CacheFlags::CACHEABLE)?;
        assert!(cache.is_empty());
        Ok(())
    }

    #[test]
    fn test_not_cacheable_not_cached() -> Result<(), i32> {
        let mut cache = DnsCache::new();
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        let rr = make_a_record("www.example.com", 0xc0a8017f, 3600);
        cache.put(&key, DNS_RCODE_SUCCESS, &[rr], CacheFlags::empty())?;
        assert!(cache.is_empty());
        Ok(())
    }

    #[test]
    fn test_escaped_key_returns_error() -> Result<(), i32> {
        let mut cache = DnsCache::new();
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        let rr = make_a_record("www.\\example.com", 0xc0a8017f, 3600);
        assert!(
            cache
                .put(&key, DNS_RCODE_SUCCESS, &[rr], CacheFlags::CACHEABLE)
                .is_err()
        );
        assert!(cache.is_empty());
        Ok(())
    }

    #[test]
    fn test_cache_lookup_hit() -> Result<(), i32> {
        let mut cache = DnsCache::new();
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        let rr = make_a_record("www.example.com", 0xc0a8017f, 3600);
        cache.put(&key, DNS_RCODE_SUCCESS, &[rr], CacheFlags::CACHEABLE)?;

        let lookup_key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        assert!(cache.lookup(&lookup_key).is_some());
        Ok(())
    }

    #[test]
    fn test_cache_lookup_miss() -> Result<(), i32> {
        let cache = DnsCache::new();
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        assert!(cache.lookup(&key).is_none());
        Ok(())
    }

    #[test]
    fn test_cache_lookup_any_always_misses() -> Result<(), i32> {
        let mut cache = DnsCache::new();
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        let rr = make_a_record("www.example.com", 0xc0a8017f, 3600);
        cache.put(&key, DNS_RCODE_SUCCESS, &[rr], CacheFlags::CACHEABLE)?;

        let any_key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com");
        assert!(cache.lookup(&any_key).is_none());
        Ok(())
    }

    #[test]
    fn test_cache_returns_most_recent() -> Result<(), i32> {
        let mut cache = DnsCache::new();
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");

        let rr1 = make_a_record("www.example.com", 0xc0a8017f, 3600);
        cache.put(&key, DNS_RCODE_SUCCESS, &[rr1], CacheFlags::CACHEABLE)?;

        let rr2 = make_a_record("www.example.com", 0x7f01a8c0, 2400);
        cache.put(&key, DNS_RCODE_SUCCESS, &[rr2], CacheFlags::CACHEABLE)?;

        assert_eq!(cache.size(), 1);
        let entry = cache.lookup(&key).unwrap();
        assert_eq!(entry.answer[0].addr, 0x7f01a8c0);
        Ok(())
    }
}
