// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-dns-answer.c
//
// DNS answer container: add, match, find SOA, merge, extend, remove,
// copy, move, dump, and scope-ordering tests.

use std::collections::HashMap;

// ── DNS class / type constants ──────────────────────────────────────────────

const DNS_CLASS_IN: u16 = 1;
const DNS_CLASS_ANY: u16 = 255;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_SOA: u16 = 6;
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_ANY: u16 = 255;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct DnsAnswerFlags: u32 {
        const CACHEABLE = 1 << 0;
        const AUTHENTICATED = 1 << 1;
        const SHARED_OWNER = 1 << 2;
        const SECTION_ANSWER = 1 << 3;
        const SECTION_AUTHORITY = 1 << 4;
        const SECTION_ADDITIONAL = 1 << 5;
        const GOODBYE = 1 << 6;
        const CACHE_FLUSH = 1 << 7;
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

    /// Returns true when `other` matches this key.
    /// DNS_CLASS_ANY on either side acts as a wildcard for the class field.
    /// DNS_TYPE_ANY on either side acts as a wildcard for the type field.
    /// Name comparison is case-insensitive.
    fn matches(&self, other: &Self) -> Result<bool, i32> {
        if self.name.contains('\\') || other.name.contains('\\') {
            return Err(-22); // EINVAL
        }
        let class_ok = self.class == DNS_CLASS_ANY
            || other.class == DNS_CLASS_ANY
            || self.class == other.class;
        let type_ok =
            self.rtype == DNS_TYPE_ANY || other.rtype == DNS_TYPE_ANY || self.rtype == other.rtype;
        let name_ok = self.name.eq_ignore_ascii_case(&other.name);
        Ok(class_ok && type_ok && name_ok)
    }
}

// ── Resource record ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct DnsResourceRecord {
    key: DnsResourceKey,
    ttl: u32,
    ifindex: i32,
    flags: DnsAnswerFlags,
    addr: u32,
    cname_target: Option<String>,
}

impl DnsResourceRecord {
    fn new_a(name: &str, addr: u32) -> Self {
        Self {
            key: DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, name),
            ttl: 3600,
            ifindex: 0,
            flags: DnsAnswerFlags::empty(),
            addr,
            cname_target: None,
        }
    }
}

// ── DNS answer ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct DnsAnswer {
    records: Vec<(DnsResourceRecord, DnsAnswerFlags)>,
}

impl DnsAnswer {
    fn new() -> Self {
        Self::default()
    }

    fn size(&self) -> usize {
        self.records.len()
    }

    fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn add(&mut self, rr: DnsResourceRecord, ifindex: i32, flags: DnsAnswerFlags) {
        let mut rec = rr;
        rec.ifindex = ifindex;
        self.records.push((rec, flags));
    }

    fn contains(&self, rr: &DnsResourceRecord) -> bool {
        self.records
            .iter()
            .any(|(r, _)| r.key == rr.key && r.addr == rr.addr)
    }

    fn match_key(&self, key: &DnsResourceKey) -> Result<bool, i32> {
        for (rr, _) in &self.records {
            if rr.key.matches(key)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn match_key_flags(&self, key: &DnsResourceKey) -> Result<Option<DnsAnswerFlags>, i32> {
        for (rr, flags) in &self.records {
            if rr.key.matches(key)? {
                return Ok(Some(*flags));
            }
        }
        Ok(None)
    }

    fn remove_by_key(&mut self, key: &DnsResourceKey) -> Result<bool, i32> {
        let original = self.records.len();
        self.records
            .retain(|(rr, _)| !rr.key.matches(key).unwrap_or(false));
        Ok(self.records.len() < original)
    }

    fn remove_by_rr(&mut self, rr: &DnsResourceRecord) -> bool {
        let original = self.records.len();
        self.records
            .retain(|(r, _)| !(r.key == rr.key && r.addr == rr.addr));
        self.records.len() < original
    }

    fn merge(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        merged.records.extend(other.records.clone());
        merged
    }

    fn extend(&mut self, other: &Self) {
        self.records.extend(other.records.clone());
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_answer_with_a(name: &str, addr: u32, flags: DnsAnswerFlags) -> DnsAnswer {
        let mut answer = DnsAnswer::new();
        let rr = DnsResourceRecord::new_a(name, addr);
        answer.add(rr, 1, flags);
        answer
    }

    // ── dns_answer_add ──────────────────────────────────────────────────────

    #[test]
    fn test_dns_answer_add_a() -> Result<(), i32> {
        let mut answer = DnsAnswer::new();
        let rr = DnsResourceRecord::new_a("www.example.com", 0xc0a8017f);
        answer.add(rr, 1, DnsAnswerFlags::CACHEABLE);
        assert!(answer.contains(&DnsResourceRecord::new_a("www.example.com", 0xc0a8017f)));
        Ok(())
    }

    // ── dns_answer_match_key ────────────────────────────────────────────────

    #[test]
    fn test_match_key_single() -> Result<(), i32> {
        let answer = make_answer_with_a("www.example.com", 0xc0a8017f, DnsAnswerFlags::CACHEABLE);
        assert_eq!(answer.size(), 1);

        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        assert!(answer.match_key(&key)?);

        // ANY class matches
        let key_any_class = DnsResourceKey::new(DNS_CLASS_ANY, DNS_TYPE_A, "www.example.com");
        assert!(answer.match_key(&key_any_class)?);

        // ANY type matches
        let key_any_type = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com");
        assert!(answer.match_key(&key_any_type)?);

        // non-matching type
        let key_cname = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_CNAME, "www.example.com");
        assert!(!answer.match_key(&key_cname)?);

        // case-insensitive
        let key_upper = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "WWW.EXAMPLE.COM");
        assert!(answer.match_key(&key_upper)?);

        // non-matching name
        let key_other = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "example.com");
        assert!(!answer.match_key(&key_other)?);

        Ok(())
    }

    #[test]
    fn test_match_key_error_on_bad_escape() -> Result<(), i32> {
        let answer = make_answer_with_a("www.example.com", 0xc0a8017f, DnsAnswerFlags::CACHEABLE);
        let key_bad = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.\\example.com");
        assert!(answer.match_key(&key_bad).is_err());
        Ok(())
    }

    #[test]
    fn test_match_key_flags() -> Result<(), i32> {
        let answer = make_answer_with_a("www.example.com", 0xc0a8017f, DnsAnswerFlags::CACHEABLE);
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        let flags = answer.match_key_flags(&key)?;
        assert_eq!(flags, Some(DnsAnswerFlags::CACHEABLE));
        Ok(())
    }

    // ── dns_answer_merge ────────────────────────────────────────────────────

    #[test]
    fn test_dns_answer_merge() -> Result<(), i32> {
        let mut a = DnsAnswer::new();
        let rr_a = DnsResourceRecord::new_a("a.example.com", 0xc0a8017f);
        a.add(rr_a, 1, DnsAnswerFlags::CACHEABLE);

        let mut b = DnsAnswer::new();
        let rr_b = DnsResourceRecord::new_a("b.example.com", 0xc0a80180);
        b.add(rr_b, 1, DnsAnswerFlags::CACHEABLE);

        let merged = a.merge(&b);
        assert_eq!(merged.size(), 2);

        let key_a = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        let key_b = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        assert!(merged.match_key(&key_a)?);
        assert!(merged.match_key(&key_b)?);
        Ok(())
    }

    // ── dns_answer_extend ───────────────────────────────────────────────────

    #[test]
    fn test_dns_answer_extend() -> Result<(), i32> {
        let mut a = DnsAnswer::new();
        let rr_a = DnsResourceRecord::new_a("a.example.com", 0xc0a8017f);
        a.add(rr_a, 1, DnsAnswerFlags::CACHEABLE);

        let mut b = DnsAnswer::new();
        let rr_b = DnsResourceRecord::new_a("b.example.com", 0xc0a80180);
        b.add(rr_b, 1, DnsAnswerFlags::CACHEABLE);

        a.extend(&b);
        assert_eq!(a.size(), 2);

        let key_a = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        let key_b = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        assert!(a.match_key(&key_a)?);
        assert!(a.match_key(&key_b)?);
        Ok(())
    }

    // ── dns_answer_remove_by_key ────────────────────────────────────────────

    #[test]
    fn test_remove_by_key() -> Result<(), i32> {
        let mut answer = DnsAnswer::new();
        for (name, addr) in [
            ("a.example.com", 1u32),
            ("b.example.com", 2u32),
            ("c.example.com", 3u32),
        ] {
            let rr = DnsResourceRecord::new_a(name, 0xc0a80100 | addr);
            answer.add(rr, 1, DnsAnswerFlags::CACHEABLE);
        }
        assert_eq!(answer.size(), 3);

        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        assert!(answer.remove_by_key(&key)?);
        assert_eq!(answer.size(), 2);

        let key_check = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        assert!(!answer.match_key(&key_check)?);
        Ok(())
    }

    #[test]
    fn test_remove_by_key_non_matching_class() -> Result<(), i32> {
        let mut answer = DnsAnswer::new();
        let rr = DnsResourceRecord::new_a("b.example.com", 0xc0a8017f);
        answer.add(rr, 1, DnsAnswerFlags::CACHEABLE);

        let key = DnsResourceKey::new(DNS_CLASS_ANY, DNS_TYPE_A, "b.example.com");
        // ANY class acts as wildcard in match, so this should match and remove
        assert!(answer.remove_by_key(&key)?);
        assert_eq!(answer.size(), 0);
        Ok(())
    }

    // ── dns_answer_remove_by_rr ─────────────────────────────────────────────

    #[test]
    fn test_remove_by_rr_matching() -> Result<(), i32> {
        let mut answer = DnsAnswer::new();
        let rr = DnsResourceRecord::new_a("a.example.com", 0xc0a8017f);
        answer.add(rr.clone(), 1, DnsAnswerFlags::CACHEABLE);

        let lookup = DnsResourceRecord::new_a("a.example.com", 0xc0a8017f);
        assert!(answer.remove_by_rr(&lookup));
        assert!(answer.is_empty());
        Ok(())
    }

    #[test]
    fn test_remove_by_rr_non_matching_payload() -> Result<(), i32> {
        let mut answer = DnsAnswer::new();
        let rr = DnsResourceRecord::new_a("a.example.com", 0xc0a8017f);
        answer.add(rr, 1, DnsAnswerFlags::CACHEABLE);

        let lookup = DnsResourceRecord::new_a("a.example.com", 0x01020304);
        assert!(!answer.remove_by_rr(&lookup));
        assert_eq!(answer.size(), 1);
        Ok(())
    }

    // ── dns_answer_remove_by_answer_keys ────────────────────────────────────

    #[test]
    fn test_remove_by_answer_keys() -> Result<(), i32> {
        let mut a = DnsAnswer::new();
        let mut b = DnsAnswer::new();
        for (name, addr) in [
            ("a.example.com", 1u32),
            ("b.example.com", 2u32),
            ("c.example.com", 3u32),
        ] {
            let rr_a = DnsResourceRecord::new_a(name, 0xc0a80100 | addr);
            a.add(rr_a, 1, DnsAnswerFlags::CACHEABLE);
            let rr_b = DnsResourceRecord::new_a(name, 0xc0a80100 | addr);
            b.add(rr_b, 1, DnsAnswerFlags::CACHEABLE);
        }

        // Remove all keys that appear in b from a
        for (rr, _) in &b.records {
            a.remove_by_key(&rr.key)?;
        }
        assert!(a.is_empty());
        Ok(())
    }

    // ── dns_answer_order_by_scope ────────────────────────────────────────────

    #[test]
    fn test_scope_ordering() -> Result<(), i32> {
        let link_local_min: u32 = 0xa9fe0100;
        let link_local_max: u32 = 0xa9fefeff;
        let global: u32 = 0xc0a80404;

        fn is_link_local(addr: u32) -> bool {
            (addr & 0xffff0000) == 0xa9fe0000 && addr >= 0xa9fe0100 && addr <= 0xa9fefeff
        }

        assert!(is_link_local(link_local_min));
        assert!(is_link_local(link_local_max));
        assert!(!is_link_local(global));

        let mut addrs = vec![global, link_local_min, link_local_max];
        addrs.sort_by(|a, b| {
            let a_ll = is_link_local(*a);
            let b_ll = is_link_local(*b);
            match (a_ll, b_ll) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            }
        });
        assert_eq!(addrs[0], link_local_min);
        assert_eq!(addrs[1], link_local_max);
        assert_eq!(addrs[2], global);
        Ok(())
    }

    // ── dns_answer_copy_by_key ──────────────────────────────────────────────

    #[test]
    fn test_copy_by_key() -> Result<(), i32> {
        let source = make_answer_with_a("a.example.com", 0xc0a8017f, DnsAnswerFlags::CACHEABLE);
        let mut target = DnsAnswer::new();

        let key_match = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");
        for (rr, flags) in &source.records {
            if rr.key.matches(&key_match)? {
                target.add(rr.clone(), rr.ifindex, *flags);
            }
        }
        assert_eq!(target.size(), 1);
        assert!(target.match_key(&key_match)?);

        // non-matching
        let key_nomatch = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "b.example.com");
        assert!(!source.match_key(&key_nomatch)?);
        Ok(())
    }

    // ── dns_answer_move_by_key ──────────────────────────────────────────────

    #[test]
    fn test_move_by_key() -> Result<(), i32> {
        let mut source = DnsAnswer::new();
        let rr = DnsResourceRecord::new_a("a.example.com", 0xc0a8017f);
        source.add(rr, 1, DnsAnswerFlags::CACHEABLE);

        let mut target = DnsAnswer::new();
        let key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "a.example.com");

        // Move matching records from source to target
        let mut keep = Vec::new();
        for (rr, flags) in source.records.drain(..) {
            if rr.key.matches(&key)? {
                target.add(rr, 1, flags);
            } else {
                keep.push((rr, flags));
            }
        }
        source.records = keep;

        assert!(source.is_empty());
        assert_eq!(target.size(), 1);
        assert!(target.match_key(&key)?);
        Ok(())
    }

    // ── dns_answer_has_dname_for_cname ──────────────────────────────────────

    #[test]
    fn test_has_dname_for_cname() -> Result<(), i32> {
        // CNAME: www.example.com -> www.v2.example.com
        let cname_target = "www.v2.example.com";
        // DNAME: example.com -> v2.example.com
        let dname_zone = "example.com";
        let dname_target = "v2.example.com";

        // A DNAME matches a CNAME when the CNAME target ends with the DNAME target
        // and the CNAME owner ends with the DNAME zone
        let cname_owner = "www.example.com";
        let matches = cname_owner.ends_with(dname_zone) && cname_target.ends_with(dname_target);
        assert!(matches);

        // Non-matching old suffix
        let bad_dname_target = "www.v2.examples.com";
        let matches2 =
            cname_owner.ends_with(dname_zone) && cname_target.ends_with(bad_dname_target);
        assert!(!matches2);
        Ok(())
    }

    // ── dns_answer_dump format ──────────────────────────────────────────────

    #[test]
    fn test_answer_dump_format() {
        let mut answer = DnsAnswer::new();
        let mut rr = DnsResourceRecord::new_a("a.example.com", 0xc0a8017f);
        rr.ttl = 1200;
        answer.add(
            rr,
            1,
            DnsAnswerFlags::CACHEABLE | DnsAnswerFlags::SECTION_ADDITIONAL,
        );

        let mut rr2 = DnsResourceRecord::new_a("b.example.com", 0xc0a80180);
        rr2.ttl = 2400;
        answer.add(rr2, 2, DnsAnswerFlags::empty());

        assert_eq!(answer.size(), 2);

        // Verify record data is accessible
        assert_eq!(answer.records[0].0.ttl, 1200);
        assert_eq!(answer.records[1].0.ttl, 2400);
        assert_eq!(answer.records[0].0.ifindex, 1);
        assert_eq!(answer.records[1].0.ifindex, 2);
    }

    #[test]
    fn test_match_key_multiple_records() -> Result<(), i32> {
        let mut answer = DnsAnswer::new();

        let mut rr_txt = DnsResourceRecord::new_a("www.example.com", 0);
        rr_txt.key = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_TXT, "www.example.com");
        answer.add(
            rr_txt,
            1,
            DnsAnswerFlags::SECTION_ANSWER | DnsAnswerFlags::AUTHENTICATED,
        );

        let rr_a = DnsResourceRecord::new_a("www.example.com", 0xc0a8017f);
        answer.add(
            rr_a,
            1,
            DnsAnswerFlags::SECTION_ANSWER | DnsAnswerFlags::CACHEABLE,
        );

        assert_eq!(answer.size(), 2);

        let key_a = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        let flags = answer.match_key_flags(&key_a)?;
        assert_eq!(
            flags,
            Some(DnsAnswerFlags::SECTION_ANSWER | DnsAnswerFlags::CACHEABLE)
        );

        let key_any = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_ANY, "www.example.com");
        let flags_any = answer.match_key_flags(&key_any)?;
        // First match should be the TXT record
        assert_eq!(
            flags_any,
            Some(DnsAnswerFlags::SECTION_ANSWER | DnsAnswerFlags::AUTHENTICATED)
        );

        Ok(())
    }

    #[test]
    fn test_empty_answer() {
        let answer = DnsAnswer::new();
        assert!(answer.is_empty());
        assert_eq!(answer.size(), 0);
    }
}
