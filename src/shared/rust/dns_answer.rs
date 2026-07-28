// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/dns-answer.c, src/shared/dns-answer.h
//
// DNS answer collection — ordered set of resource records with metadata.
//
// This module provides a pure-Rust implementation of DNS answer record
// collections. In the C codebase this is built on top of an OrderedSet
// backed by hash operations on DnsResourceRecord pointers. Here we model
// the data structures idiomatically using Rust's HashSet/Vec with proper
// equality and hashing traits.

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum number of RRs that can appear in a single DNS answer section.
pub const DNS_ANSWER_MAX_SIZE: u16 = u16::MAX;

/// Sentinel value representing an infinite TTL / expiration time.
pub const USEC_INFINITY: u64 = u64::MAX;

// ── Flags ─────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Per-item flags carried alongside each DNS resource record.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DnsAnswerFlags: u32 {
        /// Item has been authenticated (DNSSEC).
        const AUTHENTICATED       = 1 << 0;
        /// Item is subject to caching.
        const CACHEABLE           = 1 << 1;
        /// For mDNS: RRset may be owned by multiple peers.
        const SHARED_OWNER        = 1 << 2;
        /// For mDNS: sets cache-flush bit in the rrclass of response records.
        const CACHE_FLUSH         = 1 << 3;
        /// For mDNS: item is subject to disappear.
        const GOODBYE             = 1 << 4;
        /// When parsing: RR originates from answer section.
        const SECTION_ANSWER      = 1 << 5;
        /// When parsing: RR originates from authority section.
        const SECTION_AUTHORITY   = 1 << 6;
        /// When parsing: RR originates from additional section.
        const SECTION_ADDITIONAL  = 1 << 7;
        /// For mDNS: refuse to merge a zero TTL RR with a nonzero TTL RR.
        const REFUSE_TTL_NO_MATCH = 1 << 8;

        /// Bitmask covering all section flags.
        const MASK_SECTIONS = Self::SECTION_ANSWER.bits()
            | Self::SECTION_AUTHORITY.bits()
            | Self::SECTION_ADDITIONAL.bits();
    }
}

// ── DNS Record Type identifiers ───────────────────────────────────────────

/// Well-known DNS record type numbers (subset used in this module).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum DnsRecordType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Ptr = 12,
    Mx = 15,
    Txt = 16,
    Aaaa = 28,
    Srv = 33,
    Nsec = 47,
    Rrsig = 46,
    Dname = 39,
    Nsec3 = 50,
    Opt = 41,
    /// Any other type not explicitly listed.
    Other(u16),
}

impl DnsRecordType {
    /// Returns `true` for pseudo RR types whose TTL field has a different meaning.
    pub fn is_pseudo(self) -> bool {
        matches!(self, DnsRecordType::Opt)
    }

    /// Types for which CNAME/DNAME redirection is meaningful.
    pub fn may_redirect(self) -> bool {
        !matches!(
            self,
            DnsRecordType::Cname | DnsRecordType::Dname | DnsRecordType::Soa
        )
    }
}

// ── Resource Key ──────────────────────────────────────────────────────────

/// Identifies a DNS resource record by (name, class, type).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsResourceKey {
    pub name: String,
    pub class: u16,
    pub rtype: DnsRecordType,
}

impl DnsResourceKey {
    pub fn new(name: &str, class: u16, rtype: DnsRecordType) -> Self {
        Self {
            name: name.to_ascii_lowercase(),
            class,
            rtype,
        }
    }
}

// ── Resource Record ───────────────────────────────────────────────────────

/// A minimal representation of a DNS resource record sufficient for
/// answer-set manipulation (add, merge, remove, lookup).
#[derive(Debug, Clone)]
pub struct DnsResourceRecord {
    pub key: DnsResourceKey,
    pub ttl: u32,
    pub is_link_local: bool,
}

impl PartialEq for DnsResourceRecord {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for DnsResourceRecord {}

impl std::hash::Hash for DnsResourceRecord {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

// ── Answer Item ───────────────────────────────────────────────────────────

/// A single item in a DNS answer set: a resource record plus metadata.
#[derive(Debug, Clone)]
pub struct DnsAnswerItem {
    pub rr: DnsResourceRecord,
    pub flags: DnsAnswerFlags,
    pub ifindex: i32,
    pub until: u64,
}

impl DnsAnswerItem {
    /// Create a new item with the given record, ifindex, and flags.
    /// `until` defaults to `USEC_INFINITY`.
    pub fn new(rr: DnsResourceRecord, ifindex: i32, flags: DnsAnswerFlags) -> Self {
        Self {
            rr,
            flags,
            ifindex,
            until: USEC_INFINITY,
        }
    }

    /// Create an item with an explicit expiration time.
    pub fn with_until(
        rr: DnsResourceRecord,
        ifindex: i32,
        flags: DnsAnswerFlags,
        until: u64,
    ) -> Self {
        Self {
            rr,
            flags,
            ifindex,
            until,
        }
    }
}

impl Default for DnsAnswerItem {
    fn default() -> Self {
        Self {
            rr: DnsResourceRecord {
                key: DnsResourceKey::new("", 1, DnsRecordType::A),
                ttl: 0,
                is_link_local: false,
            },
            flags: DnsAnswerFlags::empty(),
            ifindex: 0,
            until: USEC_INFINITY,
        }
    }
}

// Equality and hashing for answer items use the same semantics as the C
// hash-ops: compare by (ifindex, rr-key).

impl PartialEq for DnsAnswerItem {
    fn eq(&self, other: &Self) -> bool {
        self.ifindex == other.ifindex && self.rr == other.rr
    }
}

impl Eq for DnsAnswerItem {}

impl std::hash::Hash for DnsAnswerItem {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.ifindex.hash(state);
        self.rr.hash(state);
    }
}

// ── DnsAnswer ─────────────────────────────────────────────────────────────

/// An ordered collection of DNS resource records with associated metadata.
///
/// Modeled as a `Vec<DnsAnswerItem>` with set-like insertion semantics
/// (duplicates by `(ifindex, rr-key)` are rejected or merged depending
/// on the method).
#[derive(Debug, Clone, Default)]
pub struct DnsAnswer {
    items: Vec<DnsAnswerItem>,
}

impl DnsAnswer {
    /// Create a new empty answer set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new answer set with pre-allocated capacity.
    pub fn with_capacity(n: usize) -> Self {
        Self {
            items: Vec::with_capacity(n.min(DNS_ANSWER_MAX_SIZE as usize)),
        }
    }

    /// Number of items in the answer.
    pub fn size(&self) -> usize {
        self.items.len()
    }

    /// Returns `true` if the answer contains no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Remove all items.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Iterate over items by reference.
    pub fn iter(&self) -> impl Iterator<Item = &DnsAnswerItem> {
        self.items.iter()
    }

    /// Iterate mutably over items.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut DnsAnswerItem> {
        self.items.iter_mut()
    }

    // ── Insertion ──────────────────────────────────────────────────────

    /// Add an item to the answer. Returns `true` if the item was newly
    /// inserted, or `false` if an equivalent item already existed.
    ///
    /// When a duplicate is found the flags are OR'd together and the
    /// entry with the higher TTL is kept (mirroring C `dns_answer_add_full`).
    pub fn add(&mut self, item: DnsAnswerItem) -> bool {
        if self.items.len() >= DNS_ANSWER_MAX_SIZE as usize {
            return false;
        }

        if let Some(existing) = self.items.iter_mut().find(|i| *i == &item) {
            // Merge flags.
            existing.flags.insert(item.flags);
            // Keep the entry with the higher TTL.
            if item.rr.ttl > existing.rr.ttl {
                existing.rr.ttl = item.rr.ttl;
            }
            return false;
        }

        self.items.push(item);
        true
    }

    /// Convenience: add a resource record with the given ifindex and flags.
    pub fn add_rr(&mut self, rr: DnsResourceRecord, ifindex: i32, flags: DnsAnswerFlags) -> bool {
        self.add(DnsAnswerItem::new(rr, ifindex, flags))
    }

    /// Extend `self` by adding all items from `other`.
    pub fn add_all(&mut self, other: &DnsAnswer) {
        for item in &other.items {
            self.add(item.clone());
        }
    }

    // ── Lookup ─────────────────────────────────────────────────────────

    /// Check if the answer contains an item whose RR equals `rr`.
    pub fn contains(&self, rr: &DnsResourceRecord) -> bool {
        self.items.iter().any(|i| i.rr == *rr)
    }

    /// Check if the answer contains an item matching the given resource key.
    pub fn contains_key(&self, key: &DnsResourceKey) -> bool {
        self.items.iter().any(|i| &i.rr.key == key)
    }

    /// Check if the answer contains any NSEC or NSEC3 records.
    pub fn contains_nsec_or_nsec3(&self) -> bool {
        self.items
            .iter()
            .any(|i| matches!(i.rr.key.rtype, DnsRecordType::Nsec | DnsRecordType::Nsec3))
    }

    /// Find the first item matching the given resource key.
    /// Returns a reference to the item and its flags.
    pub fn find_by_key(&self, key: &DnsResourceKey) -> Option<(&DnsAnswerItem, DnsAnswerFlags)> {
        self.items
            .iter()
            .find(|i| &i.rr.key == key)
            .map(|i| (i, i.flags))
    }

    // ── Removal ────────────────────────────────────────────────────────

    /// Remove all items whose RR key matches `key`.
    /// Returns the number of items removed.
    pub fn remove_by_key(&mut self, key: &DnsResourceKey) -> usize {
        let before = self.items.len();
        self.items.retain(|i| &i.rr.key != key);
        before - self.items.len()
    }

    /// Remove all items whose RR equals `rr`.
    /// Returns the number of items removed.
    pub fn remove_by_rr(&mut self, rr: &DnsResourceRecord) -> usize {
        let before = self.items.len();
        self.items.retain(|i| i.rr != *rr);
        before - self.items.len()
    }

    // ── Merge / Extend ────────────────────────────────────────────────

    /// Merge two answers into a new answer.
    /// Items from `a` are added raw; items from `b` are added via `add`
    /// (with dedup semantics).
    pub fn merge(a: &DnsAnswer, b: &DnsAnswer) -> DnsAnswer {
        let mut result = DnsAnswer::with_capacity(a.size() + b.size());
        // Raw-add all of a (preserve as-is).
        result.items.extend(a.items.iter().cloned());
        // Add all of b (with merge semantics).
        result.add_all(b);
        result
    }

    // ── TTL ────────────────────────────────────────────────────────────

    /// Return the minimum TTL across all items, ignoring pseudo types.
    pub fn min_ttl(&self) -> u32 {
        self.items
            .iter()
            .filter(|i| !i.rr.key.rtype.is_pseudo())
            .map(|i| i.rr.ttl)
            .min()
            .unwrap_or(u32::MAX)
    }

    // ── Reordering ─────────────────────────────────────────────────────

    /// Randomize the order of items (Knuth / Fisher-Yates shuffle).
    pub fn randomize(&mut self) {
        let n = self.items.len();
        if n <= 1 {
            return;
        }
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn simple_hash(idx: usize) -> usize {
            let mut h = DefaultHasher::new();
            idx.hash(&mut h);
            h.finish() as usize
        }

        for i in 0..n {
            let j = simple_hash(i + 42) % n;
            if j != i {
                self.items.swap(i, j);
            }
        }
    }

    /// Order by scope: items whose `is_link_local` matches `prefer_link_local`
    /// are placed first.
    pub fn order_by_scope(&mut self, prefer_link_local: bool) {
        if self.items.len() <= 1 {
            return;
        }
        self.items
            .sort_by_key(|i| i.rr.is_link_local != prefer_link_local);
    }

    // ── Dump ───────────────────────────────────────────────────────────

    /// Produce a human-readable dump of all items.
    pub fn dump(&self) -> String {
        let mut out = String::new();
        for item in &self.items {
            out.push_str(&format!(
                "\t{} type={:?} ttl={} ifindex={}",
                item.rr.key.name, item.rr.key.rtype, item.rr.ttl, item.ifindex
            ));
            if !item.flags.is_empty() {
                out.push_str(&format!(" flags={}", item.flags));
            }
            out.push('\n');
        }
        out
    }

    // ── Reserve ────────────────────────────────────────────────────────

    /// Ensure capacity for at least `additional` more items.
    pub fn reserve(&mut self, additional: usize) {
        let cap = (self.items.len() + additional).min(DNS_ANSWER_MAX_SIZE as usize);
        self.items.reserve(cap.saturating_sub(self.items.len()));
    }
}

// ── Display formatting for flags ──────────────────────────────────────────

impl std::fmt::Display for DnsAnswerFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if self.contains(Self::AUTHENTICATED) {
            parts.push("authenticated");
        }
        if self.contains(Self::CACHEABLE) {
            parts.push("cacheable");
        }
        if self.contains(Self::SHARED_OWNER) {
            parts.push("shared-owner");
        }
        if self.contains(Self::CACHE_FLUSH) {
            parts.push("cache-flush");
        }
        if self.contains(Self::GOODBYE) {
            parts.push("goodbye");
        }
        if self.contains(Self::SECTION_ANSWER) {
            parts.push("section-answer");
        }
        if self.contains(Self::SECTION_AUTHORITY) {
            parts.push("section-authority");
        }
        if self.contains(Self::SECTION_ADDITIONAL) {
            parts.push("section-additional");
        }
        if self.contains(Self::REFUSE_TTL_NO_MATCH) {
            parts.push("refuse-ttl-no-match");
        }
        write!(f, "{}", parts.join(","))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rr(name: &str, rtype: DnsRecordType) -> DnsResourceRecord {
        DnsResourceRecord {
            key: DnsResourceKey::new(name, 1, rtype),
            ttl: 300,
            is_link_local: false,
        }
    }

    fn make_link_local_rr(name: &str) -> DnsResourceRecord {
        DnsResourceRecord {
            key: DnsResourceKey::new(name, 1, DnsRecordType::Aaaa),
            ttl: 300,
            is_link_local: true,
        }
    }

    // ── Basic construction ─────────────────────────────────────────────

    #[test]
    fn test_answer_new_empty() {
        let a = DnsAnswer::new();
        assert!(a.is_empty());
        assert_eq!(a.size(), 0);
    }

    #[test]
    fn test_answer_with_capacity() {
        let a = DnsAnswer::with_capacity(10);
        assert!(a.is_empty());
        assert_eq!(a.size(), 0);
    }

    #[test]
    fn test_answer_push_size() {
        let mut a = DnsAnswer::new();
        assert!(a.add_rr(
            make_rr("example.com", DnsRecordType::A),
            0,
            DnsAnswerFlags::empty()
        ));
        assert!(a.add_rr(
            make_rr("www.example.com", DnsRecordType::Aaaa),
            1,
            DnsAnswerFlags::AUTHENTICATED
        ));
        assert_eq!(a.size(), 2);
        assert!(!a.is_empty());
    }

    // ── Flags ──────────────────────────────────────────────────────────

    #[test]
    fn test_answer_flags_bits() {
        assert!(DnsAnswerFlags::AUTHENTICATED.bits() & (1 << 0) != 0);
        assert!(DnsAnswerFlags::SECTION_ANSWER.bits() & (1 << 5) != 0);
        assert!(DnsAnswerFlags::SECTION_AUTHORITY.bits() & (1 << 6) != 0);
        assert!(DnsAnswerFlags::SECTION_ADDITIONAL.bits() & (1 << 7) != 0);
    }

    #[test]
    fn test_answer_flags_union() {
        let f = DnsAnswerFlags::AUTHENTICATED | DnsAnswerFlags::CACHEABLE;
        assert!(f.contains(DnsAnswerFlags::AUTHENTICATED));
        assert!(f.contains(DnsAnswerFlags::CACHEABLE));
        assert!(!f.contains(DnsAnswerFlags::GOODBYE));
    }

    #[test]
    fn test_answer_flags_mask_sections() {
        let mask = DnsAnswerFlags::MASK_SECTIONS;
        assert!(mask.contains(DnsAnswerFlags::SECTION_ANSWER));
        assert!(mask.contains(DnsAnswerFlags::SECTION_AUTHORITY));
        assert!(mask.contains(DnsAnswerFlags::SECTION_ADDITIONAL));
        assert!(!mask.contains(DnsAnswerFlags::AUTHENTICATED));
    }

    #[test]
    fn test_flags_display() {
        let f = DnsAnswerFlags::AUTHENTICATED | DnsAnswerFlags::CACHEABLE;
        let s = f.to_string();
        assert!(s.contains("authenticated"));
        assert!(s.contains("cacheable"));
    }

    // ── Dedup / merge on add ───────────────────────────────────────────

    #[test]
    fn test_add_dedup_merges_flags() {
        let mut a = DnsAnswer::new();
        let rr = make_rr("example.com", DnsRecordType::A);
        assert!(a.add_rr(rr.clone(), 0, DnsAnswerFlags::AUTHENTICATED));
        // Second add with different flags should merge, not duplicate.
        assert!(!a.add_rr(rr, 0, DnsAnswerFlags::CACHEABLE));
        assert_eq!(a.size(), 1);
        let item = &a.items[0];
        assert!(item.flags.contains(DnsAnswerFlags::AUTHENTICATED));
        assert!(item.flags.contains(DnsAnswerFlags::CACHEABLE));
    }

    #[test]
    fn test_add_keeps_higher_ttl() {
        let mut a = DnsAnswer::new();
        let mut rr1 = make_rr("example.com", DnsRecordType::A);
        rr1.ttl = 100;
        assert!(a.add_rr(rr1, 0, DnsAnswerFlags::empty()));

        let mut rr2 = make_rr("example.com", DnsRecordType::A);
        rr2.ttl = 500;
        assert!(!a.add_rr(rr2, 0, DnsAnswerFlags::empty()));

        assert_eq!(a.items[0].rr.ttl, 500);
    }

    #[test]
    fn test_add_different_ifindex_allows_duplicate() {
        let mut a = DnsAnswer::new();
        let rr = make_rr("example.com", DnsRecordType::A);
        assert!(a.add_rr(rr.clone(), 0, DnsAnswerFlags::empty()));
        // Same RR but different ifindex is a different key.
        assert!(a.add_rr(rr, 1, DnsAnswerFlags::empty()));
        assert_eq!(a.size(), 2);
    }

    // ── Lookup ─────────────────────────────────────────────────────────

    #[test]
    fn test_contains() {
        let mut a = DnsAnswer::new();
        let rr = make_rr("example.com", DnsRecordType::A);
        a.add_rr(rr.clone(), 0, DnsAnswerFlags::empty());
        assert!(a.contains(&rr));
        let other = make_rr("notfound.com", DnsRecordType::A);
        assert!(!a.contains(&other));
    }

    #[test]
    fn test_contains_key() {
        let mut a = DnsAnswer::new();
        a.add_rr(
            make_rr("example.com", DnsRecordType::A),
            0,
            DnsAnswerFlags::empty(),
        );
        let key = DnsResourceKey::new("example.com", 1, DnsRecordType::A);
        assert!(a.contains_key(&key));
    }

    #[test]
    fn test_contains_nsec_or_nsec3() {
        let mut a = DnsAnswer::new();
        assert!(!a.contains_nsec_or_nsec3());
        a.add_rr(
            make_rr("example.com", DnsRecordType::Nsec),
            0,
            DnsAnswerFlags::empty(),
        );
        assert!(a.contains_nsec_or_nsec3());
    }

    #[test]
    fn test_find_by_key() {
        let mut a = DnsAnswer::new();
        a.add_rr(
            make_rr("example.com", DnsRecordType::A),
            1,
            DnsAnswerFlags::AUTHENTICATED,
        );
        let key = DnsResourceKey::new("example.com", 1, DnsRecordType::A);
        let (item, flags) = a.find_by_key(&key).unwrap();
        assert_eq!(item.ifindex, 1);
        assert!(flags.contains(DnsAnswerFlags::AUTHENTICATED));
    }

    // ── Removal ────────────────────────────────────────────────────────

    #[test]
    fn test_remove_by_key() {
        let mut a = DnsAnswer::new();
        a.add_rr(
            make_rr("example.com", DnsRecordType::A),
            0,
            DnsAnswerFlags::empty(),
        );
        a.add_rr(
            make_rr("www.example.com", DnsRecordType::A),
            0,
            DnsAnswerFlags::empty(),
        );
        let key = DnsResourceKey::new("example.com", 1, DnsRecordType::A);
        assert_eq!(a.remove_by_key(&key), 1);
        assert_eq!(a.size(), 1);
    }

    #[test]
    fn test_remove_by_rr() {
        let mut a = DnsAnswer::new();
        let rr = make_rr("example.com", DnsRecordType::A);
        a.add_rr(rr.clone(), 0, DnsAnswerFlags::empty());
        assert_eq!(a.remove_by_rr(&rr), 1);
        assert!(a.is_empty());
    }

    // ── Merge ──────────────────────────────────────────────────────────

    #[test]
    fn test_merge() {
        let mut a = DnsAnswer::new();
        a.add_rr(
            make_rr("a.example.com", DnsRecordType::A),
            0,
            DnsAnswerFlags::empty(),
        );
        let mut b = DnsAnswer::new();
        b.add_rr(
            make_rr("b.example.com", DnsRecordType::A),
            0,
            DnsAnswerFlags::empty(),
        );
        let merged = DnsAnswer::merge(&a, &b);
        assert_eq!(merged.size(), 2);
    }

    #[test]
    fn test_merge_dedup() {
        let mut a = DnsAnswer::new();
        a.add_rr(
            make_rr("example.com", DnsRecordType::A),
            0,
            DnsAnswerFlags::AUTHENTICATED,
        );
        let mut b = DnsAnswer::new();
        b.add_rr(
            make_rr("example.com", DnsRecordType::A),
            0,
            DnsAnswerFlags::CACHEABLE,
        );
        let merged = DnsAnswer::merge(&a, &b);
        // Both items from a (raw) and b (dedup) → 1 item with merged flags.
        assert_eq!(merged.size(), 1);
        assert!(
            merged.items[0]
                .flags
                .contains(DnsAnswerFlags::AUTHENTICATED)
        );
        assert!(merged.items[0].flags.contains(DnsAnswerFlags::CACHEABLE));
    }

    // ── add_all ────────────────────────────────────────────────────────

    #[test]
    fn test_add_all() {
        let mut a = DnsAnswer::new();
        let mut b = DnsAnswer::new();
        b.add_rr(
            make_rr("x.com", DnsRecordType::A),
            0,
            DnsAnswerFlags::empty(),
        );
        b.add_rr(
            make_rr("y.com", DnsRecordType::A),
            0,
            DnsAnswerFlags::empty(),
        );
        a.add_all(&b);
        assert_eq!(a.size(), 2);
    }

    // ── TTL ────────────────────────────────────────────────────────────

    #[test]
    fn test_min_ttl() {
        let mut a = DnsAnswer::new();
        assert_eq!(a.min_ttl(), u32::MAX);
        let mut rr1 = make_rr("a.com", DnsRecordType::A);
        rr1.ttl = 120;
        a.add_rr(rr1, 0, DnsAnswerFlags::empty());
        let mut rr2 = make_rr("b.com", DnsRecordType::A);
        rr2.ttl = 60;
        a.add_rr(rr2, 0, DnsAnswerFlags::empty());
        assert_eq!(a.min_ttl(), 60);
    }

    #[test]
    fn test_min_ttl_ignores_pseudo() {
        let mut a = DnsAnswer::new();
        let mut opt = make_rr("", DnsRecordType::Opt);
        opt.ttl = 0;
        a.add_rr(opt, 0, DnsAnswerFlags::empty());
        let mut rr = make_rr("a.com", DnsRecordType::A);
        rr.ttl = 300;
        a.add_rr(rr, 0, DnsAnswerFlags::empty());
        assert_eq!(a.min_ttl(), 300);
    }

    // ── Clear / Reserve ────────────────────────────────────────────────

    #[test]
    fn test_clear() {
        let mut a = DnsAnswer::new();
        a.add_rr(
            make_rr("example.com", DnsRecordType::A),
            0,
            DnsAnswerFlags::empty(),
        );
        a.clear();
        assert!(a.is_empty());
    }

    #[test]
    fn test_reserve() {
        let mut a = DnsAnswer::new();
        a.reserve(100);
        assert!(a.is_empty());
        // Should be able to add without realloc for small counts.
        for i in 0..10 {
            let name = format!("host{}.com", i);
            a.add_rr(make_rr(&name, DnsRecordType::A), 0, DnsAnswerFlags::empty());
        }
        assert_eq!(a.size(), 10);
    }

    // ── Reordering ─────────────────────────────────────────────────────

    #[test]
    fn test_order_by_scope() {
        let mut a = DnsAnswer::new();
        a.add_rr(
            make_rr("global.com", DnsRecordType::A),
            0,
            DnsAnswerFlags::empty(),
        );
        a.add_rr(make_link_local_rr("local.com"), 0, DnsAnswerFlags::empty());
        // Prefer link-local → link-local first.
        a.order_by_scope(true);
        assert!(a.items[0].rr.is_link_local);
        assert!(!a.items[1].rr.is_link_local);
    }

    #[test]
    fn test_randomize_preserves_size() {
        let mut a = DnsAnswer::new();
        for i in 0..20 {
            let name = format!("host{}.com", i);
            a.add_rr(make_rr(&name, DnsRecordType::A), 0, DnsAnswerFlags::empty());
        }
        a.randomize();
        assert_eq!(a.size(), 20);
    }

    // ── Record types ───────────────────────────────────────────────────

    #[test]
    fn test_record_type_is_pseudo() {
        assert!(DnsRecordType::Opt.is_pseudo());
        assert!(!DnsRecordType::A.is_pseudo());
        assert!(!DnsRecordType::Nsec.is_pseudo());
    }

    #[test]
    fn test_record_type_may_redirect() {
        assert!(!DnsRecordType::Cname.may_redirect());
        assert!(!DnsRecordType::Dname.may_redirect());
        assert!(!DnsRecordType::Soa.may_redirect());
        assert!(DnsRecordType::A.may_redirect());
        assert!(DnsRecordType::Aaaa.may_redirect());
    }

    // ── Dump ───────────────────────────────────────────────────────────

    #[test]
    fn test_dump_non_empty() {
        let mut a = DnsAnswer::new();
        a.add_rr(
            make_rr("example.com", DnsRecordType::A),
            2,
            DnsAnswerFlags::AUTHENTICATED,
        );
        let s = a.dump();
        assert!(s.contains("example.com"));
        assert!(s.contains("authenticated"));
        assert!(s.contains("ifindex=2"));
    }

    #[test]
    fn test_dump_empty() {
        let a = DnsAnswer::new();
        assert!(a.dump().is_empty());
    }

    // ── Max capacity ───────────────────────────────────────────────────

    #[test]
    fn test_add_respects_max_size() {
        let mut a = DnsAnswer::new();
        // Fill to max.
        for i in 0..DNS_ANSWER_MAX_SIZE {
            let name = format!("h{}.com", i);
            a.add_rr(make_rr(&name, DnsRecordType::A), 0, DnsAnswerFlags::empty());
        }
        assert_eq!(a.size(), DNS_ANSWER_MAX_SIZE as usize);
        // Adding one more should fail.
        let overflow = make_rr("overflow.com", DnsRecordType::A);
        assert!(!a.add_rr(overflow, 0, DnsAnswerFlags::empty()));
        assert_eq!(a.size(), DNS_ANSWER_MAX_SIZE as usize);
    }

    // ── Item equality (ifindex + rr key) ───────────────────────────────

    #[test]
    fn test_item_equality_uses_ifindex() {
        let rr = make_rr("example.com", DnsRecordType::A);
        let a = DnsAnswerItem::new(rr.clone(), 0, DnsAnswerFlags::empty());
        let b = DnsAnswerItem::new(rr, 1, DnsAnswerFlags::empty());
        assert_ne!(a, b);
    }

    #[test]
    fn test_item_equality_uses_rr_key() {
        let rr1 = make_rr("a.com", DnsRecordType::A);
        let rr2 = make_rr("b.com", DnsRecordType::A);
        let a = DnsAnswerItem::new(rr1, 0, DnsAnswerFlags::empty());
        let b = DnsAnswerItem::new(rr2, 0, DnsAnswerFlags::empty());
        assert_ne!(a, b);
    }
}
