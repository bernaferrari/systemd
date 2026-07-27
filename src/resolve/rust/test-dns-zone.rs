// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-dns-zone.c
//
// DNS zone management tests: put, remove, remove_by_key, and lookup operations.
// Faithful port of the C test-dns-zone.c TEST() cases into safe, idiomatic Rust.

use std::collections::HashMap;

// ── DNS constants ──────────────────────────────────────────────────────────

pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_CLASS_ANY: u16 = 255;

pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_NS: u16 = 2;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_SOA: u16 = 6;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_MX: u16 = 15;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_ANY: u16 = 255;

/// Maximum length for a DNS name
const DNS_NAME_MAX: usize = 253;

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneError {
    pub kind: ZoneErrorKind,
    pub message: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneErrorKind {
    InvalidClass,
    InvalidType,
    NotFound,
    AlreadyExists,
    InvalidName,
}

impl std::fmt::Display for ZoneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for ZoneError {}

pub type Result<T> = std::result::Result<T, ZoneError>;

// ── DNS resource key ───────────────────────────────────────────────────────

/// Represents a DNS resource key (class + type + name).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsResourceKey {
    pub class: u16,
    pub rtype: u16,
    pub name: String,
}

impl DnsResourceKey {
    pub fn new(class: u16, rtype: u16, name: &str) -> Result<Self> {
        if class == DNS_CLASS_ANY {
            return Err(ZoneError {
                kind: ZoneErrorKind::InvalidClass,
                message: "DNS_CLASS_ANY is not valid for resource records",
            });
        }
        if rtype == DNS_TYPE_ANY {
            return Err(ZoneError {
                kind: ZoneErrorKind::InvalidType,
                message: "DNS_TYPE_ANY is not valid for resource records",
            });
        }
        let name_lower = name.to_ascii_lowercase();
        if name_lower.len() > DNS_NAME_MAX {
            return Err(ZoneError {
                kind: ZoneErrorKind::InvalidName,
                message: "DNS name too long",
            });
        }
        Ok(Self {
            class,
            rtype,
            name: name_lower,
        })
    }

    /// Check if this key matches another key, treating ANY as a wildcard for type.
    fn matches(&self, other: &DnsResourceKey) -> bool {
        if self.class != other.class || self.name != other.name {
            return false;
        }
        // ANY type matches any specific type
        self.rtype == DNS_TYPE_ANY || self.rtype == other.rtype
    }
}

// ── DNS resource record ────────────────────────────────────────────────────

/// Simplified DNS resource record with key and optional payload.
#[derive(Debug, Clone)]
pub struct DnsResourceRecord {
    pub key: DnsResourceKey,
    pub data: RecordData,
}

/// The data payload of a DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    A { address: u32 },
    Aaaa { address: [u8; 16] },
    Cname { cname: String },
    Ns { nsdname: String },
    Empty,
}

impl DnsResourceRecord {
    pub fn new_full(class: u16, rtype: u16, name: &str) -> Result<Self> {
        let key = DnsResourceKey::new(class, rtype, name)?;
        let data = match rtype {
            DNS_TYPE_A => RecordData::A { address: 0 },
            DNS_TYPE_AAAA => RecordData::Aaaa { address: [0u8; 16] },
            DNS_TYPE_CNAME => RecordData::Cname {
                cname: String::new(),
            },
            DNS_TYPE_NS => RecordData::Ns {
                nsdname: String::new(),
            },
            _ => RecordData::Empty,
        };
        Ok(Self { key, data })
    }

    pub fn with_a_address(mut self, addr: u32) -> Self {
        self.data = RecordData::A { address: addr };
        self
    }

    pub fn with_cname(mut self, cname: &str) -> Self {
        self.data = RecordData::Cname {
            cname: cname.to_string(),
        };
        self
    }

    pub fn with_ns(mut self, nsdname: &str) -> Self {
        self.data = RecordData::Ns {
            nsdname: nsdname.to_string(),
        };
        self
    }
}

// ── Zone item ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneItemState {
    Established,
    Probing,
}

#[derive(Debug, Clone)]
pub struct DnsZoneItem {
    pub rr: DnsResourceRecord,
    pub state: ZoneItemState,
}

// ── DNS zone ───────────────────────────────────────────────────────────────

/// A DNS zone that stores resource records indexed by key.
#[derive(Debug, Default)]
pub struct DnsZone {
    items: HashMap<DnsResourceKey, Vec<DnsZoneItem>>,
}

impl DnsZone {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Add a resource record to the zone.
    /// Returns Err for ANY class or ANY type (EINVAL per C code).
    pub fn put(&mut self, rr: &DnsResourceRecord) -> Result<()> {
        // Validate — mirrors C's dns_zone_put() EINVAL checks
        if rr.key.class == DNS_CLASS_ANY {
            return Err(ZoneError {
                kind: ZoneErrorKind::InvalidClass,
                message: "refusing DNS_CLASS_ANY",
            });
        }
        if rr.key.rtype == DNS_TYPE_ANY {
            return Err(ZoneError {
                kind: ZoneErrorKind::InvalidType,
                message: "refusing DNS_TYPE_ANY",
            });
        }

        let item = DnsZoneItem {
            rr: rr.clone(),
            state: ZoneItemState::Established,
        };
        self.items.entry(rr.key.clone()).or_default().push(item);
        Ok(())
    }

    /// Retrieve a zone item matching the given resource record.
    pub fn get(&self, rr: &DnsResourceRecord) -> Option<&DnsZoneItem> {
        self.items.get(&rr.key).and_then(|v| v.first())
    }

    /// Remove a resource record that exactly matches (key + data).
    pub fn remove_rr(&mut self, rr: &DnsResourceRecord) {
        if let Some(list) = self.items.get_mut(&rr.key) {
            list.retain(|item| !records_equal(&item.rr, rr));
            if list.is_empty() {
                self.items.remove(&rr.key);
            }
        }
    }

    /// Remove all resource records matching a given key.
    /// If the key's type is ANY, remove all records for that class+name.
    pub fn remove_rrs_by_key(&mut self, key: &DnsResourceKey) -> Result<()> {
        let keys_to_remove: Vec<DnsResourceKey> = self
            .items
            .keys()
            .filter(|k| key.matches(k))
            .cloned()
            .collect();
        for k in keys_to_remove {
            self.items.remove(&k);
        }
        Ok(())
    }

    /// Look up resource records by key.
    /// Returns (answer_records, soa_records, tentative).
    pub fn lookup(
        &self,
        key: &DnsResourceKey,
    ) -> (Vec<DnsResourceRecord>, Vec<DnsResourceRecord>, bool) {
        let mut answer = Vec::new();
        let mut soa = Vec::new();
        let tentative = false;

        // Collect matching records
        let matching_keys: Vec<&DnsResourceKey> =
            self.items.keys().filter(|k| key.matches(k)).collect();

        for mk in matching_keys {
            if let Some(list) = self.items.get(mk) {
                for item in list {
                    answer.push(item.rr.clone());
                }
            }
        }

        // If no answer was found but the name exists with other types,
        // generate a synthetic SOA response (mirrors C behavior)
        if answer.is_empty() {
            // Check if the name exists at all in the zone
            let name_exists = self.items.keys().any(|k| k.name == key.name);
            if name_exists {
                soa.push(
                    DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_SOA, &key.name).unwrap(),
                );
            }
        }

        (answer, soa, tentative)
    }
}

/// Check if two records are equal (key + payload).
fn records_equal(a: &DnsResourceRecord, b: &DnsResourceRecord) -> bool {
    if a.key != b.key {
        return false;
    }
    a.data == b.data
}

// ── Helper: convert IPv4 address to big-endian u32 ─────────────────────────

pub const fn ipv4(a: u8, b: u8, c: u8, d: u8) -> u32 {
    ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── dns_zone_put() tests ───────────────────────────────────────────────

    #[test]
    fn dns_zone_put_simple() -> Result<()> {
        let mut zone = DnsZone::new();
        let rr = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com")?
            .with_a_address(ipv4(192, 168, 1, 127));

        assert!(zone.is_empty());
        zone.put(&rr)?;
        assert!(!zone.is_empty());

        let item = zone.get(&rr).expect("item should exist");
        assert_eq!(item.state, ZoneItemState::Established);
        Ok(())
    }

    #[test]
    fn dns_zone_put_any_class_is_invalid() {
        let mut zone = DnsZone::new();
        // Construct key manually to bypass DnsResourceKey::new validation
        let key = DnsResourceKey {
            class: DNS_CLASS_ANY,
            rtype: DNS_TYPE_A,
            name: "www.example.com".to_string(),
        };
        let rr = DnsResourceRecord {
            key,
            data: RecordData::A { address: 0 },
        };

        let result = zone.put(&rr);
        assert!(result.is_err());
        assert!(zone.is_empty());
    }

    #[test]
    fn dns_zone_put_any_type_is_invalid() {
        let mut zone = DnsZone::new();
        let key = DnsResourceKey {
            class: DNS_CLASS_IN,
            rtype: DNS_TYPE_ANY,
            name: "www.example.com".to_string(),
        };
        let rr = DnsResourceRecord {
            key,
            data: RecordData::Empty,
        };

        let result = zone.put(&rr);
        assert!(result.is_err());
        assert!(zone.is_empty());
    }

    #[test]
    fn dns_zone_put_case_insensitive_key() -> Result<()> {
        let mut zone = DnsZone::new();
        let rr1 = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_A, "WWW.EXAMPLE.COM")?;
        let rr2 = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com")?;

        zone.put(&rr1)?;
        zone.put(&rr2)?;

        // Both should be stored under the same (lowercased) key
        let items = zone.items.get(&rr1.key).unwrap();
        assert_eq!(items.len(), 2);
        Ok(())
    }

    // ── dns_zone_remove_rr() tests ─────────────────────────────────────────

    #[test]
    fn dns_zone_remove_rr_match() -> Result<()> {
        let mut zone = DnsZone::new();
        let rr_in = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com")?
            .with_a_address(ipv4(192, 168, 1, 127));
        zone.put(&rr_in)?;

        let rr_out = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com")?
            .with_a_address(ipv4(192, 168, 1, 127));

        assert!(zone.get(&rr_in).is_some());
        zone.remove_rr(&rr_out);
        assert!(zone.get(&rr_in).is_none());
        Ok(())
    }

    #[test]
    fn dns_zone_remove_rr_match_one() -> Result<()> {
        let mut zone = DnsZone::new();

        let rr_a = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com")?
            .with_a_address(ipv4(192, 168, 1, 127));
        zone.put(&rr_a)?;

        let rr_cname = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "example.com")?
            .with_cname("www.example.com");
        zone.put(&rr_cname)?;

        // Remove the A record only
        let rr_out = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com")?
            .with_a_address(ipv4(192, 168, 1, 127));
        assert!(zone.get(&rr_out).is_some());
        zone.remove_rr(&rr_out);
        assert!(zone.get(&rr_out).is_none());
        assert!(zone.get(&rr_cname).is_some());
        Ok(())
    }

    #[test]
    fn dns_zone_remove_rr_different_payload() -> Result<()> {
        let mut zone = DnsZone::new();
        let rr_in = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com")?
            .with_a_address(ipv4(192, 168, 1, 127));
        zone.put(&rr_in)?;

        // Try to remove with different address — should not match
        let rr_out = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com")?
            .with_a_address(ipv4(192, 168, 1, 128));
        assert!(zone.get(&rr_in).is_some());
        zone.remove_rr(&rr_out);
        assert!(zone.get(&rr_in).is_some());
        Ok(())
    }

    // ── dns_zone_remove_rrs_by_key() tests ─────────────────────────────────

    #[test]
    fn dns_zone_remove_rrs_by_key() -> Result<()> {
        let mut zone = DnsZone::new();

        let rr1 = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com")?;
        zone.put(&rr1)?;

        let rr2 = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com")?;
        zone.put(&rr2)?;

        let rr3 = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "example.com")?
            .with_cname("www.example.com");
        zone.put(&rr3)?;

        // Remove CNAME for www.example.com — no CNAME record for that name
        let key_www_cname = DnsResourceKey {
            class: DNS_CLASS_IN,
            rtype: DNS_TYPE_CNAME,
            name: "www.example.com".to_string(),
        };
        zone.remove_rrs_by_key(&key_www_cname)?;
        assert!(zone.get(&rr3).is_some()); // CNAME for example.com still present

        // Remove CNAME for example.com
        let key_ex_cname = DnsResourceKey {
            class: DNS_CLASS_IN,
            rtype: DNS_TYPE_CNAME,
            name: "example.com".to_string(),
        };
        zone.remove_rrs_by_key(&key_ex_cname)?;
        assert!(zone.get(&rr3).is_none());

        // Remove ALL types for www.example.com (ANY wildcard)
        let key_www_any = DnsResourceKey {
            class: DNS_CLASS_IN,
            rtype: DNS_TYPE_ANY,
            name: "www.example.com".to_string(),
        };
        zone.remove_rrs_by_key(&key_www_any)?;
        assert!(zone.get(&rr1).is_none());
        assert!(zone.get(&rr2).is_none());
        Ok(())
    }

    // ── dns_zone_lookup() tests ────────────────────────────────────────────

    fn populate_zone(zone: &mut DnsZone) -> Result<()> {
        let rr1 = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com")?;
        zone.put(&rr1)?;

        let rr2 = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_AAAA, "www.example.com")?;
        zone.put(&rr2)?;

        let rr3 = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_CNAME, "example.com")?
            .with_cname("www.example.com");
        zone.put(&rr3)?;

        let rr4 = DnsResourceRecord::new_full(DNS_CLASS_IN, DNS_TYPE_NS, "app.example.com")?
            .with_ns("ns1.app.example.com");
        zone.put(&rr4)?;
        Ok(())
    }

    #[test]
    fn dns_zone_lookup_match_a() -> Result<()> {
        let mut zone = DnsZone::new();
        populate_zone(&mut zone)?;

        let qkey = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com")?;
        let (answer, soa, tentative) = zone.lookup(&qkey);

        assert!(!tentative);
        assert_eq!(answer.len(), 1);
        assert!(soa.is_empty());
        assert_eq!(answer[0].key.rtype, DNS_TYPE_A);
        Ok(())
    }

    #[test]
    fn dns_zone_lookup_match_cname() -> Result<()> {
        let mut zone = DnsZone::new();
        populate_zone(&mut zone)?;

        let qkey = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_CNAME, "example.com")?;
        let (answer, soa, tentative) = zone.lookup(&qkey);

        assert!(!tentative);
        assert_eq!(answer.len(), 1);
        assert!(soa.is_empty());
        assert_eq!(answer[0].key.rtype, DNS_TYPE_CNAME);
        Ok(())
    }

    #[test]
    fn dns_zone_lookup_match_any() -> Result<()> {
        let mut zone = DnsZone::new();
        populate_zone(&mut zone)?;

        let qkey = DnsResourceKey {
            class: DNS_CLASS_IN,
            rtype: DNS_TYPE_ANY,
            name: "www.example.com".to_string(),
        };
        let (answer, soa, tentative) = zone.lookup(&qkey);

        assert!(!tentative);
        assert_eq!(answer.len(), 2);
        assert!(soa.is_empty());

        let types: Vec<u16> = answer.iter().map(|rr| rr.key.rtype).collect();
        assert!(types.contains(&DNS_TYPE_A));
        assert!(types.contains(&DNS_TYPE_AAAA));
        Ok(())
    }

    #[test]
    fn dns_zone_lookup_match_any_apex() -> Result<()> {
        let mut zone = DnsZone::new();
        populate_zone(&mut zone)?;

        let qkey = DnsResourceKey {
            class: DNS_CLASS_IN,
            rtype: DNS_TYPE_ANY,
            name: "example.com".to_string(),
        };
        let (answer, soa, tentative) = zone.lookup(&qkey);

        assert!(!tentative);
        assert_eq!(answer.len(), 1);
        assert!(soa.is_empty());
        assert_eq!(answer[0].key.rtype, DNS_TYPE_CNAME);
        Ok(())
    }

    #[test]
    fn dns_zone_lookup_match_nothing() -> Result<()> {
        let mut zone = DnsZone::new();
        populate_zone(&mut zone)?;

        let qkey = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "nope.example.com")?;
        let (answer, soa, tentative) = zone.lookup(&qkey);

        assert!(!tentative);
        assert!(answer.is_empty());
        assert!(soa.is_empty());
        Ok(())
    }

    #[test]
    fn dns_zone_lookup_match_nothing_with_soa() -> Result<()> {
        let mut zone = DnsZone::new();
        populate_zone(&mut zone)?;

        // "example.com" has a CNAME record but query is for type A
        let qkey = DnsResourceKey::new(DNS_CLASS_IN, DNS_TYPE_A, "example.com")?;
        let (answer, soa, tentative) = zone.lookup(&qkey);

        assert!(!tentative);
        assert!(answer.is_empty());
        assert_eq!(soa.len(), 1);
        assert_eq!(soa[0].key.rtype, DNS_TYPE_SOA);
        Ok(())
    }
}
