// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/fuzz-resource-record.c
//
// DNS resource record fuzzer: constructs a DNS RR from raw fuzz input,
// exercises copy/compare, string representation, JSON serialization,
// and wire format conversion.

use std::fmt;

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum DNS packet size.
pub const DNS_PACKET_SIZE_MAX: usize = 512;

/// Common DNS record type codes.
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_NS: u16 = 2;
pub const DNS_TYPE_CNAME: u16 = 5;
pub const DNS_TYPE_SOA: u16 = 6;
pub const DNS_TYPE_PTR: u16 = 12;
pub const DNS_TYPE_MX: u16 = 15;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_SRV: u16 = 33;

/// DNS class IN (Internet).
pub const DNS_CLASS_IN: u16 = 1;

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceRecordError {
    /// Input size exceeds maximum.
    SizeOutOfRange,
    /// Failed to parse RR from raw data.
    ParseFailed(String),
    /// Copy failed.
    CopyFailed,
    /// Comparison failed.
    CompareFailed,
    /// Wire format conversion failed.
    WireFormatFailed(String),
    /// JSON serialization failed.
    JsonFailed(String),
}

impl fmt::Display for ResourceRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceRecordError::SizeOutOfRange => write!(f, "Size out of range"),
            ResourceRecordError::ParseFailed(s) => write!(f, "Parse failed: {}", s),
            ResourceRecordError::CopyFailed => write!(f, "Copy failed"),
            ResourceRecordError::CompareFailed => write!(f, "Compare failed"),
            ResourceRecordError::WireFormatFailed(s) => write!(f, "Wire format failed: {}", s),
            ResourceRecordError::JsonFailed(s) => write!(f, "JSON failed: {}", s),
        }
    }
}

impl std::error::Error for ResourceRecordError {}

// ── DNS name ───────────────────────────────────────────────────────────────

/// A DNS domain name stored in wire format (label-length-prefixed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsName {
    labels: Vec<String>,
}

impl DnsName {
    /// Parse a DNS name from wire format bytes.
    pub fn from_wire(data: &[u8], offset: usize) -> Result<(Self, usize), ResourceRecordError> {
        let mut labels = Vec::new();
        let mut pos = offset;

        loop {
            if pos >= data.len() {
                return Err(ResourceRecordError::ParseFailed(
                    "unexpected end of name".to_string(),
                ));
            }

            let len = data[pos] as usize;
            pos += 1;

            if len == 0 {
                break;
            }

            // Check for compression pointer (top 2 bits set)
            if len >= 0xC0 {
                return Err(ResourceRecordError::ParseFailed(
                    "compression pointers not supported in fuzzer".to_string(),
                ));
            }

            if pos + len > data.len() {
                return Err(ResourceRecordError::ParseFailed(
                    "label exceeds data bounds".to_string(),
                ));
            }

            let label = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
            labels.push(label);
            pos += len;
        }

        Ok((DnsName { labels }, pos))
    }

    /// Get the full domain name as a dotted string.
    pub fn to_string_lossy(&self) -> String {
        self.labels.join(".")
    }

    /// Number of labels.
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_lossy())
    }
}

// ── DNS Resource Record Key ────────────────────────────────────────────────

/// The key portion of a DNS resource record (name + class + type).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResourceRecordKey {
    pub name: DnsName,
    pub class: u16,
    pub rr_type: u16,
}

// ── DNS Resource Record ────────────────────────────────────────────────────

/// A DNS resource record parsed from raw wire data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResourceRecord {
    pub key: DnsResourceRecordKey,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl DnsResourceRecord {
    /// Create a DNS resource record from raw wire-format data.
    ///
    /// Mirrors the C `dns_resource_record_new_from_raw()`:
    /// Parses the name, type, class, TTL, and RDATA from raw bytes.
    pub fn from_raw(data: &[u8]) -> Result<Self, ResourceRecordError> {
        if data.is_empty() {
            return Err(ResourceRecordError::ParseFailed("empty data".to_string()));
        }

        // Parse name
        let (name, offset) = DnsName::from_wire(data, 0)?;

        // Need at least 10 more bytes: type(2) + class(2) + ttl(4) + rdlength(2)
        if offset + 10 > data.len() {
            return Err(ResourceRecordError::ParseFailed(
                "insufficient data for record header".to_string(),
            ));
        }

        let rr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let class = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        let ttl = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;

        let rdata_start = offset + 10;
        if rdata_start + rdlength > data.len() {
            return Err(ResourceRecordError::ParseFailed(
                "RDATA exceeds bounds".to_string(),
            ));
        }

        let rdata = data[rdata_start..rdata_start + rdlength].to_vec();

        Ok(DnsResourceRecord {
            key: DnsResourceRecordKey {
                name,
                class,
                rr_type,
            },
            ttl,
            rdata,
        })
    }

    /// Create a deep copy of this resource record.
    ///
    /// Mirrors the C `dns_resource_record_copy()`.
    pub fn copy(&self) -> Self {
        self.clone()
    }

    /// Check equality with another resource record.
    ///
    /// Mirrors the C `dns_resource_record_equal()`.
    pub fn equal(&self, other: &Self) -> bool {
        self.key == other.key && self.ttl == other.ttl && self.rdata == other.rdata
    }

    /// Convert the resource record to a human-readable string.
    ///
    /// Mirrors the C `dns_resource_record_to_string()`.
    pub fn to_display_string(&self) -> String {
        format!(
            "{} {} {} {} {} bytes",
            self.key.name,
            self.key.class,
            type_to_string(self.key.rr_type),
            self.ttl,
            self.rdata.len()
        )
    }

    /// Convert the resource record to a JSON-like structure.
    ///
    /// Mirrors the C `dns_resource_record_to_json()`.
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"name":"{}","type":"{}","class":{},"ttl":{},"rdata_size":{}}}"#,
            self.key.name,
            type_to_string(self.key.rr_type),
            self.key.class,
            self.ttl,
            self.rdata.len()
        )
    }

    /// Convert to wire format (canonical or non-canonical).
    ///
    /// Mirrors the C `dns_resource_record_to_wire_format()`.
    pub fn to_wire_format(&self, _canonical: bool) -> Result<Vec<u8>, ResourceRecordError> {
        let mut wire = Vec::new();

        // Encode name in wire format
        for label in &self.key.name.labels {
            if label.len() > 63 {
                return Err(ResourceRecordError::WireFormatFailed(
                    "label too long".to_string(),
                ));
            }
            wire.push(label.len() as u8);
            wire.extend_from_slice(label.as_bytes());
        }
        wire.push(0); // root label

        // Type, Class, TTL, RDLENGTH
        wire.extend_from_slice(&self.key.rr_type.to_be_bytes());
        wire.extend_from_slice(&self.key.class.to_be_bytes());
        wire.extend_from_slice(&self.ttl.to_be_bytes());
        wire.extend_from_slice(&(self.rdata.len() as u16).to_be_bytes());
        wire.extend_from_slice(&self.rdata);

        Ok(wire)
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Convert a DNS record type number to a human-readable string.
pub fn type_to_string(rr_type: u16) -> &'static str {
    match rr_type {
        DNS_TYPE_A => "A",
        DNS_TYPE_NS => "NS",
        DNS_TYPE_CNAME => "CNAME",
        DNS_TYPE_SOA => "SOA",
        DNS_TYPE_PTR => "PTR",
        DNS_TYPE_MX => "MX",
        DNS_TYPE_TXT => "TXT",
        DNS_TYPE_AAAA => "AAAA",
        DNS_TYPE_SRV => "SRV",
        _ => "UNKNOWN",
    }
}

/// Check if the given size is outside the valid range.
pub fn outside_size_range(size: usize, min: usize, max: usize) -> bool {
    size < min || size > max
}

// ── Fuzz entry point ───────────────────────────────────────────────────────

/// Process fuzz input as a DNS resource record.
///
/// Mirrors the C `LLVMFuzzerTestOneInput`:
/// 1. Validate size range
/// 2. Parse RR from raw data
/// 3. Copy and compare
/// 4. Convert to string representation
/// 5. Convert to JSON
/// 6. Convert to wire format (both canonical and non-canonical)
pub fn fuzz_resource_record(data: &[u8]) -> Result<(), ResourceRecordError> {
    if outside_size_range(data.len(), 0, DNS_PACKET_SIZE_MAX) {
        return Ok(());
    }

    let rr = match DnsResourceRecord::from_raw(data) {
        Ok(rr) => rr,
        Err(_) => return Ok(()), // Parse failure is acceptable for fuzz input
    };

    // Copy and compare (mirrors C: assert_se(copy = dns_resource_record_copy(rr)); assert_se(dns_resource_record_equal(copy, rr) > 0))
    let copy = rr.copy();
    if !rr.equal(&copy) {
        return Err(ResourceRecordError::CompareFailed);
    }

    // String representation (mirrors C: fprintf(f, "%s", strna(dns_resource_record_to_string(rr))))
    let _display = rr.to_display_string();

    // JSON (mirrors C: dns_resource_record_to_json)
    let _json = rr.to_json();

    // Wire format (mirrors C: dns_resource_record_to_wire_format, both canonical and non-canonical)
    let _ = rr.to_wire_format(false);
    let _ = rr.to_wire_format(true);

    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_a_record(name: &str, addr: [u8; 4]) -> Vec<u8> {
        let mut wire = Vec::new();
        // Encode name
        for label in name.split('.') {
            wire.push(label.len() as u8);
            wire.extend_from_slice(label.as_bytes());
        }
        wire.push(0);
        // Type A
        wire.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        // Class IN
        wire.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        // TTL
        wire.extend_from_slice(&300u32.to_be_bytes());
        // RDLENGTH
        wire.extend_from_slice(&4u16.to_be_bytes());
        // RDATA (IPv4 address)
        wire.extend_from_slice(&addr);
        wire
    }

    #[test]
    fn test_dns_name_from_wire() {
        // Encode "example.com"
        let wire = b"\x07example\x03com\x00";
        let (name, end) = DnsName::from_wire(wire, 0).unwrap();
        assert_eq!(name.to_string_lossy(), "example.com");
        assert_eq!(name.label_count(), 2);
        assert_eq!(end, wire.len());
    }

    #[test]
    fn test_dns_name_from_wire_root() {
        let wire = b"\x00";
        let (name, end) = DnsName::from_wire(wire, 0).unwrap();
        assert_eq!(name.to_string_lossy(), "");
        assert_eq!(name.label_count(), 0);
        assert_eq!(end, 1);
    }

    #[test]
    fn test_dns_name_from_wire_empty_data() {
        let result = DnsName::from_wire(&[], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_rr_from_raw_a_record() {
        let wire = make_a_record("example.com", [192, 168, 1, 1]);
        let rr = DnsResourceRecord::from_raw(&wire).unwrap();
        assert_eq!(rr.key.name.to_string_lossy(), "example.com");
        assert_eq!(rr.key.rr_type, DNS_TYPE_A);
        assert_eq!(rr.key.class, DNS_CLASS_IN);
        assert_eq!(rr.ttl, 300);
        assert_eq!(rr.rdata, &[192, 168, 1, 1]);
    }

    #[test]
    fn test_rr_copy_and_equal() {
        let wire = make_a_record("test.org", [10, 0, 0, 1]);
        let rr = DnsResourceRecord::from_raw(&wire).unwrap();
        let copy = rr.copy();
        assert!(rr.equal(&copy));
    }

    #[test]
    fn test_rr_not_equal_different_rdata() {
        let rr1 = DnsResourceRecord::from_raw(&make_a_record("test.org", [10, 0, 0, 1])).unwrap();
        let rr2 = DnsResourceRecord::from_raw(&make_a_record("test.org", [10, 0, 0, 2])).unwrap();
        assert!(!rr1.equal(&rr2));
    }

    #[test]
    fn test_rr_to_wire_format_roundtrip() {
        let wire = make_a_record("example.com", [1, 2, 3, 4]);
        let rr = DnsResourceRecord::from_raw(&wire).unwrap();
        let re_encoded = rr.to_wire_format(false).unwrap();
        let rr2 = DnsResourceRecord::from_raw(&re_encoded).unwrap();
        assert!(rr.equal(&rr2));
    }

    #[test]
    fn test_rr_to_display_string() {
        let wire = make_a_record("example.com", [127, 0, 0, 1]);
        let rr = DnsResourceRecord::from_raw(&wire).unwrap();
        let s = rr.to_display_string();
        assert!(s.contains("example.com"));
        assert!(s.contains("A"));
        assert!(s.contains("IN") || s.contains(&DNS_CLASS_IN.to_string()));
    }

    #[test]
    fn test_rr_to_json() {
        let wire = make_a_record("example.com", [127, 0, 0, 1]);
        let rr = DnsResourceRecord::from_raw(&wire).unwrap();
        let json = rr.to_json();
        assert!(json.contains("\"name\":\"example.com\""));
        assert!(json.contains("\"type\":\"A\""));
        assert!(json.contains("\"ttl\":300"));
    }

    #[test]
    fn test_rr_from_raw_empty() {
        assert!(DnsResourceRecord::from_raw(&[]).is_err());
    }

    #[test]
    fn test_rr_from_raw_too_short() {
        let wire = b"\x00"; // Just root name, no type/class/ttl
        assert!(DnsResourceRecord::from_raw(wire).is_err());
    }

    #[test]
    fn test_type_to_string() {
        assert_eq!(type_to_string(DNS_TYPE_A), "A");
        assert_eq!(type_to_string(DNS_TYPE_AAAA), "AAAA");
        assert_eq!(type_to_string(DNS_TYPE_NS), "NS");
        assert_eq!(type_to_string(DNS_TYPE_CNAME), "CNAME");
        assert_eq!(type_to_string(DNS_TYPE_PTR), "PTR");
        assert_eq!(type_to_string(DNS_TYPE_MX), "MX");
        assert_eq!(type_to_string(DNS_TYPE_TXT), "TXT");
        assert_eq!(type_to_string(DNS_TYPE_SOA), "SOA");
        assert_eq!(type_to_string(DNS_TYPE_SRV), "SRV");
        assert_eq!(type_to_string(9999), "UNKNOWN");
    }

    #[test]
    fn test_fuzz_resource_record_empty() {
        assert!(fuzz_resource_record(&[]).is_ok());
    }

    #[test]
    fn test_fuzz_resource_record_valid() {
        let wire = make_a_record("test.com", [1, 2, 3, 4]);
        assert!(fuzz_resource_record(&wire).is_ok());
    }

    #[test]
    fn test_fuzz_resource_record_oversize() {
        let data = vec![0u8; DNS_PACKET_SIZE_MAX + 1];
        assert!(fuzz_resource_record(&data).is_ok());
    }
}
