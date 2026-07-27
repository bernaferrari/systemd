// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/fuzz-dns-packet.c
//
// DNS packet fuzzer: validates size constraints, constructs a DNS packet
// from raw fuzz input, pads to minimum header size when needed, and
// attempts DNS packet extraction.

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum size of a DNS packet (DNS_PACKET_SIZE_MAX in C).
pub const DNS_PACKET_SIZE_MAX: usize = 512;

/// Minimum DNS header size (12 bytes: ID(2) + FLAGS(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)).
pub const DNS_PACKET_HEADER_SIZE: usize = 12;

/// DNS protocol identifier.
pub const DNS_PROTOCOL_DNS: u8 = 0;

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsPacketError {
    /// Input size is outside the valid range.
    SizeOutOfRange,
    /// Failed to allocate packet.
    AllocationFailed,
    /// Failed to append blob data.
    AppendFailed,
    /// Packet extraction failed.
    ExtractionFailed,
}

impl std::fmt::Display for DnsPacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsPacketError::SizeOutOfRange => write!(f, "DNS packet size out of range"),
            DnsPacketError::AllocationFailed => write!(f, "Failed to allocate DNS packet"),
            DnsPacketError::AppendFailed => write!(f, "Failed to append blob to DNS packet"),
            DnsPacketError::ExtractionFailed => write!(f, "Failed to extract DNS packet"),
        }
    }
}

impl std::error::Error for DnsPacketError {}

// ── DNS Packet header ─────────────────────────────────────────────────────

/// Represents a DNS packet header (12 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    /// Parse a DNS header from a byte slice.
    pub fn from_bytes(data: &[u8]) -> Result<Self, DnsPacketError> {
        if data.len() < DNS_PACKET_HEADER_SIZE {
            return Err(DnsPacketError::ExtractionFailed);
        }
        Ok(DnsHeader {
            id: u16::from_be_bytes([data[0], data[1]]),
            flags: u16::from_be_bytes([data[2], data[3]]),
            qdcount: u16::from_be_bytes([data[4], data[5]]),
            ancount: u16::from_be_bytes([data[6], data[7]]),
            nscount: u16::from_be_bytes([data[8], data[9]]),
            arcount: u16::from_be_bytes([data[10], data[11]]),
        })
    }

    /// Serialize the header to bytes.
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0..2].copy_from_slice(&self.id.to_be_bytes());
        buf[2..4].copy_from_slice(&self.flags.to_be_bytes());
        buf[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        buf[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        buf[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        buf[10..12].copy_from_slice(&self.arcount.to_be_bytes());
        buf
    }
}

// ── DNS Packet ─────────────────────────────────────────────────────────────

/// A simple DNS packet representation for fuzz testing.
#[derive(Debug, Clone)]
pub struct DnsPacket {
    /// Raw packet data.
    data: Vec<u8>,
    /// Allocated capacity.
    allocated: usize,
}

impl DnsPacket {
    /// Create a new DNS packet with the given initial capacity.
    pub fn new(protocol: u8, _initial: usize, max_size: usize) -> Result<Self, DnsPacketError> {
        let _ = protocol;
        Ok(DnsPacket {
            data: Vec::with_capacity(max_size.max(DNS_PACKET_HEADER_SIZE)),
            allocated: max_size.max(DNS_PACKET_HEADER_SIZE),
        })
    }

    /// Get the current size of the packet data.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Set the packet size (truncates or extends with zeros).
    pub fn set_size(&mut self, new_size: usize) {
        if new_size > self.data.len() {
            self.data.resize(new_size, 0);
        } else {
            self.data.truncate(new_size);
        }
    }

    /// Append raw blob data to the packet.
    pub fn append_blob(&mut self, blob: &[u8]) -> Result<(), DnsPacketError> {
        if self.data.len() + blob.len() > self.allocated {
            return Err(DnsPacketError::AppendFailed);
        }
        self.data.extend_from_slice(blob);
        Ok(())
    }

    /// Get the raw packet data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Extract and parse the DNS packet (header + remaining data).
    pub fn extract(&self) -> Result<DnsHeader, DnsPacketError> {
        DnsHeader::from_bytes(&self.data)
    }
}

// ── Size range check ───────────────────────────────────────────────────────

/// Check if the given size is outside the valid range [min, max].
/// Mirrors the C `outside_size_range()` macro.
pub fn outside_size_range(size: usize, min: usize, max: usize) -> bool {
    size < min || size > max
}

// ── Fuzz entry point ───────────────────────────────────────────────────────

/// Process fuzz input as a DNS packet.
///
/// Mirrors the C `LLVMFuzzerTestOneInput`:
/// 1. Validate size range [0, DNS_PACKET_SIZE_MAX]
/// 2. Create a new DNS packet
/// 3. Reset size to 0 (undo default header offset)
/// 4. Append fuzz data as blob
/// 5. Pad to DNS_PACKET_HEADER_SIZE if needed
/// 6. Attempt extraction
pub fn fuzz_dns_packet(data: &[u8]) -> Result<(), DnsPacketError> {
    if outside_size_range(data.len(), 0, DNS_PACKET_SIZE_MAX) {
        return Ok(());
    }

    let mut packet = DnsPacket::new(DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX)?;

    // In C: p->size = 0;  /* by default append starts after the header, undo that */
    packet.set_size(0);

    packet.append_blob(data)?;

    // Pad to minimum header size if needed
    if data.len() < DNS_PACKET_HEADER_SIZE {
        if packet.allocated >= DNS_PACKET_HEADER_SIZE {
            // Zero-fill from data.len() to DNS_PACKET_HEADER_SIZE
            let padding = DNS_PACKET_HEADER_SIZE - data.len();
            let mut padded = packet.data().to_vec();
            padded.extend(std::iter::repeat(0u8).take(padding));
            packet.data = padded;
            packet.set_size(DNS_PACKET_HEADER_SIZE);
        }
    }

    // Attempt extraction (result is intentionally discarded in the fuzzer)
    let _ = packet.extract();

    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outside_size_range_basic() {
        assert!(outside_size_range(600, 0, DNS_PACKET_SIZE_MAX));
        assert!(!outside_size_range(0, 0, DNS_PACKET_SIZE_MAX));
        assert!(!outside_size_range(512, 0, DNS_PACKET_SIZE_MAX));
        assert!(!outside_size_range(256, 0, DNS_PACKET_SIZE_MAX));
    }

    #[test]
    fn test_outside_size_range_boundaries() {
        assert!(!outside_size_range(0, 0, 100));
        assert!(!outside_size_range(100, 0, 100));
        assert!(outside_size_range(101, 0, 100));
        assert!(outside_size_range(usize::MAX, 0, 100));
    }

    #[test]
    fn test_dns_header_roundtrip() {
        let header = DnsHeader {
            id: 0x1234,
            flags: 0x8180,
            qdcount: 1,
            ancount: 2,
            nscount: 0,
            arcount: 0,
        };
        let bytes = header.to_bytes();
        let parsed = DnsHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header, parsed);
    }

    #[test]
    fn test_dns_header_parse_too_short() {
        let short_data = [0u8; 6];
        assert_eq!(
            DnsHeader::from_bytes(&short_data),
            Err(DnsPacketError::ExtractionFailed)
        );
    }

    #[test]
    fn test_dns_packet_new_and_size() {
        let packet = DnsPacket::new(DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX).unwrap();
        assert_eq!(packet.size(), 0);
        assert!(packet.allocated >= DNS_PACKET_SIZE_MAX);
    }

    #[test]
    fn test_dns_packet_append_blob() {
        let mut packet = DnsPacket::new(DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX).unwrap();
        let data = [0xAA, 0xBB, 0xCC];
        packet.append_blob(&data).unwrap();
        assert_eq!(packet.size(), 3);
        assert_eq!(packet.data(), &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_dns_packet_set_size() {
        let mut packet = DnsPacket::new(DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX).unwrap();
        packet.append_blob(&[1, 2, 3, 4, 5]).unwrap();
        assert_eq!(packet.size(), 5);

        // Truncate
        packet.set_size(3);
        assert_eq!(packet.size(), 3);

        // Extend with zeros
        packet.set_size(6);
        assert_eq!(packet.size(), 6);
        assert_eq!(packet.data()[3..6], [0, 0, 0]);
    }

    #[test]
    fn test_fuzz_dns_packet_empty() {
        assert!(fuzz_dns_packet(&[]).is_ok());
    }

    #[test]
    fn test_fuzz_dns_packet_small_input() {
        // Input smaller than header size should be padded
        let data = [0x00, 0x01, 0x02];
        assert!(fuzz_dns_packet(&data).is_ok());
    }

    #[test]
    fn test_fuzz_dns_packet_valid_header() {
        // A minimal valid DNS query header
        let data = [
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
        ];
        assert!(fuzz_dns_packet(&data).is_ok());
    }

    #[test]
    fn test_fuzz_dns_packet_oversize_rejected() {
        let data = vec![0u8; DNS_PACKET_SIZE_MAX + 1];
        // Oversize input should return Ok(()) early (mirroring C returning 0)
        assert!(fuzz_dns_packet(&data).is_ok());
    }

    #[test]
    fn test_fuzz_dns_packet_max_size() {
        let data = vec![0xAA; DNS_PACKET_SIZE_MAX];
        assert!(fuzz_dns_packet(&data).is_ok());
    }

    #[test]
    fn test_dns_header_all_zero() {
        let header = DnsHeader::from_bytes(&[0u8; 12]).unwrap();
        assert_eq!(header.id, 0);
        assert_eq!(header.flags, 0);
        assert_eq!(header.qdcount, 0);
        assert_eq!(header.ancount, 0);
        assert_eq!(header.nscount, 0);
        assert_eq!(header.arcount, 0);
    }
}
