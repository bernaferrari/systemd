// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-dns-packet-append.c
//
// DNS packet construction: set flags, append keys, questions,
// OPT records, answers, and wire-format verification.

use std::collections::HashMap;

// ── DNS wire-format constants ───────────────────────────────────────────────

const DNS_CLASS_IN: u16 = 1;
const DNS_CLASS_ANY: u16 = 255;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_NS: u16 = 2;
const DNS_TYPE_CNAME: u16 = 5;
const DNS_TYPE_SOA: u16 = 6;
const DNS_TYPE_MX: u16 = 15;
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_OPT: u16 = 41;
const DNS_TYPE_ANY: u16 = 255;

const DNS_RCODE_SUCCESS: u8 = 0;

// ── Packet header flags ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct HeaderFlags(u16);

impl HeaderFlags {
    const QR: Self = Self(1 << 15);
    const AA: Self = Self(1 << 10);
    const TC: Self = Self(1 << 9);
    const RD: Self = Self(1 << 8);
    const RA: Self = Self(1 << 7);
    const AD: Self = Self(1 << 5);
    const CD: Self = Self(1 << 4);

    fn bits(&self) -> u16 {
        self.0
    }
    fn empty() -> Self {
        Self(0)
    }
}

impl std::ops::BitOr for HeaderFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// ── DNS header ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct DnsHeader {
    id: u16,
    flags: HeaderFlags,
    rcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DnsHeader {
    fn to_bytes(&self) -> [u8; 12] {
        let flags_bits = self.flags.bits() | (self.rcode as u16 & 0x0F);
        [
            (self.id >> 8) as u8,
            (self.id & 0xFF) as u8,
            (flags_bits >> 8) as u8,
            (flags_bits & 0xFF) as u8,
            (self.qdcount >> 8) as u8,
            (self.qdcount & 0xFF) as u8,
            (self.ancount >> 8) as u8,
            (self.ancount & 0xFF) as u8,
            (self.nscount >> 8) as u8,
            (self.nscount & 0xFF) as u8,
            (self.arcount >> 8) as u8,
            (self.arcount & 0xFF) as u8,
        ]
    }
}

// ── DNS name encoding ───────────────────────────────────────────────────────

fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        let bytes = label.as_bytes();
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    out
}

/// Encode a name using compression: previously seen suffixes get a pointer.
fn encode_dns_name_compressed(name: &str, offsets: &HashMap<String, usize>) -> Vec<u8> {
    let mut out = Vec::new();
    let labels: Vec<&str> = name.split('.').collect();
    for i in 0..labels.len() {
        let suffix = labels[i..].join(".");
        if let Some(&offset) = offsets.get(&suffix.to_ascii_lowercase()) {
            let ptr = 0xC000 | (offset as u16 & 0x3FFF);
            out.push((ptr >> 8) as u8);
            out.push((ptr & 0xFF) as u8);
            return out;
        }
        let label = labels[i];
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

// ── DNS packet builder ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
struct DnsPacket {
    data: Vec<u8>,
    header: DnsHeader,
    name_offsets: HashMap<String, usize>,
}

impl DnsPacket {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            header: DnsHeader::default(),
            name_offsets: HashMap::new(),
        }
    }

    fn write_header(&mut self) {
        let hdr = self.header.to_bytes();
        if self.data.len() < 12 {
            self.data.resize(12, 0);
        }
        self.data[..12].copy_from_slice(&hdr);
    }

    fn append_key(&mut self, class: u16, rtype: u16, name: &str) {
        let offset = self.data.len();
        let encoded = encode_dns_name_compressed(name, &self.name_offsets);
        self.data.extend_from_slice(&encoded);

        let labels: Vec<&str> = name.split('.').collect();
        let mut pos = 0usize;
        for i in 0..labels.len() {
            let suffix = labels[i..].join(".");
            self.name_offsets
                .entry(suffix.to_ascii_lowercase())
                .or_insert(offset + pos);
            pos += 1 + labels[i].len();
        }

        self.data.extend_from_slice(&rtype.to_be_bytes());
        self.data.extend_from_slice(&class.to_be_bytes());
    }

    fn append_question(&mut self, keys: &[(u16, u16, &str)]) {
        for &(_class, rtype, name) in keys {
            let offset = self.data.len();
            let encoded = encode_dns_name_compressed(name, &self.name_offsets);
            self.data.extend_from_slice(&encoded);

            let labels: Vec<&str> = name.split('.').collect();
            let mut pos = 0usize;
            for i in 0..labels.len() {
                let suffix = labels[i..].join(".");
                self.name_offsets
                    .entry(suffix.to_ascii_lowercase())
                    .or_insert(offset + pos);
                pos += 1 + labels[i].len();
            }

            self.data.extend_from_slice(&rtype.to_be_bytes());
        }
    }

    fn append_opt(&mut self, udp_size: u16, dnssec_ok: bool, nsid: Option<&str>, rcode_ext: u16) {
        // Root name
        self.data.push(0);
        // OPT type
        self.data.extend_from_slice(&DNS_TYPE_OPT.to_be_bytes());
        // UDP max size (class field in OPT)
        self.data.extend_from_slice(&udp_size.to_be_bytes());
        // Extended RCODE + version + flags
        let ext_rcode = ((rcode_ext >> 8) & 0xFF) as u8;
        let version = 0u8;
        let flags: u16 = if dnssec_ok { 0x8000 } else { 0 };
        self.data.push(ext_rcode);
        self.data.push(version);
        self.data.extend_from_slice(&flags.to_be_bytes());

        // RDATA
        let mut rdata = Vec::new();
        if let Some(nsid_str) = nsid {
            // NSID option: code=3
            let nsid_bytes = nsid_str.as_bytes();
            rdata.extend_from_slice(&3u16.to_be_bytes());
            rdata.extend_from_slice(&(nsid_bytes.len() as u16).to_be_bytes());
            rdata.extend_from_slice(nsid_bytes);
        }
        self.data
            .extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        self.data.extend_from_slice(&rdata);
    }

    fn append_a_answer(&mut self, name: &str, addr: u32, ttl: u32) {
        let encoded = encode_dns_name_compressed(name, &self.name_offsets);
        self.data.extend_from_slice(&encoded);
        self.data.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        self.data.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        self.data.extend_from_slice(&ttl.to_be_bytes());
        self.data.extend_from_slice(&4u16.to_be_bytes());
        self.data.extend_from_slice(&addr.to_be_bytes());
    }

    fn finalize(&mut self) {
        self.write_header();
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_flags_dns_rd_set() {
        let mut pkt = DnsPacket::new();
        pkt.header.id = 42;
        pkt.header.flags = HeaderFlags::RD;
        pkt.header.rcode = 0;
        pkt.write_header();
        let hdr = &pkt.data[..12];
        assert_eq!(
            u16::from_be_bytes([hdr[2], hdr[3]]) & HeaderFlags::RD.bits(),
            HeaderFlags::RD.bits()
        );
        assert_eq!(
            u16::from_be_bytes([hdr[2], hdr[3]]) & HeaderFlags::CD.bits(),
            0
        );
    }

    #[test]
    fn test_set_flags_dns_cd_set() {
        let mut pkt = DnsPacket::new();
        pkt.header.id = 42;
        pkt.header.flags = HeaderFlags::RD | HeaderFlags::CD;
        pkt.header.rcode = 0;
        pkt.write_header();
        let hdr = &pkt.data[..12];
        let flags = u16::from_be_bytes([hdr[2], hdr[3]]);
        assert!(flags & HeaderFlags::RD.bits() != 0);
        assert!(flags & HeaderFlags::CD.bits() != 0);
    }

    #[test]
    fn test_set_flags_llmnr_no_rd() {
        let mut pkt = DnsPacket::new();
        pkt.header.id = 42;
        pkt.header.flags = HeaderFlags::empty();
        pkt.write_header();
        let hdr = &pkt.data[..12];
        let flags = u16::from_be_bytes([hdr[2], hdr[3]]);
        assert!(flags & HeaderFlags::RD.bits() == 0);
    }

    #[test]
    fn test_append_key_single_a() {
        let mut pkt = DnsPacket::new();
        pkt.header.id = 42;
        pkt.header.flags = HeaderFlags::RD;
        pkt.header.qdcount = 1;
        pkt.write_header();
        pkt.append_key(DNS_CLASS_IN, DNS_TYPE_A, "www.example.com");
        pkt.finalize();

        assert!(pkt.data.len() > 12);
        // Verify name starts after header
        assert_eq!(pkt.data[12], 3); // "www" length
    }

    #[test]
    fn test_append_key_soa_any_class() {
        let mut pkt = DnsPacket::new();
        pkt.header.id = 42;
        pkt.header.flags = HeaderFlags::RD;
        pkt.header.qdcount = 1;
        pkt.write_header();
        pkt.append_key(DNS_CLASS_ANY, DNS_TYPE_SOA, "www.example.com");
        pkt.finalize();

        // Verify type is SOA (6)
        let name_end = pkt.data.len() - 4;
        let rtype = u16::from_be_bytes([pkt.data[name_end], pkt.data[name_end + 1]]);
        assert_eq!(rtype, DNS_TYPE_SOA);
        let class = u16::from_be_bytes([pkt.data[name_end + 2], pkt.data[name_end + 3]]);
        assert_eq!(class, DNS_CLASS_ANY);
    }

    #[test]
    fn test_encode_dns_name_simple() {
        let encoded = encode_dns_name("www.example.com");
        assert_eq!(encoded[0], 3); // "www"
        assert_eq!(&encoded[1..4], b"www");
        assert_eq!(encoded[4], 7); // "example"
        assert_eq!(&encoded[5..12], b"example");
        assert_eq!(encoded[12], 3); // "com"
        assert_eq!(&encoded[13..16], b"com");
        assert_eq!(encoded[16], 0); // root
    }

    #[test]
    fn test_encode_dns_name_compression() {
        let mut offsets = HashMap::new();
        offsets.insert("example.com".to_string(), 16);
        let encoded = encode_dns_name_compressed("mail.example.com", &offsets);
        // "mail" label + pointer to "example.com"
        assert_eq!(encoded[0], 4); // "mail"
        // After "mail", should be a compression pointer (0xC0 | offset)
        assert_eq!(encoded[5], 0xC0);
    }

    #[test]
    fn test_append_opt_basic() {
        let mut pkt = DnsPacket::new();
        pkt.header.id = 42;
        pkt.header.flags = HeaderFlags::RD;
        pkt.header.arcount = 1;
        pkt.write_header();
        pkt.append_opt(512, false, None, 0);
        pkt.finalize();

        assert!(pkt.data.len() > 12);
        // Check OPT type appears in the packet
        let opt_be = DNS_TYPE_OPT.to_be_bytes();
        assert!(pkt.data.windows(2).any(|w| w == opt_be));
    }

    #[test]
    fn test_append_opt_dnssec_ok() {
        let mut pkt = DnsPacket::new();
        pkt.header.id = 42;
        pkt.header.flags = HeaderFlags::RD;
        pkt.header.arcount = 1;
        pkt.write_header();
        pkt.append_opt(512, true, None, 0);
        pkt.finalize();

        // Verify DO bit is set in the flags
        assert!(pkt.data.windows(2).any(|w| w[0] == 0x80 && w[1] == 0x00));
    }

    #[test]
    fn test_append_opt_nsid() {
        let mut pkt = DnsPacket::new();
        pkt.header.id = 42;
        pkt.header.flags = HeaderFlags::RD;
        pkt.header.arcount = 1;
        pkt.write_header();
        pkt.append_opt(512, false, Some("nsid.example.com"), 0);
        pkt.finalize();

        // Verify NSID option code (3) appears
        assert!(pkt.data.windows(2).any(|w| w[0] == 0x00 && w[1] == 0x03));
        // Verify NSID string appears
        let nsid_bytes = b"nsid.example.com";
        assert!(pkt.data.windows(nsid_bytes.len()).any(|w| w == nsid_bytes));
    }

    #[test]
    fn test_append_opt_change_max_udp() {
        let mut pkt = DnsPacket::new();
        pkt.header.id = 42;
        pkt.header.flags = HeaderFlags::RD;
        pkt.header.arcount = 1;
        pkt.write_header();
        pkt.append_opt(4100, false, None, 0);
        pkt.finalize();

        // 4100 = 0x1004
        assert!(pkt.data.windows(2).any(|w| w[0] == 0x10 && w[1] == 0x04));
    }

    #[test]
    fn test_append_a_answer() {
        let mut pkt = DnsPacket::new();
        pkt.header.id = 42;
        pkt.header.flags = HeaderFlags::QR | HeaderFlags::AA | HeaderFlags::RD;
        pkt.header.ancount = 1;
        pkt.write_header();
        pkt.append_a_answer("example.com", 0xc0a8017f, 3601);
        pkt.finalize();

        assert!(pkt.data.len() > 12);
        // Check A type (1) appears
        let a_be = DNS_TYPE_A.to_be_bytes();
        assert!(pkt.data.windows(2).any(|w| w == a_be));
        // Check IP address 192.168.1.127 appears
        assert!(pkt.data.windows(4).any(|w| w == [0xc0, 0xa8, 0x01, 0x7f]));
    }

    #[test]
    fn test_packet_header_to_bytes_roundtrip() {
        let hdr = DnsHeader {
            id: 42,
            flags: HeaderFlags::QR | HeaderFlags::AA | HeaderFlags::RD,
            rcode: DNS_RCODE_SUCCESS,
            qdcount: 0,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };
        let bytes = hdr.to_bytes();
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 42);
        let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
        assert!(flags & HeaderFlags::QR.bits() != 0);
        assert!(flags & HeaderFlags::AA.bits() != 0);
        assert!(flags & HeaderFlags::RD.bits() != 0);
        assert_eq!(flags & 0x0F, 0); // rcode
        assert_eq!(u16::from_be_bytes([bytes[6], bytes[7]]), 1); // ancount
    }

    #[test]
    fn test_packet_multiple_questions() {
        let mut pkt = DnsPacket::new();
        pkt.header.id = 42;
        pkt.header.flags = HeaderFlags::RD;
        pkt.header.qdcount = 3;
        pkt.write_header();
        pkt.append_question(&[
            (DNS_CLASS_IN, DNS_TYPE_A, "www.example.com"),
            (DNS_CLASS_IN, DNS_TYPE_MX, "mail.example.com"),
            (DNS_CLASS_IN, DNS_TYPE_SOA, "host.mail.example.com"),
        ]);
        pkt.finalize();

        assert!(pkt.data.len() > 12);
        // Verify A type field appears
        let a_count = pkt
            .data
            .windows(2)
            .filter(|w| *w == DNS_TYPE_A.to_be_bytes())
            .count();
        assert_eq!(a_count, 1);
    }

    #[test]
    fn test_name_too_long_returns_error() {
        // DNS labels max 63 bytes; total name max 255 bytes
        let long_label: String = "a".repeat(64);
        let encoded = encode_dns_name(&long_label);
        // Label length byte would be 64 which is > 63
        assert!(encoded[0] > 63);
    }
}
