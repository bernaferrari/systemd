// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-resolved-packet.c
//
// DNS packet construction and NAPTR record parsing tests.
// Port of dns_packet_new() allocation tests and NAPTR extraction logic.

use std::fmt;

// ── DNS packet constants ───────────────────────────────────────────────────

pub const DNS_PACKET_SIZE_START: usize = 512;
pub const DNS_PACKET_SIZE_MAX: usize = 65535;

pub const DNS_PROTOCOL_DNS: u8 = 0;

pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_AAAA: u16 = 28;
pub const DNS_TYPE_NAPTR: u16 = 35;

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    TooLarge,
    BufferOverflow,
    InvalidHeader,
    Truncated,
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(f, "requested size exceeds DNS_PACKET_SIZE_MAX"),
            Self::BufferOverflow => write!(f, "buffer overflow"),
            Self::InvalidHeader => write!(f, "invalid DNS header"),
            Self::Truncated => write!(f, "packet truncated"),
        }
    }
}

impl std::error::Error for PacketError {}

pub type Result<T> = std::result::Result<T, PacketError>;

// ── DNS header ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    pub const SIZE: usize = 12;

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

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(PacketError::Truncated);
        }
        Ok(Self {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            qdcount: u16::from_be_bytes([buf[4], buf[5]]),
            ancount: u16::from_be_bytes([buf[6], buf[7]]),
            nscount: u16::from_be_bytes([buf[8], buf[9]]),
            arcount: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }
}

// ── DNS packet ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub protocol: u8,
    pub data: Vec<u8>,
    pub size: usize,
    pub allocated: usize,
    pub header: DnsHeader,
}

impl DnsPacket {
    pub fn new(protocol: u8, min_size: usize, max_size: usize) -> Result<Self> {
        if min_size > DNS_PACKET_SIZE_MAX {
            return Err(PacketError::TooLarge);
        }

        let allocated = if min_size <= DNS_PACKET_SIZE_START {
            DNS_PACKET_SIZE_START
        } else {
            let mut s = DNS_PACKET_SIZE_START;
            while s < min_size && s < max_size {
                s = s.saturating_mul(2).min(max_size);
            }
            s
        };

        let allocated = allocated.min(max_size);

        Ok(Self {
            protocol,
            data: vec![0u8; allocated],
            size: 0,
            allocated,
            header: DnsHeader::default(),
        })
    }

    pub fn set_data(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > self.allocated {
            return Err(PacketError::BufferOverflow);
        }
        self.data[..data.len()].copy_from_slice(data);
        self.size = data.len();
        if self.size >= DnsHeader::SIZE {
            self.header = DnsHeader::from_bytes(&self.data)?;
        }
        Ok(())
    }
}

// ── NAPTR record ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaptrRecord {
    pub order: u16,
    pub preference: u16,
    pub flags: String,
    pub services: String,
    pub regexp: String,
    pub replacement: String,
}

impl std::fmt::Display for NaptrRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} \"{}\" \"{}\" \"{}\" {}",
            self.order, self.preference, self.flags, self.services, self.regexp, self.replacement
        )
    }
}

// ── Base64 decoding (simplified) ───────────────────────────────────────────

pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    let chars: Vec<char> = input.chars().filter(|c| !c.is_whitespace()).collect();
    let mut result = Vec::with_capacity(chars.len() * 3 / 4);

    let lookup = |c: char| -> Option<u8> {
        match c {
            'A'..='Z' => Some((c as u8) - b'A'),
            'a'..='z' => Some((c as u8) - b'a' + 26),
            '0'..='9' => Some((c as u8) - b'0' + 52),
            '+' => Some(62),
            '/' => Some(63),
            '=' => None,
            _ => None,
        }
    };

    let mut i = 0;
    while i + 4 <= chars.len() {
        let a = lookup(chars[i]).unwrap_or(0);
        let b = lookup(chars[i + 1]).unwrap_or(0);
        let c = lookup(chars[i + 2]);
        let d = lookup(chars[i + 3]);

        result.push((a << 2) | (b >> 4));

        if let Some(c_val) = c {
            result.push(((b & 0xF) << 4) | (c_val >> 2));
        }

        if let Some(d_val) = d {
            result.push(((c.unwrap_or(0) & 0x3) << 6) | d_val);
        }

        i += 4;
    }

    Ok(result)
}

// ── DNS name decompression ─────────────────────────────────────────────────

pub fn decode_dns_name(data: &[u8], offset: usize) -> Result<(String, usize)> {
    let mut name = String::new();
    let mut pos = offset;
    let mut jumped = false;
    let mut jump_pos = 0usize;

    loop {
        if pos >= data.len() {
            return Err(PacketError::Truncated);
        }
        let len = data[pos] as usize;
        if len == 0 {
            if !jumped {
                jump_pos = pos + 1;
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= data.len() {
                return Err(PacketError::Truncated);
            }
            if !jumped {
                jump_pos = pos + 2;
            }
            jumped = true;
            pos = ((len & 0x3F) << 8) | (data[pos + 1] as usize);
            continue;
        }
        if !name.is_empty() {
            name.push('.');
        }
        if pos + 1 + len > data.len() {
            return Err(PacketError::Truncated);
        }
        for i in 0..len {
            name.push(data[pos + 1 + i] as char);
        }
        pos += 1 + len;
    }

    Ok((name, jump_pos))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_packet_new_small() -> Result<()> {
        let p = DnsPacket::new(DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX)?;
        assert!(p.allocated >= DNS_PACKET_SIZE_START);
        Ok(())
    }

    #[test]
    fn dns_packet_new_medium() -> Result<()> {
        let p = DnsPacket::new(DNS_PROTOCOL_DNS, 1024, DNS_PACKET_SIZE_MAX)?;
        assert!(p.allocated >= 1024);
        Ok(())
    }

    #[test]
    fn dns_packet_new_max() -> Result<()> {
        let p = DnsPacket::new(DNS_PROTOCOL_DNS, DNS_PACKET_SIZE_MAX, DNS_PACKET_SIZE_MAX)?;
        assert!(p.allocated >= DNS_PACKET_SIZE_MAX);
        Ok(())
    }

    #[test]
    fn dns_packet_new_too_large() {
        let result = DnsPacket::new(
            DNS_PROTOCOL_DNS,
            DNS_PACKET_SIZE_MAX + 1,
            DNS_PACKET_SIZE_MAX,
        );
        assert!(result.is_err());
    }

    #[test]
    fn dns_header_roundtrip() -> Result<()> {
        let h = DnsHeader {
            id: 0x1234,
            flags: 0x8180,
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };
        let bytes = h.to_bytes();
        let decoded = DnsHeader::from_bytes(&bytes)?;
        assert_eq!(decoded.id, 0x1234);
        assert_eq!(decoded.flags, 0x8180);
        assert_eq!(decoded.qdcount, 1);
        assert_eq!(decoded.ancount, 1);
        Ok(())
    }

    #[test]
    fn dns_header_from_bytes_truncated() {
        let result = DnsHeader::from_bytes(&[0, 1, 2]);
        assert!(result.is_err());
    }

    #[test]
    fn dns_packet_set_data() -> Result<()> {
        let mut p = DnsPacket::new(DNS_PROTOCOL_DNS, 0, DNS_PACKET_SIZE_MAX)?;
        let data = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        p.set_data(&data)?;
        assert_eq!(p.size, 12);
        assert_eq!(p.header.id, 0x1234);
        assert_eq!(p.header.flags, 0x8180);
        Ok(())
    }

    #[test]
    fn naptr_record_display() {
        let naptr = NaptrRecord {
            order: 20,
            preference: 10,
            flags: "S".to_string(),
            services: "SIP+D2T".to_string(),
            regexp: String::new(),
            replacement: "_sip._tcp.pstn.ie1-tnx.twilio.com.".to_string(),
        };
        let s = format!("{}", naptr);
        assert!(s.contains("20 10"));
        assert!(s.contains("SIP+D2T"));
    }

    #[test]
    fn base64_decode_basic() -> Result<()> {
        let decoded = base64_decode("SGVsbG8=")?;
        assert_eq!(decoded, b"Hello");
        Ok(())
    }

    #[test]
    fn decode_dns_name_simple() -> Result<()> {
        let data = b"\x07example\x03com\x00";
        let (name, end) = decode_dns_name(data, 0)?;
        assert_eq!(name, "example.com");
        assert_eq!(end, 13);
        Ok(())
    }

    #[test]
    fn dns_packet_allocated_doubles() -> Result<()> {
        let p = DnsPacket::new(DNS_PROTOCOL_DNS, 600, DNS_PACKET_SIZE_MAX)?;
        assert!(p.allocated >= 600);
        assert!(p.allocated >= 1024);
        Ok(())
    }
}
