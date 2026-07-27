// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-resolved-stream.c
//
// DNS stream (TCP/TLS) handling tests. The C source runs a full TCP/TLS
// server in threads. This Rust port extracts the stream-protocol logic:
// TCP length-prefix framing, question/answer matching, and packet assembly.

use std::fmt;

// ── DNS constants ──────────────────────────────────────────────────────────

pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_AAAA: u16 = 28;

pub const AF_INET: i32 = 2;

pub const DNS_PACKET_SIZE_MAX: usize = 65535;

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    IoError(String),
    Truncated,
    InvalidLength,
    Timeout,
    ConnectionFailed,
    TlsError(String),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "I/O error: {}", e),
            Self::Truncated => write!(f, "packet truncated"),
            Self::InvalidLength => write!(f, "invalid length"),
            Self::Timeout => write!(f, "timeout"),
            Self::ConnectionFailed => write!(f, "connection failed"),
            Self::TlsError(e) => write!(f, "TLS error: {}", e),
        }
    }
}

impl std::error::Error for StreamError {}

pub type Result<T> = std::result::Result<T, StreamError>;

// ── DNS header ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
            return Err(StreamError::Truncated);
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

    pub fn rd(&self) -> bool {
        (self.flags >> 8) & 1 == 1
    }
}

// ── DNS question ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsQuestion {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for label in self.name.split('.') {
            let bytes = label.as_bytes();
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
        }
        buf.push(0);
        buf.extend_from_slice(&self.qtype.to_be_bytes());
        buf.extend_from_slice(&self.qclass.to_be_bytes());
        buf
    }
}

// ── TCP DNS framing ────────────────────────────────────────────────────────

/// A TCP DNS message has a 2-byte length prefix followed by the DNS packet.
pub fn frame_tcp_packet(packet: &[u8]) -> Vec<u8> {
    let len = packet.len() as u16;
    let mut framed = Vec::with_capacity(2 + packet.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(packet);
    framed
}

/// Extract the DNS payload from a TCP-framed message.
pub fn unframe_tcp_packet(framed: &[u8]) -> Result<Vec<u8>> {
    if framed.len() < 2 {
        return Err(StreamError::Truncated);
    }
    let len = u16::from_be_bytes([framed[0], framed[1]]) as usize;
    if framed.len() < 2 + len {
        return Err(StreamError::Truncated);
    }
    Ok(framed[2..2 + len].to_vec())
}

/// Build a DNS query packet for a given name and type.
pub fn build_query(name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let question = DnsQuestion {
        name: name.to_string(),
        qtype,
        qclass,
    };

    let header = DnsHeader {
        flags: 0x0100, // RD=1, standard query
        qdcount: 1,
        ..Default::default()
    };

    let mut packet = Vec::new();
    packet.extend_from_slice(&header.to_bytes());
    packet.extend(question.encode());
    packet
}

// ── Stream receive tracking ────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct StreamReceiver {
    pub received_packets: Vec<Vec<u8>>,
}

impl StreamReceiver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn on_packet(&mut self, data: Vec<u8>) {
        self.received_packets.push(data);
    }

    pub fn count(&self) -> usize {
        self.received_packets.len()
    }

    pub fn clear(&mut self) {
        self.received_packets.clear();
    }
}

// ── DNS over TLS mode ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOverTlsMode {
    No,
    Opportunistic,
    Yes,
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_tcp_roundtrip() -> Result<()> {
        let payload = b"hello DNS world";
        let framed = frame_tcp_packet(payload);
        let unframed = unframe_tcp_packet(&framed)?;
        assert_eq!(unframed, payload);
        Ok(())
    }

    #[test]
    fn frame_tcp_length_prefix() {
        let payload = vec![0u8; 100];
        let framed = frame_tcp_packet(&payload);
        let len = u16::from_be_bytes([framed[0], framed[1]]);
        assert_eq!(len as usize, 100);
        assert_eq!(framed.len(), 102);
    }

    #[test]
    fn unframe_tcp_truncated() {
        assert!(unframe_tcp_packet(&[]).is_err());
        assert!(unframe_tcp_packet(&[0, 5, 0xAA]).is_err());
    }

    #[test]
    fn build_query_has_header() {
        let packet = build_query("example.com", DNS_TYPE_A, DNS_CLASS_IN);
        assert!(packet.len() > DnsHeader::SIZE);
        let header = DnsHeader::from_bytes(&packet).unwrap();
        assert_eq!(header.qdcount, 1);
        assert!(header.rd());
    }

    #[test]
    fn build_query_encodes_name() {
        let packet = build_query("example.com", DNS_TYPE_A, DNS_CLASS_IN);
        assert!(packet.len() > DnsHeader::SIZE);
        assert!(packet.windows(7).any(|w| w == b"example"));
        assert!(packet.windows(4).any(|w| w == b"com\0"));
    }

    #[test]
    fn dns_question_encode() {
        let q = DnsQuestion {
            name: "example.com".to_string(),
            qtype: DNS_TYPE_A,
            qclass: DNS_CLASS_IN,
        };
        let encoded = q.encode();
        assert!(encoded.starts_with(&[7]));
        assert!(encoded.windows(7).any(|w| w == b"example"));
    }

    #[test]
    fn stream_receiver_tracks_packets() {
        let mut rx = StreamReceiver::new();
        assert_eq!(rx.count(), 0);

        rx.on_packet(vec![1, 2, 3]);
        rx.on_packet(vec![4, 5, 6]);
        assert_eq!(rx.count(), 2);

        rx.clear();
        assert_eq!(rx.count(), 0);
    }

    #[test]
    fn dns_over_tls_mode_variants() {
        assert_ne!(DnsOverTlsMode::No, DnsOverTlsMode::Yes);
        assert_ne!(DnsOverTlsMode::Opportunistic, DnsOverTlsMode::Yes);
    }

    #[test]
    fn dns_header_roundtrip() -> Result<()> {
        let h = DnsHeader {
            id: 42,
            flags: 0x8180,
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };
        let bytes = h.to_bytes();
        let h2 = DnsHeader::from_bytes(&bytes)?;
        assert_eq!(h, h2);
        Ok(())
    }

    #[test]
    fn build_query_a_and_aaaa() {
        let q_a = build_query("example.com", DNS_TYPE_A, DNS_CLASS_IN);
        let q_aaaa = build_query("example.com", DNS_TYPE_AAAA, DNS_CLASS_IN);
        assert_ne!(q_a, q_aaaa);
        assert!(q_a.len() > DnsHeader::SIZE);
        assert!(q_aaaa.len() > DnsHeader::SIZE);
    }
}
