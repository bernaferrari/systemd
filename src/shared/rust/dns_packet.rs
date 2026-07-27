// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/dns-packet.c, src/shared/dns-packet.h
//
// DNS packet handling — constants, types, header parsing, and packet
// construction/parsing utilities. Implements RFC 1035 §4.1 packet format.

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum DNS packet size (RFC 1035 limits UDP messages to 512, but EDNS0
/// allows up to 65535 bytes on the wire).
use crate::ffi::*;
pub const DNS_PACKET_SIZE_MAX: usize = 0xFFFF;

/// Initial allocation size for new packets (at least one full DNS header).
pub const DNS_PACKET_SIZE_START: usize = 512;

/// Default unicast response size limit without EDNS0.
pub const DNS_PACKET_UNICAST_SIZE_MAX: usize = 512;

/// Larger unicast response size limit (DNS-over-HTTPS / DoQ typical).
pub const DNS_PACKET_UNICAST_SIZE_LARGE_MAX: usize = 1232;

/// DNS packet header is always 12 bytes (6 × u16 fields).
pub const DNS_PACKET_HEADER_SIZE: usize = 12;

/// Maximum length of a single DNS label (RFC 1035 §2.3.4).
pub const DNS_LABEL_MAX: usize = 63;

/// Maximum length of a DNS hostname in wire format (255 bytes, RFC 1035 §2.3.4).
pub const DNS_HOSTNAME_MAX: usize = 255;

/// UDP/IP header overhead sizes.
pub const UDP4_PACKET_HEADER_SIZE: usize = 20 + 8;
pub const UDP6_PACKET_HEADER_SIZE: usize = 40 + 8;

/// Flag bit positions in the 16-bit flags field.
pub const DNS_PACKET_FLAG_CD: u16 = 1 << 4;
pub const DNS_PACKET_FLAG_AD: u16 = 1 << 5;
pub const DNS_PACKET_FLAG_TC: u16 = 1 << 9;

/// EDNS0 OPT record DO (DNSSEC OK) bit.
pub const EDNS0_OPT_DO: u16 = 1 << 15;

// ── DNS Protocol ──────────────────────────────────────────────────────────

/// DNS protocol identifiers used to select wire format and validation rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum DnsProtocol {
    /// Standard DNS (port 53).
    Dns = 0,
    /// Multicast DNS (port 5353, RFC 6762).
    Mdns = 1,
    /// Link-Local Multicast Name Resolution (port 5355, RFC 4795).
    Llmnr = 2,
}

impl DnsProtocol {
    pub const MAX: i32 = 3;
    pub const INVALID: i32 = -22;
}

impl std::fmt::Display for DnsProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DnsProtocol::Dns => "dns",
            DnsProtocol::Mdns => "mdns",
            DnsProtocol::Llmnr => "llmnr",
        })
    }
}

/// Resolve a DNS protocol from its textual name.
pub fn dns_protocol_from_name(name: &str) -> Option<DnsProtocol> {
    match name {
        "dns" => Some(DnsProtocol::Dns),
        "mdns" | "mDNS" => Some(DnsProtocol::Mdns),
        "llmnr" | "LLMNR" => Some(DnsProtocol::Llmnr),
        _ => None,
    }
}

// ── DNS Response Codes ────────────────────────────────────────────────────

/// DNS response codes (RCODE) as defined in various RFCs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum DnsRcode {
    Success = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NXRRSet = 8,
    NotAuth = 9,
    NotZone = 10,
    DsoTypeNi = 11,
    BadVers = 16,
    BadKey = 17,
    BadTime = 18,
    BadMode = 19,
    BadName = 20,
    BadAlg = 21,
    BadTrunc = 22,
    BadCookie = 23,
}

impl DnsRcode {
    pub const MAX_DEFINED: i32 = 24;
    pub const MAX: i32 = 65535;
    pub const INVALID: i32 = -22;

    /// Convert a numeric rcode to its canonical name.
    pub fn to_string_lossy(code: i32) -> &'static str {
        match code {
            0 => "SUCCESS",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            6 => "YXDOMAIN",
            7 => "YXRRSET",
            8 => "NXRRSET",
            9 => "NOTAUTH",
            10 => "NOTZONE",
            11 => "DSOTYPENI",
            16 => "BADVERS",
            17 => "BADKEY",
            18 => "BADTIME",
            19 => "BADMODE",
            20 => "BADNAME",
            21 => "BADALG",
            22 => "BADTRUNC",
            23 => "BADCOOKIE",
            _ => "<unknown>",
        }
    }

    /// Check if an Extended DNS Error (EDE) rcode is DNSSEC-related.
    pub fn is_dnssec(ede_rcode: i32) -> bool {
        matches!(ede_rcode, 5..=12)
    }
}

// ── EDNS0 Option Codes ────────────────────────────────────────────────────

/// EDNS0 option codes (RFC 6891 and others).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum DnsEdnsOpt {
    Reserved = 0,
    Llq = 1,
    Ul = 2,
    Nsid = 3,
    Dau = 5,
    Dhu = 6,
    N3u = 7,
    ClientSubnet = 8,
    Expire = 9,
    Cookie = 10,
    TcpKeepalive = 11,
    Padding = 12,
    Chain = 13,
    KeyTag = 14,
    ExtError = 15,
    ClientTag = 16,
    ServerTag = 17,
}

impl DnsEdnsOpt {
    pub const MAX_DEFINED: i32 = 18;
    pub const INVALID: i32 = -22;
}

// ── Extended DNS Error Codes ──────────────────────────────────────────────

/// Extended DNS Error (EDE) codes (RFC 8914).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum DnsEdeRcode {
    Other = 0,
    UnsupportedDnskeyAlg = 1,
    UnsupportedDsDigest = 2,
    StaleAnswer = 3,
    ForgedAnswer = 4,
    DnssecIndeterminate = 5,
    DnssecBogus = 6,
    SigExpired = 7,
    SigNotYetValid = 8,
    DnskeyMissing = 9,
    RrsigMissing = 10,
    NoZoneKeyBit = 11,
    NsecMissing = 12,
    CachedError = 13,
    NotReady = 14,
    Blocked = 15,
    Censored = 16,
    Filtered = 17,
    Prohibited = 18,
    StaleNxdomainAnswer = 19,
    NotAuthoritative = 20,
    NotSupported = 21,
    UnreachAuthority = 22,
    NetError = 23,
    InvalidData = 24,
    SigNever = 25,
    TooEarly = 26,
    UnsupportedNsec3Iter = 27,
    TransportPolicy = 28,
    Synthesized = 29,
}

impl DnsEdeRcode {
    pub const MAX_DEFINED: i32 = 30;
    pub const INVALID: i32 = -22;
}

// ── SVCB/HTTPS Parameter Keys ─────────────────────────────────────────────

/// SVCB and HTTPS record parameter keys (RFC 9460).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DnsSvcParamKey {
    Mandatory = 0,
    Alpn = 1,
    NoDefaultAlpn = 2,
    Port = 3,
    Ipv4Hint = 4,
    Ech = 5,
    Ipv6Hint = 6,
    DohPath = 7,
    Ohttp = 8,
}

impl DnsSvcParamKey {
    pub const MAX_DEFINED: u16 = 9;
    pub const INVALID: u16 = 65535;
}

// ── Multicast Addresses ───────────────────────────────────────────────────

/// LLMNR multicast addresses (RFC 4795 §2).
pub const LLMNR_MULTICAST_IPV4: [u8; 4] = [224, 0, 252, 0];
pub const LLMNR_MULTICAST_IPV6: [u8; 16] = [
    0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03,
];

/// mDNS multicast addresses (RFC 6762).
pub const MDNS_MULTICAST_IPV4: [u8; 4] = [224, 0, 0, 251];
pub const MDNS_MULTICAST_IPV6: [u8; 16] = [
    0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFB,
];

// ── DNS Packet Header ─────────────────────────────────────────────────────

/// DNS packet header in host byte order.
///
/// [`DnsPacketHeader::decode`] and [`DnsPacketHeader::encode`] translate this
/// value to and from the 12-byte, big-endian DNS wire format. Keeping the
/// decoded value separate from the packet buffer avoids both alignment
/// assumptions and accidentally applying DNS flag operations to wire-order
/// integers.
///
/// Layout per RFC 1035 §4.1.1:
/// ```text
///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    QDCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ANCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    NSCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                    ARCOUNT                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone, Copy)]
pub struct DnsPacketHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Default for DnsPacketHeader {
    fn default() -> Self {
        Self::new(0)
    }
}

impl DnsPacketHeader {
    pub const SIZE: usize = DNS_PACKET_HEADER_SIZE;

    /// Decode a header from the first 12 bytes of a DNS wire packet.
    #[inline]
    pub fn decode(wire: &[u8]) -> Option<Self> {
        let wire = wire.get(..Self::SIZE)?;

        Some(Self {
            id: read_be16(&wire[0..2]),
            flags: read_be16(&wire[2..4]),
            qdcount: read_be16(&wire[4..6]),
            ancount: read_be16(&wire[6..8]),
            nscount: read_be16(&wire[8..10]),
            arcount: read_be16(&wire[10..12]),
        })
    }

    /// Encode this host-order header into the first 12 bytes of a DNS wire packet.
    ///
    /// Returns `false` without modifying `wire` when it is too short.
    #[inline]
    pub fn encode(&self, wire: &mut [u8]) -> bool {
        let Some(wire) = wire.get_mut(..Self::SIZE) else {
            return false;
        };

        write_be16(&mut wire[0..2], self.id);
        write_be16(&mut wire[2..4], self.flags);
        write_be16(&mut wire[4..6], self.qdcount);
        write_be16(&mut wire[6..8], self.ancount);
        write_be16(&mut wire[8..10], self.nscount);
        write_be16(&mut wire[10..12], self.arcount);
        true
    }

    /// Create a new header with the given transaction ID.
    pub const fn new(id: u16) -> Self {
        Self {
            id,
            flags: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    // ── Flag field accessors ──────────────────────────────────────────

    /// QR bit: 0 = query, 1 = response.
    #[inline]
    pub fn qr(&self) -> bool {
        (self.flags >> 15) & 1 == 1
    }

    /// OPCODE field (4 bits): query type (0 = standard query).
    #[inline]
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0xF) as u8
    }

    /// AA bit: authoritative answer.
    #[inline]
    pub fn aa(&self) -> bool {
        (self.flags >> 10) & 1 == 1
    }

    /// TC bit: truncation — message was truncated.
    #[inline]
    pub fn tc(&self) -> bool {
        (self.flags >> 9) & 1 == 1
    }

    /// RD bit: recursion desired.
    #[inline]
    pub fn rd(&self) -> bool {
        (self.flags >> 8) & 1 == 1
    }

    /// RA bit: recursion available.
    #[inline]
    pub fn ra(&self) -> bool {
        (self.flags >> 7) & 1 == 1
    }

    /// AD bit: authenticated data (DNSSEC).
    #[inline]
    pub fn ad(&self) -> bool {
        (self.flags >> 5) & 1 == 1
    }

    /// CD bit: checking disabled (DNSSEC).
    #[inline]
    pub fn cd(&self) -> bool {
        (self.flags >> 4) & 1 == 1
    }

    /// RCODE field (4 bits): response code.
    #[inline]
    pub fn rcode(&self) -> u8 {
        (self.flags & 0xF) as u8
    }

    /// Construct a 16-bit flags word from individual fields.
    #[inline]
    pub const fn make_flags(
        qr: bool,
        opcode: u8,
        aa: bool,
        tc: bool,
        rd: bool,
        ra: bool,
        ad: bool,
        cd: bool,
        rcode: u8,
    ) -> u16 {
        ((qr as u16) << 15)
            | (((opcode & 0xF) as u16) << 11)
            | ((aa as u16) << 10)
            | ((tc as u16) << 9)
            | ((rd as u16) << 8)
            | ((ra as u16) << 7)
            | ((ad as u16) << 5)
            | ((cd as u16) << 4)
            | ((rcode & 0xF) as u16)
    }

    /// Set default query flags for the given protocol.
    ///
    /// Mirrors `dns_packet_set_flags()` from dns-packet.c.
    pub fn set_query_flags(&mut self, protocol: DnsProtocol, dnssec_cd: bool, truncated: bool) {
        self.flags = match protocol {
            DnsProtocol::Llmnr => {
                assert!(!truncated, "LLMNR queries must not set TC");
                Self::make_flags(false, 0, false, false, false, false, false, false, 0)
            }
            DnsProtocol::Mdns => {
                Self::make_flags(false, 0, false, truncated, false, false, false, false, 0)
            }
            _ => {
                assert!(!truncated, "DNS queries must not set TC");
                Self::make_flags(false, 0, false, false, true, false, false, dnssec_cd, 0)
            }
        };
    }

    /// Increment QDCOUNT by one.
    pub fn inc_qdcount(&mut self) -> Result<(), DnsPacketError> {
        self.qdcount = self
            .qdcount
            .checked_add(1)
            .ok_or(DnsPacketError::TooLarge)?;
        Ok(())
    }

    /// Increment ARCOUNT by one (used when appending OPT records).
    pub fn inc_arcount(&mut self) -> Result<(), DnsPacketError> {
        self.arcount = self
            .arcount
            .checked_add(1)
            .ok_or(DnsPacketError::TooLarge)?;
        Ok(())
    }

    /// Decrement ARCOUNT by one (used when truncating OPT records).
    pub fn dec_arcount(&mut self) -> Result<(), DnsPacketError> {
        self.arcount = self
            .arcount
            .checked_sub(1)
            .ok_or(DnsPacketError::BadMessage)?;
        Ok(())
    }
}

// ── Byte-order helpers ────────────────────────────────────────────────────

/// Read a big-endian u16 from a byte slice (unaligned-safe).
#[inline]
fn read_be16(buf: &[u8]) -> u16 {
    u16::from_be_bytes([buf[0], buf[1]])
}

/// Write a big-endian u16 into a byte slice (unaligned-safe).
#[inline]
fn write_be16(buf: &mut [u8], val: u16) {
    let bytes = val.to_be_bytes();
    buf[0] = bytes[0];
    buf[1] = bytes[1];
}

/// Read a big-endian u32 from a byte slice (unaligned-safe).
#[inline]
fn read_be32(buf: &[u8]) -> u32 {
    u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]])
}

/// Write a big-endian u32 into a byte slice (unaligned-safe).
#[inline]
fn write_be32(buf: &mut [u8], val: u32) {
    let bytes = val.to_be_bytes();
    buf.copy_from_slice(&bytes);
}

// ── DNS Packet Builder ────────────────────────────────────────────────────

/// Error type for DNS packet operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsPacketError {
    /// Packet too large.
    MessageTooLong,
    /// Out of memory / allocation failure.
    OutOfMemory,
    /// Invalid argument (e.g. bad domain name).
    InvalidArgument,
    /// Malformed packet data.
    BadMessage,
    /// Invalid state (e.g. OPT already appended).
    Busy,
    /// Not enough space.
    NoSpace,
    /// Value too large.
    TooLarge,
}

impl std::fmt::Display for DnsPacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsPacketError::MessageTooLong => write!(f, "DNS message too long"),
            DnsPacketError::OutOfMemory => write!(f, "out of memory"),
            DnsPacketError::InvalidArgument => write!(f, "invalid argument"),
            DnsPacketError::BadMessage => write!(f, "bad DNS message"),
            DnsPacketError::Busy => write!(f, "invalid state / busy"),
            DnsPacketError::NoSpace => write!(f, "no space"),
            DnsPacketError::TooLarge => write!(f, "value too large"),
        }
    }
}

impl std::error::Error for DnsPacketError {}

/// A DNS packet buffer for constructing and parsing DNS messages.
///
/// Manages a growable byte buffer with a read cursor (`rindex`). The first
/// 12 bytes are always the DNS header.
#[derive(Debug, Clone)]
pub struct DnsPacket {
    /// Wire-format packet data (header + payload).
    data: Vec<u8>,
    /// Read cursor position (always ≥ `DNS_PACKET_HEADER_SIZE`).
    rindex: usize,
    /// Maximum allowed packet size.
    max_size: usize,
    /// Protocol in use (affects validation rules).
    pub protocol: DnsProtocol,
    /// Whether to use DNSSEC canonical form for appended names.
    pub canonical_form: bool,
    /// Whether to refuse name compression pointers.
    pub refuse_compression: bool,
    /// Name compression table: domain name → offset.
    compression_names: Vec<(String, usize)>,
    /// Offset of the OPT pseudo-RR, or `None` if not yet appended.
    opt_start: Option<usize>,
    /// Size of the OPT pseudo-RR.
    opt_size: usize,
}

impl DnsPacket {
    /// Create a new DNS packet with default allocation.
    pub fn new(protocol: DnsProtocol) -> Self {
        Self::with_capacity(protocol, DNS_PACKET_SIZE_START, DNS_PACKET_SIZE_MAX)
    }

    /// Create a new DNS packet with the specified minimum allocation and maximum size.
    pub fn with_capacity(protocol: DnsProtocol, min_alloc: usize, max_size: usize) -> Self {
        let max_size = max_size
            .max(DNS_PACKET_HEADER_SIZE)
            .min(DNS_PACKET_SIZE_MAX);
        let alloc = if min_alloc < DNS_PACKET_HEADER_SIZE {
            DNS_PACKET_SIZE_START
        } else {
            min_alloc
        };
        let alloc = alloc.min(max_size);

        let mut data = Vec::with_capacity(alloc);
        data.resize(DNS_PACKET_HEADER_SIZE, 0);
        // Initialize rindex past the header
        let rindex = DNS_PACKET_HEADER_SIZE;

        Self {
            data,
            rindex,
            max_size,
            protocol,
            canonical_form: false,
            refuse_compression: false,
            compression_names: Vec::new(),
            opt_start: None,
            opt_size: usize::MAX,
        }
    }

    /// Create a new query packet with appropriate default flags set.
    pub fn new_query(protocol: DnsProtocol, dnssec_cd: bool) -> Self {
        let mut pkt = Self::new(protocol);
        pkt.set_flags(protocol, dnssec_cd, false)
            .expect("new packets always contain a DNS header");
        pkt
    }

    /// Access the raw packet data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Mutable access to the raw packet data.
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Current filled size of the packet (valid bytes).
    pub fn size(&self) -> usize {
        self.data.len().min(self.max_size)
    }

    /// Set the logical size of the packet (for truncation).
    pub fn set_size(&mut self, sz: usize) {
        let sz = sz.min(self.max_size).min(self.data.len());
        // Remove compression entries pointing past the new size
        self.compression_names.retain(|(_, off)| *off < sz);
        self.data.truncate(sz);
    }

    /// Read cursor position.
    pub fn rindex(&self) -> usize {
        self.rindex
    }

    /// Reset the read cursor.
    pub fn rewind(&mut self, idx: usize) {
        assert!(idx >= DNS_PACKET_HEADER_SIZE && idx <= self.data.len());
        self.rindex = idx;
    }

    /// Decode the DNS header from the packet's wire-format buffer.
    pub fn header(&self) -> Result<DnsPacketHeader, DnsPacketError> {
        DnsPacketHeader::decode(&self.data).ok_or(DnsPacketError::BadMessage)
    }

    /// Encode a host-order header into the packet's wire-format buffer.
    pub fn set_header(&mut self, header: DnsPacketHeader) -> Result<(), DnsPacketError> {
        if header.encode(&mut self.data) {
            Ok(())
        } else {
            Err(DnsPacketError::BadMessage)
        }
    }

    /// Decode, update, and re-encode the packet header.
    pub fn update_header<F>(&mut self, update: F) -> Result<(), DnsPacketError>
    where
        F: FnOnce(&mut DnsPacketHeader) -> Result<(), DnsPacketError>,
    {
        let mut header = self.header()?;
        update(&mut header)?;
        self.set_header(header)
    }

    /// Set protocol-specific query flags.
    pub fn set_flags(
        &mut self,
        protocol: DnsProtocol,
        dnssec_cd: bool,
        truncated: bool,
    ) -> Result<(), DnsPacketError> {
        self.update_header(|header| {
            header.set_query_flags(protocol, dnssec_cd, truncated);
            Ok(())
        })
    }

    /// Validate that the packet has a valid size.
    pub fn validate(&self) -> Result<(), DnsPacketError> {
        if self.data.len() < DNS_PACKET_HEADER_SIZE {
            return Err(DnsPacketError::BadMessage);
        }
        if self.data.len() > DNS_PACKET_SIZE_MAX {
            return Err(DnsPacketError::BadMessage);
        }
        Ok(())
    }

    /// Validate as a DNS reply packet.
    pub fn validate_reply(&self) -> Result<(), DnsPacketError> {
        self.validate()?;
        let hdr = self.header()?;

        if !hdr.qr() {
            return Err(DnsPacketError::BadMessage);
        }
        if hdr.opcode() != 0 {
            return Err(DnsPacketError::BadMessage);
        }

        match self.protocol {
            DnsProtocol::Llmnr => {
                if hdr.qdcount != 1 {
                    return Err(DnsPacketError::BadMessage);
                }
            }
            DnsProtocol::Mdns => {
                // mDNS replies must have rcode 0
                if hdr.rcode() != 0 {
                    return Err(DnsPacketError::BadMessage);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Validate as a DNS query packet.
    pub fn validate_query(&self) -> Result<(), DnsPacketError> {
        self.validate()?;
        let hdr = self.header()?;

        if hdr.qr() {
            return Err(DnsPacketError::BadMessage);
        }
        if hdr.opcode() != 0 {
            return Err(DnsPacketError::BadMessage);
        }

        match self.protocol {
            DnsProtocol::Dns => {
                if hdr.tc() {
                    return Err(DnsPacketError::BadMessage);
                }
                if hdr.qdcount != 1 {
                    return Err(DnsPacketError::BadMessage);
                }
                if hdr.ancount > 0 {
                    return Err(DnsPacketError::BadMessage);
                }
            }
            DnsProtocol::Llmnr => {
                if hdr.tc() {
                    return Err(DnsPacketError::BadMessage);
                }
                if hdr.qdcount != 1 {
                    return Err(DnsPacketError::BadMessage);
                }
                if hdr.ancount > 0 {
                    return Err(DnsPacketError::BadMessage);
                }
                if hdr.nscount > 0 {
                    return Err(DnsPacketError::BadMessage);
                }
            }
            DnsProtocol::Mdns => {
                if hdr.rcode() != 0 {
                    return Err(DnsPacketError::BadMessage);
                }
            }
        }
        Ok(())
    }

    /// Extend the packet buffer by `add` bytes, returning a mutable slice
    /// to the new region.
    fn extend(&mut self, add: usize) -> Result<&mut [u8], DnsPacketError> {
        let old_len = self.data.len();
        let new_len = old_len
            .checked_add(add)
            .ok_or(DnsPacketError::MessageTooLong)?;
        if new_len > self.max_size {
            return Err(DnsPacketError::MessageTooLong);
        }
        if new_len > self.data.capacity() {
            let new_cap = new_len
                .checked_mul(2)
                .unwrap_or(self.max_size)
                .min(self.max_size);
            if new_cap < new_len {
                return Err(DnsPacketError::MessageTooLong);
            }
            self.data.reserve(new_cap - self.data.len());
        }
        self.data.resize(new_len, 0);
        Ok(&mut self.data[old_len..])
    }

    // ── Append operations ─────────────────────────────────────────────

    /// Append a raw byte slice.
    pub fn append_blob(&mut self, d: &[u8]) -> Result<usize, DnsPacketError> {
        let start = self.data.len();
        let buf = self.extend(d.len())?;
        buf.copy_from_slice(d);
        Ok(start)
    }

    /// Append a single byte.
    pub fn append_u8(&mut self, v: u8) -> Result<usize, DnsPacketError> {
        let start = self.data.len();
        let buf = self.extend(1)?;
        buf[0] = v;
        Ok(start)
    }

    /// Append a big-endian u16.
    pub fn append_u16(&mut self, v: u16) -> Result<usize, DnsPacketError> {
        let start = self.data.len();
        let buf = self.extend(2)?;
        write_be16(buf, v);
        Ok(start)
    }

    /// Append a big-endian u32.
    pub fn append_u32(&mut self, v: u32) -> Result<usize, DnsPacketError> {
        let start = self.data.len();
        let buf = self.extend(4)?;
        write_be32(buf, v);
        Ok(start)
    }

    /// Append a DNS character-string (length-prefixed, max 255 bytes).
    pub fn append_string(&mut self, s: &[u8]) -> Result<usize, DnsPacketError> {
        self.append_raw_string(s)
    }

    /// Append a raw DNS character-string (length byte + data).
    pub fn append_raw_string(&mut self, s: &[u8]) -> Result<usize, DnsPacketError> {
        if s.len() > 255 {
            return Err(DnsPacketError::TooLarge);
        }
        let start = self.data.len();
        let buf = self.extend(1 + s.len())?;
        buf[0] = s.len() as u8;
        buf[1..].copy_from_slice(s);
        Ok(start)
    }

    /// Append a DNS label (length byte + data, max 63 bytes).
    ///
    /// If `canonical_form` is set on the packet and `canonical_candidate`
    /// is true, the label is lowercased per RFC 4034 §6.2.
    pub fn append_label(
        &mut self,
        label: &[u8],
        canonical_candidate: bool,
    ) -> Result<usize, DnsPacketError> {
        if label.len() > DNS_LABEL_MAX {
            return Err(DnsPacketError::TooLarge);
        }
        let start = self.data.len();
        let do_canonical = self.canonical_form && canonical_candidate;
        let buf = self.extend(1 + label.len())?;
        buf[0] = label.len() as u8;
        if do_canonical {
            for (i, &b) in label.iter().enumerate() {
                buf[i + 1] = b.to_ascii_lowercase();
            }
        } else {
            buf[1..].copy_from_slice(label);
        }
        Ok(start)
    }

    /// Append a null terminator (root label) for a domain name.
    pub fn append_name_terminator(&mut self) -> Result<usize, DnsPacketError> {
        self.append_u8(0)
    }

    /// Truncate the packet back to a given size.
    pub fn truncate(&mut self, sz: usize) {
        if self.data.len() > sz {
            self.set_size(sz);
        }
    }

    /// Get the RCODE, combining the base RCODE with any extended RCODE
    /// from the OPT record (upper 8 bits of the extended RCODE).
    pub fn rcode(&self) -> Result<u16, DnsPacketError> {
        Ok(self.header()?.rcode() as u16)
    }

    /// Get the advertised maximum payload size for replies.
    pub fn payload_size_max(&self) -> usize {
        // On TCP, ignore EDNS0 size data (like everybody else)
        DNS_PACKET_UNICAST_SIZE_MAX
    }

    /// Check if the DNSSEC OK (DO) bit is set in the OPT record.
    pub fn do_bit(&self) -> bool {
        self.opt_start.is_some()
    }

    /// Check if the EDNS version is supported (0 or no OPT).
    pub fn version_supported(&self) -> bool {
        // No OPT record means basic DNS, which is supported.
        // If we had OPT parsing, we'd check version == 0 here.
        true
    }

    /// Duplicate this packet.
    pub fn dup(&self) -> Result<Self, DnsPacketError> {
        self.validate()?;
        Ok(Self {
            data: self.data.clone(),
            rindex: DNS_PACKET_HEADER_SIZE,
            max_size: self.max_size,
            protocol: self.protocol,
            canonical_form: false,
            refuse_compression: false,
            compression_names: Vec::new(),
            opt_start: None,
            opt_size: usize::MAX,
        })
    }
}

// ── DNS Packet Reader ─────────────────────────────────────────────────────

/// Read cursor for parsing a DNS packet.
pub struct DnsPacketReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DnsPacketReader<'a> {
    /// Create a reader starting at the given position.
    pub fn new(data: &'a [u8], start: usize) -> Self {
        Self { data, pos: start }
    }

    /// Create a reader positioned right after the DNS header.
    pub fn from_packet(pkt: &'a DnsPacket) -> Self {
        Self::new(&pkt.data, DNS_PACKET_HEADER_SIZE)
    }

    /// Current read position.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Remaining bytes available.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Rewind to a previous position.
    pub fn rewind(&mut self, idx: usize) {
        assert!(idx >= DNS_PACKET_HEADER_SIZE && idx <= self.data.len());
        self.pos = idx;
    }

    /// Read exactly `sz` bytes, returning a slice.
    pub fn read(&mut self, sz: usize) -> Result<&'a [u8], DnsPacketError> {
        if sz > self.remaining() {
            return Err(DnsPacketError::MessageTooLong);
        }
        let slice = &self.data[self.pos..self.pos + sz];
        self.pos += sz;
        Ok(slice)
    }

    /// Read a single byte.
    pub fn read_u8(&mut self) -> Result<u8, DnsPacketError> {
        let buf = self.read(1)?;
        Ok(buf[0])
    }

    /// Read a big-endian u16.
    pub fn read_u16(&mut self) -> Result<u16, DnsPacketError> {
        let buf = self.read(2)?;
        Ok(read_be16(buf))
    }

    /// Read a big-endian u32.
    pub fn read_u32(&mut self) -> Result<u32, DnsPacketError> {
        let buf = self.read(4)?;
        Ok(read_be32(buf))
    }

    /// Read a DNS character-string (length-prefixed).
    pub fn read_string(&mut self) -> Result<&'a [u8], DnsPacketError> {
        let len = self.read_u8()? as usize;
        self.read(len)
    }

    /// Read a DNS name, handling compression pointers if allowed.
    ///
    /// Returns the domain name as a dotted string (e.g. "www.example.com").
    pub fn read_name(&mut self, allow_compression: bool) -> Result<String, DnsPacketError> {
        let mut labels = Vec::new();
        let mut seen_offsets = Vec::new();
        let mut after_offset = None;
        let mut total_label_len = 0usize;

        loop {
            let c = self.read_u8()?;

            if c == 0 {
                // End of name
                break;
            } else if c <= 63 {
                // Literal label
                let label_data = self.read(c as usize)?;
                total_label_len += c as usize;
                if total_label_len > DNS_HOSTNAME_MAX {
                    return Err(DnsPacketError::BadMessage);
                }
                // Convert to string, escaping dots
                let label_str = String::from_utf8_lossy(label_data).to_string();
                labels.push(label_str);
            } else if allow_compression && (c & 0xC0) == 0xC0 {
                // Compression pointer
                let d = self.read_u8()?;
                let ptr = (((c & 0x3F) as usize) << 8) | (d as usize);
                if ptr < DNS_PACKET_HEADER_SIZE || ptr >= self.pos {
                    return Err(DnsPacketError::BadMessage);
                }
                // Detect loops
                if seen_offsets.contains(&ptr) {
                    return Err(DnsPacketError::BadMessage);
                }
                seen_offsets.push(ptr);
                if after_offset.is_none() {
                    after_offset = Some(self.pos);
                }
                self.pos = ptr;
            } else {
                return Err(DnsPacketError::BadMessage);
            }
        }

        // Restore position after following pointers
        if let Some(offset) = after_offset {
            self.pos = offset;
        }

        Ok(labels.join("."))
    }
}

// ── LOC record validation ─────────────────────────────────────────────────

/// Validate a LOC record size byte per RFC 1876.
pub fn loc_size_ok(size: u8) -> bool {
    // The size byte uses a 4-bit mantissa and 4-bit exponent encoding.
    // The top 4 bits must not all be 1 (reserved) and the bottom 4 bits
    // encode a power-of-10 base value (0–9).
    let mantissa = size >> 4;
    let exponent = size & 0x0F;
    mantissa < 0x0F && exponent <= 9
}

// ── OPT record helpers ────────────────────────────────────────────────────

/// Check if a DNS RR type is a pseudo-type (per RFC 4034 §4.1.2).
pub fn dns_type_is_pseudo(rr_type: u16) -> bool {
    // Pseudo-types are in the range 0xFF00–0xFFFF (meta RR types).
    // Also TYPE_OPT (41) is a pseudo-type.
    rr_type == 41 || rr_type >= 0xFF00
}

// ── SVCB parameter validation ─────────────────────────────────────────────

/// Validate an SVCB/HTTPS parameter key.
pub fn dns_svc_param_is_valid(key: u16) -> bool {
    // Mandatory (0) is only valid in the first occurrence
    // and must not appear in the AliasMode form.
    // For simplicity, we accept all defined keys.
    key <= DnsSvcParamKey::MAX_DEFINED as u16
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_size() {
        assert_eq!(DnsPacketHeader::SIZE, 12);
    }

    #[test]
    fn test_header_new_default() {
        let h = DnsPacketHeader::new(0x1234);
        assert_eq!(h.id, 0x1234);
        assert_eq!(h.flags, 0);
        assert_eq!(h.qdcount, 0);
    }

    #[test]
    fn test_header_decode_encode_uses_network_byte_order() {
        let wire = [
            0x12, 0x34, 0x85, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
        ];
        let header = DnsPacketHeader::decode(&wire).unwrap();

        assert_eq!(header.id, 0x1234);
        assert_eq!(header.flags, 0x8580);
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.ancount, 2);
        assert_eq!(header.nscount, 3);
        assert_eq!(header.arcount, 4);

        let mut encoded = [0u8; DNS_PACKET_HEADER_SIZE];
        assert!(header.encode(&mut encoded));
        assert_eq!(encoded, wire);
    }

    #[test]
    fn test_header_rejects_short_buffers() {
        assert!(DnsPacketHeader::decode(&[0; DNS_PACKET_HEADER_SIZE - 1]).is_none());

        let mut short_wire = [0u8; DNS_PACKET_HEADER_SIZE - 1];
        assert!(!DnsPacketHeader::new(0).encode(&mut short_wire));
    }

    #[test]
    fn test_header_flag_extraction() {
        let mut h = DnsPacketHeader::new(0);
        h.flags = DnsPacketHeader::make_flags(true, 0, true, false, true, false, true, true, 3);
        assert!(h.qr());
        assert!(h.aa());
        assert!(!h.tc());
        assert!(h.rd());
        assert!(!h.ra());
        assert!(h.ad());
        assert!(h.cd());
        assert_eq!(h.rcode(), 3);
        assert_eq!(h.opcode(), 0);
    }

    #[test]
    fn test_header_set_query_flags_dns() {
        let mut h = DnsPacketHeader::new(0);
        h.set_query_flags(DnsProtocol::Dns, true, false);
        assert!(!h.qr());
        assert!(h.rd());
        assert!(h.cd());
        assert!(!h.tc());
        assert!(!h.aa());
    }

    #[test]
    fn test_header_set_query_flags_llmnr() {
        let mut h = DnsPacketHeader::new(0);
        h.set_query_flags(DnsProtocol::Llmnr, false, false);
        assert!(!h.rd());
        assert!(!h.cd());
        assert!(!h.tc());
    }

    #[test]
    fn test_header_set_query_flags_mdns() {
        let mut h = DnsPacketHeader::new(0);
        h.set_query_flags(DnsProtocol::Mdns, false, true);
        assert!(h.tc());
        assert!(!h.rd());
    }

    #[test]
    fn test_header_counter_bounds() {
        let mut header = DnsPacketHeader::new(0);
        header.qdcount = u16::MAX;
        assert_eq!(header.inc_qdcount(), Err(DnsPacketError::TooLarge));

        assert_eq!(header.dec_arcount(), Err(DnsPacketError::BadMessage));
        header.arcount = u16::MAX - 1;
        header.inc_arcount().unwrap();
        assert_eq!(header.arcount, u16::MAX);
    }

    #[test]
    fn test_make_flags_roundtrip() {
        let flags = DnsPacketHeader::make_flags(true, 5, true, true, true, true, true, true, 15);
        assert_eq!(flags >> 15 & 1, 1); // QR
        assert_eq!(flags >> 11 & 0xF, 5); // OPCODE
        assert_eq!(flags & 0xF, 15); // RCODE
    }

    #[test]
    fn test_packet_new() {
        let pkt = DnsPacket::new(DnsProtocol::Dns);
        assert!(pkt.data().len() >= DNS_PACKET_HEADER_SIZE);
        assert_eq!(pkt.rindex(), DNS_PACKET_HEADER_SIZE);
        assert_eq!(pkt.protocol, DnsProtocol::Dns);
    }

    #[test]
    fn test_packet_header_update_is_encoded_and_short_packets_fail_closed() {
        let mut pkt = DnsPacket::new(DnsProtocol::Dns);
        pkt.update_header(|header| {
            header.id = 0x1234;
            header.qdcount = 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(&pkt.data()[0..6], &[0x12, 0x34, 0, 0, 0, 1]);
        assert_eq!(pkt.header().unwrap().id, 0x1234);

        pkt.set_size(DNS_PACKET_HEADER_SIZE - 1);
        assert!(matches!(pkt.header(), Err(DnsPacketError::BadMessage)));
        assert!(matches!(
            pkt.update_header(|_| Ok(())),
            Err(DnsPacketError::BadMessage)
        ));
    }

    #[test]
    fn test_packet_append_and_read() {
        let mut pkt = DnsPacket::new(DnsProtocol::Dns);
        pkt.append_u16(0xABCD).unwrap();
        pkt.append_u32(0x12345678).unwrap();

        let mut reader = DnsPacketReader::from_packet(&pkt);
        assert_eq!(reader.read_u16().unwrap(), 0xABCD);
        assert_eq!(reader.read_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_packet_validate() {
        let pkt = DnsPacket::new(DnsProtocol::Dns);
        assert!(pkt.validate().is_ok());

        // Packet with header-only is valid
        let mut tiny = pkt;
        tiny.data.truncate(DNS_PACKET_HEADER_SIZE);
        assert!(tiny.validate().is_ok());
    }

    #[test]
    fn test_packet_validate_query_dns() {
        let mut pkt = DnsPacket::new(DnsProtocol::Dns);
        pkt.update_header(|hdr| {
            hdr.flags = 0; // QR=0, OPCODE=0
            hdr.qdcount = 1;
            hdr.ancount = 0;
            Ok(())
        })
        .unwrap();
        assert!(pkt.validate_query().is_ok());

        // Response should fail
        pkt.update_header(|hdr| {
            hdr.flags = 0x8000; // QR=1
            Ok(())
        })
        .unwrap();
        assert!(pkt.validate_query().is_err());

        // TC set should fail for DNS
        let mut pkt2 = DnsPacket::new(DnsProtocol::Dns);
        pkt2
            .update_header(|hdr| {
                hdr.flags = 0x0200; // TC=1
                hdr.qdcount = 1;
                Ok(())
            })
            .unwrap();
        assert!(pkt2.validate_query().is_err());
    }

    #[test]
    fn test_packet_validate_reply() {
        let mut pkt = DnsPacket::new(DnsProtocol::Dns);
        pkt.update_header(|hdr| {
            hdr.flags = 0x8000; // QR=1
            Ok(())
        })
        .unwrap();
        assert!(pkt.validate_reply().is_ok());

        // Query should fail
        pkt.update_header(|hdr| {
            hdr.flags = 0;
            Ok(())
        })
        .unwrap();
        assert!(pkt.validate_reply().is_err());
    }

    #[test]
    fn test_packet_dup() {
        let mut pkt = DnsPacket::new(DnsProtocol::Dns);
        pkt.append_u16(0xAAAA).unwrap();
        let dup = pkt.dup().unwrap();
        assert_eq!(dup.data(), pkt.data());
        assert_eq!(dup.rindex(), DNS_PACKET_HEADER_SIZE);
    }

    #[test]
    fn test_packet_truncate() {
        let mut pkt = DnsPacket::new(DnsProtocol::Dns);
        pkt.append_u16(0x1111).unwrap();
        pkt.append_u16(0x2222).unwrap();
        let size_before = pkt.data().len();
        pkt.truncate(size_before - 2);
        assert_eq!(pkt.data().len(), size_before - 2);
    }

    #[test]
    fn test_packet_append_blob() {
        let mut pkt = DnsPacket::new(DnsProtocol::Dns);
        let data = [1, 2, 3, 4, 5];
        pkt.append_blob(&data).unwrap();
        let mut reader = DnsPacketReader::from_packet(&pkt);
        assert_eq!(reader.read(5).unwrap(), &data[..]);
    }

    #[test]
    fn test_packet_append_string() {
        let mut pkt = DnsPacket::new(DnsProtocol::Dns);
        pkt.append_string(b"hello").unwrap();
        let mut reader = DnsPacketReader::from_packet(&pkt);
        assert_eq!(reader.read_string().unwrap(), b"hello");
    }

    #[test]
    fn test_packet_append_label() {
        let mut pkt = DnsPacket::new(DnsProtocol::Dns);
        pkt.append_label(b"www", false).unwrap();
        pkt.append_label(b"example", false).unwrap();
        pkt.append_label(b"com", false).unwrap();
        pkt.append_u8(0).unwrap(); // root terminator
                                   // Each label is prefixed with its length byte: \x03www\x07example\x03com\x00
        assert_eq!(
            pkt.data().len(),
            DNS_PACKET_HEADER_SIZE + (1 + 3) + (1 + 7) + (1 + 3) + 1
        );
    }

    #[test]
    fn test_packet_append_label_canonical() {
        let mut pkt = DnsPacket::new(DnsProtocol::Dns);
        pkt.canonical_form = true;
        pkt.append_label(b"WWW", true).unwrap();
        pkt.append_label(b"Example", true).unwrap();
        pkt.append_label(b"COM", true).unwrap();
        pkt.append_u8(0).unwrap();

        // After header, data should be: \x03www\x07example\x03com\x00
        let payload = &pkt.data()[DNS_PACKET_HEADER_SIZE..];
        assert_eq!(payload, b"\x03www\x07example\x03com\x00");
    }

    #[test]
    fn test_packet_append_raw_string_too_long() {
        let mut pkt = DnsPacket::new(DnsProtocol::Dns);
        let long = vec![0u8; 256];
        assert!(pkt.append_raw_string(&long).is_err());
    }

    #[test]
    fn test_packet_append_label_too_long() {
        let mut pkt = DnsPacket::new(DnsProtocol::Dns);
        let long = vec![b'a'; 64]; // DNS_LABEL_MAX is 63
        assert!(pkt.append_label(&long, false).is_err());
    }

    #[test]
    fn test_reader_read_past_end() {
        let pkt = DnsPacket::new(DnsProtocol::Dns);
        let mut reader = DnsPacketReader::from_packet(&pkt);
        assert!(reader.read_u16().is_err());
    }

    #[test]
    fn test_reader_rewind() {
        let mut pkt = DnsPacket::new(DnsProtocol::Dns);
        pkt.append_u16(0xABCD).unwrap();
        pkt.append_u16(0xEF01).unwrap();

        let mut reader = DnsPacketReader::from_packet(&pkt);
        assert_eq!(reader.read_u16().unwrap(), 0xABCD);
        reader.rewind(DNS_PACKET_HEADER_SIZE);
        assert_eq!(reader.read_u16().unwrap(), 0xABCD);
    }

    #[test]
    fn test_dns_rcode_to_string() {
        assert_eq!(DnsRcode::to_string_lossy(0), "SUCCESS");
        assert_eq!(DnsRcode::to_string_lossy(3), "NXDOMAIN");
        assert_eq!(DnsRcode::to_string_lossy(5), "REFUSED");
        assert_eq!(DnsRcode::to_string_lossy(16), "BADVERS");
        assert_eq!(DnsRcode::to_string_lossy(999), "<unknown>");
    }

    #[test]
    fn test_dns_rcode_is_dnssec() {
        assert!(DnsRcode::is_dnssec(5));
        assert!(DnsRcode::is_dnssec(12));
        assert!(!DnsRcode::is_dnssec(0));
        assert!(!DnsRcode::is_dnssec(3));
        assert!(!DnsRcode::is_dnssec(13));
    }

    #[test]
    fn test_dns_protocol_roundtrip() {
        for proto in [DnsProtocol::Dns, DnsProtocol::Mdns, DnsProtocol::Llmnr] {
            let name = proto.to_string();
            assert_eq!(dns_protocol_from_name(&name), Some(proto));
        }
        assert_eq!(dns_protocol_from_name("unknown"), None);
    }

    #[test]
    fn test_multicast_addresses() {
        assert_eq!(LLMNR_MULTICAST_IPV4, [224, 0, 252, 0]);
        assert_eq!(MDNS_MULTICAST_IPV4, [224, 0, 0, 251]);
    }

    #[test]
    fn test_loc_size_ok() {
        // Valid: mantissa < 15, exponent <= 9
        assert!(loc_size_ok(0x00)); // 0 cm
        assert!(loc_size_ok(0x11)); // 1 * 10^1 = 10 cm
        assert!(loc_size_ok(0x19)); // 1 * 10^9
                                    // Invalid: mantissa all 1s
        assert!(!loc_size_ok(0xF0));
        assert!(!loc_size_ok(0xFF));
    }

    #[test]
    fn test_dns_type_is_pseudo() {
        assert!(dns_type_is_pseudo(41)); // TYPE_OPT
        assert!(dns_type_is_pseudo(0xFF00));
        assert!(dns_type_is_pseudo(0xFFFF));
        assert!(!dns_type_is_pseudo(1)); // TYPE_A
        assert!(!dns_type_is_pseudo(28)); // TYPE_AAAA
    }

    #[test]
    fn test_dns_svc_param_is_valid() {
        assert!(dns_svc_param_is_valid(0)); // mandatory
        assert!(dns_svc_param_is_valid(1)); // alpn
        assert!(dns_svc_param_is_valid(8)); // dohpath
        assert!(!dns_svc_param_is_valid(10));
        assert!(!dns_svc_param_is_valid(65535));
    }

    #[test]
    fn test_be16_read_write() {
        let mut buf = [0u8; 2];
        write_be16(&mut buf, 0x1234);
        assert_eq!(buf, [0x12, 0x34]);
        assert_eq!(read_be16(&buf), 0x1234);
    }

    #[test]
    fn test_be32_read_write() {
        let mut buf = [0u8; 4];
        write_be32(&mut buf, 0xABCDEF01);
        assert_eq!(buf, [0xAB, 0xCD, 0xEF, 0x01]);
        assert_eq!(read_be32(&buf), 0xABCDEF01);
    }

    #[test]
    fn test_constants_sanity() {
        assert!(DNS_PACKET_SIZE_START > DNS_PACKET_HEADER_SIZE);
        assert_eq!(DNS_PACKET_SIZE_MAX, 65535);
        assert_eq!(DNS_PACKET_HEADER_SIZE, 12);
        assert_eq!(DNS_LABEL_MAX, 63);
    }
}
