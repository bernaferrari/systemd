// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-resolved-dummy-server.c
//
// DNS dummy server packet construction and EDNS handling tests.
// The C source implements a full event-loop-based DNS server; this port
// extracts the packet-building and EDNS-append logic and tests it in isolation.

use std::fmt;

// ── DNS constants ──────────────────────────────────────────────────────────

pub const DNS_PROTOCOL_DNS: u8 = 0;
pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_TYPE_OPT: u16 = 41;
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_AAAA: u16 = 28;

pub const DNS_RCODE_SERVFAIL: u16 = 2;
pub const DNS_RCODE_NXDOMAIN: u16 = 3;

pub const DNS_EDE_RCODE_DNSSEC_BOGUS: u16 = 6;
pub const DNS_EDE_RCODE_CENSORED: u16 = 7;
pub const DNS_EDE_RCODE_OTHER: u16 = 0;
pub const DNS_EDE_RCODE_MAX_DEFINED: u16 = 22;

pub const ADVERTISE_DATAGRAM_SIZE_MAX: u16 = (65536u32 - 14 - 20 - 8) as u16;

// ── DNS packet header ──────────────────────────────────────────────────────

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
    pub fn make_flags(
        qr: bool,
        opcode: u8,
        aa: bool,
        tc: bool,
        rd: bool,
        ra: bool,
        ad: bool,
        cd: bool,
        rcode: u16,
    ) -> u16 {
        let mut flags: u16 = 0;
        if qr {
            flags |= 1 << 15;
        }
        flags |= (opcode as u16 & 0xF) << 11;
        if aa {
            flags |= 1 << 10;
        }
        if tc {
            flags |= 1 << 9;
        }
        if rd {
            flags |= 1 << 8;
        }
        if ra {
            flags |= 1 << 7;
        }
        if ad {
            flags |= 1 << 5;
        }
        if cd {
            flags |= 1 << 4;
        }
        flags |= rcode & 0xF;
        flags
    }

    pub fn rd(&self) -> bool {
        (self.flags >> 8) & 1 == 1
    }
}

// ── DNS question ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    BufferOverflow,
    InvalidSize,
    InvalidRcode,
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferOverflow => write!(f, "buffer overflow"),
            Self::InvalidSize => write!(f, "invalid packet size"),
            Self::InvalidRcode => write!(f, "invalid RCODE"),
        }
    }
}

impl std::error::Error for PacketError {}

pub type Result<T> = std::result::Result<T, PacketError>;

// ── DNS packet builder ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DnsPacketBuilder {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub opt_start: usize,
    pub opt_size: usize,
    pub additional_records: Vec<OptRecord>,
}

#[derive(Debug, Clone)]
pub struct OptRecord {
    pub udp_size: u16,
    pub extended_rcode: u16,
    pub edns_version: u8,
    pub dnssec_ok: bool,
    pub ede_code: u16,
    pub extra_text: String,
}

impl DnsPacketBuilder {
    pub fn new() -> Self {
        Self {
            header: DnsHeader::default(),
            questions: Vec::new(),
            opt_start: 0,
            opt_size: 0,
            additional_records: Vec::new(),
        }
    }

    pub fn with_id(mut self, id: u16) -> Self {
        self.header.id = id;
        self
    }

    pub fn with_question(mut self, name: &str, qtype: u16, qclass: u16) -> Self {
        self.questions.push(DnsQuestion {
            name: name.to_string(),
            qtype,
            qclass,
        });
        self.header.qdcount = self.questions.len() as u16;
        self
    }

    pub fn make_reply_from_query(query: &DnsPacketBuilder) -> Self {
        let mut reply = Self::new();
        reply.header.id = query.header.id;
        reply.header.qdcount = query.header.qdcount;
        reply.questions = query.questions.clone();
        reply
    }

    pub fn append_edns(
        &mut self,
        extra_text: Option<&str>,
        rcode: u16,
        ede_code: u16,
    ) -> Result<()> {
        let text = extra_text.unwrap_or("");
        let text_len = text.len();
        let opt = OptRecord {
            udp_size: ADVERTISE_DATAGRAM_SIZE_MAX,
            extended_rcode: ((rcode & 0x0FF0) << 4) as u16,
            edns_version: 0,
            dnssec_ok: false,
            ede_code,
            extra_text: text.to_string(),
        };

        let rdata_len = 2 + 2 + 2 + text_len;
        if rdata_len > 0xFFFF as usize {
            return Err(PacketError::BufferOverflow);
        }

        self.opt_start = self.additional_records.len();
        self.additional_records.push(opt);
        self.header.arcount = self.additional_records.len() as u16;

        self.header.flags = DnsHeader::make_flags(
            true,
            0,
            false,
            false,
            self.header.rd(),
            true,
            false,
            true,
            rcode,
        );
        self.opt_size = rdata_len;
        Ok(())
    }

    pub fn fail(&mut self, rcode: u16) {
        self.header.flags = DnsHeader::make_flags(
            true,
            0,
            false,
            false,
            self.header.rd(),
            true,
            false,
            true,
            rcode,
        );
    }
}

// ── Server handler dispatch ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerAction {
    EdnsBogusDnssec,
    EdnsExtraText,
    EdnsInvalidCode,
    EdnsInvalidCodeWithExtraText,
    EdnsCodeZero,
    Unhandled,
}

pub fn dispatch_server_action(name: &str) -> ServerAction {
    match name {
        "edns-bogus-dnssec.forwarded.test" => ServerAction::EdnsBogusDnssec,
        "edns-extra-text.forwarded.test" => ServerAction::EdnsExtraText,
        "edns-invalid-code.forwarded.test" => ServerAction::EdnsInvalidCode,
        "edns-invalid-code-with-extra-text.forwarded.test" => {
            ServerAction::EdnsInvalidCodeWithExtraText
        }
        "edns-code-zero.forwarded.test" => ServerAction::EdnsCodeZero,
        _ => ServerAction::Unhandled,
    }
}

pub fn handle_server_action(action: ServerAction, packet: &mut DnsPacketBuilder) -> Result<()> {
    match action {
        ServerAction::EdnsBogusDnssec => {
            packet.append_edns(None, DNS_RCODE_SERVFAIL, DNS_EDE_RCODE_DNSSEC_BOGUS)
        }
        ServerAction::EdnsExtraText => packet.append_edns(
            Some("Nothing to see here!"),
            DNS_RCODE_SERVFAIL,
            DNS_EDE_RCODE_CENSORED,
        ),
        ServerAction::EdnsInvalidCode => {
            let code = DNS_EDE_RCODE_MAX_DEFINED + 1;
            packet.append_edns(None, DNS_RCODE_SERVFAIL, code)
        }
        ServerAction::EdnsInvalidCodeWithExtraText => {
            let code = DNS_EDE_RCODE_MAX_DEFINED + 1;
            packet.append_edns(Some("Hello [#]$%~ World"), DNS_RCODE_SERVFAIL, code)
        }
        ServerAction::EdnsCodeZero => {
            packet.append_edns(Some("\u{1F431}"), DNS_RCODE_SERVFAIL, DNS_EDE_RCODE_OTHER)
        }
        ServerAction::Unhandled => {
            packet.fail(DNS_RCODE_NXDOMAIN);
            Ok(())
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_header_make_flags_reply() {
        let flags = DnsHeader::make_flags(true, 0, false, false, true, true, false, true, 0);
        assert_eq!(flags & (1 << 15), 1 << 15); // QR=1
        assert_eq!(flags & (1 << 8), 1 << 8); // RD=1
        assert_eq!(flags & (1 << 7), 1 << 7); // RA=1
        assert_eq!(flags & (1 << 4), 1 << 4); // CD=1
    }

    #[test]
    fn dns_header_make_flags_with_rcode() {
        let flags = DnsHeader::make_flags(
            true,
            0,
            false,
            false,
            true,
            true,
            false,
            true,
            DNS_RCODE_SERVFAIL,
        );
        assert_eq!(flags & 0xF, DNS_RCODE_SERVFAIL as u16 & 0xF);
    }

    #[test]
    fn dns_header_rd_flag() {
        let mut h = DnsHeader::default();
        h.flags = 1 << 8;
        assert!(h.rd());
        h.flags = 0;
        assert!(!h.rd());
    }

    #[test]
    fn packet_builder_with_question() {
        let p = DnsPacketBuilder::new().with_id(42).with_question(
            "example.com",
            DNS_TYPE_A,
            DNS_CLASS_IN,
        );
        assert_eq!(p.header.id, 42);
        assert_eq!(p.header.qdcount, 1);
        assert_eq!(p.questions.len(), 1);
        assert_eq!(p.questions[0].name, "example.com");
    }

    #[test]
    fn make_reply_from_query() {
        let query = DnsPacketBuilder::new().with_id(1234).with_question(
            "test.com",
            DNS_TYPE_AAAA,
            DNS_CLASS_IN,
        );
        let reply = DnsPacketBuilder::make_reply_from_query(&query);
        assert_eq!(reply.header.id, 1234);
        assert_eq!(reply.header.qdcount, 1);
    }

    #[test]
    fn append_edns_bogus_dnssec() {
        let query = DnsPacketBuilder::new().with_id(1).with_question(
            "edns-bogus-dnssec.forwarded.test",
            DNS_TYPE_A,
            DNS_CLASS_IN,
        );
        let mut reply = DnsPacketBuilder::make_reply_from_query(&query);
        reply
            .append_edns(None, DNS_RCODE_SERVFAIL, DNS_EDE_RCODE_DNSSEC_BOGUS)
            .unwrap();
        assert_eq!(reply.additional_records.len(), 1);
        assert_eq!(
            reply.additional_records[0].ede_code,
            DNS_EDE_RCODE_DNSSEC_BOGUS
        );
    }

    #[test]
    fn append_edns_extra_text() {
        let mut p = DnsPacketBuilder::new();
        p.append_edns(
            Some("Nothing to see here!"),
            DNS_RCODE_SERVFAIL,
            DNS_EDE_RCODE_CENSORED,
        )
        .unwrap();
        assert_eq!(p.additional_records[0].extra_text, "Nothing to see here!");
        assert_eq!(p.additional_records[0].ede_code, DNS_EDE_RCODE_CENSORED);
    }

    #[test]
    fn dispatch_server_actions() {
        assert_eq!(
            dispatch_server_action("edns-bogus-dnssec.forwarded.test"),
            ServerAction::EdnsBogusDnssec,
        );
        assert_eq!(
            dispatch_server_action("edns-extra-text.forwarded.test"),
            ServerAction::EdnsExtraText,
        );
        assert_eq!(
            dispatch_server_action("edns-code-zero.forwarded.test"),
            ServerAction::EdnsCodeZero,
        );
        assert_eq!(
            dispatch_server_action("unknown.test"),
            ServerAction::Unhandled,
        );
    }

    #[test]
    fn handle_server_action_unhandled_fails() {
        let mut p = DnsPacketBuilder::new();
        handle_server_action(ServerAction::Unhandled, &mut p).unwrap();
        assert_eq!(p.header.flags & 0xF, DNS_RCODE_NXDOMAIN as u16 & 0xF);
    }

    #[test]
    fn handle_server_action_code_zero() {
        let mut p = DnsPacketBuilder::new();
        handle_server_action(ServerAction::EdnsCodeZero, &mut p).unwrap();
        assert_eq!(p.additional_records[0].ede_code, DNS_EDE_RCODE_OTHER);
        assert_eq!(p.additional_records[0].extra_text, "\u{1F431}");
    }

    #[test]
    fn advertise_datagram_size() {
        assert_eq!(ADVERTISE_DATAGRAM_SIZE_MAX as u32, 65536u32 - 14 - 20 - 8);
    }
}
