// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/resolve/test-dns-packet-extract.c
//
// DNS packet extraction: parse headers, validate queries/replies,
// extract questions, and verify name decompression.

use std::collections::HashSet;

// ── Constants ───────────────────────────────────────────────────────────────

const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_OPT: u16 = 41;

const DNS_RCODE_NXDOMAIN: u8 = 3;

// ── Packet flags ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct PktFlags(u16);

impl PktFlags {
    const QR: Self = Self(1 << 15);
    const AA: Self = Self(1 << 10);
    const TC: Self = Self(1 << 9);
    const RD: Self = Self(1 << 8);
    const RA: Self = Self(1 << 7);
    const AD: Self = Self(1 << 5);
    const CD: Self = Self(1 << 4);

    fn from_bits_truncate(bits: u16) -> Self {
        Self(bits)
    }

    fn contains(&self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
}

// ── Packet parser ───────────────────────────────────────────────────────────

#[derive(Debug)]
struct ParsedHeader {
    id: u16,
    flags: PktFlags,
    rcode: u8,
    opcode: u8,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

#[derive(Debug)]
struct ParsedQuestion {
    name: String,
    qtype: u16,
    qclass: u16,
}

#[derive(Debug, Default)]
struct ExtractResult {
    questions: Vec<ParsedQuestion>,
    error: Option<i32>,
}

fn parse_header(data: &[u8]) -> Result<ParsedHeader, i32> {
    if data.len() < 12 {
        return Err(-90); // EMSGSIZE
    }
    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags_raw = u16::from_be_bytes([data[2], data[3]]);
    let flags = PktFlags::from_bits_truncate(flags_raw & 0xFFF0);
    let opcode = ((flags_raw >> 11) & 0x0F) as u8;
    let rcode = (flags_raw & 0x0F) as u8;
    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    let ancount = u16::from_be_bytes([data[6], data[7]]);
    let nscount = u16::from_be_bytes([data[8], data[9]]);
    let arcount = u16::from_be_bytes([data[10], data[11]]);
    Ok(ParsedHeader {
        id,
        flags,
        rcode,
        opcode,
        qdcount,
        ancount,
        nscount,
        arcount,
    })
}

/// Parse a DNS name from the packet starting at `offset`.
/// Returns (name_string, new_offset) on success, or an error code.
fn parse_name(data: &[u8], offset: usize) -> Result<(String, usize), i32> {
    let mut name = String::new();
    let mut pos = offset;
    let mut jumped = false;
    let mut final_pos = 0usize;
    let mut seen = HashSet::new();

    loop {
        if pos >= data.len() {
            return Err(-90); // EMSGSIZE
        }
        if seen.contains(&pos) {
            return Err(-99); // EBADMSG - loop detected
        }
        let b = data[pos];
        if b == 0 {
            if !jumped {
                final_pos = pos + 1;
            }
            break;
        } else if (b & 0xC0) == 0xC0 {
            // Compression pointer
            if pos + 1 >= data.len() {
                return Err(-90);
            }
            let ptr = (((b & 0x3F) as u16) << 8) | (data[pos + 1] as u16);
            if (ptr as usize) >= data.len() || (ptr as usize) < 12 {
                return Err(-99); // EBADMSG
            }
            if !jumped {
                final_pos = pos + 2;
            }
            jumped = true;
            pos = ptr as usize;
        } else if (b & 0xC0) == 0 {
            // Label
            let len = b as usize;
            if len > 63 {
                return Err(-99); // EBADMSG
            }
            if pos + 1 + len > data.len() {
                return Err(-90); // EMSGSIZE
            }
            if !name.is_empty() {
                name.push('.');
            }
            let label = std::str::from_utf8(&data[pos + 1..pos + 1 + len]).map_err(|_| -99)?;
            name.push_str(label);
            seen.insert(pos);
            pos += 1 + len;
        } else {
            return Err(-99);
        }
    }
    Ok((name, final_pos))
}

fn parse_question(data: &[u8], offset: usize) -> Result<(ParsedQuestion, usize), i32> {
    let (name, new_offset) = parse_name(data, offset)?;
    if new_offset + 4 > data.len() {
        return Err(-90);
    }
    let qtype = u16::from_be_bytes([data[new_offset], data[new_offset + 1]]);
    let qclass = u16::from_be_bytes([data[new_offset + 2], data[new_offset + 3]]);
    Ok((
        ParsedQuestion {
            name,
            qtype,
            qclass,
        },
        new_offset + 4,
    ))
}

fn extract_questions(data: &[u8]) -> ExtractResult {
    let hdr = match parse_header(data) {
        Ok(h) => h,
        Err(e) => {
            return ExtractResult {
                questions: vec![],
                error: Some(e),
            };
        }
    };

    let mut questions = Vec::new();
    let mut offset = 12usize;

    for _ in 0..hdr.qdcount {
        match parse_question(data, offset) {
            Ok((q, new_offset)) => {
                // OPT type in question section is invalid
                if q.qtype == DNS_TYPE_OPT {
                    return ExtractResult {
                        questions: vec![],
                        error: Some(-99),
                    };
                }
                questions.push(q);
                offset = new_offset;
            }
            Err(e) => {
                return ExtractResult {
                    questions: vec![],
                    error: Some(e),
                };
            }
        }
    }

    ExtractResult {
        questions,
        error: None,
    }
}

fn validate_query(data: &[u8], protocol: &str) -> Result<bool, i32> {
    let hdr = parse_header(data).map_err(|e| if e == -90 { -99 } else { e })?;
    // QR must be 0
    if hdr.flags.contains(PktFlags::QR) {
        return Ok(false);
    }
    // Opcode must be 0
    if hdr.opcode != 0 {
        return Err(-99);
    }
    // TC must be 0
    if hdr.flags.contains(PktFlags::TC) {
        return Err(-99);
    }
    // Must have exactly 1 question
    if hdr.qdcount != 1 {
        return Err(-99);
    }
    // No answer, authority, or additional sections allowed for DNS
    if protocol == "DNS" && (hdr.ancount > 0 || hdr.nscount > 0 || hdr.arcount > 0) {
        return Err(-99);
    }
    // mDNS rcode must be 0
    if protocol == "MDNS" && hdr.rcode != 0 {
        return Err(-99);
    }
    // LLMNR: no authority section
    if protocol == "LLMNR" && hdr.nscount > 0 {
        return Err(-99);
    }
    Ok(true)
}

fn validate_reply(data: &[u8], protocol: &str) -> Result<bool, i32> {
    let hdr = parse_header(data).map_err(|e| if e == -90 { -99 } else { e })?;
    // QR must be 1
    if !hdr.flags.contains(PktFlags::QR) {
        return Ok(false);
    }
    // Opcode must be 0
    if hdr.opcode != 0 {
        return Err(-99);
    }
    // mDNS rcode must be 0
    if protocol == "MDNS" && hdr.rcode != 0 {
        return Err(-99);
    }
    // LLMNR: must have questions
    if protocol == "LLMNR" && hdr.qdcount == 0 {
        return Err(-99);
    }
    Ok(true)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_query_basic() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let hdr = parse_header(&data)?;
        assert_eq!(hdr.id, 66);
        assert!(!hdr.flags.contains(PktFlags::QR));
        assert_eq!(hdr.opcode, 0);
        assert_eq!(hdr.rcode, 0);
        assert_eq!(hdr.qdcount, 1);
        Ok(())
    }

    #[test]
    fn test_header_reply_authoritative() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x84, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        ];
        let hdr = parse_header(&data)?;
        assert_eq!(hdr.id, 66);
        assert!(hdr.flags.contains(PktFlags::QR));
        assert!(hdr.flags.contains(PktFlags::AA));
        assert_eq!(hdr.qdcount, 3);
        assert_eq!(hdr.ancount, 4);
        Ok(())
    }

    #[test]
    fn test_header_reply_nxdomain() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x84, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        ];
        let hdr = parse_header(&data)?;
        assert_eq!(hdr.rcode, DNS_RCODE_NXDOMAIN);
        assert_eq!(hdr.qdcount, 1);
        assert_eq!(hdr.nscount, 1);
        Ok(())
    }

    #[test]
    fn test_header_dnssec_bits() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x84, 0x30, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        ];
        let hdr = parse_header(&data)?;
        assert!(hdr.flags.contains(PktFlags::AD));
        assert!(hdr.flags.contains(PktFlags::CD));
        Ok(())
    }

    #[test]
    fn test_header_recursive() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x81, 0x80, 0x05, 0x03, 0x0e, 0x04, 0x00, 0x00, 0x00, 0x00,
        ];
        let hdr = parse_header(&data)?;
        assert!(hdr.flags.contains(PktFlags::QR));
        assert!(hdr.flags.contains(PktFlags::RD));
        assert!(hdr.flags.contains(PktFlags::RA));
        assert_eq!(hdr.qdcount, 1283);
        assert_eq!(hdr.ancount, 3588);
        Ok(())
    }

    #[test]
    fn test_validate_query_qr_bit() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(validate_query(&data, "DNS")?, false);
        Ok(())
    }

    #[test]
    fn test_validate_query_valid() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(validate_query(&data, "DNS")?, true);
        Ok(())
    }

    #[test]
    fn test_validate_query_bad_opcode() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(validate_query(&data, "DNS").is_err());
        Ok(())
    }

    #[test]
    fn test_validate_query_truncated() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(validate_query(&data, "DNS").is_err());
        Ok(())
    }

    #[test]
    fn test_validate_reply_valid() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(validate_reply(&data, "DNS")?, true);
        Ok(())
    }

    #[test]
    fn test_validate_reply_no_qr() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(validate_reply(&data, "DNS")?, false);
        Ok(())
    }

    #[test]
    fn test_validate_reply_bad_opcode() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x8C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(validate_reply(&data, "DNS").is_err());
        Ok(())
    }

    #[test]
    fn test_extract_single_question() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let result = extract_questions(&data);
        assert!(result.error.is_none());
        assert_eq!(result.questions.len(), 1);
        assert_eq!(result.questions[0].name, "www.example.com");
        assert_eq!(result.questions[0].qtype, DNS_TYPE_A);
        assert_eq!(result.questions[0].qclass, DNS_CLASS_IN);
        Ok(())
    }

    #[test]
    fn test_extract_multi_question() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01, 0x04, b'm', b'a', b'i', b'l', 0x07, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x0f, 0x00, 0xff,
        ];
        let result = extract_questions(&data);
        assert!(result.error.is_none());
        assert_eq!(result.questions.len(), 2);
        assert_eq!(result.questions[0].name, "www.example.com");
        assert_eq!(result.questions[1].name, "mail.example.com");
        Ok(())
    }

    #[test]
    fn test_extract_compressed_name() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'w',
            b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, 0x00, 0x01, 0x00, 0x01, 0x04, b'm', b'a', b'i', b'l', 0xc0, 0x10, 0x00, 0x0f,
            0x00, 0xff,
        ];
        let result = extract_questions(&data);
        assert!(result.error.is_none());
        assert_eq!(result.questions.len(), 2);
        assert_eq!(result.questions[1].name, "mail.example.com");
        Ok(())
    }

    #[test]
    fn test_extract_missing_bytes() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'c',
            b'o', b'm', 0x00, 0x00, 0x01,
        ];
        let result = extract_questions(&data);
        assert!(result.error.is_some());
        Ok(())
    }

    #[test]
    fn test_extract_opt_in_question_fails() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'c',
            b'o', b'm', 0x00, 0x00, 0x29, 0x00, 0x01,
        ];
        let result = extract_questions(&data);
        assert!(result.error.is_some());
        Ok(())
    }

    #[test]
    fn test_extract_bad_compression_pointer_before_header() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'c',
            b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0b, 0x00, 0x01, 0x00, 0x01,
        ];
        let result = extract_questions(&data);
        assert!(result.error.is_some());
        Ok(())
    }

    #[test]
    fn test_extract_bad_compression_forward_pointer() -> Result<(), i32> {
        let data: Vec<u8> = vec![
            0x00, 0x42, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, b'c',
            b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x80, 0x00, 0x01, 0x00, 0x01,
        ];
        let result = extract_questions(&data);
        assert!(result.error.is_some());
        Ok(())
    }

    #[test]
    fn test_extract_long_domain() -> Result<(), i32> {
        let name = "absorptivenesses.calligraphically.deacidifications.ecophysiological.\
                    falsifiabilities.heterochromatism.icositetrahedron.journalistically.\
                    kinaesthetically.lactovegetarians.misinterpretable.nitrosylsulfuric.\
                    objectlessnesses.partridgeberries.reasonlessnesse";
        let mut data = vec![
            0x00, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            let bytes = label.as_bytes();
            data.push(bytes.len() as u8);
            data.extend_from_slice(bytes);
        }
        data.push(0);
        data.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        data.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let result = extract_questions(&data);
        assert!(result.error.is_none());
        assert_eq!(result.questions.len(), 1);
        assert_eq!(result.questions[0].name, name);
        Ok(())
    }

    #[test]
    fn test_extract_label_too_long() -> Result<(), i32> {
        let mut data = vec![
            0x00, 0x42, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        // 0x48 = 72, which is > 63 and has high bits 01 set
        data.push(0x48);
        data.extend_from_slice(
            b"a-domain-name-label-that-goes-past-the-length-limit-of-sixty-three-by",
        );
        data.push(0x00);
        data.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        data.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        let result = extract_questions(&data);
        assert!(result.error.is_some());
        Ok(())
    }
}
