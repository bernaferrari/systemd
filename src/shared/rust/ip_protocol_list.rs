// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/shared/ip-protocol-list.c, src/shared/ip-protocol-list.h

pub const IPPROTO_IP: i32 = 0;
pub const IPPROTO_ICMP: i32 = 1;
pub const IPPROTO_IGMP: i32 = 2;
pub const IPPROTO_IPIP: i32 = 4;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_EGP: i32 = 8;
pub const IPPROTO_PUP: i32 = 12;
pub const IPPROTO_UDP: i32 = 17;
pub const IPPROTO_IDP: i32 = 22;
pub const IPPROTO_TP: i32 = 29;
pub const IPPROTO_DCCP: i32 = 33;
pub const IPPROTO_IPV6: i32 = 41;
pub const IPPROTO_RSVP: i32 = 46;
pub const IPPROTO_GRE: i32 = 47;
pub const IPPROTO_ESP: i32 = 50;
pub const IPPROTO_AH: i32 = 51;
pub const IPPROTO_MTP: i32 = 92;
pub const IPPROTO_BEETPH: i32 = 94;
pub const IPPROTO_ENCAP: i32 = 98;
pub const IPPROTO_PIM: i32 = 103;
pub const IPPROTO_COMP: i32 = 108;
pub const IPPROTO_SCTP: i32 = 132;
pub const IPPROTO_UDPLITE: i32 = 136;
pub const IPPROTO_MPLS: i32 = 137;
pub const IPPROTO_ETHERNET: i32 = 143;
pub const IPPROTO_RAW: i32 = 255;
pub const IPPROTO_MPTCP: i32 = 262;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocolError {
    InvalidArgument,
    OutOfRange,
    NoSupport,
    ParseFailed,
}

struct IpProtocolEntry {
    id: i32,
    name: &'static str,
}

const IP_PROTOCOL_TABLE: &[IpProtocolEntry] = &[
    IpProtocolEntry { id: 0, name: "ip" },
    IpProtocolEntry {
        id: 1,
        name: "icmp",
    },
    IpProtocolEntry {
        id: 2,
        name: "igmp",
    },
    IpProtocolEntry {
        id: 4,
        name: "ipip",
    },
    IpProtocolEntry { id: 6, name: "tcp" },
    IpProtocolEntry { id: 8, name: "egp" },
    IpProtocolEntry {
        id: 12,
        name: "pup",
    },
    IpProtocolEntry {
        id: 17,
        name: "udp",
    },
    IpProtocolEntry {
        id: 22,
        name: "idp",
    },
    IpProtocolEntry { id: 29, name: "tp" },
    IpProtocolEntry {
        id: 33,
        name: "dccp",
    },
    IpProtocolEntry {
        id: 41,
        name: "ipv6",
    },
    IpProtocolEntry {
        id: 46,
        name: "rsvp",
    },
    IpProtocolEntry {
        id: 47,
        name: "gre",
    },
    IpProtocolEntry {
        id: 50,
        name: "esp",
    },
    IpProtocolEntry { id: 51, name: "ah" },
    IpProtocolEntry {
        id: 92,
        name: "mtp",
    },
    IpProtocolEntry {
        id: 94,
        name: "beetph",
    },
    IpProtocolEntry {
        id: 98,
        name: "encap",
    },
    IpProtocolEntry {
        id: 103,
        name: "pim",
    },
    IpProtocolEntry {
        id: 108,
        name: "comp",
    },
    IpProtocolEntry {
        id: 132,
        name: "sctp",
    },
    IpProtocolEntry {
        id: 136,
        name: "udplite",
    },
    IpProtocolEntry {
        id: 137,
        name: "mpls",
    },
    IpProtocolEntry {
        id: 143,
        name: "ethernet",
    },
    IpProtocolEntry {
        id: 255,
        name: "raw",
    },
    IpProtocolEntry {
        id: 262,
        name: "mptcp",
    },
];

pub fn ip_protocol_to_name(id: i32) -> Option<&'static str> {
    if id < 0 {
        return None;
    }
    IP_PROTOCOL_TABLE
        .iter()
        .find(|p| p.id == id)
        .map(|p| p.name)
}

pub fn ip_protocol_from_name(name: &str) -> Result<i32, IpProtocolError> {
    IP_PROTOCOL_TABLE
        .iter()
        .find(|p| p.name == name)
        .map(|p| p.id)
        .ok_or(IpProtocolError::InvalidArgument)
}

pub fn parse_ip_protocol_full(s: &str, relaxed: bool) -> Result<i32, IpProtocolError> {
    if s.is_empty() {
        return Ok(IPPROTO_IP);
    }

    if let Ok(id) = ip_protocol_from_name(s) {
        return Ok(id);
    }

    let lower = s.to_ascii_lowercase();
    if let Ok(id) = ip_protocol_from_name(&lower) {
        return Ok(id);
    }

    let p: i32 = match s.parse() {
        Ok(v) => v,
        Err(_) => return Err(IpProtocolError::OutOfRange),
    };
    if p < 0 {
        return Err(IpProtocolError::OutOfRange);
    }

    if !relaxed && ip_protocol_to_name(p).is_none() {
        return Err(IpProtocolError::NoSupport);
    }

    Ok(p)
}

pub fn parse_ip_protocol(s: &str) -> Result<i32, IpProtocolError> {
    parse_ip_protocol_full(s, false)
}

pub fn ip_protocol_to_tcp_udp(id: i32) -> Option<&'static str> {
    if id == IPPROTO_TCP || id == IPPROTO_UDP {
        ip_protocol_to_name(id)
    } else {
        None
    }
}

pub fn ip_protocol_from_tcp_udp(ip_protocol: &str) -> Result<i32, IpProtocolError> {
    let id = ip_protocol_from_name(ip_protocol)?;
    if id == IPPROTO_TCP || id == IPPROTO_UDP {
        Ok(id)
    } else {
        Err(IpProtocolError::InvalidArgument)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_name_known_protocols() {
        assert_eq!(ip_protocol_to_name(IPPROTO_TCP), Some("tcp"));
        assert_eq!(ip_protocol_to_name(IPPROTO_UDP), Some("udp"));
        assert_eq!(ip_protocol_to_name(IPPROTO_IP), Some("ip"));
        assert_eq!(ip_protocol_to_name(IPPROTO_ICMP), Some("icmp"));
        assert_eq!(ip_protocol_to_name(IPPROTO_SCTP), Some("sctp"));
        assert_eq!(ip_protocol_to_name(IPPROTO_DCCP), Some("dccp"));
        assert_eq!(ip_protocol_to_name(IPPROTO_RAW), Some("raw"));
        assert_eq!(ip_protocol_to_name(IPPROTO_MPTCP), Some("mptcp"));
    }

    #[test]
    fn test_to_name_invalid() {
        assert_eq!(ip_protocol_to_name(-1), None);
        assert_eq!(ip_protocol_to_name(999), None);
        assert_eq!(ip_protocol_to_name(256), None);
    }

    #[test]
    fn test_from_name_known() {
        assert_eq!(ip_protocol_from_name("tcp"), Ok(IPPROTO_TCP));
        assert_eq!(ip_protocol_from_name("udp"), Ok(IPPROTO_UDP));
        assert_eq!(ip_protocol_from_name("ip"), Ok(IPPROTO_IP));
        assert_eq!(ip_protocol_from_name("icmp"), Ok(IPPROTO_ICMP));
        assert_eq!(ip_protocol_from_name("gre"), Ok(IPPROTO_GRE));
        assert_eq!(ip_protocol_from_name("esp"), Ok(IPPROTO_ESP));
    }

    #[test]
    fn test_from_name_case_sensitive() {
        assert_eq!(
            ip_protocol_from_name("TCP"),
            Err(IpProtocolError::InvalidArgument)
        );
        assert_eq!(
            ip_protocol_from_name("Udp"),
            Err(IpProtocolError::InvalidArgument)
        );
    }

    #[test]
    fn test_from_name_unknown() {
        assert_eq!(
            ip_protocol_from_name("invalid"),
            Err(IpProtocolError::InvalidArgument)
        );
        assert_eq!(
            ip_protocol_from_name(""),
            Err(IpProtocolError::InvalidArgument)
        );
    }

    #[test]
    fn test_parse_exact_name() {
        assert_eq!(parse_ip_protocol("tcp"), Ok(IPPROTO_TCP));
        assert_eq!(parse_ip_protocol("udp"), Ok(IPPROTO_UDP));
        assert_eq!(parse_ip_protocol("icmp"), Ok(IPPROTO_ICMP));
    }

    #[test]
    fn test_parse_case_insensitive() {
        assert_eq!(parse_ip_protocol("TCP"), Ok(IPPROTO_TCP));
        assert_eq!(parse_ip_protocol("Udp"), Ok(IPPROTO_UDP));
        assert_eq!(parse_ip_protocol("ICMP"), Ok(IPPROTO_ICMP));
        assert_eq!(parse_ip_protocol("Ip"), Ok(IPPROTO_IP));
    }

    #[test]
    fn test_parse_numeric() {
        assert_eq!(parse_ip_protocol("6"), Ok(6));
        assert_eq!(parse_ip_protocol("17"), Ok(17));
        assert_eq!(parse_ip_protocol("0"), Ok(0));
    }

    #[test]
    fn test_parse_empty() {
        assert_eq!(parse_ip_protocol(""), Ok(IPPROTO_IP));
    }

    #[test]
    fn test_parse_relaxed_accepts_unknown_numbers() {
        assert_eq!(parse_ip_protocol_full("999", true), Ok(999));
        assert_eq!(parse_ip_protocol_full("12345", true), Ok(12345));
    }

    #[test]
    fn test_parse_strict_rejects_unknown_numbers() {
        assert_eq!(
            parse_ip_protocol_full("999", false),
            Err(IpProtocolError::NoSupport)
        );
        assert_eq!(
            parse_ip_protocol_full("12345", false),
            Err(IpProtocolError::NoSupport)
        );
    }

    #[test]
    fn test_parse_negative_number() {
        assert_eq!(parse_ip_protocol("-1"), Err(IpProtocolError::OutOfRange));
    }

    #[test]
    fn test_parse_non_numeric_unknown() {
        assert_eq!(
            parse_ip_protocol("notaprotocol"),
            Err(IpProtocolError::InvalidArgument)
        );
    }

    #[test]
    fn test_to_tcp_udp() {
        assert_eq!(ip_protocol_to_tcp_udp(IPPROTO_TCP), Some("tcp"));
        assert_eq!(ip_protocol_to_tcp_udp(IPPROTO_UDP), Some("udp"));
        assert_eq!(ip_protocol_to_tcp_udp(IPPROTO_ICMP), None);
        assert_eq!(ip_protocol_to_tcp_udp(IPPROTO_IP), None);
        assert_eq!(ip_protocol_to_tcp_udp(IPPROTO_SCTP), None);
    }

    #[test]
    fn test_from_tcp_udp() {
        assert_eq!(ip_protocol_from_tcp_udp("tcp"), Ok(IPPROTO_TCP));
        assert_eq!(ip_protocol_from_tcp_udp("udp"), Ok(IPPROTO_UDP));
        assert_eq!(
            ip_protocol_from_tcp_udp("icmp"),
            Err(IpProtocolError::InvalidArgument)
        );
        assert_eq!(
            ip_protocol_from_tcp_udp("ip"),
            Err(IpProtocolError::InvalidArgument)
        );
        assert_eq!(
            ip_protocol_from_tcp_udp("sctp"),
            Err(IpProtocolError::InvalidArgument)
        );
    }

    #[test]
    fn test_round_trip_all_protocols() {
        for entry in IP_PROTOCOL_TABLE {
            let name = ip_protocol_to_name(entry.id).unwrap();
            let id = ip_protocol_from_name(name).unwrap();
            assert_eq!(id, entry.id, "round-trip failed for {}", entry.name);
        }
    }
}
