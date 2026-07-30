// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-netlink/netlink-sock-diag.c
//

pub type Result<T> = std::result::Result<T, i32>;

pub const NEG_EBADMSG: i32 = -libc::EBADMSG;
pub const NEG_EINVAL: i32 = -libc::EINVAL;
pub const NETLINK_SOCK_DIAG_FAMILY: i32 = 4;
pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
pub const NLM_F_REQUEST: u16 = 0x0001;
pub const NLM_F_ACK: u16 = 0x0004;
pub const NLM_F_DUMP: u16 = 0x0300;
pub const NLM_F_REQUEST_ACK: u16 = NLM_F_REQUEST | NLM_F_ACK;
pub const NLM_F_REQUEST_DUMP: u16 = NLM_F_REQUEST | NLM_F_DUMP;
pub const AF_UNIX_FAMILY: u8 = libc::AF_UNIX as u8;
pub const UNIX_DIAG_MSG_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockDiagSocket {
    pub family: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetlinkHeader {
    pub message_type: u16,
    pub flags: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnixDiagRequest {
    pub sdiag_family: u8,
    pub sdiag_protocol: u8,
    pub pad: u16,
    pub udiag_states: u32,
    pub udiag_ino: u32,
    pub udiag_show: u32,
    pub udiag_cookie: [u32; 2],
}

/// Decoded fixed header of the Linux `unix_diag_msg` reply payload.
///
/// This is a byte-level UAPI representation, not a C ABI type: netlink fields
/// are decoded explicitly in native byte order, matching Linux's UAPI structs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnixDiagMessage {
    pub udiag_family: u8,
    pub udiag_type: u8,
    pub udiag_state: u8,
    pub pad: u8,
    pub udiag_ino: u32,
    pub udiag_cookie: [u32; 2],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockDiagMessage {
    pub header: NetlinkHeader,
    pub request: UnixDiagRequest,
}

pub fn sock_diag_socket_open() -> Result<SockDiagSocket> {
    Ok(SockDiagSocket {
        family: NETLINK_SOCK_DIAG_FAMILY,
    })
}

pub fn split_cookie(cookie: u64) -> [u32; 2] {
    [cookie as u32, (cookie >> 32) as u32]
}

pub fn unix_diag_request(inode: libc::ino_t, cookie: u64, show: u32) -> Result<UnixDiagRequest> {
    Ok(UnixDiagRequest {
        sdiag_family: AF_UNIX_FAMILY,
        sdiag_protocol: 0,
        pad: 0,
        udiag_states: 0,
        // The Linux UAPI field is u32, and the C assignment has the same
        // truncating conversion when ino_t is wider.
        udiag_ino: inode as u32,
        udiag_show: show,
        udiag_cookie: split_cookie(cookie),
    })
}

pub fn unix_diag_dump_request(states: u32, show: u32) -> UnixDiagRequest {
    UnixDiagRequest {
        sdiag_family: AF_UNIX_FAMILY,
        sdiag_protocol: 0,
        pad: 0,
        udiag_states: states,
        udiag_ino: 0,
        udiag_show: show,
        udiag_cookie: [0, 0],
    }
}

pub fn sock_diag_message_new_unix(
    _socket: &SockDiagSocket,
    inode: libc::ino_t,
    cookie: u64,
    show: u32,
) -> Result<SockDiagMessage> {
    Ok(SockDiagMessage {
        header: NetlinkHeader {
            message_type: SOCK_DIAG_BY_FAMILY,
            flags: NLM_F_REQUEST_ACK,
        },
        request: unix_diag_request(inode, cookie, show)?,
    })
}

pub fn sock_diag_message_new_unix_dump(
    _socket: &SockDiagSocket,
    states: u32,
    show: u32,
) -> Result<SockDiagMessage> {
    Ok(SockDiagMessage {
        header: NetlinkHeader {
            message_type: SOCK_DIAG_BY_FAMILY,
            flags: NLM_F_REQUEST_DUMP,
        },
        request: unix_diag_dump_request(states, show),
    })
}

pub fn encode_request(message: &SockDiagMessage) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.push(message.request.sdiag_family);
    out.push(message.request.sdiag_protocol);
    out.extend_from_slice(&message.request.pad.to_ne_bytes());
    out.extend_from_slice(&message.request.udiag_states.to_ne_bytes());
    out.extend_from_slice(&message.request.udiag_ino.to_ne_bytes());
    out.extend_from_slice(&message.request.udiag_show.to_ne_bytes());
    out.extend_from_slice(&message.request.udiag_cookie[0].to_ne_bytes());
    out.extend_from_slice(&message.request.udiag_cookie[1].to_ne_bytes());
    out
}

pub fn decode_unix_diag_message(header: NetlinkHeader, payload: &[u8]) -> Result<UnixDiagMessage> {
    if header.message_type != SOCK_DIAG_BY_FAMILY {
        return Err(NEG_EINVAL);
    }
    if payload.len() < UNIX_DIAG_MSG_SIZE {
        return Err(NEG_EBADMSG);
    }

    Ok(UnixDiagMessage {
        udiag_family: payload[0],
        udiag_type: payload[1],
        udiag_state: payload[2],
        pad: payload[3],
        udiag_ino: u32::from_ne_bytes(payload[4..8].try_into().expect("fixed-size slice")),
        udiag_cookie: [
            u32::from_ne_bytes(payload[8..12].try_into().expect("fixed-size slice")),
            u32::from_ne_bytes(payload[12..16].try_into().expect("fixed-size slice")),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_sock_diag_family() {
        assert_eq!(
            sock_diag_socket_open().unwrap().family,
            NETLINK_SOCK_DIAG_FAMILY
        );
    }

    #[test]
    fn splits_cookie_low_and_high_words() {
        assert_eq!(
            split_cookie(0x1122_3344_5566_7788),
            [0x5566_7788, 0x1122_3344]
        );
    }

    #[test]
    fn builds_unix_diag_request() {
        let req = unix_diag_request(77, 0x1_0000_0002, 9).unwrap();
        assert_eq!(req.sdiag_family, AF_UNIX_FAMILY);
        assert_eq!(req.udiag_ino, 77);
        assert_eq!(req.udiag_show, 9);
        assert_eq!(req.udiag_cookie, [2, 1]);
    }

    #[test]
    fn truncates_inode_to_linux_uapi_field_width() {
        let too_large = (u32::MAX as u64 + 1) as libc::ino_t;
        assert_eq!(unix_diag_request(too_large, 0, 0).unwrap().udiag_ino, 0);
    }

    #[test]
    fn builds_message_with_expected_header() {
        let socket = sock_diag_socket_open().unwrap();
        let message = sock_diag_message_new_unix(&socket, 4, 9, 11).unwrap();
        assert_eq!(message.header.message_type, SOCK_DIAG_BY_FAMILY);
        assert_eq!(message.header.flags, NLM_F_REQUEST_ACK);
    }

    #[test]
    fn encodes_request_layout() {
        let socket = sock_diag_socket_open().unwrap();
        let message = sock_diag_message_new_unix(&socket, 1, 2, 3).unwrap();
        let encoded = encode_request(&message);
        assert_eq!(encoded.len(), 24);
        assert_eq!(encoded[0], AF_UNIX_FAMILY);
    }

    #[test]
    fn builds_dump_request_with_zeroed_lookup_fields() {
        let socket = sock_diag_socket_open().unwrap();
        let message = sock_diag_message_new_unix_dump(&socket, 0x1234, 0x5678).unwrap();
        assert_eq!(message.header.message_type, SOCK_DIAG_BY_FAMILY);
        assert_eq!(message.header.flags, NLM_F_REQUEST_DUMP);
        assert_eq!(message.request.udiag_states, 0x1234);
        assert_eq!(message.request.udiag_show, 0x5678);
        assert_eq!(message.request.udiag_ino, 0);
        assert_eq!(message.request.udiag_cookie, [0, 0]);
    }

    #[test]
    fn rejects_non_sock_diag_reply_type() {
        assert_eq!(
            decode_unix_diag_message(
                NetlinkHeader {
                    message_type: 0,
                    flags: 0,
                },
                &[0; UNIX_DIAG_MSG_SIZE],
            ),
            Err(NEG_EINVAL)
        );
    }

    #[test]
    fn rejects_short_unix_diag_reply() {
        assert_eq!(
            decode_unix_diag_message(
                NetlinkHeader {
                    message_type: SOCK_DIAG_BY_FAMILY,
                    flags: 0,
                },
                &[0; UNIX_DIAG_MSG_SIZE - 1],
            ),
            Err(NEG_EBADMSG)
        );
    }

    #[test]
    fn decodes_unix_diag_reply_header_in_native_order() {
        let mut payload = [0; UNIX_DIAG_MSG_SIZE];
        payload[0] = AF_UNIX_FAMILY;
        payload[1] = 2;
        payload[2] = 3;
        payload[3] = 4;
        payload[4..8].copy_from_slice(&0x1122_3344u32.to_ne_bytes());
        payload[8..12].copy_from_slice(&0x5566_7788u32.to_ne_bytes());
        payload[12..16].copy_from_slice(&0x99aa_bbccu32.to_ne_bytes());

        assert_eq!(
            decode_unix_diag_message(
                NetlinkHeader {
                    message_type: SOCK_DIAG_BY_FAMILY,
                    flags: 0,
                },
                &payload,
            )
            .unwrap(),
            UnixDiagMessage {
                udiag_family: AF_UNIX_FAMILY,
                udiag_type: 2,
                udiag_state: 3,
                pad: 4,
                udiag_ino: 0x1122_3344,
                udiag_cookie: [0x5566_7788, 0x99aa_bbcc],
            }
        );
    }
}
