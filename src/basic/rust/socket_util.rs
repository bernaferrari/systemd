// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.socket-util; authority=src/basic/socket-util.c,src/basic/socket-util.h

use std::ffi::CStr;

use libc::c_char;

use crate::ffi::Errno;

pub const IFNAMSIZ: usize = 16;
pub const ALTIFNAMSIZ: usize = 128;

pub const VMADDR_PORT_ANY: u32 = u32::MAX;
pub const VMADDR_CID_ANY: u32 = u32::MAX;
pub const VMADDR_CID_HYPERVISOR: u32 = 0;
pub const VMADDR_CID_LOCAL: u32 = 1;
pub const VMADDR_CID_HOST: u32 = 2;

pub const IFNAME_VALID_ALTERNATIVE: u32 = 1 << 0;
pub const IFNAME_VALID_NUMERIC: u32 = 1 << 1;
pub const IFNAME_VALID_SPECIAL: u32 = 1 << 2;
const IFNAME_VALID_ALL: u32 =
    IFNAME_VALID_ALTERNATIVE | IFNAME_VALID_NUMERIC | IFNAME_VALID_SPECIAL;

const ARPHRD_ETHER: u16 = 1;
const ARPHRD_INFINIBAND: u16 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Inet,
    Inet6,
    Unix,
    Netlink,
    Vsock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    Stream,
    Datagram,
    SeqPacket,
    Raw,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnixSocketPath {
    Filesystem(String),
    Abstract(String),
    Unnamed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketAddress {
    Inet {
        addr: [u8; 4],
        port: u16,
        sock_type: Option<SocketType>,
    },
    Inet6 {
        addr: [u8; 16],
        port: u16,
        scope_id: u32,
        sock_type: Option<SocketType>,
    },
    Unix {
        path: UnixSocketPath,
        size: usize,
        sock_type: Option<SocketType>,
    },
    Netlink {
        groups: u32,
        protocol: i32,
        sock_type: Option<SocketType>,
    },
    Vsock {
        cid: u32,
        port: u32,
        sock_type: Option<SocketType>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockaddrLl {
    pub hatype: u16,
}

fn parse_ifindex(s: &str) -> Option<u32> {
    let value = s.parse::<u32>().ok()?;
    if value == 0 || value > i32::MAX as u32 {
        return None;
    }
    Some(value)
}

pub fn ifname_valid_char(a: char) -> bool {
    let code = a as u32;
    if code >= 127 || code <= 32 {
        return false;
    }
    !matches!(a, ':' | '/' | '%')
}

pub fn ifname_valid_full(p: &str, flags: u32) -> bool {
    if p.is_empty() {
        return false;
    }

    if parse_ifindex(p).is_some() {
        return (flags & IFNAME_VALID_NUMERIC) != 0;
    }

    let limit = if (flags & IFNAME_VALID_ALTERNATIVE) != 0 {
        ALTIFNAMSIZ
    } else {
        IFNAMSIZ
    };
    if p.len() >= limit || p == "." || p == ".." {
        return false;
    }

    if (flags & IFNAME_VALID_SPECIAL) == 0 && matches!(p, "all" | "default") {
        return false;
    }

    let mut numeric = true;
    for ch in p.chars() {
        if !ifname_valid_char(ch) {
            return false;
        }
        numeric &= ch.is_ascii_digit();
    }

    !numeric
}

fn ifname_valid_char_byte(byte: u8) -> bool {
    (33..127).contains(&byte) && !matches!(byte, b':' | b'/' | b'%')
}

fn ifname_valid_full_bytes(p: &[u8], flags: u32, is_valid_ifindex: bool) -> bool {
    if p.is_empty() {
        return false;
    }
    if is_valid_ifindex {
        return flags & IFNAME_VALID_NUMERIC != 0;
    }
    let limit = if flags & IFNAME_VALID_ALTERNATIVE != 0 {
        ALTIFNAMSIZ
    } else {
        IFNAMSIZ
    };
    if p.len() >= limit || matches!(p, b"." | b"..") {
        return false;
    }
    if flags & IFNAME_VALID_SPECIAL == 0 && matches!(p, b"all" | b"default") {
        return false;
    }
    let mut numeric = true;
    for byte in p {
        if !ifname_valid_char_byte(*byte) {
            return false;
        }
        numeric &= byte.is_ascii_digit();
    }
    !numeric
}

/// Exact scalar C ABI shadow of `ifname_valid_char()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_ifname_valid_char(a: c_char) -> bool {
    ifname_valid_char_byte(a as u8)
}

/// Exact byte-oriented C ABI shadow of `ifname_valid_full()`.
///
/// # Safety
/// `p`, when non-null, must point to a readable NUL-terminated C string for
/// the duration of the call. Invalid flag bits are a C assertion precondition;
/// this shadow rejects them rather than aborting.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ifname_valid_full(p: *const c_char, flags: i32) -> bool {
    if p.is_null() || flags < 0 || (flags as u32 & !IFNAME_VALID_ALL) != 0 {
        return false;
    }
    // SAFETY: required by this FFI boundary's C-string contract.
    let bytes = unsafe { CStr::from_ptr(p) }.to_bytes();
    let mut ifindex = 0;
    // SAFETY: `p` is a live C string and `ifindex` is writable local storage.
    let parsed_ifindex =
        unsafe { crate::parse_util::rs_safe_atoi(p, &mut ifindex) } == 0 && ifindex > 0;
    ifname_valid_full_bytes(bytes, flags as u32, parsed_ifindex)
}

/// Exact C ABI shadow of the inline `ifname_valid()` convenience wrapper.
///
/// # Safety
/// `p`, when non-null, must point to a readable NUL-terminated C string for
/// the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ifname_valid(p: *const c_char) -> bool {
    // SAFETY: this wrapper forwards the documented C-string contract unchanged.
    unsafe { rs_ifname_valid_full(p, 0) }
}

pub fn vsock_parse_port(s: &str) -> Result<u32, i32> {
    let value = s.parse::<u32>().map_err(|_| Errno::EINVAL.to_neg_errno())?;
    if value == VMADDR_PORT_ANY {
        return Err(Errno::EINVAL.to_neg_errno());
    }
    Ok(value)
}

pub fn vsock_parse_cid(s: &str) -> Result<u32, i32> {
    match s {
        "hypervisor" => Ok(VMADDR_CID_HYPERVISOR),
        "local" => Ok(VMADDR_CID_LOCAL),
        "host" => Ok(VMADDR_CID_HOST),
        _ => s.parse::<u32>().map_err(|_| Errno::EINVAL.to_neg_errno()),
    }
}

pub fn sockaddr_port(sa: &SocketAddress) -> Result<u32, i32> {
    match sa {
        SocketAddress::Inet { port, .. } | SocketAddress::Inet6 { port, .. } => Ok((*port).into()),
        SocketAddress::Vsock { port, .. } => Ok(*port),
        _ => Err(-libc::EAFNOSUPPORT),
    }
}

pub fn sockaddr_in_addr(sa: &SocketAddress) -> Option<InAddr> {
    match sa {
        SocketAddress::Inet { addr, .. } => Some(InAddr::V4(*addr)),
        SocketAddress::Inet6 { addr, .. } => Some(InAddr::V6(*addr)),
        _ => None,
    }
}

pub fn sockaddr_set_in_addr(
    family: AddressFamily,
    addr: InAddr,
    port: u16,
) -> Result<SocketAddress, i32> {
    match (family, addr) {
        (AddressFamily::Inet, InAddr::V4(addr)) => Ok(SocketAddress::Inet {
            addr,
            port,
            sock_type: None,
        }),
        (AddressFamily::Inet6, InAddr::V6(addr)) => Ok(SocketAddress::Inet6 {
            addr,
            port,
            scope_id: 0,
            sock_type: None,
        }),
        _ => Err(-libc::EAFNOSUPPORT),
    }
}

pub fn sockaddr_equal(a: &SocketAddress, b: &SocketAddress) -> bool {
    match (a, b) {
        (SocketAddress::Inet { addr: a, .. }, SocketAddress::Inet { addr: b, .. }) => a == b,
        (SocketAddress::Inet6 { addr: a, .. }, SocketAddress::Inet6 { addr: b, .. }) => a == b,
        (SocketAddress::Vsock { cid: a, .. }, SocketAddress::Vsock { cid: b, .. }) => a == b,
        _ => false,
    }
}

pub fn sockaddr_ll_len(sa: &SockaddrLl) -> usize {
    let mac_len = match sa.hatype {
        ARPHRD_ETHER => 8usize.max(6),
        ARPHRD_INFINIBAND => 8usize.max(20),
        _ => 8,
    };
    12 + mac_len
}

pub fn sockaddr_un_len(path: &UnixSocketPath) -> usize {
    match path {
        UnixSocketPath::Unnamed => 2,
        UnixSocketPath::Abstract(name) => 2 + 1 + name.len(),
        UnixSocketPath::Filesystem(path) => 2 + path.len() + 1,
    }
}

pub fn sockaddr_len(sa: &SocketAddress) -> usize {
    match sa {
        SocketAddress::Inet { .. } => 16,
        SocketAddress::Inet6 { .. } => 28,
        SocketAddress::Unix { path, .. } => sockaddr_un_len(path),
        SocketAddress::Netlink { .. } => 12,
        SocketAddress::Vsock { .. } => 16,
    }
}

pub fn sockaddr_un_set_path(path: &str) -> Result<(UnixSocketPath, usize), i32> {
    let len = path.len();
    if len < 2 || !matches!(path.as_bytes()[0], b'/' | b'@') {
        return Err(Errno::EINVAL.to_neg_errno());
    }
    if len + 1 > 108 {
        return Err(if path.starts_with('@') {
            Errno::EINVAL.to_neg_errno()
        } else {
            -libc::ENAMETOOLONG
        });
    }

    if let Some(name) = path.strip_prefix('@') {
        Ok((UnixSocketPath::Abstract(name.to_string()), 2 + len))
    } else {
        Ok((UnixSocketPath::Filesystem(path.to_string()), 2 + len + 1))
    }
}

pub fn socket_address_verify(address: &SocketAddress, strict: bool) -> Result<(), i32> {
    match address {
        SocketAddress::Inet {
            port, sock_type, ..
        } => {
            if *port == 0 {
                return Err(Errno::EINVAL.to_neg_errno());
            }
            if !matches!(
                sock_type,
                None | Some(SocketType::Stream | SocketType::Datagram)
            ) {
                return Err(Errno::EINVAL.to_neg_errno());
            }
        }
        SocketAddress::Inet6 {
            port, sock_type, ..
        } => {
            if *port == 0 {
                return Err(Errno::EINVAL.to_neg_errno());
            }
            if !matches!(
                sock_type,
                None | Some(SocketType::Stream | SocketType::Datagram)
            ) {
                return Err(Errno::EINVAL.to_neg_errno());
            }
        }
        SocketAddress::Unix {
            path,
            size,
            sock_type,
        } => {
            if *size < 2 || *size > 111 + usize::from(!strict) {
                return Err(Errno::EINVAL.to_neg_errno());
            }
            if strict
                && matches!(path, UnixSocketPath::Filesystem(text) if *size != 2 + text.len() + 1)
            {
                return Err(Errno::EINVAL.to_neg_errno());
            }
            if !matches!(
                sock_type,
                None | Some(SocketType::Stream | SocketType::Datagram | SocketType::SeqPacket)
            ) {
                return Err(Errno::EINVAL.to_neg_errno());
            }
        }
        SocketAddress::Netlink { sock_type, .. } => {
            if !matches!(
                sock_type,
                None | Some(SocketType::Raw | SocketType::Datagram)
            ) {
                return Err(Errno::EINVAL.to_neg_errno());
            }
        }
        SocketAddress::Vsock { sock_type, .. } => {
            if !matches!(
                sock_type,
                None | Some(SocketType::Stream | SocketType::Datagram)
            ) {
                return Err(Errno::EINVAL.to_neg_errno());
            }
        }
    }

    Ok(())
}

pub fn socket_address_can_accept(address: &SocketAddress) -> bool {
    matches!(
        address,
        SocketAddress::Inet {
            sock_type: Some(SocketType::Stream | SocketType::SeqPacket),
            ..
        } | SocketAddress::Inet6 {
            sock_type: Some(SocketType::Stream | SocketType::SeqPacket),
            ..
        } | SocketAddress::Unix {
            sock_type: Some(SocketType::Stream | SocketType::SeqPacket),
            ..
        } | SocketAddress::Vsock {
            sock_type: Some(SocketType::Stream | SocketType::SeqPacket),
            ..
        }
    )
}

pub fn socket_address_get_path(address: &SocketAddress) -> Option<&str> {
    match address {
        SocketAddress::Unix {
            path: UnixSocketPath::Filesystem(path),
            ..
        } => Some(path.as_str()),
        _ => None,
    }
}

pub fn socket_address_parse_unix(s: &str) -> Result<SocketAddress, i32> {
    let (path, size) = sockaddr_un_set_path(s)?;
    Ok(SocketAddress::Unix {
        path,
        size,
        sock_type: None,
    })
}

pub fn socket_address_parse_vsock(s: &str) -> Result<SocketAddress, i32> {
    let (sock_type, rest) = if let Some(rest) = s.strip_prefix("vsock:") {
        (None, rest)
    } else if let Some(rest) = s.strip_prefix("vsock-dgram:") {
        (Some(SocketType::Datagram), rest)
    } else if let Some(rest) = s.strip_prefix("vsock-seqpacket:") {
        (Some(SocketType::SeqPacket), rest)
    } else if let Some(rest) = s.strip_prefix("vsock-stream:") {
        (Some(SocketType::Stream), rest)
    } else {
        return Err(-libc::EPROTO);
    };

    let (cid_text, port_text) = rest.split_once(':').ok_or(Errno::EINVAL.to_neg_errno())?;
    let port = vsock_parse_port(port_text)?;
    let cid = if cid_text.is_empty() {
        VMADDR_CID_ANY
    } else {
        vsock_parse_cid(cid_text)?
    };

    Ok(SocketAddress::Vsock {
        cid,
        port,
        sock_type,
    })
}

pub fn socket_address_equal_unix(a: &str, b: &str) -> Result<bool, i32> {
    let left = socket_address_parse_unix(a)?;
    let right = socket_address_parse_unix(b)?;
    Ok(left == right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifname_validation_matches_expected_rules() {
        assert!(ifname_valid_char('a'));
        assert!(!ifname_valid_char(':'));
        assert!(!ifname_valid_char(' '));
    }

    #[test]
    fn ifname_rejects_numeric_names_without_flag() {
        assert!(!ifname_valid_full("5", 0));
        assert!(ifname_valid_full("5", IFNAME_VALID_NUMERIC));
    }

    #[test]
    fn ifname_rejects_special_names_by_default() {
        assert!(!ifname_valid_full("all", 0));
        assert!(ifname_valid_full("all", IFNAME_VALID_SPECIAL));
    }

    #[test]
    fn vsock_port_rejects_any_value() {
        assert_eq!(
            vsock_parse_port("4294967295"),
            Err(Errno::EINVAL.to_neg_errno())
        );
    }

    #[test]
    fn vsock_cid_accepts_named_values() {
        assert_eq!(vsock_parse_cid("host"), Ok(VMADDR_CID_HOST));
        assert_eq!(vsock_parse_cid("local"), Ok(VMADDR_CID_LOCAL));
    }

    #[test]
    fn parse_unix_preserves_filesystem_path() {
        let address = socket_address_parse_unix("/run/test.sock").unwrap();
        assert_eq!(socket_address_get_path(&address), Some("/run/test.sock"));
        assert!(socket_address_verify(&address, true).is_ok());
    }

    #[test]
    fn parse_vsock_supports_empty_cid_as_any() {
        let address = socket_address_parse_vsock("vsock::123").unwrap();
        assert_eq!(
            address,
            SocketAddress::Vsock {
                cid: VMADDR_CID_ANY,
                port: 123,
                sock_type: None,
            }
        );
    }

    #[test]
    fn sockaddr_helpers_work_for_inet_variants() {
        let inet = sockaddr_set_in_addr(AddressFamily::Inet, InAddr::V4([1, 2, 3, 4]), 99).unwrap();
        assert_eq!(sockaddr_port(&inet), Ok(99));
        assert_eq!(sockaddr_in_addr(&inet), Some(InAddr::V4([1, 2, 3, 4])));
        assert_eq!(sockaddr_len(&inet), 16);
    }

    #[test]
    fn sockaddr_equal_only_compares_address_component() {
        let a = SocketAddress::Inet {
            addr: [1, 2, 3, 4],
            port: 80,
            sock_type: None,
        };
        let b = SocketAddress::Inet {
            addr: [1, 2, 3, 4],
            port: 8080,
            sock_type: Some(SocketType::Stream),
        };
        assert!(sockaddr_equal(&a, &b));
    }

    #[test]
    fn sockaddr_ll_len_handles_infiniband_overflow_case() {
        assert_eq!(
            sockaddr_ll_len(&SockaddrLl {
                hatype: ARPHRD_INFINIBAND
            }),
            32
        );
    }

    #[test]
    fn can_accept_is_true_for_stream_and_seqpacket() {
        let address = SocketAddress::Vsock {
            cid: 5,
            port: 6,
            sock_type: Some(SocketType::SeqPacket),
        };
        assert!(socket_address_can_accept(&address));
    }

    #[test]
    fn unix_equality_uses_normalized_path_representation() {
        assert!(socket_address_equal_unix("@abc", "@abc").unwrap());
        assert!(!socket_address_equal_unix("/a", "/b").unwrap());
    }
}
