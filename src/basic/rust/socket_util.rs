// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.socket-util; authority=src/basic/socket-util.c,src/basic/socket-util.h,src/basic/parse-util.c,src/basic/parse-util.h

// Centralized unsafe expression boundary for this C-ABI adapter.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing adapter documents and validates the raw-pointer,
        // ownership, and lifetime contract before evaluating this expression.
        unsafe { $expression }
    }};
}
use std::ffi::{CStr, CString};
use std::mem::{offset_of, size_of, zeroed};
use std::ptr;

use libc::{c_char, c_int, c_void};

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
    let bytes = unsafe_ffi!(CStr::from_ptr(p)).to_bytes();
    let mut ifindex = 0;
    // SAFETY: `p` is a live C string and `ifindex` is writable local storage.
    let parsed_ifindex =
        unsafe_ffi!(crate::parse_util::rs_safe_atoi(p, &mut ifindex)) == 0 && ifindex > 0;
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
    unsafe_ffi!(rs_ifname_valid_full(p, 0))
}

pub fn vsock_parse_port(s: &str) -> Result<u32, i32> {
    let s = CString::new(s).map_err(|_| Errno::EINVAL.to_neg_errno())?;
    let mut port = 0;
    // SAFETY: `s` owns a live NUL-terminated buffer and `port` is writable
    // local storage. Sharing the ABI implementation keeps this safe facade
    // aligned with C's base-zero numeric grammar and range errors.
    let r = unsafe_ffi!(rs_vsock_parse_port(s.as_ptr(), &mut port));
    if r < 0 { Err(r) } else { Ok(port) }
}

pub fn vsock_parse_cid(s: &str) -> Result<u32, i32> {
    let s = CString::new(s).map_err(|_| Errno::EINVAL.to_neg_errno())?;
    let mut cid = 0;
    // SAFETY: `s` owns a live NUL-terminated buffer and `cid` is writable
    // local storage. This also preserves C's `any` and `-1` aliases.
    let r = unsafe_ffi!(rs_vsock_parse_cid(s.as_ptr(), &mut cid));
    if r < 0 { Err(r) } else { Ok(cid) }
}

/// Exact C ABI shadow of `vsock_parse_port()`.
///
/// # Safety
/// `s` must point to a readable NUL-terminated C string for the duration of
/// the call, and `ret` must point to writable `unsigned` storage. As a safe
/// boundary policy, null arguments return `-EINVAL` rather than reaching the
/// C implementation's assertion precondition. On every error path `ret` is
/// left untouched.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_vsock_parse_port(s: *const c_char, ret: *mut u32) -> i32 {
    if s.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut port = 0;
    // SAFETY: `s` is a live C string under this export's contract and `port`
    // is a writable local. This reuses the C-authoritative `safe_atou()`
    // grammar, including whitespace, sign, base-prefix, and errno behavior.
    let r = unsafe_ffi!(crate::parse_util::rs_safe_atou(s, &mut port));
    if r < 0 {
        return r;
    }
    if port == VMADDR_PORT_ANY {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: the non-null `ret` pointer is writable by this export's contract.
    unsafe_ffi!(*ret = port);
    0
}

/// Exact C ABI shadow of `vsock_parse_cid()`.
///
/// # Safety
/// `s` must point to a readable NUL-terminated C string for the duration of
/// the call, and `ret` must point to writable `unsigned` storage. As a safe
/// boundary policy, null arguments return `-EINVAL` rather than reaching the
/// C implementation's assertion precondition. On every error path `ret` is
/// left untouched.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_vsock_parse_cid(s: *const c_char, ret: *mut u32) -> i32 {
    if s.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: `s` is a live C string under this export's contract.
    let value = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    let cid = match value {
        b"hypervisor" => Some(VMADDR_CID_HYPERVISOR),
        b"local" => Some(VMADDR_CID_LOCAL),
        b"host" => Some(VMADDR_CID_HOST),
        b"any" | b"-1" => Some(VMADDR_CID_ANY),
        _ => None,
    };
    if let Some(cid) = cid {
        // SAFETY: the non-null `ret` pointer is writable by this export's contract.
        unsafe_ffi!(*ret = cid);
        return 0;
    }

    // SAFETY: `s` is a live C string and `ret` is writable by this export's
    // contract. The numeric branch is exactly the C `safe_atou()` call.
    unsafe_ffi!(crate::parse_util::rs_safe_atou(s, ret))
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
        ARPHRD_ETHER => 8,
        ARPHRD_INFINIBAND => 20,
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

// ── C socket-layout ABI shadows ───────────────────────────────────────────
//
// The high-level types above deliberately do not expose C's platform socket
// union.  These declarations are confined to the FFI boundary, where callers
// really pass `union sockaddr_union` and `SocketAddress` objects from C.

#[repr(C)]
#[derive(Clone, Copy)]
struct CSockaddrLl {
    sll_family: libc::sa_family_t,
    sll_protocol: u16,
    sll_ifindex: i32,
    sll_hatype: u16,
    sll_pkttype: u8,
    sll_halen: u8,
    sll_addr: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CSockaddrNl {
    nl_family: libc::sa_family_t,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CSockaddrVm {
    svm_family: libc::sa_family_t,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_flags: u8,
    svm_zero: [u8; 3],
}

#[repr(C)]
union CSockaddrUnion {
    sa: libc::sockaddr,
    storage: libc::sockaddr_storage,
    in_: libc::sockaddr_in,
    in6: libc::sockaddr_in6,
    un: libc::sockaddr_un,
    nl: CSockaddrNl,
    ll: CSockaddrLl,
    vm: CSockaddrVm,
}

#[repr(C)]
struct CSocketAddress {
    sockaddr: CSockaddrUnion,
    size: libc::socklen_t,
    type_: c_int,
    protocol: c_int,
}

const AF_VSOCK: c_int = 40;

enum CSockaddrRef<'a> {
    Inet(&'a libc::sockaddr_in),
    Inet6(&'a libc::sockaddr_in6),
    Unix(&'a libc::sockaddr_un),
    Link(&'a CSockaddrLl),
    Vsock(&'a CSockaddrVm),
    Other(c_int),
}

/// # Safety
///
/// `sa` must point to a readable, aligned C `sockaddr` object whose family
/// member selects the corresponding complete C union member.
unsafe fn sockaddr_ref<'a>(sa: &'a libc::sockaddr) -> CSockaddrRef<'a> {
    // SAFETY: the helper's contract guarantees a readable, aligned sockaddr
    // and the matching complete union member for the selected family.
    unsafe_ffi!({
        match sa.sa_family as c_int {
            libc::AF_INET => CSockaddrRef::Inet(&*ptr::from_ref(sa).cast::<libc::sockaddr_in>()),
            libc::AF_INET6 => CSockaddrRef::Inet6(&*ptr::from_ref(sa).cast::<libc::sockaddr_in6>()),
            libc::AF_UNIX => CSockaddrRef::Unix(&*ptr::from_ref(sa).cast::<libc::sockaddr_un>()),
            libc::AF_PACKET => CSockaddrRef::Link(&*ptr::from_ref(sa).cast::<CSockaddrLl>()),
            AF_VSOCK => CSockaddrRef::Vsock(&*ptr::from_ref(sa).cast::<CSockaddrVm>()),
            family => CSockaddrRef::Other(family),
        }
    })
}

fn sockaddr_port_from_ref(sa: CSockaddrRef<'_>) -> Result<u32, i32> {
    match sa {
        CSockaddrRef::Inet(sa) => Ok(u16::from_be(sa.sin_port).into()),
        CSockaddrRef::Inet6(sa) => Ok(u16::from_be(sa.sin6_port).into()),
        CSockaddrRef::Vsock(sa) => Ok(sa.svm_port),
        _ => Err(-libc::EAFNOSUPPORT),
    }
}

fn sockaddr_in_addr_ptr_from_ref(sa: CSockaddrRef<'_>) -> *const c_void {
    match sa {
        CSockaddrRef::Inet(sa) => ptr::from_ref(&sa.sin_addr).cast(),
        CSockaddrRef::Inet6(sa) => ptr::from_ref(&sa.sin6_addr).cast(),
        _ => ptr::null(),
    }
}

fn sockaddr_equal_from_ref(a: CSockaddrRef<'_>, b: CSockaddrRef<'_>) -> bool {
    match (a, b) {
        (CSockaddrRef::Inet(a), CSockaddrRef::Inet(b)) => a.sin_addr.s_addr == b.sin_addr.s_addr,
        (CSockaddrRef::Inet6(a), CSockaddrRef::Inet6(b)) => {
            a.sin6_addr.s6_addr == b.sin6_addr.s6_addr
        }
        (CSockaddrRef::Vsock(a), CSockaddrRef::Vsock(b)) => a.svm_cid == b.svm_cid,
        _ => false,
    }
}

fn sockaddr_ll_len_from_ref(sa: CSockaddrRef<'_>) -> usize {
    let CSockaddrRef::Link(sa) = sa else {
        return 0;
    };
    let mac_len = match u16::from_be(sa.sll_hatype) {
        ARPHRD_ETHER => 8,
        ARPHRD_INFINIBAND => 20,
        _ => 8,
    };
    offset_of!(CSockaddrLl, sll_addr) + mac_len
}

fn sockaddr_un_len_from_ref(sa: CSockaddrRef<'_>) -> usize {
    let CSockaddrRef::Unix(sa) = sa else {
        return 0;
    };
    let path = &sa.sun_path;
    let start = usize::from(path[0] == 0);
    let length = path[start..]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(path.len() - start);
    offset_of!(libc::sockaddr_un, sun_path) + start + length + usize::from(path[0] != 0)
}

fn sockaddr_len_from_ref(sa: CSockaddrRef<'_>) -> usize {
    match sa {
        CSockaddrRef::Inet(_) => size_of::<libc::sockaddr_in>(),
        CSockaddrRef::Inet6(_) => size_of::<libc::sockaddr_in6>(),
        CSockaddrRef::Unix(sa) => sockaddr_un_len_from_ref(CSockaddrRef::Unix(sa)),
        CSockaddrRef::Link(sa) => sockaddr_ll_len_from_ref(CSockaddrRef::Link(sa)),
        CSockaddrRef::Vsock(_) => size_of::<CSockaddrVm>(),
        CSockaddrRef::Other(libc::AF_NETLINK) => size_of::<CSockaddrNl>(),
        CSockaddrRef::Other(_) => 0,
    }
}

/// # Safety
/// `a` must point to a readable, aligned C `SocketAddress` shadow.
#[inline]
unsafe fn c_socket_address_family(a: *const CSocketAddress) -> c_int {
    // SAFETY: all callers validate the C SocketAddress pointer before this read.
    unsafe_ffi!((*a).sockaddr.sa.sa_family as c_int)
}

fn socket_type_is(value: c_int, permitted: &[c_int]) -> bool {
    permitted.contains(&value)
}

/// # Safety
/// `sa` must be null or point to a readable C `sockaddr` (normally the first
/// member of `union sockaddr_union`), and `ret_port` must be writable when
/// non-null.  Null inputs are rejected with `-EINVAL` instead of C's assert.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sockaddr_port(sa: *const c_void, ret_port: *mut u32) -> i32 {
    if sa.is_null() || ret_port.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: non-null `sa` meets this export's readable sockaddr contract.
    let port = match sockaddr_port_from_ref(unsafe_ffi!(sockaddr_ref(&*sa.cast()))) {
        Ok(port) => port,
        Err(error) => return error,
    };
    // SAFETY: ensured non-null above and required writable by this export.
    unsafe_ffi!(*ret_port = port);
    0
}

/// # Safety
/// `sa` must be null or point to a readable C `sockaddr`.  The returned
/// pointer aliases storage owned by the caller and remains valid only while
/// that storage is alive and unchanged.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sockaddr_in_addr(sa: *const c_void) -> *const c_void {
    if sa.is_null() {
        return ptr::null();
    }
    // SAFETY: non-null `sa` meets this export's readable sockaddr contract.
    sockaddr_in_addr_ptr_from_ref(unsafe_ffi!(sockaddr_ref(&*sa.cast())))
}

/// # Safety
/// `u` must point to writable `union sockaddr_union` storage and `a` to a
/// readable C `union in_addr_union`.  For accepted families the first
/// `sockaddr_in{,6}` bytes of `u` are replaced, exactly like the C assignment.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sockaddr_set_in_addr(
    u: *mut c_void,
    family: c_int,
    a: *const c_void,
    port: u16,
) -> i32 {
    if u.is_null() || a.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    match family {
        libc::AF_INET => {
            // SAFETY: `a` contains C `in_addr_union`, whose first member is
            // `in_addr`; `u` has room for the C union's `sockaddr_in` member.
            unsafe_ffi!({
                let in_addr = ptr::read(a.cast::<libc::in_addr>());
                ptr::write(
                    u.cast::<libc::sockaddr_in>(),
                    libc::sockaddr_in {
                        sin_family: libc::AF_INET as libc::sa_family_t,
                        sin_port: port.to_be(),
                        sin_addr: in_addr,
                        sin_zero: [0; 8],
                    },
                );
            });
            0
        }
        libc::AF_INET6 => {
            // SAFETY: `in6_addr` starts at the same offset in C's address union.
            unsafe_ffi!({
                let in6_addr = ptr::read(a.cast::<libc::in6_addr>());
                ptr::write(
                    u.cast::<libc::sockaddr_in6>(),
                    libc::sockaddr_in6 {
                        sin6_family: libc::AF_INET6 as libc::sa_family_t,
                        sin6_port: port.to_be(),
                        sin6_flowinfo: 0,
                        sin6_addr: in6_addr,
                        sin6_scope_id: 0,
                    },
                );
            });
            0
        }
        _ => -libc::EAFNOSUPPORT,
    }
}

/// # Safety
/// Each non-null pointer must designate a readable C `union sockaddr_union`.
/// Nulls fail closed rather than entering the C implementation's assertions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sockaddr_equal(a: *const c_void, b: *const c_void) -> bool {
    if a.is_null() || b.is_null() {
        return false;
    }
    // SAFETY: both non-null pointers meet this export's readable union contract.
    let a = unsafe_ffi!(sockaddr_ref(&*a.cast()));
    // SAFETY: `b` has the same readable union contract as `a`.
    let b = unsafe_ffi!(sockaddr_ref(&*b.cast()));
    sockaddr_equal_from_ref(a, b)
}

/// # Safety
/// `sa` must point to a readable C `sockaddr_ll` with `sll_family == AF_PACKET`.
/// Invalid inputs return zero rather than C's assertion failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sockaddr_ll_len(sa: *const c_void) -> usize {
    if sa.is_null() {
        return 0;
    }
    // SAFETY: non-null `sa` meets this export's readable sockaddr contract.
    sockaddr_ll_len_from_ref(unsafe_ffi!(sockaddr_ref(&*sa.cast())))
}

/// # Safety
/// `sa` must point to a readable C `sockaddr_un` with `sun_family == AF_UNIX`.
/// Invalid inputs return zero rather than C's assertion failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sockaddr_un_len(sa: *const c_void) -> usize {
    if sa.is_null() {
        return 0;
    }
    // SAFETY: non-null `sa` meets this export's readable sockaddr contract.
    sockaddr_un_len_from_ref(unsafe_ffi!(sockaddr_ref(&*sa.cast())))
}

/// # Safety
/// `sa` must point to readable C `union sockaddr_union` storage.  Unknown
/// families return zero rather than reaching C's `assert_not_reached()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sockaddr_len(sa: *const c_void) -> usize {
    if sa.is_null() {
        return 0;
    }
    // SAFETY: non-null `sa` meets this export's readable union contract.
    sockaddr_len_from_ref(unsafe_ffi!(sockaddr_ref(&*sa.cast())))
}

/// Construct an AF_UNIX socket address using systemd's `@name` convention for
/// the Linux abstract namespace and `/path` convention for filesystem sockets.
///
/// The returned length is the exact `sockaddr_un` length required by
/// `bind(2)`, `connect(2)`, or `sendmsg(2)`: it excludes the trailing NUL for
/// abstract names and includes it for filesystem paths. This is the safe Rust
/// counterpart of C's `sockaddr_un_set_path()`.
///
/// Errors use systemd's negative errno convention: `-EINVAL` for malformed
/// paths or oversized abstract names and `-ENAMETOOLONG` for oversized
/// filesystem paths.
pub fn sockaddr_un_from_path_bytes(path: &[u8]) -> Result<(libc::sockaddr_un, usize), i32> {
    if path.contains(&0) {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    let bytes = path;
    let first = *bytes.first().ok_or_else(|| Errno::EINVAL.to_neg_errno())?;
    if bytes.len() < 2 || !matches!(first, b'/' | b'@') {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    // SAFETY: zero is a valid bit pattern for the C socket structure.
    let mut un: libc::sockaddr_un = unsafe_ffi!(zeroed());
    let capacity = un.sun_path.len();
    if bytes.len() + 1 > capacity {
        return Err(if first == b'@' {
            -libc::EINVAL
        } else {
            -libc::ENAMETOOLONG
        });
    }
    un.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if first == b'@' {
        for (destination, source) in un.sun_path[1..bytes.len()].iter_mut().zip(&bytes[1..]) {
            *destination = *source as c_char;
        }
        Ok((un, offset_of!(libc::sockaddr_un, sun_path) + bytes.len()))
    } else {
        for (destination, source) in un.sun_path[..bytes.len()].iter_mut().zip(bytes) {
            *destination = *source as c_char;
        }
        Ok((
            un,
            offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1,
        ))
    }
}

/// # Safety
/// `path` must be null or point to a readable NUL-terminated C string.
unsafe fn sockaddr_un_from_path(path: *const c_char) -> Result<(libc::sockaddr_un, usize), i32> {
    if path.is_null() {
        return Err(Errno::EINVAL.to_neg_errno());
    }
    // SAFETY: required by this helper's C-string contract.
    sockaddr_un_from_path_bytes(unsafe_ffi!(CStr::from_ptr(path)).to_bytes())
}

/// # Safety
/// `ret` must point to writable `sockaddr_un` storage and `path` to a readable
/// NUL-terminated C string. Null arguments return `-EINVAL`; on error `ret`
/// remains untouched.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_sockaddr_un_set_path(ret: *mut c_void, path: *const c_char) -> i32 {
    if ret.is_null() || path.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: `path` meets this export's readable C-string contract.
    match unsafe_ffi!(sockaddr_un_from_path(path)) {
        Ok((un, size)) => {
            // SAFETY: the output contract provides a properly aligned full struct.
            unsafe_ffi!(ptr::write(ret.cast::<libc::sockaddr_un>(), un));
            size as i32
        }
        Err(error) => error,
    }
}

/// # Safety
/// `a` must point to a readable, correctly laid-out C `SocketAddress`.
unsafe fn socket_address_verify_c(a: *const CSocketAddress, strict: bool) -> i32 {
    // SAFETY: this helper's contract guarantees a readable CSocketAddress.
    let family = unsafe_ffi!(c_socket_address_family(a));
    // SAFETY: callers provide a readable full C SocketAddress.
    let address = unsafe_ffi!(&*a);
    match family {
        libc::AF_INET => {
            // SAFETY: the inspected family selects this C union member.
            let in_ = unsafe_ffi!(address.sockaddr.in_);
            if address.size as usize != size_of::<libc::sockaddr_in>()
                || in_.sin_port == 0
                || !socket_type_is(address.type_, &[0, libc::SOCK_STREAM, libc::SOCK_DGRAM])
            {
                -libc::EINVAL
            } else {
                0
            }
        }
        libc::AF_INET6 => {
            // SAFETY: the inspected family selects this C union member.
            let in6 = unsafe_ffi!(address.sockaddr.in6);
            if address.size as usize != size_of::<libc::sockaddr_in6>()
                || in6.sin6_port == 0
                || !socket_type_is(address.type_, &[0, libc::SOCK_STREAM, libc::SOCK_DGRAM])
            {
                -libc::EINVAL
            } else {
                0
            }
        }
        libc::AF_UNIX => {
            // SAFETY: the inspected family selects this C union member.
            let un = unsafe_ffi!(address.sockaddr.un);
            let offset = offset_of!(libc::sockaddr_un, sun_path);
            if (address.size as usize) < offset
                || (address.size as usize) > size_of::<libc::sockaddr_un>() + usize::from(!strict)
                || !socket_type_is(
                    address.type_,
                    &[0, libc::SOCK_STREAM, libc::SOCK_DGRAM, libc::SOCK_SEQPACKET],
                )
            {
                return -libc::EINVAL;
            }
            if strict && (address.size as usize) > offset && un.sun_path[0] != 0 {
                let bytes = &un.sun_path;
                if let Some(nul) = bytes.iter().position(|byte| *byte == 0) {
                    if address.size as usize != offset + nul + 1 {
                        return -libc::EINVAL;
                    }
                } else if ![bytes.len(), bytes.len() + 1].contains(&(address.size as usize)) {
                    // Mirrors C's literal `sizeof(sun_path)` comparison, including its oddity.
                    return -libc::EINVAL;
                }
            }
            0
        }
        libc::AF_NETLINK => {
            if address.size as usize != size_of::<CSockaddrNl>()
                || !socket_type_is(address.type_, &[0, libc::SOCK_RAW, libc::SOCK_DGRAM])
            {
                -libc::EINVAL
            } else {
                0
            }
        }
        AF_VSOCK => {
            if address.size as usize != size_of::<CSockaddrVm>()
                || !socket_type_is(address.type_, &[0, libc::SOCK_STREAM, libc::SOCK_DGRAM])
            {
                -libc::EINVAL
            } else {
                0
            }
        }
        _ => -libc::EAFNOSUPPORT,
    }
}

/// # Safety
/// `a` must point to a readable C `SocketAddress`. Null returns `-EINVAL`
/// instead of triggering C's assertion; otherwise validation is byte-for-byte
/// equivalent to `socket_address_verify()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_socket_address_verify(a: *const c_void, strict: bool) -> i32 {
    if a.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: non-null `a` meets this export's readable CSocketAddress contract.
    unsafe_ffi!(socket_address_verify_c(a.cast(), strict))
}

/// # Safety
/// `a` must point to readable C `SocketAddress` storage. Null fails closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_socket_address_can_accept(a: *const c_void) -> bool {
    if a.is_null() {
        return false;
    }
    // SAFETY: non-null C SocketAddress is readable by this export's contract.
    let a = unsafe_ffi!(&*a.cast::<CSocketAddress>());
    matches!(a.type_, libc::SOCK_STREAM | libc::SOCK_SEQPACKET)
}

/// # Safety
/// `a` must point to readable C `SocketAddress` storage.  A non-null return
/// aliases the caller-owned `sun_path` storage and has no allocator transfer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_socket_address_get_path(a: *const c_void) -> *const c_char {
    // SAFETY: a non-null `a` meets this export's readable CSocketAddress contract.
    if a.is_null() || unsafe_ffi!(c_socket_address_family(a.cast())) != libc::AF_UNIX {
        return ptr::null();
    }
    // SAFETY: family selected the Unix member in valid C SocketAddress storage.
    let un = unsafe_ffi!(&(*a.cast::<CSocketAddress>()).sockaddr.un);
    if un.sun_path[0] == 0 {
        ptr::null()
    } else {
        un.sun_path.as_ptr()
    }
}

fn socket_address_from_un(un: libc::sockaddr_un, size: usize) -> CSocketAddress {
    CSocketAddress {
        sockaddr: CSockaddrUnion { un },
        size: size as libc::socklen_t,
        type_: 0,
        protocol: 0,
    }
}

/// # Safety
/// `ret_address` must point to writable C `SocketAddress` storage and `s` to
/// a readable NUL-terminated string. Nulls return `-EINVAL`; errors leave the
/// destination untouched.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_socket_address_parse_unix(
    ret_address: *mut c_void,
    s: *const c_char,
) -> i32 {
    if ret_address.is_null() || s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: this export carries the C-string validity requirement.
    let bytes = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    if !matches!(bytes.first(), Some(b'/' | b'@')) {
        return -libc::EPROTO;
    }
    // SAFETY: `s` meets this export's readable C-string contract.
    let (un, size) = match unsafe_ffi!(sockaddr_un_from_path(s)) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let address = socket_address_from_un(un, size);
    // SAFETY: output contract supplies complete writable C SocketAddress storage.
    unsafe_ffi!(ptr::write(ret_address.cast::<CSocketAddress>(), address));
    0
}

/// # Safety
/// `ret_address` must point to writable C `SocketAddress` storage and `s` to
/// a readable NUL-terminated string. Nulls return `-EINVAL`; errors leave the
/// destination untouched.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_socket_address_parse_vsock(
    ret_address: *mut c_void,
    s: *const c_char,
) -> i32 {
    if ret_address.is_null() || s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: this export carries the C-string validity requirement.
    let bytes = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    let (type_, remainder) = if let Some(rest) = bytes.strip_prefix(b"vsock:") {
        (0, rest)
    } else if let Some(rest) = bytes.strip_prefix(b"vsock-dgram:") {
        (libc::SOCK_DGRAM, rest)
    } else if let Some(rest) = bytes.strip_prefix(b"vsock-seqpacket:") {
        (libc::SOCK_SEQPACKET, rest)
    } else if let Some(rest) = bytes.strip_prefix(b"vsock-stream:") {
        (libc::SOCK_STREAM, rest)
    } else {
        return -libc::EPROTO;
    };
    let Some(separator) = remainder.iter().position(|byte| *byte == b':') else {
        return -libc::EINVAL;
    };
    let mut port = 0;
    // SAFETY: separator is in the original NUL-terminated string, so this points at a C substring.
    let port_ptr = unsafe_ffi!(s.add(bytes.len() - remainder.len() + separator + 1));
    let r = unsafe_ffi!(rs_vsock_parse_port(port_ptr, &mut port));
    if r < 0 {
        return r;
    }
    // C allocates this substring even when it is empty. Keep that allocation
    // and its ENOMEM edge case observable at the ABI boundary.
    // SAFETY: the prefix offset is within the same validated NUL-terminated string.
    let cid_start = unsafe_ffi!(s.add(bytes.len() - remainder.len()));
    // SAFETY: `cid_start` has at least `separator` readable bytes before the terminator.
    let cid_string = unsafe_ffi!(libc::strndup(cid_start, separator));
    if cid_string.is_null() {
        return -libc::ENOMEM;
    }
    let cid = if separator == 0 {
        VMADDR_CID_ANY
    } else {
        let mut value = 0;
        // SAFETY: strndup returned a NUL-terminated CID substring and `value` is local writable storage.
        let r = unsafe_ffi!(rs_vsock_parse_cid(cid_string, &mut value));
        if r < 0 {
            // SAFETY: `strndup()` returned this allocation exactly once above.
            unsafe_ffi!(libc::free(cid_string.cast()));
            return r;
        }
        value
    };
    // SAFETY: `strndup()` returned this allocation exactly once above.
    unsafe_ffi!(libc::free(cid_string.cast()));
    let address = CSocketAddress {
        sockaddr: CSockaddrUnion {
            vm: CSockaddrVm {
                svm_family: AF_VSOCK as libc::sa_family_t,
                svm_reserved1: 0,
                svm_port: port,
                svm_cid: cid,
                svm_flags: 0,
                svm_zero: [0; 3],
            },
        },
        size: size_of::<CSockaddrVm>() as libc::socklen_t,
        type_,
        protocol: 0,
    };
    // SAFETY: output contract supplies complete writable C SocketAddress storage.
    unsafe_ffi!(ptr::write(ret_address.cast::<CSocketAddress>(), address));
    0
}

/// # Safety
/// `a` and `b` must point to readable NUL-terminated C strings. Nulls return
/// `-EINVAL`; the result intentionally preserves C's union-level comparator,
/// which considers AF_UNIX addresses unequal after successful parsing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_socket_address_equal_unix(a: *const c_char, b: *const c_char) -> i32 {
    if a.is_null() || b.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: zero is valid before the parse functions initialize each aggregate.
    let mut left: CSocketAddress = unsafe_ffi!(zeroed());
    // SAFETY: zero is valid before the parse functions initialize each aggregate.
    let mut right: CSocketAddress = unsafe_ffi!(zeroed());
    let r = unsafe_ffi!(rs_socket_address_parse_unix((&raw mut left).cast(), a));
    if r < 0 {
        return r;
    }
    // SAFETY: `right` is writable local CSocketAddress storage and `b` is a valid C string.
    let r = unsafe_ffi!(rs_socket_address_parse_unix((&raw mut right).cast(), b));
    if r < 0 {
        return r;
    }
    // SAFETY: both initialized local unions remain readable for this comparison.
    unsafe_ffi!({
        rs_sockaddr_equal(
            (&raw const left.sockaddr).cast(),
            (&raw const right.sockaddr).cast(),
        ) as i32
    })
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
    fn sockaddr_un_bytes_preserves_abstract_and_filesystem_lengths() {
        let (abstract_address, abstract_length) = sockaddr_un_from_path_bytes(b"@notify").unwrap();
        assert_eq!(abstract_address.sun_path[0], 0);
        assert_eq!(
            abstract_address.sun_path[1..7]
                .iter()
                .map(|byte| *byte as u8)
                .collect::<Vec<_>>(),
            b"notify"
        );
        assert_eq!(
            abstract_length,
            offset_of!(libc::sockaddr_un, sun_path) + b"@notify".len()
        );

        let (filesystem_address, filesystem_length) =
            sockaddr_un_from_path_bytes(b"/run/notify").unwrap();
        assert_eq!(
            filesystem_address.sun_path[..11]
                .iter()
                .map(|byte| *byte as u8)
                .collect::<Vec<_>>(),
            b"/run/notify"
        );
        assert_eq!(
            filesystem_length,
            offset_of!(libc::sockaddr_un, sun_path) + b"/run/notify".len() + 1
        );
    }

    #[test]
    fn sockaddr_un_bytes_rejects_embedded_nul_and_relative_names() {
        assert!(matches!(
            sockaddr_un_from_path_bytes(b"/run\0notify"),
            Err(error) if error == Errno::EINVAL.to_neg_errno()
        ));
        assert!(matches!(
            sockaddr_un_from_path_bytes(b"notify"),
            Err(error) if error == Errno::EINVAL.to_neg_errno()
        ));
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
