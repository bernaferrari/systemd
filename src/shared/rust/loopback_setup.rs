// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/loopback-setup.c, src/shared/loopback-setup.h
//
// Loopback network interface setup.
//
// Configures the loopback interface (`lo`) by:
//   1. Adding the IPv4 loopback address 127.0.0.1/8 (IFA_F_PERMANENT, RT_SCOPE_HOST)
//   2. Adding the IPv6 loopback address ::1/128 (IFA_F_PERMANENT | IFA_F_NOPREFIXROUTE)
//   3. Bringing the interface up (IFF_UP)
//
// Uses raw rtnetlink (AF_NETLINK / NETLINK_ROUTE) for all operations.
// The netlink I/O itself is necessarily unsafe; everything else is safe Rust.

use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::ffi::Errno;
use crate::socket_netlink::{
    AF_INET, AF_INET6, AF_NETLINK, NETLINK_ROUTE, NLM_F_ACK, NLM_F_REQUEST, NLMSG_DONE,
    NLMSG_ERROR, NLMSG_NOOP, NLMSG_OVERRUN, NlMsgHdr, SockAddrNl, SocketNetlinkError, netlink_bind,
    netlink_recv, netlink_send, netlink_socket, safe_close_fd,
};

// ── Constants ─────────────────────────────────────────────────────────────

/// Loopback interface index (always 1 on Linux).
pub const LOOPBACK_IFINDEX: i32 = 1;

/// Timeout for loopback setup operations.
pub const LOOPBACK_SETUP_TIMEOUT: Duration = Duration::from_secs(5);

// rtnetlink message types
const RTM_NEWADDR: u16 = 20;
const RTM_SETLINK: u16 = 22;
const RTM_GETLINK: u16 = 18;

// rtnetlink address attributes (IFA_)
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;

// ifa_flags
const IFA_F_PERMANENT: u32 = 0x80;
const IFA_F_NOPREFIXROUTE: u32 = 0x200;

// interface info flags
const IFF_UP: u32 = 0x1;

// ifinfomsg attributes (IFLA_)
const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_FLAGS: u16 = 16;

// address scope
const RT_SCOPE_HOST: u8 = 254;

// rtnetlink family
const RTM_FAMILY_MAX: u8 = 43;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors that can occur during loopback interface setup.
#[derive(Debug)]
pub enum LoopbackSetupError {
    /// Failed to create or bind the netlink socket.
    NetlinkSocket(SocketNetlinkError),
    /// Failed to send a netlink message.
    NetlinkSend(SocketNetlinkError),
    /// Failed to receive a netlink reply.
    NetlinkRecv(SocketNetlinkError),
    /// The kernel returned an error in the netlink ACK.
    KernelError(i32),
    /// Operation timed out.
    TimedOut,
    /// Received an unexpected netlink message type.
    UnexpectedMessage(u16),
    /// Insufficient data in the netlink reply.
    TruncatedMessage,
    /// The loopback interface is not up after configuration.
    InterfaceNotUp,
    /// A privilege error occurred (EPERM/EACCES) but the interface is already up.
    PrivilegeButAlreadyUp,
    /// An I/O error occurred.
    Io(io::Error),
}

impl std::fmt::Display for LoopbackSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetlinkSocket(e) => write!(f, "netlink socket error: {e}"),
            Self::NetlinkSend(e) => write!(f, "netlink send error: {e}"),
            Self::NetlinkRecv(e) => write!(f, "netlink recv error: {e}"),
            Self::KernelError(code) => write!(f, "kernel error: {}", -code),
            Self::TimedOut => write!(f, "loopback setup timed out"),
            Self::UnexpectedMessage(t) => write!(f, "unexpected netlink message type: {t}"),
            Self::TruncatedMessage => write!(f, "truncated netlink message"),
            Self::InterfaceNotUp => write!(f, "loopback interface is not up"),
            Self::PrivilegeButAlreadyUp => {
                write!(f, "privilege denied but loopback interface is already up")
            }
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for LoopbackSetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<SocketNetlinkError> for LoopbackSetupError {
    fn from(e: SocketNetlinkError) -> Self {
        Self::NetlinkSocket(e)
    }
}

impl From<io::Error> for LoopbackSetupError {
    fn from(e: io::Error) -> Self {
        LoopbackSetupError::Io(e)
    }
}

// ── Result alias ──────────────────────────────────────────────────────────

/// Result type for loopback setup operations.
pub type Result<T> = std::result::Result<T, LoopbackSetupError>;

// ── Response state for async-style message tracking ───────────────────────

/// Tracks the expected number of netlink responses and their results.
///
/// Mirrors the C `struct state` used by `generic_handler`.
#[derive(Debug, Clone, Default)]
pub struct ResponseState {
    /// Number of outstanding netlink responses expected.
    pub pending: u32,
    /// Error code from the last processed response (0 = success).
    pub last_rcode: i32,
    /// Log messages collected during processing.
    messages: Vec<String>,
}

impl ResponseState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a message was sent and we expect one reply.
    pub fn expect_reply(&mut self) {
        self.pending = self.pending.saturating_add(1);
    }

    /// Record an incoming reply, decrementing the pending count.
    pub fn handle_reply(&mut self, rcode: i32, message: &str) {
        self.pending = self.pending.saturating_sub(1);
        self.last_rcode = rcode;
        self.messages.push(message.to_owned());
    }

    /// Check if all expected replies have been received.
    pub fn is_done(&self) -> bool {
        self.pending == 0
    }

    /// Return the collected messages.
    pub fn messages(&self) -> &[String] {
        &self.messages
    }
}

// ── rtnetlink message builders ────────────────────────────────────────────

/// rtnetlink ifinfomsg header (16 bytes on all platforms).
///
/// Layout: family(1) pad(1) type(1) index(2) flags(4) change(4)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct IfInfoMsg {
    ifi_family: u8,
    ifi_pad: u8,
    ifi_type: u8,
    ifi_index: i16,
    ifi_flags: u32,
    ifi_change: u32,
}

impl IfInfoMsg {
    fn new(ifindex: i32, flags: u32) -> Self {
        Self {
            ifi_family: AF_UNSPEC as u8,
            ifi_pad: 0,
            ifi_type: 0,
            ifi_index: ifindex as i16,
            ifi_flags: flags,
            ifi_change: 0xffffffff, // IFF_ALL
        }
    }
}

const AF_UNSPEC: i32 = 0;

/// rtnetlink ifaddrmsg header (12 bytes on all platforms).
///
/// Layout: family(1) prefixlen(1) flags(1) scope(1) index(4)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct IfAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: i32,
}

impl IfAddrMsg {
    fn new(family: u8, prefixlen: u8, scope: u8, ifindex: i32) -> Self {
        Self {
            ifa_family: family,
            ifa_prefixlen: prefixlen,
            ifa_flags: 0,
            ifa_scope: scope,
            ifa_index: ifindex,
        }
    }
}

/// rtnetlink attribute header (4 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct RtAttr {
    rta_len: u16,
    rta_type: u16,
}

impl RtAttr {
    fn new(attr_type: u16, data_len: u16) -> Self {
        // rta_len includes the header itself
        Self {
            rta_len: mem::size_of::<Self>() as u16 + data_len,
            rta_type: attr_type,
        }
    }
}

// ── Low-level netlink helpers ────────────────────────────────────────────

/// Open a rtnetlink socket (NETLINK_ROUTE).
///
/// Returns a file descriptor on success.
fn open_rtnetlink() -> Result<i32> {
    let fd = netlink_socket(NETLINK_ROUTE).map_err(LoopbackSetupError::NetlinkSocket)?;
    let addr = SockAddrNl::new(0, 0);
    netlink_bind(fd, &addr).map_err(LoopbackSetupError::NetlinkSocket)?;
    Ok(fd)
}

/// Send a rtnetlink message and synchronously receive the ACK reply.
///
/// Returns the kernel error code from the ACK (0 on success).
fn rtnl_call(fd: i32, msg_type: u16, flags: u16, payload: &[u8]) -> Result<i32> {
    let hdr = NlMsgHdr::new(msg_type, flags, 1, 0, payload.len() as u32);
    // SAFETY: `hdr` is a live repr(C) header, and the byte slice covers exactly its size.
    let hdr_bytes = unsafe {
        std::slice::from_raw_parts(
            &hdr as *const NlMsgHdr as *const u8,
            mem::size_of::<NlMsgHdr>(),
        )
    };

    let kernel_addr = SockAddrNl::new(0, 0);

    // Send header + payload
    let mut buf = Vec::with_capacity(hdr_bytes.len() + payload.len());
    buf.extend_from_slice(hdr_bytes);
    buf.extend_from_slice(payload);
    netlink_send(fd, &buf, &kernel_addr).map_err(LoopbackSetupError::NetlinkSend)?;

    // Receive and parse the ACK
    let mut recv_buf = [0u8; 4096];
    let n = netlink_recv(fd, &mut recv_buf).map_err(LoopbackSetupError::NetlinkRecv)?;
    if n < mem::size_of::<NlMsgHdr>() {
        return Err(LoopbackSetupError::TruncatedMessage);
    }

    // SAFETY: the preceding length check guarantees a complete header; unaligned access handles netlink alignment.
    let resp_hdr: NlMsgHdr =
        unsafe { std::ptr::read_unaligned(recv_buf.as_ptr() as *const NlMsgHdr) };

    match resp_hdr.type_ {
        NLMSG_ERROR => {
            // NLMSG_ERROR payload is a struct nlmsgerr: error code (i32) + original message
            let payload_start = mem::size_of::<NlMsgHdr>();
            if n < payload_start + mem::size_of::<i32>() {
                return Err(LoopbackSetupError::TruncatedMessage);
            }
            // SAFETY: the preceding length check leaves a complete i32 at `payload_start`; unaligned access is permitted.
            let error_code: i32 = unsafe {
                std::ptr::read_unaligned(recv_buf[payload_start..].as_ptr() as *const i32)
            };
            // Negative = error, 0 = success (ACK)
            Ok(error_code)
        }
        NLMSG_DONE => Ok(0),
        NLMSG_NOOP | NLMSG_OVERRUN => Err(LoopbackSetupError::UnexpectedMessage(resp_hdr.type_)),
        _ => Err(LoopbackSetupError::UnexpectedMessage(resp_hdr.type_)),
    }
}

// ── rtnetlink attribute encoding ─────────────────────────────────────────

/// Append a u32 attribute to the buffer (properly aligned).
fn append_attr_u32(buf: &mut Vec<u8>, attr_type: u16, value: u32) {
    // Align to 4 bytes (NETLINK_ALIGN)
    let pad = (4 - (buf.len() % 4)) % 4;
    buf.extend(std::iter::repeat_n(0, pad));

    let attr = RtAttr::new(attr_type, 4);
    // SAFETY: `attr` is a live repr(C) attribute header, and the byte slice covers exactly its size.
    let attr_bytes = unsafe {
        std::slice::from_raw_parts(
            &attr as *const RtAttr as *const u8,
            mem::size_of::<RtAttr>(),
        )
    };
    buf.extend_from_slice(attr_bytes);
    buf.extend_from_slice(&value.to_ne_bytes());
}

/// Append a raw byte attribute to the buffer (properly aligned).
fn append_attr_bytes(buf: &mut Vec<u8>, attr_type: u16, data: &[u8]) {
    let pad = (4 - (buf.len() % 4)) % 4;
    buf.extend(std::iter::repeat_n(0, pad));

    let attr = RtAttr::new(attr_type, data.len() as u16);
    // SAFETY: `attr` is a live repr(C) attribute header, and the byte slice covers exactly its size.
    let attr_bytes = unsafe {
        std::slice::from_raw_parts(
            &attr as *const RtAttr as *const u8,
            mem::size_of::<RtAttr>(),
        )
    };
    buf.extend_from_slice(attr_bytes);
    buf.extend_from_slice(data);

    // Pad the data to 4-byte alignment
    let data_pad = (4 - (data.len() % 4)) % 4;
    buf.extend(std::iter::repeat_n(0, data_pad));
}

// ── Core operations ──────────────────────────────────────────────────────

/// Build and send an RTM_SETLINK to bring the loopback interface up.
///
/// Returns the kernel error code (0 = success).
fn start_loopback(fd: i32) -> Result<i32> {
    let ifi = IfInfoMsg::new(LOOPBACK_IFINDEX, IFF_UP);
    // SAFETY: `ifi` is a live repr(C) link header, and the byte slice covers exactly its size.
    let ifi_bytes = unsafe {
        std::slice::from_raw_parts(
            &ifi as *const IfInfoMsg as *const u8,
            mem::size_of::<IfInfoMsg>(),
        )
    };

    let mut payload = Vec::new();
    payload.extend_from_slice(ifi_bytes);
    append_attr_u32(&mut payload, IFLA_FLAGS, IFF_UP);

    rtnl_call(fd, RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK, &payload)
}

/// Build and send an RTM_NEWADDR to add 127.0.0.1/8 to the loopback interface.
///
/// Returns the kernel error code (0 = success, -EEXIST = already present).
fn add_ipv4_address(fd: i32) -> Result<i32> {
    let ifa = IfAddrMsg::new(AF_INET as u8, 8, RT_SCOPE_HOST, LOOPBACK_IFINDEX);
    // SAFETY: `ifa` is a live repr(C) address header, and the byte slice covers exactly its size.
    let ifa_bytes = unsafe {
        std::slice::from_raw_parts(
            &ifa as *const IfAddrMsg as *const u8,
            mem::size_of::<IfAddrMsg>(),
        )
    };

    let mut payload = Vec::new();
    payload.extend_from_slice(ifa_bytes);
    append_attr_u32(&mut payload, IFA_FLAGS, IFA_F_PERMANENT);

    // IFA_LOCAL = 127.0.0.1 in network byte order (big-endian for in_addr)
    let loopback_bytes = Ipv4Addr::LOCALHOST.octets();
    append_attr_bytes(&mut payload, IFA_LOCAL, &loopback_bytes);
    append_attr_bytes(&mut payload, IFA_ADDRESS, &loopback_bytes);

    rtnl_call(fd, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK, &payload)
}

/// Build and send an RTM_NEWADDR to add ::1/128 to the loopback interface.
///
/// Returns the kernel error code (0 = success, -EEXIST = already present).
fn add_ipv6_address(fd: i32) -> Result<i32> {
    let ifa = IfAddrMsg::new(AF_INET6 as u8, 128, RT_SCOPE_HOST, LOOPBACK_IFINDEX);
    // SAFETY: `ifa` is a live repr(C) address header, and the byte slice covers exactly its size.
    let ifa_bytes = unsafe {
        std::slice::from_raw_parts(
            &ifa as *const IfAddrMsg as *const u8,
            mem::size_of::<IfAddrMsg>(),
        )
    };

    let mut payload = Vec::new();
    payload.extend_from_slice(ifa_bytes);
    append_attr_u32(
        &mut payload,
        IFA_FLAGS,
        IFA_F_PERMANENT | IFA_F_NOPREFIXROUTE,
    );

    // IFA_LOCAL = ::1
    let loopback_bytes = std::net::Ipv6Addr::LOCALHOST.octets();
    append_attr_bytes(&mut payload, IFA_LOCAL, &loopback_bytes);
    append_attr_bytes(&mut payload, IFA_ADDRESS, &loopback_bytes);

    rtnl_call(fd, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK, &payload)
}

/// Check whether the loopback interface is currently up.
///
/// Sends RTM_GETLINK and checks the IFF_UP flag in the response.
fn check_loopback(fd: i32) -> Result<bool> {
    let ifi = IfInfoMsg::new(LOOPBACK_IFINDEX, 0);
    // SAFETY: `ifi` is a live repr(C) link header, and the byte slice covers exactly its size.
    let ifi_bytes = unsafe {
        std::slice::from_raw_parts(
            &ifi as *const IfInfoMsg as *const u8,
            mem::size_of::<IfInfoMsg>(),
        )
    };

    let mut payload = Vec::new();
    payload.extend_from_slice(ifi_bytes);

    let hdr = NlMsgHdr::new(
        RTM_GETLINK,
        NLM_F_REQUEST | NLM_F_ACK,
        1,
        0,
        payload.len() as u32,
    );
    // SAFETY: `hdr` is a live repr(C) header, and the byte slice covers exactly its size.
    let hdr_bytes = unsafe {
        std::slice::from_raw_parts(
            &hdr as *const NlMsgHdr as *const u8,
            mem::size_of::<NlMsgHdr>(),
        )
    };

    let kernel_addr = SockAddrNl::new(0, 0);
    let mut buf = Vec::with_capacity(hdr_bytes.len() + payload.len());
    buf.extend_from_slice(hdr_bytes);
    buf.extend_from_slice(&payload);
    netlink_send(fd, &buf, &kernel_addr).map_err(LoopbackSetupError::NetlinkSend)?;

    // Receive reply
    let mut recv_buf = [0u8; 4096];
    let n = netlink_recv(fd, &mut recv_buf).map_err(LoopbackSetupError::NetlinkRecv)?;
    if n < mem::size_of::<NlMsgHdr>() {
        return Err(LoopbackSetupError::TruncatedMessage);
    }

    // SAFETY: the preceding length check guarantees a complete header; unaligned access handles netlink alignment.
    let resp_hdr: NlMsgHdr =
        unsafe { std::ptr::read_unaligned(recv_buf.as_ptr() as *const NlMsgHdr) };

    // Check for error in ACK
    if resp_hdr.type_ == NLMSG_ERROR {
        let payload_start = mem::size_of::<NlMsgHdr>();
        if n >= payload_start + mem::size_of::<i32>() {
            // SAFETY: the enclosing length check leaves a complete i32 at `payload_start`; unaligned access is permitted.
            let error_code: i32 = unsafe {
                std::ptr::read_unaligned(recv_buf[payload_start..].as_ptr() as *const i32)
            };
            if error_code != 0 {
                return Ok(false);
            }
        }
        // Successful ACK — but we need to look at the actual interface data
        // For RTM_GETLINK with NLM_F_ACK, the interface info may be in a separate message.
        // Re-issue without ACK to get the actual data.
    }

    // Re-issue without ACK to get actual interface data
    let hdr2 = NlMsgHdr::new(RTM_GETLINK, NLM_F_REQUEST, 2, 0, payload.len() as u32);
    // SAFETY: `hdr2` is a live repr(C) header, and the byte slice covers exactly its size.
    let hdr2_bytes = unsafe {
        std::slice::from_raw_parts(
            &hdr2 as *const NlMsgHdr as *const u8,
            mem::size_of::<NlMsgHdr>(),
        )
    };
    let mut buf2 = Vec::with_capacity(hdr2_bytes.len() + payload.len());
    buf2.extend_from_slice(hdr2_bytes);
    buf2.extend_from_slice(&payload);
    netlink_send(fd, &buf2, &kernel_addr).map_err(LoopbackSetupError::NetlinkSend)?;

    let n2 = netlink_recv(fd, &mut recv_buf).map_err(LoopbackSetupError::NetlinkRecv)?;
    if n2 < mem::size_of::<NlMsgHdr>() + mem::size_of::<IfInfoMsg>() {
        return Err(LoopbackSetupError::TruncatedMessage);
    }

    // SAFETY: the preceding length check guarantees a complete header; unaligned access handles netlink alignment.
    let resp_hdr2: NlMsgHdr =
        unsafe { std::ptr::read_unaligned(recv_buf.as_ptr() as *const NlMsgHdr) };
    if resp_hdr2.type_ != RTM_GETLINK {
        return Err(LoopbackSetupError::UnexpectedMessage(resp_hdr2.type_));
    }

    let offset_ifi = mem::size_of::<NlMsgHdr>();
    // SAFETY: `n2` was checked for a complete header plus link message; unaligned access handles the byte buffer alignment.
    let resp_ifi: IfInfoMsg =
        unsafe { std::ptr::read_unaligned(recv_buf[offset_ifi..].as_ptr() as *const IfInfoMsg) };

    Ok(resp_ifi.ifi_flags & IFF_UP != 0)
}

// ── Public API ────────────────────────────────────────────────────────────

/// Configure the loopback network interface.
///
/// This function:
/// 1. Opens a rtnetlink socket
/// 2. Adds the IPv4 loopback address 127.0.0.1/8
/// 3. Adds the IPv6 loopback address ::1/128
/// 4. Brings the loopback interface up (IFF_UP)
///
/// If the interface bring-up fails with a privilege error (EPERM/EACCES),
/// it checks whether the interface is already up and returns success if so
/// (to support unprivileged containers).
///
/// Note: Address add results (including EEXIST) are logged but not treated
/// as failures, since the kernel implicitly adds these addresses when the
/// loopback device is created. We add them explicitly to ensure they are
/// present by the time this function returns.
///
/// See: <https://github.com/systemd/systemd/issues/5641>
pub fn loopback_setup() -> Result<()> {
    let fd = open_rtnetlink()?;

    let _guard = CloseFd(fd);

    // Add IPv4 loopback address (ignore EEXIST)
    match add_ipv4_address(fd) {
        Ok(0) => {}                                         // success
        Ok(rcode) if rcode == -(Errno::EEXIST as i32) => {} // already present, fine
        Ok(rcode) => {
            // Non-zero kernel error that isn't EEXIST — log but continue
            let _ = rcode;
        }
        Err(_) => {
            // Send failure — continue with other operations
        }
    }

    // Add IPv6 loopback address (ignore EEXIST)
    match add_ipv6_address(fd) {
        Ok(0) => {}                                         // success
        Ok(rcode) if rcode == -(Errno::EEXIST as i32) => {} // already present, fine
        Ok(rcode) => {
            let _ = rcode;
        }
        Err(_) => {}
    }

    // Bring the loopback interface up
    match start_loopback(fd) {
        Ok(0) => return Ok(()),
        Ok(rcode) => {
            // Non-zero kernel error
            if is_privilege_error(rcode) {
                // If we lack permissions but the interface is already up, succeed
                match check_loopback(fd) {
                    Ok(true) => return Ok(()),
                    Ok(false) | Err(_) => {}
                }
            }
            return Err(LoopbackSetupError::KernelError(rcode));
        }
        Err(e) => return Err(e),
    }
}

/// RAII guard to close a file descriptor on drop.
struct CloseFd(i32);

impl Drop for CloseFd {
    fn drop(&mut self) {
        safe_close_fd(self.0);
    }
}

/// Check if an error code indicates a privilege error (EPERM or EACCES).
fn is_privilege_error(rcode: i32) -> bool {
    let neg = rcode;
    neg == -(Errno::EPERM as i32) || neg == -(Errno::EACCES as i32)
}

// ── Pure logic helpers (testable without root) ────────────────────────────

/// Determine if a netlink error code represents an "already exists" condition.
pub fn is_eexist(rcode: i32) -> bool {
    rcode == -(Errno::EEXIST as i32)
}

/// Determine if a netlink error code represents a success (0).
pub fn is_success(rcode: i32) -> bool {
    rcode == 0
}

/// Build the IPv4 loopback address attribute payload for testing/inspection.
pub fn ipv4_loopback_payload() -> Vec<u8> {
    let ifa = IfAddrMsg::new(AF_INET as u8, 8, RT_SCOPE_HOST, LOOPBACK_IFINDEX);
    // SAFETY: `ifa` is a live repr(C) address header, and the byte slice covers exactly its size.
    let ifa_bytes = unsafe {
        std::slice::from_raw_parts(
            &ifa as *const IfAddrMsg as *const u8,
            mem::size_of::<IfAddrMsg>(),
        )
    };
    let mut payload = Vec::new();
    payload.extend_from_slice(ifa_bytes);
    append_attr_u32(&mut payload, IFA_FLAGS, IFA_F_PERMANENT);
    let loopback_bytes = Ipv4Addr::LOCALHOST.octets();
    append_attr_bytes(&mut payload, IFA_LOCAL, &loopback_bytes);
    append_attr_bytes(&mut payload, IFA_ADDRESS, &loopback_bytes);
    payload
}

/// Build the IPv6 loopback address attribute payload for testing/inspection.
pub fn ipv6_loopback_payload() -> Vec<u8> {
    let ifa = IfAddrMsg::new(AF_INET6 as u8, 128, RT_SCOPE_HOST, LOOPBACK_IFINDEX);
    // SAFETY: `ifa` is a live repr(C) address header, and the byte slice covers exactly its size.
    let ifa_bytes = unsafe {
        std::slice::from_raw_parts(
            &ifa as *const IfAddrMsg as *const u8,
            mem::size_of::<IfAddrMsg>(),
        )
    };
    let mut payload = Vec::new();
    payload.extend_from_slice(ifa_bytes);
    append_attr_u32(
        &mut payload,
        IFA_FLAGS,
        IFA_F_PERMANENT | IFA_F_NOPREFIXROUTE,
    );
    let loopback_bytes = std::net::Ipv6Addr::LOCALHOST.octets();
    append_attr_bytes(&mut payload, IFA_LOCAL, &loopback_bytes);
    append_attr_bytes(&mut payload, IFA_ADDRESS, &loopback_bytes);
    payload
}

/// Build the SETLINK payload for bringing the interface up.
pub fn setlink_up_payload() -> Vec<u8> {
    let ifi = IfInfoMsg::new(LOOPBACK_IFINDEX, IFF_UP);
    // SAFETY: `ifi` is a live repr(C) link header, and the byte slice covers exactly its size.
    let ifi_bytes = unsafe {
        std::slice::from_raw_parts(
            &ifi as *const IfInfoMsg as *const u8,
            mem::size_of::<IfInfoMsg>(),
        )
    };
    let mut payload = Vec::new();
    payload.extend_from_slice(ifi_bytes);
    append_attr_u32(&mut payload, IFLA_FLAGS, IFF_UP);
    payload
}

/// Parse the IFA_FLAGS attribute from a payload buffer.
/// Returns the flags value if found, or None.
pub fn parse_ifa_flags(payload: &[u8]) -> Option<u32> {
    let ifa_len = mem::size_of::<IfAddrMsg>();
    if payload.len() < ifa_len {
        return None;
    }

    let mut offset = ifa_len;
    while offset + mem::size_of::<RtAttr>() <= payload.len() {
        // SAFETY: the loop condition guarantees a complete attribute header at `offset`; unaligned access handles byte alignment.
        let attr: RtAttr =
            unsafe { std::ptr::read_unaligned(payload[offset..].as_ptr() as *const RtAttr) };
        if attr.rta_len as usize <= mem::size_of::<RtAttr>() {
            break;
        }
        if attr.rta_type == IFA_FLAGS {
            let data_start = offset + mem::size_of::<RtAttr>();
            let data_end = offset + attr.rta_len as usize;
            if data_end <= payload.len() && data_end - data_start == 4 {
                // SAFETY: the bounds check guarantees four bytes at `data_start`; unaligned access handles byte alignment.
                let flags: u32 = unsafe {
                    std::ptr::read_unaligned(payload[data_start..].as_ptr() as *const u32)
                };
                return Some(u32::from_ne_bytes(flags.to_ne_bytes()));
            }
        }
        // Advance to next attribute (aligned to 4 bytes)
        let next = offset + attr.rta_len as usize;
        let aligned = (next + 3) & !3;
        if aligned <= offset {
            break; // prevent infinite loop
        }
        offset = aligned;
    }
    None
}

/// Parse the ifi_flags from a SETLINK/GETLINK payload.
pub fn parse_ifi_flags(payload: &[u8]) -> Option<u32> {
    if payload.len() < mem::size_of::<IfInfoMsg>() {
        return None;
    }
    // SAFETY: the preceding length check guarantees a complete link message; unaligned access handles byte alignment.
    let ifi: IfInfoMsg = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const IfInfoMsg) };
    Some(ifi.ifi_flags)
}

/// Check if interface flags indicate the interface is up.
pub fn is_interface_up(flags: u32) -> bool {
    flags & IFF_UP != 0
}

/// Parse the prefix length from an ifaddrmsg payload.
pub fn parse_prefix_len(payload: &[u8]) -> Option<u8> {
    if payload.is_empty() {
        return None;
    }
    Some(payload[1]) // ifa_prefixlen is at offset 1
}

/// Parse the scope from an ifaddrmsg payload.
pub fn parse_scope(payload: &[u8]) -> Option<u8> {
    if payload.len() < 4 {
        return None;
    }
    Some(payload[3]) // ifa_scope is at offset 3
}

/// Validate that an ifaddrmsg payload targets the loopback interface.
pub fn targets_loopback(payload: &[u8]) -> bool {
    if payload.len() < mem::size_of::<IfAddrMsg>() {
        return false;
    }
    // SAFETY: the preceding length check guarantees a complete address message; unaligned access handles byte alignment.
    let ifa: IfAddrMsg = unsafe { std::ptr::read_unaligned(payload.as_ptr() as *const IfAddrMsg) };
    ifa.ifa_index == LOOPBACK_IFINDEX
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loopback_ifindex_constant() {
        assert_eq!(LOOPBACK_IFINDEX, 1);
    }

    #[test]
    fn test_timeout_duration() {
        assert_eq!(LOOPBACK_SETUP_TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn test_response_state_new() {
        let state = ResponseState::new();
        assert_eq!(state.pending, 0);
        assert_eq!(state.last_rcode, 0);
        assert!(state.messages().is_empty());
        assert!(state.is_done());
    }

    #[test]
    fn test_response_state_expect_reply() {
        let mut state = ResponseState::new();
        state.expect_reply();
        assert_eq!(state.pending, 1);
        assert!(!state.is_done());

        state.expect_reply();
        assert_eq!(state.pending, 2);

        state.handle_reply(0, "success");
        assert_eq!(state.pending, 1);
        assert_eq!(state.last_rcode, 0);

        state.handle_reply(-17, "EEXIST");
        assert_eq!(state.pending, 0);
        assert_eq!(state.last_rcode, -17);
        assert!(state.is_done());
        assert_eq!(state.messages().len(), 2);
    }

    #[test]
    fn test_response_state_saturating() {
        let mut state = ResponseState::new();
        state.pending = 0;
        state.handle_reply(0, "extra reply");
        assert_eq!(state.pending, 0); // saturating_sub
    }

    #[test]
    fn test_is_eexist() {
        assert!(is_eexist(-(Errno::EEXIST as i32)));
        assert!(is_eexist(-17)); // EEXIST = 17
        assert!(!is_eexist(0));
        assert!(!is_eexist(-1));
        assert!(!is_eexist(-22)); // EINVAL
    }

    #[test]
    fn test_is_success() {
        assert!(is_success(0));
        assert!(!is_success(-1));
        assert!(!is_success(1));
    }

    #[test]
    fn test_is_privilege_error() {
        assert!(is_privilege_error(-(Errno::EPERM as i32)));
        assert!(is_privilege_error(-(Errno::EACCES as i32)));
        assert!(is_privilege_error(-1)); // EPERM
        assert!(is_privilege_error(-13)); // EACCES
        assert!(!is_privilege_error(0));
        assert!(!is_privilege_error(-22)); // EINVAL
    }

    #[test]
    fn test_ipv4_loopback_payload_structure() {
        let payload = ipv4_loopback_payload();
        // Should start with ifaddrmsg (12 bytes)
        assert!(payload.len() >= 12);
        assert_eq!(payload[0], AF_INET as u8); // family
        assert_eq!(payload[1], 8); // prefixlen
        assert_eq!(payload[3], RT_SCOPE_HOST); // scope

        // Should contain IFA_FLAGS with IFA_F_PERMANENT
        let flags = parse_ifa_flags(&payload).unwrap();
        assert_eq!(flags, IFA_F_PERMANENT);
    }

    #[test]
    fn test_ipv6_loopback_payload_structure() {
        let payload = ipv6_loopback_payload();
        assert!(payload.len() >= 12);
        assert_eq!(payload[0], AF_INET6 as u8); // family
        assert_eq!(payload[1], 128); // prefixlen
        assert_eq!(payload[3], RT_SCOPE_HOST); // scope

        // Should contain IFA_FLAGS with IFA_F_PERMANENT | IFA_F_NOPREFIXROUTE
        let flags = parse_ifa_flags(&payload).unwrap();
        assert_eq!(flags, IFA_F_PERMANENT | IFA_F_NOPREFIXROUTE);
    }

    #[test]
    fn test_setlink_up_payload_structure() {
        let payload = setlink_up_payload();
        assert!(payload.len() >= mem::size_of::<IfInfoMsg>());

        let flags = parse_ifi_flags(&payload).unwrap();
        assert!(is_interface_up(flags));
    }

    #[test]
    fn test_parse_ifi_flags_up() {
        let payload = setlink_up_payload();
        let flags = parse_ifi_flags(&payload).unwrap();
        assert_eq!(flags & IFF_UP, IFF_UP);
    }

    #[test]
    fn test_parse_ifi_flags_empty() {
        let flags = parse_ifi_flags(&[]);
        assert!(flags.is_none());
    }

    #[test]
    fn test_parse_ifi_flags_too_short() {
        let flags = parse_ifi_flags(&[0; 4]);
        assert!(flags.is_none());
    }

    #[test]
    fn test_is_interface_up() {
        assert!(is_interface_up(IFF_UP));
        assert!(is_interface_up(IFF_UP | 0x100));
        assert!(!is_interface_up(0));
        assert!(!is_interface_up(0x100));
    }

    #[test]
    fn test_parse_prefix_len_ipv4() {
        let payload = ipv4_loopback_payload();
        assert_eq!(parse_prefix_len(&payload), Some(8));
    }

    #[test]
    fn test_parse_prefix_len_ipv6() {
        let payload = ipv6_loopback_payload();
        assert_eq!(parse_prefix_len(&payload), Some(128));
    }

    #[test]
    fn test_parse_prefix_len_empty() {
        assert_eq!(parse_prefix_len(&[]), None);
    }

    #[test]
    fn test_parse_scope_ipv4() {
        let payload = ipv4_loopback_payload();
        assert_eq!(parse_scope(&payload), Some(RT_SCOPE_HOST));
    }

    #[test]
    fn test_parse_scope_ipv6() {
        let payload = ipv6_loopback_payload();
        assert_eq!(parse_scope(&payload), Some(RT_SCOPE_HOST));
    }

    #[test]
    fn test_parse_scope_empty() {
        assert_eq!(parse_scope(&[]), None);
        assert_eq!(parse_scope(&[0; 3]), None);
    }

    #[test]
    fn test_targets_loopback() {
        let payload = ipv4_loopback_payload();
        assert!(targets_loopback(&payload));

        let payload = ipv6_loopback_payload();
        assert!(targets_loopback(&payload));

        let payload = setlink_up_payload();
        assert!(targets_loopback(&payload));

        assert!(!targets_loopback(&[]));
        assert!(!targets_loopback(&[0; 12]));
    }

    #[test]
    fn test_loopback_setup_error_display() {
        let e = LoopbackSetupError::TimedOut;
        assert_eq!(format!("{e}"), "loopback setup timed out");

        let e = LoopbackSetupError::KernelError(-1);
        assert_eq!(format!("{e}"), "kernel error: 1");

        let e = LoopbackSetupError::InterfaceNotUp;
        assert_eq!(format!("{e}"), "loopback interface is not up");

        let e = LoopbackSetupError::UnexpectedMessage(42);
        assert_eq!(format!("{e}"), "unexpected netlink message type: 42");
    }

    #[test]
    fn test_loopback_setup_error_equality() {
        assert!(matches!(
            LoopbackSetupError::TimedOut,
            LoopbackSetupError::TimedOut
        ));
        assert!(matches!(
            LoopbackSetupError::KernelError(-1),
            LoopbackSetupError::KernelError(_)
        ));
        assert!(matches!(
            LoopbackSetupError::TimedOut,
            LoopbackSetupError::TimedOut
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_loopback_setup_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let lb_err = LoopbackSetupError::from(io_err);
        assert!(matches!(lb_err, LoopbackSetupError::NetlinkSocket(_)));
    }

    #[test]
    fn test_ifinfo_msg_new() {
        let ifi = IfInfoMsg::new(LOOPBACK_IFINDEX, IFF_UP);
        assert_eq!(ifi.ifi_index, 1);
        assert_eq!(ifi.ifi_flags, IFF_UP);
        assert_eq!(ifi.ifi_change, 0xffffffff);
    }

    #[test]
    fn test_ifaddr_msg_new() {
        let ifa = IfAddrMsg::new(AF_INET as u8, 8, RT_SCOPE_HOST, LOOPBACK_IFINDEX);
        assert_eq!(ifa.ifa_family, AF_INET as u8);
        assert_eq!(ifa.ifa_prefixlen, 8);
        assert_eq!(ifa.ifa_scope, RT_SCOPE_HOST);
        assert_eq!(ifa.ifa_index, LOOPBACK_IFINDEX);
    }

    #[test]
    fn test_constants_consistency() {
        // Ensure netlink message type constants are distinct
        let types = [RTM_NEWADDR, RTM_SETLINK, RTM_GETLINK];
        let unique: std::collections::HashSet<_> = types.iter().collect();
        assert_eq!(unique.len(), 3);

        // Ensure IFA_F flags are distinct
        assert_ne!(IFA_F_PERMANENT, IFA_F_NOPREFIXROUTE);
        assert_eq!(IFA_F_PERMANENT & IFA_F_NOPREFIXROUTE, 0);

        // Ensure scope values make sense
        assert_eq!(RT_SCOPE_HOST, 254);
    }
}
