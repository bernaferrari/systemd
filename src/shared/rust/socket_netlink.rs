// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/socket-netlink.c, src/shared/socket-netlink.h
//
// Netlink socket address types, in_addr_full, and netns/UNIX helpers.
//
// Pure data-structure logic and parsing are safe; only raw syscalls
// (socket, bind, sendto, recv, fstat, close) use unsafe blocks.

use crate::ffi::*;
use std::ffi::c_void;
use std::fmt;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;
use std::str::FromStr;

// ── Address family constants ─────────────────────────────────────────

pub const AF_UNSPEC: i32 = 0;
pub const AF_UNIX: i32 = 1;
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;
pub const AF_NETLINK: i32 = 16;
pub const AF_VSOCK: i32 = 40;

// ── Socket type constants ────────────────────────────────────────────

pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const SOCK_RAW: i32 = 3;

// ── Netlink protocol families ────────────────────────────────────────

pub const NETLINK_ROUTE: i32 = 0;
pub const NETLINK_UNUSED: i32 = 1;
pub const NETLINK_USERSOCK: i32 = 2;
pub const NETLINK_FIREWALL: i32 = 3;
pub const NETLINK_SOCK_DIAG: i32 = 4;
pub const NETLINK_NFLOG: i32 = 5;
pub const NETLINK_XFRM: i32 = 6;
pub const NETLINK_SELINUX: i32 = 7;
pub const NETLINK_ISCSI: i32 = 8;
pub const NETLINK_AUDIT: i32 = 9;
pub const NETLINK_FIB_LOOKUP: i32 = 10;
pub const NETLINK_CONNECTOR: i32 = 11;
pub const NETLINK_NETFILTER: i32 = 12;
pub const NETLINK_IP6_FW: i32 = 13;
pub const NETLINK_DNRTMSG: i32 = 14;
pub const NETLINK_KOBJECT_UEVENT: i32 = 15;
pub const NETLINK_GENERIC: i32 = 30;
pub const NETLINK_SCSITRANSPORT: i32 = 18;
pub const NETLINK_ECRYPTFS: i32 = 19;
pub const NETLINK_RDMA: i32 = 20;
pub const NETLINK_CRYPTO: i32 = 21;

// ── RTNetlink message types ──────────────────────────────────────────

pub const RTM_BASE: u16 = 0;
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_SETLINK: u16 = 19;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;
pub const RTM_NEWRULE: u16 = 32;
pub const RTM_DELRULE: u16 = 33;
pub const RTM_GETRULE: u16 = 34;
pub const RTM_NEWQDISC: u16 = 36;
pub const RTM_DELQDISC: u16 = 37;
pub const RTM_GETQDISC: u16 = 38;
pub const RTM_NEWTCLASS: u16 = 40;
pub const RTM_DELTCLASS: u16 = 41;
pub const RTM_GETTCLASS: u16 = 42;
pub const RTM_NEWTFILTER: u16 = 44;
pub const RTM_DELTFILTER: u16 = 45;
pub const RTM_GETTFILTER: u16 = 46;
pub const RTM_NEWACTION: u16 = 48;
pub const RTM_DELACTION: u16 = 49;
pub const RTM_GETACTION: u16 = 50;
pub const RTM_NEWPREFIX: u16 = 52;
pub const RTM_GETMULTICAST: u16 = 58;
pub const RTM_GETANYCAST: u16 = 62;
pub const RTM_NEWNEIGHTBL: u16 = 64;
pub const RTM_GETNEIGHTBL: u16 = 66;
pub const RTM_SETNEIGHTBL: u16 = 67;
pub const RTM_NEWNDUSEROPT: u16 = 68;
pub const RTM_NEWADDRLABEL: u16 = 72;
pub const RTM_DELADDRLABEL: u16 = 73;
pub const RTM_GETADDRLABEL: u16 = 74;
pub const RTM_NEWNEXTHOP: u16 = 84;
pub const RTM_DELNEXTHOP: u16 = 85;
pub const RTM_GETNEXTHOP: u16 = 86;

// ── Netlink message types ────────────────────────────────────────────

pub const NLMSG_NOOP: u16 = 0x1;
pub const NLMSG_ERROR: u16 = 0x2;
pub const NLMSG_DONE: u16 = 0x3;
pub const NLMSG_OVERRUN: u16 = 0x4;

// ── Netlink message flags ────────────────────────────────────────────

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_MULTI: u16 = 0x02;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_DUMP: u16 = 0x0300;
pub const NLM_F_REPLACE: u16 = 0x100;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_APPEND: u16 = 0x800;

// ── Netlink socket address header size ───────────────────────────────

pub const SIZEOF_SOCKADDR_NL: usize = mem::size_of::<crate::ffi::sockaddr_nl>();

// ── Netns constants ──────────────────────────────────────────────────

/// Indicates no NSID has been assigned yet.
pub const NETNSA_NSID_NOT_ASSIGNED: u32 = 0xffffffff;

/// RTM type for network namespace ID queries.
pub const RTM_GETNSID: u16 = 90;

// ── Errors ───────────────────────────────────────────────────────────

/// Error type for socket netlink operations.
#[derive(Debug)]
pub enum SocketNetlinkError {
    /// Address string could not be parsed.
    InvalidAddress(String),
    /// Address family not supported.
    InvalidFamily(i32),
    /// Port number is out of range or zero.
    InvalidPort,
    /// A port is required but was not specified.
    MissingPort,
    /// Netlink family name not recognized.
    UnknownNetlinkFamily(String),
    /// Generic parse error.
    ParseError(String),
    /// A network namespace or interface operation failed.
    NetlinkFailed(i32),
    /// File descriptor is not a socket.
    NotASocket,
    /// No data available from the requested operation.
    NoData,
    /// No such device (interface not found).
    NoSuchDevice,
    /// Underlying I/O error from a syscall.
    Io(io::Error),
}

impl fmt::Display for SocketNetlinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress(s) => write!(f, "invalid socket address: {s}"),
            Self::InvalidFamily(fam) => write!(f, "invalid address family: {fam}"),
            Self::InvalidPort => write!(f, "invalid port number"),
            Self::MissingPort => write!(f, "port number is zero"),
            Self::UnknownNetlinkFamily(s) => write!(f, "unknown netlink family: {s}"),
            Self::ParseError(s) => write!(f, "parse error: {s}"),
            Self::NetlinkFailed(code) => write!(f, "netlink operation failed: {}", -code),
            Self::NotASocket => write!(f, "file descriptor is not a socket"),
            Self::NoData => write!(f, "no data available"),
            Self::NoSuchDevice => write!(f, "no such device"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for SocketNetlinkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for SocketNetlinkError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Convenient type alias for results in this module.
pub type Result<T> = std::result::Result<T, SocketNetlinkError>;

// ── IP address union ────────────────────────────────────────────────

/// Union-style enum representing either an IPv4 or IPv6 address.
///
/// Mirrors the C `union in_addr_union` from `in-addr-util.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InAddrUnion {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl InAddrUnion {
    /// Returns the address family (AF_INET or AF_INET6).
    pub fn family(&self) -> i32 {
        match self {
            Self::V4(_) => AF_INET,
            Self::V6(_) => AF_INET6,
        }
    }

    /// Returns the IPv4 address, if this is a V4 variant.
    pub fn as_v4(&self) -> Option<Ipv4Addr> {
        match self {
            Self::V4(a) => Some(*a),
            _ => None,
        }
    }

    /// Returns the IPv6 address, if this is a V6 variant.
    pub fn as_v6(&self) -> Option<Ipv6Addr> {
        match self {
            Self::V6(a) => Some(*a),
            _ => None,
        }
    }

    /// Returns true if this is the unspecified (all-zeros) address.
    pub fn is_unspecified(&self) -> bool {
        match self {
            Self::V4(a) => a.is_unspecified(),
            Self::V6(a) => a.is_unspecified(),
        }
    }

    /// Returns true if this is a loopback address.
    pub fn is_loopback(&self) -> bool {
        match self {
            Self::V4(a) => a.is_loopback(),
            Self::V6(a) => a.is_loopback(),
        }
    }

    /// Parse from a string, auto-detecting IPv4 vs IPv6.
    pub fn from_str_auto(s: &str) -> Result<Self> {
        if let Ok(v4) = Ipv4Addr::from_str(s) {
            Ok(Self::V4(v4))
        } else if let Ok(v6) = Ipv6Addr::from_str(s) {
            Ok(Self::V6(v6))
        } else {
            Err(SocketNetlinkError::InvalidAddress(format!(
                "cannot parse address '{s}'"
            )))
        }
    }

    /// Parse from a string with a specific address family.
    pub fn from_str_with_family(s: &str, family: i32) -> Result<Self> {
        match family {
            AF_INET => {
                let addr = Ipv4Addr::from_str(s)
                    .map_err(|e| SocketNetlinkError::InvalidAddress(e.to_string()))?;
                Ok(Self::V4(addr))
            }
            AF_INET6 => {
                let addr = Ipv6Addr::from_str(s)
                    .map_err(|e| SocketNetlinkError::InvalidAddress(e.to_string()))?;
                Ok(Self::V6(addr))
            }
            _ => Err(SocketNetlinkError::InvalidFamily(family)),
        }
    }
}

impl Default for InAddrUnion {
    fn default() -> Self {
        Self::V4(Ipv4Addr::UNSPECIFIED)
    }
}

impl fmt::Display for InAddrUnion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(a) => write!(f, "{a}"),
            Self::V6(a) => write!(f, "{a}"),
        }
    }
}

// ── in_addr_full ─────────────────────────────────────────────────────

/// Full internet address with port, interface index, and optional server name.
///
/// Mirrors C `struct in_addr_full` from `socket-netlink.h`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InAddrFull {
    /// Address family (AF_INET or AF_INET6).
    pub family: i32,
    /// IP address.
    pub address: InAddrUnion,
    /// Port number in host byte order.
    pub port: u16,
    /// Interface index for scoped IPv6.
    pub ifindex: i32,
    /// Optional server name for DNS resolution.
    pub server_name: Option<String>,
}

impl InAddrFull {
    /// Create a new InAddrFull, validating family/address consistency.
    pub fn new(
        family: i32,
        address: InAddrUnion,
        port: u16,
        ifindex: i32,
        server_name: Option<String>,
    ) -> Result<Self> {
        if family != AF_INET && family != AF_INET6 {
            return Err(SocketNetlinkError::InvalidFamily(family));
        }
        if family != address.family() {
            return Err(SocketNetlinkError::InvalidFamily(family));
        }
        Ok(Self {
            family,
            address,
            port,
            ifindex,
            server_name: server_name.filter(|s| !s.is_empty()),
        })
    }

    /// Create a new InAddrFull from a parsed string.
    ///
    /// Accepts formats like:
    /// - `192.168.0.1:53`
    /// - `[2001:db8::1]:53%eth0#example.com`
    pub fn from_string(s: &str) -> Result<Self> {
        let parsed = parse_in_addr_port_ifindex_name(s)?;
        Self::new(
            parsed.family,
            parsed.address,
            parsed.port,
            parsed.ifindex,
            parsed.server_name,
        )
    }

    /// Format as a human-readable string.
    ///
    /// E.g. `192.168.0.1:53`, `[::1]:443%2#example.com`
    pub fn to_string_repr(&self) -> String {
        let addr = match &self.address {
            InAddrUnion::V4(a) => a.to_string(),
            InAddrUnion::V6(a) => format!("[{a}]"),
        };
        let mut s = addr;
        if self.port != 0 {
            s.push(':');
            s.push_str(&self.port.to_string());
        }
        if self.ifindex != 0 {
            s.push('%');
            s.push_str(&self.ifindex.to_string());
        }
        if let Some(ref name) = self.server_name {
            s.push('#');
            s.push_str(name);
        }
        s
    }
}

// ── Parsed address result ───────────────────────────────────────────

/// Intermediate result from parsing an address string with all components.
struct ParsedAddr {
    family: i32,
    address: InAddrUnion,
    port: u16,
    ifindex: i32,
    server_name: Option<String>,
}

// ── Socket address ──────────────────────────────────────────────────

/// Represents a parsed socket address.
///
/// Mirrors the C `SocketAddress` union type used throughout systemd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketAddress {
    /// IPv4 or IPv6 inet address with port and optional scope.
    Inet {
        family: i32,
        address: InAddrUnion,
        port: u16,
        ifindex: i32,
    },
    /// Unix domain socket path.
    Unix { path: String },
    /// Netlink socket with multicast groups and protocol.
    Netlink { groups: u32, protocol: i32 },
    /// VM socket (AF_VSOCK).
    Vsock { cid: u32, port: u32 },
}

impl SocketAddress {
    /// Returns the address family constant.
    pub fn family(&self) -> i32 {
        match self {
            Self::Inet { family, .. } => *family,
            Self::Unix { .. } => AF_UNIX,
            Self::Netlink { .. } => AF_NETLINK,
            Self::Vsock { .. } => AF_VSOCK,
        }
    }

    /// Returns the default socket type for this address family.
    pub fn sock_type(&self) -> i32 {
        match self {
            Self::Inet { .. } => SOCK_STREAM,
            Self::Unix { .. } => SOCK_STREAM,
            Self::Netlink { .. } => SOCK_RAW,
            Self::Vsock { .. } => SOCK_STREAM,
        }
    }
}

impl fmt::Display for SocketAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inet {
                address,
                port,
                ifindex,
                ..
            } => {
                match address {
                    InAddrUnion::V4(a) => write!(f, "{a}")?,
                    InAddrUnion::V6(a) => write!(f, "[{a}]")?,
                }
                if *port != 0 {
                    write!(f, ":{port}")?;
                }
                if *ifindex != 0 {
                    write!(f, "%{ifindex}")?;
                }
                Ok(())
            }
            Self::Unix { path } => write!(f, "{path}"),
            Self::Netlink { groups, protocol } => {
                if let Some(name) = netlink_family_to_string(*protocol) {
                    write!(f, "{name}")?;
                } else {
                    write!(f, "netlink:{protocol}")?;
                }
                if *groups != 0 {
                    write!(f, ":{groups}")?;
                }
                Ok(())
            }
            Self::Vsock { cid, port } => write!(f, "vsock:{cid}:{port}"),
        }
    }
}

// ── Netlink message header ───────────────────────────────────────────

/// Represents a netlink message header (struct nlmsghdr).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct NlMsgHdr {
    /// Total length of message including header.
    pub len: u32,
    /// Message type.
    pub type_: u16,
    /// Message flags.
    pub flags: u16,
    /// Sequence number.
    pub seq: u32,
    /// Sending process port ID.
    pub pid: u32,
}

impl NlMsgHdr {
    /// Create a new netlink message header.
    pub fn new(type_: u16, flags: u16, seq: u32, pid: u32, payload_len: u32) -> Self {
        Self {
            len: mem::size_of::<Self>() as u32 + payload_len,
            type_,
            flags,
            seq,
            pid,
        }
    }

    /// Size of the header in bytes.
    pub const fn header_size() -> usize {
        mem::size_of::<Self>()
    }

    /// Convert header to bytes (little-endian, matching kernel ABI).
    pub fn to_bytes(&self) -> [u8; 16] {
        self.len
            .to_le_bytes()
            .iter()
            .chain(self.type_.to_le_bytes().iter())
            .chain(self.flags.to_le_bytes().iter())
            .chain(self.seq.to_le_bytes().iter())
            .chain(self.pid.to_le_bytes().iter())
            .copied()
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap()
    }

    /// Parse a header from a byte slice.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        Some(Self {
            len: u32::from_le_bytes(data[0..4].try_into().ok()?),
            type_: u16::from_le_bytes(data[4..6].try_into().ok()?),
            flags: u16::from_le_bytes(data[6..8].try_into().ok()?),
            seq: u32::from_le_bytes(data[8..12].try_into().ok()?),
            pid: u32::from_le_bytes(data[12..16].try_into().ok()?),
        })
    }
}

impl Default for NlMsgHdr {
    fn default() -> Self {
        Self {
            len: mem::size_of::<Self>() as u32,
            type_: 0,
            flags: 0,
            seq: 0,
            pid: 0,
        }
    }
}

// ── Netlink socket address ───────────────────────────────────────────

/// Safe wrapper around a netlink socket address (struct sockaddr_nl).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockAddrNl {
    /// Address family (always AF_NETLINK).
    pub nl_family: u16,
    /// Padding (always 0).
    pub nl_pad: u16,
    /// Port ID (typically 0 for kernel-bound, or process PID).
    pub nl_pid: u32,
    /// Multicast groups mask.
    pub nl_groups: u32,
}

impl SockAddrNl {
    /// Create a new netlink socket address.
    pub fn new(pid: u32, groups: u32) -> Self {
        Self {
            nl_family: AF_NETLINK as u16,
            nl_pad: 0,
            nl_pid: pid,
            nl_groups: groups,
        }
    }

    /// Convert to the libc sockaddr_nl for use in syscalls.
    pub fn as_sockaddr(&self) -> crate::ffi::sockaddr_nl {
        crate::ffi::sockaddr_nl {
            nl_family: self.nl_family as i32,
            nl_pad: 0,
            nl_pid: self.nl_pid,
            nl_groups: self.nl_groups,
        }
    }

    /// Parse from a libc sockaddr_nl.
    pub fn from_sockaddr(sa: &crate::ffi::sockaddr_nl) -> Self {
        Self {
            nl_family: sa.nl_family as u16,
            nl_pad: 0,
            nl_pid: sa.nl_pid,
            nl_groups: sa.nl_groups,
        }
    }
}

impl Default for SockAddrNl {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// ── Netlink family name <-> int ──────────────────────────────────────

/// Convert a netlink family name string to its protocol number.
///
/// Recognizes names like "route", "selinux", "audit", "kobject-uevent",
/// "uevent", "generic", "netlink-generic", "sock-diag", "sock_diag".
pub fn netlink_family_from_string(s: &str) -> Result<i32> {
    match s {
        "route" => Ok(NETLINK_ROUTE),
        "selinux" => Ok(NETLINK_SELINUX),
        "audit" => Ok(NETLINK_AUDIT),
        "kobject-uevent" | "uevent" => Ok(NETLINK_KOBJECT_UEVENT),
        "generic" | "netlink-generic" => Ok(NETLINK_GENERIC),
        "sock-diag" | "sock_diag" => Ok(NETLINK_SOCK_DIAG),
        "firewall" => Ok(NETLINK_FIREWALL),
        "nflog" => Ok(NETLINK_NFLOG),
        "xfrm" => Ok(NETLINK_XFRM),
        "iscsi" => Ok(NETLINK_ISCSI),
        "fib_lookup" => Ok(NETLINK_FIB_LOOKUP),
        "connector" => Ok(NETLINK_CONNECTOR),
        "netfilter" => Ok(NETLINK_NETFILTER),
        "rdma" => Ok(NETLINK_RDMA),
        "crypto" => Ok(NETLINK_CRYPTO),
        _ => Err(SocketNetlinkError::UnknownNetlinkFamily(s.to_owned())),
    }
}

/// Convert a netlink protocol number to its canonical name string.
pub fn netlink_family_to_string(family: i32) -> Option<&'static str> {
    match family {
        NETLINK_ROUTE => Some("route"),
        NETLINK_SELINUX => Some("selinux"),
        NETLINK_AUDIT => Some("audit"),
        NETLINK_KOBJECT_UEVENT => Some("kobject-uevent"),
        NETLINK_GENERIC => Some("generic"),
        NETLINK_SOCK_DIAG => Some("sock-diag"),
        NETLINK_FIREWALL => Some("firewall"),
        NETLINK_NFLOG => Some("nflog"),
        NETLINK_XFRM => Some("xfrm"),
        NETLINK_ISCSI => Some("iscsi"),
        NETLINK_FIB_LOOKUP => Some("fib_lookup"),
        NETLINK_CONNECTOR => Some("connector"),
        NETLINK_NETFILTER => Some("netfilter"),
        NETLINK_RDMA => Some("rdma"),
        NETLINK_CRYPTO => Some("crypto"),
        _ => None,
    }
}

// ── Port parsing ─────────────────────────────────────────────────────

/// Parse a port number from a string.
///
/// Returns an error for values outside 1..=65535.
pub fn parse_ip_port(s: &str) -> Result<u16> {
    let port: u32 = s.parse().map_err(|_| SocketNetlinkError::InvalidPort)?;
    if port == 0 || port > 65535 {
        return Err(SocketNetlinkError::InvalidPort);
    }
    Ok(port as u16)
}

// ── Socket address parsing ───────────────────────────────────────────

/// Parse an IPv4 or IPv6 address with optional port from a string.
///
/// Accepts:
/// - `192.168.0.1:53` (IPv4 with port)
/// - `[2001:db8::1]:53` (IPv6 bracketed with port)
/// - `192.168.0.1` (IPv4 bare)
/// - `::1` (IPv6 bare)
fn parse_inet_address(s: &str) -> Result<(InAddrUnion, u16, i32)> {
    if let Some(rest) = s.strip_prefix('[') {
        // IPv6 bracketed form: [addr]:port
        let closing = rest
            .find(']')
            .ok_or_else(|| SocketNetlinkError::InvalidAddress("missing ']'".into()))?;
        let ip_str = &rest[..closing];
        let addr: Ipv6Addr = Ipv6Addr::from_str(ip_str)
            .map_err(|e| SocketNetlinkError::InvalidAddress(e.to_string()))?;
        let rest = &rest[closing + 1..];
        let port = if let Some(p) = rest.strip_prefix(':') {
            parse_ip_port(p)?
        } else {
            0
        };
        Ok((InAddrUnion::V6(addr), port, AF_INET6))
    } else if let Some(colon_pos) = s.rfind(':') {
        // Could be IPv4:port or bare IPv6
        let ip_str = &s[..colon_pos];
        let port_str = &s[colon_pos + 1..];
        if let Ok(addr) = Ipv4Addr::from_str(ip_str) {
            let port = parse_ip_port(port_str)?;
            Ok((InAddrUnion::V4(addr), port, AF_INET))
        } else if let Ok(addr) = Ipv6Addr::from_str(s) {
            // Bare IPv6 address (colons are part of the address)
            Ok((InAddrUnion::V6(addr), 0, AF_INET6))
        } else {
            Err(SocketNetlinkError::InvalidAddress(
                "cannot parse IPv4 or IPv6 address".into(),
            ))
        }
    } else if let Ok(addr) = Ipv4Addr::from_str(s) {
        Ok((InAddrUnion::V4(addr), 0, AF_INET))
    } else if let Ok(addr) = Ipv6Addr::from_str(s) {
        Ok((InAddrUnion::V6(addr), 0, AF_INET6))
    } else {
        Err(SocketNetlinkError::InvalidAddress(format!(
            "cannot parse address '{s}'"
        )))
    }
}

/// Parse a complex address string with optional port, ifindex, and server name.
///
/// Accepts formats:
/// - `192.168.0.1:53`
/// - `192.168.0.1:53#example.com`
/// - `[2001:db8::1]:53%eth0#example.com`
/// - `::1:443`
///
/// Mirrors C `in_addr_port_ifindex_name_from_string_auto()`.
fn parse_in_addr_port_ifindex_name(s: &str) -> Result<ParsedAddr> {
    let mut s = s;
    let mut server_name = None;
    let mut ifindex: i32 = 0;

    // Extract server name after '#'
    if let Some(pos) = s.find('#') {
        if pos + 1 >= s.len() {
            return Err(SocketNetlinkError::InvalidAddress(
                "empty server name after '#'".into(),
            ));
        }
        server_name = Some(s[pos + 1..].to_owned());
        s = &s[..pos];
    }

    // Extract interface after '%'
    if let Some(pos) = s.find('%') {
        if pos + 1 >= s.len() {
            return Err(SocketNetlinkError::InvalidAddress(
                "empty interface name after '%'".into(),
            ));
        }
        let iface = &s[pos + 1..];
        // Try to parse as numeric ifindex
        ifindex = iface.parse::<i32>().map_err(|_| {
            SocketNetlinkError::InvalidAddress(format!("invalid interface '{iface}'"))
        })?;
        s = &s[..pos];
    }

    // Parse address and port
    let (address, port, family) = parse_inet_address(s)?;

    if port == 0 {
        return Err(SocketNetlinkError::MissingPort);
    }

    Ok(ParsedAddr {
        family,
        address,
        port,
        ifindex,
        server_name,
    })
}

/// Parse a socket address from a string.
///
/// Tries to parse as:
/// 1. IPv4 address (with optional port)
/// 2. IPv6 address (with optional port, bracketed)
/// 3. Bare port number (defaults to INADDR_ANY)
///
/// Mirrors C `socket_address_parse()`.
pub fn socket_address_parse(s: &str) -> Result<SocketAddress> {
    // Try as inet address
    if let Ok((address, port, family)) = parse_inet_address(s) {
        return Ok(SocketAddress::Inet {
            family,
            address,
            port,
            ifindex: 0,
        });
    }

    // Try as bare port number
    if let Ok(port) = parse_ip_port(s) {
        // Use IPv6 if supported, otherwise IPv4
        // For portability, default to IPv4
        return Ok(SocketAddress::Inet {
            family: AF_INET,
            address: InAddrUnion::V4(Ipv4Addr::UNSPECIFIED),
            port,
            ifindex: 0,
        });
    }

    Err(SocketNetlinkError::InvalidAddress(format!(
        "cannot parse socket address '{s}'"
    )))
}

/// Parse a netlink socket address from the format "family [group]".
///
/// E.g. `route 42` -> Netlink { groups: 42, protocol: NETLINK_ROUTE }
///
/// Mirrors C `socket_address_parse_netlink()`.
pub fn socket_address_parse_netlink(s: &str) -> Result<SocketAddress> {
    let mut parts = s.splitn(2, |c: char| c.is_whitespace());
    let family_str = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| SocketNetlinkError::InvalidAddress("empty netlink address".into()))?;
    let protocol = netlink_family_from_string(family_str)?;
    let groups = parts
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>())
        .transpose()
        .map_err(|_| SocketNetlinkError::InvalidAddress("invalid group number".into()))?
        .unwrap_or(0);

    Ok(SocketAddress::Netlink { groups, protocol })
}

/// Check if a socket address matches the given string representation.
///
/// Parses `s` as a socket address and compares it to `a`.
pub fn socket_address_equal_str(a: &SocketAddress, s: &str) -> bool {
    socket_address_parse(s).map_or(false, |b| a == &b)
}

/// Check if a netlink socket address matches the given string representation.
///
/// Parses `s` as a netlink address and compares it to `a`.
pub fn socket_address_equal_netlink_str(a: &SocketAddress, s: &str) -> bool {
    socket_address_parse_netlink(s).map_or(false, |b| a == &b)
}

// ── Netlink socket helpers (minimal unsafe) ──────────────────────────

/// Read the current errno value.
fn last_errno() -> i32 {
    crate::ffi::get_errno()
}

/// Create a netlink socket with the given protocol.
///
/// The returned file descriptor is bound to the specified address.
/// Uses unsafe only for the socket() and bind() syscalls.
pub fn netlink_open(protocol: i32, pid: u32, groups: u32) -> Result<RawFd> {
    let fd = unsafe { libc::socket(AF_NETLINK, SOCK_RAW, protocol) };
    if fd < 0 {
        return Err(SocketNetlinkError::Io(io::Error::from_raw_os_error(
            last_errno(),
        )));
    }

    let addr = SockAddrNl::new(pid, groups);
    if let Err(e) = netlink_bind(fd, &addr) {
        unsafe {
            libc::close(fd);
        }
        return Err(e);
    }

    Ok(fd)
}

/// Create an unbound netlink socket with the given protocol.
pub fn netlink_socket(protocol: i32) -> Result<RawFd> {
    let fd = unsafe { libc::socket(AF_NETLINK, SOCK_RAW, protocol) };
    if fd < 0 {
        return Err(SocketNetlinkError::Io(io::Error::from_raw_os_error(
            last_errno(),
        )));
    }
    Ok(fd)
}

/// Bind a netlink socket to the given address.
pub fn netlink_bind(fd: RawFd, addr: &SockAddrNl) -> Result<()> {
    let sa = addr.as_sockaddr();
    let sa_len = mem::size_of::<crate::ffi::sockaddr_nl>() as libc::socklen_t;
    let ret = unsafe {
        libc::bind(
            fd,
            &sa as *const crate::ffi::sockaddr_nl as *const libc::sockaddr,
            sa_len,
        )
    };
    if ret < 0 {
        return Err(SocketNetlinkError::Io(io::Error::from_raw_os_error(
            last_errno(),
        )));
    }
    Ok(())
}

/// Send a raw buffer on a netlink socket to the kernel.
pub fn netlink_send(fd: RawFd, buf: &[u8], addr: &SockAddrNl) -> Result<usize> {
    let sa = addr.as_sockaddr();
    let sa_len = mem::size_of::<crate::ffi::sockaddr_nl>() as libc::socklen_t;
    let ret = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const c_void,
            buf.len(),
            0,
            &sa as *const crate::ffi::sockaddr_nl as *const libc::sockaddr,
            sa_len,
        )
    };
    if ret < 0 {
        return Err(SocketNetlinkError::Io(io::Error::from_raw_os_error(
            last_errno(),
        )));
    }
    Ok(ret as usize)
}

/// Receive data from a netlink socket.
pub fn netlink_recv(fd: RawFd, buf: &mut [u8]) -> Result<usize> {
    let ret = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
    if ret < 0 {
        return Err(SocketNetlinkError::Io(io::Error::from_raw_os_error(
            last_errno(),
        )));
    }
    Ok(ret as usize)
}

/// Close a file descriptor safely (ignores invalid fds).
pub fn safe_close_fd(fd: RawFd) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

/// Check if a file descriptor refers to a socket via fstat.
pub fn fd_is_socket(fd: RawFd) -> Result<bool> {
    let mut stat_buf: libc::stat = unsafe { mem::zeroed() };
    let ret = unsafe { libc::fstat(fd, &mut stat_buf) };
    if ret < 0 {
        return Err(SocketNetlinkError::Io(io::Error::from_raw_os_error(
            last_errno(),
        )));
    }
    Ok((stat_buf.st_mode & libc::S_IFMT) == libc::S_IFSOCK)
}

// ── Netlink message building ─────────────────────────────────────────

/// Align a length up to NLMSG_ALIGNTO (4 bytes).
const fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Minimum netlink message size (just the header).
const fn nlmsg_hdr_len() -> usize {
    16
}

/// Build a simple netlink request message with a single u32 attribute.
///
/// This is sufficient for operations like RTM_GETNSID which need one attribute.
pub fn netlink_build_simple_request(
    msg_type: u16,
    flags: u16,
    seq: u32,
    attr_type: u16,
    attr_value: u32,
) -> Vec<u8> {
    // Attribute: 4-byte header (nla_len, nla_type) + 4-byte value
    let attr_len = 4 + 4; // nla_len(2) + nla_type(2) + value(4)
    let total_len = nlmsg_hdr_len() + attr_len;

    let mut buf = Vec::with_capacity(total_len);

    // nlmsghdr
    let hdr = NlMsgHdr::new(msg_type, flags, seq, 0, attr_len as u32);
    buf.extend_from_slice(&hdr.to_bytes());

    // nlattr (netlink attribute header)
    let nla_len = attr_len as u16;
    let nla_type = attr_type;
    buf.extend_from_slice(&nla_len.to_le_bytes());
    buf.extend_from_slice(&nla_type.to_le_bytes());

    // Attribute value
    buf.extend_from_slice(&attr_value.to_le_bytes());

    buf
}

// ── Network namespace helpers ────────────────────────────────────────

/// Get the network namespace ID for a given network namespace file descriptor.
///
/// Uses raw netlink socket operations (RTM_GETNSID) to query the kernel.
/// If `netnsfd` is negative, opens the current process's network namespace.
///
/// Mirrors C `netns_get_nsid()`.
pub fn netns_get_nsid(netnsfd: RawFd) -> Result<u32> {
    let fd = netlink_socket(NETLINK_ROUTE)?;
    let _guard = CloseGuard(fd);

    let req = netlink_build_simple_request(
        RTM_GETNSID,
        NLM_F_REQUEST | NLM_F_ACK,
        1,
        1, // NETNSA_FD
        netnsfd as u32,
    );

    let kernel_addr = SockAddrNl::new(0, 0);
    netlink_send(fd, &req, &kernel_addr)?;

    let mut reply_buf = vec![0u8; 4096];
    let n = netlink_recv(fd, &mut reply_buf)?;

    // Parse the reply looking for RTM_NEWNSID with NETNSA_NSID
    let mut offset = 0;
    while offset < n {
        if offset + 16 > n {
            break;
        }
        let hdr = match NlMsgHdr::from_bytes(&reply_buf[offset..]) {
            Some(h) => h,
            None => break,
        };

        if hdr.type_ == NLMSG_ERROR {
            // Check if it's an ACK or error
            if offset + 16 + 4 > n {
                break;
            }
            let error_code =
                i32::from_le_bytes(reply_buf[offset + 16..offset + 20].try_into().unwrap());
            if error_code < 0 {
                return Err(SocketNetlinkError::NetlinkFailed(error_code));
            }
            // ACK - continue parsing
        }

        if hdr.type_ == NLMSG_DONE {
            break;
        }

        // Skip the header and look for attributes
        let attr_offset = offset + 16;
        let msg_end = offset + hdr.len as usize;

        if hdr.type_ == RTM_GETNSID + 1 {
            // RTM_NEWNSID
            let mut aoff = attr_offset;
            while aoff + 4 <= msg_end && aoff + 4 <= n {
                let nla_len =
                    u16::from_le_bytes(reply_buf[aoff..aoff + 2].try_into().unwrap()) as usize;
                let nla_type =
                    u16::from_le_bytes(reply_buf[aoff + 2..aoff + 4].try_into().unwrap());

                if nla_len < 4 {
                    break;
                }

                if nla_type == 2 && aoff + 4 + 4 <= msg_end && aoff + 4 + 4 <= n {
                    // NETNSA_NSID = 2
                    let nsid =
                        u32::from_le_bytes(reply_buf[aoff + 4..aoff + 8].try_into().unwrap());
                    if nsid == NETNSA_NSID_NOT_ASSIGNED {
                        return Err(SocketNetlinkError::NoData);
                    }
                    return Ok(nsid);
                }

                aoff += nlmsg_align(nla_len);
            }
        }

        let step = nlmsg_align(hdr.len as usize);
        if step == 0 {
            break;
        }
        offset += step;
    }

    Err(SocketNetlinkError::NoData)
}

// ── RAII guard for file descriptors ──────────────────────────────────

/// RAII guard that closes a file descriptor on drop.
struct CloseGuard(RawFd);

impl Drop for CloseGuard {
    fn drop(&mut self) {
        safe_close_fd(self.0);
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_address_family_constants() {
        assert_eq!(AF_INET, 2);
        assert_eq!(AF_INET6, 10);
        assert_eq!(AF_NETLINK, 16);
        assert_eq!(AF_UNIX, 1);
        assert_eq!(AF_VSOCK, 40);
        assert!(AF_INET < AF_INET6);
        assert!(AF_INET6 < AF_NETLINK);
    }

    #[test]
    fn test_socket_type_constants() {
        assert_eq!(SOCK_STREAM, 1);
        assert_eq!(SOCK_DGRAM, 2);
        assert_eq!(SOCK_RAW, 3);
    }

    #[test]
    fn test_netlink_protocol_constants() {
        assert_eq!(NETLINK_ROUTE, 0);
        assert_eq!(NETLINK_SOCK_DIAG, 4);
        assert_eq!(NETLINK_AUDIT, 9);
        assert_eq!(NETLINK_KOBJECT_UEVENT, 15);
        assert_eq!(NETLINK_GENERIC, 30);
        assert!(NETLINK_ROUTE < NETLINK_AUDIT);
        assert!(NETLINK_AUDIT < NETLINK_KOBJECT_UEVENT);
        assert!(NETLINK_KOBJECT_UEVENT < NETLINK_GENERIC);
    }

    #[test]
    fn test_rtnetlink_message_types() {
        assert_eq!(RTM_NEWLINK, 16);
        assert_eq!(RTM_GETLINK, 18);
        assert_eq!(RTM_NEWADDR, 20);
        assert_eq!(RTM_GETADDR, 22);
        assert_eq!(RTM_NEWROUTE, 24);
        assert_eq!(RTM_GETROUTE, 26);
        assert_eq!(RTM_GETNSID, 90);
    }

    #[test]
    fn test_netlink_message_constants() {
        assert_eq!(NLMSG_NOOP, 0x1);
        assert_eq!(NLMSG_ERROR, 0x2);
        assert_eq!(NLMSG_DONE, 0x3);
        assert_eq!(NLMSG_OVERRUN, 0x4);
        assert_eq!(NLM_F_REQUEST, 0x01);
        assert_eq!(NLM_F_MULTI, 0x02);
        assert_eq!(NLM_F_ACK, 0x04);
        assert_eq!(NLM_F_DUMP, 0x0300);
    }

    #[test]
    fn test_in_addr_union_v4() {
        let addr = InAddrUnion::V4(Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(addr.family(), AF_INET);
        assert_eq!(addr.as_v4(), Some(Ipv4Addr::new(192, 168, 0, 1)));
        assert_eq!(addr.as_v6(), None);
        assert!(!addr.is_unspecified());
        assert!(!addr.is_loopback());
    }

    #[test]
    fn test_in_addr_union_v6() {
        let addr = InAddrUnion::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(addr.family(), AF_INET6);
        assert_eq!(addr.as_v6(), Some(Ipv6Addr::LOCALHOST));
        assert_eq!(addr.as_v4(), None);
        assert!(!addr.is_unspecified());
        assert!(addr.is_loopback());
    }

    #[test]
    fn test_in_addr_union_default_unspecified() {
        let addr = InAddrUnion::default();
        assert!(addr.is_unspecified());
        assert_eq!(addr.family(), AF_INET);
    }

    #[test]
    fn test_in_addr_union_from_str_auto() {
        let v4 = InAddrUnion::from_str_auto("127.0.0.1").unwrap();
        assert_eq!(v4.family(), AF_INET);
        let v6 = InAddrUnion::from_str_auto("::1").unwrap();
        assert_eq!(v6.family(), AF_INET6);
        assert!(InAddrUnion::from_str_auto("not-valid").is_err());
    }

    #[test]
    fn test_in_addr_union_display() {
        assert_eq!(
            InAddrUnion::V4(Ipv4Addr::new(10, 0, 0, 1)).to_string(),
            "10.0.0.1"
        );
        assert_eq!(InAddrUnion::V6(Ipv6Addr::LOCALHOST).to_string(), "::1");
    }

    #[test]
    fn test_in_addr_full_new_valid() {
        let full = InAddrFull::new(
            AF_INET,
            InAddrUnion::V4(Ipv4Addr::new(127, 0, 0, 1)),
            80,
            0,
            Some("example.com".into()),
        )
        .unwrap();
        assert_eq!(full.family, AF_INET);
        assert_eq!(full.port, 80);
        assert_eq!(full.ifindex, 0);
        assert_eq!(full.server_name.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_in_addr_full_new_family_mismatch() {
        let result = InAddrFull::new(AF_INET6, InAddrUnion::V4(Ipv4Addr::LOCALHOST), 80, 0, None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SocketNetlinkError::InvalidFamily(AF_INET6)
        ));
    }

    #[test]
    fn test_in_addr_full_new_invalid_family() {
        let result = InAddrFull::new(AF_UNIX, InAddrUnion::V4(Ipv4Addr::LOCALHOST), 80, 0, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_in_addr_full_new_filters_empty_name() {
        let full = InAddrFull::new(
            AF_INET,
            InAddrUnion::V4(Ipv4Addr::LOCALHOST),
            80,
            0,
            Some("".into()),
        )
        .unwrap();
        assert!(full.server_name.is_none());
    }

    #[test]
    fn test_in_addr_full_to_string_simple() {
        let full = InAddrFull::new(
            AF_INET,
            InAddrUnion::V4(Ipv4Addr::new(10, 0, 0, 1)),
            53,
            0,
            None,
        )
        .unwrap();
        assert_eq!(full.to_string_repr(), "10.0.0.1:53");
    }

    #[test]
    fn test_in_addr_full_to_string_v6_with_all() {
        let full = InAddrFull::new(
            AF_INET6,
            InAddrUnion::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            443,
            2,
            Some("web.example.com".into()),
        )
        .unwrap();
        let s = full.to_string_repr();
        assert!(s.starts_with("[2001:db8::1]:443"));
        assert!(s.contains("%2"));
        assert!(s.contains("#web.example.com"));
    }

    #[test]
    fn test_in_addr_full_equality() {
        let a =
            InAddrFull::new(AF_INET, InAddrUnion::V4(Ipv4Addr::LOCALHOST), 80, 0, None).unwrap();
        let b =
            InAddrFull::new(AF_INET, InAddrUnion::V4(Ipv4Addr::LOCALHOST), 80, 0, None).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_in_addr_full_inequality_port() {
        let a =
            InAddrFull::new(AF_INET, InAddrUnion::V4(Ipv4Addr::LOCALHOST), 80, 0, None).unwrap();
        let b =
            InAddrFull::new(AF_INET, InAddrUnion::V4(Ipv4Addr::LOCALHOST), 443, 0, None).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_netlink_family_from_string() {
        assert_eq!(netlink_family_from_string("route").unwrap(), NETLINK_ROUTE);
        assert_eq!(
            netlink_family_from_string("kobject-uevent").unwrap(),
            NETLINK_KOBJECT_UEVENT
        );
        assert_eq!(
            netlink_family_from_string("uevent").unwrap(),
            NETLINK_KOBJECT_UEVENT
        );
        assert_eq!(
            netlink_family_from_string("generic").unwrap(),
            NETLINK_GENERIC
        );
        assert_eq!(
            netlink_family_from_string("netlink-generic").unwrap(),
            NETLINK_GENERIC
        );
        assert_eq!(
            netlink_family_from_string("sock-diag").unwrap(),
            NETLINK_SOCK_DIAG
        );
        assert_eq!(
            netlink_family_from_string("sock_diag").unwrap(),
            NETLINK_SOCK_DIAG
        );
        assert!(netlink_family_from_string("bogus").is_err());
        assert!(netlink_family_from_string("").is_err());
    }

    #[test]
    fn test_netlink_family_to_string() {
        assert_eq!(netlink_family_to_string(NETLINK_ROUTE), Some("route"));
        assert_eq!(netlink_family_to_string(NETLINK_AUDIT), Some("audit"));
        assert_eq!(netlink_family_to_string(NETLINK_GENERIC), Some("generic"));
        assert_eq!(
            netlink_family_to_string(NETLINK_SOCK_DIAG),
            Some("sock-diag")
        );
        assert_eq!(netlink_family_to_string(999), None);
    }

    #[test]
    fn test_netlink_family_roundtrip() {
        let names = [
            "route",
            "selinux",
            "audit",
            "kobject-uevent",
            "generic",
            "sock-diag",
        ];
        for name in &names {
            let proto = netlink_family_from_string(name).unwrap();
            assert_eq!(netlink_family_to_string(proto), Some(*name));
        }
    }

    #[test]
    fn test_parse_ip_port() {
        assert_eq!(parse_ip_port("80").unwrap(), 80);
        assert_eq!(parse_ip_port("443").unwrap(), 443);
        assert_eq!(parse_ip_port("1").unwrap(), 1);
        assert_eq!(parse_ip_port("65535").unwrap(), 65535);
        assert!(parse_ip_port("0").is_err());
        assert!(parse_ip_port("65536").is_err());
        assert!(parse_ip_port("abc").is_err());
        assert!(parse_ip_port("").is_err());
    }

    #[test]
    fn test_parse_inet_ipv4_with_port() {
        let (addr, port, family) = parse_inet_address("192.168.1.1:80").unwrap();
        assert_eq!(addr, InAddrUnion::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(port, 80);
        assert_eq!(family, AF_INET);
    }

    #[test]
    fn test_parse_inet_ipv6_bracketed_with_port() {
        let (addr, port, family) = parse_inet_address("[::1]:443").unwrap();
        assert_eq!(addr, InAddrUnion::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(port, 443);
        assert_eq!(family, AF_INET6);
    }

    #[test]
    fn test_parse_inet_ipv6_no_port() {
        let (addr, port, family) = parse_inet_address("fe80::1").unwrap();
        assert_eq!(
            addr,
            InAddrUnion::V6(Ipv6Addr::from_str("fe80::1").unwrap())
        );
        assert_eq!(port, 0);
        assert_eq!(family, AF_INET6);
    }

    #[test]
    fn test_parse_inet_ipv4_bare() {
        let (addr, port, family) = parse_inet_address("10.0.0.1").unwrap();
        assert_eq!(addr, InAddrUnion::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(port, 0);
        assert_eq!(family, AF_INET);
    }

    #[test]
    fn test_parse_inet_invalid() {
        assert!(parse_inet_address("not_an_address").is_err());
        assert!(parse_inet_address("[unclosed").is_err());
    }

    #[test]
    fn test_socket_address_parse_inet_v4_port() {
        let addr = socket_address_parse("192.168.1.1:8080").unwrap();
        assert_eq!(
            addr,
            SocketAddress::Inet {
                family: AF_INET,
                address: InAddrUnion::V4(Ipv4Addr::new(192, 168, 1, 1)),
                port: 8080,
                ifindex: 0,
            }
        );
    }

    #[test]
    fn test_socket_address_parse_inet_v6_port() {
        let addr = socket_address_parse("[::1]:443").unwrap();
        assert_eq!(
            addr,
            SocketAddress::Inet {
                family: AF_INET6,
                address: InAddrUnion::V6(Ipv6Addr::LOCALHOST),
                port: 443,
                ifindex: 0,
            }
        );
    }

    #[test]
    fn test_socket_address_parse_bare_port() {
        let addr = socket_address_parse("53").unwrap();
        assert_eq!(
            addr,
            SocketAddress::Inet {
                family: AF_INET,
                address: InAddrUnion::V4(Ipv4Addr::UNSPECIFIED),
                port: 53,
                ifindex: 0,
            }
        );
    }

    #[test]
    fn test_socket_address_parse_invalid() {
        assert!(socket_address_parse("not_valid_at_all").is_err());
        assert!(socket_address_parse("").is_err());
    }

    #[test]
    fn test_socket_address_parse_netlink_family_only() {
        let addr = socket_address_parse_netlink("route").unwrap();
        assert_eq!(
            addr,
            SocketAddress::Netlink {
                groups: 0,
                protocol: NETLINK_ROUTE
            }
        );
    }

    #[test]
    fn test_socket_address_parse_netlink_with_group() {
        let addr = socket_address_parse_netlink("audit 7").unwrap();
        assert_eq!(
            addr,
            SocketAddress::Netlink {
                groups: 7,
                protocol: NETLINK_AUDIT
            }
        );
    }

    #[test]
    fn test_socket_address_parse_netlink_large_group() {
        let addr = socket_address_parse_netlink("route 4294967295").unwrap();
        assert_eq!(
            addr,
            SocketAddress::Netlink {
                groups: u32::MAX,
                protocol: NETLINK_ROUTE
            }
        );
    }

    #[test]
    fn test_socket_address_parse_netlink_invalid() {
        assert!(socket_address_parse_netlink("").is_err());
        assert!(socket_address_parse_netlink("unknown_family").is_err());
        assert!(socket_address_parse_netlink("route abc").is_err());
    }

    #[test]
    fn test_socket_address_equal_str() {
        let inet = SocketAddress::Inet {
            family: AF_INET,
            address: InAddrUnion::V4(Ipv4Addr::new(192, 168, 1, 1)),
            port: 80,
            ifindex: 0,
        };
        assert!(socket_address_equal_str(&inet, "192.168.1.1:80"));
        assert!(!socket_address_equal_str(&inet, "192.168.1.2:80"));
        assert!(!socket_address_equal_str(&inet, "invalid"));
    }

    #[test]
    fn test_socket_address_equal_netlink_str() {
        let nl = SocketAddress::Netlink {
            groups: 0,
            protocol: NETLINK_ROUTE,
        };
        assert!(socket_address_equal_netlink_str(&nl, "route"));
        assert!(!socket_address_equal_netlink_str(&nl, "audit"));
    }

    #[test]
    fn test_socket_address_family() {
        let inet = SocketAddress::Inet {
            family: AF_INET,
            address: InAddrUnion::V4(Ipv4Addr::LOCALHOST),
            port: 80,
            ifindex: 0,
        };
        assert_eq!(inet.family(), AF_INET);

        let nl = SocketAddress::Netlink {
            groups: 0,
            protocol: NETLINK_ROUTE,
        };
        assert_eq!(nl.family(), AF_NETLINK);

        let unix = SocketAddress::Unix {
            path: "/tmp/foo".into(),
        };
        assert_eq!(unix.family(), AF_UNIX);
    }

    #[test]
    fn test_socket_address_sock_type() {
        let inet = SocketAddress::Inet {
            family: AF_INET,
            address: InAddrUnion::V4(Ipv4Addr::LOCALHOST),
            port: 80,
            ifindex: 0,
        };
        assert_eq!(inet.sock_type(), SOCK_STREAM);

        let nl = SocketAddress::Netlink {
            groups: 0,
            protocol: NETLINK_ROUTE,
        };
        assert_eq!(nl.sock_type(), SOCK_RAW);
    }

    #[test]
    fn test_socket_address_display() {
        let inet = SocketAddress::Inet {
            family: AF_INET,
            address: InAddrUnion::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 8080,
            ifindex: 2,
        };
        assert_eq!(inet.to_string(), "10.0.0.1:8080%2");

        let nl = SocketAddress::Netlink {
            groups: 5,
            protocol: NETLINK_ROUTE,
        };
        assert_eq!(nl.to_string(), "route:5");
    }

    #[test]
    fn test_nlmsghdr_new() {
        let hdr = NlMsgHdr::new(NLMSG_ERROR, NLM_F_REQUEST, 1, 0, 100);
        assert_eq!(hdr.type_, NLMSG_ERROR);
        assert_eq!(hdr.flags, NLM_F_REQUEST);
        assert_eq!(hdr.seq, 1);
        assert_eq!(hdr.pid, 0);
        assert_eq!(hdr.len, NlMsgHdr::header_size() as u32 + 100);
    }

    #[test]
    fn test_nlmsghdr_default() {
        let hdr = NlMsgHdr::default();
        assert_eq!(hdr.len, NlMsgHdr::header_size() as u32);
        assert_eq!(hdr.type_, 0);
        assert_eq!(hdr.flags, 0);
        assert_eq!(hdr.seq, 0);
        assert_eq!(hdr.pid, 0);
    }

    #[test]
    fn test_nlmsghdr_roundtrip() {
        let original = NlMsgHdr::new(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, 42, 1234, 256);
        let bytes = original.to_bytes();
        let parsed = NlMsgHdr::from_bytes(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_nlmsghdr_from_bytes_short() {
        assert!(NlMsgHdr::from_bytes(&[0; 15]).is_none());
        assert!(NlMsgHdr::from_bytes(&[]).is_none());
    }

    #[test]
    fn test_sockaddr_nl_new() {
        let sa = SockAddrNl::new(1234, 0x1);
        assert_eq!(sa.nl_family, AF_NETLINK as u16);
        assert_eq!(sa.nl_pid, 1234);
        assert_eq!(sa.nl_groups, 0x1);
    }

    #[test]
    fn test_sockaddr_nl_default() {
        let sa = SockAddrNl::default();
        assert_eq!(sa.nl_family, AF_NETLINK as u16);
        assert_eq!(sa.nl_pid, 0);
        assert_eq!(sa.nl_groups, 0);
    }

    #[test]
    fn test_sockaddr_nl_as_sockaddr_roundtrip() {
        let original = SockAddrNl::new(100, 5);
        let libc_sa = original.as_sockaddr();
        assert_eq!(libc_sa.nl_family, AF_NETLINK as i32);
        assert_eq!(libc_sa.nl_pid, 100);
        assert_eq!(libc_sa.nl_groups, 5);

        let back = SockAddrNl::from_sockaddr(&libc_sa);
        assert_eq!(back, original);
    }

    #[test]
    fn test_netlink_error_display() {
        let e = SocketNetlinkError::InvalidAddress("bad addr".into());
        assert_eq!(format!("{e}"), "invalid socket address: bad addr");

        let e = SocketNetlinkError::InvalidPort;
        assert_eq!(format!("{e}"), "invalid port number");

        let e = SocketNetlinkError::MissingPort;
        assert_eq!(format!("{e}"), "port number is zero");

        let e = SocketNetlinkError::NotASocket;
        assert_eq!(format!("{e}"), "file descriptor is not a socket");

        let e = SocketNetlinkError::UnknownNetlinkFamily("foo".into());
        assert_eq!(format!("{e}"), "unknown netlink family: foo");
    }

    #[test]
    fn test_netlink_error_equality() {
        assert!(matches!(
            SocketNetlinkError::InvalidFamily(AF_INET),
            SocketNetlinkError::InvalidFamily(AF_INET)
        ));
        // skipping: can't compare SocketNetlinkError variants with assert_ne
        assert!(matches!(
            SocketNetlinkError::NoData,
            SocketNetlinkError::NoData
        ));
        // skipping: can't compare SocketNetlinkError with assert_ne
    }

    #[test]
    fn test_netlink_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::InvalidInput, "test");
        let nl_err = SocketNetlinkError::from(io_err);
        assert!(matches!(nl_err, SocketNetlinkError::Io(_)));
        assert!(nl_err.source().is_some());
    }

    #[test]
    fn test_netns_constants() {
        assert_eq!(NETNSA_NSID_NOT_ASSIGNED, 0xffffffff);
        assert_eq!(NETNSA_NSID_NOT_ASSIGNED, u32::MAX);
    }

    #[test]
    fn test_nlmsg_align() {
        assert_eq!(nlmsg_align(0), 0);
        assert_eq!(nlmsg_align(1), 4);
        assert_eq!(nlmsg_align(4), 4);
        assert_eq!(nlmsg_align(5), 8);
        assert_eq!(nlmsg_align(15), 16);
        assert_eq!(nlmsg_align(16), 16);
    }

    #[test]
    fn test_netlink_build_simple_request() {
        let msg = netlink_build_simple_request(RTM_GETNSID, NLM_F_REQUEST, 1, 1, 42);
        // Header (16) + attribute header (4) + attribute value (4) = 24
        assert_eq!(msg.len(), 24);

        // Parse header
        let hdr = NlMsgHdr::from_bytes(&msg).unwrap();
        assert_eq!(hdr.type_, RTM_GETNSID);
        assert_eq!(hdr.flags, NLM_F_REQUEST);
        assert_eq!(hdr.seq, 1);
        assert_eq!(hdr.len, 24);

        // Parse attribute
        let nla_len = u16::from_le_bytes(msg[16..18].try_into().unwrap());
        let nla_type = u16::from_le_bytes(msg[18..20].try_into().unwrap());
        assert_eq!(nla_len, 8);
        assert_eq!(nla_type, 1);

        // Parse attribute value
        let value = u32::from_le_bytes(msg[20..24].try_into().unwrap());
        assert_eq!(value, 42);
    }
}
