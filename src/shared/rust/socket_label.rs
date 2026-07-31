// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/socket-label.c
//
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::io;
use std::mem::{self, offset_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use crate::mkdir_label::mkdir_parents_label;
use crate::selinux_util::{mac_selinux_create_socket_clear, mac_selinux_create_socket_prepare};
use crate::smack_util::{SmackAttr, mac_smack_apply, mac_smack_apply_fd};

pub const SOURCE_C_FILE: &str = "src/shared/socket-label.c";
pub const EXPORTED_SYMBOLS: &[&str] = &[
    "socket_address_bind_ipv6_only_to_string",
    "socket_address_bind_ipv6_only_from_string",
    "socket_address_bind_ipv6_only_or_bool_from_string",
    "socket_address_listen",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortMetadata {
    pub source_c_file: &'static str,
    pub exported_symbols: &'static [&'static str],
}

pub const PORT_METADATA: PortMetadata = PortMetadata {
    source_c_file: SOURCE_C_FILE,
    exported_symbols: EXPORTED_SYMBOLS,
};

pub fn exported_symbols() -> &'static [&'static str] {
    EXPORTED_SYMBOLS
}

#[derive(Debug)]
pub enum SocketLabelError {
    InvalidValue(&'static str),
    Unsupported(&'static str),
    Io(io::Error),
    Selinux(String),
}

impl fmt::Display for SocketLabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue(msg) => write!(f, "invalid value: {msg}"),
            Self::Unsupported(msg) => write!(f, "unsupported operation: {msg}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::Selinux(msg) => write!(f, "SELinux error: {msg}"),
        }
    }
}

impl std::error::Error for SocketLabelError {}

impl From<io::Error> for SocketLabelError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, SocketLabelError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketAddressBindIPv6Only {
    Default,
    Both,
    Ipv6Only,
}

impl SocketAddressBindIPv6Only {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Both => "both",
            Self::Ipv6Only => "ipv6-only",
        }
    }
}

pub fn socket_address_bind_ipv6_only_to_string(value: SocketAddressBindIPv6Only) -> &'static str {
    value.as_str()
}

pub fn socket_address_bind_ipv6_only_from_string(s: &str) -> Result<SocketAddressBindIPv6Only> {
    match s {
        "default" => Ok(SocketAddressBindIPv6Only::Default),
        "both" => Ok(SocketAddressBindIPv6Only::Both),
        "ipv6-only" => Ok(SocketAddressBindIPv6Only::Ipv6Only),
        _ => Err(SocketLabelError::InvalidValue("unknown IPv6 bind mode")),
    }
}

pub fn socket_address_bind_ipv6_only_or_bool_from_string(
    s: &str,
) -> Result<SocketAddressBindIPv6Only> {
    match parse_boolean(s) {
        Some(true) => Ok(SocketAddressBindIPv6Only::Ipv6Only),
        Some(false) => Ok(SocketAddressBindIPv6Only::Both),
        None => socket_address_bind_ipv6_only_from_string(s),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnixSocketPath {
    Filesystem(PathBuf),
    Abstract(Vec<u8>),
    Unnamed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketAddress {
    Inet {
        addr: SocketAddr,
        sock_type: i32,
        protocol: i32,
    },
    Unix {
        path: UnixSocketPath,
        sock_type: i32,
        protocol: i32,
    },
    Netlink {
        pid: u32,
        groups: u32,
        sock_type: i32,
        protocol: i32,
    },
    Vsock {
        cid: u32,
        port: u32,
        sock_type: i32,
        protocol: i32,
    },
}

impl SocketAddress {
    pub fn family(&self) -> i32 {
        match self {
            Self::Inet { addr, .. } => match addr {
                SocketAddr::V4(_) => libc::AF_INET,
                SocketAddr::V6(_) => libc::AF_INET6,
            },
            Self::Unix { .. } => libc::AF_UNIX,
            Self::Netlink { .. } => af_netlink(),
            Self::Vsock { .. } => af_vsock(),
        }
    }

    pub fn socket_type(&self) -> i32 {
        match self {
            Self::Inet { sock_type, .. }
            | Self::Unix { sock_type, .. }
            | Self::Netlink { sock_type, .. }
            | Self::Vsock { sock_type, .. } => *sock_type,
        }
    }

    pub fn protocol(&self) -> i32 {
        match self {
            Self::Inet { protocol, .. }
            | Self::Unix { protocol, .. }
            | Self::Netlink { protocol, .. }
            | Self::Vsock { protocol, .. } => *protocol,
        }
    }

    pub fn can_accept(&self) -> bool {
        matches!(self.socket_type(), libc::SOCK_STREAM | libc::SOCK_SEQPACKET)
    }

    pub fn get_path(&self) -> Option<&Path> {
        match self {
            Self::Unix {
                path: UnixSocketPath::Filesystem(path),
                ..
            } => Some(path.as_path()),
            _ => None,
        }
    }

    pub fn verify(&self, strict: bool) -> Result<()> {
        match self {
            Self::Inet {
                addr, sock_type, ..
            } => {
                if addr.port() == 0 {
                    return Err(SocketLabelError::InvalidValue(
                        "internet socket port must be non-zero",
                    ));
                }
                if !matches!(*sock_type, 0 | libc::SOCK_STREAM | libc::SOCK_DGRAM) {
                    return Err(SocketLabelError::InvalidValue(
                        "unsupported inet socket type",
                    ));
                }
                Ok(())
            }
            Self::Unix {
                path, sock_type, ..
            } => {
                if !matches!(
                    *sock_type,
                    0 | libc::SOCK_STREAM | libc::SOCK_DGRAM | libc::SOCK_SEQPACKET
                ) {
                    return Err(SocketLabelError::InvalidValue(
                        "unsupported unix socket type",
                    ));
                }

                if strict {
                    match path {
                        UnixSocketPath::Filesystem(path) => {
                            if path.as_os_str().is_empty() {
                                return Err(SocketLabelError::InvalidValue(
                                    "unix socket path must not be empty",
                                ));
                            }
                            if path.as_os_str().as_bytes().contains(&0) {
                                return Err(SocketLabelError::InvalidValue(
                                    "unix socket path contains NUL",
                                ));
                            }
                        }
                        UnixSocketPath::Abstract(name) if name.is_empty() => {
                            return Err(SocketLabelError::InvalidValue(
                                "abstract unix socket name must not be empty",
                            ));
                        }
                        _ => {}
                    }
                }

                self.to_raw_sockaddr().map(|_| ())
            }
            Self::Netlink { sock_type, .. } => {
                if !matches!(*sock_type, 0 | libc::SOCK_RAW | libc::SOCK_DGRAM) {
                    return Err(SocketLabelError::InvalidValue(
                        "unsupported netlink socket type",
                    ));
                }
                self.to_raw_sockaddr().map(|_| ())
            }
            Self::Vsock {
                sock_type, port, ..
            } => {
                if *port == 0 {
                    return Err(SocketLabelError::InvalidValue(
                        "vsock port must be non-zero",
                    ));
                }
                if !matches!(*sock_type, 0 | libc::SOCK_STREAM | libc::SOCK_DGRAM) {
                    return Err(SocketLabelError::InvalidValue(
                        "unsupported vsock socket type",
                    ));
                }
                self.to_raw_sockaddr().map(|_| ())
            }
        }
    }

    fn to_raw_sockaddr(&self) -> Result<RawSocketAddress> {
        match self {
            Self::Inet { addr, .. } => match addr {
                SocketAddr::V4(v4) => RawSocketAddress::from_sockaddr_in(sockaddr_in_from(v4)),
                SocketAddr::V6(v6) => RawSocketAddress::from_sockaddr_in6(sockaddr_in6_from(v6)),
            },
            Self::Unix { path, .. } => sockaddr_unix_from(path),
            Self::Netlink { pid, groups, .. } => sockaddr_netlink_from(*pid, *groups),
            Self::Vsock { cid, port, .. } => sockaddr_vsock_from(*cid, *port),
        }
    }
}

struct RawSocketAddress {
    storage: RawSocketAddressStorage,
    len: libc::socklen_t,
}

/// Owns the concrete socket address behind a borrowed `sockaddr` ABI pointer.
///
/// This avoids constructing untyped `sockaddr_storage` buffers and writing a
/// typed address into them through a raw pointer. Each variant remains valid
/// and aligned for as long as `RawSocketAddress` is borrowed by `bind(2)`.
enum RawSocketAddressStorage {
    Inet(libc::sockaddr_in),
    Inet6(libc::sockaddr_in6),
    Unix(libc::sockaddr_un),
    #[cfg(target_os = "linux")]
    Netlink(libc::sockaddr_nl),
    #[cfg(target_os = "linux")]
    Vsock(libc::sockaddr_vm),
}

impl RawSocketAddress {
    fn as_ptr(&self) -> *const libc::sockaddr {
        match &self.storage {
            RawSocketAddressStorage::Inet(addr) => (addr as *const libc::sockaddr_in).cast(),
            RawSocketAddressStorage::Inet6(addr) => (addr as *const libc::sockaddr_in6).cast(),
            RawSocketAddressStorage::Unix(addr) => (addr as *const libc::sockaddr_un).cast(),
            #[cfg(target_os = "linux")]
            RawSocketAddressStorage::Netlink(addr) => (addr as *const libc::sockaddr_nl).cast(),
            #[cfg(target_os = "linux")]
            RawSocketAddressStorage::Vsock(addr) => (addr as *const libc::sockaddr_vm).cast(),
        }
    }

    fn from_sockaddr_in(addr: libc::sockaddr_in) -> Self {
        Self {
            storage: RawSocketAddressStorage::Inet(addr),
            len: mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        }
    }

    fn from_sockaddr_in6(addr: libc::sockaddr_in6) -> Self {
        Self {
            storage: RawSocketAddressStorage::Inet6(addr),
            len: mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        }
    }

    fn from_sockaddr_un(addr: libc::sockaddr_un, len: usize) -> Self {
        Self {
            storage: RawSocketAddressStorage::Unix(addr),
            len: len as libc::socklen_t,
        }
    }

    #[cfg(target_os = "linux")]
    fn from_sockaddr_nl(addr: libc::sockaddr_nl) -> Self {
        Self {
            storage: RawSocketAddressStorage::Netlink(addr),
            len: mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        }
    }

    #[cfg(target_os = "linux")]
    fn from_sockaddr_vm(addr: libc::sockaddr_vm) -> Self {
        Self {
            storage: RawSocketAddressStorage::Vsock(addr),
            len: mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        }
    }
}

fn sockaddr_in_from(addr: &SocketAddrV4) -> libc::sockaddr_in {
    // SAFETY: sockaddr_in is a C socket-address type whose all-zero bit pattern is valid.
    let mut raw: libc::sockaddr_in = unsafe { mem::zeroed() };
    set_sockaddr_in_len(&mut raw, sockaddr_in_len());
    raw.sin_family = libc::AF_INET as libc::sa_family_t;
    raw.sin_port = addr.port().to_be();
    raw.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(addr.ip().octets()).to_be(),
    };
    raw
}

fn sockaddr_in6_from(addr: &SocketAddrV6) -> libc::sockaddr_in6 {
    // SAFETY: sockaddr_in6 is a C socket-address type whose all-zero bit pattern is valid.
    let mut raw: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    set_sockaddr_in6_len(&mut raw, sockaddr_in6_len());
    raw.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    raw.sin6_port = addr.port().to_be();
    raw.sin6_flowinfo = addr.flowinfo();
    raw.sin6_addr = libc::in6_addr {
        s6_addr: addr.ip().octets(),
    };
    raw.sin6_scope_id = addr.scope_id();
    raw
}

fn sockaddr_unix_from(path: &UnixSocketPath) -> Result<RawSocketAddress> {
    // SAFETY: sockaddr_un is a C socket-address type whose all-zero bit pattern is valid.
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    set_sockaddr_un_len(&mut addr, mem::size_of::<libc::sockaddr_un>());

    let base = offset_of!(libc::sockaddr_un, sun_path);
    let sun_path_len = addr.sun_path.len();

    match path {
        UnixSocketPath::Filesystem(path) => {
            let bytes = path.as_os_str().as_bytes();
            if bytes.is_empty() {
                return Err(SocketLabelError::InvalidValue(
                    "unix socket path must not be empty",
                ));
            }
            if bytes.len() > sun_path_len {
                return Err(SocketLabelError::InvalidValue("unix socket path too long"));
            }

            // SAFETY: the validated byte slice and sun_path are non-overlapping, and the destination is large enough.
            unsafe {
                ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    addr.sun_path.as_mut_ptr().cast(),
                    bytes.len(),
                );
            }

            let len = base + bytes.len() + usize::from(bytes.len() < sun_path_len);
            set_sockaddr_un_len(&mut addr, len);
            RawSocketAddress::from_sockaddr_un(addr, len)
        }
        UnixSocketPath::Abstract(name) => {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = name;
                Err(SocketLabelError::Unsupported(
                    "abstract unix sockets are Linux-only",
                ))
            }

            #[cfg(target_os = "linux")]
            {
                if name.is_empty() {
                    return Err(SocketLabelError::InvalidValue(
                        "abstract unix socket name must not be empty",
                    ));
                }
                if name.len() + 1 > sun_path_len {
                    return Err(SocketLabelError::InvalidValue(
                        "abstract unix socket name too long",
                    ));
                }

                // SAFETY: the validated name and sun_path tail are non-overlapping, and the destination is large enough.
                unsafe {
                    ptr::copy_nonoverlapping(
                        name.as_ptr(),
                        addr.sun_path.as_mut_ptr().add(1).cast(),
                        name.len(),
                    );
                }

                let len = base + 1 + name.len();
                set_sockaddr_un_len(&mut addr, len);
                RawSocketAddress::from_sockaddr_un(addr, len)
            }
        }
        UnixSocketPath::Unnamed => {
            set_sockaddr_un_len(&mut addr, base);
            RawSocketAddress::from_sockaddr_un(addr, base)
        }
    }
}

fn sockaddr_netlink_from(pid: u32, groups: u32) -> Result<RawSocketAddress> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `sockaddr_nl` is a plain C socket-address structure; an
        // all-zero value is valid and leaves target-specific padding intact.
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_pid = pid;
        addr.nl_groups = groups;

        // SAFETY: sockaddr_storage is a C socket-address buffer whose all-zero bit pattern is valid.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        // SAFETY: storage is suitably aligned and large enough for sockaddr_nl, and is exclusively borrowed.
        unsafe {
            ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_nl, addr);
        }

        Ok(RawSocketAddress {
            storage,
            len: mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, groups);
        Err(SocketLabelError::Unsupported(
            "netlink sockets are Linux-only",
        ))
    }
}

fn sockaddr_vsock_from(cid: u32, port: u32) -> Result<RawSocketAddress> {
    #[cfg(target_os = "linux")]
    {
        let addr = libc::sockaddr_vm {
            svm_family: libc::AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: cid,
            svm_zero: [0; 4],
        };

        // SAFETY: sockaddr_storage is a C socket-address buffer whose all-zero bit pattern is valid.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        // SAFETY: storage is suitably aligned and large enough for sockaddr_vm, and is exclusively borrowed.
        unsafe {
            ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_vm, addr);
        }

        Ok(RawSocketAddress {
            storage,
            len: mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (cid, port);
        Err(SocketLabelError::Unsupported(
            "vsock sockets are Linux-only",
        ))
    }
}

pub fn socket_address_listen(
    address: &SocketAddress,
    flags: i32,
    backlog: i32,
    only: SocketAddressBindIPv6Only,
    bind_to_device: Option<&str>,
    reuse_port: bool,
    free_bind: bool,
    transparent: bool,
    directory_mode: u32,
    socket_mode: u32,
    selinux_label: Option<&str>,
    smack_label: Option<&str>,
) -> Result<OwnedFd> {
    address.verify(true)?;

    if address.family() == libc::AF_INET6 && !socket_ipv6_is_supported() {
        return Err(SocketLabelError::Unsupported(
            "IPv6 is not supported on this host",
        ));
    }

    let _selinux_guard = SelinuxSocketCreateGuard::new(selinux_label)?;

    // SAFETY: address verification supplies a supported socket family and type; libc::socket accepts these integer arguments.
    let fd = cvt_fd(unsafe {
        libc::socket(
            address.family(),
            address.socket_type() | flags,
            address.protocol(),
        )
    })?;

    if let Some(label) = smack_label {
        let _ = mac_smack_apply_fd(fd, SmackAttr::Access, Some(label));
    }

    if address.family() == libc::AF_INET6 && only != SocketAddressBindIPv6Only::Default {
        set_sockopt_int(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            i32::from(only == SocketAddressBindIPv6Only::Ipv6Only),
        )?;
    }

    if matches!(address.family(), libc::AF_INET | libc::AF_INET6) {
        if let Some(ifname) = bind_to_device {
            socket_bind_to_ifname(fd, ifname)?;
        }

        if reuse_port {
            let _ = set_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1);
        }

        if free_bind {
            let _ = socket_set_freebind(fd, address.family(), true);
        }

        if transparent {
            let _ = socket_set_transparent(fd, address.family(), true);
        }
    }

    set_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;

    let raw = address.to_raw_sockaddr()?;
    if let Some(path) = address.get_path() {
        let _ = mkdir_parents_label(path, directory_mode);

        let _umask_guard = UmaskGuard::set((!socket_mode) & 0o777);
        match bind_socket(fd, &raw) {
            Ok(()) => {}
            Err(err) if err.raw_os_error() == Some(libc::EADDRINUSE) => {
                fs::remove_file(path).map_err(|_| SocketLabelError::Io(err))?;
                bind_socket(fd, &raw)?;
            }
            Err(err) => return Err(err.into()),
        }

        if let Some(label) = smack_label {
            let _ = mac_smack_apply(path, SmackAttr::Access, Some(label));
        }
    } else {
        bind_socket(fd, &raw)?;
    }

    if address.can_accept() {
        // SAFETY: fd is a successfully created socket descriptor that remains owned by this function.
        cvt(unsafe { libc::listen(fd, backlog) })?;
    }

    if let Some(path) = address.get_path() {
        let _ = touch(path);
    }

    // SAFETY: fd was successfully created above and its ownership is transferred exactly once to OwnedFd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn bind_socket(fd: RawFd, addr: &RawSocketAddress) -> io::Result<()> {
    // SAFETY: addr points to initialized socket storage with the matching recorded length; fd is supplied by the caller.
    cvt(unsafe { libc::bind(fd, addr.as_ptr(), addr.len) }).map(|_| ())
}

fn parse_boolean(s: &str) -> Option<bool> {
    let normalized = s.trim();
    if normalized.eq_ignore_ascii_case("1")
        || normalized.eq_ignore_ascii_case("yes")
        || normalized.eq_ignore_ascii_case("y")
        || normalized.eq_ignore_ascii_case("true")
        || normalized.eq_ignore_ascii_case("t")
        || normalized.eq_ignore_ascii_case("on")
    {
        return Some(true);
    }

    if normalized.eq_ignore_ascii_case("0")
        || normalized.eq_ignore_ascii_case("no")
        || normalized.eq_ignore_ascii_case("n")
        || normalized.eq_ignore_ascii_case("false")
        || normalized.eq_ignore_ascii_case("f")
        || normalized.eq_ignore_ascii_case("off")
    {
        return Some(false);
    }

    None
}

fn socket_ipv6_is_supported() -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/proc/net/if_inet6").exists()
    }

    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

fn socket_bind_to_ifname(fd: RawFd, ifname: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let name = CString::new(ifname)
            .map_err(|_| SocketLabelError::InvalidValue("interface name contains NUL"))?;
        // SAFETY: name is a live NUL-terminated CString, and its byte pointer and length remain valid for this call.
        cvt(unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                name.as_ptr() as *const libc::c_void,
                name.as_bytes().len() as libc::socklen_t,
            )
        })?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, ifname);
        Err(SocketLabelError::Unsupported(
            "SO_BINDTODEVICE is Linux-only",
        ))
    }
}

fn socket_set_freebind(fd: RawFd, family: i32, enabled: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let opt = match family {
            libc::AF_INET => libc::IP_FREEBIND,
            libc::AF_INET6 => libc::IPV6_FREEBIND,
            _ => {
                return Err(SocketLabelError::Unsupported(
                    "freebind requires AF_INET/AF_INET6",
                ));
            }
        };

        let level = if family == libc::AF_INET {
            libc::IPPROTO_IP
        } else {
            libc::IPPROTO_IPV6
        };
        set_sockopt_int(fd, level, opt, i32::from(enabled))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, family, enabled);
        Err(SocketLabelError::Unsupported("freebind is Linux-only"))
    }
}

fn socket_set_transparent(fd: RawFd, family: i32, enabled: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let opt = match family {
            libc::AF_INET => libc::IP_TRANSPARENT,
            libc::AF_INET6 => libc::IPV6_TRANSPARENT,
            _ => {
                return Err(SocketLabelError::Unsupported(
                    "transparent sockets require AF_INET/AF_INET6",
                ));
            }
        };

        let level = if family == libc::AF_INET {
            libc::IPPROTO_IP
        } else {
            libc::IPPROTO_IPV6
        };
        set_sockopt_int(fd, level, opt, i32::from(enabled))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (fd, family, enabled);
        Err(SocketLabelError::Unsupported(
            "transparent sockets are Linux-only",
        ))
    }
}

fn set_sockopt_int(fd: RawFd, level: i32, optname: i32, value: i32) -> Result<()> {
    let value = value as i32;
    // SAFETY: value is a live, aligned i32 and the pointer and length describe exactly that object for this call.
    cvt(unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &value as *const i32 as *const libc::c_void,
            mem::size_of::<i32>() as libc::socklen_t,
        )
    })?;
    Ok(())
}

fn touch(path: &Path) -> io::Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL byte"))?;
    // SAFETY: path is a live NUL-terminated CString; AT_FDCWD and a null times pointer are valid utimensat arguments.
    cvt(unsafe { libc::utimensat(libc::AT_FDCWD, path.as_ptr(), ptr::null(), 0) }).map(|_| ())
}

fn cvt(ret: i32) -> io::Result<i32> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn cvt_fd(ret: i32) -> Result<RawFd> {
    if ret < 0 {
        Err(SocketLabelError::Io(io::Error::last_os_error()))
    } else {
        Ok(ret)
    }
}

struct UmaskGuard(libc::mode_t);

impl UmaskGuard {
    fn set(mask: u32) -> Self {
        // SAFETY: umask accepts the converted mode value and has no pointer or lifetime requirements.
        let old = unsafe { libc::umask(mask as libc::mode_t) };
        Self(old)
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: the mode was returned by libc::umask and is valid to restore.
        unsafe {
            libc::umask(self.0);
        }
    }
}

struct SelinuxSocketCreateGuard(bool);

impl SelinuxSocketCreateGuard {
    fn new(label: Option<&str>) -> Result<Self> {
        if let Some(label) = label {
            mac_selinux_create_socket_prepare(label)
                .map_err(|err| SocketLabelError::Selinux(err.to_string()))?;
            Ok(Self(true))
        } else {
            Ok(Self(false))
        }
    }
}

impl Drop for SelinuxSocketCreateGuard {
    fn drop(&mut self) {
        if self.0 {
            mac_selinux_create_socket_clear();
        }
    }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn sockaddr_in_len() -> u8 {
    mem::size_of::<libc::sockaddr_in>() as u8
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
fn sockaddr_in_len() -> u8 {
    0
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn set_sockaddr_in_len(addr: &mut libc::sockaddr_in, len: u8) {
    addr.sin_len = len;
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
fn set_sockaddr_in_len(_addr: &mut libc::sockaddr_in, _len: u8) {}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn sockaddr_in6_len() -> u8 {
    mem::size_of::<libc::sockaddr_in6>() as u8
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
fn sockaddr_in6_len() -> u8 {
    0
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn set_sockaddr_in6_len(addr: &mut libc::sockaddr_in6, len: u8) {
    addr.sin6_len = len;
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
fn set_sockaddr_in6_len(_addr: &mut libc::sockaddr_in6, _len: u8) {}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
fn set_sockaddr_un_len(addr: &mut libc::sockaddr_un, len: usize) {
    addr.sun_len = len as u8;
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
fn set_sockaddr_un_len(_addr: &mut libc::sockaddr_un, _len: usize) {}

#[cfg(target_os = "linux")]
fn af_netlink() -> i32 {
    libc::AF_NETLINK
}

#[cfg(not(target_os = "linux"))]
fn af_netlink() -> i32 {
    16
}

#[cfg(target_os = "linux")]
fn af_vsock() -> i32 {
    libc::AF_VSOCK
}

#[cfg(not(target_os = "linux"))]
fn af_vsock() -> i32 {
    40
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new() -> Self {
            let unique = format!(
                "socket-label-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let path = std::env::temp_dir().join(unique);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn metadata_matches_source_file() {
        assert_eq!(PORT_METADATA.source_c_file, SOURCE_C_FILE);
    }

    #[test]
    fn metadata_exposes_symbol_slice() {
        assert_eq!(PORT_METADATA.exported_symbols, EXPORTED_SYMBOLS);
    }

    #[test]
    fn ipv6_only_to_string_round_trips() {
        assert_eq!(
            socket_address_bind_ipv6_only_to_string(SocketAddressBindIPv6Only::Default),
            "default"
        );
        assert_eq!(
            socket_address_bind_ipv6_only_to_string(SocketAddressBindIPv6Only::Both),
            "both"
        );
        assert_eq!(
            socket_address_bind_ipv6_only_to_string(SocketAddressBindIPv6Only::Ipv6Only),
            "ipv6-only"
        );
    }

    #[test]
    fn ipv6_only_from_string_accepts_table_values() {
        assert_eq!(
            socket_address_bind_ipv6_only_from_string("default").unwrap(),
            SocketAddressBindIPv6Only::Default
        );
        assert_eq!(
            socket_address_bind_ipv6_only_from_string("both").unwrap(),
            SocketAddressBindIPv6Only::Both
        );
        assert_eq!(
            socket_address_bind_ipv6_only_from_string("ipv6-only").unwrap(),
            SocketAddressBindIPv6Only::Ipv6Only
        );
    }

    #[test]
    fn ipv6_only_from_string_rejects_unknown_values() {
        assert!(socket_address_bind_ipv6_only_from_string("bogus").is_err());
    }

    #[test]
    fn ipv6_only_or_bool_parses_true_values() {
        assert_eq!(
            socket_address_bind_ipv6_only_or_bool_from_string("yes").unwrap(),
            SocketAddressBindIPv6Only::Ipv6Only
        );
        assert_eq!(
            socket_address_bind_ipv6_only_or_bool_from_string("1").unwrap(),
            SocketAddressBindIPv6Only::Ipv6Only
        );
    }

    #[test]
    fn ipv6_only_or_bool_parses_false_values() {
        assert_eq!(
            socket_address_bind_ipv6_only_or_bool_from_string("no").unwrap(),
            SocketAddressBindIPv6Only::Both
        );
        assert_eq!(
            socket_address_bind_ipv6_only_or_bool_from_string("0").unwrap(),
            SocketAddressBindIPv6Only::Both
        );
    }

    #[test]
    fn inet_verify_rejects_zero_port() {
        let address = SocketAddress::Inet {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            sock_type: libc::SOCK_STREAM,
            protocol: 0,
        };

        assert!(address.verify(true).is_err());
    }

    #[test]
    fn unix_filesystem_get_path_returns_path() {
        let path = PathBuf::from("/tmp/example.sock");
        let address = SocketAddress::Unix {
            path: UnixSocketPath::Filesystem(path.clone()),
            sock_type: libc::SOCK_STREAM,
            protocol: 0,
        };

        assert_eq!(address.get_path(), Some(path.as_path()));
    }

    #[test]
    fn unix_abstract_get_path_is_none() {
        let address = SocketAddress::Unix {
            path: UnixSocketPath::Abstract(b"example".to_vec()),
            sock_type: libc::SOCK_STREAM,
            protocol: 0,
        };

        assert_eq!(address.get_path(), None);
    }

    #[test]
    fn socket_address_can_accept_tracks_type() {
        let stream = SocketAddress::Unix {
            path: UnixSocketPath::Unnamed,
            sock_type: libc::SOCK_STREAM,
            protocol: 0,
        };
        let seqpacket = SocketAddress::Unix {
            path: UnixSocketPath::Unnamed,
            sock_type: libc::SOCK_SEQPACKET,
            protocol: 0,
        };
        let dgram = SocketAddress::Unix {
            path: UnixSocketPath::Unnamed,
            sock_type: libc::SOCK_DGRAM,
            protocol: 0,
        };

        assert!(stream.can_accept());
        assert!(seqpacket.can_accept());
        assert!(!dgram.can_accept());
    }

    #[test]
    fn unix_verify_rejects_empty_filesystem_path() {
        let address = SocketAddress::Unix {
            path: UnixSocketPath::Filesystem(PathBuf::new()),
            sock_type: libc::SOCK_STREAM,
            protocol: 0,
        };

        assert!(address.verify(true).is_err());
    }

    #[test]
    fn unix_verify_accepts_filesystem_path() {
        let address = SocketAddress::Unix {
            path: UnixSocketPath::Filesystem(PathBuf::from("/tmp/socket-label-test.sock")),
            sock_type: libc::SOCK_STREAM,
            protocol: 0,
        };

        assert!(address.verify(true).is_ok());
    }

    #[test]
    fn socket_address_listen_creates_unix_socket() {
        let dir = TestDir::new();
        let path = dir.join("listen.sock");
        let address = SocketAddress::Unix {
            path: UnixSocketPath::Filesystem(path.clone()),
            sock_type: libc::SOCK_STREAM,
            protocol: 0,
        };

        let fd = socket_address_listen(
            &address,
            0,
            8,
            SocketAddressBindIPv6Only::Default,
            None,
            false,
            false,
            false,
            0o755,
            0o666,
            None,
            None,
        )
        .unwrap();

        assert!(path.exists());
        assert!(fd.as_raw_fd() >= 0);
    }

    #[test]
    fn socket_address_listen_replaces_stale_socket_node() {
        let dir = TestDir::new();
        let path = dir.join("stale.sock");
        let stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
        drop(stale);

        let address = SocketAddress::Unix {
            path: UnixSocketPath::Filesystem(path.clone()),
            sock_type: libc::SOCK_STREAM,
            protocol: 0,
        };

        let fd = socket_address_listen(
            &address,
            0,
            4,
            SocketAddressBindIPv6Only::Default,
            None,
            false,
            false,
            false,
            0o755,
            0o666,
            None,
            None,
        )
        .unwrap();

        assert!(path.exists());
        assert!(fd.as_raw_fd() >= 0);
    }

    #[test]
    fn inet_family_is_derived_from_address() {
        let v4 = SocketAddress::Inet {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80),
            sock_type: libc::SOCK_STREAM,
            protocol: 0,
        };
        let v6 = SocketAddress::Inet {
            addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80),
            sock_type: libc::SOCK_STREAM,
            protocol: 0,
        };

        assert_eq!(v4.family(), libc::AF_INET);
        assert_eq!(v6.family(), libc::AF_INET6);
    }
}
