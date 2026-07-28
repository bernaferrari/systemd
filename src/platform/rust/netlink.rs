// SPDX-License-Identifier: LGPL-2.1-or-later

use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd};

// Netlink message types — stubbed on non-Linux
#[cfg(not(target_os = "linux"))]
pub const RTM_GETLINK: i32 = 0;
#[cfg(not(target_os = "linux"))]
pub const RTM_NEWLINK: i32 = 0;
#[cfg(not(target_os = "linux"))]
pub const RTM_GETADDR: i32 = 0;
#[cfg(not(target_os = "linux"))]
pub const RTM_NEWADDR: i32 = 0;
#[cfg(not(target_os = "linux"))]
pub const NLMSG_NOOP: i32 = 0;
#[cfg(not(target_os = "linux"))]
pub const NLMSG_ERROR: i32 = 0;
#[cfg(not(target_os = "linux"))]
pub const NLMSG_DONE: i32 = 0;
#[cfg(not(target_os = "linux"))]
pub const NLM_F_REQUEST: i32 = 0;
#[cfg(not(target_os = "linux"))]
pub const NLM_F_DUMP: i32 = 0;

#[cfg(target_os = "linux")]
pub use libc::{
    NLM_F_DUMP, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP, RTM_GETADDR, RTM_GETLINK,
    RTM_NEWADDR, RTM_NEWLINK,
};

#[cfg(target_os = "linux")]
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recv, send,
    socket,
};

/// A netlink socket wrapper for communicating with the kernel.
pub struct NetlinkSocket {
    #[cfg(target_os = "linux")]
    fd: OwnedFd,
}

impl NetlinkSocket {
    /// Create a new AF_NETLINK socket.
    #[cfg(target_os = "linux")]
    pub fn new() -> io::Result<Self> {
        let fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::empty(),
            SockProtocol::NetlinkRoute,
        )
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        Ok(Self { fd })
    }

    /// Create a new AF_NETLINK socket (stub on non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn new() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "netlink is only available on Linux",
        ))
    }

    /// Bind the socket to a netlink address (port groups).
    #[cfg(target_os = "linux")]
    pub fn bind(&self, addr: u32) -> io::Result<()> {
        let nl_addr = NetlinkAddr::new(0, addr);
        bind(self.fd.as_raw_fd(), &nl_addr).map_err(|e| io::Error::from_raw_os_error(e as i32))
    }

    /// Bind the socket (stub on non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn bind(&self, _addr: u32) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "netlink is only available on Linux",
        ))
    }

    /// Send a raw message on the netlink socket.
    #[cfg(target_os = "linux")]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        send(self.fd.as_raw_fd(), buf, MsgFlags::empty())
            .map_err(|e| io::Error::from_raw_os_error(e as i32))
    }

    /// Send a raw message (stub on non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn send(&self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "netlink is only available on Linux",
        ))
    }

    /// Receive a raw message from the netlink socket.
    #[cfg(target_os = "linux")]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        recv(self.fd.as_raw_fd(), buf, MsgFlags::empty())
            .map_err(|e| io::Error::from_raw_os_error(e as i32))
    }

    /// Receive a raw message (stub on non-Linux).
    #[cfg(not(target_os = "linux"))]
    pub fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "netlink is only available on Linux",
        ))
    }
}
