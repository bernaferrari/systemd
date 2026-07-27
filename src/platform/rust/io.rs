// SPDX-License-Identifier: LGPL-2.1-or-later

use std::io;
use std::io::{IoSlice, IoSliceMut};
use std::os::unix::io::IntoRawFd;

pub type RawFd = i32;

/// Create an unnamed pipe.
pub fn pipe() -> io::Result<(RawFd, RawFd)> {
    let (r, w) = nix::unistd::pipe().map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    Ok((r.into_raw_fd(), w.into_raw_fd()))
}

/// Send a file descriptor over a Unix domain socket using `SCM_RIGHTS`.
#[cfg(target_os = "linux")]
pub fn send_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
    use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, UnixAddr};

    let addr = UnixAddr::new("").map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let iov = [IoSlice::new(b"\0")];
    let cmsg = [ControlMessage::ScmRights(&[fd])];

    sendmsg(sock, &iov, &cmsg, MsgFlags::empty(), Some(&addr))
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    Ok(())
}

/// Send a file descriptor over a Unix domain socket (stub on non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn send_fd(_sock: RawFd, _fd: RawFd) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SCM_RIGHTS is only available on Linux",
    ))
}

/// Receive a file descriptor from a Unix domain socket using `SCM_RIGHTS`.
#[cfg(target_os = "linux")]
pub fn recv_fd(sock: RawFd) -> io::Result<RawFd> {
    use nix::sys::socket::{recvmsg, MsgFlags, UnixAddr};

    let mut buf = [0u8; 1];
    let mut cmsg_space = nix::cmsg_space!([RawFd; 1]);
    let mut iov = [IoSliceMut::new(&mut buf)];

    let msg = recvmsg::<UnixAddr>(sock, &mut iov, Some(&mut cmsg_space), MsgFlags::empty())
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;

    for cmsg in msg
        .cmsgs()
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?
    {
        if let nix::sys::socket::ControlMessageOwned::ScmRights(fds) = cmsg {
            if let Some(&fd) = fds.first() {
                return Ok(fd);
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "no file descriptor received",
    ))
}

/// Receive a file descriptor from a Unix domain socket (stub on non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn recv_fd(_sock: RawFd) -> io::Result<RawFd> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SCM_RIGHTS is only available on Linux",
    ))
}
