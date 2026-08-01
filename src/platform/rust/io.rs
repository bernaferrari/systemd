// SPDX-License-Identifier: LGPL-2.1-or-later

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::io;
#[cfg(target_os = "linux")]
use std::io::{IoSlice, IoSliceMut};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::fd::{BorrowedFd, OwnedFd};

pub type RawFd = i32;

/// Create an unnamed pipe.
pub fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    nix::unistd::pipe().map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Send a file descriptor over a Unix domain socket using `SCM_RIGHTS`.
#[cfg(target_os = "linux")]
pub fn send_fd(sock: BorrowedFd<'_>, fd: BorrowedFd<'_>) -> io::Result<()> {
    use nix::sys::socket::{ControlMessage, MsgFlags, UnixAddr, sendmsg};

    let iov = [IoSlice::new(b"\0")];
    let raw_fd = [fd.as_raw_fd()];
    let cmsg = [ControlMessage::ScmRights(&raw_fd)];

    sendmsg::<UnixAddr>(sock.as_raw_fd(), &iov, &cmsg, MsgFlags::MSG_NOSIGNAL, None)
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    Ok(())
}

/// Send a file descriptor over a Unix domain socket (stub on non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn send_fd(_sock: BorrowedFd<'_>, _fd: BorrowedFd<'_>) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SCM_RIGHTS is only available on Linux",
    ))
}

/// Receive a file descriptor from a Unix domain socket using `SCM_RIGHTS`.
#[cfg(target_os = "linux")]
pub fn recv_fd(sock: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    use nix::sys::socket::{MsgFlags, UnixAddr, recvmsg};

    let mut buf = [0u8; 1];
    let mut cmsg_space = nix::cmsg_space!([RawFd; 1]);
    let mut iov = [IoSliceMut::new(&mut buf)];

    let msg = recvmsg::<UnixAddr>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_space),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .map_err(|e| io::Error::from_raw_os_error(e as i32))?;

    let truncated = msg
        .flags
        .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC);
    let mut received = Vec::new();
    for cmsg in msg
        .cmsgs()
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?
    {
        if let nix::sys::socket::ControlMessageOwned::ScmRights(fds) = cmsg {
            for fd in fds {
                // SAFETY: SCM_RIGHTS installs a new descriptor in the
                // receiving process. This vector is its first Rust owner.
                received.push(unsafe_ffi!(OwnedFd::from_raw_fd(fd)));
            }
        }
    }

    if truncated {
        return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
    }
    if received.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected one file descriptor, received {}", received.len()),
        ));
    }

    Ok(received.pop().expect("length checked above"))
}

/// Receive a file descriptor from a Unix domain socket (stub on non-Linux).
#[cfg(not(target_os = "linux"))]
pub fn recv_fd(_sock: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SCM_RIGHTS is only available on Linux",
    ))
}
