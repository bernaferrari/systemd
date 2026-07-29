// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/daemon-util.c, src/shared/daemon-util.h
//
// Daemon notification utilities for communicating with the systemd service manager
// via the sd_notify protocol (NOTIFY_SOCKET).

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
#[cfg(test)]
use std::os::unix::net::UnixDatagram;
use systemd_basic_rs::socket_util::sockaddr_un_from_path_bytes;

// ── Constants ─────────────────────────────────────────────────────────────

pub const NOTIFY_READY_MESSAGE: &str = "READY=1\nSTATUS=Processing requests...";
pub const NOTIFY_STOPPING_MESSAGE: &str = "STOPPING=1\nSTATUS=Shutting down...";

// ── Message building (pure, testable) ─────────────────────────────────────

fn build_fdstore_remove_message(name: &str) -> String {
    format!("FDSTOREREMOVE=1\nFDNAME={name}")
}

fn build_fdstore_push_message(name: &str) -> String {
    format!("FDSTORE=1\nFDNAME={name}")
}

fn build_fdstore_store_message() -> &'static str {
    "FDSTORE=1"
}

fn build_reloading_message(status: Option<&str>) -> String {
    match status {
        Some(s) => format!("RELOADING=1\nMONOTONIC_USEC=0\nSTATUS={s}"),
        None => "RELOADING=1\nMONOTONIC_USEC=0".into(),
    }
}

// ── Core sd_notify ────────────────────────────────────────────────────────

fn notify_socket_path() -> io::Result<OsString> {
    env::var_os("NOTIFY_SOCKET")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "NOTIFY_SOCKET not set"))
}

/// Parse `NOTIFY_SOCKET` exactly as systemd's AF_UNIX address parser does.
///
/// `@name` denotes a Linux abstract socket; `/path` denotes a filesystem
/// socket. Keeping the returned address length avoids both pathname
/// truncation and the incorrect full-`sockaddr_un` length used by the old
/// hand-built FD-store sender.
fn notify_unix_socket_address() -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    // P2: sd_notify's C implementation also accepts VSOCK destinations. This
    // Rust helper deliberately handles the Unix subset until the port has a
    // safe, fully tested VSOCK sender with C's stream/seqpacket fallback.
    let path = notify_socket_path()?;
    let (address, length) = sockaddr_un_from_path_bytes(path.as_os_str().as_bytes())
        .map_err(|error| io::Error::from_raw_os_error(-error))?;
    let length = libc::socklen_t::try_from(length).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "NOTIFY_SOCKET address length does not fit socklen_t",
        )
    })?;
    Ok((address, length))
}

fn send_datagram(payload: &[u8]) -> io::Result<()> {
    send_fd_datagram(payload, &[])
}

/// Send a notification without changing the process environment.
pub fn sd_notify_preserve_environment(state: &str) -> io::Result<bool> {
    match send_datagram(state.as_bytes()) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Send a notification via the sd_notify protocol.
/// Returns `Ok(true)` if sent, `Ok(false)` if `NOTIFY_SOCKET` is not set.
///
/// # Safety
///
/// When `unset_environment` is true, the caller must ensure that no other
/// thread reads or mutates the process environment until this function returns.
pub unsafe fn sd_notify(unset_environment: bool, state: &str) -> io::Result<bool> {
    let result = sd_notify_preserve_environment(state);
    if unset_environment {
        // SAFETY: required by this function's contract when unsetting.
        unsafe { env::remove_var("NOTIFY_SOCKET") };
    }
    result
}

// ── FD store operations ───────────────────────────────────────────────────

/// Remove a named file descriptor from the service manager's fd store.
pub fn notify_remove_fd_warn(name: &str) -> io::Result<()> {
    send_datagram(build_fdstore_remove_message(name).as_bytes())
}

/// Remove a named file descriptor from the fd store (format-string variant).
pub fn notify_remove_fd_warnf(args: fmt::Arguments<'_>) -> io::Result<()> {
    notify_remove_fd_warn(&args.to_string())
}

/// Close a file descriptor and optionally remove it from the fd store first.
pub fn close_and_notify_warn(fd: RawFd, name: Option<&str>) -> io::Result<()> {
    if let Some(n) = name {
        let _ = notify_remove_fd_warn(n);
    }
    if fd >= 0 {
        // SAFETY: close(2) is a POSIX syscall with well-defined semantics.
        let r = unsafe { libc::close(fd) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Push a file descriptor into the service manager's fd store.
/// Any existing fd with the same name is removed first.
pub fn notify_push_fd(fd: RawFd, name: &str) -> io::Result<()> {
    let _ = notify_remove_fd_warn(name);
    send_fd_datagram(build_fdstore_push_message(name).as_bytes(), &[fd])
}

/// Push an unnamed file descriptor into the service manager's fd store.
pub fn notify_store_fd(fd: RawFd) -> io::Result<()> {
    send_fd_datagram(build_fdstore_store_message().as_bytes(), &[fd])
}

/// Push a file descriptor into the fd store (format-string variant).
pub fn notify_push_fdf(fd: RawFd, args: fmt::Arguments<'_>) -> io::Result<()> {
    notify_push_fd(fd, &args.to_string())
}

// ── Reloading notification ────────────────────────────────────────────────

/// Notify the service manager that the service is reloading with a default status.
pub fn notify_reloading() -> io::Result<()> {
    notify_reloading_full(Some("Reloading configuration..."))
}

/// Notify the service manager that the service is reloading with a custom status.
pub fn notify_reloading_full(status: Option<&str>) -> io::Result<()> {
    send_datagram(build_reloading_message(status).as_bytes())
}

// ── Cleanup helpers ───────────────────────────────────────────────────────

/// Send a start notification and return the stop message for deferred sending.
pub fn notify_start<'a>(start: Option<&str>, stop: Option<&'a str>) -> Option<&'a str> {
    if let Some(msg) = start {
        let _ = sd_notify_preserve_environment(msg);
    }
    stop
}

// ── Internal: fd-passing via sendmsg ──────────────────────────────────────

fn send_fd_datagram(message: &[u8], fds: &[RawFd]) -> io::Result<()> {
    // Match the kernel's SCM_RIGHTS limit before sizing the ancillary buffer.
    // This also makes all byte-count conversions below trivially bounded.
    const SCM_MAX_FD: usize = 253;
    if fds.len() > SCM_MAX_FD {
        return Err(io::Error::from_raw_os_error(libc::E2BIG));
    }
    let (mut address, address_length) = notify_unix_socket_address()?;

    // SAFETY: the validated address, iov, and ancillary buffers remain live
    // for this synchronous sendmsg call; CloseGuard owns the socket.
    unsafe {
        let sock = libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }
        let _guard = CloseGuard(sock);

        let iov = libc::iovec {
            iov_base: message.as_ptr() as *mut libc::c_void,
            iov_len: message.len(),
        };

        let fds_byte_len = std::mem::size_of::<RawFd>() * fds.len();
        let cmsg_space = libc::CMSG_SPACE(fds_byte_len as u32) as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];

        let mut hdr: libc::msghdr = std::mem::zeroed();
        hdr.msg_name = (&mut address as *mut libc::sockaddr_un).cast::<libc::c_void>();
        hdr.msg_namelen = address_length;
        hdr.msg_iov = &iov as *const _ as *mut _;
        hdr.msg_iovlen = 1;

        if !fds.is_empty() {
            hdr.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
            hdr.msg_controllen = cmsg_buf.len() as u32;

            let cmsg = libc::CMSG_FIRSTHDR(&hdr);
            if cmsg.is_null() {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(fds_byte_len as u32);
            let dst = libc::CMSG_DATA(cmsg) as *mut RawFd;
            std::ptr::copy_nonoverlapping(fds.as_ptr(), dst, fds.len());
        }

        let r = libc::sendmsg(sock, &hdr, libc::MSG_NOSIGNAL);
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        if r as usize != message.len() {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
    }

    Ok(())
}

struct CloseGuard(RawFd);

impl Drop for CloseGuard {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: close(2) is a POSIX syscall.
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::TestEnvironment;

    #[test]
    fn test_notify_ready_message() {
        assert_eq!(
            NOTIFY_READY_MESSAGE,
            "READY=1\nSTATUS=Processing requests..."
        );
    }

    #[test]
    fn test_notify_stopping_message() {
        assert_eq!(
            NOTIFY_STOPPING_MESSAGE,
            "STOPPING=1\nSTATUS=Shutting down..."
        );
    }

    #[test]
    fn test_build_fdstore_remove_message() {
        let msg = build_fdstore_remove_message("myfd");
        assert_eq!(msg, "FDSTOREREMOVE=1\nFDNAME=myfd");
    }

    #[test]
    fn test_build_fdstore_remove_message_empty() {
        let msg = build_fdstore_remove_message("");
        assert_eq!(msg, "FDSTOREREMOVE=1\nFDNAME=");
    }

    #[test]
    fn test_build_fdstore_push_message() {
        let msg = build_fdstore_push_message("stored");
        assert_eq!(msg, "FDSTORE=1\nFDNAME=stored");
    }

    #[test]
    fn test_build_fdstore_store_message() {
        assert_eq!(build_fdstore_store_message(), "FDSTORE=1");
    }

    #[test]
    fn test_build_reloading_message_with_status() {
        let msg = build_reloading_message(Some("loading"));
        assert_eq!(msg, "RELOADING=1\nMONOTONIC_USEC=0\nSTATUS=loading");
    }

    #[test]
    fn test_build_reloading_message_none() {
        let msg = build_reloading_message(None);
        assert_eq!(msg, "RELOADING=1\nMONOTONIC_USEC=0");
    }

    #[test]
    fn test_notify_start_returns_stop() {
        let stop = notify_start(None, Some("STOPPING=1"));
        assert_eq!(stop, Some("STOPPING=1"));
    }

    #[test]
    fn test_notify_start_with_start_message() {
        let stop = notify_start(Some("READY=1"), Some("STOPPING=1"));
        assert_eq!(stop, Some("STOPPING=1"));
    }

    #[test]
    fn test_notify_start_both_none() {
        let stop = notify_start(None, None);
        assert!(stop.is_none());
    }

    #[test]
    fn test_notify_remove_fd_warn_no_socket() {
        let r = notify_remove_fd_warn("test");
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_notify_reloading_no_socket() {
        let r = notify_reloading();
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_notify_reloading_full_no_socket() {
        let r = notify_reloading_full(Some("custom"));
        assert!(r.is_err());
    }

    #[test]
    fn test_close_and_notify_warn_negative_fd_no_name() {
        let r = close_and_notify_warn(-1, None);
        assert!(r.is_ok());
    }

    #[test]
    fn test_close_and_notify_warn_negative_fd_with_name() {
        let r = close_and_notify_warn(-1, Some("foo"));
        assert!(r.is_ok());
    }

    #[test]
    fn test_notify_push_fd_no_socket() {
        let r = notify_push_fd(42, "bar");
        assert!(r.is_err());
    }

    #[test]
    fn test_notify_store_fd_no_socket() {
        let r = notify_store_fd(42);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_notify_remove_fd_warnf_format() {
        let r = notify_remove_fd_warnf(format_args!("fd-{}", 3));
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn test_notify_push_fdf_format() {
        let r = notify_push_fdf(99, format_args!("item-{}", "test"));
        assert!(r.is_err());
    }

    #[test]
    fn test_sd_notify_no_socket() {
        let r = sd_notify_preserve_environment("READY=1");
        assert_eq!(r.unwrap(), false);
    }

    #[test]
    fn test_sd_notify_unset_env_no_socket() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        environment.remove("NOTIFY_SOCKET");
        // SAFETY: TestEnvironment serializes process-environment mutation for
        // the full duration of this test.
        let r = unsafe { sd_notify(true, "READY=1") };
        assert_eq!(r.unwrap(), false);
    }

    #[test]
    fn test_sd_notify_sends_before_unsetting_environment() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe { TestEnvironment::lock() };
        let socket_path =
            std::env::temp_dir().join(format!("systemd-daemon-util-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket_path);
        let socket = UnixDatagram::bind(&socket_path).unwrap();
        environment.set("NOTIFY_SOCKET", &socket_path);

        // SAFETY: TestEnvironment serializes process-environment mutation for
        // the full duration of this test.
        assert!(unsafe { sd_notify(true, "READY=1") }.unwrap());
        assert!(env::var_os("NOTIFY_SOCKET").is_none());

        let mut message = [0u8; 16];
        let size = socket.recv(&mut message).unwrap();
        assert_eq!(&message[..size], b"READY=1");
        let _ = std::fs::remove_file(socket_path);
    }
}
