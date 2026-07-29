// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/daemon-util.c, src/shared/daemon-util.h,
// src/libsystemd/sd-daemon/sd-daemon.c, src/systemd/sd-daemon.h
//
// Daemon notification utilities for communicating with the systemd service manager
// via the sd_notify protocol (NOTIFY_SOCKET).

use std::env;
use std::ffi::CString;
use std::fmt;
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
#[cfg(test)]
use std::os::unix::net::UnixDatagram;
use std::sync::OnceLock;

// SAFETY: This declaration exactly matches sd-daemon.h. The safe wrappers
// below provide a live C string, a bounded descriptor array (or NULL for an
// empty one), and retain both for the duration of the synchronous call.
unsafe extern "C" {
    #[link_name = "sd_pid_notify_with_fds"]
    fn c_sd_pid_notify_with_fds(
        pid: libc::pid_t,
        unset_environment: libc::c_int,
        state: *const libc::c_char,
        fds: *const libc::c_int,
        n_fds: libc::c_uint,
    ) -> libc::c_int;
}

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

fn build_reloading_message(status: Option<&str>, monotonic_usec: u64) -> String {
    match status {
        Some(s) => format!("RELOADING=1\nMONOTONIC_USEC={monotonic_usec}\nSTATUS={s}"),
        None => format!("RELOADING=1\nMONOTONIC_USEC={monotonic_usec}"),
    }
}

fn invalid_input_error() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}

/// Reject values that cannot be represented by the C string APIs this port
/// mirrors. In particular, C would silently truncate at an embedded NUL.
fn validate_c_string(value: &str) -> io::Result<()> {
    if value.as_bytes().contains(&0) {
        return Err(invalid_input_error());
    }
    Ok(())
}

fn monotonic_usec_from_timespec(timestamp: libc::timespec) -> io::Result<u64> {
    if timestamp.tv_sec < 0 || !(0..1_000_000_000).contains(&timestamp.tv_nsec) {
        return Err(invalid_input_error());
    }

    let seconds = u64::try_from(timestamp.tv_sec).map_err(|_| invalid_input_error())?;
    let nanoseconds = u64::try_from(timestamp.tv_nsec).map_err(|_| invalid_input_error())?;
    seconds
        .checked_mul(1_000_000)
        .and_then(|usec| usec.checked_add(nanoseconds / 1_000))
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))
}

/// Return the `CLOCK_MONOTONIC` timestamp in microseconds used by sd_notify.
fn monotonic_usec_now() -> io::Result<u64> {
    let mut timestamp = MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: timestamp points to sufficient output storage for clock_gettime,
    // and CLOCK_MONOTONIC is exactly the clock used by daemon-util.c.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, timestamp.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful clock_gettime initialized timestamp completely.
    monotonic_usec_from_timespec(unsafe { timestamp.assume_init() })
}

/// C's safe_atou(..., base=0) behavior, limited to the boolean distinction
/// needed for FDSTORE. It accepts C/Python integer prefixes and rejects any
/// trailing byte, just as the C parser does.
fn parse_fdstore_value(value: &[u8]) -> Option<u32> {
    const WHITESPACE: &[u8] = b" \t\n\r\x0b\x0c";

    let mut value = value;
    while let Some(byte) = value.first() {
        if !WHITESPACE.contains(byte) {
            break;
        }
        value = &value[1..];
    }

    let negative = value.first() == Some(&b'-');
    let positive = value.first() == Some(&b'+');
    if negative || positive {
        value = &value[1..];
    }

    let (base, digits) = if !negative
        && !positive
        && value.len() >= 2
        && value[0] == b'0'
        && matches!(value[1], b'b' | b'B')
    {
        (2, &value[2..])
    } else if !negative
        && !positive
        && value.len() >= 2
        && value[0] == b'0'
        && matches!(value[1], b'o' | b'O')
    {
        (8, &value[2..])
    } else if value.len() >= 2 && value[0] == b'0' && matches!(value[1], b'x' | b'X') {
        (16, &value[2..])
    } else if value.len() > 1 && value[0] == b'0' {
        (8, value)
    } else {
        (10, value)
    };

    if digits.is_empty() {
        return None;
    }

    let mut parsed = 0_u32;
    for &byte in digits {
        let digit = match byte {
            b'0'..=b'9' => (byte - b'0') as u32,
            b'a'..=b'f' => (byte - b'a' + 10) as u32,
            b'A'..=b'F' => (byte - b'A' + 10) as u32,
            _ => return None,
        };
        if digit >= base {
            return None;
        }
        parsed = parsed.checked_mul(base)?.checked_add(digit)?;
    }

    if negative && parsed != 0 {
        return None;
    }
    Some(parsed)
}

/// Determine whether systemd started this process with an FD store.
///
/// The result is cached for the process lifetime, mirroring C's static cache.
pub fn fdstore_detected() -> bool {
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| {
        env::var_os("FDSTORE")
            .as_deref()
            .and_then(|value| parse_fdstore_value(value.as_bytes()))
            .is_some_and(|value| value > 0)
    })
}

// ── Core sd_notify ────────────────────────────────────────────────────────

fn send_datagram(payload: &[u8]) -> io::Result<()> {
    send_fd_datagram(payload, &[])
}

/// Send a notification without changing the process environment.
pub fn sd_notify_preserve_environment(state: &str) -> io::Result<bool> {
    validate_c_string(state)?;
    notify_with_fds(state.as_bytes(), &[])
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
    validate_c_string(name)?;
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
    validate_c_string(name)?;
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
    if let Some(status) = status {
        validate_c_string(status)?;
    }
    let monotonic_usec = monotonic_usec_now()?;
    send_datagram(build_reloading_message(status, monotonic_usec).as_bytes())
}

// ── Cleanup helpers ───────────────────────────────────────────────────────

/// Send a start notification and return the stop message for deferred sending.
pub fn notify_start<'a>(start: Option<&str>, stop: Option<&'a str>) -> Option<&'a str> {
    if let Some(msg) = start {
        let _ = sd_notify_preserve_environment(msg);
    }
    stop
}

// ── Internal: C-authoritative notification transport ──────────────────────

fn send_fd_datagram(message: &[u8], fds: &[RawFd]) -> io::Result<()> {
    notify_with_fds(message, fds).map(|_| ())
}

/// Delegate the transport boundary to sd-daemon.c.
///
/// This intentionally keeps AF_UNIX/AF_VSOCK parsing, socket-type fallback,
/// credential and descriptor ancillary data, partial stream writes, and VSOCK
/// shutdown/EOF behavior under their single C authority.
fn notify_with_fds(message: &[u8], fds: &[RawFd]) -> io::Result<bool> {
    // Match the kernel's SCM_RIGHTS limit before sizing the ancillary buffer.
    const SCM_MAX_FD: usize = 253;
    if fds.len() > SCM_MAX_FD {
        return Err(io::Error::from_raw_os_error(libc::E2BIG));
    }
    if fds.iter().any(|fd| *fd < 0) {
        return Err(invalid_input_error());
    }
    let message = CString::new(message).map_err(|_| invalid_input_error())?;
    let n_fds = libc::c_uint::try_from(fds.len()).map_err(|_| invalid_input_error())?;
    let fds = if fds.is_empty() {
        std::ptr::null()
    } else {
        fds.as_ptr()
    };

    // SAFETY: message is a live NUL-terminated C string, fds is either NULL
    // for zero elements or points to n_fds live integers, and false preserves
    // the process environment. The call does not retain either pointer.
    let result = unsafe { c_sd_pid_notify_with_fds(0, 0, message.as_ptr(), fds, n_fds) };
    if result < 0 {
        Err(io::Error::from_raw_os_error(-result))
    } else {
        Ok(result > 0)
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
        let msg = build_reloading_message(Some("loading"), 12_345_678);
        assert_eq!(msg, "RELOADING=1\nMONOTONIC_USEC=12345678\nSTATUS=loading");
    }

    #[test]
    fn test_build_reloading_message_none() {
        let msg = build_reloading_message(None, 42);
        assert_eq!(msg, "RELOADING=1\nMONOTONIC_USEC=42");
    }

    #[test]
    fn test_monotonic_usec_from_timespec() {
        assert_eq!(
            monotonic_usec_from_timespec(libc::timespec {
                tv_sec: 12,
                tv_nsec: 345_678_999,
            })
            .unwrap(),
            12_345_678
        );
    }

    #[test]
    fn test_monotonic_usec_rejects_invalid_timespec() {
        for timestamp in [
            libc::timespec {
                tv_sec: -1,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: 0,
                tv_nsec: -1,
            },
            libc::timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000_000,
            },
        ] {
            assert_eq!(
                monotonic_usec_from_timespec(timestamp)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EINVAL)
            );
        }
    }

    #[test]
    fn test_fdstore_value_parser_matches_safe_atou_base_zero() {
        for value in [
            &b"1"[..],
            &b" 0x10"[..],
            &b"010"[..],
            &b"0o10"[..],
            &b"0b10"[..],
        ] {
            assert!(parse_fdstore_value(value).is_some_and(|value| value > 0));
        }
        for value in [
            &b"0"[..],
            &b"-0"[..],
            &b""[..],
            &b"garbage"[..],
            &b"+0b1"[..],
            &b"1 "[..],
            &b"-1"[..],
            &b"0x1_0"[..],
        ] {
            assert!(!parse_fdstore_value(value).is_some_and(|value| value > 0));
        }
    }

    #[test]
    fn test_validate_c_string_rejects_embedded_nul() {
        assert_eq!(
            validate_c_string("field\0injection")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
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
        assert!(r.is_ok());
    }

    #[test]
    fn test_notify_reloading_no_socket() {
        let r = notify_reloading();
        assert!(r.is_ok());
    }

    #[test]
    fn test_notify_reloading_full_no_socket() {
        let r = notify_reloading_full(Some("custom"));
        assert!(r.is_ok());
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
        assert!(r.is_ok());
    }

    #[test]
    fn test_notify_store_fd_rejects_negative_descriptor() {
        assert_eq!(
            notify_store_fd(-1).unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
    }

    #[test]
    fn test_notify_store_fd_no_socket() {
        let r = notify_store_fd(42);
        assert!(r.is_ok());
    }

    #[test]
    fn test_notify_remove_fd_warnf_format() {
        let r = notify_remove_fd_warnf(format_args!("fd-{}", 3));
        assert!(r.is_ok());
    }

    #[test]
    fn test_notify_push_fdf_format() {
        let r = notify_push_fdf(99, format_args!("item-{}", "test"));
        assert!(r.is_ok());
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
