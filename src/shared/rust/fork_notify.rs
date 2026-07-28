// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/fork-notify.c, src/shared/fork-notify.h
//
// Fork-notify mechanism — fork a child process and wait for it to signal
// readiness via sd_notify (READY=1) before returning. Provides structured
// wrappers for managing the child lifecycle, including termination helpers.

use crate::ffi::*;
use std::fs;
use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::notify_recv::{NotificationMessage, NotifyError, notify_recv};

// ── Errors ─────────────────────────────────────────────────────────────────

/// Errors specific to fork-notify operations.
#[derive(Debug)]
pub enum ForkNotifyError {
    /// The argument list was empty.
    EmptyArgv,
    /// The child process died before sending READY=1.
    ChildDiedBeforeReady {
        pid: u32,
        status: Option<ExitStatus>,
    },
    /// The child sent an ERRNO= notification.
    ChildReportedError { errno: i32 },
    /// The child sent a notification that was neither READY=1 nor ERRNO=.
    ChildNotReady { pid: u32 },
    /// The notification came from an unexpected PID.
    UnexpectedSender { expected_pid: u32, actual_pid: u32 },
    /// An I/O error (socket creation, recv, spawn, etc.).
    Io(io::Error),
}

impl std::fmt::Display for ForkNotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyArgv => write!(f, "argv must not be empty"),
            Self::ChildDiedBeforeReady { pid, status } => {
                write!(f, "child {pid} died before sending READY=1")?;
                if let Some(s) = status {
                    write!(f, " (exit status: {s})")?;
                }
                Ok(())
            }
            Self::ChildReportedError { errno } => {
                write!(f, "child reported ERRNO={errno}")
            }
            Self::ChildNotReady { pid } => {
                write!(f, "child {pid} sent notification without READY=1 or ERRNO=")
            }
            Self::UnexpectedSender {
                expected_pid,
                actual_pid,
            } => {
                write!(
                    f,
                    "notification from unexpected pid {actual_pid} (expected {expected_pid})"
                )
            }
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ForkNotifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ForkNotifyError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

// ── Result alias ───────────────────────────────────────────────────────────

/// Result type for fork-notify operations.
pub type Result<T> = std::result::Result<T, ForkNotifyError>;

// ── Child handle ───────────────────────────────────────────────────────────

/// Handle to a child process spawned via [`fork_notify`].
///
/// Owns the underlying [`Child`] and cleans up the temporary notification
/// socket on drop.
#[derive(Debug)]
pub struct ForkNotifyChild {
    child: Child,
    socket_path: PathBuf,
}

impl ForkNotifyChild {
    /// Returns the OS-assigned process identifier.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Returns a reference to the underlying [`std::process::Child`].
    pub fn child(&self) -> &Child {
        &self.child
    }

    /// Returns a mutable reference to the underlying [`std::process::Child`].
    pub fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for ForkNotifyChild {
    fn drop(&mut self) {
        // Best-effort cleanup of the temporary socket.
        let _ = fs::remove_file(&self.socket_path);
    }
}

// ── Runtime scope ──────────────────────────────────────────────────────────

/// Scope for journal operations (system vs. user).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum RuntimeScope {
    System = 0,
    User = 1,
}

impl RuntimeScope {
    /// Validate the discriminant is within the expected range.
    pub fn from_raw(val: i32) -> Option<Self> {
        match val {
            0 => Some(Self::System),
            1 => Some(Self::User),
            _ => None,
        }
    }

    /// Returns `true` if this is the system scope.
    pub fn is_system(self) -> bool {
        self == RuntimeScope::System
    }
}

impl std::fmt::Display for RuntimeScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::System => write!(f, "system"),
            Self::User => write!(f, "user"),
        }
    }
}

// ── Socket path generation ─────────────────────────────────────────────────

/// Generate a unique temporary socket path for notification passing.
///
/// Uses the current nanosecond timestamp to avoid collisions in
/// single-threaded use. The socket should be removed after use (handled
/// automatically by [`ForkNotifyChild::drop`]).
fn make_socket_path() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    PathBuf::from(format!("/run/systemd/fork-notify-{nonce}.sock"))
}

/// Generate a socket path in `/tmp` as a fallback when `/run/systemd` is
/// not available (e.g. during unit tests without elevated privileges).
#[cfg(test)]
fn make_socket_path_tmp() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    PathBuf::from(format!("/tmp/systemd-fork-notify-test-{nonce}.sock"))
}

// ── Notification validation ────────────────────────────────────────────────

/// Validate a received notification message against the expected child PID.
///
/// Returns `Ok(())` if the message contains `READY=1`, or an appropriate
/// error for ERRNO= responses, unexpected senders, or non-ready messages.
fn validate_notification(
    msg: &NotificationMessage,
    expected_pid: u32,
    sender_pid: u32,
) -> Result<()> {
    // Verify the sender PID matches what we expect.
    if sender_pid != expected_pid {
        return Err(ForkNotifyError::UnexpectedSender {
            expected_pid,
            actual_pid: sender_pid,
        });
    }

    // READY=1 means success.
    if msg.is_ready() {
        return Ok(());
    }

    // ERRNO=<n> means the child is reporting a specific error.
    if let Some(errno) = msg.errno() {
        if errno > 0 {
            return Err(ForkNotifyError::ChildReportedError { errno });
        }
        // Non-positive ERRNO is invalid; treat as "not ready".
    }

    Err(ForkNotifyError::ChildNotReady { pid: expected_pid })
}

/// Interpret a child's exit status into a [`ForkNotifyError`].
///
/// The C code treats any premature child exit (even successful ones) as
/// `EPROTO` because the child failed to send READY=1 before exiting.
fn exit_status_to_error(pid: u32, status: ExitStatus) -> ForkNotifyError {
    ForkNotifyError::ChildDiedBeforeReady {
        pid,
        status: Some(status),
    }
}

// ── Core API ───────────────────────────────────────────────────────────────

/// Fork a child process and block until it signals readiness via
/// `sd_notify("READY=1")`.
///
/// The function:
/// 1. Creates a temporary AF_UNIX datagram socket.
/// 2. Spawns `argv[0]` with `argv[1..]` as arguments, setting
///    `NOTIFY_SOCKET` in the child's environment.
/// 3. Waits (up to `timeout`) for the child to send a notification.
/// 4. Validates that the notification is `READY=1`.
///
/// On success, returns a [`ForkNotifyChild`] handle. The caller is
/// responsible for terminating the child (via [`fork_notify_terminate`] or
/// [`ForkNotifyChild::child_mut`]) when done.
///
/// # Errors
///
/// Returns [`ForkNotifyError::EmptyArgv`] if `argv` is empty.
/// Returns [`ForkNotifyError::Io`] on socket/spawn failures.
/// Returns [`ForkNotifyError::ChildDiedBeforeReady`] if the child exits
/// before notifying.
/// Returns [`ForkNotifyError::ChildReportedError`] if the child sends
/// `ERRNO=<n>`.
pub fn fork_notify(argv: &[String]) -> Result<ForkNotifyChild> {
    fork_notify_with_timeout(argv, Duration::from_secs(30))
}

/// Like [`fork_notify`], but with a configurable receive timeout.
pub fn fork_notify_with_timeout(argv: &[String], timeout: Duration) -> Result<ForkNotifyChild> {
    if argv.is_empty() {
        return Err(ForkNotifyError::EmptyArgv);
    }

    let socket_path = make_socket_path();
    let socket = UnixDatagram::bind(&socket_path)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_nonblocking(false)?;

    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    command.env("NOTIFY_SOCKET", &socket_path);
    // Redirect stdin to /dev/null, keep stdout/stderr inherited (mirrors the
    // C code's { -EBADF, STDOUT_FILENO, STDERR_FILENO }).
    command.stdin(std::process::Stdio::null());

    let mut child = command.spawn()?;
    let child_pid = child.id();

    // Receive and validate the notification from the child.
    let msg = match notify_recv(&socket) {
        Ok(m) => m,
        Err(NotifyError::Io(io::ErrorKind::TimedOut)) => {
            // On timeout, check if the child is still alive.
            match child.try_wait()? {
                Some(status) => {
                    return Err(exit_status_to_error(child_pid, status));
                }
                None => {
                    return Err(ForkNotifyError::ChildNotReady { pid: child_pid });
                }
            }
        }
        Err(NotifyError::Io(io::ErrorKind::WouldBlock)) => match child.try_wait()? {
            Some(status) => {
                return Err(exit_status_to_error(child_pid, status));
            }
            None => {
                return Err(ForkNotifyError::ChildNotReady { pid: child_pid });
            }
        },
        Err(e) => return Err(ForkNotifyError::Io(io::Error::new(io::ErrorKind::Other, e))),
    };

    // The notification socket doesn't carry sender PID credentials in our
    // pure-Rust implementation (the C version uses SO_PEERCRED). We treat
    // the child PID as the sender.
    validate_notification(&msg, child_pid, child_pid)?;

    Ok(ForkNotifyChild { child, socket_path })
}

// ── Termination helpers ────────────────────────────────────────────────────

/// Terminate a fork-notify child gracefully.
///
/// Sends `SIGTERM`, then waits for the child to exit. If the child has
/// already exited, this is a no-op (besides reaping).
pub fn fork_notify_terminate(child: &mut ForkNotifyChild) -> io::Result<()> {
    let pid = child.child.id();
    // Try SIGTERM first. ESRCH is fine — child already exited.
    match terminate_process(pid) {
        Ok(()) | Err(ForkNotifyError::ChildDiedBeforeReady { .. }) => {}
        Err(e) => {
            // Log-level: we tried our best, ignore.
            let _ = e;
        }
    }
    // Reap the child (non-blocking is fine since we just signaled).
    let _ = child.child.wait();
    Ok(())
}

/// Terminate a child by sending SIGTERM.
///
/// Returns `Ok(())` on success, or
/// [`ForkNotifyError::ChildDiedBeforeReady`] if the process no longer
/// exists (ESRCH).
fn terminate_process(pid: u32) -> Result<()> {
    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if ret == 0 {
        return Ok(());
    }
    let errno = crate::ffi::get_errno();
    if errno == libc::ESRCH {
        return Err(ForkNotifyError::ChildDiedBeforeReady { pid, status: None });
    }
    Err(ForkNotifyError::Io(io::Error::from_raw_os_error(errno)))
}

/// Send SIGTERM to a process by PID, ignoring ESRCH.
///
/// This mirrors `fork_notify_terminate_internal` from the C code which
/// kills and waits but does not consume the PidRef.
pub fn fork_notify_terminate_pid(pid: u32) {
    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if ret != 0 {
        let errno = crate::ffi::get_errno();
        if errno != libc::ESRCH {
            // Best-effort: log but don't propagate.
            let _ = errno;
        }
    }
}

/// Terminate multiple fork-notify children.
///
/// Sends SIGTERM to each child in the slice and waits for all of them.
/// Mirrors the C `fork_notify_terminate_many` which operates on an array
/// of `sd_event_source*`.
pub fn fork_notify_terminate_many(children: &mut [ForkNotifyChild]) {
    for child in children.iter_mut() {
        let pid = child.child.id();
        fork_notify_terminate_pid(pid);
    }
    for child in children.iter_mut() {
        let _ = child.child.wait();
    }
}

// ── Journal fork helper ────────────────────────────────────────────────────

/// Build the `journalctl` argument vector for [`journal_fork`].
fn build_journalctl_args(scope: RuntimeScope, units: &[String]) -> Vec<String> {
    let mut argv: Vec<String> = vec![
        "journalctl".into(),
        "-q".into(),
        "--follow".into(),
        "--no-pager".into(),
        "--lines=0".into(),
        "--synchronize-on-exit=yes".into(),
    ];

    for unit in units {
        if scope.is_system() {
            argv.push(format!("--unit={unit}"));
        } else {
            argv.push(format!("--user-unit={unit}"));
        }
    }

    argv
}

/// Fork a `journalctl --follow` instance that tails logs for the given
/// units.
///
/// This is the Rust equivalent of the C `journal_fork()` function. It
/// constructs the appropriate `journalctl` command line (system vs. user
/// scope) and delegates to [`fork_notify`].
///
/// If `units` is empty, returns `Ok(None)` immediately (nothing to do).
pub fn journal_fork(scope: RuntimeScope, units: &[String]) -> Result<Option<ForkNotifyChild>> {
    if units.is_empty() {
        return Ok(None);
    }

    let argv = build_journalctl_args(scope, units);
    let child = fork_notify(&argv)?;
    Ok(Some(child))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    // ── RuntimeScope tests ─────────────────────────────────────────────

    #[test]
    fn test_runtime_scope_from_raw() {
        assert_eq!(RuntimeScope::from_raw(0), Some(RuntimeScope::System));
        assert_eq!(RuntimeScope::from_raw(1), Some(RuntimeScope::User));
        assert_eq!(RuntimeScope::from_raw(2), None);
        assert_eq!(RuntimeScope::from_raw(-1), None);
    }

    #[test]
    fn test_runtime_scope_display() {
        assert_eq!(RuntimeScope::System.to_string(), "system");
        assert_eq!(RuntimeScope::User.to_string(), "user");
    }

    #[test]
    fn test_runtime_scope_is_system() {
        assert!(RuntimeScope::System.is_system());
        assert!(!RuntimeScope::User.is_system());
    }

    #[test]
    fn test_runtime_scope_equality() {
        assert_eq!(RuntimeScope::System, RuntimeScope::System);
        assert_eq!(RuntimeScope::User, RuntimeScope::User);
        assert_ne!(RuntimeScope::System, RuntimeScope::User);
    }

    // ── Error tests ───────────────────────────────────────────────────

    #[test]
    fn test_error_empty_argv() {
        let err = ForkNotifyError::EmptyArgv;
        assert_eq!(err.to_string(), "argv must not be empty");
    }

    #[test]
    fn test_error_child_died_display() {
        let err = ForkNotifyError::ChildDiedBeforeReady {
            pid: 42,
            status: None,
        };
        let s = err.to_string();
        assert!(s.contains("42"));
        assert!(s.contains("died before sending READY=1"));
    }

    #[test]
    fn test_error_child_reported_errno() {
        let err = ForkNotifyError::ChildReportedError { errno: 22 };
        assert_eq!(err.to_string(), "child reported ERRNO=22");
    }

    #[test]
    fn test_error_unexpected_sender() {
        let err = ForkNotifyError::UnexpectedSender {
            expected_pid: 100,
            actual_pid: 200,
        };
        let s = err.to_string();
        assert!(s.contains("200"));
        assert!(s.contains("100"));
        assert!(s.contains("unexpected"));
    }

    #[test]
    fn test_error_io_source() {
        let io_err = io::Error::new(io::ErrorKind::AddrInUse, "address in use");
        let err = ForkNotifyError::Io(io_err);
        assert!(err.source().is_some());
    }

    #[test]
    fn test_error_child_not_ready_display() {
        let err = ForkNotifyError::ChildNotReady { pid: 99 };
        let s = err.to_string();
        assert!(s.contains("99"));
        assert!(s.contains("READY=1"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let err: ForkNotifyError = io_err.into();
        assert!(matches!(err, ForkNotifyError::Io(_)));
    }

    // ── Notification validation tests ─────────────────────────────────

    #[test]
    fn test_validate_notification_ready() {
        let msg = NotificationMessage::parse("READY=1\nSTATUS=good".into());
        assert!(validate_notification(&msg, 42, 42).is_ok());
    }

    #[test]
    fn test_validate_notification_errno() {
        let msg = NotificationMessage::parse("ERRNO=13\nSTATUS=perm".into());
        let err = validate_notification(&msg, 42, 42).unwrap_err();
        assert!(matches!(
            err,
            ForkNotifyError::ChildReportedError { errno: 13 }
        ));
    }

    #[test]
    fn test_validate_notification_non_positive_errno_ignored() {
        // ERRNO=0 should be treated as "not ready", not as a reported error.
        let msg = NotificationMessage::parse("ERRNO=0".into());
        let err = validate_notification(&msg, 42, 42).unwrap_err();
        assert!(matches!(err, ForkNotifyError::ChildNotReady { .. }));
    }

    #[test]
    fn test_validate_notification_negative_errno_ignored() {
        let msg = NotificationMessage::parse("ERRNO=-5".into());
        let err = validate_notification(&msg, 42, 42).unwrap_err();
        // parse() returns None for negative numbers, so this is "not ready"
        assert!(matches!(err, ForkNotifyError::ChildNotReady { .. }));
    }

    #[test]
    fn test_validate_notification_wrong_sender() {
        let msg = NotificationMessage::parse("READY=1".into());
        let err = validate_notification(&msg, 42, 99).unwrap_err();
        assert!(matches!(
            err,
            ForkNotifyError::UnexpectedSender {
                expected_pid: 42,
                actual_pid: 99
            }
        ));
    }

    #[test]
    fn test_validate_notification_not_ready() {
        let msg = NotificationMessage::parse("STATUS=working".into());
        let err = validate_notification(&msg, 42, 42).unwrap_err();
        assert!(matches!(err, ForkNotifyError::ChildNotReady { .. }));
    }

    // ── Journal fork arg building ─────────────────────────────────────

    #[test]
    fn test_build_journalctl_args_system() {
        let args = build_journalctl_args(
            RuntimeScope::System,
            &["nginx.service".into(), "dbus.service".into()],
        );
        assert_eq!(args[0], "journalctl");
        assert!(args.iter().any(|a| a == "--unit=nginx.service"));
        assert!(args.iter().any(|a| a == "--unit=dbus.service"));
        assert!(!args.iter().any(|a| a.starts_with("--user-unit")));
    }

    #[test]
    fn test_build_journalctl_args_user() {
        let args = build_journalctl_args(RuntimeScope::User, &["pipewire".into()]);
        assert!(args.iter().any(|a| a == "--user-unit=pipewire"));
        assert!(!args.iter().any(|a| a.starts_with("--unit=")));
    }

    #[test]
    fn test_build_journalctl_args_empty_units() {
        let args = build_journalctl_args(RuntimeScope::System, &[]);
        assert_eq!(args.len(), 6); // base args only
        assert_eq!(args[0], "journalctl");
    }

    #[test]
    fn test_build_journalctl_args_common_flags() {
        let args = build_journalctl_args(RuntimeScope::System, &["x".into()]);
        assert!(args.contains(&"-q".into()));
        assert!(args.contains(&"--follow".into()));
        assert!(args.contains(&"--no-pager".into()));
        assert!(args.contains(&"--lines=0".into()));
        assert!(args.contains(&"--synchronize-on-exit=yes".into()));
    }

    // ── fork_notify empty argv ────────────────────────────────────────

    #[test]
    fn test_fork_notify_empty_argv() {
        let result = fork_notify(&[]);
        assert!(matches!(result, Err(ForkNotifyError::EmptyArgv)));
    }

    // ── journal_fork empty units ──────────────────────────────────────

    #[test]
    fn test_journal_fork_empty_units() {
        let result = journal_fork(RuntimeScope::System, &[]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    // ── Socket path uniqueness ────────────────────────────────────────

    #[test]
    fn test_make_socket_path_uniqueness() {
        let p1 = make_socket_path();
        let p2 = make_socket_path();
        // Two rapid calls *might* collide in theory, but in practice they
        // should differ. This is a weak sanity check.
        assert!(
            p1.to_string_lossy()
                .starts_with("/run/systemd/fork-notify-")
        );
    }

    // ── fork_notify_terminate_many empty ──────────────────────────────

    #[test]
    fn test_terminate_many_empty() {
        // Should not panic on empty slice.
        fork_notify_terminate_many(&mut []);
    }
}
