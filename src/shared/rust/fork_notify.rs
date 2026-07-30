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
use std::mem::{self, MaybeUninit};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::notify_recv::{NOTIFY_BUFFER_MAX, NOTIFY_FD_MAX, NotificationMessage};

// ── Errors ─────────────────────────────────────────────────────────────────

/// Errors specific to fork-notify operations.
#[derive(Debug)]
pub enum ForkNotifyError {
    /// The argument list was empty.
    EmptyArgv,
    /// The supplied PID cannot safely be passed to `kill(2)`.
    InvalidPid { pid: u32 },
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
            Self::InvalidPid { pid } => write!(f, "invalid process identifier: {pid}"),
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

/// Removes a notification socket pathname unless ownership is transferred to
/// a successfully returned [`ForkNotifyChild`].
///
/// Unlike an unnamed socket, binding an AF_UNIX pathname creates a filesystem
/// entry.  Keep that entry under RAII even while the process is still being
/// spawned, so errors before the child handle is constructed cannot leave a
/// stale, potentially colliding socket behind.
struct SocketPathCleanup {
    path: PathBuf,
    keep: bool,
}

impl SocketPathCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path, keep: false }
    }

    fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for SocketPathCleanup {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
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

/// Per-process disambiguator for notification socket pathnames.
///
/// The timestamp prevents collisions with stale sockets from previous
/// processes, while this counter makes concurrent calls from one process
/// distinct even on clocks with coarse resolution.
static NEXT_SOCKET_ID: AtomicU64 = AtomicU64::new(0);

/// Generate a unique temporary socket path for notification passing.
///
/// Uses the PID, a timestamp, and a process-local counter to avoid collisions.
/// The socket should be removed after use (handled automatically by
/// [`ForkNotifyChild::drop`]).
fn make_socket_path() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let id = NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(format!(
        "/run/systemd/fork-notify-{}-{nonce}-{id}.sock",
        std::process::id()
    ))
}

/// Generate a socket path in `/tmp` as a fallback when `/run/systemd` is
/// not available (e.g. during unit tests without elevated privileges).
#[cfg(test)]
fn make_socket_path_tmp() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let id = NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(format!(
        "/tmp/systemd-fork-notify-test-{}-{nonce}-{id}.sock",
        std::process::id()
    ))
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

/// Kill and reap a child after readiness setup fails.
///
/// `fork_notify()` owns a child until it has received and validated READY=1.
/// Matching the C cleanup handler, failures during that interval must not
/// leave the just-spawned command running or turn it into a zombie.  `Child`
/// owns its PID, so this uses its safe, handle-scoped operations rather than
/// a raw PID signal.
fn kill_and_reap_failed_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Ask the kernel to attach an authenticated `SCM_CREDENTIALS` record to
/// every received datagram.
fn enable_sender_credentials(socket: &UnixDatagram) -> io::Result<()> {
    let enabled: libc::c_int = 1;
    // SAFETY: the socket owns a live file descriptor and `enabled` points to
    // an initialized `c_int` for exactly the size passed to setsockopt(2).
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PASSCRED,
            (&enabled as *const libc::c_int).cast(),
            mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Receive one notification together with kernel-authenticated sender
/// credentials.
///
/// Invalid, truncated, or credential-less datagrams are returned as
/// `Ok(None)`, matching the C receiver's "ignore and keep waiting" behavior.
fn recv_notification_with_sender(
    socket: &UnixDatagram,
) -> io::Result<Option<(NotificationMessage, u32)>> {
    let mut payload = [0_u8; NOTIFY_BUFFER_MAX];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };

    // Reserve room for the mandatory credentials and for unexpected passed
    // descriptors so those descriptors can be closed rather than leaked.
    // SAFETY: CMSG_SPACE performs only ancillary-data layout arithmetic for
    // the exact payload sizes supplied here.
    let control_len = unsafe {
        libc::CMSG_SPACE(mem::size_of::<ucred>() as u32) as usize
            + libc::CMSG_SPACE(
                mem::size_of::<libc::c_int>()
                    .checked_mul(NOTIFY_FD_MAX)
                    .expect("notification fd control size overflow") as u32,
            ) as usize
    };
    let control_slots = control_len.div_ceil(mem::size_of::<libc::cmsghdr>());
    let mut control = Vec::<MaybeUninit<libc::cmsghdr>>::with_capacity(control_slots);
    control.resize_with(control_slots, MaybeUninit::uninit);

    // SAFETY: an all-zero msghdr is a valid empty message header; its live
    // payload and ancillary buffers are installed immediately below.
    let mut message = unsafe { mem::zeroed::<libc::msghdr>() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_len;

    let received =
        // SAFETY: `message` points to live writable payload and aligned control
        // buffers for the duration of recvmsg(2). MSG_CMSG_CLOEXEC prevents any
        // received descriptor from being briefly exposed across exec.
        unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }

    let reported_control_len = message.msg_controllen;
    let bounded_control_len = reported_control_len.min(control_len);
    // Keep libc's iterator inside the actual allocation even if an invalid
    // result claims more ancillary bytes than were supplied.
    message.msg_controllen = bounded_control_len;
    let control_start = message.msg_control.cast::<u8>() as usize;
    let Some(control_end) = control_start.checked_add(bounded_control_len) else {
        return Ok(None);
    };
    // SAFETY: CMSG_LEN performs only ancillary-data layout arithmetic.
    let header_len = unsafe { libc::CMSG_LEN(0) as usize };

    let mut sender = None;
    let mut malformed_control = reported_control_len > control_len;
    // SAFETY: `msg_controllen` has been clamped to the live, aligned control
    // allocation. Every returned pointer is bounds-checked before dereference.
    let mut control_message = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !control_message.is_null() {
        let cmsg_start = control_message.cast::<u8>() as usize;
        let Some(header_end) = cmsg_start.checked_add(header_len) else {
            malformed_control = true;
            break;
        };
        if cmsg_start < control_start || header_end > control_end {
            malformed_control = true;
            break;
        }

        // SAFETY: the complete, aligned cmsghdr lies within the checked
        // control-buffer range.
        let header = unsafe { &*control_message };
        let cmsg_len = header.cmsg_len as usize;
        let Some(cmsg_end) = cmsg_start.checked_add(cmsg_len) else {
            malformed_control = true;
            break;
        };
        if cmsg_len < header_len || cmsg_end > control_end {
            malformed_control = true;
            break;
        }

        // SAFETY: CMSG_DATA performs layout arithmetic from the validated,
        // complete header.
        let data = unsafe { libc::CMSG_DATA(control_message).cast::<u8>() };
        let data_start = data as usize;
        let payload_len = cmsg_len - header_len;
        if data_start != header_end
            || data_start
                .checked_add(payload_len)
                .is_none_or(|end| end > cmsg_end)
        {
            malformed_control = true;
            break;
        }

        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            if !payload_len.is_multiple_of(mem::size_of::<libc::c_int>()) {
                malformed_control = true;
                break;
            }

            for index in 0..payload_len / mem::size_of::<libc::c_int>() {
                // SAFETY: the payload bounds above prove this complete c_int
                // lies in the received control record. SCM_RIGHTS descriptors
                // are newly installed in this process by recvmsg(2).
                let fd = unsafe {
                    data.add(index * mem::size_of::<libc::c_int>())
                        .cast::<libc::c_int>()
                        .read_unaligned()
                };
                if fd < 0 {
                    malformed_control = true;
                    break;
                }
                // SAFETY: this function deliberately takes ownership of each
                // unexpected received descriptor and closes it.
                unsafe {
                    libc::close(fd);
                }
            }
            if malformed_control {
                break;
            }
        } else if header.cmsg_level == libc::SOL_SOCKET
            && header.cmsg_type == SCM_CREDENTIALS
            && payload_len == mem::size_of::<ucred>()
            && sender.is_none()
        {
            // SAFETY: the exact payload-length check proves a complete
            // `ucred` is present. `read_unaligned` avoids imposing a Rust
            // alignment requirement on the C ancillary-data pointer.
            let credentials = unsafe { data.cast::<ucred>().read_unaligned() };
            sender = u32::try_from(credentials.pid).ok().filter(|pid| *pid != 0);
        }

        // SAFETY: the current header and its length are fully contained in the
        // clamped control buffer, so libc can safely locate the next record.
        control_message = unsafe { libc::CMSG_NXTHDR(&message, control_message) };
    }

    if received == 0
        || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || malformed_control
        || sender.is_none()
    {
        return Ok(None);
    }

    let received = received as usize;
    if received > 1 && payload[..received - 1].contains(&0) {
        return Ok(None);
    }

    let text_bytes = if payload[received - 1] == 0 {
        &payload[..received - 1]
    } else {
        &payload[..received]
    };
    let Ok(text) = std::str::from_utf8(text_bytes) else {
        return Ok(None);
    };

    Ok(Some((
        NotificationMessage::parse(text.to_owned()),
        sender.expect("sender checked above"),
    )))
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
    let mut socket_path_cleanup = SocketPathCleanup::new(socket_path.clone());
    enable_sender_credentials(&socket)?;
    socket.set_nonblocking(false)?;

    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    command.env("NOTIFY_SOCKET", &socket_path);
    // Redirect stdin to /dev/null, keep stdout/stderr inherited (mirrors the
    // C code's { -EBADF, STDOUT_FILENO, STDERR_FILENO }).
    command.stdin(std::process::Stdio::null());

    let mut child = command.spawn()?;
    let child_pid = child.id();

    let readiness = (|| {
        let started = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                return Err(exit_status_to_error(child_pid, status));
            }

            let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
                return Err(ForkNotifyError::ChildNotReady { pid: child_pid });
            };
            if remaining.is_zero() {
                return Err(ForkNotifyError::ChildNotReady { pid: child_pid });
            }
            socket.set_read_timeout(Some(remaining))?;

            let received = match recv_notification_with_sender(&socket) {
                Ok(Some(message)) => message,
                Ok(None) => continue,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    match child.try_wait()? {
                        Some(status) => {
                            return Err(exit_status_to_error(child_pid, status));
                        }
                        None => {
                            return Err(ForkNotifyError::ChildNotReady { pid: child_pid });
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(ForkNotifyError::Io(error)),
            };

            match validate_notification(&received.0, child_pid, received.1) {
                Ok(()) => return Ok(()),
                // The C event handler ignores unrelated and non-ready
                // datagrams and keeps waiting for the child.
                Err(ForkNotifyError::UnexpectedSender { .. })
                | Err(ForkNotifyError::ChildNotReady { .. }) => continue,
                Err(error) => return Err(error),
            }
        }
    })();

    if let Err(error) = readiness {
        kill_and_reap_failed_child(&mut child);
        return Err(error);
    }

    socket_path_cleanup.keep();
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
fn checked_pid(pid: u32) -> Result<libc::pid_t> {
    if pid == 0 {
        return Err(ForkNotifyError::InvalidPid { pid });
    }

    pid.try_into()
        .map_err(|_| ForkNotifyError::InvalidPid { pid })
}

fn terminate_process(pid: u32) -> Result<()> {
    let raw_pid = checked_pid(pid)?;
    // SAFETY: kill(2) takes only scalar values, does not access Rust memory,
    // and raw_pid is a checked, strictly positive process identifier.
    let ret = unsafe { libc::kill(raw_pid, libc::SIGTERM) };
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
    let Ok(raw_pid) = checked_pid(pid) else {
        return;
    };

    // SAFETY: kill(2) takes only scalar values, does not access Rust memory,
    // and raw_pid is a checked, strictly positive process identifier.
    let ret = unsafe { libc::kill(raw_pid, libc::SIGTERM) };
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
        assert!(
            p1.to_string_lossy()
                .starts_with("/run/systemd/fork-notify-")
        );
        assert_ne!(p1, p2);
    }

    // ── fork_notify_terminate_many empty ──────────────────────────────

    #[test]
    fn test_terminate_many_empty() {
        // Should not panic on empty slice.
        fork_notify_terminate_many(&mut []);
    }

    #[test]
    fn test_checked_pid_rejects_non_process_values() {
        assert!(matches!(
            checked_pid(0),
            Err(ForkNotifyError::InvalidPid { pid: 0 })
        ));
        assert!(matches!(
            checked_pid(u32::MAX),
            Err(ForkNotifyError::InvalidPid { pid: u32::MAX })
        ));
        assert!(checked_pid(1).is_ok());
    }
}
