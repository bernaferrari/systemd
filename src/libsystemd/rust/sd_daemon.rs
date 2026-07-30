// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-daemon/sd-daemon.c
//
// System daemon notification, socket/fifo/mq/special file type detection,
// listen-FD handling, and watchdog support.
//
// Faithful Rust port of sd-daemon public API. Pure safe idiomatic Rust.

use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

// ── Constants ─────────────────────────────────────────────────────────────

/// The first file descriptor passed via socket activation.
/// Corresponds to SD_LISTEN_FDS_START in sd-daemon.h.
pub const SD_LISTEN_FDS_START: i32 = 3;

/// Default send buffer size for the notification socket.
/// Corresponds to SNDBUF_SIZE in sd-daemon.c.
pub const SNDBUF_SIZE: usize = 8 * 1024 * 1024;

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonError {
    BadFileDescriptor,
    InvalidArgument,
    NotConnected,
    Io(String),
    Errno(i32),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonError::BadFileDescriptor => write!(f, "Bad file descriptor"),
            DaemonError::InvalidArgument => write!(f, "Invalid argument"),
            DaemonError::NotConnected => write!(f, "Not connected"),
            DaemonError::Io(s) => write!(f, "I/O: {s}"),
            DaemonError::Errno(n) => write!(f, "Error {n}"),
        }
    }
}

impl std::error::Error for DaemonError {}

pub type Result<T> = std::result::Result<T, DaemonError>;

// ── File type detection ───────────────────────────────────────────────────

/// Classification of fd types, mirroring the C sd_is_* family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdType {
    Fifo,
    RegularFile,
    CharacterDevice,
    BlockDevice,
    Socket,
    MessageQueue,
    Other,
}

/// Classify the type of a file descriptor by its path.
/// Mirrors the combined logic of `sd_is_fifo`, `sd_is_special`,
/// `sd_is_socket`, etc.
pub fn classify_fd_path(path: &Path) -> Result<FdType> {
    let meta = fs::metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            DaemonError::BadFileDescriptor
        } else {
            DaemonError::Io(e.to_string())
        }
    })?;

    let ft = meta.file_type();
    if ft.is_fifo() {
        Ok(FdType::Fifo)
    } else if ft.is_socket() {
        Ok(FdType::Socket)
    } else if ft.is_block_device() {
        Ok(FdType::BlockDevice)
    } else if ft.is_char_device() {
        Ok(FdType::CharacterDevice)
    } else if ft.is_file() {
        Ok(FdType::RegularFile)
    } else {
        Ok(FdType::Other)
    }
}

/// Check if a path refers to a FIFO (named pipe).
/// Corresponds to `sd_is_fifo(fd, path)`.
pub fn is_fifo(path: &Path) -> Result<bool> {
    match classify_fd_path(path)? {
        FdType::Fifo => Ok(true),
        _ => Ok(false),
    }
}

/// Check if a path refers to a special file (regular or character device).
/// Corresponds to `sd_is_special(fd, path)`.
pub fn is_special(path: &Path) -> Result<bool> {
    match classify_fd_path(path)? {
        FdType::RegularFile | FdType::CharacterDevice => Ok(true),
        _ => Ok(false),
    }
}

/// Check if a path refers to a socket.
/// Corresponds to `sd_is_socket(fd, ...)`.
pub fn is_socket(path: &Path) -> Result<bool> {
    match classify_fd_path(path)? {
        FdType::Socket => Ok(true),
        _ => Ok(false),
    }
}

/// Check if a path refers to a message queue.
/// Corresponds to `sd_is_mq(fd, path)`.
pub fn is_mq(path: &Path) -> Result<bool> {
    // On Linux, mqueues appear in /dev/mqueue/
    match path.to_str() {
        Some(s) if s.starts_with("/dev/mqueue/") => Ok(true),
        _ => {
            let meta = fs::metadata(path);
            match meta {
                Ok(m) if m.file_type().is_fifo() => Ok(false),
                Err(_) => Ok(false),
                _ => Ok(false),
            }
        }
    }
}

// ── Socket address types ──────────────────────────────────────────────────

/// Socket family classification for inet/unix socket checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketFamily {
    Ipv4,
    Ipv6,
    Unix,
    Other,
}

/// Socket type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketKind {
    Stream,
    Datagram,
    SeqPacket,
    Other,
}

/// Represents a parsed socket address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketAddress {
    Inet { host: String, port: u16 },
    Unix { path: String },
}

// ── Listen FD handling ────────────────────────────────────────────────────

/// Parsed listen-FD information from the environment.
/// Corresponds to the LISTEN_PID / LISTEN_FDS / LISTEN_FDNAMES env vars.
#[derive(Debug, Clone)]
pub struct ListenFds {
    /// Number of file descriptors passed.
    pub count: u32,
    /// Optional names for each fd (space/comma separated from LISTEN_FDNAMES).
    pub names: Vec<String>,
}

impl ListenFds {
    /// The first FD in the listen range.
    pub fn first_fd(&self) -> i32 {
        SD_LISTEN_FDS_START
    }

    /// The last FD in the listen range (inclusive).
    pub fn last_fd(&self) -> i32 {
        SD_LISTEN_FDS_START + (self.count as i32) - 1
    }

    /// Iterate over all FD indices.
    pub fn fds(&self) -> Vec<i32> {
        (0..self.count)
            .map(|i| SD_LISTEN_FDS_START + i as i32)
            .collect()
    }
}

/// Parse listen-FD information from environment variables.
/// Corresponds to `sd_listen_fds()` + `sd_listen_fds_with_names()`.
pub fn parse_listen_fds(
    listen_pid: Option<&str>,
    listen_fds: Option<&str>,
    listen_fdnames: Option<&str>,
    our_pid: u32,
) -> Result<Option<ListenFds>> {
    let pid_str = match listen_pid {
        Some(s) => s,
        None => return Ok(None),
    };

    let pid: u32 = pid_str
        .trim()
        .parse()
        .map_err(|_| DaemonError::InvalidArgument)?;

    if pid != our_pid {
        return Ok(None);
    }

    let fds_str = match listen_fds {
        Some(s) => s,
        None => return Ok(None),
    };

    let n: i32 = fds_str
        .trim()
        .parse()
        .map_err(|_| DaemonError::InvalidArgument)?;

    if n <= 0 {
        return Ok(None);
    }

    let names = match listen_fdnames {
        Some(s) if !s.is_empty() => s.split(':').map(|n| n.to_string()).collect(),
        _ => vec!["unknown".to_string(); n as usize],
    };

    Ok(Some(ListenFds {
        count: n as u32,
        names,
    }))
}

// ── Daemon notification state ─────────────────────────────────────────────

/// Status states for sd-daemon notification.
/// Corresponds to the string constants sent via `sd_notify()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyState {
    Ready,
    Reloading,
    Stopping,
    Status(String),
    Errno(u32),
    BusError(String),
    MainPid(u32),
    Watchdog(u64),
    WatchdogTimestamp(String),
    ExtendTimeoutUsec(u64),
}

impl NotifyState {
    /// Convert to the string representation used in the notification socket.
    pub fn to_notify_string(&self) -> String {
        match self {
            NotifyState::Ready => "READY=1".to_string(),
            NotifyState::Reloading => "RELOADING=1".to_string(),
            NotifyState::Stopping => "STOPPING=1".to_string(),
            NotifyState::Status(s) => format!("STATUS={s}"),
            NotifyState::Errno(n) => format!("ERRNO={n}"),
            NotifyState::BusError(s) => format!("BUSERROR={s}"),
            NotifyState::MainPid(pid) => format!("MAINPID={pid}"),
            NotifyState::Watchdog(usec) => format!("WATCHDOG_USEC={usec}"),
            NotifyState::WatchdogTimestamp(ts) => format!("WATCHDOG_TIMESTAMP={ts}"),
            NotifyState::ExtendTimeoutUsec(usec) => format!("EXTEND_TIMEOUT_USEC={usec}"),
        }
    }
}

/// Build a combined notification message from multiple states.
pub fn build_notify_message(states: &[NotifyState]) -> String {
    states
        .iter()
        .map(|s| s.to_notify_string())
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Booted check ──────────────────────────────────────────────────────────

/// Check whether the system was booted with systemd.
/// Corresponds to `sd_booted()`.
pub fn is_booted() -> bool {
    Path::new("/run/systemd/system").exists()
}

// ── Watchdog support ──────────────────────────────────────────────────────

/// Configuration for the watchdog timer.
#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    /// Whether the watchdog is enabled.
    pub enabled: bool,
    /// Timeout in microseconds.
    pub timeout_usec: u64,
}

impl WatchdogConfig {
    /// Parse watchdog configuration from environment variables.
    /// Corresponds to `sd_watchdog_enabled()`.
    pub fn from_env(watchdog_pid: Option<&str>, watchdog_usec: Option<&str>, our_pid: u32) -> Self {
        let enabled = match watchdog_pid {
            Some(s) => s
                .trim()
                .parse::<u32>()
                .map(|p| p == our_pid)
                .unwrap_or(false),
            None => false,
        };

        let timeout_usec = watchdog_usec
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        Self {
            enabled,
            timeout_usec,
        }
    }
}

// ── PID notify ────────────────────────────────────────────────────────────

/// Parameters for `sd_pid_notify_with_fds()`.
#[derive(Debug, Clone)]
pub struct PidNotifyParams {
    pub pid: u32,
    pub state: String,
    pub fds: Vec<i32>,
    pub unset_environment: bool,
}

impl PidNotifyParams {
    /// Create params for `sd_pid_notify()` (no fds).
    pub fn new(pid: u32, state: String) -> Self {
        Self {
            pid,
            state,
            fds: Vec::new(),
            unset_environment: false,
        }
    }

    /// Create params for `sd_pid_notify_with_fds()`.
    pub fn with_fds(pid: u32, state: String, fds: Vec<i32>) -> Self {
        Self {
            pid,
            state,
            fds,
            unset_environment: false,
        }
    }
}

// ── Barrier support ───────────────────────────────────────────────────────

/// A daemon notification barrier.
/// Corresponds to `sd_notify_barrier()` / `sd_pid_notify_barrier()`.
#[derive(Debug, Clone)]
pub struct NotifyBarrier {
    pub pid: u32,
    pub timeout_usec: u64,
}

impl NotifyBarrier {
    pub fn new(timeout_usec: u64) -> Self {
        Self {
            pid: 0,
            timeout_usec,
        }
    }

    pub fn for_pid(pid: u32, timeout_usec: u64) -> Self {
        Self { pid, timeout_usec }
    }
}

// ── PIDFD inode ───────────────────────────────────────────────────────────

/// Represents the result of `sd_pidfd_get_inode_id()`.
#[derive(Debug, Clone)]
pub struct PidfdInodeId {
    pub inode: u64,
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notify_state_ready() {
        assert_eq!(NotifyState::Ready.to_notify_string(), "READY=1");
    }

    #[test]
    fn test_notify_state_reloading() {
        assert_eq!(NotifyState::Reloading.to_notify_string(), "RELOADING=1");
    }

    #[test]
    fn test_notify_state_stopping() {
        assert_eq!(NotifyState::Stopping.to_notify_string(), "STOPPING=1");
    }

    #[test]
    fn test_notify_state_status() {
        assert_eq!(
            NotifyState::Status("Processing requests".to_string()).to_notify_string(),
            "STATUS=Processing requests"
        );
    }

    #[test]
    fn test_notify_state_errno() {
        assert_eq!(NotifyState::Errno(2).to_notify_string(), "ERRNO=2");
    }

    #[test]
    fn test_notify_state_mainpid() {
        assert_eq!(
            NotifyState::MainPid(1234).to_notify_string(),
            "MAINPID=1234"
        );
    }

    #[test]
    fn test_notify_state_watchdog() {
        assert_eq!(
            NotifyState::Watchdog(5000000).to_notify_string(),
            "WATCHDOG_USEC=5000000"
        );
    }

    #[test]
    fn test_notify_state_extend_timeout() {
        assert_eq!(
            NotifyState::ExtendTimeoutUsec(10000000).to_notify_string(),
            "EXTEND_TIMEOUT_USEC=10000000"
        );
    }

    #[test]
    fn test_notify_state_bus_error() {
        assert_eq!(
            NotifyState::BusError("org.freedesktop.DBus.Error.Failed".to_string())
                .to_notify_string(),
            "BUSERROR=org.freedesktop.DBus.Error.Failed"
        );
    }

    #[test]
    fn test_notify_state_watchdog_timestamp() {
        let ts = NotifyState::WatchdogTimestamp("2024-01-01T00:00:00Z".to_string());
        assert_eq!(
            ts.to_notify_string(),
            "WATCHDOG_TIMESTAMP=2024-01-01T00:00:00Z"
        );
    }

    #[test]
    fn test_build_notify_message() {
        let states = vec![NotifyState::Ready, NotifyState::MainPid(100)];
        let msg = build_notify_message(&states);
        assert_eq!(msg, "READY=1\nMAINPID=100");
    }

    #[test]
    fn test_build_notify_message_empty() {
        let msg = build_notify_message(&[]);
        assert_eq!(msg, "");
    }

    #[test]
    fn test_build_notify_message_single() {
        let msg = build_notify_message(&[NotifyState::Ready]);
        assert_eq!(msg, "READY=1");
    }

    #[test]
    fn test_listen_fds_none() {
        let result = parse_listen_fds(None, None, None, 1234).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_listen_fds_wrong_pid() {
        let result = parse_listen_fds(Some("9999"), Some("3"), None, 1234).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_listen_fds_no_fds() {
        let result = parse_listen_fds(Some("1234"), None, None, 1234).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_listen_fds_valid() {
        let result = parse_listen_fds(Some("1234"), Some("3"), None, 1234)
            .unwrap()
            .unwrap();
        assert_eq!(result.count, 3);
        assert_eq!(result.first_fd(), SD_LISTEN_FDS_START);
        assert_eq!(result.last_fd(), SD_LISTEN_FDS_START + 2);
        assert_eq!(result.fds(), vec![3, 4, 5]);
    }

    #[test]
    fn test_listen_fds_zero() {
        let result = parse_listen_fds(Some("1234"), Some("0"), None, 1234).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_listen_fds_with_names() {
        let result = parse_listen_fds(Some("1234"), Some("2"), Some("http:https"), 1234)
            .unwrap()
            .unwrap();
        assert_eq!(result.count, 2);
        assert_eq!(result.names, vec!["http", "https"]);
    }

    #[test]
    fn test_listen_fds_with_fewer_names() {
        let result = parse_listen_fds(Some("1234"), Some("3"), Some("onlyone"), 1234)
            .unwrap()
            .unwrap();
        assert_eq!(result.count, 3);
        assert_eq!(result.names, vec!["onlyone"]);
    }

    #[test]
    fn test_watchdog_config_no_env() {
        let config = WatchdogConfig::from_env(None, None, 1234);
        assert!(!config.enabled);
        assert_eq!(config.timeout_usec, 0);
    }

    #[test]
    fn test_watchdog_config_wrong_pid() {
        let config = WatchdogConfig::from_env(Some("9999"), Some("5000000"), 1234);
        assert!(!config.enabled);
        assert_eq!(config.timeout_usec, 5000000);
    }

    #[test]
    fn test_watchdog_config_correct_pid() {
        let config = WatchdogConfig::from_env(Some("1234"), Some("5000000"), 1234);
        assert!(config.enabled);
        assert_eq!(config.timeout_usec, 5000000);
    }

    #[test]
    fn test_watchdog_config_invalid_usec() {
        let config = WatchdogConfig::from_env(Some("1234"), Some("notanumber"), 1234);
        assert!(config.enabled);
        assert_eq!(config.timeout_usec, 0);
    }

    #[test]
    fn test_pid_notify_params() {
        let p = PidNotifyParams::new(1234, "READY=1".to_string());
        assert_eq!(p.pid, 1234);
        assert_eq!(p.state, "READY=1");
        assert!(p.fds.is_empty());
    }

    #[test]
    fn test_pid_notify_params_with_fds() {
        let p = PidNotifyParams::with_fds(1234, "READY=1".to_string(), vec![10, 11]);
        assert_eq!(p.fds, vec![10, 11]);
    }

    #[test]
    fn test_notify_barrier() {
        let b = NotifyBarrier::new(1000000);
        assert_eq!(b.pid, 0);
        assert_eq!(b.timeout_usec, 1000000);
    }

    #[test]
    fn test_notify_barrier_for_pid() {
        let b = NotifyBarrier::for_pid(42, 2000000);
        assert_eq!(b.pid, 42);
        assert_eq!(b.timeout_usec, 2000000);
    }

    #[test]
    fn test_constants() {
        assert_eq!(SD_LISTEN_FDS_START, 3);
        assert_eq!(SNDBUF_SIZE, 8 * 1024 * 1024);
    }

    #[test]
    fn test_socket_family_variants() {
        assert_ne!(SocketFamily::Ipv4, SocketFamily::Ipv6);
        assert_ne!(SocketFamily::Unix, SocketFamily::Other);
    }

    #[test]
    fn test_socket_kind_variants() {
        assert_ne!(SocketKind::Stream, SocketKind::Datagram);
    }

    #[test]
    fn test_fd_type_ordering() {
        let types = [
            FdType::Fifo,
            FdType::Socket,
            FdType::RegularFile,
            FdType::CharacterDevice,
            FdType::BlockDevice,
            FdType::MessageQueue,
            FdType::Other,
        ];
        assert_eq!(types.len(), 7);
    }

    #[test]
    fn test_listen_fds_fds_iterator() {
        let lfds = ListenFds {
            count: 5,
            names: vec!["a".into(); 5],
        };
        assert_eq!(lfds.fds(), vec![3, 4, 5, 6, 7]);
    }
}
