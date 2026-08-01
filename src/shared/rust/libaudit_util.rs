// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/libaudit-util.c, src/shared/libaudit-util.h,
//           src/basic/audit-util.c, src/basic/audit-util.h
//
// Linux Audit utilities — audit enablement detection via netlink,
// login UID and session ID retrieval from /proc/<pid>/loginuid
// and /proc/<pid>/sessionid, and helpers for audit session validation.

// ── Constants ─────────────────────────────────────────────────────────────

/// Sentinel value indicating an invalid or unset audit session.
use crate::ffi::*;
pub const AUDIT_SESSION_INVALID: u32 = u32::MAX;

/// The sentinel UID value written by the kernel to `/proc/<pid>/loginuid`
/// when no login session has been established.
pub const AUDIT_LOGINUID_UNSET: &str = "4294967295";

/// Netlink protocol number for the audit subsystem.
const NETLINK_AUDIT: i32 = 9;

/// Netlink message type: request kernel audit features.
const AUDIT_GET_FEATURE: u16 = 1019;

/// Netlink message type: error acknowledgement.
const NLMSG_ERROR: u16 = 2;

/// Netlink flags for a request that expects an ACK.
const NLM_F_REQUEST_ACK: u16 = NLM_F_REQUEST as u16 | NLM_F_ACK as u16;

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors produced by audit utility functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    /// The operation is not supported (no audit compiled in, or kernel lacks support).
    NotSupported,
    /// Permission denied — insufficient privileges for the audit operation.
    PermissionDenied,
    /// The requested PID does not exist.
    NoSuchProcess,
    /// No audit data is available (e.g. loginuid not set, container environment).
    NoData,
    /// A generic I/O or system error occurred.
    Io(String),
    /// The value read could not be parsed.
    ParseError(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditError::NotSupported => write!(f, "audit not supported"),
            AuditError::PermissionDenied => write!(f, "permission denied for audit operation"),
            AuditError::NoSuchProcess => write!(f, "no such process"),
            AuditError::NoData => write!(f, "no audit data available"),
            AuditError::Io(msg) => write!(f, "I/O error: {msg}"),
            AuditError::ParseError(msg) => write!(f, "parse error: {msg}"),
        }
    }
}

impl std::error::Error for AuditError {}

// ── Audit session validation ──────────────────────────────────────────────

/// Returns `true` if the given audit session ID is considered valid.
///
/// A session ID is valid when it is non-zero and not the sentinel
/// `AUDIT_SESSION_INVALID` value.
pub fn audit_session_is_valid(id: u32) -> bool {
    id > 0 && id != AUDIT_SESSION_INVALID
}

// ── Netlink message structures ────────────────────────────────────────────

/// Netlink message header (matches `struct nlmsghdr` layout).
///
/// # Safety
/// This struct is only safe to use when its fields describe a valid
/// netlink message that will be sent via `sendmsg`.
#[repr(C, packed)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

/// Netlink error message payload (matches `struct nlmsgerr` layout).
#[repr(C, packed)]
struct NlMsgErr {
    error: i32,
}

/// Combined netlink request/response message for AUDIT_GET_FEATURE.
#[repr(C, packed)]
struct AuditFeatureMsg {
    hdr: NlMsgHdr,
    err: NlMsgErr,
}

impl AuditFeatureMsg {
    fn new_request() -> Self {
        let hdr_len = (std::mem::size_of::<NlMsgHdr>()) as u32;
        Self {
            hdr: NlMsgHdr {
                nlmsg_len: hdr_len,
                nlmsg_type: AUDIT_GET_FEATURE,
                nlmsg_flags: NLM_F_REQUEST_ACK,
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            },
            err: NlMsgErr { error: 0 },
        }
    }
}

// ── Netlink helpers ───────────────────────────────────────────────────────

/// Length of a netlink message payload (matches `NLMSG_LENGTH` macro).
const fn nlmsg_length(payload_len: usize) -> usize {
    std::mem::size_of::<NlMsgHdr>().saturating_add(payload_len)
}

/// Attempt a single audit netlink request on the given file descriptor.
///
/// Sends an `AUDIT_GET_FEATURE` request and reads the ACK. Returns `Ok(())`
/// if the kernel responded successfully, or an error describing the failure.
///
/// # Safety
/// `fd` must be a valid, open netlink socket file descriptor.
unsafe fn try_audit_request(fd: i32) -> Result<(), AuditError> {
    assert!(fd >= 0, "audit netlink fd must be non-negative");

    let msg = AuditFeatureMsg::new_request();

    // Build iovec for sendmsg
    let iov = libc::iovec {
        iov_base: &msg as *const _ as *mut libc::c_void,
        iov_len: msg.hdr.nlmsg_len as usize,
    };
    // SAFETY: all-zero is a valid initial msghdr before its active fields are assigned.
    let mut mh: libc::msghdr = unsafe_ffi!(std::mem::zeroed());
    mh.msg_iov = &iov as *const _ as *mut libc::iovec;
    mh.msg_iovlen = 1;

    // Send the request (MSG_NOSIGNAL = 0x4000 on Linux)
    // SAFETY: `fd` is an open netlink socket by contract, and `mh` describes the
    // initialized `msg` buffer through a live, single-element iovec for this call.
    if unsafe_ffi!(libc::sendmsg(fd, &mh, 0x4000)) < 0 {
        let err = std::io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(0);
        if is_privilege_errno(errno) || is_not_supported_errno(errno) {
            return Err(AuditError::NotSupported);
        }
        return Err(AuditError::Io(err.to_string()));
    }

    // Prepare to receive the response
    // SAFETY: AuditFeatureMsg is a C-layout integer-only message type for which zero is valid.
    let mut resp_msg = unsafe_ffi!(std::mem::zeroed::<AuditFeatureMsg>());
    let mut resp_iov = libc::iovec {
        iov_base: &mut resp_msg as *mut _ as *mut libc::c_void,
        iov_len: std::mem::size_of::<AuditFeatureMsg>(),
    };
    // SAFETY: all-zero is a valid initial msghdr before its active fields are assigned.
    let mut recv_mh: libc::msghdr = unsafe_ffi!(std::mem::zeroed());
    recv_mh.msg_iov = &mut resp_iov as *mut _ as *mut libc::iovec;
    recv_mh.msg_iovlen = 1;

    // SAFETY: `fd` is an open netlink socket by contract, and `recv_mh` points to
    // the live, writable `resp_msg` buffer with its exact capacity.
    let n = unsafe_ffi!(libc::recvmsg(fd, &mut recv_mh, 0));
    if n < 0 {
        return Err(AuditError::Io(std::io::Error::last_os_error().to_string()));
    }

    let expected_len = nlmsg_length(std::mem::size_of::<NlMsgErr>()) as isize;
    if n != expected_len {
        return Err(AuditError::Io(format!(
            "unexpected netlink response length: got {n}, expected {expected_len}"
        )));
    }

    // SAFETY: `addr_of!` forms no reference to the packed field, the response
    // buffer is initialized, and `read_unaligned` supports its packed alignment.
    let nlmsg_type: u16 = unsafe_ffi!(std::ptr::read_unaligned(std::ptr::addr_of!(
        resp_msg.hdr.nlmsg_type
    )));
    if nlmsg_type != NLMSG_ERROR {
        return Err(AuditError::Io(format!(
            "unexpected netlink message type: {nlmsg_type}"
        )));
    }

    // SAFETY: `addr_of!` forms no reference to the packed field, the response
    // buffer is initialized, and `read_unaligned` supports its packed alignment.
    let audit_error: i32 = unsafe_ffi!(std::ptr::read_unaligned(std::ptr::addr_of!(
        resp_msg.err.error
    )));
    // resp_msg.err.error == 0 means success; negative means kernel error code
    if audit_error < 0 {
        let kernel_errno = -audit_error;
        // ECONNREFUSED (111) means not in initial user namespace
        if kernel_errno == libc::ECONNREFUSED {
            return Err(AuditError::NotSupported);
        }
        return Err(AuditError::Io(format!(
            "audit netlink error: errno {kernel_errno}"
        )));
    }

    Ok(())
}

// ── Errno classification ──────────────────────────────────────────────────

/// Check if an errno value indicates a privilege error.
fn is_privilege_errno(errno: i32) -> bool {
    matches!(errno, libc::EPERM | libc::EACCES)
}

/// Check if an errno value indicates the feature is not supported.
fn is_not_supported_errno(errno: i32) -> bool {
    matches!(
        errno,
        libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::ECONNREFUSED | libc::ENOPROTOOPT
    )
}

// ── Audit enabled detection ───────────────────────────────────────────────

/// Cached result of the audit enablement check.
static AUDIT_ENABLED: std::sync::atomic::AtomicI8 = std::sync::atomic::AtomicI8::new(-1); // -1 = not yet determined

/// Determine whether the kernel's audit subsystem is available and usable.
///
/// This performs a single netlink probe and caches the result for the
/// lifetime of the process. The check is thread-safe via atomic operations.
///
/// Returns `true` if audit should be used, `false` otherwise.
pub fn use_audit() -> bool {
    loop {
        match AUDIT_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
            -1 => {
                // Not yet determined — attempt to compute the value.
                let result = detect_audit_enabled();
                let cached = if result { 1 } else { 0 };
                // Try to store; if another thread beat us, we'll read their value.
                match AUDIT_ENABLED.compare_exchange(
                    -1,
                    cached,
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                ) {
                    Ok(_) => return result,
                    Err(_) => continue, // Another thread set it; retry the load.
                }
            }
            0 => return false,
            1 => return true,
            _ => return false,
        }
    }
}

/// Reset the cached audit-enabled state. Useful for testing.
#[cfg(test)]
fn reset_audit_cache() {
    AUDIT_ENABLED.store(-1, std::sync::atomic::Ordering::Relaxed);
}

/// Perform the actual audit enablement detection via netlink socket.
fn detect_audit_enabled() -> bool {
    // Open a netlink audit socket (SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK)
    // SAFETY: `socket` receives only integer constants and does not access Rust
    // memory; success is checked before the returned descriptor is used.
    let fd = unsafe_ffi!({
        libc::socket(
            AF_NETLINK,
            libc::SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
            NETLINK_AUDIT,
        )
    });

    if fd < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if is_privilege_errno(errno) || is_not_supported_errno(errno) {
            return false;
        }
        // Unexpected error — still proceed with audit (matches C behaviour).
        return true;
    }

    // Attempt the audit request; close fd on any path.
    // SAFETY: the successful `socket` call returned a non-negative, open audit
    // netlink descriptor, satisfying `try_audit_request`'s contract.
    let result = unsafe_ffi!(try_audit_request(fd));
    // SAFETY: this scope still exclusively owns the open descriptor, and the
    // request above borrows it without closing or retaining it.
    unsafe_ffi!(libc::close(fd));

    result.is_ok()
}

// ── /proc loginuid and sessionid parsing ──────────────────────────────────

/// Result of parsing a `/proc/<pid>/loginuid` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginUid {
    /// The login UID value, or `None` if unset (sentinel `4294967295`).
    pub uid: Option<u32>,
}

/// Result of parsing a `/proc/<pid>/sessionid` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSession {
    /// The session ID, or `None` if invalid/unset.
    pub id: Option<u32>,
}

/// Parse the contents of a `/proc/<pid>/loginuid` file.
///
/// The file typically contains a single decimal UID or the sentinel
/// value `4294967295` (meaning "not part of any session").
///
/// # Arguments
/// * `content` — the raw string content of the loginuid file.
///
/// # Returns
/// A `LoginUid` with `uid` set to `Some(value)` on success, or `None`
/// if the login UID is the unset sentinel.
pub fn parse_loginuid(content: &str) -> Result<LoginUid, AuditError> {
    let trimmed = content.trim().trim_end_matches('\n');
    if trimmed.is_empty() {
        return Err(AuditError::ParseError("empty loginuid content".into()));
    }
    if trimmed == AUDIT_LOGINUID_UNSET {
        return Ok(LoginUid { uid: None });
    }
    let uid: u32 = trimmed
        .parse()
        .map_err(|e| AuditError::ParseError(format!("invalid loginuid '{trimmed}': {e}")))?;
    Ok(LoginUid { uid: Some(uid) })
}

/// Parse the contents of a `/proc/<pid>/sessionid` file.
///
/// The file contains a single decimal session ID. Returns `None` if the
/// ID is zero or equals `AUDIT_SESSION_INVALID`.
///
/// # Arguments
/// * `content` — the raw string content of the sessionid file.
///
/// # Returns
/// An `AuditSession` with `id` set to `Some(value)` if the session ID
/// is valid, or `None` otherwise.
pub fn parse_sessionid(content: &str) -> Result<AuditSession, AuditError> {
    let trimmed = content.trim().trim_end_matches('\n');
    if trimmed.is_empty() {
        return Err(AuditError::ParseError("empty sessionid content".into()));
    }
    let id: u32 = trimmed
        .parse()
        .map_err(|e| AuditError::ParseError(format!("invalid sessionid '{trimmed}': {e}")))?;
    if audit_session_is_valid(id) {
        Ok(AuditSession { id: Some(id) })
    } else {
        Ok(AuditSession { id: None })
    }
}

/// Read and parse `/proc/<pid>/loginuid` for the given PID.
///
/// # Errors
/// Returns `AuditError::Io` if the file cannot be read, or
/// `AuditError::ParseError` if the content is invalid.
pub fn read_loginuid(pid: u32) -> Result<LoginUid, AuditError> {
    let path = format!("/proc/{pid}/loginuid");
    let content =
        std::fs::read_to_string(&path).map_err(|e| AuditError::Io(format!("{path}: {e}")))?;
    parse_loginuid(&content)
}

/// Read and parse `/proc/<pid>/sessionid` for the given PID.
///
/// # Errors
/// Returns `AuditError::Io` if the file cannot be read, or
/// `AuditError::ParseError` if the content is invalid.
pub fn read_sessionid(pid: u32) -> Result<AuditSession, AuditError> {
    let path = format!("/proc/{pid}/sessionid");
    let content =
        std::fs::read_to_string(&path).map_err(|e| AuditError::Io(format!("{path}: {e}")))?;
    parse_sessionid(&content)
}

/// Read and parse `/proc/self/loginuid` for the current process.
///
/// This is a convenience wrapper around [`read_loginuid`] for the common
/// case of querying the current process's audit login UID.
pub fn read_self_loginuid() -> Result<LoginUid, AuditError> {
    let path = "/proc/self/loginuid";
    let content =
        std::fs::read_to_string(path).map_err(|e| AuditError::Io(format!("{path}: {e}")))?;
    parse_loginuid(&content)
}

/// Read and parse `/proc/self/sessionid` for the current process.
///
/// This is a convenience wrapper around [`read_sessionid`] for the common
/// case of querying the current process's audit session ID.
pub fn read_self_sessionid() -> Result<AuditSession, AuditError> {
    let path = "/proc/self/sessionid";
    let content =
        std::fs::read_to_string(path).map_err(|e| AuditError::Io(format!("{path}: {e}")))?;
    parse_sessionid(&content)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_session_is_valid() {
        assert!(audit_session_is_valid(1));
        assert!(audit_session_is_valid(100));
        assert!(audit_session_is_valid(u32::MAX - 1));
        assert!(!audit_session_is_valid(0));
        assert!(!audit_session_is_valid(u32::MAX));
    }

    #[test]
    fn test_audit_session_invalid_constant() {
        assert_eq!(AUDIT_SESSION_INVALID, u32::MAX);
    }

    #[test]
    fn test_audit_loginuid_unset_constant() {
        assert_eq!(AUDIT_LOGINUID_UNSET, "4294967295");
    }

    #[test]
    fn test_parse_loginuid_valid() {
        let result = parse_loginuid("1000\n").unwrap();
        assert_eq!(result.uid, Some(1000));
    }

    #[test]
    fn test_parse_loginuid_no_newline() {
        let result = parse_loginuid("0").unwrap();
        assert_eq!(result.uid, Some(0));
    }

    #[test]
    fn test_parse_loginuid_unset_sentinel() {
        let result = parse_loginuid("4294967295\n").unwrap();
        assert_eq!(result.uid, None);
    }

    #[test]
    fn test_parse_loginuid_unset_no_newline() {
        let result = parse_loginuid("4294967295").unwrap();
        assert_eq!(result.uid, None);
    }

    #[test]
    fn test_parse_loginuid_empty() {
        assert!(matches!(parse_loginuid(""), Err(AuditError::ParseError(_))));
    }

    #[test]
    fn test_parse_loginuid_invalid() {
        assert!(matches!(
            parse_loginuid("not_a_number\n"),
            Err(AuditError::ParseError(_))
        ));
    }

    #[test]
    fn test_parse_loginuid_negative() {
        assert!(matches!(
            parse_loginuid("-1\n"),
            Err(AuditError::ParseError(_))
        ));
    }

    #[test]
    fn test_parse_loginuid_with_whitespace() {
        let result = parse_loginuid("  42  \n").unwrap();
        assert_eq!(result.uid, Some(42));
    }

    #[test]
    fn test_parse_sessionid_valid() {
        let result = parse_sessionid("5\n").unwrap();
        assert_eq!(result.id, Some(5));
    }

    #[test]
    fn test_parse_sessionid_zero() {
        // Session ID 0 is invalid per audit_session_is_valid
        let result = parse_sessionid("0\n").unwrap();
        assert_eq!(result.id, None);
    }

    #[test]
    fn test_parse_sessionid_max() {
        // Session ID u32::MAX is the invalid sentinel
        let result = parse_sessionid("4294967295\n").unwrap();
        assert_eq!(result.id, None);
    }

    #[test]
    fn test_parse_sessionid_empty() {
        assert!(matches!(
            parse_sessionid(""),
            Err(AuditError::ParseError(_))
        ));
    }

    #[test]
    fn test_parse_sessionid_invalid() {
        assert!(matches!(
            parse_sessionid("abc"),
            Err(AuditError::ParseError(_))
        ));
    }

    #[test]
    fn test_is_privilege_errno() {
        assert!(is_privilege_errno(libc::EPERM));
        assert!(is_privilege_errno(libc::EACCES));
        assert!(!is_privilege_errno(libc::ENOENT));
        assert!(!is_privilege_errno(libc::EIO));
    }

    #[test]
    fn test_is_not_supported_errno() {
        assert!(is_not_supported_errno(libc::EAFNOSUPPORT));
        assert!(is_not_supported_errno(libc::EPROTONOSUPPORT));
        assert!(is_not_supported_errno(libc::ECONNREFUSED));
        assert!(is_not_supported_errno(libc::ENOPROTOOPT));
        assert!(!is_not_supported_errno(libc::EPERM));
        assert!(!is_not_supported_errno(libc::ENOENT));
    }

    #[test]
    fn test_nlmsg_length() {
        // NLMSG_LENGTH with zero payload should be size_of nlmsghdr
        assert!(nlmsg_length(0) >= 16); // nlmsghdr is at least 16 bytes
        assert_eq!(nlmsg_length(20), nlmsg_length(0) + 20);
    }

    #[test]
    fn test_audit_feature_msg_request() {
        let msg = AuditFeatureMsg::new_request();
        // SAFETY: `msg` initialized this packed integer field; `addr_of!` creates
        // no reference and `read_unaligned` permits the field's alignment.
        let nlmsg_type: u16 = unsafe_ffi!(std::ptr::read_unaligned(std::ptr::addr_of!(
            msg.hdr.nlmsg_type
        )));
        // SAFETY: `msg` initialized this packed integer field; `addr_of!` creates
        // no reference and `read_unaligned` permits the field's alignment.
        let nlmsg_flags: u16 = unsafe_ffi!(std::ptr::read_unaligned(std::ptr::addr_of!(
            msg.hdr.nlmsg_flags
        )));
        // SAFETY: `msg` initialized this packed integer field; `addr_of!` creates
        // no reference and `read_unaligned` permits the field's alignment.
        let nlmsg_seq: u32 = unsafe_ffi!(std::ptr::read_unaligned(std::ptr::addr_of!(
            msg.hdr.nlmsg_seq
        )));
        // SAFETY: `msg` initialized this packed integer field; `addr_of!` creates
        // no reference and `read_unaligned` permits the field's alignment.
        let nlmsg_pid: u32 = unsafe_ffi!(std::ptr::read_unaligned(std::ptr::addr_of!(
            msg.hdr.nlmsg_pid
        )));
        // SAFETY: `msg` initialized this packed integer field; `addr_of!` creates
        // no reference and `read_unaligned` permits the field's alignment.
        let err_error: i32 =
            unsafe_ffi!(std::ptr::read_unaligned(std::ptr::addr_of!(msg.err.error)));
        assert_eq!(nlmsg_type, AUDIT_GET_FEATURE);
        assert_eq!(nlmsg_flags, NLM_F_REQUEST_ACK);
        assert_eq!(nlmsg_seq, 1);
        assert_eq!(nlmsg_pid, 0);
        assert_eq!(err_error, 0);
    }

    #[test]
    fn test_audit_error_display() {
        assert!(!AuditError::NotSupported.to_string().is_empty());
        assert!(!AuditError::PermissionDenied.to_string().is_empty());
        assert!(!AuditError::NoSuchProcess.to_string().is_empty());
        assert!(!AuditError::NoData.to_string().is_empty());
        assert!(!AuditError::Io("test".into()).to_string().is_empty());
        assert!(!AuditError::ParseError("bad".into()).to_string().is_empty());
    }

    #[test]
    fn test_audit_error_debug() {
        // Ensure all variants implement Debug without panicking
        let errors = vec![
            AuditError::NotSupported,
            AuditError::PermissionDenied,
            AuditError::NoSuchProcess,
            AuditError::NoData,
            AuditError::Io("err".into()),
            AuditError::ParseError("err".into()),
        ];
        for e in &errors {
            let _ = format!("{e:?}");
        }
    }

    #[test]
    fn test_audit_error_equality() {
        assert_eq!(AuditError::NotSupported, AuditError::NotSupported);
        assert_eq!(AuditError::NoData, AuditError::NoData);
        assert_ne!(AuditError::NotSupported, AuditError::NoData);
        assert_eq!(AuditError::Io("a".into()), AuditError::Io("a".into()));
        assert_ne!(AuditError::Io("a".into()), AuditError::Io("b".into()));
    }

    #[test]
    fn test_use_audit_returns_bool() {
        // Just verify it returns without panic; actual value depends on system.
        let _ = use_audit();
    }

    #[test]
    fn test_reset_audit_cache() {
        reset_audit_cache();
        assert_eq!(AUDIT_ENABLED.load(std::sync::atomic::Ordering::Relaxed), -1);
    }

    #[test]
    fn test_read_loginuid_self() {
        // On Linux with audit, this should succeed or return Io error.
        let result = read_self_loginuid();
        match result {
            Ok(login_uid) => {
                // If we got a value, it should be a valid u32
                if let Some(uid) = login_uid.uid {
                    assert!(uid <= u32::MAX);
                }
            }
            Err(_) => {
                // Acceptable on non-Linux or without audit support
            }
        }
    }

    #[test]
    fn test_read_sessionid_self() {
        let result = read_self_sessionid();
        match result {
            Ok(session) => {
                if let Some(id) = session.id {
                    assert!(audit_session_is_valid(id));
                }
            }
            Err(_) => {
                // Acceptable on non-Linux or without audit support
            }
        }
    }

    #[test]
    fn test_read_loginuid_nonexistent_pid() {
        // PID 99999 is extremely unlikely to exist
        let result = read_loginuid(99999);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_sessionid_nonexistent_pid() {
        let result = read_sessionid(99999);
        assert!(result.is_err());
    }
}
