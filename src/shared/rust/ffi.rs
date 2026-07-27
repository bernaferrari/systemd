// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: N/A (FFI conventions)
//
// FFI layer for the shared Rust crate. Re-exports types from systemd_basic_rs
// and provides additional safe Rust wrappers for common C library operations.

#[cfg(all(target_os = "linux", target_env = "gnu"))]
use libc::c_char;

// ── Re-export all FFI types from basic ──────────────────────────────────────

pub use systemd_basic_rs::ffi::*;

pub fn errno() -> std::os::raw::c_int {
    get_errno()
}

// libc exposes updwtmpx() for several non-Linux targets, but not Linux. The
// project only enables UTMP with glibc, where <utmpx.h> declares this symbol.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
unsafe extern "C" {
    pub fn updwtmpx(file: *const c_char, ut: *const libc::utmpx);
}

#[cfg(not(target_os = "linux"))]
pub mod linux_compat {
    use std::os::raw::c_int;

    pub const O_PATH: c_int = 0;
    pub const O_NOATIME: c_int = 0;
    pub const SOCK_CLOEXEC: c_int = 0;
    pub const SOCK_NONBLOCK: c_int = 0;
    pub const AF_NETLINK: c_int = 16;
    pub const NLM_F_REQUEST: c_int = 1;
    pub const NLM_F_ACK: c_int = 4;
    pub const AT_EMPTY_PATH: c_int = 0;
    pub const SO_PASSCRED: c_int = 0;
    pub const SCM_CREDENTIALS: c_int = 0;
    pub const SI_QUEUE: c_int = -1;
    pub const SECCOMP_MODE_FILTER: c_int = 2;
    pub const PR_SET_SECCOMP: c_int = 22;
    pub const PR_GET_SECCOMP: c_int = 21;
    pub const RB_AUTOBOOT: c_int = 0;
    pub const LINUX_REBOOT_CMD_RESTART2: c_int = 0;
    pub const GRND_NONBLOCK: c_int = 1;
    pub const BLKROSET: c_int = 0;
    pub const FALLOC_FL_KEEP_SIZE: c_int = 1;
    pub const FALLOC_FL_PUNCH_HOLE: c_int = 2;
    pub const FS_NODUMP_FL: c_int = 0;
    pub const FS_NOATIME_FL: c_int = 0;
    pub const FS_DIRSYNC_FL: c_int = 0;
    pub const FS_SYNC_FL: c_int = 0;
    pub const FS_PROJINHERIT_FL: c_int = 0;
    pub const FS_NOCOW_FL: c_int = 0;
    pub const SYS_renameat2: c_int = 0;
    pub const SYS_copy_file_range: c_int = 0;

    pub const ERFKILL: c_int = 132;
    pub const EUNATCH: c_int = 150;
    pub const EUCLEAN: c_int = 117;
    pub const EBADSLT: c_int = 57;
    pub const ENOANO: c_int = 55;
    pub const ENOPKG: c_int = 65;
    pub const ENOKEY: c_int = 126;
    pub const EBADFD: c_int = 77;

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    pub struct sockaddr_nl {
        pub nl_family: c_int,
        pub nl_pad: c_int,
        pub nl_pid: u32,
        pub nl_groups: u32,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    pub struct ucred {
        pub pid: c_int,
        pub uid: u32,
        pub gid: u32,
    }

    ///
    /// # Safety
    /// Every non-null input pointer must be valid and properly aligned for all
    /// reads performed by this call, and every non-null output pointer must be
    /// valid and properly aligned for all writes. Pointer ranges must not alias
    /// in ways forbidden by the operation's documented ownership contract.
    pub unsafe fn getrandom(_buf: *mut u8, _buflen: usize, _flags: c_int) -> c_int {
        -1
    }

    ///
    /// # Safety
    /// Every non-null input pointer must be valid and properly aligned for all
    /// reads performed by this call, and every non-null output pointer must be
    /// valid and properly aligned for all writes. Pointer ranges must not alias
    /// in ways forbidden by the operation's documented ownership contract.
    pub unsafe fn pipe2(_pipefd: *mut c_int, _flags: c_int) -> c_int {
        -1
    }

    ///
    /// # Safety
    /// The caller must uphold the generated or platform ABI invariants documented
    /// by this operation; no raw Rust references may outlive the call.
    pub unsafe fn syncfs(_fd: c_int) -> c_int {
        -1
    }

    ///
    /// # Safety
    /// The caller must uphold the generated or platform ABI invariants documented
    /// by this operation; no raw Rust references may outlive the call.
    pub unsafe fn prctl(
        _option: c_int,
        _arg2: c_int,
        _arg3: c_int,
        _arg4: c_int,
        _arg5: c_int,
    ) -> c_int {
        -1
    }

    ///
    /// # Safety
    /// Every non-null input pointer must be valid and properly aligned for all
    /// reads performed by this call, and every non-null output pointer must be
    /// valid and properly aligned for all writes. Pointer ranges must not alias
    /// in ways forbidden by the operation's documented ownership contract.
    pub unsafe fn fallocate(_fd: c_int, _mode: c_int, _offset: i64, _length: i64) -> c_int {
        -1
    }

    ///
    /// # Safety
    /// Every non-null input pointer must be valid and properly aligned for all
    /// reads performed by this call, and every non-null output pointer must be
    /// valid and properly aligned for all writes. Pointer ranges must not alias
    /// in ways forbidden by the operation's documented ownership contract.
    pub unsafe fn explicit_bzero(_s: *mut u8, _n: usize) {}
}

#[cfg(target_os = "linux")]
pub mod linux_compat {
    pub use libc::{
        explicit_bzero, fallocate, getrandom, pipe2, prctl, sockaddr_nl, syncfs, ucred, AF_NETLINK,
        AT_EMPTY_PATH, EBADFD, EBADSLT, ENOANO, ENOKEY, ENOPKG, ERFKILL, EUCLEAN, EUNATCH,
        FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, GRND_NONBLOCK, LINUX_REBOOT_CMD_RESTART2,
        NLM_F_ACK, NLM_F_REQUEST, O_NOATIME, O_PATH, PR_GET_SECCOMP, PR_SET_SECCOMP, RB_AUTOBOOT,
        SCM_CREDENTIALS, SECCOMP_MODE_FILTER, SI_QUEUE, SOCK_CLOEXEC, SOCK_NONBLOCK, SO_PASSCRED,
    };
    pub use libc::{SYS_copy_file_range, SYS_renameat2};
    pub use libc::{
        BLKROSET, FS_DIRSYNC_FL, FS_NOATIME_FL, FS_NOCOW_FL, FS_NODUMP_FL, FS_PROJINHERIT_FL,
        FS_SYNC_FL,
    };
}

pub use linux_compat::*;

// ── Error type ─────────────────────────────────────────────────────────────

/// Error type for FFI bridge operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiError {
    /// A null pointer was provided where a valid pointer was required.
    NullPointer,
    /// The destination buffer is too small for the source data.
    BufferTooSmall,
    /// Invalid UTF-8 encountered when converting a C string.
    InvalidUtf8,
}

impl std::fmt::Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NullPointer => write!(f, "null pointer provided"),
            Self::BufferTooSmall => write!(f, "destination buffer too small"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 in C string"),
        }
    }
}

impl std::error::Error for FfiError {}

// ── Safe memory operations ─────────────────────────────────────────────────

/// Copy all bytes from `src` into `dest`, returning the remaining unwritten
/// portion of `dest`.
///
/// This is a safe replacement for the C `mempcpy(3)` function.
///
/// # Errors
///
/// Returns `FfiError::BufferTooSmall` if `src.len() > dest.len()`.
///
/// # Examples
///
/// ```
/// let mut buf = [0u8; 8];
/// let rest = copy_bytes(&mut buf, b"hello").unwrap();
/// assert_eq!(&buf[..5], b"hello");
/// assert_eq!(rest.len(), 3);
/// ```
pub fn copy_bytes<'a>(dest: &'a mut [u8], src: &[u8]) -> Result<&'a mut [u8], FfiError> {
    if src.len() > dest.len() {
        return Err(FfiError::BufferTooSmall);
    }
    dest[..src.len()].copy_from_slice(src);
    Ok(&mut dest[src.len()..])
}

/// Returns the length of the null-terminated C string at `ptr`, excluding the
/// null terminator byte.
///
/// This is a safe-documented replacement for calling `strlen(3)` through
/// raw `extern "C"`.
///
/// # Safety
///
/// `ptr` must point to a valid, null-terminated C string.
pub unsafe fn c_string_length(ptr: *const c_char) -> usize {
    // SAFETY: Caller guarantees ptr points to a valid null-terminated C string.
    unsafe { std::ffi::CStr::from_ptr(ptr).to_bytes().len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_errno_negation() {
        assert_eq!(Errno::EINVAL.to_neg_errno(), -22);
        assert_eq!(Errno::ENOENT.to_neg_errno(), -2);
        assert_eq!(Errno::ENOMEM.to_neg_errno(), -12);
        assert_eq!(Errno::ESRCH.to_neg_errno(), -3);
        assert_eq!(Errno::EPERM.to_neg_errno(), -1);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_errno_discriminant_values() {
        assert_eq!(Errno::EPERM as i32, 1);
        assert_eq!(Errno::ENOENT as i32, 2);
        assert_eq!(Errno::ESRCH as i32, 3);
        assert_eq!(Errno::EINTR as i32, 4);
        assert_eq!(Errno::EIO as i32, 5);
        assert_eq!(Errno::EBADF as i32, 9);
        assert_eq!(Errno::ENOMEM as i32, 12);
        assert_eq!(Errno::EACCES as i32, 13);
        assert_eq!(Errno::EINVAL as i32, 22);
        assert_eq!(Errno::ENOSYS as i32, 38);
        assert_eq!(Errno::ETIMEDOUT as i32, 110);
        assert_eq!(Errno::ECONNREFUSED as i32, 111);
        assert_eq!(Errno::ECANCELED as i32, 125);
        assert_eq!(Errno::EHWPOISON as i32, 133);
        assert_eq!(Errno::EUNATCH as i32, 150);
    }

    #[test]
    fn test_errno_equality() {
        assert_eq!(Errno::EINVAL, Errno::EINVAL);
        assert_ne!(Errno::EINVAL, Errno::ENOMEM);
        assert_ne!(Errno::EPERM, Errno::EACCES);
    }

    #[test]
    fn test_uint64_max() {
        const UINT64_MAX: u64 = u64::MAX;
        assert_eq!(UINT64_MAX, u64::MAX);
    }

    #[test]
    fn test_errno_name() {
        assert_eq!(Errno::EINVAL.name(), "EINVAL");
        assert_eq!(Errno::ENOENT.name(), "ENOENT");
        assert_eq!(Errno::ENOMEM.name(), "ENOMEM");
        assert_eq!(Errno::EPERM.name(), "EPERM");
        assert_eq!(Errno::ECONNREFUSED.name(), "ECONNREFUSED");
        assert_eq!(Errno::EHWPOISON.name(), "EHWPOISON");
    }

    #[test]
    fn test_errno_display() {
        assert_eq!(format!("{}", Errno::EINVAL), "EINVAL (22)");
        assert_eq!(format!("{}", Errno::ENOENT), "ENOENT (2)");
        assert_eq!(format!("{}", Errno::ENOMEM), "ENOMEM (12)");
    }

    #[test]
    fn test_errno_from_neg_errno() {
        assert_eq!(Errno::from_neg_errno(-22), Some(Errno::EINVAL));
        assert_eq!(Errno::from_neg_errno(-2), Some(Errno::ENOENT));
        assert_eq!(Errno::from_neg_errno(-12), Some(Errno::ENOMEM));
        assert_eq!(Errno::from_neg_errno(-1), Some(Errno::EPERM));
        assert_eq!(Errno::from_neg_errno(22), None);
        assert_eq!(Errno::from_neg_errno(0), None);
        assert_eq!(Errno::from_neg_errno(-999), None);
    }

    // ── copy_bytes tests ────────────────────────────────────────────────

    #[test]
    fn test_copy_bytes_success() {
        let mut buf = [0u8; 8];
        {
            let rest = copy_bytes(&mut buf, b"hello").unwrap();
            assert_eq!(rest.len(), 3);
        }
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn test_copy_bytes_exact_fit() {
        let mut buf = [0u8; 5];
        {
            let rest = copy_bytes(&mut buf, b"hello").unwrap();
            assert!(rest.is_empty());
        }
        assert_eq!(&buf[..], b"hello");
    }

    #[test]
    fn test_copy_bytes_empty_source() {
        let mut buf = [1u8, 2, 3];
        let rest = copy_bytes(&mut buf, b"").unwrap();
        assert_eq!(rest.len(), 3);
        assert_eq!(&buf[..], &[1, 2, 3]);
    }

    #[test]
    fn test_copy_bytes_buffer_too_small() {
        let mut buf = [0u8; 3];
        let result = copy_bytes(&mut buf, b"hello");
        assert_eq!(result, Err(FfiError::BufferTooSmall));
    }

    #[test]
    fn test_ffi_error_display() {
        assert_eq!(
            format!("{}", FfiError::NullPointer),
            "null pointer provided"
        );
        assert_eq!(
            format!("{}", FfiError::BufferTooSmall),
            "destination buffer too small"
        );
        assert_eq!(
            format!("{}", FfiError::InvalidUtf8),
            "invalid UTF-8 in C string"
        );
    }

    #[test]
    fn test_ffi_error_equality() {
        assert_eq!(FfiError::NullPointer, FfiError::NullPointer);
        assert_ne!(FfiError::NullPointer, FfiError::BufferTooSmall);
        assert_ne!(FfiError::BufferTooSmall, FfiError::InvalidUtf8);
    }

    #[test]
    fn test_ffi_error_is_std_error() {
        let err: &dyn std::error::Error = &FfiError::NullPointer;
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn test_c_string_length() {
        use std::ffi::CString;
        let s = CString::new("hello").unwrap();
        // SAFETY: s.as_ptr() points to a valid null-terminated C string.
        assert_eq!(unsafe { c_string_length(s.as_ptr()) }, 5);

        let empty = CString::new("").unwrap();
        // SAFETY: empty.as_ptr() points to a valid null-terminated C string.
        assert_eq!(unsafe { c_string_length(empty.as_ptr()) }, 0);

        let long = CString::new("abcdefghij").unwrap();
        // SAFETY: long.as_ptr() points to a valid null-terminated C string.
        assert_eq!(unsafe { c_string_length(long.as_ptr()) }, 10);
    }
}
