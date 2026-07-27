// SPDX-License-Identifier: LGPL-2.1-or-later

use crate::ffi::{ENOANO, EUCLEAN};
use std::io;

// ── Loop flags (from linux/loop.h) ─────────────────────────────────────────

/// LO_FLAGS_READ_ONLY: access backing file read-only.
pub const LO_FLAGS_READ_ONLY: u32 = 1;
/// LO_FLAGS_AUTOCLEAR: auto-clear on last close.
pub const LO_FLAGS_AUTOCLEAR: u32 = 4;
/// LO_FLAGS_PARTSCAN: scan partitions on attach.
pub const LO_FLAGS_PARTSCAN: u32 = 8;
/// LO_FLAGS_DIRECT_IO: direct I/O mode.
pub const LO_FLAGS_DIRECT_IO: u32 = 16;
/// systemd-internal request to force a real loop device before a caller
/// populates a partition table. This bit must never reach the kernel ABI.
pub(super) const LOOP_DEVICE_MAY_POPULATE_PARTITION_TABLE: u32 = 1 << 16;

// ── Open flags ─────────────────────────────────────────────────────────────

/// Default open flag for read-write access.
pub const O_RDWR: i32 = libc::O_RDWR;
/// Open flag for read-only access.
pub const O_RDONLY: i32 = libc::O_RDONLY;
/// Close-on-exec flag.
pub(super) const O_CLOEXEC: i32 = libc::O_CLOEXEC;
/// Non-blocking flag.
pub(super) const O_NONBLOCK: i32 = libc::O_NONBLOCK;
/// No controlling terminal flag.
pub(super) const O_NOCTTY: i32 = libc::O_NOCTTY;
/// Direct I/O flag.
///
/// Kept behind the Linux target because loop-device ioctls are Linux UAPI;
/// `libc` supplies the architecture-specific value (which differs on ARM,
/// MIPS, PowerPC, and SPARC).
#[cfg(target_os = "linux")]
pub(super) const O_DIRECT: i32 = libc::O_DIRECT;
/// O_PATH: path-only access (cannot read/write).
///
/// `libc` also handles the SPARC exception to the otherwise common value.
#[cfg(target_os = "linux")]
pub(super) const O_PATH: i32 = libc::O_PATH;
/// Access mode mask.
pub(super) const O_ACCMODE: i32 = libc::O_ACCMODE;

// ── Lock operations ────────────────────────────────────────────────────────

/// Shared (read) lock.
pub const LOCK_SH: i32 = libc::LOCK_SH;
/// Exclusive (write) lock.
pub const LOCK_EX: i32 = libc::LOCK_EX;
/// Unlock.
pub const LOCK_UN: i32 = libc::LOCK_UN;
/// Non-blocking lock flag.
pub const LOCK_NB: i32 = libc::LOCK_NB;

// ── Misc constants ─────────────────────────────────────────────────────────

/// Default sector size.
pub const DEFAULT_SECTOR_SIZE: u32 = 512;

/// Sentinel value meaning "no change" for size/offset.
pub const NO_CHANGE: u64 = u64::MAX;

/// Sentinel value meaning "auto-detect sector size".
pub const AUTO_SECTOR_SIZE: u32 = u32::MAX;

/// Maximum retry attempts for loop allocation.
pub(super) const MAX_ATTEMPTS: u32 = 64;

/// Maximum retry attempts for LOOP_CTL_REMOVE.
pub(super) const MAX_REMOVE_ATTEMPTS: u32 = 39;

// ── Error type ─────────────────────────────────────────────────────────────

/// Errors returned by loop device operations.
#[derive(Debug)]
pub enum LoopError {
    /// A POSIX errno occurred.
    Errno(i32),
    /// Device is busy (EBUSY).
    Busy,
    /// Device was absent / removed (ENODEV).
    DeviceAbsent,
    /// Direct I/O could not be enabled (ENOANO).
    DirectIoFailed,
    /// The fd does not refer to a block device (ENOTBLK).
    NotABlockDevice,
    /// Stale partitions needed removal (EUCLEAN).
    StalePartitions,
    /// Invalid argument.
    InvalidArgument,
    /// Buffer too small.
    NoBufferSpace,
    /// Not a loop device (foreign block device).
    NotALoopDevice,
    /// Ioctl not supported by kernel.
    IoctlNotSupported,
    /// I/O error.
    IoError,
    /// An operation timed out after maximum retries.
    MaxRetriesExceeded,
    /// Memory allocation failure.
    OutOfMemory,
    /// Invalid operation for current state.
    InvalidOperation(String),
    /// An I/O error from std::io.
    Io(io::Error),
}

impl std::fmt::Display for LoopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoopError::Errno(e) => write!(f, "loop error: errno {}", e),
            LoopError::Busy => write!(f, "loop device is busy"),
            LoopError::DeviceAbsent => write!(f, "loop device is absent"),
            LoopError::DirectIoFailed => write!(f, "direct I/O could not be enabled"),
            LoopError::NotABlockDevice => write!(f, "not a block device"),
            LoopError::StalePartitions => write!(f, "stale partitions on loop device"),
            LoopError::InvalidArgument => write!(f, "invalid argument"),
            LoopError::NoBufferSpace => write!(f, "buffer too small"),
            LoopError::NotALoopDevice => write!(f, "not a loop device"),
            LoopError::IoctlNotSupported => write!(f, "ioctl not supported by kernel"),
            LoopError::IoError => write!(f, "I/O error"),
            LoopError::MaxRetriesExceeded => write!(f, "maximum retries exceeded"),
            LoopError::OutOfMemory => write!(f, "out of memory"),
            LoopError::InvalidOperation(msg) => write!(f, "invalid operation: {}", msg),
            LoopError::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for LoopError {}

impl LoopError {
    /// Convert a raw errno value to a LoopError.
    pub fn from_errno(errno: i32) -> Self {
        match errno {
            libc::EBUSY => LoopError::Busy,
            libc::ENODEV => LoopError::DeviceAbsent,
            ENOANO => LoopError::DirectIoFailed,
            libc::ENOTBLK => LoopError::NotABlockDevice,
            EUCLEAN => LoopError::StalePartitions,
            libc::EINVAL => LoopError::InvalidArgument,
            libc::ENOBUFS => LoopError::NoBufferSpace,
            libc::ENOTTY => LoopError::NotALoopDevice,
            libc::EIO => LoopError::IoError,
            libc::ENOMEM => LoopError::OutOfMemory,
            libc::ENOTCONN | libc::EOPNOTSUPP | libc::ENOSYS => LoopError::IoctlNotSupported,
            e => LoopError::Errno(e),
        }
    }

    /// Convert an `io::Error` into a LoopError.
    pub fn from_io(err: io::Error) -> Self {
        match err.raw_os_error() {
            Some(e) => LoopError::from_errno(e),
            None => LoopError::Io(err),
        }
    }

    /// Get the raw errno value if this is an errno-based error.
    pub fn raw_errno(&self) -> Option<i32> {
        match self {
            LoopError::Errno(e) => Some(*e),
            LoopError::Busy => Some(libc::EBUSY),
            LoopError::DeviceAbsent => Some(libc::ENODEV),
            LoopError::DirectIoFailed => Some(ENOANO),
            LoopError::NotABlockDevice => Some(libc::ENOTBLK),
            LoopError::StalePartitions => Some(EUCLEAN),
            LoopError::InvalidArgument => Some(libc::EINVAL),
            LoopError::NoBufferSpace => Some(libc::ENOBUFS),
            LoopError::IoError => Some(libc::EIO),
            LoopError::OutOfMemory => Some(libc::ENOMEM),
            _ => None,
        }
    }
}

impl From<io::Error> for LoopError {
    fn from(err: io::Error) -> Self {
        LoopError::from_io(err)
    }
}

// ── Loop flags bitflags ────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags for configuring a loop device.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LoopFlags: u32 {
        /// Access the backing file read-only.
        const READ_ONLY = LO_FLAGS_READ_ONLY;
        /// Auto-clear the loop device on last close.
        const AUTOCLEAR = LO_FLAGS_AUTOCLEAR;
        /// Automatically scan for partitions.
        const PARTSCAN = LO_FLAGS_PARTSCAN;
        /// Use direct I/O to the backing file.
        const DIRECT_IO = LO_FLAGS_DIRECT_IO;
    }
}

impl Default for LoopFlags {
    fn default() -> Self {
        LoopFlags::AUTOCLEAR
    }
}

// ── Lock operation type ────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Lock operations for flock() on loop devices.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LockOp: i32 {
        /// Shared (read) lock.
        const SHARED = LOCK_SH;
        /// Exclusive (write) lock.
        const EXCLUSIVE = LOCK_EX;
        /// Unlock.
        const UNLOCK = LOCK_UN;
        /// Non-blocking attempt.
        const NON_BLOCKING = LOCK_NB;
    }
}

pub(super) fn lock_op_is_valid(operation: LockOp) -> bool {
    matches!(operation.bits() & !LOCK_NB, LOCK_UN | LOCK_SH | LOCK_EX)
}

// ── Public API: loop_device_make ───────────────────────────────────────────

/// Options for creating a loop device.
#[derive(Debug, Clone)]
pub struct LoopDeviceMakeOptions {
    /// Open flags (O_RDWR or O_RDONLY). `None` = auto-detect from fd.
    pub open_flags: Option<i32>,
    /// Offset within the backing file (bytes).
    pub offset: u64,
    /// Size limit (bytes). 0 = whole file, `NO_CHANGE` = whole file.
    pub size: u64,
    /// Sector size. 0 = default 512, `AUTO_SECTOR_SIZE` = auto-detect.
    pub sector_size: u32,
    /// Loop device flags.
    pub loop_flags: LoopFlags,
    /// Lock operation to apply after creation.
    pub lock_op: LockOp,
}

impl Default for LoopDeviceMakeOptions {
    fn default() -> Self {
        Self {
            open_flags: None,
            offset: 0,
            size: 0,
            sector_size: 0,
            loop_flags: LoopFlags::default(),
            lock_op: LockOp::EXCLUSIVE,
        }
    }
}
