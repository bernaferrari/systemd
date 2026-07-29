// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/blockdev-util.c, src/shared/blockdev-util.h
//
// Block device utilities - device size, partition management,
// sector size queries, and whole-disk resolution.
//
// Replaces the C FFI stubs with idiomatic safe Rust wrappers.
// `unsafe` is confined to ioctl syscalls (BLKGETSIZE64, BLKSSZGET).

use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use crate::ffi::Errno;
use systemd_basic_rs::devnum_util::{devnum_from_major_minor, devnum_major, devnum_minor};

// ── Constants ─────────────────────────────────────────────────────────────

/// Default logical sector size for block devices.
pub const DEFAULT_SECTOR_SIZE: u32 = 512;

/// Kernel ioctl request code: BLKGETSIZE64 (get device size in bytes).
const BLKGETSIZE64: u64 = 0x80081272;

/// Kernel ioctl request code: BLKSSZGET (get logical sector size).
const BLKSSZGET: u64 = 0x80041270;

/// Maximum recursion depth for encrypted-device chase.
const ENCRYPTION_CHASE_DEPTH: u32 = 10;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors returned by block device operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockDevError {
    /// A POSIX errno occurred.
    Errno(Errno),
    /// The fd does not refer to a block device.
    NotABlockDevice,
    /// No backing block device was found.
    NoBlockDevice,
    /// The dm-uuid prefix indicates dm-crypt encryption.
    Encrypted,
    /// A sysfs attribute had an unexpected value.
    InvalidSysfsValue(String),
    /// Recursion limit exceeded while chasing device layers.
    RecursionLimitExceeded,
    /// Multiple backing devices with different devnums.
    NotUnique,
}

impl BlockDevError {
    /// Convert an `io::Error` into a `BlockDevError`, mapping common errno
    /// values to their typed equivalents.
    pub fn from_io(err: io::Error) -> Self {
        let raw = err.raw_os_error().unwrap_or_else(|| match err.kind() {
            io::ErrorKind::NotFound => libc::ENOENT,
            io::ErrorKind::PermissionDenied => libc::EACCES,
            _ => libc::EIO,
        });
        match Errno_from_raw(raw) {
            Some(e) => BlockDevError::Errno(e),
            None => BlockDevError::Errno(Errno::EIO),
        }
    }

    /// Return the underlying errno value, if any.
    pub fn errno(&self) -> Option<Errno> {
        match self {
            BlockDevError::Errno(e) => Some(*e),
            _ => None,
        }
    }
}

impl std::fmt::Display for BlockDevError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockDevError::Errno(e) => write!(f, "block device error: errno {:?}", e),
            BlockDevError::NotABlockDevice => write!(f, "not a block device"),
            BlockDevError::NoBlockDevice => write!(f, "no backing block device"),
            BlockDevError::Encrypted => write!(f, "device is encrypted (dm-crypt)"),
            BlockDevError::InvalidSysfsValue(v) => {
                write!(f, "invalid sysfs value: {}", v)
            }
            BlockDevError::RecursionLimitExceeded => {
                write!(f, "recursion limit exceeded chasing device layers")
            }
            BlockDevError::NotUnique => {
                write!(f, "device backed by multiple distinct devices")
            }
        }
    }
}

impl std::error::Error for BlockDevError {}

impl From<io::Error> for BlockDevError {
    fn from(err: io::Error) -> Self {
        BlockDevError::from_io(err)
    }
}

impl From<Errno> for BlockDevError {
    fn from(e: Errno) -> Self {
        BlockDevError::Errno(e)
    }
}

/// Try to map a raw errno integer to the `Errno` enum.
fn Errno_from_raw(raw: i32) -> Option<Errno> {
    match raw {
        1 => Some(Errno::EPERM),
        2 => Some(Errno::ENOENT),
        5 => Some(Errno::EIO),
        6 => Some(Errno::ENXIO),
        9 => Some(Errno::EBADF),
        11 => Some(Errno::EAGAIN),
        12 => Some(Errno::ENOMEM),
        13 => Some(Errno::EACCES),
        15 => Some(Errno::ENOTBLK),
        16 => Some(Errno::EBUSY),
        19 => Some(Errno::ENODEV),
        21 => Some(Errno::EISDIR),
        22 => Some(Errno::EINVAL),
        25 => Some(Errno::ENOTTY),
        28 => Some(Errno::ENOSPC),
        34 => Some(Errno::ERANGE),
        38 => Some(Errno::ENOSYS),
        39 => Some(Errno::ENOTEMPTY),
        40 => Some(Errno::ELOOP),
        61 => Some(Errno::ENODATA),
        75 => Some(Errno::EOVERFLOW),
        76 => Some(Errno::ENOTUNIQ),
        117 => Some(Errno::ESTALE),
        _ => None,
    }
}

// ── Lookup flags ──────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling block device lookup behaviour.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BlockDeviceLookupFlags: u32 {
        /// Resolve to the whole block device (e.g. sda, nvme0n1).
        const WHOLE_DISK   = 1 << 0;
        /// Allow regular files/dirs; resolve their backing block device.
        const BACKING      = 1 << 1;
        /// Chase through DM layers to find the originating device.
        const ORIGINATING  = 1 << 2;
    }
}

// ── Result type alias ─────────────────────────────────────────────────────

/// Convenience alias used by every public function in this module.
pub type Result<T> = std::result::Result<T, BlockDevError>;

// ── dev_t helpers ─────────────────────────────────────────────────────────

/// Extract the device major number from a raw `dev_t`.
#[inline]
pub fn dev_major(devt: u64) -> u32 {
    devnum_major(devt)
}

/// Extract the device minor number from a raw `dev_t`.
#[inline]
pub fn dev_minor(devt: u64) -> u32 {
    devnum_minor(devt)
}

/// Build a `dev_t` from major and minor numbers.
#[inline]
pub fn make_dev(major: u32, minor: u32) -> u64 {
    devnum_from_major_minor(major, minor)
}

/// Return the sysfs path for a block device: `/sys/dev/block/<major>:<minor>`.
pub fn sys_block_path(devt: u64) -> String {
    format!("/sys/dev/block/{}:{}", dev_major(devt), dev_minor(devt))
}

/// Return the sysfs path for a specific attribute of a block device.
pub fn sys_block_attr_path(devt: u64, attr: &str) -> String {
    format!(
        "/sys/dev/block/{}:{}/{}",
        dev_major(devt),
        dev_minor(devt),
        attr
    )
}

// ── Core operations ───────────────────────────────────────────────────────

/// Get the block device size in bytes via `BLKGETSIZE64` ioctl.
///
/// # Errors
///
/// Returns an error if the fd is invalid or not a block device.
pub fn blockdev_get_device_size<Fd: AsRawFd>(fd: &Fd) -> Result<u64> {
    let mut size: u64 = 0;
    // SAFETY: We pass a valid pointer to a u64. The kernel writes the
    // device size into it. `AsRawFd` guarantees the fd is valid for the
    // lifetime of this call.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), BLKGETSIZE64, &mut size) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        return Err(BlockDevError::from_io(err));
    }
    Ok(size)
}

/// Get the logical sector size of a block device via `BLKSSZGET` ioctl.
///
/// Returns the sector size (typically 512). Returns an error if the
/// reported size is non-positive or the ioctl fails.
///
/// # Errors
///
/// Returns `BlockDevError::Errno` on ioctl failure, or
/// `BlockDevError::InvalidSysfsValue` if the kernel reports an invalid
/// sector size.
pub fn blockdev_get_sector_size<Fd: AsRawFd>(fd: &Fd) -> Result<u32> {
    let mut sector_size: i32 = 0;
    // SAFETY: We pass a valid pointer to a i32. The kernel writes the
    // sector size into it.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), BLKSSZGET, &mut sector_size) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        return Err(BlockDevError::from_io(err));
    }
    if sector_size <= 0 {
        return Err(BlockDevError::InvalidSysfsValue(format!(
            "sector size {}",
            sector_size
        )));
    }
    Ok(sector_size as u32)
}

/// Get the whole-disk device number for a partition device number.
///
/// Checks `/sys/dev/block/<M>:<m>/queue` — if it exists, the device is
/// already a whole disk. Otherwise checks `/sys/dev/block/<M>:<m>/partition`
/// and follows `/sys/dev/block/<M>:<m>/../dev` to find the parent.
///
/// Returns `Ok(WholeDiskResult::AlreadyWhole(devt))` if the device is
/// already a whole disk, or `Ok(WholeDiskResult::Resolved(devt))` if
/// it was resolved to the parent.
///
/// # Errors
///
/// Returns `BlockDevError::Errno(ENODEV)` if the major number is zero,
/// or on any sysfs access failure.
pub fn block_get_whole_disk(devt: u64) -> Result<WholeDiskResult> {
    if dev_major(devt) == 0 {
        return Err(BlockDevError::Errno(Errno::ENODEV));
    }

    // If it has a queue directory, it's already a whole disk.
    let queue_path = sys_block_attr_path(devt, "queue");
    match fs::metadata(&queue_path) {
        Ok(_) => return Ok(WholeDiskResult::AlreadyWhole(devt)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(BlockDevError::from_io(e)),
    }

    // Check if it is a partition.
    let partition_path = sys_block_attr_path(devt, "partition");
    match fs::metadata(&partition_path) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Not a partition and not a whole disk with queue.
            return Err(BlockDevError::Errno(Errno::ENXIO));
        }
        Err(e) => return Err(BlockDevError::from_io(e)),
    }

    // Read the parent's dev number from ../dev.
    let parent_dev_path = sys_block_attr_path(devt, "../dev");
    let parent_dev_str = fs::read_to_string(&parent_dev_path).map_err(BlockDevError::from_io)?;
    let parent_dev_str = parent_dev_str.trim();
    let parent_devt = parse_devnum(parent_dev_str)?;

    // Verify the parent has a queue directory.
    let parent_queue_path = sys_block_attr_path(parent_devt, "queue");
    match fs::metadata(&parent_queue_path) {
        Ok(_) => {}
        Err(_) => return Err(BlockDevError::Errno(Errno::ENXIO)),
    }

    Ok(WholeDiskResult::Resolved(parent_devt))
}

/// Result of [`block_get_whole_disk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WholeDiskResult {
    /// The device is already a whole disk.
    AlreadyWhole(u64),
    /// The device is a partition; the field is the parent whole-disk dev_t.
    Resolved(u64),
}

impl WholeDiskResult {
    /// Return the whole-disk device number in either case.
    pub fn devt(self) -> u64 {
        match self {
            WholeDiskResult::AlreadyWhole(d) | WholeDiskResult::Resolved(d) => d,
        }
    }
}

/// Get the block device number backing a file descriptor.
///
/// Uses `fstat` to obtain the filesystem's backing device number. Returns
/// `Ok(None)` when the filesystem is not backed by a representable block
/// device (including the currently unported btrfs fallback case).
///
/// # Errors
///
/// Returns `BlockDevError::Errno(EBADF)` for bad fds.
pub fn get_block_device_fd<Fd: AsRawFd>(fd: &Fd) -> Result<Option<u64>> {
    let raw_fd = fd.as_raw_fd();
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: raw_fd is borrowed for this call and `stat` provides writable
    // storage of exactly the ABI-required size.
    if unsafe { libc::fstat(raw_fd, stat.as_mut_ptr()) } < 0 {
        return Err(BlockDevError::from_io(io::Error::last_os_error()));
    }
    // SAFETY: successful fstat initialized every field of `stat`.
    let stat = unsafe { stat.assume_init() };

    // C's get_block_device_fd() identifies the device backing the mounted
    // filesystem, not a block special file's st_rdev. A zero major number is
    // the special btrfs/devtmpfs path; btrfs ioctl fallback remains a separate
    // P2 rather than returning an incorrect st_rdev value.
    if dev_major(stat.st_dev as u64) == 0 {
        return Ok(None);
    }

    Ok(Some(stat.st_dev as u64))
}

/// Get the block device number backing a filesystem path.
///
/// Opens the path and delegates to [`get_block_device_fd`].
///
/// # Errors
///
/// Returns an error if the path cannot be opened or fstat'd.
pub fn get_block_device(path: &Path) -> Result<Option<u64>> {
    // Match C's O_NOFOLLOW|O_CLOEXEC open rather than silently resolving a
    // user-controlled final symlink before inspecting its backing device.
    let fd = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    get_block_device_fd(&fd)
}

/// Check whether a device is encrypted by reading `dm/uuid` from sysfs.
///
/// Returns `Ok(true)` if the sysfs path contains a `dm/uuid` file whose
/// content starts with `CRYPT-`.
///
/// # Errors
///
/// Returns `BlockDevError::Errno` on sysfs access failure (other than ENOENT).
pub fn blockdev_is_encrypted(sysfs_path: &Path, depth_left: u32) -> Result<bool> {
    if depth_left == 0 {
        return Err(BlockDevError::RecursionLimitExceeded);
    }

    let uuid_path = sysfs_path.join("dm/uuid");
    if let Ok(uuid) = fs::read_to_string(&uuid_path) {
        if uuid.trim().starts_with("CRYPT-") {
            return Ok(true);
        }
    }

    // Follow slaves/ directory for stacked devices.
    let slaves_path = sysfs_path.join("slaves");
    let entries = match fs::read_dir(&slaves_path) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(BlockDevError::from_io(e)),
    };

    let mut found_encrypted = false;
    for entry in entries.flatten() {
        match blockdev_is_encrypted(&entry.path(), depth_left - 1) {
            Ok(true) => found_encrypted = true,
            Ok(false) => return Ok(false),
            Err(e) => return Err(e),
        }
    }

    Ok(found_encrypted)
}

/// Check if the block device behind an fd is encrypted.
///
/// # Errors
///
/// Returns `BlockDevError::Errno` if the backing device cannot be determined.
pub fn fd_is_encrypted<Fd: AsRawFd>(fd: &Fd) -> Result<bool> {
    let devt = match get_block_device_fd(fd)? {
        Some(d) => d,
        None => return Ok(false),
    };

    let sysfs = PathBuf::from(sys_block_path(devt));
    blockdev_is_encrypted(&sysfs, ENCRYPTION_CHASE_DEPTH)
}

use std::path::PathBuf;

/// Check if the block device behind a path is encrypted.
///
/// # Errors
///
/// Returns `BlockDevError::Errno` if the path cannot be opened or the
/// backing device cannot be determined.
pub fn path_is_encrypted(path: &Path) -> Result<bool> {
    let devt = match get_block_device(path)? {
        Some(d) => d,
        None => return Ok(false),
    };

    let sysfs = PathBuf::from(sys_block_path(devt));
    blockdev_is_encrypted(&sysfs, ENCRYPTION_CHASE_DEPTH)
}

/// Check if partition scanning is enabled on a block device via sysfs.
///
/// Checks, in order:
/// 1. `partscan` sysfs attribute (kernel >= 6.10)
/// 2. Whether the device is a partition type (partitions never partscan)
/// 3. `loop/partscan` for loopback devices
/// 4. `ext_range` attribute (value <= 1 means disabled)
/// 5. `capability` attribute for GENHD_FL_NO_PART flags
///
/// # Errors
///
/// Returns `BlockDevError::Errno` on sysfs access failure.
pub fn blockdev_partscan_enabled(sysfs_dev_path: &Path) -> Result<bool> {
    // 1. Direct 'partscan' attribute (v6.10+)
    if let Ok(val) = fs::read_to_string(sysfs_dev_path.join("partscan")) {
        let trimmed = val.trim();
        if trimmed == "1" {
            return Ok(true);
        }
        if trimmed == "0" {
            return Ok(false);
        }
    }

    // 2. Check if it's a partition device
    if let Ok(val) = fs::read_to_string(sysfs_dev_path.join("uevent")) {
        for line in val.lines() {
            if line.starts_with("DEVTYPE=") {
                if let Some(devtype) = line.strip_prefix("DEVTYPE=") {
                    if devtype.trim() == "partition" {
                        return Ok(false);
                    }
                }
            }
        }
    }

    // 3. Loop device partscan
    if let Ok(val) = fs::read_to_string(sysfs_dev_path.join("loop/partscan")) {
        let trimmed = val.trim();
        if trimmed == "0" {
            return Ok(false);
        }
    }

    // 4. ext_range check
    if let Ok(val) = fs::read_to_string(sysfs_dev_path.join("ext_range")) {
        if let Ok(ext_range) = val.trim().parse::<i32>() {
            if ext_range <= 1 {
                return Ok(false);
            }
        }
    }

    // 5. capability check for GENHD_FL_NO_PART flags
    const GENHD_FL_NO_PART_OLD: u32 = 0x0200;
    const GENHD_FL_NO_PART_NEW: u32 = 0x0004;
    if let Ok(val) = fs::read_to_string(sysfs_dev_path.join("capability")) {
        if let Ok(capability) = u32::from_str_radix(val.trim(), 16) {
            if (capability & (GENHD_FL_NO_PART_OLD | GENHD_FL_NO_PART_NEW)) != 0 {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

/// Check if partition scanning is enabled on the block device behind an fd.
///
/// Resolves the block device from the fd and then checks sysfs.
///
/// # Errors
///
/// Returns an error if the block device cannot be resolved.
pub fn blockdev_partscan_enabled_fd<Fd: AsRawFd>(fd: &Fd) -> Result<bool> {
    let devt = get_block_device_fd(fd)?.ok_or(BlockDevError::NotABlockDevice)?;

    let sysfs = PathBuf::from(sys_block_path(devt));
    blockdev_partscan_enabled(&sysfs)
}

/// Parse a device number string of the form `"major:minor"` into a `u64`.
pub fn parse_devnum(s: &str) -> Result<u64> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(BlockDevError::InvalidSysfsValue(s.to_string()));
    }
    let major: u32 = parts[0]
        .parse()
        .map_err(|_| BlockDevError::InvalidSysfsValue(s.to_string()))?;
    let minor: u32 = parts[1]
        .parse()
        .map_err(|_| BlockDevError::InvalidSysfsValue(s.to_string()))?;
    Ok(make_dev(major, minor))
}

/// Construct the partition device node path for a given device node and partition number.
///
/// If the device node's filename ends with a digit, a `p` separator is inserted
/// (e.g., `/dev/sda` + 1 → `/dev/sda1`, `/dev/nvme0n1` + 1 → `/dev/nvme0n1p1`).
pub fn partition_node_of(node: &str, nr: u32) -> Result<String> {
    if nr == 0 {
        return Err(BlockDevError::Errno(Errno::EINVAL));
    }

    let path = Path::new(node);
    let file_name = path
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or(BlockDevError::Errno(Errno::EINVAL))?;

    let need_p = file_name
        .chars()
        .last()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false);

    let sep = if need_p { "p" } else { "" };
    let partition_name = format!("{}{}{}", file_name, sep, nr);

    if let Some(parent) = path.parent() {
        Ok(parent.join(&partition_name).to_string_lossy().into_owned())
    } else {
        Ok(partition_name)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── dev_t helpers ─────────────────────────────────────────────────

    #[test]
    fn test_dev_major_minor_roundtrip() {
        assert_eq!(dev_major(make_dev(8, 0)), 8);
        assert_eq!(dev_minor(make_dev(8, 0)), 0);
        assert_eq!(dev_major(make_dev(259, 3)), 259);
        assert_eq!(dev_minor(make_dev(259, 3)), 3);
        assert_eq!(dev_major(make_dev(0, 0)), 0);
        assert_eq!(dev_minor(make_dev(0, 0)), 0);
        assert_eq!(dev_major(make_dev(u32::MAX, u32::MAX)), u32::MAX);
        assert_eq!(dev_minor(make_dev(u32::MAX, u32::MAX)), u32::MAX);
    }

    #[test]
    fn test_make_dev_decompose_symmetry() {
        for &(maj, min) in &[(0, 0), (1, 0), (8, 1), (259, 7), (0xFFFF, 0)] {
            let devt = make_dev(maj, min);
            assert_eq!(dev_major(devt), maj);
            assert_eq!(dev_minor(devt), min);
        }
    }

    // ── sysfs path construction ──────────────────────────────────────

    #[test]
    fn test_sys_block_path() {
        assert_eq!(sys_block_path(make_dev(8, 0)), "/sys/dev/block/8:0");
        assert_eq!(sys_block_path(make_dev(259, 3)), "/sys/dev/block/259:3");
        assert_eq!(sys_block_path(make_dev(0, 0)), "/sys/dev/block/0:0");
    }

    #[test]
    fn test_sys_block_attr_path() {
        assert_eq!(
            sys_block_attr_path(make_dev(8, 0), "queue"),
            "/sys/dev/block/8:0/queue"
        );
        assert_eq!(
            sys_block_attr_path(make_dev(8, 1), "partition"),
            "/sys/dev/block/8:1/partition"
        );
        assert_eq!(
            sys_block_attr_path(make_dev(259, 0), "../dev"),
            "/sys/dev/block/259:0/../dev"
        );
    }

    // ── parse_devnum ─────────────────────────────────────────────────

    #[test]
    fn test_parse_devnum_valid() {
        assert_eq!(parse_devnum("8:0").unwrap(), make_dev(8, 0));
        assert_eq!(parse_devnum("259:3").unwrap(), make_dev(259, 3));
        assert_eq!(parse_devnum("0:0").unwrap(), make_dev(0, 0));
    }

    #[test]
    fn test_parse_devnum_invalid() {
        assert!(parse_devnum("8").is_err());
        assert!(parse_devnum("8:0:0").is_err());
        assert!(parse_devnum("abc:def").is_err());
        assert!(parse_devnum("").is_err());
        assert!(parse_devnum(":").is_err());
    }

    // ── partition_node_of ────────────────────────────────────────────

    #[test]
    fn test_partition_node_of_basic() {
        // Ends with non-digit → no 'p' separator
        assert_eq!(partition_node_of("/dev/sda", 1).unwrap(), "/dev/sda1");
        assert_eq!(partition_node_of("/dev/sda", 5).unwrap(), "/dev/sda5");
    }

    #[test]
    fn test_partition_node_of_trailing_digit() {
        // Ends with digit → insert 'p' separator
        assert_eq!(
            partition_node_of("/dev/nvme0n1", 1).unwrap(),
            "/dev/nvme0n1p1"
        );
        assert_eq!(partition_node_of("/dev/loop0", 2).unwrap(), "/dev/loop0p2");
    }

    #[test]
    fn test_partition_node_of_relative() {
        assert_eq!(partition_node_of("sda", 3).unwrap(), "sda3");
        assert_eq!(partition_node_of("nvme0n1", 1).unwrap(), "nvme0n1p1");
    }

    #[test]
    fn test_partition_node_of_zero_rejected() {
        assert!(partition_node_of("/dev/sda", 0).is_err());
    }

    // ── BlockDeviceLookupFlags ───────────────────────────────────────

    #[test]
    fn test_lookup_flags_values() {
        assert_eq!(BlockDeviceLookupFlags::WHOLE_DISK.bits(), 1);
        assert_eq!(BlockDeviceLookupFlags::BACKING.bits(), 2);
        assert_eq!(BlockDeviceLookupFlags::ORIGINATING.bits(), 4);
    }

    #[test]
    fn test_lookup_flags_combinations() {
        let combined = BlockDeviceLookupFlags::WHOLE_DISK
            | BlockDeviceLookupFlags::BACKING
            | BlockDeviceLookupFlags::ORIGINATING;
        assert_eq!(combined.bits(), 0b111);

        let none = BlockDeviceLookupFlags::empty();
        assert_eq!(none.bits(), 0);
        assert!(!none.contains(BlockDeviceLookupFlags::WHOLE_DISK));
        assert!(combined.contains(BlockDeviceLookupFlags::ORIGINATING));
    }

    // ── WholeDiskResult ──────────────────────────────────────────────

    #[test]
    fn test_whole_disk_result() {
        let already = WholeDiskResult::AlreadyWhole(make_dev(8, 0));
        assert_eq!(already.devt(), make_dev(8, 0));
        assert_eq!(already, WholeDiskResult::AlreadyWhole(make_dev(8, 0)));

        let resolved = WholeDiskResult::Resolved(make_dev(8, 0));
        assert_eq!(resolved.devt(), make_dev(8, 0));
        assert_ne!(already, resolved);
    }

    // ── BlockDevError ────────────────────────────────────────────────

    #[test]
    fn test_block_dev_error_display() {
        let e = BlockDevError::NotABlockDevice;
        assert!(e.to_string().contains("not a block device"));

        let e = BlockDevError::Encrypted;
        assert!(e.to_string().contains("encrypted"));

        let e = BlockDevError::RecursionLimitExceeded;
        assert!(e.to_string().contains("recursion"));
    }

    #[test]
    fn test_block_dev_error_errno_extraction() {
        let e = BlockDevError::Errno(Errno::EINVAL);
        assert_eq!(e.errno(), Some(Errno::EINVAL));

        let e = BlockDevError::NotABlockDevice;
        assert_eq!(e.errno(), None);
    }

    #[test]
    fn test_block_dev_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "not found");
        let bd_err = BlockDevError::from_io(io_err);
        assert_eq!(bd_err.errno(), Some(Errno::ENOENT));

        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let bd_err = BlockDevError::from_io(io_err);
        assert_eq!(bd_err.errno(), Some(Errno::EACCES));
    }

    // ── block_get_whole_disk (zero dev_t) ───────────────────────────

    #[test]
    fn test_block_get_whole_disk_zero_devt() {
        let result = block_get_whole_disk(make_dev(0, 0));
        assert!(result.is_err());
        match result.unwrap_err() {
            BlockDevError::Errno(Errno::ENODEV) => {}
            other => panic!("expected ENODEV, got {:?}", other),
        }
    }

    // ── constants ────────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_SECTOR_SIZE, 512);
        assert_eq!(ENCRYPTION_CHASE_DEPTH, 10);
    }
}
