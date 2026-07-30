// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/reread-partition-table.c, src/shared/reread-partition-table.h
//
// Partition table rereading — reread_partition_table, BLKRRPART ioctl wrapper,
// partition table rescan after modification.
//
// Provides safe wrappers for rereading partition tables on block devices.
// The BLKRRPART ioctl is the primary mechanism for notifying the kernel of
// partition table changes. For GPT disks, a more fine-grained approach
// compares on-disk partition entries against kernel state and individually
// resizes, adds, or removes partitions.
//
// `unsafe` is confined to the BLKRRPART ioctl syscall.

use std::collections::{HashMap, HashSet};
use std::os::unix::io::AsRawFd;

use crate::ffi::Errno;

// ── Constants ─────────────────────────────────────────────────────────────

/// Default logical sector size in bytes (used to convert sector-based offsets).
pub const SECTOR_SIZE: u64 = 512;

/// Kernel ioctl request code: BLKRRPART — re-read partition table.
///
/// Instructs the kernel to re-read the partition table of the block device
/// referred to by the file descriptor. The kernel will send out `change`
/// uevents for the disk and `remove`/`add` events for all partitions.
const BLKRRPART: u64 = 0x125F;

// ── Flags ────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling partition table reread behaviour.
    ///
    /// Corresponds to `RereadPartitionTableFlags` in `reread-partition-table.h`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RereadPartitionTableFlags: u32 {
        /// Force a "change" uevent on partitions that were not resized, removed, or added.
        const FORCE_UEVENT = 1 << 0;
        /// Take an exclusive non-blocking BSD lock on the device around the rescan.
        const BSD_LOCK     = 1 << 1;
    }
}

// ── Error type ────────────────────────────────────────────────────────────

/// Errors returned by partition table reread operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RereadPartitionTableError {
    /// A POSIX errno occurred during an ioctl or sysfs operation.
    Errno(Errno),
    /// The block device does not support partition scanning.
    PartitionScanDisabled,
    /// A BSD lock could not be acquired (device is busy).
    LockBusy,
    /// The partition table could not be probed (e.g. not GPT, or I/O error).
    ProbeFailed(String),
    /// A partition number or offset is invalid.
    InvalidPartition(String),
}

impl RereadPartitionTableError {
    /// Return the underlying errno value, if any.
    pub fn errno(&self) -> Option<Errno> {
        match self {
            RereadPartitionTableError::Errno(e) => Some(*e),
            RereadPartitionTableError::LockBusy => Some(Errno::EAGAIN),
            RereadPartitionTableError::PartitionScanDisabled => Some(Errno::ENOTTY),
            _ => None,
        }
    }
}

impl std::fmt::Display for RereadPartitionTableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RereadPartitionTableError::Errno(e) => {
                write!(f, "partition table reread error: errno {:?}", e)
            }
            RereadPartitionTableError::PartitionScanDisabled => {
                write!(f, "block device does not support partition scanning")
            }
            RereadPartitionTableError::LockBusy => {
                write!(f, "failed to acquire BSD lock on block device")
            }
            RereadPartitionTableError::ProbeFailed(msg) => {
                write!(f, "partition table probe failed: {}", msg)
            }
            RereadPartitionTableError::InvalidPartition(msg) => {
                write!(f, "invalid partition: {}", msg)
            }
        }
    }
}

impl std::error::Error for RereadPartitionTableError {}

impl From<std::io::Error> for RereadPartitionTableError {
    fn from(err: std::io::Error) -> Self {
        let errno = match err.raw_os_error() {
            Some(raw) => match raw {
                libc::EPERM => Errno::EPERM,
                libc::ENOENT => Errno::ENOENT,
                libc::EIO => Errno::EIO,
                libc::ENXIO => Errno::ENXIO,
                libc::EBADF => Errno::EBADF,
                libc::EAGAIN => Errno::EAGAIN,
                libc::ENOMEM => Errno::ENOMEM,
                libc::EACCES => Errno::EACCES,
                libc::EBUSY => Errno::EBUSY,
                libc::ENODEV => Errno::ENODEV,
                libc::EINVAL => Errno::EINVAL,
                libc::ENOTTY => Errno::ENOTTY,
                libc::ENOSPC => Errno::ENOSPC,
                _ => Errno::EIO,
            },
            None => match err.kind() {
                std::io::ErrorKind::PermissionDenied => Errno::EACCES,
                std::io::ErrorKind::NotFound => Errno::ENOENT,
                std::io::ErrorKind::WouldBlock => Errno::EAGAIN,
                _ => Errno::EIO,
            },
        };
        RereadPartitionTableError::Errno(errno)
    }
}

impl From<Errno> for RereadPartitionTableError {
    fn from(e: Errno) -> Self {
        RereadPartitionTableError::Errno(e)
    }
}

/// Convenience alias used by every public function in this module.
pub type Result<T> = std::result::Result<T, RereadPartitionTableError>;

// ── Partition info ────────────────────────────────────────────────────────

/// Information about a single partition, as read from the on-disk partition
/// table or from the kernel's view via sysfs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionInfo {
    /// Partition number (1-based).
    pub nr: u32,
    /// Start offset in bytes from the beginning of the disk.
    pub start: u64,
    /// Size in bytes.
    pub size: u64,
}

impl PartitionInfo {
    /// Create a new partition info from sector-based values.
    ///
    /// Converts sector-based `start` and `size` to byte values using
    /// [`SECTOR_SIZE`].
    pub fn from_sectors(nr: u32, start_sectors: u64, size_sectors: u64) -> Self {
        Self {
            nr,
            start: start_sectors
                .checked_mul(SECTOR_SIZE)
                .expect("sector overflow"),
            size: size_sectors
                .checked_mul(SECTOR_SIZE)
                .expect("sector overflow"),
        }
    }

    /// Start offset in sectors.
    pub fn start_sectors(&self) -> u64 {
        self.start / SECTOR_SIZE
    }

    /// Size in sectors.
    pub fn size_sectors(&self) -> u64 {
        self.size / SECTOR_SIZE
    }
}

// ── Partition diff ────────────────────────────────────────────────────────

/// Describes the difference between the kernel's view of a partition and the
/// on-disk partition table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionChange {
    /// The partition matches exactly — no action needed.
    Unchanged,
    /// The partition start matches but size differs — it can be resized in place.
    Resize(PartitionInfo),
    /// The partition start changed — it must be removed and recreated.
    Recreate(PartitionInfo),
    /// The partition exists on disk but not in the kernel — it must be added.
    Add(PartitionInfo),
    /// The partition exists in the kernel but not on disk — it must be removed.
    Remove { nr: u32 },
}

/// Compare a single on-disk partition entry against the kernel's view.
///
/// Returns the appropriate [`PartitionChange`] variant describing what action
/// is needed to bring the kernel in sync with the on-disk table.
///
/// This corresponds to the logic in `process_partition()` from the C source:
/// - If both start and size match → `Unchanged`
/// - If only start matches → `Resize`
/// - If start differs → `Recreate`
/// - If the partition does not exist in the kernel → `Add`
pub fn compare_partition(
    on_disk: &PartitionInfo,
    kernel_start: Option<u64>,
    kernel_size: Option<u64>,
) -> PartitionChange {
    match (kernel_start, kernel_size) {
        (Some(ks), Some(kz)) if ks == on_disk.start && kz == on_disk.size => {
            PartitionChange::Unchanged
        }
        (Some(ks), Some(_)) if ks == on_disk.start => PartitionChange::Resize(on_disk.clone()),
        (Some(_), Some(_)) => PartitionChange::Recreate(on_disk.clone()),
        (None, _) | (_, None) => PartitionChange::Add(on_disk.clone()),
    }
}

// ── BLKRRPART ioctl ──────────────────────────────────────────────────────

/// Issue the BLKRRPART ioctl to request the kernel re-read the partition
/// table of the block device referred to by `fd`.
///
/// This is the fallback mechanism when fine-grained partition manipulation
/// (via the BLKPG ioctl) is not available or not applicable (e.g. non-GPT
/// partition tables). When successful the kernel sends `change` uevents
/// for the disk and `remove`/`add` events for all partitions.
///
/// # Errors
///
/// Returns an error if the ioctl fails (e.g. the device is busy, or the fd
/// does not refer to a block device).
///
/// # Safety model
///
/// The `unsafe` interior is minimal: a single `libc::ioctl` call with a
/// valid fd (guaranteed by the `AsRawFd` bound) and a null third argument
/// (BLKRRPART takes no data).
pub fn blkrrpart<Fd: AsRawFd>(fd: &Fd) -> Result<()> {
    // SAFETY: `AsRawFd` guarantees the fd is valid. BLKRRPART takes no
    // data argument (we pass 0). The kernel reads the partition table
    // from the device and updates its internal state.
    let ret = unsafe { libc::ioctl(fd.as_raw_fd(), BLKRRPART, 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

// ── Reread result ─────────────────────────────────────────────────────────

/// Result of a partition table reread operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RereadResult {
    /// The partition table was reread successfully; nothing changed.
    Unchanged,
    /// The partition table was reread and at least one partition was
    /// modified (resized, added, or removed).
    Changed,
}

// ── High-level API ────────────────────────────────────────────────────────

/// Reread the partition table of a block device using the BLKRRPART ioctl.
///
/// This is the simple fallback path used when fine-grained partition
/// manipulation is not applicable (e.g. non-GPT partition tables, or when
/// libblkid is unavailable). It issues a single ioctl and returns.
///
/// For GPT devices where per-partition changes are desired, callers should
/// probe the on-disk table with blkid, compute a diff via
/// [`compute_partition_diff`], and apply changes individually via the
/// BLKPG ioctl.
///
/// # Arguments
///
/// * `fd` - An open file descriptor for the block device.
/// * `flags` - Control flags (see [`RereadPartitionTableFlags`]).
///
/// # Errors
///
/// Returns an error if the BLKRRPART ioctl fails.
pub fn reread_partition_table<Fd: AsRawFd>(
    fd: &Fd,
    flags: RereadPartitionTableFlags,
) -> Result<RereadResult> {
    let _ = flags; // flags available for future extensions (e.g. BSD lock)
    blkrrpart(fd)?;
    Ok(RereadResult::Changed)
}

/// Reread the partition table of a block device at a given byte offset.
///
/// This variant is useful when the partition table is located at a non-zero
/// offset on the device (e.g. a partition table within a partition, or a
/// superblock-relative table).
///
/// Note: the BLKRRPART ioctl always operates on the whole device as seen
/// by the kernel. The `offset` parameter is provided for API completeness
/// and future use with blkid probing at an offset. Currently only `offset
/// == 0` is supported; non-zero offsets return an error.
///
/// # Arguments
///
/// * `fd` - An open file descriptor for the block device.
/// * `offset` - Byte offset to the partition table (must be 0 for BLKRRPART).
/// * `flags` - Control flags (see [`RereadPartitionTableFlags`]).
///
/// # Errors
///
/// Returns `ProbeFailed` if `offset` is non-zero, or if the BLKRRPART ioctl
/// fails.
pub fn reread_partition_table_with_offset<Fd: AsRawFd>(
    fd: &Fd,
    offset: u64,
    flags: RereadPartitionTableFlags,
) -> Result<RereadResult> {
    if offset != 0 {
        return Err(RereadPartitionTableError::ProbeFailed(format!(
            "non-zero offset {} not supported with BLKRRPART fallback",
            offset
        )));
    }
    reread_partition_table(fd, flags)
}

// ── Diff computation ──────────────────────────────────────────────────────

/// Compute the set of partition changes needed to bring the kernel's view
/// in sync with the on-disk partition table.
///
/// This is the pure-logic core of the fine-grained reread path. It compares
/// each on-disk partition against the kernel's view (provided via
/// `kernel_partitions`) and produces a list of [`PartitionChange`] actions.
/// It also identifies partitions that exist in the kernel but not on disk,
/// which need to be removed.
///
/// This corresponds to the combined logic of `process_partition()` and
/// `remove_partitions()` from the C source.
///
/// # Arguments
///
/// * `on_disk` - Partitions found in the on-disk partition table.
/// * `kernel_partitions` - Partitions known to the kernel, keyed by partition number.
///
/// # Returns
///
/// A vector of [`PartitionChange`] describing each action needed.
pub fn compute_partition_diff(
    on_disk: &[PartitionInfo],
    kernel_partitions: &HashMap<u32, PartitionInfo>,
) -> Vec<PartitionChange> {
    let mut changes = Vec::new();
    let mut on_disk_numbers = HashSet::new();

    for part in on_disk {
        on_disk_numbers.insert(part.nr);
        let kernel = kernel_partitions.get(&part.nr);
        let kernel_start = kernel.map(|k| k.start);
        let kernel_size = kernel.map(|k| k.size);
        changes.push(compare_partition(part, kernel_start, kernel_size));
    }

    // Find partitions in kernel but not on disk — these must be removed.
    for &nr in kernel_partitions.keys() {
        if !on_disk_numbers.contains(&nr) {
            changes.push(PartitionChange::Remove { nr });
        }
    }

    changes
}

/// Check whether any partition change actually modifies the kernel state.
///
/// Returns `true` if the diff contains at least one resize, recreate, add,
/// or remove action. Returns `false` if all partitions are [`Unchanged`].
///
/// [`Unchanged`]: PartitionChange::Unchanged
pub fn diff_requires_changes(changes: &[PartitionChange]) -> bool {
    changes
        .iter()
        .any(|c| !matches!(c, PartitionChange::Unchanged))
}

/// Collect the set of partition numbers that were found in the on-disk
/// partition table. Used to determine which kernel partitions should be
/// kept versus removed.
pub fn collect_on_disk_partition_numbers(on_disk: &[PartitionInfo]) -> HashSet<u32> {
    on_disk.iter().map(|p| p.nr).collect()
}

// ── Validation helpers ────────────────────────────────────────────────────

/// Validate a partition number.
///
/// Partition numbers must be positive (1-based). Returns an error for
/// partition number 0, which has no meaning in partition tables.
pub fn validate_partition_number(nr: u32) -> Result<()> {
    if nr == 0 {
        return Err(RereadPartitionTableError::InvalidPartition(
            "partition number must be >= 1".into(),
        ));
    }
    Ok(())
}

/// Validate partition start and size, ensuring they are sector-aligned and
/// their sector representations do not overflow `u64`.
///
/// # Errors
///
/// Returns `InvalidPartition` if `start_bytes` or `size_bytes` are not
/// sector-aligned, or if the sector representation would overflow.
pub fn validate_partition_geometry(start_bytes: u64, size_bytes: u64) -> Result<()> {
    if !start_bytes.is_multiple_of(SECTOR_SIZE) {
        return Err(RereadPartitionTableError::InvalidPartition(format!(
            "start offset {} is not sector-aligned (sector size {})",
            start_bytes, SECTOR_SIZE
        )));
    }
    if !size_bytes.is_multiple_of(SECTOR_SIZE) {
        return Err(RereadPartitionTableError::InvalidPartition(format!(
            "size {} is not sector-aligned (sector size {})",
            size_bytes, SECTOR_SIZE
        )));
    }
    if start_bytes > u64::MAX / SECTOR_SIZE {
        return Err(RereadPartitionTableError::InvalidPartition(format!(
            "start offset {} sectors would overflow u64",
            start_bytes / SECTOR_SIZE
        )));
    }
    if size_bytes > u64::MAX / SECTOR_SIZE {
        return Err(RereadPartitionTableError::InvalidPartition(format!(
            "size {} sectors would overflow u64",
            size_bytes / SECTOR_SIZE
        )));
    }
    Ok(())
}

/// Convert a start offset and size from sectors to bytes.
///
/// Returns `None` on overflow.
pub fn sectors_to_bytes(start_sectors: u64, size_sectors: u64) -> Option<(u64, u64)> {
    let start = start_sectors.checked_mul(SECTOR_SIZE)?;
    let size = size_sectors.checked_mul(SECTOR_SIZE)?;
    Some((start, size))
}

/// Count how many partitions in the diff would actually change the kernel
/// state (i.e. are not [`Unchanged`]).
///
/// [`Unchanged`]: PartitionChange::Unchanged
pub fn count_actual_changes(changes: &[PartitionChange]) -> usize {
    changes
        .iter()
        .filter(|c| !matches!(c, PartitionChange::Unchanged))
        .count()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Flags ─────────────────────────────────────────────────────────

    #[test]
    fn test_flags_values() {
        assert_eq!(RereadPartitionTableFlags::FORCE_UEVENT.bits(), 1);
        assert_eq!(RereadPartitionTableFlags::BSD_LOCK.bits(), 2);
    }

    #[test]
    fn test_flags_empty() {
        let empty = RereadPartitionTableFlags::empty();
        assert_eq!(empty.bits(), 0);
        assert!(!empty.contains(RereadPartitionTableFlags::FORCE_UEVENT));
        assert!(!empty.contains(RereadPartitionTableFlags::BSD_LOCK));
    }

    #[test]
    fn test_flags_combination() {
        let both = RereadPartitionTableFlags::FORCE_UEVENT | RereadPartitionTableFlags::BSD_LOCK;
        assert_eq!(both.bits(), 0b11);
        assert!(both.contains(RereadPartitionTableFlags::FORCE_UEVENT));
        assert!(both.contains(RereadPartitionTableFlags::BSD_LOCK));
    }

    #[test]
    fn test_flags_from_bits_truncate() {
        let flags = RereadPartitionTableFlags::from_bits_truncate(0b10);
        assert!(flags.contains(RereadPartitionTableFlags::BSD_LOCK));
        assert!(!flags.contains(RereadPartitionTableFlags::FORCE_UEVENT));
    }

    // ── PartitionInfo ─────────────────────────────────────────────────

    #[test]
    fn test_partition_info_from_sectors() {
        let info = PartitionInfo::from_sectors(1, 2048, 1024000);
        assert_eq!(info.nr, 1);
        assert_eq!(info.start, 2048 * 512);
        assert_eq!(info.size, 1024000 * 512);
    }

    #[test]
    fn test_partition_info_sector_accessors() {
        let info = PartitionInfo::from_sectors(2, 4096, 8192);
        assert_eq!(info.start_sectors(), 4096);
        assert_eq!(info.size_sectors(), 8192);
    }

    #[test]
    fn test_partition_info_equality() {
        let a = PartitionInfo::from_sectors(1, 2048, 1024000);
        let b = PartitionInfo::from_sectors(1, 2048, 1024000);
        assert_eq!(a, b);
    }

    #[test]
    fn test_partition_info_inequality() {
        let a = PartitionInfo::from_sectors(1, 2048, 1024000);
        let b = PartitionInfo::from_sectors(1, 2048, 2048000);
        assert_ne!(a, b);
    }

    // ── compare_partition ─────────────────────────────────────────────

    #[test]
    fn test_compare_partition_unchanged() {
        let on_disk = PartitionInfo::from_sectors(1, 2048, 1024000);
        let change = compare_partition(&on_disk, Some(on_disk.start), Some(on_disk.size));
        assert_eq!(change, PartitionChange::Unchanged);
    }

    #[test]
    fn test_compare_partition_resize() {
        let on_disk = PartitionInfo::from_sectors(1, 2048, 2048000);
        let kernel_start = on_disk.start;
        let change = compare_partition(&on_disk, Some(kernel_start), Some(1024000 * 512));
        assert!(matches!(change, PartitionChange::Resize(ref info) if info.size == on_disk.size));
    }

    #[test]
    fn test_compare_partition_recreate() {
        let on_disk = PartitionInfo::from_sectors(1, 4096, 1024000);
        let change = compare_partition(&on_disk, Some(2048 * 512), Some(1024000 * 512));
        assert!(matches!(change, PartitionChange::Recreate(_)));
    }

    #[test]
    fn test_compare_partition_add_no_kernel() {
        let on_disk = PartitionInfo::from_sectors(1, 2048, 1024000);
        let change = compare_partition(&on_disk, None, None);
        assert!(matches!(change, PartitionChange::Add(_)));
    }

    #[test]
    fn test_compare_partition_add_partial_kernel_info() {
        let on_disk = PartitionInfo::from_sectors(1, 2048, 1024000);
        let change = compare_partition(&on_disk, None, Some(999));
        assert!(matches!(change, PartitionChange::Add(_)));
    }

    // ── compute_partition_diff ────────────────────────────────────────

    #[test]
    fn test_compute_diff_no_changes() {
        let on_disk = vec![
            PartitionInfo::from_sectors(1, 2048, 1024000),
            PartitionInfo::from_sectors(2, 1026048, 1024000),
        ];
        let kernel: HashMap<u32, PartitionInfo> =
            on_disk.iter().map(|p| (p.nr, p.clone())).collect();

        let changes = compute_partition_diff(&on_disk, &kernel);
        assert!(
            changes
                .iter()
                .all(|c| matches!(c, PartitionChange::Unchanged))
        );
    }

    #[test]
    fn test_compute_diff_add_and_remove() {
        let on_disk = vec![PartitionInfo::from_sectors(1, 2048, 1024000)];
        let mut kernel = HashMap::new();
        kernel.insert(2, PartitionInfo::from_sectors(2, 1026048, 1024000));

        let changes = compute_partition_diff(&on_disk, &kernel);
        assert!(changes.iter().any(|c| matches!(c, PartitionChange::Add(_))));
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, PartitionChange::Remove { nr: 2 }))
        );
    }

    #[test]
    fn test_compute_diff_resize() {
        let on_disk = vec![PartitionInfo::from_sectors(1, 2048, 2048000)];
        let mut kernel = HashMap::new();
        kernel.insert(1, PartitionInfo::from_sectors(1, 2048, 1024000));

        let changes = compute_partition_diff(&on_disk, &kernel);
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, PartitionChange::Resize(_)))
        );
    }

    #[test]
    fn test_compute_diff_recreate() {
        let on_disk = vec![PartitionInfo::from_sectors(1, 4096, 1024000)];
        let mut kernel = HashMap::new();
        kernel.insert(1, PartitionInfo::from_sectors(1, 2048, 1024000));

        let changes = compute_partition_diff(&on_disk, &kernel);
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, PartitionChange::Recreate(_)))
        );
    }

    #[test]
    fn test_compute_diff_empty() {
        let on_disk: Vec<PartitionInfo> = vec![];
        let kernel: HashMap<u32, PartitionInfo> = HashMap::new();
        let changes = compute_partition_diff(&on_disk, &kernel);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_compute_diff_all_removed() {
        let on_disk: Vec<PartitionInfo> = vec![];
        let mut kernel = HashMap::new();
        kernel.insert(1, PartitionInfo::from_sectors(1, 2048, 1024000));
        kernel.insert(2, PartitionInfo::from_sectors(2, 1026048, 1024000));

        let changes = compute_partition_diff(&on_disk, &kernel);
        assert_eq!(changes.len(), 2);
        assert!(
            changes
                .iter()
                .all(|c| matches!(c, PartitionChange::Remove { .. }))
        );
    }

    // ── diff_requires_changes ─────────────────────────────────────────

    #[test]
    fn test_diff_requires_changes_true() {
        let changes = vec![
            PartitionChange::Unchanged,
            PartitionChange::Resize(PartitionInfo::from_sectors(1, 2048, 1024000)),
        ];
        assert!(diff_requires_changes(&changes));
    }

    #[test]
    fn test_diff_requires_changes_false() {
        let changes = vec![PartitionChange::Unchanged, PartitionChange::Unchanged];
        assert!(!diff_requires_changes(&changes));
    }

    #[test]
    fn test_diff_requires_changes_empty() {
        assert!(!diff_requires_changes(&[]));
    }

    // ── count_actual_changes ──────────────────────────────────────────

    #[test]
    fn test_count_actual_changes_mixed() {
        let changes = vec![
            PartitionChange::Unchanged,
            PartitionChange::Resize(PartitionInfo::from_sectors(1, 2048, 1024000)),
            PartitionChange::Unchanged,
            PartitionChange::Add(PartitionInfo::from_sectors(3, 999, 100)),
        ];
        assert_eq!(count_actual_changes(&changes), 2);
    }

    #[test]
    fn test_count_actual_changes_zero() {
        assert_eq!(count_actual_changes(&[PartitionChange::Unchanged]), 0);
    }

    // ── collect_on_disk_partition_numbers ─────────────────────────────

    #[test]
    fn test_collect_partition_numbers() {
        let on_disk = vec![
            PartitionInfo::from_sectors(1, 2048, 1024000),
            PartitionInfo::from_sectors(2, 1026048, 1024000),
            PartitionInfo::from_sectors(5, 2052096, 1024000),
        ];
        let nums = collect_on_disk_partition_numbers(&on_disk);
        assert!(nums.contains(&1));
        assert!(nums.contains(&2));
        assert!(nums.contains(&5));
        assert_eq!(nums.len(), 3);
    }

    // ── Validation helpers ────────────────────────────────────────────

    #[test]
    fn test_validate_partition_number_valid() {
        assert!(validate_partition_number(1).is_ok());
        assert!(validate_partition_number(128).is_ok());
    }

    #[test]
    fn test_validate_partition_number_zero() {
        assert!(validate_partition_number(0).is_err());
    }

    #[test]
    fn test_validate_partition_geometry_aligned() {
        assert!(validate_partition_geometry(2048 * 512, 1024000 * 512).is_ok());
        assert!(validate_partition_geometry(0, 512).is_ok());
    }

    #[test]
    fn test_validate_partition_geometry_unaligned_start() {
        assert!(validate_partition_geometry(100, 512).is_err());
    }

    #[test]
    fn test_validate_partition_geometry_unaligned_size() {
        assert!(validate_partition_geometry(512, 100).is_err());
    }

    #[test]
    fn test_sectors_to_bytes_valid() {
        assert_eq!(
            sectors_to_bytes(2048, 1024000),
            Some((2048 * 512, 1024000 * 512))
        );
        assert_eq!(sectors_to_bytes(0, 0), Some((0, 0)));
    }

    #[test]
    fn test_sectors_to_bytes_overflow() {
        assert!(sectors_to_bytes(u64::MAX, 1).is_none());
        assert!(sectors_to_bytes(1, u64::MAX).is_none());
    }

    // ── Error type ────────────────────────────────────────────────────

    #[test]
    fn test_error_errno_extraction() {
        assert_eq!(
            RereadPartitionTableError::Errno(Errno::EBADF).errno(),
            Some(Errno::EBADF)
        );
        assert_eq!(
            RereadPartitionTableError::LockBusy.errno(),
            Some(Errno::EAGAIN)
        );
        assert_eq!(
            RereadPartitionTableError::PartitionScanDisabled.errno(),
            Some(Errno::ENOTTY)
        );
        assert_eq!(
            RereadPartitionTableError::ProbeFailed("test".into()).errno(),
            None
        );
    }

    #[test]
    fn test_error_display() {
        let e = RereadPartitionTableError::PartitionScanDisabled;
        assert!(e.to_string().contains("partition scanning"));

        let e = RereadPartitionTableError::LockBusy;
        assert!(e.to_string().contains("BSD lock"));

        let e = RereadPartitionTableError::ProbeFailed("no GPT".into());
        assert!(e.to_string().contains("no GPT"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err: RereadPartitionTableError = io_err.into();
        assert_eq!(err.errno(), Some(Errno::EACCES));

        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err: RereadPartitionTableError = io_err.into();
        assert_eq!(err.errno(), Some(Errno::ENOENT));

        let io_err = std::io::Error::new(std::io::ErrorKind::WouldBlock, "busy");
        let err: RereadPartitionTableError = io_err.into();
        assert_eq!(err.errno(), Some(Errno::EAGAIN));
    }

    // ── RereadResult ──────────────────────────────────────────────────

    #[test]
    fn test_reread_result_equality() {
        assert_eq!(RereadResult::Unchanged, RereadResult::Unchanged);
        assert_eq!(RereadResult::Changed, RereadResult::Changed);
        assert_ne!(RereadResult::Unchanged, RereadResult::Changed);
    }

    // ── Constants ─────────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert_eq!(SECTOR_SIZE, 512);
        assert_eq!(BLKRRPART, 0x125F);
    }

    // ── reread_partition_table_with_offset ────────────────────────────

    #[test]
    fn test_reread_with_nonzero_offset_rejected() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let result =
            reread_partition_table_with_offset(&file, 1048576, RereadPartitionTableFlags::empty());
        match result.unwrap_err() {
            RereadPartitionTableError::ProbeFailed(msg) => {
                assert!(msg.contains("non-zero offset"));
            }
            other => panic!("expected ProbeFailed, got {:?}", other),
        }
    }

    // ── PartitionChange variants ──────────────────────────────────────

    #[test]
    fn test_partition_change_remove() {
        let r = PartitionChange::Remove { nr: 3 };
        assert_eq!(r, PartitionChange::Remove { nr: 3 });
        assert_ne!(r, PartitionChange::Remove { nr: 4 });
    }

    #[test]
    fn test_partition_change_debug() {
        let add = PartitionChange::Add(PartitionInfo::from_sectors(1, 0, 512));
        let debug_str = format!("{:?}", add);
        assert!(debug_str.contains("Add"));
    }
}
