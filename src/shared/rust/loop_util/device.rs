// SPDX-License-Identifier: LGPL-2.1-or-later

use super::linux::{
    blockdev_get_device_size, blockdev_get_sector_size, dev_from_stat, fd_get_diskseq, fd_get_path,
    fd_stat, flock_fd, get_loop_status64, ioctl_loop_clr_fd, ioctl_loop_ctl_remove,
    is_block_device, open_lock_fd, open_loop_control, open_raw, remove_all_partitions_sysfs,
    resize_partition_ioctl, set_loop_status64,
};
use super::model::{
    LO_FLAGS_AUTOCLEAR, LOCK_EX, LOCK_NB, LOCK_SH, LOCK_UN, LockOp, LoopError, MAX_REMOVE_ATTEMPTS,
    NO_CHANGE, O_CLOEXEC, O_NOCTTY, O_NONBLOCK, O_RDONLY, O_RDWR, lock_op_is_valid,
};
use std::fs;
use std::os::unix::io::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

// ── LoopDevice struct ──────────────────────────────────────────────────────

/// Represents a loop block device (or a foreign block device wrapped for
/// uniform access).
///
/// RAII semantics: on `Drop`, the loop device is cleared and removed if
/// we created it. Use `relinquish()` to opt out of automatic cleanup.
pub struct LoopDevice {
    /// File descriptor for the loop device node.
    pub(super) fd: OwnedFd,
    /// File descriptor for the BSD lock (separate fd so close triggers udev).
    pub(super) lock_fd: Option<OwnedFd>,
    /// The loop device index (e.g. 4 for `/dev/loop4`). `-1` for foreign.
    pub(super) nr: i32,
    /// Path to the loop device node (e.g. `/dev/loop4`).
    pub(super) node: PathBuf,
    /// Device number (major, minor) of the loop device itself.
    pub(super) devno: (u32, u32),
    /// Path to the backing file (if known).
    pub(super) backing_file: Option<PathBuf>,
    /// Whether this device has been relinquished (don't clean up on drop).
    pub(super) relinquished: bool,
    /// Whether we created this device (vs. opening an existing one).
    pub(super) created: bool,
    /// Backing file's device number.
    pub(super) backing_devno: Option<(u32, u32)>,
    /// Backing file's inode number.
    pub(super) backing_inode: Option<u64>,
    /// Block device sequence number (0 if unknown).
    pub(super) diskseq: u64,
    /// Sector size of the loop device.
    pub(super) sector_size: u32,
    /// Device size in bytes.
    pub(super) device_size: u64,
}

impl std::fmt::Debug for LoopDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopDevice")
            .field("nr", &self.nr)
            .field("node", &self.node)
            .field("devno", &self.devno)
            .field("backing_file", &self.backing_file)
            .field("relinquished", &self.relinquished)
            .field("created", &self.created)
            .field("diskseq", &self.diskseq)
            .field("sector_size", &self.sector_size)
            .field("device_size", &self.device_size)
            .finish()
    }
}

impl LoopDevice {
    /// Returns the loop device index (e.g. 4 for `/dev/loop4`).
    /// Returns `None` for foreign (non-loop) block devices.
    pub fn loop_nr(&self) -> Option<u32> {
        if self.nr >= 0 {
            Some(self.nr as u32)
        } else {
            None
        }
    }

    /// Returns the device node path (e.g. `/dev/loop4`).
    pub fn node(&self) -> &Path {
        &self.node
    }

    /// Returns the device number as (major, minor).
    pub fn devno(&self) -> (u32, u32) {
        self.devno
    }

    /// Returns the backing file path, if known.
    pub fn backing_file(&self) -> Option<&Path> {
        self.backing_file.as_deref()
    }

    /// Returns whether this device was created (vs. opening an existing one).
    pub fn is_created(&self) -> bool {
        self.created
    }

    /// Returns whether this is a foreign (non-loop) block device.
    pub fn is_foreign(&self) -> bool {
        self.nr < 0
    }

    /// Returns the sector size.
    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    /// Returns the device size in bytes.
    pub fn device_size(&self) -> u64 {
        self.device_size
    }

    /// Returns the disk sequence number (0 if unknown).
    pub fn diskseq(&self) -> u64 {
        self.diskseq
    }

    /// Returns the raw file descriptor for the loop device.
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Don't attempt to clean up the loop device on Drop.
    /// The kernel's autoclear logic will handle it instead.
    pub fn relinquish(&mut self) {
        self.relinquished = true;
    }

    /// Re-enable cleanup on Drop (undo a previous `relinquish()`).
    pub fn unrelinquish(&mut self) {
        self.relinquished = false;
    }

    /// Sync the loop device to ensure in-flight blocks are written.
    pub fn sync(&self) -> Result<(), LoopError> {
        // SAFETY: fsync consumes an integer fd by value.
        unsafe {
            if libc::fsync(self.fd.as_raw_fd()) < 0 {
                return Err(LoopError::from_errno(crate::ffi::get_errno()));
            }
        }
        Ok(())
    }

    /// Change the flock level on this device.
    ///
    /// `operation` should be `LockOp::SHARED`, `LockOp::EXCLUSIVE`, or
    /// `LockOp::UNLOCK` (optionally OR'd with `LockOp::NON_BLOCKING`).
    pub fn flock(&mut self, operation: LockOp) -> Result<(), LoopError> {
        let op_val = operation.bits();

        // Extract the base operation (strip NON_BLOCKING).
        let base_op = op_val & !LOCK_NB;
        if !matches!(base_op, LOCK_UN | LOCK_SH | LOCK_EX) {
            return Err(LoopError::InvalidArgument);
        }

        if base_op == LOCK_UN {
            self.lock_fd = None;
            return Ok(());
        }

        // If we have no lock fd yet, create one and lock it.
        if self.lock_fd.is_none() {
            let lock_fd = open_lock_fd(self.fd.as_raw_fd(), op_val)?;
            self.lock_fd = Some(lock_fd);
            return Ok(());
        }

        // Otherwise change the lock mode on the existing fd.
        let lock_fd = self.lock_fd.as_ref().unwrap();
        // SAFETY: flock consumes an integer fd and validated operation by value.
        unsafe {
            if libc::flock(lock_fd.as_raw_fd(), op_val) < 0 {
                return Err(LoopError::from_errno(crate::ffi::get_errno()));
            }
        }
        Ok(())
    }

    /// Set or clear the autoclear flag on the loop device.
    ///
    /// Returns `Ok(true)` if the flag was changed, `Ok(false)` if it was
    /// already in the desired state.
    pub fn set_autoclear(&self, autoclear: bool) -> Result<bool, LoopError> {
        if self.is_foreign() {
            return Ok(false);
        }

        let mut info = get_loop_status64(self.fd.as_raw_fd())?;

        let current = (info.lo_flags & LO_FLAGS_AUTOCLEAR) != 0;
        if current == autoclear {
            return Ok(false);
        }

        if autoclear {
            info.lo_flags |= LO_FLAGS_AUTOCLEAR;
        } else {
            info.lo_flags &= !LO_FLAGS_AUTOCLEAR;
        }

        set_loop_status64(self.fd.as_raw_fd(), &info)?;
        Ok(true)
    }

    /// Set the filename field of the loop device's loop_info64.
    ///
    /// This is a free-form string stored in the kernel's loop_info64.
    /// It's used by `/dev/disk/by-loop-ref/` symlinks and similar.
    ///
    /// Returns `Ok(true)` if the name was changed, `Ok(false)` if already set.
    pub fn set_filename(&self, name: Option<&str>) -> Result<bool, LoopError> {
        if let Some(n) = name {
            if n.len() >= 64 {
                return Err(LoopError::NoBufferSpace);
            }
        }

        let mut info = get_loop_status64(self.fd.as_raw_fd())?;

        // Check if already matches.
        let current_len = info
            .lo_file_name
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(info.lo_file_name.len());
        let desired = name.unwrap_or("").as_bytes();
        if &info.lo_file_name[..current_len] == desired {
            return Ok(false);
        }

        // Set the new name.
        info.lo_file_name.fill(0);
        if let Some(n) = name {
            let bytes = n.as_bytes();
            if bytes.contains(&0) {
                return Err(LoopError::InvalidArgument);
            }
            let copy_len = bytes.len().min(63);
            info.lo_file_name[..copy_len].copy_from_slice(&bytes[..copy_len]);
        }

        set_loop_status64(self.fd.as_raw_fd(), &info)?;
        Ok(true)
    }

    /// Refresh the size (and optionally offset) of the loop device.
    ///
    /// Pass `NO_CHANGE` for `offset` or `size` to leave them unchanged.
    /// If this device refers to a partition (foreign device), attempts to
    /// resize the partition instead.
    pub fn refresh_size(&mut self, offset: u64, size: u64) -> Result<(), LoopError> {
        if self.nr < 0 {
            // Not a loopback device — try to resize the partition.
            return resize_partition(self.fd.as_raw_fd(), offset, size);
        }

        let mut info = get_loop_status64(self.fd.as_raw_fd())?;

        let offset_changed = offset != NO_CHANGE && info.lo_offset != offset;
        let size_changed = size != NO_CHANGE && info.lo_sizelimit != size;

        if !offset_changed && !size_changed {
            return Ok(());
        }

        if size != NO_CHANGE {
            info.lo_sizelimit = size;
        }
        if offset != NO_CHANGE {
            info.lo_offset = offset;
        }

        set_loop_status64(self.fd.as_raw_fd(), &info)?;
        Ok(())
    }
}

impl Drop for LoopDevice {
    fn drop(&mut self) {
        // Release the lock fd first (lock protocol: control before device).
        self.lock_fd = None;

        // Open loop-control early and lock it before taking the device lock.
        let should_cleanup = !self.is_foreign() && !self.relinquished;
        let control = if should_cleanup {
            open_loop_control()
        } else {
            None
        };
        if should_cleanup {
            if let Some(ctrl_fd) = &control {
                // SAFETY: flock consumes an integer fd and operation by value.
                unsafe {
                    let _ = libc::flock(ctrl_fd.as_raw_fd(), LOCK_EX);
                }
            }
        }

        // Sync even foreign or relinquished devices, matching loop_device_free.
        // SAFETY: fsync consumes an integer fd by value.
        unsafe {
            let _ = libc::fsync(self.fd.as_raw_fd());
        }

        if should_cleanup {
            // SAFETY: flock consumes an integer fd and operation by value.
            unsafe {
                let _ = libc::flock(self.fd.as_raw_fd(), LOCK_EX);
            }

            // Best-effort cleanup mirrors the C destructor.
            let _ = remove_all_partitions_sysfs(self.fd.as_raw_fd(), self.nr);
            let _ = ioctl_loop_clr_fd(self.fd.as_raw_fd());
        }

        if let Some(ctrl_fd) = control {
            let mut delay = Duration::from_millis(5);
            for attempt in 1..=MAX_REMOVE_ATTEMPTS {
                match ioctl_loop_ctl_remove(ctrl_fd.as_raw_fd(), self.nr) {
                    Ok(()) => break,
                    Err(LoopError::Busy) if attempt < MAX_REMOVE_ATTEMPTS => {}
                    Err(_) => break,
                }
                if attempt % 5 == 0 {
                    delay *= 2;
                }
                std::thread::sleep(delay);
            }
        }
    }
}

/// Open an existing loop device by device node path.
pub fn loop_device_open_from_path(
    path: &Path,
    open_flags: i32,
    lock_op: LockOp,
) -> Result<LoopDevice, LoopError> {
    if !matches!(open_flags, O_RDONLY | O_RDWR) || !lock_op_is_valid(lock_op) {
        return Err(LoopError::InvalidArgument);
    }

    let fd = open_raw(path, O_CLOEXEC | O_NONBLOCK | O_NOCTTY | open_flags)?;

    let stat = fd_stat(fd.as_raw_fd())?;
    if !is_block_device(&stat) {
        return Err(LoopError::NotABlockDevice);
    }

    let lock_fd = if (lock_op.bits() & !LOCK_NB) != LOCK_UN {
        Some(open_lock_fd(fd.as_raw_fd(), lock_op.bits())?)
    } else {
        None
    };

    let info = match get_loop_status64(fd.as_raw_fd()) {
        Ok(i) => Some(i),
        Err(LoopError::DeviceAbsent) => None,
        Err(e) => return Err(e),
    };

    let nr = info.as_ref().map(|i| i.lo_number as i32).unwrap_or(-1);
    let devno = dev_from_stat(&stat);
    let sector_size = blockdev_get_sector_size(fd.as_raw_fd())?;
    let device_size = blockdev_get_device_size(fd.as_raw_fd())?;
    let diskseq = fd_get_diskseq(fd.as_raw_fd()).unwrap_or(0);

    // Try to read backing file from sysfs.
    let backing_file = if let Some(ref info) = info {
        let devname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let sysfs_path = format!("/sys/block/{}/loop/backing_file", devname);
        fs::read_to_string(&sysfs_path)
            .ok()
            .map(|s| PathBuf::from(s.trim().to_string()))
    } else {
        None
    };

    Ok(LoopDevice {
        fd,
        lock_fd,
        nr,
        node: path.to_path_buf(),
        devno,
        backing_file,
        relinquished: true, // Not ours, don't destroy on drop.
        created: false,
        backing_devno: info.map(|i| {
            let dev = i.lo_device as libc::dev_t;
            (libc::major(dev) as u32, libc::minor(dev) as u32)
        }),
        backing_inode: info.map(|i| i.lo_inode),
        diskseq,
        sector_size,
        device_size,
    })
}

/// Open an existing loop device from a raw fd.
pub fn loop_device_open_from_fd(
    fd: RawFd,
    open_flags: i32,
    lock_op: LockOp,
) -> Result<LoopDevice, LoopError> {
    let path = fd_get_path(fd)?;
    loop_device_open_from_path(&path, open_flags, lock_op)
}

// ── Partition resize ───────────────────────────────────────────────────────

/// Resize a partition referred to by a block device fd.
fn resize_partition(partition_fd: RawFd, offset: u64, size: u64) -> Result<(), LoopError> {
    let stat = fd_stat(partition_fd)?;
    if !is_block_device(&stat) {
        return Err(LoopError::NotABlockDevice);
    }

    let (major, minor) = dev_from_stat(&stat);

    // Check if this is a partition.
    let partition_sysfs = format!("/sys/dev/block/{}:{}/partition", major, minor);
    let partno: u64 = match fs::read_to_string(&partition_sysfs) {
        Ok(content) => content.trim().parse().map_err(|_| LoopError::IoError)?,
        Err(_) => return Err(LoopError::NotALoopDevice),
    };

    // Get current offset.
    let start_sysfs = format!("/sys/dev/block/{}:{}/start", major, minor);
    let current_start: u64 = fs::read_to_string(&start_sysfs)?
        .trim()
        .parse::<u64>()
        .map_err(|_| LoopError::IoError)?;
    let current_offset = current_start
        .checked_mul(512)
        .ok_or(LoopError::InvalidArgument)?;

    // Get current size.
    let current_size = blockdev_get_device_size(partition_fd)?;

    // Nothing to change?
    if size == NO_CHANGE && offset == NO_CHANGE {
        return Ok(());
    }
    if current_size == size && current_offset == offset {
        return Ok(());
    }

    // Find the whole device.
    let whole_sysfs = format!("/sys/dev/block/{}:{}/../dev", major, minor);
    let whole_dev_str = fs::read_to_string(&whole_sysfs)?;
    let whole_dev_parts: Vec<&str> = whole_dev_str.trim().split(':').collect();
    if whole_dev_parts.len() != 2 {
        return Err(LoopError::InvalidArgument);
    }
    let whole_major: u32 = whole_dev_parts[0]
        .parse()
        .map_err(|_| LoopError::InvalidArgument)?;
    let whole_minor: u32 = whole_dev_parts[1]
        .parse()
        .map_err(|_| LoopError::InvalidArgument)?;

    let whole_path = format!("/dev/block/{}:{}", whole_major, whole_minor);
    let whole_fd = open_raw(
        Path::new(&whole_path),
        O_RDWR | O_CLOEXEC | O_NONBLOCK | O_NOCTTY,
    )?;

    // BLKPG_RESIZE_PARTITION — this requires a raw ioctl that we
    // wrap safely.
    let final_offset = if offset == NO_CHANGE {
        current_offset
    } else {
        offset
    };
    let final_size = if size == NO_CHANGE {
        current_size
    } else {
        size
    };

    resize_partition_ioctl(whole_fd.as_raw_fd(), partno, final_offset, final_size)
}

/// Simplify a path (remove `.` and `..` components).
pub(super) fn simplify_path(path: &mut PathBuf) {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                components.pop();
            }
            c => components.push(c),
        }
    }
    *path = components.iter().collect();
}
