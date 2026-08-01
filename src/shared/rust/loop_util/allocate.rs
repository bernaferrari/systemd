// SPDX-License-Identifier: LGPL-2.1-or-later

use super::device::{LoopDevice, loop_device_open_from_fd, simplify_path};
use super::linux::{
    LoopConfig, LoopInfo64, blockdev_get_device_size, blockdev_get_sector_size, dev_from_st_dev,
    dev_from_stat, dup_fd, fd_get_diskseq, fd_get_max_discard, fd_get_path, fd_reopen,
    fd_set_max_discard, fd_stat, flock_fd, get_loop_status64, ioctl_loop_clr_fd,
    ioctl_loop_configure, ioctl_loop_ctl_get_free, ioctl_loop_set_fd, is_block_device,
    is_regular_file, loop_configure_fallback, loop_configure_verify, loop_flags_mangle,
    loop_is_bound, open_lock_fd, open_loop_control, open_raw, path_to_cstr,
    remove_all_partitions_sysfs, set_loop_status64,
};
use super::model::{
    AUTO_SECTOR_SIZE, DEFAULT_SECTOR_SIZE, LO_FLAGS_AUTOCLEAR, LO_FLAGS_DIRECT_IO,
    LO_FLAGS_PARTSCAN, LO_FLAGS_READ_ONLY, LOCK_EX, LOCK_NB, LOCK_SH, LOCK_UN,
    LOOP_DEVICE_MAY_POPULATE_PARTITION_TABLE, LockOp, LoopDeviceMakeOptions, LoopError, LoopFlags,
    MAX_ATTEMPTS, NO_CHANGE, O_ACCMODE, O_CLOEXEC, O_DIRECT, O_NOCTTY, O_NONBLOCK, O_PATH,
    O_RDONLY, O_RDWR, lock_op_is_valid,
};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// This is the Rust equivalent of `loop_device_make()` in the C source.
pub fn loop_device_make(
    fd: RawFd,
    options: LoopDeviceMakeOptions,
) -> Result<LoopDevice, LoopError> {
    if !matches!(options.open_flags, None | Some(O_RDONLY) | Some(O_RDWR)) {
        return Err(LoopError::InvalidArgument);
    }
    if !lock_op_is_valid(options.lock_op) {
        return Err(LoopError::InvalidArgument);
    }

    let mut flags = options.loop_flags;
    flags = loop_flags_mangle(flags);

    loop_device_make_internal(
        None,
        fd,
        options.open_flags,
        options.offset,
        options.size,
        options.sector_size,
        flags,
        options.lock_op,
    )
}

/// Create a loop device from a file path.
///
/// Equivalent to `loop_device_make_by_path()`.
pub fn loop_device_make_by_path(
    path: &Path,
    open_flags: Option<i32>,
    sector_size: u32,
    loop_flags: LoopFlags,
    lock_op: LockOp,
) -> Result<LoopDevice, LoopError> {
    if !matches!(open_flags, None | Some(O_RDONLY) | Some(O_RDWR)) {
        return Err(LoopError::InvalidArgument);
    }
    if !lock_op_is_valid(lock_op) {
        return Err(LoopError::InvalidArgument);
    }

    loop_device_make_by_path_at(
        libc::AT_FDCWD,
        path,
        open_flags,
        sector_size,
        loop_flags,
        lock_op,
    )
}

/// Create a loop device from a file path relative to a directory fd.
///
/// Equivalent to `loop_device_make_by_path_at()`.
pub fn loop_device_make_by_path_at(
    dir_fd: RawFd,
    path: &Path,
    open_flags: Option<i32>,
    sector_size: u32,
    loop_flags: LoopFlags,
    lock_op: LockOp,
) -> Result<LoopDevice, LoopError> {
    if !matches!(open_flags, None | Some(O_RDONLY) | Some(O_RDWR))
        || !lock_op_is_valid(lock_op)
        || (dir_fd < 0 && dir_fd != libc::AT_FDCWD)
    {
        return Err(LoopError::InvalidArgument);
    }

    let mut flags = loop_flags;
    flags = loop_flags_mangle(flags);

    let basic_flags = O_CLOEXEC | O_NONBLOCK | O_NOCTTY;
    let direct_flags = if flags.contains(LoopFlags::DIRECT_IO) {
        O_DIRECT
    } else {
        0
    };
    let rdwr_flags = open_flags.unwrap_or(O_RDWR);

    // Try opening with O_DIRECT first, then retry buffered while preserving
    // the real filesystem error if neither works.
    let fd = open_with_optional_direct(dir_fd, path, basic_flags | rdwr_flags, direct_flags != 0);

    let fd = match fd {
        Ok(f) => {
            let actual_open = open_flags.unwrap_or(O_RDWR);
            return loop_device_make_internal(
                if dir_fd == libc::AT_FDCWD {
                    Some(path.to_path_buf())
                } else {
                    None
                },
                f.as_raw_fd(),
                Some(actual_open),
                0,
                0,
                sector_size,
                flags,
                lock_op,
            );
        }
        Err(writable_error) => {
            // Try read-only.
            if open_flags.is_some() || !error_is_write_refused(&writable_error) {
                return Err(writable_error);
            }
            open_with_optional_direct(dir_fd, path, basic_flags | O_RDONLY, direct_flags != 0)
                .map_err(|_| writable_error)?
        }
    };

    loop_device_make_internal(
        if dir_fd == libc::AT_FDCWD {
            Some(path.to_path_buf())
        } else {
            None
        },
        fd.as_raw_fd(),
        Some(O_RDONLY),
        0,
        0,
        sector_size,
        flags,
        lock_op,
    )
}

/// Open a file relative to a directory fd.
fn open_at(dir_fd: RawFd, path: &Path, flags: i32) -> Result<OwnedFd, LoopError> {
    let path_c = path_to_cstr(path)?;
    // SAFETY: path_c is NUL-terminated and its storage remains alive for the call.
    let fd = unsafe_ffi!(libc::openat(dir_fd, path_c.as_ptr(), flags));
    if fd < 0 {
        return Err(LoopError::from_errno(crate::ffi::get_errno()));
    }
    // SAFETY: fd is a fresh descriptor returned by openat.
    Ok(unsafe_ffi!(OwnedFd::from_raw_fd(fd)))
}

fn open_with_optional_direct(
    dir_fd: RawFd,
    path: &Path,
    flags: i32,
    direct: bool,
) -> Result<OwnedFd, LoopError> {
    if direct {
        open_at(dir_fd, path, flags | O_DIRECT).or_else(|_| open_at(dir_fd, path, flags))
    } else {
        open_at(dir_fd, path, flags)
    }
}

fn error_is_write_refused(error: &LoopError) -> bool {
    matches!(
        error.raw_errno(),
        Some(libc::EACCES) | Some(libc::EPERM) | Some(libc::EROFS)
    )
}

/// Create a loop device backed by a copy of a file's contents (memfd).
///
/// Equivalent to `loop_device_make_by_path_memory()`.
pub fn loop_device_make_by_path_memory(
    path: &Path,
    open_flags: i32,
    sector_size: u32,
    mut loop_flags: LoopFlags,
    lock_op: LockOp,
) -> Result<LoopDevice, LoopError> {
    if !matches!(open_flags, O_RDONLY | O_RDWR) || !lock_op_is_valid(lock_op) {
        return Err(LoopError::InvalidArgument);
    }

    loop_flags.remove(LoopFlags::DIRECT_IO); // memfds don't support O_DIRECT

    let fd = open_raw(path, O_CLOEXEC | O_NONBLOCK | O_NOCTTY | O_RDONLY)?;
    let stat = fd_stat(fd.as_raw_fd())?;

    if !is_regular_file(&stat) && !is_block_device(&stat) {
        return Err(LoopError::InvalidArgument);
    }

    // Read the file contents into a memfd.
    let file = File::from(fd);
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("loop_image");
    let memfd_name = CString::new(filename).map_err(|_| LoopError::InvalidArgument)?;
    // SAFETY: memfd_name is a live NUL-terminated string; on success the
    // returned descriptor is fresh and uniquely owned.
    let memfd = unsafe_ffi!(libc::memfd_create(memfd_name.as_ptr(), libc::MFD_CLOEXEC));
    if memfd < 0 {
        return Err(LoopError::from_errno(crate::ffi::get_errno()));
    }
    // SAFETY: memfd was just returned by memfd_create and has one owner.
    let mut mfd = File::from(unsafe_ffi!(OwnedFd::from_raw_fd(memfd)));

    let mut buf = vec![0u8; 65536];
    let mut file = file;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        mfd.write_all(&buf[..n])?;
    }

    loop_device_make_internal(
        None,
        mfd.as_raw_fd(),
        Some(open_flags),
        0,
        0,
        sector_size,
        loop_flags,
        lock_op,
    )
}

/// Internal implementation for creating a loop device.
fn loop_device_make_internal(
    path: Option<PathBuf>,
    fd: RawFd,
    open_flags: Option<i32>,
    offset: u64,
    size: u64,
    sector_size: u32,
    mut loop_flags: LoopFlags,
    lock_op: LockOp,
) -> Result<LoopDevice, LoopError> {
    // Determine actual open flags from the fd if not specified.
    // SAFETY: F_GETFL consumes the integer fd by value and returns flags.
    let f_flags = unsafe_ffi!(libc::fcntl(fd, libc::F_GETFL));
    if f_flags < 0 {
        return Err(LoopError::from_errno(crate::ffi::get_errno()));
    }

    let actual_open_flags = match open_flags {
        Some(f) => f,
        None => {
            if (f_flags & O_PATH) != 0 {
                return Err(LoopError::InvalidOperation(
                    "O_PATH access mode cannot determine read/write flags".into(),
                ));
            }
            let access = f_flags & O_ACCMODE;
            if access != O_RDWR && access != O_RDONLY {
                return Err(LoopError::InvalidOperation(
                    "Access mode is write-only".into(),
                ));
            }
            access
        }
    };

    let stat = fd_stat(fd)?;
    let is_blk = is_block_device(&stat);
    let is_reg = is_regular_file(&stat);

    // Conservatively take the C shortcut only when every condition this port
    // can prove is satisfied. PARTSCAN needs partition-table probing, which is
    // not implemented here, so it always gets a real loop device.
    if is_blk && offset == 0 && (size == 0 || size == NO_CHANGE) {
        let device_sector_size = blockdev_get_sector_size(fd)?;
        let sector_matches = sector_size == 0 || sector_size == device_sector_size;
        let may_populate = (loop_flags.bits() & LOOP_DEVICE_MAY_POPULATE_PARTITION_TABLE) != 0;
        if sector_matches && !loop_flags.contains(LoopFlags::PARTSCAN) && !may_populate {
            return loop_device_open_from_fd(fd, actual_open_flags, lock_op);
        }
    }

    if !is_blk && !is_reg {
        return Err(LoopError::InvalidArgument);
    }

    // Determine backing file path.
    let backing_file = match path {
        Some(p) => {
            let mut abs = if p.is_absolute() {
                p
            } else {
                std::env::current_dir()?.join(&p)
            };
            simplify_path(&mut abs);
            Some(abs)
        }
        None => Some(fd_get_path(fd)?),
    };

    // Handle O_DIRECT mismatch with LO_FLAGS_DIRECT_IO.
    let wants_direct = loop_flags.contains(LoopFlags::DIRECT_IO);
    let has_direct = (f_flags & O_DIRECT) != 0;

    let operating_fd = if wants_direct != has_direct {
        let direct_flag = if wants_direct { O_DIRECT } else { 0 };
        match fd_reopen(fd, direct_flag | O_CLOEXEC | O_NONBLOCK | actual_open_flags) {
            Ok(new_fd) => new_fd,
            Err(_) if wants_direct => {
                // Some filesystems don't support O_DIRECT; continue without.
                loop_flags.remove(LoopFlags::DIRECT_IO);
                dup_fd(fd)?
            }
            Err(e) => return Err(e),
        }
    } else {
        dup_fd(fd)?
    };

    make_loop_with_fd(
        operating_fd,
        actual_open_flags,
        offset,
        size,
        sector_size,
        loop_flags,
        lock_op,
        backing_file,
        &stat,
    )
}

/// Actually create a loop device with the given fd.
fn make_loop_with_fd(
    fd: OwnedFd,
    open_flags: i32,
    offset: u64,
    size: u64,
    sector_size: u32,
    mut loop_flags: LoopFlags,
    lock_op: LockOp,
    backing_file: Option<PathBuf>,
    stat: &libc::stat,
) -> Result<LoopDevice, LoopError> {
    let control = open_loop_control().ok_or(LoopError::DeviceAbsent)?;

    // Determine sector size.
    let actual_sector_size = if sector_size == 0 {
        if is_block_device(stat) {
            blockdev_get_sector_size(fd.as_raw_fd())?
        } else {
            DEFAULT_SECTOR_SIZE
        }
    } else if sector_size == AUTO_SECTOR_SIZE {
        if is_block_device(stat) {
            blockdev_get_sector_size(fd.as_raw_fd())?
        } else {
            // For regular files, default to 512.
            DEFAULT_SECTOR_SIZE
        }
    } else {
        sector_size
    };

    // Build loop_config.
    let deferred_partscan = loop_flags.contains(LoopFlags::PARTSCAN);
    let effective_flags: u32 = (loop_flags.bits()
        & !(LO_FLAGS_READ_ONLY | LO_FLAGS_PARTSCAN | LOOP_DEVICE_MAY_POPULATE_PARTITION_TABLE))
        | if open_flags == O_RDONLY {
            LO_FLAGS_READ_ONLY
        } else {
            0
        }
        | LO_FLAGS_AUTOCLEAR;

    let sizelimit = if size == NO_CHANGE { 0 } else { size };

    let mut config = LoopConfig {
        fd: u32::try_from(fd.as_raw_fd()).map_err(|_| LoopError::InvalidArgument)?,
        block_size: actual_sector_size,
        info: LoopInfo64 {
            lo_flags: effective_flags,
            lo_offset: offset,
            lo_sizelimit: sizelimit,
            ..LoopInfo64::default()
        },
        ..LoopConfig::default()
    };

    // Loop around LOOP_CTL_GET_FREE since the device might be taken.
    let mut effective_open_flags = open_flags;
    let mut effective_fd = fd;

    for attempt in 0..MAX_ATTEMPTS {
        // Lock the control device to serialize allocations.
        flock_fd(control.as_raw_fd(), LOCK_EX)?;

        let nr = ioctl_loop_ctl_get_free(control.as_raw_fd())?;

        match configure_loop_device(nr, effective_open_flags, lock_op, &config) {
            Ok(mut device) => {
                if is_block_device(stat) {
                    if let Ok(max_discard) = fd_get_max_discard(effective_fd.as_raw_fd()) {
                        let _ = fd_set_max_discard(device.fd.as_raw_fd(), max_discard);
                    }
                }

                if deferred_partscan {
                    // Drain any pending open event while partition scanning is
                    // still suppressed, then enable scanning in one update.
                    drop(fd_reopen(
                        device.fd.as_raw_fd(),
                        O_RDONLY | O_CLOEXEC | O_NONBLOCK,
                    )?);
                    let mut info = get_loop_status64(device.fd.as_raw_fd())?;
                    info.lo_flags |= LO_FLAGS_PARTSCAN;
                    set_loop_status64(device.fd.as_raw_fd(), &info)?;
                }

                device.backing_file = backing_file;
                device.backing_inode = u64::try_from(stat.st_ino).ok();
                device.backing_devno = Some(dev_from_st_dev(stat));
                return Ok(device);
            }
            Err(e) => {
                // Release the control lock.
                let _ = flock_fd(control.as_raw_fd(), LOCK_UN);

                // Only retry on specific errors.
                match &e {
                    LoopError::Busy
                    | LoopError::DeviceAbsent
                    | LoopError::StalePartitions
                    | LoopError::DirectIoFailed => {}
                    _ => return Err(e),
                }

                if attempt >= MAX_ATTEMPTS - 1 {
                    return Err(LoopError::MaxRetriesExceeded);
                }

                // If direct I/O failed, retry without it.
                if matches!(e, LoopError::DirectIoFailed)
                    && loop_flags.contains(LoopFlags::DIRECT_IO)
                {
                    loop_flags.remove(LoopFlags::DIRECT_IO);
                    config.info.lo_flags &= !LO_FLAGS_DIRECT_IO;
                    effective_open_flags &= !O_DIRECT;

                    effective_fd = fd_reopen(
                        effective_fd.as_raw_fd(),
                        O_CLOEXEC | O_NONBLOCK | effective_open_flags,
                    )?;
                    config.fd = u32::try_from(effective_fd.as_raw_fd())
                        .map_err(|_| LoopError::InvalidArgument)?;
                }

                // Sleep with jitter.
                let delay_ms = 10 + (240 * (attempt + 1) as u64 / MAX_ATTEMPTS as u64);
                std::thread::sleep(Duration::from_millis(delay_ms));
            }
        }
    }

    Err(LoopError::MaxRetriesExceeded)
}

/// Owns a candidate loop fd after attachment. Any error before handoff clears
/// the backing association before the descriptor closes.
struct AttachedLoopFd {
    fd: Option<OwnedFd>,
    attached: bool,
}

impl AttachedLoopFd {
    fn new(fd: OwnedFd) -> Self {
        Self {
            fd: Some(fd),
            attached: false,
        }
    }

    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_ref().expect("attached loop fd").as_raw_fd()
    }

    fn mark_attached(&mut self) {
        self.attached = true;
    }

    fn into_fd(mut self) -> OwnedFd {
        self.attached = false;
        self.fd.take().expect("attached loop fd")
    }
}

impl Drop for AttachedLoopFd {
    fn drop(&mut self) {
        if self.attached {
            if let Some(fd) = &self.fd {
                let _ = ioctl_loop_clr_fd(fd.as_raw_fd());
            }
        }
    }
}

/// Configure a specific loop device number.
fn configure_loop_device(
    nr: i32,
    open_flags: i32,
    lock_op: LockOp,
    config: &LoopConfig,
) -> Result<LoopDevice, LoopError> {
    let node = format!("/dev/loop{}", nr);
    let node_path = Path::new(&node);

    // Open the loop device node.
    let fd = open_raw(node_path, O_CLOEXEC | O_NONBLOCK | O_NOCTTY | open_flags)?;

    // Acquire exclusive lock via a separate fd.
    let lock_fd = open_lock_fd(fd.as_raw_fd(), LOCK_EX)?;

    // Check if the loop device is unbound.
    match loop_is_bound(fd.as_raw_fd()) {
        Ok(true) => return Err(LoopError::Busy),
        Ok(false) => {}
        Err(e) => return Err(e),
    }

    // A superficially detached loop device can retain partition children.
    // Remove them and force the allocator to retry with a clean candidate.
    if remove_all_partitions_sysfs(fd.as_raw_fd(), nr)? {
        return Err(LoopError::StalePartitions);
    }

    // Try LOOP_CONFIGURE first.
    let mut loop_with_fd = AttachedLoopFd::new(fd);
    let mut use_fallback = false;

    match ioctl_loop_configure(loop_with_fd.as_raw_fd(), config) {
        Ok(()) => {
            loop_with_fd.mark_attached();
            match loop_configure_verify(loop_with_fd.as_raw_fd(), config) {
                Ok(true) => {
                    // LOOP_CONFIGURE worked.
                }
                Ok(false) => {
                    // LOOP_CONFIGURE is broken, return EBUSY to try another device.
                    return Err(LoopError::Busy);
                }
                Err(LoopError::DirectIoFailed) => {
                    return Err(LoopError::DirectIoFailed);
                }
                Err(e) => return Err(e),
            }
        }
        Err(LoopError::IoctlNotSupported) => {
            use_fallback = true;
        }
        Err(e) => return Err(e),
    }

    if use_fallback {
        // Fallback: LOOP_SET_FD + LOOP_SET_STATUS64.
        let backing_fd = i32::try_from(config.fd).map_err(|_| LoopError::InvalidArgument)?;
        ioctl_loop_set_fd(loop_with_fd.as_raw_fd(), backing_fd)?;
        loop_with_fd.mark_attached();

        loop_configure_fallback(loop_with_fd.as_raw_fd(), config)?;
    }

    // Get diskseq.
    let diskseq = fd_get_diskseq(loop_with_fd.as_raw_fd()).unwrap_or(0);

    // Adjust lock based on requested lock_op.
    let final_lock_fd = match lock_op.bits() & !LOCK_NB {
        LOCK_EX => Some(lock_fd), // Already exclusive
        LOCK_SH => {
            flock_fd(lock_fd.as_raw_fd(), LOCK_SH)?;
            Some(lock_fd)
        }
        LOCK_UN => {
            // Release the lock.
            None
        }
        _ => Some(lock_fd),
    };

    // Get device size.
    let device_size = blockdev_get_device_size(loop_with_fd.as_raw_fd())?;

    // Get device number.
    let stat = fd_stat(loop_with_fd.as_raw_fd())?;
    let devno = dev_from_stat(&stat);

    Ok(LoopDevice {
        fd: loop_with_fd.into_fd(),
        lock_fd: final_lock_fd,
        nr,
        node: PathBuf::from(&node),
        devno,
        backing_file: None,
        relinquished: false,
        created: true,
        backing_devno: None,
        backing_inode: None,
        diskseq,
        sector_size: config.block_size,
        device_size,
    })
}
