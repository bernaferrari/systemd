// SPDX-License-Identifier: LGPL-2.1-or-later

use super::model::{
    LO_FLAGS_AUTOCLEAR, LO_FLAGS_DIRECT_IO, LO_FLAGS_PARTSCAN, LO_FLAGS_READ_ONLY, LOCK_EX,
    LOCK_NB, LOCK_SH, LoopError, LoopFlags, MAX_ATTEMPTS, O_CLOEXEC, O_NOCTTY, O_NONBLOCK,
    O_RDONLY, O_RDWR,
};
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::time::Duration;

// ── Loop ioctl constants (from linux/loop.h) ───────────────────────────────

const LOOP_CLR_FD: libc::c_ulong = 0x4C01;
const LOOP_SET_FD: libc::c_ulong = 0x4C00;
const LOOP_GET_STATUS64: libc::c_ulong = 0x4C05;
const LOOP_SET_STATUS64: libc::c_ulong = 0x4C04;
const LOOP_CONFIGURE: libc::c_ulong = 0x4C0A;
const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4C82;
const LOOP_CTL_REMOVE: libc::c_ulong = 0x4C81;
const LOOP_SET_BLOCK_SIZE: libc::c_ulong = 0x4C09;
const LOOP_SET_DIRECT_IO: libc::c_ulong = 0x4C08;
const BLKPG: libc::c_ulong = 0x1269;
const BLKPG_DEL_PARTITION: i32 = 2;
const BLKPG_RESIZE_PARTITION: i32 = 3;

/// Mask of flags settable via LOOP_SET_STATUS64.
const LOOP_SET_STATUS_SETTABLE_FLAGS: u32 =
    LO_FLAGS_READ_ONLY | LO_FLAGS_AUTOCLEAR | LO_FLAGS_PARTSCAN;

// ── Kernel structures ──────────────────────────────────────────────────────

/// Raw `loop_info64` structure matching the kernel's layout.
///
/// Used for LOOP_GET_STATUS64 / LOOP_SET_STATUS64 ioctls.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(super) struct LoopInfo64 {
    pub(super) lo_device: u64,
    pub(super) lo_inode: u64,
    pub(super) lo_rdevice: u64,
    pub(super) lo_offset: u64,
    pub(super) lo_sizelimit: u64,
    pub(super) lo_number: u32,
    pub(super) lo_encrypt_type: u32,
    pub(super) lo_encrypt_key_size: u32,
    pub(super) lo_flags: u32,
    pub(super) lo_file_name: [u8; 64],
    pub(super) lo_crypt_name: [u8; 64],
    pub(super) lo_encrypt_key: [u8; 32],
    pub(super) lo_init: [u64; 2],
}

impl Default for LoopInfo64 {
    fn default() -> Self {
        Self {
            lo_device: 0,
            lo_inode: 0,
            lo_rdevice: 0,
            lo_offset: 0,
            lo_sizelimit: 0,
            lo_number: 0,
            lo_encrypt_type: 0,
            lo_encrypt_key_size: 0,
            lo_flags: 0,
            lo_file_name: [0; 64],
            lo_crypt_name: [0; 64],
            lo_encrypt_key: [0; 32],
            lo_init: [0; 2],
        }
    }
}

/// Raw `loop_config` structure matching the kernel's layout.
///
/// Used for the LOOP_CONFIGURE ioctl.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct LoopConfig {
    pub(super) fd: u32,
    pub(super) block_size: u32,
    pub(super) info: LoopInfo64,
    pub(super) __reserved: [u64; 8],
}

// Linux UAPI layout checks. If the Rust declarations drift from linux/loop.h,
// compilation fails before an ioctl can observe a truncated or shifted field.
// `__u64` follows the target C ABI: it is 8-byte aligned on many Linux ABIs,
// but only 4-byte aligned on others (for example i686).  Deriving the expected
// record alignment from Rust's target ABI therefore checks the corresponding
// C layout without accidentally rejecting supported 32-bit targets.
const _: [(); 232] = [(); std::mem::size_of::<LoopInfo64>()];
const _: [(); std::mem::align_of::<u64>()] = [(); std::mem::align_of::<LoopInfo64>()];
const _: [(); 52] = [(); std::mem::offset_of!(LoopInfo64, lo_flags)];
const _: [(); 56] = [(); std::mem::offset_of!(LoopInfo64, lo_file_name)];
const _: [(); 304] = [(); std::mem::size_of::<LoopConfig>()];
const _: [(); std::mem::align_of::<u64>()] = [(); std::mem::align_of::<LoopConfig>()];
const _: [(); 8] = [(); std::mem::offset_of!(LoopConfig, info)];
const _: [(); 240] = [(); std::mem::offset_of!(LoopConfig, __reserved)];

#[repr(C)]
struct BlkpgPartition {
    start: i64,
    length: i64,
    pno: i32,
    devname: [libc::c_char; 64],
    volname: [libc::c_char; 64],
}

#[repr(C)]
struct BlkpgIoctlArg {
    op: i32,
    flags: i32,
    datalen: i32,
    data: *mut libc::c_void,
}

const _: [(); 20] = [(); std::mem::offset_of!(BlkpgPartition, devname)];
const _: [(); 84] = [(); std::mem::offset_of!(BlkpgPartition, volname)];
const _: [(); 144 + std::mem::align_of::<i64>()] = [(); std::mem::size_of::<BlkpgPartition>()];
const _: [(); 8 + std::mem::size_of::<usize>()] = [(); std::mem::offset_of!(BlkpgIoctlArg, data)];
const _: [(); 8 + 2 * std::mem::size_of::<usize>()] = [(); std::mem::size_of::<BlkpgIoctlArg>()];

// ── Safe ioctl wrappers ────────────────────────────────────────────────────

/// Perform LOOP_GET_STATUS64 ioctl.
pub(super) fn get_loop_status64(fd: RawFd) -> Result<LoopInfo64, LoopError> {
    let mut info = LoopInfo64::default();
    // SAFETY: info is a writable loop_info64 with the checked Linux UAPI layout.
    let result = unsafe_ffi!(libc::ioctl(
        fd,
        LOOP_GET_STATUS64,
        &mut info as *mut LoopInfo64
    ));
    if result < 0 {
        let errno = crate::ffi::get_errno();
        if errno == libc::ENXIO {
            return Err(LoopError::DeviceAbsent);
        }
        return Err(LoopError::from_errno(errno));
    }
    Ok(info)
}

/// Perform LOOP_SET_STATUS64 ioctl.
pub(super) fn set_loop_status64(fd: RawFd, info: &LoopInfo64) -> Result<(), LoopError> {
    // SAFETY: info is a readable loop_info64 with the checked Linux UAPI layout.
    let result = unsafe_ffi!(libc::ioctl(
        fd,
        LOOP_SET_STATUS64,
        info as *const LoopInfo64
    ));
    if result < 0 {
        return Err(LoopError::from_errno(crate::ffi::get_errno()));
    }
    Ok(())
}

/// Perform LOOP_CLR_FD ioctl.
pub(super) fn ioctl_loop_clr_fd(fd: RawFd) -> Result<(), LoopError> {
    // SAFETY: LOOP_CLR_FD takes no pointer argument; the kernel validates fd.
    let result = unsafe_ffi!(libc::ioctl(fd, LOOP_CLR_FD));
    if result < 0 {
        return Err(LoopError::from_errno(crate::ffi::get_errno()));
    }
    Ok(())
}

/// Perform LOOP_SET_FD ioctl.
pub(super) fn ioctl_loop_set_fd(fd: RawFd, backing_fd: RawFd) -> Result<(), LoopError> {
    // SAFETY: LOOP_SET_FD consumes the integer backing fd by value; both fds
    // remain owned by their callers for the duration of the call.
    let result = unsafe_ffi!(libc::ioctl(fd, LOOP_SET_FD, backing_fd));
    if result < 0 {
        return Err(LoopError::from_errno(crate::ffi::get_errno()));
    }
    Ok(())
}

/// Perform LOOP_CTL_GET_FREE ioctl.
pub(super) fn ioctl_loop_ctl_get_free(control_fd: RawFd) -> Result<i32, LoopError> {
    // SAFETY: LOOP_CTL_GET_FREE takes no pointer argument.
    let result = unsafe_ffi!(libc::ioctl(control_fd, LOOP_CTL_GET_FREE));
    if result < 0 {
        return Err(LoopError::from_errno(crate::ffi::get_errno()));
    }
    Ok(result)
}

/// Perform LOOP_CTL_REMOVE ioctl.
pub(super) fn ioctl_loop_ctl_remove(control_fd: RawFd, nr: i32) -> Result<(), LoopError> {
    // SAFETY: LOOP_CTL_REMOVE consumes the loop number by value.
    let result = unsafe_ffi!(libc::ioctl(control_fd, LOOP_CTL_REMOVE, nr));
    if result < 0 {
        return Err(LoopError::from_errno(crate::ffi::get_errno()));
    }
    Ok(())
}

/// Perform LOOP_SET_BLOCK_SIZE ioctl.
pub(super) fn ioctl_loop_set_block_size(fd: RawFd, block_size: u32) -> Result<(), LoopError> {
    // SAFETY: LOOP_SET_BLOCK_SIZE consumes the size by value.
    let result = unsafe_ffi!(libc::ioctl(
        fd,
        LOOP_SET_BLOCK_SIZE,
        libc::c_ulong::from(block_size)
    ));
    if result < 0 {
        return Err(LoopError::from_errno(crate::ffi::get_errno()));
    }
    Ok(())
}

/// Perform LOOP_SET_DIRECT_IO ioctl.
pub(super) fn ioctl_loop_set_direct_io(fd: RawFd, enable: bool) -> Result<(), LoopError> {
    // SAFETY: LOOP_SET_DIRECT_IO consumes a boolean-sized integer by value.
    let enabled: libc::c_ulong = if enable { 1 } else { 0 };
    let result = unsafe_ffi!(libc::ioctl(fd, LOOP_SET_DIRECT_IO, enabled));
    if result < 0 {
        return Err(LoopError::from_errno(crate::ffi::get_errno()));
    }
    Ok(())
}

/// Perform LOOP_CONFIGURE ioctl.
pub(super) fn ioctl_loop_configure(fd: RawFd, config: &LoopConfig) -> Result<(), LoopError> {
    // SAFETY: config is a readable loop_config with the checked Linux UAPI
    // layout and remains alive for the duration of the ioctl.
    let result = unsafe_ffi!(libc::ioctl(fd, LOOP_CONFIGURE, config as *const LoopConfig));
    if result < 0 {
        let errno = crate::ffi::get_errno();
        // Check for ioctl-not-supported (ENOTTY, EINVAL on older kernels).
        if errno == libc::ENOTTY || errno == libc::EINVAL {
            return Err(LoopError::IoctlNotSupported);
        }
        return Err(LoopError::from_errno(errno));
    }
    Ok(())
}

// ── Safe syscall wrappers ──────────────────────────────────────────────────

/// Open a file descriptor with the given flags (safe wrapper around `libc::open`).
pub(super) fn open_raw(path: &Path, flags: i32) -> Result<OwnedFd, LoopError> {
    let path_c = path_to_cstr(path)?;
    // SAFETY: path_c is NUL-terminated and its storage remains alive for the call.
    let fd = unsafe_ffi!(libc::open(path_c.as_ptr(), flags));
    if fd < 0 {
        return Err(LoopError::from_errno(crate::ffi::get_errno()));
    }
    // SAFETY: fd >= 0, so it's a valid file descriptor.
    Ok(unsafe_ffi!(OwnedFd::from_raw_fd(fd)))
}

/// Reopen a file descriptor with new flags.
pub(super) fn fd_reopen(fd: RawFd, flags: i32) -> Result<OwnedFd, LoopError> {
    // Use /proc/self/fd/N to reopen.
    let proc_path = format!("/proc/self/fd/{}", fd);
    open_raw(Path::new(&proc_path), flags)
}

/// Duplicate an fd while preserving ownership and setting close-on-exec.
pub(super) fn dup_fd(fd: RawFd) -> Result<OwnedFd, LoopError> {
    // SAFETY: F_DUPFD_CLOEXEC does not dereference userspace pointers and the
    // returned descriptor is uniquely owned when non-negative.
    let duplicated = unsafe_ffi!(libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0));
    if duplicated < 0 {
        return Err(LoopError::from_errno(crate::ffi::get_errno()));
    }
    // SAFETY: duplicated is a fresh descriptor returned by fcntl.
    Ok(unsafe_ffi!(OwnedFd::from_raw_fd(duplicated)))
}

/// Get the path associated with a file descriptor via /proc/self/fd/.
pub(super) fn fd_get_path(fd: RawFd) -> Result<PathBuf, LoopError> {
    let proc_path = format!("/proc/self/fd/{}", fd);
    let link_target = fs::read_link(&proc_path)?;
    Ok(link_target)
}

/// Perform flock on a raw fd.
pub(super) fn flock_fd(fd: RawFd, operation: i32) -> Result<(), LoopError> {
    // SAFETY: flock consumes an integer fd and operation by value.
    unsafe_ffi!({
        if libc::flock(fd, operation) < 0 {
            return Err(LoopError::from_errno(crate::ffi::get_errno()));
        }
    });
    Ok(())
}

/// Open a separate fd for BSD locking on a device.
pub(super) fn open_lock_fd(primary_fd: RawFd, operation: i32) -> Result<OwnedFd, LoopError> {
    let base_op = operation & !LOCK_NB;
    if base_op != LOCK_SH && base_op != LOCK_EX {
        return Err(LoopError::InvalidArgument);
    }

    let lock_fd = fd_reopen(primary_fd, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY)?;
    flock_fd(lock_fd.as_raw_fd(), operation)?;
    Ok(lock_fd)
}

/// Check if a loop device is currently bound to a backing file.
pub(super) fn loop_is_bound(fd: RawFd) -> Result<bool, LoopError> {
    match get_loop_status64(fd) {
        Ok(_) => Ok(true),
        Err(LoopError::DeviceAbsent) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Open `/dev/loop-control`.
pub(super) fn open_loop_control() -> Option<OwnedFd> {
    let path = Path::new("/dev/loop-control");
    let path_c = path_to_cstr(path).ok()?;
    // SAFETY: path_c is NUL-terminated and its storage remains alive for the call.
    let fd = unsafe_ffi!(libc::open(
        path_c.as_ptr(),
        O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK
    ));
    if fd < 0 {
        return None;
    }
    // SAFETY: fd >= 0.
    Some(unsafe_ffi!(OwnedFd::from_raw_fd(fd)))
}

/// Convert a Path to a CString for use with C APIs.
pub(super) fn path_to_cstr(path: &Path) -> Result<CString, LoopError> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| LoopError::InvalidArgument)
}

/// Get block device sector size via BLKSSZGET.
pub(super) fn blockdev_get_sector_size(fd: RawFd) -> Result<u32, LoopError> {
    let mut ssz: i32 = 0;
    const BLKSSZGET: libc::c_ulong = 0x80041270;
    // SAFETY: ssz is writable for the call and matches the ioctl's u32 payload.
    let result = unsafe_ffi!(libc::ioctl(fd, BLKSSZGET, &mut ssz));
    if result < 0 {
        return Err(LoopError::from_errno(crate::ffi::get_errno()));
    }
    Ok(ssz as u32)
}

/// Get block device size in bytes via BLKGETSIZE64.
pub(super) fn blockdev_get_device_size(fd: RawFd) -> Result<u64, LoopError> {
    let mut size: u64 = 0;
    const BLKGETSIZE64: libc::c_ulong = 0x80081272;
    // SAFETY: size is writable for the call and matches the ioctl's u64 payload.
    let result = unsafe_ffi!(libc::ioctl(fd, BLKGETSIZE64, &mut size));
    if result < 0 {
        return Err(LoopError::from_errno(crate::ffi::get_errno()));
    }
    Ok(size)
}

/// Get the disk sequence number from sysfs (if available).
pub(super) fn fd_get_diskseq(fd: RawFd) -> Result<u64, LoopError> {
    let proc_path = format!("/proc/self/fd/{}", fd);
    let real_path = match fs::read_link(&proc_path) {
        Ok(p) => p,
        Err(_) => return Ok(0),
    };

    let devname = real_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    let sysfs_path = format!("/sys/block/{}/diskseq", devname);
    match fs::read_to_string(&sysfs_path) {
        Ok(content) => Ok(content.trim().parse::<u64>().unwrap_or(0)),
        Err(_) => Ok(0),
    }
}

/// Check if partitions are enabled on a block device via sysfs.
pub(super) fn blockdev_partscan_enabled_fd(fd: RawFd) -> Result<bool, LoopError> {
    let proc_path = format!("/proc/self/fd/{}", fd);
    let real_path = match fs::read_link(&proc_path) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };

    let devname = real_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    let sysfs_path = format!("/sys/block/{}/ext_range", devname);
    match fs::read_to_string(&sysfs_path) {
        Ok(content) => {
            let val: u64 = content.trim().parse().unwrap_or(0);
            Ok(val > 1)
        }
        Err(_) => Ok(false),
    }
}

fn blkpg_partition(
    whole_fd: RawFd,
    operation: i32,
    partno: i32,
    offset: u64,
    size: u64,
) -> Result<(), LoopError> {
    let mut partition = BlkpgPartition {
        start: i64::try_from(offset).map_err(|_| LoopError::InvalidArgument)?,
        length: i64::try_from(size).map_err(|_| LoopError::InvalidArgument)?,
        pno: partno,
        devname: [0; 64],
        volname: [0; 64],
    };
    let mut argument = BlkpgIoctlArg {
        op: operation,
        flags: 0,
        datalen: i32::try_from(std::mem::size_of::<BlkpgPartition>())
            .map_err(|_| LoopError::InvalidArgument)?,
        data: (&mut partition as *mut BlkpgPartition).cast(),
    };

    // SAFETY: argument and its nested partition pointer remain live and
    // writable for the call, and both layouts are checked against blkpg.h.
    let result = unsafe_ffi!(libc::ioctl(
        whole_fd,
        BLKPG,
        &mut argument as *mut BlkpgIoctlArg
    ));
    if result < 0 {
        return Err(LoopError::from_errno(crate::ffi::get_errno()));
    }
    Ok(())
}

/// Remove partition children left behind on a detached loop device.
pub(super) fn remove_all_partitions_sysfs(loop_fd: RawFd, nr: i32) -> Result<bool, LoopError> {
    let sysfs_path = format!("/sys/block/loop{}", nr);
    let mut removed = false;

    for entry in fs::read_dir(sysfs_path)? {
        let entry = entry?;
        let partition_path = entry.path().join("partition");
        let partno = match fs::read_to_string(partition_path) {
            Ok(value) => value
                .trim()
                .parse::<i32>()
                .map_err(|_| LoopError::InvalidArgument)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        blkpg_partition(loop_fd, BLKPG_DEL_PARTITION, partno, 0, 0)?;
        removed = true;
    }

    Ok(removed)
}

pub(super) fn resize_partition_ioctl(
    whole_fd: RawFd,
    partno: u64,
    offset: u64,
    size: u64,
) -> Result<(), LoopError> {
    let partno = i32::try_from(partno).map_err(|_| LoopError::InvalidArgument)?;
    blkpg_partition(whole_fd, BLKPG_RESIZE_PARTITION, partno, offset, size)
}

/// Get max discard bytes from sysfs for a block device.
pub(super) fn fd_get_max_discard(fd: RawFd) -> Result<u64, LoopError> {
    let stat = fd_stat(fd)?;
    if !is_block_device(&stat) {
        return Err(LoopError::NotABlockDevice);
    }

    let (major, minor) = dev_from_stat(&stat);
    let sysfs_path = format!("/sys/dev/block/{}:{}/queue/discard_max_bytes", major, minor);
    let content = fs::read_to_string(&sysfs_path)?;
    let val: u64 = content.trim().parse().map_err(|_| LoopError::IoError)?;
    Ok(val)
}

/// Set max discard bytes for a block device via sysfs.
pub(super) fn fd_set_max_discard(fd: RawFd, max_discard: u64) -> Result<(), LoopError> {
    let stat = fd_stat(fd)?;
    if !is_block_device(&stat) {
        return Err(LoopError::NotABlockDevice);
    }

    let (major, minor) = dev_from_stat(&stat);
    let sysfs_path = format!("/sys/dev/block/{}:{}/queue/discard_max_bytes", major, minor);
    fs::write(&sysfs_path, max_discard.to_string())?;
    Ok(())
}

/// Get stat for a file descriptor.
pub(super) fn fd_stat(fd: RawFd) -> Result<libc::stat, LoopError> {
    // SAFETY: all-zero is a valid initial byte pattern for libc::stat and the
    // value is not read until fstat initializes it.
    let mut stat: libc::stat = unsafe_ffi!(std::mem::zeroed());
    // SAFETY: stat points to writable storage for the duration of fstat.
    if unsafe_ffi!(libc::fstat(fd, &mut stat)) < 0 {
        return Err(LoopError::from_errno(crate::ffi::get_errno()));
    }
    Ok(stat)
}

/// Check if a stat result is a block device.
pub(super) fn is_block_device(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFBLK
}

/// Check if a stat result is a regular file.
pub(super) fn is_regular_file(stat: &libc::stat) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFREG
}

/// Extract (major, minor) from a stat's st_rdev.
pub(super) fn dev_from_stat(stat: &libc::stat) -> (u32, u32) {
    (
        libc::major(stat.st_rdev) as u32,
        libc::minor(stat.st_rdev) as u32,
    )
}

/// Extract (major, minor) from a stat's st_dev.
pub(super) fn dev_from_st_dev(stat: &libc::stat) -> (u32, u32) {
    (
        libc::major(stat.st_dev) as u32,
        libc::minor(stat.st_dev) as u32,
    )
}

/// Mangle loop flags based on SYSTEMD_LOOP_DIRECT_IO environment variable.
///
/// By default, LO_FLAGS_DIRECT_IO is enabled unless explicitly turned off.
pub(super) fn loop_flags_mangle(loop_flags: LoopFlags) -> LoopFlags {
    match std::env::var("SYSTEMD_LOOP_DIRECT_IO") {
        Ok(value)
            if value == "0"
                || value.eq_ignore_ascii_case("false")
                || value.eq_ignore_ascii_case("no")
                || value.eq_ignore_ascii_case("off") =>
        {
            loop_flags & !LoopFlags::DIRECT_IO
        }
        // C defaults to direct I/O when unset and ignores malformed values.
        Ok(_) | Err(_) => loop_flags | LoopFlags::DIRECT_IO,
    }
}

// ── Internal configuration helpers ─────────────────────────────────────────

/// Verify that direct I/O was actually enabled after LOOP_CONFIGURE.
pub(super) fn loop_configure_verify_direct_io(
    fd: RawFd,
    config: &LoopConfig,
) -> Result<(), LoopError> {
    if (config.info.lo_flags & LO_FLAGS_DIRECT_IO) == 0 {
        return Ok(());
    }

    let info = get_loop_status64(fd)?;
    if (info.lo_flags & LO_FLAGS_DIRECT_IO) == 0 {
        return Err(LoopError::DirectIoFailed);
    }

    Ok(())
}

/// Verify that LOOP_CONFIGURE honored all requested parameters.
///
/// Returns `Ok(true)` if everything is correct, `Ok(false)` if LOOP_CONFIGURE
/// is broken and fallback to LOOP_SET_STATUS64 is needed.
pub(super) fn loop_configure_verify(fd: RawFd, config: &LoopConfig) -> Result<bool, LoopError> {
    let mut broken = false;

    if config.block_size != 0 {
        let ssz = blockdev_get_sector_size(fd)?;
        if ssz != config.block_size {
            broken = true;
        }
    }

    if config.info.lo_sizelimit != 0 {
        let device_size = blockdev_get_device_size(fd)?;
        if device_size != config.info.lo_sizelimit {
            broken = true;
        }
    }

    if (config.info.lo_flags & LO_FLAGS_PARTSCAN) != 0 {
        match blockdev_partscan_enabled_fd(fd) {
            Ok(true) => {}
            _ => {
                broken = true;
            }
        }
    }

    loop_configure_verify_direct_io(fd, config)?;

    Ok(!broken)
}

/// Fallback configuration using LOOP_SET_FD + LOOP_SET_STATUS64.
pub(super) fn loop_configure_fallback(fd: RawFd, config: &LoopConfig) -> Result<(), LoopError> {
    // Only some flags are settable via LOOP_SET_STATUS64.
    let mut info = config.info;
    info.lo_flags &= LOOP_SET_STATUS_SETTABLE_FLAGS;

    // Retry LOOP_SET_STATUS64 on EAGAIN.
    for attempt in 0..MAX_ATTEMPTS {
        match set_loop_status64(fd, &info) {
            Ok(()) => break,
            Err(e) => {
                if e.raw_errno() != Some(libc::EAGAIN) || attempt >= MAX_ATTEMPTS - 1 {
                    return Err(e);
                }
                // Sleep with exponential backoff.
                let delay_ms = 10 + (240 * attempt as u64 / MAX_ATTEMPTS as u64);
                std::thread::sleep(Duration::from_millis(delay_ms));
            }
        }
    }

    // Try to set block size if requested.
    if config.block_size != 0 {
        let _ = ioctl_loop_set_block_size(fd, config.block_size);
        let ssz = blockdev_get_sector_size(fd)?;
        if ssz != config.block_size {
            return Err(LoopError::IoError);
        }
    }

    // Try to enable direct I/O if requested.
    if (config.info.lo_flags & LO_FLAGS_DIRECT_IO) != 0 {
        let _ = ioctl_loop_set_direct_io(fd, true);
    }

    loop_configure_verify_direct_io(fd, config)?;
    Ok(())
}
