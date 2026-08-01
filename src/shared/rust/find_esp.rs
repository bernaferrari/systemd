// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/find-esp.c, src/shared/find-esp.h
//
// EFI System Partition (ESP) and Extended Boot Loader Partition (XBOOTLDR)
// discovery and verification.
//
// Locates the ESP by checking well-known mount points (/efi, /boot, /boot/efi),
// the SYSTEMD_ESP_PATH environment variable, or an explicitly provided path.
// Similarly locates the XBOOTLDR partition via /boot, SYSTEMD_XBOOTLDR_PATH,
// or an explicit path.
//
// Verification pins the candidate directory, confirms its filesystem type and
// mount-root status, and obtains its backing device. GPT/DOS partition metadata
// probing delegates to the narrow C authority shared with find-esp.c so blkid,
// udev, optional-feature, and errno behavior cannot drift.

use crate::btrfs_util::btrfs_get_block_device_fd;
use crate::ffi::*;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use systemd_basic_rs::devnum_util::{devnum_from_major_minor, devnum_major, devnum_minor};
use systemd_basic_rs::id128_util::SdId128;
use systemd_basic_rs::virt::{detect_container, virtualization_is_container};

// SAFETY: These are the exact declarations from find-esp.h. The safe wrappers
// below pass an encoded Linux dev_t and valid, uniquely borrowed output slots;
// C neither retains pointers nor transfers ownership.
unsafe extern "C" {
    #[link_name = "verify_esp_partition"]
    fn c_verify_esp_partition(
        devid: libc::dev_t,
        unprivileged_mode: libc::c_int,
        searching: libc::c_int,
        ret_part: *mut u32,
        ret_pstart: *mut u64,
        ret_psize: *mut u64,
        ret_uuid: *mut SdId128,
    ) -> libc::c_int;

    #[link_name = "verify_xbootldr_partition"]
    fn c_verify_xbootldr_partition(
        devid: libc::dev_t,
        unprivileged_mode: libc::c_int,
        searching: libc::c_int,
        ret_uuid: *mut SdId128,
    ) -> libc::c_int;
}

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors that can occur during ESP/XBOOTLDR discovery and verification.
#[derive(Debug)]
pub enum FindEspError {
    /// The partition was not found at any of the searched locations.
    NotFound,
    /// The specified path is not a directory.
    NotADirectory(PathBuf),
    /// The path is not at the root of its filesystem (not a mount point).
    NotFsRoot(PathBuf),
    /// The filesystem is not FAT/vfat.
    NotFatFs(PathBuf),
    /// Not on a GPT partition table.
    NotGpt(PathBuf),
    /// Partition has the wrong type GUID for an ESP or XBOOTLDR.
    WrongPartitionType(PathBuf),
    /// The backing block device could not be determined (e.g. btrfs RAID).
    NoBackingDevice(PathBuf),
    /// Failed to chase/resolve a filesystem path.
    PathResolution { path: PathBuf, source: io::Error },
    /// An I/O error occurred during filesystem probing.
    Io(io::Error),
    /// A general failure with an associated message.
    General(String),
}

impl fmt::Display for FindEspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindEspError::NotFound => write!(f, "EFI System Partition not found"),
            FindEspError::NotADirectory(p) => {
                write!(f, "Path {:?} is not a directory", p)
            }
            FindEspError::NotFsRoot(p) => {
                write!(f, "Directory {:?} is not the root of the filesystem", p)
            }
            FindEspError::NotFatFs(p) => {
                write!(f, "Filesystem {:?} is not a FAT EFI System Partition", p)
            }
            FindEspError::NotGpt(p) => {
                write!(f, "Filesystem {:?} is not on a GPT partition table", p)
            }
            FindEspError::WrongPartitionType(p) => {
                write!(f, "Filesystem {:?} has wrong partition type", p)
            }
            FindEspError::NoBackingDevice(p) => {
                write!(
                    f,
                    "Could not determine backing block device of {:?} (btrfs RAID?)",
                    p
                )
            }
            FindEspError::PathResolution { path, source } => {
                write!(f, "Failed to resolve path {:?}: {}", path, source)
            }
            FindEspError::Io(e) => write!(f, "I/O error: {}", e),
            FindEspError::General(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for FindEspError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FindEspError::PathResolution { source, .. } => Some(source),
            FindEspError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for FindEspError {
    fn from(e: io::Error) -> Self {
        FindEspError::Io(e)
    }
}

// ── Constants ──────────────────────────────────────────────────────────────

/// Environment variable that, when set to an absolute path, overrides ESP discovery.
pub const ENV_ESP_PATH: &str = "SYSTEMD_ESP_PATH";

/// Environment variable that, when set to an absolute path, overrides XBOOTLDR discovery.
pub const ENV_XBOOTLDR_PATH: &str = "SYSTEMD_XBOOTLDR_PATH";

/// Environment variable to relax ESP verification checks.
pub const ENV_RELAX_ESP_CHECKS: &str = "SYSTEMD_RELAX_ESP_CHECKS";

/// Environment variable to relax XBOOTLDR verification checks.
pub const ENV_RELAX_XBOOTLDR_CHECKS: &str = "SYSTEMD_RELAX_XBOOTLDR_CHECKS";

/// Well-known directories to search for the ESP, in priority order.
pub const ESP_SEARCH_PATHS: &[&str] = &["/efi", "/boot", "/boot/efi"];

/// The single well-known directory to search for the XBOOTLDR partition.
pub const XBOOTLDR_SEARCH_PATH: &str = "/boot";

/// The GPT partition type GUID for the EFI System Partition.
/// String representation: `c12a7328-f81f-11d2-ba4b-00a0c93ec93b`.
pub const SD_GPT_ESP_STR: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";

/// The GPT partition type GUID for the Extended Boot Loader Partition.
/// String representation: `bc13c2ff-59e6-4262-a352-b275fd6f7172`.
pub const SD_GPT_XBOOTLDR_STR: &str = "bc13c2ff-59e6-4262-a352-b275fd6f7172";

/// DOS partition type hex for XBOOTLDR.
pub const XBOOTLDR_DOS_TYPE: &str = "0xea";

/// The magic number for MSDOS/FAT/VFAT filesystems (from linux/magic.h).
pub const MSDOS_SUPER_MAGIC: u64 = 0x4d44;

// ── Flags ───────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling ESP/XBOOTLDR verification behaviour.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VerifyEspFlags: u32 {
        /// Downgrade "not found" log messages to debug level during search.
        const SEARCHING          = 1 << 0;
        /// Use udev for device metadata instead of direct blkid access.
        const UNPRIVILEGED_MODE  = 1 << 1;
        /// Skip filesystem type check (FAT vs others).
        const SKIP_FSTYPE_CHECK  = 1 << 2;
        /// Skip device node / partition table check.
        const SKIP_DEVICE_CHECK  = 1 << 3;
        /// Skip the check that the candidate is the root of its filesystem.
        const SKIP_FSROOT_CHECK  = 1 << 4;
    }
}

// ── Partition info ──────────────────────────────────────────────────────────

/// Full metadata about a discovered ESP partition.
#[derive(Debug, Clone, Default)]
pub struct EspInfo {
    /// Resolved absolute path to the ESP mount point.
    pub path: Option<PathBuf>,
    /// Partition number on the block device.
    pub partition: Option<u32>,
    /// Partition offset in the partition table's sector units.
    pub partition_start: Option<u64>,
    /// Partition size in the partition table's sector units.
    pub partition_size: Option<u64>,
    /// Partition UUID (128-bit).
    pub partition_uuid: Option<[u8; 16]>,
    /// Device ID (major, minor) of the backing block device.
    pub device_id: Option<(u32, u32)>,
}

impl EspInfo {
    /// Create a new `EspInfo` with the given path and no device details.
    pub fn from_path(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            ..Default::default()
        }
    }

    /// Create a new `EspInfo` with path and device id (used for env-var override).
    pub fn from_path_and_dev(path: PathBuf, dev: u64) -> Self {
        Self {
            path: Some(path),
            // Reuse the target-authoritative Linux dev_t codec rather than
            // approximating the split with masks that lose high major bits.
            device_id: Some((devnum_major(dev), devnum_minor(dev))),
            ..Default::default()
        }
    }

    /// Create a new `EspInfo` from full partition metadata.
    pub fn from_partition_details(
        path: PathBuf,
        partition: u32,
        pstart: u64,
        psize: u64,
        uuid: [u8; 16],
        devid: (u32, u32),
    ) -> Self {
        Self {
            path: Some(path),
            partition: Some(partition),
            partition_start: Some(pstart),
            partition_size: Some(psize),
            partition_uuid: Some(uuid),
            device_id: Some(devid),
        }
    }
}

/// Metadata about a discovered XBOOTLDR partition.
#[derive(Debug, Clone, Default)]
pub struct XBootLdrInfo {
    /// Resolved absolute path to the XBOOTLDR mount point.
    pub path: Option<PathBuf>,
    /// Partition UUID (128-bit), if on a GPT partition.
    pub partition_uuid: Option<[u8; 16]>,
    /// Device ID (major, minor) of the backing block device.
    pub device_id: Option<(u32, u32)>,
}

impl XBootLdrInfo {
    /// Create a new `XBootLdrInfo` with the given path.
    pub fn from_path(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            ..Default::default()
        }
    }

    /// Create a new `XBootLdrInfo` with path and device id.
    pub fn from_path_and_dev(path: PathBuf, dev: u64) -> Self {
        Self {
            path: Some(path),
            // See EspInfo::from_path_and_dev for why this shared codec is
            // required for complete Linux dev_t decoding.
            device_id: Some((devnum_major(dev), devnum_minor(dev))),
            ..Default::default()
        }
    }
}

// ── Unprivileged mode detection ─────────────────────────────────────────────

/// Detect whether the current process is running unprivileged (non-root).
///
/// Returns `true` if the effective UID is not 0.
pub fn is_unprivileged() -> bool {
    // SAFETY: geteuid() takes no arguments, does not dereference Rust memory,
    // and every uid_t bit pattern it returns is valid.
    unsafe_ffi!(libc::geteuid() != 0)
}

/// Parse a boolean environment variable.
///
/// Interprets the same case-insensitive spellings as C's `parse_boolean()`:
/// `"1"`, `"yes"`, `"y"`, `"true"`, `"t"`, `"on"` and their false
/// counterparts. Returns `None` if the variable is unset, empty, or invalid.
pub fn parse_env_bool(name: &str) -> Option<bool> {
    let val = std::env::var(name).ok()?;
    if val.is_empty() {
        return None;
    }
    match val.to_ascii_lowercase().as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Some(true),
        "0" | "no" | "n" | "false" | "f" | "off" => Some(false),
        _ => None,
    }
}

// ── Flag initialisation ────────────────────────────────────────────────────

/// Initialise verification flags for ESP checks.
///
/// Sets `UNPRIVILEGED_MODE` when `unprivileged_mode` is `Some(true)` or when
/// the effective UID is non-zero. Sets `SKIP_FSTYPE_CHECK`,
/// `SKIP_DEVICE_CHECK`, and `SKIP_FSROOT_CHECK` when the corresponding relax
/// environment variable parses as true. Container detection independently
/// sets `SKIP_DEVICE_CHECK`, matching the C implementation.
pub fn verify_esp_flags_init(
    unprivileged_mode: Option<bool>,
    env_name_for_relaxing: &str,
) -> VerifyEspFlags {
    let mut flags = VerifyEspFlags::empty();

    let unpriv = unprivileged_mode.unwrap_or_else(is_unprivileged);
    if unpriv {
        flags |= VerifyEspFlags::UNPRIVILEGED_MODE;
    }

    if let Some(true) = parse_env_bool(env_name_for_relaxing) {
        flags |= VerifyEspFlags::SKIP_FSTYPE_CHECK
            | VerifyEspFlags::SKIP_DEVICE_CHECK
            | VerifyEspFlags::SKIP_FSROOT_CHECK;
    }

    // Match C's fail-open policy: a positive detection suppresses device
    // probing, while a detection error is logged-and-ignored by the C caller.
    if detect_container().is_ok_and(virtualization_is_container) {
        flags |= VerifyEspFlags::SKIP_DEVICE_CHECK;
    }

    flags
}

// ── Path validation helpers ─────────────────────────────────────────────────

/// Return whether a Unix path is absolute and passes C's structural limits.
///
/// This mirrors `path_is_valid()` as used by the C environment overrides:
/// an absolute, non-empty path may contain `.` and `..` components, but it may
/// not contain a NUL byte, a component longer than `NAME_MAX`, or a pathname
/// string of `PATH_MAX` bytes or more (C reserves one further byte for NUL).
fn os_path_is_valid_absolute(p: &OsStr) -> bool {
    let bytes = p.as_bytes();
    !bytes.is_empty()
        && bytes[0] == b'/'
        && !bytes.contains(&0)
        && bytes.len() < libc::PATH_MAX as usize
        && bytes
            .split(|byte| *byte == b'/')
            .all(|component| component.len() <= libc::NAME_MAX as usize)
}

/// Check that a path string is valid and absolute.
pub fn path_is_valid_absolute(p: &str) -> bool {
    os_path_is_valid_absolute(OsStr::new(p))
}

/// Extract the filename component from a path, if any, without requiring UTF-8.
///
/// Returns `None` for paths like `/` that have no filename component
/// (mirrors C's `-EADDRNOTAVAIL` case). Linux path components are byte
/// strings, so returning `OsStr` prevents a valid non-UTF-8 filename from
/// being mistaken for an absent component.
pub fn path_extract_filename(p: &Path) -> Option<&OsStr> {
    p.file_name()
}

// ── Filesystem root directory check ─────────────────────────────────────────

/// Check that a directory is the root of its filesystem and return the
/// backing device number.
///
/// Opens `path` as a directory and uses `statx(AT_EMPTY_PATH)` with
/// `STATX_ATTR_MOUNT_ROOT`, matching C's descriptor-pinned check.
pub fn verify_fsroot_dir(path: &Path) -> Result<(u32, u32), FindEspError> {
    let fd = open_path(path).map_err(|source| FindEspError::PathResolution {
        path: path.to_path_buf(),
        source,
    })?;
    verify_fsroot_dir_fd(path, fd.as_fd(), true)
}

/// Check mount-root status through a pinned directory descriptor.
fn verify_fsroot_dir_fd(
    path: &Path,
    fd: BorrowedFd<'_>,
    resolve_backing_device: bool,
) -> Result<(u32, u32), FindEspError> {
    let mut statx = std::mem::MaybeUninit::<libc::statx>::zeroed();

    // SAFETY: `fd` is live, `c""` is a valid NUL-terminated empty path used
    // with AT_EMPTY_PATH, and `statx` is writable target-native storage.
    if unsafe_ffi!({
        libc::statx(
            fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            libc::STATX_TYPE | libc::STATX_INO,
            statx.as_mut_ptr(),
        )
    }) < 0
    {
        return Err(FindEspError::Io(io::Error::last_os_error()));
    }

    // SAFETY: the storage was zeroed before a successful libc call, so all
    // bytes are initialized even if an old kernel omits optional fields.
    let statx = unsafe_ffi!(statx.assume_init());
    if statx.stx_mask & (libc::STATX_TYPE | libc::STATX_INO) != libc::STATX_TYPE | libc::STATX_INO {
        return Err(FindEspError::Io(io::Error::from_raw_os_error(
            libc::EUNATCH,
        )));
    }
    if statx.stx_mode & libc::S_IFMT as u16 != libc::S_IFDIR as u16 {
        return Err(FindEspError::NotADirectory(path.to_path_buf()));
    }

    let mount_root = libc::STATX_ATTR_MOUNT_ROOT as u64;
    if statx.stx_attributes_mask & mount_root != mount_root {
        return Err(FindEspError::Io(io::Error::from_raw_os_error(
            libc::EUNATCH,
        )));
    }
    if statx.stx_attributes & mount_root == 0 {
        return Err(FindEspError::NotFsRoot(path.to_path_buf()));
    }

    if !resolve_backing_device || statx.stx_dev_major != 0 {
        return Ok((statx.stx_dev_major, statx.stx_dev_minor));
    }

    // Match verify_fsroot_dir() in C: only a requested zero-major device
    // triggers the btrfs topology query. Multi-device btrfs intentionally
    // leaves the device number zero, while non-btrfs and ioctl errors retain
    // the helper's original errno.
    match btrfs_get_block_device_fd(fd).map_err(FindEspError::Io)? {
        Some(device) => Ok((devnum_major(device as u64), devnum_minor(device as u64))),
        None => Ok((0, 0)),
    }
}

// ── Filesystem type check ───────────────────────────────────────────────────

/// Check that a filesystem path is mounted as a FAT/vfat filesystem.
///
/// Uses `statfs` to read the filesystem type and compares against
/// `MSDOS_SUPER_MAGIC`.
pub fn check_fat_filesystem(path: &Path) -> Result<(), FindEspError> {
    let fd = open_path(path).map_err(|source| FindEspError::PathResolution {
        path: path.to_path_buf(),
        source,
    })?;
    check_fat_filesystem_fd(path, fd.as_fd())
}

/// Check the filesystem type through a pinned candidate descriptor.
fn check_fat_filesystem_fd(path: &Path, fd: BorrowedFd<'_>) -> Result<(), FindEspError> {
    // SAFETY: Linux's statfs is a C POD struct containing only integers and
    // integer arrays, for which the all-zero bit pattern is valid.
    let mut statfs_buf: libc::statfs = unsafe_ffi!(std::mem::zeroed());

    // SAFETY: `fd` is live and statfs_buf is valid writable target-native
    // storage for the duration of fstatfs.
    let r = unsafe_ffi!(libc::fstatfs(fd.as_raw_fd(), &mut statfs_buf));
    if r < 0 {
        return Err(FindEspError::Io(io::Error::last_os_error()));
    }

    if statfs_buf.f_type as u64 != MSDOS_SUPER_MAGIC {
        return Err(FindEspError::NotFatFs(path.to_path_buf()));
    }

    Ok(())
}

fn partition_probe_result(result: libc::c_int) -> Result<(), FindEspError> {
    if result == 0 {
        return Ok(());
    }

    let errno = if result < 0 {
        result.checked_neg().unwrap_or(libc::EIO)
    } else {
        libc::EIO
    };
    Err(FindEspError::Io(io::Error::from_raw_os_error(errno)))
}

fn verify_esp_partition_metadata(
    device: (u32, u32),
    flags: VerifyEspFlags,
) -> Result<(u32, u64, u64, [u8; 16]), FindEspError> {
    let mut partition = 0;
    let mut partition_start = 0;
    let mut partition_size = 0;
    let mut partition_uuid = SdId128::NULL;

    // SAFETY: devnum_from_major_minor supplies the target-authoritative dev_t
    // representation. Every output points to live, initialized, uniquely
    // borrowed storage and the C helper retains none of it.
    let result = unsafe_ffi!({
        c_verify_esp_partition(
            devnum_from_major_minor(device.0, device.1) as libc::dev_t,
            if flags.contains(VerifyEspFlags::UNPRIVILEGED_MODE) {
                1
            } else {
                0
            },
            if flags.contains(VerifyEspFlags::SEARCHING) {
                1
            } else {
                0
            },
            &mut partition,
            &mut partition_start,
            &mut partition_size,
            &mut partition_uuid,
        )
    });
    partition_probe_result(result)?;

    Ok((
        partition,
        partition_start,
        partition_size,
        partition_uuid.bytes,
    ))
}

fn verify_xbootldr_partition_metadata(
    device: (u32, u32),
    flags: VerifyEspFlags,
) -> Result<Option<[u8; 16]>, FindEspError> {
    let mut partition_uuid = SdId128::NULL;

    // SAFETY: the encoded dev_t is target-authoritative, partition_uuid is a
    // live unique output slot with sd_id128_t layout, and C retains no pointer.
    let result = unsafe_ffi!({
        c_verify_xbootldr_partition(
            devnum_from_major_minor(device.0, device.1) as libc::dev_t,
            if flags.contains(VerifyEspFlags::UNPRIVILEGED_MODE) {
                1
            } else {
                0
            },
            if flags.contains(VerifyEspFlags::SEARCHING) {
                1
            } else {
                0
            },
            &mut partition_uuid,
        )
    });
    partition_probe_result(result)?;

    Ok((!partition_uuid.is_null()).then_some(partition_uuid.bytes))
}

// ── ESP verification ────────────────────────────────────────────────────────

/// Verify that a directory is a valid EFI System Partition.
///
/// Performs the following checks (controlled by `flags`):
/// 1. Path resolves to a directory (via chase/resolve).
/// 2. Filesystem is FAT/vfat (unless `SKIP_FSTYPE_CHECK`).
/// 3. Directory is the root of its filesystem.
/// 4. Backing block device exists (unless `SKIP_DEVICE_CHECK`).
///
/// Returns an `EspInfo` with discovered metadata on success.
pub fn verify_esp(path: &Path, flags: VerifyEspFlags) -> Result<EspInfo, FindEspError> {
    verify_esp_at(None, path, flags)
}

fn verify_esp_at(
    root_fd: Option<BorrowedFd<'_>>,
    path: &Path,
    flags: VerifyEspFlags,
) -> Result<EspInfo, FindEspError> {
    let searching = flags.contains(VerifyEspFlags::SEARCHING);
    let skip_fs = flags.contains(VerifyEspFlags::SKIP_FSTYPE_CHECK);
    let skip_dev = flags.contains(VerifyEspFlags::SKIP_DEVICE_CHECK);
    let skip_fsroot = flags.contains(VerifyEspFlags::SKIP_FSROOT_CHECK);

    // Resolve the path (chase symlinks).
    let resolved = resolve_path_at(root_fd, path).map_err(|e| {
        if searching && e.kind() == io::ErrorKind::NotFound {
            FindEspError::NotFound
        } else {
            FindEspError::PathResolution {
                path: path.to_path_buf(),
                source: e,
            }
        }
    })?;
    let fd = open_path(&resolved).map_err(|source| FindEspError::PathResolution {
        path: resolved.clone(),
        source,
    })?;

    if !skip_fs {
        check_fat_filesystem_fd(&resolved, fd.as_fd())?;
    }

    let device = if skip_fsroot {
        None
    } else {
        Some(verify_fsroot_dir_fd(&resolved, fd.as_fd(), !skip_dev)?)
    };

    if skip_dev {
        return Ok(EspInfo::from_path(resolved));
    }

    // C leaves the device number zero when its caller explicitly skips the
    // fs-root check; retain that fail-closed result if device verification was
    // nevertheless requested.
    let (dev_major, dev_minor) = device.unwrap_or((0, 0));

    // A zero device remains possible for a multi-device btrfs filesystem or
    // when fs-root verification was explicitly skipped. C rejects both before
    // probing partition metadata.
    if dev_major == 0 {
        return Err(FindEspError::NoBackingDevice(resolved));
    }

    let (partition, partition_start, partition_size, partition_uuid) =
        verify_esp_partition_metadata((dev_major, dev_minor), flags)?;

    Ok(EspInfo::from_partition_details(
        resolved,
        partition,
        partition_start,
        partition_size,
        partition_uuid,
        (dev_major, dev_minor),
    ))
}

/// Attempt to canonicalise a path, falling back to resolving it via openat.
fn canonicalize_or_resolve(p: &Path) -> io::Result<PathBuf> {
    p.canonicalize().or_else(|_| {
        // If canonicalize fails (e.g. permission denied), try resolving via
        // open+readlink /proc/self/fd.
        let fd = open_path(p)?;
        readlink_fd(fd)
    })
}

/// Resolve `p` beneath `root_fd`, treating absolute paths and absolute symlink
/// targets as relative to that root, like `chaseat(root_fd, root_fd, ...)`.
fn canonicalize_or_resolve_at(root_fd: BorrowedFd<'_>, p: &Path) -> io::Result<PathBuf> {
    let c_path = CString::new(p.as_os_str().as_bytes())?;

    // SAFETY: `open_how` consists solely of integer fields, for which zero is
    // valid. All fields understood by this call are initialized below.
    let mut how: libc::open_how = unsafe_ffi!(std::mem::zeroed());
    how.flags = (O_PATH | libc::O_CLOEXEC) as u64;
    how.resolve = libc::RESOLVE_IN_ROOT;

    // SAFETY: root_fd is borrowed for the duration of the call; c_path and how
    // remain live; the kernel is given the exact size of open_how. On success,
    // the returned value is a newly owned file descriptor.
    let fd = unsafe_ffi!({
        libc::syscall(
            libc::SYS_openat2,
            root_fd.as_raw_fd(),
            c_path.as_ptr(),
            &how,
            std::mem::size_of::<libc::open_how>(),
        )
    });
    if fd >= 0 {
        // SAFETY: a successful openat2 syscall returns a new descriptor in
        // c_int range, and ownership has not been transferred elsewhere.
        return readlink_fd(unsafe_ffi!(OwnedFd::from_raw_fd(fd as i32)));
    }

    let openat2_error = io::Error::last_os_error();
    if !matches!(
        openat2_error.raw_os_error(),
        Some(libc::ENOSYS | libc::EPERM | libc::EAGAIN)
    ) {
        return Err(openat2_error);
    }

    // openat2 may be unavailable on old kernels or blocked by seccomp. The
    // fallback is deliberately conservative: resolve through the root fd and
    // reject any result outside it. Unlike openat2, this cannot reinterpret an
    // absolute symlink target inside the alternate root, but it cannot escape
    // to the host tree either.
    let root = readlink_fd_path(root_fd)?;
    let relative = p.strip_prefix("/").unwrap_or(p);
    let resolved = canonicalize_or_resolve(&root.join(relative))?;
    if !resolved.starts_with(&root) {
        return Err(io::Error::from_raw_os_error(libc::EXDEV));
    }

    Ok(resolved)
}

fn resolve_path_at(root_fd: Option<BorrowedFd<'_>>, p: &Path) -> io::Result<PathBuf> {
    match root_fd {
        Some(fd) => canonicalize_or_resolve_at(fd, p),
        None => canonicalize_or_resolve(p),
    }
}

/// Whether a failed candidate should be ignored while searching well-known
/// ESP/XBOOTLDR locations.
///
/// This is the Rust equivalent of C's `IN_SET(r, -ENOENT,
/// -EADDRNOTAVAIL, -ENOTDIR, -ENOTTY)`: a missing path, a candidate that
/// fails ESP verification, a non-directory, or an unsuitable filesystem does
/// not stop discovery at later standard locations. All other I/O errors stay
/// fatal so permission and integrity failures are not hidden.
fn is_search_miss(error: &FindEspError) -> bool {
    match error {
        FindEspError::NotFound
        | FindEspError::NotADirectory(_)
        | FindEspError::NotFsRoot(_)
        | FindEspError::NotFatFs(_)
        | FindEspError::NotGpt(_)
        | FindEspError::WrongPartitionType(_)
        | FindEspError::NoBackingDevice(_) => true,
        FindEspError::PathResolution { source, .. } | FindEspError::Io(source) => {
            matches!(
                source.raw_os_error(),
                Some(libc::ENOENT | libc::EADDRNOTAVAIL | libc::ENOTDIR | libc::ENOTTY)
            )
        }
        FindEspError::General(_) => false,
    }
}

/// Open a path (directory) with O_PATH.
fn open_path(p: &Path) -> io::Result<OwnedFd> {
    let c_path = CString::new(p.as_os_str().as_bytes())?;
    // SAFETY: c_path is NUL-terminated and remains alive for the call. These
    // flags do not include O_CREAT or O_TMPFILE, so no variadic mode argument
    // is required.
    let fd = unsafe_ffi!({
        libc::open(
            c_path.as_ptr(),
            O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    });
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: successful open returns a new descriptor, and ownership has
        // not been transferred elsewhere.
        Ok(unsafe_ffi!(OwnedFd::from_raw_fd(fd)))
    }
}

/// Read the symlink target of `/proc/self/fd/<fd>`, taking ownership of `fd`.
fn readlink_fd(fd: OwnedFd) -> io::Result<PathBuf> {
    readlink_fd_path(fd.as_fd())
}

/// Read the symlink target of `/proc/self/fd/<fd>` without taking ownership.
fn readlink_fd_path(fd: BorrowedFd<'_>) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

// ── ESP discovery (high-level) ──────────────────────────────────────────────

/// Find the EFI System Partition and return its information.
///
/// Searches in the following order:
/// 1. If `path` is provided, verify it directly.
/// 2. If `$SYSTEMD_ESP_PATH` is set, use it (with minimal validation).
/// 3. Search well-known mount points: `/efi`, `/boot`, `/boot/efi`.
///
/// The `unprivileged_mode` parameter controls whether udev is used instead
/// of direct blkid access. Pass `None` to auto-detect from the effective UID.
pub fn find_esp_and_warn(
    path: Option<&Path>,
    unprivileged_mode: Option<bool>,
) -> Result<EspInfo, FindEspError> {
    find_esp_and_warn_at(None, path, unprivileged_mode)
}

fn find_esp_and_warn_at(
    root_fd: Option<BorrowedFd<'_>>,
    path: Option<&Path>,
    unprivileged_mode: Option<bool>,
) -> Result<EspInfo, FindEspError> {
    let flags = verify_esp_flags_init(unprivileged_mode, ENV_RELAX_ESP_CHECKS);

    // Explicit path takes priority.
    if let Some(p) = path {
        return verify_esp_at(root_fd, p, flags);
    }

    // Check environment variable override.
    if let Some(env_path) = std::env::var_os(ENV_ESP_PATH) {
        let p = Path::new(&env_path);
        if !os_path_is_valid_absolute(&env_path) {
            return Err(FindEspError::General(format!(
                "${} does not refer to an absolute path, refusing: {:?}",
                ENV_ESP_PATH, env_path
            )));
        }
        let resolved = resolve_path_at(root_fd, p).map_err(|e| FindEspError::PathResolution {
            path: p.to_path_buf(),
            source: e,
        })?;

        let fd = open_path(&resolved).map_err(|source| FindEspError::PathResolution {
            path: resolved.clone(),
            source,
        })?;
        let metadata =
            std::fs::File::from(fd)
                .metadata()
                .map_err(|source| FindEspError::PathResolution {
                    path: resolved.clone(),
                    source,
                })?;
        if !metadata.is_dir() {
            return Err(FindEspError::NotADirectory(resolved));
        }

        return Ok(EspInfo::from_path_and_dev(resolved, metadata.dev()));
    }

    // Search well-known paths.
    for dir in ESP_SEARCH_PATHS {
        let p = Path::new(dir);
        match verify_esp_at(root_fd, p, flags | VerifyEspFlags::SEARCHING) {
            Ok(info) => return Ok(info),
            Err(error) if is_search_miss(&error) => {
                // Try next candidate.
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Err(FindEspError::NotFound)
}

/// Find the ESP relative to a root directory.
///
/// Opens `root` and performs the search within that directory tree.
/// If `root` is `None` or empty, the current root (`/`) is used.
pub fn find_esp_and_warn_full(
    root: Option<&Path>,
    path: Option<&Path>,
    unprivileged_mode: Option<bool>,
) -> Result<EspInfo, FindEspError> {
    // If root is empty or None, search from /.
    let effective_root = match root {
        Some(r) if !r.as_os_str().is_empty() => r,
        _ => Path::new("/"),
    };

    if effective_root == Path::new("/") {
        return find_esp_and_warn(path, unprivileged_mode);
    }

    let root_fd = open_path(effective_root).map_err(FindEspError::Io)?;
    find_esp_and_warn_at(Some(root_fd.as_fd()), path, unprivileged_mode)
}

// ── XBOOTLDR verification ──────────────────────────────────────────────────

/// Verify that a directory is a valid Extended Boot Loader Partition.
///
/// Similar to `verify_esp` but checks for XBOOTLDR partition type instead
/// of ESP type. No filesystem type check is performed (XBOOTLDR can be any fs).
pub fn verify_xbootldr(path: &Path, flags: VerifyEspFlags) -> Result<XBootLdrInfo, FindEspError> {
    verify_xbootldr_at(None, path, flags)
}

fn verify_xbootldr_at(
    root_fd: Option<BorrowedFd<'_>>,
    path: &Path,
    flags: VerifyEspFlags,
) -> Result<XBootLdrInfo, FindEspError> {
    let searching = flags.contains(VerifyEspFlags::SEARCHING);
    let skip_dev = flags.contains(VerifyEspFlags::SKIP_DEVICE_CHECK);
    let skip_fsroot = flags.contains(VerifyEspFlags::SKIP_FSROOT_CHECK);

    let resolved = resolve_path_at(root_fd, path).map_err(|e| {
        if searching && e.kind() == io::ErrorKind::NotFound {
            FindEspError::NotFound
        } else {
            FindEspError::PathResolution {
                path: path.to_path_buf(),
                source: e,
            }
        }
    })?;
    let fd = open_path(&resolved).map_err(|source| FindEspError::PathResolution {
        path: resolved.clone(),
        source,
    })?;

    let device = if skip_fsroot {
        None
    } else {
        Some(verify_fsroot_dir_fd(&resolved, fd.as_fd(), !skip_dev)?)
    };

    if skip_dev {
        return Ok(XBootLdrInfo::from_path(resolved));
    }

    let (dev_major, dev_minor) = device.unwrap_or((0, 0));

    // See verify_esp_at(): a multi-device btrfs filesystem leaves the device
    // number zero, as does an explicitly skipped device check.
    if dev_major == 0 {
        return Err(FindEspError::NoBackingDevice(resolved));
    }

    let partition_uuid = verify_xbootldr_partition_metadata((dev_major, dev_minor), flags)?;

    Ok(XBootLdrInfo {
        path: Some(resolved),
        partition_uuid,
        device_id: Some((dev_major, dev_minor)),
    })
}

// ── XBOOTLDR discovery (high-level) ────────────────────────────────────────

/// Find the Extended Boot Loader Partition and return its information.
///
/// Searches in the following order:
/// 1. If `path` is provided, verify it directly.
/// 2. If `$SYSTEMD_XBOOTLDR_PATH` is set, use it (with minimal validation).
/// 3. Check `/boot`.
pub fn find_xbootldr_and_warn(
    path: Option<&Path>,
    unprivileged_mode: Option<bool>,
) -> Result<XBootLdrInfo, FindEspError> {
    find_xbootldr_and_warn_at(None, path, unprivileged_mode)
}

fn find_xbootldr_and_warn_at(
    root_fd: Option<BorrowedFd<'_>>,
    path: Option<&Path>,
    unprivileged_mode: Option<bool>,
) -> Result<XBootLdrInfo, FindEspError> {
    let flags = verify_esp_flags_init(unprivileged_mode, ENV_RELAX_XBOOTLDR_CHECKS);

    if let Some(p) = path {
        return verify_xbootldr_at(root_fd, p, flags);
    }

    if let Some(env_path) = std::env::var_os(ENV_XBOOTLDR_PATH) {
        let p = Path::new(&env_path);
        if !os_path_is_valid_absolute(&env_path) {
            return Err(FindEspError::General(format!(
                "${} does not refer to an absolute path, refusing: {:?}",
                ENV_XBOOTLDR_PATH, env_path
            )));
        }
        let resolved = resolve_path_at(root_fd, p).map_err(|e| FindEspError::PathResolution {
            path: p.to_path_buf(),
            source: e,
        })?;

        let fd = open_path(&resolved).map_err(|source| FindEspError::PathResolution {
            path: resolved.clone(),
            source,
        })?;
        let metadata =
            std::fs::File::from(fd)
                .metadata()
                .map_err(|source| FindEspError::PathResolution {
                    path: resolved.clone(),
                    source,
                })?;
        if !metadata.is_dir() {
            return Err(FindEspError::NotADirectory(resolved));
        }

        return Ok(XBootLdrInfo::from_path_and_dev(resolved, metadata.dev()));
    }

    match verify_xbootldr_at(
        root_fd,
        Path::new(XBOOTLDR_SEARCH_PATH),
        flags | VerifyEspFlags::SEARCHING,
    ) {
        Ok(info) => Ok(info),
        Err(error) if is_search_miss(&error) => Err(FindEspError::NotFound),
        Err(e) => Err(e),
    }
}

/// Find the XBOOTLDR partition relative to a root directory.
pub fn find_xbootldr_and_warn_full(
    root: Option<&Path>,
    path: Option<&Path>,
    unprivileged_mode: Option<bool>,
) -> Result<XBootLdrInfo, FindEspError> {
    let effective_root = match root {
        Some(r) if !r.as_os_str().is_empty() => r,
        _ => Path::new("/"),
    };

    if effective_root == Path::new("/") {
        return find_xbootldr_and_warn(path, unprivileged_mode);
    }

    let root_fd = open_path(effective_root).map_err(FindEspError::Io)?;
    find_xbootldr_and_warn_at(Some(root_fd.as_fd()), path, unprivileged_mode)
}

/// Take (claim) an ESP mount point by returning the path string.
///
/// This is a convenience wrapper around `find_esp_and_warn` that returns
/// just the resolved path, or an error.
pub fn take_esp_mount_point(
    path: Option<&Path>,
    unprivileged_mode: Option<bool>,
) -> Result<PathBuf, FindEspError> {
    let info = find_esp_and_warn(path, unprivileged_mode)?;
    info.path
        .ok_or_else(|| FindEspError::General("ESP found but path is None".into()))
}

/// Verify an automount point for XBOOTLDR.
///
/// Convenience wrapper that checks if the given path could be an XBOOTLDR
/// automount point (i.e. the directory exists but the actual partition is
/// not yet mounted).
pub fn verify_xbootldr_automount(path: &Path) -> Result<XBootLdrInfo, FindEspError> {
    let flags = VerifyEspFlags::SEARCHING
        | VerifyEspFlags::UNPRIVILEGED_MODE
        | VerifyEspFlags::SKIP_DEVICE_CHECK
        // This Rust-only convenience API intentionally accepts an inactive
        // automount's underlying directory, which is not yet a mount root.
        | VerifyEspFlags::SKIP_FSROOT_CHECK;
    verify_xbootldr(path, flags)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::TestEnvironment;
    use std::ffi::OsStr;

    // ── Error display ──

    #[test]
    fn test_error_display_not_found() {
        let err = FindEspError::NotFound;
        assert_eq!(format!("{err}"), "EFI System Partition not found");
    }

    #[test]
    fn test_error_display_not_directory() {
        let err = FindEspError::NotADirectory(PathBuf::from("/some/path"));
        assert!(
            format!("{err}").contains("not a directory"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_error_display_not_fs_root() {
        let err = FindEspError::NotFsRoot(PathBuf::from("/boot"));
        assert!(
            format!("{err}").contains("not the root of the filesystem"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_error_display_not_fat() {
        let err = FindEspError::NotFatFs(PathBuf::from("/efi"));
        assert!(format!("{err}").contains("not a FAT"), "unexpected: {err}");
    }

    #[test]
    fn test_error_display_no_backing_device() {
        let err = FindEspError::NoBackingDevice(PathBuf::from("/boot"));
        assert!(
            format!("{err}").contains("Could not determine backing block device"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_error_display_general() {
        let err = FindEspError::General("something went wrong".into());
        assert_eq!(format!("{err}"), "something went wrong");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let err = FindEspError::from(io_err);
        assert!(matches!(err, FindEspError::Io(_)));
    }

    // ── Constants ──

    #[test]
    fn test_esp_search_paths() {
        assert_eq!(ESP_SEARCH_PATHS, &["/efi", "/boot", "/boot/efi"]);
        assert!(ESP_SEARCH_PATHS[0].starts_with('/'));
    }

    #[test]
    fn test_xbootldr_search_path() {
        assert_eq!(XBOOTLDR_SEARCH_PATH, "/boot");
    }

    #[test]
    fn test_gpt_guids_are_valid() {
        // GPT UUIDs are 36 chars in the canonical form (8-4-4-4-12).
        assert_eq!(SD_GPT_ESP_STR.len(), 36);
        assert_eq!(SD_GPT_XBOOTLDR_STR.len(), 36);
        assert_ne!(SD_GPT_ESP_STR, SD_GPT_XBOOTLDR_STR);
    }

    // ── Flag initialisation ──

    #[test]
    fn test_verify_esp_flags_init_no_relax() {
        // Without the env var set, only container policy may request a skip.
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe_ffi!(TestEnvironment::lock());
        environment.remove(ENV_RELAX_ESP_CHECKS);
        let flags = verify_esp_flags_init(Some(false), ENV_RELAX_ESP_CHECKS);
        assert!(!flags.contains(VerifyEspFlags::SKIP_FSTYPE_CHECK));
        let in_container = detect_container().is_ok_and(virtualization_is_container);
        assert_eq!(
            flags.contains(VerifyEspFlags::SKIP_DEVICE_CHECK),
            in_container
        );
        assert!(!flags.contains(VerifyEspFlags::SKIP_FSROOT_CHECK));
        assert!(!flags.contains(VerifyEspFlags::UNPRIVILEGED_MODE));
    }

    #[test]
    fn test_verify_esp_flags_init_unprivileged() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe_ffi!(TestEnvironment::lock());
        environment.remove(ENV_RELAX_ESP_CHECKS);
        let flags = verify_esp_flags_init(Some(true), ENV_RELAX_ESP_CHECKS);
        assert!(flags.contains(VerifyEspFlags::UNPRIVILEGED_MODE));
    }

    #[test]
    fn test_verify_esp_flags_init_searching() {
        let flags = VerifyEspFlags::SEARCHING;
        assert!(flags.contains(VerifyEspFlags::SEARCHING));
    }

    #[test]
    fn test_verify_esp_flags_init_relax_skips_every_verification() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe_ffi!(TestEnvironment::lock());
        environment.set(ENV_RELAX_ESP_CHECKS, "yes");
        let flags = verify_esp_flags_init(Some(false), ENV_RELAX_ESP_CHECKS);
        assert!(flags.contains(VerifyEspFlags::SKIP_FSTYPE_CHECK));
        assert!(flags.contains(VerifyEspFlags::SKIP_DEVICE_CHECK));
        assert!(flags.contains(VerifyEspFlags::SKIP_FSROOT_CHECK));
        environment.remove(ENV_RELAX_ESP_CHECKS);
    }

    // ── Path helpers ──

    #[test]
    fn test_path_is_valid_absolute() {
        assert!(path_is_valid_absolute("/efi"));
        assert!(path_is_valid_absolute("/boot/efi"));
        assert!(!path_is_valid_absolute(""));
        assert!(!path_is_valid_absolute("relative/path"));
        assert!(!path_is_valid_absolute("efi"));
    }

    #[test]
    fn test_path_extract_filename() {
        assert_eq!(
            path_extract_filename(Path::new("/boot/efi")),
            Some(OsStr::new("efi"))
        );
        assert_eq!(
            path_extract_filename(Path::new("/boot")),
            Some(OsStr::new("boot"))
        );
        // Root has no filename component.
        assert_eq!(path_extract_filename(Path::new("/")), None);
    }

    #[test]
    fn test_path_extract_filename_preserves_non_utf8() {
        use std::os::unix::ffi::OsStrExt;

        let path = Path::new(OsStr::from_bytes(b"/boot/\xffefi"));
        assert_eq!(
            path_extract_filename(path).map(OsStr::as_bytes),
            Some(b"\xffefi".as_slice())
        );
    }

    #[test]
    fn test_search_miss_matches_c_error_precedence() {
        assert!(is_search_miss(&FindEspError::NotADirectory(PathBuf::from(
            "/efi"
        ))));
        assert!(is_search_miss(&FindEspError::NoBackingDevice(
            PathBuf::from("/efi")
        )));
        assert!(is_search_miss(&FindEspError::PathResolution {
            path: PathBuf::from("/efi"),
            source: io::Error::from_raw_os_error(libc::ENOTTY),
        }));
        assert!(!is_search_miss(&FindEspError::Io(
            io::Error::from_raw_os_error(libc::EACCES,)
        )));
    }

    // ── Parse env bool ──

    #[test]
    fn test_parse_env_bool() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe_ffi!(TestEnvironment::lock());
        environment.set("TEST_FIND_ESP_BOOL", "1");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(true));

        environment.set("TEST_FIND_ESP_BOOL", "yes");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(true));

        environment.set("TEST_FIND_ESP_BOOL", "true");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(true));

        environment.set("TEST_FIND_ESP_BOOL", "on");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(true));

        environment.set("TEST_FIND_ESP_BOOL", "Y");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(true));

        environment.set("TEST_FIND_ESP_BOOL", "t");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(true));

        environment.set("TEST_FIND_ESP_BOOL", "0");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(false));

        environment.set("TEST_FIND_ESP_BOOL", "no");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(false));

        environment.set("TEST_FIND_ESP_BOOL", "false");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(false));

        environment.set("TEST_FIND_ESP_BOOL", "off");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(false));

        environment.set("TEST_FIND_ESP_BOOL", "N");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(false));

        environment.set("TEST_FIND_ESP_BOOL", "f");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(false));

        environment.set("TEST_FIND_ESP_BOOL", "");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), None);

        environment.remove("TEST_FIND_ESP_BOOL");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), None);

        environment.set("TEST_FIND_ESP_BOOL", "invalid");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), None);

        // parse_boolean() does not silently trim input.
        environment.set("TEST_FIND_ESP_BOOL", " yes ");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), None);
    }

    // ── EspInfo ──

    #[test]
    fn test_esp_info_from_path() {
        let info = EspInfo::from_path(PathBuf::from("/efi"));
        assert_eq!(info.path, Some(PathBuf::from("/efi")));
        assert!(info.partition.is_none());
        assert!(info.partition_uuid.is_none());
    }

    #[test]
    fn test_esp_info_from_partition_details() {
        let uuid = [0xAB; 16];
        let info = EspInfo::from_partition_details(
            PathBuf::from("/efi"),
            1,
            2048,
            524_288_000,
            uuid,
            (8, 1),
        );
        assert_eq!(info.path, Some(PathBuf::from("/efi")));
        assert_eq!(info.partition, Some(1));
        assert_eq!(info.partition_start, Some(2048));
        assert_eq!(info.partition_size, Some(524_288_000));
        assert_eq!(info.partition_uuid, Some(uuid));
        assert_eq!(info.device_id, Some((8, 1)));
    }

    #[test]
    fn test_esp_info_default() {
        let info = EspInfo::default();
        assert!(info.path.is_none());
        assert!(info.partition.is_none());
        assert!(info.device_id.is_none());
    }

    // ── XBootLdrInfo ──

    #[test]
    fn test_xbootldr_info_from_path() {
        let info = XBootLdrInfo::from_path(PathBuf::from("/boot"));
        assert_eq!(info.path, Some(PathBuf::from("/boot")));
        assert!(info.partition_uuid.is_none());
    }

    #[test]
    fn test_xbootldr_info_default() {
        let info = XBootLdrInfo::default();
        assert!(info.path.is_none());
        assert!(info.partition_uuid.is_none());
    }

    // ── Verify ESP on non-existent path ──

    #[test]
    fn test_verify_esp_nonexistent_path() {
        let result = verify_esp(
            Path::new("/nonexistent/path/that/does/not/exist"),
            VerifyEspFlags::SEARCHING,
        );
        assert!(result.is_err());
    }

    // ── Verify XBOOTLDR on non-existent path ──

    #[test]
    fn test_verify_xbootldr_nonexistent_path() {
        let result = verify_xbootldr(
            Path::new("/nonexistent/path/that/does/not/exist"),
            VerifyEspFlags::SEARCHING,
        );
        assert!(result.is_err());
    }

    // ── Find ESP with no ESP available ──

    #[test]
    fn test_find_esp_not_found() {
        // In a test environment, none of the standard paths should be a valid
        // ESP (no FAT filesystem, no GPT partition, etc.)
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe_ffi!(TestEnvironment::lock());
        environment.remove(ENV_ESP_PATH);
        let result = find_esp_and_warn(None, Some(false));
        // We expect either NotFound or some other verification error.
        // The exact error depends on the test environment.
        assert!(
            result.is_err(),
            "Expected an error when no ESP is available"
        );
    }

    // ── Find XBOOTLDR not found ──

    #[test]
    fn test_find_xbootldr_not_found() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe_ffi!(TestEnvironment::lock());
        environment.remove(ENV_XBOOTLDR_PATH);
        let result = find_xbootldr_and_warn(None, Some(false));
        assert!(
            result.is_err(),
            "Expected an error when no XBOOTLDR is available"
        );
    }

    // ── Verify fsroot dir on /tmp ──

    #[test]
    fn test_verify_fsroot_dir_tmp() {
        // /tmp is usually its own mount, so this should succeed or fail
        // gracefully depending on the environment.
        let result = verify_fsroot_dir(Path::new("/tmp"));
        // Either succeeds (mount point) or fails (not a mount point root).
        // Both are valid outcomes.
        let _ = result;
    }

    // ── Verify fsroot dir on non-existent path ──

    #[test]
    fn test_verify_fsroot_dir_nonexistent() {
        let result = verify_fsroot_dir(Path::new("/nonexistent_dir_xyz"));
        assert!(result.is_err());
    }

    // ── Check FAT filesystem on non-FAT path ──

    #[test]
    fn test_check_fat_filesystem_root() {
        // / is almost certainly not FAT on a Linux test system.
        let result = check_fat_filesystem(Path::new("/"));
        assert!(result.is_err());
        assert!(matches!(result, Err(FindEspError::NotFatFs(_))));
    }

    // ── Verify xbootldr automount ──

    #[test]
    fn test_verify_xbootldr_automount_nonexistent() {
        let result = verify_xbootldr_automount(Path::new("/nonexistent_xyz"));
        assert!(result.is_err());
    }

    // ── take_esp_mount_point ──

    #[test]
    fn test_take_esp_mount_point_not_found() {
        // SAFETY: this environment-dependent test target runs with --test-threads=1
        // and does not spawn threads that access the process environment.
        let environment = unsafe_ffi!(TestEnvironment::lock());
        environment.remove(ENV_ESP_PATH);
        let result = take_esp_mount_point(None, Some(false));
        assert!(result.is_err());
    }

    // ── Bitflags combinations ──

    #[test]
    fn test_flags_combinations() {
        let f = VerifyEspFlags::SEARCHING
            | VerifyEspFlags::UNPRIVILEGED_MODE
            | VerifyEspFlags::SKIP_FSTYPE_CHECK
            | VerifyEspFlags::SKIP_DEVICE_CHECK
            | VerifyEspFlags::SKIP_FSROOT_CHECK;
        assert!(f.contains(VerifyEspFlags::SEARCHING));
        assert!(f.contains(VerifyEspFlags::UNPRIVILEGED_MODE));
        assert!(f.contains(VerifyEspFlags::SKIP_FSTYPE_CHECK));
        assert!(f.contains(VerifyEspFlags::SKIP_DEVICE_CHECK));
        assert!(f.contains(VerifyEspFlags::SKIP_FSROOT_CHECK));
    }

    #[test]
    fn test_flags_empty() {
        let f = VerifyEspFlags::empty();
        assert!(!f.contains(VerifyEspFlags::SEARCHING));
        assert!(!f.contains(VerifyEspFlags::UNPRIVILEGED_MODE));
    }

    // ── is_unprivileged ──

    #[test]
    fn test_is_unprivileged_returns_bool() {
        // This function should always return without panicking.
        let _ = is_unprivileged();
    }
}
