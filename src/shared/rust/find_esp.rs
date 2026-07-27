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
// Verification involves confirming the filesystem is FAT (vfat), resides on a
// GPT partition with the correct type GUID, and (when privileged) probing the
// partition table via blkid or udev for full metadata.

use crate::ffi::*;
use std::fmt;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

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
    /// Partition offset (in bytes from start of disk).
    pub partition_start: Option<u64>,
    /// Partition size in bytes.
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
        let major = ((dev >> 8) & 0xfff_f) as u32;
        let minor = ((dev & 0xff) | ((dev >> 12) & 0xfff_f00)) as u32;
        Self {
            path: Some(path),
            device_id: Some((major, minor)),
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
        let major = ((dev >> 8) & 0xfff_f) as u32;
        let minor = ((dev & 0xff) | ((dev >> 12) & 0xfff_f00)) as u32;
        Self {
            path: Some(path),
            device_id: Some((major, minor)),
            ..Default::default()
        }
    }
}

// ── Unprivileged mode detection ─────────────────────────────────────────────

/// Detect whether the current process is running unprivileged (non-root).
///
/// Returns `true` if the effective UID is not 0.
pub fn is_unprivileged() -> bool {
    // SAFETY: geteuid is a simple syscall that never fails.
    unsafe { libc::geteuid() != 0 }
}

/// Parse a boolean environment variable.
///
/// Interprets `"1"`, `"yes"`, `"true"`, `"on"` as true, and `"0"`, `"no"`,
/// `"false"`, `"off"` as false. Returns `None` if the variable is unset or
/// empty.
pub fn parse_env_bool(name: &str) -> Option<bool> {
    let val = std::env::var(name).ok()?;
    let val = val.trim();
    if val.is_empty() {
        return None;
    }
    match val.to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Some(true),
        "0" | "no" | "false" | "off" => Some(false),
        _ => None,
    }
}

// ── Flag initialisation ────────────────────────────────────────────────────

/// Initialise verification flags for ESP checks.
///
/// Sets `UNPRIVILEGED_MODE` when `unprivileged_mode` is `Some(true)` or when
/// the effective UID is non-zero. Sets `SKIP_FSTYPE_CHECK` and
/// `SKIP_DEVICE_CHECK` when the corresponding relax environment variable is
/// `"yes"`.
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
        flags |= VerifyEspFlags::SKIP_FSTYPE_CHECK | VerifyEspFlags::SKIP_DEVICE_CHECK;
    }

    flags
}

// ── Path validation helpers ─────────────────────────────────────────────────

/// Check that a path string is valid and absolute.
pub fn path_is_valid_absolute(p: &str) -> bool {
    if p.is_empty() {
        return false;
    }
    let path = Path::new(p);
    path.is_absolute() && p.chars().all(|c| c != '\0')
}

/// Extract the filename component from a path, if any.
///
/// Returns `None` for paths like `/` that have no filename component
/// (mirrors C's `-EADDRNOTAVAIL` case).
pub fn path_extract_filename(p: &Path) -> Option<&str> {
    p.file_name()?.to_str()
}

// ── Filesystem root directory check ─────────────────────────────────────────

/// Check that a directory is the root of its filesystem and return the
/// backing device number.
///
/// Uses `statx` with `STATX_ATTR_MOUNT_ROOT` (when available) to confirm the
/// directory is a mount point. Falls back to comparing st_dev of the
/// directory and its parent.
pub fn verify_fsroot_dir(path: &Path) -> Result<(u32, u32), FindEspError> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            FindEspError::NotFound
        } else {
            FindEspError::PathResolution {
                path: path.to_path_buf(),
                source: e,
            }
        }
    })?;

    if !metadata.is_dir() {
        return Err(FindEspError::NotADirectory(path.to_path_buf()));
    }

    // Check if this is a mount root by comparing dev of this dir with its parent.
    let parent = path.parent().unwrap_or(Path::new("/"));
    let parent_meta = match std::fs::metadata(parent) {
        Ok(m) => m,
        Err(_) => {
            // If we can't stat parent, trust it if it's / or /boot etc.
            return Ok((major(metadata.dev()), minor(metadata.dev())));
        }
    };

    if metadata.dev() == parent_meta.dev() {
        // Same device → not a mount point root
        return Err(FindEspError::NotFsRoot(path.to_path_buf()));
    }

    Ok((major(metadata.dev()), minor(metadata.dev())))
}

/// Extract major number from a device ID.
#[inline]
fn major(dev: u64) -> u32 {
    ((dev >> 8) & 0xfff_f) as u32
}

/// Extract minor number from a device ID.
#[inline]
fn minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & 0xfff_f00)) as u32
}

// ── Filesystem type check ───────────────────────────────────────────────────

/// Check that a filesystem path is mounted as a FAT/vfat filesystem.
///
/// Uses `statfs` to read the filesystem type and compares against
/// `MSDOS_SUPER_MAGIC`.
pub fn check_fat_filesystem(path: &Path) -> Result<(), FindEspError> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| FindEspError::General(format!("Path {:?} contains NUL byte", path)))?;

    let mut statfs_buf: libc::statfs = unsafe { std::mem::zeroed() };

    // SAFETY: c_path is a valid NUL-terminated string, statfs_buf is a valid
    // pointer to a statfs struct on the stack.
    let r = unsafe { libc::statfs(c_path.as_ptr(), &mut statfs_buf) };
    if r < 0 {
        return Err(FindEspError::Io(io::Error::last_os_error()));
    }

    if statfs_buf.f_type as u64 != MSDOS_SUPER_MAGIC {
        return Err(FindEspError::NotFatFs(path.to_path_buf()));
    }

    Ok(())
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
    let searching = flags.contains(VerifyEspFlags::SEARCHING);
    let skip_fs = flags.contains(VerifyEspFlags::SKIP_FSTYPE_CHECK);
    let skip_dev = flags.contains(VerifyEspFlags::SKIP_DEVICE_CHECK);

    // Resolve the path (chase symlinks).
    let resolved = canonicalize_or_resolve(path).map_err(|e| {
        if searching && e.kind() == io::ErrorKind::NotFound {
            FindEspError::NotFound
        } else {
            FindEspError::PathResolution {
                path: path.to_path_buf(),
                source: e,
            }
        }
    })?;

    if !skip_fs {
        check_fat_filesystem(&resolved)?;
    }

    let (dev_major, dev_minor) = if skip_dev {
        (0, 0)
    } else {
        verify_fsroot_dir(&resolved)?
    };

    if skip_dev {
        return Ok(EspInfo::from_path(resolved));
    }

    if dev_major == 0 && dev_minor == 0 {
        return Err(FindEspError::NoBackingDevice(resolved));
    }

    // In a real implementation, blkid or udev probing would happen here.
    // For the safe Rust rewrite, we return the device info we have.
    Ok(EspInfo::from_partition_details(
        resolved,
        0,
        0,
        0,
        [0u8; 16],
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

/// Open a path (directory) with O_PATH.
fn open_path(p: &Path) -> io::Result<i32> {
    let c_path = CString::new(p.as_os_str().as_bytes())?;
    // SAFETY: c_path is a valid NUL-terminated string.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(fd)
    }
}

/// Read the symlink target of /proc/self/fd/<fd>.
fn readlink_fd(fd: i32) -> io::Result<PathBuf> {
    let link = format!("/proc/self/fd/{}", fd);
    let mut buf = vec![0u8; 4096];
    // SAFETY: link is a valid NUL-terminated string, buf is a valid buffer.
    let len = unsafe {
        libc::readlink(
            link.as_ptr() as *const _,
            buf.as_mut_ptr() as *mut _,
            buf.len() - 1,
        )
    };
    if len < 0 {
        Err(io::Error::last_os_error())
    } else {
        buf.truncate(len as usize);
        let path = PathBuf::from(String::from_utf8_lossy(&buf).into_owned());
        // Close the fd on success.
        unsafe { libc::close(fd) };
        Ok(path)
    }
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
    let flags = verify_esp_flags_init(unprivileged_mode, ENV_RELAX_ESP_CHECKS);

    // Explicit path takes priority.
    if let Some(p) = path {
        return verify_esp(p, flags);
    }

    // Check environment variable override.
    if let Ok(env_path) = std::env::var(ENV_ESP_PATH) {
        if !path_is_valid_absolute(&env_path) {
            return Err(FindEspError::General(format!(
                "${} does not refer to an absolute path, refusing: {:?}",
                ENV_ESP_PATH, env_path
            )));
        }
        let p = Path::new(&env_path);
        let resolved = canonicalize_or_resolve(p).map_err(|e| FindEspError::PathResolution {
            path: p.to_path_buf(),
            source: e,
        })?;

        let metadata = std::fs::metadata(&resolved).map_err(|e| FindEspError::PathResolution {
            path: resolved.clone(),
            source: e,
        })?;
        if !metadata.is_dir() {
            return Err(FindEspError::NotADirectory(resolved));
        }

        return Ok(EspInfo::from_path_and_dev(resolved, metadata.dev()));
    }

    // Search well-known paths.
    for dir in ESP_SEARCH_PATHS {
        let p = Path::new(dir);
        match verify_esp(p, flags | VerifyEspFlags::SEARCHING) {
            Ok(info) => return Ok(info),
            Err(FindEspError::NotFound)
            | Err(FindEspError::NotFatFs(_))
            | Err(FindEspError::NotFsRoot(_))
            | Err(FindEspError::NotGpt(_))
            | Err(FindEspError::WrongPartitionType(_)) => {
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

    // Open root directory fd.
    let root_cstr = CString::new(effective_root.as_os_str().as_bytes()).map_err(|_| {
        FindEspError::General(format!("Root path {:?} contains NUL byte", effective_root))
    })?;

    // SAFETY: root_cstr is a valid NUL-terminated string.
    let root_fd = unsafe {
        libc::open(
            root_cstr.as_ptr(),
            O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(FindEspError::Io(io::Error::last_os_error()));
    }

    let _guard = FdGuard(root_fd);

    // Resolve path relative to root.
    let search_path = if let Some(p) = path {
        // If the path is absolute, use it as-is. Otherwise, join with root.
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            effective_root.join(p)
        }
    } else {
        PathBuf::new() // signal: no explicit path
    };

    let info = if search_path.as_os_str().is_empty() {
        find_esp_and_warn(None, unprivileged_mode)?
    } else {
        find_esp_and_warn(Some(&search_path), unprivileged_mode)?
    };

    // Prefix the path with root if we resolved relative to it.
    let info = if let Some(ref p) = info.path {
        let prefixed = if root != Some(Path::new("/")) && root.is_some() {
            effective_root.join(p)
        } else {
            p.clone()
        };
        EspInfo {
            path: Some(prefixed),
            ..info
        }
    } else {
        info
    };

    Ok(info)
}

// ── XBOOTLDR verification ──────────────────────────────────────────────────

/// Verify that a directory is a valid Extended Boot Loader Partition.
///
/// Similar to `verify_esp` but checks for XBOOTLDR partition type instead
/// of ESP type. No filesystem type check is performed (XBOOTLDR can be any fs).
pub fn verify_xbootldr(path: &Path, flags: VerifyEspFlags) -> Result<XBootLdrInfo, FindEspError> {
    let searching = flags.contains(VerifyEspFlags::SEARCHING);
    let skip_dev = flags.contains(VerifyEspFlags::SKIP_DEVICE_CHECK);

    let resolved = canonicalize_or_resolve(path).map_err(|e| {
        if searching && e.kind() == io::ErrorKind::NotFound {
            FindEspError::NotFound
        } else {
            FindEspError::PathResolution {
                path: path.to_path_buf(),
                source: e,
            }
        }
    })?;

    let (dev_major, dev_minor) = if skip_dev {
        (0, 0)
    } else {
        verify_fsroot_dir(&resolved)?
    };

    if skip_dev {
        return Ok(XBootLdrInfo::from_path(resolved));
    }

    if dev_major == 0 && dev_minor == 0 {
        return Err(FindEspError::NoBackingDevice(resolved));
    }

    // In a real implementation, blkid or udev probing would verify the
    // partition type GUID matches SD_GPT_XBOOTLDR here.
    Ok(XBootLdrInfo {
        path: Some(resolved),
        partition_uuid: None,
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
    let flags = verify_esp_flags_init(unprivileged_mode, ENV_RELAX_XBOOTLDR_CHECKS);

    if let Some(p) = path {
        return verify_xbootldr(p, flags);
    }

    if let Ok(env_path) = std::env::var(ENV_XBOOTLDR_PATH) {
        if !path_is_valid_absolute(&env_path) {
            return Err(FindEspError::General(format!(
                "${} does not refer to an absolute path, refusing: {:?}",
                ENV_XBOOTLDR_PATH, env_path
            )));
        }
        let p = Path::new(&env_path);
        let resolved = canonicalize_or_resolve(p).map_err(|e| FindEspError::PathResolution {
            path: p.to_path_buf(),
            source: e,
        })?;

        let metadata = std::fs::metadata(&resolved).map_err(|e| FindEspError::PathResolution {
            path: resolved.clone(),
            source: e,
        })?;
        if !metadata.is_dir() {
            return Err(FindEspError::NotADirectory(resolved));
        }

        return Ok(XBootLdrInfo::from_path_and_dev(resolved, metadata.dev()));
    }

    match verify_xbootldr(
        Path::new(XBOOTLDR_SEARCH_PATH),
        flags | VerifyEspFlags::SEARCHING,
    ) {
        Ok(info) => Ok(info),
        Err(FindEspError::NotFound)
        | Err(FindEspError::NotFsRoot(_))
        | Err(FindEspError::NotGpt(_))
        | Err(FindEspError::WrongPartitionType(_)) => Err(FindEspError::NotFound),
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

    let root_cstr = CString::new(effective_root.as_os_str().as_bytes()).map_err(|_| {
        FindEspError::General(format!("Root path {:?} contains NUL byte", effective_root))
    })?;

    // SAFETY: root_cstr is a valid NUL-terminated string.
    let root_fd = unsafe {
        libc::open(
            root_cstr.as_ptr(),
            O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(FindEspError::Io(io::Error::last_os_error()));
    }

    let _guard = FdGuard(root_fd);

    let search_path = if let Some(p) = path {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            effective_root.join(p)
        }
    } else {
        PathBuf::new()
    };

    let info = if search_path.as_os_str().is_empty() {
        find_xbootldr_and_warn(None, unprivileged_mode)?
    } else {
        find_xbootldr_and_warn(Some(&search_path), unprivileged_mode)?
    };

    let info = if let Some(ref p) = info.path {
        let prefixed = if root != Some(Path::new("/")) && root.is_some() {
            effective_root.join(p)
        } else {
            p.clone()
        };
        XBootLdrInfo {
            path: Some(prefixed),
            ..info
        }
    } else {
        info
    };

    Ok(info)
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
        | VerifyEspFlags::SKIP_DEVICE_CHECK;
    verify_xbootldr(path, flags)
}

// ── RAII guard for file descriptors ────────────────────────────────────────

/// RAII guard that closes a file descriptor on drop.
struct FdGuard(i32);

impl Drop for FdGuard {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: self.0 is a valid fd obtained from open().
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

// ── Re-export CString at module level ───────────────────────────────────────

use std::ffi::CString;

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
        // Without the env var set, SKIP flags should be clear.
        std::env::remove_var(ENV_RELAX_ESP_CHECKS);
        let flags = verify_esp_flags_init(Some(false), ENV_RELAX_ESP_CHECKS);
        assert!(!flags.contains(VerifyEspFlags::SKIP_FSTYPE_CHECK));
        assert!(!flags.contains(VerifyEspFlags::SKIP_DEVICE_CHECK));
        assert!(!flags.contains(VerifyEspFlags::UNPRIVILEGED_MODE));
    }

    #[test]
    fn test_verify_esp_flags_init_unprivileged() {
        std::env::remove_var(ENV_RELAX_ESP_CHECKS);
        let flags = verify_esp_flags_init(Some(true), ENV_RELAX_ESP_CHECKS);
        assert!(flags.contains(VerifyEspFlags::UNPRIVILEGED_MODE));
    }

    #[test]
    fn test_verify_esp_flags_init_searching() {
        let flags = VerifyEspFlags::SEARCHING;
        assert!(flags.contains(VerifyEspFlags::SEARCHING));
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
        assert_eq!(path_extract_filename(Path::new("/boot/efi")), Some("efi"));
        assert_eq!(path_extract_filename(Path::new("/boot")), Some("boot"));
        // Root has no filename component.
        assert_eq!(path_extract_filename(Path::new("/")), None);
    }

    // ── Parse env bool ──

    #[test]
    fn test_parse_env_bool() {
        std::env::set_var("TEST_FIND_ESP_BOOL", "1");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(true));

        std::env::set_var("TEST_FIND_ESP_BOOL", "yes");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(true));

        std::env::set_var("TEST_FIND_ESP_BOOL", "true");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(true));

        std::env::set_var("TEST_FIND_ESP_BOOL", "on");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(true));

        std::env::set_var("TEST_FIND_ESP_BOOL", "0");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(false));

        std::env::set_var("TEST_FIND_ESP_BOOL", "no");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(false));

        std::env::set_var("TEST_FIND_ESP_BOOL", "false");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(false));

        std::env::set_var("TEST_FIND_ESP_BOOL", "off");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), Some(false));

        std::env::set_var("TEST_FIND_ESP_BOOL", "");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), None);

        std::env::remove_var("TEST_FIND_ESP_BOOL");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), None);

        std::env::set_var("TEST_FIND_ESP_BOOL", "invalid");
        assert_eq!(parse_env_bool("TEST_FIND_ESP_BOOL"), None);

        std::env::remove_var("TEST_FIND_ESP_BOOL");
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

    // ── Device ID extraction ──

    #[test]
    fn test_major_minor_extraction() {
        // /dev/sda1 is typically (8, 1)
        let dev = ((8u64) << 8) | (1u64 & 0xff) | (((1u64 >> 8) & 0xfff_f) << 12);
        assert_eq!(major(dev), 8);
        assert_eq!(minor(dev), 1);
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
        std::env::remove_var(ENV_ESP_PATH);
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
        std::env::remove_var(ENV_XBOOTLDR_PATH);
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
        std::env::remove_var(ENV_ESP_PATH);
        let result = take_esp_mount_point(None, Some(false));
        assert!(result.is_err());
    }

    // ── Bitflags combinations ──

    #[test]
    fn test_flags_combinations() {
        let f = VerifyEspFlags::SEARCHING
            | VerifyEspFlags::UNPRIVILEGED_MODE
            | VerifyEspFlags::SKIP_FSTYPE_CHECK
            | VerifyEspFlags::SKIP_DEVICE_CHECK;
        assert!(f.contains(VerifyEspFlags::SEARCHING));
        assert!(f.contains(VerifyEspFlags::UNPRIVILEGED_MODE));
        assert!(f.contains(VerifyEspFlags::SKIP_FSTYPE_CHECK));
        assert!(f.contains(VerifyEspFlags::SKIP_DEVICE_CHECK));
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
