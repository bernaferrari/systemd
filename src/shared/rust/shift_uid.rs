// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/shift-uid.c, src/shared/shift-uid.h
//
// UID/GID shifting for container filesystems.
//
// Maps UIDs and GIDs between container and host user namespaces.
// The upper 16 bits of a UID/GID identify the container; the lower
// 16 bits are the identity within the container.  A "shift" value is
// applied by replacing the upper 16 bits: `new_uid = shift | (uid & 0xFFFF)`.
//
// This module provides:
// - Pure computation helpers (`shift_uid`, `shift_gid`, validation)
// - Filesystem compatibility checks
// - The main `shift_uid_shift` entry point for recursive tree patching

use crate::ffi::*;
use std::ffi::CString;
use std::fmt;
use std::fs::{self, File};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

// ── Constants ─────────────────────────────────────────────────────────────

/// While chmod()ing a directory tree, the top-level UID base is set to this
/// "busy" base so that interrupted trees can be recognised and restarted.
pub const UID_BUSY_BASE: u32 = 0xFFFE0000;

/// Mask to extract the upper 16 bits for the busy-base check.
pub const UID_BUSY_MASK: u32 = 0xFFFF0000;

/// Lower 16-bit mask for preserving per-container identity.
const UID_LOWER_MASK: u32 = 0x0000FFFF;

/// Invalid UID sentinel (matches C's `UID_INVALID`).
pub const UID_INVALID: u32 = u32::MAX;

/// Invalid GID sentinel (matches C's `GID_INVALID`).
pub const GID_INVALID: u32 = u32::MAX;

/// The only supported UID range for the patching logic.
pub const UID_RANGE: u32 = 0x10000;

/// Linux filesystem magic numbers that are fully userns-compatible.
/// These filesystems can be mounted inside user namespaces but their
/// inodes relate to host resources, so no UID/GID patching should be applied.

/// binfmt_misc magic
pub const BINFMTFS_MAGIC: u64 = 0x42494E4D;
/// cgroup v1 magic
pub const CGROUP_SUPER_MAGIC: u64 = 0x27E0EB;
/// cgroup v2 magic
pub const CGROUP2_SUPER_MAGIC: u64 = 0x63677270;
/// debugfs magic
pub const DEBUGFS_MAGIC: u64 = 0x64626720;
/// devpts magic
pub const DEVPTS_SUPER_MAGIC: u64 = 0x1CD1;
/// efivarfs magic
pub const EFIVARFS_MAGIC: u64 = 0xDE5E81E4;
/// hugetlbfs magic
pub const HUGETLBFS_MAGIC: u64 = 0x958458F6;
/// mqueue (POSIX message queue) magic
pub const MQUEUE_MAGIC: u64 = 0x19800202;
/// procfs magic
pub const PROC_SUPER_MAGIC: u64 = 0x9FA0;
/// pstore magic
pub const PSTOREFS_MAGIC: u64 = 0x6165676C;
/// SELinux magic
pub const SELINUX_MAGIC: u64 = 0xF97CFF8C;
/// SMACK magic
pub const SMACK_MAGIC: u64 = 0x43415D53;
/// securityfs magic
pub const SECURITYFS_MAGIC: u64 = 0x73636673;
/// BPF filesystem magic
pub const BPF_FS_MAGIC: u64 = 0xCAFE4A11;
/// tracefs magic
pub const TRACEFS_MAGIC: u64 = 0x74726163;
/// sysfs magic
pub const SYSFS_MAGIC: u64 = 0x62656572;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors produced by UID/GID shifting operations.
#[derive(Debug)]
pub enum ShiftUidError {
    /// UID shift is not aligned to a 2^16 boundary.
    ShiftNotAligned { shift: u32 },
    /// UID shift conflicts with the busy base marker.
    ShiftConflictsBusyBase { shift: u32 },
    /// UID range is not the supported value (0x10000).
    UnsupportedRange { range: u32 },
    /// The top-level directory's UID and GID container IDs don't match.
    ContainerIdMismatch {
        uid_container: u32,
        gid_container: u32,
    },
    /// A UID or GID value is invalid after shifting.
    InvalidUidGid,
    /// An I/O error occurred during filesystem operations.
    Io(io::Error),
}

impl fmt::Display for ShiftUidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShiftNotAligned { shift } => {
                write!(f, "UID shift 0x{:08x} is not at a 2^16 boundary", shift)
            }
            Self::ShiftConflictsBusyBase { shift } => {
                write!(f, "UID shift 0x{:08x} conflicts with busy base", shift)
            }
            Self::UnsupportedRange { range } => write!(
                f,
                "UID range 0x{:08x} is not supported, must be 0x10000",
                range
            ),
            Self::ContainerIdMismatch {
                uid_container,
                gid_container,
            } => write!(
                f,
                "UID container ID 0x{:08x} does not match GID container ID 0x{:08x}",
                uid_container, gid_container
            ),
            Self::InvalidUidGid => write!(f, "UID or GID is invalid after shifting"),
            Self::Io(err) => write!(f, "I/O error: {}", err),
        }
    }
}

impl std::error::Error for ShiftUidError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for ShiftUidError {
    fn from(err: io::Error) -> Self {
        ShiftUidError::Io(err)
    }
}

// ── Pure helpers ──────────────────────────────────────────────────────────

/// Check whether a UID value is valid (not the sentinel).
#[inline]
pub const fn uid_is_valid(uid: u32) -> bool {
    uid != UID_INVALID
}

/// Check whether a GID value is valid (not the sentinel).
#[inline]
pub const fn gid_is_valid(gid: u32) -> bool {
    gid != GID_INVALID
}

/// Apply a UID shift: replace the upper 16 bits with `shift`.
///
/// The lower 16 bits of the original UID are preserved.
/// Returns `None` if the result is not a valid UID.
#[inline]
pub fn shift_uid(shift: u32, uid: u32) -> Option<u32> {
    let new = shift | (uid & UID_LOWER_MASK);
    if uid_is_valid(new) { Some(new) } else { None }
}

/// Apply a GID shift: replace the upper 16 bits with `shift`.
///
/// The lower 16 bits of the original GID are preserved.
/// Returns `None` if the result is not a valid GID.
#[inline]
pub fn shift_gid(shift: u32, gid: u32) -> Option<u32> {
    let new = shift | (gid & UID_LOWER_MASK);
    if gid_is_valid(new) { Some(new) } else { None }
}

/// Extract the container ID (upper 16 bits) from a UID.
#[inline]
pub const fn uid_container_id(uid: u32) -> u32 {
    uid >> 16
}

/// Extract the container ID (upper 16 bits) from a GID.
#[inline]
pub const fn gid_container_id(gid: u32) -> u32 {
    gid >> 16
}

/// Check whether a filesystem type is fully user-namespace compatible.
///
/// Returns `true` for virtual/pseudo filesystems whose inodes relate to
/// host resources and should not be patched (procfs, sysfs, cgroupfs, etc.).
pub fn is_fs_fully_userns_compatible(f_type: u64) -> bool {
    matches!(
        f_type,
        BINFMTFS_MAGIC
            | CGROUP_SUPER_MAGIC
            | CGROUP2_SUPER_MAGIC
            | DEBUGFS_MAGIC
            | DEVPTS_SUPER_MAGIC
            | EFIVARFS_MAGIC
            | HUGETLBFS_MAGIC
            | MQUEUE_MAGIC
            | PROC_SUPER_MAGIC
            | PSTOREFS_MAGIC
            | SELINUX_MAGIC
            | SMACK_MAGIC
            | SECURITYFS_MAGIC
            | BPF_FS_MAGIC
            | TRACEFS_MAGIC
            | SYSFS_MAGIC
    )
}

/// Validate shift and range parameters for the patching logic.
///
/// Returns `Ok(())` when:
/// - `shift` is aligned to a 2^16 boundary (lower 16 bits are zero),
/// - `shift` does not conflict with `UID_BUSY_BASE`,
/// - `range` equals `UID_RANGE` (0x10000).
pub fn validate_shift_range(shift: u32, range: u32) -> Result<(), ShiftUidError> {
    if (shift & UID_LOWER_MASK) != 0 {
        return Err(ShiftUidError::ShiftNotAligned { shift });
    }
    if shift == UID_BUSY_BASE {
        return Err(ShiftUidError::ShiftConflictsBusyBase { shift });
    }
    if range != UID_RANGE {
        return Err(ShiftUidError::UnsupportedRange { range });
    }
    Ok(())
}

/// Check if the top-level directory's UID and GID container IDs match.
///
/// Returns the container ID if they match, or an error.
pub fn check_container_ids_match(uid: u32, gid: u32) -> Result<u32, ShiftUidError> {
    let uc = uid_container_id(uid);
    let gc = gid_container_id(gid);
    if uc != gc {
        return Err(ShiftUidError::ContainerIdMismatch {
            uid_container: uc,
            gid_container: gc,
        });
    }
    Ok(uc)
}

/// Quick check: has the tree already been shifted to the target range?
///
/// If the upper 16 bits of `uid` already match `shift`, no patching is needed.
#[inline]
pub fn is_already_shifted(uid: u32, shift: u32) -> bool {
    uid_container_id(uid ^ shift) == 0
}

// ── Filesystem patching ───────────────────────────────────────────────────

fn shifted_ownership(
    meta: &fs::Metadata,
    shift: u32,
) -> Result<Option<(libc::uid_t, libc::gid_t)>, ShiftUidError> {
    let new_uid = shift_uid(shift, meta.uid()).ok_or(ShiftUidError::InvalidUidGid)?;
    let new_gid = shift_gid(shift, meta.gid()).ok_or(ShiftUidError::InvalidUidGid)?;

    if meta.uid() != new_uid || meta.gid() != new_gid {
        Ok(Some((new_uid, new_gid)))
    } else {
        Ok(None)
    }
}

/// Patch an inode that is already pinned by an open file descriptor.
fn patch_fd(file: &File, meta: &fs::Metadata, shift: u32) -> Result<bool, ShiftUidError> {
    let Some((new_uid, new_gid)) = shifted_ownership(meta, shift)? else {
        return Ok(false);
    };
    let fd = file.as_raw_fd();

    // SAFETY: `fd` remains owned by `file` for both calls.
    let ret = unsafe { libc::fchown(fd, new_uid, new_gid) };
    if ret < 0 {
        return Err(ShiftUidError::Io(io::Error::last_os_error()));
    }

    // The Linux kernel may alter the mode in some cases of chown(). Undo that.
    // SAFETY: `fd` is a valid file descriptor.
    let mode = meta.mode() as libc::mode_t;
    let ret = unsafe { libc::fchmod(fd, mode) };
    if ret < 0 {
        return Err(ShiftUidError::Io(io::Error::last_os_error()));
    }

    Ok(true)
}

/// Patch a directory entry without following it if it is a symbolic link.
///
/// In particular, do not open the entry: opening a symlink would operate on
/// its target, and opening a FIFO for reading could block indefinitely.
fn patch_path(path: &Path, meta: &fs::Metadata, shift: u32) -> Result<bool, ShiftUidError> {
    let Some((new_uid, new_gid)) = shifted_ownership(meta, shift)? else {
        return Ok(false);
    };
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        ShiftUidError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains an interior NUL byte",
        ))
    })?;

    // SAFETY: `path` is NUL-terminated and remains live for both syscalls.
    // AT_SYMLINK_NOFOLLOW makes the ownership update apply to the directory
    // entry rather than a symlink target; the optional chmod is skipped for
    // symlinks, which Linux cannot chmod.
    // SAFETY: all pointer and descriptor contracts hold for this operation.
    let chmod_ret = unsafe {
        let ret = libc::fchownat(
            libc::AT_FDCWD,
            path.as_ptr(),
            new_uid,
            new_gid,
            libc::AT_SYMLINK_NOFOLLOW,
        );
        if ret < 0 {
            return Err(ShiftUidError::Io(io::Error::last_os_error()));
        }

        if meta.file_type().is_symlink() {
            None
        } else {
            Some(libc::fchmodat(
                libc::AT_FDCWD,
                path.as_ptr(),
                meta.mode() as libc::mode_t,
                0,
            ))
        }
    };
    if let Some(ret) = chmod_ret {
        if ret < 0 {
            return Err(ShiftUidError::Io(io::Error::last_os_error()));
        }
    }

    Ok(true)
}

/// Open a directory without following a final symlink.
fn open_directory(path: &Path) -> Result<File, ShiftUidError> {
    Ok(fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NOATIME)
        .open(path)?)
}

/// Return whether an otherwise writable-looking filesystem rejects writes
/// through this already-pinned directory descriptor.
///
/// Network filesystems can report no `ST_RDONLY` flag while still returning
/// `EROFS` for access checks. C checks this after `fstatfs()` for every
/// subtree, so preserve that conservative skip rather than descending into a
/// tree that cannot be patched.
fn fd_is_effectively_read_only(fd: i32) -> bool {
    // SAFETY: AT_EMPTY_PATH makes the static empty C string refer to `fd` for
    // this synchronous access check. The call neither retains the descriptor
    // nor writes through the pathname pointer.
    let ret = unsafe { libc::faccessat(fd, c"".as_ptr(), libc::W_OK, libc::AT_EMPTY_PATH) };
    ret < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EROFS)
}

/// Recursively walk a directory tree, patching ownership of every inode.
///
/// Stops recursion at fully userns-compatible filesystems (procfs, sysfs,
/// etc.) and skips read-only subtrees.
///
/// Children are processed first (depth-first), then the directory itself —
/// matching the C `recurse_fd()` semantics so that the top-level directory
/// is patched last and serves as a quick indicator of completion.
fn recurse_dir(
    dir: &Path,
    shift: u32,
    is_toplevel: bool,
    open_file: Option<File>,
    original_meta: Option<&fs::Metadata>,
) -> Result<bool, ShiftUidError> {
    let mut changed = false;
    let dir_file = match open_file {
        Some(file) => file,
        None => open_directory(dir)?,
    };
    let current_meta = dir_file.metadata()?;
    let dir_meta = original_meta.unwrap_or(&current_meta);

    // Check filesystem type to see if we should skip this subtree.
    // SAFETY: `libc::statfs` is an integer-only output struct for which a
    // zeroed temporary is valid. `dir_file` owns a live descriptor and the
    // kernel may write the complete struct through the provided pointer.
    let (ret, statfs_buf) = unsafe {
        let mut statfs_buf: libc::statfs = std::mem::zeroed();
        let ret = libc::fstatfs(dir_file.as_raw_fd(), &mut statfs_buf);
        (ret, statfs_buf)
    };
    if ret < 0 {
        return Err(ShiftUidError::Io(io::Error::last_os_error()));
    }
    if is_fs_fully_userns_compatible(statfs_buf.f_type as u64) {
        return Ok(false);
    }

    // Match the C fast path for mounts that are explicitly read-only.
    if (statfs_buf.f_flags as libc::c_ulong & libc::ST_RDONLY as libc::c_ulong) != 0
        || fd_is_effectively_read_only(dir_file.as_raw_fd())
    {
        return Ok(false);
    }

    // Read directory entries.
    let entries = fs::read_dir(dir)?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        // Skip . and ..
        if name == "." || name == ".." {
            continue;
        }

        let meta = fs::symlink_metadata(&path)?;

        if meta.is_dir() {
            changed |= recurse_dir(&path, shift, false, None, None)?;
        } else {
            changed |= patch_path(&path, &meta, shift)?;
        }
    }

    // Patch the directory itself last (key ordering for crash recovery).
    match patch_fd(&dir_file, dir_meta, shift) {
        Ok(true) => return Ok(true),
        Ok(false) => {}
        Err(ShiftUidError::Io(e)) if e.raw_os_error() == Some(libc::EROFS) && !is_toplevel => {
            // A read-only nested mount is skipped, preserving prior changes.
        }
        Err(e) => return Err(e),
    }

    Ok(changed)
}

// ── Public API ────────────────────────────────────────────────────────────

/// Recursively adjust the UID/GIDs of all files in a directory tree.
///
/// This is the main entry point for automatically fixing up an OS tree to
/// the used user namespace UID range.  The shift must start at a 2^16
/// boundary and the range must be exactly 0x10000 (65536).
///
/// # Arguments
///
/// * `path` - Root directory of the tree to patch
/// * `shift` - Target UID base (upper 16 bits identify the container)
/// * `range` - UID range size; must be `UID_RANGE` (0x10000)
///
/// # Returns
///
/// `Ok(true)` if any changes were made, `Ok(false)` if the tree was already
/// in the correct state, or an error.
///
/// # Errors
///
/// Returns `ShiftUidError` for invalid parameters, container ID mismatches,
/// or I/O failures.
pub fn shift_uid_shift(path: &Path, shift: u32, range: u32) -> Result<bool, ShiftUidError> {
    validate_shift_range(shift, range)?;

    // Keep the top-level directory pinned throughout the operation, matching
    // the C implementation's O_DIRECTORY|O_NOFOLLOW open.
    let file = open_directory(path)?;
    let meta = file.metadata()?;

    // We only support containers where the UID/GID container IDs match.
    check_container_ids_match(meta.uid(), meta.gid())?;

    // Quick check: if the top-level dir already has the right upper 16 bits,
    // assume the whole tree is correct (optimisation from the C implementation).
    if is_already_shifted(meta.uid(), shift) {
        return Ok(false);
    }

    // Before starting recursive chowning, mark the top-level dir as "busy"
    // by setting its upper 16 bits to UID_BUSY_BASE.  If we are interrupted,
    // the busy marker signals that the tree needs re-patching.
    if (meta.uid() & UID_BUSY_MASK) != UID_BUSY_BASE {
        let busy_uid = UID_BUSY_BASE | (meta.uid() & !UID_BUSY_MASK);
        let busy_gid = UID_BUSY_BASE | (meta.gid() & !UID_BUSY_MASK);

        let fd = file.as_raw_fd();
        // SAFETY: `file` owns `fd` and remains live through recursion.
        let ret = unsafe { libc::fchown(fd, busy_uid, busy_gid) };
        if ret < 0 {
            // Non-fatal: we still proceed even if marking fails.
            let _ = io::Error::last_os_error();
        }
    }

    // Use the metadata captured before applying the busy marker so that the
    // final fchmod restores any set-ID bits that the marker chown cleared.
    recurse_dir(path, shift, true, Some(file), Some(&meta))
}

/// Convenience wrapper around [`shift_uid_shift`] that accepts a string path.
///
/// See [`shift_uid_shift`] for full documentation.
pub fn shift_uid_convert_path(path: &str, shift: u32, range: u32) -> Result<bool, ShiftUidError> {
    shift_uid_shift(Path::new(path), shift, range)
}

/// Returns the standard UID range (0x10000) supported by the shifting logic.
///
/// The patching algorithm only supports 16-bit UID ranges where the lower
/// 16 bits encode the identity within the container.
#[inline]
pub const fn shift_uid_range() -> u32 {
    UID_RANGE
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uid_is_valid() {
        assert!(uid_is_valid(0));
        assert!(uid_is_valid(1000));
        assert!(uid_is_valid(u32::MAX - 1));
        assert!(!uid_is_valid(UID_INVALID));
        assert!(!uid_is_valid(u32::MAX));
    }

    #[test]
    fn test_gid_is_valid() {
        assert!(gid_is_valid(0));
        assert!(gid_is_valid(100));
        assert!(!gid_is_valid(GID_INVALID));
    }

    #[test]
    fn test_shift_uid_basic() {
        // shift = 0x10000_0000 → container base at 0x10000
        // uid 0x0000_0064 (100) → 0x0001_0064
        assert_eq!(shift_uid(0x00010000, 100), Some(0x00010064));
    }

    #[test]
    fn test_shift_uid_preserves_lower_bits() {
        // Lower 16 bits must be preserved exactly.
        let uid = 0x12345678;
        let shift = 0xABCD0000;
        let result = shift_uid(shift, uid).unwrap();
        assert_eq!(result & UID_LOWER_MASK, uid & UID_LOWER_MASK);
        assert_eq!(result >> 16, 0xABCD);
    }

    #[test]
    fn test_shift_gid_basic() {
        assert_eq!(shift_gid(0x00020000, 50), Some(0x00020032));
    }

    #[test]
    fn test_shift_to_invalid_uid() {
        // Shifting should never produce UID_INVALID.
        let shift = (UID_INVALID & UID_BUSY_MASK) | 0;
        let uid = UID_INVALID & UID_LOWER_MASK;
        // If shift | uid_lower == UID_INVALID, we should get None.
        if (shift | uid) == UID_INVALID {
            assert_eq!(shift_uid(shift, uid), None);
        }
    }

    #[test]
    fn test_uid_container_id() {
        assert_eq!(uid_container_id(0x00010000), 1);
        assert_eq!(uid_container_id(0xABCD1234), 0xABCD);
        assert_eq!(uid_container_id(0x0000FFFF), 0);
        assert_eq!(uid_container_id(0xFFFF0000), 0xFFFF);
    }

    #[test]
    fn test_gid_container_id() {
        assert_eq!(gid_container_id(0x00020000), 2);
        assert_eq!(gid_container_id(0x00000000), 0);
    }

    #[test]
    fn test_validate_shift_range_ok() {
        assert!(validate_shift_range(0x00010000, UID_RANGE).is_ok());
        assert!(validate_shift_range(0x00000000, UID_RANGE).is_ok());
        assert!(validate_shift_range(0xFFFF0000, UID_RANGE).is_ok());
    }

    #[test]
    fn test_validate_shift_range_not_aligned() {
        let err = validate_shift_range(0x00010001, UID_RANGE).unwrap_err();
        assert!(matches!(
            err,
            ShiftUidError::ShiftNotAligned { shift: 0x00010001 }
        ));
    }

    #[test]
    fn test_validate_shift_range_busy_conflict() {
        let err = validate_shift_range(UID_BUSY_BASE, UID_RANGE).unwrap_err();
        assert!(matches!(err, ShiftUidError::ShiftConflictsBusyBase { .. }));
    }

    #[test]
    fn test_validate_shift_range_unsupported_range() {
        let err = validate_shift_range(0x00010000, 0x1000).unwrap_err();
        assert!(matches!(
            err,
            ShiftUidError::UnsupportedRange { range: 0x1000 }
        ));
    }

    #[test]
    fn test_check_container_ids_match_ok() {
        // uid = 0x00010000, gid = 0x00010005 → both container 1
        assert_eq!(
            check_container_ids_match(0x00010000, 0x00010005).unwrap(),
            1
        );
    }

    #[test]
    fn test_check_container_ids_match_mismatch() {
        let err = check_container_ids_match(0x00010000, 0x00020000).unwrap_err();
        assert!(matches!(
            err,
            ShiftUidError::ContainerIdMismatch {
                uid_container: 1,
                gid_container: 2
            }
        ));
    }

    #[test]
    fn test_is_already_shifted() {
        assert!(is_already_shifted(0x00010000, 0x00010000));
        assert!(is_already_shifted(0x00010064, 0x00010000));
        assert!(!is_already_shifted(0x00010000, 0x00020000));
        assert!(!is_already_shifted(0x00000000, 0x00010000));
    }

    #[test]
    fn test_is_fs_fully_userns_compatible_known() {
        assert!(is_fs_fully_userns_compatible(PROC_SUPER_MAGIC));
        assert!(is_fs_fully_userns_compatible(SYSFS_MAGIC));
        assert!(is_fs_fully_userns_compatible(CGROUP_SUPER_MAGIC));
        assert!(is_fs_fully_userns_compatible(CGROUP2_SUPER_MAGIC));
        assert!(is_fs_fully_userns_compatible(DEBUGFS_MAGIC));
        assert!(is_fs_fully_userns_compatible(DEVPTS_SUPER_MAGIC));
        assert!(is_fs_fully_userns_compatible(TRACEFS_MAGIC));
        assert!(is_fs_fully_userns_compatible(BPF_FS_MAGIC));
    }

    #[test]
    fn test_is_fs_fully_userns_compatible_unknown() {
        // ext4 magic (0xEF53) should NOT be userns-compatible.
        assert!(!is_fs_fully_userns_compatible(0xEF53));
        // xfs magic (0x58465342) should NOT be userns-compatible.
        assert!(!is_fs_fully_userns_compatible(0x58465342));
        // tmpfs magic (0x01021994) should NOT be userns-compatible.
        assert!(!is_fs_fully_userns_compatible(0x01021994));
    }

    #[test]
    fn test_shift_uid_range_constant() {
        assert_eq!(shift_uid_range(), 0x10000);
    }

    #[test]
    fn test_constants_are_correct() {
        assert_eq!(UID_BUSY_BASE, 0xFFFE0000);
        assert_eq!(UID_BUSY_MASK, 0xFFFF0000);
        assert_eq!(UID_LOWER_MASK, 0x0000FFFF);
        assert_eq!(UID_RANGE, 0x10000);
        assert_eq!(UID_INVALID, u32::MAX);
        assert_eq!(GID_INVALID, u32::MAX);
    }

    #[test]
    fn test_shift_uid_zero_shift() {
        // shift = 0 means "map to host namespace" (no upper bits).
        assert_eq!(shift_uid(0, 0x0000FFFF), Some(0x0000FFFF));
        assert_eq!(shift_uid(0, 0x12340005), Some(0x00000005));
    }

    #[test]
    fn test_shift_uid_roundtrip_preserves_identity() {
        // The lower 16 bits encode the identity within the container.
        let identity = 42u32;
        for shift_base in [0u32, 0x10000, 0xABCD0000] {
            let shifted = shift_uid(shift_base, identity).unwrap();
            assert_eq!(shifted & UID_LOWER_MASK, identity);
        }
    }

    #[test]
    fn test_error_display_messages() {
        let err = ShiftUidError::ShiftNotAligned { shift: 0x10001 };
        assert!(err.to_string().contains("not at a 2^16 boundary"));

        let err = ShiftUidError::UnsupportedRange { range: 0x20000 };
        assert!(err.to_string().contains("0x10000"));

        let err = ShiftUidError::ContainerIdMismatch {
            uid_container: 1,
            gid_container: 2,
        };
        assert!(err.to_string().contains("does not match"));
    }
}
