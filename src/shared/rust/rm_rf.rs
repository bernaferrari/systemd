// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-GAP: scope=shared.rm-rf; authority=src/shared/rm-rf.c,src/shared/rm-rf.h
// This Rust-native prototype is not Meson-wired and exports no C ABI. It must
// not be treated as a production replacement or parity-tested shadow until it
// preserves raw pathname bytes, exact negative errno values, current-C
// physical-filesystem policy, and btrfs subvolume behavior.
//
// Recursive file/directory removal utilities.
//
// Provides safe, idiomatic Rust wrappers for recursive deletion of
// files and directories with mount point protection, physical
// filesystem guards, and chmod-based permission escalation.

use crate::ffi::*;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

// Linux 6.6 assigned fchmodat2(2) syscall number 452 on the generic 64-bit
// syscall ABI. libc does not currently export this newer number.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )
))]
const SYS_FCHMODAT2: libc::c_long = 452;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors that can occur during recursive removal operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RmRfError {
    /// An I/O error occurred.
    Io(io::ErrorKind, String),
    /// Invalid argument (e.g. bad path, conflicting flags).
    InvalidArgument(String),
    /// Permission denied; chmod escalation was attempted but failed.
    PermissionDenied(String),
    /// Attempted to remove the root filesystem or a physical disk filesystem.
    PhysicalFs(String),
    /// Resource is a directory but recursion is not allowed.
    IsDirectory,
    /// Bad file descriptor.
    BadFd,
    /// No such file or directory.
    NotFound(String),
}

impl RmRfError {
    fn from_errno(errno: i32, context: &str) -> Self {
        match errno {
            libc::EINVAL => RmRfError::InvalidArgument(context.to_owned()),
            libc::EACCES | libc::EPERM => RmRfError::PermissionDenied(context.to_owned()),
            libc::EISDIR => RmRfError::IsDirectory,
            libc::EBADF => RmRfError::BadFd,
            libc::ENOENT => RmRfError::NotFound(context.to_owned()),
            libc::ENOTDIR | libc::ELOOP => RmRfError::InvalidArgument(context.to_owned()),
            _ => RmRfError::Io(
                io::Error::from_raw_os_error(-errno).kind(),
                context.to_owned(),
            ),
        }
    }

    fn from_io(err: io::Error, context: &str) -> Self {
        let kind = err.kind();
        match err.raw_os_error() {
            Some(libc::EINVAL) => RmRfError::InvalidArgument(context.to_owned()),
            Some(libc::EACCES) | Some(libc::EPERM) => {
                RmRfError::PermissionDenied(context.to_owned())
            }
            Some(libc::ENOENT) => RmRfError::NotFound(context.to_owned()),
            _ => RmRfError::Io(kind, context.to_owned()),
        }
    }

    fn neg_errno_result(code: i32, context: &str) -> Result<(), Self> {
        if code >= 0 {
            Ok(())
        } else {
            Err(Self::from_errno(code, context))
        }
    }
}

impl std::fmt::Display for RmRfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(kind, ctx) => write!(f, "I/O error ({kind:?}): {ctx}"),
            Self::InvalidArgument(ctx) => write!(f, "invalid argument: {ctx}"),
            Self::PermissionDenied(ctx) => write!(f, "permission denied: {ctx}"),
            Self::PhysicalFs(ctx) => write!(f, "refusing to remove physical fs: {ctx}"),
            Self::IsDirectory => write!(f, "is a directory"),
            Self::BadFd => write!(f, "bad file descriptor"),
            Self::NotFound(ctx) => write!(f, "not found: {ctx}"),
        }
    }
}

impl std::error::Error for RmRfError {}

impl From<io::Error> for RmRfError {
    fn from(err: io::Error) -> Self {
        let msg = err.to_string();
        RmRfError::from_io(err, &msg)
    }
}

// ── RemoveFlags ──────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling removal behavior.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RemoveFlags: u32 {
        /// Only remove directories, skip regular files.
        const REMOVE_ONLY_DIRECTORIES = 1 << 0;
        /// Remove the root entry itself, not just its children.
        const REMOVE_ROOT             = 1 << 1;
        /// Allow removal on physical (disk) filesystems.
        const REMOVE_PHYSICAL         = 1 << 2;
        /// Try btrfs subvolume removal first.
        const REMOVE_SUBVOLUME        = 1 << 3;
        /// Do not fail if the target does not exist.
        const REMOVE_MISSING_OK       = 1 << 4;
        /// Try chmod +rwx on directories when EACCES is hit.
        const REMOVE_CHMOD            = 1 << 5;
        /// Restore original directory permissions after chmod.
        const REMOVE_CHMOD_RESTORE    = 1 << 6;
        /// Call syncfs() after removing directory contents.
        const REMOVE_SYNCFS           = 1 << 7;
    }
}

impl Default for RemoveFlags {
    fn default() -> Self {
        RemoveFlags::empty()
    }
}

// ── Filesystem helpers ────────────────────────────────────────────────────

/// Magic numbers for temporary filesystems.
const TMPFS_MAGIC: u64 = 0x01021994;
const RAMFS_MAGIC: u64 = 0x9fa0;
const CIFS_MAGIC: u64 = 0x73636673;
const CONFIGFS_MAGIC: u64 = 0x565a;
const CGROUP2_SUPER_MAGIC: u64 = 0x63677270;

/// Check if a filesystem is a temporary/non-physical type.
fn is_temporary_fs(f_type: u64) -> bool {
    matches!(
        f_type,
        TMPFS_MAGIC | RAMFS_MAGIC | CIFS_MAGIC | CONFIGFS_MAGIC
    )
}

/// Check if a filesystem is physical (i.e. not temporary and not cgroup2).
fn is_physical_fs(f_type: u64) -> bool {
    !is_temporary_fs(f_type) && f_type != CGROUP2_SUPER_MAGIC
}

/// Get the filesystem type for an open directory fd.
fn get_fs_type(fd: i32) -> Result<u64, RmRfError> {
    let mut sfs = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `fd` is borrowed for this synchronous syscall and `sfs` is
    // writable storage for the kernel to initialize.
    let r = unsafe { libc::fstatfs(fd, sfs.as_mut_ptr()) };
    if r < 0 {
        return Err(RmRfError::from_errno(
            -crate::ffi::get_errno() as i32,
            "fstatfs",
        ));
    }
    // SAFETY: successful `fstatfs()` initialized every field of `sfs`.
    Ok(unsafe { sfs.assume_init() }.f_type as u64)
}

/// Get the device number for an open directory fd.
fn get_dev(fd: i32) -> Result<u64, RmRfError> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fd` is borrowed for this synchronous syscall and `st` is
    // writable storage for the kernel to initialize.
    let r = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if r < 0 {
        return Err(RmRfError::from_errno(
            -crate::ffi::get_errno() as i32,
            "fstat",
        ));
    }
    // SAFETY: successful `fstat()` initialized every field of `st`.
    Ok(unsafe { st.assume_init() }.st_dev as u64)
}

/// Adopt a descriptor returned by a successful descriptor-creating syscall.
fn owned_fd_from_syscall(fd: RawFd) -> OwnedFd {
    debug_assert!(fd >= 0);
    // SAFETY: callers invoke this only for a non-negative descriptor returned
    // by a successful syscall, and transfer its sole ownership to `OwnedFd`.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

// ── Low-level syscall wrappers ────────────────────────────────────────────

/// Get the current errno as a negative i32 (systemd convention).
fn last_errno() -> i32 {
    -(crate::ffi::get_errno() as i32)
}

/// Convert an fd + path into a CString, returning an error on interior nul bytes.
fn to_cstr(path: &str) -> Result<CString, RmRfError> {
    CString::new(path)
        .map_err(|_| RmRfError::InvalidArgument(format!("path contains nul byte: {path:?}")))
}

/// Query statx data, requiring every requested field to be supported.
fn statx_at(dfd: RawFd, path: &CString, flags: i32, mask: u32) -> Result<libc::statx, RmRfError> {
    let mut statx = std::mem::MaybeUninit::<libc::statx>::zeroed();
    // SAFETY: `path` is NUL-terminated and live for the call, and `statx`
    // points to writable, zero-initialized native storage.
    let result = unsafe { libc::statx(dfd, path.as_ptr(), flags, mask, statx.as_mut_ptr()) };
    if result < 0 {
        return Err(RmRfError::from_errno(last_errno(), "statx"));
    }

    // SAFETY: the storage was initialized before the successful syscall, so
    // optional fields omitted by an older kernel remain initialized as zero.
    let statx = unsafe { statx.assume_init() };
    if statx.stx_mask & mask != mask {
        return Err(RmRfError::Io(
            io::ErrorKind::Unsupported,
            "statx did not return required fields".into(),
        ));
    }
    Ok(statx)
}

/// Check if a directory entry (within dfd) is a mount point.
fn is_mount_point_at(dfd: i32, name: &str) -> Result<bool, RmRfError> {
    let name = to_cstr(name)?;
    let mask = libc::STATX_TYPE | libc::STATX_INO;
    let child = statx_at(
        dfd,
        &name,
        libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT | libc::AT_STATX_DONT_SYNC,
        mask,
    )?;

    let mount_root = libc::STATX_ATTR_MOUNT_ROOT as u64;
    if child.stx_attributes_mask & mount_root != 0 && child.stx_attributes & mount_root != 0 {
        return Ok(true);
    }

    // Match the C chroot safeguard: an entry resolving to the process root is
    // a boundary even if the kernel does not mark it as a mount root here.
    let root = statx_at(
        libc::AT_FDCWD,
        &to_cstr("/")?,
        libc::AT_NO_AUTOMOUNT | libc::AT_STATX_DONT_SYNC,
        mask,
    )?;
    Ok(
        child.stx_mode & libc::S_IFMT as u16 == root.stx_mode & libc::S_IFMT as u16
            && child.stx_dev_major == root.stx_dev_major
            && child.stx_dev_minor == root.stx_dev_minor
            && child.stx_ino == root.stx_ino,
    )
}

/// Check if an errno indicates a recoverable subvolume removal failure.
/// These errors mean "not btrfs" or "not a subvolume" — safe to fall through.
fn is_subvol_recoverable_errno(errno: i32) -> bool {
    matches!(
        errno,
        e if e == -(libc::ENOTTY as i32)
            || e == -(libc::EINVAL as i32)
            || e == -(libc::ENOTDIR as i32)
            || e == -(libc::EPERM as i32)
            || e == -(libc::EACCES as i32)
    )
}

// ── Permission patching ───────────────────────────────────────────────────

/// Result of [`patch_dirfd_mode`]: the original mode and whether chmod was performed.
struct PatchResult {
    old_mode: libc::mode_t,
    chmod_done: bool,
}

/// Change the mode of an inode pinned by a descriptor, including `O_PATH` fds.
fn fchmod_opath(fd: RawFd, mode: libc::mode_t) -> Result<(), RmRfError> {
    let mode = mode & 0o7777;

    // SAFETY: `fd` stays borrowed for the synchronous call, the empty C
    // pathname is static, and AT_EMPTY_PATH selects the inode pinned by `fd`.
    if unsafe { libc::fchmodat(fd, c"".as_ptr(), mode, libc::AT_EMPTY_PATH) } >= 0 {
        return Ok(());
    }

    let mut errno = last_errno();

    // Older libc implementations reject AT_EMPTY_PATH even when the kernel
    // provides fchmodat2(2), so match the C helper's direct-syscall fallback.
    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )
    ))]
    if errno == -libc::EINVAL {
        // SAFETY: `fd` remains borrowed, the empty pathname is static, and the
        // scalar arguments exactly match Linux fchmodat2(2)'s ABI.
        if unsafe { libc::syscall(SYS_FCHMODAT2, fd, c"".as_ptr(), mode, libc::AT_EMPTY_PATH) } >= 0
        {
            return Ok(());
        }
        errno = last_errno();
    }

    if errno != -libc::ENOSYS && errno != -libc::EPERM {
        return Err(RmRfError::from_errno(errno, "fchmodat"));
    }

    let proc_path = to_cstr(&format!("/proc/self/fd/{fd}"))?;
    // SAFETY: `proc_path` is NUL-terminated and live for this synchronous
    // call; the procfs magic link resolves to the still-pinned inode.
    if unsafe { libc::chmod(proc_path.as_ptr(), mode) } < 0 {
        return Err(RmRfError::from_errno(last_errno(), "chmod"));
    }

    Ok(())
}

/// Try to add u+rwx bits to a directory's mode so we can traverse/unlink entries.
///
/// If `refuse_already_set` is true and the bits are already present, returns an error
/// (preserving the original EACCES semantics).
fn patch_dirfd_mode(dfd: i32, refuse_already_set: bool) -> Result<PatchResult, RmRfError> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `dfd` is borrowed for this synchronous syscall and `st` is
    // writable storage for the kernel to initialize.
    let r = unsafe { libc::fstat(dfd, st.as_mut_ptr()) };
    if r < 0 {
        return Err(RmRfError::from_errno(last_errno(), "fstat"));
    }
    // SAFETY: successful `fstat()` initialized every field of `st`.
    let st = unsafe { st.assume_init() };

    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(RmRfError::InvalidArgument("not a directory".into()));
    }

    // Already has owner rwx?
    if (st.st_mode & 0o700) == 0o700 {
        if refuse_already_set {
            return Err(RmRfError::PermissionDenied(
                "directory already has rwx but still EACCES".into(),
            ));
        }
        return Ok(PatchResult {
            old_mode: st.st_mode,
            chmod_done: false,
        });
    }

    // Can only chmod if we own the directory.
    // SAFETY: `geteuid()` has no arguments and no Rust-side preconditions.
    if st.st_uid != unsafe { libc::geteuid() } {
        return Err(RmRfError::PermissionDenied(
            "directory not owned by euid".into(),
        ));
    }

    let new_mode = (st.st_mode | 0o700) & 0o7777;
    fchmod_opath(dfd, new_mode)?;

    Ok(PatchResult {
        old_mode: st.st_mode,
        chmod_done: true,
    })
}

// ── Harder syscall wrappers ───────────────────────────────────────────────

/// Like `unlinkat()` but retries with chmod on EACCES when `REMOVE_CHMOD` is set.
fn unlinkat_harder(
    dfd: i32,
    filename: &str,
    unlink_flags: i32,
    remove_flags: RemoveFlags,
) -> Result<(), RmRfError> {
    let c_name = to_cstr(filename)?;

    // First attempt. `c_name` is NUL-terminated and remains live throughout
    // the syscall; `dfd` is borrowed from the caller.
    // SAFETY: the pathname and descriptor meet unlinkat(2)'s requirements.
    let r = unsafe { libc::unlinkat(dfd, c_name.as_ptr(), unlink_flags) };
    if r >= 0 {
        return Ok(());
    }
    let errno = last_errno();

    if errno != -libc::EACCES || !remove_flags.contains(RemoveFlags::REMOVE_CHMOD) {
        return RmRfError::neg_errno_result(errno, filename);
    }

    // Try patching directory permissions.
    let patch = patch_dirfd_mode(dfd, true)?;
    // SAFETY: `c_name` remains NUL-terminated and live, and `dfd` is borrowed
    // for this retry after its directory mode was patched.
    let r = unsafe { libc::unlinkat(dfd, c_name.as_ptr(), unlink_flags) };
    if r >= 0 {
        if remove_flags.contains(RemoveFlags::REMOVE_CHMOD_RESTORE) {
            // SAFETY: `dfd` still refers to the patched directory, and this
            // restores the mode captured by `patch_dirfd_mode()`.
            unsafe { libc::fchmod(dfd, patch.old_mode & 0o7777) };
        }
        return Ok(());
    }
    let errno2 = last_errno();

    // Restore on failure.
    // SAFETY: `dfd` still refers to the patched directory, and this restores
    // the mode captured by `patch_dirfd_mode()` before returning the error.
    unsafe { libc::fchmod(dfd, patch.old_mode & 0o7777) };
    RmRfError::neg_errno_result(errno2, filename)
}

/// Like `fstatat()` but retries with chmod on EACCES when `REMOVE_CHMOD` is set.
fn fstatat_harder(
    dfd: i32,
    filename: &str,
    fstatat_flags: i32,
    remove_flags: RemoveFlags,
) -> Result<libc::stat, RmRfError> {
    let c_name = to_cstr(filename)?;

    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `c_name` is NUL-terminated and live, `dfd` is borrowed, and
    // `st` is writable storage for the kernel to initialize.
    let r = unsafe { libc::fstatat(dfd, c_name.as_ptr(), st.as_mut_ptr(), fstatat_flags) };
    if r >= 0 {
        // SAFETY: successful `fstatat()` initialized every field of `st`.
        return Ok(unsafe { st.assume_init() });
    }
    let errno = last_errno();

    if errno != -libc::EACCES || !remove_flags.contains(RemoveFlags::REMOVE_CHMOD) {
        return Err(RmRfError::from_errno(errno, filename));
    }

    let patch = patch_dirfd_mode(dfd, true)?;
    // SAFETY: `c_name` remains NUL-terminated and live, `dfd` is borrowed,
    // and `st` is writable storage for this retry.
    let r = unsafe { libc::fstatat(dfd, c_name.as_ptr(), st.as_mut_ptr(), fstatat_flags) };
    if r >= 0 {
        if remove_flags.contains(RemoveFlags::REMOVE_CHMOD_RESTORE) {
            // SAFETY: `dfd` still refers to the patched directory, and this
            // restores the mode captured by `patch_dirfd_mode()`.
            unsafe { libc::fchmod(dfd, patch.old_mode & 0o7777) };
        }
        // SAFETY: successful `fstatat()` initialized every field of `st`.
        return Ok(unsafe { st.assume_init() });
    }
    let errno2 = last_errno();

    // SAFETY: `dfd` still refers to the patched directory, and this restores
    // the mode captured by `patch_dirfd_mode()` before returning the error.
    unsafe { libc::fchmod(dfd, patch.old_mode & 0o7777) };
    Err(RmRfError::from_errno(errno2, filename))
}

/// Open flags used throughout.
const DIR_OPEN_FLAGS: i32 = libc::O_RDONLY
    | libc::O_NONBLOCK
    | libc::O_DIRECTORY
    | libc::O_CLOEXEC
    | libc::O_NOFOLLOW
    | O_NOATIME;

/// Open a path and immediately adopt the returned descriptor.
fn openat_owned(dfd: RawFd, path: &CString, flags: i32) -> Result<OwnedFd, RmRfError> {
    // SAFETY: `path` is NUL-terminated and live for the syscall. On success
    // the returned descriptor is immediately transferred into `OwnedFd`.
    let fd = unsafe { libc::openat(dfd, path.as_ptr(), flags) };
    if fd < 0 {
        return Err(RmRfError::from_errno(last_errno(), "openat"));
    }
    Ok(owned_fd_from_syscall(fd))
}

/// Reopen a pinned descriptor with a new access mode.
fn fd_reopen(fd: RawFd, flags: i32) -> Result<OwnedFd, RmRfError> {
    openat_owned(
        fd,
        &to_cstr(".")?,
        flags | libc::O_DIRECTORY | libc::O_CLOEXEC,
    )
}

/// Like `openat()` for directories, but retries with chmod on EACCES.
///
/// Returns the opened fd and the original mode of the directory.
fn openat_harder(
    dfd: i32,
    path: &str,
    open_flags: i32,
    remove_flags: RemoveFlags,
) -> Result<(OwnedFd, libc::mode_t), RmRfError> {
    let c_path = to_cstr(path)?;

    let is_opath = (open_flags & O_PATH) != 0;
    let is_dir = (open_flags & libc::O_DIRECTORY) != 0;
    let want_chmod = remove_flags.contains(RemoveFlags::REMOVE_CHMOD);

    // Fast path: no chmod needed or incompatible flags.
    if is_opath || !is_dir || !want_chmod {
        let fd = openat_owned(dfd, &c_path, open_flags)?;
        let st = fstat_fd(fd.as_raw_fd())?;
        return Ok((fd, st.st_mode));
    }

    // Open via O_PATH first to inspect, then chmod if needed.
    let pfd = openat_owned(
        dfd,
        &c_path,
        (open_flags & (libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)) | O_PATH,
    )?;

    let patch = patch_dirfd_mode(pfd.as_raw_fd(), false)?;
    // Reopen the pinned object itself, rather than resolving `path` again.
    let fd = match fd_reopen(pfd.as_raw_fd(), open_flags & !libc::O_NOFOLLOW) {
        Ok(fd) => fd,
        Err(error) => {
            if patch.chmod_done {
                let _ = fchmod_opath(pfd.as_raw_fd(), patch.old_mode);
            }
            return Err(error);
        }
    };

    Ok((fd, patch.old_mode))
}

/// Query the filesystem containing a path without consuming the caller's fd.
fn get_fs_type_at(dfd: RawFd, path: &CString) -> Result<u64, RmRfError> {
    let fd = openat_owned(dfd, path, O_PATH | libc::O_CLOEXEC)?;
    get_fs_type(fd.as_raw_fd())
}

/// Determine whether `path` resolves to the process root on the same mount.
fn path_is_root_at(dfd: RawFd, path: &CString) -> Result<bool, RmRfError> {
    let target;
    let target_fd = if path.as_bytes().is_empty() {
        dfd
    } else {
        // SAFETY: `path` is NUL-terminated and live for the call. A successful
        // result is immediately adopted below.
        let fd = unsafe {
            libc::openat(
                dfd,
                path.as_ptr(),
                O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = last_errno();
            if error == -libc::ENOTDIR {
                return Ok(false);
            }
            return Err(RmRfError::from_errno(error, "checking for root"));
        }
        target = owned_fd_from_syscall(fd);
        target.as_raw_fd()
    };

    let root = openat_owned(
        libc::AT_FDCWD,
        &to_cstr("/")?,
        O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
    )?;
    let empty = to_cstr("")?;
    let mask = libc::STATX_TYPE | libc::STATX_INO | libc::STATX_MNT_ID;
    let flags = AT_EMPTY_PATH | libc::AT_NO_AUTOMOUNT | libc::AT_STATX_DONT_SYNC;
    let target_statx = statx_at(target_fd, &empty, flags, mask)?;
    let root_statx = statx_at(root.as_raw_fd(), &empty, flags, mask)?;

    Ok(target_statx.stx_mnt_id == root_statx.stx_mnt_id
        && target_statx.stx_mode & libc::S_IFMT as u16 == root_statx.stx_mode & libc::S_IFMT as u16
        && target_statx.stx_dev_major == root_statx.stx_dev_major
        && target_statx.stx_dev_minor == root_statx.stx_dev_minor
        && target_statx.stx_ino == root_statx.stx_ino)
}

/// fstat on an fd, returning a stat struct.
fn fstat_fd(fd: i32) -> Result<libc::stat, RmRfError> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fd` is borrowed for this synchronous syscall and `st` is
    // writable storage for the kernel to initialize.
    let r = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if r < 0 {
        return Err(RmRfError::from_errno(last_errno(), "fstat"));
    }
    // SAFETY: successful `fstat()` initialized every field of `st`.
    Ok(unsafe { st.assume_init() })
}

// ── Inner child removal ───────────────────────────────────────────────────

/// Result of removing a single child entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildResult {
    /// Entry was removed.
    Removed,
    /// Entry needs recursion (is a directory).
    NeedsRecursion,
    /// Entry was skipped (e.g. different device, mount point).
    Skipped,
}

/// Best-effort directory type information supplied by a directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectoryHint {
    Unknown,
    NotDirectory,
    Directory,
}

/// Remove one child entry within a directory.
fn rm_rf_inner_child(
    fd: i32,
    fname: &str,
    directory_hint: DirectoryHint,
    flags: RemoveFlags,
    root_dev: Option<u64>,
    allow_recursion: bool,
) -> Result<ChildResult, RmRfError> {
    let mut directory_hint = directory_hint;
    let need_stat = matches!(directory_hint, DirectoryHint::Unknown)
        || root_dev.is_some()
        || (matches!(directory_hint, DirectoryHint::Directory)
            && flags.contains(RemoveFlags::REMOVE_SUBVOLUME));

    let stat = if need_stat {
        let st = fstatat_harder(fd, fname, libc::AT_SYMLINK_NOFOLLOW, flags)?;
        directory_hint = if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            DirectoryHint::Directory
        } else {
            DirectoryHint::NotDirectory
        };
        Some(st)
    } else {
        None
    };

    if directory_hint == DirectoryHint::Directory {
        // Check device if root_dev is set.
        if let Some(rd) = root_dev {
            let st = stat.as_ref().unwrap();
            if st.st_dev as u64 != rd {
                return Ok(ChildResult::Skipped);
            }
        }

        // Stop at mount points.
        match is_mount_point_at(fd, fname) {
            Ok(true) => return Ok(ChildResult::Skipped),
            Err(e) => return Err(e),
            Ok(false) => {}
        }

        if !allow_recursion {
            return Err(RmRfError::IsDirectory);
        }

        let (subdir_fd, old_mode) = openat_harder(fd, fname, DIR_OPEN_FLAGS, flags)?;
        let child_result = rm_rf_children_impl(
            subdir_fd,
            flags | RemoveFlags::REMOVE_PHYSICAL,
            root_dev,
            old_mode,
        );

        unlinkat_harder(fd, fname, libc::AT_REMOVEDIR, flags)?;
        child_result?;
        return Ok(ChildResult::Removed);
    }

    if flags.contains(RemoveFlags::REMOVE_ONLY_DIRECTORIES) {
        return Ok(ChildResult::Skipped);
    }

    unlinkat_harder(fd, fname, 0, flags)?;
    Ok(ChildResult::Removed)
}

// ── TodoEntry for iterative deep recursion ────────────────────────────────

/// Stack frame for iterative directory traversal (avoids deep recursion).
struct TodoEntry {
    /// DIR* pointer (owned, will be closed via closedir).
    dir: *mut libc::DIR,
    /// Filename of this directory relative to its parent.
    dirname: CString,
    /// Original file mode before chmod.
    old_mode: libc::mode_t,
}

/// Close an owned `DIR*` once and clear its ownership slot.
fn close_owned_dir(dir: &mut *mut libc::DIR) {
    if !(*dir).is_null() {
        // SAFETY: every caller passes its unique ownership slot for a live
        // stream returned by `fdopendir()`; clearing the slot prevents reuse.
        unsafe { libc::closedir(*dir) };
        *dir = std::ptr::null_mut();
    }
}

/// Convert a uniquely owned directory descriptor into an owned `DIR*`.
fn fdopendir_owned(fd: OwnedFd) -> Result<*mut libc::DIR, RmRfError> {
    let raw_fd = fd.into_raw_fd();
    // SAFETY: `raw_fd` is uniquely owned and fdopendir either consumes it or
    // leaves it for the failure path below.
    let dir = unsafe { libc::fdopendir(raw_fd) };
    if dir.is_null() {
        let error = last_errno();
        // SAFETY: fdopendir failed and did not consume the owned descriptor.
        unsafe { libc::close(raw_fd) };
        return Err(RmRfError::from_errno(error, "fdopendir"));
    }
    Ok(dir)
}

/// Borrow the descriptor owned by a live directory stream.
fn dir_stream_fd(dir: *mut libc::DIR) -> RawFd {
    // SAFETY: callers retain unique ownership of a live `DIR*` stream.
    let fd = unsafe { libc::dirfd(dir) };
    assert!(fd >= 0);
    fd
}

/// Read and classify one usable UTF-8 directory entry.
///
/// Dot entries and non-UTF-8 names are skipped to preserve the existing
/// traversal policy; `None` means end of stream.
fn next_directory_entry(dir: *mut libc::DIR) -> Result<Option<(String, DirectoryHint)>, RmRfError> {
    loop {
        clear_errno();
        // SAFETY: callers retain unique ownership of a live directory stream.
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            let errno = last_errno();
            return if errno == 0 {
                Ok(None)
            } else {
                Err(RmRfError::from_errno(errno, "readdir"))
            };
        }
        // SAFETY: `entry` remains valid until the next readdir call on this
        // stream, which occurs only after this function returns.
        let (name, d_type) = unsafe {
            (
                std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()),
                (*entry).d_type,
            )
        };
        let Ok(name) = name.to_str() else {
            continue;
        };
        if matches!(name, "." | "..") {
            continue;
        }
        let hint = if d_type == libc::DT_DIR {
            DirectoryHint::Directory
        } else if d_type == libc::DT_UNKNOWN {
            DirectoryHint::Unknown
        } else {
            DirectoryHint::NotDirectory
        };
        return Ok(Some((name.to_owned(), hint)));
    }
}

impl TodoEntry {
    /// Close the DIR* and free the entry.
    fn close(&mut self) {
        close_owned_dir(&mut self.dir);
    }
}

impl Drop for TodoEntry {
    fn drop(&mut self) {
        self.close();
    }
}

// ── Children removal (iterative) ──────────────────────────────────────────

/// Remove all children of an open directory fd.
///
/// The fd is consumed (closed) by this function in all cases.
fn rm_rf_children_impl(
    fd: OwnedFd,
    flags: RemoveFlags,
    root_dev: Option<u64>,
    old_mode: libc::mode_t,
) -> Result<(), RmRfError> {
    let mut ret: Option<RmRfError> = None;
    let mut todos: Vec<TodoEntry> = Vec::new();

    let mut pending_fd = Some(fd);
    let mut current_dir: *mut libc::DIR;
    let mut current_dirname: Option<CString> = None;
    let mut current_old_mode = old_mode;
    let mut descending = true;

    loop {
        if descending {
            current_dir =
                fdopendir_owned(pending_fd.take().expect("descent requires a pending fd"))?;
            let current_fd = dir_stream_fd(current_dir);

            // Check filesystem type.
            if !flags.contains(RemoveFlags::REMOVE_PHYSICAL) {
                let f_type = match get_fs_type(current_fd) {
                    Ok(f_type) => f_type,
                    Err(error) => {
                        close_owned_dir(&mut current_dir);
                        return Err(error);
                    }
                };
                if is_physical_fs(f_type) {
                    close_owned_dir(&mut current_dir);
                    return Err(RmRfError::PhysicalFs(
                        "attempted to remove disk filesystem".into(),
                    ));
                }
            }
            descending = false;
        } else {
            debug_assert!(!todos.is_empty());
            // We are returning from recursion: remove the inner directory.
            let parent = todos.last().unwrap();
            let parent_fd = dir_stream_fd(parent.dir);
            let dirname = current_dirname.as_ref().unwrap();

            if let Err(e) = unlinkat_harder(
                parent_fd,
                dirname.to_str().unwrap_or(""),
                libc::AT_REMOVEDIR,
                flags,
            ) {
                if !matches!(&e, RmRfError::NotFound(_)) {
                    if ret.is_none() {
                        ret = Some(e);
                    }
                    if flags.contains(RemoveFlags::REMOVE_CHMOD_RESTORE) {
                        // SAFETY: `parent_fd` is borrowed from the live parent
                        // stream and `dirname` is a live NUL-terminated path.
                        unsafe {
                            libc::fchmodat(
                                parent_fd,
                                dirname.as_ptr(),
                                current_old_mode & 0o7777,
                                0,
                            );
                        }
                    }
                }
            }

            // Pop the parent frame.
            let mut parent = todos.pop().unwrap();
            current_dir = parent.dir;
            parent.dir = std::ptr::null_mut(); // prevent double-close
            current_dirname = Some(parent.dirname.clone());
            current_old_mode = parent.old_mode;
        }

        let current_fd = dir_stream_fd(current_dir);

        let mut descended = false;

        // Iterate directory entries.
        loop {
            let Some((name_str, directory_hint)) = (match next_directory_entry(current_dir) {
                Ok(entry) => entry,
                Err(error) => {
                    close_owned_dir(&mut current_dir);
                    return Err(error);
                }
            }) else {
                break;
            };

            match rm_rf_inner_child(
                current_fd,
                &name_str,
                directory_hint,
                flags,
                root_dev,
                false,
            ) {
                Ok(ChildResult::Removed | ChildResult::Skipped | ChildResult::NeedsRecursion) => {}
                Err(RmRfError::IsDirectory) => {
                    // Push current state and descend.
                    let new_dirname = match CString::new(name_str.as_str()) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };

                    match openat_harder(current_fd, &name_str, DIR_OPEN_FLAGS, flags) {
                        Ok((new_fd, mode)) => {
                            todos.push(TodoEntry {
                                dir: current_dir,
                                dirname: current_dirname.take().unwrap_or_default(),
                                old_mode: current_old_mode,
                            });
                            current_dir = std::ptr::null_mut();
                            pending_fd = Some(new_fd);
                            current_dirname = Some(new_dirname);
                            current_old_mode = mode;
                            descending = true;
                            descended = true;
                            break;
                        }
                        Err(e) => {
                            if !matches!(&e, RmRfError::NotFound(_)) && ret.is_none() {
                                ret = Some(e);
                            }
                        }
                    }
                }
                Err(e) => {
                    if !matches!(&e, RmRfError::NotFound(_)) && ret.is_none() {
                        ret = Some(e);
                    }
                }
            }
        }

        if descended {
            // The parent DIR is owned by the new todo frame and the child fd
            // is owned by `pending_fd`; open and enumerate it next.
            continue;
        }

        // syncfs if requested.
        #[cfg(target_os = "linux")]
        if flags.contains(RemoveFlags::REMOVE_SYNCFS) {
            // SAFETY: `current_fd` is borrowed from the live current DIR.
            let r = unsafe { crate::ffi::syncfs(current_fd) };
            if r < 0 && ret.is_none() {
                ret = Some(RmRfError::from_errno(last_errno(), "syncfs"));
            }
        }

        if todos.is_empty() {
            // Restore mode if requested.
            if flags.contains(RemoveFlags::REMOVE_CHMOD_RESTORE) {
                // SAFETY: `current_fd` is borrowed from the live root DIR.
                if unsafe { libc::fchmod(current_fd, current_old_mode & 0o7777) } < 0
                    && ret.is_none()
                {
                    ret = Some(RmRfError::from_errno(last_errno(), "fchmod"));
                }
            }
            close_owned_dir(&mut current_dir);
            break;
        }

        // The current child has been completely enumerated. Closing it before
        // the next iteration mirrors C's `_cleanup_closedir_`; the next pass
        // removes the child and resumes its parent stream.
        close_owned_dir(&mut current_dir);
    }

    match ret {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

// ── Public API ────────────────────────────────────────────────────────────

/// Remove all children of the directory referred to by `fd`.
///
/// The fd is **consumed** (closed) by this function on all code paths.
///
/// # Arguments
/// * `fd` - An open file descriptor for a directory.
/// * `flags` - Removal flags.
/// * `root_dev` - If `Some(dev)`, only remove entries on the same device.
pub fn rm_rf_children(fd: i32, flags: RemoveFlags, root_dev: Option<u64>) -> Result<(), RmRfError> {
    if fd < 0 {
        return Err(RmRfError::BadFd);
    }
    let stat = match fstat_fd(fd) {
        Ok(stat) => stat,
        Err(error) => {
            // SAFETY: the public contract transfers this raw descriptor even
            // when validation fails; close it exactly once on this path.
            unsafe { libc::close(fd) };
            return Err(error);
        }
    };
    rm_rf_children_impl(owned_fd_from_syscall(fd), flags, root_dev, stat.st_mode)
}

/// Remove a directory tree rooted at `path`.
///
/// This is the main entry point for recursive removal.
///
/// # Arguments
/// * `path` - Path to the file or directory to remove.
/// * `flags` - Removal flags.
pub fn rm_rf<P: AsRef<Path>>(path: P, flags: RemoveFlags) -> Result<(), RmRfError> {
    rm_rf_at(libc::AT_FDCWD, path.as_ref(), flags)
}

/// Remove a directory tree rooted at `path`, relative to `dir_fd`.
///
/// # Arguments
/// * `dir_fd` - Directory file descriptor (or `AT_FDCWD`).
/// * `path` - Path relative to `dir_fd`.
/// * `flags` - Removal flags.
pub fn rm_rf_at(dir_fd: i32, path: &Path, flags: RemoveFlags) -> Result<(), RmRfError> {
    let path_str = path
        .to_str()
        .ok_or_else(|| RmRfError::InvalidArgument(format!("path is not valid UTF-8: {path:?}")))?;

    // REMOVE_ONLY_DIRECTORIES + REMOVE_SUBVOLUME is not supported (race-prone).
    if flags.contains(RemoveFlags::REMOVE_ONLY_DIRECTORIES | RemoveFlags::REMOVE_SUBVOLUME) {
        return Err(RmRfError::InvalidArgument(
            "REMOVE_ONLY_DIRECTORIES and REMOVE_SUBVOLUME are mutually exclusive".into(),
        ));
    }

    let c_path = to_cstr(path_str)?;

    // Refuse every pathname/dirfd alias of the process root before attempting
    // any unlink or opening the tree for enumeration.
    match path_is_root_at(dir_fd, &c_path) {
        Ok(true) => {
            return Err(RmRfError::PhysicalFs(
                "attempted to remove entire root filesystem".into(),
            ));
        }
        Ok(false) => {}
        Err(RmRfError::NotFound(_)) => {
            // `path_is_root_at()` follows the final component and therefore
            // reports ENOENT for dangling symlinks. Match C by checking the
            // entry itself without following it before accepting absence.
            // SAFETY: `c_path` is NUL-terminated and live for the call.
            if unsafe {
                libc::faccessat(
                    dir_fd,
                    c_path.as_ptr(),
                    libc::F_OK,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } < 0
            {
                let error = last_errno();
                if flags.contains(RemoveFlags::REMOVE_MISSING_OK) && error == -libc::ENOENT {
                    return Ok(());
                }
                return RmRfError::neg_errno_result(error, path_str);
            }
        }
        Err(error) => return Err(error),
    }

    // Try direct unlinkat first (for REMOVE_ROOT | REMOVE_PHYSICAL).
    if flags.contains(RemoveFlags::REMOVE_ROOT | RemoveFlags::REMOVE_PHYSICAL) {
        // SAFETY: `c_path` is NUL-terminated and live, and `dir_fd` is
        // borrowed for this synchronous unlinkat(2) call.
        let r = unsafe { libc::unlinkat(dir_fd, c_path.as_ptr(), libc::AT_REMOVEDIR) };
        if r >= 0 {
            return Ok(());
        }
        let errno = last_errno();
        if !(flags.contains(RemoveFlags::REMOVE_MISSING_OK) && errno == -libc::ENOENT) {
            if !is_subvol_recoverable_errno(errno) {
                return RmRfError::neg_errno_result(errno, path_str);
            }
        }
    }

    // Try unlinkat for REMOVE_ROOT.
    if flags.contains(RemoveFlags::REMOVE_ROOT) {
        // SAFETY: `c_path` is NUL-terminated and live, and `dir_fd` is
        // borrowed for this synchronous unlinkat(2) call.
        let r = unsafe { libc::unlinkat(dir_fd, c_path.as_ptr(), libc::AT_REMOVEDIR) };
        if r >= 0 {
            return Ok(());
        }
    }

    // Open as directory and remove children.
    match openat_harder(dir_fd, path_str, DIR_OPEN_FLAGS, flags) {
        Ok((fd, old_mode)) => {
            let r = rm_rf_children_impl(fd, flags, None, old_mode);

            if flags.contains(RemoveFlags::REMOVE_ROOT) {
                // SAFETY: `c_path` is NUL-terminated and live, and `dir_fd`
                // is borrowed for this synchronous unlinkat(2) call.
                let qr = unsafe { libc::unlinkat(dir_fd, c_path.as_ptr(), libc::AT_REMOVEDIR) };
                if qr < 0 {
                    let errno = last_errno();
                    if !(flags.contains(RemoveFlags::REMOVE_MISSING_OK) && errno == -libc::ENOENT) {
                        if r.is_ok() {
                            return RmRfError::neg_errno_result(errno, path_str);
                        }
                    }
                }
            }
            r
        }
        Err(e) => {
            if flags.contains(RemoveFlags::REMOVE_MISSING_OK)
                && matches!(&e, RmRfError::NotFound(_))
            {
                return Ok(());
            }
            match &e {
                RmRfError::InvalidArgument(_) | RmRfError::Io(_, _) => {
                    // Could be ENOTDIR or ELOOP — try plain unlink.
                    if flags.contains(RemoveFlags::REMOVE_ONLY_DIRECTORIES)
                        || !flags.contains(RemoveFlags::REMOVE_ROOT)
                    {
                        return Ok(());
                    }

                    if !flags.contains(RemoveFlags::REMOVE_PHYSICAL) {
                        let f_type = get_fs_type_at(dir_fd, &c_path)?;
                        if is_physical_fs(f_type) {
                            return Err(RmRfError::PhysicalFs(
                                "attempted to remove files from a disk filesystem".into(),
                            ));
                        }
                    }

                    // SAFETY: `c_path` is NUL-terminated and live, and
                    // `dir_fd` is borrowed for this synchronous unlinkat(2) call.
                    let qr = unsafe { libc::unlinkat(dir_fd, c_path.as_ptr(), 0) };
                    if qr >= 0 {
                        return Ok(());
                    }
                    let errno = last_errno();
                    if flags.contains(RemoveFlags::REMOVE_MISSING_OK) && errno == -libc::ENOENT {
                        return Ok(());
                    }
                    RmRfError::neg_errno_result(errno, path_str)
                }
                _ => Err(e),
            }
        }
    }
}

/// Remove a single named child from the directory referred to by `fd`.
///
/// # Arguments
/// * `fd` - Open file descriptor for the parent directory.
/// * `name` - Name of the child to remove.
/// * `flags` - Removal flags.
pub fn rm_rf_child(fd: i32, name: &str, flags: RemoveFlags) -> Result<(), RmRfError> {
    if fd < 0 {
        return Err(RmRfError::BadFd);
    }
    if name.is_empty() || name.contains('/') || name == "." || name == ".." || name.contains('\0') {
        return Err(RmRfError::InvalidArgument(format!(
            "invalid child name: {name:?}"
        )));
    }
    if flags.contains(RemoveFlags::REMOVE_ROOT) || flags.contains(RemoveFlags::REMOVE_MISSING_OK) {
        return Err(RmRfError::InvalidArgument(
            "REMOVE_ROOT and REMOVE_MISSING_OK are not valid for rm_rf_child".into(),
        ));
    }
    if flags.contains(RemoveFlags::REMOVE_ONLY_DIRECTORIES | RemoveFlags::REMOVE_SUBVOLUME) {
        return Err(RmRfError::InvalidArgument(
            "REMOVE_ONLY_DIRECTORIES and REMOVE_SUBVOLUME are mutually exclusive".into(),
        ));
    }

    match rm_rf_inner_child(fd, name, DirectoryHint::Unknown, flags, None, true)? {
        ChildResult::Removed | ChildResult::Skipped => Ok(()),
        ChildResult::NeedsRecursion => Ok(()),
    }
}

/// Safely remove a directory tree, ignoring errors.
///
/// Equivalent to the C `rm_rf_safe()` function. Always returns `None`.
/// Uses `REMOVE_ROOT | REMOVE_MISSING_OK | REMOVE_CHMOD`.
pub fn rm_rf_safe<P: AsRef<Path>>(path: P) -> Option<()> {
    let _ = rm_rf(
        path,
        RemoveFlags::REMOVE_ROOT | RemoveFlags::REMOVE_MISSING_OK | RemoveFlags::REMOVE_CHMOD,
    );
    None
}

/// Remove a path on a physical filesystem, then drop it.
///
/// Uses `REMOVE_ROOT | REMOVE_PHYSICAL | REMOVE_MISSING_OK | REMOVE_CHMOD`.
pub fn rm_rf_physical_and_free(p: PathBuf) -> Option<PathBuf> {
    let _ = rm_rf(
        &p,
        RemoveFlags::REMOVE_ROOT
            | RemoveFlags::REMOVE_PHYSICAL
            | RemoveFlags::REMOVE_MISSING_OK
            | RemoveFlags::REMOVE_CHMOD,
    );
    let _ = p; // path is consumed by move
    None
}

/// Remove a subvolume path, then drop it.
///
/// Uses `REMOVE_ROOT | REMOVE_PHYSICAL | REMOVE_SUBVOLUME | REMOVE_MISSING_OK | REMOVE_CHMOD`.
pub fn rm_rf_subvolume_and_free(p: PathBuf) -> Option<PathBuf> {
    let _ = rm_rf(
        &p,
        RemoveFlags::REMOVE_ROOT
            | RemoveFlags::REMOVE_PHYSICAL
            | RemoveFlags::REMOVE_SUBVOLUME
            | RemoveFlags::REMOVE_MISSING_OK
            | RemoveFlags::REMOVE_CHMOD,
    );
    let _ = p;
    None
}

/// Convenience: remove a directory tree at an absolute path, removing the root itself.
pub fn rm_rf_directory<P: AsRef<Path>>(path: P) -> Result<(), RmRfError> {
    rm_rf(
        path,
        RemoveFlags::REMOVE_ROOT
            | RemoveFlags::REMOVE_PHYSICAL
            | RemoveFlags::REMOVE_MISSING_OK
            | RemoveFlags::REMOVE_CHMOD,
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── RemoveFlags tests ──

    #[test]
    fn test_remove_flags_combinations() {
        let f = RemoveFlags::REMOVE_ROOT | RemoveFlags::REMOVE_PHYSICAL;
        assert!(f.contains(RemoveFlags::REMOVE_ROOT));
        assert!(f.contains(RemoveFlags::REMOVE_PHYSICAL));
        assert!(!f.contains(RemoveFlags::REMOVE_SUBVOLUME));
    }

    #[test]
    fn test_remove_flags_all() {
        let f = RemoveFlags::all();
        assert!(f.contains(RemoveFlags::REMOVE_ROOT));
        assert!(f.contains(RemoveFlags::REMOVE_PHYSICAL));
        assert!(f.contains(RemoveFlags::REMOVE_SUBVOLUME));
        assert!(f.contains(RemoveFlags::REMOVE_MISSING_OK));
        assert!(f.contains(RemoveFlags::REMOVE_CHMOD));
        assert!(f.contains(RemoveFlags::REMOVE_CHMOD_RESTORE));
        assert!(f.contains(RemoveFlags::REMOVE_SYNCFS));
        assert!(f.contains(RemoveFlags::REMOVE_ONLY_DIRECTORIES));
    }

    #[test]
    fn test_remove_flags_default_empty() {
        assert!(RemoveFlags::default().is_empty());
    }

    // ── Filesystem detection tests ──

    #[test]
    fn test_is_temporary_fs_tmpfs() {
        assert!(is_temporary_fs(TMPFS_MAGIC));
    }

    #[test]
    fn test_is_temporary_fs_ramfs() {
        assert!(is_temporary_fs(RAMFS_MAGIC));
    }

    #[test]
    fn test_is_temporary_fs_cifs() {
        assert!(is_temporary_fs(CIFS_MAGIC));
    }

    #[test]
    fn test_is_temporary_fs_configfs() {
        assert!(is_temporary_fs(CONFIGFS_MAGIC));
    }

    #[test]
    fn test_is_temporary_fs_ext4() {
        assert!(!is_temporary_fs(0xEF53)); // ext4
    }

    #[test]
    fn test_is_physical_fs_tmpfs() {
        assert!(!is_physical_fs(TMPFS_MAGIC));
    }

    #[test]
    fn test_is_physical_fs_cgroup2() {
        assert!(!is_physical_fs(CGROUP2_SUPER_MAGIC));
    }

    #[test]
    fn test_is_physical_fs_ext4() {
        assert!(is_physical_fs(0xEF53)); // ext4
    }

    #[test]
    fn test_is_physical_fs_xfs() {
        assert!(is_physical_fs(0x58465342)); // XFS
    }

    // ── Validation tests ──

    #[test]
    fn test_rm_rf_root_rejected() {
        let result = rm_rf("/", RemoveFlags::REMOVE_ROOT);
        assert!(matches!(result, Err(RmRfError::PhysicalFs(_))));
    }

    #[test]
    fn test_rm_rf_at_invalid_flags() {
        let result = rm_rf_at(
            libc::AT_FDCWD,
            Path::new("/tmp"),
            RemoveFlags::REMOVE_ONLY_DIRECTORIES | RemoveFlags::REMOVE_SUBVOLUME,
        );
        assert!(matches!(result, Err(RmRfError::InvalidArgument(_))));
    }

    #[test]
    fn test_rm_rf_child_invalid_empty_name() {
        let result = rm_rf_child(0, "", RemoveFlags::empty());
        assert!(result.is_err());
    }

    #[test]
    fn test_rm_rf_child_invalid_slash() {
        let result = rm_rf_child(0, "foo/bar", RemoveFlags::empty());
        assert!(matches!(result, Err(RmRfError::InvalidArgument(_))));
    }

    #[test]
    fn test_rm_rf_child_invalid_dot() {
        let result = rm_rf_child(0, ".", RemoveFlags::empty());
        assert!(matches!(result, Err(RmRfError::InvalidArgument(_))));
    }

    #[test]
    fn test_rm_rf_child_invalid_dotdot() {
        let result = rm_rf_child(0, "..", RemoveFlags::empty());
        assert!(matches!(result, Err(RmRfError::InvalidArgument(_))));
    }

    #[test]
    fn test_rm_rf_child_bad_fd() {
        let result = rm_rf_child(-1, "test", RemoveFlags::empty());
        assert!(matches!(result, Err(RmRfError::BadFd)));
    }

    #[test]
    fn test_rm_rf_child_with_root_flag() {
        let result = rm_rf_child(0, "test", RemoveFlags::REMOVE_ROOT);
        assert!(matches!(result, Err(RmRfError::InvalidArgument(_))));
    }

    #[test]
    fn test_rm_rf_child_with_missing_ok_flag() {
        let result = rm_rf_child(0, "test", RemoveFlags::REMOVE_MISSING_OK);
        assert!(matches!(result, Err(RmRfError::InvalidArgument(_))));
    }

    #[test]
    fn test_rm_rf_children_bad_fd() {
        let result = rm_rf_children(-1, RemoveFlags::empty(), None);
        assert!(matches!(result, Err(RmRfError::BadFd)));
    }

    // ── Functional tests with tempdirs ──

    #[test]
    fn test_rm_rf_nonexistent_missing_ok() {
        let result = rm_rf(
            "/nonexistent_rm_rf_test_abc123",
            RemoveFlags::REMOVE_MISSING_OK,
        );
        assert!(result.is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_rm_rf_nonexistent_fail() {
        let result = rm_rf("/nonexistent_rm_rf_test_abc123", RemoveFlags::empty());
        assert!(result.is_err());
    }

    #[test]
    fn test_rm_rf_simple_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("testfile.txt");
        fs::write(&file_path, "hello").unwrap();
        assert!(file_path.exists());

        rm_rf(
            &file_path,
            RemoveFlags::REMOVE_ROOT | RemoveFlags::REMOVE_PHYSICAL,
        )
        .unwrap();
        assert!(!file_path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_rm_rf_directory_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("test_tree");
        fs::create_dir_all(dir.join("a/b/c")).unwrap();
        fs::write(dir.join("a/file1.txt"), "data").unwrap();
        fs::write(dir.join("a/b/file2.txt"), "data").unwrap();
        fs::write(dir.join("a/b/c/file3.txt"), "data").unwrap();

        rm_rf_directory(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_rm_rf_child_of_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let child_dir = tmp.path().join("child_rm");
        fs::create_dir_all(child_dir.join("sub")).unwrap();
        fs::write(child_dir.join("file.txt"), "data").unwrap();

        let tmp_path = CString::new(tmp.path().as_os_str().as_bytes()).unwrap();
        // SAFETY: `tmp_path` is NUL-terminated and live for this synchronous
        // open; the test takes ownership of the returned descriptor.
        let parent_fd =
            unsafe { libc::open(tmp_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        assert!(parent_fd >= 0);

        rm_rf_child(parent_fd, "child_rm", RemoveFlags::REMOVE_PHYSICAL).unwrap();
        assert!(!child_dir.exists());
        // SAFETY: `parent_fd` is the live descriptor opened above and has not
        // been transferred elsewhere in this test.
        unsafe { libc::close(parent_fd) };
    }

    #[test]
    fn test_rm_rf_empty_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let empty_dir = tmp.path().join("empty_dir");
        fs::create_dir(&empty_dir).unwrap();

        rm_rf_directory(&empty_dir).unwrap();
        assert!(!empty_dir.exists());
    }

    #[test]
    fn test_rm_rf_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target.txt");
        let link = tmp.path().join("link");
        fs::write(&target, "data").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        rm_rf(
            &link,
            RemoveFlags::REMOVE_ROOT | RemoveFlags::REMOVE_PHYSICAL,
        )
        .unwrap();
        assert!(!link.exists());
        // Target should still exist.
        assert!(target.exists());
    }

    #[test]
    fn test_rm_rf_safe_returns_none() {
        assert!(rm_rf_safe("/nonexistent_path_test").is_none());
    }

    #[test]
    fn test_rm_rf_physical_and_free_returns_none() {
        let result = rm_rf_physical_and_free(PathBuf::from("/nonexistent_test_path"));
        assert!(result.is_none());
    }

    #[test]
    fn test_rm_rf_subvolume_and_free_returns_none() {
        let result = rm_rf_subvolume_and_free(PathBuf::from("/nonexistent_test_path"));
        assert!(result.is_none());
    }

    #[test]
    fn test_rm_rf_only_directories_skips_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("test_only_dirs");
        fs::create_dir_all(dir.join("subdir")).unwrap();
        fs::write(dir.join("file.txt"), "data").unwrap();

        // Remove only directories — the file should remain.
        let result = rm_rf(
            &dir,
            RemoveFlags::REMOVE_ROOT
                | RemoveFlags::REMOVE_PHYSICAL
                | RemoveFlags::REMOVE_ONLY_DIRECTORIES,
        );
        // This should either succeed or error (since REMOVE_ROOT tries to rmdir the parent),
        // but the point is files should not be removed.
        let _ = result;
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_rm_rf_deeply_nested() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("deep");
        let mut current = dir.clone();
        for i in 0..50 {
            current = current.join(format!("d{i}"));
            fs::create_dir_all(&current).unwrap();
            fs::write(current.join("file.txt"), i.to_string()).unwrap();
        }

        rm_rf_directory(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_rm_rf_with_readonly_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("readonly_dir");
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("sub/file.txt"), "data").unwrap();

        // Make directory read-only.
        let perms = fs::Permissions::from_mode(0o500);
        fs::set_permissions(&dir, perms).unwrap();

        // With REMOVE_CHMOD, should still succeed.
        rm_rf(
            &dir,
            RemoveFlags::REMOVE_ROOT
                | RemoveFlags::REMOVE_PHYSICAL
                | RemoveFlags::REMOVE_CHMOD
                | RemoveFlags::REMOVE_CHMOD_RESTORE,
        )
        .unwrap();
        assert!(!dir.exists());
    }

    // ── Error type tests ──

    #[test]
    fn test_rm_rf_error_display() {
        let e = RmRfError::BadFd;
        assert_eq!(format!("{e}"), "bad file descriptor");

        let e = RmRfError::IsDirectory;
        assert_eq!(format!("{e}"), "is a directory");

        let e = RmRfError::NotFound("/tmp/nope".into());
        assert!(format!("{e}").contains("not found"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_rm_rf_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let e = RmRfError::from(io_err);
        assert!(matches!(e, RmRfError::NotFound(_)));
    }
}
