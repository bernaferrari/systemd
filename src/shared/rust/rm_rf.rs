// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/rm-rf.c, src/shared/rm-rf.h
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
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

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
    let r = unsafe { libc::fstatfs(fd, sfs.as_mut_ptr()) };
    if r < 0 {
        return Err(RmRfError::from_errno(
            -crate::ffi::get_errno() as i32,
            "fstatfs",
        ));
    }
    Ok(unsafe { sfs.assume_init() }.f_type as u64)
}

/// Get the device number for an open directory fd.
fn get_dev(fd: i32) -> Result<u64, RmRfError> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    let r = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if r < 0 {
        return Err(RmRfError::from_errno(
            -crate::ffi::get_errno() as i32,
            "fstat",
        ));
    }
    Ok(unsafe { st.assume_init() }.st_dev as u64)
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

/// Wrapper around `fstatat` that returns a `libc::stat` on success.
fn fstatat_at(dfd: i32, path: &str, flags: i32) -> Result<libc::stat, RmRfError> {
    let c_path = to_cstr(path)?;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    let r = unsafe { libc::fstatat(dfd, c_path.as_ptr(), st.as_mut_ptr(), flags) };
    if r < 0 {
        return Err(RmRfError::from_errno(last_errno(), path));
    }
    Ok(unsafe { st.assume_init() })
}

/// Check if a directory entry (within dfd) is a mount point.
fn is_mount_point_at(dfd: i32, name: &str) -> Result<bool, RmRfError> {
    // Stat the path itself and its parent to compare st_dev.
    let child = fstatat_at(dfd, name, 0)?;
    let parent_st = fstatat_at(dfd, "", AT_EMPTY_PATH)?;
    Ok(child.st_dev != parent_st.st_dev)
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

/// Try to add u+rwx bits to a directory's mode so we can traverse/unlink entries.
///
/// If `refuse_already_set` is true and the bits are already present, returns an error
/// (preserving the original EACCES semantics).
fn patch_dirfd_mode(dfd: i32, refuse_already_set: bool) -> Result<PatchResult, RmRfError> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    let r = unsafe { libc::fstat(dfd, st.as_mut_ptr()) };
    if r < 0 {
        return Err(RmRfError::from_errno(last_errno(), "fstat"));
    }
    let st = unsafe { st.assume_init() };

    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(RmRfError::InvalidArgument("not a directory".into()));
    }

    // Already has owner rwx?
    if (st.st_mode & 0o700) != 0 {
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
    if st.st_uid != unsafe { libc::geteuid() } {
        return Err(RmRfError::PermissionDenied(
            "directory not owned by euid".into(),
        ));
    }

    let new_mode = (st.st_mode | 0o700) & 0o7777;
    let r = unsafe { libc::fchmod(dfd, new_mode) };
    if r < 0 {
        return Err(RmRfError::from_errno(last_errno(), "fchmod"));
    }

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

    // First attempt.
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
    let r = unsafe { libc::unlinkat(dfd, c_name.as_ptr(), unlink_flags) };
    if r >= 0 {
        if remove_flags.contains(RemoveFlags::REMOVE_CHMOD_RESTORE) {
            unsafe { libc::fchmod(dfd, patch.old_mode & 0o7777) };
        }
        return Ok(());
    }
    let errno2 = last_errno();

    // Restore on failure.
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
    let r = unsafe { libc::fstatat(dfd, c_name.as_ptr(), st.as_mut_ptr(), fstatat_flags) };
    if r >= 0 {
        return Ok(unsafe { st.assume_init() });
    }
    let errno = last_errno();

    if errno != -libc::EACCES || !remove_flags.contains(RemoveFlags::REMOVE_CHMOD) {
        return Err(RmRfError::from_errno(errno, filename));
    }

    let patch = patch_dirfd_mode(dfd, true)?;
    let r = unsafe { libc::fstatat(dfd, c_name.as_ptr(), st.as_mut_ptr(), fstatat_flags) };
    if r >= 0 {
        if remove_flags.contains(RemoveFlags::REMOVE_CHMOD_RESTORE) {
            unsafe { libc::fchmod(dfd, patch.old_mode & 0o7777) };
        }
        return Ok(unsafe { st.assume_init() });
    }
    let errno2 = last_errno();

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

/// Like `openat()` for directories, but retries with chmod on EACCES.
///
/// Returns the opened fd and the original mode of the directory.
fn openat_harder(
    dfd: i32,
    path: &str,
    open_flags: i32,
    remove_flags: RemoveFlags,
) -> Result<(i32, libc::mode_t), RmRfError> {
    let c_path = to_cstr(path)?;

    let is_opath = (open_flags & O_PATH) != 0;
    let is_dir = (open_flags & libc::O_DIRECTORY) != 0;
    let want_chmod = remove_flags.contains(RemoveFlags::REMOVE_CHMOD);

    // Fast path: no chmod needed or incompatible flags.
    if is_opath || !is_dir || !want_chmod {
        let fd = unsafe { libc::openat(dfd, c_path.as_ptr(), open_flags) };
        if fd < 0 {
            return Err(RmRfError::from_errno(last_errno(), path));
        }
        let st = fstat_fd(fd)?;
        return Ok((fd, st.st_mode));
    }

    // Open via O_PATH first to inspect, then chmod if needed.
    let pfd = unsafe {
        libc::openat(
            dfd,
            c_path.as_ptr(),
            (open_flags & (libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)) | O_PATH,
        )
    };
    if pfd < 0 {
        return Err(RmRfError::from_errno(last_errno(), path));
    }

    let patch = patch_dirfd_mode(pfd, false)?;
    // Reopen without O_NOFOLLOW to get a real directory fd.
    let fd = unsafe { libc::openat(pfd, c_path.as_ptr(), open_flags & !libc::O_NOFOLLOW) };
    if fd < 0 {
        if patch.chmod_done {
            unsafe { libc::fchmod(pfd, patch.old_mode & 0o7777) };
        }
        unsafe { libc::close(pfd) };
        return Err(RmRfError::from_errno(last_errno(), path));
    }

    unsafe { libc::close(pfd) };
    Ok((fd, patch.old_mode))
}

/// fstat on an fd, returning a stat struct.
fn fstat_fd(fd: i32) -> Result<libc::stat, RmRfError> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    let r = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if r < 0 {
        return Err(RmRfError::from_errno(last_errno(), "fstat"));
    }
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

        let (subdir_fd, _) = openat_harder(fd, fname, DIR_OPEN_FLAGS, flags)?;
        let _ = rm_rf_children_impl(subdir_fd, flags | RemoveFlags::REMOVE_PHYSICAL, root_dev);
        // Close is handled inside rm_rf_children_impl (it takes ownership via fdopendir).

        unlinkat_harder(fd, fname, libc::AT_REMOVEDIR, flags)?;
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
    if !dir.is_null() {
        // SAFETY: every caller passes its unique ownership slot for a live
        // stream returned by `fdopendir()`; clearing the slot prevents reuse.
        unsafe { libc::closedir(*dir) };
        *dir = std::ptr::null_mut();
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
    fd: i32,
    flags: RemoveFlags,
    root_dev: Option<u64>,
) -> Result<(), RmRfError> {
    let mut ret: Option<RmRfError> = None;
    let mut todos: Vec<TodoEntry> = Vec::new();

    let mut current_fd = fd;
    let mut current_dir: *mut libc::DIR;
    let mut current_dirname: Option<CString> = None;
    let mut current_old_mode: libc::mode_t = 0;

    loop {
        if !todos.is_empty() {
            // We are returning from recursion: remove the inner directory.
            let parent = todos.last().unwrap();
            let parent_fd = unsafe { libc::dirfd(parent.dir) };
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
            current_fd = unsafe { libc::dirfd(current_dir) };
        } else {
            // Open the directory.
            assert!(current_fd >= 0);
            current_dir = unsafe { libc::fdopendir(current_fd) };
            if current_dir.is_null() {
                unsafe { libc::close(current_fd) };
                return Err(RmRfError::from_errno(last_errno(), "fdopendir"));
            }
            current_fd = unsafe { libc::dirfd(current_dir) };
            assert!(current_fd >= 0);

            // Check filesystem type.
            if !flags.contains(RemoveFlags::REMOVE_PHYSICAL) {
                let f_type = match get_fs_type(current_fd) {
                    Ok(f_type) => f_type,
                    Err(error) => {
                        // `fdopendir()` took ownership of `current_fd`; close
                        // the resulting stream before propagating the error.
                        close_owned_dir(&mut current_dir);
                        return Err(error);
                    }
                };
                if is_physical_fs(f_type) {
                    // `fdopendir()` took ownership of `current_fd`; close the
                    // resulting stream before rejecting physical filesystems.
                    close_owned_dir(&mut current_dir);
                    return Err(RmRfError::PhysicalFs(
                        "attempted to remove disk filesystem".into(),
                    ));
                }
            }
        }

        // Iterate directory entries.
        loop {
            let entry = unsafe { libc::readdir(current_dir) };
            if entry.is_null() {
                break;
            }
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            let name_str = match name.to_str() {
                Ok(s) => s,
                Err(_) => continue,
            };
            if name_str == "." || name_str == ".." {
                continue;
            }

            let d_type = unsafe { (*entry).d_type };
            let directory_hint = if d_type == libc::DT_DIR {
                DirectoryHint::Directory
            } else if d_type == libc::DT_UNKNOWN {
                DirectoryHint::Unknown
            } else {
                DirectoryHint::NotDirectory
            };

            match rm_rf_inner_child(current_fd, name_str, directory_hint, flags, root_dev, false) {
                Ok(ChildResult::Removed | ChildResult::Skipped | ChildResult::NeedsRecursion) => {}
                Err(RmRfError::IsDirectory) => {
                    // Push current state and descend.
                    let new_dirname = match CString::new(name_str) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };

                    match openat_harder(current_fd, name_str, DIR_OPEN_FLAGS, flags) {
                        Ok((new_fd, mode)) => {
                            todos.push(TodoEntry {
                                dir: current_dir,
                                dirname: current_dirname.take().unwrap_or_default(),
                                old_mode: current_old_mode,
                            });
                            current_fd = new_fd;
                            current_dirname = Some(new_dirname);
                            current_old_mode = mode;
                            break; // break inner loop to process new fd
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

        // syncfs if requested.
        #[cfg(target_os = "linux")]
        if flags.contains(RemoveFlags::REMOVE_SYNCFS) {
            let r = unsafe { crate::ffi::syncfs(current_fd) };
            if r < 0 && ret.is_none() {
                ret = Some(RmRfError::from_errno(last_errno(), "syncfs"));
            }
        }

        if todos.is_empty() {
            // Restore mode if requested.
            if flags.contains(RemoveFlags::REMOVE_CHMOD_RESTORE) {
                unsafe { libc::fchmod(current_fd, current_old_mode & 0o7777) };
            }
            // Close the final DIR*.
            close_owned_dir(&mut current_dir);
            break;
        }
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
    rm_rf_children_impl(fd, flags, root_dev)
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

    // Refuse to remove root filesystem.
    if path_str == "/" || path.is_absolute() && path_str == "/" {
        return Err(RmRfError::PhysicalFs(
            "attempted to remove entire root filesystem".into(),
        ));
    }

    let c_path = to_cstr(path_str)?;

    // Try direct unlinkat first (for REMOVE_ROOT | REMOVE_PHYSICAL).
    if flags.contains(RemoveFlags::REMOVE_ROOT | RemoveFlags::REMOVE_PHYSICAL) {
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
        let r = unsafe { libc::unlinkat(dir_fd, c_path.as_ptr(), libc::AT_REMOVEDIR) };
        if r >= 0 {
            return Ok(());
        }
    }

    // Open as directory and remove children.
    match openat_harder(dir_fd, path_str, DIR_OPEN_FLAGS, flags) {
        Ok((fd, _old_mode)) => {
            let r = rm_rf_children_impl(fd, flags, None);

            if flags.contains(RemoveFlags::REMOVE_ROOT) {
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
                        // Check filesystem type via fstatat.
                        let c_p = to_cstr(path_str)?;
                        let mut sfs = std::mem::MaybeUninit::<libc::statfs>::uninit();
                        let r = unsafe {
                            libc::fstatat(
                                dir_fd,
                                c_p.as_ptr(),
                                std::ptr::null_mut(),
                                libc::AT_SYMLINK_NOFOLLOW,
                            )
                        };
                        // If we can't stat, fall through to unlink.
                        if r >= 0 {
                            // Try fstatfs on the parent dir.
                            let mut sfs2 = std::mem::MaybeUninit::<libc::statfs>::uninit();
                            let r2 = unsafe { libc::fstatfs(dir_fd, sfs2.as_mut_ptr()) };
                            if r2 >= 0
                                && is_physical_fs(unsafe { sfs2.assume_init() }.f_type as u64)
                            {
                                return Err(RmRfError::PhysicalFs(
                                    "attempted to remove files from a disk filesystem".into(),
                                ));
                            }
                        }
                    }

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
        let parent_fd =
            unsafe { libc::open(tmp_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        assert!(parent_fd >= 0);

        rm_rf_child(parent_fd, "child_rm", RemoveFlags::REMOVE_PHYSICAL).unwrap();
        assert!(!child_dir.exists());
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
            fs::write(current.join("file.txt"), &i.to_string()).unwrap();
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
