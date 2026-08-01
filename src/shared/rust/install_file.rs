// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/install-file.c, src/shared/install-file.h
//
// File installation utilities for moving files/directories into place
// with optional syncing, read-only marking, and atomic replacement.
//
// Supports regular files, directories, and special inodes with
// platform-specific read-only semantics (btrfs subvolumes, immutable
// flags, block-device read-only mode).

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use crate::ffi::*;
use std::ffi::CString;
use std::io;
use std::os::fd::RawFd;
use std::time::{SystemTime, UNIX_EPOCH};

// ── Constants ─────────────────────────────────────────────────────────────

/// Microseconds per second.
pub const USEC_PER_SEC: u64 = 1_000_000;

/// Sentinel for "infinity" usec value (matches C `USEC_INFINITY`).
pub const USEC_INFINITY: u64 = u64::MAX;

/// Linux `renameat2` flags.
const RENAME_NOREPLACE: u64 = 1;
const RENAME_EXCHANGE: u64 = 2;

/// Linux filesystem immutable flag (`FS_IMMUTABLE_FL`).
const FS_IMMUTABLE_FL: u32 = 0x0000_0010;

// ── Bitflags ──────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling [`install_file`] behaviour.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct InstallFileFlags: u32 {
        /// Replace existing target atomically.
        const REPLACE   = 1 << 0;
        /// Mark installed file/directory read-only.
        const READ_ONLY = 1 << 1;
        /// `fsync()` the source before installing.
        const FSYNC     = 1 << 2;
        /// `fsync()` the source **and** its parent directory.
        const FSYNC_FULL = 1 << 3;
        /// `syncfs()` the filesystem containing the source.
        const SYNCFS    = 1 << 4;
        /// Do not fail on non-critical errors.
        const GRACEFUL  = 1 << 5;
    }
}

// ── RAII fd guard ─────────────────────────────────────────────────────────

/// RAII wrapper that closes a raw fd on drop (equivalent to C `_cleanup_close_`).
struct FdGuard {
    fd: RawFd,
}

impl FdGuard {
    /// Create a new guard. Only non-negative fds are treated as owned;
    /// negative values mean "no fd" (like the C `EBADF` sentinel).
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }

    fn is_valid(&self) -> bool {
        self.fd >= 0
    }

    fn raw(&self) -> RawFd {
        self.fd
    }

    /// Release ownership, returning the raw fd. The caller becomes
    /// responsible for closing it (matches C `TAKE_FD`).
    fn take(&mut self) -> RawFd {
        let fd = self.fd;
        self.fd = -1;
        fd
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: this guard exclusively owns `fd`; `take()` invalidates it, so
            // every non-negative descriptor reaches `close()` at most once.
            unsafe_ffi!({
                libc::close(self.fd);
            })
        }
    }
}

// ── Pure logic helpers ────────────────────────────────────────────────────

/// Returns `true` when we need to pin the source file via an `O_PATH` fd.
///
/// This is the case when any sync or read-only flag is set, because those
/// operations require opening the source inode.
pub fn need_opath(flags: InstallFileFlags) -> bool {
    flags.intersects(
        InstallFileFlags::FSYNC
            | InstallFileFlags::FSYNC_FULL
            | InstallFileFlags::SYNCFS
            | InstallFileFlags::READ_ONLY,
    )
}

/// Parse a `SOURCE_DATE_EPOCH` value from an optional string.
///
/// Returns the epoch value in **microseconds** on success.
/// Returns `Err` if the value is missing, empty, not a valid unsigned
/// integer, or would overflow when converted to microseconds.
pub fn parse_source_date_epoch(value: Option<&str>) -> io::Result<u64> {
    let v = match value {
        None | Some("") => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "SOURCE_DATE_EPOCH not set",
            ));
        }
        Some(s) => s,
    };

    let secs: u64 = v.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid SOURCE_DATE_EPOCH: {v:?}"),
        )
    })?;

    secs.checked_mul(USEC_PER_SEC).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOURCE_DATE_EPOCH overflow when converting to microseconds",
        )
    })
}

/// Return the `SOURCE_DATE_EPOCH` timestamp (in microseconds) or the
/// current wall-clock time if the environment variable is unset or invalid.
pub fn source_date_epoch_or_now(value: Option<&str>) -> u64 {
    parse_source_date_epoch(value).unwrap_or_else(|_| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as u64)
            .unwrap_or(USEC_INFINITY)
    })
}

// ── Syscall helpers ────────────────────────────────────────────────────────

/// Return the current `errno` as a negative `i32` (systemd convention).
fn last_errno() -> i32 {
    -(crate::ffi::get_errno() as i32)
}

/// Return the current `errno` as an [`io::Error`].
fn last_io_error() -> io::Error {
    io::Error::last_os_error()
}

/// Convert a Rust string to a `CString`. Fails if the string contains
/// an interior nul byte.
fn to_cstr(path: &str) -> io::Result<CString> {
    CString::new(path).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path contains nul byte: {path:?}"),
        )
    })
}

/// Open a path relative to `dirfd`, returning an owning descriptor guard.
fn open_at(dirfd: RawFd, path: &CString, flags: i32) -> io::Result<FdGuard> {
    // SAFETY: path is a live NUL-terminated string for this call; openat does
    // not retain its pointer and the returned descriptor is guarded on success.
    let fd = unsafe_ffi!(libc::openat(dirfd, path.as_ptr(), flags | libc::O_CLOEXEC));
    if fd < 0 {
        return Err(last_io_error());
    }
    Ok(FdGuard::new(fd))
}

/// Read complete `stat` metadata for a live descriptor.
fn fstat_fd(fd: RawFd) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: stat is writable storage for fstat and is read only after a
    // successful return.
    if unsafe_ffi!(libc::fstat(fd, stat.as_mut_ptr())) < 0 {
        return Err(last_io_error());
    }
    // SAFETY: fstat initialized the full stat object above.
    Ok(unsafe_ffi!(stat.assume_init()))
}

/// Issue a pointer-based ioctl without exposing caller memory to the kernel
/// beyond the duration of the syscall.
fn ioctl_ref<T>(fd: RawFd, request: libc::c_ulong, value: &mut T) -> io::Result<()> {
    // SAFETY: value is live, correctly aligned storage for the request's ABI,
    // and ioctl does not retain the pointer after it returns.
    if unsafe_ffi!(libc::ioctl(fd, request, value)) < 0 {
        Err(last_io_error())
    } else {
        Ok(())
    }
}

/// Rename a directory entry while keeping both path pointers scoped to the
/// syscall boundary.
fn rename_at(
    olddirfd: RawFd,
    oldpath: &CString,
    newdirfd: RawFd,
    newpath: &CString,
) -> io::Result<()> {
    // SAFETY: both strings are live NUL-terminated paths and renameat does
    // not retain either pointer.
    if unsafe_ffi!(libc::renameat(
        olddirfd,
        oldpath.as_ptr(),
        newdirfd,
        newpath.as_ptr()
    )) < 0
    {
        Err(last_io_error())
    } else {
        Ok(())
    }
}

/// Remove a path using the supplied unlinkat flags.
fn unlink_at(dirfd: RawFd, path: &CString, flags: i32) -> io::Result<()> {
    // SAFETY: path is a live NUL-terminated path and unlinkat does not retain
    // its pointer.
    if unsafe_ffi!(libc::unlinkat(dirfd, path.as_ptr(), flags)) < 0 {
        Err(last_io_error())
    } else {
        Ok(())
    }
}

/// Re-open an existing fd with different flags via `/proc/self/fd`.
///
/// This is the Rust equivalent of the C `fd_reopen()` helper.
fn fd_reopen(fd: RawFd, flags: i32) -> io::Result<FdGuard> {
    let proc_path = format!("/proc/self/fd/{fd}");
    let c_path = to_cstr(&proc_path)?;
    open_at(libc::AT_FDCWD, &c_path, flags)
}

/// `fsync(2)` a file descriptor.
fn fsync_fd(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fsync()` takes the descriptor by value and does not retain Rust
    // memory; validity is checked by the kernel and reported through `errno`.
    if unsafe_ffi!(libc::fsync(fd)) < 0 {
        Err(last_io_error())
    } else {
        Ok(())
    }
}

/// `syncfs(2)` a file descriptor.
fn syncfs_fd(fd: RawFd) -> io::Result<()> {
    // SAFETY: `syncfs()` takes the descriptor by value and does not retain Rust
    // memory; validity is checked by the kernel and reported through `errno`.
    if unsafe_ffi!(crate::ffi::syncfs(fd)) < 0 {
        Err(last_io_error())
    } else {
        Ok(())
    }
}

/// Sync the parent directory of an open fd by opening `../` relative to
/// the fd's `/proc/self/fd` entry and `fsync`-ing it.
fn fsync_directory_of_file(fd: RawFd) -> io::Result<()> {
    let parent_path = format!("/proc/self/fd/{fd}/..");
    let c_path = to_cstr(&parent_path)?;
    let dir = open_at(libc::AT_FDCWD, &c_path, libc::O_RDONLY | libc::O_DIRECTORY)?;
    fsync_fd(dir.raw())
}

/// Sync the parent directory of a file referenced by `(dirfd, name)`.
fn fsync_parent_at(dirfd: RawFd, name: &str) -> io::Result<()> {
    let c_name = to_cstr(name)?;
    let pfd = open_at(dirfd, &c_name, O_PATH | libc::O_NOFOLLOW)?;
    fsync_directory_of_file(pfd.raw())
}

/// Full `fsync`: sync the fd itself **and** its parent directory.
fn fsync_full(fd: RawFd) -> io::Result<()> {
    fsync_fd(fd)?;
    fsync_directory_of_file(fd)
}

/// Atomic rename that fails with `EEXIST` if the target already exists.
///
/// Wrapper around `renameat2(2)` with `RENAME_NOREPLACE`.
fn rename_noreplace(
    olddirfd: RawFd,
    oldpath: &CString,
    newdirfd: RawFd,
    newpath: &CString,
) -> io::Result<()> {
    rename_at2(olddirfd, oldpath, newdirfd, newpath, RENAME_NOREPLACE)
}

/// Invoke Linux `renameat2(2)` with an explicit flag set.
fn rename_at2(
    olddirfd: RawFd,
    oldpath: &CString,
    newdirfd: RawFd,
    newpath: &CString,
    flags: u64,
) -> io::Result<()> {
    // SAFETY: both `CString` pointers are live and NUL-terminated for the
    // syscall; the kernel copies their contents and does not retain them.
    let r = unsafe_ffi!({
        libc::syscall(
            SYS_renameat2,
            olddirfd,
            oldpath.as_ptr(),
            newdirfd,
            newpath.as_ptr(),
            flags,
        )
    });
    if r < 0 { Err(last_io_error()) } else { Ok(()) }
}

/// Atomically exchange two directory entries via `renameat2(2)` with
/// `RENAME_EXCHANGE`.
fn rename_exchange(
    olddirfd: RawFd,
    oldpath: &CString,
    newdirfd: RawFd,
    newpath: &CString,
) -> io::Result<()> {
    rename_at2(olddirfd, oldpath, newdirfd, newpath, RENAME_EXCHANGE)
}

// ── unlinkat_maybe_dir ────────────────────────────────────────────────────

/// Remove a file at `(dirfd, pathname)`. If the first `unlinkat` fails
/// with `EISDIR`, retry with `AT_REMOVEDIR`.
///
/// This handles the common case where we do not know ahead of time
/// whether the entry is a file or a directory.
pub fn unlinkat_maybe_dir(dirfd: RawFd, pathname: &str) -> io::Result<()> {
    let c_path = to_cstr(pathname)?;

    match unlink_at(dirfd, &c_path, 0) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::EISDIR) => {
            unlink_at(dirfd, &c_path, libc::AT_REMOVEDIR)
        }
        Err(error) => Err(error),
    }
}

// ── fs_make_very_read_only ────────────────────────────────────────────────

/// Make an fd "comprehensively" read-only. Behaviour depends on inode type:
///
/// | Inode type     | Action                                                |
/// |----------------|-------------------------------------------------------|
/// | Directory      | Try btrfs subvolume RO flag, fall back to immutable   |
/// | Regular file   | Strip write bits (`mode & 07555`)                     |
/// | Block device   | `BLKROSET` ioctl                                      |
/// | Other          | `EBADFD`                                              |
pub fn fs_make_very_read_only(fd: RawFd) -> io::Result<()> {
    let st = fstat_fd(fd)?;

    match st.st_mode & libc::S_IFMT {
        libc::S_IFDIR => {
            // Try btrfs subvolume read-only first
            if is_btrfs_subvolume(&st) {
                if btrfs_subvol_set_read_only(fd, true).is_ok() {
                    return Ok(());
                }
                // Fall through to chattr if btrfs ioctl not supported
            }
            // Set FS_IMMUTABLE_FL via ioctl
            chattr_fd(fd, FS_IMMUTABLE_FL, FS_IMMUTABLE_FL)?;
        }

        libc::S_IFREG => {
            if (st.st_mode & 0o222) != 0 {
                let new_mode = st.st_mode & 0o7555;
                // SAFETY: `fchmod()` takes scalar arguments only; descriptor
                // validity is checked by the kernel.
                if unsafe_ffi!(libc::fchmod(fd, new_mode as _)) < 0 {
                    return Err(last_io_error());
                }
            }
        }

        libc::S_IFBLK => {
            let mut ro: i32 = 1;
            ioctl_ref(fd, BLKROSET as _, &mut ro)?;
        }

        _ => {
            return Err(io::Error::from_raw_os_error(EBADFD));
        }
    }

    Ok(())
}

/// Heuristic: a btrfs subvolume is a directory with a non-zero `st_rdev`.
fn is_btrfs_subvolume(st: &libc::stat) -> bool {
    (st.st_mode & libc::S_IFMT) == libc::S_IFDIR && st.st_rdev != 0
}

/// Set / clear the read-only flag on a btrfs subvolume via ioctl.
fn btrfs_subvol_set_read_only(fd: RawFd, read_only: bool) -> io::Result<()> {
    // BTRFS_IOC_SUBVOL_SETFLAGS = _IOW('B', 14, __u64) = 0x4008_420e
    const BTRFS_IOC_SUBVOL_SETFLAGS: u64 = 0x4008_420e;
    const BTRFS_SUBVOL_RDONLY: u64 = 2;

    let mut flags: u64 = if read_only { BTRFS_SUBVOL_RDONLY } else { 0 };
    ioctl_ref(fd, BTRFS_IOC_SUBVOL_SETFLAGS as _, &mut flags)
}

/// Set filesystem attribute flags via `FS_IOC_SETFLAGS` ioctl.
fn chattr_fd(fd: RawFd, set: u32, mask: u32) -> io::Result<()> {
    // FS_IOC_GETFLAGS = _IOR('f', 1, long)  = 0x8004_6601
    // FS_IOC_SETFLAGS = _IOW('f', 2, long)  = 0x4004_6602
    const FS_IOC_GETFLAGS: u64 = 0x8004_6601;
    const FS_IOC_SETFLAGS: u64 = 0x4004_6602;

    let mut flags: libc::c_long = 0;
    ioctl_ref(fd, FS_IOC_GETFLAGS as _, &mut flags)?;

    let new_flags = (flags as u32 & !mask) | set;
    if new_flags as libc::c_long == flags {
        return Ok(());
    }

    let mut new_flags = new_flags as libc::c_long;
    ioctl_ref(fd, FS_IOC_SETFLAGS as _, &mut new_flags)
}

// ── Graceful error helper ─────────────────────────────────────────────────

/// Execute `op`. If it fails and `graceful` is `true`, silently ignore the
/// error and return `None`. Otherwise propagate the error.
fn graceful_run(graceful: bool, op: io::Result<()>) -> io::Result<Option<()>> {
    match op {
        Ok(()) => Ok(Some(())),
        Err(e) => {
            if graceful {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

// ── rm_rf_children wrapper ────────────────────────────────────────────────

/// Best-effort removal of all children of the directory referred to by `fd`.
///
/// Takes ownership of `fd` and delegates to [`crate::rm_rf::rm_rf_children`]
/// with the standard `REMOVE_PHYSICAL | REMOVE_SUBVOLUME | REMOVE_CHMOD` flag
/// set. The delegated function consumes the descriptor on every path.
fn rm_rf_children_best_effort(mut fd: FdGuard) {
    if !fd.is_valid() {
        return;
    }
    let flags = crate::rm_rf::RemoveFlags::REMOVE_PHYSICAL
        | crate::rm_rf::RemoveFlags::REMOVE_SUBVOLUME
        | crate::rm_rf::RemoveFlags::REMOVE_CHMOD;
    let _ = crate::rm_rf::rm_rf_children(fd.take(), flags, None);
}

// ── install_file ──────────────────────────────────────────────────────────

/// Install (move) a file or directory tree into place.
///
/// This is the primary entry point, ported from the C `install_file()`.
///
/// # What it does
///
/// 1. Optionally syncs the source before/after to act as a barrier.
/// 2. Optionally marks the result read-only via [`fs_make_very_read_only`].
/// 3. Optionally operates in **replacing** or **non-replacing** mode.
/// 4. When replacing, removes the old tree atomically.
///
/// If `target_name` is `None`, no renaming takes place — only syncing
/// and read-only marking are applied to the source. With
/// `target_name = None` and `flags = empty` the call is a no-op.
///
/// # Arguments
///
/// * `source_atfd`  — dirfd for the source (or `AT_FDCWD`).
/// * `source_name`  — path of the source relative to `source_atfd`.
/// * `target_atfd`  — dirfd for the target (or `AT_FDCWD`).
/// * `target_name`  — path of the target, or `None` for in-place mode.
/// * `flags`        — behaviour flags (see [`InstallFileFlags`]).
pub fn install_file(
    source_atfd: RawFd,
    source_name: &str,
    target_atfd: RawFd,
    target_name: Option<&str>,
    flags: InstallFileFlags,
) -> io::Result<()> {
    let graceful = flags.contains(InstallFileFlags::GRACEFUL);
    let mut rofd = FdGuard::new(-1);

    // ── Phase 1: open O_PATH fd and sync source if needed ────────────

    if need_opath(flags) {
        let c_source = to_cstr(source_name)?;
        let pfd = open_at(source_atfd, &c_source, O_PATH | libc::O_NOFOLLOW)?;
        let st = fstat_fd(pfd.raw())?;

        match st.st_mode & libc::S_IFMT {
            libc::S_IFREG => match fd_reopen(pfd.raw(), libc::O_RDONLY) {
                Ok(mut regfd) => {
                    if flags.intersects(InstallFileFlags::FSYNC_FULL | InstallFileFlags::SYNCFS) {
                        graceful_run(graceful, fsync_full(regfd.raw()))?;
                    } else if flags.contains(InstallFileFlags::FSYNC) {
                        graceful_run(graceful, fsync_fd(regfd.raw()))?;
                    }

                    if flags.contains(InstallFileFlags::READ_ONLY) {
                        rofd = regfd;
                    }
                }
                Err(e) => {
                    if !graceful {
                        return Err(e);
                    }
                }
            },

            libc::S_IFDIR => match fd_reopen(pfd.raw(), libc::O_RDONLY | libc::O_DIRECTORY) {
                Ok(mut dfd) => {
                    if flags.contains(InstallFileFlags::SYNCFS) {
                        graceful_run(graceful, syncfs_fd(dfd.raw()))?;
                    } else if flags.contains(InstallFileFlags::FSYNC_FULL) {
                        graceful_run(graceful, fsync_full(dfd.raw()))?;
                    } else if flags.contains(InstallFileFlags::FSYNC) {
                        graceful_run(graceful, fsync_fd(dfd.raw()))?;
                    }

                    if flags.contains(InstallFileFlags::READ_ONLY) {
                        rofd = dfd;
                    }
                }
                Err(e) => {
                    if !graceful {
                        return Err(e);
                    }
                }
            },

            _ => {
                // Char/block devices, fifos, symlinks, sockets only need
                // their parent directory synced.
                if target_name.is_some()
                    && flags.intersects(InstallFileFlags::FSYNC_FULL | InstallFileFlags::SYNCFS)
                {
                    graceful_run(graceful, fsync_directory_of_file(pfd.raw()))?;
                }
            }
        }
    }

    // ── Phase 2: rename ───────────────────────────────────────────────

    if let Some(tname) = target_name {
        let c_source = to_cstr(source_name)?;
        let c_target = to_cstr(tname)?;

        if flags.contains(InstallFileFlags::REPLACE) {
            // Try simple renameat first.
            if let Err(err) = rename_at(source_atfd, &c_source, target_atfd, &c_target) {
                let errno = err.raw_os_error().unwrap_or(0);

                if !matches!(
                    errno,
                    libc::EEXIST | libc::ENOTDIR | libc::ENOTEMPTY | libc::EISDIR | libc::EBUSY
                ) {
                    return Err(err);
                }

                // Target already exists — open it as a directory so we
                // can clean up its children later.
                let dfd = match open_at(target_atfd, &c_target, libc::O_RDONLY | libc::O_DIRECTORY)
                {
                    Ok(fd) => fd,
                    Err(error) if error.raw_os_error() == Some(libc::ENOTDIR) => FdGuard::new(-1),
                    Err(error) => return Err(error),
                };

                // Try RENAME_EXCHANGE
                match rename_exchange(source_atfd, &c_source, target_atfd, &c_target) {
                    Ok(()) => {
                        // Exchange succeeded → remove old target (now at
                        // source path) plus its children.
                        rm_rf_children_best_effort(dfd);
                        unlinkat_maybe_dir(source_atfd, source_name)?;
                    }
                    Err(exchange_err) => {
                        let exchange_errno = exchange_err.raw_os_error().unwrap_or(0);
                        if exchange_errno != libc::ENOSYS && exchange_errno != libc::EINVAL {
                            return Err(exchange_err);
                        }

                        // Exchange not supported → remove target contents
                        // first, then plain rename.
                        rm_rf_children_best_effort(dfd);

                        unlinkat_maybe_dir(target_atfd, tname)?;

                        rename_at(source_atfd, &c_source, target_atfd, &c_target)?;
                    }
                }
            }
        } else {
            // Non-replacing rename (fails if target exists)
            rename_noreplace(source_atfd, &c_source, target_atfd, &c_target)?;
        }
    }

    // ── Phase 3: make read-only ───────────────────────────────────────

    if rofd.is_valid() {
        graceful_run(graceful, fs_make_very_read_only(rofd.raw()))?;
    }

    // ── Phase 4: final parent sync ────────────────────────────────────

    if flags.intersects(InstallFileFlags::FSYNC_FULL | InstallFileFlags::SYNCFS) {
        let (dirfd, name) = match target_name {
            Some(tname) => (target_atfd, tname),
            None => (source_atfd, source_name),
        };
        graceful_run(graceful, fsync_parent_at(dirfd, name))?;
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── need_opath ──

    #[test]
    fn test_need_opath_each_sync_flag() {
        assert!(need_opath(InstallFileFlags::FSYNC));
        assert!(need_opath(InstallFileFlags::FSYNC_FULL));
        assert!(need_opath(InstallFileFlags::SYNCFS));
        assert!(need_opath(InstallFileFlags::READ_ONLY));
    }

    #[test]
    fn test_need_opath_non_sync_flags() {
        assert!(!need_opath(InstallFileFlags::REPLACE));
        assert!(!need_opath(InstallFileFlags::GRACEFUL));
        assert!(!need_opath(InstallFileFlags::empty()));
    }

    #[test]
    fn test_need_opath_combined() {
        assert!(need_opath(
            InstallFileFlags::FSYNC | InstallFileFlags::REPLACE
        ));
        assert!(need_opath(
            InstallFileFlags::FSYNC_FULL | InstallFileFlags::SYNCFS
        ));
        assert!(!need_opath(
            InstallFileFlags::REPLACE | InstallFileFlags::GRACEFUL
        ));
    }

    // ── parse_source_date_epoch ──

    #[test]
    fn test_parse_epoch_valid() {
        assert_eq!(parse_source_date_epoch(Some("0")).unwrap(), 0,);
        assert_eq!(
            parse_source_date_epoch(Some("123")).unwrap(),
            123 * USEC_PER_SEC,
        );
    }

    #[test]
    fn test_parse_epoch_none() {
        assert!(parse_source_date_epoch(None).is_err());
    }

    #[test]
    fn test_parse_epoch_empty() {
        assert!(parse_source_date_epoch(Some("")).is_err());
    }

    #[test]
    fn test_parse_epoch_invalid_string() {
        assert!(parse_source_date_epoch(Some("abc")).is_err());
        assert!(parse_source_date_epoch(Some("12.5")).is_err());
        assert!(parse_source_date_epoch(Some("-1")).is_err());
    }

    #[test]
    fn test_parse_epoch_overflow() {
        // u64::MAX / 1_000_000 fits, but multiplied overflows
        let big = format!("{}", u64::MAX);
        assert!(parse_source_date_epoch(Some(&big)).is_err());
    }

    #[test]
    fn test_parse_epoch_large_but_valid() {
        // 10_000_000_000 seconds → still fits in u64 when * 1_000_000
        let val = 10_000_000_000u64;
        let expected = val * USEC_PER_SEC;
        assert_eq!(
            parse_source_date_epoch(Some(&val.to_string())).unwrap(),
            expected,
        );
    }

    // ── source_date_epoch_or_now ──

    #[test]
    fn test_epoch_or_now_with_valid_value() {
        let result = source_date_epoch_or_now(Some("100"));
        assert_eq!(result, 100 * USEC_PER_SEC);
    }

    #[test]
    fn test_epoch_or_now_with_none_returns_recent_time() {
        let now_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        let result = source_date_epoch_or_now(None);
        // Must be within a generous window (±5 s) of the current time
        assert!(result > now_micros.saturating_sub(5_000_000));
        assert!(result < now_micros.saturating_add(5_000_000));
    }

    #[test]
    fn test_epoch_or_now_with_invalid_returns_recent_time() {
        let now_micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        let result = source_date_epoch_or_now(Some("not-a-number"));
        assert!(result > now_micros.saturating_sub(5_000_000));
        assert!(result < now_micros.saturating_add(5_000_000));
    }

    // ── InstallFileFlags bitflags ──

    #[test]
    fn test_flags_bitflags_operations() {
        let flags = InstallFileFlags::REPLACE | InstallFileFlags::FSYNC;
        assert!(flags.contains(InstallFileFlags::REPLACE));
        assert!(flags.contains(InstallFileFlags::FSYNC));
        assert!(!flags.contains(InstallFileFlags::GRACEFUL));
    }

    #[test]
    fn test_flags_all_intersect() {
        let all = InstallFileFlags::all();
        assert!(all.contains(InstallFileFlags::REPLACE));
        assert!(all.contains(InstallFileFlags::READ_ONLY));
        assert!(all.contains(InstallFileFlags::FSYNC));
        assert!(all.contains(InstallFileFlags::FSYNC_FULL));
        assert!(all.contains(InstallFileFlags::SYNCFS));
        assert!(all.contains(InstallFileFlags::GRACEFUL));
    }

    // ── FdGuard ──

    #[test]
    fn test_fd_guard_negative_is_invalid() {
        let g = FdGuard::new(-1);
        assert!(!g.is_valid());
        let g2 = FdGuard::new(-5);
        assert!(!g2.is_valid());
    }

    #[test]
    fn test_fd_guard_take_resets() {
        let mut g = FdGuard::new(-1);
        assert!(!g.is_valid());
        let fd = g.take();
        assert_eq!(fd, -1);
        assert!(!g.is_valid());
    }
}
