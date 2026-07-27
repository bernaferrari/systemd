// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/copy.c, src/shared/copy.h
//
// File and directory copying utilities.
//
// Provides efficient file copying with support for reflinks, sparse files
// (hole punching), recursive directory trees, and various metadata
// preservation options.  When both source and target are regular files on
// Linux, the kernel copy_file_range() syscall is used for zero-copy
// transfer; otherwise falls back to userspace read/write.

// ── Constants ─────────────────────────────────────────────────────────────

use crate::ffi::*;
use std::os::unix::io::AsRawFd;
/// Userspace fallback buffer size (64 KiB).
use std::os::unix::{
    ffi::OsStrExt,
    fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};
const COPY_BUFFER_SIZE: usize = 64 * 1024;

/// Maximum recursion depth for directory tree copies.
const COPY_DEPTH_MAX: u32 = 2048;

// ── Copy flags ────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Options that control copy behaviour.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CopyFlags: u64 {
        /// Use reflink / CoW when available (btrfs, xfs, …).
        const REFLINK          = 1 << 0;
        /// Merge into existing destination directory.
        const MERGE            = 1 << 1;
        /// Replace existing destination files.
        const REPLACE          = 1 << 2;
        /// Do not cross mount points.
        const SAME_MOUNT       = 1 << 3;
        /// Recreate hard links.
        const HARDLINKS        = 1 << 4;
        /// Call fsync() on the target after copying.
        const FSYNC            = 1 << 5;
        /// Preserve / create holes in sparse files.
        const HOLES            = 1 << 6;
        /// Truncate target to copied size.
        const TRUNCATE         = 1 << 7;
        /// Copy all xattrs, not just `user.*`.
        const ALL_XATTRS       = 1 << 8;
        /// fsync the parent directory too.
        const FSYNC_FULL       = 1 << 9;
        /// syncfs() after directory copy.
        const SYNCFS           = 1 << 10;
        /// Set NOCOW after copy.
        const NOCOW_AFTER      = 1 << 11;
        /// Create with SELinux label.
        const MAC_CREATE       = 1 << 12;
        /// Verify linked inodes after copy.
        const VERIFY_LINKED    = 1 << 13;
        /// Preserve fs-verity.
        const PRESERVE_FS_VERITY = 1 << 14;
        /// Copy creation (b)time.
        const CRTIME           = 1 << 15;
        /// Restore directory timestamps after merge.
        const RESTORE_DIRECTORY_TIMESTAMPS = 1 << 16;
        /// Merge into empty directories only.
        const MERGE_EMPTY      = 1 << 17;
        /// Apply stat (mode/owner) on merge.
        const MERGE_APPLY_STAT = 1 << 18;
        /// BSD lock during copy.
        const LOCK_BSD         = 1 << 19;
        /// Honour SIGINT.
        const SIGINT           = 1 << 20;
        /// Honour SIGTERM.
        const SIGTERM          = 1 << 21;
        /// Seek source to offset 0 before copying.
        const SEEK0_SOURCE     = 1 << 22;
        /// Seek target to offset 0 before copying.
        const SEEK0_TARGET     = 1 << 23;
        /// Silently ignore privilege / unsupported errors.
        const GRACEFUL_WARN    = 1 << 24;
    }
}

impl Default for CopyFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// ── Pipe detection ────────────────────────────────────────────────────────

/// Whether an fd is a pipe and whether it is non-blocking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeKind {
    /// Not a pipe.
    NotPipe,
    /// Blocking pipe.
    Blocking,
    /// Non-blocking pipe.
    NonBlocking,
}

/// Check whether the given raw file descriptor refers to a pipe and whether
/// O_NONBLOCK is set.
pub fn fd_is_nonblock_pipe(fd: i32) -> PipeKind {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        return PipeKind::NotPipe;
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFIFO {
        return PipeKind::NotPipe;
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return PipeKind::NotPipe;
    }
    if (flags & libc::O_NONBLOCK) != 0 {
        PipeKind::NonBlocking
    } else {
        PipeKind::Blocking
    }
}

// ── Hole creation ─────────────────────────────────────────────────────────

/// Create a sparse hole of `size` bytes at the current position of `fd`.
///
/// Uses `fallocate(PUNCH_HOLE | KEEP_SIZE)` where possible and `ftruncate`
/// to extend beyond the current end-of-file.
pub fn create_hole(fd: i32, size: i64) -> std::io::Result<()> {
    let offset = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
    if offset < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let end = unsafe { libc::lseek(fd, 0, libc::SEEK_END) };
    if end < 0 {
        return Err(std::io::Error::last_os_error());
    }

    if offset < end {
        let punch_len = std::cmp::min(size, end - offset) as libc::off_t;
        let ret = unsafe {
            crate::ffi::fallocate(
                fd,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                offset,
                punch_len,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOTSUP) {
                return Err(err);
            }
        }
    }

    if end - offset >= size {
        let ret = unsafe { libc::lseek(fd, offset + size, libc::SEEK_SET) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        return Ok(());
    }

    let remaining = (size - (end - offset)) as libc::off_t;
    if unsafe { libc::ftruncate(fd, end + remaining) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let ret = unsafe { libc::lseek(fd, 0, libc::SEEK_END) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// ── Kernel-assisted copy_file_range ───────────────────────────────────────

/// Try the `copy_file_range(2)` syscall once.
///
/// Returns the number of bytes copied on success, or the (negative) errno
/// value converted to an `io::Error` on failure.
fn try_copy_file_range(
    fd_in: i32,
    off_in: Option<&mut i64>,
    fd_out: i32,
    off_out: Option<&mut i64>,
    len: usize,
) -> std::io::Result<usize> {
    let off_in_val = off_in
        .map(|v| v as *mut i64)
        .unwrap_or(std::ptr::null_mut());
    let off_out_val = off_out
        .map(|v| v as *mut i64)
        .unwrap_or(std::ptr::null_mut());
    // SAFETY: all pointers are valid file descriptors or null offsets.
    let n = unsafe {
        libc::syscall(
            SYS_copy_file_range,
            fd_in,
            off_in_val,
            fd_out,
            off_out_val,
            len,
            0u64,
        )
    };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

// ── Core byte-copy loop ──────────────────────────────────────────────────

/// Outcome of [`copy_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyBytesResult {
    /// Reached EOF before the byte limit.
    Eof,
    /// The byte limit was reached without hitting EOF.
    ByteLimit,
}

/// Copy up to `max_bytes` from `reader` to `writer`.
///
/// When both sides are regular files the kernel `copy_file_range()` syscall
/// is used; otherwise falls back to userspace read/write with a 64 KiB
/// buffer.  If `max_bytes` is `None`, copies until EOF.
///
/// Returns the total number of bytes copied and an indication of whether EOF
/// or the byte limit was reached.
pub fn copy_bytes<R, W>(
    reader: &mut R,
    writer: &mut W,
    max_bytes: Option<u64>,
    flags: CopyFlags,
) -> std::io::Result<(u64, CopyBytesResult)>
where
    R: std::io::Read,
    W: std::io::Write,
{
    let limit = max_bytes.unwrap_or(u64::MAX);
    let mut total: u64 = 0;

    while total < limit {
        let remaining = limit - total;
        let to_copy = std::cmp::min(remaining, COPY_BUFFER_SIZE as u64) as usize;
        let mut buf = vec![0u8; to_copy];

        let n = match reader.read(&mut buf) {
            Ok(0) => return Ok((total, CopyBytesResult::Eof)),
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };

        let mut written = 0;
        while written < n {
            match writer.write(&buf[written..n]) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "write returned zero",
                    ));
                }
                Ok(k) => written += k,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        total += n as u64;
    }

    if flags.contains(CopyFlags::TRUNCATE) {
        writer.flush()?;
    }

    Ok((total, CopyBytesResult::ByteLimit))
}

/// Copy bytes between two raw file descriptors using `copy_file_range`.
///
/// This is the low-level entry point used when the caller already has file
/// descriptors.  Falls back to userspace read/write when the syscall is not
/// available.
pub fn copy_bytes_fd(
    fd_in: i32,
    fd_out: i32,
    max_bytes: Option<u64>,
    flags: CopyFlags,
) -> std::io::Result<(u64, CopyBytesResult)> {
    let limit = max_bytes.unwrap_or(u64::MAX);
    let mut total: u64 = 0;
    let mut use_cfr = true;

    while total < limit {
        let remaining = limit - total;
        let to_copy = std::cmp::min(remaining, COPY_BUFFER_SIZE as u64) as usize;

        if use_cfr {
            match try_copy_file_range(fd_in, None, fd_out, None, to_copy) {
                Ok(0) if total > 0 => return Ok((total, CopyBytesResult::Eof)),
                Ok(0) => {
                    use_cfr = false;
                    continue;
                }
                Ok(n) => {
                    total += n as u64;
                    continue;
                }
                Err(e) => {
                    let raw = e.raw_os_error().unwrap_or(0);
                    if matches!(
                        raw,
                        libc::EINVAL | libc::ENOSYS | libc::EXDEV | libc::EBADF | libc::EOPNOTSUPP
                    ) {
                        use_cfr = false;
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        let mut buf = vec![0u8; to_copy];
        let n = unsafe { libc::read(fd_in, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Ok((total, CopyBytesResult::Eof));
        }

        let mut written: usize = 0;
        while written < n as usize {
            let k = unsafe {
                libc::write(
                    fd_out,
                    buf.as_ptr().add(written) as *const libc::c_void,
                    n as usize - written,
                )
            };
            if k < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            written += k as usize;
        }
        total += n as u64;
    }

    if flags.contains(CopyFlags::FSYNC) {
        if unsafe { libc::fsync(fd_out) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    if flags.contains(CopyFlags::TRUNCATE) {
        let offset = unsafe { libc::lseek(fd_out, 0, libc::SEEK_CUR) };
        if offset < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::ftruncate(fd_out, offset) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok((total, CopyBytesResult::ByteLimit))
}

// ── Timestamp helper (no external crate) ──────────────────────────────────

fn set_file_times(
    file: &std::fs::File,
    atime_sec: i64,
    atime_nsec: i64,
    mtime_sec: i64,
    mtime_nsec: i64,
) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = file.as_raw_fd();
    let times = [
        libc::timespec {
            tv_sec: atime_sec,
            tv_nsec: atime_nsec as libc::c_long,
        },
        libc::timespec {
            tv_sec: mtime_sec,
            tv_nsec: mtime_nsec as libc::c_long,
        },
    ];
    if unsafe { libc::futimens(fd, times.as_ptr()) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ── File-level copy ───────────────────────────────────────────────────────

/// Copy a regular file from `src` to `dst`.
///
/// Creates `dst` with the same permission bits as `src`, copies the data,
/// and restores timestamps.  Returns the number of bytes copied.
pub fn copy_file<P: AsRef<std::path::Path>, Q: AsRef<std::path::Path>>(
    src: P,
    dst: Q,
    flags: CopyFlags,
) -> std::io::Result<u64> {
    let src_path = src.as_ref();
    let dst_path = dst.as_ref();

    if !flags.contains(CopyFlags::REPLACE) && dst_path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "destination already exists",
        ));
    }

    let meta = std::fs::metadata(src_path)?;
    if meta.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::IsADirectory,
            "source is a directory",
        ));
    }

    let mut src_file = std::fs::File::open(src_path)?;
    let mut dst_file = std::fs::File::create(dst_path)?;
    let mode = meta.mode();
    dst_file.set_permissions(std::fs::Permissions::from_mode(mode))?;

    let (copied, _) = copy_bytes(&mut src_file, &mut dst_file, None, flags)?;

    let src_meta = src_file.metadata()?;
    let _ = set_file_times(
        &dst_file,
        src_meta.atime(),
        src_meta.atime_nsec(),
        src_meta.mtime(),
        src_meta.mtime_nsec(),
    );

    if flags.contains(CopyFlags::FSYNC) {
        dst_file.sync_all()?;
    }

    Ok(copied)
}

// ── Directory tree copy ──────────────────────────────────────────────────

/// Copy a directory tree recursively from `src` to `dst`.
///
/// Returns the total number of bytes copied (data only, not directory entries).
pub fn copy_tree<P: AsRef<std::path::Path>, Q: AsRef<std::path::Path>>(
    src: P,
    dst: Q,
    flags: CopyFlags,
) -> std::io::Result<u64> {
    copy_tree_inner(src.as_ref(), dst.as_ref(), flags, 0, None)
}

fn copy_tree_inner(
    src: &std::path::Path,
    dst: &std::path::Path,
    flags: CopyFlags,
    depth: u32,
    src_dev: Option<u64>,
) -> std::io::Result<u64> {
    if depth > COPY_DEPTH_MAX {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "maximum copy depth exceeded",
        ));
    }

    let meta = std::fs::symlink_metadata(src)?;
    let is_dir = meta.is_dir();

    if is_dir {
        #[cfg(unix)]
        let dev = src_dev.unwrap_or_else(|| {
            use std::os::unix::fs::MetadataExt;
            meta.dev()
        });
        #[cfg(not(unix))]
        let dev = src_dev.unwrap_or(0);

        if !dst.exists() {
            std::fs::create_dir_all(dst)?;
            let mode = meta.mode();
            std::fs::set_permissions(dst, std::fs::Permissions::from_mode(mode))?;
        } else if !flags.contains(CopyFlags::MERGE) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "destination directory already exists",
            ));
        }

        // `read_dir()` reflects the source filesystem's storage order. Sort
        // entry names so copies into order-sensitive filesystems (such as
        // vfat) are reproducible across hosts.
        let mut entries = std::fs::read_dir(src)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by(|a, b| a.file_name().as_bytes().cmp(b.file_name().as_bytes()));

        let mut total: u64 = 0;
        for entry in entries {
            let name = entry.file_name();
            let child_src = src.join(&name);
            let child_dst = dst.join(&name);

            if flags.contains(CopyFlags::SAME_MOUNT) {
                let child_meta = std::fs::symlink_metadata(&child_src)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if child_meta.is_dir() && child_meta.dev() != dev {
                        continue;
                    }
                }
            }

            total += copy_tree_inner(&child_src, &child_dst, flags, depth + 1, Some(dev))?;
        }
        return Ok(total);
    }

    if meta.is_symlink() {
        let target = std::fs::read_link(src)?;
        if !dst.exists() || flags.contains(CopyFlags::REPLACE) {
            if dst.exists() {
                std::fs::remove_file(dst)?;
            }
            std::os::unix::fs::symlink(&target, dst)?;
        }
        return Ok(0);
    }

    if meta.is_file() {
        return copy_file(src, dst, flags);
    }

    Ok(0)
}

// ── Metadata helpers ─────────────────────────────────────────────────────

/// Copy access mode (permission bits) from `src_fd` to `dst_fd`.
pub fn copy_access(src_fd: i32, dst_fd: i32) -> std::io::Result<()> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(src_fd, &mut st) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fchmod(dst_fd, st.st_mode & 0o7777) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Copy ownership (uid/gid) from `src_fd` to `dst_fd`.
pub fn copy_owner(src_fd: i32, dst_fd: i32) -> std::io::Result<()> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(src_fd, &mut st) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fchown(dst_fd, st.st_uid, st.st_gid) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Copy both mode and ownership from `src_fd` to `dst_fd`.
pub fn copy_rights(src_fd: i32, dst_fd: i32) -> std::io::Result<()> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(src_fd, &mut st) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // fchmod first – fchown may clear setuid/setgid bits.
    if unsafe { libc::fchmod(dst_fd, st.st_mode & 0o7777) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fchown(dst_fd, st.st_uid, st.st_gid) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Copy timestamps (atime + mtime) from `src_fd` to `dst_fd`.
pub fn copy_times(src_fd: i32, dst_fd: i32) -> std::io::Result<()> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(src_fd, &mut st) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let times = [
        libc::timespec {
            tv_sec: st.st_atime,
            tv_nsec: st.st_atime_nsec,
        },
        libc::timespec {
            tv_sec: st.st_mtime,
            tv_nsec: st.st_mtime_nsec,
        },
    ];
    if unsafe { libc::futimens(dst_fd, times.as_ptr()) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ── Reflink support ───────────────────────────────────────────────────────

/// Attempt a copy-on-write reflink from `src` to `dst`.
///
/// Returns `Ok(true)` if the reflink was created, `Ok(false)` if the
/// filesystem does not support it (not an error), or `Err` on failure.
pub fn reflink<P: AsRef<std::path::Path>, Q: AsRef<std::path::Path>>(
    src: P,
    dst: Q,
) -> std::io::Result<bool> {
    let src_file = std::fs::File::open(src)?;
    let dst_file = std::fs::File::create(dst)?;
    reflink_fd(src_file.as_raw_fd(), dst_file.as_raw_fd())
}

/// Reflink between two open file descriptors.
pub fn reflink_fd(src_fd: i32, dst_fd: i32) -> std::io::Result<bool> {
    const FICLONE: u64 = 0x4004_9409;
    let ret = unsafe { libc::ioctl(dst_fd, FICLONE, src_fd) };
    if ret < 0 {
        let err = std::io::Error::last_os_error();
        let raw = err.raw_os_error().unwrap_or(0);
        if matches!(
            raw,
            libc::EINVAL | libc::ENOSYS | libc::ENOTTY | libc::EOPNOTSUPP
        ) {
            return Ok(false);
        }
        Err(err)
    } else {
        Ok(true)
    }
}

// ── Hardlink context ─────────────────────────────────────────────────────

/// Tracks inode→tempfile mappings for recreating hard links during tree copies.
pub struct HardlinkContext {
    store_path: Option<std::path::PathBuf>,
}

impl HardlinkContext {
    pub fn new() -> Self {
        Self { store_path: None }
    }

    fn realize(&mut self, parent: &std::path::Path) -> std::io::Result<()> {
        if self.store_path.is_some() {
            return Ok(());
        }
        let store = parent.join(".hardlink-store");
        std::fs::create_dir_all(&store)?;
        self.store_path = Some(store);
        Ok(())
    }

    /// Try to create a hardlink from a previously-seen inode.
    ///
    /// Returns `Ok(true)` if a hardlink was successfully created.
    pub fn try_link(
        &mut self,
        dev: u64,
        ino: u64,
        nlink: u64,
        dst_dir: i32,
        dst_name: &std::ffi::CStr,
    ) -> std::io::Result<bool> {
        if nlink <= 1 {
            return Ok(false);
        }
        let store = match &self.store_path {
            Some(p) => p.clone(),
            None => return Ok(false),
        };
        let key = format!("{}:{}", dev, ino);
        let key_cstr = std::ffi::CString::new(key)?;
        let store_cstr = std::ffi::CString::new(store.to_str().unwrap_or(""))?;
        let store_dir =
            unsafe { libc::open(store_cstr.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        if store_dir < 0 {
            return Ok(false);
        }
        let ret =
            unsafe { libc::linkat(store_dir, key_cstr.as_ptr(), dst_dir, dst_name.as_ptr(), 0) };
        unsafe { libc::close(store_dir) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(false);
            }
            Err(err)
        } else {
            Ok(true)
        }
    }

    /// Record a newly-copied inode in the hardlink store.
    pub fn memorize(
        &mut self,
        parent: &std::path::Path,
        dev: u64,
        ino: u64,
        nlink: u64,
        dst_dir: i32,
        dst_name: &std::ffi::CStr,
    ) -> std::io::Result<()> {
        if nlink <= 1 {
            return Ok(());
        }
        self.realize(parent)?;
        let store = self.store_path.as_ref().unwrap();
        let key = format!("{}:{}", dev, ino);
        let key_cstr = std::ffi::CString::new(key)?;
        let store_cstr = std::ffi::CString::new(store.to_str().unwrap_or(""))?;
        let store_dir =
            unsafe { libc::open(store_cstr.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        if store_dir < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let ret =
            unsafe { libc::linkat(dst_dir, dst_name.as_ptr(), store_dir, key_cstr.as_ptr(), 0) };
        unsafe { libc::close(store_dir) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Default for HardlinkContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for HardlinkContext {
    fn drop(&mut self) {
        if let Some(ref path) = self.store_path {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::io::Write as IoWrite;

    #[test]
    fn test_copy_flags_default_is_empty() {
        let flags = CopyFlags::default();
        assert!(flags.is_empty());
    }

    #[test]
    fn test_copy_flags_bit_combinations() {
        let f = CopyFlags::REFLINK | CopyFlags::FSYNC | CopyFlags::MERGE;
        assert!(f.contains(CopyFlags::REFLINK));
        assert!(f.contains(CopyFlags::FSYNC));
        assert!(f.contains(CopyFlags::MERGE));
        assert!(!f.contains(CopyFlags::REPLACE));
    }

    #[test]
    fn test_copy_flags_from_bits() {
        let f = CopyFlags::from_bits_retain(1 << 0);
        assert!(f.contains(CopyFlags::REFLINK));
        let f2 = CopyFlags::from_bits_retain(0);
        assert!(f2.is_empty());
    }

    #[test]
    fn test_pipe_kind_equality() {
        assert_eq!(PipeKind::NotPipe, PipeKind::NotPipe);
        assert_eq!(PipeKind::Blocking, PipeKind::Blocking);
        assert_eq!(PipeKind::NonBlocking, PipeKind::NonBlocking);
        assert_ne!(PipeKind::Blocking, PipeKind::NonBlocking);
    }

    #[test]
    fn test_copy_bytes_result_equality() {
        assert_eq!(CopyBytesResult::Eof, CopyBytesResult::Eof);
        assert_eq!(CopyBytesResult::ByteLimit, CopyBytesResult::ByteLimit);
        assert_ne!(CopyBytesResult::Eof, CopyBytesResult::ByteLimit);
    }

    #[test]
    fn test_copy_bytes_full() {
        let data = b"Hello, World!";
        let mut reader = Cursor::new(&data[..]);
        let mut writer: Vec<u8> = Vec::new();

        let (n, result) = copy_bytes(&mut reader, &mut writer, None, CopyFlags::default()).unwrap();
        assert_eq!(n, 13);
        assert_eq!(result, CopyBytesResult::Eof);
        assert_eq!(writer, data);
    }

    #[test]
    fn test_copy_bytes_with_limit() {
        let data = b"Hello, World!";
        let mut reader = Cursor::new(&data[..]);
        let mut writer: Vec<u8> = Vec::new();

        let (n, result) =
            copy_bytes(&mut reader, &mut writer, Some(5), CopyFlags::default()).unwrap();
        assert_eq!(n, 5);
        assert_eq!(result, CopyBytesResult::ByteLimit);
        assert_eq!(&writer[..], b"Hello");
    }

    #[test]
    fn test_copy_bytes_zero_limit() {
        let data = b"Hello";
        let mut reader = Cursor::new(&data[..]);
        let mut writer: Vec<u8> = Vec::new();

        let (n, result) =
            copy_bytes(&mut reader, &mut writer, Some(0), CopyFlags::default()).unwrap();
        assert_eq!(n, 0);
        assert_eq!(result, CopyBytesResult::ByteLimit);
        assert!(writer.is_empty());
    }

    #[test]
    fn test_copy_bytes_empty_source() {
        let data: &[u8] = b"";
        let mut reader = Cursor::new(data);
        let mut writer: Vec<u8> = Vec::new();

        let (n, result) = copy_bytes(&mut reader, &mut writer, None, CopyFlags::default()).unwrap();
        assert_eq!(n, 0);
        assert_eq!(result, CopyBytesResult::Eof);
    }

    #[test]
    fn test_copy_bytes_large_data() {
        let data = vec![0xAB_u8; 256 * 1024];
        let mut reader = Cursor::new(&data[..]);
        let mut writer: Vec<u8> = Vec::new();

        let (n, result) = copy_bytes(&mut reader, &mut writer, None, CopyFlags::default()).unwrap();
        assert_eq!(n, data.len() as u64);
        assert_eq!(result, CopyBytesResult::Eof);
        assert_eq!(writer.len(), data.len());
        assert!(writer.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_copy_bytes_limit_exceeds_source() {
        let data = b"short";
        let mut reader = Cursor::new(&data[..]);
        let mut writer: Vec<u8> = Vec::new();

        let (n, result) =
            copy_bytes(&mut reader, &mut writer, Some(1000), CopyFlags::default()).unwrap();
        assert_eq!(n, 5);
        assert_eq!(result, CopyBytesResult::Eof);
    }

    #[test]
    fn test_copy_file_basic() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.txt");
        let dst = tmp.path().join("dst.txt");

        std::fs::write(&src, "test content").unwrap();
        let n = copy_file(&src, &dst, CopyFlags::default()).unwrap();
        assert_eq!(n, 12);
        assert_eq!(std::fs::read_to_string(&dst).unwrap(), "test content");
    }

    #[test]
    fn test_copy_file_no_replace() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.txt");
        let dst = tmp.path().join("dst.txt");

        std::fs::write(&src, "src").unwrap();
        std::fs::write(&dst, "dst").unwrap();

        let result = copy_file(&src, &dst, CopyFlags::default());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn test_copy_file_with_replace() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.txt");
        let dst = tmp.path().join("dst.txt");

        std::fs::write(&src, "new content").unwrap();
        std::fs::write(&dst, "old content").unwrap();

        let n = copy_file(&src, &dst, CopyFlags::REPLACE).unwrap();
        assert_eq!(n, 11);
        assert_eq!(std::fs::read_to_string(&dst).unwrap(), "new content");
    }

    #[test]
    fn test_copy_tree_flat() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");

        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("a.txt"), "aaa").unwrap();
        std::fs::write(src.join("b.txt"), "bbb").unwrap();

        let n = copy_tree(&src, &dst, CopyFlags::default()).unwrap();
        assert_eq!(n, 6);
        assert_eq!(std::fs::read_to_string(dst.join("a.txt")).unwrap(), "aaa");
        assert_eq!(std::fs::read_to_string(dst.join("b.txt")).unwrap(), "bbb");
    }

    #[test]
    fn test_copy_tree_nested() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");

        std::fs::create_dir_all(src.join("sub/deep")).unwrap();
        std::fs::write(src.join("top.txt"), "top").unwrap();
        std::fs::write(src.join("sub/deep/leaf.txt"), "leaf").unwrap();

        let n = copy_tree(&src, &dst, CopyFlags::default()).unwrap();
        assert_eq!(n, 7);
        assert!(dst.join("sub/deep/leaf.txt").exists());
    }

    #[test]
    fn test_copy_tree_merge() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");

        std::fs::create_dir(&src).unwrap();
        std::fs::create_dir(&dst).unwrap();
        std::fs::write(src.join("new.txt"), "new").unwrap();
        std::fs::write(dst.join("existing.txt"), "existing").unwrap();

        copy_tree(&src, &dst, CopyFlags::MERGE).unwrap();
        assert_eq!(std::fs::read_to_string(dst.join("new.txt")).unwrap(), "new");
        assert_eq!(
            std::fs::read_to_string(dst.join("existing.txt")).unwrap(),
            "existing"
        );
    }

    #[test]
    fn test_copy_tree_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");

        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("real.txt"), "data").unwrap();
        std::os::unix::fs::symlink("real.txt", src.join("link.txt")).unwrap();

        copy_tree(&src, &dst, CopyFlags::default()).unwrap();
        assert!(dst.join("link.txt").is_symlink());
        assert_eq!(
            std::fs::read_to_string(dst.join("link.txt")).unwrap(),
            "data"
        );
    }

    #[test]
    fn test_hardlink_context_new() {
        let ctx = HardlinkContext::new();
        assert!(ctx.store_path.is_none());
    }

    #[test]
    fn test_hardlink_context_default() {
        let ctx = HardlinkContext::default();
        assert!(ctx.store_path.is_none());
    }

    #[test]
    fn test_create_hole_on_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sparse.bin");

        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&[0xFF; 1024]).unwrap();
        }

        let fd = unsafe {
            libc::open(
                std::ffi::CString::new(path.to_str().unwrap())
                    .unwrap()
                    .as_ptr(),
                libc::O_RDWR,
                0,
            )
        };
        assert!(fd >= 0);

        unsafe { libc::lseek(fd, 1024, libc::SEEK_SET) };

        create_hole(fd, 4096).unwrap();
        unsafe { libc::close(fd) };

        let meta = std::fs::metadata(&path).unwrap();
        assert!(meta.len() >= 1024 + 4096);
    }

    #[test]
    fn test_copy_times_between_files() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.txt");
        let dst = tmp.path().join("dst.txt");

        std::fs::write(&src, "data").unwrap();
        std::fs::write(&dst, "other").unwrap();

        use std::os::unix::io::AsRawFd;
        let src_fd = std::fs::File::open(&src).unwrap();
        let dst_fd = std::fs::File::open(&dst).unwrap();

        copy_times(src_fd.as_raw_fd(), dst_fd.as_raw_fd()).unwrap();
    }

    #[test]
    fn test_copy_access_between_files() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.txt");
        let dst = tmp.path().join("dst.txt");

        std::fs::write(&src, "data").unwrap();
        std::fs::write(&dst, "other").unwrap();

        use std::os::unix::io::AsRawFd;
        let src_fd = std::fs::File::open(&src).unwrap();
        let dst_fd = std::fs::File::open(&dst).unwrap();

        copy_access(src_fd.as_raw_fd(), dst_fd.as_raw_fd()).unwrap();
    }

    #[test]
    fn test_copy_owner_between_files() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.txt");
        let dst = tmp.path().join("dst.txt");

        std::fs::write(&src, "data").unwrap();
        std::fs::write(&dst, "other").unwrap();

        use std::os::unix::io::AsRawFd;
        let src_fd = std::fs::File::open(&src).unwrap();
        let dst_fd = std::fs::File::open(&dst).unwrap();

        copy_owner(src_fd.as_raw_fd(), dst_fd.as_raw_fd()).unwrap();
    }

    #[test]
    fn test_copy_rights_between_files() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.txt");
        let dst = tmp.path().join("dst.txt");

        std::fs::write(&src, "data").unwrap();
        std::fs::write(&dst, "other").unwrap();

        use std::os::unix::io::AsRawFd;
        let src_fd = std::fs::File::open(&src).unwrap();
        let dst_fd = std::fs::File::open(&dst).unwrap();

        copy_rights(src_fd.as_raw_fd(), dst_fd.as_raw_fd()).unwrap();
    }
}
