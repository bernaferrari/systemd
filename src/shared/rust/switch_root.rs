// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/switch-root.c
//
// switch_root() implementation: pivot to a new root filesystem.
//
// Provides a safe Rust API for switching the root filesystem during
// system boot. Uses mount(2) and pivot_root(2) syscalls internally.

use std::ffi::{CStr, CString};
use std::path::Path;

// ── Flags ────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling switch_root behavior.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SwitchRootFlags: u32 {
        /// Destroy the old root if it is a temporary filesystem (tmpfs/ramfs).
        const DESTROY_OLD_ROOT = 1 << 0;
        /// Skip calling sync() before performing the switch.
        const DONT_SYNC = 1 << 1;
        /// Use recursive bind mount for /run instead of simple bind mount.
        const RECURSIVE_RUN = 1 << 2;
    }
}

// ── Mount constants ──────────────────────────────────────────────────────

/// Bind mount: create a mount at the same location.
#[cfg(target_os = "linux")]
const MS_BIND: u64 = libc::MS_BIND;

/// Recursive mount propagation.
#[cfg(target_os = "linux")]
const MS_REC: u64 = libc::MS_REC;

/// Atomically move a mount tree.
#[cfg(target_os = "linux")]
const MS_MOVE: u64 = 8192;

/// Make mount private to this mount namespace.
#[cfg(target_os = "linux")]
const MS_PRIVATE: u64 = 1 << 18;

/// Lazy detach: perform the unmount without blocking.
#[cfg(target_os = "linux")]
const MNT_DETACH: i32 = 2;

/// tmpfs magic number from linux/magic.h.
#[cfg(target_os = "linux")]
const TMPFS_MAGIC: u64 = 0x0102_1994;

/// ramfs magic number from linux/magic.h.
#[cfg(target_os = "linux")]
const RAMFS_MAGIC: u64 = 0x8584_58f6;

// ── Transfer table ───────────────────────────────────────────────────────

/// Entry describing a mount point to transfer from old root to new root.
#[cfg(target_os = "linux")]
struct TransferEntry {
    /// Source path on the old root.
    path: &'static str,
    /// Mount flags for normal operation.
    mount_flags: u64,
    /// Mount flags when RECURSIVE_RUN is set.
    mount_flags_recursive_run: u64,
}

/// Mount points that should be transferred during switch_root.
/// Ordered by dependency: core virtual filesystems first, then /run subdirs.
#[cfg(target_os = "linux")]
const TRANSFER_TABLE: &[TransferEntry] = &[
    TransferEntry {
        path: "/dev",
        mount_flags: MS_BIND | MS_REC,
        mount_flags_recursive_run: MS_BIND | MS_REC,
    },
    TransferEntry {
        path: "/sys",
        mount_flags: MS_BIND | MS_REC,
        mount_flags_recursive_run: MS_BIND | MS_REC,
    },
    TransferEntry {
        path: "/proc",
        mount_flags: MS_BIND | MS_REC,
        mount_flags_recursive_run: MS_BIND | MS_REC,
    },
    TransferEntry {
        path: "/run",
        mount_flags: MS_BIND,
        mount_flags_recursive_run: MS_BIND | MS_REC,
    },
    TransferEntry {
        path: "/run/credentials",
        mount_flags: MS_BIND | MS_REC,
        mount_flags_recursive_run: 0,
    },
    TransferEntry {
        path: "/run/host",
        mount_flags: MS_BIND | MS_REC,
        mount_flags_recursive_run: 0,
    },
];

// ── Path construction helpers (pure, cross-platform, testable) ───────────

/// Resolve the old root path after pivot: joins `new_root` and `old_root_after`.
///
/// Strips trailing slashes from `new_root` and leading slashes from
/// `old_root_after` to produce a clean joined path.
pub fn resolve_old_root_path(new_root: &str, old_root_after: &str) -> String {
    format!(
        "{}/{}",
        new_root.trim_end_matches('/'),
        old_root_after.trim_start_matches('/')
    )
}

/// Build the destination path for transferring a mount into the new root.
pub fn build_transfer_path(new_root: &str, mount_path: &str) -> String {
    format!(
        "{}/{}",
        new_root.trim_end_matches('/'),
        mount_path.trim_start_matches('/')
    )
}

/// Select the appropriate mount flags for a transfer entry based on flags.
#[cfg(target_os = "linux")]
fn select_mount_flags(entry: &TransferEntry, flags: SwitchRootFlags) -> u64 {
    if flags.contains(SwitchRootFlags::RECURSIVE_RUN) {
        entry.mount_flags_recursive_run
    } else {
        entry.mount_flags
    }
}

// ── Error type ───────────────────────────────────────────────────────────

/// Errors that can occur during switch_root operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchRootError {
    /// Failed to open a directory (contains errno value).
    OpenFailed(i32),
    /// Old root is not a temporary filesystem when DESTROY_OLD_ROOT is set.
    NotTemporaryFs,
    /// A mount(2) operation failed (contains errno value).
    MountFailed(i32),
    /// The pivot_root(2) syscall failed (contains errno value).
    PivotRootFailed(i32),
    /// fchdir(2) failed (contains errno value).
    FchdirFailed(i32),
    /// chroot(2) failed (contains errno value).
    ChrootFailed(i32),
    /// chdir(2) failed (contains errno value).
    ChdirFailed(i32),
    /// An invalid argument was provided (e.g. NUL byte in path).
    InvalidArgument,
}

impl std::fmt::Display for SwitchRootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenFailed(e) => write!(f, "failed to open directory: errno {e}"),
            Self::NotTemporaryFs => write!(f, "old root is not a temporary filesystem"),
            Self::MountFailed(e) => write!(f, "mount(2) failed: errno {e}"),
            Self::PivotRootFailed(e) => write!(f, "pivot_root(2) failed: errno {e}"),
            Self::FchdirFailed(e) => write!(f, "fchdir(2) failed: errno {e}"),
            Self::ChrootFailed(e) => write!(f, "chroot(2) failed: errno {e}"),
            Self::ChdirFailed(e) => write!(f, "chdir(2) failed: errno {e}"),
            Self::InvalidArgument => write!(f, "invalid argument"),
        }
    }
}

impl std::error::Error for SwitchRootError {}

// ── Internal helpers (Linux only) ────────────────────────────────────────

/// RAII guard for a raw file descriptor. Closes on drop.
#[cfg(target_os = "linux")]
struct RawFdGuard(i32);

#[cfg(target_os = "linux")]
impl RawFdGuard {
    /// Open a directory (O_DIRECTORY | O_CLOEXEC), returning an RAII guard.
    fn open_dir(path: &CStr) -> Result<Self, SwitchRootError> {
        // SAFETY: libc::open with valid NUL-terminated CStr and known flags.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if fd < 0 {
            Err(SwitchRootError::OpenFailed(current_errno()))
        } else {
            Ok(Self(fd))
        }
    }

    /// Open a path (O_PATH | O_DIRECTORY | O_CLOEXEC), returning an RAII guard.
    fn open_path(path: &CStr) -> Result<Self, SwitchRootError> {
        // SAFETY: libc::open with valid NUL-terminated CStr and known flags.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(SwitchRootError::OpenFailed(current_errno()))
        } else {
            Ok(Self(fd))
        }
    }

    fn as_raw(&self) -> i32 {
        self.0
    }

    /// Consume the guard without closing the fd, transferring ownership to the caller.
    fn into_raw(self) -> i32 {
        let fd = self.0;
        std::mem::forget(self);
        fd
    }
}

#[cfg(target_os = "linux")]
impl Drop for RawFdGuard {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: closing a valid file descriptor.
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

/// Get the current thread-local errno value.
#[cfg(target_os = "linux")]
fn current_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Check if the filesystem at the given fd is tmpfs or ramfs.
#[cfg(target_os = "linux")]
fn fd_is_temporary_fs(fd: i32) -> Result<bool, SwitchRootError> {
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: fstatfs with valid fd and initialized output buffer.
    if unsafe { libc::fstatfs(fd, &mut buf) } < 0 {
        return Err(SwitchRootError::OpenFailed(current_errno()));
    }
    let f_type = buf.f_type as u64;
    Ok(f_type == TMPFS_MAGIC || f_type == RAMFS_MAGIC)
}

/// Check whether a path is a mount point by comparing st_dev with its parent.
#[cfg(target_os = "linux")]
fn is_mount_point(path: &CStr) -> bool {
    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    let mut parent_stat_buf: libc::stat = unsafe { std::mem::zeroed() };

    // SAFETY: stat with valid NUL-terminated CStr and initialized buffer.
    if unsafe { libc::stat(path.as_ptr(), &mut stat_buf) } < 0 {
        return false;
    }

    let parent = match path.to_str() {
        Ok(s) => match Path::new(s).parent() {
            Some(p) => CString::new(p.to_string_lossy().as_ref()).unwrap_or_default(),
            None => return false,
        },
        Err(_) => return false,
    };

    // SAFETY: stat with valid NUL-terminated CStr and initialized buffer.
    if unsafe { libc::stat(parent.as_ptr(), &mut parent_stat_buf) } < 0 {
        return false;
    }

    stat_buf.st_dev != parent_stat_buf.st_dev
}

/// Create a directory (best-effort mkdir -p).
#[cfg(target_os = "linux")]
fn mkdir_p(path: &str, mode: libc::mode_t) {
    if let Ok(c_path) = CString::new(path) {
        // SAFETY: mkdir with valid NUL-terminated CStr and mode.
        unsafe {
            libc::mkdir(c_path.as_ptr(), mode);
        }
    }
}

/// Invoke the pivot_root(2) syscall via libc::syscall.
#[cfg(target_os = "linux")]
fn pivot_root_syscall(new_root: *const libc::c_char, put_old: *const libc::c_char) -> i32 {
    // SAFETY: syscall with pointers assumed valid by caller.
    unsafe { libc::syscall(libc::SYS_pivot_root, new_root, put_old) as i32 }
}

/// Remove all immediate children of a directory given by fd.
/// Takes ownership of fd (does not close it separately).
#[cfg(target_os = "linux")]
fn rm_rf_children(fd: i32) {
    // SAFETY: fdopendir takes ownership of fd; fd is valid.
    let dir = unsafe { libc::fdopendir(fd) };
    if dir.is_null() {
        unsafe {
            libc::close(fd);
        }
        return;
    }

    loop {
        // SAFETY: readdir on valid DIR pointer.
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }
        let entry = unsafe { &*entry };
        // SAFETY: d_name is NUL-terminated by the kernel.
        let name = unsafe { CStr::from_ptr(entry.d_name.as_ptr()) };
        let name_bytes = name.to_bytes();

        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }

        if let Ok(c_path) = CString::new(format!(
            "/proc/self/fd/{}/{}",
            fd,
            String::from_utf8_lossy(name_bytes)
        )) {
            // SAFETY: unlink with valid NUL-terminated CStr.
            unsafe {
                libc::unlink(c_path.as_ptr());
            }
        }
    }

    // SAFETY: closedir on valid DIR pointer.
    unsafe {
        libc::closedir(dir);
    }
}

// ── Core implementation ──────────────────────────────────────────────────

/// Perform a switch_root operation: pivot the root filesystem to `new_root`.
///
/// Transfers configured mount points (/dev, /proc, /sys, /run) from the old
/// root to the new root, then calls pivot_root(2) to make the new root the
/// filesystem root.
///
/// # Arguments
/// * `new_root` - Path to the new root directory.
/// * `old_root_after` - Optional path within new_root where the old root
///   will be placed after pivot. If `None`, the old root is detached.
/// * `flags` - Behavioral flags (see [`SwitchRootFlags`]).
///
/// # Errors
/// Returns [`SwitchRootError`] on failure. The filesystem state may be
/// partially modified on error — this is intended for PID 1 use only.
///
/// # Platform support
/// Only available on Linux. On other platforms, always returns an error.
#[cfg(target_os = "linux")]
pub fn switch_root(
    new_root: &str,
    old_root_after: Option<&str>,
    flags: SwitchRootFlags,
) -> Result<(), SwitchRootError> {
    let new_root_c = CString::new(new_root).map_err(|_| SwitchRootError::InvalidArgument)?;

    // Open the current root directory.
    let old_root_fd = RawFdGuard::open_dir(CStr::from_bytes_with_nul(b"/\0").unwrap())?;

    // Open the new root directory.
    let new_root_fd = RawFdGuard::open_path(&new_root_c)?;

    // Check if old root is temporary when DESTROY_OLD_ROOT is set.
    let old_root_is_tmp = if flags.contains(SwitchRootFlags::DESTROY_OLD_ROOT) {
        Some(fd_is_temporary_fs(old_root_fd.as_raw())?)
    } else {
        None
    };

    // Prepare the old_root_after directory if specified.
    let resolved_after = if let Some(after) = old_root_after {
        let resolved = resolve_old_root_path(new_root, after);
        mkdir_p(&resolved, 0o755);
        Some(resolved)
    } else {
        None
    };

    // Sync filesystems unless DONT_SYNC is set.
    if !flags.contains(SwitchRootFlags::DONT_SYNC) {
        // SAFETY: sync() takes no arguments and is always safe to call.
        unsafe {
            libc::sync();
        }
    }

    // Make the root mount private to prevent propagation.
    // SAFETY: mount with null source/type/data and known flags.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            b"/\0".as_ptr().cast(),
            std::ptr::null(),
            MS_REC | MS_PRIVATE,
            std::ptr::null(),
        )
    } < 0
    {
        return Err(SwitchRootError::MountFailed(current_errno()));
    }
    // old_root_fd and new_root_fd are closed by RAII if we return here.

    // Transfer configured mount points into the new root.
    for entry in TRANSFER_TABLE {
        let mf = select_mount_flags(entry, flags);
        if mf == 0 {
            continue;
        }

        let src_c = match CString::new(entry.path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Skip if source path doesn't exist.
        // SAFETY: access with valid NUL-terminated CStr.
        if unsafe { libc::access(src_c.as_ptr(), libc::F_OK) } < 0 {
            continue;
        }

        let dst = build_transfer_path(new_root, entry.path);
        mkdir_p(&dst, 0o755);

        let dst_c = match CString::new(dst.as_str()) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if is_mount_point(&dst_c) {
            continue;
        }

        // SAFETY: mount with valid NUL-terminated CStr pointers and known flags.
        if unsafe {
            libc::mount(
                src_c.as_ptr(),
                dst_c.as_ptr(),
                std::ptr::null(),
                mf,
                std::ptr::null(),
            )
        } < 0
        {
            return Err(SwitchRootError::MountFailed(current_errno()));
        }
    }

    // Change working directory to the new root.
    // SAFETY: fchdir with valid fd opened as directory.
    if unsafe { libc::fchdir(new_root_fd.as_raw()) } < 0 {
        return Err(SwitchRootError::FchdirFailed(current_errno()));
    }

    // Perform the pivot_root.
    let pivot_result = if let Some(ref after) = resolved_after {
        let after_c = CString::new(after.as_str()).map_err(|_| SwitchRootError::InvalidArgument)?;
        pivot_root_syscall(b".\0".as_ptr().cast(), after_c.as_ptr())
    } else {
        let dot = CString::new(".").unwrap();
        let r = pivot_root_syscall(dot.as_ptr(), dot.as_ptr());
        if r >= 0 {
            // SAFETY: umount2 with valid NUL-terminated CStr and known flag.
            unsafe {
                libc::umount2(dot.as_ptr(), MNT_DETACH);
            }
        }
        r
    };

    if pivot_result < 0 {
        // pivot_root failed; fall back to MS_MOVE + chroot.
        if let Some(ref after) = resolved_after {
            let after_c =
                CString::new(after.as_str()).map_err(|_| SwitchRootError::InvalidArgument)?;

            // Bind-mount the old root into the after location.
            // SAFETY: mount with valid NUL-terminated CStr pointers and known flags.
            if unsafe {
                libc::mount(
                    b"/\0".as_ptr().cast(),
                    after_c.as_ptr(),
                    std::ptr::null(),
                    MS_BIND | MS_REC,
                    std::ptr::null(),
                )
            } < 0
            {
                return Err(SwitchRootError::MountFailed(current_errno()));
            }
        }

        // Move the current root mount to "/".
        // SAFETY: mount with valid NUL-terminated CStr pointers and known flag.
        if unsafe {
            libc::mount(
                b".\0".as_ptr().cast(),
                b"/\0".as_ptr().cast(),
                std::ptr::null(),
                MS_MOVE,
                std::ptr::null(),
            )
        } < 0
        {
            return Err(SwitchRootError::MountFailed(current_errno()));
        }

        // chroot into the new root.
        // SAFETY: chroot with valid NUL-terminated CStr.
        if unsafe { libc::chroot(b".\0".as_ptr().cast()) } < 0 {
            return Err(SwitchRootError::ChrootFailed(current_errno()));
        }

        // Change directory to the new root.
        // SAFETY: chdir with valid NUL-terminated CStr.
        if unsafe { libc::chdir(b"/\0".as_ptr().cast()) } < 0 {
            return Err(SwitchRootError::ChdirFailed(current_errno()));
        }

        // Clean up old root if it was a temporary filesystem.
        match old_root_is_tmp {
            Some(true) => {
                let fd = old_root_fd.into_raw();
                rm_rf_children(fd);
            }
            _ => {
                // old_root_fd closed by RAII.
            }
        }
    }

    // new_root_fd closed by RAII.
    Ok(())
}

/// Returns an error indicating switch_root is not supported on this platform.
#[cfg(not(target_os = "linux"))]
pub fn switch_root(
    _new_root: &str,
    _old_root_after: Option<&str>,
    _flags: SwitchRootFlags,
) -> Result<(), SwitchRootError> {
    Err(SwitchRootError::InvalidArgument)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SwitchRootFlags ──────────────────────────────────────────────────

    #[test]
    fn test_flags_destroy_old_root() {
        let f = SwitchRootFlags::DESTROY_OLD_ROOT;
        assert!(f.contains(SwitchRootFlags::DESTROY_OLD_ROOT));
        assert!(!f.contains(SwitchRootFlags::DONT_SYNC));
        assert!(!f.contains(SwitchRootFlags::RECURSIVE_RUN));
        assert_eq!(f.bits(), 1);
    }

    #[test]
    fn test_flags_dont_sync() {
        let f = SwitchRootFlags::DONT_SYNC;
        assert!(!f.contains(SwitchRootFlags::DESTROY_OLD_ROOT));
        assert!(f.contains(SwitchRootFlags::DONT_SYNC));
        assert!(!f.contains(SwitchRootFlags::RECURSIVE_RUN));
        assert_eq!(f.bits(), 2);
    }

    #[test]
    fn test_flags_recursive_run() {
        let f = SwitchRootFlags::RECURSIVE_RUN;
        assert!(!f.contains(SwitchRootFlags::DESTROY_OLD_ROOT));
        assert!(!f.contains(SwitchRootFlags::DONT_SYNC));
        assert!(f.contains(SwitchRootFlags::RECURSIVE_RUN));
        assert_eq!(f.bits(), 4);
    }

    #[test]
    fn test_flags_combined() {
        let f = SwitchRootFlags::DESTROY_OLD_ROOT | SwitchRootFlags::DONT_SYNC;
        assert!(f.contains(SwitchRootFlags::DESTROY_OLD_ROOT));
        assert!(f.contains(SwitchRootFlags::DONT_SYNC));
        assert!(!f.contains(SwitchRootFlags::RECURSIVE_RUN));
        assert_eq!(f.bits(), 3);
    }

    #[test]
    fn test_flags_all() {
        let f = SwitchRootFlags::all();
        assert_eq!(f.bits(), 7);
        assert!(f.contains(SwitchRootFlags::DESTROY_OLD_ROOT));
        assert!(f.contains(SwitchRootFlags::DONT_SYNC));
        assert!(f.contains(SwitchRootFlags::RECURSIVE_RUN));
    }

    #[test]
    fn test_flags_empty() {
        let f = SwitchRootFlags::empty();
        assert_eq!(f.bits(), 0);
        assert!(f.is_empty());
    }

    #[test]
    fn test_flags_from_bits_truncate() {
        let f = SwitchRootFlags::from_bits_truncate(0xFF);
        assert_eq!(f.bits(), 7);
        assert!(f.contains(SwitchRootFlags::all()));
    }

    #[test]
    fn test_flags_intersects() {
        let a = SwitchRootFlags::DESTROY_OLD_ROOT | SwitchRootFlags::DONT_SYNC;
        let b = SwitchRootFlags::DONT_SYNC | SwitchRootFlags::RECURSIVE_RUN;
        assert!(a.intersects(b));
        assert!(a.intersects(SwitchRootFlags::DONT_SYNC));
        assert!(!a.intersects(SwitchRootFlags::RECURSIVE_RUN));
    }

    #[test]
    fn test_flags_contains_all() {
        let combined = SwitchRootFlags::all();
        assert!(combined.contains(SwitchRootFlags::DESTROY_OLD_ROOT));
        assert!(combined.contains(SwitchRootFlags::DONT_SYNC));
        assert!(combined.contains(SwitchRootFlags::RECURSIVE_RUN));
    }

    // ── Transfer table ───────────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_transfer_table_count() {
        assert_eq!(TRANSFER_TABLE.len(), 6);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_transfer_table_paths() {
        let paths: Vec<&str> = TRANSFER_TABLE.iter().map(|e| e.path).collect();
        assert_eq!(
            paths,
            [
                "/dev",
                "/sys",
                "/proc",
                "/run",
                "/run/credentials",
                "/run/host"
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_transfer_table_run_has_different_flags() {
        let run = &TRANSFER_TABLE[3];
        assert_eq!(run.path, "/run");
        assert_ne!(run.mount_flags, run.mount_flags_recursive_run);
        assert_eq!(run.mount_flags_recursive_run, MS_BIND | MS_REC);
    }

    // ── Path construction ────────────────────────────────────────────────

    #[test]
    fn test_resolve_old_root_path_basic() {
        assert_eq!(resolve_old_root_path("/sysroot", "old"), "/sysroot/old");
    }

    #[test]
    fn test_resolve_old_root_path_trailing_slash() {
        assert_eq!(resolve_old_root_path("/sysroot/", "/old"), "/sysroot/old");
        assert_eq!(resolve_old_root_path("/sysroot//", "//old"), "/sysroot/old");
    }

    #[test]
    fn test_build_transfer_path_basic() {
        assert_eq!(build_transfer_path("/sysroot", "/dev"), "/sysroot/dev");
    }

    #[test]
    fn test_build_transfer_path_nested() {
        assert_eq!(
            build_transfer_path("/sysroot", "/run/credentials"),
            "/sysroot/run/credentials"
        );
    }

    #[test]
    fn test_build_transfer_path_trailing_slash() {
        assert_eq!(build_transfer_path("/sysroot/", "/dev"), "/sysroot/dev");
        assert_eq!(build_transfer_path("/sysroot", "dev"), "/sysroot/dev");
    }

    // ── Error type ───────────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let e = SwitchRootError::InvalidArgument;
        assert!(!e.to_string().is_empty());
        assert!(e.to_string().contains("invalid"));

        let e = SwitchRootError::NotTemporaryFs;
        assert!(e.to_string().contains("temporary"));
    }

    #[test]
    fn test_error_equality() {
        assert_eq!(
            SwitchRootError::InvalidArgument,
            SwitchRootError::InvalidArgument
        );
        assert_ne!(
            SwitchRootError::InvalidArgument,
            SwitchRootError::NotTemporaryFs
        );
        assert_eq!(
            SwitchRootError::MountFailed(5),
            SwitchRootError::MountFailed(5)
        );
        assert_ne!(
            SwitchRootError::MountFailed(5),
            SwitchRootError::MountFailed(13)
        );
    }

    #[test]
    fn test_error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(SwitchRootError::MountFailed(5));
        assert!(e.to_string().contains("mount"));
    }

    #[test]
    fn test_error_debug() {
        let e = SwitchRootError::PivotRootFailed(22);
        let debug = format!("{e:?}");
        assert!(debug.contains("PivotRootFailed"));
        assert!(debug.contains("22"));
    }

    #[test]
    fn test_error_all_variants() {
        let variants = [
            SwitchRootError::OpenFailed(2),
            SwitchRootError::NotTemporaryFs,
            SwitchRootError::MountFailed(1),
            SwitchRootError::PivotRootFailed(1),
            SwitchRootError::FchdirFailed(1),
            SwitchRootError::ChrootFailed(1),
            SwitchRootError::ChdirFailed(1),
            SwitchRootError::InvalidArgument,
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
        assert_eq!(variants.len(), 8);
    }

    // ── Platform stub ────────────────────────────────────────────────────

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_switch_root_not_supported() {
        let result = switch_root("/sysroot", None, SwitchRootFlags::empty());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), SwitchRootError::InvalidArgument);
    }
}
