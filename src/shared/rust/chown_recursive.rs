// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/chown-recursive.c, src/shared/chown-recursive.h
//
// Recursive chown operations for directory trees.
//
// Provides functions to recursively change ownership (uid/gid) and
// permissions of files and directories.  The public API mirrors the C
// implementation: `path_chown_recursive` (by filesystem path) and
// `fd_chown_recursive` (by already-opened file descriptor).
//
// `unsafe` is used exclusively around raw syscalls (`fchown`, `fchmod`,
// `fremovexattr`, `fstat`).  All surrounding logic is safe Rust.

use crate::ffi::*;
use std::fs::{self, Metadata};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

// ── Constants ─────────────────────────────────────────────────────────────

/// Invalid UID sentinel (matches C's `UID_INVALID`).
pub const UID_INVALID: u32 = u32::MAX;

/// Invalid GID sentinel (matches C's `GID_INVALID`).
pub const GID_INVALID: u32 = u32::MAX;

/// Default permission mask — all permission bits.
pub const MODE_MASK_FULL: u32 = 0o7777;

/// POSIX ACL extended-attribute names removed before chown.
const ACL_XATTR_NAMES: &[&[u8]] = &[b"system.posix_acl_access\0", b"system.posix_acl_default\0"];

// ── Types ─────────────────────────────────────────────────────────────────

/// Controls which aspects of file metadata are changed during a recursive
/// chown operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChownOptions {
    /// UID to set. `None` means "don't change".
    pub uid: Option<u32>,
    /// GID to set. `None` means "don't change".
    pub gid: Option<u32>,
    /// Only permission bits set in this mask are applied to the mode.
    pub mode_mask: u32,
}

impl Default for ChownOptions {
    fn default() -> Self {
        Self {
            uid: None,
            gid: None,
            mode_mask: MODE_MASK_FULL,
        }
    }
}

impl ChownOptions {
    /// Options that change only the UID.
    pub fn new_uid(uid: u32) -> Self {
        Self {
            uid: Some(uid),
            ..Self::default()
        }
    }

    /// Options that change only the GID.
    pub fn new_gid(gid: u32) -> Self {
        Self {
            gid: Some(gid),
            ..Self::default()
        }
    }

    /// Options that change both UID and GID.
    pub fn new_uid_gid(uid: u32, gid: u32) -> Self {
        Self {
            uid: Some(uid),
            gid: Some(gid),
            ..Self::default()
        }
    }

    /// Builder: override the mode mask.
    pub fn with_mode_mask(mut self, mask: u32) -> Self {
        self.mode_mask = mask;
        self
    }

    /// True when no uid/gid change is requested *and* the mask covers all
    /// permission bits — equivalent to the C `nothing to do` early-return.
    pub fn is_noop(&self) -> bool {
        self.uid.is_none() && self.gid.is_none() && self.mode_mask == MODE_MASK_FULL
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

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

/// True if the metadata indicates a change is needed under the given options.
///
/// Mirrors the C shortcut check:
/// ```c
/// (!uid_is_valid(uid) || st.st_uid == uid) &&
/// (!gid_is_valid(gid) || st.st_gid == gid) &&
/// ((st.st_mode & ~mask & 07777) == 0)
/// ```
fn needs_change(meta: &Metadata, opts: &ChownOptions) -> bool {
    if let Some(uid) = opts.uid {
        if meta.uid() != uid {
            return true;
        }
    }
    if let Some(gid) = opts.gid {
        if meta.gid() != gid {
            return true;
        }
    }
    // Any permission bits set outside the mask?
    (meta.mode() as u32 & !opts.mode_mask & 0o7777) != 0
}

/// Remove POSIX ACL extended attributes from the inode behind `fd`.
///
/// Ignores `ENODATA` (no such xattr) and `ENOTSUP` (filesystem doesn't
/// support xattrs), but propagates other errors.
fn remove_acl_xattrs(fd: i32) -> io::Result<()> {
    for name in ACL_XATTR_NAMES {
        // SAFETY: `fd` stays owned by the caller, and every attribute name is
        // a static NUL-terminated byte string for the duration of the call.
        let ret = unsafe {
            #[cfg(target_os = "linux")]
            {
                libc::fremovexattr(fd, name.as_ptr().cast())
            }
            #[cfg(not(target_os = "linux"))]
            {
                // fremovexattr is Linux-only; no-op on other platforms.
                0_i32
            }
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            let code = err.raw_os_error().unwrap_or(0);
            if code != libc::ENODATA && code != libc::ENOTSUP {
                return Err(err);
            }
        }
    }
    Ok(())
}

// ── Core: single-item chown ───────────────────────────────────────────────

/// Change ownership and permissions of a single inode (identified by `fd`).
///
/// This is the Rust equivalent of C's `chown_one()`:
/// 1. Remove POSIX ACLs.
/// 2. Apply `mode & mask` via `fchmod`.
/// 3. Apply uid/gid via `fchown`.
fn chown_one_fd(fd: i32, meta: &Metadata, opts: &ChownOptions) -> io::Result<()> {
    remove_acl_xattrs(fd)?;

    let mode = (meta.mode() as u32 & 0o7777) & opts.mode_mask;
    let uid = opts.uid.unwrap_or(meta.uid());
    let gid = opts.gid.unwrap_or(meta.gid());

    // SAFETY: `fd` is valid and owned by the caller.
    if unsafe { libc::fchmod(fd, mode as libc::mode_t) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `fd` is valid and owned by the caller.
    if unsafe { libc::fchown(fd, uid, gid) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

// ── Core: recursive directory walk ────────────────────────────────────────

/// Recursively chown a directory tree.
///
/// Children are processed first (depth-first), then the directory itself —
/// matching the C `chown_recursive_internal()` semantics.
fn open_directory(path: &Path, follow_symlinks: bool) -> io::Result<fs::File> {
    let no_follow = if follow_symlinks { 0 } else { libc::O_NOFOLLOW };
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOATIME | no_follow)
        .open(path)
}

fn chown_recursive_dir(
    dir: &Path,
    opts: &ChownOptions,
    open_file: Option<fs::File>,
    original_meta: Option<&Metadata>,
) -> io::Result<bool> {
    let mut changed = false;
    let dir_file = match open_file {
        Some(file) => file,
        None => open_directory(dir, false)?,
    };
    let current_meta = dir_file.metadata()?;
    let dir_meta = original_meta.unwrap_or(&current_meta);

    let entries = fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;

        if meta.is_dir() {
            if chown_recursive_dir(&path, opts, None, None)? {
                changed = true;
            }
        } else if needs_change(&meta, opts) {
            let file = fs::File::open(&path)?;
            chown_one_fd(file.as_raw_fd(), &meta, opts)?;
            changed = true;
        }
    }

    // Chown the directory itself last.
    if needs_change(&dir_meta, opts) {
        chown_one_fd(dir_file.as_raw_fd(), dir_meta, opts)?;
        return Ok(true);
    }

    Ok(changed)
}

// ── Public API ────────────────────────────────────────────────────────────

/// Recursively change ownership and permissions of a directory tree by path.
///
/// If `follow_symlinks` is true the initial `path` resolution follows a final
/// symlink. `path` itself must resolve to a directory, matching the C
/// `O_DIRECTORY` entry point. Nested directory opens use `O_NOFOLLOW`; the
/// remaining non-directory traversal is still path-based (a documented P2).
///
/// Returns `Ok(true)` if any changes were made, `Ok(false)` if the shortcut
/// optimisation determined no work is needed, or an error.
pub fn path_chown_recursive(
    path: &Path,
    opts: &ChownOptions,
    follow_symlinks: bool,
) -> io::Result<bool> {
    // Match the C authority: this API is directory-only, opens before its
    // no-op check, and follows a final symlink only when explicitly asked.
    let file = open_directory(path, follow_symlinks)?;

    if opts.is_noop() {
        return Ok(false);
    }

    let meta = file.metadata()?;

    // Shortcut — mirrors the C early-return.
    if !needs_change(&meta, opts) {
        return Ok(false);
    }

    chown_recursive_dir(path, opts, Some(file), Some(&meta))
}

/// Recursively change ownership and permissions of a directory tree by fd.
///
/// The fd must refer to a directory; `ENOTDIR` is returned otherwise.
pub fn fd_chown_recursive<Fd: AsRawFd>(fd: &Fd, opts: &ChownOptions) -> io::Result<bool> {
    let raw = fd.as_raw_fd();

    // Stat first (before the directory check), matching C's ordering in
    // `fd_chown_recursive()`.
    let mut stat_buf = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat_buf` is writable, properly aligned output storage. `raw`
    // is borrowed from the caller and remains valid for this synchronous call.
    if unsafe { libc::fstat(raw, stat_buf.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstat(2) initialized the complete output struct.
    let stat_buf = unsafe { stat_buf.assume_init() };

    if (stat_buf.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "fd does not refer to a directory",
        ));
    }

    if opts.is_noop() {
        return Ok(false);
    }

    // Shortcut — same logic as in `path_chown_recursive`.
    let uid_ok = opts.uid.map_or(true, |u| stat_buf.st_uid == u);
    let gid_ok = opts.gid.map_or(true, |g| stat_buf.st_gid == g);
    let mode_ok = (stat_buf.st_mode as u32 & !opts.mode_mask & 0o7777) == 0;
    if uid_ok && gid_ok && mode_ok {
        return Ok(false);
    }

    // Resolve the fd to a path and delegate.
    let fd_path = std::path::PathBuf::from(format!("/proc/self/fd/{raw}"));
    path_chown_recursive(&fd_path, opts, false)
}

// ── Convenience wrappers ──────────────────────────────────────────────────

/// Recursively chown by path, changing only the UID.
pub fn chown_recursive_uid(path: &Path, uid: u32) -> io::Result<bool> {
    path_chown_recursive(path, &ChownOptions::new_uid(uid), false)
}

/// Recursively chown by path, changing only the GID.
pub fn chown_recursive_gid(path: &Path, gid: u32) -> io::Result<bool> {
    path_chown_recursive(path, &ChownOptions::new_gid(gid), false)
}

/// Recursively chown by path, changing both UID and GID.
pub fn chown_recursive_uid_gid(path: &Path, uid: u32, gid: u32) -> io::Result<bool> {
    path_chown_recursive(path, &ChownOptions::new_uid_gid(uid, gid), false)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // ── ChownOptions construction ──────────────────────────────────────

    #[test]
    fn test_default_options() {
        let o = ChownOptions::default();
        assert_eq!(o.uid, None);
        assert_eq!(o.gid, None);
        assert_eq!(o.mode_mask, MODE_MASK_FULL);
    }

    #[test]
    fn test_new_uid() {
        let o = ChownOptions::new_uid(1000);
        assert_eq!(o.uid, Some(1000));
        assert_eq!(o.gid, None);
        assert_eq!(o.mode_mask, MODE_MASK_FULL);
    }

    #[test]
    fn test_new_gid() {
        let o = ChownOptions::new_gid(100);
        assert_eq!(o.uid, None);
        assert_eq!(o.gid, Some(100));
        assert_eq!(o.mode_mask, MODE_MASK_FULL);
    }

    #[test]
    fn test_new_uid_gid() {
        let o = ChownOptions::new_uid_gid(1000, 100);
        assert_eq!(o.uid, Some(1000));
        assert_eq!(o.gid, Some(100));
        assert_eq!(o.mode_mask, MODE_MASK_FULL);
    }

    #[test]
    fn test_with_mode_mask() {
        let o = ChownOptions::new_uid(0).with_mode_mask(0o0755);
        assert_eq!(o.uid, Some(0));
        assert_eq!(o.mode_mask, 0o0755);
    }

    #[test]
    fn test_options_clone_and_eq() {
        let a = ChownOptions::new_uid_gid(1, 2).with_mode_mask(0o0700);
        let b = a;
        assert_eq!(a, b);
    }

    // ── Validity helpers ───────────────────────────────────────────────

    #[test]
    fn test_uid_is_valid() {
        assert!(uid_is_valid(0));
        assert!(uid_is_valid(1000));
        assert!(!uid_is_valid(UID_INVALID));
        assert!(!uid_is_valid(u32::MAX));
    }

    #[test]
    fn test_gid_is_valid() {
        assert!(gid_is_valid(0));
        assert!(gid_is_valid(100));
        assert!(!gid_is_valid(GID_INVALID));
        assert!(!gid_is_valid(u32::MAX));
    }

    // ── Noop detection ─────────────────────────────────────────────────

    #[test]
    fn test_is_noop_default() {
        assert!(ChownOptions::default().is_noop());
    }

    #[test]
    fn test_is_noop_with_uid() {
        assert!(!ChownOptions::new_uid(1000).is_noop());
    }

    #[test]
    fn test_is_noop_with_restricted_mask() {
        let o = ChownOptions::default().with_mode_mask(0o0755);
        assert!(!o.is_noop());
    }

    // ── needs_change logic ─────────────────────────────────────────────

    /// Helper: create a temp file and return (path, metadata).
    fn tmp_file() -> (tempfile::TempDir, std::path::PathBuf, Metadata) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        fs::write(&p, "x").unwrap();
        let m = fs::symlink_metadata(&p).unwrap();
        (dir, p, m)
    }

    #[test]
    fn test_needs_change_all_match() {
        let (_d, _p, m) = tmp_file();
        let opts = ChownOptions {
            uid: Some(m.uid()),
            gid: Some(m.gid()),
            mode_mask: MODE_MASK_FULL,
        };
        assert!(!needs_change(&m, &opts));
    }

    #[test]
    fn test_needs_change_uid_mismatch() {
        let (_d, _p, m) = tmp_file();
        let other = if m.uid() == 0 { 1 } else { 0 };
        assert!(needs_change(&m, &ChownOptions::new_uid(other)));
    }

    #[test]
    fn test_needs_change_gid_mismatch() {
        let (_d, _p, m) = tmp_file();
        let other = if m.gid() == 0 { 1 } else { 0 };
        assert!(needs_change(&m, &ChownOptions::new_gid(other)));
    }

    #[test]
    fn test_needs_change_mode_outside_mask() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        fs::write(&p, "x").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o0777)).unwrap();
        let m = fs::symlink_metadata(&p).unwrap();

        // Mask that drops other-write — file has 0o0777, mask is 0o0775
        let opts = ChownOptions {
            uid: Some(m.uid()),
            gid: Some(m.gid()),
            mode_mask: 0o0775,
        };
        assert!(needs_change(&m, &opts));
    }

    // ── Path-based operations ──────────────────────────────────────────

    #[test]
    fn test_path_chown_nonexistent() {
        let r = path_chown_recursive(Path::new("/no/such/path"), &ChownOptions::new_uid(0), false);
        assert!(r.is_err());
    }

    #[test]
    fn test_path_chown_noop_default_opts() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("d");
        fs::create_dir(&sub).unwrap();
        assert_eq!(
            path_chown_recursive(&sub, &ChownOptions::default(), false).unwrap(),
            false
        );
    }

    #[test]
    fn test_path_chown_noop_already_correct() {
        let (_d, p, m) = tmp_file();
        let opts = ChownOptions {
            uid: Some(m.uid()),
            gid: Some(m.gid()),
            mode_mask: MODE_MASK_FULL,
        };
        // Shortcut: already matches, should return false without touching the fs.
        assert_eq!(path_chown_recursive(&p, &opts, false).unwrap(), false);
    }

    #[test]
    fn test_path_chown_single_file_does_not_panic() {
        let (_d, p, _) = tmp_file();
        // May succeed (root) or fail (EPERM) — must not panic either way.
        let _ = path_chown_recursive(&p, &ChownOptions::new_uid(65534), false);
    }

    #[test]
    fn test_path_chown_empty_dir_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("empty");
        fs::create_dir(&sub).unwrap();
        let _ = path_chown_recursive(&sub, &ChownOptions::new_uid(65534), false);
    }

    #[test]
    fn test_path_chown_nested_tree_does_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let deep = dir.path().join("a/b/c");
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("f"), "data").unwrap();
        let _ = path_chown_recursive(
            dir.path().join("a").as_path(),
            &ChownOptions::new_uid_gid(65534, 65534),
            false,
        );
    }

    // ── fd-based operations ────────────────────────────────────────────

    #[test]
    fn test_fd_chown_regular_file_rejects() {
        let (_d, p, _) = tmp_file();
        let file = fs::File::open(&p).unwrap();
        let r = fd_chown_recursive(&file, &ChownOptions::new_uid(0));
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::NotADirectory);
    }

    #[test]
    fn test_fd_chown_noop_default_opts() {
        let dir = tempfile::tempdir().unwrap();
        let d = fs::File::open(dir.path()).unwrap();
        // Default opts = noop → should return false without error.
        assert_eq!(
            fd_chown_recursive(&d, &ChownOptions::default()).unwrap(),
            false
        );
    }

    // ── Convenience wrappers ───────────────────────────────────────────

    #[test]
    fn test_convenience_wrappers_do_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x");
        fs::create_dir(&p).unwrap();
        let _ = chown_recursive_uid(&p, 65534);
        let _ = chown_recursive_gid(&p, 65534);
        let _ = chown_recursive_uid_gid(&p, 65534, 65534);
    }
}
