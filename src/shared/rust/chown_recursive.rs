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
// `unsafe` is confined to small syscall, descriptor-ownership, and libc
// directory-stream boundaries. All traversal and policy decisions remain safe
// Rust.

use crate::ffi::*;
use std::ffi::{CStr, CString};
use std::fs::{self, Metadata};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
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

fn proc_fd_path(fd: RawFd) -> CString {
    CString::new(format!("/proc/self/fd/{fd}")).expect("proc fd path contains no NUL")
}

fn errno_is_xattr_absent(code: libc::c_int) -> bool {
    code == libc::ENODATA
        || code == libc::ENOENT
        || code == libc::EOPNOTSUPP
        || code == libc::ENOTTY
        || code == libc::ENOSYS
        || code == libc::EAFNOSUPPORT
        || code == libc::EPFNOSUPPORT
        || code == libc::EPROTONOSUPPORT
        || code == libc::ESOCKTNOSUPPORT
        || code == libc::ENOPROTOOPT
}

/// Remove POSIX ACL extended attributes from the inode behind `fd`.
///
/// Ignores the same "xattr absent or unsupported" errno family as the C
/// `ERRNO_IS_NEG_XATTR_ABSENT()` helper, but propagates other errors.
fn remove_acl_xattrs(fd: RawFd) -> io::Result<()> {
    for name in ACL_XATTR_NAMES {
        // SAFETY: `fd` stays owned by the caller, and every attribute name is
        // a static NUL-terminated byte string for the duration of the call.
        let mut ret = unsafe {
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

        if ret < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF) {
            // O_PATH descriptors deliberately reject fremovexattr(2). The
            // procfs magic link still names the pinned inode, so this does not
            // reopen the directory entry and cannot be redirected by rename.
            let fd_path = proc_fd_path(fd);
            // SAFETY: both arguments are valid NUL-terminated strings for the
            // duration of this synchronous call.
            ret = unsafe { libc::removexattr(fd_path.as_ptr(), name.as_ptr().cast()) };
        }

        if ret < 0 {
            let err = io::Error::last_os_error();
            let code = err.raw_os_error().unwrap_or(0);
            if !errno_is_xattr_absent(code) {
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
/// 2. If ownership changes, temporarily tighten the mode as needed.
/// 3. Apply uid/gid through the pinned descriptor.
/// 4. Restore `mode & mask`, including bits implicitly cleared by chown.
fn chmod_fd(fd: RawFd, mode: libc::mode_t) -> io::Result<()> {
    // SAFETY: `fd` is valid and borrowed for this synchronous call.
    if unsafe { libc::fchmod(fd, mode) } >= 0 {
        return Ok(());
    }

    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::EBADF) {
        return Err(err);
    }

    // fchmod(2) rejects O_PATH descriptors. Like systemd's fchmod_opath(),
    // address the already-pinned inode through procfs instead of reopening
    // the mutable directory entry.
    let fd_path = proc_fd_path(fd);
    // SAFETY: `fd_path` is a valid NUL-terminated path and `mode` is passed by
    // value.
    if unsafe { libc::chmod(fd_path.as_ptr(), mode) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn chown_one_fd(fd: RawFd, meta: &Metadata, opts: &ChownOptions) -> io::Result<()> {
    let is_symlink = meta.file_type().is_symlink();
    remove_acl_xattrs(fd)?;

    let old_mode = meta.mode() as u32 & 0o7777;
    let new_mode = old_mode & opts.mode_mask;
    let do_chown = opts.uid.is_some_and(|uid| uid != meta.uid())
        || opts.gid.is_some_and(|gid| gid != meta.gid());
    let do_chmod = !is_symlink && (old_mode != new_mode || do_chown);

    // Tighten permissions before changing ownership, then restore the desired
    // mode afterwards. This preserves setuid/setgid bits cleared by chown and
    // never temporarily grants permissions outside either the old or new mode.
    if do_chown && do_chmod {
        let minimal = old_mode & new_mode;
        if minimal != old_mode {
            chmod_fd(fd, minimal as libc::mode_t)?;
        }
    }

    if do_chown {
        let uid = opts.uid.unwrap_or(UID_INVALID);
        let gid = opts.gid.unwrap_or(GID_INVALID);
        // SAFETY: `fd` names the pinned inode, the empty pathname is
        // NUL-terminated, and AT_EMPTY_PATH explicitly requests fd operation.
        if unsafe { libc::fchownat(fd, c"".as_ptr(), uid, gid, libc::AT_EMPTY_PATH) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    if do_chmod {
        chmod_fd(fd, new_mode as libc::mode_t)?;
    }

    Ok(())
}

// ── Core: recursive directory walk ────────────────────────────────────────

fn open_directory(path: &Path, follow_symlinks: bool) -> io::Result<fs::File> {
    let no_follow = if follow_symlinks { 0 } else { libc::O_NOFOLLOW };
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOATIME | no_follow)
        .open(path)
}

fn openat_file(dir_fd: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<fs::File> {
    // SAFETY: `dir_fd` stays borrowed, `name` is NUL-terminated, and openat
    // returns a new descriptor that is immediately transferred to `File`.
    let fd = unsafe { libc::openat(dir_fd, name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is newly owned by this function and has not been wrapped.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn duplicate_fd(fd: RawFd) -> io::Result<fs::File> {
    // SAFETY: fcntl borrows `fd` and returns a separately owned descriptor.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `duplicate` is newly owned and has not been wrapped elsewhere.
    Ok(unsafe { fs::File::from_raw_fd(duplicate) })
}

struct DirStream(*mut libc::DIR);

impl DirStream {
    fn from_file(file: fs::File) -> io::Result<Self> {
        let fd = file.as_raw_fd();
        // SAFETY: fdopendir takes ownership only on success. `file` is
        // forgotten in that case and otherwise closes the descriptor.
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            return Err(io::Error::last_os_error());
        }
        std::mem::forget(file);
        Ok(Self(stream))
    }

    fn fd(&self) -> RawFd {
        // SAFETY: `self.0` remains a live DIR until Drop.
        unsafe { libc::dirfd(self.0) }
    }

    fn next_name(&mut self) -> io::Result<Option<CString>> {
        // SAFETY: this module targets Linux; setting thread-local errno before
        // readdir lets a null result be distinguished from end-of-directory.
        unsafe { *libc::__errno_location() = 0 };
        // SAFETY: `self.0` is a live DIR and this method has exclusive access
        // while readdir advances its internal position.
        let entry = unsafe { libc::readdir(self.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(0) {
                Ok(None)
            } else {
                Err(error)
            };
        }

        // SAFETY: d_name is NUL-terminated for a successful readdir result;
        // copy it before the next call may invalidate the storage.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        Ok(Some(name.to_owned()))
    }
}

impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: `self.0` is owned by this wrapper and closed exactly once.
        unsafe { libc::closedir(self.0) };
    }
}

/// Recursively chown a directory tree.
///
/// Every child is opened relative to the already-open parent with
/// O_PATH|O_NOFOLLOW before it is inspected. Children are processed first,
/// then the directory itself, matching `chown_recursive_internal()`.
fn chown_recursive_dir(
    dir_file: fs::File,
    dir_meta: &Metadata,
    opts: &ChownOptions,
) -> io::Result<bool> {
    let mut stream = DirStream::from_file(dir_file)?;

    while let Some(name) = stream.next_name()? {
        if name.as_bytes() == b"." || name.as_bytes() == b".." {
            continue;
        }

        let child = openat_file(
            stream.fd(),
            &name,
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )?;
        let child_meta = child.metadata()?;

        if child_meta.is_dir() {
            let subdir = openat_file(
                child.as_raw_fd(),
                c".",
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOATIME,
            )?;
            chown_recursive_dir(subdir, &child_meta, opts)?;
        } else {
            chown_one_fd(child.as_raw_fd(), &child_meta, opts)?;
        }
    }

    // Chown the directory itself last.
    chown_one_fd(stream.fd(), dir_meta, opts)?;

    // C's chown_one() reports success as a change even when fchmod_and_chown()
    // finds the inode already correct; mirror that observable return value.
    Ok(true)
}

// ── Public API ────────────────────────────────────────────────────────────

/// Recursively change ownership and permissions of a directory tree by path.
///
/// If `follow_symlinks` is true the initial `path` resolution follows a final
/// symlink. `path` itself must resolve to a directory, matching the C
/// `O_DIRECTORY` entry point. All descendants are pinned and manipulated
/// descriptor-relatively without following symlinks.
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

    chown_recursive_dir(file, &meta, opts)
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

    // fdopendir takes ownership, so duplicate the caller's descriptor exactly
    // as the C implementation does.
    let duplicate = duplicate_fd(raw)?;
    let meta = duplicate.metadata()?;
    chown_recursive_dir(duplicate, &meta, opts)
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
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("d");
        fs::create_dir(&p).unwrap();
        let m = fs::symlink_metadata(&p).unwrap();
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
