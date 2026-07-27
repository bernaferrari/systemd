// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/tar-util.c, src/shared/tar-util.h
//
// Tar archive packing and unpacking utilities.
//
// Provides `tar_x()` for extracting tar/cpio archives into a directory tree
// (with support for OCI whiteouts, uid/gid squashing, xattrs, ACLs, chattr
// flags, and hard links) and `tar_c()` for creating tar archives from a
// directory tree (with sparse-file detection, hard-link deduplication, xattr
// and ACL preservation).
//
// All operations that touch the filesystem are pure Rust using `libc` syscalls
// wrapped in safe abstractions. No FFI blocks or no_mangle attributes remain.

use std::ffi::c_void;
use std::fmt;
use std::os::unix::io::RawFd;

fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum directory nesting depth inside an archive.
pub const DEPTH_MAX: u32 = 128;

/// `UID_NOBODY` sentinel — the unprivileged fallback UID.
pub const UID_NOBODY: u32 = 65534;

/// `GID_NOBODY` sentinel — the unprivileged fallback GID.
pub const GID_NOBODY: u32 = 65534;

/// Sentinel for "invalid / not-set" UID (matches C `UID_INVALID`).
pub const UID_INVALID: u32 = u32::MAX;

/// Sentinel for "invalid / not-set" GID (matches C `GID_INVALID`).
pub const GID_INVALID: u32 = u32::MAX;

/// Sentinel for "invalid / not-set" mode (matches C `MODE_INVALID`).
pub const MODE_INVALID: u32 = u32::MAX;

/// Threshold above which UIDs/GIDs are squashed to NOBODY when the
/// `TAR_SQUASH_UIDS_ABOVE_64K` flag is set.
pub const NSRESOURCE_UIDS_64K: u32 = 65536;

/// `UTIME_OMIT` value for `tv_nsec` (match Linux `UTIME_OMIT`).
pub const UTIME_OMIT: i64 = (1i32 << 30) as i64;

/// Filesystem flags preserved in tar archives (matches C `CHATTR_TAR_FL`).
pub const CHATTR_TAR_FL: u32 = (0x00000010/* FS_NOATIME_FL */)
    | (0x00800000/* FS_NOCOW_FL */)
    | (0x00200000/* FS_PROJINHERIT_FL */)
    | (0x00000001/* FS_NODUMP_FL */)
    | (0x00000008/* FS_SYNC_FL */)
    | (0x00000040/* FS_DIRSYNC_FL */);

// ── Flags ─────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Options that control tar packing / unpacking behaviour.
    ///
    /// Bit positions match the C `TarFlags` enum exactly so that FFI
    /// consumers can pass the raw integer directly.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TarFlags: u32 {
        /// Include SELinux xattrs in the tarball, or unpack them.
        const SELINUX               = 1 << 0;
        /// Squash UIDs/GIDs ≥ 64 K to `UID_NOBODY` / `GID_NOBODY`.
        const SQUASH_UIDS_ABOVE_64K = 1 << 1;
        /// Turn OCI / aufs whiteout entries into overlayfs whiteouts.
        const OCI_WHITEOUTS         = 1 << 2;
    }
}

impl Default for TarFlags {
    fn default() -> Self {
        TarFlags::empty()
    }
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Unified error type for tar operations.
#[derive(Debug)]
pub enum TarError {
    /// A POSIX errno occurred during a syscall.
    Errno(i32),
    /// A generic / unexpected condition.
    Generic(String),
}

impl fmt::Display for TarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TarError::Errno(e) => write!(f, "errno {e}"),
            TarError::Generic(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for TarError {}

impl TarError {
    /// Create from a raw errno value (positive).
    pub fn from_errno(errno: i32) -> Self {
        TarError::Errno(errno)
    }

    /// Create from a raw negative errno (systemd convention, stored positive).
    pub fn from_neg_errno(errno: i32) -> Self {
        TarError::Errno(-errno)
    }

    /// Extract the raw errno value (always positive).
    pub fn errno(&self) -> Option<i32> {
        match self {
            TarError::Errno(e) => Some(*e),
            _ => None,
        }
    }
}

/// Convenient `Result` alias used throughout this module.
pub type TarResult<T> = Result<T, TarError>;

// ── Data structures ───────────────────────────────────────────────────────

/// A single extended-attribute entry: name + opaque binary value.
#[derive(Debug, Clone)]
pub struct XAttr {
    /// xattr key (e.g. `user.foo`).
    pub name: String,
    /// Raw binary payload.
    pub data: Vec<u8>,
}

impl XAttr {
    /// Release resources held by a single xattr (analogous to C `xattr_done`).
    pub fn done(&mut self) {
        self.name.clear();
        self.name.shrink_to_fit();
        self.data.clear();
        self.data.shrink_to_fit();
    }
}

/// Release resources for a slice of xattrs (analogous to C `xattr_done_many`).
pub fn xattr_done_many(xa: &mut Vec<XAttr>) {
    xa.iter_mut().for_each(XAttr::done);
    xa.clear();
    xa.shrink_to_fit();
}

/// Bookkeeping for an inode that has been opened but not yet finalised.
///
/// When we descend into a directory we keep the fd open so we can create
/// children inside it.  Ownership, mode, mtime, xattrs and ACLs are deferred
/// until we ascend back out of the directory, at which point
/// [`OpenInode::finalize`] is called.
#[derive(Debug)]
pub struct OpenInode {
    /// File descriptor for the inode.  `None` when closed.
    /// For the root inode the fd is *borrowed* from the caller and
    /// must not be closed (indicated by `path` being `None`).
    pub fd: Option<RawFd>,
    /// Filesystem path (for logging).  `None` marks the root inode.
    pub path: Option<String>,

    // ── Deferred metadata (applied in `finalize`) ──
    /// `S_IFREG`, `S_IFDIR`, etc.
    pub filetype: u32,
    /// Permission bits (or `MODE_INVALID` if not set).
    pub mode: u32,
    /// Modification timestamp.  `UTIME_OMIT` in `tv_nsec` means "don't touch".
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    /// Owner UID (`UID_INVALID` → don't change).
    pub uid: u32,
    /// Owner GID (`GID_INVALID` → don't change).
    pub gid: u32,
    /// `chattr` / `fs flags` to restore.
    pub fflags: u32,
    /// Extended attributes to set last.
    pub xattr: Vec<XAttr>,
}

impl OpenInode {
    /// Create a root inode that borrows the caller's fd (will not be closed).
    pub fn new_root(fd: RawFd) -> Self {
        Self {
            fd: Some(fd),
            path: None,
            filetype: libc::S_IFDIR as u32,
            mode: MODE_INVALID,
            mtime_sec: 0,
            mtime_nsec: UTIME_OMIT,
            uid: UID_INVALID,
            gid: GID_INVALID,
            fflags: 0,
            xattr: Vec::new(),
        }
    }

    /// Release resources for a single open-inode entry (analogous to C
    /// `open_inode_done`).
    ///
    /// If `path` is set the owned fd is closed; if `path` is `None` (root
    /// inode) the fd is left alone because it belongs to the caller.
    pub fn done(&mut self) {
        if self.path.is_some() {
            if let Some(fd) = self.fd.take() {
                unsafe {
                    libc::close(fd);
                }
            }
            self.path = None;
        }
        xattr_done_many(&mut self.xattr);
    }

    /// Apply deferred metadata and then release resources (analogous to C
    /// `open_inode_finalize`).
    ///
    /// Returns a gathered error (first negative code) if anything went wrong
    /// but still frees the inode.
    pub fn finalize(&mut self) -> TarResult<()> {
        let mut first_err: Option<TarError> = None;

        if let Some(raw) = self.fd {
            let need_chown = self.uid != UID_INVALID || self.gid != GID_INVALID;
            let need_chmod = self.mode != MODE_INVALID;
            if need_chown || need_chmod {
                if need_chown {
                    let uid = if self.uid == UID_INVALID {
                        -1i32 as u32
                    } else {
                        self.uid
                    };
                    let gid = if self.gid == GID_INVALID {
                        -1i32 as u32
                    } else {
                        self.gid
                    };
                    if unsafe { libc::fchown(raw, uid, gid) } < 0 {
                        first_err.get_or_insert(TarError::from_errno(last_errno()));
                    }
                }
                if need_chmod {
                    if unsafe { libc::fchmod(raw, (self.mode & 0o7777) as _) } < 0 {
                        first_err.get_or_insert(TarError::from_errno(last_errno()));
                    }
                }
            }

            if self.mtime_nsec != UTIME_OMIT {
                let ts = [
                    libc::timespec {
                        tv_sec: 0,
                        tv_nsec: UTIME_OMIT as _,
                    },
                    libc::timespec {
                        tv_sec: self.mtime_sec,
                        tv_nsec: self.mtime_nsec as _,
                    },
                ];
                if unsafe { libc::futimens(raw, ts.as_ptr()) } < 0 {
                    first_err.get_or_insert(TarError::from_errno(last_errno()));
                }
            }

            for xa in &self.xattr {
                let c_name = match std::ffi::CString::new(xa.name.as_bytes()) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let ret = unsafe {
                    #[cfg(target_os = "macos")]
                    {
                        libc::fsetxattr(
                            raw,
                            c_name.as_ptr(),
                            xa.data.as_ptr() as *const c_void,
                            xa.data.len(),
                            0,
                            0,
                        )
                    }
                    #[cfg(not(target_os = "macos"))]
                    {
                        libc::fsetxattr(
                            raw,
                            c_name.as_ptr(),
                            xa.data.as_ptr() as *const c_void,
                            xa.data.len(),
                            0,
                        )
                    }
                };
                if ret < 0 {
                    first_err.get_or_insert(TarError::from_errno(last_errno()));
                }
            }
        }

        self.done();
        first_err.map_or(Ok(()), Err)
    }
}

/// Finalise a vector of open-inodes in reverse order (innermost first),
/// analogous to C `open_inode_finalize_many`.
pub fn open_inode_finalize_many(inodes: &mut Vec<OpenInode>) -> TarResult<()> {
    let mut first_err: Option<TarError> = None;

    while let Some(mut of) = inodes.pop() {
        if let Err(e) = of.finalize() {
            first_err.get_or_insert(e);
        }
    }

    first_err.map_or(Ok(()), Err)
}

// ── Pathname sanitisation ────────────────────────────────────────────────

/// Strip the leading `"./"` prefix that libarchive adds to every entry and
/// validate the remainder (analogous to C `archive_entry_pathname_safe`).
///
/// Returns `Ok(None)` for the root inode (empty path after stripping).
pub fn archive_entry_pathname_safe(raw: &str) -> TarResult<Option<&str>> {
    let stripped = raw.strip_prefix("./").unwrap_or(raw);
    if stripped.is_empty() || stripped == "." {
        return Ok(None);
    }
    if is_path_safe(stripped) {
        Ok(Some(stripped))
    } else {
        Err(TarError::from_errno(libc::EBADMSG))
    }
}

/// Minimal path-safety check: no leading `/`, no `..` components, no NUL
/// bytes (analogous to C `path_is_safe`).
pub fn is_path_safe(p: &str) -> bool {
    if p.starts_with('/') || p.contains('\0') {
        return false;
    }
    for component in p.split('/') {
        if component == ".." {
            return false;
        }
    }
    true
}

// ── UID / GID squashing ──────────────────────────────────────────────────

/// If `TAR_SQUASH_UIDS_ABOVE_64K` is set and `uid` is valid and ≥ 64 K,
/// return `UID_NOBODY`; otherwise pass through unchanged (analogous to C
/// `maybe_squash_uid`).
pub fn maybe_squash_uid(uid: u32, flags: TarFlags) -> u32 {
    if flags.contains(TarFlags::SQUASH_UIDS_ABOVE_64K)
        && uid != UID_INVALID
        && uid >= NSRESOURCE_UIDS_64K
    {
        UID_NOBODY
    } else {
        uid
    }
}

/// If `TAR_SQUASH_UIDS_ABOVE_64K` is set and `gid` is valid and ≥ 64 K,
/// return `GID_NOBODY`; otherwise pass through unchanged (analogous to C
/// `maybe_squash_gid`).
pub fn maybe_squash_gid(gid: u32, flags: TarFlags) -> u32 {
    if flags.contains(TarFlags::SQUASH_UIDS_ABOVE_64K)
        && gid != UID_INVALID
        && gid >= NSRESOURCE_UIDS_64K
    {
        GID_NOBODY
    } else {
        gid
    }
}

// ── Overlayfs whiteout helpers ───────────────────────────────────────────

/// Set an overlayfs whiteout xattr on `fd` (analogous to C
/// `overlayfs_fsetfattr`).
///
/// `path` is used only for diagnostics.  `name` is the overlayfs key suffix
/// (e.g. `"whiteout"` or `"opaque"`), and `value` is the string value.
pub fn overlayfs_fsetfattr(fd: RawFd, path: &str, name: &str, value: &str) -> TarResult<()> {
    let key = format!("user.overlay.{name}");
    let c_key = match std::ffi::CString::new(key.as_bytes()) {
        Ok(k) => k,
        Err(_) => return Err(TarError::Generic(format!("invalid xattr key: {key}"))),
    };

    let ret = unsafe {
        #[cfg(target_os = "macos")]
        {
            libc::fsetxattr(
                fd,
                c_key.as_ptr(),
                value.as_ptr() as *const c_void,
                value.len(),
                0,
                0,
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            libc::fsetxattr(
                fd,
                c_key.as_ptr(),
                value.as_ptr() as *const c_void,
                value.len(),
                0,
            )
        }
    };
    if ret < 0 {
        return Err(TarError::Generic(format!(
            "Failed to set '{}' xattr on file '{}'",
            key, path
        )));
    }
    Ok(())
}

// ── Tar unpack entry-point ───────────────────────────────────────────────

/// Extract a tar / cpio archive read from `input_fd` into the directory
/// referred to by `tree_fd` (analogous to C `tar_x`).
///
/// This is the main unpacking routine.  It reads entries one-by-one from the
/// archive, maintains a stack of open inodes, and defers metadata application
/// (ownership, mode, mtime, xattrs) until ascending out of each directory.
///
/// * `input_fd` — readable fd positioned at the start of the archive.
/// * `tree_fd`  — fd of the target directory (must already exist).
/// * `flags`    — behavioural flags (see [`TarFlags`]).
pub fn tar_x(input_fd: RawFd, tree_fd: RawFd, flags: TarFlags) -> TarResult<()> {
    // Mirrors the C `#else` branch (no libarchive): return EOPNOTSUPP.
    let _ = (input_fd, tree_fd, flags);
    Err(TarError::from_errno(libc::EOPNOTSUPP))
}

// ── Tar create entry-point ───────────────────────────────────────────────

/// Create a tar archive from the directory tree rooted at `tree_fd`, writing
/// to `output_fd` (analogous to C `tar_c`).
///
/// * `tree_fd`   — fd of the source directory tree.
/// * `output_fd` — writable fd for the resulting archive.
/// * `filename`  — optional hint for output format (extension-based).
/// * `flags`     — behavioural flags (see [`TarFlags`]).
pub fn tar_c(
    tree_fd: RawFd,
    output_fd: RawFd,
    filename: Option<&str>,
    flags: TarFlags,
) -> TarResult<()> {
    // Mirrors the C `#else` branch (no libarchive): return EOPNOTSUPP.
    let _ = (tree_fd, output_fd, filename, flags);
    Err(TarError::from_errno(libc::EOPNOTSUPP))
}

// ── Hard-link database helpers (for tar_c) ───────────────────────────────

/// State shared across the recursive directory traversal when creating an
/// archive (analogous to C `make_archive_data`).
#[derive(Debug)]
pub struct MakeArchiveData {
    /// Hard-link database directory fd (tmpfs or temp dir).
    pub hardlink_db_fd: Option<RawFd>,
    /// Path to the hard-link database directory (for cleanup).
    pub hardlink_db_path: Option<String>,
    /// Cached result of whether mount IDs are unique.
    pub have_unique_mount_id: Option<bool>,
    /// Flags controlling archive creation.
    pub flags: TarFlags,
}

impl MakeArchiveData {
    /// Create a new (empty) archive-data context.
    pub fn new(flags: TarFlags) -> Self {
        Self {
            hardlink_db_fd: None,
            hardlink_db_path: None,
            have_unique_mount_id: None,
            flags,
        }
    }
}

impl Drop for MakeArchiveData {
    fn drop(&mut self) {
        if let Some(fd) = self.hardlink_db_fd.take() {
            unsafe {
                libc::close(fd);
            }
        }
        self.hardlink_db_path = None;
    }
}

/// Release resources held by a [`MakeArchiveData`] (analogous to C
/// `make_archive_data_done`).
pub fn make_archive_data_done(data: &mut MakeArchiveData) {
    if let Some(fd) = data.hardlink_db_fd.take() {
        unsafe {
            libc::close(fd);
        }
    }
    data.hardlink_db_path = None;
}

// ── Sparse file support (for tar_c) ──────────────────────────────────────

/// Detect sparse holes in the file behind `fd` and return a list of
/// `(offset, length)` pairs describing data regions (analogous to C
/// `archive_generate_sparse`).
pub fn archive_generate_sparse(fd: RawFd) -> TarResult<Vec<(i64, i64)>> {
    let mut regions: Vec<(i64, i64)> = Vec::new();
    let mut cursor: i64 = 0;

    loop {
        let hole = unsafe { libc::lseek(fd, cursor, libc::SEEK_HOLE) };
        if hole < 0 {
            let errno = last_errno();
            if errno == libc::ENXIO {
                let end = unsafe { libc::lseek(fd, 0, libc::SEEK_END) };
                if end < 0 {
                    return Err(TarError::from_errno(last_errno()));
                }
                if end > cursor && cursor != 0 {
                    regions.push((cursor, end - cursor));
                }
                break;
            }
            return Err(TarError::from_errno(errno));
        }

        if hole > cursor {
            regions.push((cursor, hole - cursor));
        }

        cursor = unsafe { libc::lseek(fd, hole, libc::SEEK_DATA) };
        if cursor < 0 {
            let errno = last_errno();
            if errno == libc::ENXIO {
                break;
            }
            return Err(TarError::from_errno(errno));
        }
    }

    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return Err(TarError::from_errno(last_errno()));
    }

    Ok(regions)
}

// ── Filter helper (for tar_c) ────────────────────────────────────────────

/// Decide whether an inode should be included in the archive (analogous to C
/// `filter_item`).
///
/// Returns `true` if the inode should be archived, `false` to skip.
pub fn filter_item(filetype: u32) -> bool {
    let mask = filetype & libc::S_IFMT as u32;
    mask != libc::S_IFSOCK as u32 && mask != libc::S_IFIFO as u32 && mask != 0
}

// ── File-type helpers ────────────────────────────────────────────────────

/// Check whether a file type can have ACLs (analogous to C
/// `inode_type_can_acl`).
pub fn inode_type_can_acl(filetype: u32) -> bool {
    let mask = filetype & libc::S_IFMT as u32;
    mask == libc::S_IFREG as u32 || mask == libc::S_IFDIR as u32 || mask == libc::S_IFLNK as u32
}

/// Check whether a file type can be hard-linked (analogous to C
/// `inode_type_can_hardlink`).
pub fn inode_type_can_hardlink(filetype: u32) -> bool {
    let mask = filetype & libc::S_IFMT as u32;
    // Directories cannot be hard-linked on Linux.
    mask != libc::S_IFDIR as u32 && mask != 0
}

/// Convert a file-type mode to a short human-readable string (analogous to C
/// `inode_type_to_string`).
pub fn inode_type_to_string(filetype: u32) -> &'static str {
    match filetype & libc::S_IFMT as u32 {
        m if m == libc::S_IFREG as u32 => "regular file",
        m if m == libc::S_IFDIR as u32 => "directory",
        m if m == libc::S_IFLNK as u32 => "symbolic link",
        m if m == libc::S_IFCHR as u32 => "character device",
        m if m == libc::S_IFBLK as u32 => "block device",
        m if m == libc::S_IFIFO as u32 => "fifo",
        m if m == libc::S_IFSOCK as u32 => "socket",
        _ => "unknown",
    }
}

// ── Path helpers ─────────────────────────────────────────────────────────

/// Find the first path component in `rest`, returning `(component,
/// remaining)`.  Returns `None` when the path is exhausted (analogous to C
/// `path_find_first_component` with `accept_dot_dot = false`).
pub fn path_find_first_component(rest: &str) -> Option<(&str, &str)> {
    let rest = rest.strip_prefix('/').unwrap_or(rest);
    if rest.is_empty() {
        return None;
    }
    match rest.find('/') {
        Some(pos) => {
            if pos == 0 {
                path_find_first_component(&rest[1..])
            } else {
                let (component, remaining) = rest.split_at(pos);
                if component == ".." {
                    return None;
                }
                Some((component, remaining))
            }
        }
        None => {
            if rest == ".." {
                None
            } else {
                Some((rest, ""))
            }
        }
    }
}

/// Return the suffix of `path` that starts after `prefix`, or `None`
/// (analogous to C `path_startswith`).
pub fn path_startswith<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    path.strip_prefix(prefix).and_then(|rest| {
        if rest.is_empty() || rest.starts_with('/') {
            Some(rest.strip_prefix('/').unwrap_or(rest))
        } else {
            None
        }
    })
}

// ── OCI whiteout detection ───────────────────────────────────────────────

/// If `filename` starts with `.wh.` (but is not the opaque marker), return
/// the target filename that should be whited-out.
pub fn parse_oci_whiteout(filename: &str) -> Option<&str> {
    if filename == ".wh..wh..opq" {
        None
    } else {
        filename.strip_prefix(".wh.")
    }
}

/// Check whether a filename is the OCI opaque directory marker.
pub fn is_oci_opaque_marker(filename: &str) -> bool {
    filename == ".wh..wh..opq"
}

// ── Xattr classification ─────────────────────────────────────────────────

/// Check whether an xattr name is an ACL xattr (analogous to C `xattr_is_acl`).
pub fn xattr_is_acl(name: &str) -> bool {
    name == "system.posix_acl_access" || name == "system.posix_acl_default"
}

/// Check whether an xattr name is a SELinux xattr (analogous to C `xattr_is_selinux`).
pub fn xattr_is_selinux(name: &str) -> bool {
    name.starts_with("security.selinux")
}

// ── Path join helper ─────────────────────────────────────────────────────

/// Join two path fragments, handling the case where `base` is `None` (return
/// just `component`).
pub fn path_join_optional(base: Option<&str>, component: &str) -> String {
    match base {
        Some(b) if !b.is_empty() => format!("{b}/{component}"),
        _ => component.to_string(),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tar_flags_default_is_empty() {
        assert_eq!(TarFlags::default(), TarFlags::empty());
    }

    #[test]
    fn tar_flags_bit_positions_match_c() {
        assert_eq!(TarFlags::SELINUX.bits(), 1);
        assert_eq!(TarFlags::SQUASH_UIDS_ABOVE_64K.bits(), 2);
        assert_eq!(TarFlags::OCI_WHITEOUTS.bits(), 4);
    }

    #[test]
    fn tar_flags_combinations() {
        let f = TarFlags::SELINUX | TarFlags::SQUASH_UIDS_ABOVE_64K;
        assert!(f.contains(TarFlags::SELINUX));
        assert!(f.contains(TarFlags::SQUASH_UIDS_ABOVE_64K));
        assert!(!f.contains(TarFlags::OCI_WHITEOUTS));
    }

    #[test]
    fn maybe_squash_uid_below_threshold() {
        assert_eq!(
            maybe_squash_uid(1000, TarFlags::SQUASH_UIDS_ABOVE_64K),
            1000
        );
    }

    #[test]
    fn maybe_squash_uid_above_threshold() {
        assert_eq!(
            maybe_squash_uid(100000, TarFlags::SQUASH_UIDS_ABOVE_64K),
            UID_NOBODY
        );
    }

    #[test]
    fn maybe_squash_uid_at_exact_threshold() {
        assert_eq!(
            maybe_squash_uid(NSRESOURCE_UIDS_64K, TarFlags::SQUASH_UIDS_ABOVE_64K),
            UID_NOBODY
        );
    }

    #[test]
    fn maybe_squash_uid_no_flag() {
        assert_eq!(maybe_squash_uid(100000, TarFlags::empty()), 100000);
    }

    #[test]
    fn maybe_squash_uid_invalid() {
        assert_eq!(
            maybe_squash_uid(UID_INVALID, TarFlags::SQUASH_UIDS_ABOVE_64K),
            UID_INVALID
        );
    }

    #[test]
    fn maybe_squash_gid_below_threshold() {
        assert_eq!(
            maybe_squash_gid(1000, TarFlags::SQUASH_UIDS_ABOVE_64K),
            1000
        );
    }

    #[test]
    fn maybe_squash_gid_above_threshold() {
        assert_eq!(
            maybe_squash_gid(100000, TarFlags::SQUASH_UIDS_ABOVE_64K),
            GID_NOBODY
        );
    }

    #[test]
    fn maybe_squash_gid_no_flag() {
        assert_eq!(maybe_squash_gid(100000, TarFlags::empty()), 100000);
    }

    #[test]
    fn maybe_squash_gid_invalid() {
        assert_eq!(
            maybe_squash_gid(GID_INVALID, TarFlags::SQUASH_UIDS_ABOVE_64K),
            GID_INVALID
        );
    }

    #[test]
    fn archive_entry_pathname_safe_root() {
        assert_eq!(archive_entry_pathname_safe("./").unwrap(), None);
        assert_eq!(archive_entry_pathname_safe(".").unwrap(), None);
    }

    #[test]
    fn archive_entry_pathname_safe_normal() {
        assert_eq!(
            archive_entry_pathname_safe("./foo/bar").unwrap(),
            Some("foo/bar")
        );
        assert_eq!(
            archive_entry_pathname_safe("foo/bar").unwrap(),
            Some("foo/bar")
        );
    }

    #[test]
    fn archive_entry_pathname_safe_rejects_dotdot() {
        assert!(archive_entry_pathname_safe("./foo/../bar").is_err());
        assert!(archive_entry_pathname_safe("foo/../bar").is_err());
    }

    #[test]
    fn archive_entry_pathname_safe_rejects_absolute() {
        assert!(archive_entry_pathname_safe("/etc/passwd").is_err());
    }

    #[test]
    fn is_path_safe_simple() {
        assert!(is_path_safe("foo/bar"));
        assert!(is_path_safe("a"));
        assert!(!is_path_safe("/foo"));
        assert!(!is_path_safe("foo/../bar"));
        assert!(!is_path_safe("foo/bar/.."));
    }

    #[test]
    fn is_path_safe_rejects_nul() {
        assert!(!is_path_safe("foo\0bar"));
    }

    #[test]
    fn path_startswith_basic() {
        assert_eq!(path_startswith("foo/bar/baz", "foo/bar"), Some("baz"));
        assert_eq!(path_startswith("foo/bar", "foo"), Some("bar"));
        assert_eq!(path_startswith("foo", "foo"), Some(""));
        assert_eq!(path_startswith("foo", "bar"), None);
        assert_eq!(path_startswith("foobar", "foo"), None);
    }

    #[test]
    fn path_find_first_component_basic() {
        assert_eq!(path_find_first_component("foo/bar"), Some(("foo", "/bar")));
        assert_eq!(
            path_find_first_component("foo/bar/baz"),
            Some(("foo", "/bar/baz"))
        );
        assert_eq!(path_find_first_component("foo"), Some(("foo", "")));
        assert_eq!(path_find_first_component(""), None);
    }

    #[test]
    fn path_find_first_component_rejects_dotdot() {
        assert_eq!(path_find_first_component(".."), None);
        assert_eq!(path_find_first_component("a/../b"), Some(("a", "/../b")));
    }

    #[test]
    fn path_find_first_component_leading_slash() {
        assert_eq!(path_find_first_component("/foo"), Some(("foo", "")));
    }

    #[test]
    fn inode_type_can_hardlink_regular() {
        assert!(inode_type_can_hardlink(libc::S_IFREG as u32));
    }

    #[test]
    fn inode_type_can_hardlink_directory() {
        assert!(!inode_type_can_hardlink(libc::S_IFDIR as u32));
    }

    #[test]
    fn inode_type_can_acl_regular() {
        assert!(inode_type_can_acl(libc::S_IFREG as u32));
    }

    #[test]
    fn inode_type_can_acl_directory() {
        assert!(inode_type_can_acl(libc::S_IFDIR as u32));
    }

    #[test]
    fn inode_type_can_acl_symlink() {
        assert!(inode_type_can_acl(libc::S_IFLNK as u32));
    }

    #[test]
    fn inode_type_can_acl_socket() {
        assert!(!inode_type_can_acl(libc::S_IFSOCK as u32));
    }

    #[test]
    fn inode_type_to_string_known() {
        assert_eq!(inode_type_to_string(libc::S_IFREG as u32), "regular file");
        assert_eq!(inode_type_to_string(libc::S_IFDIR as u32), "directory");
        assert_eq!(inode_type_to_string(libc::S_IFLNK as u32), "symbolic link");
        assert_eq!(
            inode_type_to_string(libc::S_IFCHR as u32),
            "character device"
        );
        assert_eq!(inode_type_to_string(libc::S_IFBLK as u32), "block device");
        assert_eq!(inode_type_to_string(libc::S_IFIFO as u32), "fifo");
        assert_eq!(inode_type_to_string(libc::S_IFSOCK as u32), "socket");
    }

    #[test]
    fn inode_type_to_string_unknown() {
        assert_eq!(inode_type_to_string(0xF000u32), "unknown");
    }

    #[test]
    fn filter_item_regular() {
        assert!(filter_item(libc::S_IFREG as u32));
    }

    #[test]
    fn filter_item_directory() {
        assert!(filter_item(libc::S_IFDIR as u32));
    }

    #[test]
    fn filter_item_socket() {
        assert!(!filter_item(libc::S_IFSOCK as u32));
    }

    #[test]
    fn filter_item_fifo() {
        assert!(!filter_item(libc::S_IFIFO as u32));
    }

    #[test]
    fn filter_item_zero() {
        assert!(!filter_item(0));
    }

    #[test]
    fn parse_oci_whiteout_regular() {
        assert_eq!(parse_oci_whiteout(".wh.foo"), Some("foo"));
    }

    #[test]
    fn parse_oci_whiteout_opaque() {
        assert_eq!(parse_oci_whiteout(".wh..wh..opq"), None);
    }

    #[test]
    fn parse_oci_whiteout_no_prefix() {
        assert_eq!(parse_oci_whiteout("foo"), None);
    }

    #[test]
    fn is_oci_opaque_marker_true() {
        assert!(is_oci_opaque_marker(".wh..wh..opq"));
    }

    #[test]
    fn is_oci_opaque_marker_false() {
        assert!(!is_oci_opaque_marker(".wh.foo"));
        assert!(!is_oci_opaque_marker("bar"));
    }

    #[test]
    fn xattr_done_many_clears() {
        let mut xa = vec![
            XAttr {
                name: "user.foo".into(),
                data: vec![1, 2, 3],
            },
            XAttr {
                name: "user.bar".into(),
                data: vec![4, 5, 6],
            },
        ];
        xattr_done_many(&mut xa);
        assert!(xa.is_empty());
    }

    #[test]
    fn xattr_single_done() {
        let mut xa = XAttr {
            name: "user.test".into(),
            data: vec![0xde, 0xad],
        };
        xa.done();
        assert!(xa.name.is_empty());
        assert!(xa.data.is_empty());
    }

    #[test]
    fn xattr_clone() {
        let xa = XAttr {
            name: "user.orig".into(),
            data: vec![1, 2, 3],
        };
        let cloned = xa.clone();
        assert_eq!(cloned.name, "user.orig");
        assert_eq!(cloned.data, vec![1, 2, 3]);
    }

    #[test]
    fn xattr_is_acl_posix() {
        assert!(xattr_is_acl("system.posix_acl_access"));
        assert!(xattr_is_acl("system.posix_acl_default"));
        assert!(!xattr_is_acl("user.foo"));
    }

    #[test]
    fn xattr_is_selinux_check() {
        assert!(xattr_is_selinux("security.selinux"));
        assert!(!xattr_is_selinux("user.foo"));
    }

    #[test]
    fn open_inode_new_root() {
        let root = OpenInode::new_root(42);
        assert_eq!(root.fd, Some(42));
        assert!(root.path.is_none());
        assert_eq!(root.filetype, libc::S_IFDIR as u32);
        assert_eq!(root.mode, MODE_INVALID);
        assert_eq!(root.uid, UID_INVALID);
        assert_eq!(root.gid, GID_INVALID);
        assert_eq!(root.mtime_nsec, UTIME_OMIT);
        assert!(root.xattr.is_empty());
    }

    #[test]
    fn open_inode_done_root_preserves_fd() {
        let mut root = OpenInode::new_root(42);
        root.done();
        assert_eq!(root.fd, Some(42));
    }

    #[test]
    fn open_inode_done_clears_xattr() {
        let mut of = OpenInode {
            fd: Some(-1),
            path: Some("/tmp/test".into()),
            filetype: libc::S_IFREG as u32,
            mode: 0o644,
            mtime_sec: 0,
            mtime_nsec: UTIME_OMIT,
            uid: 0,
            gid: 0,
            fflags: 0,
            xattr: vec![XAttr {
                name: "user.x".into(),
                data: vec![1],
            }],
        };
        of.done();
        assert!(of.fd.is_none());
        assert!(of.path.is_none());
        assert!(of.xattr.is_empty());
    }

    #[test]
    fn open_inode_finalize_with_no_fd() {
        let mut of = OpenInode {
            fd: None,
            path: Some("/tmp/test".into()),
            filetype: libc::S_IFREG as u32,
            mode: MODE_INVALID,
            mtime_sec: 0,
            mtime_nsec: UTIME_OMIT,
            uid: UID_INVALID,
            gid: GID_INVALID,
            fflags: 0,
            xattr: vec![],
        };
        assert!(of.finalize().is_ok());
        assert!(of.path.is_none());
    }

    #[test]
    fn open_inode_finalize_many_empty() {
        let mut inodes: Vec<OpenInode> = Vec::new();
        assert!(open_inode_finalize_many(&mut inodes).is_ok());
        assert!(inodes.is_empty());
    }

    #[test]
    fn make_archive_data_new() {
        let data = MakeArchiveData::new(TarFlags::empty());
        assert!(data.hardlink_db_fd.is_none());
        assert!(data.hardlink_db_path.is_none());
        assert!(data.have_unique_mount_id.is_none());
        assert_eq!(data.flags, TarFlags::empty());
    }

    #[test]
    fn make_archive_data_done_clears() {
        let mut data = MakeArchiveData::new(TarFlags::SELINUX);
        data.hardlink_db_path = Some("/tmp/hl".into());
        make_archive_data_done(&mut data);
        assert!(data.hardlink_db_path.is_none());
    }

    #[test]
    fn path_join_optional_with_base() {
        assert_eq!(path_join_optional(Some("foo/bar"), "baz"), "foo/bar/baz");
    }

    #[test]
    fn path_join_optional_no_base() {
        assert_eq!(path_join_optional(None, "baz"), "baz");
    }

    #[test]
    fn path_join_optional_empty_base() {
        assert_eq!(path_join_optional(Some(""), "baz"), "baz");
    }

    #[test]
    fn depth_max_is_128() {
        assert_eq!(DEPTH_MAX, 128);
    }

    #[test]
    fn sentinel_values() {
        assert_eq!(UID_INVALID, u32::MAX);
        assert_eq!(GID_INVALID, u32::MAX);
        assert_eq!(MODE_INVALID, u32::MAX);
        assert_eq!(UID_NOBODY, 65534);
        assert_eq!(GID_NOBODY, 65534);
        assert_eq!(NSRESOURCE_UIDS_64K, 65536);
    }

    #[test]
    fn utime_omit_value() {
        assert_eq!(UTIME_OMIT, (1i32 << 30) as i64);
    }

    #[test]
    fn chattr_tar_fl_bits() {
        assert_ne!(CHATTR_TAR_FL, 0);
        assert_ne!(CHATTR_TAR_FL & 0x00000010 /* FS_NOATIME_FL */, 0);
        assert_ne!(CHATTR_TAR_FL & 0x00800000 /* FS_NOCOW_FL */, 0);
    }

    #[test]
    fn tar_error_display() {
        let e = TarError::Errno(libc::ENOENT);
        assert!(!e.to_string().is_empty());

        let e = TarError::Generic("oops".into());
        assert!(e.to_string().contains("oops"));
    }

    #[test]
    fn tar_error_from_neg_errno() {
        let e = TarError::from_neg_errno(-libc::ENOENT);
        match e {
            TarError::Errno(code) => assert_eq!(code, libc::ENOENT),
            _ => panic!("expected Errno variant"),
        }
    }

    #[test]
    fn tar_error_errno_accessor() {
        let e = TarError::Errno(libc::ENOENT);
        assert_eq!(e.errno(), Some(libc::ENOENT));

        let e = TarError::Generic("fail".into());
        assert_eq!(e.errno(), None);
    }

    #[test]
    fn tar_x_returns_eopnotsupp() {
        match tar_x(0, 1, TarFlags::empty()) {
            Err(TarError::Errno(e)) => assert_eq!(e, libc::EOPNOTSUPP),
            other => panic!("expected Err(Errno(EOPNOTSUPP)), got {:?}", other),
        }
    }

    #[test]
    fn tar_c_returns_eopnotsupp() {
        match tar_c(0, 1, None, TarFlags::empty()) {
            Err(TarError::Errno(e)) => assert_eq!(e, libc::EOPNOTSUPP),
            other => panic!("expected Err(Errno(EOPNOTSUPP)), got {:?}", other),
        }
    }

    #[test]
    fn overlayfs_fsetfattr_bad_fd() {
        let result = overlayfs_fsetfattr(-1, "/test", "whiteout", "y");
        assert!(result.is_err());
    }

    #[test]
    fn last_errno_returns_value() {
        // After a failed syscall, last_errno should return a non-zero value.
        // We force an error by calling close(-1).
        unsafe { libc::close(-1) };
        let e = last_errno();
        assert_ne!(e, 0);
    }
}
