// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/dev-setup.c, src/shared/dev-setup.h

use std::os::unix::fs::MetadataExt;
use std::ffi::CString;
use std::fmt;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const DEFAULT_PARENT_DIR: &str = "/run/systemd";

const DEV_SYMLINKS: [(&str, &str); 5] = [
    ("-/proc/kcore", "/dev/core"),
    ("/proc/self/fd", "/dev/fd"),
    ("/proc/self/fd/0", "/dev/stdin"),
    ("/proc/self/fd/1", "/dev/stdout"),
    ("/proc/self/fd/2", "/dev/stderr"),
];

const INACCESSIBLE_NODES: [libc::mode_t; 6] = [
    libc::S_IFREG,
    libc::S_IFDIR,
    libc::S_IFIFO,
    libc::S_IFSOCK,
    libc::S_IFCHR,
    libc::S_IFBLK,
];

pub const UID_INVALID: libc::uid_t = !0;
pub const GID_INVALID: libc::gid_t = !0;

#[derive(Debug)]
pub enum DevSetupError {
    InvalidPath(PathBuf),
    Io { path: PathBuf, source: io::Error },
}

impl fmt::Display for DevSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(path) => {
                write!(f, "path contains interior NUL byte: {}", path.display())
            }
            Self::Io { path, source } => write!(f, "{}: {}", path.display(), source),
        }
    }
}

impl std::error::Error for DevSetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPath(_) => None,
            Self::Io { source, .. } => Some(source),
        }
    }
}

pub fn uid_is_valid(uid: libc::uid_t) -> bool {
    uid != UID_INVALID
}

pub fn gid_is_valid(gid: libc::gid_t) -> bool {
    gid != GID_INVALID
}

pub fn inode_type_to_string(inode_type: libc::mode_t) -> Option<&'static str> {
    match inode_type & libc::S_IFMT {
        libc::S_IFREG => Some("reg"),
        libc::S_IFDIR => Some("dir"),
        libc::S_IFLNK => Some("lnk"),
        libc::S_IFCHR => Some("chr"),
        libc::S_IFBLK => Some("blk"),
        libc::S_IFIFO => Some("fifo"),
        libc::S_IFSOCK => Some("sock"),
        _ => None,
    }
}

pub fn dev_setup(
    prefix: Option<&Path>,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> Result<(), DevSetupError> {
    for &(source_spec, destination) in &DEV_SYMLINKS {
        let (source, optional) = parse_symlink_source(source_spec);
        if optional && libc_path_exists(Path::new(source)).is_err() {
            continue;
        }

        let link_path = prefixed_destination(prefix, destination);
        symlink_label(Path::new(source), &link_path);

        if uid_is_valid(uid) || gid_is_valid(gid) {
            lchown_nofollow(&link_path, uid, gid);
        }
    }

    Ok(())
}

pub fn make_inaccessible_nodes(
    parent_dir: Option<&Path>,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> Result<(), DevSetupError> {
    let parent_dir = parent_dir.unwrap_or_else(|| Path::new(DEFAULT_PARENT_DIR));
    let _umask_guard = UmaskGuard::new(0);

    let parent_fd = FdGuard::new(open_parent_dir(parent_dir)?);
    let inaccessible_fd = FdGuard::new(open_or_create_directory_at(
        parent_fd.raw(),
        "inaccessible",
        0o755,
    )?);

    for &inode_type in &INACCESSIBLE_NODES {
        let Some(file_name) = inode_type_to_string(inode_type) else {
            continue;
        };

        let log_path = parent_dir.join("inaccessible").join(file_name);

        match create_inaccessible_node(inaccessible_fd.raw(), file_name, inode_type) {
            Ok(()) => {}
            Err(errno) if errno == libc::EEXIST => {
                if let Err(error) = fchmodat_nofollow(inaccessible_fd.raw(), file_name, 0) {
                    debug_log(format!(
                        "Failed to adjust access mode of existing inode '{}', ignoring: {}",
                        log_path.display(),
                        error
                    ));
                }
            }
            Err(errno) => {
                debug_log(format!(
                    "Failed to create '{}', ignoring: {}",
                    log_path.display(),
                    io::Error::from_raw_os_error(errno)
                ));
                continue;
            }
        }

        if uid_is_valid(uid) || gid_is_valid(gid) {
            if let Err(error) = fchownat_nofollow(inaccessible_fd.raw(), file_name, uid, gid) {
                debug_log(format!(
                    "Failed to chown '{}', ignoring: {}",
                    log_path.display(),
                    error
                ));
            }
        }
    }

    if let Err(error) = fchmod_fd(inaccessible_fd.raw(), 0o555) {
        debug_log(format!(
            "Failed to mark inaccessible directory read-only, ignoring: {}",
            error
        ));
    }

    Ok(())
}

fn parse_symlink_source(source_spec: &str) -> (&str, bool) {
    match source_spec.strip_prefix('-') {
        Some(source) => (source, true),
        None => (source_spec, false),
    }
}

fn prefixed_destination(prefix: Option<&Path>, destination: &str) -> PathBuf {
    match prefix {
        Some(prefix) => prefix.join(strip_leading_slash(Path::new(destination))),
        None => PathBuf::from(destination),
    }
}

fn strip_leading_slash(path: &Path) -> &Path {
    path.strip_prefix(Path::new("/")).unwrap_or(path)
}

fn debug_log(message: String) {
    eprintln!("dev-setup: {message}");
}

fn libc_path_exists(path: &Path) -> Result<(), io::Error> {
    let path_c = cstring_from_path(path).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let rc = unsafe {
        // SAFETY: `path_c` is a valid, NUL-terminated pathname.
        libc::access(path_c.as_ptr(), libc::F_OK)
    };

    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn symlink_label(target: &Path, link_path: &Path) {
    if let Err(error) = std::os::unix::fs::symlink(target, link_path) {
        debug_log(format!(
            "Failed to symlink {} to {}: {}",
            target.display(),
            link_path.display(),
            error
        ));
    }
}

fn lchown_nofollow(path: &Path, uid: libc::uid_t, gid: libc::gid_t) {
    let Ok(path_c) = cstring_from_path(path) else {
        debug_log(format!("Failed to chown {}: invalid path", path.display()));
        return;
    };

    let rc = unsafe {
        // SAFETY: `path_c` is a valid, NUL-terminated pathname.
        libc::lchown(path_c.as_ptr(), uid, gid)
    };

    if rc < 0 {
        debug_log(format!(
            "Failed to chown {}: {}",
            path.display(),
            io::Error::last_os_error()
        ));
    }
}

fn open_parent_dir(path: &Path) -> Result<i32, DevSetupError> {
    let path_c =
        cstring_from_path(path).map_err(|_| DevSetupError::InvalidPath(path.to_path_buf()))?;
    let fd = unsafe {
        // SAFETY: `path_c` is a valid, NUL-terminated pathname.
        libc::open(path_c.as_ptr(), open_parent_dir_flags(), 0)
    };

    if fd >= 0 {
        Ok(fd)
    } else {
        Err(io_error(path, io::Error::last_os_error()))
    }
}

fn open_or_create_directory_at(
    parent_fd: i32,
    file_name: &str,
    mode: libc::mode_t,
) -> Result<i32, DevSetupError> {
    let file_name_c = CString::new(file_name)
        .map_err(|_| DevSetupError::InvalidPath(PathBuf::from(file_name)))?;

    let mkdir_rc = unsafe {
        // SAFETY: `file_name_c` is valid and `parent_fd` refers to a directory.
        libc::mkdirat(parent_fd, file_name_c.as_ptr(), mode)
    };
    if mkdir_rc < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(io_error(Path::new(file_name), error));
        }
    }

    let fd = unsafe {
        // SAFETY: `file_name_c` is valid and `parent_fd` refers to a directory.
        libc::openat(
            parent_fd,
            file_name_c.as_ptr(),
            libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_RDONLY,
            0,
        )
    };

    if fd >= 0 {
        Ok(fd)
    } else {
        Err(io_error(Path::new(file_name), io::Error::last_os_error()))
    }
}

fn create_inaccessible_node(
    dir_fd: i32,
    file_name: &str,
    inode_type: libc::mode_t,
) -> Result<(), i32> {
    let file_name_c = CString::new(file_name).map_err(|_| libc::EINVAL)?;

    let rc = if (inode_type & libc::S_IFMT) == libc::S_IFDIR {
        unsafe {
            // SAFETY: `file_name_c` is valid and `dir_fd` refers to a directory.
            libc::mkdirat(dir_fd, file_name_c.as_ptr(), 0)
        }
    } else {
        unsafe {
            // SAFETY: `file_name_c` is valid and `dir_fd` refers to a directory.
            libc::mknodat(
                dir_fd,
                file_name_c.as_ptr(),
                inode_type | 0,
                libc::makedev(0, 0),
            )
        }
    };

    if rc >= 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    }
}

fn fchmodat_nofollow(
    dir_fd: i32,
    file_name: &str,
    mode: libc::mode_t,
) -> Result<(), io::Error> {
    let file_name_c =
        CString::new(file_name).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let rc = unsafe {
        // SAFETY: `file_name_c` is valid and `dir_fd` refers to a directory.
        libc::fchmodat(
            dir_fd,
            file_name_c.as_ptr(),
            mode,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };

    if rc >= 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn fchownat_nofollow(
    dir_fd: i32,
    file_name: &str,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> Result<(), io::Error> {
    let file_name_c =
        CString::new(file_name).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let rc = unsafe {
        // SAFETY: `file_name_c` is valid and `dir_fd` refers to a directory.
        libc::fchownat(
            dir_fd,
            file_name_c.as_ptr(),
            uid,
            gid,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };

    if rc >= 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn fchmod_fd(fd: i32, mode: libc::mode_t) -> Result<(), io::Error> {
    let rc = unsafe {
        // SAFETY: `fd` is owned by the caller.
        libc::fchmod(fd, mode)
    };

    if rc >= 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn cstring_from_path(path: &Path) -> Result<CString, std::ffi::NulError> {
    CString::new(path.as_os_str().as_bytes())
}

fn io_error(path: &Path, source: io::Error) -> DevSetupError {
    DevSetupError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(target_os = "linux")]
fn open_parent_dir_flags() -> i32 {
    libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_PATH
}

#[cfg(not(target_os = "linux"))]
fn open_parent_dir_flags() -> i32 {
    libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_RDONLY
}

struct FdGuard(i32);

impl FdGuard {
    fn new(fd: i32) -> Self {
        Self(fd)
    }

    fn raw(&self) -> i32 {
        self.0
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                // SAFETY: `self.0` is owned by this guard.
                libc::close(self.0);
            }
        }
    }
}

struct UmaskGuard(libc::mode_t);

impl UmaskGuard {
    fn new(mask: libc::mode_t) -> Self {
        let old = unsafe {
            // SAFETY: `umask` is process-global and returns the previous mask.
            libc::umask(mask)
        };
        Self(old)
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: restore the previously returned umask value.
            libc::umask(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use tempfile::tempdir;

    #[test]
    fn parse_optional_symlink_source() {
        assert_eq!(parse_symlink_source("-/proc/kcore"), ("/proc/kcore", true));
    }

    #[test]
    fn parse_required_symlink_source() {
        assert_eq!(
            parse_symlink_source("/proc/self/fd"),
            ("/proc/self/fd", false)
        );
    }

    #[test]
    fn prefixed_destination_preserves_prefix_for_absolute_targets() {
        let root = Path::new("/tmp/root");
        assert_eq!(
            prefixed_destination(Some(root), "/dev/stdin"),
            PathBuf::from("/tmp/root/dev/stdin")
        );
    }

    #[test]
    fn prefixed_destination_without_prefix_keeps_absolute_path() {
        assert_eq!(
            prefixed_destination(None, "/dev/stdout"),
            PathBuf::from("/dev/stdout")
        );
    }

    #[test]
    fn strip_leading_slash_keeps_relative_path() {
        assert_eq!(
            strip_leading_slash(Path::new("dev/stderr")),
            Path::new("dev/stderr")
        );
    }

    #[test]
    fn uid_and_gid_validity_match_invalid_sentinels() {
        assert!(uid_is_valid(0));
        assert!(gid_is_valid(0));
        assert!(!uid_is_valid(UID_INVALID));
        assert!(!gid_is_valid(GID_INVALID));
    }

    #[test]
    fn inode_type_to_string_maps_expected_values() {
        assert_eq!(inode_type_to_string(libc::S_IFREG), Some("reg"));
        assert_eq!(inode_type_to_string(libc::S_IFDIR), Some("dir"));
        assert_eq!(inode_type_to_string(libc::S_IFLNK), Some("lnk"));
        assert_eq!(inode_type_to_string(libc::S_IFCHR), Some("chr"));
        assert_eq!(inode_type_to_string(libc::S_IFBLK), Some("blk"));
        assert_eq!(inode_type_to_string(libc::S_IFIFO), Some("fifo"));
        assert_eq!(inode_type_to_string(libc::S_IFSOCK), Some("sock"));
    }

    #[test]
    fn inode_type_to_string_rejects_unknown_values() {
        assert_eq!(inode_type_to_string(0), None);
    }

    #[test]
    fn dev_symlink_table_matches_c() {
        assert_eq!(DEV_SYMLINKS.len(), 5);
        assert_eq!(DEV_SYMLINKS[0], ("-/proc/kcore", "/dev/core"));
        assert_eq!(DEV_SYMLINKS[4], ("/proc/self/fd/2", "/dev/stderr"));
    }

    #[test]
    fn inaccessible_node_table_matches_c() {
        assert_eq!(
            INACCESSIBLE_NODES,
            [
                libc::S_IFREG,
                libc::S_IFDIR,
                libc::S_IFIFO,
                libc::S_IFSOCK,
                libc::S_IFCHR,
                libc::S_IFBLK
            ]
        );
    }

    #[test]
    fn error_display_mentions_path() {
        let error = DevSetupError::InvalidPath(PathBuf::from("/bad\0path"));
        assert!(format!("{error}").contains("NUL"));
    }

    #[test]
    fn open_or_create_directory_at_creates_directory() {
        let dir = tempdir().unwrap();
        let parent = open_parent_dir(dir.path()).unwrap();
        let parent = FdGuard::new(parent);
        let child = open_or_create_directory_at(parent.raw(), "inaccessible", 0o755).unwrap();
        let _child = FdGuard::new(child);

        assert!(dir.path().join("inaccessible").is_dir());
    }

    #[test]
    fn open_or_create_directory_at_reuses_existing_directory() {
        let dir = tempdir().unwrap();
        fs::create_dir(dir.path().join("inaccessible")).unwrap();
        let parent = open_parent_dir(dir.path()).unwrap();
        let parent = FdGuard::new(parent);
        let child = open_or_create_directory_at(parent.raw(), "inaccessible", 0o755).unwrap();
        let _child = FdGuard::new(child);

        assert!(dir.path().join("inaccessible").is_dir());
    }

    #[test]
    fn dev_setup_with_prefix_creates_proc_symlinks_when_parents_exist() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("dev")).unwrap();

        dev_setup(Some(dir.path()), UID_INVALID, GID_INVALID).unwrap();

        for name in ["fd", "stdin", "stdout", "stderr"] {
            let path = dir.path().join("dev").join(name);
            if path.exists() || fs::symlink_metadata(&path).is_ok() {
                let metadata = fs::symlink_metadata(&path).unwrap();
                assert!(metadata.file_type().is_symlink());
            }
        }
    }

    #[test]
    fn dev_setup_does_not_create_core_symlink_without_source() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("dev")).unwrap();

        dev_setup(Some(dir.path()), UID_INVALID, GID_INVALID).unwrap();

        let core = dir.path().join("dev/core");
        if libc_path_exists(Path::new("/proc/kcore")).is_err() {
            assert!(fs::symlink_metadata(core).is_err());
        }
    }

    #[test]
    fn make_inaccessible_nodes_creates_directory_and_locks_it_down() {
        let dir = tempdir().unwrap();

        make_inaccessible_nodes(Some(dir.path()), UID_INVALID, GID_INVALID).unwrap();

        let inaccessible = dir.path().join("inaccessible");
        let metadata = fs::metadata(&inaccessible).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o555);
    }

    #[test]
    fn make_inaccessible_nodes_creates_expected_user_visible_entries_when_possible() {
        let dir = tempdir().unwrap();

        make_inaccessible_nodes(Some(dir.path()), UID_INVALID, GID_INVALID).unwrap();

        let inaccessible = dir.path().join("inaccessible");
        let dir_entry = inaccessible.join("dir");
        assert!(dir_entry.is_dir());

        let reg_entry = inaccessible.join("reg");
        if let Ok(metadata) = fs::symlink_metadata(&reg_entry) {
            assert!(metadata.is_file());
        }

        let fifo_entry = inaccessible.join("fifo");
        if let Ok(metadata) = fs::symlink_metadata(&fifo_entry) {
            assert!(metadata.file_type().is_fifo());
        }
    }

    #[test]
    fn make_inaccessible_nodes_is_idempotent_for_existing_entries() {
        let dir = tempdir().unwrap();

        make_inaccessible_nodes(Some(dir.path()), UID_INVALID, GID_INVALID).unwrap();
        make_inaccessible_nodes(Some(dir.path()), UID_INVALID, GID_INVALID).unwrap();

        let inaccessible = dir.path().join("inaccessible");
        assert!(inaccessible.is_dir());
        assert_eq!(
            fs::metadata(inaccessible).unwrap().permissions().mode() & 0o777,
            0o555
        );
    }

    #[test]
    fn make_inaccessible_nodes_reports_missing_parent() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("missing");

        let error = make_inaccessible_nodes(Some(&missing), UID_INVALID, GID_INVALID).unwrap_err();
        assert!(format!("{error}").contains("missing"));
    }

    #[test]
    fn umask_guard_restores_previous_value() {
        let before = unsafe {
            // SAFETY: reading current umask by setting and restoring it.
            libc::umask(0o022)
        };
        unsafe {
            // SAFETY: restore original value.
            libc::umask(before);
        }

        {
            let _guard = UmaskGuard::new(0);
            let current = unsafe {
                // SAFETY: reading current umask by setting and restoring it.
                libc::umask(0o077)
            };
            assert_eq!(current, 0);
        }

        let after = unsafe {
            // SAFETY: reading current umask by setting and restoring it.
            libc::umask(0o077)
        };
        unsafe {
            // SAFETY: restore observed value.
            libc::umask(after);
        }
        assert_eq!(after, before);
    }

    #[test]
    fn created_stdin_symlink_points_to_proc_fd_zero_when_present() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("dev")).unwrap();

        dev_setup(Some(dir.path()), UID_INVALID, GID_INVALID).unwrap();

        let path = dir.path().join("dev/stdin");
        if let Ok(target) = fs::read_link(&path) {
            assert_eq!(target, PathBuf::from("/proc/self/fd/0"));
        }
    }

    #[test]
    fn inaccessible_dir_is_owned_by_current_user_when_no_chown_requested() {
        let dir = tempdir().unwrap();

        make_inaccessible_nodes(Some(dir.path()), UID_INVALID, GID_INVALID).unwrap();

        let metadata = fs::metadata(dir.path().join("inaccessible")).unwrap();
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.gid(), unsafe { libc::getegid() });
    }
}
