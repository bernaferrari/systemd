// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/base-filesystem.c, src/shared/base-filesystem.h
//
use crate::ffi::*;
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BaseFilesystemFlags: u32 {
        const IGNORE_ON_FAILURE = 1 << 0;
        const EMPTY_MARKER = 1 << 1;
        const EMPTY_ONLY = 1 << 2;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseFilesystemEntry {
    pub dir: &'static str,
    pub mode: libc::mode_t,
    pub target: Option<&'static [&'static str]>,
    pub exists: Option<&'static str>,
    pub flags: BaseFilesystemFlags,
}

const BASE_FILESYSTEM_PREFIX: &[BaseFilesystemEntry] = &[
    BaseFilesystemEntry {
        dir: "bin",
        mode: 0,
        target: Some(&["usr/bin"]),
        exists: None,
        flags: BaseFilesystemFlags::EMPTY_MARKER,
    },
    BaseFilesystemEntry {
        dir: "lib",
        mode: 0,
        target: Some(&["usr/lib"]),
        exists: None,
        flags: BaseFilesystemFlags::EMPTY_MARKER,
    },
    BaseFilesystemEntry {
        dir: "root",
        mode: 0o750,
        target: None,
        exists: None,
        flags: BaseFilesystemFlags::IGNORE_ON_FAILURE,
    },
    BaseFilesystemEntry {
        dir: "sbin",
        mode: 0,
        target: Some(&["usr/sbin"]),
        exists: None,
        flags: BaseFilesystemFlags::EMPTY_MARKER,
    },
    BaseFilesystemEntry {
        dir: "usr",
        mode: 0o755,
        target: None,
        exists: None,
        flags: BaseFilesystemFlags::empty(),
    },
    BaseFilesystemEntry {
        dir: "var",
        mode: 0o755,
        target: None,
        exists: None,
        flags: BaseFilesystemFlags::empty(),
    },
    BaseFilesystemEntry {
        dir: "etc",
        mode: 0o755,
        target: None,
        exists: None,
        flags: BaseFilesystemFlags::empty(),
    },
    BaseFilesystemEntry {
        dir: "proc",
        mode: 0o555,
        target: None,
        exists: None,
        flags: BaseFilesystemFlags::IGNORE_ON_FAILURE,
    },
    BaseFilesystemEntry {
        dir: "sys",
        mode: 0o555,
        target: None,
        exists: None,
        flags: BaseFilesystemFlags::IGNORE_ON_FAILURE,
    },
    BaseFilesystemEntry {
        dir: "dev",
        mode: 0o555,
        target: None,
        exists: None,
        flags: BaseFilesystemFlags::IGNORE_ON_FAILURE,
    },
    BaseFilesystemEntry {
        dir: "run",
        mode: 0o555,
        target: None,
        exists: None,
        flags: BaseFilesystemFlags::IGNORE_ON_FAILURE,
    },
];

#[cfg(target_arch = "aarch64")]
const ARCH_LIB_ENTRY: Option<BaseFilesystemEntry> = Some(BaseFilesystemEntry {
    dir: "lib64",
    mode: 0,
    target: Some(&["usr/lib64", "usr/lib"]),
    exists: Some("ld-linux-aarch64.so.1"),
    flags: BaseFilesystemFlags::EMPTY_ONLY,
});

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const ARCH_LIB_ENTRY: Option<BaseFilesystemEntry> = Some(BaseFilesystemEntry {
    dir: "lib64",
    mode: 0,
    target: Some(&["usr/lib64", "usr/lib"]),
    exists: Some("ld-linux-x86-64.so.2"),
    flags: BaseFilesystemFlags::empty(),
});

#[cfg(all(target_arch = "powerpc64", target_endian = "little"))]
const ARCH_LIB_ENTRY: Option<BaseFilesystemEntry> = Some(BaseFilesystemEntry {
    dir: "lib64",
    mode: 0,
    target: Some(&["usr/lib64", "usr/lib"]),
    exists: Some("ld64.so.2"),
    flags: BaseFilesystemFlags::empty(),
});

#[cfg(target_arch = "riscv64")]
const ARCH_LIB_ENTRY: Option<BaseFilesystemEntry> = Some(BaseFilesystemEntry {
    dir: "lib64",
    mode: 0,
    target: Some(&["usr/lib64", "usr/lib"]),
    exists: Some("ld-linux-riscv64-lp64d.so.1"),
    flags: BaseFilesystemFlags::EMPTY_ONLY,
});

#[cfg(target_arch = "s390x")]
const ARCH_LIB_ENTRY: Option<BaseFilesystemEntry> = Some(BaseFilesystemEntry {
    dir: "lib64",
    mode: 0,
    target: Some(&["usr/lib64", "usr/lib"]),
    exists: Some("ld-lsb-s390x.so.3"),
    flags: BaseFilesystemFlags::EMPTY_ONLY,
});

#[cfg(all(
    not(target_arch = "aarch64"),
    not(target_arch = "x86"),
    not(target_arch = "x86_64"),
    not(all(target_arch = "powerpc64", target_endian = "little")),
    not(target_arch = "riscv64"),
    not(target_arch = "s390x"),
))]
const ARCH_LIB_ENTRY: Option<BaseFilesystemEntry> = None;

#[derive(Debug)]
pub enum BaseFilesystemError {
    InvalidPath(PathBuf),
    OpenRoot {
        root: PathBuf,
        source: io::Error,
    },
    Create {
        root: PathBuf,
        entry: String,
        source: io::Error,
    },
    Chown {
        root: PathBuf,
        entry: String,
        source: io::Error,
    },
}

impl fmt::Display for BaseFilesystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(path) => {
                write!(f, "path contains an embedded NUL byte: {}", path.display())
            }
            Self::OpenRoot { root, source } => {
                write!(
                    f,
                    "failed to open root file system {}: {source}",
                    root.display()
                )
            }
            Self::Create {
                root,
                entry,
                source,
            } => write!(f, "failed to create {}/{}: {source}", root.display(), entry),
            Self::Chown {
                root,
                entry,
                source,
            } => write!(f, "failed to chown {}/{}: {source}", root.display(), entry),
        }
    }
}

impl std::error::Error for BaseFilesystemError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPath(_) => None,
            Self::OpenRoot { source, .. }
            | Self::Create { source, .. }
            | Self::Chown { source, .. } => Some(source),
        }
    }
}

pub fn base_filesystem_table() -> Vec<BaseFilesystemEntry> {
    let mut table = BASE_FILESYSTEM_PREFIX.to_vec();
    if let Some(entry) = ARCH_LIB_ENTRY {
        table.push(entry);
    }
    table
}

pub fn has_lib64_entry() -> bool {
    ARCH_LIB_ENTRY.is_some()
}

pub fn base_filesystem_create_fd(
    fd: BorrowedFd<'_>,
    root: &Path,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> Result<(), BaseFilesystemError> {
    create_entries(fd.as_raw_fd(), root, uid, gid, &base_filesystem_table())
}

pub fn base_filesystem_create(
    root: &Path,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> Result<(), BaseFilesystemError> {
    let root_c =
        path_to_cstring(root).map_err(|_| BaseFilesystemError::InvalidPath(root.to_path_buf()))?;

    let fd = unsafe { libc::open(root_c.as_ptr(), libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(BaseFilesystemError::OpenRoot {
            root: root.to_path_buf(),
            source: io::Error::last_os_error(),
        });
    }

    let file = unsafe { File::from_raw_fd(fd) };
    base_filesystem_create_fd(file.as_fd(), root, uid, gid)
}

fn create_entries(
    fd: RawFd,
    root: &Path,
    uid: libc::uid_t,
    gid: libc::gid_t,
    table: &[BaseFilesystemEntry],
) -> Result<(), BaseFilesystemError> {
    let mut empty_fs = false;

    for entry in table {
        if entry.flags.contains(BaseFilesystemFlags::EMPTY_ONLY) && !empty_fs {
            continue;
        }

        let dir_c = str_to_cstring(entry.dir)
            .map_err(|_| BaseFilesystemError::InvalidPath(PathBuf::from(entry.dir)))?;

        if path_exists_at(fd, &dir_c) {
            continue;
        }

        if entry.flags.contains(BaseFilesystemFlags::EMPTY_MARKER) {
            empty_fs = true;
        }

        let result = if let Some(targets) = entry.target {
            match select_symlink_target(fd, targets, entry.exists)? {
                Some(target) => symlink_at(fd, &target, &dir_c),
                None => continue,
            }
        } else {
            mkdir_at(fd, &dir_c, entry.mode).and_then(|()| chmod_at(fd, &dir_c, entry.mode))
        };

        match result {
            Ok(()) => {}
            Err(error) if should_ignore_error(&error, entry.flags) => continue,
            Err(source) => {
                return Err(BaseFilesystemError::Create {
                    root: root.to_path_buf(),
                    entry: entry.dir.to_string(),
                    source,
                });
            }
        }

        if uid_is_valid(uid) || gid_is_valid(gid) {
            fchown_at(fd, &dir_c, uid, gid).map_err(|source| BaseFilesystemError::Chown {
                root: root.to_path_buf(),
                entry: entry.dir.to_string(),
                source,
            })?;
        }
    }

    Ok(())
}

fn select_symlink_target(
    fd: RawFd,
    targets: &[&str],
    exists: Option<&str>,
) -> Result<Option<CString>, BaseFilesystemError> {
    for target in targets {
        let target_c = str_to_cstring(target)
            .map_err(|_| BaseFilesystemError::InvalidPath(PathBuf::from(target)))?;

        if !path_exists_at(fd, &target_c) {
            continue;
        }

        if let Some(exists_name) = exists {
            let exists_path = Path::new(target).join(exists_name);
            let exists_c = path_to_cstring(&exists_path)
                .map_err(|_| BaseFilesystemError::InvalidPath(exists_path.clone()))?;
            if !path_exists_at(fd, &exists_c) {
                continue;
            }
        }

        return Ok(Some(target_c));
    }

    Ok(None)
}

fn str_to_cstring(value: &str) -> Result<CString, std::ffi::NulError> {
    CString::new(value.as_bytes())
}

fn path_to_cstring(path: &Path) -> Result<CString, std::ffi::NulError> {
    CString::new(path.as_os_str().as_bytes())
}

fn path_exists_at(fd: RawFd, path: &CString) -> bool {
    unsafe { libc::faccessat(fd, path.as_ptr(), libc::F_OK, libc::AT_SYMLINK_NOFOLLOW) >= 0 }
}

fn mkdir_at(fd: RawFd, path: &CString, mode: libc::mode_t) -> io::Result<()> {
    if unsafe { libc::mkdirat(fd, path.as_ptr(), mode) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn chmod_at(fd: RawFd, path: &CString, mode: libc::mode_t) -> io::Result<()> {
    if unsafe { libc::fchmodat(fd, path.as_ptr(), mode, libc::AT_SYMLINK_NOFOLLOW) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn symlink_at(fd: RawFd, target: &CString, path: &CString) -> io::Result<()> {
    if unsafe { libc::symlinkat(target.as_ptr(), fd, path.as_ptr()) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn fchown_at(fd: RawFd, path: &CString, uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
    if unsafe { libc::fchownat(fd, path.as_ptr(), uid, gid, libc::AT_SYMLINK_NOFOLLOW) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn uid_is_valid(uid: libc::uid_t) -> bool {
    uid != libc::uid_t::MAX
}

fn gid_is_valid(gid: libc::gid_t) -> bool {
    gid != libc::gid_t::MAX
}

fn should_ignore_error(error: &io::Error, flags: BaseFilesystemFlags) -> bool {
    matches!(error.raw_os_error(), Some(libc::EEXIST) | Some(libc::EROFS))
        || flags.contains(BaseFilesystemFlags::IGNORE_ON_FAILURE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::fd::AsFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use tempfile::TempDir;

    fn invalid_uid() -> libc::uid_t {
        libc::uid_t::MAX
    }

    fn invalid_gid() -> libc::gid_t {
        libc::gid_t::MAX
    }

    fn custom_create(
        root: &Path,
        table: &[BaseFilesystemEntry],
    ) -> Result<(), BaseFilesystemError> {
        let file = File::open(root).unwrap();
        create_entries(file.as_raw_fd(), root, invalid_uid(), invalid_gid(), table)
    }

    fn restore_permissions(path: &Path) {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(_) => return,
        };

        if metadata.file_type().is_symlink() {
            return;
        }

        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));

        if metadata.is_dir() {
            let entries = match fs::read_dir(path) {
                Ok(entries) => entries,
                Err(_) => return,
            };

            for entry in entries.flatten() {
                restore_permissions(&entry.path());
            }
        }
    }

    #[test]
    fn table_contains_required_entries() {
        let names: Vec<_> = base_filesystem_table()
            .into_iter()
            .map(|entry| entry.dir)
            .collect();
        for required in [
            "bin", "lib", "root", "sbin", "usr", "var", "etc", "proc", "sys", "dev", "run",
        ] {
            assert!(names.contains(&required));
        }
    }

    #[test]
    fn table_preserves_entry_ordering_rule() {
        let table = base_filesystem_table();
        let first_empty_only = table
            .iter()
            .position(|entry| entry.flags.contains(BaseFilesystemFlags::EMPTY_ONLY));

        if let Some(index) = first_empty_only {
            assert!(
                table[..index]
                    .iter()
                    .any(|entry| entry.flags.contains(BaseFilesystemFlags::EMPTY_MARKER))
            );
        }
    }

    #[test]
    fn invalid_uid_and_gid_are_detected() {
        assert!(!uid_is_valid(invalid_uid()));
        assert!(!gid_is_valid(invalid_gid()));
        assert!(uid_is_valid(0));
        assert!(gid_is_valid(0));
    }

    #[test]
    fn ignores_missing_symlink_targets() {
        let tmp = TempDir::new().unwrap();
        let table = [BaseFilesystemEntry {
            dir: "bin",
            mode: 0,
            target: Some(&["usr/bin"]),
            exists: None,
            flags: BaseFilesystemFlags::empty(),
        }];

        custom_create(tmp.path(), &table).unwrap();
        assert!(!tmp.path().join("bin").exists());
    }

    #[test]
    fn creates_directory_entries_with_expected_mode() {
        let tmp = TempDir::new().unwrap();
        let table = [BaseFilesystemEntry {
            dir: "etc",
            mode: 0o755,
            target: None,
            exists: None,
            flags: BaseFilesystemFlags::empty(),
        }];

        custom_create(tmp.path(), &table).unwrap();

        let metadata = fs::metadata(tmp.path().join("etc")).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.mode() & 0o777, 0o755);
    }

    #[test]
    fn creates_symlink_entries() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("usr/bin")).unwrap();

        let table = [BaseFilesystemEntry {
            dir: "bin",
            mode: 0,
            target: Some(&["usr/bin"]),
            exists: None,
            flags: BaseFilesystemFlags::empty(),
        }];

        custom_create(tmp.path(), &table).unwrap();

        assert_eq!(
            fs::read_link(tmp.path().join("bin")).unwrap(),
            PathBuf::from("usr/bin")
        );
    }

    #[test]
    fn selects_first_existing_symlink_target() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("usr/lib64")).unwrap();
        fs::create_dir_all(tmp.path().join("usr/lib")).unwrap();
        fs::write(tmp.path().join("usr/lib64/ld.so"), b"").unwrap();
        fs::write(tmp.path().join("usr/lib/ld.so"), b"").unwrap();

        let table = [BaseFilesystemEntry {
            dir: "lib64",
            mode: 0,
            target: Some(&["usr/lib64", "usr/lib"]),
            exists: Some("ld.so"),
            flags: BaseFilesystemFlags::empty(),
        }];

        custom_create(tmp.path(), &table).unwrap();

        assert_eq!(
            fs::read_link(tmp.path().join("lib64")).unwrap(),
            PathBuf::from("usr/lib64")
        );
    }

    #[test]
    fn skips_target_without_required_loader_file() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("usr/lib64")).unwrap();
        fs::create_dir_all(tmp.path().join("usr/lib")).unwrap();
        fs::write(tmp.path().join("usr/lib/ld.so"), b"").unwrap();

        let table = [BaseFilesystemEntry {
            dir: "lib64",
            mode: 0,
            target: Some(&["usr/lib64", "usr/lib"]),
            exists: Some("ld.so"),
            flags: BaseFilesystemFlags::empty(),
        }];

        custom_create(tmp.path(), &table).unwrap();

        assert_eq!(
            fs::read_link(tmp.path().join("lib64")).unwrap(),
            PathBuf::from("usr/lib")
        );
    }

    #[test]
    fn empty_only_entries_are_skipped_when_filesystem_is_not_empty() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("usr/lib64")).unwrap();
        fs::write(tmp.path().join("usr/lib64/ld.so"), b"").unwrap();
        fs::create_dir_all(tmp.path().join("bin")).unwrap();

        let table = [
            BaseFilesystemEntry {
                dir: "bin",
                mode: 0,
                target: Some(&["usr/bin"]),
                exists: None,
                flags: BaseFilesystemFlags::EMPTY_MARKER,
            },
            BaseFilesystemEntry {
                dir: "lib64",
                mode: 0,
                target: Some(&["usr/lib64"]),
                exists: Some("ld.so"),
                flags: BaseFilesystemFlags::EMPTY_ONLY,
            },
        ];

        custom_create(tmp.path(), &table).unwrap();
        assert!(!tmp.path().join("lib64").exists());
    }

    #[test]
    fn empty_only_entries_are_created_after_missing_marker() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("usr/bin")).unwrap();
        fs::create_dir_all(tmp.path().join("usr/lib64")).unwrap();
        fs::write(tmp.path().join("usr/lib64/ld.so"), b"").unwrap();

        let table = [
            BaseFilesystemEntry {
                dir: "bin",
                mode: 0,
                target: Some(&["usr/bin"]),
                exists: None,
                flags: BaseFilesystemFlags::EMPTY_MARKER,
            },
            BaseFilesystemEntry {
                dir: "lib64",
                mode: 0,
                target: Some(&["usr/lib64"]),
                exists: Some("ld.so"),
                flags: BaseFilesystemFlags::EMPTY_ONLY,
            },
        ];

        custom_create(tmp.path(), &table).unwrap();
        assert_eq!(
            fs::read_link(tmp.path().join("lib64")).unwrap(),
            PathBuf::from("usr/lib64")
        );
    }

    #[test]
    fn existing_entries_are_left_untouched() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("var")).unwrap();
        fs::write(tmp.path().join("var/existing"), b"ok").unwrap();

        let table = [BaseFilesystemEntry {
            dir: "var",
            mode: 0o700,
            target: None,
            exists: None,
            flags: BaseFilesystemFlags::empty(),
        }];

        custom_create(tmp.path(), &table).unwrap();
        assert!(tmp.path().join("var/existing").exists());
    }

    #[test]
    fn create_reports_missing_root_directory() {
        let missing = Path::new("/definitely/not/present/systemd-base-filesystem-test");
        let error = base_filesystem_create(missing, invalid_uid(), invalid_gid()).unwrap_err();
        assert!(matches!(error, BaseFilesystemError::OpenRoot { .. }));
    }

    #[test]
    fn full_table_creates_core_layout() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("usr/bin")).unwrap();
        fs::create_dir_all(tmp.path().join("usr/lib")).unwrap();
        fs::create_dir_all(tmp.path().join("usr/sbin")).unwrap();
        if has_lib64_entry() {
            fs::create_dir_all(tmp.path().join("usr/lib64")).unwrap();
            #[cfg(target_arch = "aarch64")]
            fs::write(tmp.path().join("usr/lib64/ld-linux-aarch64.so.1"), b"").unwrap();
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            fs::write(tmp.path().join("usr/lib64/ld-linux-x86-64.so.2"), b"").unwrap();
            #[cfg(all(target_arch = "powerpc64", target_endian = "little"))]
            fs::write(tmp.path().join("usr/lib64/ld64.so.2"), b"").unwrap();
            #[cfg(target_arch = "riscv64")]
            fs::write(
                tmp.path().join("usr/lib64/ld-linux-riscv64-lp64d.so.1"),
                b"",
            )
            .unwrap();
            #[cfg(target_arch = "s390x")]
            fs::write(tmp.path().join("usr/lib64/ld-lsb-s390x.so.3"), b"").unwrap();
        }

        let file = File::open(tmp.path()).unwrap();
        base_filesystem_create_fd(file.as_fd(), tmp.path(), invalid_uid(), invalid_gid()).unwrap();

        for dir in ["root", "usr", "var", "etc", "proc", "sys", "dev", "run"] {
            assert!(tmp.path().join(dir).exists(), "missing {dir}");
        }

        assert_eq!(
            fs::read_link(tmp.path().join("bin")).unwrap(),
            PathBuf::from("usr/bin")
        );
        assert_eq!(
            fs::read_link(tmp.path().join("lib")).unwrap(),
            PathBuf::from("usr/lib")
        );
        assert_eq!(
            fs::read_link(tmp.path().join("sbin")).unwrap(),
            PathBuf::from("usr/sbin")
        );

        restore_permissions(tmp.path());
    }

    #[test]
    fn invalid_path_error_is_reported() {
        let path = Path::new(std::ffi::OsStr::from_bytes(b"bad\0path"));
        let error = base_filesystem_create(path, invalid_uid(), invalid_gid()).unwrap_err();
        assert!(matches!(error, BaseFilesystemError::InvalidPath(_)));
    }

    #[test]
    fn has_lib64_entry_matches_arch_configuration() {
        let expected = cfg!(target_arch = "aarch64")
            || cfg!(target_arch = "x86")
            || cfg!(target_arch = "x86_64")
            || cfg!(all(target_arch = "powerpc64", target_endian = "little"))
            || cfg!(target_arch = "riscv64")
            || cfg!(target_arch = "s390x");
        assert_eq!(has_lib64_entry(), expected);
    }
}
