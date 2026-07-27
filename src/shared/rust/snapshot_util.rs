// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/snapshot-util.c, src/shared/snapshot-util.h

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

use crate::btrfs_util::BtrfsSnapshotFlags;

const HIDDEN_TMP_PREFIX: &[u8] = b".#";
const SNAPSHOT_PREFIX: &[u8] = b"snapshot.";
const RANDOM_SUFFIX_HEX_LEN: usize = 16;
const NAME_MAX: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeScope {
    System,
    User,
}

pub trait SnapshotBackend<L> {
    fn path_is_mount_point(&mut self, directory: &Path) -> Result<bool, i32>;

    fn image_path_lock(
        &mut self,
        scope: RuntimeScope,
        path: &Path,
        lock_flags: i32,
        tree_global_lock: Option<&mut L>,
        tree_local_lock: &mut L,
    ) -> Result<(), i32>;

    fn create_snapshot(
        &mut self,
        source: &Path,
        destination: &Path,
        flags: BtrfsSnapshotFlags,
    ) -> Result<(), i32>;

    fn random_u64(&mut self) -> u64;
}

pub fn ephemeral_snapshot_flags(read_only: bool) -> BtrfsSnapshotFlags {
    let mut flags = BtrfsSnapshotFlags::FALLBACK_COPY
        | BtrfsSnapshotFlags::FALLBACK_DIRECTORY
        | BtrfsSnapshotFlags::RECURSIVE
        | BtrfsSnapshotFlags::QUOTA
        | BtrfsSnapshotFlags::SIGINT;

    if read_only {
        flags |= BtrfsSnapshotFlags::READ_ONLY;
    }

    flags
}

pub fn ephemeral_snapshot_lock_flags() -> i32 {
    libc::LOCK_EX | libc::LOCK_NB
}

pub fn ephemeral_snapshot_path(
    directory: &Path,
    is_mount_point: bool,
    random: u64,
) -> Result<PathBuf, i32> {
    let suffix = format!("{random:0width$x}", width = RANDOM_SUFFIX_HEX_LEN);

    if is_mount_point {
        tempfn_random_child(directory, SNAPSHOT_PREFIX, &suffix)
    } else {
        tempfn_random(directory, SNAPSHOT_PREFIX, &suffix)
    }
}

pub fn create_ephemeral_snapshot<B, L>(
    backend: &mut B,
    directory: &Path,
    scope: RuntimeScope,
    read_only: bool,
    tree_global_lock: Option<&mut L>,
    tree_local_lock: &mut L,
) -> Result<PathBuf, i32>
where
    B: SnapshotBackend<L>,
{
    let is_mount_point = backend.path_is_mount_point(directory)?;
    let new_path = ephemeral_snapshot_path(directory, is_mount_point, backend.random_u64())?;

    backend.image_path_lock(
        scope,
        &new_path,
        ephemeral_snapshot_lock_flags(),
        match scope {
            RuntimeScope::System => tree_global_lock,
            RuntimeScope::User => None,
        },
        tree_local_lock,
    )?;

    backend.create_snapshot(directory, &new_path, ephemeral_snapshot_flags(read_only))?;
    Ok(new_path)
}

fn tempfn_random(path: &Path, extra: &[u8], suffix: &str) -> Result<PathBuf, i32> {
    let (directory, file_name) = split_prefix_filename(path)?;
    let max_file_name_len = NAME_MAX - HIDDEN_TMP_PREFIX.len() - extra.len() - suffix.len();
    let mut file_name_bytes = file_name.into_vec();

    if file_name_bytes.len() > max_file_name_len {
        file_name_bytes.truncate(max_file_name_len);
    }

    let mut mangled = Vec::with_capacity(
        HIDDEN_TMP_PREFIX.len() + extra.len() + file_name_bytes.len() + suffix.len(),
    );
    mangled.extend_from_slice(HIDDEN_TMP_PREFIX);
    mangled.extend_from_slice(extra);
    mangled.extend_from_slice(&file_name_bytes);
    mangled.extend_from_slice(suffix.as_bytes());

    let mangled_name = OsString::from_vec(mangled);
    Ok(match directory {
        Some(parent) => parent.join(mangled_name),
        None => PathBuf::from(mangled_name),
    })
}

fn tempfn_random_child(path: &Path, extra: &[u8], suffix: &str) -> Result<PathBuf, i32> {
    if path.as_os_str().as_bytes().is_empty() {
        return Err(-libc::EINVAL);
    }

    if extra.len() + suffix.len() > NAME_MAX - HIDDEN_TMP_PREFIX.len() {
        return Err(-libc::EINVAL);
    }

    let mut mangled = Vec::with_capacity(HIDDEN_TMP_PREFIX.len() + extra.len() + suffix.len());
    mangled.extend_from_slice(HIDDEN_TMP_PREFIX);
    mangled.extend_from_slice(extra);
    mangled.extend_from_slice(suffix.as_bytes());

    Ok(simplify_path(path).join(OsString::from_vec(mangled)))
}

fn split_prefix_filename(path: &Path) -> Result<(Option<PathBuf>, OsString), i32> {
    let path_bytes = trim_trailing_slashes(path.as_os_str().as_bytes());

    if path_bytes.is_empty() {
        return Err(-libc::EINVAL);
    }
    if path_bytes == b"." || path_bytes == b"/" {
        return Err(-libc::EADDRNOTAVAIL);
    }
    if path_bytes == b".." {
        return Err(-libc::EINVAL);
    }

    let (directory, file_name) = match path_bytes.iter().rposition(|byte| *byte == b'/') {
        Some(index) => {
            let file_name = &path_bytes[index + 1..];
            let directory = if index == 0 {
                Some(PathBuf::from("/"))
            } else {
                Some(simplify_path(Path::new(OsStr::from_bytes(
                    &path_bytes[..index],
                ))))
            };
            (directory, file_name)
        }
        None => (None, path_bytes),
    };

    if file_name.is_empty() || file_name == b"." {
        return Err(-libc::EADDRNOTAVAIL);
    }
    if file_name == b".." {
        return Err(-libc::EINVAL);
    }

    let directory = directory.and_then(|dir| {
        if dir.as_os_str().is_empty() || dir.as_os_str() == OsStr::new(".") {
            None
        } else {
            Some(dir)
        }
    });

    Ok((directory, OsString::from_vec(file_name.to_vec())))
}

fn trim_trailing_slashes(mut path: &[u8]) -> &[u8] {
    while path.len() > 1 && path.last() == Some(&b'/') {
        path = &path[..path.len() - 1];
    }
    path
}

fn simplify_path(path: &Path) -> PathBuf {
    let mut result = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        PathBuf::new()
    };

    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => result.push(".."),
            Component::Normal(part) => result.push(part),
            Component::Prefix(prefix) => result.push(prefix.as_os_str()),
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct MockLock;

    #[derive(Debug, PartialEq, Eq)]
    enum Call {
        MountPoint(PathBuf),
        Lock {
            scope: RuntimeScope,
            path: PathBuf,
            flags: i32,
            used_global_lock: bool,
        },
        Snapshot {
            source: PathBuf,
            destination: PathBuf,
            flags: BtrfsSnapshotFlags,
        },
    }

    struct MockBackend {
        mount_point_result: Result<bool, i32>,
        lock_result: Result<(), i32>,
        snapshot_result: Result<(), i32>,
        random: u64,
        calls: Vec<Call>,
    }

    impl Default for MockBackend {
        fn default() -> Self {
            Self {
                mount_point_result: Ok(false),
                lock_result: Ok(()),
                snapshot_result: Ok(()),
                random: 0x0123_4567_89ab_cdef,
                calls: Vec::new(),
            }
        }
    }

    impl SnapshotBackend<MockLock> for MockBackend {
        fn path_is_mount_point(&mut self, directory: &Path) -> Result<bool, i32> {
            self.calls.push(Call::MountPoint(directory.to_path_buf()));
            self.mount_point_result
        }

        fn image_path_lock(
            &mut self,
            scope: RuntimeScope,
            path: &Path,
            lock_flags: i32,
            tree_global_lock: Option<&mut MockLock>,
            _tree_local_lock: &mut MockLock,
        ) -> Result<(), i32> {
            self.calls.push(Call::Lock {
                scope,
                path: path.to_path_buf(),
                flags: lock_flags,
                used_global_lock: tree_global_lock.is_some(),
            });
            self.lock_result
        }

        fn create_snapshot(
            &mut self,
            source: &Path,
            destination: &Path,
            flags: BtrfsSnapshotFlags,
        ) -> Result<(), i32> {
            self.calls.push(Call::Snapshot {
                source: source.to_path_buf(),
                destination: destination.to_path_buf(),
                flags,
            });
            self.snapshot_result
        }

        fn random_u64(&mut self) -> u64 {
            self.random
        }
    }

    #[test]
    fn sibling_snapshot_path_matches_tempfn_random_shape() {
        assert_eq!(
            ephemeral_snapshot_path(Path::new("/srv/tree"), false, 0xabc).unwrap(),
            PathBuf::from("/srv/.#snapshot.tree0000000000000abc")
        );
    }

    #[test]
    fn child_snapshot_path_matches_tempfn_random_child_shape() {
        assert_eq!(
            ephemeral_snapshot_path(Path::new("/srv/tree"), true, 0xabc).unwrap(),
            PathBuf::from("/srv/tree/.#snapshot.0000000000000abc")
        );
    }

    #[test]
    fn sibling_snapshot_path_strips_trailing_slashes() {
        assert_eq!(
            ephemeral_snapshot_path(Path::new("/srv/tree///"), false, 1).unwrap(),
            PathBuf::from("/srv/.#snapshot.tree0000000000000001")
        );
    }

    #[test]
    fn sibling_snapshot_path_simplifies_dot_prefix() {
        assert_eq!(
            ephemeral_snapshot_path(Path::new("./tree"), false, 2).unwrap(),
            PathBuf::from(".#snapshot.tree0000000000000002")
        );
    }

    #[test]
    fn sibling_snapshot_path_preserves_parent_components() {
        assert_eq!(
            ephemeral_snapshot_path(Path::new("../tree"), false, 3).unwrap(),
            PathBuf::from("../.#snapshot.tree0000000000000003")
        );
    }

    #[test]
    fn sibling_snapshot_path_rejects_root() {
        assert_eq!(
            ephemeral_snapshot_path(Path::new("/"), false, 4),
            Err(-libc::EADDRNOTAVAIL)
        );
    }

    #[test]
    fn sibling_snapshot_path_rejects_dot() {
        assert_eq!(
            ephemeral_snapshot_path(Path::new("."), false, 5),
            Err(-libc::EADDRNOTAVAIL)
        );
    }

    #[test]
    fn sibling_snapshot_path_rejects_dot_dot() {
        assert_eq!(
            ephemeral_snapshot_path(Path::new(".."), false, 6),
            Err(-libc::EINVAL)
        );
    }

    #[test]
    fn sibling_snapshot_path_truncates_long_file_names_to_name_max() {
        let long_name = "x".repeat(NAME_MAX);
        let path = ephemeral_snapshot_path(Path::new(&long_name), false, 7).unwrap();
        let file_name = path.file_name().unwrap().as_bytes();

        assert_eq!(file_name.len(), NAME_MAX);
        assert!(file_name.starts_with(b".#snapshot."));
        assert!(file_name.ends_with(b"0000000000000007"));
    }

    #[test]
    fn snapshot_flags_match_c_defaults() {
        let flags = ephemeral_snapshot_flags(false);
        assert!(flags.contains(BtrfsSnapshotFlags::FALLBACK_COPY));
        assert!(flags.contains(BtrfsSnapshotFlags::FALLBACK_DIRECTORY));
        assert!(flags.contains(BtrfsSnapshotFlags::RECURSIVE));
        assert!(flags.contains(BtrfsSnapshotFlags::QUOTA));
        assert!(flags.contains(BtrfsSnapshotFlags::SIGINT));
        assert!(!flags.contains(BtrfsSnapshotFlags::READ_ONLY));
    }

    #[test]
    fn snapshot_flags_add_read_only_when_requested() {
        assert!(ephemeral_snapshot_flags(true).contains(BtrfsSnapshotFlags::READ_ONLY));
    }

    #[test]
    fn create_ephemeral_snapshot_uses_global_lock_for_system_scope() {
        let mut backend = MockBackend::default();
        backend.mount_point_result = Ok(true);
        let mut global_lock = MockLock;
        let mut local_lock = MockLock;

        let path = create_ephemeral_snapshot(
            &mut backend,
            Path::new("/var/lib/machines"),
            RuntimeScope::System,
            true,
            Some(&mut global_lock),
            &mut local_lock,
        )
        .unwrap();

        assert_eq!(
            path,
            PathBuf::from("/var/lib/machines/.#snapshot.0123456789abcdef")
        );
        assert_eq!(backend.calls.len(), 3);
        assert_eq!(
            backend.calls[0],
            Call::MountPoint(PathBuf::from("/var/lib/machines"))
        );
        assert_eq!(
            backend.calls[1],
            Call::Lock {
                scope: RuntimeScope::System,
                path: PathBuf::from("/var/lib/machines/.#snapshot.0123456789abcdef"),
                flags: libc::LOCK_EX | libc::LOCK_NB,
                used_global_lock: true,
            }
        );
        match &backend.calls[2] {
            Call::Snapshot {
                source,
                destination,
                flags,
            } => {
                assert_eq!(source, &PathBuf::from("/var/lib/machines"));
                assert_eq!(
                    destination,
                    &PathBuf::from("/var/lib/machines/.#snapshot.0123456789abcdef")
                );
                assert!(flags.contains(BtrfsSnapshotFlags::READ_ONLY));
            }
            other => panic!("unexpected call: {other:?}"),
        }
    }

    #[test]
    fn create_ephemeral_snapshot_ignores_global_lock_for_user_scope() {
        let mut backend = MockBackend::default();
        let mut global_lock = MockLock;
        let mut local_lock = MockLock;

        create_ephemeral_snapshot(
            &mut backend,
            Path::new("/srv/tree"),
            RuntimeScope::User,
            false,
            Some(&mut global_lock),
            &mut local_lock,
        )
        .unwrap();

        assert_eq!(
            backend.calls[1],
            Call::Lock {
                scope: RuntimeScope::User,
                path: PathBuf::from("/srv/.#snapshot.tree0123456789abcdef"),
                flags: libc::LOCK_EX | libc::LOCK_NB,
                used_global_lock: false,
            }
        );
    }

    #[test]
    fn create_ephemeral_snapshot_propagates_mount_point_errors() {
        let mut backend = MockBackend {
            mount_point_result: Err(-libc::ENOENT),
            ..MockBackend::default()
        };
        let mut local_lock = MockLock;

        assert_eq!(
            create_ephemeral_snapshot(
                &mut backend,
                Path::new("/missing"),
                RuntimeScope::User,
                false,
                None::<&mut MockLock>,
                &mut local_lock,
            ),
            Err(-libc::ENOENT)
        );
        assert_eq!(
            backend.calls,
            vec![Call::MountPoint(PathBuf::from("/missing"))]
        );
    }

    #[test]
    fn create_ephemeral_snapshot_propagates_lock_errors_before_snapshotting() {
        let mut backend = MockBackend {
            lock_result: Err(-libc::EWOULDBLOCK),
            ..MockBackend::default()
        };
        let mut local_lock = MockLock;

        assert_eq!(
            create_ephemeral_snapshot(
                &mut backend,
                Path::new("/srv/tree"),
                RuntimeScope::User,
                false,
                None::<&mut MockLock>,
                &mut local_lock,
            ),
            Err(-libc::EWOULDBLOCK)
        );
        assert_eq!(backend.calls.len(), 2);
    }

    #[test]
    fn create_ephemeral_snapshot_propagates_snapshot_errors() {
        let mut backend = MockBackend {
            snapshot_result: Err(-libc::EROFS),
            ..MockBackend::default()
        };
        let mut local_lock = MockLock;

        assert_eq!(
            create_ephemeral_snapshot(
                &mut backend,
                Path::new("/srv/tree"),
                RuntimeScope::User,
                true,
                None::<&mut MockLock>,
                &mut local_lock,
            ),
            Err(-libc::EROFS)
        );
        assert_eq!(backend.calls.len(), 3);
    }
}
