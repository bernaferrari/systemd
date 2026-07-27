// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/mountpoint-util.c (fstype_is_ro, fstype_needs_quota,
//            fstype_has_internal_quota, fstype_can_ownership,
//            fstype_can_uid_gid, file_handle_equal, path_below_api_vfs)

const NETWORK_FSTYPES: &[&str] = &[
    "afs",
    "ceph",
    "cifs",
    "gfs",
    "gfs2",
    "ncp",
    "ncpfs",
    "nfs",
    "nfs4",
    "ocfs2",
    "orangefs",
    "pvfs2",
    "smb3",
    "smbfs",
    "davfs",
    "glusterfs",
    "lustre",
    "sshfs",
];

const API_VFS_FSTYPES: &[&str] = &[
    "cgroup",
    "cgroup2",
    "devpts",
    "devtmpfs",
    "mqueue",
    "proc",
    "sysfs",
    "binfmt_misc",
    "configfs",
    "efivarfs",
    "fusectl",
    "hugetlbfs",
    "rpc_pipefs",
    "securityfs",
    "bpf",
    "debugfs",
    "pstore",
    "tracefs",
    "ramfs",
    "tmpfs",
    "autofs",
    "cpuset",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHandle {
    pub handle_type: i32,
    pub bytes: Vec<u8>,
}

impl FileHandle {
    pub fn new(handle_type: i32, bytes: Vec<u8>) -> Self {
        Self { handle_type, bytes }
    }
}

fn strip_fuse_prefix(fstype: &str) -> &str {
    fstype.strip_prefix("fuse.").unwrap_or(fstype)
}

pub fn fstype_is_ro(fstype: &str) -> bool {
    matches!(
        fstype,
        "DM_verity_hash" | "cramfs" | "erofs" | "iso9660" | "squashfs"
    )
}

pub fn fstype_is_network(fstype: &str) -> bool {
    let fstype = strip_fuse_prefix(fstype);
    NETWORK_FSTYPES.contains(&fstype)
}

pub fn fstype_is_api_vfs(fstype: &str) -> bool {
    API_VFS_FSTYPES.contains(&fstype)
}

pub fn fstype_is_blockdev_backed(fstype: &str) -> bool {
    let fstype = strip_fuse_prefix(fstype);
    !matches!(fstype, "9p" | "overlay") && !fstype_is_network(fstype) && !fstype_is_api_vfs(fstype)
}

pub fn fstype_needs_quota(fstype: &str) -> bool {
    matches!(
        fstype,
        "ext2" | "ext3" | "ext4" | "reiserfs" | "jfs" | "f2fs"
    )
}

/// Filesystems with built-in quota support that do not need quota services.
pub fn fstype_has_internal_quota(fstype: &str) -> bool {
    matches!(fstype, "xfs" | "gfs2" | "ocfs2" | "btrfs")
}

/// Whether the filesystem can represent per-inode uid/gid ownership.
pub fn fstype_can_ownership(fstype: &str) -> bool {
    !matches!(
        fstype,
        "adfs" | "exfat" | "fat" | "hfs" | "hpfs" | "msdos" | "ntfs" | "vfat"
    )
}

pub fn fstype_can_uid_gid(fstype: &str) -> bool {
    matches!(
        fstype,
        "adfs" | "exfat" | "fat" | "hfs" | "hpfs" | "iso9660" | "msdos" | "ntfs" | "vfat"
    )
}

pub fn path_below_api_vfs(path: &str) -> bool {
    matches!(path, "/dev" | "/sys" | "/proc")
        || path.starts_with("/dev/")
        || path.starts_with("/sys/")
        || path.starts_with("/proc/")
}

pub fn file_handle_equal(a: Option<&FileHandle>, b: Option<&FileHandle>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
        (Some(a), Some(b)) => a.handle_type == b.handle_type && a.bytes == b.bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ro_filesystem_set_matches_c_list() {
        assert!(fstype_is_ro("erofs"));
        assert!(fstype_is_ro("squashfs"));
        assert!(!fstype_is_ro("ext4"));
    }

    #[test]
    fn network_filesystems_match_table_and_fuse_aliases() {
        assert!(fstype_is_network("nfs"));
        assert!(fstype_is_network("sshfs"));
        assert!(fstype_is_network("fuse.sshfs"));
        assert!(!fstype_is_network("ext4"));
    }

    #[test]
    fn api_vfs_detection_matches_known_sets() {
        assert!(fstype_is_api_vfs("proc"));
        assert!(fstype_is_api_vfs("tmpfs"));
        assert!(fstype_is_api_vfs("autofs"));
        assert!(!fstype_is_api_vfs("xfs"));
    }

    #[test]
    fn block_device_backed_logic_matches_c_predicate() {
        assert!(fstype_is_blockdev_backed("ext4"));
        assert!(!fstype_is_blockdev_backed("overlay"));
        assert!(!fstype_is_blockdev_backed("nfs"));
        assert!(!fstype_is_blockdev_backed("proc"));
        assert!(!fstype_is_blockdev_backed("fuse.sshfs"));
    }

    #[test]
    fn quota_requirements_match_curated_c_list() {
        assert!(fstype_needs_quota("ext2"));
        assert!(fstype_needs_quota("f2fs"));
        assert!(!fstype_needs_quota("xfs"));
    }

    #[test]
    fn internal_quota_filesystems_match_c_list() {
        assert!(fstype_has_internal_quota("xfs"));
        assert!(fstype_has_internal_quota("btrfs"));
        assert!(!fstype_has_internal_quota("ext4"));
    }

    #[test]
    fn ownership_capability_excludes_fixed_ownership_filesystems() {
        assert!(!fstype_can_ownership("vfat"));
        assert!(!fstype_can_ownership("ntfs"));
        assert!(fstype_can_ownership("ext4"));
        assert!(fstype_can_ownership("iso9660"));
    }

    #[test]
    fn uid_gid_capability_matches_curated_c_list() {
        assert!(fstype_can_uid_gid("vfat"));
        assert!(fstype_can_uid_gid("iso9660"));
        assert!(!fstype_can_uid_gid("ext4"));
    }

    #[test]
    fn api_vfs_path_detection_requires_exact_prefix_boundary() {
        assert!(path_below_api_vfs("/dev"));
        assert!(path_below_api_vfs("/dev/null"));
        assert!(path_below_api_vfs("/proc/self"));
        assert!(!path_below_api_vfs("/procx"));
        assert!(!path_below_api_vfs("/devnull"));
    }

    #[test]
    fn file_handle_equal_treats_two_missing_handles_as_equal() {
        assert!(file_handle_equal(None, None));
    }

    #[test]
    fn file_handle_equal_checks_type_and_bytes() {
        let first = FileHandle::new(7, vec![1, 2, 3]);
        let same = FileHandle::new(7, vec![1, 2, 3]);
        let different_type = FileHandle::new(8, vec![1, 2, 3]);
        let different_bytes = FileHandle::new(7, vec![3, 2, 1]);

        assert!(file_handle_equal(Some(&first), Some(&same)));
        assert!(!file_handle_equal(Some(&first), Some(&different_type)));
        assert!(!file_handle_equal(Some(&first), Some(&different_bytes)));
        assert!(!file_handle_equal(Some(&first), None));
    }
}
