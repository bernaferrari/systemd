// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.fstype-util; authority=src/basic/mountpoint-util.c,src/basic/mountpoint-util.h,src/basic/filesystem-sets.py

const NETWORK_FSTYPES: &[&[u8]] = &[
    b"afs",
    b"ceph",
    b"cifs",
    b"gfs",
    b"gfs2",
    b"ncp",
    b"ncpfs",
    b"nfs",
    b"nfs4",
    b"ocfs2",
    b"orangefs",
    b"pvfs2",
    b"smb3",
    b"smbfs",
    b"davfs",
    b"glusterfs",
    b"lustre",
    b"sshfs",
];

const API_VFS_FSTYPES: &[&[u8]] = &[
    b"cgroup",
    b"cgroup2",
    b"devpts",
    b"devtmpfs",
    b"mqueue",
    b"proc",
    b"sysfs",
    b"binfmt_misc",
    b"configfs",
    b"efivarfs",
    b"fusectl",
    b"hugetlbfs",
    b"rpc_pipefs",
    b"securityfs",
    b"bpf",
    b"debugfs",
    b"pstore",
    b"tracefs",
    b"ramfs",
    b"tmpfs",
    b"autofs",
    b"cpuset",
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

#[inline]
fn strip_fuse_prefix(fstype: &[u8]) -> &[u8] {
    fstype.strip_prefix(b"fuse.").unwrap_or(fstype)
}

pub fn fstype_is_ro(fstype: &str) -> bool {
    fstype_is_ro_bytes(fstype.as_bytes())
}

pub fn fstype_is_network(fstype: &str) -> bool {
    fstype_is_network_bytes(fstype.as_bytes())
}

pub fn fstype_is_api_vfs(fstype: &str) -> bool {
    fstype_is_api_vfs_bytes(fstype.as_bytes())
}

pub fn fstype_is_blockdev_backed(fstype: &str) -> bool {
    fstype_is_blockdev_backed_bytes(fstype.as_bytes())
}

pub fn fstype_needs_quota(fstype: &str) -> bool {
    fstype_needs_quota_bytes(fstype.as_bytes())
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
    fstype_can_uid_gid_bytes(fstype.as_bytes())
}

pub fn path_below_api_vfs(path: &str) -> bool {
    path_below_api_vfs_bytes(path.as_bytes())
}

#[inline]
fn fstype_is_ro_bytes(fstype: &[u8]) -> bool {
    fstype == b"DM_verity_hash"
        || fstype == b"cramfs"
        || fstype == b"erofs"
        || fstype == b"iso9660"
        || fstype == b"squashfs"
}

#[inline]
fn fstype_is_network_bytes(fstype: &[u8]) -> bool {
    let fstype = strip_fuse_prefix(fstype);
    NETWORK_FSTYPES.iter().any(|candidate| *candidate == fstype)
}

#[inline]
fn fstype_is_api_vfs_bytes(fstype: &[u8]) -> bool {
    API_VFS_FSTYPES.iter().any(|candidate| *candidate == fstype)
}

#[inline]
fn fstype_is_blockdev_backed_bytes(fstype: &[u8]) -> bool {
    let fstype = strip_fuse_prefix(fstype);
    fstype != b"9p"
        && fstype != b"overlay"
        && !fstype_is_network_bytes(fstype)
        && !fstype_is_api_vfs_bytes(fstype)
}

#[inline]
fn fstype_needs_quota_bytes(fstype: &[u8]) -> bool {
    fstype == b"ext2"
        || fstype == b"ext3"
        || fstype == b"ext4"
        || fstype == b"reiserfs"
        || fstype == b"jfs"
        || fstype == b"f2fs"
}

#[inline]
fn fstype_can_uid_gid_bytes(fstype: &[u8]) -> bool {
    fstype == b"adfs"
        || fstype == b"exfat"
        || fstype == b"fat"
        || fstype == b"hfs"
        || fstype == b"hpfs"
        || fstype == b"iso9660"
        || fstype == b"msdos"
        || fstype == b"ntfs"
        || fstype == b"vfat"
}

#[inline]
fn path_below_api_vfs_bytes(path: &[u8]) -> bool {
    path == b"/dev"
        || path == b"/sys"
        || path == b"/proc"
        || path.starts_with(b"/dev/")
        || path.starts_with(b"/sys/")
        || path.starts_with(b"/proc/")
}

/// Apply a predicate to an optional borrowed C string's raw, non-NUL bytes.
///
/// # Safety
///
/// When non-NULL, `input` must point to a live NUL-terminated C string for
/// the duration of the call. `predicate` must not retain the borrowed slice.
#[inline]
unsafe fn c_string_predicate(
    input: *const libc::c_char,
    predicate: impl FnOnce(&[u8]) -> bool,
) -> bool {
    if input.is_null() {
        return false;
    }

    // SAFETY: required by this helper's contract after the NULL check.
    predicate(unsafe { std::ffi::CStr::from_ptr(input) }.to_bytes())
}

/// C ABI facade for `fstype_is_ro()`.
///
/// # Safety
///
/// `fstype`, when non-NULL, must point to a live NUL-terminated C string.
/// NULL is treated as invalid input and returns `false`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_fstype_is_ro(fstype: *const libc::c_char) -> bool {
    // SAFETY: required by this entry point's contract.
    unsafe { c_string_predicate(fstype, fstype_is_ro_bytes) }
}

/// C ABI facade for `fstype_needs_quota()`.
///
/// # Safety
///
/// `fstype`, when non-NULL, must point to a live NUL-terminated C string.
/// NULL is treated as invalid input and returns `false`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_fstype_needs_quota(fstype: *const libc::c_char) -> bool {
    // SAFETY: required by this entry point's contract.
    unsafe { c_string_predicate(fstype, fstype_needs_quota_bytes) }
}

/// C ABI facade for `fstype_can_uid_gid()`.
///
/// # Safety
///
/// `fstype`, when non-NULL, must point to a live NUL-terminated C string.
/// NULL is treated as invalid input and returns `false`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_fstype_can_uid_gid(fstype: *const libc::c_char) -> bool {
    // SAFETY: required by this entry point's contract.
    unsafe { c_string_predicate(fstype, fstype_can_uid_gid_bytes) }
}

/// C ABI facade for `path_below_api_vfs()`.
///
/// # Safety
///
/// `path`, when non-NULL, must point to a live NUL-terminated C string.
/// NULL is treated as invalid input and returns `false`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_below_api_vfs(path: *const libc::c_char) -> bool {
    // SAFETY: required by this entry point's contract.
    unsafe { c_string_predicate(path, path_below_api_vfs_bytes) }
}

/// C ABI facade for `fstype_is_network()`.
///
/// # Safety
///
/// `fstype`, when non-NULL, must point to a live NUL-terminated C string.
/// NULL is treated as invalid input and returns `false`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_fstype_is_network(fstype: *const libc::c_char) -> bool {
    // SAFETY: required by this entry point's contract.
    unsafe { c_string_predicate(fstype, fstype_is_network_bytes) }
}

/// C ABI facade for `fstype_is_api_vfs()`.
///
/// # Safety
///
/// `fstype`, when non-NULL, must point to a live NUL-terminated C string.
/// NULL is treated as invalid input and returns `false`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_fstype_is_api_vfs(fstype: *const libc::c_char) -> bool {
    // SAFETY: required by this entry point's contract.
    unsafe { c_string_predicate(fstype, fstype_is_api_vfs_bytes) }
}

/// C ABI facade for `fstype_is_blockdev_backed()`.
///
/// # Safety
///
/// `fstype`, when non-NULL, must point to a live NUL-terminated C string.
/// NULL is treated as invalid input and returns `false`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_fstype_is_blockdev_backed(fstype: *const libc::c_char) -> bool {
    // SAFETY: required by this entry point's contract.
    unsafe { c_string_predicate(fstype, fstype_is_blockdev_backed_bytes) }
}

/// C ABI facade for `file_handle_equal()`.
///
/// # Safety
///
/// Each non-NULL pointer must point to a live, properly aligned native
/// `struct file_handle`, followed by at least `handle_bytes` readable payload
/// bytes. The pointed-to storage must remain live for the duration of the
/// call. NULL is supported and follows the C function's pointer semantics.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_file_handle_equal(
    a: *const libc::file_handle,
    b: *const libc::file_handle,
) -> bool {
    if std::ptr::eq(a, b) {
        return true;
    }
    if a.is_null() || b.is_null() {
        return false;
    }

    // SAFETY: the entry point contract guarantees that both non-NULL pointers
    // reference initialized native file_handle headers for this call.
    let a = unsafe { &*a };
    // SAFETY: the entry point contract guarantees that both non-NULL pointers
    // reference initialized native file_handle headers for this call.
    let b = unsafe { &*b };

    if a.handle_type != b.handle_type {
        return false;
    }

    let a_len = a.handle_bytes as usize;
    let b_len = b.handle_bytes as usize;
    let shared_len = a_len.min(b_len);
    if shared_len > 0 {
        // SAFETY: the entry point contract guarantees that each flexible-array
        // payload contains its advertised number of readable bytes.
        let a_bytes = unsafe { std::slice::from_raw_parts(a.f_handle.as_ptr(), shared_len) };
        // SAFETY: the entry point contract guarantees that each flexible-array
        // payload contains its advertised number of readable bytes.
        let b_bytes = unsafe { std::slice::from_raw_parts(b.f_handle.as_ptr(), shared_len) };

        if a_bytes != b_bytes {
            return false;
        }
    }

    a_len == b_len
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
