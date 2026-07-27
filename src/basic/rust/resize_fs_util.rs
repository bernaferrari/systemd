// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/resize-fs.c (minimal_size_by_fs_name, minimal_size_by_fs_magic,
//            fs_can_online_shrink_and_grow)
//
// Filesystem resize utilities — pure computation, no I/O.

// ── Constants from linux/magic.h ──────────────────────────────────────────

const EXT4_SUPER_MAGIC: u64 = 0xEF53;
const XFS_SUPER_MAGIC: u64 = 0x58465342;
const BTRFS_SUPER_MAGIC: u64 = 0x9123683E;

// ── Constants from macro.h / resize-fs.h ─────────────────────────────────

const U64_KB: u64 = 1024;
const U64_MB: u64 = 1024 * U64_KB;

const EXT4_MINIMAL_SIZE: u64 = 32 * U64_MB;
const XFS_MINIMAL_SIZE: u64 = 300 * U64_MB;
const BTRFS_MINIMAL_SIZE: u64 = 256 * U64_MB;

// ── Public API ────────────────────────────────────────────────────────────

/// Faithful port of C minimal_size_by_fs_name().
/// Returns the minimal filesystem size for the given filesystem name,
/// or `u64::MAX` if the filesystem type is unknown.
pub fn minimal_size_by_fs_name(name: &str) -> u64 {
    match name {
        "ext4" => EXT4_MINIMAL_SIZE,
        "xfs" => XFS_MINIMAL_SIZE,
        "btrfs" => BTRFS_MINIMAL_SIZE,
        _ => u64::MAX,
    }
}

/// Faithful port of C minimal_size_by_fs_magic().
/// Returns the minimal filesystem size for the given filesystem magic number,
/// or `u64::MAX` if the magic is unknown.
pub fn minimal_size_by_fs_magic(magic: u64) -> u64 {
    match magic {
        EXT4_SUPER_MAGIC => EXT4_MINIMAL_SIZE,
        XFS_SUPER_MAGIC => XFS_MINIMAL_SIZE,
        BTRFS_SUPER_MAGIC => BTRFS_MINIMAL_SIZE,
        _ => u64::MAX,
    }
}

/// Faithful port of C fs_can_online_shrink_and_grow().
/// Returns true for the only filesystem that can online shrink AND grow (btrfs).
pub fn fs_can_online_shrink_and_grow(magic: u64) -> bool {
    magic == BTRFS_SUPER_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── minimal_size_by_fs_name tests ───────────────────────────────────

    #[test]
    fn test_minimal_size_by_fs_name_ext4() {
        assert_eq!(minimal_size_by_fs_name("ext4"), EXT4_MINIMAL_SIZE);
    }

    #[test]
    fn test_minimal_size_by_fs_name_xfs() {
        assert_eq!(minimal_size_by_fs_name("xfs"), XFS_MINIMAL_SIZE);
    }

    #[test]
    fn test_minimal_size_by_fs_name_btrfs() {
        assert_eq!(minimal_size_by_fs_name("btrfs"), BTRFS_MINIMAL_SIZE);
    }

    #[test]
    fn test_minimal_size_by_fs_name_unknown() {
        assert_eq!(minimal_size_by_fs_name("vfat"), u64::MAX);
    }

    #[test]
    fn test_minimal_size_by_fs_name_empty() {
        assert_eq!(minimal_size_by_fs_name(""), u64::MAX);
    }

    #[test]
    fn test_minimal_size_by_fs_name_case_sensitive() {
        assert_eq!(minimal_size_by_fs_name("Ext4"), u64::MAX);
        assert_eq!(minimal_size_by_fs_name("BTRFS"), u64::MAX);
        assert_eq!(minimal_size_by_fs_name("XFS"), u64::MAX);
    }

    // ── minimal_size_by_fs_magic tests ──────────────────────────────────

    #[test]
    fn test_minimal_size_by_fs_magic_ext4() {
        assert_eq!(
            minimal_size_by_fs_magic(EXT4_SUPER_MAGIC),
            EXT4_MINIMAL_SIZE
        );
    }

    #[test]
    fn test_minimal_size_by_fs_magic_xfs() {
        assert_eq!(minimal_size_by_fs_magic(XFS_SUPER_MAGIC), XFS_MINIMAL_SIZE);
    }

    #[test]
    fn test_minimal_size_by_fs_magic_btrfs() {
        assert_eq!(
            minimal_size_by_fs_magic(BTRFS_SUPER_MAGIC),
            BTRFS_MINIMAL_SIZE
        );
    }

    #[test]
    fn test_minimal_size_by_fs_magic_unknown() {
        assert_eq!(minimal_size_by_fs_magic(0), u64::MAX);
        assert_eq!(minimal_size_by_fs_magic(u64::MAX), u64::MAX);
        assert_eq!(minimal_size_by_fs_magic(0x1234), u64::MAX);
    }

    // ── fs_can_online_shrink_and_grow tests ─────────────────────────────

    #[test]
    fn test_fs_can_online_shrink_and_grow_btrfs() {
        assert!(fs_can_online_shrink_and_grow(BTRFS_SUPER_MAGIC));
    }

    #[test]
    fn test_fs_can_online_shrink_and_grow_others() {
        assert!(!fs_can_online_shrink_and_grow(EXT4_SUPER_MAGIC));
        assert!(!fs_can_online_shrink_and_grow(XFS_SUPER_MAGIC));
        assert!(!fs_can_online_shrink_and_grow(0));
        assert!(!fs_can_online_shrink_and_grow(u64::MAX));
    }

    // ── constant correctness ────────────────────────────────────────────

    #[test]
    fn test_constants_match_c_header() {
        assert_eq!(EXT4_MINIMAL_SIZE, 32 * 1024 * 1024);
        assert_eq!(XFS_MINIMAL_SIZE, 300 * 1024 * 1024);
        assert_eq!(BTRFS_MINIMAL_SIZE, 256 * 1024 * 1024);
    }

    #[test]
    fn test_magic_values_match_linux_headers() {
        assert_eq!(EXT4_SUPER_MAGIC, 0xEF53);
        assert_eq!(XFS_SUPER_MAGIC, 0x58465342);
        assert_eq!(BTRFS_SUPER_MAGIC, 0x9123683E);
    }
}
