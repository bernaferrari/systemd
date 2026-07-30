// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/btrfs-util.c, src/shared/btrfs-util.h
//
// Btrfs filesystem utility types, pure-logic helpers, and a safe backing-device
// query facade.
//
// This module provides idiomatic Rust types and pure functions that mirror
// the C btrfs-util implementation. The backing-device query is deliberately
// delegated to the authoritative C implementation so its ioctl validation,
// single-device policy, and kernel-error behavior remain shared.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

// SAFETY: This is the exact exported declaration from btrfs-util.h. The safe
// wrapper below supplies a live descriptor, null optional inputs/outputs, and
// a uniquely borrowed, correctly typed dev_t output slot.
unsafe extern "C" {
    #[link_name = "btrfs_get_block_device_at_full"]
    fn c_btrfs_get_block_device_at_full(
        dir_fd: libc::c_int,
        path: *const libc::c_char,
        ret_devid: *mut u64,
        ret_path: *mut *mut libc::c_char,
        ret: *mut libc::dev_t,
    ) -> libc::c_int;
}

// ── Constants ─────────────────────────────────────────────────────────────

/// Number of bits the qgroup level occupies in a packed qgroupid.
pub const BTRFS_QGROUP_LEVEL_SHIFT: u32 = 48;

/// Btrfs subvolumes always have inode 256.
pub const BTRFS_SUBVOL_INODE_NUMBER: u64 = 256;

/// Maximum path length for btrfs volume arguments.
pub const BTRFS_PATH_NAME_MAX: usize = 4096;

/// Sentinel for "no qgroup found" in subtree qgroup searches.
pub const BTRFS_NO_QGROUP: u64 = u64::MAX;

// ── Safe I/O facade ───────────────────────────────────────────────────────

/// Return the sole block device backing the btrfs filesystem at `fd`.
///
/// This is the fd form of C's `btrfs_get_block_device_at_full()`. `Ok(None)`
/// means that the filesystem has multiple devices; the C helper intentionally
/// declines to select one in that case. A non-btrfs descriptor is reported as
/// `ENOTTY`, and all other kernel/filesystem errors retain their original
/// errno.
///
/// The descriptor is borrowed and is never consumed or closed.
pub fn btrfs_get_block_device_fd(fd: BorrowedFd<'_>) -> io::Result<Option<libc::dev_t>> {
    let mut device: libc::dev_t = 0;

    // SAFETY: `fd` stays live for the call, null selects the fd itself exactly
    // like the C inline btrfs_get_block_device_fd(), unused outputs are null,
    // and `device` is a valid unique output slot.
    let result = unsafe {
        c_btrfs_get_block_device_at_full(
            fd.as_raw_fd(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut device,
        )
    };

    if result < 0 {
        return Err(io::Error::from_raw_os_error(-result));
    }
    if result == 0 {
        return Ok(None);
    }

    debug_assert_eq!(result, 1);
    Ok(Some(device))
}

// ── Data structures ───────────────────────────────────────────────────────

/// Information about a btrfs subvolume.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BtrfsSubvolInfo {
    pub subvol_id: u64,
    /// Creation time in microseconds.
    pub otime: u64,
    /// Change time in microseconds.
    pub ctime: u64,
    /// 128-bit UUID of this subvolume.
    pub uuid: [u8; 16],
    /// 128-bit UUID of the parent subvolume.
    pub parent_uuid: [u8; 16],
    pub read_only: bool,
}

/// Quota usage information for a btrfs qgroup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsQuotaInfo {
    /// Bytes referenced (shared + exclusive).
    pub referenced: u64,
    /// Bytes exclusive to this qgroup.
    pub exclusive: u64,
    /// Hard limit on referenced bytes (u64::MAX = unlimited).
    pub referenced_max: u64,
    /// Hard limit on exclusive bytes (u64::MAX = unlimited).
    pub exclusive_max: u64,
}

impl Default for BtrfsQuotaInfo {
    fn default() -> Self {
        Self {
            referenced: u64::MAX,
            exclusive: u64::MAX,
            referenced_max: u64::MAX,
            exclusive_max: u64::MAX,
        }
    }
}

bitflags::bitflags! {
    /// Flags controlling btrfs subvolume snapshot creation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BtrfsSnapshotFlags: u32 {
        const FALLBACK_COPY      = 1 << 0;
        const READ_ONLY          = 1 << 1;
        const RECURSIVE          = 1 << 2;
        const QUOTA              = 1 << 3;
        const FALLBACK_DIRECTORY = 1 << 4;
        const FALLBACK_IMMUTABLE = 1 << 5;
        const SIGINT             = 1 << 6;
        const SIGTERM            = 1 << 7;
        const LOCK_BSD           = 1 << 8;
    }
}

bitflags::bitflags! {
    /// Flags controlling btrfs subvolume removal.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BtrfsRemoveFlags: u32 {
        const RECURSIVE = 1 << 0;
        const QUOTA     = 1 << 1;
    }
}

/// A single stripe within a btrfs chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsStripe {
    pub devid: u64,
    pub offset: u64,
}

/// A btrfs chunk (extent mapping).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsChunk {
    pub offset: u64,
    pub length: u64,
    pub chunk_type: u64,
    pub stripes: Vec<BtrfsStripe>,
    pub stripe_len: u64,
}

/// Collection of btrfs chunks, sorted by offset for binary search.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BtrfsChunkTree {
    pub chunks: Vec<BtrfsChunk>,
}

// ── Btrfs ioctl search key (pure logic) ───────────────────────────────────

/// A btrfs search key, matching `struct btrfs_ioctl_search_key`.
///
/// Used to control btrfs tree searches via `BTRFS_IOC_TREE_SEARCH`.
/// The min/max fields define the search range; the iterator helpers
/// advance through results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtrfsSearchKey {
    pub tree_id: u64,
    pub min_objectid: u64,
    pub max_objectid: u64,
    pub min_type: u64,
    pub max_type: u64,
    pub min_offset: u64,
    pub max_offset: u64,
    pub min_transid: u64,
    pub max_transid: u64,
    pub nr_items: u32,
}

impl Default for BtrfsSearchKey {
    fn default() -> Self {
        Self {
            tree_id: 0,
            min_objectid: 0,
            max_objectid: 0,
            min_type: 0,
            max_type: 0,
            min_offset: 0,
            max_offset: u64::MAX,
            min_transid: 0,
            max_transid: u64::MAX,
            nr_items: 0,
        }
    }
}

/// Header returned for each item in a btrfs tree search result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsSearchHeader {
    pub objectid: u64,
    pub offset: u64,
    pub transid: u64,
    pub type_: u64,
    pub len: u32,
}

// ── Pure helper functions ─────────────────────────────────────────────────

/// Construct a qgroupid from its level and id components.
///
/// Returns `Ok(qgroupid)` on success, or `Err(-EINVAL)` if either component
/// overflows its bit-width. The level uses the upper 16 bits (48..=63),
/// the id uses the lower 48 bits.
///
/// Corresponds to `btrfs_qgroupid_make()` in btrfs-util.c.
pub fn qgroupid_make(level: u64, id: u64) -> Result<u64, i32> {
    let max_level = 1u64 << (64 - BTRFS_QGROUP_LEVEL_SHIFT);
    let max_id = 1u64 << BTRFS_QGROUP_LEVEL_SHIFT;

    if level >= max_level {
        return Err(-22); // -EINVAL
    }
    if id >= max_id {
        return Err(-22);
    }

    Ok((level << BTRFS_QGROUP_LEVEL_SHIFT) | id)
}

/// Split a qgroupid into its level and id components.
///
/// Either or both output values can be requested. Returns the split values
/// as `(Option<level>, Option<id>)`.
///
/// Corresponds to `btrfs_qgroupid_split()` in btrfs-util.c.
pub fn qgroupid_split(qgroupid: u64) -> (u64, u64) {
    let level = qgroupid >> BTRFS_QGROUP_LEVEL_SHIFT;
    let id = qgroupid & ((1u64 << BTRFS_QGROUP_LEVEL_SHIFT) - 1);
    (level, id)
}

/// Check whether a directory's inode number suggests it could be a btrfs subvolume.
///
/// This is a heuristic: btrfs subvolumes always have inode 256. A final
/// determination requires additionally checking the filesystem type.
///
/// Corresponds to `btrfs_might_be_subvol()` in btrfs-util.c.
pub fn might_be_subvol(ino: u64, is_dir: bool) -> bool {
    is_dir && ino == BTRFS_SUBVOL_INODE_NUMBER
}

/// Advance the minimum bounds of a btrfs search key by one position.
///
/// The btrfs key is a composite of (objectid, type, offset) treated as
/// a single 136-bit integer. This increments with proper carry propagation.
///
/// Returns `true` if the key was successfully advanced, `false` if it has
/// wrapped past the maximum.
///
/// Corresponds to `btrfs_ioctl_search_args_inc()` in btrfs-util.c.
pub fn search_key_inc(key: &mut BtrfsSearchKey) -> bool {
    if key.min_offset < u64::MAX {
        key.min_offset += 1;
        return true;
    }

    if key.min_type < u8::MAX as u64 {
        key.min_type += 1;
        key.min_offset = 0;
        return true;
    }

    if key.min_objectid < u64::MAX {
        key.min_objectid += 1;
        key.min_offset = 0;
        key.min_type = 0;
        return true;
    }

    false
}

/// Set the minimum bounds of a search key from a search result header.
///
/// This ensures the next search starts at or after the given header position.
///
/// Corresponds to `btrfs_ioctl_search_args_set()` in btrfs-util.c.
pub fn search_key_set(key: &mut BtrfsSearchKey, header: &BtrfsSearchHeader) {
    key.min_objectid = header.objectid;
    key.min_type = header.type_;
    key.min_offset = header.offset;
}

/// Compare the min and max bounds of a search key.
///
/// Returns negative if min < max, zero if equal, positive if min > max.
/// Used to determine if the search range has been exhausted.
///
/// Corresponds to `btrfs_ioctl_search_args_compare()` in btrfs-util.c.
pub fn search_key_compare(key: &BtrfsSearchKey) -> i32 {
    let r = key.min_objectid.cmp(&key.max_objectid);
    if r != std::cmp::Ordering::Equal {
        return r as i32;
    }

    let r = key.min_type.cmp(&key.max_type);
    if r != std::cmp::Ordering::Equal {
        return r as i32;
    }

    key.min_offset.cmp(&key.max_offset) as i32
}

/// Find a chunk in the chunk tree that contains the given logical address.
///
/// Uses binary search over the (sorted) chunk list. Returns the index of
/// the chunk containing the address, or `None` if no chunk matches.
///
/// Corresponds to `btrfs_find_chunk_from_logical_address()` in btrfs-util.c.
pub fn find_chunk_from_logical_address(tree: &BtrfsChunkTree, logical: u64) -> Option<usize> {
    if tree.chunks.is_empty() {
        return None;
    }

    let mut lo = 0usize;
    let mut hi = tree.chunks.len() - 1;

    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        let chunk = &tree.chunks[mid];

        if logical < chunk.offset {
            if mid == 0 {
                return None;
            }
            hi = mid - 1;
        } else if logical >= chunk.offset + chunk.length {
            lo = mid + 1;
        } else {
            return Some(mid);
        }
    }

    None
}

/// Compute the physical offset on disk for a file extent.
///
/// Given a chunk and a logical address within it, computes the physical
/// offset using stripe information. Returns `None` for non-single profiles
/// or invalid stripe configurations.
///
/// Corresponds to the stripe math in `btrfs_get_file_physical_offset_fd()`.
pub fn compute_physical_offset(chunk: &BtrfsChunk, logical: u64) -> Option<u64> {
    // Only SINGLE profile (no RAID bits set)
    const BTRFS_BLOCK_GROUP_PROFILE_MASK: u64 = 0x07E0;
    if (chunk.chunk_type & BTRFS_BLOCK_GROUP_PROFILE_MASK) != 0 {
        return None;
    }

    if chunk.stripes.is_empty() || chunk.stripe_len == 0 {
        return None;
    }

    assert!(logical >= chunk.offset);
    let relative_chunk = logical - chunk.offset;
    let stripe_nr = relative_chunk / chunk.stripe_len;
    let relative_stripe = relative_chunk - stripe_nr * chunk.stripe_len;
    let stripe_index = (stripe_nr as usize) % chunk.stripes.len();

    let stripe = &chunk.stripes[stripe_index];
    Some(
        stripe.offset
            + (stripe_nr as usize / chunk.stripes.len()) as u64 * chunk.stripe_len
            + relative_stripe,
    )
}

/// Determine if a filesystem stat looks like a btrfs subvolume.
///
/// Convenience wrapper that takes raw stat fields.
/// Returns `true` if `st_mode` indicates a directory and `st_ino == 256`.
pub fn is_btrfs_subvol_inode(st_mode: u32, st_ino: u64) -> bool {
    // S_ISDIR check: mode & 0xF000 == 0x4000
    (st_mode & 0xF000) == 0x4000 && st_ino == BTRFS_SUBVOL_INODE_NUMBER
}

/// Find the lowest-level parent qgroup for a subvolume.
///
/// Given a subvolume's leaf qgroup id and a list of parent qgroup ids,
/// finds the parent with the lowest level that shares the same id part.
///
/// Returns `Some((qgroupid, level))` if a subtree qgroup was found,
/// `None` if no suitable higher-level qgroup exists (the leaf qgroup
/// itself should be used).
///
/// Corresponds to the core logic of `btrfs_subvol_find_subtree_qgroup()`.
pub fn find_subtree_qgroup(subvol_id: u64, parent_qgroups: &[u64]) -> Option<(u64, u64)> {
    let (subvol_level, _) = qgroupid_split(subvol_id);
    if subvol_level != 0 {
        // Input must be a leaf qgroup
        return None;
    }

    let mut lowest = u64::MAX;
    let mut lowest_qgroupid = 0u64;

    for &qgroup in parent_qgroups {
        let (level, id) = qgroupid_split(qgroup);
        if id != subvol_id {
            continue;
        }
        if lowest == u64::MAX || level < lowest {
            lowest_qgroupid = qgroup;
            lowest = level;
        }
    }

    if lowest == u64::MAX {
        None
    } else {
        Some((lowest_qgroupid, lowest))
    }
}

/// Construct a search key for quota tree queries scoped to a specific qgroupid.
///
/// Sets up the key to search the quota tree (`BTRFS_QUOTA_TREE_OBJECTID`)
/// for items related to the given qgroupid, within the specified type range.
pub fn quota_search_key(qgroupid: u64, min_type: u64, max_type: u64) -> BtrfsSearchKey {
    BtrfsSearchKey {
        tree_id: 0, // BTRFS_QUOTA_TREE_OBJECTID
        min_objectid: 0,
        max_objectid: 0,
        min_type,
        max_type,
        min_offset: qgroupid,
        max_offset: qgroupid,
        min_transid: 0,
        max_transid: u64::MAX,
        nr_items: 256,
    }
}

/// Construct a search key for root tree queries scoped to a subvolume.
///
/// Sets up the key to search the root tree for backref entries
/// related to child subvolumes of the given subvol_id.
pub fn root_backref_search_key(subvol_id: u64) -> BtrfsSearchKey {
    BtrfsSearchKey {
        tree_id: 0,             // BTRFS_ROOT_TREE_OBJECTID
        min_objectid: 0,        // BTRFS_FIRST_FREE_OBJECTID
        max_objectid: u64::MAX, // BTRFS_LAST_FREE_OBJECTID
        min_type: 0,            // BTRFS_ROOT_BACKREF_KEY
        max_type: 0,
        min_offset: subvol_id,
        max_offset: subvol_id,
        min_transid: 0,
        max_transid: u64::MAX,
        nr_items: 256,
    }
}

/// Check if a path exceeds the btrfs path name limit.
///
/// Returns `true` if the path is too long for btrfs volume arguments.
pub fn path_exceeds_limit(path: &str) -> bool {
    path.len() > BTRFS_PATH_NAME_MAX
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qgroupid_make_basic() {
        // Level 0, id 256 -> qgroupid = 256
        assert_eq!(qgroupid_make(0, 256).unwrap(), 256);
        // Level 1, id 256 -> qgroupid = (1 << 48) | 256
        assert_eq!(qgroupid_make(1, 256).unwrap(), (1u64 << 48) | 256);
    }

    #[test]
    fn test_qgroupid_make_roundtrip() {
        for level in [0u64, 1, 100, 255] {
            for id in [0u64, 1, 256, (1u64 << 48) - 1] {
                let qgroupid = qgroupid_make(level, id).unwrap();
                let (got_level, got_id) = qgroupid_split(qgroupid);
                assert_eq!(got_level, level, "level mismatch for ({level}, {id})");
                assert_eq!(got_id, id, "id mismatch for ({level}, {id})");
            }
        }
    }

    #[test]
    fn test_qgroupid_make_invalid_level() {
        // Level must fit in 16 bits
        let max_level = 1u64 << 16;
        assert_eq!(qgroupid_make(max_level, 0), Err(-22));
        assert_eq!(qgroupid_make(u64::MAX, 0), Err(-22));
    }

    #[test]
    fn test_qgroupid_make_invalid_id() {
        // Id must fit in 48 bits
        let max_id = 1u64 << 48;
        assert_eq!(qgroupid_make(0, max_id), Err(-22));
    }

    #[test]
    fn test_qgroupid_split_zero() {
        let (level, id) = qgroupid_split(0);
        assert_eq!(level, 0);
        assert_eq!(id, 0);
    }

    #[test]
    fn test_might_be_subvol() {
        assert!(might_be_subvol(256, true));
        assert!(!might_be_subvol(257, true));
        assert!(!might_be_subvol(256, false)); // not a directory
        assert!(!might_be_subvol(0, false));
    }

    #[test]
    fn test_is_btrfs_subvol_inode() {
        // S_IFDIR = 0x4000
        assert!(is_btrfs_subvol_inode(0o40755, 256));
        assert!(!is_btrfs_subvol_inode(0o40755, 257));
        assert!(!is_btrfs_subvol_inode(0o100644, 256)); // regular file
    }

    #[test]
    fn test_search_key_inc_offset() {
        let mut key = BtrfsSearchKey::default();
        key.min_offset = 100;
        assert!(search_key_inc(&mut key));
        assert_eq!(key.min_offset, 101);
        assert_eq!(key.min_type, 0);
        assert_eq!(key.min_objectid, 0);
    }

    #[test]
    fn test_search_key_inc_offset_overflow() {
        let mut key = BtrfsSearchKey::default();
        key.min_offset = u64::MAX;
        key.min_type = 5;
        assert!(search_key_inc(&mut key));
        assert_eq!(key.min_offset, 0);
        assert_eq!(key.min_type, 6);
    }

    #[test]
    fn test_search_key_inc_type_overflow() {
        let mut key = BtrfsSearchKey::default();
        key.min_offset = u64::MAX;
        key.min_type = u8::MAX as u64;
        key.min_objectid = 42;
        assert!(search_key_inc(&mut key));
        assert_eq!(key.min_offset, 0);
        assert_eq!(key.min_type, 0);
        assert_eq!(key.min_objectid, 43);
    }

    #[test]
    fn test_search_key_inc_full_overflow() {
        let mut key = BtrfsSearchKey::default();
        key.min_offset = u64::MAX;
        key.min_type = u8::MAX as u64;
        key.min_objectid = u64::MAX;
        assert!(!search_key_inc(&mut key));
    }

    #[test]
    fn test_search_key_set() {
        let mut key = BtrfsSearchKey::default();
        let header = BtrfsSearchHeader {
            objectid: 42,
            offset: 100,
            transid: 7,
            type_: 3,
            len: 50,
        };
        search_key_set(&mut key, &header);
        assert_eq!(key.min_objectid, 42);
        assert_eq!(key.min_type, 3);
        assert_eq!(key.min_offset, 100);
    }

    #[test]
    fn test_search_key_compare_equal() {
        let key = BtrfsSearchKey {
            min_objectid: 5,
            max_objectid: 5,
            min_type: 3,
            max_type: 3,
            min_offset: 10,
            max_offset: 10,
            ..Default::default()
        };
        assert_eq!(search_key_compare(&key), 0);
    }

    #[test]
    fn test_search_key_compare_less() {
        let key = BtrfsSearchKey {
            min_objectid: 5,
            max_objectid: 10,
            min_type: 3,
            max_type: 3,
            min_offset: 10,
            max_offset: 10,
            ..Default::default()
        };
        assert!(search_key_compare(&key) < 0);
    }

    #[test]
    fn test_search_key_compare_greater() {
        let key = BtrfsSearchKey {
            min_objectid: 10,
            max_objectid: 5,
            min_type: 3,
            max_type: 3,
            min_offset: 10,
            max_offset: 10,
            ..Default::default()
        };
        assert!(search_key_compare(&key) > 0);
    }

    #[test]
    fn test_find_chunk_empty_tree() {
        let tree = BtrfsChunkTree::default();
        assert!(find_chunk_from_logical_address(&tree, 0).is_none());
    }

    #[test]
    fn test_find_chunk_exact_match() {
        let tree = BtrfsChunkTree {
            chunks: vec![BtrfsChunk {
                offset: 1000,
                length: 500,
                chunk_type: 0,
                stripes: vec![],
                stripe_len: 4096,
            }],
        };
        assert_eq!(find_chunk_from_logical_address(&tree, 1000), Some(0));
        assert_eq!(find_chunk_from_logical_address(&tree, 1250), Some(0));
        assert_eq!(find_chunk_from_logical_address(&tree, 1499), Some(0));
    }

    #[test]
    fn test_find_chunk_before_and_after() {
        let tree = BtrfsChunkTree {
            chunks: vec![BtrfsChunk {
                offset: 1000,
                length: 500,
                chunk_type: 0,
                stripes: vec![],
                stripe_len: 4096,
            }],
        };
        // Before the chunk
        assert!(find_chunk_from_logical_address(&tree, 999).is_none());
        // Past the end
        assert!(find_chunk_from_logical_address(&tree, 1500).is_none());
    }

    #[test]
    fn test_find_chunk_multiple() {
        let tree = BtrfsChunkTree {
            chunks: vec![
                BtrfsChunk {
                    offset: 0,
                    length: 100,
                    chunk_type: 0,
                    stripes: vec![],
                    stripe_len: 4096,
                },
                BtrfsChunk {
                    offset: 200,
                    length: 300,
                    chunk_type: 0,
                    stripes: vec![],
                    stripe_len: 4096,
                },
                BtrfsChunk {
                    offset: 600,
                    length: 400,
                    chunk_type: 0,
                    stripes: vec![],
                    stripe_len: 4096,
                },
            ],
        };
        assert_eq!(find_chunk_from_logical_address(&tree, 50), Some(0));
        assert_eq!(find_chunk_from_logical_address(&tree, 150), None); // gap
        assert_eq!(find_chunk_from_logical_address(&tree, 250), Some(1));
        assert_eq!(find_chunk_from_logical_address(&tree, 700), Some(2));
    }

    #[test]
    fn test_compute_physical_offset_single() {
        let chunk = BtrfsChunk {
            offset: 0,
            length: 131072,
            chunk_type: 0, // SINGLE profile (no RAID bits)
            stripes: vec![BtrfsStripe {
                devid: 1,
                offset: 1048576, // physical offset of stripe
            }],
            stripe_len: 65536,
        };
        // Logical 0 -> stripe_nr=0, relative_stripe=0 -> physical = 1048576
        assert_eq!(compute_physical_offset(&chunk, 0).unwrap(), 1048576);
        // Logical 65536 -> stripe_nr=1, relative_stripe=0 -> physical = 1048576 + 65536
        assert_eq!(
            compute_physical_offset(&chunk, 65536).unwrap(),
            1048576 + 65536
        );
    }

    #[test]
    fn test_compute_physical_offset_raid_rejected() {
        let chunk = BtrfsChunk {
            offset: 0,
            length: 131072,
            chunk_type: 0x0040, // RAID1 profile bit
            stripes: vec![BtrfsStripe {
                devid: 1,
                offset: 1048576,
            }],
            stripe_len: 65536,
        };
        // RAID profiles should return None
        assert!(compute_physical_offset(&chunk, 0).is_none());
    }

    #[test]
    fn test_find_subtree_qgroup_found() {
        // subvol_id = 256, parent qgroups at levels 1 and 5 with same id part
        let qg_level1 = qgroupid_make(1, 256).unwrap();
        let qg_level5 = qgroupid_make(5, 256).unwrap();
        let qg_other = qgroupid_make(2, 512).unwrap();

        let parents = vec![qg_level1, qg_level5, qg_other];
        let result = find_subtree_qgroup(256, &parents);
        assert_eq!(result, Some((qg_level1, 1))); // level 1 is lowest
    }

    #[test]
    fn test_find_subtree_qgroup_not_found() {
        // subvol_id = 256, but no parent shares the same id part
        let qg_other = qgroupid_make(2, 512).unwrap();
        let parents = vec![qg_other];
        let result = find_subtree_qgroup(256, &parents);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_subtree_qgroup_rejects_non_leaf() {
        // subvol_id has level != 0
        let qg = qgroupid_make(1, 256).unwrap();
        let result = find_subtree_qgroup(qg, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_quota_search_key() {
        let key = quota_search_key(256, 0, 0);
        assert_eq!(key.min_offset, 256);
        assert_eq!(key.max_offset, 256);
        assert_eq!(key.nr_items, 256);
    }

    #[test]
    fn test_root_backref_search_key() {
        let key = root_backref_search_key(42);
        assert_eq!(key.min_offset, 42);
        assert_eq!(key.max_offset, 42);
    }

    #[test]
    fn test_path_exceeds_limit() {
        assert!(!path_exceeds_limit("/short/path"));
        assert!(path_exceeds_limit(&"x".repeat(BTRFS_PATH_NAME_MAX + 1)));
        assert!(!path_exceeds_limit(&"x".repeat(BTRFS_PATH_NAME_MAX)));
    }

    #[test]
    fn test_btrfs_subvol_info_default() {
        let info = BtrfsSubvolInfo::default();
        assert_eq!(info.subvol_id, 0);
        assert!(!info.read_only);
        assert_eq!(info.uuid, [0u8; 16]);
    }

    #[test]
    fn test_btrfs_quota_info_default() {
        let info = BtrfsQuotaInfo::default();
        assert_eq!(info.referenced, u64::MAX);
        assert_eq!(info.exclusive_max, u64::MAX);
    }

    #[test]
    fn test_btrfs_snapshot_flags() {
        let flags = BtrfsSnapshotFlags::READ_ONLY | BtrfsSnapshotFlags::RECURSIVE;
        assert!(flags.contains(BtrfsSnapshotFlags::READ_ONLY));
        assert!(flags.contains(BtrfsSnapshotFlags::RECURSIVE));
        assert!(!flags.contains(BtrfsSnapshotFlags::QUOTA));
    }

    #[test]
    fn test_btrfs_remove_flags() {
        let flags = BtrfsRemoveFlags::RECURSIVE;
        assert!(flags.contains(BtrfsRemoveFlags::RECURSIVE));
        assert!(!flags.contains(BtrfsRemoveFlags::QUOTA));
    }
}
