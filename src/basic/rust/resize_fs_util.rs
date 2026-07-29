// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.resize-fs-util; authority=src/shared/resize-fs.c,src/shared/resize-fs.h
//
// Filesystem resize utilities — pure computation, no I/O.

use std::ffi::CStr;
use std::os::raw::c_char;

// ── Constants from linux/magic.h ──────────────────────────────────────────

const EXT4_SUPER_MAGIC: libc::c_long = 0xEF53;
const XFS_SUPER_MAGIC: libc::c_long = 0x5846_5342;
// The C authority casts this `u32` magic to `statfs_f_type_t`.  Keeping the
// cast makes the ABI match both 64-bit Linux (positive `long`) and 32-bit
// Linux (the corresponding negative signed `long`) without an overflowing
// integer literal.
const BTRFS_SUPER_MAGIC: libc::c_long = 0x9123_683E_u32 as libc::c_long;

// ── Constants from macro.h / resize-fs.h ─────────────────────────────────

const U64_KB: u64 = 1024;
const U64_MB: u64 = 1024 * U64_KB;

const EXT4_MINIMAL_SIZE: u64 = 32 * U64_MB;
const XFS_MINIMAL_SIZE: u64 = 300 * U64_MB;
const BTRFS_MINIMAL_SIZE: u64 = 256 * U64_MB;

// ── Public API ────────────────────────────────────────────────────────────

/// Faithful byte-wise port of C `minimal_size_by_fs_name()`.
///
/// `name` contains the raw non-NUL bytes of an already validated C string.
/// No UTF-8 interpretation is performed, matching `streq_ptr()`.
fn minimal_size_by_fs_name_bytes(name: &[u8]) -> u64 {
    match name {
        b"ext4" => EXT4_MINIMAL_SIZE,
        b"xfs" => XFS_MINIMAL_SIZE,
        b"btrfs" => BTRFS_MINIMAL_SIZE,
        _ => u64::MAX,
    }
}

/// Faithful port of C minimal_size_by_fs_magic().
/// Returns the minimal filesystem size for the given filesystem magic number,
/// or `u64::MAX` if the magic is unknown.
fn minimal_size_by_fs_magic(magic: libc::c_long) -> u64 {
    match magic {
        EXT4_SUPER_MAGIC => EXT4_MINIMAL_SIZE,
        XFS_SUPER_MAGIC => XFS_MINIMAL_SIZE,
        BTRFS_SUPER_MAGIC => BTRFS_MINIMAL_SIZE,
        _ => u64::MAX,
    }
}

/// Faithful port of C fs_can_online_shrink_and_grow().
/// Returns true for the only filesystem that can online shrink AND grow (btrfs).
fn fs_can_online_shrink_and_grow(magic: libc::c_long) -> bool {
    magic == BTRFS_SUPER_MAGIC
}

/// C ABI facade for `minimal_size_by_fs_name()`.
///
/// # Safety
///
/// When non-NULL, `name` must point to a live NUL-terminated C string for the
/// duration of the call. The string is borrowed only; its raw bytes are not
/// retained or allocated across the ABI boundary. NULL has the same meaning as
/// in C's `streq_ptr()` and returns `UINT64_MAX`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_minimal_size_by_fs_name(name: *const c_char) -> u64 {
    if name.is_null() {
        return u64::MAX;
    }

    // SAFETY: required by this entry point's contract after the NULL check.
    minimal_size_by_fs_name_bytes(unsafe { CStr::from_ptr(name) }.to_bytes())
}

/// C ABI facade for `minimal_size_by_fs_magic()`.
///
/// `libc::c_long` is the Rust ABI counterpart of Linux `statfs_f_type_t`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_minimal_size_by_fs_magic(magic: libc::c_long) -> u64 {
    minimal_size_by_fs_magic(magic)
}

/// C ABI facade for `fs_can_online_shrink_and_grow()`.
///
/// `libc::c_long` is the Rust ABI counterpart of Linux `statfs_f_type_t`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_fs_can_online_shrink_and_grow(magic: libc::c_long) -> bool {
    fs_can_online_shrink_and_grow(magic)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── minimal_size_by_fs_name tests ───────────────────────────────────

    #[test]
    fn test_minimal_size_by_fs_name_ext4() {
        assert_eq!(minimal_size_by_fs_name_bytes(b"ext4"), EXT4_MINIMAL_SIZE);
    }

    #[test]
    fn test_minimal_size_by_fs_name_xfs() {
        assert_eq!(minimal_size_by_fs_name_bytes(b"xfs"), XFS_MINIMAL_SIZE);
    }

    #[test]
    fn test_minimal_size_by_fs_name_btrfs() {
        assert_eq!(minimal_size_by_fs_name_bytes(b"btrfs"), BTRFS_MINIMAL_SIZE);
    }

    #[test]
    fn test_minimal_size_by_fs_name_unknown() {
        assert_eq!(minimal_size_by_fs_name_bytes(b"vfat"), u64::MAX);
    }

    #[test]
    fn test_minimal_size_by_fs_name_empty() {
        assert_eq!(minimal_size_by_fs_name_bytes(b""), u64::MAX);
    }

    #[test]
    fn test_minimal_size_by_fs_name_case_sensitive() {
        assert_eq!(minimal_size_by_fs_name_bytes(b"Ext4"), u64::MAX);
        assert_eq!(minimal_size_by_fs_name_bytes(b"BTRFS"), u64::MAX);
        assert_eq!(minimal_size_by_fs_name_bytes(b"XFS"), u64::MAX);
    }

    #[test]
    fn test_minimal_size_by_fs_name_non_utf8() {
        assert_eq!(minimal_size_by_fs_name_bytes(b"ext4\xff"), u64::MAX);
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
        assert_eq!(minimal_size_by_fs_magic(-1), u64::MAX);
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
        assert!(!fs_can_online_shrink_and_grow(-1));
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
