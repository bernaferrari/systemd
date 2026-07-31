// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.stat-util; authority=src/basic/stat-util.c,src/basic/stat-util.h,src/shared/btrfs-util.c
//
// Inode type string conversion, comparison, and verification utilities.

// S_IFMT and S_IF* values from <sys/stat.h>
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFIFO: u32 = 0o010000;
const S_IFSOCK: u32 = 0o140000;

// MODE_INVALID from basic-forward.h
const MODE_INVALID: u32 = 0xFFFFFFFF;

// `struct statfs::f_type` is not one C type across Linux ABIs. Keep the Rust
// C ABI parameter identical to libc's target field instead of assuming long.
#[cfg(target_arch = "s390x")]
type StatFsType = libc::c_uint;
#[cfg(all(
    not(target_arch = "s390x"),
    any(target_env = "musl", target_os = "android")
))]
type StatFsType = libc::c_ulong;
#[cfg(all(
    not(target_arch = "s390x"),
    not(any(target_env = "musl", target_os = "android")),
    target_arch = "x86_64",
    target_pointer_width = "32"
))]
type StatFsType = i64;
#[cfg(all(
    not(target_arch = "s390x"),
    not(any(target_env = "musl", target_os = "android")),
    not(all(target_arch = "x86_64", target_pointer_width = "32"))
))]
type StatFsType = libc::c_long;

// ── typed stat verification predicates ─────────────────────────────────────

mod descriptor;
mod filesystem;
mod hash;
mod inode;
mod inode_same;
mod moderate;
mod verification;
mod xstatx;

/// Convert a nullable ABI pointer to a temporary typed borrow, keeping the
/// only dereference in one audited adapter. The surrounding `extern "C"`
/// function documents the pointee's layout and lifetime contract.
macro_rules! ffi_borrow_or_return {
    ($pointer:expr, $fallback:expr) => {{
        // SAFETY: a non-null pointer is valid for the enclosing C ABI call.
        let Some(value) = (unsafe { ($pointer).as_ref() }) else {
            return $fallback;
        };
        value
    }};
}

pub use descriptor::{
    rs_fd_verify_block, rs_fd_verify_directory, rs_fd_verify_linked, rs_fd_verify_regular,
    rs_fd_verify_regular_or_block, rs_fd_verify_socket, rs_fd_verify_symlink, rs_is_device_node,
    rs_is_dir, rs_is_dir_at, rs_is_socket, rs_is_symlink, rs_verify_regular_at,
};
pub use filesystem::{
    rs_fd_is_network_fs, rs_fd_is_read_only_fs, rs_fd_is_temporary_fs, rs_is_fs_type_at,
    rs_is_network_fs, rs_is_temporary_fs, rs_path_is_network_fs, rs_path_is_read_only_fs,
    rs_path_is_temporary_fs, rs_vfs_free_bytes, rs_xstatfsat,
};
pub use hash::{rs_inode_hash_func, rs_inode_unmodified_hash_func};
pub use inode::{
    rs_inode_compare_func, rs_inode_type_can_chattr, rs_inode_type_from_string,
    rs_inode_type_to_string, rs_inode_unmodified_compare_func, rs_stat_inode_same,
    rs_stat_inode_unmodified, rs_statx_inode_same, rs_statx_mount_same,
};
pub use inode_same::{rs_fd_inode_same, rs_inode_same, rs_inode_same_at};
pub use moderate::{
    rs_dir_is_empty, rs_dir_is_empty_at, rs_fd_is_fs_type, rs_null_or_empty, rs_null_or_empty_path,
    rs_null_or_empty_path_with_root, rs_path_is_fs_type, rs_proc_mounted,
};
pub use verification::{
    rs_inode_type_can_hardlink, rs_stat_is_empty, rs_stat_may_be_dev_null, rs_stat_verify_block,
    rs_stat_verify_char, rs_stat_verify_device_node, rs_stat_verify_directory,
    rs_stat_verify_linked, rs_stat_verify_regular, rs_stat_verify_regular_or_block,
    rs_stat_verify_socket, rs_stat_verify_symlink, rs_statx_verify_directory,
    rs_statx_verify_regular, rs_statx_verify_socket,
};
pub use xstatx::{rs_xstatx, rs_xstatx_full};

// ── stat_is_set / statx_is_set / statx timestamps ───────────────────────

/*
 * These entry points used to read a hand-written, target-specific prefix of
 * each C structure.  That is both needlessly unsafe and wrong on the other
 * Linux ABIs that systemd supports.  `libc` owns the platform C layouts, so
 * keep the raw-pointer conversion at the ABI edge and make the comparison
 * core operate on typed borrowed values.
 */

#[inline]
fn stat_is_set(st: &libc::stat) -> bool {
    st.st_dev != 0 && st.st_mode != MODE_INVALID as libc::mode_t
}

#[inline]
fn statx_is_set(stx: &libc::statx) -> bool {
    stx.stx_mask != 0
}

#[inline]
fn timestamp_load_usec(sec: i64, nsec: libc::c_long) -> u64 {
    if sec < 0 || nsec < 0 {
        return u64::MAX;
    }

    let sec = sec as u64;
    let nsec = nsec as u64;
    if sec > (u64::MAX - nsec / 1_000) / 1_000_000 {
        return u64::MAX;
    }
    sec * 1_000_000 + nsec / 1_000
}

#[inline]
fn timestamp_load_nsec(sec: i64, nsec: libc::c_long) -> u64 {
    if sec < 0 || nsec < 0 {
        return u64::MAX;
    }

    let sec = sec as u64;
    let nsec = nsec as u64;
    if sec >= (u64::MAX - nsec) / 1_000_000_000 {
        return u64::MAX;
    }
    sec * 1_000_000_000 + nsec
}

/// C ABI mirror of `stat_is_set()` from `stat-util.h`.
///
/// # Safety
///
/// `st` must be null or point to a live `struct stat` for the duration of
/// this call. A null pointer is deliberately fail-closed, exactly as the C
/// inline helper does.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_stat_is_set(st: *const libc::stat) -> bool {
    let st = ffi_borrow_or_return!(st, false);
    stat_is_set(st)
}

/// C ABI mirror of `statx_is_set()` from `stat-util.h`.
///
/// # Safety
///
/// `stx` must be null or point to a live `struct statx` for the duration of
/// this call. A null pointer is deliberately fail-closed, exactly as the C
/// inline helper does.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_statx_is_set(stx: *const libc::statx) -> bool {
    let stx = ffi_borrow_or_return!(stx, false);
    statx_is_set(stx)
}

/// C ABI mirror of `statx_timestamp_load()` from `stat-util.c`.
///
/// # Safety
///
/// `ts` must point to a live `struct statx_timestamp` for the duration of the
/// call. Upstream asserts this precondition. The Rust ABI returns infinity for
/// null as a fail-closed extension for existing comparison callers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_statx_timestamp_load(ts: *const libc::statx_timestamp) -> u64 {
    let ts = ffi_borrow_or_return!(ts, u64::MAX);

    // C first converts the u32 kernel nanosecond field to `timespec.tv_nsec`
    // (`long`); preserving that conversion matters on 32-bit Linux.
    timestamp_load_usec(ts.tv_sec, ts.tv_nsec as libc::c_long)
}

/// C ABI mirror of `statx_timestamp_load_nsec()` from `stat-util.c`.
///
/// # Safety
///
/// `ts` must point to a live `struct statx_timestamp` for the duration of the
/// call. Upstream asserts this precondition. The Rust ABI returns infinity for
/// null as a fail-closed extension for existing comparison callers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_statx_timestamp_load_nsec(ts: *const libc::statx_timestamp) -> u64 {
    let ts = ffi_borrow_or_return!(ts, u64::MAX);
    timestamp_load_nsec(ts.tv_sec, ts.tv_nsec as libc::c_long)
}

// ── is_fs_type ───────────────────────────────────────────────────────────

#[inline]
fn is_fs_type(statfs: &libc::statfs, magic_value: StatFsType) -> bool {
    // This is the typed equivalent of C's F_TYPE_EQUAL(), whose cast is needed
    // because `struct statfs::f_type` varies between Linux architectures.
    statfs.f_type == magic_value
}

/// C ABI mirror of `is_fs_type()` from `stat-util.c`.
///
/// # Safety
///
/// `statfs` must point to a live `struct statfs` for the duration of this
/// call. Upstream asserts this precondition. A null pointer is rejected with
/// `false` instead of dereferencing it, which preserves a safe fail-closed ABI
/// boundary for the shadow callers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_fs_type(
    statfs: *const libc::statfs,
    magic_value: StatFsType,
) -> bool {
    let statfs = ffi_borrow_or_return!(statfs, false);
    is_fs_type(statfs, magic_value)
}

// -- btrfs_might_be_subvol ----------------------------------------------------

/// Typed core of C's `btrfs_might_be_subvol()` from `btrfs-util.c`.
///
/// This is intentionally only a heuristic: filesystem type confirmation is
/// the caller's responsibility, just as it is in C.
#[inline]
fn btrfs_might_be_subvol(st: &libc::stat) -> bool {
    (st.st_mode as u32 & S_IFMT) == S_IFDIR && st.st_ino == 256
}

/// C ABI mirror of `btrfs_might_be_subvol()`.
///
/// # Safety
///
/// `st` must be null or point to a live native `struct stat` for this call.
/// A null pointer is accepted and returns `false`, exactly as the upstream C
/// helper does. `libc::stat` deliberately owns the target-specific layout;
/// the safe core above never reads guessed field offsets.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_btrfs_might_be_subvol(st: *const libc::stat) -> bool {
    let st = ffi_borrow_or_return!(st, false);

    btrfs_might_be_subvol(st)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stat_verify_regular_success() {
        // SAFETY: libc's all-integer stat layout accepts an all-zero value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_mode = S_IFREG as libc::mode_t;
        // SAFETY: `st` is initialized and live for this call.
        assert_eq!(unsafe { rs_stat_verify_regular(&st) }, 0);
    }

    #[test]
    fn test_stat_verify_regular_null() {
        // SAFETY: null is an explicitly supported fail-closed extension.
        assert_eq!(
            unsafe { rs_stat_verify_regular(std::ptr::null()) },
            -libc::EINVAL
        );
    }

    #[test]
    fn test_stat_verify_regular_directory() {
        // SAFETY: libc's all-integer stat layout accepts an all-zero value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_mode = S_IFDIR as libc::mode_t;
        // SAFETY: `st` is initialized and live for this call.
        assert_eq!(unsafe { rs_stat_verify_regular(&st) }, -libc::EISDIR);
    }

    #[test]
    fn test_stat_verify_regular_symlink() {
        // SAFETY: libc's all-integer stat layout accepts an all-zero value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_mode = S_IFLNK as libc::mode_t;
        // SAFETY: `st` is initialized and live for this call.
        assert_eq!(unsafe { rs_stat_verify_regular(&st) }, -libc::ELOOP);
    }

    #[test]
    fn test_statx_verify_regular_success() {
        // SAFETY: libc's all-integer statx layout accepts an all-zero value.
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        stx.stx_mask = libc::STATX_TYPE;
        stx.stx_mode = S_IFREG as u16;
        // SAFETY: `stx` is initialized and live for this call.
        assert_eq!(unsafe { rs_statx_verify_regular(&stx) }, 0);
    }

    #[test]
    fn test_statx_verify_regular_null() {
        // SAFETY: null is an explicitly supported fail-closed extension.
        assert_eq!(
            unsafe { rs_statx_verify_regular(std::ptr::null()) },
            -libc::EINVAL
        );
    }

    #[test]
    fn test_statx_verify_regular_no_type() {
        // SAFETY: libc's all-integer statx layout accepts an all-zero value.
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        stx.stx_mode = S_IFREG as u16;
        // SAFETY: `stx` is initialized and live for this call.
        assert_eq!(unsafe { rs_statx_verify_regular(&stx) }, -libc::ENODATA);
    }

    #[test]
    fn test_stat_verify_directory_success() {
        // SAFETY: libc's all-integer stat layout accepts an all-zero value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_mode = S_IFDIR as libc::mode_t;
        // SAFETY: `st` is initialized and live for this call.
        assert_eq!(unsafe { rs_stat_verify_directory(&st) }, 0);
    }

    #[test]
    fn test_stat_verify_directory_null() {
        // SAFETY: null is an explicitly supported fail-closed extension.
        assert_eq!(
            unsafe { rs_stat_verify_directory(std::ptr::null()) },
            -libc::EINVAL
        );
    }

    #[test]
    fn test_stat_verify_directory_not_dir() {
        // SAFETY: libc's all-integer stat layout accepts an all-zero value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_mode = S_IFREG as libc::mode_t;
        // SAFETY: `st` is initialized and live for this call.
        assert_eq!(unsafe { rs_stat_verify_directory(&st) }, -libc::ENOTDIR);
    }

    #[test]
    fn test_statx_verify_directory_success() {
        // SAFETY: libc's all-integer statx layout accepts an all-zero value.
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        stx.stx_mask = libc::STATX_TYPE;
        stx.stx_mode = S_IFDIR as u16;
        // SAFETY: `stx` is initialized and live for this call.
        assert_eq!(unsafe { rs_statx_verify_directory(&stx) }, 0);
    }

    #[test]
    fn test_statx_verify_directory_null() {
        // SAFETY: null is an explicitly supported fail-closed extension.
        assert_eq!(
            unsafe { rs_statx_verify_directory(std::ptr::null()) },
            -libc::EINVAL
        );
    }

    #[test]
    fn test_stat_verify_symlink_success() {
        // SAFETY: libc's all-integer stat layout accepts an all-zero value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_mode = S_IFLNK as libc::mode_t;
        // SAFETY: `st` is initialized and live for this call.
        assert_eq!(unsafe { rs_stat_verify_symlink(&st) }, 0);
    }

    #[test]
    fn test_stat_verify_symlink_null() {
        // SAFETY: null is an explicitly supported fail-closed extension.
        assert_eq!(
            unsafe { rs_stat_verify_symlink(std::ptr::null()) },
            -libc::EINVAL
        );
    }

    #[test]
    fn test_stat_verify_symlink_directory() {
        // SAFETY: libc's all-integer stat layout accepts an all-zero value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_mode = S_IFDIR as libc::mode_t;
        // SAFETY: `st` is initialized and live for this call.
        assert_eq!(unsafe { rs_stat_verify_symlink(&st) }, -libc::EISDIR);
    }

    #[test]
    fn test_stat_verify_socket_success() {
        // SAFETY: libc's all-integer stat layout accepts an all-zero value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_mode = S_IFSOCK as libc::mode_t;
        // SAFETY: `st` is initialized and live for this call.
        assert_eq!(unsafe { rs_stat_verify_socket(&st) }, 0);
    }

    #[test]
    fn test_stat_verify_socket_null() {
        // SAFETY: null is an explicitly supported fail-closed extension.
        assert_eq!(
            unsafe { rs_stat_verify_socket(std::ptr::null()) },
            -libc::EINVAL
        );
    }

    #[test]
    fn test_statx_verify_socket_success() {
        // SAFETY: libc's all-integer statx layout accepts an all-zero value.
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        stx.stx_mode = S_IFSOCK as u16;
        // SAFETY: `stx` is initialized and live for this call.
        assert_eq!(unsafe { rs_statx_verify_socket(&stx) }, 0);
    }

    #[test]
    fn test_statx_verify_socket_null() {
        // SAFETY: null is an explicitly supported fail-closed extension.
        assert_eq!(
            unsafe { rs_statx_verify_socket(std::ptr::null()) },
            -libc::EINVAL
        );
    }

    #[test]
    fn test_stat_verify_linked_success() {
        // SAFETY: libc's all-integer stat layout accepts an all-zero value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_nlink = 1;
        // SAFETY: `st` is initialized and live for this call.
        assert_eq!(unsafe { rs_stat_verify_linked(&st) }, 0);
    }

    #[test]
    fn test_stat_verify_linked_null() {
        // SAFETY: null is an explicitly supported fail-closed extension.
        assert_eq!(
            unsafe { rs_stat_verify_linked(std::ptr::null()) },
            -libc::EINVAL
        );
    }

    #[test]
    fn test_stat_verify_linked_zero_nlink() {
        // SAFETY: libc's all-integer stat layout accepts an all-zero value.
        let st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `st` is initialized and live for this call.
        assert_eq!(unsafe { rs_stat_verify_linked(&st) }, -libc::EIDRM);
    }

    #[test]
    fn test_stat_verify_device_node_success() {
        // SAFETY: libc's all-integer stat layout accepts an all-zero value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_mode = S_IFCHR as libc::mode_t;
        // SAFETY: `st` is initialized and live for these calls.
        assert_eq!(unsafe { rs_stat_verify_device_node(&st) }, 0);
        st.st_mode = S_IFBLK as libc::mode_t;
        // SAFETY: `st` remains initialized and live for this call.
        assert_eq!(unsafe { rs_stat_verify_device_node(&st) }, 0);
    }

    #[test]
    fn test_stat_verify_device_node_null() {
        // SAFETY: null is an explicitly supported fail-closed extension.
        assert_eq!(
            unsafe { rs_stat_verify_device_node(std::ptr::null()) },
            -libc::EINVAL
        );
    }

    #[test]
    fn test_stat_verify_device_node_not_device() {
        // SAFETY: libc's all-integer stat layout accepts an all-zero value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_mode = S_IFREG as libc::mode_t;
        // SAFETY: `st` is initialized and live for this call.
        assert_eq!(unsafe { rs_stat_verify_device_node(&st) }, -libc::ENOTTY);
    }

    #[test]
    fn test_stat_may_be_dev_null() {
        // SAFETY: libc's all-integer stat layout accepts an all-zero value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_mode = S_IFCHR as libc::mode_t;
        // SAFETY: `st` is initialized and live for these calls.
        assert!(unsafe { rs_stat_may_be_dev_null(&mut st) });
        st.st_mode = S_IFREG as libc::mode_t;
        // SAFETY: `st` remains initialized and live for this call.
        assert!(!unsafe { rs_stat_may_be_dev_null(&mut st) });
    }

    #[test]
    fn test_stat_may_be_dev_null_null() {
        // SAFETY: null is an explicitly supported fail-closed extension.
        assert!(!unsafe { rs_stat_may_be_dev_null(std::ptr::null_mut()) });
    }

    #[test]
    fn test_stat_is_empty() {
        // SAFETY: libc's all-integer stat layout accepts an all-zero value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_mode = S_IFREG as libc::mode_t;
        // SAFETY: `st` is initialized and live for these calls.
        assert!(unsafe { rs_stat_is_empty(&mut st) });
        st.st_size = 100;
        // SAFETY: `st` remains initialized and live for this call.
        assert!(!unsafe { rs_stat_is_empty(&mut st) });
        st.st_size = -1;
        // SAFETY: `st` remains initialized and live for this call.
        assert!(unsafe { rs_stat_is_empty(&mut st) });
    }

    #[test]
    fn test_stat_is_empty_null() {
        // SAFETY: null is an explicitly supported fail-closed extension.
        assert!(!unsafe { rs_stat_is_empty(std::ptr::null_mut()) });
    }

    #[test]
    fn test_stat_is_empty_non_regular() {
        // SAFETY: libc's all-integer stat layout accepts an all-zero value.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_mode = S_IFDIR as libc::mode_t;
        // SAFETY: `st` is initialized and live for this call.
        assert!(!unsafe { rs_stat_is_empty(&mut st) });
    }

    #[test]
    fn test_inode_type_can_hardlink() {
        assert!(rs_inode_type_can_hardlink(S_IFREG as libc::mode_t));
        assert!(rs_inode_type_can_hardlink(S_IFBLK as libc::mode_t));
        assert!(rs_inode_type_can_hardlink(S_IFCHR as libc::mode_t));
        assert!(rs_inode_type_can_hardlink(S_IFLNK as libc::mode_t));
        assert!(rs_inode_type_can_hardlink(S_IFIFO as libc::mode_t));
        assert!(rs_inode_type_can_hardlink(S_IFSOCK as libc::mode_t));
        assert!(!rs_inode_type_can_hardlink(S_IFDIR as libc::mode_t));
    }

    #[test]
    fn test_stat_is_set() {
        // SAFETY: all-integer libc C ABI structs accept an all-zero initial
        // representation; the test then initializes each field it observes.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        st.st_dev = 1;
        st.st_mode = S_IFREG as libc::mode_t;
        // SAFETY: `st` remains live and initialized for this call.
        assert!(unsafe { rs_stat_is_set(&st) });

        st.st_dev = 0;
        // SAFETY: `st` remains live and initialized for this call.
        assert!(!unsafe { rs_stat_is_set(&st) });

        st.st_dev = 1;
        st.st_mode = MODE_INVALID as libc::mode_t;
        // SAFETY: `st` remains live and initialized for this call.
        assert!(!unsafe { rs_stat_is_set(&st) });
    }

    #[test]
    fn test_stat_is_set_null() {
        // SAFETY: null is explicitly accepted and fail-closed by this ABI.
        assert!(!unsafe { rs_stat_is_set(std::ptr::null()) });
    }

    #[test]
    fn test_statx_is_set() {
        // SAFETY: all-integer libc C ABI structs accept an all-zero initial
        // representation; the test initializes the observed mask field.
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        stx.stx_mask = 1;
        // SAFETY: `stx` remains live and initialized for this call.
        assert!(unsafe { rs_statx_is_set(&stx) });
        stx.stx_mask = 0;
        // SAFETY: `stx` remains live and initialized for this call.
        assert!(!unsafe { rs_statx_is_set(&stx) });
    }

    #[test]
    fn test_statx_is_set_null() {
        // SAFETY: null is explicitly accepted and fail-closed by this ABI.
        assert!(!unsafe { rs_statx_is_set(std::ptr::null()) });
    }

    #[test]
    fn test_statx_timestamp_load() {
        // SAFETY: all-integer libc C ABI structs accept an all-zero initial
        // representation; the test initializes both public fields.
        let mut ts: libc::statx_timestamp = unsafe { std::mem::zeroed() };
        ts.tv_sec = 100;
        ts.tv_nsec = 500_000_000;
        // SAFETY: `ts` remains live and initialized for this call.
        assert_eq!(unsafe { rs_statx_timestamp_load(&ts) }, 100_500_000u64);
    }

    #[test]
    fn test_statx_timestamp_load_null() {
        // SAFETY: null is explicitly accepted and fail-closed by this ABI.
        assert_eq!(
            unsafe { rs_statx_timestamp_load(std::ptr::null()) },
            u64::MAX
        );
    }

    #[test]
    fn test_statx_timestamp_load_negative() {
        // SAFETY: all-integer libc C ABI structs accept an all-zero initial
        // representation; the test initializes both public fields.
        let mut ts: libc::statx_timestamp = unsafe { std::mem::zeroed() };
        ts.tv_sec = -1;
        // SAFETY: `ts` remains live and initialized for this call.
        assert_eq!(unsafe { rs_statx_timestamp_load(&ts) }, u64::MAX);
    }

    #[test]
    fn test_statx_timestamp_load_nsec() {
        // SAFETY: all-integer libc C ABI structs accept an all-zero initial
        // representation; the test initializes both public fields.
        let mut ts: libc::statx_timestamp = unsafe { std::mem::zeroed() };
        ts.tv_sec = 1;
        ts.tv_nsec = 500_000_000;
        // SAFETY: `ts` remains live and initialized for this call.
        assert_eq!(
            unsafe { rs_statx_timestamp_load_nsec(&ts) },
            1_500_000_000u64
        );
    }

    #[test]
    fn test_statx_timestamp_load_nsec_null() {
        // SAFETY: null is explicitly accepted and fail-closed by this ABI.
        assert_eq!(
            unsafe { rs_statx_timestamp_load_nsec(std::ptr::null()) },
            u64::MAX
        );
    }

    #[test]
    fn test_statx_timestamp_load_nsec_negative() {
        // SAFETY: all-integer libc C ABI structs accept an all-zero initial
        // representation; the test initializes both public fields.
        let mut ts: libc::statx_timestamp = unsafe { std::mem::zeroed() };
        ts.tv_sec = -1;
        // SAFETY: `ts` remains live and initialized for this call.
        assert_eq!(unsafe { rs_statx_timestamp_load_nsec(&ts) }, u64::MAX);
    }

    #[test]
    fn test_is_fs_type_match() {
        // SAFETY: all-integer libc C ABI structs accept an all-zero initial
        // representation; the test initializes the observed type field.
        let mut statfs: libc::statfs = unsafe { std::mem::zeroed() };
        statfs.f_type = 0x1234;
        // SAFETY: `statfs` remains live and initialized for this call.
        assert!(unsafe { rs_is_fs_type(&statfs, 0x1234) });
    }

    #[test]
    fn test_is_fs_type_no_match() {
        // SAFETY: all-integer libc C ABI structs accept an all-zero initial
        // representation; the test initializes the observed type field.
        let mut statfs: libc::statfs = unsafe { std::mem::zeroed() };
        statfs.f_type = 0x1234;
        // SAFETY: `statfs` remains live and initialized for this call.
        assert!(!unsafe { rs_is_fs_type(&statfs, 0x5678) });
    }

    #[test]
    fn test_is_fs_type_null() {
        // SAFETY: null is explicitly accepted and fail-closed by this ABI.
        assert!(!unsafe { rs_is_fs_type(std::ptr::null(), 0x1234) });
    }
}
