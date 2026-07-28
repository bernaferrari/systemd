// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.stat-util; authority=src/basic/stat-util.c,src/basic/stat-util.h
//
// Inode type names, chattr predicate, and inode comparisons.

use std::cmp::Ordering;
use std::ffi::{CStr, c_char};

use super::{
    MODE_INVALID, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK,
    stat_is_set, statx_is_set,
};

// Linux UAPI STATX_MNT_ID_UNIQUE; libc 0.2.184 does not expose this bit.
const STATX_MNT_ID_UNIQUE: u32 = 0x4000;

#[inline]
pub(super) fn inode_type(mode: libc::mode_t) -> libc::mode_t {
    mode & S_IFMT as libc::mode_t
}

#[inline]
fn ordering_to_c(ordering: Ordering) -> libc::c_int {
    match ordering {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

#[inline]
fn inode_type_can_chattr(mode: libc::mode_t) -> bool {
    matches!(
        inode_type(mode),
        value if value == S_IFREG as libc::mode_t || value == S_IFDIR as libc::mode_t
    )
}

#[inline]
fn inode_type_name(mode: libc::mode_t) -> Option<&'static CStr> {
    match inode_type(mode) {
        value if value == S_IFREG as libc::mode_t => Some(c"reg"),
        value if value == S_IFDIR as libc::mode_t => Some(c"dir"),
        value if value == S_IFLNK as libc::mode_t => Some(c"lnk"),
        value if value == S_IFCHR as libc::mode_t => Some(c"chr"),
        value if value == S_IFBLK as libc::mode_t => Some(c"blk"),
        value if value == S_IFIFO as libc::mode_t => Some(c"fifo"),
        value if value == S_IFSOCK as libc::mode_t => Some(c"sock"),
        _ => None,
    }
}

#[inline]
fn inode_type_from_bytes(name: &[u8]) -> libc::mode_t {
    match name {
        b"reg" => S_IFREG as libc::mode_t,
        b"dir" => S_IFDIR as libc::mode_t,
        b"lnk" => S_IFLNK as libc::mode_t,
        b"chr" => S_IFCHR as libc::mode_t,
        b"blk" => S_IFBLK as libc::mode_t,
        b"fifo" => S_IFIFO as libc::mode_t,
        b"sock" => S_IFSOCK as libc::mode_t,
        _ => MODE_INVALID as libc::mode_t,
    }
}

#[inline]
fn inode_compare(a: &libc::stat, b: &libc::stat) -> libc::c_int {
    ordering_to_c(
        a.st_dev
            .cmp(&b.st_dev)
            .then_with(|| a.st_ino.cmp(&b.st_ino))
            .then_with(|| inode_type(a.st_mode).cmp(&inode_type(b.st_mode))),
    )
}

#[inline]
fn inode_unmodified_compare(a: &libc::stat, b: &libc::stat) -> libc::c_int {
    let ordering = a
        .st_dev
        .cmp(&b.st_dev)
        .then_with(|| a.st_ino.cmp(&b.st_ino))
        .then_with(|| inode_type(a.st_mode).cmp(&inode_type(b.st_mode)))
        .then_with(|| a.st_mtime.cmp(&b.st_mtime))
        .then_with(|| a.st_mtime_nsec.cmp(&b.st_mtime_nsec))
        .then_with(|| {
            if inode_type(a.st_mode) == S_IFREG as libc::mode_t {
                a.st_size.cmp(&b.st_size)
            } else {
                Ordering::Equal
            }
        })
        .then_with(|| {
            if matches!(
                inode_type(a.st_mode),
                value
                    if value == S_IFCHR as libc::mode_t
                        || value == S_IFBLK as libc::mode_t
            ) {
                a.st_rdev.cmp(&b.st_rdev)
            } else {
                Ordering::Equal
            }
        });
    ordering_to_c(ordering)
}

#[inline]
pub(super) fn stat_inode_same(a: &libc::stat, b: &libc::stat) -> bool {
    stat_is_set(a)
        && stat_is_set(b)
        && inode_type(a.st_mode) == inode_type(b.st_mode)
        && a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
}

#[inline]
fn stat_inode_unmodified(a: &libc::stat, b: &libc::stat) -> bool {
    stat_inode_same(a, b)
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && (inode_type(a.st_mode) != S_IFREG as libc::mode_t || a.st_size == b.st_size)
        && (!matches!(
            inode_type(a.st_mode),
            value
                if value == S_IFCHR as libc::mode_t || value == S_IFBLK as libc::mode_t
        ) || a.st_rdev == b.st_rdev)
}

#[inline]
fn statx_has_type_and_inode(stx: &libc::statx) -> bool {
    stx.stx_mask & (libc::STATX_TYPE | libc::STATX_INO) == (libc::STATX_TYPE | libc::STATX_INO)
}

#[inline]
fn statx_inode_same(a: &libc::statx, b: &libc::statx) -> bool {
    if !statx_is_set(a)
        || !statx_is_set(b)
        || !statx_has_type_and_inode(a)
        || !statx_has_type_and_inode(b)
    {
        return false;
    }

    inode_type(a.stx_mode as libc::mode_t) == inode_type(b.stx_mode as libc::mode_t)
        && a.stx_dev_major == b.stx_dev_major
        && a.stx_dev_minor == b.stx_dev_minor
        && a.stx_ino == b.stx_ino
}

#[inline]
fn statx_mount_same(a: &libc::statx, b: &libc::statx) -> libc::c_int {
    if !statx_is_set(a) || !statx_is_set(b) {
        return 0;
    }

    let both_have_mount_id =
        a.stx_mask & libc::STATX_MNT_ID != 0 && b.stx_mask & libc::STATX_MNT_ID != 0;
    let both_have_unique_mount_id =
        a.stx_mask & STATX_MNT_ID_UNIQUE != 0 && b.stx_mask & STATX_MNT_ID_UNIQUE != 0;
    if both_have_mount_id || both_have_unique_mount_id {
        return libc::c_int::from(a.stx_mnt_id == b.stx_mnt_id);
    }

    -libc::ENODATA
}

/// C ABI mirror of `inode_type_can_chattr()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_inode_type_can_chattr(mode: libc::mode_t) -> bool {
    inode_type_can_chattr(mode)
}

/// C ABI mirror of `inode_type_to_string()`.
///
/// The returned pointer is either null or borrowed static storage.
#[unsafe(no_mangle)]
pub extern "C" fn rs_inode_type_to_string(mode: libc::mode_t) -> *const c_char {
    inode_type_name(mode).map_or(std::ptr::null(), CStr::as_ptr)
}

/// C ABI mirror of `inode_type_from_string()`.
///
/// # Safety
///
/// `name` must be null or point to a readable NUL-terminated byte string for
/// this call. Null is accepted and returns `MODE_INVALID`, as current C does.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_inode_type_from_string(name: *const c_char) -> libc::mode_t {
    if name.is_null() {
        return MODE_INVALID as libc::mode_t;
    }

    // SAFETY: guaranteed by the entry-point contract after the null check.
    inode_type_from_bytes(unsafe { CStr::from_ptr(name) }.to_bytes())
}

/// C ABI mirror of `inode_compare_func()`.
///
/// # Safety
///
/// Each pointer must be null or point to a live native `struct stat` for this
/// call. Null is a fail-closed extension and returns `-EINVAL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_inode_compare_func(
    a: *const libc::stat,
    b: *const libc::stat,
) -> libc::c_int {
    // SAFETY: the entry-point contract permits null or a live native stat.
    let (Some(a), Some(b)) = (unsafe { a.as_ref() }, unsafe { b.as_ref() }) else {
        return -libc::EINVAL;
    };
    inode_compare(a, b)
}

/// C ABI mirror of `inode_unmodified_compare_func()`.
///
/// # Safety
///
/// Each pointer must be null or point to a live native `struct stat` for this
/// call. Null is a fail-closed extension and returns `-EINVAL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_inode_unmodified_compare_func(
    a: *const libc::stat,
    b: *const libc::stat,
) -> libc::c_int {
    // SAFETY: the entry-point contract permits null or a live native stat.
    let (Some(a), Some(b)) = (unsafe { a.as_ref() }, unsafe { b.as_ref() }) else {
        return -libc::EINVAL;
    };
    inode_unmodified_compare(a, b)
}

/// C ABI mirror of `stat_inode_same()`.
///
/// # Safety
///
/// Each pointer must be null or point to a live native `struct stat` for this
/// call. Null is a fail-closed extension and returns `false`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_stat_inode_same(a: *const libc::stat, b: *const libc::stat) -> bool {
    // SAFETY: the entry-point contract permits null or a live native stat.
    let (Some(a), Some(b)) = (unsafe { a.as_ref() }, unsafe { b.as_ref() }) else {
        return false;
    };
    stat_inode_same(a, b)
}

/// C ABI mirror of `stat_inode_unmodified()`.
///
/// # Safety
///
/// Each pointer must be null or point to a live native `struct stat` for this
/// call. Null is a fail-closed extension and returns `false`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_stat_inode_unmodified(
    a: *const libc::stat,
    b: *const libc::stat,
) -> bool {
    // SAFETY: the entry-point contract permits null or a live native stat.
    let (Some(a), Some(b)) = (unsafe { a.as_ref() }, unsafe { b.as_ref() }) else {
        return false;
    };
    stat_inode_unmodified(a, b)
}

/// C ABI mirror of `statx_inode_same()`.
///
/// # Safety
///
/// Each pointer must be null or point to a live native `struct statx` for this
/// call. Null, unset structures, and missing `STATX_TYPE|STATX_INO` assertion
/// preconditions fail closed and return `false`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_statx_inode_same(a: *const libc::statx, b: *const libc::statx) -> bool {
    // SAFETY: the entry-point contract permits null or a live native statx.
    let (Some(a), Some(b)) = (unsafe { a.as_ref() }, unsafe { b.as_ref() }) else {
        return false;
    };
    statx_inode_same(a, b)
}

/// C ABI mirror of `statx_mount_same()`.
///
/// # Safety
///
/// Each pointer must be null or point to a live native `struct statx` for this
/// call. Null and unset structures return zero, as current C does.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_statx_mount_same(
    a: *const libc::statx,
    b: *const libc::statx,
) -> libc::c_int {
    // SAFETY: the entry-point contract permits null or a live native statx.
    let (Some(a), Some(b)) = (unsafe { a.as_ref() }, unsafe { b.as_ref() }) else {
        return 0;
    };
    statx_mount_same(a, b)
}
