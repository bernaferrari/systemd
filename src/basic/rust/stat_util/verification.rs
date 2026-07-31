// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.stat-util; authority=src/basic/stat-util.c,src/basic/stat-util.h
//
// stat/statx value verification helpers and inode_type_can_hardlink.

use super::{S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK};

/*
 * Keep target-specific C structure layout and scalar widths in libc. The
 * verification cores borrow native values and are safe; only the small C ABI
 * adapters below dereference caller-owned pointers.
 */

#[inline]
fn inode_type(mode: libc::mode_t) -> libc::mode_t {
    mode & S_IFMT as libc::mode_t
}

#[inline]
fn mode_verify_regular(mode: libc::mode_t) -> libc::c_int {
    if inode_type(mode) == S_IFDIR as libc::mode_t {
        return -libc::EISDIR;
    }
    if inode_type(mode) == S_IFLNK as libc::mode_t {
        return -libc::ELOOP;
    }
    if inode_type(mode) != S_IFREG as libc::mode_t {
        return -libc::EBADFD;
    }
    0
}

#[inline]
fn mode_verify_directory(mode: libc::mode_t) -> libc::c_int {
    if inode_type(mode) == S_IFLNK as libc::mode_t {
        return -libc::ELOOP;
    }
    if inode_type(mode) != S_IFDIR as libc::mode_t {
        return -libc::ENOTDIR;
    }
    0
}

#[inline]
fn mode_verify_socket(mode: libc::mode_t) -> libc::c_int {
    if inode_type(mode) == S_IFDIR as libc::mode_t {
        return -libc::EISDIR;
    }
    if inode_type(mode) == S_IFLNK as libc::mode_t {
        return -libc::ELOOP;
    }
    if inode_type(mode) != S_IFSOCK as libc::mode_t {
        return -libc::ENOTSOCK;
    }
    0
}

#[inline]
fn mode_verify_block(mode: libc::mode_t) -> libc::c_int {
    if inode_type(mode) == S_IFDIR as libc::mode_t {
        return -libc::EISDIR;
    }
    if inode_type(mode) == S_IFLNK as libc::mode_t {
        return -libc::ELOOP;
    }
    if inode_type(mode) != S_IFBLK as libc::mode_t {
        return -libc::ENOTBLK;
    }
    0
}

#[inline]
fn mode_verify_char(mode: libc::mode_t) -> libc::c_int {
    if inode_type(mode) == S_IFDIR as libc::mode_t {
        return -libc::EISDIR;
    }
    if inode_type(mode) == S_IFLNK as libc::mode_t {
        return -libc::ELOOP;
    }
    if inode_type(mode) != S_IFCHR as libc::mode_t {
        return -libc::EBADFD;
    }
    0
}

#[inline]
fn mode_verify_regular_or_block(mode: libc::mode_t) -> libc::c_int {
    if inode_type(mode) == S_IFDIR as libc::mode_t {
        return -libc::EISDIR;
    }
    if inode_type(mode) == S_IFLNK as libc::mode_t {
        return -libc::ELOOP;
    }
    if !matches!(
        inode_type(mode),
        value if value == S_IFREG as libc::mode_t || value == S_IFBLK as libc::mode_t
    ) {
        return -libc::EBADFD;
    }
    0
}

#[inline]
pub(super) fn stat_verify_regular(st: &libc::stat) -> libc::c_int {
    mode_verify_regular(st.st_mode)
}

#[inline]
fn statx_verify_regular(stx: &libc::statx) -> libc::c_int {
    if stx.stx_mask & libc::STATX_TYPE == 0 {
        return -libc::ENODATA;
    }
    mode_verify_regular(stx.stx_mode as libc::mode_t)
}

#[inline]
pub(super) fn stat_verify_directory(st: &libc::stat) -> libc::c_int {
    mode_verify_directory(st.st_mode)
}

#[inline]
fn statx_verify_directory(stx: &libc::statx) -> libc::c_int {
    if stx.stx_mask & libc::STATX_TYPE == 0 {
        return -libc::ENODATA;
    }
    mode_verify_directory(stx.stx_mode as libc::mode_t)
}

#[inline]
pub(super) fn stat_verify_symlink(st: &libc::stat) -> libc::c_int {
    if inode_type(st.st_mode) == S_IFDIR as libc::mode_t {
        return -libc::EISDIR;
    }
    if inode_type(st.st_mode) != S_IFLNK as libc::mode_t {
        return -libc::ENOLINK;
    }
    0
}

#[inline]
pub(super) fn stat_verify_socket(st: &libc::stat) -> libc::c_int {
    mode_verify_socket(st.st_mode)
}

#[inline]
fn statx_verify_socket(stx: &libc::statx) -> libc::c_int {
    mode_verify_socket(stx.stx_mode as libc::mode_t)
}

#[inline]
pub(super) fn stat_verify_linked(st: &libc::stat) -> libc::c_int {
    if st.st_nlink == 0 {
        return -libc::EIDRM;
    }
    0
}

#[inline]
pub(super) fn stat_verify_device_node(st: &libc::stat) -> libc::c_int {
    if inode_type(st.st_mode) == S_IFDIR as libc::mode_t {
        return -libc::EISDIR;
    }
    if inode_type(st.st_mode) == S_IFLNK as libc::mode_t {
        return -libc::ELOOP;
    }
    if !matches!(
        inode_type(st.st_mode),
        value if value == S_IFBLK as libc::mode_t || value == S_IFCHR as libc::mode_t
    ) {
        return -libc::ENOTTY;
    }
    0
}

#[inline]
pub(super) fn stat_verify_block(st: &libc::stat) -> libc::c_int {
    mode_verify_block(st.st_mode)
}

#[inline]
fn stat_verify_char(st: &libc::stat) -> libc::c_int {
    mode_verify_char(st.st_mode)
}

#[inline]
pub(super) fn stat_verify_regular_or_block(st: &libc::stat) -> libc::c_int {
    mode_verify_regular_or_block(st.st_mode)
}

#[inline]
pub(super) fn stat_may_be_dev_null(st: &libc::stat) -> bool {
    inode_type(st.st_mode) == S_IFCHR as libc::mode_t
}

#[inline]
pub(super) fn stat_is_empty(st: &libc::stat) -> bool {
    inode_type(st.st_mode) == S_IFREG as libc::mode_t && st.st_size <= 0
}

#[inline]
fn inode_type_can_hardlink(m: libc::mode_t) -> bool {
    matches!(
        inode_type(m),
        value
            if value == S_IFSOCK as libc::mode_t
                || value == S_IFLNK as libc::mode_t
                || value == S_IFREG as libc::mode_t
                || value == S_IFBLK as libc::mode_t
                || value == S_IFCHR as libc::mode_t
                || value == S_IFIFO as libc::mode_t
    )
}

// These private adapters are reached only from the documented C ABI exports
// below. They centralize nullable native-struct borrowing before the safe
// verification cores inspect the target libc layouts.
fn with_stat<T>(
    st: *const libc::stat,
    fallback: T,
    verification: impl FnOnce(&libc::stat) -> T,
) -> T {
    // SAFETY: callers are the audited C ABI adapters with nullable live stat pointers.
    unsafe { st.as_ref().map_or(fallback, verification) }
}

fn with_statx<T>(
    stx: *const libc::statx,
    fallback: T,
    verification: impl FnOnce(&libc::statx) -> T,
) -> T {
    // SAFETY: callers are the audited C ABI adapters with nullable live statx pointers.
    unsafe { stx.as_ref().map_or(fallback, verification) }
}

/// C ABI mirror of `stat_verify_regular()`.
///
/// # Safety
///
/// `st` must be null or point to a live native `struct stat` for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_stat_verify_regular(st: *const libc::stat) -> libc::c_int {
    with_stat(st, -libc::EINVAL, stat_verify_regular)
}

/// C ABI mirror of `statx_verify_regular()`.
///
/// # Safety
///
/// `stx` must be null or point to a live native `struct statx` for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_statx_verify_regular(stx: *const libc::statx) -> libc::c_int {
    with_statx(stx, -libc::EINVAL, statx_verify_regular)
}

/// C ABI mirror of `stat_verify_directory()`.
///
/// # Safety
///
/// `st` must be null or point to a live native `struct stat` for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_stat_verify_directory(st: *const libc::stat) -> libc::c_int {
    with_stat(st, -libc::EINVAL, stat_verify_directory)
}

/// C ABI mirror of `statx_verify_directory()`.
///
/// # Safety
///
/// `stx` must be null or point to a live native `struct statx` for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_statx_verify_directory(stx: *const libc::statx) -> libc::c_int {
    with_statx(stx, -libc::EINVAL, statx_verify_directory)
}

/// C ABI mirror of `stat_verify_symlink()`.
///
/// # Safety
///
/// `st` must be null or point to a live native `struct stat` for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_stat_verify_symlink(st: *const libc::stat) -> libc::c_int {
    with_stat(st, -libc::EINVAL, stat_verify_symlink)
}

/// C ABI mirror of `stat_verify_socket()`.
///
/// # Safety
///
/// `st` must be null or point to a live native `struct stat` for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_stat_verify_socket(st: *const libc::stat) -> libc::c_int {
    with_stat(st, -libc::EINVAL, stat_verify_socket)
}

/// C ABI mirror of `statx_verify_socket()`.
///
/// # Safety
///
/// `stx` must be null or point to a live native `struct statx` for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_statx_verify_socket(stx: *const libc::statx) -> libc::c_int {
    with_statx(stx, -libc::EINVAL, statx_verify_socket)
}

/// C ABI mirror of `stat_verify_linked()`.
///
/// # Safety
///
/// `st` must be null or point to a live native `struct stat` for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_stat_verify_linked(st: *const libc::stat) -> libc::c_int {
    with_stat(st, -libc::EINVAL, stat_verify_linked)
}

/// C ABI mirror of `stat_verify_block()`.
///
/// # Safety
///
/// `st` must be null or point to a live native `struct stat` for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_stat_verify_block(st: *const libc::stat) -> libc::c_int {
    with_stat(st, -libc::EINVAL, stat_verify_block)
}

/// C ABI mirror of `stat_verify_char()`.
///
/// # Safety
///
/// `st` must be null or point to a live native `struct stat` for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_stat_verify_char(st: *const libc::stat) -> libc::c_int {
    with_stat(st, -libc::EINVAL, stat_verify_char)
}

/// C ABI mirror of `stat_verify_regular_or_block()`.
///
/// # Safety
///
/// `st` must be null or point to a live native `struct stat` for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_stat_verify_regular_or_block(st: *const libc::stat) -> libc::c_int {
    with_stat(st, -libc::EINVAL, stat_verify_regular_or_block)
}

/// C ABI mirror of `stat_verify_device_node()`.
///
/// # Safety
///
/// `st` must be null or point to a live native `struct stat` for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_stat_verify_device_node(st: *const libc::stat) -> libc::c_int {
    with_stat(st, -libc::EINVAL, stat_verify_device_node)
}

/// C ABI mirror of `stat_may_be_dev_null()`.
///
/// # Safety
///
/// `st` must be null or point to a live native `struct stat` for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_stat_may_be_dev_null(st: *mut libc::stat) -> bool {
    with_stat(st.cast_const(), false, stat_may_be_dev_null)
}

/// C ABI mirror of `stat_is_empty()`.
///
/// # Safety
///
/// `st` must be null or point to a live native `struct stat` for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_stat_is_empty(st: *mut libc::stat) -> bool {
    with_stat(st.cast_const(), false, stat_is_empty)
}

/// C ABI mirror of `inode_type_can_hardlink()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_inode_type_can_hardlink(m: libc::mode_t) -> bool {
    inode_type_can_hardlink(m)
}
