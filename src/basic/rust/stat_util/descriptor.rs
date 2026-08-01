// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.stat-util; authority=src/basic/stat-util.c,src/basic/stat-util.h,src/basic/fd-util.h
//
// Descriptor and path verification adapters (verify_* / is_* / fd_verify_*).

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;

use super::verification::{
    stat_verify_block, stat_verify_device_node, stat_verify_directory, stat_verify_linked,
    stat_verify_regular, stat_verify_regular_or_block, stat_verify_socket, stat_verify_symlink,
};

pub(super) const XAT_FDROOT: libc::c_int = -8192;

#[derive(Clone, Copy)]
enum Verification {
    Regular,
    Directory,
    Symlink,
    Socket,
    Linked,
    Block,
    DeviceNode,
    RegularOrBlock,
}

#[inline]
pub(super) fn wildcard_fd_is_valid(fd: libc::c_int) -> bool {
    fd >= 0 || fd == libc::AT_FDCWD || fd == XAT_FDROOT
}

#[inline]
fn verify_stat(st: &libc::stat, verification: Verification) -> libc::c_int {
    match verification {
        Verification::Regular => stat_verify_regular(st),
        Verification::Directory => stat_verify_directory(st),
        Verification::Symlink => stat_verify_symlink(st),
        Verification::Socket => stat_verify_socket(st),
        Verification::Linked => stat_verify_linked(st),
        Verification::Block => stat_verify_block(st),
        Verification::DeviceNode => stat_verify_device_node(st),
        Verification::RegularOrBlock => stat_verify_regular_or_block(st),
    }
}

pub(super) fn resolve_at_path<'a>(
    fd: libc::c_int,
    path: Option<&'a CStr>,
) -> Result<(libc::c_int, Cow<'a, CStr>), libc::c_int> {
    let path = path.unwrap_or(c"");
    if fd != XAT_FDROOT {
        return Ok((fd, Cow::Borrowed(path)));
    }

    if path.is_empty() {
        return Ok((libc::AT_FDCWD, Cow::Borrowed(c"/")));
    }
    if path.to_bytes().starts_with(b"/") {
        return Ok((libc::AT_FDCWD, Cow::Borrowed(path)));
    }

    let mut rooted = Vec::new();
    let capacity = path.to_bytes().len().checked_add(1).ok_or(-libc::ENOMEM)?;
    rooted
        .try_reserve_exact(capacity)
        .map_err(|_| -libc::ENOMEM)?;
    rooted.push(b'/');
    rooted.extend_from_slice(path.to_bytes());
    let rooted = CString::new(rooted).map_err(|_| -libc::EINVAL)?;
    Ok((libc::AT_FDCWD, Cow::Owned(rooted)))
}

fn stat_at(fd: libc::c_int, path: Option<&CStr>, follow: bool) -> Result<libc::stat, libc::c_int> {
    if !wildcard_fd_is_valid(fd) {
        return Err(-libc::EBADF);
    }

    let (fd, path) = resolve_at_path(fd, path)?;
    let empty = path.is_empty();
    if empty && follow {
        return Err(-libc::EINVAL);
    }

    let flags = if empty { libc::AT_EMPTY_PATH } else { 0 }
        | if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
    let mut st = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `path` is NUL-terminated, `st` is writable native storage, and
    // the descriptor/flag combinations were normalized above.
    if unsafe_ffi!(libc::fstatat(fd, path.as_ptr(), st.as_mut_ptr(), flags)) < 0 {
        return Err(-crate::ffi::get_errno());
    }

    // SAFETY: successful `fstatat()` initialized the complete native value.
    Ok(unsafe_ffi!(st.assume_init()))
}

fn verify_stat_at(
    fd: libc::c_int,
    path: Option<&CStr>,
    follow: bool,
    verification: Verification,
    exact_error: bool,
) -> libc::c_int {
    let st = match stat_at(fd, path, follow) {
        Ok(st) => st,
        Err(error) => return error,
    };
    let result = verify_stat(&st, verification);
    if exact_error {
        result
    } else {
        libc::c_int::from(result >= 0)
    }
}

// SAFETY: callers must uphold the C-string contract for a non-null pointer.
unsafe fn optional_c_path<'a>(path: *const libc::c_char) -> Option<&'a CStr> {
    if path.is_null() {
        None
    } else {
        // SAFETY: the caller guarantees a readable NUL-terminated C string.
        Some(unsafe_ffi!(CStr::from_ptr(path)))
    }
}

/// # Safety
///
/// `path` must be null or point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_verify_regular_at(
    fd: libc::c_int,
    path: *const libc::c_char,
    follow: bool,
) -> libc::c_int {
    // SAFETY: forwarded from this entry point's pointer contract.
    let path = unsafe_ffi!(optional_c_path(path));
    verify_stat_at(fd, path, follow, Verification::Regular, true)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_fd_verify_regular(fd: libc::c_int) -> libc::c_int {
    if fd == libc::AT_FDCWD || fd == XAT_FDROOT {
        return -libc::EISDIR;
    }
    verify_stat_at(fd, None, false, Verification::Regular, true)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_fd_verify_directory(fd: libc::c_int) -> libc::c_int {
    if fd == libc::AT_FDCWD || fd == XAT_FDROOT {
        return 0;
    }
    verify_stat_at(fd, None, false, Verification::Directory, true)
}

/// # Safety
///
/// `path` must be null or point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_dir_at(
    fd: libc::c_int,
    path: *const libc::c_char,
    follow: bool,
) -> libc::c_int {
    // SAFETY: forwarded from this entry point's pointer contract.
    let path = unsafe_ffi!(optional_c_path(path));
    verify_stat_at(fd, path, follow, Verification::Directory, false)
}

/// # Safety
///
/// `path` must point to a readable, nonempty NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_dir(path: *const libc::c_char, follow: bool) -> libc::c_int {
    // SAFETY: forwarded from this entry point's pointer contract.
    let path = unsafe_ffi!(optional_c_path(path));
    if path.is_none_or(CStr::is_empty) {
        return -libc::EINVAL;
    }
    verify_stat_at(libc::AT_FDCWD, path, follow, Verification::Directory, false)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_fd_verify_symlink(fd: libc::c_int) -> libc::c_int {
    if fd == libc::AT_FDCWD || fd == XAT_FDROOT {
        return -libc::EISDIR;
    }
    verify_stat_at(fd, None, false, Verification::Symlink, true)
}

/// # Safety
///
/// `path` must point to a readable, nonempty NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_symlink(path: *const libc::c_char) -> libc::c_int {
    // SAFETY: forwarded from this entry point's pointer contract.
    let path = unsafe_ffi!(optional_c_path(path));
    if path.is_none_or(CStr::is_empty) {
        return -libc::EINVAL;
    }
    verify_stat_at(libc::AT_FDCWD, path, false, Verification::Symlink, false)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_fd_verify_socket(fd: libc::c_int) -> libc::c_int {
    if fd == libc::AT_FDCWD || fd == XAT_FDROOT {
        return -libc::EISDIR;
    }
    verify_stat_at(fd, None, false, Verification::Socket, true)
}

/// # Safety
///
/// `path` must point to a readable, nonempty NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_socket(path: *const libc::c_char) -> libc::c_int {
    // SAFETY: forwarded from this entry point's pointer contract.
    let path = unsafe_ffi!(optional_c_path(path));
    if path.is_none_or(CStr::is_empty) {
        return -libc::EINVAL;
    }
    verify_stat_at(libc::AT_FDCWD, path, true, Verification::Socket, false)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_fd_verify_linked(fd: libc::c_int) -> libc::c_int {
    if fd == XAT_FDROOT {
        return 0;
    }
    verify_stat_at(fd, None, false, Verification::Linked, true)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_fd_verify_block(fd: libc::c_int) -> libc::c_int {
    if fd == libc::AT_FDCWD || fd == XAT_FDROOT {
        return -libc::EISDIR;
    }
    verify_stat_at(fd, None, false, Verification::Block, true)
}

/// # Safety
///
/// `path` must point to a readable, nonempty NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_device_node(path: *const libc::c_char) -> libc::c_int {
    // SAFETY: forwarded from this entry point's pointer contract.
    let path = unsafe_ffi!(optional_c_path(path));
    if path.is_none_or(CStr::is_empty) {
        return -libc::EINVAL;
    }
    verify_stat_at(libc::AT_FDCWD, path, false, Verification::DeviceNode, false)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_fd_verify_regular_or_block(fd: libc::c_int) -> libc::c_int {
    if fd == libc::AT_FDCWD || fd == XAT_FDROOT {
        return -libc::EISDIR;
    }
    verify_stat_at(fd, None, false, Verification::RegularOrBlock, true)
}
