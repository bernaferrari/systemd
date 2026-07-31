// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.stat-util; authority=src/basic/stat-util.c,src/basic/stat-util.h,src/basic/filesystem-sets.py
//
// statfs/filesystem queries and vfs_free_bytes.

use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::StatFsType;
use super::descriptor::{XAT_FDROOT, resolve_at_path, wildcard_fd_is_valid};

const AFS_FS_MAGIC: u64 = 0x6b41_4653;
const AFS_SUPER_MAGIC: u64 = 0x5346_414f;
const CEPH_SUPER_MAGIC: u64 = 0x00c3_6400;
const CIFS_SUPER_MAGIC: u64 = 0xff53_4d42;
const SMB2_SUPER_MAGIC: u64 = 0xfe53_4d42;
const GFS2_MAGIC: u64 = 0x0116_1970;
const NCP_SUPER_MAGIC: u64 = 0x564c;
const NFS_SUPER_MAGIC: u64 = 0x6969;
const OCFS2_SUPER_MAGIC: u64 = 0x7461_636f;
const ORANGEFS_DEVREQ_MAGIC: u64 = 0x2003_0528;
const SMB_SUPER_MAGIC: u64 = 0x517b;
const RAMFS_MAGIC: u64 = 0x8584_58f6;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const ST_RDONLY: u64 = 1;

const NETWORK_FILESYSTEM_MAGICS: &[u64] = &[
    AFS_FS_MAGIC,
    AFS_SUPER_MAGIC,
    CEPH_SUPER_MAGIC,
    CIFS_SUPER_MAGIC,
    SMB2_SUPER_MAGIC,
    GFS2_MAGIC,
    NCP_SUPER_MAGIC,
    NFS_SUPER_MAGIC,
    OCFS2_SUPER_MAGIC,
    ORANGEFS_DEVREQ_MAGIC,
    SMB_SUPER_MAGIC,
];

#[inline]
fn negative_errno() -> libc::c_int {
    -crate::ffi::get_errno()
}

/// Borrow a required C path for one query only, preventing the C-string
/// lifetime from escaping into filesystem logic.
fn with_c_path<T>(
    path: *const libc::c_char,
    query: impl FnOnce(&CStr) -> T,
) -> Result<T, libc::c_int> {
    if path.is_null() {
        return Err(-libc::EINVAL);
    }
    // SAFETY: exported callers uphold the readable NUL-terminated path contract
    // for the duration of this synchronous query.
    Ok(query(unsafe { CStr::from_ptr(path) }))
}

/// Borrow an optional C path for one query only.
fn with_optional_c_path<T>(path: *const libc::c_char, query: impl FnOnce(Option<&CStr>) -> T) -> T {
    let path = if path.is_null() {
        None
    } else {
        // SAFETY: exported callers uphold the readable NUL-terminated path contract.
        Some(unsafe { CStr::from_ptr(path) })
    };
    query(path)
}

/// Adopt a successful `open(2)` result and preserve errno before ownership is
/// converted into RAII-managed Rust storage.
fn adopt_open_fd(fd: libc::c_int) -> Result<OwnedFd, libc::c_int> {
    if fd < 0 {
        return Err(negative_errno());
    }
    // SAFETY: a nonnegative `open`/`openat` result is a newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn with_statfs_ref<T>(
    statfs: *const libc::statfs,
    query: impl FnOnce(&libc::statfs) -> T,
) -> Option<T> {
    if statfs.is_null() {
        None
    } else {
        // SAFETY: exported callers uphold the live native `statfs` pointer contract.
        Some(query(unsafe { &*statfs }))
    }
}

fn xfstatfs(fd: libc::c_int) -> Result<libc::statfs, libc::c_int> {
    if !wildcard_fd_is_valid(fd) {
        return Err(-libc::EBADF);
    }

    let mut statfs = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `statfs` is writable native storage. The special descriptors
    // are mapped to the exact paths used by current C.
    let result = unsafe {
        if fd == libc::AT_FDCWD {
            libc::statfs(c".".as_ptr(), statfs.as_mut_ptr())
        } else if fd == XAT_FDROOT {
            libc::statfs(c"/".as_ptr(), statfs.as_mut_ptr())
        } else {
            libc::fstatfs(fd, statfs.as_mut_ptr())
        }
    };
    if result < 0 {
        return Err(negative_errno());
    }

    // SAFETY: the successful libc call initialized the complete native value.
    Ok(unsafe { statfs.assume_init() })
}

/// Retrieve the mount flags using `statvfs`, whose `f_flag` field is exposed
/// by libc on all Linux targets. Some libc `statfs` layouts (including
/// aarch64) intentionally omit `f_flags`, despite the kernel ABI carrying
/// the same read-only bit.
fn xstatvfs_flags(fd: libc::c_int) -> Result<u64, libc::c_int> {
    if !wildcard_fd_is_valid(fd) {
        return Err(-libc::EBADF);
    }

    let mut statvfs = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `statvfs` is writable native storage. The special descriptors
    // use the same paths as `xfstatfs`; all other descriptors are borrowed.
    let result = unsafe {
        if fd == libc::AT_FDCWD {
            libc::statvfs(c".".as_ptr(), statvfs.as_mut_ptr())
        } else if fd == XAT_FDROOT {
            libc::statvfs(c"/".as_ptr(), statvfs.as_mut_ptr())
        } else {
            libc::fstatvfs(fd, statvfs.as_mut_ptr())
        }
    };
    if result < 0 {
        return Err(negative_errno());
    }

    // SAFETY: the successful libc call initialized the complete native value.
    Ok(unsafe { statvfs.assume_init() }.f_flag as u64)
}

fn xstatfsat(dir_fd: libc::c_int, path: Option<&CStr>) -> Result<libc::statfs, libc::c_int> {
    if !wildcard_fd_is_valid(dir_fd) {
        return Err(-libc::EBADF);
    }

    let path = path.unwrap_or(c"");
    if path.is_empty() {
        return xfstatfs(dir_fd);
    }

    let (dir_fd, path) = resolve_at_path(dir_fd, Some(path))?;
    // SAFETY: `path` is NUL-terminated and `dir_fd` is a validated descriptor
    // or AT_FDCWD.
    let fd = unsafe { libc::openat(dir_fd, path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    let fd = adopt_open_fd(fd)?;
    xfstatfs(fd.as_raw_fd())
}

pub(super) fn is_fs_type_at(
    dir_fd: libc::c_int,
    path: Option<&CStr>,
    magic_value: StatFsType,
) -> libc::c_int {
    let statfs = match xstatfsat(dir_fd, path) {
        Ok(statfs) => statfs,
        Err(error) => return error,
    };
    libc::c_int::from(statfs.f_type as StatFsType == magic_value)
}

#[inline]
fn is_temporary_fs(statfs: &libc::statfs) -> bool {
    matches!(
        statfs.f_type as StatFsType,
        magic if magic == RAMFS_MAGIC as StatFsType
            || magic == TMPFS_MAGIC as StatFsType
    )
}

#[inline]
fn is_network_fs(statfs: &libc::statfs) -> bool {
    NETWORK_FILESYSTEM_MAGICS
        .iter()
        .any(|magic| statfs.f_type as StatFsType == *magic as StatFsType)
}

fn access_fd(fd: libc::c_int, mode: libc::c_int) -> libc::c_int {
    if !wildcard_fd_is_valid(fd) {
        return -libc::EBADF;
    }

    // SAFETY: all paths are static NUL-terminated strings; ordinary
    // descriptors use Linux AT_EMPTY_PATH exactly like current C.
    let result = unsafe {
        if fd == libc::AT_FDCWD {
            libc::access(c".".as_ptr(), mode)
        } else if fd == XAT_FDROOT {
            libc::access(c"/".as_ptr(), mode)
        } else {
            libc::faccessat(fd, c"".as_ptr(), mode, libc::AT_EMPTY_PATH)
        }
    };
    if result < 0 { negative_errno() } else { 0 }
}

fn fd_is_read_only_fs(fd: libc::c_int) -> libc::c_int {
    let statfs = match xfstatfs(fd) {
        Ok(statfs) => statfs,
        Err(error) => return error,
    };

    let flags = match xstatvfs_flags(fd) {
        Ok(flags) => flags,
        Err(error) => return error,
    };
    if flags & ST_RDONLY != 0 {
        return 1;
    }
    if is_network_fs(&statfs) {
        return libc::c_int::from(access_fd(fd, libc::W_OK) == -libc::EROFS);
    }
    0
}

fn statfs_path(path: &CStr) -> Result<libc::statfs, libc::c_int> {
    let mut statfs = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `path` is NUL-terminated and `statfs` is writable native
    // storage for the duration of the call.
    if unsafe { libc::statfs(path.as_ptr(), statfs.as_mut_ptr()) } < 0 {
        return Err(negative_errno());
    }
    // SAFETY: successful `statfs()` initialized the complete native value.
    Ok(unsafe { statfs.assume_init() })
}

/// Multiply current C's explicitly widened `statvfs` fields.
///
/// GCC's `__builtin_mul_overflow`, used by `MUL_SAFE`, stores the wrapped
/// result even when it reports overflow. Return both values so the ABI adapter
/// can preserve that output-before-`ERANGE` behavior.
#[inline]
fn vfs_free_bytes_from_statvfs(statvfs: &libc::statvfs) -> (u64, bool) {
    let fragment_size = statvfs.f_frsize as u64;
    let free_blocks = statvfs.f_bfree as u64;
    let (bytes, overflowed) = fragment_size.overflowing_mul(free_blocks);
    (bytes, overflowed)
}

/// C ABI mirror of `vfs_free_bytes()`.
///
/// # Safety
///
/// `ret` must be null or point to writable `uint64_t` storage for this call.
/// A negative `fd` or null output pointer is accepted as a fail-closed
/// extension and returns `-EINVAL` without issuing `fstatvfs()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_vfs_free_bytes(fd: libc::c_int, ret: *mut u64) -> libc::c_int {
    if fd < 0 || ret.is_null() {
        return -libc::EINVAL;
    }

    let mut statvfs = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `statvfs` points to writable native `struct statvfs` storage,
    // and the validated nonnegative descriptor is only borrowed by libc.
    if unsafe { libc::fstatvfs(fd, statvfs.as_mut_ptr()) } < 0 {
        let errno = crate::ffi::get_errno();
        return if errno > 0 { -errno } else { -libc::EIO };
    }

    // SAFETY: successful `fstatvfs()` initialized the complete native value.
    let statvfs = unsafe { statvfs.assume_init() };
    let (bytes, overflowed) = vfs_free_bytes_from_statvfs(&statvfs);

    // SAFETY: the entry-point contract guarantees writable output storage.
    unsafe { ret.write(bytes) };
    if overflowed {
        return -libc::ERANGE;
    }

    0
}

/// # Safety
///
/// `path` must be null or point to a readable NUL-terminated C string, and
/// `ret` must point to writable native `struct statfs` storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_xstatfsat(
    dir_fd: libc::c_int,
    path: *const libc::c_char,
    ret: *mut libc::statfs,
) -> libc::c_int {
    if ret.is_null() {
        return -libc::EINVAL;
    }
    let statfs = match with_optional_c_path(path, |path| xstatfsat(dir_fd, path)) {
        Ok(statfs) => statfs,
        Err(error) => return error,
    };
    // SAFETY: the entry-point contract guarantees writable output storage.
    unsafe { ret.write(statfs) };
    0
}

/// # Safety
///
/// `path` must be null or point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_fs_type_at(
    dir_fd: libc::c_int,
    path: *const libc::c_char,
    magic_value: StatFsType,
) -> libc::c_int {
    with_optional_c_path(path, |path| is_fs_type_at(dir_fd, path, magic_value))
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_fd_is_read_only_fs(fd: libc::c_int) -> libc::c_int {
    fd_is_read_only_fs(fd)
}

/// # Safety
///
/// `path` must point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_is_read_only_fs(path: *const libc::c_char) -> libc::c_int {
    match with_c_path(path, |path| {
        // SAFETY: `path` is NUL-terminated by `with_c_path`.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_CLOEXEC | libc::O_PATH) };
        adopt_open_fd(fd).map(|fd| fd_is_read_only_fs(fd.as_raw_fd()))
    }) {
        Ok(Ok(result)) => result,
        Ok(Err(error)) | Err(error) => error,
    }
}

/// # Safety
///
/// `statfs` must point to a live native `struct statfs`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_temporary_fs(statfs: *const libc::statfs) -> bool {
    with_statfs_ref(statfs, is_temporary_fs).unwrap_or(false)
}

/// # Safety
///
/// `statfs` must point to a live native `struct statfs`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_network_fs(statfs: *const libc::statfs) -> bool {
    with_statfs_ref(statfs, is_network_fs).unwrap_or(false)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_fd_is_temporary_fs(fd: libc::c_int) -> libc::c_int {
    match xfstatfs(fd) {
        Ok(statfs) => libc::c_int::from(is_temporary_fs(&statfs)),
        Err(error) => error,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_fd_is_network_fs(fd: libc::c_int) -> libc::c_int {
    match xfstatfs(fd) {
        Ok(statfs) => libc::c_int::from(is_network_fs(&statfs)),
        Err(error) => error,
    }
}

/// # Safety
///
/// `path` must point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_is_temporary_fs(path: *const libc::c_char) -> libc::c_int {
    match with_c_path(path, statfs_path) {
        Ok(Ok(statfs)) => libc::c_int::from(is_temporary_fs(&statfs)),
        Ok(Err(error)) | Err(error) => error,
    }
}

/// # Safety
///
/// `path` must point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_is_network_fs(path: *const libc::c_char) -> libc::c_int {
    match with_c_path(path, statfs_path) {
        Ok(Ok(statfs)) => libc::c_int::from(is_network_fs(&statfs)),
        Ok(Err(error)) | Err(error) => error,
    }
}
