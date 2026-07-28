// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.stat-util; authority=src/basic/stat-util.c,src/basic/stat-util.h
//
// xstatx_full / xstatx wrappers around native statx.
// The native libc type owns struct statx's target layout. The only raw
// operation in this module is the libc statx call and its initialized output.

use std::ffi::CStr;
use std::mem::MaybeUninit;

use super::descriptor::{resolve_at_path, wildcard_fd_is_valid};

type XStatXFlags = libc::c_uint;

const XSTATX_MNT_ID_BEST: XStatXFlags = 1 << 0;
// Linux UAPI value. libc 0.2.184 does not expose this mask yet.
pub(super) const STATX_MNT_ID_UNIQUE: libc::c_uint = 0x4000;
const STATX_MNT_ID_MASK: libc::c_uint = libc::STATX_MNT_ID | STATX_MNT_ID_UNIQUE;

#[inline]
fn flags_set(value: libc::c_uint, flags: libc::c_uint) -> bool {
    value & flags == flags
}

#[inline]
fn attributes_set(value: u64, attributes: u64) -> bool {
    value & attributes == attributes
}

fn native_statx(
    fd: libc::c_int,
    path: &CStr,
    flags: libc::c_int,
    mask: libc::c_uint,
) -> Result<libc::statx, libc::c_int> {
    // C zero-initializes the complete native structure before entering libc,
    // both to define fields omitted by old kernels and to keep MSan silent.
    let mut statx = MaybeUninit::<libc::statx>::zeroed();

    // SAFETY: `path` is a live NUL-terminated string and `statx` is writable
    // target-native storage. libc owns both the syscall ABI and struct layout.
    if unsafe { libc::statx(fd, path.as_ptr(), flags, mask, statx.as_mut_ptr()) } < 0 {
        return Err(-crate::ffi::get_errno());
    }

    // SAFETY: the backing storage was zeroed before the successful libc call,
    // so every byte is initialized even when an old kernel omits newer fields.
    Ok(unsafe { statx.assume_init() })
}

pub(super) fn xstatx_full(
    fd: libc::c_int,
    path: Option<&CStr>,
    statx_flags: libc::c_int,
    xstatx_flags: XStatXFlags,
    mandatory_mask: libc::c_uint,
    optional_mask: libc::c_uint,
    mandatory_attributes: u64,
) -> Result<(libc::statx, libc::c_int), libc::c_int> {
    if !wildcard_fd_is_valid(fd) {
        return Err(-libc::EBADF);
    }
    if mandatory_mask & optional_mask != 0 {
        return Err(-libc::EINVAL);
    }
    if xstatx_flags & XSTATX_MNT_ID_BEST != 0
        && (mandatory_mask | optional_mask) & STATX_MNT_ID_MASK != 0
    {
        return Err(-libc::EINVAL);
    }

    let (fd, path) = resolve_at_path(fd, path)?;
    let mut request_mask = mandatory_mask | optional_mask;
    if xstatx_flags & XSTATX_MNT_ID_BEST != 0 {
        request_mask |= STATX_MNT_ID_MASK;
    }

    let flags = statx_flags
        | if path.is_empty() {
            libc::AT_EMPTY_PATH
        } else {
            0
        };
    let statx = native_statx(fd, &path, flags, request_mask)?;

    if xstatx_flags & XSTATX_MNT_ID_BEST != 0 && statx.stx_mask & STATX_MNT_ID_MASK == 0 {
        return Err(-libc::EUNATCH);
    }
    if !flags_set(statx.stx_mask, mandatory_mask) {
        return Err(-libc::EUNATCH);
    }
    if !attributes_set(statx.stx_attributes_mask, mandatory_attributes) {
        return Err(-libc::EUNATCH);
    }

    let all_optional_supported = libc::c_int::from(flags_set(statx.stx_mask, optional_mask));
    Ok((statx, all_optional_supported))
}

// SAFETY: callers must uphold the C-string contract for a non-null pointer.
unsafe fn optional_c_path<'a>(path: *const libc::c_char) -> Option<&'a CStr> {
    if path.is_null() {
        None
    } else {
        // SAFETY: the caller guarantees a readable NUL-terminated C string.
        Some(unsafe { CStr::from_ptr(path) })
    }
}

/// C ABI mirror of `xstatx_full()`.
///
/// # Safety
///
/// `path` must be null or point to a readable NUL-terminated C string.
/// `ret` must point to writable native `struct statx` storage. The output is
/// left untouched unless the operation and all mandatory checks succeed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_xstatx_full(
    fd: libc::c_int,
    path: *const libc::c_char,
    statx_flags: libc::c_int,
    xstatx_flags: XStatXFlags,
    mandatory_mask: libc::c_uint,
    optional_mask: libc::c_uint,
    mandatory_attributes: u64,
    ret: *mut libc::statx,
) -> libc::c_int {
    if ret.is_null() {
        return -libc::EINVAL;
    }

    // SAFETY: forwarded from this entry point's pointer contract.
    let path = unsafe { optional_c_path(path) };
    let (statx, result) = match xstatx_full(
        fd,
        path,
        statx_flags,
        xstatx_flags,
        mandatory_mask,
        optional_mask,
        mandatory_attributes,
    ) {
        Ok(value) => value,
        Err(error) => return error,
    };

    // SAFETY: checked non-null above; the entry-point contract guarantees
    // writable target-native storage, and no output is written on failure.
    unsafe { ret.write(statx) };
    result
}

/// C ABI mirror of the header-inline `xstatx()` facade.
///
/// # Safety
///
/// `path` and `ret` have the same contracts as `rs_xstatx_full`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_xstatx(
    fd: libc::c_int,
    path: *const libc::c_char,
    statx_flags: libc::c_int,
    mandatory_mask: libc::c_uint,
    ret: *mut libc::statx,
) -> libc::c_int {
    // SAFETY: this facade forwards the complete pointer contract unchanged
    // and supplies the exact zero optional-mask/attribute arguments from C.
    unsafe { rs_xstatx_full(fd, path, statx_flags, 0, mandatory_mask, 0, 0, ret) }
}
