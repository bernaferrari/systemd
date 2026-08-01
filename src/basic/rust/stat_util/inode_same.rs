// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.stat-util; authority=src/basic/stat-util.c,src/basic/stat-util.h,src/basic/mountpoint-util.c
//
// inode_same_at and related identity helpers.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ffi::CStr;
use std::mem::{MaybeUninit, align_of, offset_of};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr::NonNull;

use super::inode::stat_inode_same;
use super::xstatx::{STATX_MNT_ID_UNIQUE, xstatx_full};

const ORIGINAL_MAX_HANDLE_SIZE: usize = 128;
const AT_HANDLE_MNT_ID_UNIQUE: libc::c_int = 0x001;
const AT_HANDLE_FID: libc::c_int = libc::AT_REMOVEDIR;
const INODE_SAME_FLAGS: libc::c_int =
    libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT;

#[derive(Debug, Eq, PartialEq)]
struct FileHandle {
    handle_type: libc::c_int,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy)]
enum MountIdRequest {
    Ordinary,
    PreferUnique,
    RequireUnique,
}

#[derive(Clone, Copy, Debug)]
enum MountId {
    Ordinary(libc::c_int),
    Unique(u64),
}

impl MountId {
    #[inline]
    fn value(self) -> u64 {
        match self {
            Self::Ordinary(value) => value as u64,
            Self::Unique(value) => value,
        }
    }
}

struct NativeFileHandle {
    pointer: NonNull<libc::file_handle>,
    layout: Layout,
}

impl NativeFileHandle {
    fn new(handle_bytes: usize) -> Result<Self, libc::c_int> {
        let size = offset_of!(libc::file_handle, f_handle)
            .checked_add(handle_bytes)
            .ok_or(-libc::EOVERFLOW)?;
        let layout = Layout::from_size_align(size, align_of::<libc::file_handle>())
            .map_err(|_| -libc::EOVERFLOW)?;

        // SAFETY: `layout` is nonzero and was constructed from the native
        // file_handle alignment. Ownership is immediately captured by Drop.
        let allocation = unsafe_ffi!(alloc_zeroed(layout));
        let pointer = NonNull::new(allocation.cast::<libc::file_handle>()).ok_or(-libc::ENOMEM)?;

        // SAFETY: the allocation is aligned and large enough for the native
        // header plus `handle_bytes` writable payload bytes.
        unsafe_ffi!({
            pointer.as_ptr().write(libc::file_handle {
                handle_bytes: handle_bytes as libc::c_uint,
                handle_type: 0,
                f_handle: [],
            })
        });
        Ok(Self { pointer, layout })
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut libc::file_handle {
        self.pointer.as_ptr()
    }

    fn reported_size(&self) -> usize {
        // SAFETY: `pointer` remains live for self's lifetime.
        unsafe_ffi!(self.pointer.as_ref().handle_bytes as usize)
    }

    fn snapshot(&self) -> Result<FileHandle, libc::c_int> {
        let handle_bytes = self.reported_size();
        let capacity = self
            .layout
            .size()
            .checked_sub(offset_of!(libc::file_handle, f_handle))
            .ok_or(-libc::EOVERFLOW)?;
        if handle_bytes > capacity {
            return Err(-libc::EOVERFLOW);
        }

        // SAFETY: a successful name_to_handle_at call initialized the native
        // header and exactly `handle_bytes` payload bytes within this allocation.
        let native = unsafe_ffi!(self.pointer.as_ref());
        // SAFETY: capacity was checked above and f_handle begins the payload.
        let bytes = unsafe_ffi!(std::slice::from_raw_parts(
            native.f_handle.as_ptr(),
            handle_bytes
        ))
        .to_vec();
        Ok(FileHandle {
            handle_type: native.handle_type,
            bytes,
        })
    }
}

impl Drop for NativeFileHandle {
    fn drop(&mut self) {
        // SAFETY: this allocation was created with the same layout in new()
        // and is uniquely owned by this RAII value.
        unsafe_ffi!(dealloc(self.pointer.as_ptr().cast::<u8>(), self.layout));
    }
}

fn is_name_to_handle_at_fatal_error(error: libc::c_int) -> bool {
    crate::mountpoint_util::is_name_to_handle_at_fatal_error(error)
}

fn call_name_to_handle_at(
    fd: libc::c_int,
    path: &CStr,
    handle: &mut NativeFileHandle,
    mount_id: *mut libc::c_int,
    flags: libc::c_int,
) -> Result<(), libc::c_int> {
    // SAFETY: `path` is NUL-terminated, `handle` owns writable target-native
    // storage, and mount_id is either null or live storage selected below.
    if unsafe_ffi!(libc::name_to_handle_at(
        fd,
        path.as_ptr(),
        handle.as_mut_ptr(),
        mount_id,
        flags
    )) < 0
    {
        Err(-crate::ffi::get_errno())
    } else {
        Ok(())
    }
}

fn statx_unique_mount_id(
    fd: libc::c_int,
    path: &CStr,
    flags: libc::c_int,
) -> Result<u64, libc::c_int> {
    let path_flags = flags & (libc::AT_SYMLINK_FOLLOW | libc::AT_EMPTY_PATH);
    let statx_flags = if path_flags & libc::AT_SYMLINK_FOLLOW != 0 {
        path_flags & !libc::AT_SYMLINK_FOLLOW
    } else {
        path_flags | libc::AT_SYMLINK_NOFOLLOW
    } | libc::AT_STATX_DONT_SYNC;
    let (statx, _) = xstatx_full(fd, Some(path), statx_flags, 0, STATX_MNT_ID_UNIQUE, 0, 0)?;
    Ok(statx.stx_mnt_id)
}

fn name_to_handle_at_loop(
    fd: libc::c_int,
    path: &CStr,
    flags: libc::c_int,
    mount_request: MountIdRequest,
) -> Result<(FileHandle, MountId), libc::c_int> {
    let mut size = ORIGINAL_MAX_HANDLE_SIZE;
    loop {
        let mut handle = NativeFileHandle::new(size)?;

        if !matches!(mount_request, MountIdRequest::Ordinary) {
            let mut unique_mount_id = 0u64;
            // With AT_HANDLE_MNT_ID_UNIQUE the kernel treats this nominal
            // `int *` argument as a pointer to a complete u64.
            let mount_pointer = (&mut unique_mount_id as *mut u64).cast::<libc::c_int>();
            match call_name_to_handle_at(
                fd,
                path,
                &mut handle,
                mount_pointer,
                flags | AT_HANDLE_MNT_ID_UNIQUE,
            ) {
                Ok(()) => return Ok((handle.snapshot()?, MountId::Unique(unique_mount_id))),
                Err(error) if error == -libc::EOVERFLOW => {
                    let reported_size = handle.reported_size();
                    if reported_size <= size {
                        return Err(-libc::EOVERFLOW);
                    }
                    if reported_size
                        > libc::c_uint::MAX as usize - offset_of!(libc::file_handle, f_handle)
                    {
                        return Err(-libc::EOVERFLOW);
                    }
                    size = reported_size;
                    continue;
                }
                Err(error) if error != -libc::EINVAL => return Err(error),
                Err(_) => {
                    // EINVAL means this kernel does not know the unique-ID flag.
                }
            }
        }

        let mut ordinary_mount_id = 0;
        match call_name_to_handle_at(fd, path, &mut handle, &mut ordinary_mount_id, flags) {
            Ok(()) => {
                let file_handle = handle.snapshot()?;
                if !matches!(mount_request, MountIdRequest::Ordinary) {
                    match statx_unique_mount_id(fd, path, flags) {
                        Ok(unique_mount_id) => {
                            return Ok((file_handle, MountId::Unique(unique_mount_id)));
                        }
                        Err(error)
                            if error == -libc::EUNATCH
                                && matches!(mount_request, MountIdRequest::PreferUnique) => {}
                        Err(error) => return Err(error),
                    }
                }
                return Ok((file_handle, MountId::Ordinary(ordinary_mount_id)));
            }
            Err(error) if error != -libc::EOVERFLOW => return Err(error),
            Err(_) => {}
        }

        let reported_size = handle.reported_size();
        if reported_size <= size {
            return Err(-libc::EOVERFLOW);
        }
        if reported_size > libc::c_uint::MAX as usize - offset_of!(libc::file_handle, f_handle) {
            return Err(-libc::EOVERFLOW);
        }
        size = reported_size;
    }
}

fn name_to_handle_at_try_fid(
    fd: libc::c_int,
    path: &CStr,
    flags: libc::c_int,
    mount_request: MountIdRequest,
) -> Result<(FileHandle, MountId), libc::c_int> {
    match name_to_handle_at_loop(fd, path, flags | AT_HANDLE_FID, mount_request) {
        result @ Ok(_) => result,
        Err(error) if is_name_to_handle_at_fatal_error(error) => Err(error),
        Err(_) => name_to_handle_at_loop(fd, path, flags & !AT_HANDLE_FID, mount_request),
    }
}

fn pin_path(fd: libc::c_int, path: &CStr, nofollow: bool) -> Result<OwnedFd, libc::c_int> {
    let flags = libc::O_PATH | libc::O_CLOEXEC | if nofollow { libc::O_NOFOLLOW } else { 0 };
    // SAFETY: path is NUL-terminated and fd has already passed validation.
    let pinned = unsafe_ffi!(libc::openat(fd, path.as_ptr(), flags));
    if pinned < 0 {
        return Err(-crate::ffi::get_errno());
    }
    // SAFETY: openat returned a new uniquely owned descriptor.
    Ok(unsafe_ffi!(OwnedFd::from_raw_fd(pinned)))
}

fn native_fstatat(
    fd: libc::c_int,
    path: &CStr,
    flags: libc::c_int,
) -> Result<libc::stat, libc::c_int> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: path is NUL-terminated and stat points to writable native storage.
    if unsafe_ffi!(libc::fstatat(fd, path.as_ptr(), stat.as_mut_ptr(), flags)) < 0 {
        return Err(-crate::ffi::get_errno());
    }
    // SAFETY: successful fstatat initialized the complete native structure.
    Ok(unsafe_ffi!(stat.assume_init()))
}

#[inline]
fn path_is_empty(path: Option<&CStr>) -> bool {
    path.is_none_or(CStr::is_empty)
}

fn handle_flags(flags: libc::c_int) -> libc::c_int {
    let flags = if flags & libc::AT_SYMLINK_NOFOLLOW != 0 {
        flags & !libc::AT_SYMLINK_NOFOLLOW
    } else {
        flags | libc::AT_SYMLINK_FOLLOW
    };
    flags & (libc::AT_EMPTY_PATH | libc::AT_SYMLINK_FOLLOW)
}

fn inode_same_at(
    mut fda: libc::c_int,
    mut filea: Option<&CStr>,
    mut fdb: libc::c_int,
    mut fileb: Option<&CStr>,
    mut flags: libc::c_int,
) -> libc::c_int {
    if (fda < 0 && fda != libc::AT_FDCWD) || (fdb < 0 && fdb != libc::AT_FDCWD) {
        return -libc::EBADF;
    }
    if flags & !INODE_SAME_FLAGS != 0 {
        return -libc::EINVAL;
    }
    if (path_is_empty(filea) || path_is_empty(fileb)) && flags & libc::AT_EMPTY_PATH == 0 {
        return -libc::EINVAL;
    }
    if fda >= 0
        && fda == fdb
        && path_is_empty(filea)
        && path_is_empty(fileb)
        && flags & libc::AT_SYMLINK_NOFOLLOW != 0
    {
        return 1;
    }

    let mut pin_a = None;
    let mut pin_b = None;
    if flags & libc::AT_NO_AUTOMOUNT == 0 {
        let nofollow = flags & libc::AT_SYMLINK_NOFOLLOW != 0;
        if let Some(path) = filea.filter(|path| !path.is_empty()) {
            let pinned = match pin_path(fda, path, nofollow) {
                Ok(pinned) => pinned,
                Err(error) => return error,
            };
            fda = pinned.as_raw_fd();
            pin_a = Some(pinned);
            filea = None;
            flags |= libc::AT_EMPTY_PATH;
        }
        if let Some(path) = fileb.filter(|path| !path.is_empty()) {
            let pinned = match pin_path(fdb, path, nofollow) {
                Ok(pinned) => pinned,
                Err(error) => return error,
            };
            fdb = pinned.as_raw_fd();
            pin_b = Some(pinned);
            fileb = None;
            flags |= libc::AT_EMPTY_PATH;
        }

        let ntha_flags = handle_flags(flags);
        let (handle_a, mount_a) = match name_to_handle_at_try_fid(
            fda,
            filea.unwrap_or(c""),
            ntha_flags,
            MountIdRequest::PreferUnique,
        ) {
            Ok(value) => value,
            Err(error) if is_name_to_handle_at_fatal_error(error) => return error,
            Err(_) => return inode_same_fallback(fda, filea, fdb, fileb, flags),
        };
        let mount_request = if matches!(mount_a, MountId::Unique(_)) {
            MountIdRequest::RequireUnique
        } else {
            MountIdRequest::Ordinary
        };
        let (handle_b, mount_b) =
            match name_to_handle_at_try_fid(fdb, fileb.unwrap_or(c""), ntha_flags, mount_request) {
                Ok(value) => value,
                Err(error) if is_name_to_handle_at_fatal_error(error) => return error,
                Err(_) => return inode_same_fallback(fda, filea, fdb, fileb, flags),
            };

        if handle_a != handle_b {
            return 0;
        }
        if mount_a.value() == mount_b.value() {
            return 1;
        }
    }

    // Keep the pinned descriptors alive through the fallback calls.
    let _pins = (pin_a, pin_b);
    inode_same_fallback(fda, filea, fdb, fileb, flags)
}

fn inode_same_fallback(
    fda: libc::c_int,
    filea: Option<&CStr>,
    fdb: libc::c_int,
    fileb: Option<&CStr>,
    flags: libc::c_int,
) -> libc::c_int {
    let stat_a = match native_fstatat(fda, filea.unwrap_or(c""), flags) {
        Ok(stat) => stat,
        Err(error) => return error,
    };
    let stat_b = match native_fstatat(fdb, fileb.unwrap_or(c""), flags) {
        Ok(stat) => stat,
        Err(error) => return error,
    };
    libc::c_int::from(stat_inode_same(&stat_a, &stat_b))
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

/// C ABI mirror of `inode_same_at()`.
///
/// # Safety
///
/// Each path must be null or point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_inode_same_at(
    fda: libc::c_int,
    filea: *const libc::c_char,
    fdb: libc::c_int,
    fileb: *const libc::c_char,
    flags: libc::c_int,
) -> libc::c_int {
    // SAFETY: forwarded from this entry point's pointer contract.
    let filea = unsafe_ffi!(optional_c_path(filea));
    // SAFETY: forwarded from this entry point's pointer contract.
    let fileb = unsafe_ffi!(optional_c_path(fileb));
    inode_same_at(fda, filea, fdb, fileb, flags)
}

/// C ABI mirror of the header-inline `inode_same()`.
///
/// # Safety
///
/// Each path has the same contract as `rs_inode_same_at`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_inode_same(
    filea: *const libc::c_char,
    fileb: *const libc::c_char,
    flags: libc::c_int,
) -> libc::c_int {
    // SAFETY: the inline facade forwards both pointer contracts unchanged.
    unsafe_ffi!(rs_inode_same_at(
        libc::AT_FDCWD,
        filea,
        libc::AT_FDCWD,
        fileb,
        flags
    ))
}

/// C ABI mirror of the header-inline `fd_inode_same()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_fd_inode_same(fda: libc::c_int, fdb: libc::c_int) -> libc::c_int {
    inode_same_at(fda, None, fdb, None, libc::AT_EMPTY_PATH)
}
