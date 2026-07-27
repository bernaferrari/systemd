// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/stat-util.c (directory/null/proc helpers)
// PORT-SYNC: src/basic/stat-util.h (inline stat filesystem facades)

use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::StatFsType;
use super::descriptor::{XAT_FDROOT, resolve_at_path, wildcard_fd_is_valid};
use super::filesystem::is_fs_type_at;
use super::verification::{stat_is_empty, stat_may_be_dev_null};

const CHASE_PREFIX_ROOT: libc::c_int = 1 << 0;
const PROC_SUPER_MAGIC: u64 = 0x9fa0;

#[repr(C)]
struct LinuxDirent64 {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
    d_name: [u8; 0],
}

// SAFETY: this binds the canonical C chase implementation. The adapter below
// supplies native `struct stat` storage and null output-path ownership.
unsafe extern "C" {
    fn chase_and_stat(
        path: *const libc::c_char,
        root: *const libc::c_char,
        chase_flags: libc::c_int,
        ret_path: *mut *mut libc::c_char,
        ret_stat: *mut libc::stat,
    ) -> libc::c_int;
}

#[inline]
fn negative_errno() -> libc::c_int {
    -crate::ffi::get_errno()
}

fn open_directory_at(dir_fd: libc::c_int, path: Option<&CStr>) -> Result<OwnedFd, libc::c_int> {
    if !wildcard_fd_is_valid(dir_fd) {
        return Err(-libc::EBADF);
    }

    let path = path.unwrap_or(c"");
    let (dir_fd, path) = if path.is_empty() {
        if dir_fd == XAT_FDROOT {
            (libc::AT_FDCWD, std::borrow::Cow::Borrowed(c"/"))
        } else {
            (dir_fd, std::borrow::Cow::Borrowed(c"."))
        }
    } else {
        resolve_at_path(dir_fd, Some(path))?
    };

    // SAFETY: `path` is NUL-terminated and `dir_fd` is validated. Successful
    // openat returns a newly owned descriptor which is adopted immediately.
    let fd = unsafe { libc::openat(dir_fd, path.as_ptr(), libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(negative_errno());
    }
    // SAFETY: successful `openat()` returned a newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[inline]
fn dot_or_dot_dot(name: &[u8]) -> bool {
    name == b"." || name == b".."
}

fn hidden_or_backup_file(name: &[u8]) -> bool {
    if name.starts_with(b".")
        || matches!(name, b"lost+found" | b"aquota.user" | b"aquota.group")
        || name.ends_with(b"~")
    {
        return true;
    }

    let Some(dot) = name.iter().rposition(|byte| *byte == b'.') else {
        return false;
    };
    matches!(
        &name[dot + 1..],
        b"ignore"
            | b"rpmnew"
            | b"rpmsave"
            | b"rpmorig"
            | b"dpkg-old"
            | b"dpkg-new"
            | b"dpkg-tmp"
            | b"dpkg-dist"
            | b"dpkg-bak"
            | b"dpkg-backup"
            | b"dpkg-remove"
            | b"ucf-new"
            | b"ucf-old"
            | b"ucf-dist"
            | b"swp"
            | b"bak"
            | b"old"
            | b"new"
    )
}

fn directory_buffer_has_entry(
    buffer: &[u8],
    ignore_hidden_or_backup: bool,
) -> Result<bool, libc::c_int> {
    let reclen_offset = std::mem::offset_of!(LinuxDirent64, d_reclen);
    let name_offset = std::mem::offset_of!(LinuxDirent64, d_name);
    let mut cursor = 0usize;

    while cursor < buffer.len() {
        let reclen_end = cursor
            .checked_add(reclen_offset)
            .and_then(|offset| offset.checked_add(std::mem::size_of::<u16>()))
            .ok_or(-libc::EIO)?;
        if reclen_end > buffer.len() {
            return Err(-libc::EIO);
        }
        let reclen = u16::from_ne_bytes(
            buffer[cursor + reclen_offset..reclen_end]
                .try_into()
                .map_err(|_| -libc::EIO)?,
        ) as usize;
        let record_end = cursor.checked_add(reclen).ok_or(-libc::EIO)?;
        let name_start = cursor.checked_add(name_offset).ok_or(-libc::EIO)?;
        if reclen <= name_offset || record_end > buffer.len() {
            return Err(-libc::EIO);
        }

        let record_name = &buffer[name_start..record_end];
        let Some(nul) = record_name.iter().position(|byte| *byte == 0) else {
            return Err(-libc::EIO);
        };
        let name = &record_name[..nul];
        let ignored = if ignore_hidden_or_backup {
            hidden_or_backup_file(name)
        } else {
            dot_or_dot_dot(name)
        };
        if !ignored {
            return Ok(true);
        }
        cursor = record_end;
    }
    Ok(false)
}

fn dir_is_empty_at(
    dir_fd: libc::c_int,
    path: Option<&CStr>,
    ignore_hidden_or_backup: bool,
) -> libc::c_int {
    let fd = match open_directory_at(dir_fd, path) {
        Ok(fd) => fd,
        Err(error) => return error,
    };
    let mut storage = MaybeUninit::<[libc::dirent; 16]>::uninit();
    let capacity = if ignore_hidden_or_backup {
        std::mem::size_of::<[libc::dirent; 16]>()
    } else {
        std::mem::size_of::<[libc::dirent; 3]>()
    };

    loop {
        // SAFETY: `storage` provides aligned writable capacity for getdents64;
        // only the returned initialized byte count is exposed below.
        let count = unsafe {
            libc::syscall(
                libc::SYS_getdents64 as libc::c_long,
                fd.as_raw_fd(),
                storage.as_mut_ptr().cast::<libc::c_void>(),
                capacity,
            )
        };
        if count < 0 {
            return negative_errno();
        }
        if count == 0 {
            return 1;
        }
        if count as usize > capacity {
            return -libc::EIO;
        }

        // SAFETY: getdents64 initialized exactly `count` bytes within storage.
        let bytes =
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), count as usize) };
        match directory_buffer_has_entry(bytes, ignore_hidden_or_backup) {
            Ok(true) => return 0,
            Ok(false) => {}
            Err(error) => return error,
        }
    }
}

struct PathComponents<'a> {
    path: &'a [u8],
    cursor: usize,
}

impl<'a> PathComponents<'a> {
    fn new(path: &'a [u8]) -> Self {
        Self { path, cursor: 0 }
    }
}

impl<'a> Iterator for PathComponents<'a> {
    type Item = Result<&'a [u8], ()>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            while self.cursor < self.path.len() && self.path[self.cursor] == b'/' {
                self.cursor += 1;
            }
            if self.cursor == self.path.len() {
                return None;
            }
            let start = self.cursor;
            while self.cursor < self.path.len() && self.path[self.cursor] != b'/' {
                self.cursor += 1;
            }
            let component = &self.path[start..self.cursor];
            if component.len() > libc::NAME_MAX as usize {
                return Some(Err(()));
            }
            if component == b"." {
                continue;
            }
            return Some(Ok(component));
        }
    }
}

fn is_dev_null_beneath_root(path: &[u8], root: Option<&[u8]>) -> bool {
    let root = root.unwrap_or(b"/");
    if path.starts_with(b"/") != root.starts_with(b"/") {
        return false;
    }

    let mut path_components = PathComponents::new(path);
    for root_component in PathComponents::new(root) {
        let (Ok(root_component), Some(Ok(path_component))) =
            (root_component, path_components.next())
        else {
            return false;
        };
        if path_component != root_component {
            return false;
        }
    }

    let Some(Ok(first)) = path_components.next() else {
        return false;
    };
    let Some(Ok(second)) = path_components.next() else {
        return false;
    };
    first == b"dev" && second == b"null" && path_components.next().is_none()
}

fn chase_stat(path: &CStr, root: Option<&CStr>) -> Result<libc::stat, libc::c_int> {
    let mut st = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: both paths are NUL-terminated, no owned ret_path is requested,
    // and `st` is writable native storage for the canonical chase call.
    let result = unsafe {
        chase_and_stat(
            path.as_ptr(),
            root.map_or(std::ptr::null(), CStr::as_ptr),
            CHASE_PREFIX_ROOT,
            std::ptr::null_mut(),
            st.as_mut_ptr(),
        )
    };
    if result < 0 {
        return Err(result);
    }
    // SAFETY: successful chase_and_stat initialized the complete native stat.
    Ok(unsafe { st.assume_init() })
}

fn null_or_empty(st: &libc::stat) -> bool {
    stat_may_be_dev_null(st) || stat_is_empty(st)
}

fn null_or_empty_path_with_root(path: &CStr, root: Option<&CStr>) -> libc::c_int {
    if is_dev_null_beneath_root(path.to_bytes(), root.map(CStr::to_bytes)) {
        return 1;
    }
    match chase_stat(path, root) {
        Ok(st) => libc::c_int::from(null_or_empty(&st)),
        Err(error) => error,
    }
}

fn set_errno(errno: libc::c_int) {
    // SAFETY: errno is thread-local storage exposed by libc on Linux.
    unsafe { *libc::__errno_location() = errno };
}

struct ErrnoGuard(libc::c_int);

impl Drop for ErrnoGuard {
    fn drop(&mut self) {
        set_errno(self.0);
    }
}

fn proc_mounted() -> libc::c_int {
    let _errno_guard = ErrnoGuard(crate::ffi::get_errno());
    let result = is_fs_type_at(
        libc::AT_FDCWD,
        Some(c"/proc/"),
        PROC_SUPER_MAGIC as StatFsType,
    );
    if result == -libc::ENOENT { 0 } else { result }
}

// SAFETY: callers must uphold the C-string contract for a non-null pointer.
unsafe fn optional_c_path<'a>(path: *const libc::c_char) -> Option<&'a CStr> {
    if path.is_null() {
        None
    } else {
        // SAFETY: guaranteed by the caller after the null check.
        Some(unsafe { CStr::from_ptr(path) })
    }
}

/// # Safety
///
/// `path` must be null or point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dir_is_empty_at(
    dir_fd: libc::c_int,
    path: *const libc::c_char,
    ignore_hidden_or_backup: bool,
) -> libc::c_int {
    // SAFETY: forwarded from this entry point's pointer contract.
    let path = unsafe { optional_c_path(path) };
    dir_is_empty_at(dir_fd, path, ignore_hidden_or_backup)
}

/// # Safety
///
/// `path` must be null or point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dir_is_empty(
    path: *const libc::c_char,
    ignore_hidden_or_backup: bool,
) -> libc::c_int {
    // SAFETY: forwarded from this entry point's pointer contract.
    let path = unsafe { optional_c_path(path) };
    dir_is_empty_at(libc::AT_FDCWD, path, ignore_hidden_or_backup)
}

/// # Safety
///
/// `st` must point to a live native `struct stat`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_null_or_empty(st: *mut libc::stat) -> bool {
    if st.is_null() {
        return false;
    }
    // SAFETY: guaranteed by the entry-point contract after the null check.
    null_or_empty(unsafe { &*st })
}

/// # Safety
///
/// `path` must point to a readable NUL-terminated C string; `root` may be null
/// or point to another readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_null_or_empty_path_with_root(
    path: *const libc::c_char,
    root: *const libc::c_char,
) -> libc::c_int {
    if path.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: guaranteed by the entry-point contract after the null check.
    let path = unsafe { CStr::from_ptr(path) };
    // SAFETY: forwarded from this entry point's pointer contract.
    let root = unsafe { optional_c_path(root) };
    null_or_empty_path_with_root(path, root)
}

/// # Safety
///
/// `path` must point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_null_or_empty_path(path: *const libc::c_char) -> libc::c_int {
    if path.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: guaranteed by the entry-point contract after the null check.
    let path = unsafe { CStr::from_ptr(path) };
    null_or_empty_path_with_root(path, None)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_fd_is_fs_type(fd: libc::c_int, magic_value: StatFsType) -> libc::c_int {
    is_fs_type_at(fd, None, magic_value)
}

/// # Safety
///
/// `path` must be null or point to a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_is_fs_type(
    path: *const libc::c_char,
    magic_value: StatFsType,
) -> libc::c_int {
    // SAFETY: forwarded from this entry point's pointer contract.
    let path = unsafe { optional_c_path(path) };
    is_fs_type_at(libc::AT_FDCWD, path, magic_value)
}

#[unsafe(no_mangle)]
pub extern "C" fn rs_proc_mounted() -> libc::c_int {
    proc_mounted()
}
