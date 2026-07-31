// SPDX-License-Identifier: LGPL-2.1-or-later

//! Audited Linux ABI boundary for descriptor-confined cgroup traversal.
//!
//! `CgroupRoot` pins the manager-selected hierarchy once. Every descendant is
//! then resolved one validated component at a time beneath an already-open
//! directory. `openat2()` supplies kernel-enforced confinement when available;
//! its fallback is still descriptor-relative, rejects `.`/`..`/slashes, and
//! uses `O_NOFOLLOW`, so it cannot escape through a renamed parent or symlink.

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use nix::unistd::{SysconfVar, read as nix_read, sysconf, write as nix_write};

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

static OPENAT2_AVAILABLE: AtomicBool = AtomicBool::new(true);

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(Debug)]
pub(super) struct CgroupDirectory(OwnedFd);

impl AsFd for CgroupDirectory {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl CgroupDirectory {
    const MAX_RECURSIVE_DEPTH: usize = 256;
    const MAX_RECURSIVE_DIRECTORIES: usize = 4096;

    fn duplicate(&self) -> io::Result<Self> {
        duplicate_fd(self.as_fd()).map(Self)
    }

    pub(super) fn ensure_child(&self, component: &OsStr) -> io::Result<Self> {
        let component = component_cstr(component)?;
        mkdirat_if_missing(self.as_fd(), &component)?;
        open_component(
            self.as_fd(),
            &component,
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )
        .map(Self)
    }

    fn open_child(&self, component: &OsStr) -> io::Result<Self> {
        let component = component_cstr(component)?;
        open_component(
            self.as_fd(),
            &component,
            libc::O_PATH | libc::O_DIRECTORY,
            0,
        )
        .map(Self)
    }

    pub(super) fn open_file(&self, name: &str, access_flags: libc::c_int) -> io::Result<OwnedFd> {
        let name = component_cstr(OsStr::new(name))?;
        open_component(self.as_fd(), &name, access_flags, 0)
    }

    /// Read every `cgroup.procs` below this already-confined directory.
    ///
    /// A delegated service may create and enter arbitrary descendant cgroups,
    /// so reading only the unit root cannot prove its membership. Keep each
    /// kernel file as a separate byte string: concatenating two malformed
    /// files could otherwise manufacture a valid PID across their boundary.
    /// The aggregate byte budget bounds both kernel data and manager memory.
    pub(super) fn read_processes_recursive(&self, max_bytes: usize) -> io::Result<Vec<Vec<u8>>> {
        fn visit(
            directory: &CgroupDirectory,
            max_bytes: usize,
            depth: usize,
            directories: &mut usize,
            used: &mut usize,
            result: &mut Vec<Vec<u8>>,
        ) -> io::Result<()> {
            if depth > CgroupDirectory::MAX_RECURSIVE_DEPTH
                || *directories >= CgroupDirectory::MAX_RECURSIVE_DIRECTORIES
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "delegated cgroup hierarchy exceeds the manager recursion bound",
                ));
            }
            *directories += 1;
            let remaining = max_bytes.checked_sub(*used).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "recursive cgroup.procs snapshot exceeds its byte budget",
                )
            })?;
            let fd = directory.open_file("cgroup.procs", libc::O_RDONLY)?;
            let mut content = Vec::new();
            File::from(fd)
                .take((remaining as u64).saturating_add(1))
                .read_to_end(&mut content)?;
            if content.len() > remaining {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "recursive cgroup.procs snapshot exceeds its byte budget",
                ));
            }
            *used += content.len();
            result.push(content);

            // `/proc/self/fd/N` names this open capability. Children are still
            // reopened one component at a time with O_NOFOLLOW/openat2
            // confinement before recursion.
            let path = format!("/proc/self/fd/{}", directory.as_fd().as_raw_fd());
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let child = directory.open_child(&entry.file_name())?;
                visit(&child, max_bytes, depth + 1, directories, used, result)?;
            }
            Ok(())
        }

        let mut directories = 0;
        let mut used = 0;
        let mut result = Vec::new();
        visit(self, max_bytes, 0, &mut directories, &mut used, &mut result)?;
        Ok(result)
    }

    #[cfg(test)]
    pub(super) fn create_test_file(&self, name: &str, content: &[u8]) -> io::Result<()> {
        let name = component_cstr(OsStr::new(name))?;
        let fd = open_component(
            self.as_fd(),
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )?;
        write_once(fd.as_fd(), content)
    }

    /// Write a cgroup control without allowing synchronous kernel-side work to
    /// stall the manager (notably memory.max and memory.high reclaim).
    pub(super) fn write_control_file(&self, name: &str, content: &[u8]) -> io::Result<()> {
        #[cfg(test)]
        {
            // Ordinary files do not have cgroupfs's command-on-write
            // semantics, so truncate the fixture on every synthetic control
            // write just as the former `fs::write()` test path did.
            self.create_test_file(name, content)
        }

        #[cfg(not(test))]
        {
            let fd = self.open_file(name, libc::O_WRONLY | libc::O_NONBLOCK)?;
            write_once(fd.as_fd(), content)
        }
    }

    #[cfg(test)]
    fn remove_test_entries(&self) -> io::Result<()> {
        let directory = format!("/proc/self/fd/{}", self.as_fd().as_raw_fd());
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let name = component_cstr(&file_name)?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                let child = self.open_child(&file_name)?;
                child.remove_test_entries()?;
                unlinkat(self.as_fd(), &name, libc::AT_REMOVEDIR)?;
            } else {
                unlinkat(self.as_fd(), &name, 0)?;
            }
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn remove_descendant_directories(&self) -> io::Result<()> {
        fn remove(
            directory: &CgroupDirectory,
            depth: usize,
            directories: &mut usize,
        ) -> io::Result<()> {
            if depth > CgroupDirectory::MAX_RECURSIVE_DEPTH
                || *directories >= CgroupDirectory::MAX_RECURSIVE_DIRECTORIES
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "delegated cgroup hierarchy exceeds the manager recursion bound",
                ));
            }
            *directories += 1;

            let path = format!("/proc/self/fd/{}", directory.as_fd().as_raw_fd());
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let name = entry.file_name();
                let child = directory.open_child(&name)?;
                remove(&child, depth + 1, directories)?;
                let name = component_cstr(&name)?;
                unlinkat(directory.as_fd(), &name, libc::AT_REMOVEDIR)?;
            }
            Ok(())
        }

        // cgroupfs interface files are kernel-owned and disappear with their
        // directory; only descendant cgroup directories need explicit
        // depth-first removal. `/proc/self/fd/N` names this already-confined
        // capability and never re-resolves the original hierarchy path.
        let mut directories = 0;
        remove(self, 0, &mut directories)
    }
}

#[derive(Debug)]
pub(super) struct CgroupRoot {
    path: PathBuf,
    directory: Option<CgroupDirectory>,
    open_errno: Option<i32>,
}

impl CgroupRoot {
    pub(super) fn new(path: PathBuf) -> Self {
        match open_root(&path) {
            Ok(directory) => Self {
                path,
                directory: Some(CgroupDirectory(directory)),
                open_errno: None,
            },
            Err(error) => Self {
                path,
                directory: None,
                open_errno: Some(error.raw_os_error().unwrap_or(libc::EINVAL)),
            },
        }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn handoff_fd(&self) -> io::Result<BorrowedFd<'_>> {
        Ok(self.directory()?.as_fd())
    }

    /// Return the physical-memory authority used for percentage cgroup limits.
    ///
    /// This mirrors `physical_memory()`: start with physical pages and clamp
    /// to a finite memory.max on the manager's own preopened cgroup root. A
    /// missing or malformed cgroup limit is advisory and leaves physical RAM
    /// authoritative.
    pub(super) fn physical_memory_bytes(&self) -> io::Result<(u64, u64)> {
        let pages = sysconf(SysconfVar::_PHYS_PAGES)
            .map_err(io::Error::from)?
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let page_size = sysconf(SysconfVar::PAGE_SIZE)
            .map_err(io::Error::from)?
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let page_size = u64::try_from(page_size)
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let physical = u64::try_from(pages)
            .ok()
            .filter(|value| *value > 0)
            .and_then(|pages| pages.checked_mul(page_size))
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;

        let Some(directory) = self.directory.as_ref() else {
            return Ok((physical, page_size));
        };
        let Ok(fd) = directory.open_file("memory.max", libc::O_RDONLY) else {
            return Ok((physical, page_size));
        };
        let mut value = String::new();
        if File::from(fd)
            .take(4096)
            .read_to_string(&mut value)
            .is_err()
        {
            return Ok((physical, page_size));
        }
        let Some(limit) = value
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|limit| *limit < u64::MAX)
        else {
            return Ok((physical, page_size));
        };
        let limit = limit / page_size * page_size;
        Ok((physical.min(limit), page_size))
    }

    fn directory(&self) -> io::Result<&CgroupDirectory> {
        self.directory
            .as_ref()
            .ok_or_else(|| io::Error::from_raw_os_error(self.open_errno.unwrap_or(libc::EBADF)))
    }

    pub(super) fn ensure_directory(&self, components: &[String]) -> io::Result<CgroupDirectory> {
        let mut directory = self.directory()?.duplicate()?;
        for component in components {
            directory = directory.ensure_child(OsStr::new(component))?;
        }
        Ok(directory)
    }

    pub(super) fn open_directory(&self, components: &[String]) -> io::Result<CgroupDirectory> {
        let mut directory = self.directory()?.duplicate()?;
        for component in components {
            directory = directory.open_child(OsStr::new(component))?;
        }
        Ok(directory)
    }

    pub(super) fn remove_directory(&self, components: &[String]) -> io::Result<()> {
        let Some((name, parents)) = components.split_last() else {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        };
        let parent = self.open_directory(parents)?;
        let name_cstr = component_cstr(OsStr::new(name))?;

        #[cfg(test)]
        {
            let child = parent.open_child(OsStr::new(name))?;
            child.remove_test_entries()?;
        }
        #[cfg(not(test))]
        {
            let child = parent.open_child(OsStr::new(name))?;
            child.remove_descendant_directories()?;
        }

        unlinkat(parent.as_fd(), &name_cstr, libc::AT_REMOVEDIR)
    }
}

impl PartialEq<PathBuf> for CgroupRoot {
    fn eq(&self, other: &PathBuf) -> bool {
        self.path == *other
    }
}

pub(super) struct InotifyEvent {
    pub(super) watch_descriptor: i32,
    pub(super) mask: u32,
}

pub(super) fn inotify_init_nonblocking() -> io::Result<OwnedFd> {
    // SAFETY: `inotify_init1()` takes only validated flag bits and returns a new
    // owned descriptor on success.
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    owned_fd_or_errno(fd)
}

pub(super) fn inotify_add_watch_fd(
    inotify: BorrowedFd<'_>,
    target: BorrowedFd<'_>,
    mask: u32,
) -> io::Result<i32> {
    let path = CString::new(format!("/proc/self/fd/{}", target.as_raw_fd()))
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: both descriptors are borrowed and live for this call; `path` is
    // NUL-terminated, and `mask` is passed through to the kernel unchanged.
    let watch = unsafe { libc::inotify_add_watch(inotify.as_raw_fd(), path.as_ptr(), mask) };
    if watch < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(watch)
    }
}

pub(super) fn inotify_remove_watch(inotify: BorrowedFd<'_>, watch: i32) -> io::Result<()> {
    // SAFETY: the borrowed inotify descriptor remains live for the call.
    let result = unsafe { libc::inotify_rm_watch(inotify.as_raw_fd(), watch) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn read_inotify_events(
    inotify: BorrowedFd<'_>,
    buffer: &mut [u8],
) -> io::Result<Vec<InotifyEvent>> {
    let size =
        nix_read(inotify, buffer).map_err(|error| io::Error::from_raw_os_error(error as i32))?;
    let header_size = std::mem::size_of::<libc::inotify_event>();
    let mut events = Vec::new();
    let mut offset = 0usize;
    while offset < size {
        if size - offset < header_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated inotify event header",
            ));
        }

        // SAFETY: the bounds check above covers the complete fixed header.
        // Kernel event records need not be naturally aligned in a byte buffer.
        let event = unsafe {
            std::ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<libc::inotify_event>())
        };
        let record_size = header_size.checked_add(event.len as usize).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "inotify event length overflow")
        })?;
        if record_size > size - offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated inotify event name",
            ));
        }
        events.push(InotifyEvent {
            watch_descriptor: event.wd,
            mask: event.mask,
        });
        offset += record_size;
    }
    Ok(events)
}

fn component_cstr(component: &OsStr) -> io::Result<CString> {
    let bytes = component.as_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&0)
    {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

fn open_root(path: &Path) -> io::Result<OwnedFd> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: `path` is NUL-terminated. The kernel creates a new descriptor;
    // `O_NOFOLLOW|O_DIRECTORY` rejects a symlink or non-directory root.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    owned_fd_or_errno(fd)
}

fn open_component(
    parent: BorrowedFd<'_>,
    component: &CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> io::Result<OwnedFd> {
    let flags = flags | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    if OPENAT2_AVAILABLE.load(Ordering::Relaxed) {
        let how = OpenHow {
            flags: flags as u64,
            mode: mode as u64,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        // SAFETY: `component` and `how` remain live for the syscall; `how` has
        // the Linux `open_how` layout and the size passed is exact.
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                parent.as_raw_fd(),
                component.as_ptr(),
                &how,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if result >= 0 {
            // SAFETY: successful `openat2()` returns one newly owned fd.
            return Ok(unsafe { OwnedFd::from_raw_fd(result as i32) });
        }

        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ENOSYS) => {
                OPENAT2_AVAILABLE.store(false, Ordering::Relaxed);
            }
            // Match current C chase_openat2(): seccomp may report EPERM and
            // RESOLVE_BENEATH can transiently report EAGAIN during renames.
            Some(libc::EPERM | libc::EAGAIN) => {}
            _ => return Err(error),
        }
    }

    // `component_cstr()` rejects separators and dot components. Combined with
    // this already-open parent and O_NOFOLLOW, openat() is a confined fallback
    // rather than a pathname re-resolution from the host root.
    // SAFETY: pointers and the borrowed parent remain valid for the call.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), component.as_ptr(), flags, mode) };
    owned_fd_or_errno(fd)
}

fn mkdirat_if_missing(parent: BorrowedFd<'_>, component: &CStr) -> io::Result<()> {
    // SAFETY: `component` is a validated NUL-terminated single path component
    // and the borrowed parent descriptor remains live for the call.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o755) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EEXIST) {
        Ok(())
    } else {
        Err(error)
    }
}

fn unlinkat(parent: BorrowedFd<'_>, component: &CStr, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: `component` is a validated NUL-terminated single path component
    // and `flags` is either zero or AT_REMOVEDIR.
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), component.as_ptr(), flags) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn duplicate_fd(fd: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    // SAFETY: `fd` remains live for the call. F_DUPFD_CLOEXEC returns a new
    // independently owned descriptor.
    let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    owned_fd_or_errno(duplicate)
}

fn write_once(fd: BorrowedFd<'_>, content: &[u8]) -> io::Result<()> {
    loop {
        let written = match nix_write(fd, content) {
            Ok(written) => written,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(io::Error::from_raw_os_error(error as i32)),
        };
        if written != content.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short write to cgroup control file",
            ));
        }
        return Ok(());
    }
}

fn owned_fd_or_errno(fd: libc::c_int) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: callers pass only fresh descriptors returned by Linux.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}
