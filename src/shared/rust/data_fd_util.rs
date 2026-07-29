// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/data-fd-util.c, src/shared/data-fd-util.h

use crate::ffi::*;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const DATA_FD_MEMORY_LIMIT: u64 = 64 * 1024;
const DATA_FD_TMP_LIMIT: u64 = 1024 * 1024;
const COPY_BUFFER_SIZE: usize = 64 * 1024;
const TMPFILE_ATTEMPTS: u64 = 128;

#[cfg(target_os = "linux")]
const MFD_CLOEXEC: u32 = 0x0001;
#[cfg(target_os = "linux")]
const MFD_ALLOW_SEALING: u32 = 0x0002;
#[cfg(target_os = "linux")]
const MFD_NOEXEC_SEAL: u32 = 0x0008;
#[cfg(target_os = "linux")]
const MFD_EXEC: u32 = 0x0010;
#[cfg(target_os = "linux")]
const F_ADD_SEALS_CONST: i32 = 1033;
#[cfg(target_os = "linux")]
const F_SEAL_SEAL_CONST: i32 = 0x0001;
#[cfg(target_os = "linux")]
const F_SEAL_SHRINK_CONST: i32 = 0x0002;
#[cfg(target_os = "linux")]
const F_SEAL_GROW_CONST: i32 = 0x0004;
#[cfg(target_os = "linux")]
const F_SEAL_WRITE_CONST: i32 = 0x0008;

static TMPFILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CopyProgress {
    ExhaustedSource,
    ReachedLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceKind {
    Regular,
    Socket,
    Fifo,
    CharacterDevice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceInfo {
    kind: SourceKind,
    size_hint: Option<u64>,
}

pub fn copy_data_fd(fd: RawFd) -> io::Result<OwnedFd> {
    let source = inspect_source_fd(fd)?;
    let source_fd = dup_fd(fd)?;

    let mut partial_copy = if source.kind != SourceKind::Regular
        || source
            .size_hint
            .is_none_or(|size| size < DATA_FD_MEMORY_LIMIT)
    {
        let memfd = create_copy_memfd()?;

        match copy_bytes_raw(
            source_fd.as_raw_fd(),
            memfd.as_raw_fd(),
            DATA_FD_MEMORY_LIMIT,
        )? {
            CopyProgress::ExhaustedSource => return finalize_small_copy(memfd),
            CopyProgress::ReachedLimit => {
                rewind_fd(memfd.as_raw_fd())?;
                Some(memfd)
            }
        }
    } else {
        None
    };

    if source.kind != SourceKind::Regular
        || source.size_hint.is_none_or(|size| size < DATA_FD_TMP_LIMIT)
    {
        let tmpfd = open_anonymous_tmpfile(Path::new("/tmp"))?;

        match copy_into_fallback(
            tmpfd,
            partial_copy.take(),
            source_fd.as_raw_fd(),
            DATA_FD_TMP_LIMIT.saturating_sub(DATA_FD_MEMORY_LIMIT),
        )? {
            Ok(result) => return Ok(result),
            Err(too_large_tmp) => partial_copy = Some(too_large_tmp),
        }
    }

    let tmpfd = open_anonymous_tmpfile(&var_tmp_dir())?;
    copy_from_prefix_and_source(tmpfd, partial_copy.take(), source_fd.as_raw_fd())
}

pub fn memfd_clone_fd(fd: RawFd, name: &str, mode: i32) -> io::Result<OwnedFd> {
    if fd < 0 || name.is_empty() {
        return Err(invalid_input_error());
    }

    let access_mode = mode & libc::O_ACCMODE;
    if access_mode != libc::O_RDONLY && access_mode != libc::O_RDWR {
        return Err(invalid_input_error());
    }

    if mode & !(libc::O_ACCMODE | libc::O_CLOEXEC) != 0 {
        return Err(invalid_input_error());
    }

    let st = fstat(fd)?;
    let read_only = access_mode == libc::O_RDONLY;
    let executable = (st.st_mode & 0o111) != 0;

    let target = create_named_memfd(name, read_only, executable)?;
    let source_fd = dup_fd(fd)?;
    copy_all(source_fd.as_raw_fd(), target.as_raw_fd())?;

    if read_only {
        seal_for_read_only(&target)?;
        return reopen_fd(target.as_raw_fd(), mode);
    }

    rewind_fd(target.as_raw_fd())?;
    set_cloexec(target.as_raw_fd(), mode & libc::O_CLOEXEC != 0)?;
    Ok(target)
}

fn inspect_source_fd(fd: RawFd) -> io::Result<SourceInfo> {
    let st = fstat(fd)?;

    let kind = mode_to_source_kind(st.st_mode)?;
    let size_hint = if kind == SourceKind::Regular && st.st_size >= 0 {
        Some(st.st_size as u64)
    } else {
        None
    };

    Ok(SourceInfo { kind, size_hint })
}

fn mode_to_source_kind(mode: libc::mode_t) -> io::Result<SourceKind> {
    match mode & libc::S_IFMT {
        libc::S_IFREG => Ok(SourceKind::Regular),
        libc::S_IFSOCK => Ok(SourceKind::Socket),
        libc::S_IFIFO => Ok(SourceKind::Fifo),
        libc::S_IFCHR => Ok(SourceKind::CharacterDevice),
        libc::S_IFDIR => Err(io::Error::from_raw_os_error(libc::EISDIR)),
        libc::S_IFLNK => Err(io::Error::from_raw_os_error(libc::ELOOP)),
        _ => Err(io::Error::from_raw_os_error(EBADFD)),
    }
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: st points to aligned, writable storage for one libc::stat, and
    // fstat neither retains the pointer nor requires fd to be valid for memory safety.
    let r = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: a successful fstat fully initialized the stat object above.
        Ok(unsafe { st.assume_init() })
    }
}

fn dup_fd(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC takes only scalar arguments; an invalid borrowed
    // descriptor is reported by the kernel without affecting Rust memory.
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: successful F_DUPFD_CLOEXEC returns a fresh descriptor whose
        // ownership has not been transferred anywhere else.
        Ok(unsafe { OwnedFd::from_raw_fd(dup) })
    }
}

fn copy_bytes_raw(src: RawFd, dst: RawFd, max_bytes: u64) -> io::Result<CopyProgress> {
    let mut remaining = max_bytes;
    let mut buffer = [0u8; COPY_BUFFER_SIZE];

    while remaining > 0 {
        let request = remaining.min(buffer.len() as u64) as usize;
        let n_read = loop {
            // SAFETY: buffer has writable capacity for request bytes, and read
            // neither outlives this call nor retains its destination pointer.
            let n = unsafe { libc::read(src, buffer.as_mut_ptr().cast(), request) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            break n as usize;
        };

        if n_read == 0 {
            return Ok(CopyProgress::ExhaustedSource);
        }

        write_all_raw(dst, &buffer[..n_read])?;
        remaining -= n_read as u64;
    }

    Ok(CopyProgress::ReachedLimit)
}

fn write_all_raw(fd: RawFd, mut buffer: &[u8]) -> io::Result<()> {
    while !buffer.is_empty() {
        // SAFETY: buffer is readable for buffer.len() bytes, and write neither
        // mutates nor retains the source slice.
        let n = unsafe { libc::write(fd, buffer.as_ptr().cast(), buffer.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        buffer = &buffer[n as usize..];
    }

    Ok(())
}

fn copy_all(src: RawFd, dst: RawFd) -> io::Result<()> {
    let mut buffer = [0u8; COPY_BUFFER_SIZE];

    loop {
        let n_read = loop {
            // SAFETY: buffer is valid writable storage for its full length, and
            // read does not retain the pointer after returning.
            let n = unsafe { libc::read(src, buffer.as_mut_ptr().cast(), buffer.len()) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            break n as usize;
        };

        if n_read == 0 {
            return Ok(());
        }

        write_all_raw(dst, &buffer[..n_read])?;
    }
}

fn rewind_fd(fd: RawFd) -> io::Result<()> {
    // SAFETY: lseek receives only the borrowed descriptor and scalar arguments;
    // an invalid or non-seekable descriptor is returned as an OS error.
    let offset = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    if offset < 0 {
        return Err(io::Error::last_os_error());
    }
    if offset != 0 {
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    Ok(())
}

fn finalize_small_copy(fd: OwnedFd) -> io::Result<OwnedFd> {
    if seal_for_read_only(&fd).is_ok() {
        return Ok(fd);
    }

    reopen_fd(fd.as_raw_fd(), libc::O_RDONLY | libc::O_CLOEXEC)
}

fn copy_into_fallback(
    tmpfd: OwnedFd,
    prefix: Option<OwnedFd>,
    source_fd: RawFd,
    remaining_limit: u64,
) -> io::Result<Result<OwnedFd, OwnedFd>> {
    let tmpfd = copy_prefix_if_needed(tmpfd, prefix)?;

    match copy_bytes_raw(source_fd, tmpfd.as_raw_fd(), remaining_limit)? {
        CopyProgress::ExhaustedSource => {
            let ro = reopen_fd(tmpfd.as_raw_fd(), libc::O_RDONLY | libc::O_CLOEXEC)?;
            Ok(Ok(ro))
        }
        CopyProgress::ReachedLimit => {
            rewind_fd(tmpfd.as_raw_fd())?;
            Ok(Err(tmpfd))
        }
    }
}

fn copy_prefix_if_needed(mut tmpfd: OwnedFd, prefix: Option<OwnedFd>) -> io::Result<OwnedFd> {
    if let Some(prefix) = prefix {
        copy_all(prefix.as_raw_fd(), tmpfd.as_raw_fd())?;
    }
    Ok(tmpfd)
}

fn copy_from_prefix_and_source(
    tmpfd: OwnedFd,
    prefix: Option<OwnedFd>,
    source_fd: RawFd,
) -> io::Result<OwnedFd> {
    let tmpfd = copy_prefix_if_needed(tmpfd, prefix)?;
    copy_all(source_fd, tmpfd.as_raw_fd())?;
    reopen_fd(tmpfd.as_raw_fd(), libc::O_RDONLY | libc::O_CLOEXEC)
}

#[cfg(target_os = "linux")]
fn create_copy_memfd() -> io::Result<OwnedFd> {
    create_linux_memfd("data-fd", MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL)
}

#[cfg(not(target_os = "linux"))]
fn create_copy_memfd() -> io::Result<OwnedFd> {
    open_anonymous_tmpfile(Path::new("/tmp"))
}

#[cfg(target_os = "linux")]
fn create_named_memfd(name: &str, read_only: bool, executable: bool) -> io::Result<OwnedFd> {
    let mut flags = 0;

    if read_only {
        flags |= MFD_CLOEXEC | MFD_ALLOW_SEALING;
    }
    if executable {
        flags |= MFD_EXEC;
    } else {
        flags |= MFD_NOEXEC_SEAL;
    }

    create_linux_memfd(name, flags)
}

#[cfg(not(target_os = "linux"))]
fn create_named_memfd(_name: &str, _read_only: bool, _executable: bool) -> io::Result<OwnedFd> {
    open_anonymous_tmpfile(Path::new("/tmp"))
}

#[cfg(target_os = "linux")]
fn create_linux_memfd(name: &str, flags: u32) -> io::Result<OwnedFd> {
    let c_name = CString::new(name).map_err(|_| invalid_input_error())?;
    // SAFETY: c_name is NUL-terminated and remains alive for the syscall, which
    // reads but does not retain its pointer; the remaining arguments are scalars.
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, c_name.as_ptr(), flags) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: successful memfd_create returns a fresh descriptor whose
        // ownership has not been transferred elsewhere.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }
}

fn open_anonymous_tmpfile(dir: &Path) -> io::Result<OwnedFd> {
    for _ in 0..TMPFILE_ATTEMPTS {
        let path = unique_temp_path(dir);
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => {
                fs::remove_file(&path)?;
                return Ok(file.into());
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to create unique temporary file",
    ))
}

fn unique_temp_path(dir: &Path) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = TMPFILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!(
        ".data-fd-util-{}-{nonce}-{counter}",
        std::process::id()
    ))
}

fn reopen_fd(fd: RawFd, flags: i32) -> io::Result<OwnedFd> {
    let mut last_error = None;

    for candidate in [format!("/proc/self/fd/{fd}"), format!("/dev/fd/{fd}")] {
        let c_candidate = CString::new(candidate).map_err(|_| invalid_input_error())?;
        // SAFETY: c_candidate is a live NUL-terminated path for the duration of
        // open, which does not retain the pointer; flags contains no pointers.
        let reopened = unsafe { libc::open(c_candidate.as_ptr(), flags) };
        if reopened >= 0 {
            // SAFETY: successful open returns a fresh descriptor whose ownership
            // is transferred exactly once to this OwnedFd.
            return Ok(unsafe { OwnedFd::from_raw_fd(reopened) });
        }
        last_error = Some(io::Error::last_os_error());
    }

    Err(last_error.unwrap_or_else(|| io::Error::from_raw_os_error(libc::EBADF)))
}

fn set_cloexec(fd: RawFd, enabled: bool) -> io::Result<()> {
    // SAFETY: F_GETFD takes only a borrowed descriptor; invalid descriptors are
    // reported by the kernel and do not violate Rust memory safety.
    let current = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if current < 0 {
        return Err(io::Error::last_os_error());
    }

    let desired = if enabled {
        current | libc::FD_CLOEXEC
    } else {
        current & !libc::FD_CLOEXEC
    };

    if desired != current {
        // SAFETY: F_SETFD takes only the borrowed descriptor and scalar flags,
        // and does not alter or assume ownership of the descriptor.
        let r = unsafe { libc::fcntl(fd, libc::F_SETFD, desired) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn seal_for_read_only(fd: &OwnedFd) -> io::Result<()> {
    let seals = F_SEAL_SEAL_CONST | F_SEAL_SHRINK_CONST | F_SEAL_GROW_CONST | F_SEAL_WRITE_CONST;
    // SAFETY: F_ADD_SEALS takes the live borrowed descriptor and scalar seal
    // mask only; it neither retains nor assumes ownership of the descriptor.
    let r = unsafe { libc::fcntl(fd.as_raw_fd(), F_ADD_SEALS_CONST, seals) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
fn seal_for_read_only(_fd: &OwnedFd) -> io::Result<()> {
    Err(io::Error::from_raw_os_error(libc::ENOTSUP))
}

fn var_tmp_dir() -> PathBuf {
    let var_tmp = PathBuf::from("/var/tmp");
    if var_tmp.is_dir() {
        var_tmp
    } else {
        PathBuf::from("/tmp")
    }
}

fn invalid_input_error() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::net::UnixStream;
    use tempfile::{NamedTempFile, TempDir};

    fn make_temp_file_with_len(len: usize) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        file.write_all(&data).unwrap();
        file.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
        file
    }

    fn read_fd_all(fd: &OwnedFd) -> Vec<u8> {
        let dup = dup_fd(fd.as_raw_fd()).unwrap();
        let mut file = File::from(dup);
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();
        data
    }

    fn fd_flags(fd: &OwnedFd) -> i32 {
        // SAFETY: fd is a live borrowed descriptor and F_GETFD has no pointer
        // arguments or ownership effects.
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) }
    }

    fn assert_not_writable(fd: &OwnedFd) {
        let dup = dup_fd(fd.as_raw_fd()).unwrap();
        let byte = [0x7f_u8];
        // SAFETY: byte is readable for byte.len() bytes, dup keeps the descriptor
        // alive, and write does not retain the pointer.
        let r = unsafe { libc::write(dup.as_raw_fd(), byte.as_ptr().cast(), byte.len()) };
        assert_eq!(r, -1);
        let err = io::Error::last_os_error();
        assert!(matches!(
            err.raw_os_error(),
            Some(libc::EBADF | libc::EPERM)
        ));
    }

    #[test]
    fn copy_data_fd_rejects_invalid_fd() {
        let err = copy_data_fd(-1).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    fn copy_data_fd_rejects_directories() {
        let dir = TempDir::new().unwrap();
        let file = File::open(dir.path()).unwrap();
        let err = copy_data_fd(file.as_raw_fd()).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EISDIR));
    }

    #[test]
    fn copy_data_fd_copies_small_regular_files() {
        let file = make_temp_file_with_len(4096);
        let copied = copy_data_fd(file.as_file().as_raw_fd()).unwrap();
        assert_eq!(
            read_fd_all(&copied),
            read_fd_all(&dup_fd(file.as_file().as_raw_fd()).unwrap())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn copy_data_fd_small_result_is_not_writable() {
        let file = make_temp_file_with_len(1024);
        let copied = copy_data_fd(file.as_file().as_raw_fd()).unwrap();
        assert_not_writable(&copied);
    }

    #[test]
    fn copy_data_fd_handles_exact_memory_limit() {
        let file = make_temp_file_with_len(DATA_FD_MEMORY_LIMIT as usize);
        let copied = copy_data_fd(file.as_file().as_raw_fd()).unwrap();
        assert_eq!(read_fd_all(&copied).len(), DATA_FD_MEMORY_LIMIT as usize);
    }

    #[test]
    fn copy_data_fd_copies_medium_regular_files() {
        let len = (DATA_FD_MEMORY_LIMIT + 4096) as usize;
        let file = make_temp_file_with_len(len);
        let copied = copy_data_fd(file.as_file().as_raw_fd()).unwrap();
        assert_eq!(
            read_fd_all(&copied),
            read_fd_all(&dup_fd(file.as_file().as_raw_fd()).unwrap())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn copy_data_fd_medium_result_is_read_only() {
        let len = (DATA_FD_MEMORY_LIMIT + 11) as usize;
        let file = make_temp_file_with_len(len);
        let copied = copy_data_fd(file.as_file().as_raw_fd()).unwrap();
        assert_not_writable(&copied);
    }

    #[test]
    fn copy_data_fd_copies_large_regular_files() {
        let len = (DATA_FD_TMP_LIMIT + 8192) as usize;
        let file = make_temp_file_with_len(len);
        let copied = copy_data_fd(file.as_file().as_raw_fd()).unwrap();
        assert_eq!(read_fd_all(&copied).len(), len);
        assert_eq!(
            read_fd_all(&copied)[..128],
            read_fd_all(&dup_fd(file.as_file().as_raw_fd()).unwrap())[..128]
        );
    }

    #[test]
    fn copy_data_fd_copies_pipes() {
        let mut pipefds = [-1; 2];
        // SAFETY: pipefds is aligned writable storage for exactly two RawFd
        // values and pipe does not retain the pointer.
        assert_eq!(unsafe { libc::pipe(pipefds.as_mut_ptr()) }, 0);
        // SAFETY: successful pipe initialized pipefds[0] as a fresh read-end,
        // and ownership is transferred exactly once to reader.
        let reader = unsafe { OwnedFd::from_raw_fd(pipefds[0]) };
        // SAFETY: successful pipe initialized pipefds[1] as a fresh write-end,
        // and ownership is transferred exactly once to writer.
        let mut writer = unsafe { File::from_raw_fd(pipefds[1]) };
        let payload = b"pipe payload".repeat(512);
        writer.write_all(&payload).unwrap();
        drop(writer);
        let copied = copy_data_fd(reader.as_raw_fd()).unwrap();
        assert_eq!(read_fd_all(&copied), payload);
    }

    #[test]
    fn copy_data_fd_copies_sockets() {
        let (mut left, mut right) = UnixStream::pair().unwrap();
        let payload = b"socket payload".repeat(300);
        right.write_all(&payload).unwrap();
        right.shutdown(std::net::Shutdown::Write).unwrap();
        let copied = copy_data_fd(left.as_raw_fd()).unwrap();
        assert_eq!(read_fd_all(&copied), payload);
    }

    #[test]
    fn copy_data_fd_advances_source_offset_to_end() {
        let mut file = make_temp_file_with_len(7000);
        let original_len = file.as_file().metadata().unwrap().len() as i64;
        let _ = copy_data_fd(file.as_file().as_raw_fd()).unwrap();
        // SAFETY: the temporary file keeps this borrowed descriptor live, and
        // lseek takes only scalar arguments with no ownership effects.
        let pos = unsafe { libc::lseek(file.as_file().as_raw_fd(), 0, libc::SEEK_CUR) };
        assert_eq!(pos, original_len);
    }

    #[test]
    fn memfd_clone_fd_rejects_invalid_mode_bits() {
        let file = make_temp_file_with_len(10);
        let err = memfd_clone_fd(
            file.as_file().as_raw_fd(),
            "clone",
            libc::O_RDONLY | libc::O_APPEND,
        )
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memfd_clone_fd_copies_read_only() {
        let file = make_temp_file_with_len(12345);
        let cloned = memfd_clone_fd(file.as_file().as_raw_fd(), "clone", libc::O_RDONLY).unwrap();
        assert_eq!(
            read_fd_all(&cloned),
            read_fd_all(&dup_fd(file.as_file().as_raw_fd()).unwrap())
        );
        assert_not_writable(&cloned);
    }

    #[test]
    fn memfd_clone_fd_copies_read_write() {
        let file = make_temp_file_with_len(512);
        let cloned = memfd_clone_fd(file.as_file().as_raw_fd(), "clone", libc::O_RDWR).unwrap();
        let mut reopened = File::from(dup_fd(cloned.as_raw_fd()).unwrap());
        reopened.seek(SeekFrom::Start(0)).unwrap();
        reopened.write_all(b"xy").unwrap();
        reopened.seek(SeekFrom::Start(0)).unwrap();
        let mut prefix = [0u8; 2];
        reopened.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, b"xy");
    }

    #[test]
    fn memfd_clone_fd_honors_cloexec() {
        let file = make_temp_file_with_len(32);
        let cloned = memfd_clone_fd(
            file.as_file().as_raw_fd(),
            "clone",
            libc::O_RDWR | libc::O_CLOEXEC,
        )
        .unwrap();
        assert_ne!(fd_flags(&cloned) & libc::FD_CLOEXEC, 0);
    }
}
