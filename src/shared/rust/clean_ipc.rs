// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/clean-ipc.c, src/shared/clean-ipc.h
//
// IPC resource cleanup: removes System V and POSIX IPC objects
// (shared memory segments, message queues, semaphores) owned by
// a given UID or GID.

use std::ffi::{CString, OsStr};
use std::fs::{self, File, OpenOptions, ReadDir};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const UID_INVALID: libc::uid_t = u32::MAX;
const GID_INVALID: libc::gid_t = u32::MAX;

// ── Types ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcStatus {
    NotFound = 0,
    Found = 1,
}

// ── /proc/sysvipc parsers ─────────────────────────────────────────────────

struct SysvShmEntry {
    shmid: i32,
    nattch: u32,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

struct SysvSemEntry {
    semid: i32,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

struct SysvMsgEntry {
    msgid: i32,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

fn parse_sysvipc_shm_line(line: &str) -> Option<SysvShmEntry> {
    let p: Vec<&str> = line.split_whitespace().collect();
    if p.len() < 11 {
        return None;
    }
    Some(SysvShmEntry {
        shmid: p[1].parse().ok()?,
        nattch: p[6].parse().ok()?,
        uid: p[7].parse().ok()?,
        gid: p[8].parse().ok()?,
    })
}

fn parse_sysvipc_sem_line(line: &str) -> Option<SysvSemEntry> {
    let p: Vec<&str> = line.split_whitespace().collect();
    if p.len() < 9 {
        return None;
    }
    Some(SysvSemEntry {
        semid: p[1].parse().ok()?,
        uid: p[4].parse().ok()?,
        gid: p[5].parse().ok()?,
    })
}

fn parse_sysvipc_msg_line(line: &str) -> Option<SysvMsgEntry> {
    let p: Vec<&str> = line.split_whitespace().collect();
    if p.len() < 11 {
        return None;
    }
    Some(SysvMsgEntry {
        msgid: p[1].parse().ok()?,
        uid: p[7].parse().ok()?,
        gid: p[8].parse().ok()?,
    })
}

// ── UID/GID matching ──────────────────────────────────────────────────────

fn match_uid_gid(
    subject_uid: libc::uid_t,
    subject_gid: libc::gid_t,
    delete_uid: Option<libc::uid_t>,
    delete_gid: Option<libc::gid_t>,
) -> bool {
    delete_uid.is_some_and(|u| subject_uid == u) || delete_gid.is_some_and(|g| subject_gid == g)
}

fn effective_uid(uid: libc::uid_t) -> Option<libc::uid_t> {
    match uid {
        0 | UID_INVALID => None,
        u => Some(u),
    }
}

fn effective_gid(gid: libc::gid_t) -> Option<libc::gid_t> {
    match gid {
        0 | GID_INVALID => None,
        g => Some(g),
    }
}

// ── SysV IPC removal ─────────────────────────────────────────────────────

fn shm_remove(shmid: i32) -> io::Result<bool> {
    // SAFETY: shmctl(IPC_RMID, NULL) marks the segment for deletion.
    // shmid is parsed from /proc/sysvipc/shm.
    let ret = unsafe { libc::shmctl(shmid, libc::IPC_RMID, std::ptr::null_mut()) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        let code = err.raw_os_error().unwrap_or(0);
        if code == libc::EIDRM || code == libc::EINVAL {
            return Ok(false);
        }
        Err(err)
    } else {
        Ok(true)
    }
}

fn sem_remove(semid: i32) -> io::Result<bool> {
    // SAFETY: semctl(IPC_RMID) removes the semaphore set.
    // semid is parsed from /proc/sysvipc/sem.
    let ret = unsafe { libc::semctl(semid, 0, libc::IPC_RMID) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        let code = err.raw_os_error().unwrap_or(0);
        if code == libc::EIDRM || code == libc::EINVAL {
            return Ok(false);
        }
        Err(err)
    } else {
        Ok(true)
    }
}

#[cfg(target_os = "linux")]
fn msg_remove(msgid: i32) -> io::Result<bool> {
    // SAFETY: msgctl(IPC_RMID, NULL) removes the message queue.
    // msgid is parsed from /proc/sysvipc/msg.
    let ret = unsafe { libc::msgctl(msgid, libc::IPC_RMID, std::ptr::null_mut()) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        let code = err.raw_os_error().unwrap_or(0);
        if code == libc::EIDRM || code == libc::EINVAL {
            return Ok(false);
        }
        Err(err)
    } else {
        Ok(true)
    }
}

// ── POSIX MQ removal ─────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn mq_unlink_named(name: &OsStr) -> io::Result<()> {
    let mut bytes = Vec::with_capacity(name.as_bytes().len() + 1);
    bytes.push(b'/');
    bytes.extend_from_slice(name.as_bytes());
    let c_name = CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "NUL in queue name"))?;
    // SAFETY: mq_unlink removes a POSIX message queue by name.
    // name is prefixed with '/' per POSIX requirements.
    let ret = unsafe { libc::mq_unlink(c_name.as_ptr()) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn remember_error(last_error: &mut Option<io::Error>, error: io::Error) {
    *last_error = Some(error);
}

fn finish_cleanup(found: bool, last_error: Option<io::Error>) -> io::Result<IpcStatus> {
    match last_error {
        Some(error) => Err(error),
        None if found => Ok(IpcStatus::Found),
        None => Ok(IpcStatus::NotFound),
    }
}

// ── /proc/sysvipc reader ─────────────────────────────────────────────────

fn read_proc_sysvipc(path: &str) -> io::Result<String> {
    match fs::read_to_string(path) {
        Ok(c) => Ok(c),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(String::new()),
        Err(e) => Err(e),
    }
}

// ── SysV IPC cleaners ────────────────────────────────────────────────────

fn clean_sysvipc_shm(
    delete_uid: Option<libc::uid_t>,
    delete_gid: Option<libc::gid_t>,
    remove: bool,
) -> io::Result<IpcStatus> {
    let content = read_proc_sysvipc("/proc/sysvipc/shm")?;
    if content.is_empty() {
        return Ok(IpcStatus::NotFound);
    }

    let mut found = false;
    let mut last_error = None;
    for line in content.lines().skip(1) {
        let entry = match parse_sysvipc_shm_line(line) {
            Some(e) => e,
            None => continue,
        };
        if entry.nattch > 0 {
            continue;
        }
        if !match_uid_gid(entry.uid, entry.gid, delete_uid, delete_gid) {
            continue;
        }
        if !remove {
            return Ok(IpcStatus::Found);
        }
        match shm_remove(entry.shmid) {
            Ok(removed) => found |= removed,
            Err(e) => {
                eprintln!(
                    "Failed to remove SysV shared memory segment {}: {}",
                    entry.shmid, e
                );
                remember_error(&mut last_error, e);
            }
        }
    }

    finish_cleanup(found, last_error)
}

fn clean_sysvipc_sem(
    delete_uid: Option<libc::uid_t>,
    delete_gid: Option<libc::gid_t>,
    remove: bool,
) -> io::Result<IpcStatus> {
    let content = read_proc_sysvipc("/proc/sysvipc/sem")?;
    if content.is_empty() {
        return Ok(IpcStatus::NotFound);
    }

    let mut found = false;
    let mut last_error = None;
    for line in content.lines().skip(1) {
        let entry = match parse_sysvipc_sem_line(line) {
            Some(e) => e,
            None => continue,
        };
        if !match_uid_gid(entry.uid, entry.gid, delete_uid, delete_gid) {
            continue;
        }
        if !remove {
            return Ok(IpcStatus::Found);
        }
        match sem_remove(entry.semid) {
            Ok(removed) => found |= removed,
            Err(e) => {
                eprintln!("Failed to remove SysV semaphore {}: {}", entry.semid, e);
                remember_error(&mut last_error, e);
            }
        }
    }

    finish_cleanup(found, last_error)
}

#[cfg(target_os = "linux")]
fn clean_sysvipc_msg(
    delete_uid: Option<libc::uid_t>,
    delete_gid: Option<libc::gid_t>,
    remove: bool,
) -> io::Result<IpcStatus> {
    let content = read_proc_sysvipc("/proc/sysvipc/msg")?;
    if content.is_empty() {
        return Ok(IpcStatus::NotFound);
    }

    let mut found = false;
    let mut last_error = None;
    for line in content.lines().skip(1) {
        let entry = match parse_sysvipc_msg_line(line) {
            Some(e) => e,
            None => continue,
        };
        if !match_uid_gid(entry.uid, entry.gid, delete_uid, delete_gid) {
            continue;
        }
        if !remove {
            return Ok(IpcStatus::Found);
        }
        match msg_remove(entry.msgid) {
            Ok(removed) => found |= removed,
            Err(e) => {
                eprintln!("Failed to remove SysV message queue {}: {}", entry.msgid, e);
                remember_error(&mut last_error, e);
            }
        }
    }

    finish_cleanup(found, last_error)
}

// ── POSIX shared memory cleaner ──────────────────────────────────────────

fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
}

fn openat_directory(parent_fd: RawFd, name: &OsStr) -> io::Result<OwnedFd> {
    let c_name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "NUL in directory name"))?;

    // SAFETY: c_name is a valid NUL-terminated pathname, parent_fd remains
    // open for the call, and a successful descriptor is immediately owned.
    let fd = unsafe {
        libc::openat(
            parent_fd,
            c_name.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_NOATIME
                | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: fd was just returned by openat and ownership is transferred
        // exactly once to OwnedFd.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn read_dir_fd(fd: RawFd) -> io::Result<ReadDir> {
    // Rust's standard library has no safe fdopendir/readdir interface. The
    // procfs magic link reopens this pinned descriptor for iteration; all
    // security-sensitive stat/open/remove operations below remain *at()-based.
    // P2: replace this /proc dependency if a small safe directory-stream
    // abstraction is introduced for the Rust port.
    fs::read_dir(format!("/proc/self/fd/{fd}"))
}

fn fstatat_nofollow(parent_fd: RawFd, name: &OsStr) -> io::Result<libc::stat> {
    let c_name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "NUL in directory entry"))?;
    let mut stat = MaybeUninit::<libc::stat>::uninit();

    // SAFETY: parent_fd remains open, c_name is NUL-terminated, and stat
    // points to writable storage. AT_SYMLINK_NOFOLLOW matches the C cleanup
    // code and prevents ownership checks from following an attacker symlink.
    if unsafe {
        libc::fstatat(
            parent_fd,
            c_name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } < 0
    {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: fstatat returned success and initialized the structure.
        Ok(unsafe { stat.assume_init() })
    }
}

fn unlinkat_entry(parent_fd: RawFd, name: &OsStr, directory: bool) -> io::Result<()> {
    let c_name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "NUL in directory entry"))?;
    let flags = if directory { libc::AT_REMOVEDIR } else { 0 };

    // SAFETY: parent_fd remains open and c_name is a valid NUL-terminated
    // pathname. The flags select file or empty-directory removal.
    if unsafe { libc::unlinkat(parent_fd, c_name.as_ptr(), flags) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn clean_posix_shm_dir(
    dir: &File,
    display_path: &Path,
    delete_uid: Option<libc::uid_t>,
    delete_gid: Option<libc::gid_t>,
    remove: bool,
) -> io::Result<IpcStatus> {
    let entries = read_dir_fd(dir.as_raw_fd())?;

    let mut found = false;
    let mut last_error = None;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => return Err(e),
        };

        let name = entry.file_name();
        if name.as_bytes() == b"." || name.as_bytes() == b".." {
            continue;
        }
        let entry_path = display_path.join(&name);

        let stat = match fstatat_nofollow(dir.as_raw_fd(), &name) {
            Ok(stat) => stat,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(e) => {
                eprintln!("Failed to stat POSIX shm {}: {}", entry_path.display(), e);
                remember_error(&mut last_error, e);
                continue;
            }
        };

        let is_dir = stat.st_mode & libc::S_IFMT == libc::S_IFDIR;

        if is_dir {
            match openat_directory(dir.as_raw_fd(), &name) {
                Ok(child_fd) => {
                    let child = File::from(child_fd);
                    match clean_posix_shm_dir(&child, &entry_path, delete_uid, delete_gid, remove) {
                        Ok(IpcStatus::Found) if !remove => return Ok(IpcStatus::Found),
                        Ok(IpcStatus::Found) => {}
                        Err(error) => remember_error(&mut last_error, error),
                        Ok(IpcStatus::NotFound) => {}
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
                Err(e) => {
                    eprintln!(
                        "Failed to enter POSIX shm directory {}: {}",
                        entry_path.display(),
                        e
                    );
                    remember_error(&mut last_error, e);
                }
            }
        }

        if !match_uid_gid(stat.st_uid, stat.st_gid, delete_uid, delete_gid) {
            continue;
        }

        if !remove {
            return Ok(IpcStatus::Found);
        }

        match unlinkat_entry(dir.as_raw_fd(), &name, is_dir) {
            Ok(()) => found = true,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
            Err(e) => {
                eprintln!("Failed to remove POSIX shm {}: {}", entry_path.display(), e);
                remember_error(&mut last_error, e);
            }
        }
    }

    finish_cleanup(found, last_error)
}

fn clean_posix_shm(
    delete_uid: Option<libc::uid_t>,
    delete_gid: Option<libc::gid_t>,
    remove: bool,
) -> io::Result<IpcStatus> {
    let path = Path::new("/dev/shm");
    let dir = match open_directory(path) {
        Ok(dir) => dir,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(IpcStatus::NotFound),
        Err(e) => return Err(e),
    };
    clean_posix_shm_dir(&dir, path, delete_uid, delete_gid, remove)
}

// ── POSIX message queue cleaner ──────────────────────────────────────────

#[cfg(target_os = "linux")]
fn clean_posix_mq(
    delete_uid: Option<libc::uid_t>,
    delete_gid: Option<libc::gid_t>,
    remove: bool,
) -> io::Result<IpcStatus> {
    let dir = match open_directory(Path::new("/dev/mqueue")) {
        Ok(dir) => dir,
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => return Ok(IpcStatus::NotFound),
        Err(e) => return Err(e),
    };
    let entries = read_dir_fd(dir.as_raw_fd())?;

    let mut found = false;
    let mut last_error = None;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => return Err(e),
        };

        let name = entry.file_name();
        if name.as_bytes() == b"." || name.as_bytes() == b".." {
            continue;
        }

        let stat = match fstatat_nofollow(dir.as_raw_fd(), &name) {
            Ok(stat) => stat,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(e) => {
                eprintln!("Failed to stat MQ {}: {}", name.to_string_lossy(), e);
                remember_error(&mut last_error, e);
                continue;
            }
        };

        if !match_uid_gid(stat.st_uid, stat.st_gid, delete_uid, delete_gid) {
            continue;
        }

        if !remove {
            return Ok(IpcStatus::Found);
        }

        match mq_unlink_named(&name) {
            Ok(()) => found = true,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
            Err(e) => {
                eprintln!(
                    "Failed to unlink POSIX message queue /{}: {}",
                    name.to_string_lossy(),
                    e
                );
                remember_error(&mut last_error, e);
            }
        }
    }

    finish_cleanup(found, last_error)
}

// ── Public API ────────────────────────────────────────────────────────────

fn clean_ipc_core(uid: libc::uid_t, gid: libc::gid_t, remove: bool) -> io::Result<IpcStatus> {
    if uid == 0 || gid == 0 {
        if !remove {
            return Ok(IpcStatus::Found);
        }
    }

    let delete_uid = effective_uid(uid);
    let delete_gid = effective_gid(gid);

    if delete_uid.is_none() && delete_gid.is_none() {
        return Ok(IpcStatus::NotFound);
    }

    #[cfg(target_os = "linux")]
    {
        let cleaners: &[fn(
            Option<libc::uid_t>,
            Option<libc::gid_t>,
            bool,
        ) -> io::Result<IpcStatus>] = &[
            clean_sysvipc_shm,
            clean_sysvipc_sem,
            clean_sysvipc_msg,
            clean_posix_shm,
            clean_posix_mq,
        ];

        let mut first_outcome = None;
        for cleaner in cleaners {
            match cleaner(delete_uid, delete_gid, remove) {
                Ok(IpcStatus::Found) if !remove => return Ok(IpcStatus::Found),
                Err(e) if !remove => return Err(e),
                Ok(IpcStatus::Found) => {
                    first_outcome.get_or_insert(Ok(IpcStatus::Found));
                }
                Err(e) => {
                    first_outcome.get_or_insert(Err(e));
                }
                Ok(IpcStatus::NotFound) => {}
            }
        }

        return first_outcome.unwrap_or(Ok(IpcStatus::NotFound));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let cleaners: &[fn(
            Option<libc::uid_t>,
            Option<libc::gid_t>,
            bool,
        ) -> io::Result<IpcStatus>] = &[clean_sysvipc_shm, clean_sysvipc_sem, clean_posix_shm];

        let mut first_outcome = None;
        for cleaner in cleaners {
            match cleaner(delete_uid, delete_gid, remove) {
                Ok(IpcStatus::Found) if !remove => return Ok(IpcStatus::Found),
                Err(e) if !remove => return Err(e),
                Ok(IpcStatus::Found) => {
                    first_outcome.get_or_insert(Ok(IpcStatus::Found));
                }
                Err(e) => {
                    first_outcome.get_or_insert(Err(e));
                }
                Ok(IpcStatus::NotFound) => {}
            }
        }

        first_outcome.unwrap_or(Ok(IpcStatus::NotFound))
    }
}

/// Remove all IPC objects owned by the given UID.
pub fn clean_ipc_by_uid(uid: libc::uid_t) -> io::Result<IpcStatus> {
    clean_ipc_core(uid, GID_INVALID, true)
}

/// Remove all IPC objects owned by the given GID.
pub fn clean_ipc_by_gid(gid: libc::gid_t) -> io::Result<IpcStatus> {
    clean_ipc_core(UID_INVALID, gid, true)
}

/// Remove (or search for) IPC objects owned by the given UID or GID.
pub fn clean_ipc_internal(
    uid: libc::uid_t,
    gid: libc::gid_t,
    remove: bool,
) -> io::Result<IpcStatus> {
    clean_ipc_core(uid, gid, remove)
}

/// Search for IPC objects owned by the given UID or GID without removing them.
pub fn search_ipc(uid: libc::uid_t, gid: libc::gid_t) -> io::Result<IpcStatus> {
    clean_ipc_core(uid, gid, false)
}

// ── Test helper ───────────────────────────────────────────────────────────

#[cfg(test)]
fn parse_proc_content(
    content: &str,
    delete_uid: Option<libc::uid_t>,
    delete_gid: Option<libc::gid_t>,
    remove: bool,
    skip_attached: bool,
) -> io::Result<IpcStatus> {
    if content.is_empty() {
        return Ok(IpcStatus::NotFound);
    }

    let mut found = false;
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        let uid: libc::uid_t = match parts[7].parse() {
            Ok(u) => u,
            Err(_) => continue,
        };
        let gid: libc::gid_t = match parts[8].parse() {
            Ok(g) => g,
            Err(_) => continue,
        };

        if skip_attached {
            let nattch: u32 = parts[6].parse().unwrap_or(1);
            if nattch > 0 {
                continue;
            }
        }

        if !match_uid_gid(uid, gid, delete_uid, delete_gid) {
            continue;
        }

        if !remove {
            return Ok(IpcStatus::Found);
        }
        found = true;
    }

    Ok(if found {
        IpcStatus::Found
    } else {
        IpcStatus::NotFound
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SHM_HEADER: &str = "       key      shmid perms          size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime";

    const SHM_SAMPLE: &str = "       key      shmid perms          size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime
0x00000000 32768 0600        524288  1234     0      0  1000  1000  1000  1000 1700000000 1700000000 1700000000
0x00000001 65536 0666        1048576  5678  9012      2  2000  2000  2000  2000 1700000000 1700000000 1700000000
0x00000002 98304 0644         262144  1111     0      0  1000  1000  1000  1000 1700000000 1700000000 1700000000
";

    const SEM_HEADER: &str =
        "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime";

    const SEM_SAMPLE: &str =
        "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime
0x00000000     0 0600         4  1000  1000  1000  1000 1700000000 1700000000
0x00000001 65536 0666         2  2000  2000  2000  2000 1700000000 1700000000
";

    const MSG_HEADER: &str = "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime";

    const MSG_SAMPLE: &str = "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime
0x00000000     0 0644        0             0     0     0  1000  1000  1000  1000 1700000000 1700000000 1700000000
0x00000001 65536 0644       128             3  1234  5678  2000  2000  2000  2000 1700000000 1700000000 1700000000
";

    #[test]
    fn test_match_uid_gid_uid_only() {
        assert!(match_uid_gid(1000, 100, Some(1000), None));
        assert!(!match_uid_gid(1000, 100, Some(999), None));
    }

    #[test]
    fn test_match_uid_gid_gid_only() {
        assert!(match_uid_gid(1000, 500, None, Some(500)));
        assert!(!match_uid_gid(1000, 500, None, Some(499)));
    }

    #[test]
    fn test_match_uid_gid_both() {
        assert!(match_uid_gid(1000, 500, Some(1000), Some(500)));
        assert!(match_uid_gid(1000, 500, Some(999), Some(500)));
        assert!(match_uid_gid(1000, 500, Some(1000), Some(499)));
    }

    #[test]
    fn test_match_uid_gid_none() {
        assert!(!match_uid_gid(1000, 500, None, None));
    }

    #[test]
    fn test_match_uid_gid_zero() {
        assert!(match_uid_gid(0, 1000, Some(0), None));
        assert!(match_uid_gid(1000, 0, None, Some(0)));
    }

    #[test]
    fn test_match_uid_gid_max() {
        assert!(match_uid_gid(UID_INVALID, 0, Some(UID_INVALID), None));
        assert!(match_uid_gid(0, GID_INVALID, None, Some(GID_INVALID)));
    }

    #[test]
    fn test_parse_sysvipc_shm_line_valid() {
        let line = "0x00000000 32768 0600 524288 1234 0 0 1000 1000 1000 1000 1700000000 1700000000 1700000000";
        let entry = parse_sysvipc_shm_line(line).unwrap();
        assert_eq!(entry.shmid, 32768);
        assert_eq!(entry.nattch, 0);
        assert_eq!(entry.uid, 1000);
        assert_eq!(entry.gid, 1000);
    }

    #[test]
    fn test_parse_sysvipc_shm_line_too_short() {
        let line = "0x00000000 32768 0600";
        assert!(parse_sysvipc_shm_line(line).is_none());
    }

    #[test]
    fn test_parse_sysvipc_shm_line_bad_number() {
        let line = "0x00000000 notanumber 0600 524288 1234 0 0 1000 1000 1000 1000";
        assert!(parse_sysvipc_shm_line(line).is_none());
    }

    #[test]
    fn test_parse_sysvipc_sem_line_valid() {
        let line = "0x00000000 0 0600 4 1000 1000 1000 1000 1700000000 1700000000";
        let entry = parse_sysvipc_sem_line(line).unwrap();
        assert_eq!(entry.semid, 0);
        assert_eq!(entry.uid, 1000);
        assert_eq!(entry.gid, 1000);
    }

    #[test]
    fn test_parse_sysvipc_sem_line_too_short() {
        let line = "0x00000000 0 0600 4 1000";
        assert!(parse_sysvipc_sem_line(line).is_none());
    }

    #[test]
    fn test_parse_sysvipc_msg_line_valid() {
        let line = "0x00000000 0 0644 0 0 0 0 1000 1001 1002 1003 1700000000 1700000000 1700000000";
        let entry = parse_sysvipc_msg_line(line).unwrap();
        assert_eq!(entry.msgid, 0);
        assert_eq!(entry.uid, 1000);
        assert_eq!(entry.gid, 1001);
    }

    #[test]
    fn test_parse_sysvipc_msg_line_too_short() {
        let line = "0x00000000 0 0644 0 0 1000 1000";
        assert!(parse_sysvipc_msg_line(line).is_none());
    }

    #[test]
    fn test_parse_content_empty() {
        let result = parse_proc_content("", Some(1000), None, false, false).unwrap();
        assert_eq!(result, IpcStatus::NotFound);
    }

    #[test]
    fn test_parse_content_header_only() {
        let result = parse_proc_content(SHM_HEADER, Some(1000), None, false, false).unwrap();
        assert_eq!(result, IpcStatus::NotFound);
    }

    #[test]
    fn test_parse_content_found_by_uid() {
        let result = parse_proc_content(SHM_SAMPLE, Some(1000), None, false, false).unwrap();
        assert_eq!(result, IpcStatus::Found);
    }

    #[test]
    fn test_parse_content_not_found_by_uid() {
        let result = parse_proc_content(SHM_SAMPLE, Some(9999), None, false, false).unwrap();
        assert_eq!(result, IpcStatus::NotFound);
    }

    #[test]
    fn test_parse_content_skip_attached() {
        let result = parse_proc_content(SHM_SAMPLE, Some(1000), None, false, true).unwrap();
        assert_eq!(result, IpcStatus::Found);

        let result = parse_proc_content(SHM_SAMPLE, Some(2000), None, false, true).unwrap();
        assert_eq!(result, IpcStatus::NotFound);

        let result = parse_proc_content(SHM_SAMPLE, Some(2000), None, false, false).unwrap();
        assert_eq!(result, IpcStatus::Found);
    }

    #[test]
    fn test_parse_content_found_by_gid() {
        let result = parse_proc_content(SHM_SAMPLE, None, Some(2000), false, false).unwrap();
        assert_eq!(result, IpcStatus::Found);
    }

    #[test]
    fn test_ipc_status_values() {
        assert_eq!(IpcStatus::NotFound as i32, 0);
        assert_eq!(IpcStatus::Found as i32, 1);
    }

    #[test]
    fn test_effective_uid_root() {
        assert_eq!(effective_uid(0), None);
    }

    #[test]
    fn test_effective_uid_invalid() {
        assert_eq!(effective_uid(UID_INVALID), None);
    }

    #[test]
    fn test_effective_uid_valid() {
        assert_eq!(effective_uid(1000), Some(1000));
    }

    #[test]
    fn test_parse_shm_multiple_entries() {
        let result = parse_proc_content(SHM_SAMPLE, Some(1000), None, false, false).unwrap();
        assert_eq!(result, IpcStatus::Found);
    }

    #[test]
    fn test_parse_sem_found_by_uid() {
        let result = parse_proc_content(SEM_SAMPLE, Some(1000), None, false, false).unwrap();
        assert_eq!(result, IpcStatus::Found);
    }

    #[test]
    fn test_parse_sem_not_found() {
        let result = parse_proc_content(SEM_SAMPLE, Some(9999), None, false, false).unwrap();
        assert_eq!(result, IpcStatus::NotFound);
    }

    #[test]
    fn test_parse_msg_found_by_uid() {
        let result = parse_proc_content(MSG_SAMPLE, Some(1000), None, false, false).unwrap();
        assert_eq!(result, IpcStatus::Found);
    }

    #[test]
    fn test_parse_msg_found_by_gid() {
        let result = parse_proc_content(MSG_SAMPLE, None, Some(2000), false, false).unwrap();
        assert_eq!(result, IpcStatus::Found);
    }

    #[test]
    fn test_clean_ipc_root_search() {
        let result = clean_ipc_core(0, GID_INVALID, false).unwrap();
        assert_eq!(result, IpcStatus::Found);
    }

    #[test]
    fn test_clean_ipc_root_by_gid_search() {
        let result = clean_ipc_core(UID_INVALID, 0, false).unwrap();
        assert_eq!(result, IpcStatus::Found);
    }

    #[test]
    fn test_clean_ipc_no_criteria() {
        let result = clean_ipc_core(UID_INVALID, GID_INVALID, true).unwrap();
        assert_eq!(result, IpcStatus::NotFound);
    }
}
