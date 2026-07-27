// SPDX-License-Identifier: LGPL-2.1-or-later

//! Audited Linux process-identity and clone ABI for service launch.
//!
//! The caller prepares all launch storage before entering this adapter. Raw
//! clone3 is preferred for a race-free pidfd and optional cgroup-directory
//! placement; only stable unsupported/privilege classes select the retained
//! fork fallback. A forked direct child may degrade to numeric identity solely
//! for C-compatible descriptor/memory exhaustion because PID 1 still owns the
//! wait relationship.

use super::ProcessIdentity;
use nix::sys::wait::waitpid;
use nix::unistd::{fork, Pid};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU8, Ordering};

const CLONE_PIDFD_FLAG: u64 = 0x0000_1000;
const CLONE_INTO_CGROUP_FLAG: u64 = 0x0000_0002_0000_0000;

const FALLBACK_NONE: u8 = 0;
const FALLBACK_UNSUPPORTED: u8 = 1;
const FALLBACK_PRIVILEGE: u8 = 2;

/// Caches why a Linux clone facility was disabled. The cgroup extension may
/// be disabled after either an unsupported or privilege failure. Bare clone3
/// selects the fork compatibility path only when the syscall is unsupported;
/// a privilege denial remains fatal rather than bypassing policy.
static CLONE3_FALLBACK: AtomicU8 = AtomicU8::new(FALLBACK_NONE);
static CLONE_INTO_CGROUP_FALLBACK: AtomicU8 = AtomicU8::new(FALLBACK_NONE);

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

enum RawCloneResult {
    Parent { child: Pid, pidfd: OwnedFd },
    Child,
}

pub(super) enum ServiceFork {
    Parent {
        child: Pid,
        identity: ProcessIdentity,
        cloned_into_cgroup: bool,
    },
    Child,
}

fn errno_or_invalid_argument() -> i32 {
    // SAFETY: Linux exposes the calling thread's errno through this pointer.
    let errno = unsafe { *libc::__errno_location() };
    if errno == 0 {
        libc::EINVAL
    } else {
        errno
    }
}

fn clone_fallback_class(errno: i32) -> Option<u8> {
    match errno {
        libc::EOPNOTSUPP
        | libc::ENOTTY
        | libc::ENOSYS
        | libc::EAFNOSUPPORT
        | libc::EPFNOSUPPORT
        | libc::EPROTONOSUPPORT
        | libc::ESOCKTNOSUPPORT
        | libc::ENOPROTOOPT => Some(FALLBACK_UNSUPPORTED),
        libc::EACCES | libc::EPERM => Some(FALLBACK_PRIVILEGE),
        _ => None,
    }
}

fn raw_clone3(cgroup_fd: Option<RawFd>) -> Result<RawCloneResult, i32> {
    let mut pidfd = -1;
    let mut args = CloneArgs {
        flags: CLONE_PIDFD_FLAG,
        pidfd: (&mut pidfd as *mut libc::c_int) as usize as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    if let Some(cgroup_fd) = cgroup_fd {
        args.flags |= CLONE_INTO_CGROUP_FLAG;
        args.cgroup = cgroup_fd as u64;
    }

    // SAFETY: `args` has the kernel's clone_args layout and remains live for
    // the syscall; its pidfd output points to parent stack storage. No sharing
    // flags are used, and the child returns to the allocation-free launch path.
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &args as *const CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if result < 0 {
        return Err(errno_or_invalid_argument());
    }
    if result == 0 {
        return Ok(RawCloneResult::Child);
    }

    let child = Pid::from_raw(result as libc::pid_t);
    if pidfd < 0 {
        terminate_unconfirmed_child_pid(child);
        return Err(libc::EPROTO);
    }
    // SAFETY: CLONE_PIDFD returned a new descriptor in the parent-owned output
    // slot and no other owner has been constructed.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    Ok(RawCloneResult::Parent { child, pidfd })
}

pub(super) fn spawn_process(
    cgroup_directory: Option<BorrowedFd<'_>>,
    cgroup_threaded: bool,
) -> Result<ServiceFork, String> {
    if CLONE3_FALLBACK.load(Ordering::Relaxed) == FALLBACK_NONE {
        if let Some(cgroup_directory) = cgroup_directory
            .filter(|_| CLONE_INTO_CGROUP_FALLBACK.load(Ordering::Relaxed) == FALLBACK_NONE)
        {
            match raw_clone3(Some(cgroup_directory.as_raw_fd())) {
                Ok(RawCloneResult::Child) => return Ok(ServiceFork::Child),
                Ok(RawCloneResult::Parent { child, pidfd }) => {
                    return Ok(ServiceFork::Parent {
                        child,
                        identity: ProcessIdentity::with_pidfd(child.as_raw() as u32, pidfd),
                        cloned_into_cgroup: true,
                    });
                }
                Err(errno) => {
                    if errno == libc::EOPNOTSUPP && cgroup_threaded {
                        return Err(
                            "clone3(CLONE_INTO_CGROUP) rejected a threaded or invalid cgroup"
                                .to_string(),
                        );
                    }
                    let Some(class) = clone_fallback_class(errno) else {
                        return Err(format!(
                            "clone3(CLONE_INTO_CGROUP|CLONE_PIDFD) failed: {}",
                            std::io::Error::from_raw_os_error(errno)
                        ));
                    };
                    CLONE_INTO_CGROUP_FALLBACK.store(class, Ordering::Relaxed);
                }
            }
        }

        match raw_clone3(None) {
            Ok(RawCloneResult::Child) => return Ok(ServiceFork::Child),
            Ok(RawCloneResult::Parent { child, pidfd }) => {
                return Ok(ServiceFork::Parent {
                    child,
                    identity: ProcessIdentity::with_pidfd(child.as_raw() as u32, pidfd),
                    cloned_into_cgroup: false,
                });
            }
            Err(errno) => {
                // Match C's final pidfd_spawn fallback: once the cgroup
                // extension has been removed, only a genuinely unavailable
                // clone3 may select fork. In particular, do not turn a
                // seccomp/privilege denial of bare CLONE_PIDFD into a
                // successful fork that bypasses that policy.
                if clone_fallback_class(errno) != Some(FALLBACK_UNSUPPORTED) {
                    return Err(format!(
                        "clone3(CLONE_PIDFD) failed: {}",
                        std::io::Error::from_raw_os_error(errno)
                    ));
                }
                CLONE3_FALLBACK.store(FALLBACK_UNSUPPORTED, Ordering::Relaxed);
            }
        }
    }

    // SAFETY: this is the retained compatibility fork. All launch storage and
    // child scratch buffers were prepared by the caller before reaching it.
    match unsafe { fork() } {
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            let identity = match acquire_process_identity(child.as_raw() as u32) {
                Ok(identity) => identity,
                Err(error) => {
                    terminate_unconfirmed_child_pid(child);
                    return Err(error);
                }
            };
            Ok(ServiceFork::Parent {
                child,
                identity,
                cloned_into_cgroup: false,
            })
        }
        Ok(nix::unistd::ForkResult::Child) => Ok(ServiceFork::Child),
        Err(error) => Err(format!("fork failed: {error}")),
    }
}

fn is_resource_errno(errno: i32) -> bool {
    matches!(errno, libc::EMFILE | libc::ENFILE | libc::ENOMEM)
}

pub(super) fn acquire_process_identity(pid: u32) -> Result<ProcessIdentity, String> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(format!("invalid PID for pidfd acquisition: {pid}"));
    }

    // SAFETY: pidfd_open takes a validated positive PID and zero flags and
    // returns a new owned descriptor on success.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if pidfd >= 0 {
        // SAFETY: pidfd_open returned a new descriptor with no existing owner.
        return Ok(ProcessIdentity::with_pidfd(pid, unsafe {
            OwnedFd::from_raw_fd(pidfd as RawFd)
        }));
    }

    let errno = errno_or_invalid_argument();
    if is_resource_errno(errno) {
        return Ok(ProcessIdentity::numeric(pid));
    }
    Err(format!(
        "pidfd_open({pid}) failed without a permitted numeric fallback: {}",
        std::io::Error::from_raw_os_error(errno)
    ))
}

pub(super) fn signal_process_identity(
    identity: &ProcessIdentity,
    signal: i32,
) -> Result<(), String> {
    let result = if let Some(pidfd) = identity.as_pidfd() {
        // SAFETY: the pidfd is manager-owned and live, the signal number is
        // passed through unchanged, and null siginfo with flags=0 is the
        // pidfd_send_signal contract.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        }
    } else {
        // SAFETY: numeric signaling is reachable only for resource-exhaustion
        // identity class established by acquire_process_identity().
        unsafe { libc::kill(identity.pid() as libc::pid_t, signal) as libc::c_long }
    };

    if result == 0 {
        Ok(())
    } else {
        let errno = errno_or_invalid_argument();
        Err(format!(
            "signaling PID {} failed: {}",
            identity.pid(),
            std::io::Error::from_raw_os_error(errno)
        ))
    }
}

fn reap_failed_child(child: Pid) {
    loop {
        match waitpid(child, None) {
            Ok(_) | Err(nix::errno::Errno::ECHILD) => return,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => return,
        }
    }
}

fn terminate_unconfirmed_child_pid(child: Pid) {
    // SAFETY: `child` is the process created by this call. This path is only
    // used when the parent cannot establish whether exec happened, so retaining
    // an untracked service would be less safe than terminating and reaping it.
    unsafe {
        libc::kill(child.as_raw(), libc::SIGKILL);
    }
    reap_failed_child(child);
}

pub(super) fn terminate_unconfirmed_child(child: Pid, identity: &ProcessIdentity) {
    if identity.signal(libc::SIGKILL).is_err() {
        // This cleanup path still owns an unreaped direct child with the exact
        // PID returned by clone/fork. Numeric fallback here cannot target a
        // reused PID or safely be omitted.
        // SAFETY: ownership of the unreaped child proves this PID is current.
        unsafe {
            libc::kill(child.as_raw(), libc::SIGKILL);
        }
    }
    reap_failed_child(child);
}
