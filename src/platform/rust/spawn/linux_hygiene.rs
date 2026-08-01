// SPDX-License-Identifier: LGPL-2.1-or-later

//! Post-fork signal and descriptor hygiene shared by the Linux service child.
//!
//! Keep these operations in a focused module so the launch state machine does
//! not grow past its architectural debt cap. Every function is called only in
//! the narrow child window between fork and exec.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::os::fd::{BorrowedFd, RawFd};

use super::child_errno_or_invalid_argument;
use super::{ChildSpawnStage, child_report_failure};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::unistd::{close, dup2_stderr, dup2_stdin, dup2_stdout};

/// Restore the dispositions that PID 1 deliberately changes for itself.
///
/// `main.c` makes PID 1 ignore `SIGPIPE`, and `exec-invoke.c` restores this
/// set immediately before preparing a service. The crash signals are included
/// for the same reason: a reexecuted manager must never leak an inherited
/// handler into an `execve()` target. Other dispositions are left alone,
/// matching C's `default_signals(SIGNALS_CRASH_HANDLER, SIGNALS_IGNORE)`.
pub(super) fn reset_child_signal_dispositions() -> Result<(), i32> {
    // SAFETY: `sigemptyset` initializes the local mask before it is embedded
    // in `sigaction`. The action installs only SIG_DFL (no Rust callback),
    // and every signal below is a valid, mutable Linux signal disposition.
    unsafe_ffi!({
        let mut mask = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        if libc::sigemptyset(mask.as_mut_ptr()) != 0 {
            return Err(child_errno_or_invalid_argument());
        }
        let action = libc::sigaction {
            sa_sigaction: libc::SIG_DFL,
            sa_mask: mask.assume_init(),
            sa_flags: 0,
            sa_restorer: None,
        };
        for signal in [
            libc::SIGSEGV,
            libc::SIGILL,
            libc::SIGFPE,
            libc::SIGBUS,
            libc::SIGQUIT,
            libc::SIGABRT,
            libc::SIGPIPE,
        ] {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
                return Err(child_errno_or_invalid_argument());
            }
        }
    });
    Ok(())
}

fn child_close_fd_range(first: libc::c_uint, last: libc::c_uint) -> Result<(), i32> {
    if first > last {
        return Err(libc::EINVAL);
    }
    // SAFETY: close_range changes only the calling child's descriptor table;
    // both bounds are scalar descriptor numbers and no pointer is involved.
    let result = unsafe_ffi!(libc::syscall(libc::SYS_close_range, first, last, 0_u32));
    if result == 0 {
        Ok(())
    } else {
        Err(child_errno_or_invalid_argument())
    }
}

/// Close every manager-owned descriptor except the child's explicit contract.
///
/// Activation descriptors have already been installed contiguously from fd 3
/// through `first_unlisted_fd - 1`; the CLOEXEC exec-status descriptor is the
/// sole higher-numbered exception. All cgroup, activation-source, temporary,
/// event-loop, bus, and notify descriptors are closed before namespace and
/// security setup. This mirrors C's `close_remaining_fds()` ordering and also
/// prevents a pre-exec child from keeping old PID 1 sockets alive across a
/// concurrent reexec. Linux 5.14 is the project's kernel baseline, so a
/// missing or policy-blocked `close_range(2)` fails the launch instead of
/// silently leaking capabilities.
pub(super) fn child_sanitize_inherited_fds(
    first_unlisted_fd: RawFd,
    status_fd: RawFd,
) -> Result<(), i32> {
    if first_unlisted_fd < libc::STDERR_FILENO + 1 || status_fd < first_unlisted_fd {
        return Err(libc::EINVAL);
    }

    if first_unlisted_fd < status_fd {
        child_close_fd_range(
            first_unlisted_fd as libc::c_uint,
            (status_fd - 1) as libc::c_uint,
        )?;
    }
    if status_fd < i32::MAX {
        child_close_fd_range((status_fd + 1) as libc::c_uint, libc::c_uint::MAX)?;
    }
    Ok(())
}

pub(super) fn duplicate_child_fd_cloexec(
    fd: RawFd,
    minimum_fd: RawFd,
) -> Result<RawFd, nix::errno::Errno> {
    // SAFETY: every caller passes a descriptor retained by PreparedLaunch or
    // an OwnedFd that remains live for this post-fork operation.
    let fd = unsafe_ffi!(BorrowedFd::borrow_raw(fd));
    fcntl(fd, FcntlArg::F_DUPFD_CLOEXEC(minimum_fd))
}

pub(super) fn duplicate_activation_fds(
    source_fds: &[RawFd],
    temporary_fds: &mut [RawFd],
) -> Result<(), (ChildSpawnStage, i32)> {
    if source_fds.len() != temporary_fds.len() {
        return Err((ChildSpawnStage::ActivationFd, libc::EINVAL));
    }

    let first_activation_fd = libc::STDERR_FILENO + 1;
    let first_temporary_fd = first_activation_fd
        .checked_add(source_fds.len() as RawFd)
        .ok_or((ChildSpawnStage::ActivationFd, libc::EMFILE))?;

    // Both vectors were allocated before fork. Write temporary descriptors in
    // place so the collision-safe remap itself allocates no memory in the
    // post-fork child.
    for (source, temporary) in source_fds.iter().zip(temporary_fds.iter_mut()) {
        *temporary = duplicate_child_fd_cloexec(*source, first_temporary_fd)
            .map_err(|error| (ChildSpawnStage::ActivationFd, error as i32))?;
    }

    Ok(())
}

pub(super) fn close_original_activation_fds(source_fds: &[RawFd]) {
    for source in source_fds {
        if *source > libc::STDERR_FILENO {
            let _ = close(*source);
        }
    }
}

pub(super) fn install_activation_fds(
    temporary_fds: &[RawFd],
    status_fd: RawFd,
) -> Result<(), (ChildSpawnStage, i32)> {
    let first_activation_fd = libc::STDERR_FILENO + 1;
    for (index, duplicate) in temporary_fds.iter().copied().enumerate() {
        if duplicate < 0 {
            return Err((ChildSpawnStage::ActivationRemap, libc::EINVAL));
        }
        let target = first_activation_fd + index as RawFd;
        if target == status_fd {
            let _ = close(duplicate);
            return Err((ChildSpawnStage::ActivationRemap, libc::EBUSY));
        }
        // SAFETY: `duplicate` is a valid F_DUPFD_CLOEXEC result and `target`
        // is a checked slot intentionally replaced by dup3 in this child.
        if unsafe_ffi!(libc::dup3(duplicate, target, OFlag::empty().bits())) < 0 {
            return Err((
                ChildSpawnStage::ActivationRemap,
                child_errno_or_invalid_argument(),
            ));
        }
        let _ = close(duplicate);
    }

    Ok(())
}

pub(super) fn redirect_child_stdio(
    source: Option<RawFd>,
    target: RawFd,
    stage: ChildSpawnStage,
    status_fd: RawFd,
) {
    if let Some(source) = source {
        // SAFETY: stdio sources were validated before fork and remain open in
        // PreparedLaunch throughout child setup.
        let source = unsafe_ffi!(BorrowedFd::borrow_raw(source));
        let result = match target {
            libc::STDIN_FILENO => dup2_stdin(source),
            libc::STDOUT_FILENO => dup2_stdout(source),
            libc::STDERR_FILENO => dup2_stderr(source),
            _ => Err(nix::errno::Errno::EINVAL),
        };
        if let Err(error) = result {
            child_report_failure(status_fd, stage, error as i32);
        }
    }
}
