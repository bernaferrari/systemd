// SPDX-License-Identifier: LGPL-2.1-or-later

use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{Gid, Pid, Uid, fork, getgid, getpid, getppid, getuid};

/// Fork a new child process and run `f` in the child.
///
/// Returns the child's PID in the parent. The child exits immediately after
/// `f` returns, without running Rust destructors or process-exit handlers.
///
/// # Safety
///
/// The caller must ensure that `f` only performs operations that are safe
/// after `fork()` in a possibly multi-threaded process: it must not allocate,
/// lock, panic, access thread-local state, or invoke non-async-signal-safe
/// library code. `f` must also not retain references to parent-only state.
pub unsafe fn fork_child(f: impl FnOnce()) -> nix::Result<Pid> {
    // SAFETY: the caller upholds the post-fork contract documented above.
    match unsafe_ffi!(fork()?) {
        nix::unistd::ForkResult::Parent { child } => Ok(child),
        nix::unistd::ForkResult::Child => {
            f();
            // SAFETY: _exit(2) terminates this child without invoking Rust
            // destructors or process-exit handlers after fork.
            unsafe_ffi!(libc::_exit(0))
        }
    }
}

/// Block until the given child process changes state.
pub fn waitpid_block(pid: Pid) -> nix::Result<WaitStatus> {
    match waitpid(pid, None)? {
        WaitStatus::StillAlive => {
            unreachable!("waitpid with no WNOHANG should not return StillAlive")
        }
        status => Ok(status),
    }
}

/// Get the current process ID.
pub fn get_pid() -> Pid {
    getpid()
}

/// Get the parent process ID.
pub fn get_parent_pid() -> Pid {
    getppid()
}

/// Get the real user ID of the current process.
pub fn get_uid() -> Uid {
    getuid()
}

/// Get the real group ID of the current process.
pub fn get_gid() -> Gid {
    getgid()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ids() {
        let pid = get_pid();
        assert!(pid.as_raw() > 0);

        let ppid = get_parent_pid();
        assert!(ppid.as_raw() > 0);

        let uid = get_uid();
        assert!(uid.as_raw() > 0);

        let gid = get_gid();
        assert!(gid.as_raw() > 0);
    }
}
