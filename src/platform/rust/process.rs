// SPDX-License-Identifier: LGPL-2.1-or-later

use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, getgid, getpid, getppid, getuid, Gid, Pid, Uid};

/// Fork a new child process and run the given closure in the child.
///
/// Returns the child's PID in the parent. The child process will execute
/// the provided closure and then exit.
///
/// # Safety
///
/// This is a safe wrapper around `fork()`. The child must only call
/// async-signal-safe functions.
pub fn fork_child(f: impl FnOnce()) -> nix::Result<Pid> {
    match unsafe { fork()? } {
        nix::unistd::ForkResult::Parent { child } => Ok(child),
        nix::unistd::ForkResult::Child => {
            f();
            // Exit the child process to avoid continuing execution
            // of the parent's code path.
            std::process::exit(0);
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
