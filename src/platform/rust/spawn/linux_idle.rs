// SPDX-License-Identifier: LGPL-2.1-or-later

//! Allocation-free child side of the manager-owned `Type=idle` protocol.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use super::super::IdlePipe;
use super::child_errno_or_invalid_argument;
use std::os::fd::RawFd;

const IDLE_TIMEOUT_MSEC: libc::c_int = 5_000;
const IDLE_TIMEOUT2_MSEC: libc::c_int = 1_000;

fn child_close_idle_fd(fd: RawFd) {
    if fd >= 0 {
        // SAFETY: this is the async-signal-safe close syscall on an inherited
        // descriptor. Errors intentionally match C's `safe_close()` behavior.
        let _ = unsafe_ffi!(libc::close(fd));
    }
}

fn child_wait_for_idle_hup(fd: RawFd, timeout_msec: libc::c_int) -> i32 {
    let mut pollfd = libc::pollfd {
        fd,
        events: libc::POLLHUP,
        revents: 0,
    };
    loop {
        // SAFETY: pollfd points to valid stack storage for one entry.
        let result = unsafe_ffi!(libc::poll(&mut pollfd, 1, timeout_msec));
        if result < 0 && child_errno_or_invalid_argument() == libc::EINTR {
            continue;
        }
        return result;
    }
}

/// Execute C's `do_idle_pipe_dance()` in the allocation-free child path.
///
/// It is deliberately before the rest of launch setup: `Type=idle` only
/// serializes console-visible process startup, and the service must not reach
/// its executable or any potentially noisy pre-exec operation first.
pub(super) fn child_do_idle_pipe_dance(idle_pipe: IdlePipe) {
    child_close_idle_fd(idle_pipe.manager_release_fd);
    child_close_idle_fd(idle_pipe.manager_alert_fd);

    if idle_pipe.child_wait_fd >= 0 {
        let result = child_wait_for_idle_hup(idle_pipe.child_wait_fd, IDLE_TIMEOUT_MSEC);
        if idle_pipe.child_alert_fd >= 0 && result == 0 {
            let alert = b"x";
            // SAFETY: the one-byte static payload and inherited descriptor
            // are valid. EAGAIN and other failures are ignored just as C
            // treats the advisory alert as best effort.
            let wrote = unsafe_ffi!({
                libc::write(
                    idle_pipe.child_alert_fd,
                    alert.as_ptr().cast::<libc::c_void>(),
                    alert.len(),
                )
            });
            if wrote > 0 {
                let _ = child_wait_for_idle_hup(idle_pipe.child_wait_fd, IDLE_TIMEOUT2_MSEC);
            }
        }
        child_close_idle_fd(idle_pipe.child_wait_fd);
    }

    child_close_idle_fd(idle_pipe.child_alert_fd);
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::OFlag;
    use nix::unistd::pipe2;
    use std::os::fd::AsRawFd;

    #[test]
    fn idle_pipe_child_waits_for_manager_hup_before_returning() {
        let flags = OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
        let (child_wait, manager_release) = pipe2(flags).unwrap();
        let (manager_alert, child_alert) = pipe2(flags).unwrap();
        let idle_pipe = IdlePipe {
            child_wait_fd: child_wait.as_raw_fd(),
            manager_release_fd: manager_release.as_raw_fd(),
            manager_alert_fd: manager_alert.as_raw_fd(),
            child_alert_fd: child_alert.as_raw_fd(),
        };

        // SAFETY: the child immediately executes the allocation-free helper
        // under test and terminates through _exit without touching Rust-owned
        // state. The parent retains the manager endpoints exactly as PID 1.
        let child = unsafe_ffi!(libc::fork());
        assert!(child >= 0, "fork must succeed for idle-pipe test");
        if child == 0 {
            child_do_idle_pipe_dance(idle_pipe);
            // SAFETY: this child must not unwind Rust test destructors.
            unsafe_ffi!(libc::_exit(0))
        }

        std::thread::sleep(std::time::Duration::from_millis(25));
        let mut status = 0;
        // SAFETY: child is our direct child and status is valid writable
        // stack storage for waitpid.
        assert_eq!(
            unsafe_ffi!(libc::waitpid(child, &mut status, libc::WNOHANG)),
            0
        );

        drop(manager_release);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            // SAFETY: child is our direct child and status remains valid.
            let waited = unsafe_ffi!(libc::waitpid(child, &mut status, libc::WNOHANG));
            if waited == child {
                break;
            }
            if std::time::Instant::now() >= deadline {
                // SAFETY: child is a direct child which failed its bounded
                // protocol test; terminate it before failing the test.
                let _ = unsafe_ffi!(libc::kill(child, libc::SIGKILL));
                // SAFETY: reap the direct child after SIGKILL.
                let _ = unsafe_ffi!(libc::waitpid(child, &mut status, 0));
                panic!("idle child did not proceed after manager HUP");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);

        drop(child_wait);
        drop(manager_alert);
        drop(child_alert);
    }
}
