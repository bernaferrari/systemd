// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/audit-fd.c
//

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/core/audit-fd.c";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditFd {
    initialized: bool,
    raw_fd: i32,
}

impl Default for AuditFd {
    fn default() -> Self {
        Self {
            initialized: false,
            raw_fd: Errno::EBADF.to_neg_errno(),
        }
    }
}

impl AuditFd {
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn raw_fd(self) -> i32 {
        self.raw_fd
    }

    pub const fn initialized(self) -> bool {
        self.initialized
    }

    pub fn get_core_audit_fd<F>(&mut self, have_audit_write: bool, opener: F) -> Result<i32, Errno>
    where
        F: FnOnce() -> i32,
    {
        if !self.initialized {
            self.raw_fd = if have_audit_write {
                opener()
            } else {
                Errno::EPERM.to_neg_errno()
            };

            self.initialized = true;
        }

        if self.raw_fd >= 0 {
            Ok(self.raw_fd)
        } else {
            Err(match -self.raw_fd {
                1 => Errno::EPERM,
                9 => Errno::EBADF,
                104 => Errno::ECONNRESET,
                _ => Errno::EIO,
            })
        }
    }

    pub fn close_core_audit_fd<F>(&mut self, closer: F)
    where
        F: FnOnce(i32),
    {
        closer(self.raw_fd);
        self.initialized = true;
        self.raw_fd = Errno::ECONNRESET.to_neg_errno();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_uninitialized_and_badfd() {
        let state = AuditFd::new();
        assert!(!state.initialized());
        assert_eq!(state.raw_fd(), Errno::EBADF.to_neg_errno());
    }

    #[test]
    fn opens_fd_once_when_capability_is_present() {
        let mut state = AuditFd::new();
        let first = state.get_core_audit_fd(true, || 17).unwrap();
        let second = state.get_core_audit_fd(true, || 99).unwrap();

        assert_eq!(first, 17);
        assert_eq!(second, 17);
        assert!(state.initialized());
    }

    #[test]
    fn capability_failure_becomes_eperm() {
        let mut state = AuditFd::new();
        let result = state.get_core_audit_fd(false, || unreachable!());

        assert_eq!(result, Err(Errno::EPERM));
        assert_eq!(state.raw_fd(), Errno::EPERM.to_neg_errno());
    }

    #[test]
    fn opener_error_is_returned_as_errno() {
        let mut state = AuditFd::new();
        let result = state.get_core_audit_fd(true, || Errno::EBADF.to_neg_errno());

        assert_eq!(result, Err(Errno::EBADF));
    }

    #[test]
    fn unknown_negative_error_falls_back_to_eio() {
        let mut state = AuditFd::new();
        let result = state.get_core_audit_fd(true, || -777);

        assert_eq!(result, Err(Errno::EIO));
    }

    #[test]
    fn close_transitions_to_connection_reset() {
        let mut state = AuditFd::new();
        let _ = state.get_core_audit_fd(true, || 23);

        let mut closed_fd = None;
        state.close_core_audit_fd(|fd| closed_fd = Some(fd));

        assert_eq!(closed_fd, Some(23));
        assert_eq!(state.raw_fd(), Errno::ECONNRESET.to_neg_errno());
        assert!(state.initialized());
    }

    #[test]
    fn close_without_open_still_marks_state_closed() {
        let mut state = AuditFd::new();
        let mut closed_fd = None;
        state.close_core_audit_fd(|fd| closed_fd = Some(fd));

        assert_eq!(closed_fd, Some(Errno::EBADF.to_neg_errno()));
        assert_eq!(state.raw_fd(), Errno::ECONNRESET.to_neg_errno());
    }

    #[test]
    fn get_after_close_returns_connection_reset() {
        let mut state = AuditFd::new();
        state.close_core_audit_fd(|_| {});

        assert_eq!(state.get_core_audit_fd(true, || 55), Err(Errno::ECONNRESET));
    }

    #[test]
    fn raw_fd_is_preserved_after_cached_failure() {
        let mut state = AuditFd::new();
        let _ = state.get_core_audit_fd(true, || Errno::EPERM.to_neg_errno());

        assert_eq!(state.raw_fd(), Errno::EPERM.to_neg_errno());
        assert_eq!(state.get_core_audit_fd(true, || 77), Err(Errno::EPERM));
    }
}
