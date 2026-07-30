// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/audit-fd.c, src/core/audit-fd.h
//

use crate::ffi::Errno;

pub const SOURCE_PATHS: &[&str] = &["src/core/audit-fd.c", "src/core/audit-fd.h"];

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

    /// Return the cached audit descriptor or its exact negative errno.
    ///
    /// This mirrors `get_core_audit_fd()`'s C ABI: a negative result is not
    /// collapsed into a Rust error enum because `open_audit_fd_or_warn()` may
    /// return any Linux errno.
    pub fn get_core_audit_fd<F>(&mut self, have_audit_write: bool, opener: F) -> i32
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

        self.raw_fd
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
    fn source_paths_cover_the_c_implementation_and_abi() {
        assert_eq!(
            SOURCE_PATHS,
            &["src/core/audit-fd.c", "src/core/audit-fd.h"]
        );
    }

    #[test]
    fn opens_fd_once_when_capability_is_present() {
        let mut state = AuditFd::new();
        let first = state.get_core_audit_fd(true, || 17);
        let second = state.get_core_audit_fd(true, || 99);

        assert_eq!(first, 17);
        assert_eq!(second, 17);
        assert!(state.initialized());
    }

    #[test]
    fn capability_failure_becomes_eperm() {
        let mut state = AuditFd::new();
        let result = state.get_core_audit_fd(false, || unreachable!());

        assert_eq!(result, Errno::EPERM.to_neg_errno());
        assert_eq!(state.raw_fd(), Errno::EPERM.to_neg_errno());
    }

    #[test]
    fn opener_error_is_returned_verbatim() {
        let mut state = AuditFd::new();
        let result = state.get_core_audit_fd(true, || Errno::EBADF.to_neg_errno());

        assert_eq!(result, Errno::EBADF.to_neg_errno());
    }

    #[test]
    fn arbitrary_negative_errno_is_preserved() {
        let mut state = AuditFd::new();
        let result = state.get_core_audit_fd(true, || -777);

        assert_eq!(result, -777);
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

        assert_eq!(
            state.get_core_audit_fd(true, || 55),
            Errno::ECONNRESET.to_neg_errno()
        );
    }

    #[test]
    fn raw_fd_is_preserved_after_cached_failure() {
        let mut state = AuditFd::new();
        let _ = state.get_core_audit_fd(true, || Errno::EPERM.to_neg_errno());

        assert_eq!(state.raw_fd(), Errno::EPERM.to_neg_errno());
        assert_eq!(
            state.get_core_audit_fd(true, || 77),
            Errno::EPERM.to_neg_errno()
        );
    }

    #[test]
    fn minimum_i32_error_is_preserved_without_negation_overflow() {
        let mut state = AuditFd::new();

        assert_eq!(state.get_core_audit_fd(true, || i32::MIN), i32::MIN);
    }
}
