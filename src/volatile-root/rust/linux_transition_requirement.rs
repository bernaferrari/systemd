// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/chase.c, src/shared/mount-util.c

//! Fail-closed diagnostics for Linux volatile-root syscall fallback boundaries.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

/// A kernel operation for which C has a legacy fallback that the staged Rust
/// transition deliberately does not emulate yet.
///
/// C's `chase()` and `bind_remount_recursive()` can fall back to a long,
/// race-aware userspace implementation when the modern Linux syscall is
/// unavailable or unsuitable. Replacing either one with a host-path walk or
/// a flag-clobbering remount loop would make the Rust transition less safe.
/// Until those complete fallbacks are ported, this enum lets an integration
/// boundary identify the exact missing capability instead of treating every
/// `EOPNOTSUPP` as an indistinguishable mount failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVolatileTransitionRequirement {
    /// `openat2(RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS)` could not perform the
    /// root-bounded `/usr` resolution.
    RootBoundedUsrResolution,
    /// `mount_setattr(AT_RECURSIVE)` could not make the copied `/usr` mount
    /// tree read-only.
    RecursiveReadOnlyRemount,
}

impl LinuxVolatileTransitionRequirement {
    /// Name of the modern syscall whose C-compatible fallback is required.
    pub const fn syscall_name(self) -> &'static str {
        match self {
            Self::RootBoundedUsrResolution => "openat2",
            Self::RecursiveReadOnlyRemount => "mount_setattr",
        }
    }
}

/// Diagnostic preserved when the staged Linux backend must fail closed.
///
/// Call [`linux_volatile_transition_requirement`] on an `io::Error` returned
/// by [`crate::LinuxVolatileTransitionBackend`] to distinguish this deliberate
/// boundary from an ordinary filesystem or mount failure. `source_errno` is
/// retained for logs and later C-compatible error mapping; no mount side
/// effect is attempted as a substitute for the missing fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxVolatileTransitionFallbackRequired {
    requirement: LinuxVolatileTransitionRequirement,
    source_errno: i32,
}

impl LinuxVolatileTransitionFallbackRequired {
    /// The operation for which a C-compatible fallback is still required.
    pub const fn requirement(self) -> LinuxVolatileTransitionRequirement {
        self.requirement
    }

    /// The errno returned by the modern syscall before the fail-closed stop.
    pub const fn source_errno(self) -> i32 {
        self.source_errno
    }
}

impl std::fmt::Display for LinuxVolatileTransitionFallbackRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} requires the unported C-compatible volatile-root fallback (errno {})",
            self.requirement.syscall_name(),
            self.source_errno,
        )
    }
}

impl std::error::Error for LinuxVolatileTransitionFallbackRequired {}

/// Return the explicit fallback requirement carried by a staged Linux backend
/// error, if it has one.
pub fn linux_volatile_transition_requirement(
    error: &io::Error,
) -> Option<LinuxVolatileTransitionFallbackRequired> {
    error
        .get_ref()?
        .downcast_ref::<LinuxVolatileTransitionFallbackRequired>()
        .copied()
}

pub(crate) fn fallback_required_error(
    requirement: LinuxVolatileTransitionRequirement,
    source_errno: i32,
) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        LinuxVolatileTransitionFallbackRequired {
            requirement,
            source_errno,
        },
    )
}

/// C caches `ENOSYS` from `openat2()` and skips the unavailable modern path
/// afterwards. Keep the same process-local rule; `EPERM` and `EAGAIN` remain
/// per-call because they can be caused by a seccomp profile or a transient
/// rename/mount-lock race respectively.
static OPENAT2_AVAILABLE: AtomicBool = AtomicBool::new(true);

/// C's `bind_remount_recursive()` similarly stops attempting its
/// `mount_setattr()` shortcut after the kernel reports that the syscall is
/// unsupported. Other errors must *not* be cached: C immediately falls back
/// to its classic per-mount implementation because it can make progress even
/// when the atomic syscall cannot.
static MOUNT_SETATTR_AVAILABLE: AtomicBool = AtomicBool::new(true);

pub(crate) fn openat2_available() -> bool {
    OPENAT2_AVAILABLE.load(Ordering::Relaxed)
}

pub(crate) fn mark_openat2_unavailable() {
    OPENAT2_AVAILABLE.store(false, Ordering::Relaxed);
}

pub(crate) fn mount_setattr_available() -> bool {
    MOUNT_SETATTR_AVAILABLE.load(Ordering::Relaxed)
}

pub(crate) fn mark_mount_setattr_unavailable() {
    MOUNT_SETATTR_AVAILABLE.store(false, Ordering::Relaxed);
}

/// Whether the errno denotes a permanently unavailable `mount_setattr()`
/// fast path. Reuse the Rust port of `ERRNO_IS_NOT_SUPPORTED()` rather than
/// duplicating its wider, target-aware errno family here.
pub(crate) fn mount_setattr_is_unsupported(errno: i32) -> bool {
    systemd_basic_rs::errno_classify::errno_is_not_supported(errno.into())
}
