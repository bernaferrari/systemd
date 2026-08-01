// SPDX-License-Identifier: LGPL-2.1-or-later
// PORT-SYNC: src/volatile-root/volatile-root.c

//! Linux mount-attribute boundary for the volatile-root transition.
//!
//! The C implementation first tries recursive `mount_setattr()` and then
//! falls back to its classic mountinfo walk for every syscall failure. Rust
//! keeps that fallback explicit and typed until the older-kernel walk is
//! ported, rather than silently treating a compatibility boundary as a final
//! mount failure.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use systemd_shared_rs::unsafe_ffi;

use crate::linux_transition_requirement::{
    LinuxVolatileTransitionRequirement, fallback_required_error, mark_mount_setattr_unavailable,
    mount_setattr_available, mount_setattr_is_unsupported,
};

/// Linux mount-attribute ABI, stable since Linux 5.12.
///
/// `libc` intentionally does not expose this tiny UAPI structure on every
/// supported target. Its four `u64` fields are the kernel ABI from
/// `linux/mount.h`; keeping it local confines the unavoidable raw syscall to
/// the one operation for which the existing mount facade has no safe wrapper.
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// Apply a read-only attribute recursively with the same subtree scope as
/// C's modern `bind_remount_recursive()` fast path.
pub(crate) fn set_mount_tree_read_only(target: &Path) -> io::Result<()> {
    // `bind_remount_recursive()` remembers only the fact that this modern
    // shortcut is unavailable. Once C has observed that, it enters its
    // classic recursive algorithm directly on later calls. We cannot safely
    // substitute that algorithm yet, so preserve its capability result as an
    // explicit, typed boundary before attempting a syscall.
    if !mount_setattr_available() {
        return Err(fallback_required_error(
            LinuxVolatileTransitionRequirement::RecursiveReadOnlyRemount,
            libc::EOPNOTSUPP,
        ));
    }

    let target = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "target contains NUL"))?;
    let attribute = MountAttr {
        attr_set: libc::MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };

    // SAFETY: target is retained and NUL-terminated; `attribute` exactly
    // matches Linux `struct mount_attr` and stays valid for the syscall. No
    // pointer is retained by the kernel after this synchronous operation.
    let result = unsafe_ffi!({
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            target.as_ptr(),
            (libc::AT_SYMLINK_NOFOLLOW | libc::AT_RECURSIVE) as libc::c_uint,
            &attribute,
            std::mem::size_of::<MountAttr>(),
        )
    });
    if result < 0 {
        let error = io::Error::last_os_error();
        let errno = error.raw_os_error().unwrap_or(libc::EIO);

        // C deliberately falls back to the classic recursive remount
        // implementation after *every* `mount_setattr()` error. In
        // particular EINVAL can mean that `target` is not itself a mount
        // point, while permission and busy errors can still allow the
        // classic per-mount walk to make partial progress. Do not return an
        // untyped ordinary I/O error here: it would conceal the fact that the
        // staged Rust backend stopped exactly where the unported C fallback
        // must take over.
        //
        // C caches only a genuinely unsupported syscall result. Other
        // failures remain per-call, because they may be namespace, policy,
        // or mount-tree specific.
        if mount_setattr_is_unsupported(errno) {
            mark_mount_setattr_unavailable();
        }
        return Err(fallback_required_error(
            LinuxVolatileTransitionRequirement::RecursiveReadOnlyRemount,
            errno,
        ));
    }
    Ok(())
}
