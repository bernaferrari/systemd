// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/errno-util.h (ERRNO_IS_NEG_* and ERRNO_IS_* functions),
//            src/shared/seccomp-util.h (ERRNO_IS_NEG_SECCOMP_FATAL)
//
// Error classification functions.  Each checks whether a (possibly negative)
// errno value belongs to a specific category used throughout systemd.
//
// The C code uses `_DEFINE_ABS_WRAPPER(name)` which generates:
//   `ERRNO_IS_name(r) = ERRNO_IS_NEG_name(-ABS(r))` (with `INTMAX_MIN` guard).

use libc::intmax_t;

// ── Internal helpers ──────────────────────────────────────────────────────

/// Convert a target C errno constant to the negative convention used by C.
const fn neg_errno(e: libc::c_int) -> intmax_t {
    -(e as intmax_t)
}

/// Check whether `r` matches any value in `set`.
fn matches_set(r: intmax_t, set: &[intmax_t]) -> bool {
    set.contains(&r)
}

// ── TRANSIENT ─────────────────────────────────────────────────────────────

const TRANSIENT_SET: &[intmax_t] = &[neg_errno(libc::EAGAIN), neg_errno(libc::EINTR)];

/// `ERRNO_IS_NEG_TRANSIENT`: checks for `EAGAIN`, `EINTR`.
pub fn errno_is_neg_transient(r: intmax_t) -> bool {
    matches_set(r, TRANSIENT_SET)
}

/// `ERRNO_IS_TRANSIENT`: absolute wrapper for `errno_is_neg_transient`.
/// Returns `false` for `INTMAX_MIN` to avoid overflow on `abs()`.
pub fn errno_is_transient(r: intmax_t) -> bool {
    if r == intmax_t::MIN {
        return false;
    }
    errno_is_neg_transient(-r.abs())
}

// ── DISCONNECT ────────────────────────────────────────────────────────────

const DISCONNECT_SET: &[intmax_t] = &[
    neg_errno(libc::ECONNABORTED),
    neg_errno(libc::ECONNREFUSED),
    neg_errno(libc::ECONNRESET),
    neg_errno(libc::EHOSTDOWN),
    neg_errno(libc::EHOSTUNREACH),
    neg_errno(libc::ENETDOWN),
    neg_errno(libc::ENETRESET),
    neg_errno(libc::ENETUNREACH),
    neg_errno(libc::ENONET),
    neg_errno(libc::ENOPROTOOPT),
    neg_errno(libc::ENOTCONN),
    neg_errno(libc::EPIPE),
    neg_errno(libc::EPROTO),
    neg_errno(libc::ESHUTDOWN),
    neg_errno(libc::ETIMEDOUT),
];

/// `ERRNO_IS_NEG_DISCONNECT`: network / connection-related errors.
pub fn errno_is_neg_disconnect(r: intmax_t) -> bool {
    matches_set(r, DISCONNECT_SET)
}

/// `ERRNO_IS_DISCONNECT`: absolute wrapper.
pub fn errno_is_disconnect(r: intmax_t) -> bool {
    if r == intmax_t::MIN {
        return false;
    }
    errno_is_neg_disconnect(-r.abs())
}

// ── ACCEPT_AGAIN ──────────────────────────────────────────────────────────

/// `ERRNO_IS_NEG_ACCEPT_AGAIN`: union of disconnect + transient + `EOPNOTSUPP`.
pub fn errno_is_neg_accept_again(r: intmax_t) -> bool {
    errno_is_neg_disconnect(r) || errno_is_neg_transient(r) || r == neg_errno(libc::EOPNOTSUPP)
}

/// `ERRNO_IS_ACCEPT_AGAIN`: absolute wrapper.
pub fn errno_is_accept_again(r: intmax_t) -> bool {
    if r == intmax_t::MIN {
        return false;
    }
    errno_is_neg_accept_again(-r.abs())
}

// ── RESOURCE ──────────────────────────────────────────────────────────────

const RESOURCE_SET: &[intmax_t] = &[
    neg_errno(libc::EMFILE),
    neg_errno(libc::ENFILE),
    neg_errno(libc::ENOMEM),
];

/// `ERRNO_IS_NEG_RESOURCE`: resource exhaustion errors.
pub fn errno_is_neg_resource(r: intmax_t) -> bool {
    matches_set(r, RESOURCE_SET)
}

/// `ERRNO_IS_RESOURCE`: absolute wrapper.
pub fn errno_is_resource(r: intmax_t) -> bool {
    if r == intmax_t::MIN {
        return false;
    }
    errno_is_neg_resource(-r.abs())
}

// ── NOT_SUPPORTED ─────────────────────────────────────────────────────────

const NOT_SUPPORTED_SET: &[intmax_t] = &[
    neg_errno(libc::EOPNOTSUPP),
    neg_errno(libc::ENOTTY),
    neg_errno(libc::ENOSYS),
    neg_errno(libc::EAFNOSUPPORT),
    neg_errno(libc::EPFNOSUPPORT),
    neg_errno(libc::EPROTONOSUPPORT),
    neg_errno(libc::ESOCKTNOSUPPORT),
    neg_errno(libc::ENOPROTOOPT),
];

/// `ERRNO_IS_NEG_NOT_SUPPORTED`: operation / feature not supported errors.
pub fn errno_is_neg_not_supported(r: intmax_t) -> bool {
    matches_set(r, NOT_SUPPORTED_SET)
}

/// `ERRNO_IS_NOT_SUPPORTED`: absolute wrapper.
pub fn errno_is_not_supported(r: intmax_t) -> bool {
    if r == intmax_t::MIN {
        return false;
    }
    errno_is_neg_not_supported(-r.abs())
}

// ── IOCTL_NOT_SUPPORTED ───────────────────────────────────────────────────

/// `ERRNO_IS_NEG_IOCTL_NOT_SUPPORTED`: not_supported ∪ `EINVAL`.
pub fn errno_is_neg_ioctl_not_supported(r: intmax_t) -> bool {
    errno_is_neg_not_supported(r) || r == neg_errno(libc::EINVAL)
}

/// `ERRNO_IS_IOCTL_NOT_SUPPORTED`: absolute wrapper.
pub fn errno_is_ioctl_not_supported(r: intmax_t) -> bool {
    if r == intmax_t::MIN {
        return false;
    }
    errno_is_neg_ioctl_not_supported(-r.abs())
}

// ── PRIVILEGE ─────────────────────────────────────────────────────────────

const PRIVILEGE_SET: &[intmax_t] = &[neg_errno(libc::EACCES), neg_errno(libc::EPERM)];

/// `ERRNO_IS_NEG_PRIVILEGE`: permission / privilege errors.
pub fn errno_is_neg_privilege(r: intmax_t) -> bool {
    matches_set(r, PRIVILEGE_SET)
}

/// `ERRNO_IS_PRIVILEGE`: absolute wrapper.
pub fn errno_is_privilege(r: intmax_t) -> bool {
    if r == intmax_t::MIN {
        return false;
    }
    errno_is_neg_privilege(-r.abs())
}

// ── FS_WRITE_REFUSED ──────────────────────────────────────────────────────

/// `ERRNO_IS_NEG_FS_WRITE_REFUSED`: `EROFS` ∪ privilege.
pub fn errno_is_neg_fs_write_refused(r: intmax_t) -> bool {
    r == neg_errno(libc::EROFS) || errno_is_neg_privilege(r)
}

/// `ERRNO_IS_FS_WRITE_REFUSED`: absolute wrapper.
pub fn errno_is_fs_write_refused(r: intmax_t) -> bool {
    if r == intmax_t::MIN {
        return false;
    }
    errno_is_neg_fs_write_refused(-r.abs())
}

// ── DISK_SPACE ────────────────────────────────────────────────────────────

const DISK_SPACE_SET: &[intmax_t] = &[
    neg_errno(libc::ENOSPC),
    neg_errno(libc::EDQUOT),
    neg_errno(libc::EFBIG),
];

/// `ERRNO_IS_NEG_DISK_SPACE`: disk-full / quota errors.
pub fn errno_is_neg_disk_space(r: intmax_t) -> bool {
    matches_set(r, DISK_SPACE_SET)
}

/// `ERRNO_IS_DISK_SPACE`: absolute wrapper.
pub fn errno_is_disk_space(r: intmax_t) -> bool {
    if r == intmax_t::MIN {
        return false;
    }
    errno_is_neg_disk_space(-r.abs())
}

// ── DEVICE_ABSENT ─────────────────────────────────────────────────────────

const DEVICE_ABSENT_SET: &[intmax_t] = &[
    neg_errno(libc::ENODEV),
    neg_errno(libc::ENXIO),
    neg_errno(libc::ENOENT),
];

/// `ERRNO_IS_NEG_DEVICE_ABSENT`: device not found errors.
pub fn errno_is_neg_device_absent(r: intmax_t) -> bool {
    matches_set(r, DEVICE_ABSENT_SET)
}

/// `ERRNO_IS_DEVICE_ABSENT`: absolute wrapper.
pub fn errno_is_device_absent(r: intmax_t) -> bool {
    if r == intmax_t::MIN {
        return false;
    }
    errno_is_neg_device_absent(-r.abs())
}

// ── DEVICE_ABSENT_OR_EMPTY ────────────────────────────────────────────────

/// `ERRNO_IS_NEG_DEVICE_ABSENT_OR_EMPTY`: device_absent ∪ `ENOMEDIUM`.
pub fn errno_is_neg_device_absent_or_empty(r: intmax_t) -> bool {
    errno_is_neg_device_absent(r) || r == neg_errno(libc::ENOMEDIUM)
}

/// `ERRNO_IS_DEVICE_ABSENT_OR_EMPTY`: absolute wrapper.
pub fn errno_is_device_absent_or_empty(r: intmax_t) -> bool {
    if r == intmax_t::MIN {
        return false;
    }
    errno_is_neg_device_absent_or_empty(-r.abs())
}

// ── XATTR_ABSENT ──────────────────────────────────────────────────────────

/// `ERRNO_IS_NEG_XATTR_ABSENT`: `ENODATA`, `ENOENT` ∪ not_supported.
pub fn errno_is_neg_xattr_absent(r: intmax_t) -> bool {
    r == neg_errno(libc::ENODATA) || r == neg_errno(libc::ENOENT) || errno_is_neg_not_supported(r)
}

/// `ERRNO_IS_XATTR_ABSENT`: absolute wrapper.
pub fn errno_is_xattr_absent(r: intmax_t) -> bool {
    if r == intmax_t::MIN {
        return false;
    }
    errno_is_neg_xattr_absent(-r.abs())
}

// ── SECCOMP_FATAL ─────────────────────────────────────────────────────────

const SECCOMP_FATAL_SET: &[intmax_t] = &[
    neg_errno(libc::EPERM),
    neg_errno(libc::EACCES),
    neg_errno(libc::ENOMEM),
    neg_errno(libc::EFAULT),
];

/// `ERRNO_IS_NEG_SECCOMP_FATAL` (from seccomp-util.h).
pub fn errno_is_neg_seccomp_fatal(r: intmax_t) -> bool {
    matches_set(r, SECCOMP_FATAL_SET)
}

/// `ERRNO_IS_SECCOMP_FATAL`: absolute wrapper.
pub fn errno_is_seccomp_fatal(r: intmax_t) -> bool {
    if r == intmax_t::MIN {
        return false;
    }
    errno_is_neg_seccomp_fatal(-r.abs())
}

#[cfg(test)]
mod tests {
    use super::*;

    /* Keep the test inputs tied to the target C errno definitions too. The
     * production core deliberately does not use the project-wide `Errno`
     * enum, because that enum encodes the generic Linux numbering rather than
     * every systemd target's ABI values. */
    struct Errno;

    impl Errno {
        const EACCES: libc::c_int = libc::EACCES;
        const EAGAIN: libc::c_int = libc::EAGAIN;
        const ECONNREFUSED: libc::c_int = libc::ECONNREFUSED;
        const ECONNRESET: libc::c_int = libc::ECONNRESET;
        const EDQUOT: libc::c_int = libc::EDQUOT;
        const EFAULT: libc::c_int = libc::EFAULT;
        const EINTR: libc::c_int = libc::EINTR;
        const EINVAL: libc::c_int = libc::EINVAL;
        const EMFILE: libc::c_int = libc::EMFILE;
        const ENODATA: libc::c_int = libc::ENODATA;
        const ENODEV: libc::c_int = libc::ENODEV;
        const ENOENT: libc::c_int = libc::ENOENT;
        const ENOMEDIUM: libc::c_int = libc::ENOMEDIUM;
        const ENOMEM: libc::c_int = libc::ENOMEM;
        const ENOSPC: libc::c_int = libc::ENOSPC;
        const ENOSYS: libc::c_int = libc::ENOSYS;
        const ENOTTY: libc::c_int = libc::ENOTTY;
        const EOPNOTSUPP: libc::c_int = libc::EOPNOTSUPP;
        const EPERM: libc::c_int = libc::EPERM;
        const EROFS: libc::c_int = libc::EROFS;
        const ETIMEDOUT: libc::c_int = libc::ETIMEDOUT;
    }

    // ── TRANSIENT ──────────────────────────────────────────────────────

    #[test]
    fn test_transient_eagain() {
        assert!(errno_is_neg_transient(neg_errno(Errno::EAGAIN)));
        assert!(errno_is_transient(Errno::EAGAIN as intmax_t));
    }

    #[test]
    fn test_transient_eintr() {
        assert!(errno_is_neg_transient(neg_errno(Errno::EINTR)));
        assert!(errno_is_transient(Errno::EINTR as intmax_t));
    }

    #[test]
    fn test_transient_non_matching() {
        assert!(!errno_is_neg_transient(neg_errno(Errno::EINVAL)));
        assert!(!errno_is_transient(Errno::EINVAL as intmax_t));
    }

    #[test]
    fn test_transient_zero() {
        assert!(!errno_is_neg_transient(0));
        assert!(!errno_is_transient(0));
    }

    // ── DISCONNECT ─────────────────────────────────────────────────────

    #[test]
    fn test_disconnect_econnreset() {
        assert!(errno_is_neg_disconnect(neg_errno(Errno::ECONNRESET)));
        assert!(errno_is_disconnect(Errno::ECONNRESET as intmax_t));
    }

    #[test]
    fn test_disconnect_econnrefused() {
        assert!(errno_is_neg_disconnect(neg_errno(Errno::ECONNREFUSED)));
        assert!(errno_is_disconnect(Errno::ECONNREFUSED as intmax_t));
    }

    #[test]
    fn test_disconnect_etimedout() {
        assert!(errno_is_neg_disconnect(neg_errno(Errno::ETIMEDOUT)));
        assert!(errno_is_disconnect(Errno::ETIMEDOUT as intmax_t));
    }

    #[test]
    fn test_disconnect_non_matching() {
        assert!(!errno_is_neg_disconnect(neg_errno(Errno::EPERM)));
        assert!(!errno_is_disconnect(Errno::EPERM as intmax_t));
    }

    // ── ACCEPT_AGAIN ───────────────────────────────────────────────────

    #[test]
    fn test_accept_again_eopnotsupp() {
        assert!(errno_is_neg_accept_again(neg_errno(Errno::EOPNOTSUPP)));
        assert!(errno_is_accept_again(Errno::EOPNOTSUPP as intmax_t));
    }

    #[test]
    fn test_accept_again_union() {
        assert!(errno_is_neg_accept_again(neg_errno(Errno::ECONNRESET)));
        assert!(errno_is_neg_accept_again(neg_errno(Errno::EAGAIN)));
    }

    #[test]
    fn test_accept_again_non_matching() {
        assert!(!errno_is_neg_accept_again(neg_errno(Errno::ENOMEM)));
    }

    // ── RESOURCE ───────────────────────────────────────────────────────

    #[test]
    fn test_resource_emfile() {
        assert!(errno_is_neg_resource(neg_errno(Errno::EMFILE)));
        assert!(errno_is_resource(Errno::EMFILE as intmax_t));
    }

    #[test]
    fn test_resource_enomem() {
        assert!(errno_is_neg_resource(neg_errno(Errno::ENOMEM)));
        assert!(errno_is_resource(Errno::ENOMEM as intmax_t));
    }

    #[test]
    fn test_resource_non_matching() {
        assert!(!errno_is_neg_resource(neg_errno(Errno::EINVAL)));
    }

    // ── NOT_SUPPORTED ──────────────────────────────────────────────────

    #[test]
    fn test_not_supported_enosys() {
        assert!(errno_is_neg_not_supported(neg_errno(Errno::ENOSYS)));
        assert!(errno_is_not_supported(Errno::ENOSYS as intmax_t));
    }

    #[test]
    fn test_not_supported_enotty() {
        assert!(errno_is_neg_not_supported(neg_errno(Errno::ENOTTY)));
    }

    #[test]
    fn test_not_supported_non_matching() {
        assert!(!errno_is_neg_not_supported(neg_errno(Errno::EPERM)));
    }

    // ── IOCTL_NOT_SUPPORTED ────────────────────────────────────────────

    #[test]
    fn test_ioctl_not_supported_einval() {
        assert!(errno_is_neg_ioctl_not_supported(neg_errno(Errno::EINVAL)));
        assert!(errno_is_ioctl_not_supported(Errno::EINVAL as intmax_t));
    }

    #[test]
    fn test_ioctl_not_supported_from_not_supported() {
        assert!(errno_is_neg_ioctl_not_supported(neg_errno(
            Errno::EOPNOTSUPP
        )));
    }

    #[test]
    fn test_ioctl_not_supported_non_matching() {
        assert!(!errno_is_neg_ioctl_not_supported(neg_errno(Errno::EPERM)));
    }

    // ── PRIVILEGE ──────────────────────────────────────────────────────

    #[test]
    fn test_privilege_eacces() {
        assert!(errno_is_neg_privilege(neg_errno(Errno::EACCES)));
        assert!(errno_is_privilege(Errno::EACCES as intmax_t));
    }

    #[test]
    fn test_privilege_eperm() {
        assert!(errno_is_neg_privilege(neg_errno(Errno::EPERM)));
        assert!(errno_is_privilege(Errno::EPERM as intmax_t));
    }

    #[test]
    fn test_privilege_non_matching() {
        assert!(!errno_is_neg_privilege(neg_errno(Errno::EINVAL)));
    }

    // ── FS_WRITE_REFUSED ───────────────────────────────────────────────

    #[test]
    fn test_fs_write_refused_erofs() {
        assert!(errno_is_neg_fs_write_refused(neg_errno(Errno::EROFS)));
        assert!(errno_is_fs_write_refused(Errno::EROFS as intmax_t));
    }

    #[test]
    fn test_fs_write_refused_eacces() {
        assert!(errno_is_neg_fs_write_refused(neg_errno(Errno::EACCES)));
    }

    #[test]
    fn test_fs_write_refused_non_matching() {
        assert!(!errno_is_neg_fs_write_refused(neg_errno(Errno::EINVAL)));
    }

    // ── DISK_SPACE ─────────────────────────────────────────────────────

    #[test]
    fn test_disk_space_enospc() {
        assert!(errno_is_neg_disk_space(neg_errno(Errno::ENOSPC)));
        assert!(errno_is_disk_space(Errno::ENOSPC as intmax_t));
    }

    #[test]
    fn test_disk_space_edquot() {
        assert!(errno_is_neg_disk_space(neg_errno(Errno::EDQUOT)));
    }

    #[test]
    fn test_disk_space_non_matching() {
        assert!(!errno_is_neg_disk_space(neg_errno(Errno::EINVAL)));
    }

    // ── DEVICE_ABSENT ──────────────────────────────────────────────────

    #[test]
    fn test_device_absent_enodev() {
        assert!(errno_is_neg_device_absent(neg_errno(Errno::ENODEV)));
        assert!(errno_is_device_absent(Errno::ENODEV as intmax_t));
    }

    #[test]
    fn test_device_absent_enoent() {
        assert!(errno_is_neg_device_absent(neg_errno(Errno::ENOENT)));
    }

    #[test]
    fn test_device_absent_non_matching() {
        assert!(!errno_is_neg_device_absent(neg_errno(Errno::EINVAL)));
    }

    // ── DEVICE_ABSENT_OR_EMPTY ─────────────────────────────────────────

    #[test]
    fn test_device_absent_or_empty_enomedium() {
        assert!(errno_is_neg_device_absent_or_empty(neg_errno(
            Errno::ENOMEDIUM
        )));
        assert!(errno_is_device_absent_or_empty(
            Errno::ENOMEDIUM as intmax_t
        ));
    }

    #[test]
    fn test_device_absent_or_empty_from_absent() {
        assert!(errno_is_neg_device_absent_or_empty(neg_errno(
            Errno::ENODEV
        )));
    }

    #[test]
    fn test_device_absent_or_empty_non_matching() {
        assert!(!errno_is_neg_device_absent_or_empty(neg_errno(
            Errno::EINVAL
        )));
    }

    // ── XATTR_ABSENT ───────────────────────────────────────────────────

    #[test]
    fn test_xattr_absent_enodata() {
        assert!(errno_is_neg_xattr_absent(neg_errno(Errno::ENODATA)));
        assert!(errno_is_xattr_absent(Errno::ENODATA as intmax_t));
    }

    #[test]
    fn test_xattr_absent_enoent() {
        assert!(errno_is_neg_xattr_absent(neg_errno(Errno::ENOENT)));
        assert!(errno_is_xattr_absent(Errno::ENOENT as intmax_t));
    }

    #[test]
    fn test_xattr_absent_from_not_supported() {
        assert!(errno_is_neg_xattr_absent(neg_errno(Errno::EOPNOTSUPP)));
    }

    #[test]
    fn test_xattr_absent_non_matching() {
        assert!(!errno_is_neg_xattr_absent(neg_errno(Errno::EINVAL)));
    }

    // ── SECCOMP_FATAL ──────────────────────────────────────────────────

    #[test]
    fn test_seccomp_fatal_eperm() {
        assert!(errno_is_neg_seccomp_fatal(neg_errno(Errno::EPERM)));
        assert!(errno_is_seccomp_fatal(Errno::EPERM as intmax_t));
    }

    #[test]
    fn test_seccomp_fatal_enomem() {
        assert!(errno_is_neg_seccomp_fatal(neg_errno(Errno::ENOMEM)));
    }

    #[test]
    fn test_seccomp_fatal_efault() {
        assert!(errno_is_neg_seccomp_fatal(neg_errno(Errno::EFAULT)));
    }

    #[test]
    fn test_seccomp_fatal_non_matching() {
        assert!(!errno_is_neg_seccomp_fatal(neg_errno(Errno::EINVAL)));
    }

    // ── ABS INTMAX_MIN guard ──────────────────────────────────────────

    #[test]
    fn test_abs_i64_min() {
        assert!(!errno_is_transient(intmax_t::MIN));
        assert!(!errno_is_disconnect(intmax_t::MIN));
        assert!(!errno_is_resource(intmax_t::MIN));
        assert!(!errno_is_not_supported(intmax_t::MIN));
        assert!(!errno_is_privilege(intmax_t::MIN));
        assert!(!errno_is_disk_space(intmax_t::MIN));
        assert!(!errno_is_device_absent(intmax_t::MIN));
        assert!(!errno_is_seccomp_fatal(intmax_t::MIN));
    }

    // ── Zero values ───────────────────────────────────────────────────

    #[test]
    fn test_zero_values() {
        assert!(!errno_is_neg_transient(0));
        assert!(!errno_is_neg_disconnect(0));
        assert!(!errno_is_neg_resource(0));
        assert!(!errno_is_neg_not_supported(0));
        assert!(!errno_is_neg_privilege(0));
        assert!(!errno_is_neg_disk_space(0));
        assert!(!errno_is_neg_device_absent(0));
        assert!(!errno_is_neg_seccomp_fatal(0));
    }

    // ── Positive values on neg functions ───────────────────────────────

    #[test]
    fn test_positive_values_neg_functions() {
        assert!(!errno_is_neg_transient(Errno::EAGAIN as intmax_t));
        assert!(!errno_is_neg_disconnect(Errno::ECONNRESET as intmax_t));
        assert!(!errno_is_neg_resource(Errno::ENOMEM as intmax_t));
    }
}
