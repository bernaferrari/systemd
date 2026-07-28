// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/xattr-util.c, src/basic/xattr-util.h
//
// Extended attribute classification utilities.
//
// Provides helpers to identify whether a given xattr name refers to a
// POSIX ACL entry or the SELinux security context, matching the logic
// in the C implementation's `xattr_is_acl()` and `xattr_is_selinux()`.

use std::ffi::CStr;

use libc::c_char;

// ── Constants ─────────────────────────────────────────────────────────────

/// Xattr name for POSIX ACL access entries.
pub const XATTR_POSIX_ACL_ACCESS: &str = "system.posix_acl_access";

/// Xattr name for POSIX ACL default entries.
pub const XATTR_POSIX_ACL_DEFAULT: &str = "system.posix_acl_default";

/// Xattr name for the SELinux security context.
pub const XATTR_SECURITY_SELINUX: &str = "security.selinux";

// ── Classification functions ──────────────────────────────────────────────

/// Returns true if the extended attribute name is a POSIX ACL entry.
///
/// Mirrors C `xattr_is_acl()` from xattr-util.c which checks:
/// ```c
/// STR_IN_SET(ASSERT_PTR(name),
///            "system.posix_acl_access",
///            "system.posix_acl_default");
/// ```
pub fn xattr_is_acl(name: &str) -> bool {
    name == XATTR_POSIX_ACL_ACCESS || name == XATTR_POSIX_ACL_DEFAULT
}

/// Returns true if the extended attribute name is the SELinux security context.
///
/// Mirrors C `xattr_is_selinux()` from xattr-util.c which checks:
/// ```c
/// streq(ASSERT_PTR(name), "security.selinux");
/// ```
pub fn xattr_is_selinux(name: &str) -> bool {
    name == XATTR_SECURITY_SELINUX
}

/// C ABI facade for `xattr_is_acl()`.
///
/// # Safety
/// `name` must be either null or point to a readable NUL-terminated C string.
/// A null pointer is treated as non-matching, keeping the ABI boundary defined
/// even though the C helper asserts its non-null precondition.
#[unsafe(export_name = "rs_xattr_is_acl")]
pub unsafe extern "C" fn rs_xattr_is_acl(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }

    // SAFETY: the C ABI contract requires a readable NUL-terminated string.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    name == XATTR_POSIX_ACL_ACCESS.as_bytes() || name == XATTR_POSIX_ACL_DEFAULT.as_bytes()
}

/// C ABI facade for `xattr_is_selinux()`.
///
/// # Safety
/// `name` must be either null or point to a readable NUL-terminated C string.
/// A null pointer is treated as non-matching, keeping the ABI boundary defined
/// even though the C helper asserts its non-null precondition.
#[unsafe(export_name = "rs_xattr_is_selinux")]
pub unsafe extern "C" fn rs_xattr_is_selinux(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }

    // SAFETY: the C ABI contract requires a readable NUL-terminated string.
    unsafe { CStr::from_ptr(name) }.to_bytes() == XATTR_SECURITY_SELINUX.as_bytes()
}

/// Returns a descriptive label for well-known xattr names, or None.
///
/// Convenience wrapper that classifies the attribute into a human-readable
/// category string.
pub fn xattr_classify(name: &str) -> Option<&'static str> {
    if xattr_is_acl(name) {
        Some("posix-acl")
    } else if xattr_is_selinux(name) {
        Some("selinux")
    } else {
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- xattr_is_acl ----------------------------------------------------------

    #[test]
    fn test_xattr_is_acl_access() {
        assert!(xattr_is_acl("system.posix_acl_access"));
    }

    #[test]
    fn test_xattr_is_acl_default() {
        assert!(xattr_is_acl("system.posix_acl_default"));
    }

    #[test]
    fn test_xattr_is_acl_rejects_other() {
        assert!(!xattr_is_acl("user.comment"));
        assert!(!xattr_is_acl("security.selinux"));
        assert!(!xattr_is_acl("system.posix_acl")); // prefix only
        assert!(!xattr_is_acl(""));
    }

    #[test]
    fn test_xattr_is_acl_is_case_sensitive() {
        assert!(!xattr_is_acl("System.Posix_Acl_Access"));
        assert!(!xattr_is_acl("SYSTEM.POSIX_ACL_ACCESS"));
    }

    #[test]
    fn test_xattr_is_acl_rejects_near_misses() {
        assert!(!xattr_is_acl("system.posix_acl_accessx"));
        assert!(!xattr_is_acl("xsystem.posix_acl_access"));
    }

    // -- xattr_is_selinux ------------------------------------------------------

    #[test]
    fn test_xattr_is_selinux_exact() {
        assert!(xattr_is_selinux("security.selinux"));
    }

    #[test]
    fn test_xattr_is_selinux_rejects_other() {
        assert!(!xattr_is_selinux("security.capability"));
        assert!(!xattr_is_selinux("system.posix_acl_access"));
        assert!(!xattr_is_selinux(""));
    }

    #[test]
    fn test_xattr_is_selinux_case_sensitive() {
        assert!(!xattr_is_selinux("Security.SELinux"));
        assert!(!xattr_is_selinux("SECURITY.SELINUX"));
    }

    #[test]
    fn test_xattr_is_selinux_rejects_near_misses() {
        assert!(!xattr_is_selinux("security.selinuxx"));
        assert!(!xattr_is_selinux("xsecurity.selinux"));
    }

    // -- xattr_classify --------------------------------------------------------

    #[test]
    fn test_xattr_classify_acl() {
        assert_eq!(xattr_classify("system.posix_acl_access"), Some("posix-acl"));
        assert_eq!(
            xattr_classify("system.posix_acl_default"),
            Some("posix-acl")
        );
    }

    #[test]
    fn test_xattr_classify_selinux() {
        assert_eq!(xattr_classify("security.selinux"), Some("selinux"));
    }

    #[test]
    fn test_xattr_classify_unknown() {
        assert_eq!(xattr_classify("user.comment"), None);
        assert_eq!(xattr_classify("security.capability"), None);
        assert_eq!(xattr_classify(""), None);
    }

    // -- constants -------------------------------------------------------------

    #[test]
    fn test_constants_match_strings() {
        assert_eq!(XATTR_POSIX_ACL_ACCESS, "system.posix_acl_access");
        assert_eq!(XATTR_POSIX_ACL_DEFAULT, "system.posix_acl_default");
        assert_eq!(XATTR_SECURITY_SELINUX, "security.selinux");
    }
}
