// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=shared.dns-domain-validators; authority=src/shared/dns-domain.c,src/shared/dns-domain.h
//
// DNS domain name validators. Implements RFC 6763 Section 4.1.1 and Section 7.2.
// DNS SRV/DNS-SD type parsing lives in dns_label.rs; this module owns the
// exported validator facades declared by dns_domain_validators.h.

use libc::c_char;

// ── Constants ─────────────────────────────────────────────────────────────

const DNS_LABEL_MAX: usize = 63;

// ── Internal helpers ──────────────────────────────────────────────────────

/// Check if a string contains control characters (0x00-0x1F, 0x7F).
/// Mirrors C `string_has_cc(p, NULL)`.
fn has_control_chars(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7F)
}

/// Common validation for both service names and subtype names.
fn dns_label_name_is_valid(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    // Rust &str is guaranteed valid UTF-8, so no explicit UTF-8 check needed.

    if has_control_chars(name) {
        return false;
    }

    if name.len() > DNS_LABEL_MAX {
        return false;
    }

    true
}

// ── Public API ────────────────────────────────────────────────────────────

/// Validate a DNS service instance name per RFC 6763 Section 4.1.1.
///
/// Port of C `dns_service_name_is_valid()`.
/// Name must be valid UTF-8, contain no control characters,
/// and be 1–63 bytes long.
pub fn dns_service_name_is_valid(name: &str) -> bool {
    dns_label_name_is_valid(name)
}

use std::ffi::CStr;

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_service_name_is_valid(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }
    // SAFETY: the caller guarantees name is a live NUL-terminated C string.
    let s = unsafe_ffi!(CStr::from_ptr(name)).to_str().unwrap_or("");
    dns_service_name_is_valid(s)
}

/// Validate a DNS sub-type name per RFC 6763 Section 7.2.
///
/// Port of C `dns_subtype_name_is_valid()`.
/// Name must be valid UTF-8, contain no control characters,
/// and be 1–63 bytes long.
pub fn dns_subtype_name_is_valid(name: &str) -> bool {
    dns_label_name_is_valid(name)
}

/// C ABI shadow of `dns_subtype_name_is_valid()`.
///
/// # Safety
/// `name` must be NULL or point to a live, NUL-terminated C string borrowed
/// for this call. Invalid UTF-8 fails closed, matching the service-name facade.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_subtype_name_is_valid(name: *const c_char) -> bool {
    if name.is_null() {
        return false;
    }

    // SAFETY: the entry point contract requires a live NUL-terminated string.
    let value = unsafe_ffi!(CStr::from_ptr(name)).to_str().unwrap_or("");
    dns_subtype_name_is_valid(value)
}

/// C ABI shadow of C `dns_srv_type_is_valid()`.
///
/// The byte-level label parser is shared with the DNS-name facade so escaped
/// labels, label-length handling, and the two-label rule stay in one audited
/// implementation.
///
/// # Safety
/// `name` must be NULL or point to a live, NUL-terminated C string borrowed
/// for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dns_srv_type_is_valid(name: *const c_char) -> bool {
    // SAFETY: the entry point contract is exactly the callee's raw C-string
    // contract; the helper performs the NULL check before traversing it.
    unsafe_ffi!(crate::dns_label::rs_dns_srv_type_is_valid(name))
}

/// C ABI shadow of C `dnssd_srv_type_is_valid()`.
///
/// This delegates to the shared DNS-label implementation, which first checks
/// the SRV two-label grammar and then applies the DNS-SD `_tcp`/`_udp` suffix
/// rule.
///
/// # Safety
/// `name` must be NULL or point to a live, NUL-terminated C string borrowed
/// for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dnssd_srv_type_is_valid(name: *const c_char) -> bool {
    // SAFETY: the entry point contract is exactly the callee's raw C-string
    // contract; the helper performs the NULL check before traversing it.
    unsafe_ffi!(crate::dns_label::rs_dnssd_srv_type_is_valid(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── dns_service_name_is_valid tests ────────────────────────────────

    #[test]
    fn service_name_valid_simple() {
        assert!(dns_service_name_is_valid("MyPrinter"));
    }

    #[test]
    fn service_name_valid_with_space() {
        assert!(dns_service_name_is_valid("My Printer"));
    }

    #[test]
    fn service_name_valid_with_underscore() {
        assert!(dns_service_name_is_valid("My_Printer"));
    }

    #[test]
    fn service_name_valid_single_char() {
        assert!(dns_service_name_is_valid("a"));
        assert!(dns_service_name_is_valid("A"));
        assert!(dns_service_name_is_valid("0"));
    }

    #[test]
    fn service_name_valid_special_chars() {
        assert!(dns_service_name_is_valid("hello-world"));
        assert!(dns_service_name_is_valid("Service.Name"));
    }

    #[test]
    fn service_name_valid_utf8() {
        assert!(dns_service_name_is_valid("café"));
    }

    #[test]
    fn service_name_empty_rejected() {
        assert!(!dns_service_name_is_valid(""));
    }

    #[test]
    fn service_name_too_long_rejected() {
        assert!(!dns_service_name_is_valid(&"a".repeat(64)));
    }

    #[test]
    fn service_name_max_length_accepted() {
        assert!(dns_service_name_is_valid(&"a".repeat(63)));
    }

    #[test]
    fn service_name_control_char_rejected() {
        assert!(!dns_service_name_is_valid("\x01test"));
        assert!(!dns_service_name_is_valid("\x1ftest"));
        assert!(!dns_service_name_is_valid("test\x7f"));
        assert!(!dns_service_name_is_valid("te\x0ast"));
    }

    #[test]
    fn service_name_tab_rejected() {
        assert!(!dns_service_name_is_valid("tab\there"));
    }

    #[test]
    fn service_name_null_byte_rejected() {
        // Rust &str can't contain null bytes, but the control char check handles 0x00-0x1F
        // We verify the check covers the full range via has_control_chars
        assert!(has_control_chars("\x00"));
    }

    // ── dns_subtype_name_is_valid tests ────────────────────────────────

    #[test]
    fn subtype_name_valid() {
        assert!(dns_subtype_name_is_valid("_sub"));
        assert!(dns_subtype_name_is_valid("subtype"));
        assert!(dns_subtype_name_is_valid("my-subtype"));
        assert!(dns_subtype_name_is_valid("a"));
    }

    #[test]
    fn subtype_name_empty_rejected() {
        assert!(!dns_subtype_name_is_valid(""));
    }

    #[test]
    fn subtype_name_too_long_rejected() {
        assert!(!dns_subtype_name_is_valid(&"a".repeat(64)));
    }

    #[test]
    fn subtype_name_max_length_accepted() {
        assert!(dns_subtype_name_is_valid(&"a".repeat(63)));
    }

    #[test]
    fn subtype_name_control_char_rejected() {
        assert!(!dns_subtype_name_is_valid("\x01sub"));
        assert!(!dns_subtype_name_is_valid("sub\x1f"));
        assert!(!dns_subtype_name_is_valid("\x7fx"));
    }

    // ── Cross-validation tests ────────────────────────────────────────

    #[test]
    fn both_validators_agree_on_valid() {
        let names = ["valid", "with space", "café", "a", "test-name"];
        for name in names {
            assert_eq!(
                dns_service_name_is_valid(name),
                dns_subtype_name_is_valid(name),
                "validators should agree on: {name}"
            );
        }
    }

    #[test]
    fn both_validators_agree_on_invalid() {
        let invalid = ["", "\x01test", &"a".repeat(64)];
        for name in invalid {
            assert_eq!(
                dns_service_name_is_valid(name),
                dns_subtype_name_is_valid(name),
                "validators should agree on invalid: {name:?}"
            );
        }
    }
}
