// SPDX-License-Identifier: LGPL-2.1-or-later

use super::*;
use crate::ffi::Errno;
use std::ffi::{CStr, CString};

// TPM2_ALG_* values are C header constants rather than part of this Rust
// module's public ABI. Keep the FFI tests typed to the ABI's uint16_t input.
const TPM2_ALG_SHA1: u16 = 0x4;
const TPM2_ALG_SHA256: u16 = 0xB;
const TPM2_ALG_SHA512: u16 = 0xD;

#[test]
fn bond_mode_roundtrip_and_invalid_lookup() {
    let s = rs_bond_mode_to_string(1);
    assert!(!s.is_null());
    assert_eq!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        unsafe_ffi!(CStr::from_ptr(s)).to_bytes(),
        b"active-backup"
    );

    let in_s = CString::new("active-backup").unwrap();
    assert_eq!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        unsafe_ffi!(rs_bond_mode_from_string(in_s.as_ptr())),
        1
    );

    let bad = CString::new("not-a-mode").unwrap();
    assert_eq!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        unsafe_ffi!(rs_bond_mode_from_string(bad.as_ptr())),
        Errno::EINVAL.to_neg_errno()
    );
}

#[test]
fn static_cstr_comparison_uses_terminator_free_bytes() {
    let a = CString::new("abc").unwrap();
    let c = CString::new("abd").unwrap();

    assert!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        unsafe_ffi!(cstr_eq_static(a.as_ptr(), b"abc\0"))
    );
    // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
    assert!(!unsafe_ffi!(cstr_eq_static(c.as_ptr(), b"abc\0")));
    assert_eq!(static_cstr(b"abc\0").to_bytes(), b"abc");
}

#[test]
fn dns_rcode_table_preserves_the_canonical_yrrset_spelling() {
    let value = rs_dns_rcode_to_string(7);
    assert_eq!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        unsafe_ffi!(CStr::from_ptr(value)).to_bytes(),
        b"YRRSET"
    );
}

#[test]
fn coredump_filter_roundtrip_and_mask() {
    let s = CString::new("private-anonymous shared-dax").unwrap();
    let mut mask = 0u64;
    assert_eq!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        unsafe_ffi!(rs_coredump_filter_mask_from_string(s.as_ptr(), &mut mask)),
        0
    );
    assert_eq!(mask, (1u64 << 0) | (1u64 << 8));
    assert_eq!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        unsafe_ffi!(CStr::from_ptr(rs_coredump_filter_to_string(8))).to_bytes(),
        b"shared-dax"
    );
}

#[test]
fn boolean_string_tables_accept_boolean_inputs() {
    let yes = CString::new("yes").unwrap();
    let no = CString::new("no").unwrap();
    assert_eq!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        unsafe_ffi!(rs_resolve_support_from_string(yes.as_ptr())),
        2
    );
    assert_eq!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        unsafe_ffi!(rs_resolve_support_from_string(no.as_ptr())),
        0
    );
}

#[test]
fn fallback_tables_accept_numeric_values() {
    let value = CString::new("7").unwrap();
    assert_eq!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        unsafe_ffi!(rs_ioprio_class_from_string(value.as_ptr())),
        7
    );
}

#[test]
fn wol_options_string_alloc_formats_set_bits() {
    let mut out = std::ptr::null_mut();
    assert_eq!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        unsafe_ffi!(rs_wol_options_to_string_alloc(
            (1 << 0) | (1 << 5),
            &mut out
        )),
        1
    );
    assert_eq!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        unsafe_ffi!(CStr::from_ptr(out)).to_bytes(),
        b"phy,magic"
    );
    // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
    unsafe_ffi!(crate::ffi::free(out.cast()));
}

#[test]
fn tpm2_hash_helpers_match_known_algorithms() {
    assert_eq!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        rs_tpm2_hash_alg_to_size(TPM2_ALG_SHA256),
        32
    );
    assert_eq!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        unsafe_ffi!(CStr::from_ptr(rs_tpm2_hash_alg_to_string(TPM2_ALG_SHA1))).to_bytes(),
        b"sha1"
    );
    let sha512 = CString::new("sha512").unwrap();
    assert_eq!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        unsafe_ffi!(rs_tpm2_hash_alg_from_string(sha512.as_ptr())),
        TPM2_ALG_SHA512 as i32
    );
}

#[test]
fn nl80211_tables_expose_expected_values() {
    assert_eq!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        unsafe_ffi!(CStr::from_ptr(rs_nl80211_iftype_to_string(6))).to_bytes(),
        b"monitor"
    );
    assert!(
        // SAFETY: this C ABI lookup takes no pointer input and returns only a borrowed static pointer.
        rs_nl80211_cmd_to_string(0).is_null()
    );
}

#[test]
fn tpm2_nvpcr_name_validation_rejects_pcr_alias() {
    let good = CString::new("custom-name").unwrap();
    let bad = CString::new("7").unwrap();
    assert!(
        // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
        unsafe_ffi!(rs_tpm2_nvpcr_name_is_valid(good.as_ptr()))
    );
    // SAFETY: This test controls all input and output lifetimes; returned pointers are validated before dereference and C allocations are released exactly once.
    assert!(!unsafe_ffi!(rs_tpm2_nvpcr_name_is_valid(bad.as_ptr())));
}
