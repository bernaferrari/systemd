// SPDX-License-Identifier: LGPL-2.1-or-later
//
// systemd-basic-rs: Rust twin modules for src/basic/
// PORT-SYNC: N/A (crate root, not ported from a C file)
//
// This crate provides Rust implementations of leaf utility functions from
// systemd's src/basic/. Most public modules map directly to one C source
// domain. Modules that deliberately group or split C authorities declare their
// exact provenance in their own PORT-SYNC or PORT-GAP header.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(improper_ctypes_definitions)]
#![deny(clippy::missing_safety_doc)]
#![deny(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::absurd_extreme_comparisons)]
#![allow(clippy::while_immutable_condition)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::comparison_chain)]
#![allow(clippy::len_without_is_empty)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::missing_transmute_annotations)]
#![allow(clippy::manual_is_ascii_check)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::manual_c_str_literals)]
#![allow(clippy::ptr_eq)]
#![allow(clippy::needless_return)]
#![allow(clippy::duplicated_attributes)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::needless_late_init)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::assigning_clones)]
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::partialeq_ne_impl)]
#![allow(clippy::from_over_into)]
#![allow(clippy::unnecessary_literal_unwrap)]
#![allow(clippy::single_match)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::redundant_closure)]

/// Check if string `s` starts with `prefix`. Returns `Some(rest)` on match
/// where `rest` is the substring after the prefix, or `None` on mismatch.
///
/// Equivalent to the C `startswith(s, prefix)` from string-util.h which
/// returns a pointer past the prefix on match, NULL otherwise.
#[inline]
pub fn startswith<'a>(s: &'a str, prefix: &'a str) -> Option<&'a str> {
    s.strip_prefix(prefix)
}

// Public module surface. Keep this alphabetized so source-domain ownership is
// easy to locate without conflating it with private ABI implementation pieces.
#[macro_use]
pub mod ffi;
pub mod af_list;
pub mod alloc_util;
pub mod basic_validators;
pub mod bitmap;
pub mod bus_label;
pub mod capability_util;
pub mod credential_validators;
pub mod device_nodes;
pub mod devnum_util;
pub mod dlfcn_util;
pub mod dns_domain_validators;
pub mod dns_label;
pub mod dns_type_predicates;
pub mod env_util;
pub mod errno_classify;
pub mod errno_util;
pub mod escape;
pub mod ether_addr_util;
pub mod exec_util;
pub mod exit_status;
pub mod extract_word;
pub mod gpt_util;
pub mod gunicode;
pub mod hexdecoct;
pub mod hostname_util;
pub mod id128_util;
pub mod image_policy_util;
pub mod import_util;
pub mod in_addr_util;
pub mod iovec_util;
pub mod iovec_wrapper;
pub mod memory_util;
pub mod mempool;
pub mod misc_validators;
pub mod mount_setup;
pub mod mountpoint_util;
pub mod netdev_str_tables;
pub mod nsflags;
pub mod nulstr_util;
pub mod parse_util;
pub mod path_util;
pub mod pe_binary;
pub mod percent_util;
pub mod prioq;
pub mod process_util_str_tables;
pub mod procfs_util;
pub mod ratelimit;
pub mod rlimit_util;
pub mod seccomp_util;
pub mod serialize;
pub mod sha1;
pub mod sha256_hmac;
pub mod shared_facades;
pub mod signal_util;
pub mod siphash24;
pub mod socket_util;
pub mod sort_util;
pub mod stat_util;
pub mod strbuf;
pub mod string_table;
pub mod string_util;
pub mod strv;
pub mod strverscmp;
pub mod strxcpyx;
pub mod time_util;
pub mod udev_util;
pub mod unaligned;
pub mod unit_def;
pub mod unit_name;
pub mod user_util;
pub mod utf8;
pub mod virt;
pub mod xml_tokenizer;

// Private implementation fragments. Keep these separate from the public
// module surface so a Rust consumer cannot accidentally depend on an ABI helper.
mod ffi_string_table;
mod header_inline_abi;
mod string_util_ffi;
pub mod string_util_fundamental;
mod unit_inline_abi;

pub use std::ffi::c_void;

#[cfg(test)]
mod tests {
    use crate::ffi::Errno;

    // ── startswith tests ───────────────────────────────────────────────

    #[test]
    fn test_startswith_match() {
        assert_eq!(super::startswith("foobar", "foo"), Some("bar"));
    }

    #[test]
    fn test_startswith_exact_match() {
        assert_eq!(super::startswith("hello", "hello"), Some(""));
    }

    #[test]
    fn test_startswith_no_match() {
        assert_eq!(super::startswith("foobar", "baz"), None);
    }

    #[test]
    fn test_startswith_empty_prefix() {
        assert_eq!(super::startswith("hello", ""), Some("hello"));
    }

    #[test]
    fn test_startswith_empty_both() {
        assert_eq!(super::startswith("", ""), Some(""));
    }

    #[test]
    fn test_startswith_prefix_longer() {
        assert_eq!(super::startswith("hi", "hello"), None);
    }

    #[test]
    fn test_startswith_empty_string() {
        assert_eq!(super::startswith("", "a"), None);
    }

    #[test]
    fn test_startswith_single_char() {
        assert_eq!(super::startswith("a", "a"), Some(""));
        assert_eq!(super::startswith("ab", "a"), Some("b"));
    }

    #[test]
    fn test_startswith_slash() {
        assert_eq!(super::startswith("/foo/bar", "/"), Some("foo/bar"));
        assert_eq!(super::startswith("/foo", "/foo"), Some(""));
    }

    // ── Errno roundtrip tests ──────────────────────────────────────────

    #[test]
    fn test_errno_roundtrip() {
        let neg = Errno::EINVAL.to_neg_errno();
        assert!(neg < 0);
        assert_eq!(Errno::from_neg_errno(neg), Some(Errno::EINVAL));
        assert_eq!(Errno::from_raw(-neg), Some(Errno::EINVAL));
    }

    #[test]
    fn test_errno_various() {
        assert_eq!(Errno::ENOENT.to_neg_errno(), -2);
        assert_eq!(Errno::ENOMEM.to_neg_errno(), -12);
        assert_eq!(Errno::EPERM.to_neg_errno(), -1);
    }

    #[test]
    fn test_errno_from_raw_invalid() {
        assert_eq!(Errno::from_raw(0), None);
        assert_eq!(Errno::from_raw(-1), None);
    }

    #[test]
    fn test_errno_from_neg_positive_returns_none() {
        assert_eq!(Errno::from_neg_errno(0), None);
        assert_eq!(Errno::from_neg_errno(22), None);
    }
}
