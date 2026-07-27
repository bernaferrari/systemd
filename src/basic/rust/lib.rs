// SPDX-License-Identifier: LGPL-2.1-or-later
//
// systemd-basic-rs: Rust twin modules for src/basic/
// PORT-SYNC: N/A (crate root, not ported from a C file)
//
// This crate provides Rust implementations of leaf utility functions from
// systemd's src/basic/. Each module has a 1:1 mapping to a C source file.

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
#![allow(clippy::redundant_bool_assert)]
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

pub mod alloc_util;
pub mod af_list;
pub mod bus_error_util;
pub mod bus_type_util;
pub mod ansi_color;
pub mod arphrd_util;
pub mod argv_util;
pub mod architecture;
pub mod bus_label;
pub mod capability_list;
pub mod devnum_util;
pub mod xattr_util;
pub mod device_nodes;
pub mod env_util;
pub mod errno_util;
pub mod escape;
pub mod ether_addr_util;
pub mod extract_word;
pub mod ffi;
mod ffi_string_table;
pub mod format_util;
pub mod hexdecoct;
pub mod glyph_util;
pub mod gunicode;
pub mod hostname_util;
mod header_inline_abi;
pub mod in_addr_util;
pub mod iovec_util;
pub mod iovec_wrapper;
pub mod murmurhash2;
pub mod nulstr_util;
pub mod parse_util;
pub mod path_util;
pub mod percent_util;
pub mod prioq;
pub mod proc_cmdline;
pub mod ratelimit;
pub mod rlimit_util;
pub mod runtime_scope;
pub mod sha256_hmac;
pub mod siphash24;
pub mod sort_util;
pub mod strbuf;
pub mod strv;
pub mod string_table;
pub mod time_util;
pub mod string_util;
mod string_util_fundamental;
mod string_util_ffi;
pub mod uid_range;
pub mod mempool;
pub mod memory_util;
pub mod replace_var;
pub mod signal_util;
pub mod strxcpyx;
pub mod terminal_util;
pub mod syslog_util;
pub mod sysctl_util;
pub mod compress_util;
pub mod confidential_virt;
pub mod cgroup_util_str_tables;
pub mod image_class;
pub mod locale_util;
pub mod log_target;
pub mod process_util_str_tables;
pub mod unit_def;
pub mod utf8;
pub mod virt;
pub mod unit_name;
mod unit_inline_abi;
pub mod install_change;
pub mod unaligned;
pub mod uid_classification;
pub mod safe_math;
pub mod ioprio_util;
pub mod at_flags_util;
pub mod shared_facades;
pub mod errno_classify;
pub mod basic_validators;
pub mod sha1;

pub mod netdev_str_tables;
pub mod dns_type_predicates;
pub mod exit_status;
pub mod xml_tokenizer;
pub mod dns_domain_validators;
pub mod dns_label;
pub mod gpt_util;
pub mod hostname_setup;
pub mod bitmap;
pub mod btrfs_util;
pub mod mountpoint_util;
pub mod credential_validators;
pub mod glob_util;
pub mod fstype_util;
pub mod user_shell_util;
pub mod file_classify;
pub mod misc_validators;
pub mod nsflags;
pub mod udev_util;
pub mod stat_util;
pub mod user_util;
pub mod seccomp_util;
pub mod import_util;
pub mod strverscmp;
pub mod compare_operator;
pub mod dirent_util;
pub mod namespace_util;
pub mod pe_binary;
pub mod procfs_util;
pub mod serialize;
pub mod socket_util;
pub mod specifier_util;
pub mod bootspec_util;
pub mod id128_util;
pub mod image_policy_util;
pub mod exec_util;
pub mod efivars_util;
pub mod capability_util;
pub mod recovery_key;
pub mod mount_setup;
pub mod resize_fs_util;
pub mod edid;

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
