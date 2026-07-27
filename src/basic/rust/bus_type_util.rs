// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-bus/bus-type.c, src/libsystemd/sd-bus/bus-type.h,
//            src/basic/hash-funcs.c, src/basic/hash-funcs.h
//
// D-Bus type predicates, size/alignment helpers, and small comparison helpers.

use std::ffi::c_void;

use libc::c_char;

use crate::ffi::Errno;

const VALID_TYPES: &[u8] = b"ybnqiuxtdsogvaerh";
const BASIC_TYPES: &[u8] = b"ybnqiuxtdsogh";
const TRIVIAL_TYPES: &[u8] = b"ybnqiuxtd";
const CONTAINER_TYPES: &[u8] = b"avre";

#[inline]
fn cmp_ord<T: Ord>(a: T, b: T) -> i32 {
    match a.cmp(&b) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

#[inline]
fn as_type_byte(c: c_char) -> u8 {
    c as u8
}

#[inline]
fn contains(table: &[u8], c: c_char) -> bool {
    table.contains(&as_type_byte(c))
}

#[inline]
fn gnu_dev_major(dev: u64) -> u32 {
    (((dev & 0x0000_0000_000f_ff00) >> 8) | ((dev & 0xffff_f000_0000_0000) >> 32)) as u32
}

#[inline]
fn gnu_dev_minor(dev: u64) -> u32 {
    ((dev & 0x0000_0000_0000_00ff) | ((dev & 0x0000_0fff_fff0_0000) >> 12)) as u32
}

#[export_name = "rs_bus_type_is_valid"]
pub extern "C" fn rs_bus_type_is_valid(c: c_char) -> bool {
    contains(VALID_TYPES, c)
}

#[export_name = "rs_bus_type_is_basic"]
pub extern "C" fn rs_bus_type_is_basic(c: c_char) -> bool {
    contains(BASIC_TYPES, c)
}

#[export_name = "rs_bus_type_is_trivial"]
pub extern "C" fn rs_bus_type_is_trivial(c: c_char) -> bool {
    contains(TRIVIAL_TYPES, c)
}

#[export_name = "rs_bus_type_is_container"]
pub extern "C" fn rs_bus_type_is_container(c: c_char) -> bool {
    contains(CONTAINER_TYPES, c)
}

fn bus_type_alignment(c: c_char) -> Result<i32, Errno> {
    match as_type_byte(c) {
        b'y' | b'g' | b'v' => Ok(1),
        b'n' | b'q' => Ok(2),
        b'b' | b'i' | b'u' | b's' | b'o' | b'a' | b'h' => Ok(4),
        b'x' | b't' | b'd' | b'r' | b'e' | b'(' | b'{' => Ok(8),
        _ => Err(Errno::EINVAL),
    }
}

#[export_name = "rs_bus_type_get_alignment"]
pub extern "C" fn rs_bus_type_get_alignment(c: c_char) -> i32 {
    bus_type_alignment(c).unwrap_or_else(Errno::to_neg_errno)
}

fn bus_type_size(c: c_char) -> Result<i32, Errno> {
    match as_type_byte(c) {
        b'y' => Ok(1),
        b'n' | b'q' => Ok(2),
        b'b' | b'i' | b'u' | b'h' => Ok(4),
        b'x' | b't' | b'd' => Ok(8),
        _ => Err(Errno::EINVAL),
    }
}

#[export_name = "rs_bus_type_get_size"]
pub extern "C" fn rs_bus_type_get_size(c: c_char) -> i32 {
    bus_type_size(c).unwrap_or_else(Errno::to_neg_errno)
}

#[export_name = "rs_trivial_compare_func"]
pub extern "C" fn rs_trivial_compare_func(a: *const c_void, b: *const c_void) -> i32 {
    cmp_ord(a as usize, b as usize)
}

/// Compare two C `uint64_t` values.
///
/// # Safety
/// `a` and `b` must each point to one readable, properly aligned `uint64_t`.
#[export_name = "rs_uint64_compare_func"]
pub unsafe extern "C" fn rs_uint64_compare_func(a: *const u64, b: *const u64) -> i32 {
    // SAFETY: required by this C ABI entry point's contract.
    unsafe { cmp_ord(*a, *b) }
}

/// Compare two C `dev_t` values by major then minor device number.
///
/// # Safety
/// `a` and `b` must each point to one readable, properly aligned `dev_t`.
#[export_name = "rs_devt_compare_func"]
pub unsafe extern "C" fn rs_devt_compare_func(a: *const u64, b: *const u64) -> i32 {
    // SAFETY: required by this C ABI entry point's contract.
    let (a, b) = unsafe { (*a, *b) };
    let major_cmp = cmp_ord(gnu_dev_major(a), gnu_dev_major(b));
    if major_cmp != 0 {
        return major_cmp;
    }

    cmp_ord(gnu_dev_minor(a), gnu_dev_minor(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dev(major: u32, minor: u32) -> u64 {
        (minor as u64 & 0x0000_00ff)
            | (((major as u64) & 0x0000_0fff) << 8)
            | (((minor as u64) & 0xffff_ff00) << 12)
            | (((major as u64) & 0xffff_f000) << 32)
    }

    #[test]
    fn valid_type_set_matches_c_table() {
        for c in *b"ybnqiuxtdsogvaerh" {
            assert!(rs_bus_type_is_valid(c as c_char));
        }
    }

    #[test]
    fn invalid_types_are_rejected() {
        for c in [b'z', b'A', b' ', 0, b'(', b')', b'{', b'}'] {
            assert!(!rs_bus_type_is_valid(c as c_char));
        }
    }

    #[test]
    fn basic_types_exclude_containers() {
        for c in *b"ybnqiuxtdsogh" {
            assert!(rs_bus_type_is_basic(c as c_char));
        }
        for c in *b"avre" {
            assert!(!rs_bus_type_is_basic(c as c_char));
        }
    }

    #[test]
    fn trivial_types_match_c_table() {
        for c in *b"ybnqiuxtd" {
            assert!(rs_bus_type_is_trivial(c as c_char));
        }
        for c in [b's', b'o', b'g', b'h', b'a'] {
            assert!(!rs_bus_type_is_trivial(c as c_char));
        }
    }

    #[test]
    fn container_types_match_c_table() {
        for c in *b"avre" {
            assert!(rs_bus_type_is_container(c as c_char));
        }
        for c in [b'y', b'b', b's'] {
            assert!(!rs_bus_type_is_container(c as c_char));
        }
    }

    #[test]
    fn alignments_match_c_logic() {
        assert_eq!(rs_bus_type_get_alignment('y' as c_char), 1);
        assert_eq!(rs_bus_type_get_alignment('q' as c_char), 2);
        assert_eq!(rs_bus_type_get_alignment('s' as c_char), 4);
        assert_eq!(rs_bus_type_get_alignment('(' as c_char), 8);
        assert_eq!(
            rs_bus_type_get_alignment('z' as c_char),
            Errno::EINVAL.to_neg_errno()
        );
    }

    #[test]
    fn sizes_match_c_logic() {
        assert_eq!(rs_bus_type_get_size('y' as c_char), 1);
        assert_eq!(rs_bus_type_get_size('n' as c_char), 2);
        assert_eq!(rs_bus_type_get_size('u' as c_char), 4);
        assert_eq!(rs_bus_type_get_size('d' as c_char), 8);
        assert_eq!(
            rs_bus_type_get_size('s' as c_char),
            Errno::EINVAL.to_neg_errno()
        );
    }

    #[test]
    fn trivial_pointer_compare_is_address_based() {
        let a = 1u8;
        let b = 2u8;
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(
                rs_trivial_compare_func(
                    &a as *const _ as *const c_void,
                    &a as *const _ as *const c_void
                ),
                0
            );
            assert_eq!(
                rs_trivial_compare_func(std::ptr::null(), &a as *const _ as *const c_void),
                -1
            );
            assert_eq!(
                rs_trivial_compare_func(&b as *const _ as *const c_void, std::ptr::null()),
                1
            );
        }
    }

    #[test]
    fn uint64_compare_matches_cmp_macro() {
        let a = 10u64;
        let b = 20u64;
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_uint64_compare_func(&a, &a), 0);
            assert!(rs_uint64_compare_func(&a, &b) < 0);
            assert!(rs_uint64_compare_func(&b, &a) > 0);
        }
    }

    #[test]
    fn devt_compare_sorts_by_major_then_minor() {
        let a = make_dev(8, 1);
        let b = make_dev(8, 2);
        let c = make_dev(9, 0);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert!(rs_devt_compare_func(&a, &b) < 0);
            assert!(rs_devt_compare_func(&b, &c) < 0);
            assert_eq!(rs_devt_compare_func(&c, &c), 0);
        }
    }
}
