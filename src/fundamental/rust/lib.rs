// SPDX-License-Identifier: LGPL-2.1-or-later
//
// systemd-fundamental-rs: Rust twin modules for src/fundamental/
// PORT-SYNC: N/A (crate root, not ported from a single C file)
//
// This crate provides #![no_std] compatible Rust implementations of
// fundamental utilities shared with the EFI boot code (sd-boot).
//
// Sub-modules are each PORT-SYNCed to their respective C headers/sources.
#![deny(unsafe_op_in_unsafe_fn)]
#![no_std]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::manual_is_ascii_check)]
#![allow(clippy::indexing_slicing)]

extern crate alloc;

// ── Module declarations ──────────────────────────────────────────────────

pub mod bootspec;
pub mod chid;
pub mod cleanup;
pub mod confidential_virt;
pub mod edid;
pub mod efi_guid;
pub mod efivars;
pub mod iovec_util;
pub mod logarithm;
pub mod macro_fundamental;
pub mod memory_util;
pub mod sbat;
pub mod sha1;
pub mod sha256;
pub mod string_table;
pub mod string_util;
pub mod strv;
pub mod tpm2_pcr;
pub mod uki;
pub mod unaligned;

// ── Crate-level constants ────────────────────────────────────────────────

pub const EFI_PAGE_SIZE: usize = 4096;

pub const fn efi_size_to_pages(bytes: usize) -> usize {
    bytes.div_ceil(EFI_PAGE_SIZE)
}

pub const EFI_MAX_CONFIGURATION_TABLES: usize = 256;

pub const CHAR16_NULL: u16 = 0;

// ── Crate-level helpers ──────────────────────────────────────────────────

#[inline]
pub const fn div_round_up(n: usize, d: usize) -> usize {
    n.div_ceil(d)
}

pub fn const_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    result == 0
}

pub fn starts_with(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack[..needle.len()] == needle[..]
}

/// Find the first occurrence of `needle` in `haystack`.
pub fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    for (i, &b) in haystack.iter().enumerate() {
        if b == needle {
            return Some(i);
        }
    }
    None
}

/// Reverse the bytes in a slice.
pub fn reverse_bytes(data: &mut [u8]) {
    let len = data.len();
    for i in 0..len / 2 {
        data.swap(i, len - 1 - i);
    }
}

/// Swap two equal-length slices element by element.
pub fn swap_slices(a: &mut [u8], b: &mut [u8]) {
    assert_eq!(a.len(), b.len());
    for i in 0..a.len() {
        core::mem::swap(&mut a[i], &mut b[i]);
    }
}

/// Check if a byte slice contains only ASCII characters.
pub fn is_ascii(data: &[u8]) -> bool {
    data.iter().all(|&b| b.is_ascii())
}

/// Convert a hexadecimal character to its 4-bit value.
pub fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Clamp a value between a minimum and maximum.
#[inline]
pub const fn clamp(value: usize, min: usize, max: usize) -> usize {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

/// Round down to the nearest multiple of `alignment`.
#[inline]
pub const fn round_down(value: usize, alignment: usize) -> usize {
    value / alignment * alignment
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn test_efi_page_size() {
        assert_eq!(EFI_PAGE_SIZE, 4096);
        assert!(is_power_of_2(EFI_PAGE_SIZE as u64));
    }

    #[test]
    fn test_efi_size_to_pages() {
        assert_eq!(efi_size_to_pages(0), 0);
        assert_eq!(efi_size_to_pages(1), 1);
        assert_eq!(efi_size_to_pages(4096), 1);
        assert_eq!(efi_size_to_pages(4097), 2);
        assert_eq!(efi_size_to_pages(8192), 2);
    }

    #[test]
    fn test_div_round_up() {
        assert_eq!(div_round_up(0, 4), 0);
        assert_eq!(div_round_up(1, 4), 1);
        assert_eq!(div_round_up(3, 4), 1);
        assert_eq!(div_round_up(4, 4), 1);
        assert_eq!(div_round_up(5, 4), 2);
        assert_eq!(div_round_up(8, 4), 2);
    }

    #[test]
    fn test_const_time_eq_equal() {
        assert!(const_time_eq(b"hello", b"hello"));
        assert!(const_time_eq(b"", b""));
        assert!(const_time_eq(&[0u8; 256], &[0u8; 256]));
    }

    #[test]
    fn test_const_time_eq_not_equal() {
        assert!(!const_time_eq(b"hello", b"world"));
        assert!(!const_time_eq(b"hello", b"hella"));
        assert!(!const_time_eq(b"short", b"longer"));
    }

    #[test]
    fn test_const_time_eq_single_byte_diff() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[31] = 1;
        assert!(!const_time_eq(&a, &b));
    }

    #[test]
    fn test_starts_with() {
        assert!(starts_with(b"hello world", b"hello"));
        assert!(starts_with(b"hello", b"hello"));
        assert!(starts_with(b"hello", b""));
        assert!(!starts_with(b"hello", b"world"));
        assert!(!starts_with(b"hi", b"hello"));
    }

    #[test]
    fn test_char16_null() {
        assert_eq!(CHAR16_NULL, 0u16);
    }

    #[test]
    fn test_find_byte() {
        assert_eq!(find_byte(b"hello", b'l'), Some(2));
        assert_eq!(find_byte(b"hello", b'z'), None);
        assert_eq!(find_byte(b"", b'a'), None);
        assert_eq!(find_byte(b"aaa", b'a'), Some(0));
    }

    #[test]
    fn test_reverse_bytes() {
        let mut data = [1u8, 2, 3, 4, 5];
        reverse_bytes(&mut data);
        assert_eq!(data, [5, 4, 3, 2, 1]);
    }

    #[test]
    fn test_reverse_bytes_even() {
        let mut data = [1u8, 2, 3, 4];
        reverse_bytes(&mut data);
        assert_eq!(data, [4, 3, 2, 1]);
    }

    #[test]
    fn test_swap_slices() {
        let mut a = [1u8, 2, 3];
        let mut b = [4u8, 5, 6];
        swap_slices(&mut a, &mut b);
        assert_eq!(a, [4, 5, 6]);
        assert_eq!(b, [1, 2, 3]);
    }

    #[test]
    fn test_is_ascii() {
        assert!(is_ascii(b"hello"));
        assert!(is_ascii(b""));
        assert!(!is_ascii(&[0x80u8]));
    }

    #[test]
    fn test_hex_digit() {
        assert_eq!(hex_digit(b'0'), Some(0));
        assert_eq!(hex_digit(b'9'), Some(9));
        assert_eq!(hex_digit(b'a'), Some(10));
        assert_eq!(hex_digit(b'F'), Some(15));
        assert_eq!(hex_digit(b'g'), None);
        assert_eq!(hex_digit(b' '), None);
    }

    #[test]
    fn test_clamp() {
        assert_eq!(clamp(5, 0, 10), 5);
        assert_eq!(clamp(15, 0, 10), 10);
        assert_eq!(clamp(3, 5, 10), 5);
    }

    #[test]
    fn test_round_down() {
        assert_eq!(round_down(17, 8), 16);
        assert_eq!(round_down(16, 8), 16);
        assert_eq!(round_down(7, 8), 0);
        assert_eq!(round_down(0, 4), 0);
    }

    fn is_power_of_2(x: u64) -> bool {
        x != 0 && (x & (x - 1)) == 0
    }
}
