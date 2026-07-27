// SPDX-License-Identifier: LGPL-2.1-or-later

//! Shared implementation detail for borrowed static C string tables.
//!
//! Domain modules retain their own table data and exported symbol names. This
//! module centralizes the only raw C-string read needed by ordinary enum table
//! facades, so adding a table does not duplicate unsafe lifetime machinery.

use std::ffi::{c_char, CStr};

pub(crate) type Entry = (i32, &'static [u8]);

#[inline]
pub(crate) fn entry_cstr(bytes: &'static [u8]) -> &'static CStr {
    CStr::from_bytes_with_nul(bytes)
        .expect("FFI string-table entries must contain exactly one trailing NUL")
}

/// View a checked static C-string entry as Rust UTF-8 without its terminator.
///
/// All current table declarations are ASCII protocol names. Keeping this
/// conversion here means each domain owns exactly one NUL-backed literal, and
/// cannot accidentally maintain a second `&str` spelling for its Rust API.
#[inline]
pub(crate) fn entry_str(bytes: &'static [u8]) -> &'static str {
    let bytes = entry_cstr(bytes).to_bytes();
    std::str::from_utf8(bytes).expect("Rust string-table entries must be valid UTF-8")
}

#[inline]
pub(crate) fn to_str(table: &'static [Entry], value: i32) -> Option<&'static str> {
    table
        .iter()
        .find_map(|&(candidate, bytes)| (candidate == value).then_some(entry_str(bytes)))
}

#[inline]
pub(crate) fn from_str(table: &'static [Entry], input: &str) -> Option<i32> {
    table
        .iter()
        .find_map(|&(value, bytes)| (entry_str(bytes) == input).then_some(value))
}

#[inline]
pub(crate) fn to_ptr(table: &'static [Entry], value: i32) -> *const c_char {
    table
        .iter()
        .find_map(|&(candidate, bytes)| (candidate == value).then_some(bytes))
        .map_or(std::ptr::null(), |bytes| entry_cstr(bytes).as_ptr())
}

/// Match a borrowed C string against a static byte table.
///
/// # Safety
///
/// A non-NULL `input` must point to a live NUL-terminated C string for this
/// call. The function reads it without taking ownership.
#[inline]
pub(crate) unsafe fn from_ptr(table: &'static [Entry], input: *const c_char, invalid: i32) -> i32 {
    if input.is_null() {
        return invalid;
    }

    // SAFETY: required by this helper's contract and checked for NULL above.
    let input = unsafe { CStr::from_ptr(input) }.to_bytes();
    table
        .iter()
        .find_map(|&(value, bytes)| (entry_cstr(bytes).to_bytes() == input).then_some(value))
        .unwrap_or(invalid)
}
