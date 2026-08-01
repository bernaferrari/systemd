// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Shared, safe lookup primitives for the multi-source string-table shadow.
//
// Table data remains in the source-domain facade so its PORT-SYNC anchors are
// visible beside the corresponding C names.  This module deliberately has no
// ABI exports and contains the only conversion from an inbound C string to
// bytes; all table matching itself is ordinary safe Rust.

use std::ffi::{CStr, c_char};

pub(crate) type Entry = (i32, &'static [u8]);

/// Validate a static table literal and expose it as a C string.
#[inline]
pub(crate) fn static_cstr(bytes: &'static [u8]) -> &'static CStr {
    CStr::from_bytes_with_nul(bytes)
        .expect("string-table entries must be single, NUL-terminated C strings")
}

#[inline]
pub(crate) fn static_cstr_ptr(bytes: &'static [u8]) -> *const c_char {
    static_cstr(bytes).as_ptr()
}

#[inline]
pub(crate) fn to_cstr(table: &'static [Entry], value: i32) -> Option<&'static CStr> {
    table
        .iter()
        .find_map(|&(candidate, name)| (candidate == value).then(|| static_cstr(name)))
}

#[inline]
pub(crate) fn from_bytes(table: &'static [Entry], input: &[u8]) -> Option<i32> {
    table
        .iter()
        .find_map(|&(value, name)| (static_cstr(name).to_bytes() == input).then_some(value))
}

/// Borrow a caller-owned C string without taking ownership.
///
/// # Safety
/// `input` must be null or point to a live, NUL-terminated C string for the
/// returned borrow's lifetime. The caller retains ownership and must not
/// mutate the bytes while the returned slice is used.
#[inline]
pub(crate) unsafe fn input_bytes<'a>(input: *const c_char) -> Option<&'a [u8]> {
    if input.is_null() {
        return None;
    }

    // SAFETY: required by this function's contract; CStr only reads through
    // the first terminating NUL and the borrow does not outlive this call site.
    Some(unsafe_ffi!(CStr::from_ptr(input)).to_bytes())
}
