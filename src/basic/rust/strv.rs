// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.strv; authority=src/basic/strv.c,src/basic/strv.h,src/fundamental/strv.h
//
// NULL-terminated string array utility functions.

use std::ffi::{CStr, c_void};
use std::marker::PhantomData;

use libc::c_char;

use crate::ffi::{
    Errno, SIZE_MAX, calloc, free, malloc, memmove, reallocarray, strcasecmp, strcmp, strdup,
    strndup,
};

mod allocating_transforms;
mod matching_escape;

pub use allocating_transforms::{rs_strv_extend_strv, rs_strv_filter_prefix};
pub use matching_escape::{rs_strv_fnmatch_full, rs_strv_shell_escape};

// ── Safe iterator over NULL-terminated string array ────────────────────────

/// Safe iterator over a NULL-terminated string array.
#[derive(Clone)]
struct StrvIter<'a> {
    ptr: *const *const c_char,
    index: usize,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Iterator for StrvIter<'a> {
    type Item = &'a CStr;

    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let entry = self.ptr.add(self.index);
            if (*entry).is_null() {
                return None;
            }
            self.index += 1;
            Some(CStr::from_ptr(*entry))
        }
    }
}

unsafe fn strv_iter(l: *const *const c_char) -> StrvIter<'static> {
    StrvIter {
        ptr: l,
        index: 0,
        _marker: PhantomData,
    }
}

// ── Internal helpers ───────────────────────────────────────────────────────

/// Free an owned NULL-terminated string vector and all of its entries.
///
/// # Safety
/// `l` must be null or an array allocated by the C allocator whose non-null
/// entries are also individually owned C-allocator strings.
unsafe fn free_owned_strv(l: *mut *mut c_char) {
    if l.is_null() {
        return;
    }
    let mut index = 0;
    // SAFETY: the caller guarantees l is readable through its NULL terminator.
    while !unsafe { (*l.add(index)).is_null() } {
        // SAFETY: every non-null entry is an owned C-allocator string.
        unsafe { free((*l.add(index)).cast()) };
        index += 1;
    }
    // SAFETY: l itself is an owned C-allocator array.
    unsafe { free(l.cast()) };
}

/// strcmp_ptr: NULL-aware strcmp. NULL < non-NULL.
unsafe fn strcmp_ptr(a: *const c_char, b: *const c_char) -> i32 {
    if a == b {
        return 0;
    }
    if a.is_null() {
        return -1;
    }
    if b.is_null() {
        return 1;
    }
    // SAFETY: the caller guarantees both non-null arguments are live C strings.
    unsafe { strcmp(a, b) }
}

/// cstr_startswith: returns Some(suffix_ptr) if `s` starts with `prefix`, else None.
/// The returned pointer points into the original C string, past the prefix.
fn cstr_startswith(s: &CStr, prefix: &CStr) -> Option<*const c_char> {
    let s_bytes = s.to_bytes();
    let p_bytes = prefix.to_bytes();
    if s_bytes.starts_with(p_bytes) {
        // SAFETY: the suffix starts within a valid C string and includes its NUL terminator
        Some(unsafe { s.as_ptr().add(p_bytes.len()) })
    } else {
        None
    }
}

/// strv_isempty: true if l is NULL or points to a NULL entry.
unsafe fn strv_isempty(l: *const *const c_char) -> bool {
    // SAFETY: the caller guarantees non-null l points to the first strv entry.
    l.is_null() || unsafe { (*l).is_null() }
}

// ── strv_length ────────────────────────────────────────────────────────────

/// Return the number of strings in the NULL-terminated array `l`.
/// Returns 0 if `l` is NULL.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_length(l: *const *mut c_char) -> usize {
    if l.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees l is a NULL-terminated string vector.
    unsafe { strv_iter(l.cast()) }.count()
}

// ── strv_find ──────────────────────────────────────────────────────────────

/// Find `name` in the NULL-terminated string array `l`.
/// Returns a pointer to the found string, or NULL if not found.
/// The returned pointer points into the original array (do not free).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_find(l: *const *mut c_char, name: *const c_char) -> *mut c_char {
    if name.is_null() || l.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller guarantees name is a live C string.
    let needle = unsafe { CStr::from_ptr(name) };
    // SAFETY: the caller guarantees l is a NULL-terminated string vector.
    for entry in unsafe { strv_iter(l.cast()) } {
        if entry == needle {
            return entry.as_ptr() as *mut c_char;
        }
    }
    std::ptr::null_mut()
}

// ── strv_find_case ─────────────────────────────────────────────────────────

/// Find `name` in the NULL-terminated string array `l` using case-insensitive comparison.
/// Returns a pointer to the found string, or NULL if not found.
/// The returned pointer points into the original array (do not free).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_find_case(
    l: *const *mut c_char,
    name: *const c_char,
) -> *mut c_char {
    if name.is_null() || l.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller guarantees l is a NULL-terminated string vector.
    for entry in unsafe { strv_iter(l.cast()) } {
        // SAFETY: entry and name are live C strings.
        if unsafe { strcasecmp(entry.as_ptr(), name) } == 0 {
            return entry.as_ptr() as *mut c_char;
        }
    }
    std::ptr::null_mut()
}

// ── strv_find_prefix ───────────────────────────────────────────────────────

/// Find a string in `l` that starts with `name` as a prefix.
/// Returns a pointer to the found string, or NULL if not found.
/// The returned pointer points into the original array (do not free).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_find_prefix(
    l: *const *mut c_char,
    name: *const c_char,
) -> *mut c_char {
    if name.is_null() || l.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller guarantees name is a live C string.
    let prefix = unsafe { CStr::from_ptr(name) };
    // SAFETY: the caller guarantees l is a NULL-terminated string vector.
    for entry in unsafe { strv_iter(l.cast()) } {
        if cstr_startswith(entry, prefix).is_some() {
            return entry.as_ptr() as *mut c_char;
        }
    }
    std::ptr::null_mut()
}

// ── strv_find_startswith ───────────────────────────────────────────────────

/// Find a string in `l` that starts with `name` as a prefix.
/// Returns a pointer past the matched prefix, or NULL if not found.
/// The returned pointer points into the original array (do not free).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_find_startswith(
    l: *const *mut c_char,
    name: *const c_char,
) -> *mut c_char {
    if name.is_null() || l.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller guarantees name is a live C string.
    let prefix = unsafe { CStr::from_ptr(name) };
    // SAFETY: the caller guarantees l is a NULL-terminated string vector.
    for entry in unsafe { strv_iter(l.cast()) } {
        if let Some(suffix) = cstr_startswith(entry, prefix) {
            return suffix as *mut c_char;
        }
    }
    std::ptr::null_mut()
}

// ── strv_is_uniq ───────────────────────────────────────────────────────────

/// Check if all strings in `l` are unique (no duplicates).
/// Returns true if all entries are unique or if `l` is NULL.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_is_uniq(l: *const *mut c_char) -> bool {
    if l.is_null() {
        return true;
    }

    // Match the allocation-free nested scan in the C implementation. Apart
    // from preserving its failure-free contract, this keeps allocation and
    // panic paths out of the C ABI boundary.
    // SAFETY: the caller guarantees l is a NULL-terminated string vector.
    let mut entries = unsafe { strv_iter(l.cast()) };
    while let Some(entry) = entries.next() {
        if entries.clone().any(|candidate| entry == candidate) {
            return false;
        }
    }
    true
}

// ── strv_overlap ───────────────────────────────────────────────────────────

/// Check if arrays `a` and `b` have any common elements.
/// Returns true if there is at least one overlap, false otherwise.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_overlap(a: *const *mut c_char, b: *const *mut c_char) -> bool {
    if a.is_null() || b.is_null() {
        return false;
    }
    // SAFETY: the caller guarantees a is a NULL-terminated string vector.
    for ea in unsafe { strv_iter(a.cast()) } {
        // SAFETY: the caller guarantees b is a NULL-terminated string vector.
        for eb in unsafe { strv_iter(b.cast()) } {
            if ea == eb {
                return true;
            }
        }
    }
    false
}

// ── strv_compare ───────────────────────────────────────────────────────────

/// Compare two NULL-terminated string arrays lexicographically.
/// Returns negative if `a` < `b`, zero if equal, positive if `a` > `b`.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_compare(a: *const *mut c_char, b: *const *mut c_char) -> i32 {
    let a = a.cast::<*const c_char>();
    let b = b.cast::<*const c_char>();
    // SAFETY: the caller guarantees both optional vectors are NULL-terminated.
    if unsafe { strv_isempty(a) } {
        // SAFETY: same vector contract.
        if unsafe { strv_isempty(b) } {
            return 0;
        }
        return -1;
    }
    // SAFETY: the caller guarantees b is NULL or a NULL-terminated vector.
    if unsafe { strv_isempty(b) } {
        return 1;
    }
    let mut ai: usize = 0;
    let mut bi: usize = 0;
    loop {
        // SAFETY: ai/bi advance in lockstep only until each vector's terminator.
        let (a_entry, b_entry) = unsafe { (*a.add(ai), *b.add(bi)) };
        let ea = a_entry.is_null();
        let eb = b_entry.is_null();
        if ea && eb {
            return 0;
        }
        // SAFETY: the entries were just read from the live vectors.
        let r = unsafe { strcmp_ptr(a_entry, b_entry) };
        if r != 0 {
            return r;
        }
        ai += 1;
        bi += 1;
    }
}

// ── strv_equal_ignore_order ────────────────────────────────────────────────

/// Check if arrays `a` and `b` contain the same elements regardless of order.
/// Returns true if both arrays have identical sets of strings.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_equal_ignore_order(
    a: *const *mut c_char,
    b: *const *mut c_char,
) -> bool {
    if a == b {
        return true;
    }
    // Every element of a must be in b
    if !a.is_null() {
        // SAFETY: the caller guarantees a is a NULL-terminated string vector.
        for ea in unsafe { strv_iter(a.cast()) } {
            let mut found = false;
            if !b.is_null() {
                // SAFETY: the caller guarantees b is a NULL-terminated string vector.
                for eb in unsafe { strv_iter(b.cast()) } {
                    if ea == eb {
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                return false;
            }
        }
    }
    // Every element of b must be in a
    if !b.is_null() {
        // SAFETY: the caller guarantees b is a NULL-terminated string vector.
        for eb in unsafe { strv_iter(b.cast()) } {
            let mut found = false;
            if !a.is_null() {
                // SAFETY: the caller guarantees a is a NULL-terminated string vector.
                for ea in unsafe { strv_iter(a.cast()) } {
                    if ea == eb {
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                return false;
            }
        }
    }
    true
}

// ── strv_copy_n ────────────────────────────────────────────────────────────

/// Copy up to `n` strings from `l` into a newly allocated array.
/// Returns a malloc'd array (caller must free), or NULL on OOM.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_copy_n(l: *const *mut c_char, n: usize) -> *mut *mut c_char {
    // SAFETY: the caller guarantees l is NULL or a NULL-terminated string vector.
    let total = unsafe { rs_strv_length(l) };
    let count = if n < total { n } else { total };

    // SAFETY: malloc accepts the finite pointer-array size.
    let result = unsafe { malloc((count + 1) * std::mem::size_of::<*mut c_char>()) }.cast();
    if result.is_null() {
        return std::ptr::null_mut();
    }

    let mut copied: usize = 0;
    if !l.is_null() {
        // SAFETY: the caller guarantees l is a NULL-terminated string vector.
        for entry in unsafe { strv_iter(l.cast()) } {
            if copied >= count {
                break;
            }
            // SAFETY: entry is a live C string from the vector.
            let dup = unsafe { strdup(entry.as_ptr()) };
            if dup.is_null() {
                // Free what we've allocated so far
                for j in 0..copied {
                    // SAFETY: entries below copied are owned strdup allocations.
                    unsafe { free(*result.add(j) as *mut c_void) };
                }
                // SAFETY: result is the pointer array allocated above.
                unsafe { free(result.cast()) };
                return std::ptr::null_mut();
            }
            // SAFETY: copied < count keeps the write within result.
            unsafe { *result.add(copied) = dup };
            copied += 1;
        }
    }
    // SAFETY: result reserves one terminator slot after count entries.
    unsafe { *result.add(copied) = std::ptr::null_mut() };
    result
}

// ── strv_remove ────────────────────────────────────────────────────────────

/// Remove all occurrences of `s` from array `l` in-place, freeing removed strings.
/// Returns `l` on success, NULL if `l` or `s` is NULL.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_remove(l: *mut *mut c_char, s: *const c_char) -> *mut *mut c_char {
    if l.is_null() || s.is_null() {
        return std::ptr::null_mut();
    }
    // Two-pointer: f reads, t writes
    let mut f: usize = 0;
    let mut t: usize = 0;
    // SAFETY: the caller guarantees l is writable through its NULL terminator.
    while !unsafe { *l.add(f) }.is_null() {
        // SAFETY: f indexes the live vector and s is a live C string.
        let entry = unsafe { *l.add(f) };
        // SAFETY: entry and s are live C strings.
        if unsafe { strcmp(entry, s) } == 0 {
            // SAFETY: vector entries are owned allocations under strv_remove's contract.
            unsafe { free(entry.cast()) };
        } else {
            // SAFETY: t <= f and both indices are within the vector.
            unsafe { *l.add(t) = entry };
            t += 1;
        }
        f += 1;
    }
    // SAFETY: t is within the original vector allocation.
    unsafe { *l.add(t) = std::ptr::null_mut() };
    l
}

// ── strv_uniq ──────────────────────────────────────────────────────────────

/// Remove duplicate entries from array `l` in-place, keeping first occurrence.
/// Returns `l` on success, NULL if `l` is NULL.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_uniq(l: *mut *mut c_char) -> *mut *mut c_char {
    if l.is_null() {
        return std::ptr::null_mut();
    }
    let mut i: usize = 0;
    // SAFETY: the caller guarantees l is writable through its NULL terminator.
    while !unsafe { *l.add(i) }.is_null() {
        // SAFETY: i indexes a live entry and i+1 points to the remaining suffix.
        unsafe { rs_strv_remove(l.add(i + 1), *l.add(i)) };
        i += 1;
    }
    l
}

// ── strv_sort ──────────────────────────────────────────────────────────────

/// Sort array `l` in-place using strcmp.
/// Returns `l` on success, NULL if `l` is NULL.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_sort(l: *mut *mut c_char) -> *mut *mut c_char {
    if l.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller guarantees l is a NULL-terminated vector.
    let n = unsafe { rs_strv_length(l.cast()) };
    if n > 0 {
        // SAFETY: n was measured from l and excludes the terminator.
        let slice = unsafe { std::slice::from_raw_parts_mut(l, n) };
        // C uses qsort(), whose ordering is unstable and whose operation does
        // not allocate. Rust's unstable slice sort has the same relevant
        // properties and avoids introducing an OOM/panic path at this ABI.
        slice.sort_unstable_by(|a, b| {
            if a.is_null() && b.is_null() {
                std::cmp::Ordering::Equal
            } else if a.is_null() {
                std::cmp::Ordering::Less
            } else if b.is_null() {
                std::cmp::Ordering::Greater
            } else {
                // SAFETY: non-null slice entries are live C strings.
                unsafe { crate::ffi::strcmp(*a, *b) }.cmp(&0)
            }
        });
    }
    l
}

// ── strv_reverse ───────────────────────────────────────────────────────────

/// Reverse the order of strings in array `l` in-place.
/// Returns `l` on success, NULL if `l` is NULL.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_reverse(l: *mut *mut c_char) -> *mut *mut c_char {
    if l.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller guarantees l is a NULL-terminated vector.
    let n = unsafe { rs_strv_length(l.cast()) };
    if n <= 1 {
        return l;
    }
    let half = n / 2;
    for i in 0..half {
        // SAFETY: both indices are below the measured vector length.
        unsafe {
            let tmp = *l.add(i);
            *l.add(i) = *l.add(n - 1 - i);
            *l.add(n - 1 - i) = tmp;
        }
    }
    l
}

// ── strv_skip ──────────────────────────────────────────────────────────────

/// Skip the first `n` entries in array `l`.
/// Returns a pointer into the original array (do not free), or NULL if fewer than `n` entries.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_skip(mut l: *mut *mut c_char, n: usize) -> *mut *mut c_char {
    if l.is_null() {
        return std::ptr::null_mut();
    }
    let mut remaining = n;
    while remaining > 0 {
        // SAFETY: l remains an in-bounds suffix of the caller's vector.
        if unsafe { strv_isempty(l.cast()) } {
            return std::ptr::null_mut();
        }
        // SAFETY: the non-empty check proves another vector slot exists.
        l = unsafe { l.add(1) };
        remaining -= 1;
    }
    // SAFETY: l remains an in-bounds suffix of the caller's vector.
    if unsafe { strv_isempty(l.cast()) } {
        return std::ptr::null_mut();
    }
    l
}

// ── strv_find_closest_prefix ────────────────────────────────────────────

unsafe fn startswith_internal(s: *const c_char, prefix: *const c_char) -> *const c_char {
    if s.is_null() || prefix.is_null() {
        return std::ptr::null();
    }
    // SAFETY: the caller guarantees both pointers are live C strings.
    let p_bytes = unsafe { CStr::from_ptr(prefix) }.to_bytes();
    // SAFETY: as above.
    let s_bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    if s_bytes.len() < p_bytes.len() {
        return std::ptr::null();
    }
    if &s_bytes[..p_bytes.len()] == p_bytes {
        // SAFETY: starts_with proved this offset lies within s.
        unsafe { s.add(p_bytes.len()) }
    } else {
        std::ptr::null()
    }
}

unsafe fn endswith_internal(s: *const c_char, suffix: *const c_char) -> *const c_char {
    if s.is_null() || suffix.is_null() {
        return std::ptr::null();
    }
    // SAFETY: the caller guarantees both pointers are live C strings.
    let suf_bytes = unsafe { CStr::from_ptr(suffix) }.to_bytes();
    // SAFETY: as above.
    let s_bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    let suf_len = suf_bytes.len();
    if s_bytes.len() < suf_len {
        return std::ptr::null();
    }
    if &s_bytes[s_bytes.len() - suf_len..] == suf_bytes {
        // SAFETY: the suffix match proves the computed offset lies within s.
        unsafe { s.add(s_bytes.len() - suf_len) }
    } else {
        std::ptr::null()
    }
}

/// Find the closest matching string in `l` to `name` by prefix match.
/// Returns a pointer to the best match, or NULL if no prefix match found.
/// The returned pointer points into the original array (do not free).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_strv_find_closest_prefix(
    l: *const *const c_char,
    name: *const c_char,
) -> *mut c_char {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller guarantees name is a live C string.
    let name_bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    let mut best_distance: usize = usize::MAX;
    let mut best: *mut c_char = std::ptr::null_mut();

    // SAFETY: the caller guarantees l is a NULL-terminated vector.
    for entry in unsafe { strv_iter(l) } {
        let s_bytes = entry.to_bytes();
        if s_bytes.len() >= name_bytes.len() && &s_bytes[..name_bytes.len()] == name_bytes {
            let n = s_bytes.len() - name_bytes.len();
            if n < best_distance {
                best_distance = n;
                best = entry.as_ptr() as *mut c_char;
            }
        }
    }
    best
}

/// Find the closest matching string in `l` to `name` by Levenshtein distance.
/// Returns a pointer to the best match (distance <= 5), or NULL if none found.
/// The returned pointer points into the original array (do not free).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_strv_find_closest_by_levenshtein(
    l: *const *const c_char,
    name: *const c_char,
) -> *mut c_char {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    let mut best_distance: isize = isize::MAX;
    let mut best: *mut c_char = std::ptr::null_mut();

    // SAFETY: the caller guarantees l is a NULL-terminated vector.
    for entry in unsafe { strv_iter(l) } {
        // SAFETY: entry and name are live C strings.
        let distance = unsafe { crate::string_util::rs_strlevenshtein(entry.as_ptr(), name) };
        if distance < 0 {
            return std::ptr::null_mut();
        }
        if distance > 5 {
            continue;
        }
        if distance < best_distance {
            best_distance = distance;
            best = entry.as_ptr() as *mut c_char;
        }
    }
    best
}

/// Find the closest matching string in `l` to `name` (prefix first, then Levenshtein).
/// Returns a pointer to the best match, or NULL if none found.
/// The returned pointer points into the original array (do not free).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_find_closest(
    l: *const *mut c_char,
    name: *const c_char,
) -> *mut c_char {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: this function forwards the same vector/string contracts.
    let found = unsafe { rs_strv_find_closest_prefix(l.cast(), name) };
    if !found.is_null() {
        return found;
    }
    // SAFETY: this function forwards the same vector/string contracts.
    unsafe { rs_strv_find_closest_by_levenshtein(l.cast(), name) }
}

// ── startswith_strv_internal ────────────────────────────────────────────

/// Check if string `s` starts with any prefix in array `l`.
/// Returns a pointer past the matched prefix, or NULL if no match.
/// The returned pointer points into the original string (do not free).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_startswith_strv_internal(
    s: *const c_char,
    l: *const *mut c_char,
) -> *mut c_char {
    // SAFETY: the caller guarantees l is a NULL-terminated vector.
    for entry in unsafe { strv_iter(l.cast()) } {
        // SAFETY: s and entry are live C strings.
        let found = unsafe { startswith_internal(s, entry.as_ptr()) };
        if !found.is_null() {
            return found as *mut c_char;
        }
    }
    std::ptr::null_mut()
}

// ── endswith_strv_internal ──────────────────────────────────────────────

/// Check if string `s` ends with any suffix in array `l`.
/// Returns a pointer to the matching suffix, or NULL if no match.
/// The returned pointer points into the original string (do not free).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_endswith_strv_internal(
    s: *const c_char,
    l: *const *mut c_char,
) -> *mut c_char {
    // SAFETY: the caller guarantees l is a NULL-terminated vector.
    for entry in unsafe { strv_iter(l.cast()) } {
        // SAFETY: s and entry are live C strings.
        let found = unsafe { endswith_internal(s, entry.as_ptr()) };
        if !found.is_null() {
            return found as *mut c_char;
        }
    }
    std::ptr::null_mut()
}

// ── strv_join_full ──────────────────────────────────────────────────────

/// Join all strings in `l` with `separator`, optional `prefix`, and optional escaping.
/// Returns a malloc'd string (caller must free), or NULL on OOM or invalid args.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_join_full(
    l: *const *mut c_char,
    separator: *const c_char,
    prefix: *const c_char,
    escape_separator: bool,
) -> *mut c_char {
    let sep = if separator.is_null() {
        b" \0"
    } else {
        // SAFETY: the caller guarantees non-null separator is a live C string.
        unsafe { CStr::from_ptr(separator) }.to_bytes_with_nul()
    };
    let k = sep.len() - 1; // strlen(separator)
    let m = if prefix.is_null() {
        0
    } else {
        // SAFETY: the caller guarantees non-null prefix is a live C string.
        unsafe { CStr::from_ptr(prefix) }.to_bytes().len()
    };

    if escape_separator && k != 1 {
        return std::ptr::null_mut();
    }

    // Calculate total size. The C implementation's unchecked arithmetic can
    // wrap for adversarial vectors; fail closed instead of risking a short
    // allocation followed by out-of-bounds writes.
    let mut n: usize = 0;
    // SAFETY: the caller guarantees l is a NULL-terminated vector.
    for (i, entry) in unsafe { strv_iter(l.cast()) }.enumerate() {
        if i > 0 {
            let Some(updated) = n.checked_add(k) else {
                return std::ptr::null_mut();
            };
            n = updated;
        }
        let s_bytes = entry.to_bytes();
        let needs_escaping = escape_separator && s_bytes.contains(&sep[0]);
        let Some(entry_size) = s_bytes
            .len()
            .checked_mul(1 + needs_escaping as usize)
            .and_then(|size| size.checked_add(m))
        else {
            return std::ptr::null_mut();
        };
        let Some(updated) = n.checked_add(entry_size) else {
            return std::ptr::null_mut();
        };
        n = updated;
    }

    let Some(allocation_size) = n.checked_add(1) else {
        return std::ptr::null_mut();
    };
    // SAFETY: calloc accepts the checked finite size computed above.
    let buf = unsafe { calloc(allocation_size, 1) }.cast();
    if buf.is_null() {
        return std::ptr::null_mut();
    }

    let mut pos: usize = 0;
    // SAFETY: the caller guarantees l is a NULL-terminated vector.
    for (i, entry) in unsafe { strv_iter(l.cast()) }.enumerate() {
        if i > 0 {
            // stpcpy: copy separator
            for j in 0..k {
                // SAFETY: n includes every separator byte written here.
                unsafe { *buf.add(pos) = sep[j] as c_char };
                pos += 1;
            }
        }

        if !prefix.is_null() {
            // SAFETY: the caller guarantees prefix is a live C string.
            let p_bytes = unsafe { CStr::from_ptr(prefix) }.to_bytes();
            for j in 0..p_bytes.len() {
                // SAFETY: n includes every prefix byte written here.
                unsafe { *buf.add(pos) = p_bytes[j] as c_char };
                pos += 1;
            }
        }

        let s_bytes = entry.to_bytes();
        let needs_escaping = escape_separator && s_bytes.contains(&sep[0]);

        if needs_escaping {
            for j in 0..s_bytes.len() {
                if s_bytes[j] == sep[0] {
                    // SAFETY: n includes every required escape byte.
                    unsafe { *buf.add(pos) = b'\\' as c_char };
                    pos += 1;
                }
                // SAFETY: n includes every entry byte and escape byte.
                unsafe { *buf.add(pos) = s_bytes[j] as c_char };
                pos += 1;
            }
        } else {
            for j in 0..s_bytes.len() {
                // SAFETY: n includes every entry byte written here.
                unsafe { *buf.add(pos) = s_bytes[j] as c_char };
                pos += 1;
            }
        }
    }

    // SAFETY: calloc reserved one final terminator byte.
    unsafe { *buf.add(pos) = 0 };
    buf
}

// ── strv_sort_uniq ──────────────────────────────────────────────────────

unsafe fn streq_ptr(a: *const c_char, b: *const c_char) -> bool {
    // SAFETY: this helper forwards its optional C-string contracts.
    (unsafe { strcmp_ptr(a, b) }) == 0
}

/// Sort array and remove duplicate entries in-place.
/// Returns the original array on success, NULL on OOM.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_sort_uniq(l: *mut *mut c_char) -> *mut *mut c_char {
    // SAFETY: the caller guarantees non-null l points to the first vector entry.
    if l.is_null() || unsafe { (*l).is_null() } {
        return l;
    }

    // Sort
    // SAFETY: this function forwards the mutable vector contract.
    unsafe { rs_strv_sort(l) };

    let mut tail = l;
    let mut prev: *const c_char = std::ptr::null();
    let mut i = l;

    // SAFETY: i advances within the caller's NULL-terminated vector.
    while !unsafe { (*i).is_null() } {
        // SAFETY: i points to a live vector entry.
        let entry = unsafe { *i };
        // SAFETY: entry and optional prev satisfy streq_ptr's contract.
        if unsafe { streq_ptr(entry, prev) } {
            // SAFETY: duplicate vector entries are owned allocations.
            unsafe { free(entry.cast()) };
        } else {
            // SAFETY: tail never advances beyond i.
            unsafe { *tail = entry };
            prev = entry;
            // SAFETY: tail remains within the vector allocation.
            tail = unsafe { tail.add(1) };
        }
        // SAFETY: the loop condition proved i points before the terminator.
        i = unsafe { i.add(1) };
    }
    // SAFETY: tail remains within the vector allocation.
    unsafe { *tail = std::ptr::null_mut() };
    l
}

// ── strv_push_pair ───────────────────────────────────────────────────────

/// Append a pair of strings (a, b) to the string array. NULL values are skipped.
/// Returns 0 on success, -ENOMEM on failure.
/// Returns 0 on success, -ENOMEM on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_push_pair(
    l: *mut *mut *mut c_char,
    a: *mut c_char,
    b: *mut c_char,
) -> i32 {
    if l.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    if a.is_null() && b.is_null() {
        return 0;
    }

    // SAFETY: the caller guarantees *l is NULL or a NULL-terminated vector.
    let n = unsafe { rs_strv_length(*l as *const *mut c_char) };

    if n > SIZE_MAX - 3 {
        return Errno::ENOMEM.to_neg_errno();
    }

    let extra = (if !a.is_null() { 1 } else { 0 }) + (if !b.is_null() { 1 } else { 0 });
    let new_len = crate::basic_validators::rs_GREEDY_ALLOC_ROUND_UP(n + extra + 1);
    // SAFETY: l is writable, and reallocarray receives the current allocation
    // with a finite rounded element count.
    let c = unsafe {
        reallocarray(
            *l as *mut c_void,
            new_len,
            std::mem::size_of::<*mut c_char>(),
        )
    }
    .cast();
    if c.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: l is writable by the caller contract.
    unsafe { *l = c };
    let mut idx = n;
    if !a.is_null() {
        // SAFETY: c reserves n+extra+1 entries.
        unsafe { *c.add(idx) = a };
        idx += 1;
    }
    if !b.is_null() {
        // SAFETY: c reserves n+extra+1 entries.
        unsafe { *c.add(idx) = b };
        idx += 1;
    }
    // SAFETY: c reserves the final NULL terminator slot.
    unsafe { *c.add(idx) = std::ptr::null_mut() };

    0
}

// ── strv_insert ──────────────────────────────────────────────────────────

/// Insert value at position in the string array.
/// Returns 0 on success, -ENOMEM on failure.
/// Returns 0 on success, -ENOMEM on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_insert(
    l: *mut *mut *mut c_char,
    position: usize,
    value: *mut c_char,
) -> i32 {
    if l.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    if value.is_null() {
        return 0;
    }

    // SAFETY: the caller guarantees *l is NULL or a NULL-terminated vector.
    let n = unsafe { rs_strv_length(*l as *const *mut c_char) };
    let pos = if position < n { position } else { n };

    if n > SIZE_MAX - 2 {
        return Errno::ENOMEM.to_neg_errno();
    }
    let m = n + 2;

    // SAFETY: l is writable, and reallocarray receives the current allocation
    // with a finite rounded element count.
    let c = unsafe {
        reallocarray(
            *l as *mut c_void,
            crate::basic_validators::rs_GREEDY_ALLOC_ROUND_UP(m),
            std::mem::size_of::<*mut c_char>(),
        )
    }
    .cast();
    if c.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: l is writable by the caller contract.
    unsafe { *l = c };
    // Shift entries to make room (only if inserting before end)
    if n > pos {
        // SAFETY: both ranges are within c and memmove permits their overlap.
        unsafe {
            memmove(
                c.add(pos + 1).cast(),
                c.add(pos).cast(),
                (n - pos) * std::mem::size_of::<*mut c_char>(),
            )
        };
    }
    // SAFETY: c reserves n+2 entries.
    unsafe {
        *c.add(pos) = value;
        *c.add(n + 1) = std::ptr::null_mut();
    }

    0
}

// ── strv_copy_unless_empty ───────────────────────────────────────────────

/// Copy string array only if non-empty.
/// Returns 0 if empty, 1 if copied, negative errno on OOM.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_copy_unless_empty(
    l: *const *mut c_char,
    ret: *mut *mut *mut c_char,
) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: the caller guarantees non-null l points to the first vector entry.
    if l.is_null() || unsafe { (*l).is_null() } {
        // SAFETY: ret is non-null and writable.
        unsafe { *ret = std::ptr::null_mut() };
        return 0;
    }

    // SAFETY: this function forwards the vector contract.
    let copy = unsafe { rs_strv_copy_n(l.cast(), SIZE_MAX) };
    if copy.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: ret is non-null and writable.
    unsafe { *ret = copy };
    1
}

// ── strv_extend_n ───────────────────────────────────────────────────────

/// Extend strv a with n copies of strdup(s).
/// Returns 0 on success, negative errno on OOM.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_extend_n(
    a: *mut *mut *mut c_char,
    s: *const c_char,
    n: usize,
) -> i32 {
    if a.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    if s.is_null() {
        return 0;
    }
    if n == 0 {
        return 0;
    }

    // SAFETY: the caller guarantees *a is NULL or a NULL-terminated vector.
    let k = unsafe { rs_strv_length(*a as *const *mut c_char) };
    if k >= SIZE_MAX - n {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: a is writable, and reallocarray receives the current allocation
    // with a finite rounded element count.
    let nl = unsafe {
        reallocarray(
            *a as *mut c_void,
            crate::basic_validators::rs_GREEDY_ALLOC_ROUND_UP(k + n + 1),
            std::mem::size_of::<*mut c_char>(),
        )
    }
    .cast();
    if nl.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    // SAFETY: a is writable by the caller contract.
    unsafe { *a = nl };

    let mut i = k;
    while i < k + n {
        // SAFETY: s is a live C string and i is within the expanded vector.
        unsafe { *nl.add(i) = strdup(s) };
        // SAFETY: i is within the expanded vector.
        if unsafe { (*nl.add(i)).is_null() } {
            let mut j = k;
            while j < i {
                // SAFETY: entries in [k, i) are owned strdup allocations.
                unsafe { free(*nl.add(j) as *mut c_void) };
                j += 1;
            }
            // SAFETY: k is within the expanded vector.
            unsafe { *nl.add(k) = std::ptr::null_mut() };
            return Errno::ENOMEM.to_neg_errno();
        }
        i += 1;
    }
    // SAFETY: the expanded vector reserves a final terminator slot.
    unsafe { *nl.add(i) = std::ptr::null_mut() };
    0
}

// ── strv_consume_prepend ────────────────────────────────────────────────

/// Prepend s to strv *l, taking ownership of s.
/// Returns 0 on success, negative errno on failure.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_consume_prepend(l: *mut *mut *mut c_char, s: *mut c_char) -> i32 {
    if l.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    if s.is_null() {
        return 0;
    }
    // SAFETY: this function forwards l's ownership contract and transfers s.
    if unsafe { rs_strv_insert(l, 0, s) } < 0 {
        // SAFETY: insertion failed, so this function still owns s.
        unsafe { free(s.cast()) };
        return Errno::ENOMEM.to_neg_errno();
    }
    0
}

// ── strv_prepend ────────────────────────────────────────────────────────

/// Prepend a copy of s to strv *l.
/// Returns 0 on success, negative errno on OOM.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_prepend(l: *mut *mut *mut c_char, s: *const c_char) -> i32 {
    if s.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees s is a live C string.
    let v = unsafe { strdup(s) };
    if v.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    // SAFETY: this function forwards l's ownership contract and transfers v.
    if unsafe { rs_strv_consume_prepend(l, v) } < 0 {
        return Errno::ENOMEM.to_neg_errno();
    }
    0
}

// ── strv_extend_strv ────────────────────────────────────────────────────

// ── strv_push_with_size ─────────────────────────────────────────────────
// Low-level push with optional size tracking for preallocation.

/// Push value onto strv, optionally tracking allocated size.
/// Does not take ownership on failure. Returns 0 on success, negative errno on
/// failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_push_with_size(
    l: *mut *mut *mut c_char,
    size: *mut usize,
    value: *mut c_char,
) -> i32 {
    if value.is_null() {
        return 0;
    }
    if l.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: the caller guarantees non-null size is readable and writable.
    let mut sz = if !size.is_null() {
        unsafe { *size }
    } else {
        SIZE_MAX
    };
    if sz == SIZE_MAX {
        // SAFETY: the caller guarantees *l is NULL or a NULL-terminated vector.
        sz = unsafe { rs_strv_length(*l as *const *mut c_char) };
    }

    if sz > SIZE_MAX - 2 {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: l is writable, and reallocarray receives the current allocation
    // with a finite rounded element count.
    let c = unsafe {
        reallocarray(
            *l as *mut c_void,
            crate::basic_validators::rs_GREEDY_ALLOC_ROUND_UP(sz + 2),
            std::mem::size_of::<*mut c_char>(),
        )
    }
    .cast();
    if c.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: c reserves sz+2 entries.
    unsafe {
        *c.add(sz) = value;
        *c.add(sz + 1) = std::ptr::null_mut();
    }

    if !size.is_null() {
        // SAFETY: non-null size is writable by the caller contract.
        unsafe { *size = sz + 1 };
    }

    // SAFETY: l is writable by the caller contract.
    unsafe { *l = c };
    0
}

// ── strv_consume_with_size ───────────────────────────────────────────────

/// Push `value` onto `*l`, consuming and freeing it if the push fails.
///
/// # Safety
/// `l` must be writable and contain null or a C-allocator-owned,
/// NULL-terminated vector. Non-null `n` must be writable and either hold the
/// exact vector length or `SIZE_MAX`. Non-null `value` must be a uniquely owned
/// C-allocator string whose ownership transfers to this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_consume_with_size(
    l: *mut *mut *mut c_char,
    n: *mut usize,
    value: *mut c_char,
) -> i32 {
    // SAFETY: this function forwards the vector and optional size contracts.
    let result = unsafe { rs_strv_push_with_size(l, n, value) };
    if result < 0 && !value.is_null() {
        // SAFETY: push_with_size leaves value ownership with the caller on
        // failure, and this consuming wrapper owns it exactly once.
        unsafe { free(value.cast()) };
    }
    result
}

// ── strv_consume ─────────────────────────────────────────────────────────
// Pushes string, takes ownership. Frees s on error.

/// Push s onto strv *l, taking ownership of s.
/// Returns 0 on success, negative errno on failure.
/// Returns 0 on success, negative errno on failure.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_consume(l: *mut *mut *mut c_char, s: *mut c_char) -> i32 {
    // SAFETY: this function forwards l's ownership contract and transfers s.
    unsafe { rs_strv_consume_with_size(l, std::ptr::null_mut(), s) }
}

// ── strv_extend ──────────────────────────────────────────────────────────
// Pushes a strdup copy of s onto strv.

/// Push a copy of s onto strv *l.
/// Returns 0 on success, negative errno on OOM.
/// Returns 0 on success, negative errno on OOM.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_extend(l: *mut *mut *mut c_char, s: *const c_char) -> i32 {
    if s.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees s is a live C string.
    let v = unsafe { strdup(s) };
    if v.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    // SAFETY: this function forwards l's ownership contract and transfers v.
    if unsafe { rs_strv_consume(l, v) } < 0 {
        // rs_strv_consume already freed v on failure
        return Errno::ENOMEM.to_neg_errno();
    }
    0
}

// ── strv_extend_assignment ───────────────────────────────────────────────

/// Add "lhs=rhs" to the array. If rhs is NULL, does nothing.
/// Returns 0 on success, negative errno on OOM.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_extend_assignment(
    l: *mut *mut *mut c_char,
    lhs: *const c_char,
    rhs: *const c_char,
) -> i32 {
    if rhs.is_null() {
        return 0;
    }

    // Build "lhs=rhs" string
    // SAFETY: the caller guarantees lhs and rhs are live C strings.
    let lhs_len = unsafe { crate::ffi::strlen(lhs) };
    // SAFETY: as above.
    let rhs_len = unsafe { crate::ffi::strlen(rhs) };
    // total = lhs_len + 1 (=) + rhs_len + 1 (NUL)
    if lhs_len >= SIZE_MAX - rhs_len - 2 {
        return Errno::ENOMEM.to_neg_errno();
    }
    let total = lhs_len + 1 + rhs_len + 1;

    // SAFETY: malloc accepts the checked finite total.
    let j = unsafe { crate::ffi::malloc(total) }.cast();
    if j.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // Copy lhs
    // SAFETY: lhs is readable for lhs_len bytes and j owns total bytes.
    unsafe { std::ptr::copy_nonoverlapping(lhs, j, lhs_len) };
    // Copy '='
    // SAFETY: lhs_len is within the total allocation.
    unsafe { *j.add(lhs_len) = b'=' as c_char };
    // Copy rhs
    // SAFETY: rhs is readable for rhs_len bytes and the destination range is in j.
    unsafe { std::ptr::copy_nonoverlapping(rhs, j.add(lhs_len + 1), rhs_len) };
    // NUL terminate
    // SAFETY: total reserves the final NUL slot.
    unsafe { *j.add(lhs_len + 1 + rhs_len) = 0 };

    // SAFETY: this function forwards l's ownership contract and transfers j.
    if unsafe { rs_strv_consume(l, j) } < 0 {
        return Errno::ENOMEM.to_neg_errno();
    }
    0
}

// ── strv_split_full ─────────────────────────────────────────────────────

/// Split string s by separators into a new string array.
/// Returns number of entries on success, negative errno on failure.
/// Caller must free the returned array.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_split_full(
    t: *mut *mut *mut c_char,
    s: *const c_char,
    separators: *const c_char,
    flags: u32,
) -> i32 {
    if t.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut l: *mut *mut c_char = std::ptr::null_mut();
    let mut n: usize = 0;
    let mut p = s;

    loop {
        let mut word: *mut c_char = std::ptr::null_mut();
        // SAFETY: p/word are writable locals and s/separators satisfy the caller contract.
        let r = unsafe {
            crate::extract_word::rs_extract_first_word(&mut p, &mut word, separators, flags)
        };
        if r < 0 {
            // Cleanup
            let mut j: usize = 0;
            while j < n {
                // SAFETY: entries below n are owned allocations in l.
                unsafe { free(*l.add(j) as *mut c_void) };
                j += 1;
            }
            if !l.is_null() {
                // SAFETY: l is the pointer array allocated by this function.
                unsafe { free(l.cast()) };
            }
            return r;
        }
        if r == 0 {
            break;
        }

        // GREEDY_REALLOC(l, n + 2)
        // SAFETY: reallocarray receives this function's current allocation and
        // a finite rounded element count.
        let new_l = unsafe {
            reallocarray(
                l.cast(),
                crate::basic_validators::rs_GREEDY_ALLOC_ROUND_UP(n + 2),
                std::mem::size_of::<*mut c_char>(),
            )
        }
        .cast();
        if new_l.is_null() {
            // Cleanup
            let mut j: usize = 0;
            while j < n {
                // SAFETY: entries below n are owned allocations in l.
                unsafe { free(*l.add(j) as *mut c_void) };
                j += 1;
            }
            // SAFETY: word ownership was returned by rs_extract_first_word.
            unsafe { free(word.cast()) };
            if !l.is_null() {
                // SAFETY: l is the pointer array allocated by this function.
                unsafe { free(l.cast()) };
            }
            return Errno::ENOMEM.to_neg_errno();
        }
        l = new_l;
        // SAFETY: new_l reserves n+2 entries.
        unsafe { *l.add(n) = word };
        n += 1;
        // SAFETY: new_l reserves the final NULL terminator slot.
        unsafe { *l.add(n) = std::ptr::null_mut() };
    }

    // C behavior: if no words found, allocate empty array [NULL]
    if l.is_null() {
        // SAFETY: calloc accepts one pointer-sized element.
        l = unsafe { calloc(1, std::mem::size_of::<*mut c_char>()) }.cast();
        if l.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
    }

    // SAFETY: t is non-null and writable by the caller contract.
    unsafe { *t = l };
    n as i32
}

// ── strv_split_newlines_full / strv_split_newlines ───────────────────────

const NEWLINE: &[u8] = b"\n\r\0";

/// Split string by newlines into a new string array.
/// Returns number of entries on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_split_newlines_full(
    ret: *mut *mut *mut c_char,
    s: *const c_char,
    flags: u32,
) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut l: *mut *mut c_char = std::ptr::null_mut();
    // SAFETY: s is caller-validated, l is a writable local, and NEWLINE is static.
    let r = unsafe { rs_strv_split_full(&mut l, s, NEWLINE.as_ptr().cast(), flags) };
    if r < 0 {
        return r;
    }

    // SAFETY: l is NULL or the vector returned by rs_strv_split_full.
    let n = unsafe { rs_strv_length(l.cast()) };
    // Suppress trailing empty string
    if n > 0 && !l.is_null() {
        // SAFETY: n > 0 bounds the final entry access.
        let last = unsafe { *l.add(n - 1) };
        // SAFETY: non-null last is a live C string.
        if !last.is_null() && unsafe { *last } == 0 {
            // isempty check
            // SAFETY: last is an owned split allocation and the vector slot is writable.
            unsafe {
                free(last.cast());
                *l.add(n - 1) = std::ptr::null_mut();
            }
        }
    }

    // SAFETY: ret is non-null and writable by the caller contract.
    unsafe { *ret = l };
    // Return count (may be less than r if trailing empty was suppressed)
    // SAFETY: l remains a valid NULL-terminated vector.
    (unsafe { rs_strv_length(l.cast()) }) as i32
}

/// Split string by newlines, returning a new array or NULL on error.
/// Caller must free the returned array.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_split_newlines(s: *const c_char) -> *mut *mut c_char {
    let mut ret: *mut *mut c_char = std::ptr::null_mut();
    // SAFETY: s is caller-validated and ret is a writable local.
    if unsafe { rs_strv_split_newlines_full(&mut ret, s, 0) } < 0 {
        return std::ptr::null_mut();
    }
    ret
}

// ── strv_rebreak_lines ───────────────────────────────────────────────────

/// Re-break lines to fit within the given console width.
/// Returns 0 on success, negative errno on OOM.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_rebreak_lines(
    l: *mut *mut c_char,
    width: usize,
    ret: *mut *mut *mut c_char,
) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut broken: *mut *mut c_char = std::ptr::null_mut();

    if width == SIZE_MAX {
        // NOP: just copy
        // SAFETY: this function forwards l's vector contract.
        let copy = unsafe { rs_strv_copy_n(l.cast(), SIZE_MAX) };
        if copy.is_null() && !l.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        // SAFETY: ret is non-null and writable by the caller contract.
        unsafe { *ret = copy };
        return 0;
    }

    if l.is_null() {
        // SAFETY: ret is non-null and writable by the caller contract.
        unsafe { *ret = std::ptr::null_mut() };
        return 0;
    }

    let mut i: usize = 0;
    // SAFETY: the caller guarantees l is readable through its NULL terminator.
    while !unsafe { (*l.add(i)).is_null() } {
        // SAFETY: i currently indexes a live vector entry.
        let line = unsafe { *l.add(i) };
        let mut start = line;
        let mut whitespace_begin: *const c_char = std::ptr::null();
        let mut whitespace_end: *const c_char = std::ptr::null();
        let mut in_prefix: bool = true;
        let mut w: usize = 0;
        let mut p = line;

        // SAFETY: each line is a live NUL-terminated C string.
        while unsafe { *p } != 0 {
            // SAFETY: p currently points before the terminating NUL.
            let ch = unsafe { *p } as u8;

            if NEWLINE.contains(&ch) {
                in_prefix = true;
                whitespace_begin = std::ptr::null();
                whitespace_end = std::ptr::null();
                w = 0;
            } else if crate::ffi::is_whitespace(ch) {
                if !in_prefix && (whitespace_begin.is_null() || !whitespace_end.is_null()) {
                    whitespace_begin = p;
                    whitespace_end = std::ptr::null();
                }
            } else {
                if !whitespace_begin.is_null() && whitespace_end.is_null() {
                    whitespace_end = p;
                }
                in_prefix = false;
            }

            let mut unichar = 0_u32;
            // SAFETY: p points to a live suffix of the current C string.
            let encoded_len = unsafe { crate::utf8::rs_utf8_encoded_to_unichar(p, &mut unichar) };
            if encoded_len < 0 {
                // C rejects the complete operation on malformed UTF-8 without
                // publishing the partially accumulated result.
                // SAFETY: broken is the owned vector accumulated by this function.
                unsafe { free_owned_strv(broken) };
                return encoded_len;
            }
            // SAFETY: decoding above proved p begins a valid UTF-8 scalar.
            let cw = unsafe { crate::utf8::rs_utf8_char_console_width(p) };
            debug_assert!(cw >= 0);
            w += cw as usize;

            if w > width && !whitespace_begin.is_null() && !whitespace_end.is_null() {
                // Break here
                // SAFETY: start and whitespace_begin lie within the same C string.
                let segment_len = unsafe { whitespace_begin.offset_from(start) } as usize;
                // SAFETY: start is readable for segment_len bytes.
                let truncated = unsafe { strndup(start, segment_len) };
                if truncated.is_null() {
                    // SAFETY: broken is the owned vector accumulated by this function.
                    unsafe { free_owned_strv(broken) };
                    return Errno::ENOMEM.to_neg_errno();
                }

                // SAFETY: broken is a writable local vector and ownership of truncated transfers.
                let r = unsafe { rs_strv_consume(&mut broken, truncated) };
                if r < 0 {
                    // SAFETY: broken is the owned vector accumulated by this function.
                    unsafe { free_owned_strv(broken) };
                    return Errno::ENOMEM.to_neg_errno();
                }

                p = whitespace_end;
                start = whitespace_end;
                whitespace_begin = std::ptr::null();
                whitespace_end = std::ptr::null();
                w = 0;
                // Reprocess whitespace_end as the first character of the next
                // line, matching the C loop's continue path.
                continue;
            }

            // Advance to next UTF-8 char
            // SAFETY: encoded_len is the validated byte length at p.
            p = unsafe { p.add(encoded_len as usize) };
        }

        // Process rest of the line
        if in_prefix {
            // Never saw non-whitespace — generate empty line
            let empty = b"\0".as_ptr().cast::<c_char>();
            // SAFETY: broken is a writable local and empty is static C-compatible storage.
            let r = unsafe { rs_strv_extend(&mut broken, empty) };
            if r < 0 {
                // SAFETY: broken is the owned vector accumulated by this function.
                unsafe { free_owned_strv(broken) };
                return r;
            }
        } else if !whitespace_begin.is_null() && whitespace_end.is_null() {
            // Ends in whitespace — chop it off
            // SAFETY: start and whitespace_begin lie within the same C string.
            let segment_len = unsafe { whitespace_begin.offset_from(start) } as usize;
            // SAFETY: start is readable for segment_len bytes.
            let truncated = unsafe { strndup(start, segment_len) };
            if truncated.is_null() {
                // SAFETY: broken is the owned vector accumulated by this function.
                unsafe { free_owned_strv(broken) };
                return Errno::ENOMEM.to_neg_errno();
            }
            // SAFETY: broken is a writable local vector and ownership of truncated transfers.
            let r = unsafe { rs_strv_consume(&mut broken, truncated) };
            if r < 0 {
                // SAFETY: broken is the owned vector accumulated by this function.
                unsafe { free_owned_strv(broken) };
                return Errno::ENOMEM.to_neg_errno();
            }
        } else {
            // Use line as-is
            // SAFETY: broken is a writable local vector and start is a live C-string suffix.
            let r = unsafe { rs_strv_extend(&mut broken, start) };
            if r < 0 {
                // SAFETY: broken is the owned vector accumulated by this function.
                unsafe { free_owned_strv(broken) };
                return r;
            }
        }

        i += 1;
    }

    // SAFETY: ret is non-null and writable by the caller contract.
    unsafe { *ret = broken };
    0
}

// ── strv_split (simple wrapper) ───────────────────────────────────────────

/// Split string by separators with EXTRACT_RETAIN_ESCAPE.
/// Returns a malloc'd array (caller must free), or NULL on OOM.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_split(
    s: *const c_char,
    separators: *const c_char,
) -> *mut *mut c_char {
    let mut ret: *mut *mut c_char = std::ptr::null_mut();
    // SAFETY: s/separators are caller-validated and ret is a writable local.
    let r = unsafe { rs_strv_split_full(&mut ret, s, separators, 1 << 7) }; // EXTRACT_RETAIN_ESCAPE
    if r < 0 {
        return std::ptr::null_mut();
    }
    ret
}

// ── strv_consume_pair ─────────────────────────────────────────────────────

/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_consume_pair(
    l: *mut *mut *mut c_char,
    a: *mut c_char,
    b: *mut c_char,
) -> i32 {
    // SAFETY: this function forwards l's ownership contract and transfers a/b.
    let r = unsafe { rs_strv_push_pair(l, a, b) };
    if r < 0 {
        if !a.is_null() {
            // SAFETY: push failed, so this function still owns a.
            unsafe { free(a.cast()) };
        }
        if !b.is_null() {
            // SAFETY: push failed, so this function still owns b.
            unsafe { free(b.cast()) };
        }
    }
    r
}

// ── strv_contains ─────────────────────────────────────────────────────────

/// Check if strv l contains string s.
/// Returns true if found, false otherwise.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_contains(l: *const *mut c_char, s: *const c_char) -> bool {
    if s.is_null() {
        return false;
    }
    if l.is_null() {
        return false;
    }
    // SAFETY: the caller guarantees l is a NULL-terminated vector.
    for entry in unsafe { strv_iter(l.cast()) } {
        // SAFETY: entry and s are live C strings.
        if unsafe { strcmp(entry.as_ptr(), s) } == 0 {
            return true;
        }
    }
    false
}

// ── strv_free_and_replace ─────────────────────────────────────────────────

/// Free *a and replace it with b, taking ownership of b.
/// The caller must not free b after this call.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_strv_free_and_replace(a: *mut *mut *mut c_char, b: *mut *mut c_char) {
    if a.is_null() {
        return;
    }
    // Free existing array
    // SAFETY: the caller guarantees a is readable/writable.
    let old = unsafe { *a };
    if !old.is_null() {
        // SAFETY: old is the owned vector currently stored in *a.
        unsafe { free_owned_strv(old) };
    }
    // SAFETY: a is writable by the caller contract.
    unsafe { *a = b };
}

// ── strv_extend_strv_consume ──────────────────────────────────────────────

/// Caller must not free b after this call.
/// Caller must not free b after this call.
/// Returns number of entries added on success, negative errno on failure.
/// Caller must not free b after this call.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_extend_strv_consume(
    a: *mut *mut *mut c_char,
    b: *mut *mut c_char,
    filter_duplicates: bool,
) -> i32 {
    if a.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: b is NULL or an owned NULL-terminated vector.
    let q = unsafe { rs_strv_length(b.cast()) };
    if q == 0 {
        // Free b (it's empty)
        if !b.is_null() {
            // SAFETY: an empty b has no entries, so only the array is freed.
            unsafe { free(b.cast()) };
        }
        return 0;
    }

    // SAFETY: the caller guarantees *a is NULL or a NULL-terminated vector.
    let p = unsafe { rs_strv_length(*a as *const *mut c_char) };
    if p == 0 {
        // Take over b entirely
        // SAFETY: this function forwards a's ownership contract and transfers b.
        unsafe { rs_strv_free_and_replace(a, b) };
        if filter_duplicates {
            // SAFETY: *a now owns b and remains a writable vector.
            unsafe { rs_strv_uniq(*a) };
        }
        // SAFETY: *a is the resulting NULL-terminated vector.
        return unsafe { rs_strv_length(*a as *const *mut c_char) } as i32;
    }

    if p >= SIZE_MAX - q {
        if !b.is_null() {
            // SAFETY: no entries were moved, so b remains owned here.
            unsafe { free_owned_strv(b) };
        }
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: a is writable, and reallocarray receives its current allocation
    // with a finite rounded element count.
    let t = unsafe {
        reallocarray(
            *a as *mut c_void,
            crate::basic_validators::rs_GREEDY_ALLOC_ROUND_UP(p + q + 1),
            std::mem::size_of::<*mut c_char>(),
        )
    }
    .cast();
    if t.is_null() {
        if !b.is_null() {
            // SAFETY: no entries were moved, so b remains owned here.
            unsafe { free_owned_strv(b) };
        }
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: t reserves p+q+1 entries and a is writable.
    unsafe {
        *t.add(p) = std::ptr::null_mut();
        *a = t;
    }

    let mut i: usize = 0;
    if !filter_duplicates {
        // Copy all entries from b, then NUL-terminate
        let mut j: usize = 0;
        while j < q {
            // SAFETY: j < q keeps both accesses within their vectors.
            unsafe { *t.add(p + j) = *b.add(j) };
            j += 1;
        }
        // SAFETY: t reserves the final NULL terminator slot.
        unsafe { *t.add(p + q) = std::ptr::null_mut() };
        i = q;
    } else {
        // Copy only non-duplicate entries
        // SAFETY: b is an owned NULL-terminated vector.
        for entry in unsafe { strv_iter(b.cast()) } {
            // SAFETY: t is the live destination vector and entry is a live C string.
            if unsafe { rs_strv_contains(t.cast(), entry.as_ptr()) } {
                // SAFETY: duplicate entry ownership remains with this function.
                unsafe { free(entry.as_ptr().cast_mut().cast()) };
            } else {
                // SAFETY: i < q and t reserves p+q+1 entries.
                unsafe { *t.add(p + i) = entry.as_ptr().cast_mut() };
                i += 1;
                // SAFETY: t reserves the final NULL terminator slot.
                unsafe { *t.add(p + i) = std::ptr::null_mut() };
            }
        }
    }

    // Free the b array (not its entries — they were moved or freed above)
    // SAFETY: all entries were moved or freed; only b's pointer array remains.
    unsafe { free(b.cast()) };

    i as i32
}

// ── strv_split_and_extend_full ────────────────────────────────────────────

/// Returns number of entries on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_split_and_extend_full(
    t: *mut *mut *mut c_char,
    s: *const c_char,
    separators: *const c_char,
    filter_duplicates: bool,
    flags: u32,
) -> i32 {
    if t.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    if s.is_null() {
        return 0;
    }

    let mut l: *mut *mut c_char = std::ptr::null_mut();
    // SAFETY: s/separators are caller-validated and l is a writable local.
    let r = unsafe { rs_strv_split_full(&mut l, s, separators, flags) };
    if r < 0 {
        return r;
    }

    // SAFETY: this function forwards t's ownership contract and transfers l.
    let r2 = unsafe { rs_strv_extend_strv_consume(t, l, filter_duplicates) };
    if r2 < 0 {
        return r2;
    }

    // SAFETY: *t is the resulting NULL-terminated vector.
    (unsafe { rs_strv_length(*t as *const *mut c_char) }) as i32
}

// ── strv.h inline wrapper functions ───────────────────────────────────────

/// Copy the entire NULL-terminated string array `l` into a newly allocated array.
/// Returns a malloc'd array (caller must free), or NULL on OOM.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_copy(l: *const *mut c_char) -> *mut *mut c_char {
    // SAFETY: this function forwards the vector contract unchanged.
    unsafe { rs_strv_copy_n(l.cast(), SIZE_MAX) }
}

/// Push value onto the string array *l, taking ownership of value.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_push(l: *mut *mut *mut c_char, value: *mut c_char) -> i32 {
    // SAFETY: this function forwards l's ownership contract and transfers value.
    unsafe { rs_strv_push_with_size(l, std::ptr::null_mut(), value) }
}

/// Prepend value at the beginning of the string array *l.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_push_prepend(l: *mut *mut *mut c_char, value: *mut c_char) -> i32 {
    // SAFETY: this function forwards l's ownership contract and transfers value.
    unsafe { rs_strv_insert(l, 0, value) }
}

/// Check if two NULL-terminated string arrays a and b are equal.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_equal(a: *const *mut c_char, b: *const *mut c_char) -> bool {
    // SAFETY: this function forwards both vector contracts unchanged.
    (unsafe { rs_strv_compare(a.cast(), b.cast()) }) == 0
}

/// Return x if non-NULL, otherwise POINTER_MAX as sentinel.
#[unsafe(no_mangle)]
pub extern "C" fn rs_STRV_IFNOTNULL(x: *const c_char) -> *const c_char {
    if x.is_null() {
        usize::MAX as *const c_char // POINTER_MAX sentinel
    } else {
        x
    }
}

/// Check if the NULL-terminated string array l is empty or NULL.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_isempty(l: *const *mut c_char) -> bool {
    // SAFETY: the caller guarantees non-null l points to the first vector entry.
    l.is_null() || unsafe { (*l).is_null() }
}

/// Join all strings in l with separator.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_join(
    l: *const *mut c_char,
    separator: *const c_char,
) -> *mut c_char {
    // SAFETY: this function forwards the vector/separator contracts unchanged.
    unsafe { rs_strv_join_full(l, separator, std::ptr::null(), false) }
}

/// Check if string s matches any pattern in patterns using fnmatch.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_fnmatch(patterns: *const *mut c_char, s: *const c_char) -> bool {
    // SAFETY: this function forwards the pattern vector and string contracts.
    unsafe { rs_strv_fnmatch_full(patterns.cast(), s, 0, std::ptr::null_mut()) }
}

/// Check if string s matches any pattern, or if patterns is empty.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_fnmatch_or_empty(
    patterns: *const *mut c_char,
    s: *const c_char,
    flags: i32,
) -> bool {
    if s.is_null() {
        return false;
    }
    // SAFETY: this function forwards the pattern vector contract.
    (unsafe { rs_strv_isempty(patterns) })
        // SAFETY: this function forwards the pattern vector and string contracts.
        || unsafe { rs_strv_fnmatch_full(
            patterns.cast::<*mut c_char>(),
            s,
            flags,
            std::ptr::null_mut(),
        ) }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn make_strv(strings: &[&str]) -> *mut *mut c_char {
        // SAFETY: Allocate array with malloc so C can free it
        let ptr = unsafe {
            malloc((strings.len() + 1) * std::mem::size_of::<*mut c_char>()) as *mut *mut c_char
        };
        if ptr.is_null() {
            return std::ptr::null_mut();
        }

        // SAFETY: Allocate each string with strdup so C can free it
        for (i, s) in strings.iter().enumerate() {
            let c_str = CString::new(*s).unwrap();
            // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
            let dup = unsafe { strdup(c_str.as_ptr()) };
            if dup.is_null() {
                // Cleanup on OOM
                for j in 0..i {
                    // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
                    unsafe { free(*ptr.add(j) as *mut c_void) };
                }
                // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
                unsafe { free(ptr as *mut c_void) };
                return std::ptr::null_mut();
            }
            // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
            unsafe { *ptr.add(i) = dup };
        }

        // Null-terminate the array
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { *ptr.add(strings.len()) = std::ptr::null_mut() };
        ptr
    }

    unsafe fn free_strv(l: *mut *mut c_char) {
        // SAFETY: test vectors are allocated entry-by-entry with the C allocator.
        unsafe { super::free_owned_strv(l) };
    }

    #[test]
    fn test_strv_length_empty() {
        let empty: [*mut c_char; 1] = [std::ptr::null_mut()];
        let ptr = empty.as_ptr();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert_eq!(unsafe { rs_strv_length(ptr) }, 0);
    }

    #[test]
    fn test_strv_length_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert_eq!(unsafe { rs_strv_length(std::ptr::null()) }, 0);
    }

    #[test]
    fn test_strv_length_single() {
        let v = make_strv(&["hello"]);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert_eq!(unsafe { rs_strv_length(v as *const *mut c_char) }, 1);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { free_strv(v) };
    }

    #[test]
    fn test_strv_length_multiple() {
        let v = make_strv(&["a", "b", "c"]);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert_eq!(unsafe { rs_strv_length(v as *const *mut c_char) }, 3);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { free_strv(v) };
    }

    #[test]
    fn test_strv_find_present() {
        let v = make_strv(&["foo", "bar", "baz"]);
        let needle = CString::new("bar").unwrap();
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        let result = unsafe { rs_strv_find(v as *const *mut c_char, needle.as_ptr()) };
        assert!(!result.is_null());
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        unsafe { assert_eq!(CStr::from_ptr(result), needle.as_c_str()) };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { free_strv(v) };
    }

    #[test]
    fn test_strv_find_absent() {
        let v = make_strv(&["foo", "bar", "baz"]);
        let needle = CString::new("qux").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = unsafe { rs_strv_find(v as *const *mut c_char, needle.as_ptr()) };
        assert!(result.is_null());
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { free_strv(v) };
    }

    #[test]
    fn test_strv_sort_unsorted() {
        let v = make_strv(&["charlie", "alpha", "bravo"]);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { rs_strv_sort(v) };
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let len = unsafe { rs_strv_length(v as *const *mut c_char) };
        assert_eq!(len, 3);
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        unsafe {
            assert_eq!(CStr::from_ptr(*v.add(0)).to_str().unwrap(), "alpha");
            assert_eq!(CStr::from_ptr(*v.add(1)).to_str().unwrap(), "bravo");
            assert_eq!(CStr::from_ptr(*v.add(2)).to_str().unwrap(), "charlie");
        }
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { free_strv(v) };
    }

    #[test]
    fn test_strv_is_uniq_with_duplicates() {
        let v = make_strv(&["a", "b", "a"]);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(!unsafe { rs_strv_is_uniq(v as *const *mut c_char) });
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { free_strv(v) };
    }

    #[test]
    fn test_strv_is_uniq_without_duplicates() {
        let v = make_strv(&["a", "b", "c"]);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(unsafe { rs_strv_is_uniq(v as *const *mut c_char) });
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { free_strv(v) };
    }

    #[test]
    fn test_strv_is_uniq_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(unsafe { rs_strv_is_uniq(std::ptr::null()) });
    }
}
