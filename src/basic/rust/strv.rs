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
        unsafe_ffi!({
            let entry = self.ptr.add(self.index);
            if (*entry).is_null() {
                return None;
            }
            self.index += 1;
            Some(CStr::from_ptr(*entry))
        })
    }
}

/// # Safety
/// `l` must point to a readable, NULL-terminated vector of live C strings for
/// as long as the returned iterator or any item yielded from it is used.
unsafe fn strv_iter(l: *const *const c_char) -> StrvIter<'static> {
    StrvIter {
        ptr: l,
        index: 0,
        _marker: PhantomData,
    }
}

/// A mutable, NULL-terminated C string vector viewed as a safe slice.
///
/// The terminator is deliberately excluded: all mutation methods preserve the
/// original final NULL slot, while their slice operations cannot overwrite it.
struct StrvMut<'a> {
    entries: &'a mut [*mut c_char],
}

impl<'a> StrvMut<'a> {
    /// # Safety
    /// `l` must be non-null, writable through its NULL terminator, and every
    /// entry before that terminator must be a live C string.
    unsafe fn from_raw(l: *mut *mut c_char) -> Self {
        let mut len = 0;
        // SAFETY: the caller guarantees that l is readable through its terminator.
        while !unsafe_ffi!((*l.add(len)).is_null()) {
            len += 1;
        }
        // SAFETY: len was measured from l and excludes the final NULL slot.
        Self {
            entries: unsafe_ffi!(std::slice::from_raw_parts_mut(l, len)),
        }
    }

    fn reverse(&mut self) {
        self.entries.reverse();
    }

    fn sort(&mut self) {
        self.entries.sort_unstable_by(|a, b| {
            // SAFETY: StrvMut only exposes entries validated by from_raw.
            unsafe_ffi!(CStr::from_ptr(*a))
                .to_bytes()
                .cmp(unsafe_ffi!(CStr::from_ptr(*b)).to_bytes())
        });
    }

    fn remove_all(&mut self, needle: &CStr) {
        let mut kept = 0;
        for index in 0..self.entries.len() {
            let entry = self.entries[index];
            // SAFETY: StrvMut only exposes live, NUL-terminated entries.
            if unsafe_ffi!(CStr::from_ptr(entry)) == needle {
                // SAFETY: strv_remove owns every removed C-allocator entry.
                unsafe_ffi!(free(entry.cast()));
            } else {
                self.entries[kept] = entry;
                kept += 1;
            }
        }
        self.entries[kept..].fill(std::ptr::null_mut());
    }

    fn dedup_keep_first(&mut self) {
        let mut kept = 0;
        for index in 0..self.entries.len() {
            let entry = self.entries[index];
            // SAFETY: StrvMut only exposes live, NUL-terminated entries.
            let duplicate = self.entries[..kept]
                .iter()
                .any(|previous| unsafe_ffi!(CStr::from_ptr(*previous) == CStr::from_ptr(entry)));
            if duplicate {
                // SAFETY: strv_uniq owns every removed C-allocator entry.
                unsafe_ffi!(free(entry.cast()));
            } else {
                self.entries[kept] = entry;
                kept += 1;
            }
        }
        self.entries[kept..].fill(std::ptr::null_mut());
    }

    fn sort_uniq(&mut self) {
        self.sort();
        let mut kept = 1;
        for index in 1..self.entries.len() {
            let entry = self.entries[index];
            // SAFETY: StrvMut only exposes live, NUL-terminated entries.
            if unsafe_ffi!(CStr::from_ptr(self.entries[kept - 1]) == CStr::from_ptr(entry)) {
                // SAFETY: strv_sort_uniq owns duplicate C-allocator entries.
                unsafe_ffi!(free(entry.cast()));
            } else {
                self.entries[kept] = entry;
                kept += 1;
            }
        }
        self.entries[kept..].fill(std::ptr::null_mut());
    }
}

/// Fresh C-allocator string-vector storage with an always-present NULL slot.
///
/// This deliberately stores raw strings, rather than Rust `CString`s: every
/// successful result is released by the C caller with `strv_free()`/`free()`.
struct CStrvAllocation {
    ptr: *mut *mut c_char,
    slots: usize,
    len: usize,
}

impl CStrvAllocation {
    fn malloc(slots: usize) -> Option<Self> {
        let bytes = slots.checked_mul(std::mem::size_of::<*mut c_char>())?;
        let ptr = malloc(bytes).cast::<*mut c_char>();
        if ptr.is_null() {
            return None;
        }
        // SAFETY: `ptr` owns `slots` pointer-sized slots, including slot zero.
        unsafe_ffi!(*ptr = std::ptr::null_mut());
        Some(Self { ptr, slots, len: 0 })
    }

    fn push(&mut self, entry: *mut c_char) {
        debug_assert!(self.len + 1 < self.slots);
        // SAFETY: callers only push while the reserved terminator slot remains.
        unsafe_ffi!({
            *self.ptr.add(self.len) = entry;
            self.len += 1;
            *self.ptr.add(self.len) = std::ptr::null_mut();
        })
    }

    fn free_entries_and_storage(mut self) {
        // SAFETY: the first `len` slots are distinct owned C allocations.
        unsafe_ffi!({
            for index in 0..self.len {
                free((*self.ptr.add(index)).cast());
            }
            free(self.ptr.cast());
        });
        self.ptr = std::ptr::null_mut();
    }

    fn into_raw(mut self) -> *mut *mut c_char {
        let ptr = self.ptr;
        self.ptr = std::ptr::null_mut();
        ptr
    }
}

impl Drop for CStrvAllocation {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: unconsumed storage is a fresh C allocation; no entry is
            // owned by this destructor unless an explicit rollback consumed it.
            unsafe_ffi!(free(self.ptr.cast()));
        }
    }
}

/// A caller-owned lvalue slot containing a C-allocator string vector.
///
/// Construction audits the raw FFI contract once; methods then preserve the
/// vector's NULL sentinel and publish a realloc'ed pointer only on success.
struct StrvSlot {
    slot: *mut *mut *mut c_char,
}

impl StrvSlot {
    /// # Safety
    /// `slot` must be writable and `*slot` must be null or an owned,
    /// NULL-terminated C string vector.
    unsafe fn from_raw(slot: *mut *mut *mut c_char) -> Self {
        Self { slot }
    }

    fn len(&self) -> usize {
        // SAFETY: StrvSlot's construction contract makes `*slot` a valid vector.
        unsafe_ffi!(rs_strv_length(*self.slot))
    }

    fn grow_for(&mut self, slots: usize) -> Option<*mut *mut c_char> {
        // SAFETY: `*slot` is C-allocator storage or null, and the caller has
        // checked the requested finite element count.
        let grown = unsafe_ffi!({
            reallocarray(
                (*self.slot).cast(),
                crate::basic_validators::rs_GREEDY_ALLOC_ROUND_UP(slots),
                std::mem::size_of::<*mut c_char>(),
            )
        })
        .cast::<*mut c_char>();
        if grown.is_null() {
            None
        } else {
            // SAFETY: `slot` is writable by StrvSlot's construction contract.
            unsafe_ffi!(*self.slot = grown);
            Some(grown)
        }
    }

    fn append(&mut self, entries: &[*mut c_char]) -> Option<()> {
        let len = self.len();
        let end = len.checked_add(entries.len())?.checked_add(1)?;
        let grown = self.grow_for(end)?;
        // SAFETY: `grown` has all `end` slots and entries cannot overlap the
        // destination vector under the C ownership contract.
        unsafe_ffi!({
            std::ptr::copy_nonoverlapping(entries.as_ptr(), grown.add(len), entries.len());
            *grown.add(end - 1) = std::ptr::null_mut();
        });
        Some(())
    }

    fn insert(&mut self, position: usize, value: *mut c_char) -> Option<()> {
        let len = self.len();
        let position = position.min(len);
        let grown = self.grow_for(len.checked_add(2)?)?;
        // SAFETY: the newly grown vector has `len + 2` slots and memmove
        // permits the overlapping suffix shift.
        unsafe_ffi!({
            if position < len {
                memmove(
                    grown.add(position + 1).cast(),
                    grown.add(position).cast(),
                    (len - position) * std::mem::size_of::<*mut c_char>(),
                );
            }
            *grown.add(position) = value;
            *grown.add(len + 1) = std::ptr::null_mut();
        });
        Some(())
    }

    fn append_strdup_n(&mut self, s: *const c_char, count: usize) -> Option<()> {
        let len = self.len();
        let end = len.checked_add(count)?.checked_add(1)?;
        let grown = self.grow_for(end)?;
        for index in 0..count {
            // SAFETY: s is a live C string and each index is a reserved slot.
            let duplicate = unsafe_ffi!(strdup(s));
            if duplicate.is_null() {
                // SAFETY: initialized suffix entries are owned strdup results.
                unsafe_ffi!({
                    for rollback in 0..index {
                        free((*grown.add(len + rollback)).cast());
                    }
                    *grown.add(len) = std::ptr::null_mut();
                });
                return None;
            }
            // SAFETY: this is one of `count` reserved slots.
            unsafe_ffi!(*grown.add(len + index) = duplicate);
        }
        // SAFETY: end's final slot is reserved for the terminator.
        unsafe_ffi!(*grown.add(end - 1) = std::ptr::null_mut());
        Some(())
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
    while !unsafe_ffi!((*l.add(index)).is_null()) {
        // SAFETY: every non-null entry is an owned C-allocator string.
        unsafe_ffi!(free((*l.add(index)).cast()));
        index += 1;
    }
    // SAFETY: l itself is an owned C-allocator array.
    unsafe_ffi!(free(l.cast()));
}

/// strcmp_ptr: NULL-aware strcmp. NULL < non-NULL.
///
/// # Safety
/// Each non-null pointer must designate a live, NUL-terminated C string for
/// the duration of the comparison.
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
    unsafe_ffi!(strcmp(a, b))
}

/// cstr_startswith: returns Some(suffix_ptr) if `s` starts with `prefix`, else None.
/// The returned pointer points into the original C string, past the prefix.
fn cstr_startswith(s: &CStr, prefix: &CStr) -> Option<*const c_char> {
    let s_bytes = s.to_bytes();
    let p_bytes = prefix.to_bytes();
    if s_bytes.starts_with(p_bytes) {
        // SAFETY: the suffix starts within a valid C string and includes its NUL terminator
        Some(unsafe_ffi!(s.as_ptr().add(p_bytes.len())))
    } else {
        None
    }
}

/// strv_isempty: true if l is NULL or points to a NULL entry.
///
/// # Safety
/// If non-null, `l` must be valid and aligned for reading its first vector
/// entry for the duration of this call.
unsafe fn strv_isempty(l: *const *const c_char) -> bool {
    // SAFETY: the caller guarantees non-null l points to the first strv entry.
    l.is_null() || unsafe_ffi!((*l).is_null())
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
    unsafe_ffi!(strv_iter(l.cast())).count()
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
    let needle = unsafe_ffi!(CStr::from_ptr(name));
    // SAFETY: the caller guarantees l is a NULL-terminated string vector.
    for entry in unsafe_ffi!(strv_iter(l.cast())) {
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
    for entry in unsafe_ffi!(strv_iter(l.cast())) {
        // SAFETY: entry and name are live C strings.
        if unsafe_ffi!(strcasecmp(entry.as_ptr(), name)) == 0 {
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
    let prefix = unsafe_ffi!(CStr::from_ptr(name));
    // SAFETY: the caller guarantees l is a NULL-terminated string vector.
    for entry in unsafe_ffi!(strv_iter(l.cast())) {
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
    let prefix = unsafe_ffi!(CStr::from_ptr(name));
    // SAFETY: the caller guarantees l is a NULL-terminated string vector.
    for entry in unsafe_ffi!(strv_iter(l.cast())) {
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
    let mut entries = unsafe_ffi!(strv_iter(l.cast()));
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
    for ea in unsafe_ffi!(strv_iter(a.cast())) {
        // SAFETY: the caller guarantees b is a NULL-terminated string vector.
        for eb in unsafe_ffi!(strv_iter(b.cast())) {
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
    if unsafe_ffi!(strv_isempty(a)) {
        // SAFETY: same vector contract.
        if unsafe_ffi!(strv_isempty(b)) {
            return 0;
        }
        return -1;
    }
    // SAFETY: the caller guarantees b is NULL or a NULL-terminated vector.
    if unsafe_ffi!(strv_isempty(b)) {
        return 1;
    }
    let mut ai: usize = 0;
    let mut bi: usize = 0;
    loop {
        // SAFETY: ai/bi advance in lockstep only until each vector's terminator.
        let (a_entry, b_entry) = unsafe_ffi!((*a.add(ai), *b.add(bi)));
        let ea = a_entry.is_null();
        let eb = b_entry.is_null();
        if ea && eb {
            return 0;
        }
        // SAFETY: the entries were just read from the live vectors.
        let r = unsafe_ffi!(strcmp_ptr(a_entry, b_entry));
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
        for ea in unsafe_ffi!(strv_iter(a.cast())) {
            let mut found = false;
            if !b.is_null() {
                // SAFETY: the caller guarantees b is a NULL-terminated string vector.
                for eb in unsafe_ffi!(strv_iter(b.cast())) {
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
        for eb in unsafe_ffi!(strv_iter(b.cast())) {
            let mut found = false;
            if !a.is_null() {
                // SAFETY: the caller guarantees a is a NULL-terminated string vector.
                for ea in unsafe_ffi!(strv_iter(a.cast())) {
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
    let total = unsafe_ffi!(rs_strv_length(l));
    let count = if n < total { n } else { total };

    let Some(slots) = count.checked_add(1) else {
        return std::ptr::null_mut();
    };
    let Some(mut result) = CStrvAllocation::malloc(slots) else {
        return std::ptr::null_mut();
    };

    if !l.is_null() {
        // SAFETY: the caller guarantees l is a NULL-terminated string vector.
        for entry in unsafe_ffi!(strv_iter(l.cast())) {
            if result.len >= count {
                break;
            }
            // SAFETY: entry is a live C string from the vector.
            let dup = unsafe_ffi!(strdup(entry.as_ptr()));
            if dup.is_null() {
                result.free_entries_and_storage();
                return std::ptr::null_mut();
            }
            result.push(dup);
        }
    }
    result.into_raw()
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
    // SAFETY: the caller guarantees s is a live C string.
    let needle = unsafe_ffi!(CStr::from_ptr(s));
    // SAFETY: the caller guarantees l is writable through its NULL terminator.
    let mut entries = unsafe_ffi!(StrvMut::from_raw(l));
    entries.remove_all(needle);
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
    // SAFETY: the caller guarantees l is writable through its NULL terminator.
    let mut entries = unsafe_ffi!(StrvMut::from_raw(l));
    entries.dedup_keep_first();
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
    // SAFETY: the caller guarantees l is writable through its NULL terminator.
    let mut entries = unsafe_ffi!(StrvMut::from_raw(l));
    // C uses qsort(), whose ordering is unstable and whose operation does not
    // allocate. The slice sort has the same relevant properties.
    entries.sort();
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
    // SAFETY: the caller guarantees l is writable through its NULL terminator.
    unsafe_ffi!(StrvMut::from_raw(l)).reverse();
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
        if unsafe_ffi!(strv_isempty(l.cast())) {
            return std::ptr::null_mut();
        }
        // SAFETY: the non-empty check proves another vector slot exists.
        l = unsafe_ffi!(l.add(1));
        remaining -= 1;
    }
    // SAFETY: l remains an in-bounds suffix of the caller's vector.
    if unsafe_ffi!(strv_isempty(l.cast())) {
        return std::ptr::null_mut();
    }
    l
}

// ── strv_find_closest_prefix ────────────────────────────────────────────

/// # Safety
/// Each non-null pointer must designate a live, NUL-terminated C string for
/// the duration of the call.
unsafe fn startswith_internal(s: *const c_char, prefix: *const c_char) -> *const c_char {
    if s.is_null() || prefix.is_null() {
        return std::ptr::null();
    }
    // SAFETY: the caller guarantees both pointers are live C strings.
    let p_bytes = unsafe_ffi!(CStr::from_ptr(prefix)).to_bytes();
    // SAFETY: as above.
    let s_bytes = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    if s_bytes.len() < p_bytes.len() {
        return std::ptr::null();
    }
    if &s_bytes[..p_bytes.len()] == p_bytes {
        // SAFETY: starts_with proved this offset lies within s.
        unsafe_ffi!(s.add(p_bytes.len()))
    } else {
        std::ptr::null()
    }
}

/// # Safety
/// Each non-null pointer must designate a live, NUL-terminated C string for
/// the duration of the call.
unsafe fn endswith_internal(s: *const c_char, suffix: *const c_char) -> *const c_char {
    if s.is_null() || suffix.is_null() {
        return std::ptr::null();
    }
    // SAFETY: the caller guarantees both pointers are live C strings.
    let suf_bytes = unsafe_ffi!(CStr::from_ptr(suffix)).to_bytes();
    // SAFETY: as above.
    let s_bytes = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    let suf_len = suf_bytes.len();
    if s_bytes.len() < suf_len {
        return std::ptr::null();
    }
    if &s_bytes[s_bytes.len() - suf_len..] == suf_bytes {
        // SAFETY: the suffix match proves the computed offset lies within s.
        unsafe_ffi!(s.add(s_bytes.len() - suf_len))
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_find_closest_prefix(
    l: *const *mut c_char,
    name: *const c_char,
) -> *mut c_char {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller guarantees name is a live C string.
    let name_bytes = unsafe_ffi!(CStr::from_ptr(name)).to_bytes();
    let mut best_distance: usize = usize::MAX;
    let mut best: *mut c_char = std::ptr::null_mut();

    // SAFETY: the caller guarantees l is a NULL-terminated vector.
    for entry in unsafe_ffi!(strv_iter(l.cast())) {
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_find_closest_by_levenshtein(
    l: *const *mut c_char,
    name: *const c_char,
) -> *mut c_char {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    let mut best_distance: isize = isize::MAX;
    let mut best: *mut c_char = std::ptr::null_mut();

    // SAFETY: the caller guarantees l is a NULL-terminated vector.
    for entry in unsafe_ffi!(strv_iter(l.cast())) {
        // SAFETY: entry and name are live C strings.
        let distance = unsafe_ffi!(crate::string_util::rs_strlevenshtein(entry.as_ptr(), name));
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
    let found = unsafe_ffi!(rs_strv_find_closest_prefix(l.cast(), name));
    if !found.is_null() {
        return found;
    }
    // SAFETY: this function forwards the same vector/string contracts.
    unsafe_ffi!(rs_strv_find_closest_by_levenshtein(l.cast(), name))
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
    for entry in unsafe_ffi!(strv_iter(l.cast())) {
        // SAFETY: s and entry are live C strings.
        let found = unsafe_ffi!(startswith_internal(s, entry.as_ptr()));
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
    for entry in unsafe_ffi!(strv_iter(l.cast())) {
        // SAFETY: s and entry are live C strings.
        let found = unsafe_ffi!(endswith_internal(s, entry.as_ptr()));
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
        unsafe_ffi!(CStr::from_ptr(separator)).to_bytes_with_nul()
    };
    let k = sep.len() - 1; // strlen(separator)
    let m = if prefix.is_null() {
        0
    } else {
        // SAFETY: the caller guarantees non-null prefix is a live C string.
        unsafe_ffi!(CStr::from_ptr(prefix)).to_bytes().len()
    };

    if escape_separator && k != 1 {
        return std::ptr::null_mut();
    }

    // Calculate total size. The C implementation's unchecked arithmetic can
    // wrap for adversarial vectors; fail closed instead of risking a short
    // allocation followed by out-of-bounds writes.
    let mut n: usize = 0;
    // SAFETY: the caller guarantees l is a NULL-terminated vector.
    for (i, entry) in unsafe_ffi!(strv_iter(l.cast())).enumerate() {
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
    let buf = calloc(allocation_size, 1).cast::<c_char>();
    if buf.is_null() {
        return std::ptr::null_mut();
    }

    let mut pos: usize = 0;
    // SAFETY: the caller guarantees l is a NULL-terminated vector.
    for (i, entry) in unsafe_ffi!(strv_iter(l.cast())).enumerate() {
        if i > 0 {
            // stpcpy: copy separator
            for &byte in sep.iter().take(k) {
                // SAFETY: n includes every separator byte written here.
                unsafe_ffi!(*buf.add(pos) = byte as c_char);
                pos += 1;
            }
        }

        if !prefix.is_null() {
            // SAFETY: the caller guarantees prefix is a live C string.
            let p_bytes = unsafe_ffi!(CStr::from_ptr(prefix)).to_bytes();
            for &byte in p_bytes {
                // SAFETY: n includes every prefix byte written here.
                unsafe_ffi!(*buf.add(pos) = byte as c_char);
                pos += 1;
            }
        }

        let s_bytes = entry.to_bytes();
        let needs_escaping = escape_separator && s_bytes.contains(&sep[0]);

        if needs_escaping {
            for &byte in s_bytes {
                if byte == sep[0] {
                    // SAFETY: n includes every required escape byte.
                    unsafe_ffi!(*buf.add(pos) = b'\\' as c_char);
                    pos += 1;
                }
                // SAFETY: n includes every entry byte and escape byte.
                unsafe_ffi!(*buf.add(pos) = byte as c_char);
                pos += 1;
            }
        } else {
            for &byte in s_bytes {
                // SAFETY: n includes every entry byte written here.
                unsafe_ffi!(*buf.add(pos) = byte as c_char);
                pos += 1;
            }
        }
    }

    // SAFETY: calloc reserved one final terminator byte.
    unsafe_ffi!(*buf.add(pos) = 0);
    buf
}

// ── strv_sort_uniq ──────────────────────────────────────────────────────

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
    if l.is_null() {
        return l;
    }
    // SAFETY: the caller guarantees l is writable through its NULL terminator.
    let mut entries = unsafe_ffi!(StrvMut::from_raw(l));
    if !entries.entries.is_empty() {
        entries.sort_uniq();
    }
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

    // SAFETY: the caller guarantees l is a writable C string-vector slot.
    let mut slot = unsafe_ffi!(StrvSlot::from_raw(l));
    if slot.len() > SIZE_MAX - 3 {
        return Errno::ENOMEM.to_neg_errno();
    }
    let pair = [a, b];
    let entries = match (a.is_null(), b.is_null()) {
        (false, false) => &pair[..],
        (false, true) => &pair[..1],
        (true, false) => &pair[1..],
        (true, true) => &[],
    };
    if slot.append(entries).is_none() {
        return Errno::ENOMEM.to_neg_errno();
    }
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

    // SAFETY: the caller guarantees l is a writable C string-vector slot.
    let mut slot = unsafe_ffi!(StrvSlot::from_raw(l));
    if slot.len() > SIZE_MAX - 2 {
        return Errno::ENOMEM.to_neg_errno();
    }
    if slot.insert(position, value).is_none() {
        return Errno::ENOMEM.to_neg_errno();
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
    if l.is_null() || unsafe_ffi!((*l).is_null()) {
        // SAFETY: ret is non-null and writable.
        unsafe_ffi!(*ret = std::ptr::null_mut());
        return 0;
    }

    // SAFETY: this function forwards the vector contract.
    let copy = unsafe_ffi!(rs_strv_copy_n(l.cast(), SIZE_MAX));
    if copy.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: ret is non-null and writable.
    unsafe_ffi!(*ret = copy);
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

    // SAFETY: the caller guarantees a is a writable C string-vector slot.
    let mut slot = unsafe_ffi!(StrvSlot::from_raw(a));
    if slot.len() >= SIZE_MAX - n {
        return Errno::ENOMEM.to_neg_errno();
    }
    slot.append_strdup_n(s, n)
        .map(|()| 0)
        .unwrap_or_else(|| Errno::ENOMEM.to_neg_errno())
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
    if unsafe_ffi!(rs_strv_insert(l, 0, s)) < 0 {
        // SAFETY: insertion failed, so this function still owns s.
        unsafe_ffi!(free(s.cast()));
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
    let v = unsafe_ffi!(strdup(s));
    if v.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    // SAFETY: this function forwards l's ownership contract and transfers v.
    if unsafe_ffi!(rs_strv_consume_prepend(l, v)) < 0 {
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
        unsafe_ffi!(*size)
    } else {
        SIZE_MAX
    };
    if sz == SIZE_MAX {
        // SAFETY: the caller guarantees *l is NULL or a NULL-terminated vector.
        sz = unsafe_ffi!(rs_strv_length(*l as *const *mut c_char));
    }

    if sz > SIZE_MAX - 2 {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: l is writable, and reallocarray receives the current allocation
    // with a finite rounded element count.
    let c = unsafe_ffi!({
        reallocarray(
            *l as *mut c_void,
            crate::basic_validators::rs_GREEDY_ALLOC_ROUND_UP(sz + 2),
            std::mem::size_of::<*mut c_char>(),
        )
    })
    .cast::<*mut c_char>();
    if c.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: c reserves sz+2 entries.
    unsafe_ffi!({
        *c.add(sz) = value;
        *c.add(sz + 1) = std::ptr::null_mut();
    });

    if !size.is_null() {
        // SAFETY: non-null size is writable by the caller contract.
        unsafe_ffi!(*size = sz + 1);
    }

    // SAFETY: l is writable by the caller contract.
    unsafe_ffi!(*l = c);
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
    let result = unsafe_ffi!(rs_strv_push_with_size(l, n, value));
    if result < 0 && !value.is_null() {
        // SAFETY: push_with_size leaves value ownership with the caller on
        // failure, and this consuming wrapper owns it exactly once.
        unsafe_ffi!(free(value.cast()));
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
    unsafe_ffi!(rs_strv_consume_with_size(l, std::ptr::null_mut(), s))
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
    let v = unsafe_ffi!(strdup(s));
    if v.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    // SAFETY: this function forwards l's ownership contract and transfers v.
    if unsafe_ffi!(rs_strv_consume(l, v)) < 0 {
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
    let lhs_len = unsafe_ffi!(crate::ffi::strlen(lhs));
    // SAFETY: as above.
    let rhs_len = unsafe_ffi!(crate::ffi::strlen(rhs));
    // total = lhs_len + 1 (=) + rhs_len + 1 (NUL)
    if lhs_len >= SIZE_MAX - rhs_len - 2 {
        return Errno::ENOMEM.to_neg_errno();
    }
    let total = lhs_len + 1 + rhs_len + 1;

    // SAFETY: malloc accepts the checked finite total.
    let j = crate::ffi::malloc(total).cast::<c_char>();
    if j.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // Copy lhs
    // SAFETY: lhs is readable for lhs_len bytes and j owns total bytes.
    unsafe_ffi!(std::ptr::copy_nonoverlapping(lhs, j, lhs_len));
    // Copy '='
    // SAFETY: lhs_len is within the total allocation.
    unsafe_ffi!(*j.add(lhs_len) = b'=' as c_char);
    // Copy rhs
    // SAFETY: rhs is readable for rhs_len bytes and the destination range is in j.
    unsafe_ffi!(std::ptr::copy_nonoverlapping(
        rhs,
        j.add(lhs_len + 1),
        rhs_len
    ));
    // NUL terminate
    // SAFETY: total reserves the final NUL slot.
    unsafe_ffi!(*j.add(lhs_len + 1 + rhs_len) = 0);

    // SAFETY: this function forwards l's ownership contract and transfers j.
    if unsafe_ffi!(rs_strv_consume(l, j)) < 0 {
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
        let r = unsafe_ffi!({
            crate::extract_word::rs_extract_first_word(&mut p, &mut word, separators, flags)
        });
        if r < 0 {
            // Cleanup
            let mut j: usize = 0;
            while j < n {
                // SAFETY: entries below n are owned allocations in l.
                unsafe_ffi!(free(*l.add(j) as *mut c_void));
                j += 1;
            }
            if !l.is_null() {
                // SAFETY: l is the pointer array allocated by this function.
                unsafe_ffi!(free(l.cast()));
            }
            return r;
        }
        if r == 0 {
            break;
        }

        // GREEDY_REALLOC(l, n + 2)
        // SAFETY: reallocarray receives this function's current allocation and
        // a finite rounded element count.
        let new_l = unsafe_ffi!({
            reallocarray(
                l.cast(),
                crate::basic_validators::rs_GREEDY_ALLOC_ROUND_UP(n + 2),
                std::mem::size_of::<*mut c_char>(),
            )
        })
        .cast::<*mut c_char>();
        if new_l.is_null() {
            // Cleanup
            let mut j: usize = 0;
            while j < n {
                // SAFETY: entries below n are owned allocations in l.
                unsafe_ffi!(free(*l.add(j) as *mut c_void));
                j += 1;
            }
            // SAFETY: word ownership was returned by rs_extract_first_word.
            unsafe_ffi!(free(word.cast()));
            if !l.is_null() {
                // SAFETY: l is the pointer array allocated by this function.
                unsafe_ffi!(free(l.cast()));
            }
            return Errno::ENOMEM.to_neg_errno();
        }
        l = new_l;
        // SAFETY: new_l reserves n+2 entries.
        unsafe_ffi!(*l.add(n) = word);
        n += 1;
        // SAFETY: new_l reserves the final NULL terminator slot.
        unsafe_ffi!(*l.add(n) = std::ptr::null_mut());
    }

    // C behavior: if no words found, allocate empty array [NULL]
    if l.is_null() {
        // SAFETY: calloc accepts one pointer-sized element.
        l = calloc(1, std::mem::size_of::<*mut c_char>()).cast::<*mut c_char>();
        if l.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
    }

    // SAFETY: t is non-null and writable by the caller contract.
    unsafe_ffi!(*t = l);
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
    let r = unsafe_ffi!(rs_strv_split_full(
        &mut l,
        s,
        NEWLINE.as_ptr().cast(),
        flags
    ));
    if r < 0 {
        return r;
    }

    // SAFETY: l is NULL or the vector returned by rs_strv_split_full.
    let n = unsafe_ffi!(rs_strv_length(l.cast()));
    // Suppress trailing empty string
    if n > 0 && !l.is_null() {
        // SAFETY: n > 0 bounds the final entry access.
        let last = unsafe_ffi!(*l.add(n - 1));
        // SAFETY: non-null last is a live C string.
        if !last.is_null() && unsafe_ffi!(*last) == 0 {
            // isempty check
            // SAFETY: last is an owned split allocation and the vector slot is writable.
            unsafe_ffi!({
                free(last.cast());
                *l.add(n - 1) = std::ptr::null_mut();
            })
        }
    }

    // SAFETY: ret is non-null and writable by the caller contract.
    unsafe_ffi!(*ret = l);
    // Return count (may be less than r if trailing empty was suppressed)
    // SAFETY: l remains a valid NULL-terminated vector.
    (unsafe_ffi!(rs_strv_length(l.cast()))) as i32
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
    if unsafe_ffi!(rs_strv_split_newlines_full(&mut ret, s, 0)) < 0 {
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
        let copy = unsafe_ffi!(rs_strv_copy_n(l.cast(), SIZE_MAX));
        if copy.is_null() && !l.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        // SAFETY: ret is non-null and writable by the caller contract.
        unsafe_ffi!(*ret = copy);
        return 0;
    }

    if l.is_null() {
        // SAFETY: ret is non-null and writable by the caller contract.
        unsafe_ffi!(*ret = std::ptr::null_mut());
        return 0;
    }

    let mut i: usize = 0;
    // SAFETY: the caller guarantees l is readable through its NULL terminator.
    while !unsafe_ffi!((*l.add(i)).is_null()) {
        // SAFETY: i currently indexes a live vector entry.
        let line = unsafe_ffi!(*l.add(i));
        let mut start: *const c_char = line;
        let mut whitespace_begin: *const c_char = std::ptr::null();
        let mut whitespace_end: *const c_char = std::ptr::null();
        let mut in_prefix: bool = true;
        let mut w: usize = 0;
        let mut p: *const c_char = line;

        // SAFETY: each line is a live NUL-terminated C string.
        while unsafe_ffi!(*p) != 0 {
            // SAFETY: p currently points before the terminating NUL.
            let ch = unsafe_ffi!(*p) as u8;

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
            let encoded_len = unsafe_ffi!(crate::utf8::rs_utf8_encoded_to_unichar(p, &mut unichar));
            if encoded_len < 0 {
                // C rejects the complete operation on malformed UTF-8 without
                // publishing the partially accumulated result.
                // SAFETY: broken is the owned vector accumulated by this function.
                unsafe_ffi!(free_owned_strv(broken));
                return encoded_len;
            }
            // SAFETY: decoding above proved p begins a valid UTF-8 scalar.
            let cw = unsafe_ffi!(crate::utf8::rs_utf8_char_console_width(p));
            debug_assert!(cw >= 0);
            w += cw as usize;

            if w > width && !whitespace_begin.is_null() && !whitespace_end.is_null() {
                // Break here
                // SAFETY: start and whitespace_begin lie within the same C string.
                let segment_len = unsafe_ffi!(whitespace_begin.offset_from(start)) as usize;
                // SAFETY: start is readable for segment_len bytes.
                let truncated = unsafe_ffi!(strndup(start, segment_len));
                if truncated.is_null() {
                    // SAFETY: broken is the owned vector accumulated by this function.
                    unsafe_ffi!(free_owned_strv(broken));
                    return Errno::ENOMEM.to_neg_errno();
                }

                // SAFETY: broken is a writable local vector and ownership of truncated transfers.
                let r = unsafe_ffi!(rs_strv_consume(&mut broken, truncated));
                if r < 0 {
                    // SAFETY: broken is the owned vector accumulated by this function.
                    unsafe_ffi!(free_owned_strv(broken));
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
            p = unsafe_ffi!(p.add(encoded_len as usize));
        }

        // Process rest of the line
        if in_prefix {
            // Never saw non-whitespace — generate empty line
            let empty = b"\0".as_ptr().cast::<c_char>();
            // SAFETY: broken is a writable local and empty is static C-compatible storage.
            let r = unsafe_ffi!(rs_strv_extend(&mut broken, empty));
            if r < 0 {
                // SAFETY: broken is the owned vector accumulated by this function.
                unsafe_ffi!(free_owned_strv(broken));
                return r;
            }
        } else if !whitespace_begin.is_null() && whitespace_end.is_null() {
            // Ends in whitespace — chop it off
            // SAFETY: start and whitespace_begin lie within the same C string.
            let segment_len = unsafe_ffi!(whitespace_begin.offset_from(start)) as usize;
            // SAFETY: start is readable for segment_len bytes.
            let truncated = unsafe_ffi!(strndup(start, segment_len));
            if truncated.is_null() {
                // SAFETY: broken is the owned vector accumulated by this function.
                unsafe_ffi!(free_owned_strv(broken));
                return Errno::ENOMEM.to_neg_errno();
            }
            // SAFETY: broken is a writable local vector and ownership of truncated transfers.
            let r = unsafe_ffi!(rs_strv_consume(&mut broken, truncated));
            if r < 0 {
                // SAFETY: broken is the owned vector accumulated by this function.
                unsafe_ffi!(free_owned_strv(broken));
                return Errno::ENOMEM.to_neg_errno();
            }
        } else {
            // Use line as-is
            // SAFETY: broken is a writable local vector and start is a live C-string suffix.
            let r = unsafe_ffi!(rs_strv_extend(&mut broken, start));
            if r < 0 {
                // SAFETY: broken is the owned vector accumulated by this function.
                unsafe_ffi!(free_owned_strv(broken));
                return r;
            }
        }

        i += 1;
    }

    // SAFETY: ret is non-null and writable by the caller contract.
    unsafe_ffi!(*ret = broken);
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
    let r = unsafe_ffi!(rs_strv_split_full(&mut ret, s, separators, 1 << 7)); // EXTRACT_RETAIN_ESCAPE
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
    let r = unsafe_ffi!(rs_strv_push_pair(l, a, b));
    if r < 0 {
        if !a.is_null() {
            // SAFETY: push failed, so this function still owns a.
            unsafe_ffi!(free(a.cast()));
        }
        if !b.is_null() {
            // SAFETY: push failed, so this function still owns b.
            unsafe_ffi!(free(b.cast()));
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
    for entry in unsafe_ffi!(strv_iter(l.cast())) {
        // SAFETY: entry and s are live C strings.
        if unsafe_ffi!(strcmp(entry.as_ptr(), s)) == 0 {
            return true;
        }
    }
    false
}

// ── strv_free_and_replace ─────────────────────────────────────────────────

/// Free `*a` and replace it with `*b`, consuming `*b`.
///
/// This is the function-shaped C ABI equivalent of
/// `strv_free_and_replace(a, b)`: both arguments point to the caller's
/// lvalues, and `*b` is reset to NULL after the replacement.
///
/// # Safety
/// `a` and `b` must be non-null pointers to writable lvalue slots. `*a` must
/// be null or an owned, NULL-terminated vector whose entries use the C
/// allocator; `*b` is moved without copying and must satisfy the same
/// ownership contract. Both slots must remain live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_free_and_replace(
    a: *mut *mut *mut c_char,
    b: *mut *mut *mut c_char,
) {
    // Free existing array
    // SAFETY: the caller guarantees a and b name readable/writable lvalues.
    let old = unsafe_ffi!(*a);
    if !old.is_null() {
        // SAFETY: old is the owned vector currently stored in *a.
        unsafe_ffi!(free_owned_strv(old));
    }
    // SAFETY: this mirrors free_and_replace_full: read b after freeing a,
    // assign it to a, then consume b by clearing its caller-visible lvalue.
    unsafe_ffi!({
        *a = *b;
        *b = std::ptr::null_mut();
    })
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
    let q = unsafe_ffi!(rs_strv_length(b.cast()));
    if q == 0 {
        // Free b (it's empty)
        if !b.is_null() {
            // SAFETY: an empty b has no entries, so only the array is freed.
            unsafe_ffi!(free(b.cast()));
        }
        return 0;
    }

    // SAFETY: the caller guarantees *a is NULL or a NULL-terminated vector.
    let p = unsafe_ffi!(rs_strv_length(*a as *const *mut c_char));
    if p == 0 {
        // Take over b entirely
        let mut b_consume = b;
        // SAFETY: b_consume is this function's local ownership slot, matching
        // the C implementation's cleanup-managed b_consume lvalue.
        unsafe_ffi!(rs_strv_free_and_replace(a, &mut b_consume));
        if filter_duplicates {
            // SAFETY: *a now owns b and remains a writable vector.
            unsafe_ffi!(rs_strv_uniq(*a));
        }
        // SAFETY: *a is the resulting NULL-terminated vector.
        return unsafe_ffi!(rs_strv_length(*a as *const *mut c_char)) as i32;
    }

    if p >= SIZE_MAX - q {
        if !b.is_null() {
            // SAFETY: no entries were moved, so b remains owned here.
            unsafe_ffi!(free_owned_strv(b));
        }
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: a is writable, and reallocarray receives its current allocation
    // with a finite rounded element count.
    let t = unsafe_ffi!({
        reallocarray(
            *a as *mut c_void,
            crate::basic_validators::rs_GREEDY_ALLOC_ROUND_UP(p + q + 1),
            std::mem::size_of::<*mut c_char>(),
        )
    })
    .cast::<*mut c_char>();
    if t.is_null() {
        if !b.is_null() {
            // SAFETY: no entries were moved, so b remains owned here.
            unsafe_ffi!(free_owned_strv(b));
        }
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: t reserves p+q+1 entries and a is writable.
    unsafe_ffi!({
        *t.add(p) = std::ptr::null_mut();
        *a = t;
    });

    let mut i: usize = 0;
    if !filter_duplicates {
        // Copy all entries from b, then NUL-terminate
        let mut j: usize = 0;
        while j < q {
            // SAFETY: j < q keeps both accesses within their vectors.
            unsafe_ffi!(*t.add(p + j) = *b.add(j));
            j += 1;
        }
        // SAFETY: t reserves the final NULL terminator slot.
        unsafe_ffi!(*t.add(p + q) = std::ptr::null_mut());
        i = q;
    } else {
        // Copy only non-duplicate entries
        // SAFETY: b is an owned NULL-terminated vector.
        for entry in unsafe_ffi!(strv_iter(b.cast())) {
            // SAFETY: t is the live destination vector and entry is a live C string.
            if unsafe_ffi!(rs_strv_contains(t.cast(), entry.as_ptr())) {
                // SAFETY: duplicate entry ownership remains with this function.
                unsafe_ffi!(free(entry.as_ptr().cast_mut().cast()));
            } else {
                // SAFETY: i < q and t reserves p+q+1 entries.
                unsafe_ffi!(*t.add(p + i) = entry.as_ptr().cast_mut());
                i += 1;
                // SAFETY: t reserves the final NULL terminator slot.
                unsafe_ffi!(*t.add(p + i) = std::ptr::null_mut());
            }
        }
    }

    // Free the b array (not its entries — they were moved or freed above)
    // SAFETY: all entries were moved or freed; only b's pointer array remains.
    unsafe_ffi!(free(b.cast()));

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
    let r = unsafe_ffi!(rs_strv_split_full(&mut l, s, separators, flags));
    if r < 0 {
        return r;
    }

    // SAFETY: this function forwards t's ownership contract and transfers l.
    let r2 = unsafe_ffi!(rs_strv_extend_strv_consume(t, l, filter_duplicates));
    if r2 < 0 {
        return r2;
    }

    // SAFETY: *t is the resulting NULL-terminated vector.
    (unsafe_ffi!(rs_strv_length(*t as *const *mut c_char))) as i32
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
    unsafe_ffi!(rs_strv_copy_n(l.cast(), SIZE_MAX))
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
    unsafe_ffi!(rs_strv_push_with_size(l, std::ptr::null_mut(), value))
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
    unsafe_ffi!(rs_strv_insert(l, 0, value))
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
    (unsafe_ffi!(rs_strv_compare(a.cast(), b.cast()))) == 0
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
    l.is_null() || unsafe_ffi!((*l).is_null())
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
    unsafe_ffi!(rs_strv_join_full(l, separator, std::ptr::null(), false))
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
    unsafe_ffi!(rs_strv_fnmatch_full(
        patterns.cast(),
        s,
        0,
        std::ptr::null_mut()
    ))
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
    (unsafe_ffi!(rs_strv_isempty(patterns)))
        // SAFETY: this function forwards the pattern vector and string contracts.
        || unsafe_ffi!({ rs_strv_fnmatch_full(
            patterns.cast::<*mut c_char>(),
            s,
            flags,
            std::ptr::null_mut(),
        ) })
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // Keep the test-only FFI boundary explicit while allowing assertions to stay in safe Rust.
    macro_rules! test_ffi {
        ($expression:expr) => {{
            // SAFETY: test inputs are constructed in this module and satisfy the
            // documented C ABI preconditions of the exercised facade.
            unsafe_ffi!({ $expression })
        }};
    }
    use super::*;
    use std::ffi::CString;

    fn make_strv(strings: &[&str]) -> *mut *mut c_char {
        // SAFETY: Allocate array with malloc so C can free it
        let ptr =
            malloc((strings.len() + 1) * std::mem::size_of::<*mut c_char>()) as *mut *mut c_char;
        if ptr.is_null() {
            return std::ptr::null_mut();
        }

        // SAFETY: Allocate each string with strdup so C can free it
        for (i, s) in strings.iter().enumerate() {
            let c_str = CString::new(*s).unwrap();
            // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
            let dup = test_ffi!(strdup(c_str.as_ptr()));
            if dup.is_null() {
                // Cleanup on OOM
                for j in 0..i {
                    // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
                    test_ffi!(free(*ptr.add(j) as *mut c_void));
                }
                // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
                test_ffi!(free(ptr as *mut c_void));
                return std::ptr::null_mut();
            }
            // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
            test_ffi!(*ptr.add(i) = dup);
        }

        // Null-terminate the array
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        test_ffi!(*ptr.add(strings.len()) = std::ptr::null_mut());
        ptr
    }

    /// Release a test vector allocated by `make_strv`.
    ///
    /// # Safety
    /// `l` must be null or be the null-terminated, libc-allocated vector
    /// returned by `make_strv`; this consumes the vector exactly once.
    unsafe fn free_strv(l: *mut *mut c_char) {
        // SAFETY: test vectors are allocated entry-by-entry with the C allocator.
        test_ffi!(super::free_owned_strv(l));
    }

    #[test]
    fn test_strv_length_empty() {
        let empty: [*mut c_char; 1] = [std::ptr::null_mut()];
        let ptr = empty.as_ptr();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert_eq!(test_ffi!(rs_strv_length(ptr)), 0);
    }

    #[test]
    fn test_strv_length_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert_eq!(test_ffi!(rs_strv_length(std::ptr::null())), 0);
    }

    #[test]
    fn test_strv_length_single() {
        let v = make_strv(&["hello"]);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert_eq!(test_ffi!(rs_strv_length(v as *const *mut c_char)), 1);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        test_ffi!(free_strv(v));
    }

    #[test]
    fn test_strv_length_multiple() {
        let v = make_strv(&["a", "b", "c"]);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert_eq!(test_ffi!(rs_strv_length(v as *const *mut c_char)), 3);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        test_ffi!(free_strv(v));
    }

    #[test]
    fn test_strv_find_present() {
        let v = make_strv(&["foo", "bar", "baz"]);
        let needle = CString::new("bar").unwrap();
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        let result = test_ffi!(rs_strv_find(v as *const *mut c_char, needle.as_ptr()));
        assert!(!result.is_null());
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        test_ffi!(assert_eq!(CStr::from_ptr(result), needle.as_c_str()));
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        test_ffi!(free_strv(v));
    }

    #[test]
    fn test_strv_find_absent() {
        let v = make_strv(&["foo", "bar", "baz"]);
        let needle = CString::new("qux").unwrap();
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        let result = test_ffi!(rs_strv_find(v as *const *mut c_char, needle.as_ptr()));
        assert!(result.is_null());
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        test_ffi!(free_strv(v));
    }

    #[test]
    fn test_strv_sort_unsorted() {
        let v = make_strv(&["charlie", "alpha", "bravo"]);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        test_ffi!(rs_strv_sort(v));
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let len = test_ffi!(rs_strv_length(v as *const *mut c_char));
        assert_eq!(len, 3);
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        unsafe_ffi!({
            assert_eq!(CStr::from_ptr(*v.add(0)).to_str().unwrap(), "alpha");
            assert_eq!(CStr::from_ptr(*v.add(1)).to_str().unwrap(), "bravo");
            assert_eq!(CStr::from_ptr(*v.add(2)).to_str().unwrap(), "charlie");
        });
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        test_ffi!(free_strv(v));
    }

    #[test]
    fn test_strv_is_uniq_with_duplicates() {
        let v = make_strv(&["a", "b", "a"]);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(!test_ffi!(rs_strv_is_uniq(v as *const *mut c_char)));
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        test_ffi!(free_strv(v));
    }

    #[test]
    fn test_strv_is_uniq_without_duplicates() {
        let v = make_strv(&["a", "b", "c"]);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(test_ffi!(rs_strv_is_uniq(v as *const *mut c_char)));
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        test_ffi!(free_strv(v));
    }

    #[test]
    fn test_strv_is_uniq_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(test_ffi!(rs_strv_is_uniq(std::ptr::null())));
    }
}
