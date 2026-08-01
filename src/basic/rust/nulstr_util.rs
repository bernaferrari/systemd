// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.nulstr-util; authority=src/basic/nulstr-util.c,src/basic/nulstr-util.h
//
// NUL-terminated string list utilities.
// Safe Rust core with narrow C-allocator ABI facades.

use std::ffi::{CStr, c_void};
use std::ptr;

use libc::c_char;

use crate::ffi::{calloc, free, malloc};

// ── nulstr_get ────────────────────────────────────────────────────────────

/// Search a NUL-terminated string list for `needle`.
///
/// Faithful to `const char* nulstr_get(const char *nulstr, const char *needle)` in nulstr-util.c.
/// The input `nulstr` is a sequence of NUL-terminated strings, ending with an empty string
/// (i.e., two consecutive NUL bytes). Returns `Some(index)` of the matching string's byte offset,
/// or `None` if not found.
pub fn nulstr_get(nulstr: &[u8], needle: &[u8]) -> Option<usize> {
    if nulstr.is_empty() {
        return None;
    }

    let mut pos = 0;
    while pos < nulstr.len() {
        let end = memchr(nulstr, 0, pos);
        if end == pos {
            break;
        }
        if end <= nulstr.len() {
            let entry = &nulstr[pos..end];
            if entry == needle {
                return Some(pos);
            }
        }
        pos = end + 1;
    }

    None
}

/// Exact C ABI facade for `nulstr_get()`.
///
/// The result, when non-null, is a borrowed pointer into `nulstr`; ownership
/// remains with the caller. `nulstr == NULL` is the one nullable input case
/// accepted by the C implementation. Like C's `streq()`, `needle` is otherwise
/// a required NUL-terminated string; this facade fails closed for a null
/// `needle` instead of dereferencing it.
///
/// # Safety
///
/// When non-null, `nulstr` must point to a readable NULSTR: a sequence of
/// readable NUL-terminated strings followed by an empty string. `needle` must
/// point to a readable NUL-terminated C string. Both inputs and the returned
/// borrowed pointer must remain live for the duration required by the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_nulstr_get(
    nulstr: *const c_char,
    needle: *const c_char,
) -> *const c_char {
    if nulstr.is_null() || needle.is_null() {
        return ptr::null();
    }

    // SAFETY: the entry-point contract guarantees that `needle` is a live C
    // string and that every entry reached through `nulstr` is one too.
    let needle = unsafe_ffi!(CStr::from_ptr(needle));
    let mut entry = nulstr;
    loop {
        // SAFETY: the NULSTR contract guarantees a NUL terminator for each
        // entry, including the final empty terminator entry.
        let candidate = unsafe_ffi!(CStr::from_ptr(entry));
        if candidate.to_bytes().is_empty() {
            return ptr::null();
        }
        if candidate == needle {
            return entry;
        }

        // SAFETY: `candidate` includes the terminator of the current entry,
        // so this advances exactly to the next live NULSTR entry.
        entry = unsafe_ffi!(entry.add(candidate.to_bytes_with_nul().len()));
    }
}

// ── nulstr_contains ───────────────────────────────────────────────────────

/// Check if a NUL-terminated string list contains `needle`.
///
/// Faithful to `static inline bool nulstr_contains(const char *nulstr, const char *needle)`
/// in nulstr-util.h: `return nulstr_get(nulstr, needle);`
pub fn nulstr_contains(nulstr: &[u8], needle: &[u8]) -> bool {
    nulstr_get(nulstr, needle).is_some()
}

// ── strv_parse_nulstr_full ────────────────────────────────────────────────

/// Parse a NUL-separated byte buffer into a vector of byte slices.
///
/// Faithful to `char** strv_parse_nulstr_full(const char *s, size_t l, bool drop_trailing_nuls)`
/// in nulstr-util.c. Returns a vector of byte slices (each string without its NUL terminator).
/// Unlike a traditional nulstr, this parser accepts embedded empty strings.
///
/// # Arguments
/// * `s` - The byte buffer to parse
/// * `drop_trailing_nuls` - If true, trailing NUL bytes are stripped before parsing
///
/// # Returns
/// A vector of byte slices borrowed from the input
pub fn strv_parse_nulstr_full(s: &[u8], drop_trailing_nuls: bool) -> Vec<&[u8]> {
    let mut len = s.len();

    if drop_trailing_nuls && len > 0 {
        while len > 0 && s[len - 1] == 0 {
            len -= 1;
        }
    }

    if len == 0 {
        return Vec::new();
    }

    let slice = &s[..len];

    let mut count = 0usize;
    for &b in slice {
        if b == 0 {
            count += 1;
        }
    }
    if slice[len - 1] != 0 {
        count += 1;
    }

    let mut result = Vec::with_capacity(count);
    let mut p = 0;
    while p < len {
        let e = memchr(slice, 0, p);
        let elem_end = if e <= len { e } else { len };
        result.push(&slice[p..elem_end]);
        if e > len {
            break;
        }
        p = e + 1;
    }

    result
}

/// Free a partially-built C-owned strv after an allocation failure.
///
/// # Safety
///
/// `strv` must be null or a C-allocator-owned, NULL-terminated array whose
/// populated entries are each unique C-allocator-owned strings.
unsafe fn free_c_strv(strv: *mut *mut c_char) {
    if strv.is_null() {
        return;
    }

    let mut index = 0;
    // SAFETY: the caller guarantees the allocation has a NULL terminator and
    // all preceding entries are owned C allocations.
    while !unsafe_ffi!((*strv.add(index)).is_null()) {
        // SAFETY: this is one of the owned entries described above.
        unsafe_ffi!(free((*strv.add(index)).cast::<c_void>()));
        index += 1;
    }
    // SAFETY: `strv` itself is the C allocation described above.
    unsafe_ffi!(free(strv.cast::<c_void>()));
}

/// Copy raw, non-NUL bytes into a C-owned NUL-terminated string.
///
/// # Safety
///
/// `bytes` must designate `length` readable bytes for this call.
unsafe fn malloc_suffix0(bytes: *const u8, length: usize) -> *mut c_char {
    let Some(allocation_size) = length.checked_add(1) else {
        return ptr::null_mut();
    };
    let allocation = malloc(allocation_size).cast::<c_char>();
    if allocation.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `allocation` has `length + 1` writable bytes. The caller gives
    // us `length` readable source bytes, and the two allocations are disjoint.
    unsafe_ffi!({
        ptr::copy_nonoverlapping(bytes, allocation.cast::<u8>(), length);
        *allocation.cast::<u8>().add(length) = 0;
    });
    allocation
}

/// Exact C ABI facade for `strv_parse_nulstr_full()`.
///
/// It preserves the C ownership boundary: the returned NULL-terminated vector
/// and each entry are allocated by the C allocator and must be freed with
/// `strv_free()` (or equivalent per-entry `free()` followed by `free()` of the
/// vector). Allocation failure returns NULL after freeing every temporary
/// allocation. `s == NULL, l == 0` produces the C API's allocated empty strv;
/// a null `s` with a nonzero length violates C's assertion and fails closed.
///
/// # Safety
///
/// `s` may be null only when `l` is zero. Otherwise it must designate `l`
/// readable bytes for this call. The non-null return is an owned C-allocator
/// strv with individually owned C-allocator NUL-terminated entries, released
/// by the caller exactly once with `strv_free()` or the equivalent sequence of
/// `free()` calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strv_parse_nulstr_full(
    s: *const c_char,
    l: usize,
    drop_trailing_nuls: bool,
) -> *mut *mut c_char {
    if s.is_null() && l != 0 {
        return ptr::null_mut();
    }

    let mut length = l;
    if drop_trailing_nuls {
        while length > 0 {
            // SAFETY: for nonzero length the entry-point contract guarantees
            // `s` points to all `l` readable bytes.
            if unsafe_ffi!(*s.cast::<u8>().add(length - 1)) != 0 {
                break;
            }
            length -= 1;
        }
    }

    if length == 0 {
        // `new0(char*, 1)` in C: an allocated, one-element NULL vector.
        return calloc(1, std::mem::size_of::<*mut c_char>()).cast::<*mut c_char>();
    }

    let mut count = 0usize;
    for index in 0..length {
        // SAFETY: the entry-point contract guarantees this byte is readable.
        if unsafe_ffi!(*s.cast::<u8>().add(index)) == 0 {
            let Some(next) = count.checked_add(1) else {
                return ptr::null_mut();
            };
            count = next;
        }
    }
    // A final non-NUL byte starts the final nonempty-terminated entry.
    // SAFETY: `length > 0`, and the entry-point contract covers this byte.
    if unsafe_ffi!(*s.cast::<u8>().add(length - 1)) != 0 {
        let Some(next) = count.checked_add(1) else {
            return ptr::null_mut();
        };
        count = next;
    }

    let Some(slots) = count.checked_add(1) else {
        return ptr::null_mut();
    };
    let result = calloc(slots, std::mem::size_of::<*mut c_char>()).cast::<*mut c_char>();
    if result.is_null() {
        return ptr::null_mut();
    }

    let mut begin = 0usize;
    let mut slot = 0usize;
    while begin < length {
        let mut end = begin;
        while end < length {
            // SAFETY: the entry-point contract guarantees this byte is readable.
            if unsafe_ffi!(*s.cast::<u8>().add(end)) == 0 {
                break;
            }
            end += 1;
        }

        // SAFETY: `begin..end` is a subrange of the `length` readable bytes
        // guaranteed by the entry-point contract.
        let entry = unsafe_ffi!(malloc_suffix0(
            s.cast::<u8>().wrapping_add(begin),
            end - begin
        ));
        if entry.is_null() {
            // SAFETY: all slots below `slot` contain exactly the owned C
            // allocations installed by this function, and calloc supplied the
            // NULL terminator immediately after them.
            unsafe_ffi!(free_c_strv(result));
            return ptr::null_mut();
        }
        // SAFETY: `slot < count`, because the count pass uses exactly the same
        // split rule, and `result` has `count + 1` zeroed slots.
        unsafe_ffi!(*result.add(slot) = entry);
        slot += 1;

        if end == length {
            break;
        }
        begin = end + 1;
    }

    result
}

/// Convenience wrapper for `strv_parse_nulstr_full` without dropping trailing NULs.
///
/// Faithful to `static inline char** strv_parse_nulstr(const char *s, size_t l)`.
pub fn strv_parse_nulstr(s: &[u8]) -> Vec<&[u8]> {
    strv_parse_nulstr_full(s, false)
}

// ── strv_split_nulstr ─────────────────────────────────────────────────────

/// Split a NUL-terminated string list into a vector of byte slices.
///
/// Faithful to `char** strv_split_nulstr(const char *s)` in nulstr-util.c.
/// Unlike `strv_parse_nulstr`, this stops at an empty string (which is the
/// traditional NULSTR_FOREACH end marker). Cannot parse embedded empty strings.
pub fn strv_split_nulstr(s: &[u8]) -> Vec<&[u8]> {
    let mut result = Vec::new();
    let mut pos = 0;

    while pos < s.len() {
        let end = memchr(s, 0, pos);
        if end == pos {
            break;
        }
        if end > s.len() {
            break;
        }
        result.push(&s[pos..end]);
        pos = end + 1;
    }

    result
}

// ── strv_make_nulstr ──────────────────────────────────────────────────────

/// Build a NUL-terminated string list from a slice of byte slices.
///
/// Faithful to `int strv_make_nulstr(char * const *l, char **ret, size_t *ret_size)`
/// in nulstr-util.c. Returns the nulstr buffer and its size (excluding the trailing NUL).
/// An extra NUL byte is appended but not counted in the size.
pub fn strv_make_nulstr(strings: &[&[u8]]) -> (Vec<u8>, usize) {
    let mut buf = Vec::new();

    for s in strings {
        buf.extend_from_slice(s);
        buf.push(0);
    }

    let size = buf.len();

    // Append extra NUL as end marker (not counted in size)
    if !buf.is_empty() {
        buf.push(0);
    } else {
        // Return buffer with two trailing NULs for consistency with C behavior
        buf = vec![0, 0];
    }

    (buf, size)
}

/// Find the index of byte `c` in `data` starting from position `start`.
/// Returns `data.len() + 1` if not found (mimicking C pointer arithmetic where
/// memchr returns NULL and the caller checks against end boundary).
fn memchr(data: &[u8], c: u8, start: usize) -> usize {
    let mut i = start;
    while i < data.len() {
        if data[i] == c {
            return i;
        }
        i += 1;
    }
    data.len() + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nulstr_get_empty_nulstr() {
        assert!(nulstr_get(b"", b"foo").is_none());
    }

    #[test]
    fn test_nulstr_get_terminator_only() {
        assert!(nulstr_get(b"\0", b"foo").is_none());
    }

    #[test]
    fn test_nulstr_get_found_first() {
        let nulstr = b"foo\0bar\0baz\0";
        let result = nulstr_get(nulstr, b"foo");
        assert_eq!(result, Some(0));
        assert_eq!(&nulstr[result.unwrap()..result.unwrap() + 3], b"foo");
    }

    #[test]
    fn test_nulstr_get_found_middle() {
        let nulstr = b"foo\0bar\0baz\0";
        let result = nulstr_get(nulstr, b"bar");
        assert!(result.is_some());
        let pos = result.unwrap();
        assert_eq!(&nulstr[pos..pos + 3], b"bar");
    }

    #[test]
    fn test_nulstr_get_found_last() {
        let nulstr = b"foo\0bar\0baz\0";
        let result = nulstr_get(nulstr, b"baz");
        assert!(result.is_some());
        let pos = result.unwrap();
        assert_eq!(&nulstr[pos..pos + 3], b"baz");
    }

    #[test]
    fn test_nulstr_get_not_found() {
        assert!(nulstr_get(b"foo\0bar\0baz\0", b"qux").is_none());
    }

    #[test]
    fn test_nulstr_get_single_entry() {
        let result = nulstr_get(b"only\0", b"only");
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_nulstr_get_partial_match_not_found() {
        assert!(nulstr_get(b"foo\0foobar\0", b"fo").is_none());
    }

    #[test]
    fn test_nulstr_contains() {
        assert!(nulstr_contains(b"foo\0bar\0\0", b"foo"));
        assert!(nulstr_contains(b"foo\0bar\0\0", b"bar"));
        assert!(!nulstr_contains(b"foo\0bar\0\0", b"baz"));
        assert!(!nulstr_contains(b"\0", b""));
    }

    #[test]
    fn test_strv_parse_nulstr_full_empty() {
        let result = strv_parse_nulstr_full(b"", false);
        assert!(result.is_empty());
    }

    #[test]
    fn test_strv_parse_nulstr_full_single_string() {
        let result = strv_parse_nulstr_full(b"hello", false);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], b"hello");
    }

    #[test]
    fn test_strv_parse_nulstr_full_multiple_strings() {
        let nulstr = b"foo\0bar\0baz";
        let result = strv_parse_nulstr_full(nulstr, false);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], b"foo");
        assert_eq!(result[1], b"bar");
        assert_eq!(result[2], b"baz");
    }

    #[test]
    fn test_strv_parse_nulstr_full_drop_trailing_nuls() {
        let nulstr = b"foo\0bar\0\0";
        let result = strv_parse_nulstr_full(nulstr, true);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], b"foo");
        assert_eq!(result[1], b"bar");
    }

    #[test]
    fn test_strv_parse_nulstr_full_keep_trailing_nuls() {
        let nulstr = b"foo\0";
        let result = strv_parse_nulstr_full(nulstr, false);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], b"foo");
    }

    #[test]
    fn test_strv_parse_nulstr_full_empty_strings() {
        let nulstr = b"\0\0";
        let result = strv_parse_nulstr_full(nulstr, false);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], b"");
        assert_eq!(result[1], b"");
    }

    #[test]
    fn test_strv_parse_nulstr_full_no_trailing_nul() {
        let nulstr = b"foo\0bar";
        let result = strv_parse_nulstr_full(nulstr, false);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], b"foo");
        assert_eq!(result[1], b"bar");
    }

    #[test]
    fn test_strv_parse_nulstr_full_drop_all_trailing() {
        let nulstr = b"\0\0";
        let result = strv_parse_nulstr_full(nulstr, true);
        assert!(result.is_empty());
    }

    #[test]
    fn test_strv_parse_nulstr_convenience() {
        let result = strv_parse_nulstr(b"foo\0bar");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], b"foo");
        assert_eq!(result[1], b"bar");
    }

    #[test]
    fn test_strv_split_nulstr_basic() {
        let nulstr = b"foo\0bar\0baz\0";
        let result = strv_split_nulstr(nulstr);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], b"foo");
        assert_eq!(result[1], b"bar");
        assert_eq!(result[2], b"baz");
    }

    #[test]
    fn test_strv_split_nulstr_stops_at_empty() {
        let nulstr = b"foo\0\0bar\0";
        let result = strv_split_nulstr(nulstr);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], b"foo");
    }

    #[test]
    fn test_strv_split_nulstr_empty_input() {
        let result = strv_split_nulstr(b"");
        assert!(result.is_empty());
    }

    #[test]
    fn test_strv_make_nulstr_basic() {
        let strings: &[&[u8]] = &[b"foo", b"bar", b"baz"];
        let (buf, size) = strv_make_nulstr(strings);
        assert_eq!(size, 12); // 3+1 + 3+1 + 3+1 = 12
        assert_eq!(&buf[..size], b"foo\0bar\0baz\0");
        // Extra trailing NUL
        assert_eq!(buf[size], 0);
    }

    #[test]
    fn test_strv_make_nulstr_empty_input() {
        let strings: &[&[u8]] = &[];
        let (buf, size) = strv_make_nulstr(strings);
        assert_eq!(size, 0);
        // Two trailing NULs for consistency
        assert_eq!(buf, vec![0, 0]);
    }

    #[test]
    fn test_strv_make_nulstr_roundtrip() {
        let original: &[&[u8]] = &[b"hello", b"world"];
        let (buf, _size) = strv_make_nulstr(original);
        // Parse back (without trailing NUL handling)
        let result = strv_parse_nulstr_full(&buf, false);
        // Should get our strings back plus empty entries from trailing NULs
        assert_eq!(result[0], b"hello");
        assert_eq!(result[1], b"world");
    }
}
