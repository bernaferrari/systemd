// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/string-util.c
//
// General string utility functions.

use std::ffi::{CStr, c_void};

use libc::c_char;

use crate::ffi::{memcmp, strcasecmp, strlen, strncmp};
#[path = "string_util_escape.rs"]
mod escape;
#[path = "string_util_json.rs"]
mod json;
#[path = "string_util_lines.rs"]
mod lines;
#[path = "string_util_owned.rs"]
mod owned;
#[path = "string_util_replace.rs"]
mod replace;
#[path = "string_util_scan.rs"]
mod scan;

pub use escape::{rs_cellescape, rs_escape_non_printable_full, rs_strextendn, rs_string_erase};
pub(crate) use escape::{try_utf8_escape_non_printable, valid_utf8_character};
pub use json::{rs_json_dashify, rs_json_underscorify, rs_strgrowpad0};
pub use lines::{
    rs_find_line_after_internal, rs_find_line_internal, rs_find_line_startswith_internal,
    rs_string_contains_word_strv, rs_string_extract_line, rs_string_truncate_lines,
};
pub use owned::{
    rs_free_and_strdup, rs_free_and_strndup, rs_make_cstring, rs_split_pair, rs_strdup_to_full,
};
pub use replace::{
    rs_str_common_prefix, rs_strdupcspn, rs_strdupspn, rs_streq_skip_trailing_chars,
    rs_string_replace_char, rs_strrep, rs_strreplace, rs_strspn_from_end,
};
pub use scan::{
    rs_char_is_cc, rs_in_charset, rs_strlevenshtein, rs_strrstr_internal, rs_strshorten,
    rs_version_is_valid,
};

// ── string-util.h inline functions ────────────────────────────────────────

/// Shadow of C strcmp_ptr() from string-util.h
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_strcmp_ptr(a: *const c_char, b: *const c_char) -> i32 {
    if !a.is_null() && !b.is_null() {
        // SAFETY: the caller guarantees both non-null arguments are live C strings.
        return unsafe { crate::ffi::strcmp(a, b) };
    }
    // CMP(a, b): NULL < non-NULL
    if a.is_null() && b.is_null() {
        return 0;
    }
    if a.is_null() {
        return -1;
    }
    1
}

/// Shadow of C strncmp_ptr() from string-util.h
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_strncmp_ptr(a: *const c_char, b: *const c_char, n: usize) -> i32 {
    if !a.is_null() && !b.is_null() {
        // SAFETY: the caller guarantees both ranges satisfy strncmp's n-byte contract.
        return unsafe { strncmp(a, b, n) };
    }
    if a.is_null() && b.is_null() {
        return 0;
    }
    if a.is_null() {
        return -1;
    }
    1
}

/// Shadow of C strcasecmp_ptr() from string-util.h
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_strcasecmp_ptr(a: *const c_char, b: *const c_char) -> i32 {
    if !a.is_null() && !b.is_null() {
        // SAFETY: the caller guarantees both non-null arguments are live C strings.
        return unsafe { strcasecmp(a, b) };
    }
    if a.is_null() && b.is_null() {
        return 0;
    }
    if a.is_null() {
        return -1;
    }
    1
}

/// Shadow of C streq_ptr() from string-util.h
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_streq_ptr(a: *const c_char, b: *const c_char) -> bool {
    // SAFETY: this function forwards the optional C-string contracts unchanged.
    (unsafe { rs_strcmp_ptr(a, b) }) == 0
}

/// Shadow of C strneq_ptr() from string-util.h
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_strneq_ptr(a: *const c_char, b: *const c_char, n: usize) -> bool {
    // SAFETY: this function forwards the counted-range contracts unchanged.
    (unsafe { rs_strncmp_ptr(a, b, n) }) == 0
}

/// Shadow of C strcaseeq_ptr() from string-util.h
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_strcaseeq_ptr(a: *const c_char, b: *const c_char) -> bool {
    // SAFETY: this function forwards the optional C-string contracts unchanged.
    (unsafe { rs_strcasecmp_ptr(a, b) }) == 0
}

/// Shadow of C strlen_ptr() from string-util.h
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_strlen_ptr(s: *const c_char) -> usize {
    if s.is_null() {
        return 0;
    }
    // SAFETY: the caller guarantees non-null s is a live C string.
    unsafe { strlen(s) }
}

/// Shadow of C isempty() from string-util.h
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_isempty(a: *const c_char) -> bool {
    // SAFETY: the caller guarantees non-null a is readable for at least one byte.
    a.is_null() || unsafe { *a } == 0
}

/// Shadow of C strempty() from string-util.h
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_strempty(s: *const c_char) -> *const c_char {
    if s.is_null() {
        static EMPTY: &[u8] = b"";
        EMPTY.as_ptr() as *const c_char
    } else {
        s
    }
}

/// Shadow of C yes_no() from string-util.h
pub fn rs_yes_no(b: bool) -> *const c_char {
    if b {
        static YES: &[u8] = b"yes";
        YES.as_ptr() as *const c_char
    } else {
        static NO: &[u8] = b"no";
        NO.as_ptr() as *const c_char
    }
}

/// Shadow of C on_off() from string-util.h
pub fn rs_on_off(b: bool) -> *const c_char {
    if b {
        static ON: &[u8] = b"on";
        ON.as_ptr() as *const c_char
    } else {
        static OFF: &[u8] = b"off";
        OFF.as_ptr() as *const c_char
    }
}

/// Shadow of C comparison_operator() from string-util.h
pub fn rs_comparison_operator(result: i32) -> *const c_char {
    if result < 0 {
        static LT: &[u8] = b"<";
        LT.as_ptr() as *const c_char
    } else if result > 0 {
        static GT: &[u8] = b">";
        GT.as_ptr() as *const c_char
    } else {
        static EQ: &[u8] = b"==";
        EQ.as_ptr() as *const c_char
    }
}

/// Shadow of C memory_startswith() from string-util.h
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_memory_startswith(
    p: *const c_void,
    sz: usize,
    token: *const c_char,
) -> *mut c_void {
    if token.is_null() || p.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: the caller guarantees token is a live C string.
    let n = unsafe { strlen(token) };
    if sz < n {
        return std::ptr::null_mut();
    }

    // SAFETY: p is readable for sz >= n bytes and token for n bytes.
    if unsafe { memcmp(p, token.cast(), n) } != 0 {
        return std::ptr::null_mut();
    }

    // SAFETY: n <= sz keeps the result within or one-past the input range.
    unsafe { p.cast::<u8>().add(n).cast_mut().cast() }
}

// ── strstr_ptr_internal ────────────────────────────────────────────────────

/// Shadow of C strstr_ptr_internal() from string-util.h
/// NULL-safe wrapper around strstr. Returns NULL if either argument is NULL.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strstr_ptr_internal(
    haystack: *const c_char,
    needle: *const c_char,
) -> *mut c_char {
    if haystack.is_null() || needle.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller guarantees both non-null arguments are live C strings.
    unsafe { crate::ffi::strstr(haystack, needle) }.cast_mut()
}

// ── strstrafter_internal ───────────────────────────────────────────────────

/// Shadow of C strstrafter_internal() from string-util.h
/// Returns NULL if not found, or pointer to first character after needle if found.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strstrafter_internal(
    haystack: *const c_char,
    needle: *const c_char,
) -> *mut c_char {
    // SAFETY: this function forwards the same C-string contracts.
    let p = unsafe { rs_strstr_ptr_internal(haystack, needle) };
    if p.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: needle is a live C string by contract.
    let needle_len = unsafe { strlen(needle) };
    // SAFETY: strstr returned p at a matching range at least needle_len bytes long.
    unsafe { p.add(needle_len) }
}

// ── memory_startswith_no_case ──────────────────────────────────────────────

/// Shadow of C memory_startswith_no_case() from string-util.h
/// Like startswith_no_case(), but operates on arbitrary memory blocks.
/// Works only for ASCII strings.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_memory_startswith_no_case(
    p: *const c_void,
    sz: usize,
    token: *const c_char,
) -> *mut c_void {
    if token.is_null() || p.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller guarantees token is a live C string.
    let n = unsafe { strlen(token) };
    if sz < n {
        return std::ptr::null_mut();
    }
    let pb = p as *const u8;
    let tb = token as *const u8;
    for i in 0..n {
        // SAFETY: p is readable for sz >= n bytes and token for n bytes.
        let (p_byte, t_byte) = unsafe { (*pb.add(i), *tb.add(i)) };
        if ascii_tolower_byte(p_byte) != ascii_tolower_byte(t_byte) {
            return std::ptr::null_mut();
        }
    }
    // SAFETY: n <= sz keeps the result within or one-past the input range.
    unsafe { p.cast::<u8>().add(n).cast_mut().cast() }
}

// ── skip_leading_chars ─────────────────────────────────────────────────────

/// Shadow of C skip_leading_chars() from string-util.h
/// Returns pointer past leading characters in 'bad'. If bad is NULL, uses WHITESPACE.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_skip_leading_chars(
    s: *const c_char,
    bad: *const c_char,
) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let bad = if bad.is_null() {
        c" \t\n\r".as_ptr()
    } else {
        bad
    };
    // SAFETY: s and bad are live C strings by the caller contract.
    let span = unsafe { crate::ffi::strspn(s, bad) };
    // SAFETY: strspn returns an in-bounds prefix length for s.
    unsafe { s.cast_mut().add(span) }
}

// ── strncpy_exact ──────────────────────────────────────────────────────────

/// Shadow of C strncpy_exact() from string-util.h
/// Just like strncpy, but without the -Wstringop-truncation warning.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strncpy_exact(buf: *mut c_char, src: *const c_char, buf_len: usize) {
    // strncpy: copies at most buf_len bytes from src, then pads remaining with NUL
    let mut i: usize = 0;
    while i < buf_len {
        // SAFETY: the caller guarantees src and buf are valid for buf_len bytes.
        let c = unsafe { *src.add(i) };
        // SAFETY: i < buf_len keeps the write within buf.
        unsafe { *buf.add(i) = c };
        if c == 0 {
            i += 1;
            // Pad remaining bytes with NUL
            while i < buf_len {
                // SAFETY: i < buf_len keeps the padding write within buf.
                unsafe { *buf.add(i) = 0 };
                i += 1;
            }
            return;
        }
        i += 1;
    }
}

// ── truncate_nl ────────────────────────────────────────────────────────────

/// Shadow of C truncate_nl() from string-util.h
/// Thin wrapper around truncate_nl_full that discards the length.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_truncate_nl(s: *mut c_char) -> *mut c_char {
    // SAFETY: this function forwards the mutable C-string contract unchanged.
    unsafe { rs_truncate_nl_full(s, std::ptr::null_mut()) }
}

// ── strdup_to ──────────────────────────────────────────────────────────────

/// Shadow of C strdup_to() from string-util.h
/// Like strdup_to_full, but always returns 0 on success (suppresses return value of 1).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strdup_to(ret: *mut *mut c_char, src: *const c_char) -> i32 {
    // SAFETY: this function forwards the same output/source contracts.
    let r = unsafe { rs_strdup_to_full(ret, src) };
    if r < 0 { r } else { 0 }
}

// ── string_contains_word ───────────────────────────────────────────────────

/// Shadow of C string_contains_word() from string-util.h
/// Thin wrapper: checks if 'word' is contained in 'string' using separators.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_string_contains_word(
    string: *const c_char,
    separators: *const c_char,
    word: *const c_char,
) -> i32 {
    // Build a STRV_MAKE(word, NULL) on the stack
    let wv: [*mut c_char; 2] = [word.cast_mut(), std::ptr::null_mut()];
    // SAFETY: the caller supplies the three C strings and wv is a live
    // stack-allocated null-terminated pointer vector for this call.
    unsafe { rs_string_contains_word_strv(string, separators, wv.as_ptr(), std::ptr::null_mut()) }
}

// ── empty_or_dash_to_null ──────────────────────────────────────────────────

/// Check the `empty_or_dash()` C-string predicate without constructing a Rust
/// reference to caller-owned memory.
///
/// # Safety
/// If non-null, `str_` must be readable through a terminating NUL. In
/// particular, a leading dash requires that the following byte is readable.
unsafe fn rs_empty_or_dash(str_: *const c_char) -> bool {
    if str_.is_null() {
        return true;
    }

    // SAFETY: the caller guarantees str_ is readable through its terminating NUL.
    unsafe { *str_ == 0 || (*str_ == b'-' as c_char && *str_.add(1) == 0) }
}

/// Shadow of C empty_or_dash_to_null() from string-util.h
/// Returns NULL if string is NULL, empty, or "-"; otherwise returns the string.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_empty_or_dash_to_null(p: *const c_char) -> *const c_char {
    // SAFETY: this function forwards the optional C-string contract.
    if unsafe { rs_empty_or_dash(p) } {
        std::ptr::null()
    } else {
        p
    }
}

/// Shadow of C ascii_isdigit() from string-util.h
pub fn rs_ascii_isdigit(p: u8) -> bool {
    p >= b'0' && p <= b'9'
}

/// Shadow of C ascii_ishex() from string-util.h
pub fn rs_ascii_ishex(a: c_char) -> bool {
    let c = a as u8;
    (c >= b'0' && c <= b'9') || (c >= b'a' && c <= b'f') || (c >= b'A' && c <= b'F')
}

/// Shadow of C ascii_isalpha() from string-util.h
pub fn rs_ascii_isalpha(a: c_char) -> bool {
    let c = a as u8;
    (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z')
}

// ── ascii_tolower / ascii_toupper ──────────────────────────────────────────

pub fn rs_ascii_tolower(x: c_char) -> c_char {
    let c = x as u8;
    if c >= b'A' && c <= b'Z' {
        (c + 32) as c_char
    } else {
        x
    }
}

pub fn rs_ascii_toupper(x: c_char) -> c_char {
    let c = x as u8;
    if c >= b'a' && c <= b'z' {
        (c - 32) as c_char
    } else {
        x
    }
}

// ── ascii_strcasecmp_n ────────────────────────────────────────────────────

/// # Safety
/// `a` and `b` must be non-null and readable for exactly `n` bytes. This is a
/// byte-counted comparison, so the readable range must include bytes following
/// any earlier NUL byte when `n` requires them.
pub unsafe fn rs_ascii_strcasecmp_n(a: *const c_char, b: *const c_char, n: usize) -> i32 {
    for i in 0..n {
        // SAFETY: the function contract requires both source ranges to be
        // readable for exactly `n` bytes. This intentionally does not stop at
        // NUL, matching C's byte-counted implementation.
        let (ua, ub) = unsafe {
            (
                ascii_tolower_byte(*a.add(i) as u8),
                ascii_tolower_byte(*b.add(i) as u8),
            )
        };
        if ua != ub {
            return (ua as i32) - (ub as i32);
        }
    }
    0
}

// ── ascii_strcasecmp_nn ───────────────────────────────────────────────────

/// # Safety
/// `a` and `b` must be non-null and readable for exactly `n` and `m` bytes,
/// respectively. The function compares `min(n, m)` bytes from each range.
pub unsafe fn rs_ascii_strcasecmp_nn(
    a: *const c_char,
    n: usize,
    b: *const c_char,
    m: usize,
) -> i32 {
    // SAFETY: `a` and `b` satisfy the counted-range contract of the callee
    // for the minimum of their two caller-provided extents.
    let result = unsafe { rs_ascii_strcasecmp_n(a, b, n.min(m)) };
    if result != 0 {
        return result;
    }

    if n < m {
        -1
    } else if n > m {
        1
    } else {
        0
    }
}

// ── chars_intersect ───────────────────────────────────────────────────────

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_chars_intersect(a: *const c_char, b: *const c_char) -> bool {
    if a.is_null() || b.is_null() {
        return false;
    }
    // SAFETY: the caller guarantees both pointers are live C strings.
    let a_bytes = unsafe { CStr::from_ptr(a) }.to_bytes();
    // SAFETY: as above.
    let b_bytes = unsafe { CStr::from_ptr(b) }.to_bytes();
    a_bytes.iter().any(|&ca| b_bytes.contains(&ca))
}

// ── string_has_cc ─────────────────────────────────────────────────────────

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_string_has_cc(p: *const c_char, ok: *const c_char) -> bool {
    if p.is_null() {
        return false;
    }
    // SAFETY: the caller guarantees p is a live C string.
    let bytes = unsafe { CStr::from_ptr(p) }.to_bytes();
    let ok_bytes = if ok.is_null() {
        &[] as &[u8]
    } else {
        // SAFETY: the caller guarantees non-null ok is a live C string.
        unsafe { CStr::from_ptr(ok) }.to_bytes()
    };

    for &c in bytes {
        if ok_bytes.contains(&c) {
            continue;
        }
        if matches!(c, 1..=0x1f | 0x7f) {
            return true;
        }
    }
    false
}

// ── string_is_safe ────────────────────────────────────────────────────────

/// Rust-only compatibility helper for C `string_is_safe(p, 0)`.
///
/// The C API is flag-bearing, so this fixed-default helper deliberately has no
/// C ABI export. It retains the `flags == 0` semantics used by its Rust caller:
/// reject empty or invalid UTF-8 input, controls (including newlines), quotes,
/// backslashes, and glob characters.
///
/// # Safety
/// `p` must be null or a readable NUL-terminated byte string.
pub unsafe fn rs_string_is_safe(p: *const c_char) -> bool {
    if p.is_null() {
        return false;
    }
    // SAFETY: non-null `p` is a readable C string by the function contract.
    let bytes = unsafe { CStr::from_ptr(p) }.to_bytes();
    !bytes.is_empty()
        && std::str::from_utf8(bytes).is_ok()
        && bytes.iter().all(|byte| {
            !matches!(
                *byte,
                1..=31 | 0x7f | b'\\' | b'"' | b'\'' | b'*' | b'?' | b'['
            )
        })
}

// ── skip_leading_chars ──────────────────────────────────────────────────

const WHITESPACE: &[u8] = b" \t\n\r";

/// Raw equivalent of `strchr(set, byte) != NULL` that deliberately does not
/// create a shared slice: C permits `set` to alias an in-place-mutated string.
///
/// # Safety
/// `set` must be readable through a terminating NUL for each call.
unsafe fn c_string_contains_byte(mut set: *const c_char, byte: u8) -> bool {
    loop {
        // SAFETY: the caller guarantees set is readable through its NUL.
        let current = unsafe { *set } as u8;
        if current == 0 {
            return false;
        }
        if current == byte {
            return true;
        }
        // SAFETY: a non-NUL byte is followed by another readable slot.
        set = unsafe { set.add(1) };
    }
}

/// Return the first byte of `s` that is absent from the given C character set.
///
/// # Safety
/// If non-null, `s` and `bad` must each be readable through a terminating NUL
/// for the duration of the call. The returned pointer is a suffix of `s` and
/// inherits its lifetime. A null `bad` selects the static whitespace set.
unsafe fn skip_leading_chars(s: *const u8, bad: *const u8) -> *const u8 {
    if s.is_null() {
        return std::ptr::null();
    }
    if bad.is_null() {
        // Use WHITESPACE
        let mut p = s;
        while !p.is_null()
            // SAFETY: p remains within the caller's C string.
            && unsafe { *p } != 0
            // SAFETY: p currently points before the terminating NUL.
            && WHITESPACE.contains(&unsafe { *p })
        {
            // SAFETY: advancing from a non-NUL byte remains within the C string.
            p = unsafe { p.add(1) };
        }
        p
    } else {
        // SAFETY: the caller guarantees bad is a live C string.
        let bad_bytes = unsafe { CStr::from_ptr(bad.cast()) }.to_bytes();
        let mut p = s;
        while !p.is_null()
            // SAFETY: p remains within the caller's C string.
            && unsafe { *p } != 0
            // SAFETY: p currently points before the terminating NUL.
            && bad_bytes.contains(&unsafe { *p })
        {
            // SAFETY: advancing from a non-NUL byte remains within the C string.
            p = unsafe { p.add(1) };
        }
        p
    }
}

// ── strstrip ───────────────────────────────────────────────────────────

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strstrip(s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    // skip_leading_chars then delete_trailing_chars
    // SAFETY: s is the caller-validated mutable C string.
    let after_leading = unsafe { skip_leading_chars(s.cast(), std::ptr::null()) };
    // SAFETY: after_leading is an in-bounds suffix of s.
    unsafe { rs_delete_trailing_chars(after_leading.cast_mut().cast(), std::ptr::null()) }
}

// ── delete_chars ────────────────────────────────────────────────────────

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_delete_chars(s: *mut c_char, bad: *const c_char) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let mut f: usize = 0;
    let mut t: usize = 0;
    // SAFETY: the caller guarantees s is writable through its terminating NUL.
    while unsafe { *s.add(f) } != 0 {
        // SAFETY: f currently indexes a byte before the terminator.
        let c = unsafe { *s.add(f) };
        let rejected = if bad.is_null() {
            WHITESPACE.contains(&(c as u8))
        } else {
            // SAFETY: the caller guarantees bad remains a readable C string;
            // scanning it anew preserves C behavior when bad aliases s.
            unsafe { c_string_contains_byte(bad, c as u8) }
        };
        if rejected {
            f += 1;
        } else {
            // SAFETY: t <= f and both indices remain within s.
            unsafe { *s.add(t) = c };
            f += 1;
            t += 1;
        }
    }
    // SAFETY: t is within the original C string allocation.
    unsafe { *s.add(t) = 0 };
    s
}

// ── delete_trailing_chars ───────────────────────────────────────────────

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_delete_trailing_chars(
    s: *mut c_char,
    bad: *const c_char,
) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let mut last_good: usize = 0;
    let mut i: usize = 0;
    // SAFETY: the caller guarantees s is writable through its terminating NUL.
    while unsafe { *s.add(i) } != 0 {
        // SAFETY: i currently indexes a byte before the terminator.
        let byte = unsafe { *s.add(i) } as u8;
        let rejected = if bad.is_null() {
            WHITESPACE.contains(&byte)
        } else {
            // SAFETY: the caller guarantees bad remains a readable C string;
            // scanning it anew preserves C behavior when bad aliases s.
            unsafe { c_string_contains_byte(bad, byte) }
        };
        if !rejected {
            last_good = i + 1;
        }
        i += 1;
    }
    // SAFETY: last_good is within the original C string allocation.
    unsafe { *s.add(last_good) = 0 };
    s
}

// ── truncate_nl_full ────────────────────────────────────────────────────

const NEWLINE: &[u8] = b"\n\r";

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_truncate_nl_full(s: *mut c_char, ret_len: *mut usize) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let mut n: usize = 0;
    while
    // SAFETY: the caller guarantees s is writable through its NUL terminator.
    unsafe { *s.add(n) } != 0
        // SAFETY: n currently indexes a byte within the C string.
        && !NEWLINE.contains(&(unsafe { *s.add(n) } as u8))
    {
        n += 1;
    }
    // SAFETY: n is within the original C string allocation.
    unsafe { *s.add(n) = 0 };
    if !ret_len.is_null() {
        // SAFETY: the caller guarantees non-null ret_len is writable.
        unsafe { *ret_len = n };
    }
    s
}

// ── ascii_strlower / ascii_strupper / ascii_strlower_n ─────────────────

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ascii_strlower(s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let mut p = s;
    // SAFETY: the caller guarantees p is writable through its NUL terminator.
    while unsafe { *p } != 0 {
        // SAFETY: p currently points to a writable byte before the terminator.
        unsafe { *p = ascii_tolower_byte(*p as u8) as c_char };
        // SAFETY: advancing from a non-NUL byte remains within the C string.
        p = unsafe { p.add(1) };
    }
    s
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ascii_strupper(s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }
    let mut p = s;
    // SAFETY: the caller guarantees p is writable through its NUL terminator.
    while unsafe { *p } != 0 {
        // SAFETY: p currently points to a byte before the terminator.
        let c = unsafe { *p } as u8;
        // SAFETY: p currently points to a writable byte.
        unsafe { *p = (if c >= b'a' && c <= b'z' { c - 32 } else { c }) as c_char };
        // SAFETY: advancing from a non-NUL byte remains within the C string.
        p = unsafe { p.add(1) };
    }
    s
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ascii_strlower_n(s: *mut c_char, n: usize) -> *mut c_char {
    for i in 0..n {
        // SAFETY: the caller guarantees s is writable for exactly n bytes.
        unsafe { *s.add(i) = ascii_tolower_byte(*s.add(i) as u8) as c_char };
    }
    s
}

// ── first_word ──────────────────────────────────────────────────────────

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_first_word(s: *const c_char, word: *const c_char) -> *mut c_char {
    if s.is_null() || word.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller guarantees word is a live C string.
    if unsafe { *word } == 0 {
        return s as *mut c_char;
    }
    // SAFETY: the caller guarantees s and word are live C strings.
    let s_bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    // SAFETY: as above.
    let w_bytes = unsafe { CStr::from_ptr(word) }.to_bytes();
    if !s_bytes.starts_with(w_bytes) {
        return std::ptr::null_mut();
    }
    // SAFETY: starts_with proved the matched word length lies within s.
    let p = unsafe { s.add(w_bytes.len()) };
    // SAFETY: p is an in-bounds suffix of s.
    if unsafe { *p } == 0 {
        return p as *mut c_char;
    }
    // SAFETY: p is an in-bounds suffix of the caller's C string.
    let after = unsafe { skip_leading_chars(p.cast(), std::ptr::null()) };
    if after == p as *const u8 {
        return std::ptr::null_mut();
    }
    after as *mut c_char
}

// ── Internal helpers ─────────────────────────────────────────────────────

#[inline]
fn ascii_tolower_byte(c: u8) -> u8 {
    if c >= b'A' && c <= b'Z' { c + 32 } else { c }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::ffi::{Errno, SIZE_MAX, free};
    use crate::string_util::{
        rs_ascii_strcasecmp_n, rs_ascii_strcasecmp_nn, rs_ascii_tolower, rs_ascii_toupper,
        rs_chars_intersect, rs_free_and_strdup, rs_free_and_strndup, rs_split_pair,
        rs_str_common_prefix, rs_strdup_to_full, rs_strdupcspn, rs_strdupspn,
        rs_streq_skip_trailing_chars, rs_string_replace_char, rs_strreplace, rs_strspn_from_end,
    };
    use libc::c_char;
    use std::ffi::{CStr, CString, c_void};

    fn c(s: &str) -> *const c_char {
        CString::new(s).unwrap().into_raw()
    }

    fn c_mut(s: &str) -> *mut c_char {
        let v = CString::new(s).unwrap().into_raw();
        v
    }

    fn drop_c(p: *mut c_char) {
        if !p.is_null() {
            // SAFETY: string utility results use `malloc` and this helper
            // consumes their unique C-allocator ownership exactly once.
            unsafe { free(p.cast::<c_void>()) }
        }
    }

    fn reclaim_cstring(p: *mut c_char) {
        if !p.is_null() {
            // SAFETY: `p` originates from `CString::into_raw` in this test
            // module and is reclaimed exactly once with the Rust allocator.
            unsafe { drop(CString::from_raw(p)) }
        }
    }

    fn drop_c_const(p: *const c_char) {
        if !p.is_null() {
            // SAFETY: `p` originates from `CString::into_raw` in this module and is reclaimed exactly once.
            unsafe { drop(CString::from_raw(p as *mut c_char)) }
        }
    }

    #[test]
    fn test_ascii_tolower() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_ascii_tolower(b'A' as c_char), b'a' as c_char);
            assert_eq!(rs_ascii_tolower(b'Z' as c_char), b'z' as c_char);
            assert_eq!(rs_ascii_tolower(b'a' as c_char), b'a' as c_char);
            assert_eq!(rs_ascii_tolower(b'0' as c_char), b'0' as c_char);
        }
    }

    #[test]
    fn test_ascii_toupper() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_ascii_toupper(b'a' as c_char), b'A' as c_char);
            assert_eq!(rs_ascii_toupper(b'z' as c_char), b'Z' as c_char);
            assert_eq!(rs_ascii_toupper(b'A' as c_char), b'A' as c_char);
        }
    }

    #[test]
    fn test_ascii_strcasecmp_n() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let a = c("Hello");
            let b = c("hello");
            assert_eq!(rs_ascii_strcasecmp_n(a, b, 5), 0);
            drop_c_const(a);
            drop_c_const(b);
        }
    }

    #[test]
    fn test_ascii_strcasecmp_nn() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let a = c("abc");
            let b = c("ABCDEF");
            assert!(rs_ascii_strcasecmp_nn(a, 3, b, 6) < 0);
            drop_c_const(a);
            drop_c_const(b);
        }
    }

    #[test]
    fn test_chars_intersect() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let a = c("abc");
            let b = c("xyz");
            assert!(!rs_chars_intersect(a, b));

            let c2 = c("cde");
            assert!(rs_chars_intersect(a, c2));
            drop_c_const(a);
            drop_c_const(b);
            drop_c_const(c2);
        }
    }

    #[test]
    fn test_strdup_to_full() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let src = c("hello");
            let mut ret: *mut c_char = std::ptr::null_mut();
            assert_eq!(rs_strdup_to_full(&mut ret, src), 1);
            assert_eq!(CStr::from_ptr(ret).to_str().unwrap(), "hello");
            drop_c(ret);
            drop_c_const(src);
        }
    }

    #[test]
    fn test_strdup_to_full_null_src() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let mut ret: *mut c_char = std::ptr::null_mut();
            assert_eq!(rs_strdup_to_full(&mut ret, std::ptr::null()), 0);
            assert!(ret.is_null());
        }
    }

    #[test]
    fn test_strdup_to_full_null_ret() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let src = c("hello");
            assert_eq!(rs_strdup_to_full(std::ptr::null_mut(), src), 1);
            drop_c_const(src);
        }
    }

    #[test]
    fn test_split_pair() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let s = c("foo:bar");
            let sep = c(":");
            let mut first: *mut c_char = std::ptr::null_mut();
            let mut second: *mut c_char = std::ptr::null_mut();
            assert_eq!(rs_split_pair(s, sep, &mut first, &mut second), 0);
            assert_eq!(CStr::from_ptr(first).to_str().unwrap(), "foo");
            assert_eq!(CStr::from_ptr(second).to_str().unwrap(), "bar");
            drop_c(first);
            drop_c(second);
            drop_c_const(s);
            drop_c_const(sep);
        }
    }

    #[test]
    fn test_split_pair_no_separator() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let s = c("nospaces");
            let sep = c(":");
            let mut first: *mut c_char = std::ptr::null_mut();
            let mut second: *mut c_char = std::ptr::null_mut();
            assert_eq!(
                rs_split_pair(s, sep, &mut first, &mut second),
                Errno::EINVAL.to_neg_errno()
            );
            drop_c_const(s);
            drop_c_const(sep);
        }
    }

    #[test]
    fn test_str_common_prefix() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let a = c("hello world");
            let b = c("hello there");
            assert_eq!(rs_str_common_prefix(a, b), 6);
            drop_c_const(a);
            drop_c_const(b);
        }
    }

    #[test]
    fn test_str_common_prefix_identical() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let a = c("hello");
            let b = c("hello");
            assert_eq!(rs_str_common_prefix(a, b), SIZE_MAX);
            drop_c_const(a);
            drop_c_const(b);
        }
    }

    #[test]
    fn test_strspn_from_end() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let s = c("hello   ");
            assert_eq!(rs_strspn_from_end(s, c(" ")), 3);
            drop_c_const(s);
        }
    }

    #[test]
    fn test_streq_skip_trailing_chars() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let hello = c("hello");
            let hello_spaces = c("hello   ");
            let space = c(" ");
            assert!(rs_streq_skip_trailing_chars(hello, hello_spaces, space));
            drop_c_const(hello);
            drop_c_const(hello_spaces);
            drop_c_const(space);

            let hello = c("hello");
            let world = c("world");
            let space = c(" ");
            assert!(!rs_streq_skip_trailing_chars(hello, world, space));
            drop_c_const(hello);
            drop_c_const(world);
            drop_c_const(space);

            assert!(rs_streq_skip_trailing_chars(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null()
            ));

            let hello = c("hello");
            let space = c(" ");
            assert!(!rs_streq_skip_trailing_chars(
                hello,
                std::ptr::null(),
                space
            ));
            drop_c_const(hello);
            drop_c_const(space);

            let hello_tab = c("hello\t");
            let hello = c("hello");
            let tab = c("\t");
            assert!(rs_streq_skip_trailing_chars(hello_tab, hello, tab));
            drop_c_const(hello_tab);
            drop_c_const(hello);
            drop_c_const(tab);

            let hello = c("hello");
            let hello_newline = c("hello\n");
            assert!(rs_streq_skip_trailing_chars(
                hello,
                hello_newline,
                std::ptr::null()
            ));
            drop_c_const(hello);
            drop_c_const(hello_newline);

            let hello_space = c("hello ");
            let hello_tab = c("hello\t");
            let space_tab = c(" \t");
            assert!(rs_streq_skip_trailing_chars(
                hello_space,
                hello_tab,
                space_tab
            ));
            drop_c_const(hello_space);
            drop_c_const(hello_tab);
            drop_c_const(space_tab);
        }
    }

    #[test]
    fn test_strdupspn() {
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        unsafe {
            let result = rs_strdupspn(c("   hello"), c(" "));
            assert_eq!(CStr::from_ptr(result).to_str().unwrap(), "   ");
            drop_c(result);
        }
    }

    #[test]
    fn test_strdupcspn() {
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        unsafe {
            let result = rs_strdupcspn(c("hello world"), c(" "));
            assert_eq!(CStr::from_ptr(result).to_str().unwrap(), "hello");
            drop_c(result);
        }
    }

    #[test]
    fn test_string_replace_char() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let s = c_mut("hello world");
            rs_string_replace_char(s, b' ' as c_char, b'_' as c_char);
            assert_eq!(CStr::from_ptr(s).to_str().unwrap(), "hello_world");
            reclaim_cstring(s);
        }
    }

    #[test]
    fn test_strreplace() {
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        unsafe {
            let result = rs_strreplace(c("foo bar foo"), c("foo"), c("baz"));
            assert_eq!(CStr::from_ptr(result).to_str().unwrap(), "baz bar baz");
            drop_c(result);
        }
    }

    #[test]
    fn test_strreplace_no_match() {
        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        unsafe {
            let result = rs_strreplace(c("hello world"), c("xyz"), c("abc"));
            assert_eq!(CStr::from_ptr(result).to_str().unwrap(), "hello world");
            drop_c(result);
        }
    }

    #[test]
    fn test_strreplace_null_text() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let result = rs_strreplace(std::ptr::null(), c("a"), c("b"));
            assert!(result.is_null());
        }
    }

    #[test]
    fn test_free_and_strdup() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let s = c("hello");
            let mut p: *mut c_char = std::ptr::null_mut();
            assert_eq!(rs_free_and_strdup(&mut p, s), 1);
            assert_eq!(CStr::from_ptr(p).to_str().unwrap(), "hello");
            drop_c(p);
            drop_c_const(s);
        }
    }

    #[test]
    fn test_free_and_strdup_null_ret() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let s = c("hello");
            assert_eq!(
                rs_free_and_strdup(std::ptr::null_mut(), s),
                Errno::EINVAL.to_neg_errno()
            );
            drop_c_const(s);
        }
    }

    #[test]
    fn test_free_and_strdup_uses_null_safe_content_equality() {
        // SAFETY: all allocations are paired with their originating allocator,
        // and every input is a valid NUL-terminated C string.
        unsafe {
            let first = c("same");
            let second = c("same");
            let mut p = std::ptr::null_mut();
            assert_eq!(rs_free_and_strdup(&mut p, first), 1);
            let original = p;
            assert_eq!(rs_free_and_strdup(&mut p, second), 0);
            assert_eq!(p, original);
            drop_c(p);
            drop_c_const(first);
            drop_c_const(second);

            let mut absent = std::ptr::null_mut();
            assert_eq!(rs_free_and_strdup(&mut absent, std::ptr::null()), 0);
        }
    }

    #[test]
    fn test_free_and_strndup_accepts_empty_non_null_source() {
        // SAFETY: `empty` is readable for its declared length and all owned
        // output is released with the C allocator.
        unsafe {
            let empty = [0 as c_char, 1, 2, 3];
            let mut p = std::ptr::null_mut();
            assert_eq!(rs_free_and_strndup(&mut p, empty.as_ptr(), empty.len()), 1);
            assert_eq!(CStr::from_ptr(p).to_bytes(), b"");
            assert_eq!(rs_free_and_strndup(&mut p, empty.as_ptr(), empty.len()), 0);
            drop_c(p);
            assert_eq!(
                rs_free_and_strndup(std::ptr::null_mut(), std::ptr::null(), 0),
                Errno::EINVAL.to_neg_errno()
            );
            let mut absent = std::ptr::null_mut();
            assert_eq!(rs_free_and_strndup(&mut absent, std::ptr::null(), 0), 0);
            assert_eq!(
                rs_free_and_strndup(&mut absent, std::ptr::null(), 1),
                Errno::EINVAL.to_neg_errno()
            );
        }
    }
}
