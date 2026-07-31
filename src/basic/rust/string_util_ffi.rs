// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/string-util.c, src/basic/string-util.h
//
// Deliberately narrow C ABI facade for the reviewed string-util subset. The
// implementation domains retain their normal Rust ABI; this module owns symbol
// export, C pointer contracts, and allocator-boundary documentation.

use libc::{c_char, c_void};
use std::ffi::CStr;
use std::ptr;

use crate::string_util as core;
use crate::string_util_fundamental as fundamental;

const EMPTY: &[u8] = b"\0";
const YES: &[u8] = b"yes\0";
const NO: &[u8] = b"no\0";
const ON: &[u8] = b"on\0";
const OFF: &[u8] = b"off\0";
const LESS: &[u8] = b"<\0";
const EQUAL: &[u8] = b"==\0";
const GREATER: &[u8] = b">\0";

/// Invoke a reviewed core C-ABI implementation from an exported adapter.
///
/// The caller's surrounding `# Safety` section is the contract forwarded to
/// the core implementation. Keeping the unsafe operation here makes the FFI
/// layer's pointer hand-off explicit and prevents otherwise identical adapter
/// bodies from duplicating an unsafe operation site.
macro_rules! forward_core_ffi {
    ($call:expr) => {{
        // SAFETY: the invoking exported adapter documents and forwards this contract.
        unsafe { $call }
    }};
}

/// Borrow an optional C string as bytes without transferring ownership.
///
/// Callers use this only from an ABI adapter whose contract guarantees that a
/// non-null pointer is a live NUL-terminated string for the borrow's use.
macro_rules! optional_c_string_bytes {
    ($value:expr) => {{
        if $value.is_null() {
            None
        } else {
            // SAFETY: upheld by the invoking C ABI adapter's C-string contract.
            Some(unsafe { CStr::from_ptr($value) }.to_bytes())
        }
    }};
}

#[inline]
fn static_c(bytes: &'static [u8]) -> *const c_char {
    bytes.as_ptr().cast()
}

/// C ABI for fundamental `strcmp_ptr()`.
///
/// For non-null inputs, this preserves the C library's complete comparison
/// result, not merely its sign. This is required because the C inline forwards
/// `strcmp()` directly.
///
/// # Safety
/// Each non-null argument must be a readable NUL-terminated C string. Null
/// values keep C's `CMP()` ordering: null sorts before non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strcmp_ptr(a: *const c_char, b: *const c_char) -> i32 {
    // SAFETY: this entry point establishes the same optional C-string contract
    // as the shared, reviewed Rust implementation.
    forward_core_ffi!(core::rs_strcmp_ptr(a, b))
}

/// C ABI for fundamental `strncmp_ptr()`.
///
/// For non-null inputs, this preserves the C library's complete comparison
/// result, not merely its sign. This is required because the C inline forwards
/// `strncmp()` directly.
///
/// # Safety
/// Each non-null argument must be readable through its NUL terminator. Null
/// values keep C's `CMP()` ordering regardless of `n`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strncmp_ptr(a: *const c_char, b: *const c_char, n: usize) -> i32 {
    // SAFETY: this entry point establishes the same optional C-string contract
    // as the shared, reviewed Rust implementation.
    forward_core_ffi!(core::rs_strncmp_ptr(a, b, n))
}

/// C ABI for fundamental `strcasecmp_ptr()`.
///
/// For non-null inputs, this preserves the C library's complete comparison
/// result and locale behavior because the C inline forwards `strcasecmp()`
/// directly.
///
/// # Safety
/// Each non-null argument must be a readable NUL-terminated C string. Null
/// values keep C's `CMP()` ordering.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strcasecmp_ptr(a: *const c_char, b: *const c_char) -> i32 {
    // SAFETY: this entry point establishes the same optional C-string contract
    // as the shared, reviewed Rust implementation.
    forward_core_ffi!(core::rs_strcasecmp_ptr(a, b))
}

/// C ABI for fundamental `streq_ptr()`.
///
/// # Safety
/// Each non-null argument must be a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_streq_ptr(a: *const c_char, b: *const c_char) -> bool {
    // SAFETY: forwarded C-string contract.
    forward_core_ffi!(rs_strcmp_ptr(a, b) == 0)
}

/// C ABI for fundamental `strneq_ptr()`.
///
/// # Safety
/// Each non-null argument must be a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strneq_ptr(a: *const c_char, b: *const c_char, n: usize) -> bool {
    // SAFETY: forwarded C-string contract.
    forward_core_ffi!(rs_strncmp_ptr(a, b, n) == 0)
}

/// C ABI for fundamental `strcaseeq_ptr()`.
///
/// # Safety
/// Each non-null argument must be a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strcaseeq_ptr(a: *const c_char, b: *const c_char) -> bool {
    // SAFETY: forwarded C-string contract.
    forward_core_ffi!(rs_strcasecmp_ptr(a, b) == 0)
}

/// C ABI for fundamental `strlen_ptr()`.
///
/// # Safety
/// A non-null argument must be a readable NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strlen_ptr(s: *const c_char) -> usize {
    // SAFETY: established by this entry point's C-string contract.
    optional_c_string_bytes!(s).map_or(0, <[u8]>::len)
}

/// C ABI for fundamental `isempty()`.
///
/// # Safety
/// A non-null argument must point to at least one readable byte.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_isempty(s: *const c_char) -> bool {
    let first = if s.is_null() {
        None
    } else {
        // SAFETY: established by this entry point's one-byte contract.
        Some(unsafe { *s.cast::<u8>() })
    };
    fundamental::isempty(first)
}

/// C ABI for fundamental `strempty()`.
///
/// # Safety
/// This preserves an input pointer without dereferencing it; a non-null
/// result remains valid only as long as the caller's source pointer is valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strempty(s: *const c_char) -> *const c_char {
    if s.is_null() { static_c(EMPTY) } else { s }
}

/// C ABI for fundamental `yes_no()`.
///
/// # Safety
/// No pointer or ownership preconditions apply. The returned static string is
/// borrowed for the process lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn rs_yes_no(value: bool) -> *const c_char {
    static_c(if value { YES } else { NO })
}

/// C ABI for fundamental `on_off()`.
///
/// # Safety
/// No pointer or ownership preconditions apply. The returned static string is
/// borrowed for the process lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn rs_on_off(value: bool) -> *const c_char {
    static_c(if value { ON } else { OFF })
}

/// C ABI for fundamental `comparison_operator()`.
///
/// # Safety
/// No pointer or ownership preconditions apply. The returned static string is
/// borrowed for the process lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn rs_comparison_operator(result: i32) -> *const c_char {
    static_c(if result < 0 {
        LESS
    } else if result > 0 {
        GREATER
    } else {
        EQUAL
    })
}

/// C ABI for fundamental `memory_startswith()`.
///
/// # Safety
/// `token` must be a non-null readable NUL-terminated C string; `p` must be
/// non-null and readable for `sz` bytes. The returned non-null pointer aliases
/// `p` at the first byte following the matched token.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_memory_startswith(
    p: *const c_void,
    sz: usize,
    token: *const c_char,
) -> *mut c_void {
    if p.is_null() || token.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: established by this entry point's C-string and counted-memory contracts.
    let (input, token) = unsafe {
        (
            std::slice::from_raw_parts(p.cast::<u8>(), sz),
            CStr::from_ptr(token).to_bytes(),
        )
    };
    let Some(offset) = fundamental::memory_startswith(input, token) else {
        return ptr::null_mut();
    };
    // SAFETY: `offset <= sz`, guaranteed by `memory_startswith()` above.
    unsafe { p.cast_mut().cast::<u8>().add(offset).cast() }
}

/// C ABI for fundamental `ascii_isdigit()`.
///
/// # Safety
/// This value-only ABI has no pointer or ownership preconditions.
#[unsafe(no_mangle)]
pub extern "C" fn rs_ascii_isdigit(value: c_char) -> bool {
    fundamental::ascii_isdigit(value as u8)
}

/// C ABI for fundamental `ascii_ishex()`.
///
/// # Safety
/// This value-only ABI has no pointer or ownership preconditions.
#[unsafe(no_mangle)]
pub extern "C" fn rs_ascii_ishex(value: c_char) -> bool {
    fundamental::ascii_ishex(value as u8)
}

/// C ABI for fundamental `ascii_isalpha()`.
///
/// # Safety
/// This value-only ABI has no pointer or ownership preconditions.
#[unsafe(no_mangle)]
pub extern "C" fn rs_ascii_isalpha(value: c_char) -> bool {
    fundamental::ascii_isalpha(value as u8)
}

/// C ABI for `ascii_tolower()`.
///
/// # Safety
/// This is C-callable solely for ABI consistency. `x` is an ordinary C `char`
/// value and has no pointer or ownership preconditions.
#[unsafe(no_mangle)]
pub extern "C" fn rs_ascii_tolower(x: c_char) -> c_char {
    core::rs_ascii_tolower(x)
}

/// C ABI for `ascii_toupper()`.
///
/// # Safety
/// This is C-callable solely for ABI consistency. `x` is an ordinary C `char`
/// value and has no pointer or ownership preconditions.
#[unsafe(no_mangle)]
pub extern "C" fn rs_ascii_toupper(x: c_char) -> c_char {
    core::rs_ascii_toupper(x)
}

/// C ABI for `char_is_cc()`.
///
/// # Safety
/// This has no pointer or ownership preconditions. The conversion to `u8`
/// preserves C's explicit `uint8_t` cast on targets with signed `char`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_char_is_cc(p: c_char) -> bool {
    core::rs_char_is_cc(p as u8)
}

/// C ABI for `ascii_strcasecmp_n()`.
///
/// # Safety
/// `a` and `b` must be non-null and readable for `n` bytes. As in C, this is
/// a counted byte comparison and may read past an earlier NUL byte.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ascii_strcasecmp_n(
    a: *const c_char,
    b: *const c_char,
    n: usize,
) -> i32 {
    // SAFETY: the wrapper's contract is exactly the core's counted-range contract.
    forward_core_ffi!(core::rs_ascii_strcasecmp_n(a, b, n))
}

/// C ABI for `ascii_strcasecmp_nn()`.
///
/// # Safety
/// `a` and `b` must be non-null and readable for `n` and `m` bytes,
/// respectively. The function may read `min(n, m)` bytes from each input.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_ascii_strcasecmp_nn(
    a: *const c_char,
    n: usize,
    b: *const c_char,
    m: usize,
) -> i32 {
    // SAFETY: the wrapper's contract is exactly the core's counted-range contract.
    forward_core_ffi!(core::rs_ascii_strcasecmp_nn(a, n, b, m))
}

/// C ABI for `chars_intersect()`.
///
/// # Safety
/// `a` and `b` must be non-null readable NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_chars_intersect(a: *const c_char, b: *const c_char) -> bool {
    // SAFETY: the wrapper's C-string contract implies the core contract.
    forward_core_ffi!(core::rs_chars_intersect(a, b))
}

/// C ABI for `string_has_cc()`.
///
/// # Safety
/// `p` must be a non-null readable NUL-terminated string. `ok` may be null or
/// a readable NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_string_has_cc(p: *const c_char, ok: *const c_char) -> bool {
    // SAFETY: the wrapper's C-string contract implies the core contract.
    forward_core_ffi!(core::rs_string_has_cc(p, ok))
}

/// C ABI for `strdup_to_full()`.
///
/// # Safety
/// `src` may be null or a readable NUL-terminated string. `ret` may be null
/// or writable for one pointer; on a successful non-null `src` result it owns
/// a malloc-compatible allocation that the C caller must release with `free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strdup_to_full(ret: *mut *mut c_char, src: *const c_char) -> i32 {
    // SAFETY: the wrapper's optional-output and C-string contracts match the core.
    forward_core_ffi!(core::rs_strdup_to_full(ret, src))
}

/// C ABI for `free_and_strdup()`.
///
/// # Safety
/// `p` must be non-null and writable for one pointer whose current non-null
/// value is uniquely owned and malloc-compatible. `s` may be null or a
/// readable NUL-terminated string. On success `*p` remains caller-owned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_free_and_strdup(p: *mut *mut c_char, s: *const c_char) -> i32 {
    // SAFETY: the wrapper's ownership and C-string contracts match the core.
    forward_core_ffi!(core::rs_free_and_strdup(p, s))
}

/// C ABI for `free_and_strndup()`.
///
/// # Safety
/// `p` must be non-null and writable for one pointer whose current non-null
/// value is uniquely owned and malloc-compatible. `s` may be null only when
/// `l` is zero; otherwise it must be readable through its first NUL byte or
/// for `l` bytes, whichever comes first. On success `*p` remains caller-owned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_free_and_strndup(
    p: *mut *mut c_char,
    s: *const c_char,
    l: usize,
) -> i32 {
    // SAFETY: the wrapper's ownership and counted-range contracts match the core.
    forward_core_ffi!(core::rs_free_and_strndup(p, s, l))
}

/// C ABI for `make_cstring()`.
///
/// # Safety
/// `s` may be null only when `n` is zero; otherwise it must be readable for
/// `n` bytes. `ret` may be null or writable for one pointer and receives a
/// malloc-compatible allocation on success. The raw integer mode uses the C
/// enum representation and invalid values fail closed with `-EINVAL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_make_cstring(
    s: *const c_void,
    n: usize,
    mode: i32,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: the wrapper's counted-range, output, and ownership contracts
    // match the core; byte buffers have no alignment requirement.
    forward_core_ffi!(core::rs_make_cstring(s.cast::<c_char>(), n, mode, ret))
}

/// C ABI for `split_pair()`.
///
/// # Safety
/// `s` and `sep` must be non-null readable NUL-terminated strings and `sep`
/// must not be empty. Each output may be null or writable for one pointer; on
/// success each non-null output owns a malloc-compatible string for `free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_split_pair(
    s: *const c_char,
    sep: *const c_char,
    ret_first: *mut *mut c_char,
    ret_second: *mut *mut c_char,
) -> i32 {
    // SAFETY: the wrapper's C-string and optional-output contracts match the core.
    forward_core_ffi!(core::rs_split_pair(s, sep, ret_first, ret_second))
}

/// C ABI for `str_common_prefix()`.
///
/// # Safety
/// `a` and `b` must be non-null readable NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_str_common_prefix(a: *const c_char, b: *const c_char) -> usize {
    // SAFETY: the wrapper's C-string contract implies the core contract.
    forward_core_ffi!(core::rs_str_common_prefix(a, b))
}

/// C ABI for `strspn_from_end()`.
///
/// # Safety
/// `str` and `accept` must be non-null readable NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strspn_from_end(str_: *const c_char, accept: *const c_char) -> usize {
    // SAFETY: the wrapper's C-string contract implies the core contract.
    forward_core_ffi!(core::rs_strspn_from_end(str_, accept))
}

/// C ABI for `streq_skip_trailing_chars()`.
///
/// # Safety
/// `s1` and `s2` may be null or readable NUL-terminated strings. `ok` may be
/// null (selecting C's whitespace default) or a readable NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_streq_skip_trailing_chars(
    s1: *const c_char,
    s2: *const c_char,
    ok: *const c_char,
) -> bool {
    // SAFETY: the wrapper's nullable C-string contract matches the core.
    forward_core_ffi!(core::rs_streq_skip_trailing_chars(s1, s2, ok))
}

/// C ABI for `strdupspn()`.
///
/// # Safety
/// `a` and `accept` may be null or readable NUL-terminated strings. The
/// returned allocation is malloc-compatible and must be released with `free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strdupspn(a: *const c_char, accept: *const c_char) -> *mut c_char {
    // SAFETY: the wrapper's C-string contract implies the core contract.
    forward_core_ffi!(core::rs_strdupspn(a, accept))
}

/// C ABI for `strdupcspn()`.
///
/// # Safety
/// `a` and `reject` may be null or readable NUL-terminated strings. The
/// returned allocation is malloc-compatible and must be released with `free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strdupcspn(a: *const c_char, reject: *const c_char) -> *mut c_char {
    // SAFETY: the wrapper's C-string contract implies the core contract.
    forward_core_ffi!(core::rs_strdupcspn(a, reject))
}

/// C ABI for `string_replace_char()`.
///
/// # Safety
/// `str` must be a non-null writable NUL-terminated string. `old_char` and
/// `new_char` must be distinct and non-NUL, matching the C preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_string_replace_char(
    str_: *mut c_char,
    old_char: c_char,
    new_char: c_char,
) -> *mut c_char {
    // SAFETY: the wrapper's writable-string contract implies the core contract.
    forward_core_ffi!(core::rs_string_replace_char(str_, old_char, new_char))
}

/// C ABI for `strrep()`.
///
/// # Safety
/// `s` must be a non-null readable NUL-terminated string. The returned
/// allocation is malloc-compatible and must be released with `free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strrep(s: *const c_char, n: usize) -> *mut c_char {
    // SAFETY: the wrapper's C-string contract implies the core contract.
    forward_core_ffi!(core::rs_strrep(s, n))
}

/// C ABI for `strreplace()`.
///
/// # Safety
/// `text` may be null or a readable NUL-terminated string. `old_string` and
/// `new_string` must be non-null readable NUL-terminated strings. The returned
/// allocation is malloc-compatible and must be released with `free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strreplace(
    text: *const c_char,
    old_string: *const c_char,
    new_string: *const c_char,
) -> *mut c_char {
    // SAFETY: the wrapper's C-string contract implies the core contract.
    forward_core_ffi!(core::rs_strreplace(text, old_string, new_string))
}

/// C ABI for `json_underscorify()`.
///
/// # Safety
/// `p` must be null or a writable NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_json_underscorify(p: *mut c_char) -> *mut c_char {
    // SAFETY: the wrapper's writable C-string contract matches the core.
    forward_core_ffi!(core::rs_json_underscorify(p))
}

/// C ABI for `json_dashify()`.
///
/// # Safety
/// `p` must be null or a writable NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_json_dashify(p: *mut c_char) -> *mut c_char {
    // SAFETY: the wrapper's writable C-string contract matches the core.
    forward_core_ffi!(core::rs_json_dashify(p))
}

/// C ABI for `in_charset()`.
///
/// # Safety
/// `s` and `charset` must be non-null readable NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_in_charset(s: *const c_char, charset: *const c_char) -> bool {
    // SAFETY: the wrapper's C-string contract implies the core contract.
    forward_core_ffi!(core::rs_in_charset(s, charset))
}

/// C ABI for `strgrowpad0()`.
///
/// # Safety
/// `s` must be non-null and writable for one pointer. Its current non-null
/// value must be a uniquely-owned malloc-compatible NUL-terminated allocation.
/// On success `*s` remains caller-owned and can be released with `free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strgrowpad0(s: *mut *mut c_char, l: usize) -> i32 {
    // SAFETY: the wrapper's allocation ownership contract matches the core.
    forward_core_ffi!(core::rs_strgrowpad0(s, l))
}

/// C ABI for `strshorten()`.
///
/// # Safety
/// `s` must be non-null and readable through its first NUL or for `l + 1`
/// bytes, whichever comes first. If no NUL occurs before byte `l`, that byte
/// must be writable. No terminator is required beyond the bounded region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strshorten(s: *mut c_char, l: usize) -> *mut c_char {
    // SAFETY: the wrapper's writable C-string contract matches the core.
    forward_core_ffi!(core::rs_strshorten(s, l))
}

/// C ABI for `strrstr_internal()`.
///
/// # Safety
/// `haystack` and `needle` may be null; each non-null pointer must designate
/// a readable NUL-terminated C string. A non-null result aliases `haystack`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strrstr_internal(
    haystack: *const c_char,
    needle: *const c_char,
) -> *mut c_char {
    // SAFETY: the wrapper's nullable C-string contract matches the core.
    forward_core_ffi!(core::rs_strrstr_internal(haystack, needle))
}

/// C ABI for `strlevenshtein()`.
///
/// # Safety
/// `x` and `y` may be null; each non-null pointer must designate a readable
/// NUL-terminated C string. Inputs are compared as bytes, not locale or UTF-8
/// characters. Allocation failure is reported as `-ENOMEM`, as in C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strlevenshtein(x: *const c_char, y: *const c_char) -> isize {
    // SAFETY: the wrapper's nullable C-string contract matches the core.
    forward_core_ffi!(core::rs_strlevenshtein(x, y))
}

/// C ABI for `version_is_valid()`.
///
/// # Safety
/// `s` may be null or a readable NUL-terminated C string. `flags` uses the C
/// `VersionFlags` integer representation; unrecognized bits are ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_version_is_valid(s: *const c_char, flags: i32) -> bool {
    // SAFETY: the wrapper's nullable C-string contract and integer flag ABI
    // match the core and current C authority.
    forward_core_ffi!(core::rs_version_is_valid(s, flags))
}

/// C ABI for `cellescape()`.
///
/// # Safety
/// `buf` must be non-null and writable for `len > 0` bytes. `s` must be a
/// non-null readable NUL-terminated byte string. The returned non-null pointer
/// is exactly `buf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_cellescape(
    buf: *mut c_char,
    len: usize,
    s: *const c_char,
) -> *mut c_char {
    // SAFETY: the wrapper's output-capacity and C-string contract matches the core.
    forward_core_ffi!(core::rs_cellescape(buf, len, s))
}

/// C ABI for `string_erase()`.
///
/// # Safety
/// `x` may be null or a writable NUL-terminated C string. Non-null visible
/// bytes are erased with libc's non-elidable `explicit_bzero` primitive.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_string_erase(x: *mut c_char) -> *mut c_char {
    // SAFETY: the wrapper's nullable writable C-string contract matches the core.
    forward_core_ffi!(core::rs_string_erase(x))
}

/// C ABI for `strextendn()`.
///
/// # Safety
/// `x` must be non-null and writable for one pointer whose current value is
/// null or uniquely-owned malloc-compatible NUL-terminated storage. For
/// non-zero `l`, `s` must be readable through its first NUL or for `l` bytes,
/// whichever comes first, and must not alias the allocation currently held in
/// `*x`. Success updates `*x` to a malloc-compatible allocation; allocation
/// failure leaves it unchanged.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_strextendn(
    x: *mut *mut c_char,
    s: *const c_char,
    l: usize,
) -> *mut c_char {
    // SAFETY: the wrapper's allocation, source, and non-aliasing contract matches the core.
    forward_core_ffi!(core::rs_strextendn(x, s, l))
}

/// C ABI for `escape_non_printable_full()`.
///
/// # Safety
/// `str` must be a non-null readable NUL-terminated byte string. `flags` uses
/// the C `XEscapeFlags` integer representation. A non-null result is a fresh
/// malloc-compatible allocation owned by the caller and released with `free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_escape_non_printable_full(
    str_: *const c_char,
    console_width: usize,
    flags: i32,
) -> *mut c_char {
    // SAFETY: the wrapper's C-string, flag, and allocator contract matches the core.
    forward_core_ffi!(core::rs_escape_non_printable_full(
        str_,
        console_width,
        flags
    ))
}
