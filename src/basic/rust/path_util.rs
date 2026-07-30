// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.path-util; authority=src/basic/path-util.c,src/basic/path-util.h,src/basic/fd-util.c,src/basic/fd-util.h
//
// Path and filename validation/comparison utilities.

use std::ffi::CStr;

use crate::ffi::{
    Errno, free, malloc, memcmp, memmove, strchr, strcmp, strdup, strlen, strrchr, strstr,
};
use libc::c_char;

mod byte_abi;

// ── Constants ──────────────────────────────────────────────────────────────

const NAME_MAX: usize = 255;
const FDNAME_MAX: usize = 255;
const PATH_MAX_VAL: usize = 4096;

// ── Internal helpers ──────────────────────────────────────────────────────

/// Check if byte string s starts with prefix p.
// SAFETY: `s` and `p` must each be live, NUL-terminated C strings readable for
// the duration of this call.
unsafe fn startswith(s: *const c_char, p: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let s = CStr::from_ptr(s);
        let p = CStr::from_ptr(p);
        s.to_bytes().starts_with(p.to_bytes())
    }
}

/// Check if byte string s ends with suffix p.
// SAFETY: `s` and `p` must each be live, NUL-terminated C strings readable for
// the duration of this call.
unsafe fn endswith(s: *const c_char, p: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let s = CStr::from_ptr(s);
        let p = CStr::from_ptr(p);
        let s_bytes = s.to_bytes();
        let p_bytes = p.to_bytes();
        if p_bytes.len() > s_bytes.len() {
            return false;
        }
        s_bytes.ends_with(p_bytes)
    }
}

/// Check if string is in a set of candidates.
// SAFETY: `s` and every pointer in `candidates` must be live, NUL-terminated
// C strings readable for the duration of this call.
unsafe fn str_in_set(s: *const c_char, candidates: &[*const c_char]) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let s = CStr::from_ptr(s);
        for &c in candidates {
            if strcmp(s.as_ptr(), c) == 0 {
                return true;
            }
        }
        false
    }
}

/// Check if string ends with any of the given suffixes.
// SAFETY: `s` and every pointer in `suffixes` must be live, NUL-terminated C
// strings readable for the duration of this call.
unsafe fn endswith_set(s: *const c_char, suffixes: &[*const c_char]) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        for &suffix in suffixes {
            if endswith(s, suffix) {
                return true;
            }
        }
        false
    }
}

/// streq: fast check for string equality.
// SAFETY: `a` and `b` must each be live, NUL-terminated C strings readable for
// the duration of this call.
unsafe fn streq(a: *const c_char, b: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe { strcmp(a, b) == 0 }
}

/// Skip leading '/' and "./" sequences.
/// Port of static skip_slash_or_dot() from path-util.c.
// SAFETY: `p` must be a live, readable NUL-terminated C string; the returned
// pointer borrows that string.
unsafe fn skip_slash_or_dot(mut p: *const c_char) -> *const c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        while !isempty(p) {
            if *p == b'/' as c_char {
                p = p.add(1);
                continue;
            }
            if *p == b'.' as c_char && *p.add(1) == b'/' as c_char {
                p = p.add(2);
                continue;
            }
            break;
        }
        p
    }
}

/// Check if path is valid, optionally accepting ".." components.
/// Port of path_is_valid_full() from path-util.c.
// SAFETY: when non-null, `p` must be a live, readable NUL-terminated C string
// for the duration of this call.
unsafe fn rs_path_is_valid_full(p: *const c_char, accept_dot_dot: bool) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if p.is_null() || *p == 0 {
            return false;
        }

        let mut e = p;
        loop {
            let r =
                rs_path_find_first_component_inner(&mut e, accept_dot_dot, std::ptr::null_mut());
            if r < 0 {
                return false;
            }
            if e.offset_from(p) as usize >= PATH_MAX_VAL {
                return false;
            }
            if *e == 0 {
                return true;
            }
        }
    }
}

/// Internal: like C isempty for C string
// SAFETY: when non-null, `s` must point to a live, readable `c_char` for the
// duration of this call.
unsafe fn isempty(s: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe { s.is_null() || *s == 0 }
}

/// Compare two booleans as -1/0/1.
fn cmp_bool(a: bool, b: bool) -> i32 {
    if a == b {
        0
    } else if a {
        1
    } else {
        -1
    }
}

/// Compare two i32 values as -1/0/1.
fn cmp_int(a: i32, b: i32) -> i32 {
    if a == b {
        0
    } else if a > b {
        1
    } else {
        -1
    }
}

/// Release a uniquely-owned C-allocator string.
///
/// # Safety
/// `p` must be null or the original base pointer of a still-live allocation
/// obtained from this crate's C-compatible allocation helpers.
unsafe fn libc_free(p: *mut c_char) {
    // SAFETY: upheld by this helper's contract.
    unsafe { free(p as *mut std::ffi::c_void) };
}

// ── Public API ────────────────────────────────────────────────────────────

/// Check if a string contains a '/' character (i.e. looks like a path).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_path(p: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if p.is_null() {
            return false;
        }
        !strchr(p, '/' as i32).is_null()
    }
}

/// Check if path is "." or "..".
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dot_or_dot_dot(path: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if path.is_null() {
            return false;
        }
        let s = CStr::from_ptr(path);
        let bytes = s.to_bytes();
        bytes == b"." || bytes == b".."
    }
}

/// Check if string is valid as part of a filename (allows "." and "..").
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_filename_part_is_valid(p: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if p.is_null() {
            return false;
        }

        // Find first '/' or NUL
        let mut e = p;
        while *e != 0 && *e != b'/' as c_char {
            e = e.add(1);
        }

        if *e != 0 {
            return false; // Found '/' before NUL
        }

        let len = e.offset_from(p) as usize;
        if len > NAME_MAX {
            return false;
        }

        true
    }
}

/// Check if string is a valid filename (excludes "." and "..").
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_filename_is_valid(p: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if p.is_null() || *p == 0 {
            return false;
        }
        if rs_dot_or_dot_dot(p) {
            return false;
        }
        rs_filename_part_is_valid(p)
    }
}

/// Validate a name for $LISTEN_FDNAMES: ASCII, no control chars, no ':'.
/// Validates a name for $LISTEN_FDNAMES: ASCII, no control chars, no ':'.
/// Empty string is allowed. Max length is FDNAME_MAX (255).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_fdname_is_valid(s: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if s.is_null() {
            return false;
        }
        let mut len: usize = 0;
        let mut p = s;
        while *p != 0 {
            let c = *p as u8;
            if c < b' ' || c >= 127 || c == b':' {
                return false;
            }
            len += 1;
            if len > FDNAME_MAX {
                return false;
            }
            p = p.add(1);
        }
        true
    }
}

/// Check if filename is hidden or a backup file.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_hidden_or_backup_file(filename: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if filename.is_null() {
            return false;
        }

        if *filename == b'.' as c_char {
            return true;
        }

        let lost_found = c"lost+found";
        let aquota_user = c"aquota.user";
        let aquota_group = c"aquota.group";

        if str_in_set(
            filename,
            &[
                lost_found.as_ptr(),
                aquota_user.as_ptr(),
                aquota_group.as_ptr(),
            ],
        ) {
            return true;
        }

        if endswith(filename, c"~".as_ptr()) {
            return true;
        }

        let dot = strrchr(filename, '.' as i32);
        if dot.is_null() {
            return false;
        }

        let suffix = dot.add(1);
        static SUFFIXES: &[&[u8]] = &[
            b"ignore",
            b"rpmnew",
            b"rpmsave",
            b"rpmorig",
            b"dpkg-old",
            b"dpkg-new",
            b"dpkg-tmp",
            b"dpkg-dist",
            b"dpkg-bak",
            b"dpkg-backup",
            b"dpkg-remove",
            b"ucf-new",
            b"ucf-old",
            b"ucf-dist",
            b"swp",
            b"bak",
            b"old",
            b"new",
        ];

        // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
        let suffix_cstr = CStr::from_ptr(suffix);
        for &s in SUFFIXES {
            if suffix_cstr.to_bytes() == s {
                return true;
            }
        }

        false
    }
}

/// Check if path is empty, NULL, or "/".
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_empty_or_root(path: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if path.is_null() || *path == 0 {
            return true;
        }
        // path_equal(path, "/")
        *path == b'/' as c_char && *path.add(1) == 0
    }
}

/// Return a borrowed `"/"` if `path` is empty, otherwise return `path`.
///
/// The result is either the original borrowed pointer or this module's static
/// NUL-terminated root string; callers must not free it.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_empty_to_root(path: *const c_char) -> *const c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        static ROOT: &[u8] = b"/\0";
        if path.is_null() || *path == 0 {
            return ROOT.as_ptr() as *const c_char;
        }
        path
    }
}

/// Check if path implies a directory (ends with "/", ".", or "..").
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_implies_directory(path: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if path.is_null() {
            return false;
        }

        if rs_dot_or_dot_dot(path) {
            return true;
        }

        endswith_set(path, &[c"/".as_ptr(), c"/.".as_ptr(), c"/..".as_ptr()])
    }
}

// ── Path normalization chain ──────────────────────────────────────────────
// PORT-SYNC: src/basic/path-util.c

/// Check if path is normalized: safe, no ".", "./", "/.", "/./", or "//".
/// Port of path_is_normalized() from path-util.c.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_is_normalized(p: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if !rs_path_is_safe(p) {
            return false;
        }

        if streq(p, c".".as_ptr())
            || startswith(p, c"./".as_ptr())
            || endswith(p, c"/.".as_ptr())
            || !strstr(p, c"/./".as_ptr()).is_null()
        {
            return false;
        }

        if !strstr(p, c"//".as_ptr()).is_null() {
            return false;
        }

        true
    }
}

/// Check if path is absolute (starts with '/').
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_is_absolute(p: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if p.is_null() {
            return false;
        }
        *p == b'/' as c_char
    }
}

// ── is_device_path ─────────────────────────────────────────────────────────

fn next_path_component_bytes<'a>(
    path: &'a [u8],
    cursor: &mut usize,
) -> Result<Option<&'a [u8]>, ()> {
    loop {
        while path.get(*cursor) == Some(&b'/') {
            *cursor += 1;
        }
        if *cursor == path.len() {
            return Ok(None);
        }

        let start = *cursor;
        while *cursor < path.len() && path[*cursor] != b'/' {
            *cursor += 1;
        }
        let component = &path[start..*cursor];
        if component.len() > libc::NAME_MAX as usize {
            return Err(());
        }
        if component == b"." {
            continue;
        }
        return Ok(Some(component));
    }
}

/// Return the byte offset selected by path-util.h's `skip_dev_prefix()`.
///
/// `path_startswith()` is component-aware: repeated slashes and `./` are
/// ignored, a component may not exceed NAME_MAX, and the returned pointer is
/// after separators following the matched `dev` component. A mismatch (or an
/// invalid overlong component) returns zero, which is the original pointer.
pub(crate) fn skip_dev_prefix_offset(path: &[u8]) -> usize {
    fn skip_slash_or_dot(path: &[u8], mut cursor: usize) -> usize {
        while cursor < path.len() {
            if path[cursor] == b'/' {
                cursor += 1;
            } else if path[cursor..].starts_with(b"./") {
                cursor += 2;
            } else {
                break;
            }
        }
        cursor
    }

    // The literal prefix `/dev/` is absolute, so path_startswith() first
    // rejects relative candidates.
    if path.first() != Some(&b'/') {
        return 0;
    }

    let first = skip_slash_or_dot(path, 0);
    if first == path.len() || path[first..] == *b"." {
        return 0;
    }
    let end = path[first..]
        .iter()
        .position(|&byte| byte == b'/')
        .map_or(path.len(), |length| first + length);
    if end - first > libc::NAME_MAX as usize || &path[first..end] != b"dev" {
        return 0;
    }

    let next = skip_slash_or_dot(path, end);
    if path[next..] == *b"." {
        next + 1
    } else {
        next
    }
}

/// Safe byte core of C's `is_device_path()`.
///
/// C's `path_startswith()` compares path components: it ignores repeated
/// slashes and `.` components, accepts `..`, rejects overlong components, and
/// never interprets the bytes as UTF-8.
#[inline]
fn is_device_path_bytes(path: &[u8]) -> bool {
    if path.first() != Some(&b'/') {
        return false;
    }

    let mut cursor = 0;
    let Ok(Some(first)) = next_path_component_bytes(path, &mut cursor) else {
        return false;
    };
    if first != b"dev" && first != b"sys" {
        return false;
    }

    matches!(next_path_component_bytes(path, &mut cursor), Ok(Some(_)))
}

/// C ABI mirror of `is_device_path()`.
///
/// # Safety
///
/// `path` must be null or point to a readable NUL-terminated byte string for
/// this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_device_path(path: *const c_char) -> bool {
    if path.is_null() {
        return false;
    }

    // SAFETY: guaranteed by the entry-point contract after the null check.
    is_device_path_bytes(unsafe { CStr::from_ptr(path) }.to_bytes())
}

/// Check if path starts with /dev/ or /run/systemd/inaccessible/, is normalized, and does not end with /.
/// Checks: starts with /dev/ or /run/systemd/inaccessible/, doesn't end with /, is normalized.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_valid_device_node_path(path: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if path.is_null() {
            return false;
        }
        // Check prefix
        let has_dev_prefix = startswith(path, c"/dev/".as_ptr());
        let has_inaccessible_prefix = startswith(path, c"/run/systemd/inaccessible/".as_ptr());
        if !has_dev_prefix && !has_inaccessible_prefix {
            return false;
        }
        // Must not end with /
        let len = strlen(path);
        if len > 0 && *path.add(len - 1) == b'/' as c_char {
            return false;
        }
        // Must be normalized
        rs_path_is_normalized(path)
    }
}

/// Check if path is a valid device node or a "block-"/"char-" prefix.
/// Like valid_device_node_path(), but also allows "block-" and "char-" prefixes.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_valid_device_allow_pattern(path: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if path.is_null() {
            return false;
        }
        // Check for "block-" or "char-" prefix
        if startswith(path, c"block-".as_ptr()) || startswith(path, c"char-".as_ptr()) {
            return true;
        }
        rs_valid_device_node_path(path)
    }
}

// ── path_find_first_component (public) ────────────────────────────────────

/// Find the first path component, advancing *p past it.
/// Finds the first path component, advancing *p past it.
/// Returns: component length (>= 0) on success, -22 on invalid.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_find_first_component(
    p: *mut *const c_char,
    accept_dot_dot: bool,
    ret: *mut *const c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe { rs_path_find_first_component_inner(p, accept_dot_dot, ret) }
}

/// # Safety
///
/// `p` must be a writable pointer to a live C-string pointer. `ret`, when
/// non-null, must be writable. Any pointer published through either output
/// borrows the input C string and is valid only while that input remains live.
unsafe fn rs_path_find_first_component_inner(
    p: *mut *const c_char,
    accept_dot_dot: bool,
    ret: *mut *const c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let q = *p;

        let first = skip_slash_or_dot(q);
        if isempty(first) {
            *p = first;
            if !ret.is_null() {
                *ret = std::ptr::null();
            }
            return 0;
        }
        if streq(first, c".".as_ptr()) {
            *p = first.add(1);
            if !ret.is_null() {
                *ret = std::ptr::null();
            }
            return 0;
        }

        // Find end of first component
        let mut end_first = first;
        while *end_first != 0 && *end_first != b'/' as c_char {
            end_first = end_first.add(1);
        }

        let len = end_first.offset_from(first) as usize;
        if len > NAME_MAX {
            return Errno::EINVAL.to_neg_errno();
        }
        if !accept_dot_dot && len == 2 && *first == b'.' as _ && *first.add(1) == b'.' as _ {
            return Errno::EINVAL.to_neg_errno();
        }

        let next = skip_slash_or_dot(end_first);

        if streq(next, c".".as_ptr()) {
            *p = next.add(1);
        } else {
            *p = next;
        }
        if !ret.is_null() {
            *ret = first;
        }
        len as i32
    }
}

// ── path_find_last_component ──────────────────────────────────────────────

/// Skip backward past '/' and '/./' sequences.
///
/// # Safety
///
/// `path` and `q` must point into the same live NUL-terminated C string, with
/// `q` at or after `path`. The returned pointer borrows that input string.
unsafe fn skip_slash_or_dot_backward(path: *const c_char, mut q: *const c_char) -> *const c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        loop {
            if q.is_null() {
                return std::ptr::null();
            }
            let c = *q;
            if c == b'/' as c_char {
                // continue
            } else if q > path && *q.sub(1) == b'/' as c_char && c == b'.' as c_char {
                // "/." — continue
            } else if q == path && c == b'.' as c_char {
                // "." at start — continue
            } else {
                break;
            }
            if q == path {
                return std::ptr::null();
            }
            q = q.sub(1);
        }
        q
    }
}

/// Find the last path component, similar to path_find_first_component but from the end.
/// Finds the last path component, similar to path_find_first_component but from the end.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_find_last_component(
    path: *const c_char,
    accept_dot_dot: bool,
    next: *mut *const c_char,
    ret: *mut *const c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if isempty(path) {
            if !next.is_null() {
                *next = path;
            }
            if !ret.is_null() {
                *ret = std::ptr::null();
            }
            return 0;
        }

        let q = if !next.is_null() && !(*next).is_null() {
            let n = *next;
            if n < path || n > path.add(strlen(path)) {
                return Errno::EINVAL.to_neg_errno();
            }
            if n == path {
                if !ret.is_null() {
                    *ret = std::ptr::null();
                }
                return 0;
            }
            let cv = *n as u8;
            if cv != 0 && cv != b'/' {
                return Errno::EINVAL.to_neg_errno();
            }
            n.sub(1)
        } else {
            path.add(strlen(path)).sub(1)
        };

        let q = skip_slash_or_dot_backward(path, q);
        if q.is_null() {
            // root directory, "." or "./"
            if !next.is_null() {
                *next = path;
            }
            if !ret.is_null() {
                *ret = std::ptr::null();
            }
            return 0;
        }

        let last_end = q.add(1);

        // Walk backward to find beginning of last component
        let mut qb = q;
        while !qb.is_null() && *qb != b'/' as c_char {
            if qb == path {
                qb = std::ptr::null();
                break;
            }
            qb = qb.sub(1);
        }

        let last_begin = if !qb.is_null() { qb.add(1) } else { path };
        let len = last_end.offset_from(last_begin) as usize;

        if len > NAME_MAX {
            return Errno::EINVAL.to_neg_errno();
        }
        if !accept_dot_dot
            && len == 2
            && *last_begin == b'.' as c_char
            && *last_begin.add(1) == b'.' as c_char
        {
            return Errno::EINVAL.to_neg_errno();
        }

        if !next.is_null() {
            let q2 = skip_slash_or_dot_backward(path, qb);
            *next = if !q2.is_null() { q2.add(1) } else { path };
        }

        if !ret.is_null() {
            *ret = last_begin;
        }
        len as i32
    }
}

// ── last_path_component ───────────────────────────────────────────────────

/// Find the last component of the path, preserving trailing slash.
/// Finds the last component of the path, preserving trailing slash.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_last_path_component(path: *const c_char) -> *const c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if path.is_null() {
            return std::ptr::null();
        }

        let l = strlen(path);
        if l == 0 {
            return path;
        }

        let mut k = l;
        while k > 0 && *path.add(k - 1) == b'/' as c_char {
            k -= 1;
        }

        if k == 0 {
            // root directory
            return path.add(l - 1);
        }

        while k > 0 && *path.add(k - 1) != b'/' as c_char {
            k -= 1;
        }

        path.add(k)
    }
}

// ── path_compare ──────────────────────────────────────────────────────────

/// Compare two paths component by component.
/// Compares two paths component by component.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_compare(a: *const c_char, b: *const c_char) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        // Order NULL before non-NULL
        let mut r = cmp_bool(!a.is_null(), !b.is_null());
        if r != 0 {
            return r;
        }

        // Absolute before relative (or vice versa — just consistent)
        r = cmp_bool(rs_path_is_absolute(a), rs_path_is_absolute(b));
        if r != 0 {
            return r;
        }

        let mut pa = a;
        let mut pb = b;

        loop {
            let mut aa: *const c_char = std::ptr::null();
            let mut bb: *const c_char = std::ptr::null();

            let j = rs_path_find_first_component_inner(&mut pa, true, &mut aa);
            let k = rs_path_find_first_component_inner(&mut pb, true, &mut bb);

            if j < 0 || k < 0 {
                // Invalid paths: order invalid after valid
                r = cmp_bool(j >= 0, k >= 0);
                if r != 0 {
                    return r;
                }
                // Both invalid: fall back to strcmp
                return strcmp(pa, pb);
            }

            // Prefixes first: "/foo" before "/foo/bar"
            if j == 0 {
                if k == 0 {
                    return 0;
                }
                return -1;
            }
            if k == 0 {
                return 1;
            }

            // Alphabetical: "/foo/aaa" before "/foo/b"
            let min_jk = if j < k { j } else { k } as usize;
            r = memcmp(
                aa as *const std::ffi::c_void,
                bb as *const std::ffi::c_void,
                min_jk,
            );
            if r != 0 {
                return r;
            }

            // "/foo/a" before "/foo/aaa"
            r = cmp_int(j, k);
            if r != 0 {
                return r;
            }
        }
    }
}

// ── path_startswith_full ──────────────────────────────────────────────────

/// Flags for path_startswith_full (matching C PathStartWithFlags).
const PATH_STARTSWITH_REFUSE_DOT_DOT: u32 = 1;
const PATH_STARTSWITH_RETURN_LEADING_SLASH: u32 = 2;

/// Return pointer past matched prefix, or NULL if prefix does not match.
/// Returns pointer past matched prefix, or NULL if prefix doesn't match.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_startswith_full(
    original_path: *const c_char,
    mut prefix: *const c_char,
    flags: u32,
) -> *const c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let mut path = original_path;

        // Both must be absolute or both relative
        let pa = *path == b'/' as c_char;
        let pb = *prefix == b'/' as c_char;
        if pa != pb {
            return std::ptr::null();
        }

        let accept_dot_dot = (flags & PATH_STARTSWITH_REFUSE_DOT_DOT) == 0;

        loop {
            let mut p: *const c_char = std::ptr::null();
            let mut q: *const c_char = std::ptr::null();

            let m = rs_path_find_first_component_inner(&mut path, accept_dot_dot, &mut p);
            if m < 0 {
                return std::ptr::null();
            }

            let n = rs_path_find_first_component_inner(&mut prefix, accept_dot_dot, &mut q);
            if n < 0 {
                return std::ptr::null();
            }

            if n == 0 {
                // Prefix exhausted — return remaining path
                let mut result = if !p.is_null() { p } else { path };

                if (flags & PATH_STARTSWITH_RETURN_LEADING_SLASH) != 0 {
                    if result <= original_path {
                        return std::ptr::null();
                    }
                    result = result.sub(1);
                    if *result != b'/' as c_char {
                        return std::ptr::null();
                    }
                }

                return result;
            }

            if m != n {
                return std::ptr::null();
            }

            // Compare component bytes
            let len = m as usize;
            let mut ok = true;
            for i in 0..len {
                if *p.add(i) != *q.add(i) {
                    ok = false;
                    break;
                }
            }
            if !ok {
                return std::ptr::null();
            }
        }
    }
}

// ── path_simplify_alloc ───────────────────────────────────────────────────

/// Remove redundant slashes and dots from a path. Modifies in-place.
/// Removes redundant slashes and dots from a path. Modifies in-place.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_simplify_full(path: *mut c_char, flags: u32) -> *mut c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if isempty(path) {
            return path;
        }

        let keep_trailing_slash = (flags & 1 != 0) && endswith(path, c"/".as_ptr());
        let absolute = rs_path_is_absolute(path);
        let mut f = path;
        if absolute {
            f = f.add(1); // skip leading /
        }

        let mut add_slash = false;
        let mut beginning = true;
        let mut p: *const c_char = f;

        loop {
            let mut e: *const c_char = std::ptr::null();
            let r = rs_path_find_first_component_inner(&mut p, true, &mut e);

            if r == 0 {
                break;
            }

            if r > 0 && absolute && beginning && startswith(e, c"..".as_ptr()) {
                // Skip ".." at beginning of absolute path
                continue;
            }

            beginning = false;

            if add_slash {
                *f = b'/' as c_char;
                f = f.add(1);
            }

            if r < 0 {
                // Invalid path — copy remaining as-is
                let remaining = strlen(p) + 1;
                memmove(
                    f as *mut std::ffi::c_void,
                    p as *const std::ffi::c_void,
                    remaining,
                );
                return path;
            }

            // Copy component
            let len = r as usize;
            for i in 0..len {
                *f = *e.add(i);
                f = f.add(1);
            }

            add_slash = true;
        }

        // If we stripped everything, add "."
        if f == path {
            *f = b'.' as c_char;
            f = f.add(1);
        }

        if *f.sub(1) != b'/' as c_char && keep_trailing_slash {
            *f = b'/' as c_char;
            f = f.add(1);
        }

        *f = 0;
        path
    }
}

/// Simplify a path, returning a newly allocated copy.
/// Simplifies a path, returning a newly allocated copy.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_simplify_alloc(path: *const c_char, ret: *mut *mut c_char) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if ret.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }
        if path.is_null() {
            *ret = std::ptr::null_mut();
            return 0;
        }

        let t = strdup(path);
        if t.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }

        rs_path_simplify_full(t, 0);
        *ret = t;
        0
    }
}

// ── path_make_relative ────────────────────────────────────────────────────

/// Make a path relative to another by stripping common prefix and adding ".." elements.
/// Makes a path relative to another by stripping common prefix and adding ".." elements.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_make_relative(
    mut from: *const c_char,
    mut to: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if from.is_null() || to.is_null() || ret.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        if !rs_path_is_absolute(from) || !rs_path_is_absolute(to) {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut result: *mut c_char = std::ptr::null_mut();
        let remaining_to: *const c_char;

        // Strip common prefix
        loop {
            let mut f: *const c_char = std::ptr::null();
            let mut t: *const c_char = std::ptr::null();

            let r = rs_path_find_first_component_inner(&mut from, true, &mut f);
            if r < 0 {
                return r;
            }

            let k = rs_path_find_first_component_inner(&mut to, true, &mut t);
            if k < 0 {
                return k;
            }

            if r == 0 {
                // End of 'from'
                if k == 0 {
                    // from and to are equivalent
                    result = strdup(c".".as_ptr());
                    if result.is_null() {
                        return Errno::ENOMEM.to_neg_errno();
                    }
                } else {
                    // 'to' is inside of 'from'
                    let r2 = rs_path_simplify_alloc(t, &mut result);
                    if r2 < 0 {
                        return r2;
                    }
                    if !rs_path_is_valid_full(result, true) {
                        libc_free(result);
                        return Errno::EINVAL.to_neg_errno();
                    }
                }
                *ret = result;
                return 0;
            }

            // Check if components differ
            let r_usize = r as usize;
            if r != k {
                remaining_to = t;
                break;
            }
            let mut eq = true;
            for i in 0..r_usize {
                if *f.add(i) != *t.add(i) {
                    eq = false;
                    break;
                }
            }
            if !eq {
                remaining_to = t;
                break;
            }
        }

        // Count remaining 'from' components to determine number of ".." needed
        let mut n_parents: u32 = 1;
        loop {
            let mut f: *const c_char = std::ptr::null();
            let r = rs_path_find_first_component_inner(&mut from, false, &mut f);
            if r < 0 {
                return r;
            }
            if r == 0 {
                break;
            }
            n_parents += 1;
        }

        // 'remaining_to' points to the divergent component and rest of 'to' path
        let t_len = strlen(remaining_to);
        let t_empty = *remaining_to == 0;

        // Check buffer size
        if t_empty && n_parents * 3 > PATH_MAX_VAL as u32 {
            return Errno::EINVAL.to_neg_errno();
        }

        // Allocate result buffer: "../" * n_parents + remaining 'to'
        let buf_size = (n_parents as usize) * 3 + (if t_empty { 0 } else { t_len + 1 });
        result = malloc(buf_size) as *mut c_char;
        if result.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }

        let mut p = result;
        for _ in 0..n_parents {
            // Copy "../"
            *p = b'.' as c_char;
            p = p.add(1);
            *p = b'.' as c_char;
            p = p.add(1);
            *p = b'/' as c_char;
            p = p.add(1);
        }

        if t_empty {
            // Remove trailing slash
            p = p.sub(1);
            *p = 0;
            *ret = result;
            return 0;
        }

        // Copy remaining 'to' path
        for i in 0..t_len {
            *p = *remaining_to.add(i);
            p = p.add(1);
        }
        *p = 0;

        rs_path_simplify_full(result, 0);

        if !rs_path_is_valid_full(result, true) {
            libc_free(result);
            return Errno::EINVAL.to_neg_errno();
        }

        *ret = result;
        0
    }
}

// ── path_equal ────────────────────────────────────────────────────────────

/// Check if two paths are equal.
/// Returns true if two paths are equal.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_equal(a: *const c_char, b: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe { rs_path_compare(a, b) == 0 }
}

// ── path_startswith ───────────────────────────────────────────────────────

/// Return pointer past the prefix if path starts with prefix, NULL otherwise.
/// Returns pointer past the prefix if path starts with prefix, NULL otherwise.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_startswith(path: *const c_char, prefix: *const c_char) -> *mut c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe { rs_path_startswith_full(path, prefix, 0) as *mut c_char }
}

// ── path_is_valid ─────────────────────────────────────────────────────────

/// Check if the path is valid.
/// Returns true if the path is valid.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_is_valid(p: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe { rs_path_is_valid_full(p, true) }
}

// ── path_is_safe ──────────────────────────────────────────────────────────

/// Check if the path is valid and does not contain "..".
/// Returns true if the path is valid and does not contain "..".
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_is_safe(p: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe { rs_path_is_valid_full(p, false) }
}

// ── filename_or_absolute_path_is_valid ────────────────────────────────────

/// Check if p is a valid filename or absolute path.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_filename_or_absolute_path_is_valid(p: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if rs_path_is_absolute(p) {
            return rs_path_is_valid(p);
        }
        rs_filename_is_valid(p)
    }
}

// ── skip_dev_prefix ───────────────────────────────────────────────────────

/// Drop any /dev prefix from the path.
/// Drops any /dev prefix if there is any.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_skip_dev_prefix(p: *const c_char) -> *const c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let e = rs_path_startswith(p, c"/dev/".as_ptr());
        if e.is_null() { p } else { e }
    }
}

// ── path_simplify (inline wrapper) ────────────────────────────────────────

/// Simplify a path in-place by removing redundant slashes and dots.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_simplify(path: *mut c_char) -> *mut c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe { rs_path_simplify_full(path, 0) }
}

// ── path_startswith_strv ──────────────────────────────────────────────────

/// Return the remainder of the path after the first matching prefix in strv.
/// Returns the remainder of the path after the first matching prefix in strv.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_startswith_strv(p: *const c_char, strv: *mut *const c_char) -> *mut c_char {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if p.is_null() {
            return std::ptr::null_mut();
        }
        let mut i: usize = 0;
        while !strv.add(i).is_null() && !(*strv.add(i)).is_null() {
            let s = *strv.add(i);
            let t = rs_path_startswith(p, s);
            if !t.is_null() {
                return t;
            }
            i += 1;
        }
        std::ptr::null_mut()
    }
}

// ── path_strv_contains ────────────────────────────────────────────────────

/// Check if any string in strv equals path.
/// Returns true if any string in strv equals path.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_strv_contains(l: *mut *const c_char, path: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if path.is_null() {
            return false;
        }
        let mut i: usize = 0;
        while !l.add(i).is_null() && !(*l.add(i)).is_null() {
            if rs_path_equal(*l.add(i), path) {
                return true;
            }
            i += 1;
        }
        false
    }
}

// ── prefixed_path_strv_contains ───────────────────────────────────────────

/// Check if any string in strv equals path, skipping leading '-' and '+' prefixes.
/// Like path_strv_contains but skips leading '-' and '+' prefixes.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_prefixed_path_strv_contains(l: *mut *const c_char, path: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if path.is_null() {
            return false;
        }
        let mut i: usize = 0;
        while !l.add(i).is_null() && !(*l.add(i)).is_null() {
            let mut j = *l.add(i);
            if *j == b'-' as c_char {
                j = j.add(1);
            }
            if *j == b'+' as c_char {
                j = j.add(1);
            }
            if rs_path_equal(j, path) {
                return true;
            }
            i += 1;
        }
        false
    }
}

// ── path_split_prefix_filename ────────────────────────────────────────────

/// Split the path into dir prefix/filename pair.
/// Splits the path into dir prefix/filename pair.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_split_prefix_filename(
    path: *const c_char,
    ret_dir: *mut *mut c_char,
    ret_filename: *mut *mut c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if isempty(path) {
            return Errno::EINVAL.to_neg_errno();
        }

        let mut next: *const c_char = std::ptr::null();
        let mut c: *const c_char = std::ptr::null();
        let r = rs_path_find_last_component(path, false, &mut next, &mut c);
        if r < 0 {
            return r;
        }
        if r == 0 {
            // root directory or "."
            return Errno::EADDRNOTAVAIL.to_neg_errno();
        }

        // We need a mutable buffer for d since path_simplify modifies in-place
        let mut d: *mut c_char = std::ptr::null_mut();

        if !ret_dir.is_null() {
            if next == path {
                if *path != b'/' as c_char {
                    // filename only
                    if ret_filename.is_null() {
                        return Errno::EDESTADDRREQ.to_neg_errno();
                    }
                } else {
                    d = strdup(c"/".as_ptr());
                    if d.is_null() {
                        return Errno::ENOMEM.to_neg_errno();
                    }
                }
            } else {
                let dir_len = next.offset_from(path) as usize;
                d = crate::ffi::strndup(path, dir_len);
                if d.is_null() {
                    return Errno::ENOMEM.to_neg_errno();
                }
                rs_path_simplify_full(d, 0);
                if !rs_path_is_valid_full(d, true) {
                    libc_free(d);
                    return Errno::EINVAL.to_neg_errno();
                }
            }
        } else if !rs_path_is_valid_full(path, true) {
            return Errno::EINVAL.to_neg_errno();
        }

        if !ret_filename.is_null() {
            let fn_len = r as usize;
            let fn_ptr = crate::ffi::strndup(c, fn_len);
            if fn_ptr.is_null() {
                libc_free(d);
                return Errno::ENOMEM.to_neg_errno();
            }
            *ret_filename = fn_ptr;
        }

        if !ret_dir.is_null() {
            *ret_dir = d;
        }

        // Preserve C's O_DIRECTORY success value for a trailing slash. This is
        // part of the public function contract, rather than a generic boolean
        // success indicator.
        if strlen(c) > r as usize {
            libc::O_DIRECTORY
        } else {
            0
        }
    }
}

// ── path_extract_filename ─────────────────────────────────────────────────

/// Extract the filename component from a path.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_extract_filename(path: *const c_char, ret: *mut *mut c_char) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe { rs_path_split_prefix_filename(path, std::ptr::null_mut(), ret) }
}

// ── path_extract_directory ────────────────────────────────────────────────

/// Extract the directory component from a path.
/// Suppresses O_DIRECTORY return value.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_extract_directory(path: *const c_char, ret: *mut *mut c_char) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        let r = rs_path_split_prefix_filename(path, ret, std::ptr::null_mut());
        if r < 0 { r } else { 0 }
    }
}

// ── file_in_same_dir ──────────────────────────────────────────────────

/// Remove the last component of path and append filename.
/// Removes the last component of path and appends filename, unless filename is absolute
/// or path isn't absolute.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_file_in_same_dir(
    path: *const c_char,
    filename: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        if path.is_null() || filename.is_null() || ret.is_null() {
            return Errno::EINVAL.to_neg_errno();
        }

        let b: *mut c_char;
        if rs_path_is_absolute(filename) {
            b = strdup(filename);
        } else {
            let mut dn: *mut c_char = std::ptr::null_mut();
            let r = rs_path_extract_directory(path, &mut dn);
            if r == Errno::EDESTADDRREQ.to_neg_errno() {
                // no path prefix
                b = strdup(filename);
            } else if r < 0 {
                return r;
            } else {
                // path_join(dn, filename): add '/' between if needed
                let dlen = strlen(dn);
                let flen = strlen(filename);
                let need_slash = dlen > 0 && *dn.add(dlen - 1) != b'/' as c_char;
                let sep: usize = if need_slash { 1 } else { 0 };
                let total = dlen + sep + flen + 1;
                b = malloc(total) as *mut c_char;
                if b.is_null() {
                    libc_free(dn);
                    return Errno::ENOMEM.to_neg_errno();
                }
                std::ptr::copy_nonoverlapping(dn, b, dlen);
                if need_slash {
                    *b.add(dlen) = b'/' as c_char;
                }
                std::ptr::copy_nonoverlapping(filename, b.add(dlen + sep), flen + 1);
                libc_free(dn);
            }
        }
        if b.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        *ret = b;
        0
    }
}

// ── path_compare_filename ─────────────────────────────────────────────────

/// Compare two paths by their filename components.
/// Compares two paths by their filename components.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_compare_filename(a: *const c_char, b: *const c_char) -> i32 {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe {
        // Order NULL before non-NULL
        let mut r = cmp_bool(!a.is_null(), !b.is_null());
        if r != 0 {
            return r;
        }

        let mut fa: *mut c_char = std::ptr::null_mut();
        let mut fb: *mut c_char = std::ptr::null_mut();

        let j = rs_path_extract_filename(a, &mut fa);
        let k = rs_path_extract_filename(b, &mut fb);

        // When one of paths is "." or root, order it earlier.
        let eaddrnotavail = Errno::EADDRNOTAVAIL.to_neg_errno();
        r = cmp_bool(j != eaddrnotavail, k != eaddrnotavail);
        if r != 0 {
            libc_free(fa);
            libc_free(fb);
            return r;
        }

        // When one of paths is invalid (or we get OOM), order invalid path after valid one.
        r = cmp_bool(j < 0, k < 0);
        if r != 0 {
            libc_free(fa);
            libc_free(fb);
            return r;
        }

        // Fallback to strcmp() if both paths are invalid.
        if j < 0 {
            libc_free(fa);
            libc_free(fb);
            // C calls strcmp(a, b) here, but with NULL args it's UB.
            // Handle NULL explicitly.
            if a.is_null() && b.is_null() {
                return 0;
            }
            if a.is_null() {
                return -1;
            }
            if b.is_null() {
                return 1;
            }
            return strcmp(a, b);
        }

        let result = strcmp(fa, fb);
        libc_free(fa);
        libc_free(fb);
        result
    }
}

// ── path_equal_filename ───────────────────────────────────────────────────

/// Check if two paths have equal filename components.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_path_equal_filename(a: *const c_char, b: *const c_char) -> bool {
    // SAFETY: this raw-pointer port is one audited FFI operation region; its
    // documented caller contract covers every pointer traversal and C call below.
    unsafe { rs_path_compare_filename(a, b) == 0 }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn cstr(s: &str) -> *const c_char {
        CString::new(s).unwrap().into_raw()
    }

    fn free_cstr(p: *const c_char) {
        // SAFETY: ownership of the allocation is transferred exactly once from C back to Rust here.
        unsafe {
            let _ = CString::from_raw(p as *mut c_char);
        }
    }

    #[test]
    fn test_rs_is_path() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let with_slash = cstr("/foo");
            assert!(rs_is_path(with_slash));
            free_cstr(with_slash);

            let no_slash = cstr("foo");
            assert!(!rs_is_path(no_slash));
            free_cstr(no_slash);

            assert!(!rs_is_path(std::ptr::null()));
        }
    }

    #[test]
    fn test_rs_dot_or_dot_dot() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let dot = cstr(".");
            assert!(rs_dot_or_dot_dot(dot));
            free_cstr(dot);

            let dotdot = cstr("..");
            assert!(rs_dot_or_dot_dot(dotdot));
            free_cstr(dotdot);

            let foo = cstr("foo");
            assert!(!rs_dot_or_dot_dot(foo));
            free_cstr(foo);

            assert!(!rs_dot_or_dot_dot(std::ptr::null()));
        }
    }

    #[test]
    fn test_rs_filename_is_valid() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let valid = cstr("hello.txt");
            assert!(rs_filename_is_valid(valid));
            free_cstr(valid);

            let dot = cstr(".");
            assert!(!rs_filename_is_valid(dot));
            free_cstr(dot);

            let dotdot = cstr("..");
            assert!(!rs_filename_is_valid(dotdot));
            free_cstr(dotdot);

            let empty = cstr("");
            assert!(!rs_filename_is_valid(empty));
            free_cstr(empty);

            assert!(!rs_filename_is_valid(std::ptr::null()));
        }
    }

    #[test]
    fn test_rs_hidden_or_backup_file() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let hidden = cstr(".foo");
            assert!(rs_hidden_or_backup_file(hidden));
            free_cstr(hidden);

            let lost_found = cstr("lost+found");
            assert!(rs_hidden_or_backup_file(lost_found));
            free_cstr(lost_found);

            let backup = cstr("foo~");
            assert!(rs_hidden_or_backup_file(backup));
            free_cstr(backup);

            let normal = cstr("foo.txt");
            assert!(!rs_hidden_or_backup_file(normal));
            free_cstr(normal);

            let bak = cstr("foo.bak");
            assert!(rs_hidden_or_backup_file(bak));
            free_cstr(bak);
        }
    }

    #[test]
    fn test_rs_fdname_is_valid() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let valid = cstr("stdin");
            let invalid = cstr("std:in");
            assert!(rs_fdname_is_valid(valid));
            assert!(!rs_fdname_is_valid(invalid));
            free_cstr(valid);
            free_cstr(invalid);
        }
    }

    #[test]
    fn test_rs_path_is_absolute_and_device_path() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let abs = cstr("/dev/sda");
            let rel = cstr("dev/sda");
            assert!(rs_path_is_absolute(abs));
            assert!(rs_is_device_path(abs));
            assert!(!rs_path_is_absolute(rel));
            assert!(!rs_is_device_path(rel));
            free_cstr(abs);
            free_cstr(rel);
        }
    }

    #[test]
    fn test_is_device_path_component_and_byte_boundaries() {
        assert!(is_device_path_bytes(b"/./dev/foo"));
        assert!(is_device_path_bytes(b"/sys/\xff"));
        assert!(is_device_path_bytes(b"/dev/.."));
        assert!(is_device_path_bytes(b"/dev//./foo"));
        assert!(!is_device_path_bytes(b"/dev/."));
        assert!(!is_device_path_bytes(b"/../dev/foo"));
        assert!(!is_device_path_bytes(b"dev/foo"));

        let mut overlong = b"/dev/".to_vec();
        overlong.extend(std::iter::repeat(b'x').take(libc::NAME_MAX as usize + 1));
        assert!(!is_device_path_bytes(&overlong));
    }

    #[test]
    fn test_rs_path_implies_directory() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let slash = cstr("/tmp/");
            let dot = cstr(".");
            let file = cstr("/tmp/file");
            assert!(rs_path_implies_directory(slash));
            assert!(rs_path_implies_directory(dot));
            assert!(!rs_path_implies_directory(file));
            free_cstr(slash);
            free_cstr(dot);
            free_cstr(file);
        }
    }

    #[test]
    fn test_rs_path_compare_and_equal() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            let a = cstr("/foo/bar");
            let b = cstr("/foo//bar");
            let c = cstr("/foo/baz");
            assert_eq!(rs_path_compare(a, b), 0);
            assert!(rs_path_equal(a, b));
            assert!(rs_path_compare(a, c) < 0);
            free_cstr(a);
            free_cstr(b);
            free_cstr(c);
        }
    }
}
