// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/unit-name.c (pure subset)
//
// Unit name validation, parsing, building, and escaping functions.
// Skipped: unit_name_path_escape/unescape (path_simplify_alloc dependency),
//          unit_name_hash_long (siphash24_string dependency),
//          unit_name_from_path/from_path_instance/to_path (path dependency),
//          unit_name_mangle_with_suffix (logging, glob, device_path dependencies)

use libc::c_char;

use std::ffi::{CStr, c_void};
use std::ptr;

use crate::ffi::{Errno, free, malloc, strchr, strdup as ffi_strdup, strlen, strrchr};
use crate::path_util::{
    rs_empty_or_root, rs_is_device_path, rs_path_is_absolute, rs_path_is_normalized,
    rs_path_simplify_alloc,
};

// ── Constants ─────────────────────────────────────────────────────────────

const UNIT_NAME_MAX: usize = 256;
const UNIT_NAME_HASH_LENGTH_CHARS: usize = 16;
const SPECIAL_ROOT_SLICE: &CStr = c"-.slice";

const VALID_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:-_.\\";
const VALID_CHARS_WITH_AT: &[u8] =
    b"@abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:-_.\\";
const VALID_CHARS_GLOB: &[u8] =
    b"@abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:-_.\\[]!-*?";
const LOWERCASE_HEXDIGITS: &[u8] = b"0123456789abcdef";

// ── UnitType constants ────────────────────────────────────────────────────

const UNIT_SERVICE: i32 = 0;
const UNIT_MOUNT: i32 = 1;
const UNIT_SWAP: i32 = 2;
const UNIT_SOCKET: i32 = 3;
const UNIT_TARGET: i32 = 4;
const UNIT_DEVICE: i32 = 5;
const UNIT_AUTOMOUNT: i32 = 6;
const UNIT_TIMER: i32 = 7;
const UNIT_PATH: i32 = 8;
const UNIT_SLICE: i32 = 9;
const UNIT_SCOPE: i32 = 10;
const _UNIT_TYPE_MAX: i32 = 11;

// ── UnitNameFlags constants ───────────────────────────────────────────────

const UNIT_NAME_PLAIN: i32 = 1 << 0;
const UNIT_NAME_TEMPLATE: i32 = 1 << 1;
const UNIT_NAME_INSTANCE: i32 = 1 << 2;
const UNIT_NAME_ANY: i32 = UNIT_NAME_PLAIN | UNIT_NAME_TEMPLATE | UNIT_NAME_INSTANCE;

const UNIT_NAME_MANGLE_GLOB: i32 = 1 << 0;
#[cfg(test)]
const UNIT_NAME_MANGLE_WARN: i32 = 1 << 1;

// ── Internal helpers ──────────────────────────────────────────────────────

fn char_in_set(c: u8, set: &[u8]) -> bool {
    set.contains(&c)
}

fn isempty(s: *const c_char) -> bool {
    // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
    s.is_null() || unsafe { *s == 0 }
}

fn hexchar(x: i32) -> u8 {
    let d = (x & 0xf) as u8;
    if d < 10 { b'0' + d } else { b'a' + (d - 10) }
}

fn unhexchar(c: c_char) -> i32 {
    let c = c as u8;
    if c >= b'0' && c <= b'9' {
        (c - b'0') as i32
    } else if c >= b'a' && c <= b'f' {
        (c - b'a' + 10) as i32
    } else if c >= b'A' && c <= b'F' {
        (c - b'A' + 10) as i32
    } else {
        -1
    }
}

/// Sum C-allocation components without wrapping. C's `new()`/`strjoin()`
/// helpers reject overflow; a wrapped Rust allocation followed by raw copies
/// would otherwise be memory-unsafe in release builds.
#[inline]
fn checked_c_allocation(parts: &[usize]) -> Option<usize> {
    parts
        .iter()
        .try_fold(0usize, |total, part| total.checked_add(*part))
}

#[inline]
fn checked_escape_allocation(length: usize, suffix: usize) -> Option<usize> {
    length.checked_mul(4)?.checked_add(suffix)
}

/// Allocate a NUL-terminated copy of the first `n` bytes of `s`.
/// Returns null on OOM or null input. Caller must free.
// SAFETY: when non-null, `s` must point to a live NUL-terminated C string.
unsafe fn strndup_owned(s: *const c_char, n: usize) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller guarantees that `s` is a live NUL-terminated string.
    let len = unsafe { strlen(s) };
    let copy_len = len.min(n);
    let Some(allocation) = checked_c_allocation(&[copy_len, 1]) else {
        return ptr::null_mut();
    };
    let ptr = malloc(allocation) as *mut c_char;
    if ptr.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `ptr` names `allocation >= copy_len + 1` writable bytes and
    // `s` names at least `copy_len` readable bytes; the allocation is fresh.
    unsafe {
        ptr::copy_nonoverlapping(s, ptr, copy_len);
        *ptr.add(copy_len) = 0;
    }
    ptr
}

/// Write a malloc'd copy of `s` into `*ret`. Returns 0 on success, negative errno on failure.
// SAFETY: when non-null, `ret` must be writable and `s` must be a live
// NUL-terminated C string.
unsafe fn strdup_to(ret: *mut *mut c_char, s: *const c_char) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    if s.is_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe { *ret = ptr::null_mut() };
        return 0;
    }
    // SAFETY: the caller guarantees that `s` is a live NUL-terminated string.
    let dup = unsafe { ffi_strdup(s) };
    if dup.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
    unsafe { *ret = dup };
    0
}

/// Concatenate three NUL-terminated C strings. Returns null on OOM or null input.
// SAFETY: every non-null input must point to a live NUL-terminated C string.
unsafe fn strjoin3(a: *const c_char, b: *const c_char, c: *const c_char) -> *mut c_char {
    if a.is_null() || b.is_null() || c.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller guarantees that all three inputs are live
    // NUL-terminated strings.
    let (la, lb, lc) = unsafe { (strlen(a), strlen(b), strlen(c)) };
    let Some(allocation) = checked_c_allocation(&[la, lb, lc, 1]) else {
        return ptr::null_mut();
    };
    let ptr = malloc(allocation) as *mut c_char;
    if ptr.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the fresh allocation is large enough for all three source
    // ranges plus the terminator, and the source ranges do not overlap it.
    unsafe {
        ptr::copy_nonoverlapping(a, ptr, la);
        ptr::copy_nonoverlapping(b, ptr.add(la), lb);
        ptr::copy_nonoverlapping(c, ptr.add(la + lb), lc);
        *ptr.add(la + lb + lc) = 0;
    }
    ptr
}

/// Compare two byte sequences of given lengths.
// SAFETY: `a` and `b` must be readable for `alen` and `blen` bytes,
// respectively, whenever those lengths are non-zero.
unsafe fn memcmp_nn(a: *const c_char, alen: usize, b: *const c_char, blen: usize) -> i32 {
    let min_len = alen.min(blen);
    if min_len > 0 {
        // SAFETY: the caller guarantees that both inputs are readable for
        // their supplied lengths; `min_len` cannot exceed either length.
        let (a_slice, b_slice) = unsafe {
            (
                std::slice::from_raw_parts(a as *const u8, min_len),
                std::slice::from_raw_parts(b as *const u8, min_len),
            )
        };
        let r = a_slice.cmp(b_slice);
        match r {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    } else {
        0
    }
}

// ── unit_type_from_string / unit_type_to_string ───────────────────────────

const UNIT_TYPE_TABLE: &[(&[u8], i32)] = &[
    (b"service\0", UNIT_SERVICE),
    (b"mount\0", UNIT_MOUNT),
    (b"swap\0", UNIT_SWAP),
    (b"socket\0", UNIT_SOCKET),
    (b"target\0", UNIT_TARGET),
    (b"device\0", UNIT_DEVICE),
    (b"automount\0", UNIT_AUTOMOUNT),
    (b"timer\0", UNIT_TIMER),
    (b"path\0", UNIT_PATH),
    (b"slice\0", UNIT_SLICE),
    (b"scope\0", UNIT_SCOPE),
];

// SAFETY: `s` must point to a live NUL-terminated C string.
unsafe fn unit_type_from_string(s: *const c_char) -> i32 {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: the caller guarantees that `s` is a live NUL-terminated string.
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    for &(name, val) in UNIT_TYPE_TABLE.iter() {
        // name includes the NUL terminator; compare without it
        let name_bytes = &name[..name.len() - 1];
        if bytes == name_bytes {
            return val;
        }
    }
    Errno::EINVAL.to_neg_errno()
}

fn unit_type_to_string(t: i32) -> *const c_char {
    if t < 0 || t >= _UNIT_TYPE_MAX {
        return ptr::null();
    }
    for &(name, val) in UNIT_TYPE_TABLE.iter() {
        if val == t {
            return name.as_ptr() as *const c_char;
        }
    }
    ptr::null()
}

// ── Internal: unit_name_is_valid ─────────────────────────────────────────

fn unit_name_bytes_are_valid(n: &[u8], flags: i32) -> bool {
    if flags == 0 || n.is_empty() || n.len() >= UNIT_NAME_MAX {
        return false;
    }

    let Some(dot) = n.iter().rposition(|&byte| byte == b'.') else {
        return false;
    };
    if dot == 0 {
        return false;
    }
    let suffix = &n[dot + 1..];
    if !UNIT_TYPE_TABLE
        .iter()
        .any(|(name, _)| suffix == &name[..name.len() - 1])
    {
        return false;
    }

    let prefix = &n[..dot];
    let at_pos = prefix.iter().position(|&byte| byte == b'@');
    if prefix
        .iter()
        .any(|&byte| !char_in_set(byte, VALID_CHARS_WITH_AT))
        || at_pos == Some(0)
    {
        return false;
    }

    ((flags & UNIT_NAME_PLAIN) != 0 && at_pos.is_none())
        || ((flags & UNIT_NAME_INSTANCE) != 0
            && at_pos.is_some_and(|position| position + 1 < prefix.len()))
        || ((flags & UNIT_NAME_TEMPLATE) != 0
            && at_pos.is_some_and(|position| position + 1 == prefix.len()))
}

/// Validate the unit-name forms accepted by `systemd.unit=` and
/// `rd.systemd.unit=` in PID 1.
pub fn unit_name_is_valid_plain_or_instance(name: &str) -> bool {
    unit_name_bytes_are_valid(name.as_bytes(), UNIT_NAME_PLAIN | UNIT_NAME_INSTANCE)
}

// SAFETY: when non-null, `n` must point to a live NUL-terminated C string.
unsafe fn unit_name_is_valid_internal(n: *const c_char, flags: i32) -> bool {
    if n.is_null() {
        return false;
    }
    // SAFETY: the caller guarantees a live NUL-terminated string.
    unit_name_bytes_are_valid(unsafe { CStr::from_ptr(n) }.to_bytes(), flags)
}

// ── FFI exports: validation ──────────────────────────────────────────────

/// Check if a unit name is valid according to the given flags.
/// Returns true if valid, false otherwise.
/// # Safety
///
/// Non-null pointers must designate live NUL-terminated C strings for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_name_is_valid(n: *const c_char, flags: i32) -> bool {
    // SAFETY: this export forwards its documented pointer contract.
    unsafe { unit_name_is_valid_internal(n, flags) }
}

/// Check if a unit name prefix is valid (contains only allowed characters).
/// Returns true if valid, false otherwise.
/// # Safety
///
/// Non-null pointers must designate live NUL-terminated C strings for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_prefix_is_valid(p: *const c_char) -> bool {
    if isempty(p) {
        return false;
    }
    // SAFETY: `p` is nonempty and the caller guarantees a live
    // NUL-terminated string.
    let bytes = unsafe { CStr::from_ptr(p) }.to_bytes();
    bytes.iter().all(|&c| char_in_set(c, VALID_CHARS))
}

/// Check if a unit instance name is valid (allows '@' plus standard chars).
/// Returns true if valid, false otherwise.
/// # Safety
///
/// Non-null pointers must designate live NUL-terminated C strings for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_instance_is_valid(i: *const c_char) -> bool {
    if isempty(i) {
        return false;
    }
    // SAFETY: `i` is nonempty and the caller guarantees a live
    // NUL-terminated string.
    let bytes = unsafe { CStr::from_ptr(i) }.to_bytes();
    bytes
        .iter()
        .all(|&c| c == b'@' || char_in_set(c, VALID_CHARS))
}

/// Check if a unit suffix (e.g., ".service") is valid.
/// Returns true if valid, false otherwise.
/// # Safety
///
/// Non-null pointers must designate live NUL-terminated C strings for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_suffix_is_valid(s: *const c_char) -> bool {
    if isempty(s) {
        return false;
    }
    // SAFETY: `s` is nonempty and live under the caller's contract.
    if unsafe { *s } != b'.' as c_char {
        return false;
    }
    // SAFETY: advancing past the first non-NUL byte remains within `s`.
    unsafe { unit_type_from_string(s.add(1)) >= 0 }
}

/// Check if a unit name has a hashed suffix (_<16 hex chars>).
/// Returns true if hashed, false otherwise.
/// # Safety
///
/// Non-null pointers must designate live NUL-terminated C strings for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_name_is_hashed(name: *const c_char) -> bool {
    // SAFETY: this export forwards its documented input contract.
    if !unsafe { unit_name_is_valid_internal(name, UNIT_NAME_PLAIN) } {
        return false;
    }

    // SAFETY: `name` is a live NUL-terminated string.
    let s = unsafe { strrchr(name, b'.' as i32) };
    if s.is_null() {
        return false;
    }
    // SAFETY: `s` was returned for `name`, so both pointers share an allocation.
    let offset = unsafe { s.offset_from(name) } as usize;

    if offset < UNIT_NAME_HASH_LENGTH_CHARS + 1 {
        return false;
    }

    // SAFETY: the preceding length check keeps both derived pointers within
    // the live string.
    let hash_start = unsafe { name.add(offset - UNIT_NAME_HASH_LENGTH_CHARS) };
    // SAFETY: `hash_start` is at least one byte after `name`.
    if unsafe { *hash_start.sub(1) } != b'_' as c_char {
        return false;
    }

    for i in 0..UNIT_NAME_HASH_LENGTH_CHARS {
        // SAFETY: `i` is bounded by the verified hash suffix length.
        let c = unsafe { *hash_start.add(i) } as u8;
        if !char_in_set(c, LOWERCASE_HEXDIGITS) {
            return false;
        }
    }

    true
}

/// Check if name is a valid slice unit name.
/// Returns true if valid, false otherwise.
/// # Safety
///
/// Non-null pointers must designate live NUL-terminated C strings for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_slice_name_is_valid(name: *const c_char) -> bool {
    // SAFETY: this export forwards its documented input contract.
    if !unsafe { unit_name_is_valid_internal(name, UNIT_NAME_PLAIN) } {
        return false;
    }

    // SAFETY: validation above established a live NUL-terminated string.
    let name_cstr = unsafe { CStr::from_ptr(name) };
    if name_cstr == SPECIAL_ROOT_SLICE {
        return true;
    }

    let bytes = name_cstr.to_bytes();
    if !bytes.ends_with(b".slice") {
        return false;
    }

    // SAFETY: the validated suffix proves the string has at least six bytes.
    let slice_end = unsafe { name.add(strlen(name) - 6) }; // before ".slice"
    let mut p = name;
    let mut has_dash = false;

    while p < slice_end {
        // SAFETY: the loop bounds keep `p` within the string prefix.
        let c = unsafe { *p } as u8;
        if c == b'-' {
            if p == name {
                return false;
            }
            if has_dash {
                return false;
            }
            has_dash = true;
        } else {
            has_dash = false;
        }
        // SAFETY: the loop only advances toward the in-allocation `slice_end`.
        p = unsafe { p.add(1) };
    }

    !has_dash
}

/// Check if unit names a and b have equal prefixes.
/// Returns true if prefixes match, false otherwise.
/// # Safety
///
/// Non-null pointers must designate live NUL-terminated C strings for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_name_prefix_equal(a: *const c_char, b: *const c_char) -> bool {
    // SAFETY: this export forwards its documented input contract to both
    // validation calls.
    if !unsafe { unit_name_is_valid_internal(a, UNIT_NAME_ANY) }
        || !unsafe { unit_name_is_valid_internal(b, UNIT_NAME_ANY) }
    {
        return false;
    }

    // SAFETY: both inputs are validated NUL-terminated strings.
    let p = unsafe { strchr(a, b'@' as i32) };
    let p = if p.is_null() {
        // SAFETY: `a` is a validated NUL-terminated string.
        unsafe { strrchr(a, b'.' as i32) }
    } else {
        p
    };

    // SAFETY: `b` is a validated NUL-terminated string.
    let q = unsafe { strchr(b, b'@' as i32) };
    let q = if q.is_null() {
        // SAFETY: `b` is a validated NUL-terminated string.
        unsafe { strrchr(b, b'.' as i32) }
    } else {
        q
    };

    // SAFETY: each result pointer came from searching its corresponding input.
    let (alen, blen) = unsafe { (p.offset_from(a) as usize, q.offset_from(b) as usize) };

    // SAFETY: the computed prefix lengths are within their validated strings.
    unsafe { memcmp_nn(a, alen, b, blen) == 0 }
}

// ── FFI exports: parsing ─────────────────────────────────────────────────

/// Extract the prefix from unit name n. Returns malloc'd string in *ret (caller must free).
/// Returns 0 on success, negative errno on failure.
/// # Safety
///
/// `n` must be a live NUL-terminated C string and `ret` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_name_to_prefix(n: *const c_char, ret: *mut *mut c_char) -> i32 {
    // SAFETY: this export forwards its documented input contract.
    if !unsafe { unit_name_is_valid_internal(n, UNIT_NAME_ANY) } {
        return Errno::EINVAL.to_neg_errno();
    }

    let p = {
        // SAFETY: `n` is a validated NUL-terminated string.
        let at = unsafe { strchr(n, b'@' as i32) };
        if at.is_null() {
            // SAFETY: `n` is a validated NUL-terminated string.
            unsafe { strrchr(n, b'.' as i32) }
        } else {
            at
        }
    };

    // SAFETY: `p` came from searching `n`, and the helper receives that
    // in-allocation prefix length.
    let prefix_len = unsafe { p.offset_from(n) } as usize;
    // SAFETY: `n` is live and readable for the computed prefix.
    let s = unsafe { strndup_owned(n, prefix_len) };
    if s.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: the caller guarantees that `ret` is writable.
    unsafe { *ret = s };
    0
}

/// Extract the instance from unit name n. Returns malloc'd string in *ret (caller must free).
/// Returns UNIT_NAME_PLAIN/INSTANCE/TEMPLATE on success, negative errno on failure.
/// # Safety
///
/// `n` must be a live NUL-terminated C string; when non-null, `ret` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_name_to_instance(n: *const c_char, ret: *mut *mut c_char) -> i32 {
    // SAFETY: this export forwards its documented input contract.
    if !unsafe { unit_name_is_valid_internal(n, UNIT_NAME_ANY) } {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: `n` is a validated NUL-terminated string.
    let p = unsafe { strchr(n, b'@' as i32) };
    if p.is_null() {
        if !ret.is_null() {
            // SAFETY: non-null `ret` is writable under the caller's contract.
            unsafe { *ret = ptr::null_mut() };
        }
        return UNIT_NAME_PLAIN;
    }

    // SAFETY: the match is within `n`, so advancing remains within the string.
    let p = unsafe { p.add(1) };
    // SAFETY: `p` is a suffix of the validated NUL-terminated string.
    let d = unsafe { strrchr(p, b'.' as i32) };
    if d.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    if !ret.is_null() {
        // SAFETY: `d` was found within the suffix starting at `p`.
        let ilen = unsafe { d.offset_from(p) } as usize;
        // SAFETY: the computed instance prefix is readable.
        let i = unsafe { strndup_owned(p, ilen) };
        if i.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        // SAFETY: non-null `ret` is writable under the caller's contract.
        unsafe { *ret = i };
    }

    if d > p {
        UNIT_NAME_INSTANCE
    } else {
        UNIT_NAME_TEMPLATE
    }
}

/// Extract the prefix from unit name n. Returns malloc'd string in *ret (caller must free).
/// Returns 0 on success, negative errno on failure.
/// # Safety
///
/// `n` must be a live NUL-terminated C string and `ret` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_name_to_prefix_and_instance(
    n: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this export forwards its documented input contract.
    if !unsafe { unit_name_is_valid_internal(n, UNIT_NAME_ANY) } {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: `n` is a validated NUL-terminated string.
    let d = unsafe { strrchr(n, b'.' as i32) };
    if d.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: `d` was found within `n`.
    let prefix_len = unsafe { d.offset_from(n) } as usize;
    // SAFETY: the computed prefix is readable.
    let s = unsafe { strndup_owned(n, prefix_len) };
    if s.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: the caller guarantees that `ret` is writable.
    unsafe { *ret = s };
    0
}

/// Get the unit type from unit name n.
/// Returns the unit type on success, negative errno on failure.
/// # Safety
///
/// `n` must be a live NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_name_to_type(n: *const c_char) -> i32 {
    // SAFETY: this export forwards its documented input contract.
    if !unsafe { unit_name_is_valid_internal(n, UNIT_NAME_ANY) } {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: validation guarantees a dot in the live input.
    let e = unsafe { strrchr(n, b'.' as i32) };
    // SAFETY: advancing past that dot remains in the NUL-terminated string.
    unsafe { unit_type_from_string(e.add(1)) }
}

// ── FFI exports: building ────────────────────────────────────────────────

/// Change the suffix of unit name n. Returns malloc'd string in *ret (caller must free).
/// Returns 0 on success, negative errno on failure.
/// # Safety
///
/// Inputs must be live NUL-terminated C strings and `ret` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_name_change_suffix(
    n: *const c_char,
    suffix: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this export forwards its documented input contract.
    if !unsafe { unit_name_is_valid_internal(n, UNIT_NAME_ANY) } {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: this export forwards the documented string contract.
    if !unsafe { rs_unit_suffix_is_valid(suffix) } {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: both strings were validated above.
    let e = unsafe { strrchr(n, b'.' as i32) };
    // SAFETY: `e` was found within `n`; `suffix` is NUL-terminated.
    let (a, b) = unsafe { (e.offset_from(n) as usize, strlen(suffix)) };

    let Some(allocation) = checked_c_allocation(&[a, b, 1]) else {
        return Errno::ENOMEM.to_neg_errno();
    };
    let s = malloc(allocation) as *mut c_char;
    if s.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: the fresh allocation covers both validated source ranges and
    // their terminator, with no overlap.
    unsafe {
        ptr::copy_nonoverlapping(n, s, a);
        ptr::copy_nonoverlapping(suffix, s.add(a), b);
        *s.add(a + b) = 0;
    }

    // SAFETY: `s` is now a live NUL-terminated string.
    if !unsafe { unit_name_is_valid_internal(s, UNIT_NAME_ANY) } {
        // SAFETY: `s` is the unique allocation obtained above.
        unsafe { free(s as *mut c_void) };
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: the caller guarantees that `ret` is writable.
    unsafe { *ret = s };
    0
}

/// Build a unit name from prefix, instance, and suffix. Returns malloc'd string in *ret (caller must free).
/// Returns 0 on success, negative errno on failure.
/// # Safety
///
/// `prefix`, `suffix`, and `ret` must be non-null; every non-null string input
/// must be a live NUL-terminated C string, and `ret` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_name_build(
    prefix: *const c_char,
    instance: *const c_char,
    suffix: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: `suffix` is non-null and live under the documented contract.
    if unsafe { *suffix } != b'.' as c_char {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: advancing past the non-NUL leading dot remains within `suffix`.
    let t = unsafe { unit_type_from_string(suffix.add(1)) };
    if t < 0 {
        return t;
    }

    // SAFETY: the pointer contract is identical to this forwarding export.
    unsafe { rs_unit_name_build_from_type(prefix, instance, t, ret) }
}

/// Build a unit name from prefix, instance, and suffix. Returns malloc'd string in *ret (caller must free).
/// Returns 0 on success, negative errno on failure.
/// # Safety
///
/// `prefix` and `ret` must be non-null; every non-null string input must be a
/// live NUL-terminated C string, and `ret` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_name_build_from_type(
    prefix: *const c_char,
    instance: *const c_char,
    utype: i32,
    ret: *mut *mut c_char,
) -> i32 {
    if utype < 0 || utype >= _UNIT_TYPE_MAX {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: this export forwards its documented prefix contract.
    if !unsafe { rs_unit_prefix_is_valid(prefix) } {
        return Errno::EINVAL.to_neg_errno();
    }

    let ut = unit_type_to_string(utype);

    let s = if !instance.is_null() {
        // SAFETY: non-null `instance` is documented as a live C string.
        if !unsafe { rs_unit_instance_is_valid(instance) } {
            return Errno::EINVAL.to_neg_errno();
        }
        // SAFETY: all three pointers name live NUL-terminated strings.
        let (prefix_len, instance_len, ut_len) =
            unsafe { (strlen(prefix), strlen(instance), strlen(ut)) };
        let Some(total) = checked_c_allocation(&[prefix_len, 1, instance_len, 1, ut_len, 1]) else {
            return Errno::ENOMEM.to_neg_errno();
        };
        let ptr = malloc(total) as *mut c_char;
        if ptr.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        // SAFETY: `total` was checked for every component, the allocation is
        // fresh, and each source range is readable and disjoint from it.
        unsafe {
            ptr::copy_nonoverlapping(prefix, ptr, prefix_len);
            *ptr.add(prefix_len) = b'@' as c_char;
            ptr::copy_nonoverlapping(instance, ptr.add(prefix_len + 1), instance_len);
            *ptr.add(prefix_len + 1 + instance_len) = b'.' as c_char;
            ptr::copy_nonoverlapping(ut, ptr.add(prefix_len + 1 + instance_len + 1), ut_len + 1);
        }
        ptr
    } else {
        // SAFETY: both pointers name live NUL-terminated strings.
        let (prefix_len, ut_len) = unsafe { (strlen(prefix), strlen(ut)) };
        let Some(total) = checked_c_allocation(&[prefix_len, 1, ut_len, 1]) else {
            return Errno::ENOMEM.to_neg_errno();
        };
        let ptr = malloc(total) as *mut c_char;
        if ptr.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        // SAFETY: the checked fresh allocation covers both source ranges,
        // separator, and terminator.
        unsafe {
            ptr::copy_nonoverlapping(prefix, ptr, prefix_len);
            *ptr.add(prefix_len) = b'.' as c_char;
            ptr::copy_nonoverlapping(ut, ptr.add(prefix_len + 1), ut_len + 1);
        }
        ptr
    };

    if s.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    let expected = if !instance.is_null() {
        UNIT_NAME_INSTANCE
    } else {
        UNIT_NAME_PLAIN
    };

    // SAFETY: `s` was initialized above as a live NUL-terminated string.
    if !unsafe { unit_name_is_valid_internal(s, expected) } {
        // SAFETY: `s` is the unique allocation created above.
        unsafe { free(s as *mut c_void) };
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: the caller guarantees that `ret` is writable.
    unsafe { *ret = s };
    0
}

/// Build the parent slice name. Returns malloc'd string in *ret (caller must free), or NULL for root.
/// Returns 0 on success, 1 if result is root slice, negative errno on failure.
/// # Safety
///
/// `slice` must be a live NUL-terminated C string and `ret` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_slice_build_parent_slice(
    slice: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this export forwards its documented input contract.
    if !unsafe { rs_slice_name_is_valid(slice) } {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: validation above established a live NUL-terminated string.
    if unsafe { CStr::from_ptr(slice) } == SPECIAL_ROOT_SLICE {
        // SAFETY: the caller guarantees that `ret` is writable.
        unsafe { *ret = ptr::null_mut() };
        return 0;
    }

    // SAFETY: `slice` is a validated live C string.
    let s = unsafe { strndup_owned(slice, usize::MAX) };
    if s.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: `s` is a live NUL-terminated allocation.
    let dash = unsafe { strrchr(s, b'-' as i32) };
    if dash.is_null() {
        // SAFETY: `s` is the unique allocation returned above.
        unsafe { free(s as *mut c_void) };
        // SAFETY: `ret` is writable and the static C string is live.
        let result = unsafe { strdup_to(ret, SPECIAL_ROOT_SLICE.as_ptr()) };
        return if result < 0 { result } else { 1 };
    }

    // SAFETY: `dash` was found within `s`.
    let dash_pos = unsafe { dash.offset_from(s) } as usize;
    let suffix = b".slice\0";
    // SAFETY: replacing from the dash with the NUL-terminated `.slice` suffix
    // stays within the original validated `.slice` allocation.
    unsafe {
        ptr::copy_nonoverlapping(suffix.as_ptr(), s.add(dash_pos) as *mut u8, suffix.len());
    }

    // SAFETY: the caller guarantees that `ret` is writable.
    unsafe { *ret = s };
    1
}

/// Build a subslice name from slice and name. Returns malloc'd string in *ret (caller must free).
/// Returns 0 on success, negative errno on failure.
/// # Safety
///
/// Inputs must be live NUL-terminated C strings and `ret` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_slice_build_subslice(
    slice: *const c_char,
    name: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this export forwards its documented input contracts.
    if !unsafe { rs_slice_name_is_valid(slice) } {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: this export forwards its documented input contracts.
    if !unsafe { rs_unit_prefix_is_valid(name) } {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: both inputs are validated live C strings.
    let subslice = if unsafe { CStr::from_ptr(slice) } == SPECIAL_ROOT_SLICE {
        // SAFETY: all three inputs are live NUL-terminated strings.
        unsafe { strjoin3(name, c".".as_ptr(), c"slice".as_ptr()) }
    } else {
        // SAFETY: both inputs are validated NUL-terminated strings; the slice
        // validator guarantees the six-byte suffix.
        let (elen, nlen) = unsafe { (strlen(slice) - 6, strlen(name)) }; // remove ".slice"
        let Some(total) = checked_c_allocation(&[elen, 1, nlen, 6, 1]) else {
            return Errno::ENOMEM.to_neg_errno();
        };
        let s = malloc(total) as *mut c_char;
        if s.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        let mut p = s as *mut u8;
        // SAFETY: `total` covers every copied component and the trailing NUL
        // already included in `.slice`; all sources are live and disjoint.
        unsafe {
            ptr::copy_nonoverlapping(slice as *const u8, p, elen);
            p = p.add(elen);
            *p = b'-';
            p = p.add(1);
            ptr::copy_nonoverlapping(name as *const u8, p, nlen);
            p = p.add(nlen);
            let suffix = b".slice\0";
            ptr::copy_nonoverlapping(suffix.as_ptr(), p, suffix.len());
        }
        s
    };

    if subslice.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: the caller guarantees that `ret` is writable.
    unsafe { *ret = subslice };
    0
}

// ── FFI exports: escape/unescape ─────────────────────────────────────────

// SAFETY: `t` must point to at least four writable bytes.
unsafe fn do_escape_char(c: u8, t: *mut u8) -> *mut u8 {
    // SAFETY: the caller reserves four writable bytes at `t`.
    unsafe {
        *t = b'\\';
        *t.add(1) = b'x';
        *t.add(2) = hexchar((c >> 4) as i32);
        *t.add(3) = hexchar(c as i32);
        t.add(4)
    }
}

// SAFETY: `f` must be a live NUL-terminated C string, and `t` must have four
// writable bytes for each input byte that can be escaped.
unsafe fn do_escape(f: *const c_char, t: *mut u8) -> *mut u8 {
    let mut ft = f;
    let mut tt = t;

    // SAFETY: the caller supplies a live NUL-terminated input.
    if unsafe { *ft } == b'.' as c_char {
        // SAFETY: `tt` has four output bytes per remaining input byte.
        tt = unsafe { do_escape_char(*ft as u8, tt) };
        // SAFETY: the byte inspected above was non-NUL.
        ft = unsafe { ft.add(1) };
    }

    // SAFETY: each iteration stays within the live NUL-terminated input.
    while unsafe { *ft } != 0 {
        // SAFETY: `ft` points at the current live input byte.
        let c = unsafe { *ft } as u8;
        if c == b'/' {
            // SAFETY: at least one output byte remains for this input byte.
            unsafe { *tt = b'-' };
            // SAFETY: advancing remains within the reserved output range.
            tt = unsafe { tt.add(1) };
        } else if c == b'-' || c == b'\\' || !char_in_set(c, VALID_CHARS) {
            // SAFETY: four output bytes are reserved per input byte.
            tt = unsafe { do_escape_char(c, tt) };
        } else {
            // SAFETY: at least one output byte remains for this input byte.
            unsafe { *tt = c };
            // SAFETY: advancing remains within the reserved output range.
            tt = unsafe { tt.add(1) };
        }
        // SAFETY: the current byte was non-NUL, so advancing remains in the
        // NUL-terminated input.
        ft = unsafe { ft.add(1) };
    }

    tt
}

/// Escape a path for use as a unit name. Returns malloc'd string (caller must free), or NULL on OOM.
/// # Safety
///
/// `f` must be a live NUL-terminated C string; the caller owns the returned C allocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_name_escape(f: *const c_char) -> *mut c_char {
    // SAFETY: the caller guarantees that `f` is a live NUL-terminated string.
    let len = unsafe { strlen(f) };
    let Some(allocation) = checked_escape_allocation(len, 1) else {
        return ptr::null_mut();
    };
    let r = malloc(allocation) as *mut c_char;
    if r.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: the allocation reserves four bytes per input byte plus the NUL.
    let t = unsafe { do_escape(f, r as *mut u8) };
    // SAFETY: `do_escape` returns the first uninitialized byte in that range.
    unsafe { *t = 0 };

    r
}

/// Unescape a unit name back to a path. Returns malloc'd string in *ret (caller must free).
/// Returns 0 on success, negative errno on failure.
/// # Safety
///
/// `f` must be a live NUL-terminated C string and `ret` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_name_unescape(f: *const c_char, ret: *mut *mut c_char) -> i32 {
    // SAFETY: the caller guarantees a live NUL-terminated input.
    let r = unsafe { strndup_owned(f, usize::MAX) };
    if r.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    let mut ft = f;
    let mut t = r;

    // SAFETY: each iteration stays within the live input and the duplicate
    // output allocation.
    while unsafe { *ft } != 0 {
        // SAFETY: `ft` points at the current live input byte.
        if unsafe { *ft } == b'-' as c_char {
            // SAFETY: `t` stays within the duplicate allocation.
            unsafe { *t = b'/' as c_char };
            // SAFETY: one output byte was initialized.
            t = unsafe { t.add(1) };
        // SAFETY: `ft` points at the current live input byte.
        } else if unsafe { *ft } == b'\\' as c_char {
            // SAFETY: the caller's string is NUL-terminated; reading the byte
            // after a non-NUL backslash stays within its allocation.
            if unsafe { *ft.add(1) } != b'x' as c_char {
                // SAFETY: `r` is the unique allocation returned above.
                unsafe { free(r as *mut c_void) };
                return Errno::EINVAL.to_neg_errno();
            }

            // SAFETY: a valid `\x` escape must provide two following bytes;
            // NUL reads are allowed and rejected by `unhexchar`.
            let a = unhexchar(unsafe { *ft.add(2) });
            if a < 0 {
                // SAFETY: `r` is the unique allocation returned above.
                unsafe { free(r as *mut c_void) };
                return Errno::EINVAL.to_neg_errno();
            }

            // SAFETY: as above, this read remains within the terminated input.
            let b = unhexchar(unsafe { *ft.add(3) });
            if b < 0 {
                // SAFETY: `r` is the unique allocation returned above.
                unsafe { free(r as *mut c_void) };
                return Errno::EINVAL.to_neg_errno();
            }

            // SAFETY: `t` stays within the same-size duplicate allocation.
            unsafe { *t = (((a << 4) | b) as u8) as c_char };
            // SAFETY: one output byte was initialized.
            t = unsafe { t.add(1) };
            // SAFETY: the validated escape consumes four input bytes total.
            ft = unsafe { ft.add(3) };
        } else {
            // SAFETY: both current input and output pointers are in bounds.
            unsafe { *t = *ft };
            // SAFETY: one output byte was initialized.
            t = unsafe { t.add(1) };
        }
        // SAFETY: the current input component was non-NUL and consumed.
        ft = unsafe { ft.add(1) };
    }

    // SAFETY: the output never grows and has room for its terminator.
    unsafe { *t = 0 };
    // SAFETY: the caller guarantees that `ret` is writable.
    unsafe { *ret = r };
    0
}

/// Replace the instance in a unit name. Returns malloc'd string in *ret (caller must free).
/// Returns 0 on success, negative errno on failure.
/// # Safety
///
/// Inputs must be live NUL-terminated C strings and `ret` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_name_replace_instance_full(
    original: *const c_char,
    instance: *const c_char,
    accept_glob: bool,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this export forwards its documented input contract.
    if !unsafe { unit_name_is_valid_internal(original, UNIT_NAME_INSTANCE | UNIT_NAME_TEMPLATE) } {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: `instance` is a live C string under this export's contract.
    let instance_valid = unsafe { rs_unit_instance_is_valid(instance) };
    let glob_valid = accept_glob && {
        // SAFETY: `instance` is a live NUL-terminated string.
        let bytes = unsafe { CStr::from_ptr(instance) }.to_bytes();
        bytes.iter().all(|&c| char_in_set(c, VALID_CHARS_GLOB))
    };
    if !instance_valid && !glob_valid {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: `original` was validated above.
    let (prefix, suffix) = unsafe {
        (
            strchr(original, b'@' as i32),
            strrchr(original, b'.' as i32),
        )
    };

    // SAFETY: both search results are within `original`, while `instance` and
    // `suffix` are live NUL-terminated strings.
    let (pl, ilen, slen) = unsafe {
        (
            prefix.offset_from(original) as usize + 1,
            strlen(instance),
            strlen(suffix),
        )
    };

    let Some(allocation) = checked_c_allocation(&[pl, ilen, slen, 1]) else {
        return Errno::ENOMEM.to_neg_errno();
    };
    let s = malloc(allocation) as *mut c_char;
    if s.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: the checked fresh allocation covers all source ranges, and the
    // sources are live and disjoint from it.
    unsafe {
        ptr::copy_nonoverlapping(original, s, pl);
        ptr::copy_nonoverlapping(instance, s.add(pl), ilen);
        ptr::copy_nonoverlapping(suffix, s.add(pl + ilen), slen + 1);
    }

    // SAFETY: `s` is now a live NUL-terminated string.
    if !accept_glob && !unsafe { unit_name_is_valid_internal(s, UNIT_NAME_INSTANCE) } {
        // SAFETY: `s` is the unique allocation obtained above.
        unsafe { free(s as *mut c_void) };
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: the caller guarantees that `ret` is writable.
    unsafe { *ret = s };
    0
}

/// Extract the template from an instance unit name. Returns malloc'd string in *ret (caller must free).
/// Returns 0 on success, negative errno on failure.
/// # Safety
///
/// `f` must be a live NUL-terminated C string and `ret` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_unit_name_template(f: *const c_char, ret: *mut *mut c_char) -> i32 {
    // SAFETY: this export forwards its documented input contract.
    if !unsafe { unit_name_is_valid_internal(f, UNIT_NAME_INSTANCE | UNIT_NAME_TEMPLATE) } {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: `f` was validated above.
    let (p, e) = unsafe { (strchr(f, b'@' as i32), strrchr(f, b'.' as i32)) };

    // SAFETY: both search results are within `f`.
    let (a, elen) = unsafe { (p.offset_from(f) as usize, strlen(e)) };

    let Some(allocation) = checked_c_allocation(&[a, 1, elen, 1]) else {
        return Errno::ENOMEM.to_neg_errno();
    };
    let s = malloc(allocation) as *mut c_char;
    if s.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: the checked fresh allocation covers the copied prefix and
    // suffix, and the source ranges are live and disjoint from it.
    unsafe {
        ptr::copy_nonoverlapping(f, s, a + 1);
        ptr::copy_nonoverlapping(e, s.add(a + 1), elen + 1);
    }

    // SAFETY: the caller guarantees that `ret` is writable.
    unsafe { *ret = s };
    0
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_unit_name_replace_instance(
    original: *const c_char,
    instance: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this wrapper forwards the same pointer contract unchanged.
    unsafe { rs_unit_name_replace_instance_full(original, instance, false, ret) }
}

// SAFETY: when non-null, `s` must point to a live NUL-terminated C string.
unsafe fn c_string_is_glob(s: *const c_char) -> bool {
    if s.is_null() {
        return false;
    }

    let mut p = s;
    // SAFETY: the caller guarantees that `s` is a live NUL-terminated string.
    while unsafe { *p } != 0 {
        // SAFETY: `p` points at the current live input byte.
        if matches!(unsafe { *p } as u8, b'*' | b'?' | b'[') {
            return true;
        }
        // SAFETY: the current byte is non-NUL, so advancing remains within the
        // NUL-terminated string.
        p = unsafe { p.add(1) };
    }
    false
}

// SAFETY: when non-null, `s` must point to a live NUL-terminated C string.
unsafe fn c_string_in_charset(s: *const c_char, charset: &[u8]) -> bool {
    if s.is_null() {
        return false;
    }

    let mut p = s;
    // SAFETY: the caller guarantees that `s` is a live NUL-terminated string.
    while unsafe { *p } != 0 {
        // SAFETY: `p` points at the current live input byte.
        if !char_in_set(unsafe { *p } as u8, charset) {
            return false;
        }
        // SAFETY: the current byte is non-NUL, so advancing remains within the
        // NUL-terminated string.
        p = unsafe { p.add(1) };
    }
    true
}

// SAFETY: `f` must be a live NUL-terminated C string, and `t` must provide
// four writable bytes per input byte plus one byte for the terminator.
unsafe fn do_escape_mangle(f: *const c_char, allow_globs: bool, t: *mut u8) -> bool {
    let mut ff = f;
    let mut tt = t;
    let valid_chars = if allow_globs {
        VALID_CHARS_GLOB
    } else {
        VALID_CHARS_WITH_AT
    };
    let mut mangled = false;

    // SAFETY: the caller supplies a live NUL-terminated input and a destination
    // with four bytes reserved per input byte plus a terminator.
    while unsafe { *ff } != 0 {
        // SAFETY: `ff` points at the current live input byte.
        let c = unsafe { *ff } as u8;
        if c == b'/' {
            // SAFETY: one destination byte remains for this input byte.
            unsafe { *tt = b'-' };
            // SAFETY: advancing remains within the reserved output.
            tt = unsafe { tt.add(1) };
            mangled = true;
        } else if !char_in_set(c, valid_chars) {
            // SAFETY: four destination bytes remain for this input byte.
            tt = unsafe { do_escape_char(c, tt) };
            mangled = true;
        } else {
            // SAFETY: one destination byte remains for this input byte.
            unsafe { *tt = c };
            // SAFETY: advancing remains within the reserved output.
            tt = unsafe { tt.add(1) };
        }
        // SAFETY: the current byte was non-NUL.
        ff = unsafe { ff.add(1) };
    }
    // SAFETY: the caller reserved an additional byte for the terminator.
    unsafe { *tt = 0 };

    mangled
}

// SAFETY: `path` must be a live NUL-terminated C string and `ret` must be
// writable for one pointer value.
unsafe fn unit_name_path_escape_simple(path: *const c_char, ret: *mut *mut c_char) -> i32 {
    let mut simplified: *mut c_char = ptr::null_mut();
    // SAFETY: the caller guarantees that `path` is a live C string; the local
    // output pointer is writable.
    let r = unsafe { rs_path_simplify_alloc(path, &mut simplified) };
    if r < 0 {
        return r;
    }

    // SAFETY: `simplified` is the live C string returned above.
    if unsafe { rs_empty_or_root(simplified) } {
        // SAFETY: the static input is a live C string.
        let dash = unsafe { ffi_strdup(c"-".as_ptr()) };
        // SAFETY: `simplified` is the unique allocation returned above.
        unsafe { free(simplified as *mut c_void) };
        if dash.is_null() {
            return Errno::ENOMEM.to_neg_errno();
        }
        // SAFETY: the caller guarantees that `ret` is writable.
        unsafe { *ret = dash };
        return 0;
    }

    // SAFETY: `simplified` is a live NUL-terminated string.
    if !unsafe { rs_path_is_normalized(simplified) } {
        // SAFETY: `simplified` is the unique allocation returned above.
        unsafe { free(simplified as *mut c_void) };
        return Errno::EINVAL.to_neg_errno();
    }

    let mut start = simplified as *const c_char;
    // SAFETY: `start` traverses the live NUL-terminated `simplified` string.
    while unsafe { *start } == b'/' as c_char {
        // SAFETY: a non-NUL slash was just observed.
        start = unsafe { start.add(1) };
    }

    // SAFETY: `start` is a suffix of the live C string.
    let escaped = unsafe { rs_unit_name_escape(start) };
    // SAFETY: `simplified` is the unique allocation returned above.
    unsafe { free(simplified as *mut c_void) };
    if escaped.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: the caller guarantees that `ret` is writable.
    unsafe { *ret = escaped };
    0
}

// SAFETY: `path` and `suffix` must be live NUL-terminated C strings, and
// `ret` must be writable for one pointer value.
unsafe fn unit_name_from_path_simple(
    path: *const c_char,
    suffix: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: the caller guarantees that `suffix` is a live C string.
    if !unsafe { rs_unit_suffix_is_valid(suffix) } {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut escaped: *mut c_char = ptr::null_mut();
    // SAFETY: the caller's path contract and the local writable output pointer
    // satisfy the helper.
    let r = unsafe { unit_name_path_escape_simple(path, &mut escaped) };
    if r < 0 {
        return r;
    }

    // SAFETY: both pointers are live NUL-terminated strings.
    let (elen, slen) = unsafe { (strlen(escaped), strlen(suffix)) };
    let Some(allocation) = checked_c_allocation(&[elen, slen, 1]) else {
        // SAFETY: `escaped` is the unique allocation returned above.
        unsafe { free(escaped as *mut c_void) };
        return Errno::ENOMEM.to_neg_errno();
    };
    let s = malloc(allocation) as *mut c_char;
    if s.is_null() {
        // SAFETY: `escaped` is the unique allocation returned above.
        unsafe { free(escaped as *mut c_void) };
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: the checked fresh allocation covers both live source ranges and
    // their terminator, and the sources are disjoint from it.
    unsafe {
        ptr::copy_nonoverlapping(escaped, s, elen);
        ptr::copy_nonoverlapping(suffix, s.add(elen), slen + 1);
    }
    // SAFETY: `escaped` is the unique allocation returned above.
    unsafe { free(escaped as *mut c_void) };

    // SAFETY: `s` is now a live NUL-terminated string.
    if !unsafe { unit_name_is_valid_internal(s, UNIT_NAME_PLAIN) } {
        // SAFETY: `s` is the unique allocation obtained above.
        unsafe { free(s as *mut c_void) };
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: the caller guarantees that `ret` is writable.
    unsafe { *ret = s };
    0
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_unit_name_mangle_with_suffix(
    name: *const c_char,
    _operation: *const c_char,
    flags: i32,
    suffix: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    if isempty(name) {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: the caller guarantees that `suffix` is a live C string.
    if !unsafe { rs_unit_suffix_is_valid(suffix) } {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: this function forwards its input contract to validation.
    if unsafe { unit_name_is_valid_internal(name, UNIT_NAME_ANY) } {
        // SAFETY: `name` is live and `ret` is writable under the caller contract.
        return unsafe { strdup_to(ret, name) };
    }

    // SAFETY: both helpers receive the documented live string.
    if unsafe { c_string_is_glob(name) } && unsafe { c_string_in_charset(name, VALID_CHARS_GLOB) } {
        if (flags & UNIT_NAME_MANGLE_GLOB) != 0 {
            // SAFETY: `name` is live and `ret` is writable.
            return unsafe { strdup_to(ret, name) };
        }
    }

    // SAFETY: `name` is a live NUL-terminated string.
    if unsafe { rs_path_is_absolute(name) } {
        let mut simplified: *mut c_char = ptr::null_mut();
        // SAFETY: `name` is live and the local output pointer is writable.
        let r = unsafe { rs_path_simplify_alloc(name, &mut simplified) };
        if r < 0 {
            return r;
        }

        // SAFETY: `simplified` is a live C string returned above.
        if unsafe { rs_is_device_path(simplified) } {
            // SAFETY: inputs are live and `ret` is writable.
            let rd = unsafe { unit_name_from_path_simple(simplified, c".device".as_ptr(), ret) };
            if rd >= 0 {
                // SAFETY: `simplified` is the unique allocation returned above.
                unsafe { free(simplified as *mut c_void) };
                return 1;
            }
            if rd != Errno::EINVAL.to_neg_errno() {
                // SAFETY: `simplified` is the unique allocation returned above.
                unsafe { free(simplified as *mut c_void) };
                return rd;
            }
        }

        // SAFETY: inputs are live and `ret` is writable.
        let rm = unsafe { unit_name_from_path_simple(simplified, c".mount".as_ptr(), ret) };
        // SAFETY: `simplified` is the unique allocation returned above.
        unsafe { free(simplified as *mut c_void) };
        if rm >= 0 {
            return 1;
        }
        if rm != Errno::EINVAL.to_neg_errno() {
            return rm;
        }
    }

    // SAFETY: both inputs are live NUL-terminated strings.
    let (name_len, suffix_len) = unsafe { (strlen(name), strlen(suffix)) };
    let Some(allocation) =
        checked_escape_allocation(name_len, suffix_len).and_then(|escaped| escaped.checked_add(1))
    else {
        return Errno::ENOMEM.to_neg_errno();
    };
    let s = malloc(allocation) as *mut c_char;
    if s.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: the allocation reserves four bytes per name byte plus the suffix
    // and terminator, satisfying the helper's output contract.
    unsafe { do_escape_mangle(name, (flags & UNIT_NAME_MANGLE_GLOB) != 0, s as *mut u8) };

    // SAFETY: `s` is a live NUL-terminated string initialized by the helper.
    if ((flags & UNIT_NAME_MANGLE_GLOB) == 0 || !unsafe { c_string_is_glob(s) })
        && unsafe { rs_unit_name_to_type(s) } < 0
    {
        // SAFETY: `s` is live; the allocation reserved `suffix_len + 1`
        // additional bytes after its current contents.
        let pos = unsafe { strlen(s) };
        // SAFETY: the destination tail is writable and disjoint from `suffix`.
        unsafe { ptr::copy_nonoverlapping(suffix, s.add(pos), suffix_len + 1) };
    }

    // SAFETY: `s` is a live NUL-terminated string.
    if (flags & UNIT_NAME_MANGLE_GLOB) == 0
        && !unsafe { unit_name_is_valid_internal(s, UNIT_NAME_ANY) }
    {
        // SAFETY: `s` is the unique allocation obtained above.
        unsafe { free(s as *mut c_void) };
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: the caller guarantees that `ret` is writable.
    unsafe { *ret = s };
    1
}

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub unsafe fn rs_unit_name_mangle(name: *const c_char, flags: i32, ret: *mut *mut c_char) -> i32 {
    // SAFETY: this wrapper forwards the same pointer contract unchanged.
    unsafe { rs_unit_name_mangle_with_suffix(name, ptr::null(), flags, c".service".as_ptr(), ret) }
}

// ── unit_type_may_alias / unit_type_may_template ────────────────────────
// From src/shared/unit-file.h

const MAY_ALIAS: &[i32] = &[
    UNIT_SERVICE,
    UNIT_SOCKET,
    UNIT_TARGET,
    UNIT_DEVICE,
    UNIT_TIMER,
    UNIT_PATH,
];

/// Check if unit type t may alias with other unit types.
/// Returns true if aliasing is allowed, false otherwise.
pub(crate) fn unit_type_may_alias_raw(t: i32) -> bool {
    MAY_ALIAS.contains(&t)
}

const MAY_TEMPLATE: &[i32] = &[
    UNIT_SERVICE,
    UNIT_SOCKET,
    UNIT_TARGET,
    UNIT_TIMER,
    UNIT_PATH,
];

/// Check if unit type t may be templated.
/// Returns true if templating is allowed, false otherwise.
pub(crate) fn unit_type_may_template_raw(t: i32) -> bool {
    MAY_TEMPLATE.contains(&t)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn cstr(s: &str) -> *const c_char {
        CString::new(s).unwrap().into_raw()
    }

    fn reclaim_cstring(ptr: *const c_char) {
        if !ptr.is_null() {
            // SAFETY: `ptr` came from `CString::into_raw` in this test module and is reclaimed exactly once.
            unsafe {
                drop(CString::from_raw(ptr as *mut c_char));
            }
        }
    }

    fn from_raw_mut(ptr: *mut c_char) -> String {
        // SAFETY: the unit-name API returned a live NUL-terminated string from
        // this crate's C-compatible allocator.
        unsafe {
            let s = CStr::from_ptr(ptr).to_str().unwrap().to_string();
            // SAFETY: `ptr` is the unique C-allocator allocation returned by
            // the unit-name API and is released exactly once here.
            free(ptr.cast::<c_void>());
            s
        }
    }

    // ── unit_name_is_valid tests ─────────────────────────────────────────

    #[test]
    fn test_unit_name_is_valid_plain_service() {
        let name = cstr("foo.service");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(unsafe { rs_unit_name_is_valid(name, UNIT_NAME_PLAIN) });
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn safe_plain_or_instance_validator_matches_pid1_cmdline_contract() {
        for valid in [
            "default.target",
            "getty@tty1.service",
            r"escaped\x2dname.service",
        ] {
            assert!(unit_name_is_valid_plain_or_instance(valid), "{valid}");
        }
        for invalid in [
            "",
            "nosuffix",
            "@missing-prefix.service",
            "template@.service",
            "space name.target",
            "unknown.kind",
            "/path.target",
        ] {
            assert!(!unit_name_is_valid_plain_or_instance(invalid), "{invalid}");
        }
    }

    #[test]
    fn test_unit_name_is_valid_instance() {
        let name = cstr("foo@bar.service");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(unsafe { rs_unit_name_is_valid(name, UNIT_NAME_INSTANCE) });
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_is_valid_template() {
        let name = cstr("foo@.service");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(unsafe { rs_unit_name_is_valid(name, UNIT_NAME_TEMPLATE) });
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_is_valid_empty() {
        let name = cstr("");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(!unsafe { rs_unit_name_is_valid(name, UNIT_NAME_PLAIN) });
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_is_valid_no_suffix() {
        let name = cstr("foo");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(!unsafe { rs_unit_name_is_valid(name, UNIT_NAME_PLAIN) });
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_is_valid_invalid_suffix() {
        let name = cstr("foo.baz");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(!unsafe { rs_unit_name_is_valid(name, UNIT_NAME_PLAIN) });
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_is_valid_invalid_chars() {
        let name = cstr("fo o.service");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(!unsafe { rs_unit_name_is_valid(name, UNIT_NAME_PLAIN) });
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_is_valid_at_start() {
        let name = cstr("@foo.service");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(!unsafe { rs_unit_name_is_valid(name, UNIT_NAME_PLAIN) });
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_is_valid_null() {
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(!unsafe { rs_unit_name_is_valid(ptr::null(), UNIT_NAME_PLAIN) });
    }

    #[test]
    fn test_unit_name_is_valid_flags_zero() {
        let name = cstr("foo.service");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(!unsafe { rs_unit_name_is_valid(name, 0) });
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_is_valid_all_types() {
        let types = [
            "foo.service",
            "foo.mount",
            "foo.swap",
            "foo.socket",
            "foo.target",
            "foo.device",
            "foo.automount",
            "foo.timer",
            "foo.path",
            "foo.slice",
            "foo.scope",
        ];
        for t in types {
            let name = cstr(t);
            // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
            assert!(
                unsafe { rs_unit_name_is_valid(name, UNIT_NAME_PLAIN) },
                "failed for {t}"
            );
            // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
            reclaim_cstring(name);
        }
    }

    // ── unit_name_to_type tests ──────────────────────────────────────────

    #[test]
    fn test_unit_name_to_type_service() {
        let name = cstr("foo.service");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert_eq!(unsafe { rs_unit_name_to_type(name) }, UNIT_SERVICE);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_to_type_socket() {
        let name = cstr("foo.socket");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert_eq!(unsafe { rs_unit_name_to_type(name) }, UNIT_SOCKET);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_to_type_mount() {
        let name = cstr("foo.mount");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert_eq!(unsafe { rs_unit_name_to_type(name) }, UNIT_MOUNT);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_to_type_timer() {
        let name = cstr("foo.timer");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert_eq!(unsafe { rs_unit_name_to_type(name) }, UNIT_TIMER);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_to_type_slice() {
        let name = cstr("foo.slice");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert_eq!(unsafe { rs_unit_name_to_type(name) }, UNIT_SLICE);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_to_type_invalid() {
        let name = cstr("foo.baz");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(unsafe { rs_unit_name_to_type(name) } < 0);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    // ── unit_name_build roundtrip tests ──────────────────────────────────

    #[test]
    fn test_unit_name_build_plain() {
        let prefix = cstr("foo");
        let suffix = cstr(".service");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_unit_name_build(prefix, ptr::null(), suffix, &mut ret) };
        assert_eq!(rc, 0);
        assert!(!ret.is_null());
        assert_eq!(from_raw_mut(ret), "foo.service");
        reclaim_cstring(prefix);
        reclaim_cstring(suffix);
    }

    #[test]
    fn test_unit_name_build_instance() {
        let prefix = cstr("foo");
        let instance = cstr("bar");
        let suffix = cstr(".service");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_unit_name_build(prefix, instance, suffix, &mut ret) };
        assert_eq!(rc, 0);
        assert!(!ret.is_null());
        assert_eq!(from_raw_mut(ret), "foo@bar.service");
        reclaim_cstring(prefix);
        reclaim_cstring(instance);
        reclaim_cstring(suffix);
    }

    #[test]
    fn test_unit_name_build_roundtrip() {
        let prefix = cstr("myapp");
        let instance = cstr("worker1");
        let suffix = cstr(".socket");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_unit_name_build(prefix, instance, suffix, &mut ret) };
        assert_eq!(rc, 0);

        let built = from_raw_mut(ret);
        assert_eq!(built, "myapp@worker1.socket");

        // Parse it back
        let name = cstr(&built);
        let mut parsed_prefix: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc2 = unsafe { rs_unit_name_to_prefix(name, &mut parsed_prefix) };
        assert_eq!(rc2, 0);
        assert_eq!(from_raw_mut(parsed_prefix), "myapp@worker1");

        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let type_val = unsafe { rs_unit_name_to_type(name) };
        assert_eq!(type_val, UNIT_SOCKET);

        reclaim_cstring(prefix);
        reclaim_cstring(instance);
        reclaim_cstring(suffix);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_build_invalid_suffix() {
        let prefix = cstr("foo");
        let suffix = cstr("no-dot");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_unit_name_build(prefix, ptr::null(), suffix, &mut ret) };
        assert_eq!(rc, Errno::EINVAL.to_neg_errno());
        reclaim_cstring(prefix);
        reclaim_cstring(suffix);
    }

    #[test]
    fn test_unit_name_build_invalid_prefix() {
        let prefix = cstr("bad prefix");
        let suffix = cstr(".service");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_unit_name_build(prefix, ptr::null(), suffix, &mut ret) };
        assert_eq!(rc, Errno::EINVAL.to_neg_errno());
        reclaim_cstring(prefix);
        reclaim_cstring(suffix);
    }

    // ── unit_name_to_prefix tests ────────────────────────────────────────

    #[test]
    fn test_unit_name_to_prefix_plain() {
        let name = cstr("foo.service");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_unit_name_to_prefix(name, &mut ret) };
        assert_eq!(rc, 0);
        assert_eq!(from_raw_mut(ret), "foo");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_to_prefix_instance() {
        let name = cstr("foo@bar.service");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_unit_name_to_prefix(name, &mut ret) };
        assert_eq!(rc, 0);
        assert_eq!(from_raw_mut(ret), "foo@bar");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    // ── unit_name_to_instance tests ──────────────────────────────────────

    #[test]
    fn test_unit_name_to_instance_plain() {
        let name = cstr("foo.service");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_unit_name_to_instance(name, &mut ret) };
        assert_eq!(rc, UNIT_NAME_PLAIN);
        assert!(ret.is_null());
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_to_instance_with_instance() {
        let name = cstr("foo@bar.service");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_unit_name_to_instance(name, &mut ret) };
        assert_eq!(rc, UNIT_NAME_INSTANCE);
        assert_eq!(from_raw_mut(ret), "bar");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_unit_name_to_instance_template() {
        let name = cstr("foo@.service");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_unit_name_to_instance(name, &mut ret) };
        assert_eq!(rc, UNIT_NAME_TEMPLATE);
        assert_eq!(from_raw_mut(ret), "");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    // ── slice tests ──────────────────────────────────────────────────────

    #[test]
    fn test_slice_name_is_valid_root() {
        let name = cstr("-.slice");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(unsafe { rs_slice_name_is_valid(name) });
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_slice_name_is_valid_nested() {
        let name = cstr("user-1000.slice");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(unsafe { rs_slice_name_is_valid(name) });
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_slice_build_parent_slice_nested() {
        let slice = cstr("foo-bar.slice");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: `slice` is a live NUL-terminated string and `ret` is writable.
        let rc = unsafe { rs_slice_build_parent_slice(slice, &mut ret) };
        assert_eq!(rc, 1);
        assert_eq!(from_raw_mut(ret), "foo.slice");
        reclaim_cstring(slice);
    }

    #[test]
    fn test_slice_build_subslice_from_root() {
        let slice = cstr("-.slice");
        let name = cstr("user");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_slice_build_subslice(slice, name, &mut ret) };
        assert_eq!(rc, 0);
        assert_eq!(from_raw_mut(ret), "user.slice");
        reclaim_cstring(slice);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    #[test]
    fn test_slice_build_subslice_from_nested() {
        let slice = cstr("user.slice");
        let name = cstr("1000");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_slice_build_subslice(slice, name, &mut ret) };
        assert_eq!(rc, 0);
        assert_eq!(from_raw_mut(ret), "user-1000.slice");
        reclaim_cstring(slice);
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }

    // ── escape/unescape tests ────────────────────────────────────────────

    #[test]
    fn test_unit_name_escape() {
        let input = cstr("/foo/bar-baz");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let result = unsafe { rs_unit_name_escape(input) };
        assert!(!result.is_null());
        assert_eq!(from_raw_mut(result), "-foo-bar\\x2dbaz");
        reclaim_cstring(input);
    }

    #[test]
    fn test_unit_name_unescape() {
        let input = cstr("-foo-bar\\x2dbaz");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_unit_name_unescape(input, &mut ret) };
        assert_eq!(rc, 0);
        assert_eq!(from_raw_mut(ret), "/foo/bar-baz");
        reclaim_cstring(input);
    }

    // ── prefix_equal tests ───────────────────────────────────────────────

    #[test]
    fn test_unit_name_prefix_equal_same_prefix() {
        let a = cstr("foo@bar.service");
        let b = cstr("foo@baz.service");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(unsafe { rs_unit_name_prefix_equal(a, b) });
        reclaim_cstring(a);
        reclaim_cstring(b);
    }

    #[test]
    fn test_unit_name_prefix_equal_different_prefix() {
        let a = cstr("foo@bar.service");
        let b = cstr("baz@bar.service");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        assert!(!unsafe { rs_unit_name_prefix_equal(a, b) });
        reclaim_cstring(a);
        reclaim_cstring(b);
    }

    // ── replace_instance tests ───────────────────────────────────────────

    #[test]
    fn test_unit_name_replace_instance() {
        let original = cstr("foo@.service");
        let instance = cstr("bar");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_unit_name_replace_instance(original, instance, &mut ret) };
        assert_eq!(rc, 0);
        assert_eq!(from_raw_mut(ret), "foo@bar.service");
        reclaim_cstring(original);
        reclaim_cstring(instance);
    }

    #[test]
    fn test_unit_name_replace_instance_c_edge_cases() {
        let cases = [
            ("foo@xyz.service", "waldo", 0, Some("foo@waldo.service")),
            ("xyz", "waldo", Errno::EINVAL.to_neg_errno(), None),
            ("", "waldo", Errno::EINVAL.to_neg_errno(), None),
            ("foo.service", "waldo", Errno::EINVAL.to_neg_errno(), None),
            (".service", "waldo", Errno::EINVAL.to_neg_errno(), None),
            ("foo@", "waldo", Errno::EINVAL.to_neg_errno(), None),
            ("@bar", "waldo", Errno::EINVAL.to_neg_errno(), None),
        ];

        for (pattern, repl, expected_rc, expected) in cases {
            let pattern_c = cstr(pattern);
            let repl_c = cstr(repl);
            let mut out: *mut c_char = ptr::null_mut();
            // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
            let rc = unsafe { rs_unit_name_replace_instance(pattern_c, repl_c, &mut out) };
            assert_eq!(rc, expected_rc, "{pattern} -> {repl}");
            match expected {
                Some(value) => assert_eq!(from_raw_mut(out), value),
                None => assert!(out.is_null()),
            }
            reclaim_cstring(pattern_c);
            reclaim_cstring(repl_c);
        }
    }

    #[test]
    fn test_unit_name_is_valid_c_edge_cases() {
        let positive = [
            ("foo@bar@bar.service", UNIT_NAME_INSTANCE),
            ("foo@.service", UNIT_NAME_TEMPLATE),
            (".test.service", UNIT_NAME_PLAIN),
            (".test@.service", UNIT_NAME_TEMPLATE),
            ("_strange::::.service", UNIT_NAME_ANY),
            ("user@1000.slice", UNIT_NAME_INSTANCE),
        ];
        for (name, flags) in positive {
            let name_c = cstr(name);
            // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
            assert!(unsafe { rs_unit_name_is_valid(name_c, flags) }, "{name}");
            reclaim_cstring(name_c);
        }

        let negative = [
            ".service",
            "@.service",
            "@piep.service",
            "foo@%i.service",
            "foo@%%i.service",
            "foo.target.wants/plain.service",
        ];
        for name in negative {
            let name_c = cstr(name);
            // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
            assert!(
                !unsafe { rs_unit_name_is_valid(name_c, UNIT_NAME_ANY) },
                "{name}"
            );
            reclaim_cstring(name_c);
        }
    }

    #[test]
    fn test_unit_name_mangle_matches_c_cases() {
        let cases = [
            (false, "foo.service", 0, Some("foo.service")),
            (false, "/home", 1, Some("home.mount")),
            (false, "/dev/sda", 1, Some("dev-sda.device")),
            (
                false,
                "üxknürz.service",
                1,
                Some("\\xc3\\xbcxkn\\xc3\\xbcrz.service"),
            ),
            (
                false,
                "_____####----.....service",
                1,
                Some("_____\\x23\\x23\\x23\\x23----.....service"),
            ),
            (false, "", Errno::EINVAL.to_neg_errno(), None),
            (true, "foo.service", 0, Some("foo.service")),
            (true, "foo", 1, Some("foo.service")),
            (true, "foo*", 0, Some("foo*")),
            (true, "ü*", 1, Some("\\xc3\\xbc*")),
        ];

        for (allow_glob, input, expected_rc, expected_value) in cases {
            let input_c = cstr(input);
            let flags =
                (if allow_glob { UNIT_NAME_MANGLE_GLOB } else { 0 }) | UNIT_NAME_MANGLE_WARN;
            let mut out: *mut c_char = ptr::null_mut();
            // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
            let rc = unsafe { rs_unit_name_mangle(input_c, flags, &mut out) };
            assert_eq!(rc, expected_rc, "input={input}");
            match expected_value {
                Some(value) => {
                    let rendered = from_raw_mut(out);
                    assert_eq!(rendered, value, "input={input}");

                    let rendered_c = cstr(&rendered);
                    let mut second: *mut c_char = ptr::null_mut();
                    // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
                    let rc2 = unsafe { rs_unit_name_mangle(rendered_c, flags, &mut second) };
                    assert_eq!(rc2, 0, "idempotency for {input}");
                    assert_eq!(from_raw_mut(second), rendered);
                    reclaim_cstring(rendered_c);
                }
                None => assert!(out.is_null()),
            }
            reclaim_cstring(input_c);
        }
    }

    // ── template tests ───────────────────────────────────────────────────

    #[test]
    fn test_unit_name_template_from_instance() {
        let input = cstr("foo@bar.service");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_unit_name_template(input, &mut ret) };
        assert_eq!(rc, 0);
        assert_eq!(from_raw_mut(ret), "foo@.service");
        reclaim_cstring(input);
    }

    // ── suffix_change tests ──────────────────────────────────────────────

    #[test]
    fn test_unit_name_change_suffix() {
        let name = cstr("foo.service");
        let suffix = cstr(".socket");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_unit_name_change_suffix(name, suffix, &mut ret) };
        assert_eq!(rc, 0);
        assert_eq!(from_raw_mut(ret), "foo.socket");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
        reclaim_cstring(suffix);
    }

    // ── prefix_and_instance tests ────────────────────────────────────────

    #[test]
    fn test_unit_name_to_prefix_and_instance() {
        let name = cstr("foo@bar.service");
        let mut ret: *mut c_char = ptr::null_mut();
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        let rc = unsafe { rs_unit_name_to_prefix_and_instance(name, &mut ret) };
        assert_eq!(rc, 0);
        assert_eq!(from_raw_mut(ret), "foo@bar");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        reclaim_cstring(name);
    }
}
