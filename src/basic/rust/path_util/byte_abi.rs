// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.path-util; authority=src/basic/path-util.c,src/basic/path-util.h

//! Exact C ABI facades for path operations that do not require filesystem I/O.
//!
//! All path semantics live in the safe byte-slice core below. The exported
//! functions only translate NUL-terminated C storage, borrowed offsets, and
//! C-allocator ownership at the ABI boundary. Paths are never interpreted as
//! UTF-8 and never pass through `std::path::Path`.

use std::cmp::Ordering;
use std::ffi::CStr;
use std::ptr;

use libc::{c_char, c_uint};

const NAME_MAX: usize = libc::NAME_MAX as usize;
const PATH_MAX: usize = libc::PATH_MAX as usize;
const PATH_STARTSWITH_REFUSE_DOT_DOT: c_uint = 1 << 0;
const PATH_STARTSWITH_RETURN_LEADING_SLASH: c_uint = 1 << 1;
const PATH_SIMPLIFY_KEEP_TRAILING_SLASH: c_uint = 1 << 0;

#[derive(Clone, Copy, Debug)]
struct Component {
    start: usize,
    end: usize,
    next: usize,
}

#[derive(Clone, Copy, Debug)]
struct LastComponent {
    start: usize,
    end: usize,
    next: usize,
}

fn skip_slash_or_dot(path: &[u8], mut cursor: usize) -> usize {
    while cursor < path.len() {
        if path[cursor] == b'/' {
            cursor += 1;
        } else if path[cursor] == b'.' && path.get(cursor + 1).copied() == Some(b'/') {
            cursor += 2;
        } else {
            break;
        }
    }
    cursor
}

fn first_component(
    path: &[u8],
    cursor: usize,
    accept_dot_dot: bool,
) -> Result<Option<Component>, i32> {
    let first = skip_slash_or_dot(path, cursor);
    if first == path.len() {
        return Ok(None);
    }
    if &path[first..] == b"." {
        return Ok(None);
    }

    let end = path[first..]
        .iter()
        .position(|&byte| byte == b'/')
        .map_or(path.len(), |relative| first + relative);
    let len = end - first;
    if len > NAME_MAX || (!accept_dot_dot && &path[first..end] == b"..") {
        return Err(-libc::EINVAL);
    }

    let mut next = skip_slash_or_dot(path, end);
    if &path[next..] == b"." {
        next = path.len();
    }
    Ok(Some(Component {
        start: first,
        end,
        next,
    }))
}

fn skip_slash_or_dot_backward(path: &[u8], mut cursor: Option<usize>) -> Option<usize> {
    while let Some(q) = cursor {
        if path[q] != b'/'
            && !(q > 0 && path[q - 1] == b'/' && path[q] == b'.')
            && !(q == 0 && path[q] == b'.')
        {
            return Some(q);
        }
        cursor = q.checked_sub(1);
    }
    None
}

fn last_component(
    path: &[u8],
    next: Option<usize>,
    accept_dot_dot: bool,
) -> Result<Option<LastComponent>, i32> {
    if path.is_empty() {
        return Ok(None);
    }

    let q = match next {
        Some(0) => return Ok(None),
        Some(next) => {
            if next > path.len() || (next < path.len() && path[next] != b'/') {
                return Err(-libc::EINVAL);
            }
            next - 1
        }
        None => path.len() - 1,
    };

    let Some(q) = skip_slash_or_dot_backward(path, Some(q)) else {
        return Ok(None);
    };
    let end = q + 1;
    let preceding_slash = path[..=q].iter().rposition(|&byte| byte == b'/');
    let start = preceding_slash.map_or(0, |slash| slash + 1);
    let len = end - start;
    if len > NAME_MAX || (!accept_dot_dot && &path[start..end] == b"..") {
        return Err(-libc::EINVAL);
    }

    let previous = preceding_slash
        .and_then(|slash| skip_slash_or_dot_backward(path, Some(slash)))
        .map_or(0, |q| q + 1);
    Ok(Some(LastComponent {
        start,
        end,
        next: previous,
    }))
}

fn last_path_component_offset(path: &[u8]) -> usize {
    if path.is_empty() {
        return 0;
    }
    let mut end = path.len();
    while end > 0 && path[end - 1] == b'/' {
        end -= 1;
    }
    if end == 0 {
        return path.len() - 1;
    }
    path[..end]
        .iter()
        .rposition(|&byte| byte == b'/')
        .map_or(0, |slash| slash + 1)
}

fn cmp_bool(a: bool, b: bool) -> i32 {
    match a.cmp(&b) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

fn strcmp_bytes(a: &[u8], b: &[u8]) -> i32 {
    for (&left, &right) in a.iter().zip(b) {
        if left != right {
            return i32::from(left) - i32::from(right);
        }
    }
    match a.len().cmp(&b.len()) {
        Ordering::Less => -i32::from(b[a.len()]),
        Ordering::Equal => 0,
        Ordering::Greater => i32::from(a[b.len()]),
    }
}

fn path_compare_bytes(a: Option<&[u8]>, b: Option<&[u8]>) -> i32 {
    let null_order = cmp_bool(a.is_some(), b.is_some());
    if null_order != 0 {
        return null_order;
    }
    let (Some(a), Some(b)) = (a, b) else {
        return 0;
    };

    let absolute_order = cmp_bool(a.first() == Some(&b'/'), b.first() == Some(&b'/'));
    if absolute_order != 0 {
        return absolute_order;
    }

    let (mut a_cursor, mut b_cursor) = (0, 0);
    loop {
        let a_component = first_component(a, a_cursor, true);
        let b_component = first_component(b, b_cursor, true);
        match (a_component, b_component) {
            (Err(_), Err(_)) => return strcmp_bytes(&a[a_cursor..], &b[b_cursor..]),
            (Err(_), _) => return 1,
            (_, Err(_)) => return -1,
            (Ok(None), Ok(None)) => return 0,
            (Ok(None), Ok(Some(_))) => return -1,
            (Ok(Some(_)), Ok(None)) => return 1,
            (Ok(Some(left)), Ok(Some(right))) => {
                let left_bytes = &a[left.start..left.end];
                let right_bytes = &b[right.start..right.end];
                let common = left_bytes.len().min(right_bytes.len());
                let byte_order = strcmp_bytes(&left_bytes[..common], &right_bytes[..common]);
                if byte_order != 0 {
                    return byte_order;
                }
                let len_order = cmp_bool(
                    left_bytes.len() > right_bytes.len(),
                    left_bytes.len() < right_bytes.len(),
                );
                if len_order != 0 {
                    return len_order;
                }
                a_cursor = left.next;
                b_cursor = right.next;
            }
        }
    }
}

fn path_startswith_offset(path: &[u8], prefix: &[u8], flags: c_uint) -> Option<usize> {
    if (path.first() == Some(&b'/')) != (prefix.first() == Some(&b'/')) {
        return None;
    }

    let accept_dot_dot = flags & PATH_STARTSWITH_REFUSE_DOT_DOT == 0;
    let (mut path_cursor, mut prefix_cursor) = (0, 0);
    loop {
        let path_component = first_component(path, path_cursor, accept_dot_dot).ok()?;
        let prefix_component = first_component(prefix, prefix_cursor, accept_dot_dot).ok()?;

        let Some(prefix_component) = prefix_component else {
            let mut result = path_component.map_or(path_cursor, |component| component.start);
            if flags & PATH_STARTSWITH_RETURN_LEADING_SLASH != 0 {
                result = result.checked_sub(1)?;
                if path[result] != b'/' {
                    return None;
                }
            }
            return Some(result);
        };
        let Some(path_component) = path_component else {
            return None;
        };
        if path[path_component.start..path_component.end]
            != prefix[prefix_component.start..prefix_component.end]
        {
            return None;
        }
        path_cursor = path_component.next;
        prefix_cursor = prefix_component.next;
    }
}

fn simplify_bytes(path: &[u8], flags: c_uint) -> Vec<u8> {
    if path.is_empty() {
        return Vec::new();
    }

    let keep_trailing_slash =
        flags & PATH_SIMPLIFY_KEEP_TRAILING_SLASH != 0 && path.ends_with(b"/");
    let absolute = path.starts_with(b"/");
    let mut output = Vec::with_capacity(path.len());
    if absolute {
        output.push(b'/');
    }

    let mut cursor = usize::from(absolute);
    let mut add_slash = false;
    let mut beginning = true;
    loop {
        match first_component(path, cursor, true) {
            Ok(None) => break,
            Ok(Some(component)) => {
                if absolute && beginning && &path[component.start..component.end] == b".." {
                    cursor = component.next;
                    continue;
                }
                beginning = false;
                if add_slash {
                    output.push(b'/');
                }
                output.extend_from_slice(&path[component.start..component.end]);
                add_slash = true;
                cursor = component.next;
            }
            Err(_) => {
                beginning = false;
                if add_slash {
                    output.push(b'/');
                }
                output.extend_from_slice(&path[cursor..]);
                return output;
            }
        }
    }

    if output.is_empty() {
        output.push(b'.');
    }
    if output.last() != Some(&b'/') && keep_trailing_slash {
        output.push(b'/');
    }
    output
}

fn path_is_valid_bytes(path: &[u8], accept_dot_dot: bool) -> bool {
    if path.is_empty() {
        return false;
    }
    let mut cursor = 0;
    loop {
        match first_component(path, cursor, accept_dot_dot) {
            Err(_) => return false,
            Ok(None) => return cursor < PATH_MAX,
            Ok(Some(component)) => {
                cursor = component.next;
                if cursor >= PATH_MAX {
                    return false;
                }
            }
        }
    }
}

fn filename_is_valid_bytes(path: &[u8]) -> bool {
    !path.is_empty()
        && path != b"."
        && path != b".."
        && path.len() <= NAME_MAX
        && !path.contains(&b'/')
}

fn make_relative_bytes(from: &[u8], to: &[u8]) -> Result<Vec<u8>, i32> {
    if !from.starts_with(b"/") || !to.starts_with(b"/") {
        return Err(-libc::EINVAL);
    }

    let (mut from_cursor, mut to_cursor) = (0, 0);
    let divergent_to;
    loop {
        let from_component = first_component(from, from_cursor, true)?;
        let to_component = first_component(to, to_cursor, true)?;
        match (from_component, to_component) {
            (None, None) => return Ok(b".".to_vec()),
            (None, Some(to_component)) => {
                let result = simplify_bytes(&to[to_component.start..], 0);
                return path_is_valid_bytes(&result, true)
                    .then_some(result)
                    .ok_or(-libc::EINVAL);
            }
            (Some(_), None) => {
                divergent_to = to.len();
                break;
            }
            (Some(from_component), Some(to_component)) => {
                from_cursor = from_component.next;
                to_cursor = to_component.next;
                if from[from_component.start..from_component.end]
                    != to[to_component.start..to_component.end]
                {
                    divergent_to = to_component.start;
                    break;
                }
            }
        }
    }

    let mut parents = 1usize;
    loop {
        match first_component(from, from_cursor, false)? {
            None => break,
            Some(component) => {
                parents = parents.checked_add(1).ok_or(-libc::ENOMEM)?;
                from_cursor = component.next;
            }
        }
    }

    if divergent_to == to.len() && parents.checked_mul(3).ok_or(-libc::ENOMEM)? > PATH_MAX {
        return Err(-libc::EINVAL);
    }
    let mut result = Vec::new();
    result
        .try_reserve(
            parents
                .checked_mul(3)
                .and_then(|size| size.checked_add(to.len() - divergent_to))
                .ok_or(-libc::ENOMEM)?,
        )
        .map_err(|_| -libc::ENOMEM)?;
    for _ in 0..parents {
        result.extend_from_slice(b"../");
    }
    if divergent_to == to.len() {
        result.pop();
        return Ok(result);
    }
    result.extend_from_slice(&to[divergent_to..]);
    result = simplify_bytes(&result, 0);
    path_is_valid_bytes(&result, true)
        .then_some(result)
        .ok_or(-libc::EINVAL)
}

fn split_prefix_filename_bytes(
    path: &[u8],
    want_dir: bool,
    want_filename: bool,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>, bool), i32> {
    if path.is_empty() {
        return Err(-libc::EINVAL);
    }
    let component = last_component(path, None, false)?.ok_or(-libc::EADDRNOTAVAIL)?;

    let directory = if want_dir {
        if component.next == 0 {
            if path[0] != b'/' {
                if !want_filename {
                    return Err(-libc::EDESTADDRREQ);
                }
                None
            } else {
                Some(b"/".to_vec())
            }
        } else {
            let directory = simplify_bytes(&path[..component.next], 0);
            if !path_is_valid_bytes(&directory, true) {
                return Err(-libc::EINVAL);
            }
            Some(directory)
        }
    } else {
        if !path_is_valid_bytes(path, true) {
            return Err(-libc::EINVAL);
        }
        None
    };
    let filename = want_filename.then(|| path[component.start..component.end].to_vec());
    Ok((directory, filename, component.end < path.len()))
}

fn filename_compare_bytes(a: Option<&[u8]>, b: Option<&[u8]>) -> i32 {
    let null_order = cmp_bool(a.is_some(), b.is_some());
    if null_order != 0 {
        return null_order;
    }
    let (Some(a), Some(b)) = (a, b) else {
        return 0;
    };
    let left = split_prefix_filename_bytes(a, false, true);
    let right = split_prefix_filename_bytes(b, false, true);
    let root_order = cmp_bool(
        !matches!(left, Err(error) if error == -libc::EADDRNOTAVAIL),
        !matches!(right, Err(error) if error == -libc::EADDRNOTAVAIL),
    );
    if root_order != 0 {
        return root_order;
    }
    let invalid_order = cmp_bool(left.is_err(), right.is_err());
    if invalid_order != 0 {
        return invalid_order;
    }
    match (left, right) {
        (Ok((_, Some(left), _)), Ok((_, Some(right), _))) => strcmp_bytes(&left, &right),
        (Err(_), Err(_)) => strcmp_bytes(a, b),
        _ => 0,
    }
}

/// # Safety
/// `path` must be null or point to a live NUL-terminated byte string.
unsafe fn bytes_or_none<'a>(path: *const c_char) -> Option<&'a [u8]> {
    if path.is_null() {
        None
    } else {
        // SAFETY: callers uphold the C-string input contract.
        Some(unsafe { CStr::from_ptr(path) }.to_bytes())
    }
}

/// # Safety
/// `path` must point to a live NUL-terminated byte string.
unsafe fn bytes<'a>(path: *const c_char) -> &'a [u8] {
    // SAFETY: callers uphold the nonnull C-string input contract.
    unsafe { CStr::from_ptr(path) }.to_bytes()
}

fn malloc_bytes(value: &[u8]) -> Result<*mut c_char, i32> {
    let size = value.len().checked_add(1).ok_or(-libc::ENOMEM)?;
    // SAFETY: malloc accepts every size and the null result is checked.
    let allocation = unsafe { libc::malloc(size) }.cast::<c_char>();
    if allocation.is_null() {
        return Err(-libc::ENOMEM);
    }
    // SAFETY: allocation has `size` writable bytes and the source is disjoint.
    unsafe {
        ptr::copy_nonoverlapping(value.as_ptr().cast::<c_char>(), allocation, value.len());
        *allocation.add(value.len()) = 0;
    }
    Ok(allocation)
}

/// C ABI mirror of `path_find_first_component()`.
///
/// # Safety
/// `p` must point to a live C-string pointer and `ret`, when nonnull, must be
/// writable. Published pointers borrow the original input string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_find_first_component(
    p: *mut *const c_char,
    accept_dot_dot: bool,
    ret: *mut *const c_char,
) -> i32 {
    if p.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: guaranteed by the entry-point contract.
    let input = unsafe { *p };
    let Some(path) = (unsafe { bytes_or_none(input) }) else {
        if !ret.is_null() {
            // SAFETY: guaranteed by the entry-point contract.
            unsafe { *ret = ptr::null() };
        }
        return 0;
    };
    match first_component(path, 0, accept_dot_dot) {
        Err(error) => error,
        Ok(None) => {
            // SAFETY: all offsets are within the input C string.
            unsafe {
                *p = input.add(path.len());
                if !ret.is_null() {
                    *ret = ptr::null();
                }
            }
            0
        }
        Ok(Some(component)) => {
            // SAFETY: all offsets are within the input C string.
            unsafe {
                *p = input.add(component.next);
                if !ret.is_null() {
                    *ret = input.add(component.start);
                }
            }
            (component.end - component.start) as i32
        }
    }
}

/// C ABI mirror of `path_find_last_component()`.
///
/// # Safety
/// `path` must be null or a live C string. `next` and `ret`, when nonnull,
/// must be writable; an incoming nonnull `*next` must point into `path`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_find_last_component(
    path: *const c_char,
    accept_dot_dot: bool,
    next: *mut *const c_char,
    ret: *mut *const c_char,
) -> i32 {
    // SAFETY: upheld by this entry point's C-string contract.
    let Some(path_bytes) = (unsafe { bytes_or_none(path) }) else {
        // SAFETY: guaranteed by the entry-point contract.
        unsafe {
            if !next.is_null() {
                *next = path;
            }
            if !ret.is_null() {
                *ret = ptr::null();
            }
        }
        return 0;
    };
    // SAFETY: a nonnull `next` is readable by the entry-point contract.
    let next_offset = if next.is_null() || unsafe { *next }.is_null() {
        None
    } else {
        // Address arithmetic avoids creating an out-of-allocation offset before
        // the explicit range check in the safe core.
        // SAFETY: `next` was checked nonnull above and is readable.
        let address = unsafe { *next } as usize;
        let base = path as usize;
        if address < base {
            return -libc::EINVAL;
        }
        Some(address - base)
    };
    match last_component(path_bytes, next_offset, accept_dot_dot) {
        Err(error) => error,
        Ok(None) => {
            // SAFETY: guaranteed by the entry-point contract.
            unsafe {
                if !next.is_null() {
                    *next = path;
                }
                if !ret.is_null() {
                    *ret = ptr::null();
                }
            }
            0
        }
        Ok(Some(component)) => {
            // SAFETY: safe-core offsets are within the input C string.
            unsafe {
                if !next.is_null() {
                    *next = path.add(component.next);
                }
                if !ret.is_null() {
                    *ret = path.add(component.start);
                }
            }
            (component.end - component.start) as i32
        }
    }
}

/// C ABI mirror of `last_path_component()`.
///
/// # Safety
/// `path` must be null or point to a live NUL-terminated byte string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_last_path_component(path: *const c_char) -> *const c_char {
    // SAFETY: upheld by this entry point's C-string contract.
    let Some(path_bytes) = (unsafe { bytes_or_none(path) }) else {
        return ptr::null();
    };
    // SAFETY: the safe core returns an in-bounds or one-past offset.
    unsafe { path.add(last_path_component_offset(path_bytes)) }
}

/// C ABI mirror of `path_compare()`.
///
/// # Safety
/// Inputs must be null or point to live NUL-terminated byte strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_compare(a: *const c_char, b: *const c_char) -> i32 {
    // SAFETY: upheld by this entry point's C-string contracts.
    path_compare_bytes(unsafe { bytes_or_none(a) }, unsafe { bytes_or_none(b) })
}

/// C ABI mirror of `path_startswith_full()`.
///
/// # Safety
/// Inputs must point to live NUL-terminated byte strings. A successful result
/// borrows storage from `path`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_startswith_full(
    path: *const c_char,
    prefix: *const c_char,
    flags: c_uint,
) -> *mut c_char {
    if path.is_null() || prefix.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: both pointers passed the null checks and satisfy the entry contract.
    let offset = path_startswith_offset(unsafe { bytes(path) }, unsafe { bytes(prefix) }, flags);
    offset.map_or(ptr::null_mut(), |offset| {
        // SAFETY: the safe core returns an in-bounds or one-past offset.
        unsafe { path.add(offset).cast_mut() }
    })
}

/// C ABI mirror of `path_startswith()`.
///
/// # Safety
/// Inputs must point to live NUL-terminated byte strings. A successful result
/// borrows storage from `path`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_startswith(
    path: *const c_char,
    prefix: *const c_char,
) -> *mut c_char {
    // SAFETY: this facade forwards the same input contract.
    unsafe { rs_path_startswith_full(path, prefix, 0) }
}

/// C ABI mirror of `path_simplify_full()`.
///
/// # Safety
/// `path` must be null or a writable NUL-terminated byte string whose full
/// current extent remains writable. The return aliases `path`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_simplify_full(path: *mut c_char, flags: c_uint) -> *mut c_char {
    if path.is_null() {
        return path;
    }
    // SAFETY: `path` passed the null check and satisfies the entry contract.
    let original = unsafe { bytes(path) };
    let simplified = simplify_bytes(original, flags);
    debug_assert!(simplified.len() <= original.len());
    // SAFETY: simplification never grows beyond the original writable extent.
    unsafe {
        ptr::copy_nonoverlapping(simplified.as_ptr().cast::<c_char>(), path, simplified.len());
        *path.add(simplified.len()) = 0;
    }
    path
}

/// C ABI mirror of `path_simplify()`.
///
/// # Safety
/// The contract is identical to `rs_path_simplify_full()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_simplify(path: *mut c_char) -> *mut c_char {
    // SAFETY: this facade forwards the same input contract.
    unsafe { rs_path_simplify_full(path, 0) }
}

/// C ABI mirror of `path_simplify_alloc()`.
///
/// # Safety
/// `path` must be null or a live C string and `ret` must be writable. On
/// success, `*ret` is null or a C-allocator allocation owned by the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_simplify_alloc(path: *const c_char, ret: *mut *mut c_char) -> i32 {
    if ret.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: upheld by this entry point's C-string contract.
    let Some(path) = (unsafe { bytes_or_none(path) }) else {
        // SAFETY: guaranteed by the entry-point contract.
        unsafe { *ret = ptr::null_mut() };
        return 0;
    };
    let allocation = match malloc_bytes(&simplify_bytes(path, 0)) {
        Ok(allocation) => allocation,
        Err(error) => return error,
    };
    // SAFETY: output is published only after complete allocation.
    unsafe { *ret = allocation };
    0
}

/// C ABI mirror of `path_make_relative()`.
///
/// # Safety
/// Inputs must point to live C strings and `ret` must be writable. On success,
/// `*ret` is a C-allocator allocation owned by the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_make_relative(
    from: *const c_char,
    to: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    if from.is_null() || to.is_null() || ret.is_null() {
        return -libc::EINVAL;
    }
    // SAFETY: both pointers passed the null checks and satisfy the entry contract.
    let value = match make_relative_bytes(unsafe { bytes(from) }, unsafe { bytes(to) }) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let allocation = match malloc_bytes(&value) {
        Ok(allocation) => allocation,
        Err(error) => return error,
    };
    // SAFETY: output is published only after complete allocation.
    unsafe { *ret = allocation };
    0
}

/// C ABI mirror of `path_equal()`.
///
/// # Safety
/// Inputs must be null or point to live NUL-terminated byte strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_equal(a: *const c_char, b: *const c_char) -> bool {
    // SAFETY: upheld by this entry point's C-string contracts.
    path_compare_bytes(unsafe { bytes_or_none(a) }, unsafe { bytes_or_none(b) }) == 0
}

/// C ABI mirror of `path_is_valid()`.
///
/// # Safety
/// `path` must be null or point to a live NUL-terminated byte string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_is_valid(path: *const c_char) -> bool {
    // SAFETY: upheld by this entry point's C-string contract.
    unsafe { bytes_or_none(path) }.is_some_and(|path| path_is_valid_bytes(path, true))
}

/// C ABI mirror of `path_is_safe()`.
///
/// # Safety
/// `path` must be null or point to a live NUL-terminated byte string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_is_safe(path: *const c_char) -> bool {
    // SAFETY: upheld by this entry point's C-string contract.
    unsafe { bytes_or_none(path) }.is_some_and(|path| path_is_valid_bytes(path, false))
}

/// C ABI mirror of `filename_or_absolute_path_is_valid()`.
///
/// # Safety
/// `path` must be null or point to a live NUL-terminated byte string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_filename_or_absolute_path_is_valid(path: *const c_char) -> bool {
    // SAFETY: upheld by this entry point's C-string contract.
    unsafe { bytes_or_none(path) }.is_some_and(|path| {
        if path.starts_with(b"/") {
            path_is_valid_bytes(path, true)
        } else {
            filename_is_valid_bytes(path)
        }
    })
}

/// C ABI mirror of `path_startswith_strv()`.
///
/// # Safety
/// `path` must point to a live C string. `strv` must be null or point to a
/// null-terminated vector of live C-string pointers. The result borrows `path`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_startswith_strv(
    path: *const c_char,
    strv: *const *mut c_char,
) -> *mut c_char {
    if path.is_null() || strv.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `path` passed the null check and satisfies the entry contract.
    let path_bytes = unsafe { bytes(path) };
    let mut index = 0;
    loop {
        // SAFETY: guaranteed by the null-terminated strv contract.
        let prefix = unsafe { *strv.add(index) };
        if prefix.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: strv entries are live C strings by the entry contract.
        if let Some(offset) = path_startswith_offset(path_bytes, unsafe { bytes(prefix) }, 0) {
            // SAFETY: the safe core returns an in-bounds or one-past offset.
            return unsafe { path.add(offset).cast_mut() };
        }
        index += 1;
    }
}

/// # Safety
/// `strv` must be null or a null-terminated vector of live C-string pointers.
unsafe fn strv_contains(strv: *const *mut c_char, path: &[u8], strip_prefixes: bool) -> bool {
    if strv.is_null() {
        return false;
    }
    let mut index = 0;
    loop {
        // SAFETY: guaranteed by the null-terminated strv contract.
        let item = unsafe { *strv.add(index) };
        if item.is_null() {
            return false;
        }
        // SAFETY: strv entries are live C strings by this helper's contract.
        let mut item = unsafe { bytes(item) };
        if strip_prefixes && item.first() == Some(&b'-') {
            item = &item[1..];
        }
        if strip_prefixes && item.first() == Some(&b'+') {
            item = &item[1..];
        }
        if path_compare_bytes(Some(item), Some(path)) == 0 {
            return true;
        }
        index += 1;
    }
}

/// C ABI mirror of `path_strv_contains()`.
///
/// # Safety
/// `path` must point to a live C string. `strv` must be null or point to a
/// null-terminated vector of live C-string pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_strv_contains(
    strv: *const *mut c_char,
    path: *const c_char,
) -> bool {
    if path.is_null() {
        return false;
    }
    // SAFETY: the entry contract covers both the C string and strv.
    unsafe { strv_contains(strv, bytes(path), false) }
}

/// C ABI mirror of `prefixed_path_strv_contains()`.
///
/// # Safety
/// `path` must point to a live C string. `strv` must be null or point to a
/// null-terminated vector of live C-string pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_prefixed_path_strv_contains(
    strv: *const *mut c_char,
    path: *const c_char,
) -> bool {
    if path.is_null() {
        return false;
    }
    // SAFETY: the entry contract covers both the C string and strv.
    unsafe { strv_contains(strv, bytes(path), true) }
}

/// C ABI mirror of `path_split_prefix_filename()`.
///
/// # Safety
/// `path` must be null or a live C string. Nonnull output pointers must be
/// writable. Successful nonnull outputs are C-allocator-owned by the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_split_prefix_filename(
    path: *const c_char,
    ret_dir: *mut *mut c_char,
    ret_filename: *mut *mut c_char,
) -> i32 {
    // SAFETY: upheld by this entry point's C-string contract.
    let Some(path) = (unsafe { bytes_or_none(path) }) else {
        return -libc::EINVAL;
    };
    let (directory, filename, trailing_slash) =
        match split_prefix_filename_bytes(path, !ret_dir.is_null(), !ret_filename.is_null()) {
            Ok(result) => result,
            Err(error) => return error,
        };

    let directory = match directory {
        Some(directory) => match malloc_bytes(&directory) {
            Ok(allocation) => allocation,
            Err(error) => return error,
        },
        None => ptr::null_mut(),
    };
    let filename = match filename {
        Some(filename) => match malloc_bytes(&filename) {
            Ok(allocation) => allocation,
            Err(error) => {
                // SAFETY: directory is null or owned by this function.
                unsafe { libc::free(directory.cast()) };
                return error;
            }
        },
        None => ptr::null_mut(),
    };

    // SAFETY: allocations are complete and outputs satisfy the entry contract.
    unsafe {
        if !ret_dir.is_null() {
            *ret_dir = directory;
        }
        if !ret_filename.is_null() {
            *ret_filename = filename;
        }
    }
    if trailing_slash { libc::O_DIRECTORY } else { 0 }
}

/// C ABI mirror of `path_extract_filename()`.
///
/// # Safety
/// The contract is the filename-output subset of
/// `rs_path_split_prefix_filename()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_extract_filename(
    path: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this facade forwards the same input and output contracts.
    unsafe { rs_path_split_prefix_filename(path, ptr::null_mut(), ret) }
}

/// C ABI mirror of `path_extract_directory()`.
///
/// # Safety
/// The contract is the directory-output subset of
/// `rs_path_split_prefix_filename()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_extract_directory(
    path: *const c_char,
    ret: *mut *mut c_char,
) -> i32 {
    // SAFETY: this facade forwards the same input and output contracts.
    let result = unsafe { rs_path_split_prefix_filename(path, ret, ptr::null_mut()) };
    if result < 0 { result } else { 0 }
}

/// C ABI mirror of `path_compare_filename()`.
///
/// # Safety
/// Inputs must be null or point to live NUL-terminated byte strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_compare_filename(a: *const c_char, b: *const c_char) -> i32 {
    // SAFETY: upheld by this entry point's C-string contracts.
    filename_compare_bytes(unsafe { bytes_or_none(a) }, unsafe { bytes_or_none(b) })
}

/// C ABI mirror of `path_equal_filename()`.
///
/// # Safety
/// Inputs must be null or point to live NUL-terminated byte strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_path_equal_filename(a: *const c_char, b: *const c_char) -> bool {
    // SAFETY: upheld by this entry point's C-string contracts.
    filename_compare_bytes(unsafe { bytes_or_none(a) }, unsafe { bytes_or_none(b) }) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_core_keeps_bytes_and_cursors() {
        let path = b"//.//\xff///bb/./";
        let first = first_component(path, 0, true).unwrap().unwrap();
        assert_eq!(&path[first.start..first.end], b"\xff");
        let second = first_component(path, first.next, true).unwrap().unwrap();
        assert_eq!(&path[second.start..second.end], b"bb");
        assert!(first_component(path, second.next, true).unwrap().is_none());
    }

    #[test]
    fn simplify_matches_component_rules_without_utf8() {
        assert_eq!(simplify_bytes(b"///\xff//./x/", 0), b"/\xff/x");
        assert_eq!(
            simplify_bytes(b"///\xff//./x/", PATH_SIMPLIFY_KEEP_TRAILING_SLASH,),
            b"/\xff/x/"
        );
        assert_eq!(simplify_bytes(b"/../../x", 0), b"/x");
        assert_eq!(simplify_bytes(b"a/../b", 0), b"a/../b");
    }

    #[test]
    fn relative_and_split_core_preserve_raw_suffixes() {
        assert_eq!(
            make_relative_bytes(b"/a/\xff", b"/a/x//./y").unwrap(),
            b"../x/y"
        );
        let (dir, filename, trailing) =
            split_prefix_filename_bytes(b"//a/./\xff//", true, true).unwrap();
        assert_eq!(dir.unwrap(), b"/a");
        assert_eq!(filename.unwrap(), b"\xff");
        assert!(trailing);
    }
}
