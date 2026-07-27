// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/import-util.c (import_url_*, tar_strip_suffixes,
// raw_strip_suffixes); src/shared/reboot-util.c (reboot_parameter_is_valid)
//
// Keep the algorithms below in byte slices: the C authority operates on
// NUL-terminated bytes, not UTF-8 strings. The five C entry points are the
// only unsafe boundary; their successful string outputs are libc allocations
// and may therefore be released by the C caller with free(3).

use std::ffi::{CStr, c_char, c_int};
use std::ops::Range;
use std::ptr;

use crate::ffi::{Errno, malloc};

const TAR_SUFFIXES: &[&[u8]] = &[
    b".tar",
    b".tar.xz",
    b".tar.gz",
    b".tar.bz2",
    b".tar.zst",
    b".tgz",
];
const RAW_SUFFIXES: &[&[u8]] = &[
    b".xz",
    b".gz",
    b".bz2",
    b".zst",
    b".sysext.raw",
    b".confext.raw",
    b".raw",
    b".qcow2",
    b".img",
    b".bin",
];

/// Return the byte index after the authority portion of the deliberately
/// lenient URI grammar used by the C helper.
fn skip_protocol_and_hostname(url: &[u8]) -> Option<usize> {
    let colon = url.iter().position(|&byte| byte == b':')?;
    if colon == 0 {
        return None;
    }

    let mut position = colon + 1;
    while url.get(position) == Some(&b'/') {
        position += 1;
    }

    let hostname_len = url[position..]
        .iter()
        .position(|&byte| matches!(byte, b'/' | b'?' | b'#'))
        .unwrap_or(url.len() - position);
    (hostname_len != 0).then_some(position + hostname_len)
}

fn url_end_without_query_or_fragment(url: &[u8], hostname_end: usize) -> usize {
    hostname_end
        + url[hostname_end..]
            .iter()
            .position(|&byte| matches!(byte, b'?' | b'#'))
            .unwrap_or(url.len() - hostname_end)
}

fn import_url_last_component_range(url: &[u8]) -> Result<Range<usize>, Errno> {
    let hostname_end = skip_protocol_and_hostname(url).ok_or(Errno::EINVAL)?;
    let mut end = url_end_without_query_or_fragment(url, hostname_end);
    while end > hostname_end && url[end - 1] == b'/' {
        end -= 1;
    }

    let mut start = end;
    while start > hostname_end && url[start - 1] != b'/' {
        start -= 1;
    }
    if end <= start {
        return Err(Errno::EADDRNOTAVAIL);
    }
    Ok(start..end)
}

fn import_url_change_suffix_prefix_end(
    url: &[u8],
    mut n_drop_components: usize,
) -> Result<usize, Errno> {
    let hostname_end = skip_protocol_and_hostname(url).ok_or(Errno::EINVAL)?;
    let mut end = url_end_without_query_or_fragment(url, hostname_end);
    while end > hostname_end && url[end - 1] == b'/' {
        end -= 1;
    }

    while n_drop_components > 0 {
        while end > hostname_end && url[end - 1] != b'/' {
            end -= 1;
        }
        while end > hostname_end && url[end - 1] == b'/' {
            end -= 1;
        }
        n_drop_components -= 1;
    }
    Ok(end)
}

fn tar_strip_suffixes_end(name: &[u8]) -> Result<usize, Errno> {
    let end = TAR_SUFFIXES
        .iter()
        .find_map(|suffix| name.strip_suffix(suffix).map(|prefix| prefix.len()))
        .unwrap_or(name.len());
    (end != 0).then_some(end).ok_or(Errno::EINVAL)
}

fn raw_strip_suffixes_end(name: &[u8]) -> usize {
    let mut end = name.len();
    loop {
        let mut changed = false;
        // Do not stop after a match: C's NULSTR_FOREACH() continues over the
        // ordered table after changing q, then repeats the entire table.
        for suffix in RAW_SUFFIXES {
            if name[..end].ends_with(suffix) {
                end -= suffix.len();
                changed = true;
            }
        }
        if !changed {
            return end;
        }
    }
}

fn reboot_parameter_is_valid_bytes(parameter: &[u8]) -> bool {
    parameter.len() <= libc::NAME_MAX as usize && parameter.iter().all(u8::is_ascii)
}

/// Allocate an exact byte slice plus its NUL terminator using libc malloc.
fn malloc_c_bytes(bytes: &[u8]) -> Result<*mut c_char, Errno> {
    let allocation_size = bytes.len().checked_add(1).ok_or(Errno::ENOMEM)?;
    let allocation = malloc(allocation_size).cast::<u8>();
    if allocation.is_null() {
        return Err(Errno::ENOMEM);
    }
    // SAFETY: malloc returned allocation_size writable bytes. The source is a
    // live byte slice and the terminating byte is within that allocation.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), allocation, bytes.len());
        *allocation.add(bytes.len()) = 0;
    }
    Ok(allocation.cast::<c_char>())
}

fn malloc_changed_url(url: &[u8], prefix_end: usize, suffix: &[u8]) -> Result<*mut c_char, Errno> {
    let allocation_size = prefix_end
        .checked_add(1)
        .and_then(|size| size.checked_add(suffix.len()))
        .and_then(|size| size.checked_add(1))
        .ok_or(Errno::ENOMEM)?;
    let allocation = malloc(allocation_size).cast::<u8>();
    if allocation.is_null() {
        return Err(Errno::ENOMEM);
    }
    // SAFETY: each destination range is disjoint and contained in the freshly
    // allocated buffer. The source slices are live by the safe caller.
    unsafe {
        ptr::copy_nonoverlapping(url.as_ptr(), allocation, prefix_end);
        *allocation.add(prefix_end) = b'/';
        ptr::copy_nonoverlapping(
            suffix.as_ptr(),
            allocation.add(prefix_end + 1),
            suffix.len(),
        );
        *allocation.add(allocation_size - 1) = 0;
    }
    Ok(allocation.cast::<c_char>())
}

/// Extract the last URL component for Rust callers with valid UTF-8 input.
pub fn import_url_last_component(url: &str) -> Result<String, Errno> {
    let range = import_url_last_component_range(url.as_bytes())?;
    // A range of a UTF-8 input is not necessarily a character boundary only
    // for malformed separator logic; all separators are single-byte ASCII and
    // therefore this subslice remains valid UTF-8.
    Ok(url[range].to_owned())
}

/// Change a URL suffix for Rust callers with valid UTF-8 input.
pub fn import_url_change_suffix(
    url: &str,
    n_drop_components: usize,
    suffix: Option<&str>,
) -> Result<String, Errno> {
    let end = import_url_change_suffix_prefix_end(url.as_bytes(), n_drop_components)?;
    let mut result = String::with_capacity(end + 1 + suffix.map_or(0, str::len));
    result.push_str(&url[..end]);
    result.push('/');
    result.push_str(suffix.unwrap_or_default());
    Ok(result)
}

pub fn import_url_change_last_component(url: &str, suffix: &str) -> Result<String, Errno> {
    import_url_change_suffix(url, 1, Some(suffix))
}

pub fn import_url_append_component(url: &str, suffix: &str) -> Result<String, Errno> {
    import_url_change_suffix(url, 0, Some(suffix))
}

pub fn tar_strip_suffixes(name: &str) -> Result<String, Errno> {
    let end = tar_strip_suffixes_end(name.as_bytes())?;
    Ok(name[..end].to_owned())
}

pub fn raw_strip_suffixes(name: &str) -> Result<String, Errno> {
    Ok(name[..raw_strip_suffixes_end(name.as_bytes())].to_owned())
}

/// # Safety
///
/// `url` must be either NULL or a live NUL-terminated C string. If `ret` is
/// non-NULL it must be writable `char *` storage. On success with non-NULL
/// `ret`, the caller owns a fresh libc allocation and must free it with free(3).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_import_url_last_component(
    url: *const c_char,
    ret: *mut *mut c_char,
) -> c_int {
    if url.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: required by the entry point's C-string contract.
    let url = unsafe { CStr::from_ptr(url) }.to_bytes();
    let range = match import_url_last_component_range(url) {
        Ok(range) => range,
        Err(error) => return error.to_neg_errno(),
    };
    if !ret.is_null() {
        let output = match malloc_c_bytes(&url[range]) {
            Ok(output) => output,
            Err(error) => return error.to_neg_errno(),
        };
        // SAFETY: required by the entry point's optional output contract.
        unsafe { *ret = output };
    }
    0
}

/// # Safety
///
/// `url` and non-NULL `suffix` must be live NUL-terminated C strings, and
/// `ret` must be writable non-NULL `char *` storage. On success the caller owns
/// a fresh libc allocation and must free it with free(3).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_import_url_change_suffix(
    url: *const c_char,
    n_drop_components: usize,
    suffix: *const c_char,
    ret: *mut *mut c_char,
) -> c_int {
    if url.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: required by the entry point's C-string contracts.
    let url = unsafe { CStr::from_ptr(url) }.to_bytes();
    let suffix = if suffix.is_null() {
        &[][..]
    } else {
        // SAFETY: required by the entry point's C-string contract.
        unsafe { CStr::from_ptr(suffix) }.to_bytes()
    };
    let end = match import_url_change_suffix_prefix_end(url, n_drop_components) {
        Ok(end) => end,
        Err(error) => return error.to_neg_errno(),
    };
    let output = match malloc_changed_url(url, end, suffix) {
        Ok(output) => output,
        Err(error) => return error.to_neg_errno(),
    };
    // SAFETY: required by the entry point's output contract; failure paths do
    // not modify it, matching the C function.
    unsafe { *ret = output };
    0
}

/// # Safety
///
/// `name` must be a live NUL-terminated C string and `ret` must be writable
/// non-NULL `char *` storage. On success the caller owns a fresh libc
/// allocation and must free it with free(3).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_tar_strip_suffixes(
    name: *const c_char,
    ret: *mut *mut c_char,
) -> c_int {
    if name.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: required by the entry point's C-string contract.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    let end = match tar_strip_suffixes_end(name) {
        Ok(end) => end,
        Err(error) => return error.to_neg_errno(),
    };
    let output = match malloc_c_bytes(&name[..end]) {
        Ok(output) => output,
        Err(error) => return error.to_neg_errno(),
    };
    // SAFETY: required by the entry point's output contract.
    unsafe { *ret = output };
    0
}

/// # Safety
///
/// `name` must be a live NUL-terminated C string and `ret` must be writable
/// non-NULL `char *` storage. On success the caller owns a fresh libc
/// allocation (including for an empty result) and must free it with free(3).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_raw_strip_suffixes(
    name: *const c_char,
    ret: *mut *mut c_char,
) -> c_int {
    if name.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: required by the entry point's C-string contract.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    let output = match malloc_c_bytes(&name[..raw_strip_suffixes_end(name)]) {
        Ok(output) => output,
        Err(error) => return error.to_neg_errno(),
    };
    // SAFETY: required by the entry point's output contract.
    unsafe { *ret = output };
    0
}

/// # Safety
///
/// `parameter` must be a live NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_reboot_parameter_is_valid(parameter: *const c_char) -> bool {
    if parameter.is_null() {
        return false;
    }
    // SAFETY: required by the entry point's C-string contract.
    reboot_parameter_is_valid_bytes(unsafe { CStr::from_ptr(parameter) }.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_helpers_match_no_path_and_trailing_slash_c_cases() {
        assert_eq!(
            import_url_last_component("https://example.com"),
            Err(Errno::EADDRNOTAVAIL)
        );
        assert_eq!(
            import_url_last_component("https://example.com/path/"),
            Ok("path".to_string())
        );
        assert_eq!(
            import_url_change_suffix("https://example.com", 0, None),
            Ok("https://example.com/".to_string())
        );
    }

    #[test]
    fn suffix_helpers_preserve_current_c_empty_rules() {
        assert_eq!(tar_strip_suffixes(""), Err(Errno::EINVAL));
        assert_eq!(tar_strip_suffixes(".tar"), Err(Errno::EINVAL));
        assert_eq!(raw_strip_suffixes(""), Ok(String::new()));
        assert_eq!(raw_strip_suffixes(".raw"), Ok(String::new()));
        assert_eq!(raw_strip_suffixes("image.raw.xz"), Ok("image".to_string()));
    }

    #[test]
    fn byte_cores_do_not_require_utf8() {
        let url = b"x://host/\xff.raw";
        assert_eq!(import_url_last_component_range(url), Ok(9..14));
        assert_eq!(raw_strip_suffixes_end(b"\xff.raw"), 1);
        assert!(reboot_parameter_is_valid_bytes(b"\x7f"));
        assert!(!reboot_parameter_is_valid_bytes(b"\x80"));
    }
}
