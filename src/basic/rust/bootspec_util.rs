// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.bootspec-util; authority=src/shared/bootspec.c,src/shared/bootspec.h,src/fundamental/bootspec.c,src/fundamental/bootspec.h
//
// Boot specification utilities: filename try-count extraction and
// os-release field selection for boot entry metadata.

use std::ffi::{CStr, c_char};
use std::ptr;

// ── Constants ─────────────────────────────────────────────────────────────

/// Sentinel for "no tries parsed" (mirrors C's `UINT_MAX`).
pub const TRIES_UNSET: u32 = u32::MAX;

/// Maximum allowed try count (mirrors C's `INT_MAX` limit from `safe_atou_full`).
pub const TRIES_MAX: u64 = i32::MAX as u64;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors from boot filename parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootFilenameError {
    /// The try counter exceeds `INT_MAX`.
    OutOfRange,
    /// A required pointer argument was null (C FFI guard; unused in pure Rust).
    InvalidArgument,
    /// Memory allocation failure.
    NoMemory,
}

impl std::fmt::Display for BootFilenameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootFilenameError::OutOfRange => write!(f, "try counter out of range"),
            BootFilenameError::InvalidArgument => write!(f, "invalid argument"),
            BootFilenameError::NoMemory => write!(f, "memory allocation failure"),
        }
    }
}

impl std::error::Error for BootFilenameError {}

// ── Result of boot_filename_extract_tries ─────────────────────────────────

/// Parsed result from `boot_filename_extract_tries`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootFilenameTries {
    /// The filename with the `+N-M` try section stripped.
    pub stripped: String,
    /// Number of remaining boot attempts, or `TRIES_UNSET` if none parsed.
    pub tries_left: u32,
    /// Number of completed boot attempts, or `TRIES_UNSET` if none parsed.
    pub tries_done: u32,
}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Parse an unsigned integer from the start of `s`.
///
/// Returns:
/// - `Ok((parsed_value, digit_count))` if digits were found and in range
/// - `Ok((TRIES_UNSET, 0))` if no leading digits
/// - `Err(OutOfRange)` if the number exceeds `INT_MAX`
///
/// Mirrors C `parse_tries()` from bootspec.c:
/// ```c
/// n = strspn(*p, DIGITS);
/// if (n == 0) { *ret = UINT_MAX; return 0; }
/// d = strndup(*p, n);
/// r = safe_atou_full(d, 10, &tries);
/// if (r >= 0 && tries > INT_MAX) r = -ERANGE;
/// ```
fn parse_tries(s: &str) -> Result<(u32, usize), BootFilenameError> {
    let n = s.chars().take_while(|c| c.is_ascii_digit()).count();
    if n == 0 {
        return Ok((TRIES_UNSET, 0));
    }

    let digit_str = &s[..n];
    let tries: u64 = digit_str
        .parse()
        .map_err(|_| BootFilenameError::OutOfRange)?;

    if tries > TRIES_MAX {
        return Err(BootFilenameError::OutOfRange);
    }

    Ok((tries as u32, n))
}

// ── Public API ────────────────────────────────────────────────────────────

/// Extract boot try counters from a filename.
///
/// For a filename like `"entry+3-2.conf"`, returns:
/// - `stripped`: `"entry.conf"`
/// - `tries_left`: `3`
/// - `tries_done`: `2`
///
/// If the filename does not contain a `+N` or `+N-M` pattern before the
/// suffix, returns the original filename unchanged with both try counts
/// set to `TRIES_UNSET`.
///
/// Mirrors C `boot_filename_extract_tries()` from bootspec.c.
pub fn boot_filename_extract_tries(fname: &str) -> Result<BootFilenameTries, BootFilenameError> {
    // Find last '.' (suffix)
    let suffix_idx = match fname.rfind('.') {
        Some(i) => i,
        None => return fallback(fname),
    };

    // Find last '+' before the suffix
    let before_suffix = &fname[..suffix_idx];
    let plus_idx = match before_suffix.rfind('+') {
        Some(i) => i,
        None => return fallback(fname),
    };

    let mut p = &fname[plus_idx + 1..];

    let (tries_left, consumed) = parse_tries(p)?;
    if consumed == 0 {
        return fallback(fname);
    }
    p = &p[consumed..];

    let mut tries_done = TRIES_UNSET;
    if p.starts_with('-') {
        p = &p[1..];
        let (done, consumed2) = parse_tries(p)?;
        if consumed2 == 0 {
            return fallback(fname);
        }
        tries_done = done;
        p = &p[consumed2..];
    }

    // p must now point exactly to the suffix
    let expected_suffix_start = plus_idx + 1 + (fname[plus_idx + 1..].len() - p.len());
    if expected_suffix_start != suffix_idx {
        return fallback(fname);
    }

    // Build stripped: fname[0..plus_idx] + fname[suffix_idx..]
    let stripped = format!("{}{}", &fname[..plus_idx], &fname[suffix_idx..]);

    Ok(BootFilenameTries {
        stripped,
        tries_left,
        tries_done,
    })
}

/// "nothing" fallback: return fname as-is with `TRIES_UNSET` for both counters.
fn fallback(fname: &str) -> Result<BootFilenameTries, BootFilenameError> {
    Ok(BootFilenameTries {
        stripped: fname.to_string(),
        tries_left: TRIES_UNSET,
        tries_done: TRIES_UNSET,
    })
}

// ── Boot entry name/version/sort-key selection ────────────────────────────

/// Select the best human-readable title, version string, and sort key
/// for a boot entry from os-release fields.
///
/// Priority (from C `bootspec_pick_name_version_sort_key()` in
/// bootspec.c):
/// - **name**: PRETTY_NAME > IMAGE_ID > NAME > ID
/// - **version**: IMAGE_VERSION > VERSION > VERSION_ID > BUILD_ID
/// - **sort_key**: IMAGE_ID > ID
///
/// Returns `Ok((name, version, sort_key))` if at least a name could be
/// resolved; returns `Err(())` if all name fields are `None`.
pub fn bootspec_pick_name_version_sort_key<'a>(
    os_pretty_name: Option<&'a str>,
    os_image_id: Option<&'a str>,
    os_name: Option<&'a str>,
    os_id: Option<&'a str>,
    os_image_version: Option<&'a str>,
    os_version: Option<&'a str>,
    os_version_id: Option<&'a str>,
    os_build_id: Option<&'a str>,
) -> Result<(Option<&'a str>, Option<&'a str>, Option<&'a str>), ()> {
    let good_name = os_pretty_name.or(os_image_id).or(os_name).or(os_id);

    let good_version = os_image_version
        .or(os_version)
        .or(os_version_id)
        .or(os_build_id);

    let good_sort_key = os_image_id.or(os_id);

    if good_name.is_none() {
        return Err(());
    }

    Ok((good_name, good_version, good_sort_key))
}

// ── C ABI facades ─────────────────────────────────────────────────────────

/// Parse the consecutive ASCII decimal digits at the start of `bytes`.
///
/// This is the allocation-free equivalent of the small `strndup()` plus
/// `safe_atou_full()` sequence in C's private `parse_tries()` helper.  The
/// caller receives the number of consumed bytes, not Unicode scalar values:
/// the C authority accepts opaque C-string bytes.
fn parse_tries_bytes(bytes: &[u8]) -> Result<(u32, usize), BootFilenameError> {
    let digits = bytes
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits == 0 {
        return Ok((TRIES_UNSET, 0));
    }

    let mut value = 0_u64;
    for &byte in &bytes[..digits] {
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or(BootFilenameError::OutOfRange)?;
        if value > TRIES_MAX {
            return Err(BootFilenameError::OutOfRange);
        }
    }

    Ok((value as u32, digits))
}

/// Publish C's `nothing:` fallback result.
///
/// # Safety
///
/// `fname` must be a live NUL-terminated C string and `ret_stripped` must be
/// writable. Optional counter outputs must be writable when non-NULL.
unsafe fn publish_no_tries(
    fname: *const c_char,
    ret_stripped: *mut *mut c_char,
    ret_tries_left: *mut u32,
    ret_tries_done: *mut u32,
) -> i32 {
    // SAFETY: required by this helper's documented C-string contract.
    let output = unsafe { libc::strdup(fname) };
    if output.is_null() {
        return -libc::ENOMEM;
    }
    // SAFETY: required writable output and any non-NULL optional outputs are
    // part of this helper's contract. Preserve C's publication order.
    unsafe {
        *ret_stripped = output;
        if !ret_tries_left.is_null() {
            *ret_tries_left = TRIES_UNSET;
        }
        if !ret_tries_done.is_null() {
            *ret_tries_done = TRIES_UNSET;
        }
    }
    0
}

/// C ABI for `boot_filename_extract_tries()`.
///
/// This stays byte-oriented rather than passing through Rust `str`, because
/// the C API accepts arbitrary non-NUL filename bytes. Successful outputs use
/// the C allocator, so callers free `*ret_stripped` with `free(3)`.
///
/// # Safety
///
/// `fname` must be a live NUL-terminated C string. `ret_stripped` must point
/// to writable pointer storage. Optional counter outputs, when non-NULL, must
/// likewise be writable. The C authority asserts the first two requirements;
/// this boundary returns `-EINVAL` for a null required pointer instead.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_boot_filename_extract_tries(
    fname: *const c_char,
    ret_stripped: *mut *mut c_char,
    ret_tries_left: *mut u32,
    ret_tries_done: *mut u32,
) -> i32 {
    if fname.is_null() || ret_stripped.is_null() {
        return -libc::EINVAL;
    }

    // SAFETY: required by this entry point's documented C-string contract.
    let filename = unsafe { CStr::from_ptr(fname) }.to_bytes();

    let Some(suffix) = filename.iter().rposition(|&byte| byte == b'.') else {
        // SAFETY: all helper preconditions were validated by this boundary.
        return unsafe { publish_no_tries(fname, ret_stripped, ret_tries_left, ret_tries_done) };
    };

    let Some(marker) = filename[..suffix].iter().rposition(|&byte| byte == b'+') else {
        // SAFETY: all helper preconditions were validated by this boundary.
        return unsafe { publish_no_tries(fname, ret_stripped, ret_tries_left, ret_tries_done) };
    };

    let mut position = marker + 1;
    let (tries_left, consumed) = match parse_tries_bytes(&filename[position..]) {
        Ok(parsed) => parsed,
        Err(BootFilenameError::OutOfRange) => return -libc::ERANGE,
        Err(_) => return -libc::ENOMEM,
    };
    if consumed == 0 {
        // SAFETY: all helper preconditions were validated by this boundary.
        return unsafe { publish_no_tries(fname, ret_stripped, ret_tries_left, ret_tries_done) };
    }
    position += consumed;

    let mut tries_done = TRIES_UNSET;
    if filename.get(position) == Some(&b'-') {
        position += 1;
        let (parsed, consumed) = match parse_tries_bytes(&filename[position..]) {
            Ok(parsed) => parsed,
            Err(BootFilenameError::OutOfRange) => return -libc::ERANGE,
            Err(_) => return -libc::ENOMEM,
        };
        if consumed == 0 {
            // SAFETY: all helper preconditions were validated by this boundary.
            return unsafe {
                publish_no_tries(fname, ret_stripped, ret_tries_left, ret_tries_done)
            };
        }
        tries_done = parsed;
        position += consumed;
    }

    if position != suffix {
        // SAFETY: all helper preconditions were validated by this boundary.
        return unsafe { publish_no_tries(fname, ret_stripped, ret_tries_left, ret_tries_done) };
    }

    let Some(output_length) = marker.checked_add(filename.len() - suffix) else {
        return -libc::ENOMEM;
    };
    let Some(allocation_size) = output_length.checked_add(1) else {
        return -libc::ENOMEM;
    };
    // SAFETY: the checked allocation has room for the two non-overlapping
    // source ranges plus a NUL and uses the C allocator expected by callers.
    let output = unsafe {
        let output = libc::malloc(allocation_size).cast::<c_char>();
        if !output.is_null() {
            ptr::copy_nonoverlapping(filename.as_ptr().cast::<c_char>(), output, marker);
            ptr::copy_nonoverlapping(
                filename[suffix..].as_ptr().cast::<c_char>(),
                output.add(marker),
                filename.len() - suffix,
            );
            *output.add(output_length) = 0;
        }
        output
    };
    if output.is_null() {
        return -libc::ENOMEM;
    }

    // SAFETY: all documented writable outputs are updated only after the
    // allocation succeeds, as the C authority does. Preserve C's write order.
    unsafe {
        *ret_stripped = output;
        if !ret_tries_left.is_null() {
            *ret_tries_left = tries_left;
        }
        if !ret_tries_done.is_null() {
            *ret_tries_done = tries_done;
        }
    }
    0
}

/// C ABI for `bootspec_pick_name_version_sort_key()`.
///
/// The authority only selects among borrowed input pointers; it performs no
/// string reads or allocations. This preserves opaque-byte behavior and the
/// input lifetime/ownership relationship exactly.
///
/// # Safety
///
/// Any non-NULL output pointer must be writable for the call. Selected input
/// strings must outlive every use of an output pointer that aliases them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_bootspec_pick_name_version_sort_key(
    os_pretty_name: *const c_char,
    os_image_id: *const c_char,
    os_name: *const c_char,
    os_id: *const c_char,
    os_image_version: *const c_char,
    os_version: *const c_char,
    os_version_id: *const c_char,
    os_build_id: *const c_char,
    ret_name: *mut *const c_char,
    ret_version: *mut *const c_char,
    ret_sort_key: *mut *const c_char,
) -> bool {
    let good_name = if !os_pretty_name.is_null() {
        os_pretty_name
    } else if !os_image_id.is_null() {
        os_image_id
    } else if !os_name.is_null() {
        os_name
    } else {
        os_id
    };
    if good_name.is_null() {
        return false;
    }
    let good_version = if !os_image_version.is_null() {
        os_image_version
    } else if !os_version.is_null() {
        os_version
    } else if !os_version_id.is_null() {
        os_version_id
    } else {
        os_build_id
    };
    let good_sort_key = if !os_image_id.is_null() {
        os_image_id
    } else {
        os_id
    };

    // SAFETY: every non-NULL output is writable by this entry point's
    // contract. Keep C's name/version/sort-key publication order.
    unsafe {
        if !ret_name.is_null() {
            *ret_name = good_name;
        }
        if !ret_version.is_null() {
            *ret_version = good_version;
        }
        if !ret_sort_key.is_null() {
            *ret_sort_key = good_sort_key;
        }
    }
    true
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_tries -----------------------------------------------------------

    #[test]
    fn test_parse_tries_valid() {
        assert_eq!(parse_tries("123abc"), Ok((123, 3)));
        assert_eq!(parse_tries("0abc"), Ok((0, 1)));
        assert_eq!(parse_tries("42"), Ok((42, 2)));
    }

    #[test]
    fn test_parse_tries_no_digits() {
        assert_eq!(parse_tries("abc"), Ok((TRIES_UNSET, 0)));
        assert_eq!(parse_tries(""), Ok((TRIES_UNSET, 0)));
        assert_eq!(parse_tries("-1"), Ok((TRIES_UNSET, 0)));
    }

    #[test]
    fn test_parse_tries_overflow() {
        let big = format!("{}abc", u64::MAX);
        assert!(parse_tries(&big).is_err());
    }

    #[test]
    fn test_parse_tries_at_int_max() {
        let s = format!("{}abc", i32::MAX);
        assert_eq!(parse_tries(&s), Ok((i32::MAX as u32, s.len() - 3)));
    }

    #[test]
    fn test_parse_tries_over_int_max() {
        let val = (i32::MAX as u64) + 1;
        let s = format!("{}abc", val);
        assert!(parse_tries(&s).is_err());
    }

    // -- boot_filename_extract_tries -------------------------------------------

    #[test]
    fn test_extract_tries_basic() {
        let r = boot_filename_extract_tries("entry+3-2.conf").unwrap();
        assert_eq!(r.stripped, "entry.conf");
        assert_eq!(r.tries_left, 3);
        assert_eq!(r.tries_done, 2);
    }

    #[test]
    fn test_extract_tries_left_only() {
        let r = boot_filename_extract_tries("entry+5.conf").unwrap();
        assert_eq!(r.stripped, "entry.conf");
        assert_eq!(r.tries_left, 5);
        assert_eq!(r.tries_done, TRIES_UNSET);
    }

    #[test]
    fn test_extract_tries_no_plus() {
        let r = boot_filename_extract_tries("entry.conf").unwrap();
        assert_eq!(r.stripped, "entry.conf");
        assert_eq!(r.tries_left, TRIES_UNSET);
        assert_eq!(r.tries_done, TRIES_UNSET);
    }

    #[test]
    fn test_extract_tries_no_suffix() {
        let r = boot_filename_extract_tries("entry+3-2").unwrap();
        assert_eq!(r.stripped, "entry+3-2");
        assert_eq!(r.tries_left, TRIES_UNSET);
        assert_eq!(r.tries_done, TRIES_UNSET);
    }

    #[test]
    fn test_extract_tries_zero_tries() {
        let r = boot_filename_extract_tries("entry+0-0.conf").unwrap();
        assert_eq!(r.stripped, "entry.conf");
        assert_eq!(r.tries_left, 0);
        assert_eq!(r.tries_done, 0);
    }

    #[test]
    fn test_extract_tries_large_number() {
        let fname = format!("entry+{}.conf", i32::MAX);
        let r = boot_filename_extract_tries(&fname).unwrap();
        assert_eq!(r.stripped, "entry.conf");
        assert_eq!(r.tries_left, i32::MAX as u32);
    }

    #[test]
    fn test_extract_tries_efi_suffix() {
        let r = boot_filename_extract_tries("linux+1-0.efi").unwrap();
        assert_eq!(r.stripped, "linux.efi");
        assert_eq!(r.tries_left, 1);
        assert_eq!(r.tries_done, 0);
    }

    // -- bootspec_pick_name_version_sort_key -----------------------------------

    #[test]
    fn test_pick_all_fields_set() {
        let (name, version, sort_key) = bootspec_pick_name_version_sort_key(
            Some("Pretty Name"),
            Some("image-id"),
            Some("OS Name"),
            Some("os-id"),
            Some("1.0"),
            Some("2.0"),
            Some("2.0-id"),
            Some("build-123"),
        )
        .unwrap();
        assert_eq!(name, Some("Pretty Name"));
        assert_eq!(version, Some("1.0"));
        assert_eq!(sort_key, Some("image-id"));
    }

    #[test]
    fn test_pick_fallback_name_to_image_id() {
        let (name, version, sort_key) = bootspec_pick_name_version_sort_key(
            None,
            Some("image-id"),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(name, Some("image-id"));
        assert!(version.is_none());
        assert_eq!(sort_key, Some("image-id"));
    }

    #[test]
    fn test_pick_fallback_chain() {
        let (name, version, sort_key) = bootspec_pick_name_version_sort_key(
            None,
            None,
            Some("OS Name"),
            Some("os-id"),
            None,
            Some("2.0"),
            None,
            None,
        )
        .unwrap();
        assert_eq!(name, Some("OS Name"));
        assert_eq!(version, Some("2.0"));
        assert_eq!(sort_key, Some("os-id"));
    }

    #[test]
    fn test_pick_all_null() {
        assert!(
            bootspec_pick_name_version_sort_key(None, None, None, None, None, None, None, None)
                .is_err()
        );
    }

    #[test]
    fn test_pick_version_fallback_to_build_id() {
        let (name, version, _) = bootspec_pick_name_version_sort_key(
            Some("Test"),
            None,
            None,
            Some("test-id"),
            None,
            None,
            None,
            Some("build-456"),
        )
        .unwrap();
        assert_eq!(name, Some("Test"));
        assert_eq!(version, Some("build-456"));
    }
}
