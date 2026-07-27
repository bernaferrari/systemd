// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/user-util.c (valid_user_group_name, capsule_name_is_valid)
//
// User/group name validation and closely related pure helpers.

use std::ffi::CStr;

use libc::c_char;

use crate::ffi::Errno;

const LOGIN_NAME_MAX: usize = 256;
const NAME_MAX_VAL: usize = 255;
const UT_NAMESIZE: usize = 32;

const VALID_USER_RELAX: u32 = 1 << 0;
const VALID_USER_WARN: u32 = 1 << 1;
const VALID_USER_ALLOW_NUMERIC: u32 = 1 << 2;

#[inline]
fn uid_is_valid(uid: u32) -> bool {
    uid != u32::MAX && uid != 0xffff
}

/// Borrow a C string as UTF-8.
///
/// # Safety
/// `ptr` must be null or point to a readable NUL-terminated string that
/// remains live for the returned borrow.
unsafe fn c_text<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }

    // SAFETY: the pointer is expected to reference a valid NUL-terminated C string for this call.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

fn parse_uid_str(text: &str) -> Result<u32, Errno> {
    if text.is_empty() {
        return Err(Errno::EINVAL);
    }
    if text.starts_with('+') || text.starts_with('-') || text.starts_with(char::is_whitespace) {
        return Err(Errno::EINVAL);
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err(Errno::EINVAL);
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Errno::EINVAL);
    }

    let uid = text.parse::<u32>().map_err(|_| Errno::ERANGE)?;
    if !uid_is_valid(uid) {
        return Err(Errno::ENXIO);
    }
    Ok(uid)
}

fn is_utf8_and_has_no_cc(text: &str) -> bool {
    !text
        .as_bytes()
        .iter()
        .any(|byte| matches!(*byte, 1..=31 | 0x7f))
}

fn is_all_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

fn is_negative_numeric(text: &str) -> bool {
    text.starts_with('-') && is_all_digits(&text[1..])
}

fn filename_is_valid(text: &str) -> bool {
    !text.is_empty() && text != "." && text != ".." && !text.contains('/')
}

fn valid_user_group_name_str(text: &str, flags: u32) -> bool {
    if text.is_empty() {
        return false;
    }

    if parse_uid_str(text).is_ok() {
        return (flags & VALID_USER_ALLOW_NUMERIC) != 0;
    }

    if (flags & VALID_USER_RELAX) != 0 {
        if text.starts_with(' ') || text.ends_with(' ') {
            return false;
        }
        if !is_utf8_and_has_no_cc(text) {
            return false;
        }
        if text.contains(':') || text.contains('/') {
            return false;
        }
        if is_all_digits(text) || is_negative_numeric(text) {
            return false;
        }
        if matches!(text, "." | "..") {
            return false;
        }

        let _ = flags & VALID_USER_WARN;
        return true;
    }

    let bytes = text.as_bytes();
    if !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_') {
        return false;
    }
    if !bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return false;
    }

    text.len() <= LOGIN_NAME_MAX && text.len() <= NAME_MAX_VAL && text.len() < UT_NAMESIZE
}

fn capsule_name_is_valid_str(text: &str) -> i32 {
    if !filename_is_valid(text) {
        return 0;
    }

    // `c-` supplies the alphabetic prefix required by the strict user-name
    // rules. Validate the remaining bytes directly so this C-ABI-reachable
    // path stays allocation-free and cannot abort on OOM.
    let Some(length) = text.len().checked_add(2) else {
        return 0;
    };
    if length <= LOGIN_NAME_MAX
        && length <= NAME_MAX_VAL
        && length < UT_NAMESIZE
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        1
    } else {
        0
    }
}

fn parse_uid_range_str(text: &str) -> Result<(u32, u32), Errno> {
    match text.split_once('-') {
        None => {
            let uid = parse_uid_str(text)?;
            Ok((uid, uid))
        }
        Some((lower, upper)) => {
            if upper.is_empty() {
                return Err(Errno::EINVAL);
            }
            let lower = parse_uid_str(lower)?;
            let upper = parse_uid_str(upper)?;
            if lower > upper {
                return Err(Errno::EINVAL);
            }
            Ok((lower, upper))
        }
    }
}

fn id128_is_valid_str(text: &str) -> bool {
    match text.len() {
        32 => text.bytes().all(|b| b.is_ascii_hexdigit()),
        36 => text.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        }),
        _ => false,
    }
}

/// Validate a NUL-terminated C user/group name.
///
/// # Safety
/// `u` must be null or point to a readable NUL-terminated string.
#[export_name = "rs_valid_user_group_name"]
pub unsafe extern "C" fn rs_valid_user_group_name(u: *const c_char, flags: u32) -> bool {
    // SAFETY: required by this C ABI entry point's contract.
    unsafe { c_text(u) }
        .map(|text| valid_user_group_name_str(text, flags))
        .unwrap_or(false)
}

/// Validate a NUL-terminated C capsule name.
///
/// # Safety
/// `name` must be null or point to a readable NUL-terminated string.
#[export_name = "rs_capsule_name_is_valid"]
pub unsafe extern "C" fn rs_capsule_name_is_valid(name: *const c_char) -> i32 {
    // SAFETY: required by this C ABI entry point's contract.
    unsafe { c_text(name) }
        .map(capsule_name_is_valid_str)
        .unwrap_or(0)
}

#[export_name = "rs_uid_is_valid"]
pub extern "C" fn rs_uid_is_valid(uid: u32) -> bool {
    uid_is_valid(uid)
}

/// Parse a NUL-terminated C UID string.
///
/// # Safety
/// `s` must be null or point to a readable NUL-terminated string. If non-null,
/// `ret` must point to writable, properly aligned `uid_t` storage.
#[export_name = "rs_parse_uid"]
pub unsafe extern "C" fn rs_parse_uid(s: *const c_char, ret: *mut u32) -> i32 {
    // SAFETY: required by this C ABI entry point's contract.
    let Some(text) = (unsafe { c_text(s) }) else {
        return Errno::EINVAL.to_neg_errno();
    };

    match parse_uid_str(text) {
        Ok(uid) => {
            if !ret.is_null() {
                // SAFETY: required by this C ABI entry point's contract.
                unsafe { ret.write(uid) };
            }
            0
        }
        Err(errno) => errno.to_neg_errno(),
    }
}

/// Parse a NUL-terminated C UID range.
///
/// # Safety
/// `s` must point to a readable NUL-terminated string. Both output pointers
/// must point to writable, properly aligned `uid_t` storage.
#[export_name = "rs_parse_uid_range"]
pub unsafe extern "C" fn rs_parse_uid_range(
    s: *const c_char,
    ret_lower: *mut u32,
    ret_upper: *mut u32,
) -> i32 {
    if s.is_null() || ret_lower.is_null() || ret_upper.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: required by this C ABI entry point's contract.
    let Some(text) = (unsafe { c_text(s) }) else {
        return Errno::EINVAL.to_neg_errno();
    };

    match parse_uid_range_str(text) {
        Ok((lower, upper)) => {
            // SAFETY: required by this C ABI entry point's contract. Raw
            // writes preserve C's behavior even if the outputs alias.
            unsafe {
                ret_lower.write(lower);
                ret_upper.write(upper);
            }
            0
        }
        Err(errno) => errno.to_neg_errno(),
    }
}

/// Validate a NUL-terminated C ID128 string.
///
/// # Safety
/// `s` must be null or point to a readable NUL-terminated string.
#[export_name = "rs_id128_is_valid"]
pub unsafe extern "C" fn rs_id128_is_valid(s: *const c_char) -> bool {
    // SAFETY: required by this C ABI entry point's contract.
    unsafe { c_text(s) }
        .map(id128_is_valid_str)
        .unwrap_or(false)
}

/// Check the first byte of a C password hash.
///
/// # Safety
/// `password` must be null or point to at least one readable byte.
#[export_name = "rs_hashed_password_is_locked_or_invalid"]
pub unsafe extern "C" fn rs_hashed_password_is_locked_or_invalid(password: *const c_char) -> bool {
    // SAFETY: required by this C ABI entry point's contract.
    !password.is_null() && unsafe { *password != b'$' as c_char }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn strict_user_names_match_c_rules() {
        for name in ["root", "_systemd", "my-user", "user123"] {
            assert!(valid_user_group_name_str(name, 0));
        }
    }

    #[test]
    fn strict_user_names_reject_invalid_forms() {
        for name in ["", "0user", "-user", "user.name", "user:name", "user name"] {
            assert!(!valid_user_group_name_str(name, 0));
        }
    }

    #[test]
    fn numeric_user_names_require_flag() {
        assert!(!valid_user_group_name_str("12345", 0));
        assert!(valid_user_group_name_str("12345", VALID_USER_ALLOW_NUMERIC));
        assert!(valid_user_group_name_str("0", VALID_USER_ALLOW_NUMERIC));
    }

    #[test]
    fn relaxed_mode_allows_broader_names_but_blocks_dangerous_ones() {
        let flags = VALID_USER_RELAX;
        for name in ["user.name", "User Name", "user@domain"] {
            assert!(valid_user_group_name_str(name, flags));
        }
        for name in [
            " user",
            "user ",
            "user\nname",
            "user:name",
            "user/name",
            "12345",
            "-1",
            ".",
            "..",
            "   ",
        ] {
            assert!(!valid_user_group_name_str(name, flags));
        }
    }

    #[test]
    fn capsule_names_match_prefix_validation_rule() {
        assert_eq!(capsule_name_is_valid_str("mycapsule"), 1);
        assert_eq!(capsule_name_is_valid_str("my-capsule"), 1);
        assert_eq!(capsule_name_is_valid_str("1bad"), 1);
        assert_eq!(capsule_name_is_valid_str("-bad"), 1);
        assert_eq!(capsule_name_is_valid_str(":bad"), 0);
        assert_eq!(capsule_name_is_valid_str(""), 0);
        assert_eq!(capsule_name_is_valid_str("a/b"), 0);
        assert_eq!(capsule_name_is_valid_str("."), 0);
    }

    #[test]
    fn uid_validation_matches_c_special_cases() {
        assert!(rs_uid_is_valid(0));
        assert!(rs_uid_is_valid(65_534));
        assert!(!rs_uid_is_valid(65_535));
        assert!(!rs_uid_is_valid(u32::MAX));
    }

    #[test]
    fn parse_uid_matches_expected_errors() {
        assert_eq!(parse_uid_str("0"), Ok(0));
        assert_eq!(parse_uid_str("1000"), Ok(1000));
        assert_eq!(parse_uid_str("01"), Err(Errno::EINVAL));
        assert_eq!(parse_uid_str(" 1"), Err(Errno::EINVAL));
        assert_eq!(parse_uid_str("+1"), Err(Errno::EINVAL));
        assert_eq!(parse_uid_str("-1"), Err(Errno::EINVAL));
        assert_eq!(parse_uid_str("65535"), Err(Errno::ENXIO));
        assert_eq!(parse_uid_str("4294967295"), Err(Errno::ENXIO));
    }

    #[test]
    fn parse_uid_range_handles_single_and_range_forms() {
        assert_eq!(parse_uid_range_str("1000"), Ok((1000, 1000)));
        assert_eq!(parse_uid_range_str("1000-2000"), Ok((1000, 2000)));
        assert_eq!(parse_uid_range_str("2000-1000"), Err(Errno::EINVAL));
        assert_eq!(parse_uid_range_str("1000-"), Err(Errno::EINVAL));
    }

    #[test]
    fn id128_validation_matches_plain_and_uuid_forms() {
        assert!(id128_is_valid_str("c5a4166e3f224932a4987f3a63a18b02"));
        assert!(id128_is_valid_str("c5a4166e-3f22-4932-a498-7f3a63a18b02"));
        assert!(!id128_is_valid_str("abcdef"));
        assert!(!id128_is_valid_str("c5a4166e3f22-4932-a498-7f3a63a18b02"));
    }

    #[test]
    fn exported_pointer_apis_behave_as_expected() {
        let input = CString::new("1000").unwrap();
        let mut uid = 0;
        // SAFETY: the raw pointer is derived from a live allocation and is used only for the duration of this operation.
        unsafe {
            assert_eq!(rs_parse_uid(input.as_ptr(), &mut uid), 0);
            assert_eq!(uid, 1000);
            assert!(rs_valid_user_group_name(
                CString::new("root").unwrap().as_ptr(),
                0
            ));
            assert_eq!(
                rs_capsule_name_is_valid(CString::new("mycapsule").unwrap().as_ptr()),
                1
            );
            assert!(rs_id128_is_valid(
                CString::new("00000000000000000000000000000000")
                    .unwrap()
                    .as_ptr()
            ));
        }
    }
}
