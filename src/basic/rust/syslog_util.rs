// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.syslog-util; authority=src/basic/syslog-util.c,src/basic/syslog-util.h

use crate::ffi::Errno;
use std::ffi::CStr;
use std::os::raw::c_char;

const LOG_FACMASK: i32 = 0x03f8;
const LOG_FAC_MAX: i32 = 127;
const LOG_DEBUG: i32 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFacility {
    Kern,
    User,
    Mail,
    Daemon,
    Auth,
    Syslog,
    Lpr,
    News,
    Uucp,
    Cron,
    Authpriv,
    Ftp,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
}

impl LogFacility {
    pub const fn unshifted_value(self) -> i32 {
        match self {
            Self::Kern => 0,
            Self::User => 1,
            Self::Mail => 2,
            Self::Daemon => 3,
            Self::Auth => 4,
            Self::Syslog => 5,
            Self::Lpr => 6,
            Self::News => 7,
            Self::Uucp => 8,
            Self::Cron => 9,
            Self::Authpriv => 10,
            Self::Ftp => 11,
            Self::Local0 => 16,
            Self::Local1 => 17,
            Self::Local2 => 18,
            Self::Local3 => 19,
            Self::Local4 => 20,
            Self::Local5 => 21,
            Self::Local6 => 22,
            Self::Local7 => 23,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Emerg,
    Alert,
    Crit,
    Err,
    Warning,
    Notice,
    Info,
    Debug,
}

impl LogLevel {
    pub const fn value(self) -> i32 {
        match self {
            Self::Emerg => 0,
            Self::Alert => 1,
            Self::Crit => 2,
            Self::Err => 3,
            Self::Warning => 4,
            Self::Notice => 5,
            Self::Info => 6,
            Self::Debug => 7,
        }
    }
}

const LOG_FACILITY_TABLE: &[(i32, &'static str)] = &[
    (LogFacility::Kern.unshifted_value(), "kern"),
    (LogFacility::User.unshifted_value(), "user"),
    (LogFacility::Mail.unshifted_value(), "mail"),
    (LogFacility::Daemon.unshifted_value(), "daemon"),
    (LogFacility::Auth.unshifted_value(), "auth"),
    (LogFacility::Syslog.unshifted_value(), "syslog"),
    (LogFacility::Lpr.unshifted_value(), "lpr"),
    (LogFacility::News.unshifted_value(), "news"),
    (LogFacility::Uucp.unshifted_value(), "uucp"),
    (LogFacility::Cron.unshifted_value(), "cron"),
    (LogFacility::Authpriv.unshifted_value(), "authpriv"),
    (LogFacility::Ftp.unshifted_value(), "ftp"),
    (LogFacility::Local0.unshifted_value(), "local0"),
    (LogFacility::Local1.unshifted_value(), "local1"),
    (LogFacility::Local2.unshifted_value(), "local2"),
    (LogFacility::Local3.unshifted_value(), "local3"),
    (LogFacility::Local4.unshifted_value(), "local4"),
    (LogFacility::Local5.unshifted_value(), "local5"),
    (LogFacility::Local6.unshifted_value(), "local6"),
    (LogFacility::Local7.unshifted_value(), "local7"),
];

const LOG_LEVEL_TABLE: &[(i32, &'static str)] = &[
    (LogLevel::Emerg.value(), "emerg"),
    (LogLevel::Alert.value(), "alert"),
    (LogLevel::Crit.value(), "crit"),
    (LogLevel::Err.value(), "err"),
    (LogLevel::Warning.value(), "warning"),
    (LogLevel::Notice.value(), "notice"),
    (LogLevel::Info.value(), "info"),
    (LogLevel::Debug.value(), "debug"),
];

fn lookup_name(table: &[(i32, &'static str)], value: i32) -> Option<&'static str> {
    table
        .iter()
        .find_map(move |(candidate, name)| (*candidate == value).then_some(*name))
}

fn lookup_value_with_fallback(
    table: &[(i32, &'static str)],
    name: &str,
    fallback_max: i32,
) -> Result<i32, Errno> {
    if let Some(value) = table
        .iter()
        .find_map(|(value, candidate)| (*candidate == name).then_some(*value))
    {
        return Ok(value);
    }

    let Some(parsed) = parse_safe_atou(name.as_bytes()) else {
        return Err(Errno::EINVAL);
    };
    if parsed > fallback_max as u32 {
        return Err(Errno::EINVAL);
    }

    Ok(parsed as i32)
}

/// Parse exactly the `safe_atou(..., base=0)` grammar used by C's string-table
/// fallback, without crossing the C boundary.
fn parse_safe_atou(bytes: &[u8]) -> Option<u32> {
    let mut start = 0;
    while matches!(
        bytes.get(start),
        Some(b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c')
    ) {
        start += 1;
    }
    if start == bytes.len() {
        return None;
    }

    /* parse-util's base mangling happens before strtoul() consumes a sign, so
     * `0b` and `0o` remain deliberately unsigned-prefix-only. */
    let (index, base) = if bytes[start..].starts_with(b"0b") || bytes[start..].starts_with(b"0B") {
        (start + 2, 2)
    } else if bytes[start..].starts_with(b"0o") || bytes[start..].starts_with(b"0O") {
        (start + 2, 8)
    } else {
        let mut index = start;
        let negative = matches!(bytes.get(index), Some(b'-'));
        if matches!(bytes.get(index), Some(b'+' | b'-')) {
            index += 1;
        }
        let (index, base) =
            if bytes[index..].starts_with(b"0x") || bytes[index..].starts_with(b"0X") {
                (index + 2, 16)
            } else if bytes.get(index) == Some(&b'0') {
                (index, 8)
            } else {
                (index, 10)
            };
        return parse_digits(bytes, index, base, negative);
    };

    parse_digits(bytes, index, base, false)
}

fn parse_digits(bytes: &[u8], mut index: usize, base: u8, negative: bool) -> Option<u32> {
    let first_digit = index;
    let mut value = 0_u32;
    while let Some(byte) = bytes.get(index) {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        if digit >= base {
            return None;
        }
        value = value.checked_mul(base as u32)?.checked_add(digit as u32)?;
        index += 1;
    }
    (index != first_digit && (!negative || value == 0)).then_some(value)
}

pub const fn log_facility_unshifted_is_valid(facility: i32) -> bool {
    facility >= 0 && facility <= LOG_FAC_MAX
}

pub fn log_facility_unshifted_to_string(value: i32) -> Result<String, Errno> {
    if !log_facility_unshifted_is_valid(value) {
        return Err(Errno::ERANGE);
    }

    Ok(lookup_name(LOG_FACILITY_TABLE, value)
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string()))
}

pub fn log_facility_unshifted_from_string(name: &str) -> Result<i32, Errno> {
    lookup_value_with_fallback(LOG_FACILITY_TABLE, name, LOG_FAC_MAX)
}

pub const fn log_level_is_valid(level: i32) -> bool {
    level >= 0 && level <= LOG_DEBUG
}

pub fn log_level_to_string(value: i32) -> Result<String, Errno> {
    if !log_level_is_valid(value) {
        return Err(Errno::ERANGE);
    }

    Ok(lookup_name(LOG_LEVEL_TABLE, value)
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string()))
}

pub fn log_level_from_string(name: &str) -> Result<i32, Errno> {
    lookup_value_with_fallback(LOG_LEVEL_TABLE, name, LOG_DEBUG)
}

pub fn syslog_parse_priority(
    input: &str,
    priority: i32,
    with_facility: bool,
) -> Option<(&str, i32)> {
    if !input.starts_with('<') {
        return None;
    }

    let end = input.find('>')?;
    let digits = &input[1..end];
    if !(1..=3).contains(&digits.len()) || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let mut a = 0;
    let mut b = 0;
    let c;

    match digits.as_bytes() {
        [c0] => {
            c = (c0 - b'0') as i32;
        }
        [b0, c0] => {
            b = (b0 - b'0') as i32;
            c = (c0 - b'0') as i32;
        }
        [a0, b0, c0] => {
            a = (a0 - b'0') as i32;
            b = (b0 - b'0') as i32;
            c = (c0 - b'0') as i32;
        }
        _ => return None,
    }

    if !with_facility && (a != 0 || b != 0 || c > LOG_DEBUG) {
        return None;
    }

    let parsed = if with_facility {
        a * 100 + b * 10 + c
    } else {
        (priority & LOG_FACMASK) | c
    };

    Some((&input[end + 1..], parsed))
}

/// Copy bytes into a C-owned NUL-terminated allocation.
///
/// # Safety
/// `ret` must point to writable storage for one `char *`.
unsafe fn copy_to_c_allocator(bytes: &[u8], ret: *mut *mut c_char) -> i32 {
    let Some(allocation_size) = bytes.len().checked_add(1) else {
        return Errno::ENOMEM.to_neg_errno();
    };

    let allocation = crate::ffi::malloc(allocation_size).cast::<c_char>();
    if allocation.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }

    // SAFETY: allocation has bytes.len() + 1 writable bytes, and bytes is a
    // live Rust slice. The final byte is within the allocation.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), allocation.cast::<u8>(), bytes.len());
        *allocation.cast::<u8>().add(bytes.len()) = 0;
        *ret = allocation;
    }
    0
}

// SAFETY: name is NULL-checked before borrowing it as a C string; table is a
// Rust-owned static lookup and no raw output pointer is dereferenced here.
unsafe fn log_value_from_c_string(
    name: *const c_char,
    table: &[(i32, &'static str)],
    maximum: i32,
) -> i32 {
    if name.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: the FFI caller promises a live NUL-terminated input string.
    let name_bytes = unsafe { CStr::from_ptr(name) }.to_bytes();
    if let Some(value) = table
        .iter()
        .find_map(|(value, candidate)| (name_bytes == candidate.as_bytes()).then_some(*value))
    {
        return value;
    }

    let Some(numeric) = parse_safe_atou(name_bytes) else {
        return Errno::EINVAL.to_neg_errno();
    };
    if numeric > maximum as u32 {
        return Errno::EINVAL.to_neg_errno();
    }

    numeric as i32
}

/// C ABI facade for `log_facility_unshifted_is_valid()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_log_facility_unshifted_is_valid(facility: i32) -> bool {
    log_facility_unshifted_is_valid(facility)
}

/// C ABI facade for `log_facility_unshifted_from_string()`.
///
/// # Safety
/// `name` must be null or a readable NUL-terminated C string for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_log_facility_unshifted_from_string(name: *const c_char) -> i32 {
    // SAFETY: this facade forwards its C-string contract to the parser.
    unsafe { log_value_from_c_string(name, LOG_FACILITY_TABLE, LOG_FAC_MAX) }
}

/// C ABI facade for `log_facility_unshifted_to_string_alloc()`.
///
/// # Safety
/// `ret` must be a non-null, writable `char **`. On success it receives a
/// fresh `malloc(3)` allocation owned by the C caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_log_facility_unshifted_to_string_alloc(
    value: i32,
    ret: *mut *mut c_char,
) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: ret satisfies this function's writable-output contract.
    unsafe { *ret = std::ptr::null_mut() };
    let Ok(rendered) = log_facility_unshifted_to_string(value) else {
        return Errno::ERANGE.to_neg_errno();
    };
    // SAFETY: ret satisfies this facade's writable-output contract.
    unsafe { copy_to_c_allocator(rendered.as_bytes(), ret) }
}

/// C ABI facade for `log_level_is_valid()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_log_level_is_valid(level: i32) -> bool {
    log_level_is_valid(level)
}

/// C ABI facade for `log_level_from_string()`.
///
/// # Safety
/// `name` must be null or a readable NUL-terminated C string for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_log_level_from_string(name: *const c_char) -> i32 {
    // SAFETY: this facade forwards its C-string contract to the parser.
    unsafe { log_value_from_c_string(name, LOG_LEVEL_TABLE, LOG_DEBUG) }
}

/// C ABI facade for `log_level_to_string_alloc()`.
///
/// # Safety
/// `ret` must be a non-null, writable `char **`. On success it receives a
/// fresh `malloc(3)` allocation owned by the C caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_log_level_to_string_alloc(value: i32, ret: *mut *mut c_char) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: ret satisfies this function's writable-output contract.
    unsafe { *ret = std::ptr::null_mut() };
    let Ok(rendered) = log_level_to_string(value) else {
        return Errno::ERANGE.to_neg_errno();
    };
    // SAFETY: ret satisfies this facade's writable-output contract.
    unsafe { copy_to_c_allocator(rendered.as_bytes(), ret) }
}

/// C ABI facade for `syslog_parse_priority()`.
///
/// # Safety
/// `p` must point to a writable C-string pointer and `priority` to a writable
/// `int`; the input string must remain live and NUL-terminated for the call.
/// The pointer slots may not alias incompatible storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_syslog_parse_priority(
    p: *mut *const c_char,
    priority: *mut i32,
    with_facility: bool,
) -> i32 {
    if p.is_null() || priority.is_null() {
        return 0;
    }
    // SAFETY: p satisfies this function's writable pointer-slot contract.
    let input = unsafe { *p };
    if input.is_null() {
        return 0;
    }
    // SAFETY: input satisfies this function's C-string contract.
    let bytes = unsafe { CStr::from_ptr(input) }.to_bytes();
    if bytes.first() != Some(&b'<') {
        return 0;
    }
    let Some(end) = bytes.iter().position(|byte| *byte == b'>') else {
        return 0;
    };
    let k = end;
    if !(2..=4).contains(&k) {
        return 0;
    }
    let digits = &bytes[1..k];
    if !digits.iter().all(|byte| byte.is_ascii_digit()) {
        return 0;
    }
    let (a, b, c) = match digits {
        [c] => (0, 0, (c - b'0') as i32),
        [b, c] => (0, (b - b'0') as i32, (c - b'0') as i32),
        [a, b, c] => ((a - b'0') as i32, (b - b'0') as i32, (c - b'0') as i32),
        _ => return 0,
    };
    if !with_facility && (a != 0 || b != 0 || c > LOG_DEBUG) {
        return 0;
    }
    // SAFETY: p and priority satisfy this function's writable-output contract.
    unsafe {
        *priority = if with_facility {
            a * 100 + b * 10 + c
        } else {
            (*priority & LOG_FACMASK) | c
        };
        *p = input.add(k + 1);
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facility_validity_matches_c_range() {
        assert!(log_facility_unshifted_is_valid(0));
        assert!(log_facility_unshifted_is_valid(23));
        assert!(log_facility_unshifted_is_valid(127));
        assert!(!log_facility_unshifted_is_valid(-1));
        assert!(!log_facility_unshifted_is_valid(128));
    }

    #[test]
    fn facility_lookup_prefers_named_entries() {
        assert_eq!(log_facility_unshifted_to_string(0), Ok("kern".to_string()));
        assert_eq!(
            log_facility_unshifted_to_string(23),
            Ok("local7".to_string())
        );
    }

    #[test]
    fn facility_lookup_falls_back_to_numeric_strings() {
        assert_eq!(log_facility_unshifted_to_string(12), Ok("12".to_string()));
    }

    #[test]
    fn facility_lookup_rejects_out_of_range_values() {
        assert_eq!(log_facility_unshifted_to_string(-1), Err(Errno::ERANGE));
        assert_eq!(log_facility_unshifted_to_string(128), Err(Errno::ERANGE));
    }

    #[test]
    fn facility_parsing_is_case_sensitive_with_numeric_fallback() {
        assert_eq!(log_facility_unshifted_from_string("kern"), Ok(0));
        assert_eq!(log_facility_unshifted_from_string("23"), Ok(23));
        assert_eq!(
            log_facility_unshifted_from_string("KERN"),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn string_table_numeric_fallback_uses_safe_atou_grammar() {
        assert_eq!(log_facility_unshifted_from_string(" 15"), Ok(15));
        assert_eq!(log_facility_unshifted_from_string("+15"), Ok(15));
        assert_eq!(log_facility_unshifted_from_string("0xf"), Ok(15));
        assert_eq!(log_facility_unshifted_from_string("0b1111"), Ok(15));
        assert_eq!(log_facility_unshifted_from_string("0o17"), Ok(15));
        assert_eq!(
            log_facility_unshifted_from_string("+0b1111"),
            Err(Errno::EINVAL)
        );
        assert_eq!(log_facility_unshifted_from_string("08"), Err(Errno::EINVAL));
    }

    #[test]
    fn level_validity_matches_c_range() {
        assert!(log_level_is_valid(0));
        assert!(log_level_is_valid(7));
        assert!(!log_level_is_valid(-1));
        assert!(!log_level_is_valid(8));
    }

    #[test]
    fn level_lookup_and_parsing_match_tables() {
        assert_eq!(log_level_to_string(7), Ok("debug".to_string()));
        assert_eq!(log_level_from_string("debug"), Ok(7));
        assert_eq!(log_level_from_string("7"), Ok(7));
        assert_eq!(log_level_from_string("Debug"), Err(Errno::EINVAL));
    }

    #[test]
    fn syslog_parse_priority_handles_level_only_inputs() {
        assert_eq!(
            syslog_parse_priority("<5>rest", 0x120, false),
            Some(("rest", 0x125))
        );
        assert_eq!(
            syslog_parse_priority("<007>rest", 0x120, false),
            Some(("rest", 0x127))
        );
    }

    #[test]
    fn syslog_parse_priority_handles_facility_values() {
        assert_eq!(
            syslog_parse_priority("<191>msg", 0, true),
            Some(("msg", 191))
        );
        assert_eq!(syslog_parse_priority("<13>", 0, true), Some(("", 13)));
    }

    #[test]
    fn syslog_parse_priority_rejects_malformed_prefixes_like_c() {
        assert_eq!(syslog_parse_priority("hello", 0, false), None);
        assert_eq!(syslog_parse_priority("<8>msg", 0, false), None);
        assert_eq!(syslog_parse_priority("<abc>msg", 0, false), None);
        assert_eq!(syslog_parse_priority("<1234>msg", 0, true), None);
        assert_eq!(syslog_parse_priority("<1", 0, false), None);
    }
}
