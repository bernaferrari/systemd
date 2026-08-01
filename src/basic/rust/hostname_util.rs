// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.hostname-util-abi; authority=src/basic/hostname-util.c,src/basic/hostname-util.h,src/basic/user-util.c,src/basic/user-util.h,src/basic/string-util.c,src/basic/string-util.h,src/basic/utf8.c,src/basic/utf8.h
//
// Hostname validation, cleanup, and parsing utilities.
//
// Supports validation of LDH hostnames, localhost detection,
// synthetic hostname checks, and user@host expression splitting.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::ffi::CStr;
use std::ptr;

use libc::{c_char, c_int};

// ── Constants ──────────────────────────────────────────────────────────────

/// Maximum hostname length on Linux (min of HOST_NAME_MAX and 64).
const LINUX_HOST_NAME_MAX: usize = 64;

// ── Flags ──────────────────────────────────────────────────────────────────

// Flags controlling hostname validation behavior.
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ValidHostnameFlags: u32 {
        /// Accept trailing dot on multi-label names.
        const TRAILING_DOT = 1 << 0;
        /// Accept ".host" as valid hostname.
        const DOT_HOST = 1 << 1;
        /// Accept "?" as placeholder for hashed machine ID.
        const QUESTION_MARK = 1 << 2;
        /// Accept "$" as a placeholder for a word-list substitution.
        const WORD_TOKEN = 1 << 3;
    }
}

// ── Error constants ────────────────────────────────────────────────────────

const EINVAL: i32 = -22;
const ENOMEM: i32 = -12;

// ── Internal helpers ──────────────────────────────────────────────────────

/// Check if byte is ASCII letter (a-z, A-Z).
#[inline]
fn ascii_isalpha(c: u8) -> bool {
    (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z')
}

/// Check if byte is ASCII digit (0-9).
#[inline]
fn ascii_isdigit(c: u8) -> bool {
    c >= b'0' && c <= b'9'
}

/// Case-insensitive ASCII comparison.
#[inline]
fn ascii_tolower(c: u8) -> u8 {
    if c >= b'A' && c <= b'Z' { c + 32 } else { c }
}

/// Case-insensitive string equality.
fn strcaseeq(a: &str, b: &str) -> bool {
    a.bytes()
        .zip(b.bytes())
        .all(|(ca, cb)| ascii_tolower(ca) == ascii_tolower(cb))
        && a.len() == b.len()
}

/// Case-insensitive check if s equals any of the given strings.
fn strcase_in_set(s: &str, candidates: &[&str]) -> bool {
    candidates.iter().any(|c| strcaseeq(s, c))
}

/// Case-insensitive check if s ends with suffix.
fn endswith_no_case(s: &str, suffix: &str) -> bool {
    if suffix.len() > s.len() {
        return false;
    }
    if suffix.is_empty() {
        return true;
    }
    let s_tail = &s[s.len() - suffix.len()..];
    strcaseeq(s_tail, suffix)
}

// ── Simple user name validation ───────────────────────────────────────────

/// Check if a string is a valid POSIX user/group name.
///
/// Mirrors `valid_user_group_name(u, VALID_USER_RELAX | VALID_USER_ALLOW_NUMERIC)`
/// from user-util.c. Allows alphanumeric, underscore, hyphen; leading digits OK.
fn valid_user_group_name_relaxed(u: &str) -> bool {
    if u.is_empty() {
        return true; // VALID_USER_RELAX allows empty
    }
    if u.len() > 256 {
        return false;
    }
    u.bytes()
        .all(|c| ascii_isalpha(c) || ascii_isdigit(c) || c == b'_' || c == b'-')
}

// ── Public API ────────────────────────────────────────────────────────────

/// Check if a character is a valid LDH character (Letter, Digit, Hyphen).
///
/// "LDH" → "Letters, digits, hyphens", as per RFC 5890, Section 2.3.1.
pub fn valid_ldh_char(c: u8) -> bool {
    ascii_isalpha(c) || ascii_isdigit(c) || c == b'-'
}

/// Check if a string looks like a valid hostname or FQDN.
///
/// Returns `true` if valid, `false` otherwise.
pub fn hostname_is_valid(s: &str, flags: ValidHostnameFlags) -> bool {
    if s.is_empty() {
        return false;
    }

    if s == ".host" {
        return flags.contains(ValidHostnameFlags::DOT_HOST);
    }

    let mut n_dots: u32 = 0;
    let mut dot = true;
    let mut hyphen = true;

    for ch in s.bytes() {
        if ch == b'.' {
            if dot || hyphen {
                return false;
            }
            dot = true;
            hyphen = false;
            n_dots += 1;
        } else if ch == b'-' {
            if dot {
                return false;
            }
            dot = false;
            hyphen = true;
        } else {
            if !valid_ldh_char(ch)
                && (ch != b'?' || !flags.contains(ValidHostnameFlags::QUESTION_MARK))
                && (ch != b'$' || !flags.contains(ValidHostnameFlags::WORD_TOKEN))
            {
                return false;
            }
            dot = false;
            hyphen = false;
        }
    }

    if dot && (n_dots < 2 || !flags.contains(ValidHostnameFlags::TRAILING_DOT)) {
        return false;
    }
    if hyphen {
        return false;
    }

    // Note that host name max is 64 on Linux, but DNS allows domain names up to 255 characters.
    if s.len() > LINUX_HOST_NAME_MAX {
        return false;
    }

    true
}

/// Clean up a hostname string.
///
/// Removes invalid characters, collapses consecutive dots/hyphens, trims
/// trailing dot/hyphen, truncates to LINUX_HOST_NAME_MAX.
pub fn hostname_cleanup(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(bytes.len().min(LINUX_HOST_NAME_MAX));
    let mut dot = true;
    let mut hyphen = true;

    for &ch in bytes.iter() {
        if result.len() >= LINUX_HOST_NAME_MAX {
            break;
        }
        if ch == b'.' {
            if dot || hyphen {
                continue;
            }
            result.push(b'.');
            dot = true;
            hyphen = false;
        } else if ch == b'-' {
            if dot {
                continue;
            }
            result.push(b'-');
            dot = false;
            hyphen = true;
        } else if valid_ldh_char(ch) || matches!(ch, b'?' | b'$') {
            result.push(ch);
            dot = false;
            hyphen = false;
        }
    }

    // Remove trailing dot or hyphen
    while result.last() == Some(&b'-') || result.last() == Some(&b'.') {
        result.pop();
    }

    String::from_utf8_lossy(&result).into_owned()
}

/// Check if a hostname matches localhost patterns (RFC 6761 + localdomain).
pub fn is_localhost(hostname: &str) -> bool {
    strcase_in_set(
        hostname,
        &[
            "localhost",
            "localhost.",
            "localhost.localdomain",
            "localhost.localdomain.",
        ],
    ) || endswith_no_case(hostname, ".localhost")
        || endswith_no_case(hostname, ".localhost.")
        || endswith_no_case(hostname, ".localhost.localdomain")
        || endswith_no_case(hostname, ".localhost.localdomain.")
}

/// Check if hostname is the synthetic "gateway" host.
pub fn is_gateway_hostname(hostname: &str) -> bool {
    strcase_in_set(hostname, &["_gateway", "_gateway."])
}

/// Check if hostname is the synthetic "outbound" host.
pub fn is_outbound_hostname(hostname: &str) -> bool {
    strcase_in_set(hostname, &["_outbound", "_outbound."])
}

/// Check if hostname is the DNS stub hostname.
pub fn is_dns_stub_hostname(hostname: &str) -> bool {
    strcase_in_set(hostname, &["_localdnsstub", "_localdnsstub."])
}

/// Check if hostname is the DNS proxy stub hostname.
pub fn is_dns_proxy_stub_hostname(hostname: &str) -> bool {
    strcase_in_set(hostname, &["_localdnsproxy", "_localdnsproxy."])
}

/// Result of splitting a user@host expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitResult {
    /// The user part (before @), if any.
    pub user: Option<String>,
    /// The host part (after @, or entire string if no @).
    pub host: Option<String>,
    /// Whether an '@' was found in the input.
    pub has_at: bool,
}

/// Split a user@host expression.
///
/// Returns a `SplitResult` on success, or a negative errno on error.
/// Sets user/host to `None` if that part was empty.
pub fn split_user_at_host(s: &str) -> Result<SplitResult, i32> {
    if let Some(at_pos) = s.find('@') {
        let user_part = if at_pos > 0 {
            Some(s[..at_pos].to_string())
        } else {
            None
        };

        let host_part = if at_pos + 1 < s.len() {
            Some(s[at_pos + 1..].to_string())
        } else {
            None
        };

        Ok(SplitResult {
            user: user_part,
            host: host_part,
            has_at: true,
        })
    } else {
        if s.is_empty() {
            return Err(EINVAL);
        }

        Ok(SplitResult {
            user: None,
            host: Some(s.to_string()),
            has_at: false,
        })
    }
}

/// Validate a machine specification (user@host format).
///
/// Returns `Ok(true)` if valid, `Ok(false)` if invalid, `Err` on error.
pub fn machine_spec_valid(s: &str) -> Result<bool, i32> {
    let split = match split_user_at_host(s) {
        Ok(r) => r,
        Err(EINVAL) => return Ok(false),
        Err(e) => return Err(e),
    };

    let mut valid = true;

    if let Some(ref u) = split.user {
        if !valid_user_group_name_relaxed(u) {
            valid = false;
        }
    }

    if valid {
        if let Some(ref h) = split.host {
            if !hostname_is_valid(h, ValidHostnameFlags::DOT_HOST) {
                valid = false;
            }
        }
    }

    Ok(valid)
}

/// Maximum number of machine tags accepted by `machine_tags_from_string`.
pub const MACHINE_TAGS_MAX: usize = 1024;

/// Validate one machine tag.
///
/// This mirrors `machine_tag_is_valid()`: tags are ASCII alphanumeric strings
/// with `-`, `.`, and `=` separators; `=` optionally separates a tag key from
/// its value.
pub fn machine_tag_is_valid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() >= 256 {
        return false;
    }

    if matches!(bytes[0], b'-' | b'.' | b'=') {
        return false;
    }

    if let Some(eq) = bytes.iter().position(|byte| *byte == b'=') {
        if matches!(bytes[eq - 1], b'-' | b'.') {
            return false;
        }
    } else if matches!(bytes[bytes.len() - 1], b'-' | b'.') {
        return false;
    }

    bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'='))
}

/// Validate a complete machine-tag list, including the one-value-per-key rule.
pub fn machine_tag_list_is_valid(tags: &[String]) -> bool {
    if tags.len() > MACHINE_TAGS_MAX || tags.iter().any(|tag| !machine_tag_is_valid(tag)) {
        return false;
    }

    for (index, tag) in tags.iter().enumerate() {
        let Some(eq) = tag.find('=') else {
            continue;
        };
        let key = &tag[..=eq];
        if tags[..index]
            .iter()
            .any(|other| other != tag && other.starts_with(key))
        {
            return false;
        }
    }

    true
}

/// Parse the colon-separated `TAGS=` machine-info value.
///
/// Invalid tags either reject the input or are omitted, depending on
/// `graceful`. The returned tags are sorted and deduplicated, as in C.
pub fn machine_tags_from_string(s: &str, graceful: bool) -> Result<Vec<String>, i32> {
    if s.is_empty() {
        return Ok(Vec::new());
    }

    let mut tags: Vec<String> = s.split(':').map(str::to_owned).collect();
    tags.sort_unstable();
    tags.dedup();

    if !graceful {
        return machine_tag_list_is_valid(&tags)
            .then_some(tags)
            .ok_or(EINVAL);
    }

    let mut cleaned = Vec::new();
    let mut valid_tag_count = 0;
    for tag in tags {
        if !machine_tag_is_valid(&tag) {
            continue;
        }

        valid_tag_count += 1;
        if valid_tag_count > MACHINE_TAGS_MAX {
            return Err(-(libc::E2BIG as i32));
        }

        if let Some(eq) = tag.find('=') {
            let key = &tag[..=eq];
            if cleaned.iter().any(|other: &String| other.starts_with(key)) {
                continue;
            }
        }
        cleaned.push(tag);
    }

    Ok(cleaned)
}

// ── C ABI adapters ───────────────────────────────────────────────────────

/// Current `hostname_is_valid()` policy over the visible bytes of a C string.
///
/// The C authority is deliberately byte-oriented: host names only admit the
/// ASCII LDH alphabet plus the two explicitly enabled placeholder bytes.
fn hostname_is_valid_bytes(bytes: &[u8], flags: u32) -> bool {
    if bytes.is_empty() {
        return false;
    }

    if bytes == b".host" {
        return flags & ValidHostnameFlags::DOT_HOST.bits() != 0;
    }

    let mut n_dots = 0_u32;
    let mut dot = true;
    let mut hyphen = true;
    for &byte in bytes {
        match byte {
            b'.' => {
                if dot || hyphen {
                    return false;
                }
                dot = true;
                hyphen = false;
                n_dots += 1;
            }
            b'-' => {
                if dot {
                    return false;
                }
                dot = false;
                hyphen = true;
            }
            _ => {
                if !valid_ldh_char(byte)
                    && (byte != b'?' || flags & ValidHostnameFlags::QUESTION_MARK.bits() == 0)
                    && (byte != b'$' || flags & ValidHostnameFlags::WORD_TOKEN.bits() == 0)
                {
                    return false;
                }
                dot = false;
                hyphen = false;
            }
        }
    }

    if dot && (n_dots < 2 || flags & ValidHostnameFlags::TRAILING_DOT.bits() == 0) {
        return false;
    }
    !hyphen && bytes.len() <= LINUX_HOST_NAME_MAX
}

/// Clean a writable C-string byte buffer in place and return its visible length.
///
/// `bytes` includes the input's trailing NUL, which is rewritten after the
/// compacted hostname. The destination never advances beyond its source index.
fn hostname_cleanup_bytes(bytes: &mut [u8]) -> usize {
    let input_len = bytes.len().saturating_sub(1);
    let mut destination = 0;
    let mut dot = true;
    let mut hyphen = true;

    for source in 0..input_len {
        let byte = bytes[source];
        if byte == b'.' {
            if dot || hyphen {
                continue;
            }
            bytes[destination] = b'.';
            destination += 1;
            dot = true;
            hyphen = false;
        } else if byte == b'-' {
            if dot {
                continue;
            }
            bytes[destination] = b'-';
            destination += 1;
            dot = false;
            hyphen = true;
        } else if valid_ldh_char(byte) || matches!(byte, b'?' | b'$') {
            bytes[destination] = byte;
            destination += 1;
            dot = false;
            hyphen = false;
        }
        if destination >= LINUX_HOST_NAME_MAX {
            break;
        }
    }

    while destination > 0 && matches!(bytes[destination - 1], b'-' | b'.') {
        destination -= 1;
    }
    bytes[destination] = 0;
    destination
}

#[inline]
fn bytes_equal_no_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(&left, &right)| ascii_tolower(left) == ascii_tolower(right))
}

#[inline]
fn bytes_ends_with_no_case(bytes: &[u8], suffix: &[u8]) -> bool {
    bytes.len() >= suffix.len() && bytes_equal_no_case(&bytes[bytes.len() - suffix.len()..], suffix)
}

fn localhost_bytes_are_valid(bytes: &[u8]) -> bool {
    [
        b"localhost".as_slice(),
        b"localhost.".as_slice(),
        b"localhost.localdomain".as_slice(),
        b"localhost.localdomain.".as_slice(),
    ]
    .into_iter()
    .any(|candidate| bytes_equal_no_case(bytes, candidate))
        || [
            b".localhost".as_slice(),
            b".localhost.".as_slice(),
            b".localhost.localdomain".as_slice(),
            b".localhost.localdomain.".as_slice(),
        ]
        .into_iter()
        .any(|suffix| bytes_ends_with_no_case(bytes, suffix))
}

fn bytes_in_no_case_set(bytes: &[u8], choices: &[&[u8]]) -> bool {
    choices
        .iter()
        .copied()
        .any(|choice| bytes_equal_no_case(bytes, choice))
}

fn malloc_c_string(bytes: &[u8]) -> *mut c_char {
    let Some(allocation_size) = bytes.len().checked_add(1) else {
        return ptr::null_mut();
    };
    let allocation = crate::ffi::malloc(allocation_size).cast::<u8>();
    if allocation.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: `allocation` names `allocation_size` writable bytes from the C
    // allocator; `bytes` is live for the copy and the final NUL is in range.
    unsafe_ffi!({
        ptr::copy_nonoverlapping(bytes.as_ptr(), allocation, bytes.len());
        *allocation.add(bytes.len()) = 0;
    });
    allocation.cast::<c_char>()
}

fn valid_utf8_bytes(bytes: &[u8]) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        let Some((length, _)) = crate::string_util::valid_utf8_character(&bytes[offset..]) else {
            return false;
        };
        offset += length;
    }
    true
}

fn parses_as_valid_uid(bytes: &[u8]) -> bool {
    if bytes.is_empty() || (bytes.len() > 1 && bytes[0] == b'0') {
        return false;
    }

    let mut value = 0_u32;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return false;
        }
        let Some(next) = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u32::from(byte - b'0')))
        else {
            return false;
        };
        value = next;
    }
    value != u32::MAX && value != 0xffff
}

/// The `VALID_USER_RELAX | VALID_USER_ALLOW_NUMERIC` slice used solely by
/// `machine_spec_valid()`. This keeps the C ABI path raw-byte-safe while
/// preserving C's UTF-8 and control-character restrictions.
fn valid_machine_user_bytes(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if parses_as_valid_uid(bytes) {
        return true;
    }
    if bytes.first() == Some(&b' ') || bytes.last() == Some(&b' ') {
        return false;
    }
    if !valid_utf8_bytes(bytes)
        || bytes.iter().any(|byte| *byte < b' ' || *byte == 127)
        || bytes.iter().any(|byte| matches!(*byte, b':' | b'/'))
    {
        return false;
    }
    if bytes.iter().all(u8::is_ascii_digit)
        || (bytes.first() == Some(&b'-') && bytes[1..].iter().all(u8::is_ascii_digit))
    {
        return false;
    }
    !matches!(bytes, b"." | b"..")
}

fn machine_spec_valid_bytes(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }

    let Some(at) = bytes.iter().position(|byte| *byte == b'@') else {
        return hostname_is_valid_bytes(bytes, ValidHostnameFlags::DOT_HOST.bits());
    };
    let user_is_valid = at == 0 || valid_machine_user_bytes(&bytes[..at]);
    let host_is_valid = at + 1 == bytes.len()
        || hostname_is_valid_bytes(&bytes[at + 1..], ValidHostnameFlags::DOT_HOST.bits());
    user_is_valid && host_is_valid
}

/// C ABI for `valid_ldh_char()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_valid_ldh_char(c: c_char) -> bool {
    valid_ldh_char(c as u8)
}

/// C ABI for `hostname_is_valid()`.
///
/// # Safety
/// `s` must be null or point to a readable NUL-terminated byte string that
/// remains live for the call. A null pointer is rejected rather than invoking
/// the C authority's assertion.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_hostname_is_valid(s: *const c_char, flags: c_int) -> bool {
    if s.is_null() {
        return false;
    }
    // SAFETY: documented by this adapter's C-string contract.
    let bytes = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    hostname_is_valid_bytes(bytes, flags as u32)
}

/// C ABI for `hostname_cleanup()`.
///
/// # Safety
/// `s` must be null or point to an exclusively owned, writable,
/// NUL-terminated byte string. The input allocation must remain live for the
/// call; the returned pointer aliases that same allocation and must not be
/// freed separately.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_hostname_cleanup(s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: documented by this adapter's C-string contract.
    let input_len = unsafe_ffi!(CStr::from_ptr(s.cast_const())).to_bytes().len();
    // SAFETY: the writable C-string contract provides all visible bytes plus
    // the trailing terminator as one exclusive byte slice.
    let bytes = unsafe_ffi!(std::slice::from_raw_parts_mut(
        s.cast::<u8>(),
        input_len + 1
    ));
    hostname_cleanup_bytes(bytes);
    s
}

/// C ABI for `is_localhost()`.
///
/// # Safety
/// `hostname` must be null or point to a readable NUL-terminated byte string
/// that remains live for the call. A null pointer is rejected instead of
/// triggering C's assertion.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_localhost(hostname: *const c_char) -> bool {
    if hostname.is_null() {
        return false;
    }
    // SAFETY: documented by this adapter's C-string contract.
    localhost_bytes_are_valid(unsafe_ffi!(CStr::from_ptr(hostname)).to_bytes())
}

/// Evaluate one synthetic hostname classifier after the shared C-string
/// boundary check.
///
/// # Safety
/// `hostname` must be null or point to a readable NUL-terminated byte string
/// that remains live for the call.
fn is_synthetic_hostname(hostname: *const c_char, first: &[u8], second: &[u8]) -> bool {
    if hostname.is_null() {
        return false;
    }
    // SAFETY: this private helper is called only by the audited C ABI adapters.
    let bytes = unsafe_ffi!(CStr::from_ptr(hostname)).to_bytes();
    bytes_in_no_case_set(bytes, &[first, second])
}

/// C ABI for `is_gateway_hostname()`.
///
/// # Safety
/// `hostname` must be null or point to a readable NUL-terminated byte string
/// that remains live for the call. A null pointer is rejected instead of
/// triggering C's assertion.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_gateway_hostname(hostname: *const c_char) -> bool {
    is_synthetic_hostname(hostname, b"_gateway", b"_gateway.")
}

/// C ABI for `is_outbound_hostname()`.
///
/// # Safety
/// `hostname` must be null or point to a readable NUL-terminated byte string
/// that remains live for the call. A null pointer is rejected instead of
/// triggering C's assertion.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_outbound_hostname(hostname: *const c_char) -> bool {
    is_synthetic_hostname(hostname, b"_outbound", b"_outbound.")
}

/// C ABI for `is_dns_stub_hostname()`.
///
/// # Safety
/// `hostname` must be null or point to a readable NUL-terminated byte string
/// that remains live for the call. A null pointer is rejected instead of
/// triggering C's assertion.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_dns_stub_hostname(hostname: *const c_char) -> bool {
    is_synthetic_hostname(hostname, b"_localdnsstub", b"_localdnsstub.")
}

/// C ABI for `is_dns_proxy_stub_hostname()`.
///
/// # Safety
/// `hostname` must be null or point to a readable NUL-terminated byte string
/// that remains live for the call. A null pointer is rejected instead of
/// triggering C's assertion.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_is_dns_proxy_stub_hostname(hostname: *const c_char) -> bool {
    is_synthetic_hostname(hostname, b"_localdnsproxy", b"_localdnsproxy.")
}

/// C ABI for `split_user_at_host()`.
///
/// # Safety
/// `s` must be null or point to a readable NUL-terminated byte string that
/// remains live for the call. Each non-null output pointer must designate
/// writable `char *` storage. On success, non-null outputs receive either
/// null or a fresh libc allocation owned by the C caller and released with
/// `free(3)`. Outputs are not modified on allocation failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_split_user_at_host(
    s: *const c_char,
    ret_user: *mut *mut c_char,
    ret_host: *mut *mut c_char,
) -> c_int {
    if s.is_null() {
        return EINVAL;
    }
    // SAFETY: documented by this adapter's C-string contract.
    let bytes = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    let at = bytes.iter().position(|byte| *byte == b'@');
    if at.is_none() && bytes.is_empty() {
        return EINVAL;
    }

    let (user, host, result) = match at {
        Some(at) => (
            (!ret_user.is_null() && at > 0).then(|| &bytes[..at]),
            (!ret_host.is_null() && at + 1 < bytes.len()).then(|| &bytes[at + 1..]),
            1,
        ),
        None => (None, (!ret_host.is_null()).then_some(bytes), 0),
    };
    let user_allocation = user.map_or(ptr::null_mut(), malloc_c_string);
    if user.is_some() && user_allocation.is_null() {
        return ENOMEM;
    }
    let host_allocation = host.map_or(ptr::null_mut(), malloc_c_string);
    if host.is_some() && host_allocation.is_null() {
        // SAFETY: this allocation was created by `malloc_c_string` above and
        // has not been published to the caller.
        unsafe_ffi!(crate::ffi::free(user_allocation.cast()));
        return ENOMEM;
    }

    if !ret_user.is_null() {
        // SAFETY: documented by this adapter's output-pointer contract.
        unsafe_ffi!(*ret_user = user_allocation);
    }
    if !ret_host.is_null() {
        // SAFETY: documented by this adapter's output-pointer contract.
        unsafe_ffi!(*ret_host = host_allocation);
    }
    result
}

/// C ABI for `machine_spec_valid()`.
///
/// # Safety
/// `s` must be null or point to a readable NUL-terminated byte string that
/// remains live for the call. A null pointer is rejected instead of invoking
/// C's assertion.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_machine_spec_valid(s: *const c_char) -> c_int {
    if s.is_null() {
        return 0;
    }
    // SAFETY: documented by this adapter's C-string contract.
    let bytes = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    c_int::from(machine_spec_valid_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rs_valid_ldh_char_uses_c_char() {
        let valid: c_char = b'a' as c_char;
        let invalid: c_char = b'_' as c_char;

        assert!(rs_valid_ldh_char(valid));
        assert!(!rs_valid_ldh_char(invalid));
    }

    #[test]
    fn test_valid_ldh_char_letters() {
        assert!(valid_ldh_char(b'a'));
        assert!(valid_ldh_char(b'z'));
        assert!(valid_ldh_char(b'A'));
        assert!(valid_ldh_char(b'Z'));
    }

    #[test]
    fn test_valid_ldh_char_digits_and_hyphen() {
        assert!(valid_ldh_char(b'0'));
        assert!(valid_ldh_char(b'9'));
        assert!(valid_ldh_char(b'-'));
    }

    #[test]
    fn test_valid_ldh_char_invalid() {
        assert!(!valid_ldh_char(b'_'));
        assert!(!valid_ldh_char(b'.'));
        assert!(!valid_ldh_char(b' '));
        assert!(!valid_ldh_char(b'@'));
    }

    #[test]
    fn test_hostname_is_valid_simple() {
        assert!(hostname_is_valid("myhost", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid("my-host", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid("my.host", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid(
            "myhost.example.com",
            ValidHostnameFlags::empty()
        ));
    }

    #[test]
    fn test_hostname_is_valid_trailing_dot() {
        assert!(!hostname_is_valid("myhost.", ValidHostnameFlags::empty()));
        assert!(!hostname_is_valid(
            "myhost.",
            ValidHostnameFlags::TRAILING_DOT
        ));
        assert!(hostname_is_valid(
            "myhost.example.",
            ValidHostnameFlags::TRAILING_DOT | ValidHostnameFlags::QUESTION_MARK
        ));
    }

    #[test]
    fn test_hostname_is_valid_dot_host() {
        assert!(!hostname_is_valid(".host", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid(".host", ValidHostnameFlags::DOT_HOST));
    }

    #[test]
    fn test_hostname_is_valid_question_mark() {
        assert!(!hostname_is_valid("my?host", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid(
            "my?host",
            ValidHostnameFlags::QUESTION_MARK
        ));
    }

    #[test]
    fn test_hostname_is_valid_word_token() {
        assert!(!hostname_is_valid("my$host", ValidHostnameFlags::empty()));
        assert!(hostname_is_valid("my$host", ValidHostnameFlags::WORD_TOKEN));
    }

    #[test]
    fn test_hostname_is_valid_empty_and_null() {
        assert!(!hostname_is_valid("", ValidHostnameFlags::empty()));
    }

    #[test]
    fn test_hostname_is_valid_starting_hyphen() {
        assert!(!hostname_is_valid("-host", ValidHostnameFlags::empty()));
    }

    #[test]
    fn test_hostname_is_valid_ending_hyphen() {
        assert!(!hostname_is_valid("host-", ValidHostnameFlags::empty()));
    }

    #[test]
    fn test_hostname_is_valid_consecutive_dots() {
        assert!(!hostname_is_valid(
            "host..name",
            ValidHostnameFlags::empty()
        ));
    }

    #[test]
    fn test_hostname_is_valid_too_long() {
        let long = "a".repeat(65);
        assert!(!hostname_is_valid(&long, ValidHostnameFlags::empty()));
    }

    #[test]
    fn test_hostname_is_valid_max_length() {
        let max = "a".repeat(64);
        assert!(hostname_is_valid(&max, ValidHostnameFlags::empty()));
    }

    #[test]
    fn test_hostname_cleanup_basic() {
        assert_eq!(hostname_cleanup("myhost"), "myhost");
    }

    #[test]
    fn test_hostname_cleanup_trailing_dot() {
        assert_eq!(hostname_cleanup("myhost."), "myhost");
    }

    #[test]
    fn test_hostname_cleanup_trailing_hyphen() {
        assert_eq!(hostname_cleanup("myhost-"), "myhost");
    }

    #[test]
    fn test_hostname_cleanup_word_token_and_multiple_trailing_separators() {
        assert_eq!(hostname_cleanup("my$host--."), "my$host");
    }

    #[test]
    fn test_hostname_cleanup_consecutive_dots() {
        assert_eq!(hostname_cleanup("my..host"), "my.host");
    }

    #[test]
    fn test_hostname_cleanup_invalid_chars() {
        assert_eq!(hostname_cleanup("my host"), "myhost");
        assert_eq!(hostname_cleanup("my_host"), "myhost");
    }

    #[test]
    fn test_is_localhost() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("LOCALHOST"));
        assert!(is_localhost("localhost."));
        assert!(is_localhost("localhost.localdomain"));
        assert!(is_localhost("foo.localhost"));
        assert!(is_localhost("foo.localhost."));
    }

    #[test]
    fn test_is_localhost_not_localhost() {
        assert!(!is_localhost("example.com"));
        assert!(!is_localhost("myhost"));
    }

    #[test]
    fn test_is_gateway_hostname() {
        assert!(is_gateway_hostname("_gateway"));
        assert!(is_gateway_hostname("_GATEWAY"));
        assert!(is_gateway_hostname("_gateway."));
    }

    #[test]
    fn test_is_gateway_hostname_not_gateway() {
        assert!(!is_gateway_hostname("gateway"));
        assert!(!is_gateway_hostname("localhost"));
    }

    #[test]
    fn test_is_outbound_hostname() {
        assert!(is_outbound_hostname("_outbound"));
        assert!(is_outbound_hostname("_outbound."));
    }

    #[test]
    fn test_is_outbound_hostname_not_outbound() {
        assert!(!is_outbound_hostname("outbound"));
    }

    #[test]
    fn test_is_dns_stub_hostname() {
        assert!(is_dns_stub_hostname("_localdnsstub"));
        assert!(is_dns_stub_hostname("_localdnsstub."));
    }

    #[test]
    fn test_is_dns_stub_hostname_not_stub() {
        assert!(!is_dns_stub_hostname("localdnsstub"));
    }

    #[test]
    fn test_is_dns_proxy_stub_hostname() {
        assert!(is_dns_proxy_stub_hostname("_localdnsproxy"));
        assert!(is_dns_proxy_stub_hostname("_localdnsproxy."));
    }

    #[test]
    fn test_is_dns_proxy_stub_hostname_not_proxy() {
        assert!(!is_dns_proxy_stub_hostname("localdnsproxy"));
    }

    #[test]
    fn test_split_user_at_host_with_user() {
        let result = split_user_at_host("user@host").unwrap();
        assert_eq!(result.user.as_deref(), Some("user"));
        assert_eq!(result.host.as_deref(), Some("host"));
        assert!(result.has_at);
    }

    #[test]
    fn test_split_user_at_host_no_user() {
        let result = split_user_at_host("@host").unwrap();
        assert!(result.user.is_none());
        assert_eq!(result.host.as_deref(), Some("host"));
        assert!(result.has_at);
    }

    #[test]
    fn test_split_user_at_host_no_at() {
        let result = split_user_at_host("host").unwrap();
        assert!(result.user.is_none());
        assert_eq!(result.host.as_deref(), Some("host"));
        assert!(!result.has_at);
    }

    #[test]
    fn test_split_user_at_host_empty() {
        assert!(split_user_at_host("").is_err());
    }

    #[test]
    fn test_machine_spec_valid() {
        assert!(machine_spec_valid("host").unwrap());
        assert!(machine_spec_valid("user@host").unwrap());
        assert!(!machine_spec_valid("").unwrap());
    }

    #[test]
    fn machine_tags_validate_canonical_forms() {
        assert!(machine_tag_is_valid("build"));
        assert!(machine_tag_is_valid("role=worker"));
        assert!(machine_tag_is_valid("release=2026.07"));
        assert!(!machine_tag_is_valid("-build"));
        assert!(!machine_tag_is_valid("role-=worker"));
        assert!(!machine_tag_is_valid("build."));
        assert!(!machine_tag_is_valid("role/worker"));
    }

    #[test]
    fn machine_tags_reject_multiple_values_for_one_key() {
        let tags = vec!["role=api".to_owned(), "role=worker".to_owned()];
        assert!(!machine_tag_list_is_valid(&tags));
        assert!(machine_tags_from_string("role=api:role=worker", false).is_err());
    }

    #[test]
    fn graceful_machine_tags_are_sorted_and_keep_first_value_per_key() {
        assert_eq!(
            machine_tags_from_string("role=worker:bad/:role=api:build", true),
            Ok(vec!["build".to_owned(), "role=api".to_owned()])
        );
    }
}
