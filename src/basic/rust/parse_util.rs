// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.parse-util; authority=src/basic/parse-util.c,src/basic/parse-util.h
//
// Safe numeric parsing, boolean parsing, and size parsing.
// Core safe_ato* family and parse_boolean used throughout systemd.

// Centralized unsafe expression boundary for this C-ABI adapter.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing adapter documents and validates the raw-pointer,
        // ownership, and lifetime contract before evaluating this expression.
        unsafe { $expression }
    }};
}
use crate::errno_util::errno_from_name as errno_from_name_rs;
use crate::ffi::{Errno, clear_errno, get_errno, is_whitespace};
use crate::process_util_str_tables::oom_score_adjust_is_valid as oom_score_adjust_is_valid_rs;
use std::ffi::{CStr, CString};

use libc::{c_char, c_long, c_ulong};

// ── SAFE_ATO flags ─────────────────────────────────────────────────────────

pub const SAFE_ATO_REFUSE_PLUS_MINUS: u32 = 1 << 30;
pub const SAFE_ATO_REFUSE_LEADING_ZERO: u32 = 1 << 29;
pub const SAFE_ATO_REFUSE_LEADING_WHITESPACE: u32 = 1 << 28;
pub const SAFE_ATO_ALL_FLAGS: u32 =
    SAFE_ATO_REFUSE_PLUS_MINUS | SAFE_ATO_REFUSE_LEADING_ZERO | SAFE_ATO_REFUSE_LEADING_WHITESPACE;

pub const fn safe_ato_mask_flags(base: u32) -> u32 {
    base & !SAFE_ATO_ALL_FLAGS
}

// ── Local helpers ─────────────────────────────────────────────────────────

/// Convert an ABI C-string argument into the safe representation used by the
/// parsers below.
///
/// # Safety
/// `s` must be null or point to a live NUL-terminated C string for the call.
unsafe fn cstr_bytes<'a>(s: *const c_char) -> Result<&'a [u8], i32> {
    if s.is_null() {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    // SAFETY: upheld by this helper's contract.
    Ok(unsafe_ffi!(CStr::from_ptr(s)).to_bytes())
}

/// Resolve a C errno name through the safe Rust table.
fn errno_from_name(name: &[u8]) -> i32 {
    let Ok(name) = std::str::from_utf8(name) else {
        return Errno::EINVAL.to_neg_errno();
    };

    errno_from_name_rs(name).unwrap_or(Errno::EINVAL.to_neg_errno())
}

fn nice_is_valid(n: i32) -> bool {
    (-20..=19).contains(&n)
}

const ERRNO_MAX: i32 = 4095;

fn errno_is_valid(e: i32) -> bool {
    e > 0 && e <= ERRNO_MAX
}

// ── Private helpers ────────────────────────────────────────────────────────

fn skip_whitespace(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|byte| !is_whitespace(*byte))
        .unwrap_or(bytes.len());
    &bytes[first..]
}

/// Match the C library's `strto*()` leading-ASCII-whitespace grammar. This is
/// intentionally broader than systemd's `WHITESPACE`, which is used only by
/// the explicit refusal flag above.
fn skip_c_whitespace(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    &bytes[first..]
}

/// Return the first non-whitespace byte of an ABI C string.
///
/// # Safety
/// `s` must point to a live NUL-terminated C string for this call.
unsafe fn skip_whitespace_ptr(s: *const c_char) -> *const c_char {
    // SAFETY: upheld by this helper's contract.
    let bytes = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    let offset = bytes
        .iter()
        .position(|byte| !is_whitespace(*byte))
        .unwrap_or(bytes.len());
    // SAFETY: offset was measured within the C string above.
    unsafe_ffi!(s.add(offset))
}

fn strcase_in_set(value: &[u8], set: &[&CStr]) -> bool {
    set.iter()
        .any(|item| value.eq_ignore_ascii_case(item.to_bytes()))
}

/// Mangle base: handle Python 3 style "0b"/"0B" and "0o"/"0O" prefixes.
fn mangle_base<'a>(bytes: &'a [u8], base: &mut u32) -> &'a [u8] {
    // If base is already explicitly specified (non-zero actual base), don't mangle.
    if safe_ato_mask_flags(*base) != 0 {
        return bytes;
    }

    if bytes.starts_with(b"0b") || bytes.starts_with(b"0B") {
        *base = 2 | (*base & SAFE_ATO_ALL_FLAGS);
        return &bytes[2..];
    }

    if bytes.starts_with(b"0o") || bytes.starts_with(b"0O") {
        *base = 8 | (*base & SAFE_ATO_ALL_FLAGS);
        return &bytes[2..];
    }

    bytes
}

/// Flags_SET equivalent: check if flags are set in value.
#[inline]
const fn flags_set(value: u32, flags: u32) -> bool {
    (value & flags) != 0
}

/// IN_SET equivalent: check if value matches any of the given values.
#[inline]
fn in_set<T: PartialEq>(value: T, set: &[T]) -> bool {
    set.contains(&value)
}

fn digit_value(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some((byte - b'0') as u32),
        b'a'..=b'f' => Some((byte - b'a') as u32 + 10),
        b'A'..=b'F' => Some((byte - b'A') as u32 + 10),
        _ => None,
    }
}

fn parse_unsigned_digits(bytes: &[u8], mut base: u32, limit: u64) -> Result<u64, i32> {
    if base == 1 || base > 16 {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    let mut pos = 0;
    if base == 0 {
        base = if bytes.starts_with(b"0x") || bytes.starts_with(b"0X") {
            pos = 2;
            16
        } else if bytes.starts_with(b"0") {
            8
        } else {
            10
        };
    } else if base == 16 && (bytes.starts_with(b"0x") || bytes.starts_with(b"0X")) {
        pos = 2;
    }

    let mut value = 0u64;
    let mut digits = 0;
    while let Some(&byte) = bytes.get(pos) {
        let Some(digit) = digit_value(byte) else {
            break;
        };
        if digit >= base {
            break;
        }
        value = value
            .checked_mul(base as u64)
            .and_then(|value| value.checked_add(digit as u64))
            .filter(|value| *value <= limit)
            .ok_or(Errno::ERANGE.to_neg_errno())?;
        pos += 1;
        digits += 1;
    }

    if digits == 0 || pos != bytes.len() {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    Ok(value)
}

fn parse_unsigned(bytes: &[u8], base: u32, limit: u64) -> Result<u64, i32> {
    let bytes = skip_c_whitespace(bytes);
    let (negative, bytes) = match bytes.first() {
        Some(b'+') => (false, &bytes[1..]),
        Some(b'-') => (true, &bytes[1..]),
        _ => (false, bytes),
    };
    let value = parse_unsigned_digits(bytes, base, limit)?;
    if negative && value != 0 {
        return Err(Errno::ERANGE.to_neg_errno());
    }
    Ok(value)
}

fn parse_signed(bytes: &[u8], base: u32, min: i64, max: i64) -> Result<i64, i32> {
    let bytes = skip_c_whitespace(bytes);
    let (negative, bytes) = match bytes.first() {
        Some(b'+') => (false, &bytes[1..]),
        Some(b'-') => (true, &bytes[1..]),
        _ => (false, bytes),
    };
    let limit = if negative {
        (-(min + 1)) as u64 + 1
    } else {
        max as u64
    };
    let value = parse_unsigned_digits(bytes, base, limit)?;
    if negative {
        Ok(if value == limit { min } else { -(value as i64) })
    } else {
        Ok(value as i64)
    }
}

// ── parse_boolean ─────────────────────────────────────────────────────────

static TRUE_VALUES: [&CStr; 6] = [c"1", c"yes", c"y", c"true", c"t", c"on"];
static FALSE_VALUES: [&CStr; 6] = [c"0", c"no", c"n", c"false", c"f", c"off"];

fn parse_boolean_inner(v: &[u8]) -> i32 {
    if strcase_in_set(v, &TRUE_VALUES) {
        return 1;
    }

    if strcase_in_set(v, &FALSE_VALUES) {
        return 0;
    }

    Errno::EINVAL.to_neg_errno()
}

/// Parse a boolean string ("yes", "no", "true", "false", "1", "0", etc.).
/// Returns 1 for true, 0 for false, negative errno on invalid input.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_boolean(v: *const c_char) -> i32 {
    // SAFETY: the ABI contract guarantees that a non-null input is a C string.
    match unsafe_ffi!(cstr_bytes(v)) {
        Ok(bytes) => parse_boolean_inner(bytes),
        Err(error) => error,
    }
}

// ── safe_atou_full ────────────────────────────────────────────────────────

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub(crate) unsafe fn safe_atou_full_inner(s: *const c_char, base: u32, ret_u: *mut u32) -> i32 {
    if safe_ato_mask_flags(base) > 16 {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: upheld by this function's C-string contract.
    let Ok(bytes) = (unsafe_ffi!(cstr_bytes(s))) else {
        return Errno::EINVAL.to_neg_errno();
    };
    if flags_set(base, SAFE_ATO_REFUSE_LEADING_WHITESPACE)
        && bytes.first().is_some_and(|byte| is_whitespace(*byte))
    {
        return Errno::EINVAL.to_neg_errno();
    }
    let bytes = skip_whitespace(bytes);
    if flags_set(base, SAFE_ATO_REFUSE_PLUS_MINUS)
        && bytes.first().is_some_and(|byte| in_set(*byte, b"+-"))
    {
        return Errno::EINVAL.to_neg_errno();
    }
    if flags_set(base, SAFE_ATO_REFUSE_LEADING_ZERO)
        && bytes.first() == Some(&b'0')
        && bytes.len() > 1
    {
        return Errno::EINVAL.to_neg_errno();
    }
    let mut mang_base = base;
    let bytes = mangle_base(bytes, &mut mang_base);
    let value = match parse_unsigned(bytes, safe_ato_mask_flags(mang_base), u32::MAX as u64) {
        Ok(value) => value,
        Err(error) => return error,
    };

    if !ret_u.is_null() {
        // SAFETY: the caller guarantees non-null ret_u is writable.
        unsafe_ffi!(*ret_u = value as u32);
    }
    0
}

/// Parse an unsigned integer from string s with the given base and flags.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atou_full(s: *const c_char, base: u32, ret_u: *mut u32) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(safe_atou_full_inner(s, base, ret_u))
}

/// Parse an unsigned integer from string s.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atou(s: *const c_char, ret_u: *mut u32) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(safe_atou_full_inner(s, 0, ret_u))
}

/// Parse an unsigned integer from string s, bounded between min and max.
/// Returns 0 on success, negative errno on failure or out of range.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atou_bounded(
    s: *const c_char,
    min: u32,
    max: u32,
    ret: *mut u32,
) -> i32 {
    let mut v: u32 = 0;
    // SAFETY: s is caller-validated and v is a live writable local.
    let r = unsafe_ffi!(safe_atou_full_inner(s, 0, &mut v));
    if r < 0 {
        return r;
    }
    if v < min || v > max {
        return Errno::ERANGE.to_neg_errno();
    }
    if !ret.is_null() {
        // SAFETY: the caller guarantees non-null ret is writable.
        unsafe_ffi!(*ret = v);
    }
    0
}

/// Parse an unsigned 8-bit integer from string s with the given base.
/// Returns 0 on success, negative errno on failure or out of range.
/// Parse an unsigned 8-bit integer from string s with the given base.
/// Returns 0 on success, negative errno on failure or out of range.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atou8_full(s: *const c_char, base: u32, ret: *mut u8) -> i32 {
    let mut u: u32 = 0;
    // SAFETY: s is caller-validated and u is a live writable local.
    let r = unsafe_ffi!(safe_atou_full_inner(s, base, &mut u));
    if r < 0 {
        return r;
    }
    if u > 255 {
        return Errno::ERANGE.to_neg_errno();
    }
    if !ret.is_null() {
        // SAFETY: the caller guarantees non-null ret is writable.
        unsafe_ffi!(*ret = u as u8);
    }
    0
}

/// Parse an unsigned 16-bit integer from string s with the given base.
/// Returns 0 on success, negative errno on failure or out of range.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atou16_full(s: *const c_char, base: u32, ret: *mut u16) -> i32 {
    let mut u: u32 = 0;
    // SAFETY: s is caller-validated and u is a live writable local.
    let r = unsafe_ffi!(safe_atou_full_inner(s, base, &mut u));
    if r < 0 {
        return r;
    }
    if u > 65535 {
        return Errno::ERANGE.to_neg_errno();
    }
    if !ret.is_null() {
        // SAFETY: the caller guarantees non-null ret is writable.
        unsafe_ffi!(*ret = u as u16);
    }
    0
}

// ── safe_atoi ─────────────────────────────────────────────────────────────

// SAFETY: callers pass either NULL (rejected) or a readable NUL-terminated C string;
// a non-NULL output is writable for one i32 and is only published on success.
unsafe fn safe_atoi_inner(s: *const c_char, ret_i: *mut i32) -> i32 {
    // SAFETY: upheld by this function's C-string contract.
    let Ok(bytes) = (unsafe_ffi!(cstr_bytes(s))) else {
        return Errno::EINVAL.to_neg_errno();
    };
    let bytes = skip_whitespace(bytes);
    let mut base: u32 = 0;
    let bytes = mangle_base(bytes, &mut base);
    let value = match parse_signed(bytes, base, c_long::MIN as i64, c_long::MAX as i64) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if value < i32::MIN as i64 || value > i32::MAX as i64 {
        return Errno::ERANGE.to_neg_errno();
    }

    if !ret_i.is_null() {
        // SAFETY: the caller guarantees non-null ret_i is writable.
        unsafe_ffi!(*ret_i = value as i32);
    }
    0
}

/// Parse a signed integer from string s.
/// Returns 0 on success, negative errno on failure.
/// Parse a signed integer from string s.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atoi(s: *const c_char, ret_i: *mut i32) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(safe_atoi_inner(s, ret_i))
}

/// Parse a signed 16-bit integer from string s.
/// Returns 0 on success, negative errno on failure or out of range.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atoi16(s: *const c_char, ret: *mut i16) -> i32 {
    // SAFETY: upheld by this export's C-string contract.
    let Ok(bytes) = (unsafe_ffi!(cstr_bytes(s))) else {
        return Errno::EINVAL.to_neg_errno();
    };
    let mut base = 0;
    let bytes = mangle_base(skip_whitespace(bytes), &mut base);
    let value = match parse_signed(bytes, base, i16::MIN as i64, i16::MAX as i64) {
        Ok(value) => value,
        Err(error) => return error,
    };
    if value < i16::MIN as i64 || value > i16::MAX as i64 {
        return Errno::ERANGE.to_neg_errno();
    }

    if !ret.is_null() {
        // SAFETY: the caller guarantees non-null ret is writable.
        unsafe_ffi!(*ret = value as i16);
    }
    0
}

// ── safe_atolli ───────────────────────────────────────────────────────────

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub(crate) unsafe fn safe_atolli_inner(s: *const c_char, ret_lli: *mut i64) -> i32 {
    // SAFETY: upheld by this function's C-string contract.
    let Ok(bytes) = (unsafe_ffi!(cstr_bytes(s))) else {
        return Errno::EINVAL.to_neg_errno();
    };
    let bytes = skip_whitespace(bytes);
    let mut base: u32 = 0;
    let bytes = mangle_base(bytes, &mut base);
    let value = match parse_signed(bytes, base, i64::MIN, i64::MAX) {
        Ok(value) => value,
        Err(error) => return error,
    };

    if !ret_lli.is_null() {
        // SAFETY: the caller guarantees non-null ret_lli is writable.
        unsafe_ffi!(*ret_lli = value);
    }
    0
}

/// Parse a signed 64-bit integer from string s.
/// Returns 0 on success, negative errno on failure.
/// Parse a signed 64-bit integer from string s.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atolli(s: *const c_char, ret_lli: *mut i64) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(safe_atolli_inner(s, ret_lli))
}

// ── safe_atollu_full ──────────────────────────────────────────────────────

///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
pub(crate) unsafe fn safe_atollu_full_inner(s: *const c_char, base: u32, ret_llu: *mut u64) -> i32 {
    if safe_ato_mask_flags(base) > 16 {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: upheld by this function's C-string contract.
    let Ok(bytes) = (unsafe_ffi!(cstr_bytes(s))) else {
        return Errno::EINVAL.to_neg_errno();
    };
    if flags_set(base, SAFE_ATO_REFUSE_LEADING_WHITESPACE)
        && bytes.first().is_some_and(|byte| is_whitespace(*byte))
    {
        return Errno::EINVAL.to_neg_errno();
    }
    let bytes = skip_whitespace(bytes);
    if flags_set(base, SAFE_ATO_REFUSE_PLUS_MINUS)
        && bytes.first().is_some_and(|byte| in_set(*byte, b"+-"))
    {
        return Errno::EINVAL.to_neg_errno();
    }
    if flags_set(base, SAFE_ATO_REFUSE_LEADING_ZERO)
        && bytes.first() == Some(&b'0')
        && bytes.len() > 1
    {
        return Errno::EINVAL.to_neg_errno();
    }
    let mut mang_base = base;
    let bytes = mangle_base(bytes, &mut mang_base);
    let value = match parse_unsigned(bytes, safe_ato_mask_flags(mang_base), u64::MAX) {
        Ok(value) => value,
        Err(error) => return error,
    };

    if !ret_llu.is_null() {
        // SAFETY: the caller guarantees non-null ret_llu is writable.
        unsafe_ffi!(*ret_llu = value);
    }
    0
}

/// Parse an unsigned 64-bit integer from string s with the given base.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atollu_full(
    s: *const c_char,
    base: u32,
    ret_llu: *mut u64,
) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(safe_atollu_full_inner(s, base, ret_llu))
}

/// Parse an unsigned 64-bit integer from string s.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atollu(s: *const c_char, ret_llu: *mut u64) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(safe_atollu_full_inner(s, 0, ret_llu))
}

/// Parse an unsigned 64-bit integer from string s.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atou64(s: *const c_char, ret_u: *mut u64) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(safe_atollu_full_inner(s, 0, ret_u))
}

/// Parse a signed 64-bit integer from string s.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atoi64(s: *const c_char, ret_i: *mut i64) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(safe_atolli_inner(s, ret_i))
}

/// Parse an unsigned 64-bit hexadecimal integer from string s.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atoux64(s: *const c_char, ret: *mut u64) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(safe_atollu_full_inner(s, 16, ret))
}

/// Parse an unsigned 8-bit integer from string s.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atou8(s: *const c_char, ret: *mut u8) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(rs_safe_atou8_full(s, 0, ret))
}

/// Parse an unsigned 16-bit integer from string s.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atou16(s: *const c_char, ret: *mut u16) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(rs_safe_atou16_full(s, 0, ret))
}

/// Parse an unsigned 16-bit hexadecimal integer from string s.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atoux16(s: *const c_char, ret: *mut u16) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(rs_safe_atou16_full(s, 16, ret))
}

/// Parse an unsigned 32-bit integer from string s.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atou32(s: *const c_char, ret_u: *mut u32) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(safe_atou_full_inner(s, 0, ret_u))
}

/// Parse a signed 32-bit integer from string s.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atoi32(s: *const c_char, ret_i: *mut i32) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(safe_atoi_inner(s, ret_i))
}

/// Parse an unsigned long integer from string s with specified base.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atolu_full(
    s: *const c_char,
    base: u32,
    ret_u: *mut c_ulong,
) -> i32 {
    let mut parsed = 0u64;
    // SAFETY: s follows this function's C-string contract and parsed is a
    // writable full-width intermediate.
    let r = unsafe_ffi!(safe_atollu_full_inner(s, base, &mut parsed));
    if r < 0 {
        return r;
    }
    if parsed > c_ulong::MAX as u64 {
        return Errno::ERANGE.to_neg_errno();
    }
    if !ret_u.is_null() {
        // SAFETY: the caller guarantees non-null ret_u is writable.
        unsafe_ffi!(*ret_u = parsed as c_ulong);
    }
    0
}

/// Parse an unsigned long integer from string s.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atolu(s: *const c_char, ret_u: *mut c_ulong) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(rs_safe_atolu_full(s, 0, ret_u))
}

/// Parse a signed long integer from string s.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atoli(s: *const c_char, ret_u: *mut c_long) -> i32 {
    let mut parsed = 0i64;
    // SAFETY: s follows this function's C-string contract and parsed is a
    // writable full-width intermediate.
    let r = unsafe_ffi!(safe_atolli_inner(s, &mut parsed));
    if r < 0 {
        return r;
    }
    if parsed < c_long::MIN as i64 || parsed > c_long::MAX as i64 {
        return Errno::ERANGE.to_neg_errno();
    }
    if !ret_u.is_null() {
        // SAFETY: the caller guarantees non-null ret_u is writable.
        unsafe_ffi!(*ret_u = parsed as c_long);
    }
    0
}

/// Parse an unsigned size_t value from string s.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_safe_atozu(s: *const c_char, ret_u: *mut usize) -> i32 {
    let mut parsed: c_ulong = 0;
    // SAFETY: `s` follows this function's C-string contract and `parsed` is a
    // live, correctly aligned `u64` output.
    let result = unsafe_ffi!(rs_safe_atolu(s, &mut parsed));
    if result < 0 {
        return result;
    }
    let Ok(value) = usize::try_from(parsed) else {
        return Errno::ERANGE.to_neg_errno();
    };
    if !ret_u.is_null() {
        // SAFETY: the caller guarantees that non-null `ret_u` is writable and
        // correctly aligned for `usize`.
        unsafe_ffi!(*ret_u = value);
    }
    0
}

/// Parse a tristate value: -1 for empty, 0/1 for boolean.
/// Returns 0 on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_tristate(v: *const c_char, ret: *mut i32) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(rs_parse_tristate_full(v, std::ptr::null(), ret))
}

// ── parse_size ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct SizeEntry {
    suffix: &'static CStr,
    factor: u64,
}

const IEC_TABLE: [SizeEntry; 8] = [
    SizeEntry {
        suffix: c"E",
        factor: 1024_u64 * 1024 * 1024 * 1024 * 1024 * 1024,
    },
    SizeEntry {
        suffix: c"P",
        factor: 1024_u64 * 1024 * 1024 * 1024 * 1024,
    },
    SizeEntry {
        suffix: c"T",
        factor: 1024_u64 * 1024 * 1024 * 1024,
    },
    SizeEntry {
        suffix: c"G",
        factor: 1024_u64 * 1024 * 1024,
    },
    SizeEntry {
        suffix: c"M",
        factor: 1024_u64 * 1024,
    },
    SizeEntry {
        suffix: c"K",
        factor: 1024_u64,
    },
    SizeEntry {
        suffix: c"B",
        factor: 1,
    },
    SizeEntry {
        suffix: c"",
        factor: 1,
    },
];

const SI_TABLE: [SizeEntry; 8] = [
    SizeEntry {
        suffix: c"E",
        factor: 1000_u64 * 1000 * 1000 * 1000 * 1000 * 1000,
    },
    SizeEntry {
        suffix: c"P",
        factor: 1000_u64 * 1000 * 1000 * 1000 * 1000,
    },
    SizeEntry {
        suffix: c"T",
        factor: 1000_u64 * 1000 * 1000 * 1000,
    },
    SizeEntry {
        suffix: c"G",
        factor: 1000_u64 * 1000 * 1000,
    },
    SizeEntry {
        suffix: c"M",
        factor: 1000_u64 * 1000,
    },
    SizeEntry {
        suffix: c"K",
        factor: 1000_u64,
    },
    SizeEntry {
        suffix: c"B",
        factor: 1,
    },
    SizeEntry {
        suffix: c"",
        factor: 1,
    },
];

/// Check if byte at `s` starts with the CStr suffix.
// SAFETY: callers provide a readable NUL-terminated string at s; this helper
// reads only through its terminator while comparing a Rust-owned suffix.
unsafe fn startswith_cstr(s: *const c_char, suffix: &CStr) -> bool {
    let suffix_bytes = suffix.to_bytes();
    let mut i = 0;
    loop {
        if i >= suffix_bytes.len() {
            return true;
        }
        // SAFETY: the caller guarantees s is readable through its NUL terminator.
        if unsafe_ffi!(*s.add(i)) == 0 {
            return false;
        }
        // SAFETY: the preceding check proved this byte is before the terminator.
        if unsafe_ffi!(*s.add(i)) as u8 != suffix_bytes[i] {
            return false;
        }
        i += 1;
    }
}

// SAFETY: t is NULL-checked before C-string reads; a non-NULL size points to
// writable u64 storage and is updated only after successful parsing.
unsafe fn parse_size_inner(t: *const c_char, base: u64, size: *mut u64) -> i32 {
    if t.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    if base != 1000 && base != 1024 {
        return Errno::EINVAL.to_neg_errno();
    }
    if size.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let table: &[SizeEntry] = if base == 1000 { &SI_TABLE } else { &IEC_TABLE };
    let n_entries = table.len();
    let mut start_pos: usize = 0;
    let mut p = t;
    let mut r: u64 = 0;

    loop {
        // Skip whitespace
        // SAFETY: p remains within the caller's C string.
        p = unsafe_ffi!(skip_whitespace_ptr(p));

        let mut x: *mut c_char = std::ptr::null_mut();
        clear_errno();
        // SAFETY: p is a live C string and x is a writable end-pointer.
        let l = unsafe_ffi!(crate::ffi::strtoull(p, &mut x, 10));
        let errno_val = get_errno();
        if errno_val > 0 {
            return -errno_val;
        }
        if x as *const c_char == p {
            return Errno::EINVAL.to_neg_errno();
        }
        // SAFETY: p remains within the caller's C string.
        if (unsafe_ffi!(*p) as u8) == b'-' {
            return Errno::ERANGE.to_neg_errno();
        }

        // Handle fractional part
        let mut frac: f64 = 0.0;
        let mut e = x;
        // SAFETY: e is the end-pointer returned within p.
        if (unsafe_ffi!(*e) as u8) == b'.' {
            // SAFETY: the dot is before the terminating NUL.
            e = unsafe_ffi!(e.add(1));
            // SAFETY: e remains within the C string.
            if (unsafe_ffi!(*e) as u8).is_ascii_digit() {
                let mut x2: *mut c_char = std::ptr::null_mut();
                clear_errno();
                // SAFETY: e is a live suffix C string and x2 is a writable end-pointer.
                let l2 = unsafe_ffi!(crate::ffi::strtoull(e, &mut x2, 10));
                let errno_val2 = get_errno();
                if errno_val2 > 0 {
                    return -errno_val2;
                }
                frac = l2 as f64;
                while e < x2 {
                    frac /= 10.0;
                    // SAFETY: e < x2 and both point within the same C string.
                    e = unsafe_ffi!(e.add(1));
                }
            }
        }

        // Skip whitespace after number
        // SAFETY: e remains within the caller's C string.
        e = unsafe_ffi!(skip_whitespace_ptr(e)).cast_mut();

        // Find matching suffix
        let mut i = start_pos;
        let mut found = false;
        while i < n_entries {
            // SAFETY: e is a live suffix C string.
            if unsafe_ffi!(startswith_cstr(e, table[i].suffix)) {
                found = true;
                break;
            }
            i += 1;
        }
        if !found {
            return Errno::EINVAL.to_neg_errno();
        }

        let factor = table[i].factor;
        if l.saturating_add(if frac > 0.0 { 1 } else { 0 }) > u64::MAX / factor {
            return Errno::ERANGE.to_neg_errno();
        }
        let tmp = l * factor + (frac * factor as f64) as u64;
        if tmp > u64::MAX - r {
            return Errno::ERANGE.to_neg_errno();
        }
        r += tmp;

        // SAFETY: the selected suffix was just matched at e.
        p = unsafe_ffi!(e.add(table[i].suffix.to_bytes().len()));
        start_pos = i + 1;

        // SAFETY: p remains within the caller's C string.
        if unsafe_ffi!(*p) == 0 {
            break;
        }
    }

    // SAFETY: size is non-null and writable by the caller contract.
    unsafe_ffi!(*size = r);
    0
}

/// Parse a size string (e.g., "1K", "2M") into bytes.
/// Returns 0 on success, negative errno on failure.
/// The parsed value is written to `*size` (allocated by caller).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_size(t: *const c_char, base: u64, size: *mut u64) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(parse_size_inner(t, base, size))
}

/// Safe Rust facade for the C-compatible size grammar.
///
/// `base` must be either 1000 (SI, used by I/O limits) or 1024 (IEC, used by
/// memory limits). The returned error is a negative errno, matching the C
/// parser and the FFI entry point above.
pub fn parse_size(value: &str, base: u64) -> Result<u64, i32> {
    if !matches!(base, 1000 | 1024) {
        return Err(Errno::EINVAL.to_neg_errno());
    }
    let value = CString::new(value).map_err(|_| Errno::EINVAL.to_neg_errno())?;
    let mut parsed = 0;
    // SAFETY: `value` is NUL-terminated and `parsed` is a live writable u64.
    let result = unsafe_ffi!(rs_parse_size(value.as_ptr(), base, &mut parsed));
    if result < 0 { Err(result) } else { Ok(parsed) }
}

// ── Higher-level parsers ───────────────────────────────────────────────────

// SAFETY: s is NULL-checked before C-string reads and non-NULL ret is writable
// i32 storage; the result is published only after all validation succeeds.
unsafe fn parse_pid_inner(s: *const c_char, ret: *mut i32) -> i32 {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut x: *mut c_char = std::ptr::null_mut();
    clear_errno();
    // SAFETY: s is a live C string and x is a writable end-pointer.
    let ul = unsafe_ffi!(crate::ffi::strtoul(s, &mut x, 10));
    let errno_val = get_errno();
    if errno_val > 0 {
        return -errno_val;
    }
    // SAFETY: a non-null x returned by strtoul points within s.
    if x.is_null() || x as *const c_char == s || unsafe_ffi!(*x) != 0 {
        return Errno::EINVAL.to_neg_errno();
    }
    let pid = ul as i32;
    if ul as u64 != (pid as u64) {
        return Errno::ERANGE.to_neg_errno();
    }

    // pid_is_valid: on Linux, PIDs must be > 0
    if pid <= 0 {
        return Errno::ERANGE.to_neg_errno();
    }

    if !ret.is_null() {
        // SAFETY: the caller guarantees non-null ret is writable.
        unsafe_ffi!(*ret = pid);
    }
    0
}

/// Parse a PID string into an integer.
/// Returns 0 on success, negative errno on failure.
/// The parsed value is written to `*ret` (allocated by caller).
/// Parse a PID string into an integer.
/// Returns 0 on success, negative errno on failure.
/// The parsed value is written to `*ret` (allocated by caller).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_pid(s: *const c_char, ret: *mut i32) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(parse_pid_inner(s, ret))
}

// SAFETY: s is NULL-checked before C-string reads and non-NULL ret is writable
// u32 storage; the result is published only after successful validation.
unsafe fn parse_mode_inner(s: *const c_char, ret: *mut u32) -> i32 {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut m: u32 = 0;
    // SAFETY: s is caller-validated and m is a live writable local.
    let r = unsafe_ffi!(safe_atou_full_inner(
        s,
        8 | SAFE_ATO_REFUSE_PLUS_MINUS,
        &mut m
    ));
    if r < 0 {
        return r;
    }
    if m > 0o7777 {
        return Errno::ERANGE.to_neg_errno();
    }

    if !ret.is_null() {
        // SAFETY: the caller guarantees non-null ret is writable.
        unsafe_ffi!(*ret = m);
    }
    0
}

/// Parse a file mode string (octal) into a mode value.
/// Returns 0 on success, negative errno on failure.
/// The parsed value is written to `*ret` (allocated by caller).
/// Parse a file mode string (octal) into a mode value.
/// Returns 0 on success, negative errno on failure.
/// The parsed value is written to `*ret` (allocated by caller).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_mode(s: *const c_char, ret: *mut u32) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(parse_mode_inner(s, ret))
}

// SAFETY: s is NULL-checked and otherwise denotes a readable NUL-terminated C string.
unsafe fn parse_ifindex_inner(s: *const c_char) -> i32 {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut ifi: i32 = 0;
    // SAFETY: s is caller-validated and ifi is a live writable local.
    let r = unsafe_ffi!(safe_atoi_inner(s, &mut ifi));
    if r < 0 {
        return r;
    }
    if ifi <= 0 {
        return Errno::EINVAL.to_neg_errno();
    }

    ifi
}

/// Parse a network interface index string into an integer.
/// Returns the interface index on success, negative errno on failure.
/// Parse a network interface index string into an integer.
/// Returns the interface index on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_ifindex(s: *const c_char) -> i32 {
    // SAFETY: this function forwards its C-string contract unchanged.
    unsafe_ffi!(parse_ifindex_inner(s))
}

// SAFETY: s is NULL-checked and otherwise denotes a readable NUL-terminated C string.
unsafe fn parse_fd_inner(s: *const c_char) -> i32 {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut fd: i32 = 0;
    // SAFETY: s is caller-validated and fd is a live writable local.
    let r = unsafe_ffi!(safe_atoi_inner(s, &mut fd));
    if r < 0 {
        return r;
    }
    if fd < 0 {
        return Errno::EBADF.to_neg_errno();
    }

    fd
}

/// Parse a file descriptor string into an integer.
/// Returns the file descriptor on success, negative errno on failure.
/// Parse a file descriptor string into an integer.
/// Returns the file descriptor on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_fd(s: *const c_char) -> i32 {
    // SAFETY: this function forwards its C-string contract unchanged.
    unsafe_ffi!(parse_fd_inner(s))
}

// SAFETY: s is NULL-checked and otherwise denotes a readable NUL-terminated C string.
unsafe fn parse_errno_inner(s: *const c_char) -> i32 {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: `s` is non-null and the caller guarantees a live
    // NUL-terminated string.
    let r = match unsafe_ffi!(cstr_bytes(s)) {
        Ok(bytes) => errno_from_name(bytes),
        Err(error) => return error,
    };
    if r > 0 {
        return r;
    }

    let mut e: i32 = 0;
    // SAFETY: s is caller-validated and e is a live writable local.
    let r2 = unsafe_ffi!(safe_atoi_inner(s, &mut e));
    if r2 < 0 {
        return r2;
    }

    if !errno_is_valid(e) && e != 0 {
        return Errno::ERANGE.to_neg_errno();
    }

    e
}

/// Parse an errno name or number string into an errno value.
/// Returns the errno value on success, negative errno on failure.
/// Parse an errno name or number string into an errno value.
/// Returns the errno value on success, negative errno on failure.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_errno(s: *const c_char) -> i32 {
    // SAFETY: this function forwards its C-string contract unchanged.
    unsafe_ffi!(parse_errno_inner(s))
}

// SAFETY: s is NULL-checked before C-string reads and non-NULL ret is writable
// i32 storage; the result is published only after range validation.
unsafe fn parse_nice_inner(s: *const c_char, ret: *mut i32) -> i32 {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut n: i32 = 0;
    // SAFETY: s is caller-validated and n is a live writable local.
    let r = unsafe_ffi!(safe_atoi_inner(s, &mut n));
    if r < 0 {
        return r;
    }

    if !nice_is_valid(n) {
        return Errno::ERANGE.to_neg_errno();
    }

    if !ret.is_null() {
        // SAFETY: the caller guarantees non-null ret is writable.
        unsafe_ffi!(*ret = n);
    }
    0
}

/// Parse a nice value string into an integer.
/// Returns 0 on success, negative errno on failure.
/// The parsed value is written to `*ret` (allocated by caller).
/// Parse a nice value string into an integer.
/// Returns 0 on success, negative errno on failure.
/// The parsed value is written to `*ret` (allocated by caller).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_nice(s: *const c_char, ret: *mut i32) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(parse_nice_inner(s, ret))
}

// ── parse_oom_score_adjust ──────────────────────────────────────────────

fn rs_oom_score_adjust_is_valid(oa: i32) -> bool {
    oom_score_adjust_is_valid_rs(oa)
}

// SAFETY: s and ret are NULL-checked; s is a readable C string and ret is
// writable i32 storage, published only after all parsing succeeds.
unsafe fn parse_oom_score_adjust_inner(s: *const c_char, ret: *mut i32) -> i32 {
    if s.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut v: i32 = 0;
    // SAFETY: s is caller-validated and v is a live writable local.
    let r = unsafe_ffi!(rs_safe_atoi(s, &mut v));
    if r < 0 {
        return r;
    }
    if !rs_oom_score_adjust_is_valid(v) {
        return Errno::ERANGE.to_neg_errno();
    }
    // SAFETY: ret is non-null and writable by the caller contract.
    unsafe_ffi!(*ret = v);
    0
}

/// Parse an OOM score adjust string into an integer.
/// Returns 0 on success, negative errno on failure.
/// The parsed value is written to `*ret` (allocated by caller).
///
/// # Safety
/// `s` must be a non-null readable NUL-terminated string and `ret` must point
/// to writable, properly aligned `int` storage.
#[unsafe(export_name = "rs_parse_oom_score_adjust")]
pub unsafe extern "C" fn rs_parse_oom_score_adjust(s: *const c_char, ret: *mut i32) -> i32 {
    // SAFETY: the C ABI contract above implies the inner pointer contract.
    unsafe_ffi!(parse_oom_score_adjust_inner(s, ret))
}

// SAFETY: s is NULL-checked before C-string reads and non-NULL ret is writable
// u16 storage; the parsed port is published only on success.
unsafe fn parse_ip_port_inner(s: *const c_char, ret: *mut u16) -> i32 {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut l: u16 = 0;
    // SAFETY: s is caller-validated and l is a live writable local.
    let r = unsafe_ffi!(rs_safe_atou16_full(
        s,
        SAFE_ATO_REFUSE_LEADING_WHITESPACE,
        &mut l
    ));
    if r < 0 {
        return r;
    }

    if l == 0 {
        return Errno::EINVAL.to_neg_errno();
    }

    if !ret.is_null() {
        // SAFETY: the caller guarantees non-null ret is writable.
        unsafe_ffi!(*ret = l);
    }
    0
}

/// Parse an IP port string into a u16 value.
/// Returns 0 on success, negative errno on failure.
/// The parsed value is written to `*ret` (allocated by caller).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_ip_port(s: *const c_char, ret: *mut u16) -> i32 {
    // SAFETY: this function forwards its input/output contracts unchanged.
    unsafe_ffi!(parse_ip_port_inner(s, ret))
}

// ── parse_range ─────────────────────────────────────────────────────────
// From src/basic/parse-util.c

/// Parse a range like "5-10" into lower and upper bounds.
/// Parses a range like "5-10" into lower and upper bounds.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_range(t: *const c_char, lower: *mut u32, upper: *mut u32) -> i32 {
    if lower.is_null() || upper.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    if t.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut p = t;
    let pp = &mut p as *mut *const c_char;
    let sep = c"-";
    let flags: u32 = 64; // EXTRACT_DONT_COALESCE_SEPARATORS = 1 << 6

    let mut word: *mut c_char = std::ptr::null_mut();
    // SAFETY: pp/word are writable locals, t is a live C string, and sep is static.
    let r = unsafe_ffi!(crate::extract_word::rs_extract_first_word(
        pp,
        &mut word,
        sep.as_ptr(),
        flags
    ));
    if r < 0 {
        return r;
    }
    if r == 0 {
        return Errno::EINVAL.to_neg_errno();
    }

    // Parse lower bound
    let mut l: u32 = 0;
    // SAFETY: word is the live C string allocated by rs_extract_first_word.
    let r2 = unsafe_ffi!(rs_safe_atou(word, &mut l));
    // SAFETY: `rs_extract_first_word` allocated `word` with the C allocator
    // and this function still owns the returned allocation.
    unsafe_ffi!(crate::ffi::free(word as *mut std::ffi::c_void));
    if r2 < 0 {
        return r2;
    }

    // Check for upper bound
    // SAFETY: pp points to the live local p.
    let p2 = unsafe_ffi!(*pp);
    if p2.is_null() {
        // Single number
        // SAFETY: upper is non-null and writable by the caller contract.
        unsafe_ffi!(*upper = l);
    // SAFETY: p2 is the remaining in-bounds position in t.
    } else if unsafe_ffi!(*p2) == 0 {
        // Trailing dash is an error
        return Errno::EINVAL.to_neg_errno();
    } else {
        let mut u: u32 = 0;
        // SAFETY: p2 is a live C-string suffix and u is a writable local.
        let r3 = unsafe_ffi!(rs_safe_atou(p2, &mut u));
        if r3 < 0 {
            return r3;
        }
        // SAFETY: upper is non-null and writable by the caller contract.
        unsafe_ffi!(*upper = u);
    }

    // SAFETY: lower is non-null and writable by the caller contract.
    unsafe_ffi!(*lower = l);
    0
}

// ── parse_ip_port_range ─────────────────────────────────────────────────

// SAFETY: s is NULL-checked before C-string reads; any non-NULL output points
// to writable u16 storage and is not updated until the full range is valid.
unsafe fn parse_ip_port_range_inner(
    s: *const c_char,
    low: *mut u16,
    high: *mut u16,
    allow_zero: bool,
) -> i32 {
    if low.is_null() || high.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut l: u32 = 0;
    let mut h: u32 = 0;
    // SAFETY: s is caller-validated and l/h are writable locals.
    let r = unsafe_ffi!(rs_parse_range(s, &mut l, &mut h));
    if r < 0 {
        return r;
    }
    if l > 65535 || h > 65535 {
        return Errno::EINVAL.to_neg_errno();
    }
    if !allow_zero && (l == 0 || h == 0) {
        return Errno::EINVAL.to_neg_errno();
    }
    if h < l {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: low/high are non-null and writable by the caller contract.
    unsafe {
        *low = l as u16;
        *high = h as u16;
    }
    0
}

/// Parse an IP port range string (e.g., "1000-2000") into low/high values.
/// Returns 0 on success, negative errno on failure.
/// The parsed values are written to `*low` and `*high` (allocated by caller).
///
/// # Safety
/// `s` must be a non-null readable NUL-terminated string. `low` and `high`
/// must point to writable, properly aligned `uint16_t` storage.
#[unsafe(export_name = "rs_parse_ip_port_range")]
pub unsafe extern "C" fn rs_parse_ip_port_range(
    s: *const c_char,
    low: *mut u16,
    high: *mut u16,
    allow_zero: bool,
) -> i32 {
    // SAFETY: the C ABI contract above implies the inner pointer contract.
    unsafe_ffi!(parse_ip_port_range_inner(s, low, high, allow_zero))
}

// ── parse_tristate_full ────────────────────────────────────────────────────
// From src/basic/parse-util.c

/// Parse a tristate: empty/third → -1, boolean strings → 0/1.
/// Returns 0 on success, negative errno on failure.
/// The parsed value is written to `*ret` (allocated by caller).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_tristate_full(
    v: *const c_char,
    third: *const c_char,
    ret: *mut i32,
) -> i32 {
    // NULL or empty string matches the "third" state
    let v_bytes = if v.is_null() {
        &[] as &[u8]
    } else {
        // SAFETY: the caller guarantees non-null v is a live C string.
        unsafe_ffi!(CStr::from_ptr(v)).to_bytes()
    };
    if v_bytes.is_empty()
        || (!third.is_null()
            // SAFETY: the caller guarantees non-null third is a live C string.
            && v_bytes == unsafe_ffi!(CStr::from_ptr(third)).to_bytes())
    {
        if !ret.is_null() {
            // SAFETY: the caller guarantees non-null ret is writable.
            unsafe_ffi!(*ret = -1);
        }
        return 0;
    }

    // SAFETY: v is the caller-validated C string.
    let r = unsafe_ffi!(rs_parse_boolean(v));
    if r < 0 {
        return r;
    }

    if !ret.is_null() {
        // SAFETY: the caller guarantees non-null ret is writable.
        unsafe_ffi!(*ret = r);
    }

    0
}

// ── parse_mtu ──────────────────────────────────────────────────────────────
// From src/basic/parse-util.c

/// Parse an MTU value with family-specific minimum validation.
/// Parses an MTU value with family-specific minimum validation.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_mtu(family: i32, s: *const c_char, ret: *mut u32) -> i32 {
    if s.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut u: u64 = 0;
    // SAFETY: s is caller-validated and u is a live writable local.
    let r = unsafe_ffi!(rs_parse_size(s, 1024, &mut u));
    if r < 0 {
        return r;
    }

    if u > u32::MAX as u64 {
        return Errno::ERANGE.to_neg_errno();
    }

    let m: u64 = match family {
        2 => 68,    // AF_INET → IPV4_MIN_MTU
        10 => 1280, // AF_INET6 → IPV6_MIN_MTU
        _ => 0,
    };

    if u < m {
        return Errno::ERANGE.to_neg_errno();
    }

    // SAFETY: ret is non-null and writable by the caller contract.
    unsafe_ffi!(*ret = u as u32);
    0
}

// ── parse_sector_size ──────────────────────────────────────────────────────
// From src/basic/parse-util.c

/// Parse a sector size: must be power-of-2 between 512 and 4096.
/// Parses a sector size: must be power-of-2 between 512 and 4096.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_sector_size(t: *const c_char, ret: *mut u64) -> i32 {
    if t.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut ss: u64 = 0;
    // SAFETY: t is caller-validated and ss is a live writable local.
    let r = unsafe_ffi!(rs_safe_atou64(t, &mut ss));
    if r < 0 {
        return r;
    }

    if ss < 512 || ss > 4096 {
        return Errno::ERANGE.to_neg_errno();
    }

    // ISPOWEROF2 check: exactly one bit set
    if ss == 0 || (ss & (ss - 1)) != 0 {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: ret is non-null and writable by the caller contract.
    unsafe_ffi!(*ret = ss);
    0
}

// ── store_loadavg_fixed_point / parse_loadavg_fixed_point ─────────────────
// From src/basic/parse-util.c

const LOADAVG_PRECISION_BITS: u32 = 11;
const LOADAVG_FIXED_POINT_1_0: u64 = 1u64 << LOADAVG_PRECISION_BITS;

/// Store a loadavg value in fixed-point format (11 bits of fractional precision).
/// Stores a loadavg value in fixed-point format (11 bits of fractional precision).
pub(crate) fn store_loadavg_fixed_point_inner(i: c_ulong, f: c_ulong) -> Option<c_ulong> {
    let precision = LOADAVG_PRECISION_BITS;
    let shift_mask = c_ulong::MAX.wrapping_shl(precision);

    if i >= shift_mask {
        return None; // -ERANGE
    }

    let i = i << precision;
    // DIV_ROUND_UP(f << precision, 100) = (f << precision + 99) / 100
    let f_shifted = f.wrapping_shl(precision).wrapping_add(99) / 100;

    if f_shifted >= LOADAVG_FIXED_POINT_1_0 as c_ulong {
        return None; // -ERANGE
    }

    Some(i | f_shifted)
}

/// Store a loadavg value in fixed-point format (11 bits of fractional precision).
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_store_loadavg_fixed_point(
    i: c_ulong,
    f: c_ulong,
    ret: *mut c_ulong,
) -> i32 {
    if ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    match store_loadavg_fixed_point_inner(i, f) {
        Some(val) => {
            // SAFETY: ret is non-null and writable by the caller contract.
            unsafe_ffi!(*ret = val);
            0
        }
        None => Errno::ERANGE.to_neg_errno(),
    }
}

/// Parse a loadavg string like "0.45" into fixed-point format.
/// Parses a loadavg string like "0.45" into fixed-point format.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_loadavg_fixed_point(s: *const c_char, ret: *mut c_ulong) -> i32 {
    if s.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // Find the first dot, matching strchr() in the C implementation.
    let mut dot_pos: Option<usize> = None;
    let mut len: usize = 0;
    // SAFETY: the caller guarantees s is readable through its NUL terminator.
    while unsafe_ffi!(*s.add(len)) != 0 {
        // SAFETY: len currently indexes a byte before the terminator.
        if unsafe_ffi!(*s.add(len)) as u8 == b'.' && dot_pos.is_none() {
            dot_pos = Some(len);
        }
        len += 1;
    }

    let Some(dot_pos) = dot_pos else {
        return Errno::EINVAL.to_neg_errno();
    };

    let Some(integer_allocation_size) = dot_pos.checked_add(1) else {
        return Errno::ENOMEM.to_neg_errno();
    };
    // SAFETY: malloc accepts the checked byte count.
    let integer_string = unsafe_ffi!(libc::malloc(integer_allocation_size)).cast::<c_char>();
    if integer_string.is_null() {
        return Errno::ENOMEM.to_neg_errno();
    }
    // SAFETY: integer_string has dot_pos+1 bytes; the source prefix has
    // dot_pos readable bytes and cannot overlap this fresh allocation.
    unsafe {
        std::ptr::copy_nonoverlapping(s, integer_string, dot_pos);
        *integer_string.add(dot_pos) = 0;
    }

    let mut i: c_ulong = 0;
    // SAFETY: integer_string is live and NUL-terminated, and i is writable.
    let integer_result = unsafe_ffi!(rs_safe_atolu_full(integer_string, 10, &mut i));
    // SAFETY: integer_string came from malloc and is no longer used.
    unsafe_ffi!(libc::free(integer_string.cast()));
    if integer_result < 0 {
        return integer_result;
    }

    let mut f: c_ulong = 0;
    // SAFETY: dot_pos indexes the measured C string and add(1) remains within
    // it (possibly at its trailing NUL); f is writable.
    let fraction_result = unsafe_ffi!(rs_safe_atolu_full(s.add(dot_pos + 1), 10, &mut f));
    if fraction_result < 0 {
        return fraction_result;
    }

    store_loadavg_fixed_point_inner(i, f).map_or(Errno::ERANGE.to_neg_errno(), |val| {
        // SAFETY: ret is non-null and writable by the caller contract.
        unsafe_ffi!(*ret = val);
        0
    })
}

/// C ABI facade for `parse_fractional_part_u()`.
///
/// The output pointer and input cursor are published only on success. The
/// arithmetic intentionally wraps as C's unsigned arithmetic does.
///
/// # Safety
///
/// `p` and `res` must be writable. `*p` must be a non-null, live
/// NUL-terminated C string. Pointer ranges must not overlap in a way that
/// makes the cursor update invalidate the read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_fractional_part_u(
    p: *mut *const c_char,
    digits: usize,
    res: *mut u32,
) -> i32 {
    if p.is_null() || res.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: `p` is writable under this export's contract.
    let mut cursor = unsafe_ffi!(*p);
    if cursor.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut value = 0u32;
    for index in 0..digits {
        // SAFETY: `cursor` starts in a live C string and advances only after
        // reading a non-NUL decimal byte, so it remains in that allocation.
        let byte = unsafe_ffi!(*cursor) as u8;
        if !byte.is_ascii_digit() {
            if index == 0 {
                return Errno::EINVAL.to_neg_errno();
            }
            for _ in index..digits {
                value = value.wrapping_mul(10);
            }
            break;
        }
        value = value.wrapping_mul(10).wrapping_add((byte - b'0') as u32);
        // SAFETY: the byte was non-NUL, so its successor remains in the C string.
        cursor = unsafe_ffi!(cursor.add(1));
    }

    // SAFETY: `cursor` remains within the live C string by the loop invariant.
    let round = unsafe_ffi!(*cursor) as u8;
    if (b'5'..=b'9').contains(&round) {
        value = value.wrapping_add(1);
    }
    // C uses strspn(s, DIGITS), preserving opaque non-digit bytes and stopping
    // exactly at the first one.
    loop {
        // SAFETY: `cursor` is within the live NUL-terminated C string.
        let byte = unsafe_ffi!(*cursor) as u8;
        if !byte.is_ascii_digit() {
            break;
        }
        // SAFETY: the byte was non-NUL, so the successor stays in range.
        cursor = unsafe_ffi!(cursor.add(1));
    }

    // SAFETY: both output locations are writable by this export's contract.
    unsafe {
        *p = cursor;
        *res = value;
    }
    0
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn cstr(s: &str) -> *const c_char {
        CString::new(s).unwrap().into_raw()
    }

    fn free_cstr(s: *const c_char) {
        // SAFETY: ownership of the allocation is transferred exactly once from C back to Rust here.
        unsafe {
            let _ = CString::from_raw(s.cast_mut());
        }
    }

    #[test]
    fn test_rs_parse_boolean_yes() {
        let s = cstr("yes");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_parse_boolean(s), 1);
        }
        free_cstr(s);
    }

    #[test]
    fn test_rs_parse_boolean_no() {
        let s = cstr("no");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_parse_boolean(s), 0);
        }
        free_cstr(s);
    }

    #[test]
    fn test_rs_parse_boolean_true() {
        let s = cstr("true");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_parse_boolean(s), 1);
        }
        free_cstr(s);
    }

    #[test]
    fn test_rs_parse_boolean_false() {
        let s = cstr("false");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_parse_boolean(s), 0);
        }
        free_cstr(s);
    }

    #[test]
    fn test_rs_parse_boolean_one() {
        let s = cstr("1");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_parse_boolean(s), 1);
        }
        free_cstr(s);
    }

    #[test]
    fn test_rs_parse_boolean_zero() {
        let s = cstr("0");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_parse_boolean(s), 0);
        }
        free_cstr(s);
    }

    #[test]
    fn test_rs_parse_boolean_invalid() {
        let s = cstr("invalid");
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_parse_boolean(s), Errno::EINVAL.to_neg_errno());
        }
        free_cstr(s);
    }

    #[test]
    fn test_rs_safe_atou_42() {
        let s = cstr("42");
        let mut val: u32 = 0;
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_safe_atou(s, &mut val), 0);
            assert_eq!(val, 42);
        }
        free_cstr(s);
    }

    #[test]
    fn test_rs_safe_atou_zero() {
        let s = cstr("0");
        let mut val: u32 = 0;
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_safe_atou(s, &mut val), 0);
            assert_eq!(val, 0);
        }
        free_cstr(s);
    }

    #[test]
    fn test_rs_safe_atou_negative() {
        let s = cstr("-1");
        let mut val: u32 = 0;
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_safe_atou(s, &mut val), Errno::ERANGE.to_neg_errno());
        }
        free_cstr(s);
    }

    #[test]
    fn test_rs_safe_atou_abc() {
        let s = cstr("abc");
        let mut val: u32 = 0;
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_safe_atou(s, &mut val), Errno::EINVAL.to_neg_errno());
        }
        free_cstr(s);
    }

    #[test]
    fn test_rs_safe_atoi_negative() {
        let s = cstr("-42");
        let mut val: i32 = 0;
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_safe_atoi(s, &mut val), 0);
            assert_eq!(val, -42);
        }
        free_cstr(s);
    }

    #[test]
    fn test_rs_safe_atoi_zero() {
        let s = cstr("0");
        let mut val: i32 = 0;
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_safe_atoi(s, &mut val), 0);
            assert_eq!(val, 0);
        }
        free_cstr(s);
    }

    #[test]
    fn test_rs_safe_atoi_positive() {
        let s = cstr("42");
        let mut val: i32 = 0;
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_safe_atoi(s, &mut val), 0);
            assert_eq!(val, 42);
        }
        free_cstr(s);
    }

    #[test]
    fn test_safe_numeric_slice_grammar() {
        let mut binary_base = 0;
        assert_eq!(
            parse_unsigned(
                mangle_base(b"0b101", &mut binary_base),
                binary_base,
                u64::MAX
            ),
            Ok(5)
        );
        let mut octal_base = 0;
        assert_eq!(
            parse_unsigned(mangle_base(b"0o17", &mut octal_base), octal_base, u64::MAX),
            Ok(15)
        );
        assert_eq!(parse_unsigned(b"0x10", 0, u64::MAX), Ok(16));
        assert_eq!(parse_unsigned(b"\x0b42", 0, u64::MAX), Ok(42));
        assert_eq!(parse_unsigned(b"-0", 0, u64::MAX), Ok(0));
        assert_eq!(
            parse_unsigned(b"-1", 0, u64::MAX),
            Err(Errno::ERANGE.to_neg_errno())
        );
        assert_eq!(
            parse_unsigned(b"09", 0, u64::MAX),
            Err(Errno::EINVAL.to_neg_errno())
        );
        assert_eq!(
            parse_unsigned(b"18446744073709551616", 10, u64::MAX),
            Err(Errno::ERANGE.to_neg_errno())
        );
        assert_eq!(
            parse_signed(b"-0x8000000000000000", 0, i64::MIN, i64::MAX),
            Ok(i64::MIN)
        );
    }

    #[test]
    fn test_rs_parse_size_1k() {
        let s = cstr("1K");
        let mut val: u64 = 0;
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_parse_size(s, 1024, &mut val), 0);
            assert_eq!(val, 1024);
        }
        free_cstr(s);
    }

    #[test]
    fn test_rs_parse_size_1m() {
        let s = cstr("1M");
        let mut val: u64 = 0;
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_parse_size(s, 1024, &mut val), 0);
            assert_eq!(val, 1024 * 1024);
        }
        free_cstr(s);
    }

    #[test]
    fn test_rs_parse_size_1g() {
        let s = cstr("1G");
        let mut val: u64 = 0;
        // SAFETY: this block performs raw/FFI operations and relies on invariants enforced by the surrounding checks.
        unsafe {
            assert_eq!(rs_parse_size(s, 1024, &mut val), 0);
            assert_eq!(val, 1024 * 1024 * 1024);
        }
        free_cstr(s);
    }
}
