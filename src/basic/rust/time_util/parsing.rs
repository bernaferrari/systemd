// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.time-util; authority=src/basic/time-util.c,src/basic/time-util.h
//
// Duration parsing and its byte-oriented C-string helpers.

use std::ffi::CStr;

use libc::c_char;

use crate::ffi::Errno;

use super::types::{
    USEC_INFINITY, USEC_PER_DAY, USEC_PER_HOUR, USEC_PER_MINUTE, USEC_PER_MONTH, USEC_PER_MSEC,
    USEC_PER_SEC, USEC_PER_WEEK, USEC_PER_YEAR,
};

const WHITESPACE: &[u8] = b" \t\n\r";
const DIGITS: &[u8] = b"0123456789";

fn parse_nonnegative_decimal_bytes(input: &[u8], start: usize) -> Result<(u64, usize), i32> {
    let mut cursor = start;
    // strtoll(), used by the C authority, accepts the full C-locale
    // whitespace set even though skip_leading_chars() above intentionally
    // uses systemd's narrower WHITESPACE definition.
    while matches!(
        input.get(cursor),
        Some(b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
    ) {
        cursor += 1;
    }

    let sign = input.get(cursor).copied();
    let negative = sign == Some(b'-');
    if matches!(sign, Some(b'-' | b'+')) {
        cursor += 1;
    }

    let digits_start = cursor;
    let mut value = 0_u64;

    while let Some(&c) = input.get(cursor).filter(|byte| byte.is_ascii_digit()) {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add((c - b'0') as u64))
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or_else(|| Errno::ERANGE.to_neg_errno())?;
        cursor += 1;
    }

    if cursor == digits_start {
        // strtoll() reports no conversion by leaving endptr at the original
        // input. The caller needs that distinction to accept ".5" while
        // rejecting inputs such as "+.5".
        return Ok((0, start));
    }
    if negative {
        return Err(Errno::ERANGE.to_neg_errno());
    }

    Ok((value, cursor))
}

fn skip_leading_chars_bytes(input: &[u8], mut cursor: usize) -> usize {
    while input
        .get(cursor)
        .is_some_and(|byte| WHITESPACE.contains(byte))
    {
        cursor += 1;
    }
    cursor
}

fn in_charset(c: u8, s: &[u8]) -> bool {
    for &ch in s.iter() {
        if ch == c {
            return true;
        }
    }
    false
}

fn startswith_bytes(input: &[u8], cursor: usize, prefix: &[u8]) -> Option<usize> {
    let prefix = prefix.strip_suffix(&[0]).unwrap_or(prefix);
    input
        .get(cursor..)
        .filter(|remaining| remaining.starts_with(prefix))
        .map(|_| cursor + prefix.len())
}

fn strspn_chars_bytes(input: &[u8], cursor: usize, accept: &[u8]) -> usize {
    input[cursor..]
        .iter()
        .take_while(|byte| accept.contains(byte))
        .count()
}

// ── extract_multiplier ────────────────────────────────────────────────────

struct TimeMultiplier {
    suffix: &'static [u8],
    usec: u64,
}

static MULTIPLIER_TABLE: &[TimeMultiplier] = &[
    TimeMultiplier {
        suffix: b"seconds",
        usec: USEC_PER_SEC,
    },
    TimeMultiplier {
        suffix: b"second",
        usec: USEC_PER_SEC,
    },
    TimeMultiplier {
        suffix: b"sec",
        usec: USEC_PER_SEC,
    },
    TimeMultiplier {
        suffix: b"s",
        usec: USEC_PER_SEC,
    },
    TimeMultiplier {
        suffix: b"minutes",
        usec: USEC_PER_MINUTE,
    },
    TimeMultiplier {
        suffix: b"minute",
        usec: USEC_PER_MINUTE,
    },
    TimeMultiplier {
        suffix: b"min",
        usec: USEC_PER_MINUTE,
    },
    TimeMultiplier {
        suffix: b"months",
        usec: USEC_PER_MONTH,
    },
    TimeMultiplier {
        suffix: b"month",
        usec: USEC_PER_MONTH,
    },
    TimeMultiplier {
        suffix: b"M",
        usec: USEC_PER_MONTH,
    },
    TimeMultiplier {
        suffix: b"msec",
        usec: USEC_PER_MSEC,
    },
    TimeMultiplier {
        suffix: b"ms",
        usec: USEC_PER_MSEC,
    },
    TimeMultiplier {
        suffix: b"m",
        usec: USEC_PER_MINUTE,
    },
    TimeMultiplier {
        suffix: b"hours",
        usec: USEC_PER_HOUR,
    },
    TimeMultiplier {
        suffix: b"hour",
        usec: USEC_PER_HOUR,
    },
    TimeMultiplier {
        suffix: b"hr",
        usec: USEC_PER_HOUR,
    },
    TimeMultiplier {
        suffix: b"h",
        usec: USEC_PER_HOUR,
    },
    TimeMultiplier {
        suffix: b"days",
        usec: USEC_PER_DAY,
    },
    TimeMultiplier {
        suffix: b"day",
        usec: USEC_PER_DAY,
    },
    TimeMultiplier {
        suffix: b"d",
        usec: USEC_PER_DAY,
    },
    TimeMultiplier {
        suffix: b"weeks",
        usec: USEC_PER_WEEK,
    },
    TimeMultiplier {
        suffix: b"week",
        usec: USEC_PER_WEEK,
    },
    TimeMultiplier {
        suffix: b"w",
        usec: USEC_PER_WEEK,
    },
    TimeMultiplier {
        suffix: b"years",
        usec: USEC_PER_YEAR,
    },
    TimeMultiplier {
        suffix: b"year",
        usec: USEC_PER_YEAR,
    },
    TimeMultiplier {
        suffix: b"y",
        usec: USEC_PER_YEAR,
    },
    TimeMultiplier {
        suffix: b"usec",
        usec: 1,
    },
    TimeMultiplier {
        suffix: b"us",
        usec: 1,
    },
    // U+03bc (GREEK SMALL LETTER MU) — UTF-8: 0xce 0xbc
    TimeMultiplier {
        suffix: &[0xce, 0xbc, b's', 0],
        usec: 1,
    },
    // U+00b5 (MICRO SIGN) — UTF-8: 0xc2 0xb5
    TimeMultiplier {
        suffix: &[0xc2, 0xb5, b's', 0],
        usec: 1,
    },
];

fn extract_multiplier_bytes(input: &[u8], cursor: usize, default_unit: u64) -> (usize, u64) {
    for entry in MULTIPLIER_TABLE {
        if let Some(end) = startswith_bytes(input, cursor, entry.suffix) {
            return (end, entry.usec);
        }
    }
    (cursor, default_unit)
}

fn parse_time_bytes(input: &[u8], default_unit: u64) -> Result<u64, i32> {
    if default_unit == 0 {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    let mut cursor = skip_leading_chars_bytes(input, 0);
    if let Some(end) = startswith_bytes(input, cursor, b"infinity") {
        let next = input.get(end).copied().unwrap_or(0);
        if !in_charset(next, WHITESPACE) && next != 0 {
            return Err(Errno::EINVAL.to_neg_errno());
        }
        return Ok(USEC_INFINITY);
    }

    let mut usec = 0_u64;
    let mut something = false;
    loop {
        cursor = skip_leading_chars_bytes(input, cursor);
        if cursor == input.len() {
            if !something {
                return Err(Errno::EINVAL.to_neg_errno());
            }
            break;
        }
        if input[cursor] == b'-' {
            return Err(Errno::ERANGE.to_neg_errno());
        }

        let (integer, end) = parse_nonnegative_decimal_bytes(input, cursor)?;
        let had_dot = input.get(end) == Some(&b'.');
        let mut next = end;
        if had_dot {
            next += 1;
            next += strspn_chars_bytes(input, next, DIGITS);
        }

        let before_whitespace = next;
        next += strspn_chars_bytes(input, next, WHITESPACE);
        let (after_multiplier, multiplier) = extract_multiplier_bytes(input, next, default_unit);
        if after_multiplier == before_whitespace && input.get(after_multiplier).is_some() {
            return Err(Errno::EINVAL.to_neg_errno());
        }
        cursor = after_multiplier;

        if integer >= USEC_INFINITY / multiplier {
            return Err(Errno::ERANGE.to_neg_errno());
        }
        let whole = integer * multiplier;
        if whole >= USEC_INFINITY - usec {
            return Err(Errno::ERANGE.to_neg_errno());
        }
        usec += whole;
        something = true;

        if had_dot {
            let mut scale = multiplier / 10;
            let mut fraction = end + 1;
            let fraction_start = fraction;
            while let Some(&digit) = input.get(fraction).filter(|byte| byte.is_ascii_digit()) {
                let value = (digit - b'0') as u64 * scale;
                if value >= USEC_INFINITY - usec {
                    return Err(Errno::ERANGE.to_neg_errno());
                }
                usec += value;
                scale /= 10;
                fraction += 1;
            }
            if fraction == fraction_start {
                return Err(Errno::EINVAL.to_neg_errno());
            }
        }
    }

    Ok(usec)
}

// ── parse_time ────────────────────────────────────────────────────────────

/// Shadow of C parse_time()
/// Parses a time value like "5s", "100ms", "2min 500ms", "infinity", etc.
/// default_unit is used when no suffix is given (e.g. USEC_PER_SEC for parse_sec).
// SAFETY: A non-null t must be a readable, NUL-terminated C string. ret is
// either null or a valid writable u64 location, written only after parsing.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_time(t: *const c_char, ret: *mut u64, default_unit: u64) -> i32 {
    if t.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    // SAFETY: the caller guarantees `t` is a live NUL-terminated C string;
    // non-null `ret` is writable for the final publication below.
    unsafe_ffi!({
        let usec = match parse_time_bytes(CStr::from_ptr(t).to_bytes(), default_unit) {
            Ok(usec) => usec,
            Err(error) => return error,
        };
        if !ret.is_null() {
            *ret = usec;
        }
    });
    0
}

// ── parse_sec / parse_sec_fix_0 / parse_sec_def_infinity ───────────────────

// SAFETY: t and optional ret obey rs_parse_time's readable C-string and
// writable-output contracts; this wrapper adds no pointer manipulation.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_sec(t: *const c_char, ret: *mut u64) -> i32 {
    // SAFETY: the caller supplies the input and optional output contracts forwarded here.
    unsafe_ffi!(rs_parse_time(t, ret, USEC_PER_SEC))
}

/// Safe Rust facade for systemd's `parse_sec()` duration grammar.
///
/// The returned value is measured in microseconds. Errors are negative errno
/// values so Rust callers can preserve the exact parser result without
/// crossing the pointer-oriented C ABI.
pub fn parse_sec(value: &str) -> Result<u64, i32> {
    let value = std::ffi::CString::new(value).map_err(|_| Errno::EINVAL.to_neg_errno())?;
    parse_time_bytes(value.as_bytes(), USEC_PER_SEC)
}

// SAFETY: A non-null t must be a readable, NUL-terminated C string; a
// non-null ret must be a writable u64 location before this wrapper stores it.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_sec_fix_0(t: *const c_char, ret: *mut u64) -> i32 {
    if t.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut k: u64 = 0;
    // SAFETY: t is caller-validated and k is a live writable u64.
    let r = unsafe_ffi!(rs_parse_sec(t, &mut k));
    if r < 0 {
        return r;
    }

    // SAFETY: ret is non-null and writable by the caller contract.
    unsafe_ffi!(*ret = if k == 0 { USEC_INFINITY } else { k });
    0
}

// SAFETY: A non-null t must be a readable, NUL-terminated C string; a
// non-null ret must be a writable u64 location before this wrapper stores it.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_sec_def_infinity(t: *const c_char, ret: *mut u64) -> i32 {
    if t.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: the caller supplies a live C string and writable output storage.
    unsafe_ffi!({
        let input = CStr::from_ptr(t).to_bytes();
        if skip_leading_chars_bytes(input, 0) == input.len() {
            *ret = USEC_INFINITY;
            return 0;
        }
        let value = match parse_time_bytes(input, USEC_PER_SEC) {
            Ok(value) => value,
            Err(error) => return error,
        };
        *ret = value;
    });
    0
}
