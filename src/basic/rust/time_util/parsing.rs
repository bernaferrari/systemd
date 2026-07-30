// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.time-util; authority=src/basic/time-util.c,src/basic/time-util.h
//
// Duration parsing and its byte-oriented C-string helpers.

use libc::c_char;

use crate::ffi::Errno;

use super::types::{
    USEC_INFINITY, USEC_PER_DAY, USEC_PER_HOUR, USEC_PER_MINUTE, USEC_PER_MONTH, USEC_PER_MSEC,
    USEC_PER_SEC, USEC_PER_WEEK, USEC_PER_YEAR,
};

const WHITESPACE: &[u8] = b" \t\n\r";
const DIGITS: &[u8] = b"0123456789";

/// # Safety
/// `p` must point to a readable NUL-terminated C string.
unsafe fn parse_nonnegative_decimal(p: *const c_char) -> Result<(u64, *const c_char), i32> {
    if p.is_null() {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    let start = p;
    let mut q = p;
    // strtoll(), used by the C authority, accepts the full C-locale
    // whitespace set even though skip_leading_chars() above intentionally
    // uses systemd's narrower WHITESPACE definition.
    while matches!(
        // SAFETY: the caller guarantees q remains within a live NUL-terminated string.
        unsafe { *q } as u8,
        b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c
    ) {
        q = q.wrapping_add(1);
    }

    // SAFETY: q remains within the caller's live C string.
    let sign = unsafe { *q };
    let negative = sign == b'-' as c_char;
    if negative || sign == b'+' as c_char {
        q = q.wrapping_add(1);
    }

    let digits_start = q;
    let mut value = 0_u64;

    // SAFETY: the caller guarantees q remains within a live NUL-terminated string.
    while unsafe { *q } != 0 {
        // SAFETY: q currently points before the terminating NUL.
        let c = unsafe { *q } as u8;
        if !c.is_ascii_digit() {
            break;
        }

        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add((c - b'0') as u64))
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or_else(|| Errno::ERANGE.to_neg_errno())?;
        // SAFETY: advancing from a digit remains within the C string allocation.
        q = unsafe { q.add(1) };
    }

    if q == digits_start {
        // strtoll() reports no conversion by leaving endptr at the original
        // input. The caller needs that distinction to accept ".5" while
        // rejecting inputs such as "+.5".
        return Ok((0, start));
    }
    if negative {
        return Err(Errno::ERANGE.to_neg_errno());
    }

    Ok((value, q))
}

// SAFETY: p must address a readable, NUL-terminated C string; the returned
// pointer is an in-bounds position within that same string.
unsafe fn skip_leading_chars(p: *const c_char, _bad: *const u8) -> *const c_char {
    let mut q = p;
    // SAFETY: the caller guarantees q remains within a live NUL-terminated string.
    while unsafe { *q } != 0 {
        // SAFETY: q currently points before the terminating NUL.
        let c = unsafe { *q } as u8;
        let mut ws = false;
        for &w in WHITESPACE.iter() {
            if c == w {
                ws = true;
                break;
            }
        }
        if !ws {
            break;
        }
        // SAFETY: advancing from a non-NUL byte remains within the C string allocation.
        q = unsafe { q.add(1) };
    }
    q
}

// SAFETY: This helper reads only the checked Rust slice and scalar argument;
// its unsafe signature keeps the pointer-oriented parser helper interface.
fn in_charset(c: u8, s: &[u8]) -> bool {
    for &ch in s.iter() {
        if ch == c {
            return true;
        }
    }
    false
}

// SAFETY: s must address a readable, NUL-terminated C string. prefix is a
// valid Rust slice, and a successful return stays within the input string.
unsafe fn startswith(s: *const c_char, prefix: &[u8]) -> *const c_char {
    let mut si: usize = 0;
    let mut pi: usize = 0;
    loop {
        if pi >= prefix.len() || prefix[pi] == 0 {
            // SAFETY: si counts bytes successfully matched within the caller's C string.
            return unsafe { s.add(si) };
        }
        // SAFETY: the caller guarantees s is readable through its NUL terminator.
        if unsafe { *s.add(si) } != prefix[pi] as c_char {
            return std::ptr::null();
        }
        si += 1;
        pi += 1;
    }
}

// SAFETY: p must address a readable, NUL-terminated C string; accept is a
// valid Rust slice, so scanning stops before reading past the terminator.
unsafe fn strspn_chars(p: *const c_char, accept: &[u8]) -> usize {
    let mut n: usize = 0;
    let mut q = p;
    // SAFETY: the caller guarantees q remains within a live NUL-terminated string.
    while unsafe { *q } != 0 {
        // SAFETY: q currently points before the terminating NUL.
        let c = unsafe { *q } as u8;
        let mut found = false;
        for &a in accept.iter() {
            if c == a {
                found = true;
                break;
            }
        }
        if !found {
            break;
        }
        n += 1;
        // SAFETY: advancing from a non-NUL byte remains within the C string allocation.
        q = unsafe { q.add(1) };
    }
    n
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

/// Returns pointer past the matched suffix, or the original pointer if no match.
// SAFETY: p must be a readable, NUL-terminated C string and ret_multiplier
// must be writable; returned pointers remain within p's original allocation.
unsafe fn extract_multiplier(p: *const c_char, ret_multiplier: *mut u64) -> *const c_char {
    for entry in MULTIPLIER_TABLE.iter() {
        // SAFETY: the caller guarantees p is a live C string; suffix is a static byte slice.
        let e = unsafe { startswith(p, entry.suffix) };
        if !e.is_null() {
            // SAFETY: the caller guarantees ret_multiplier is writable.
            unsafe { *ret_multiplier = entry.usec };
            return e;
        }
    }
    p
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
    if default_unit == 0 {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: the caller guarantees t is a live NUL-terminated C string.
    let mut p = unsafe { skip_leading_chars(t, std::ptr::null()) };

    // Check for "infinity"
    let inf = b"infinity";
    // SAFETY: p is an in-bounds position in the caller's C string.
    let s = unsafe { startswith(p, inf) };
    if !s.is_null() {
        // SAFETY: s points within the caller's NUL-terminated C string.
        let c = unsafe { *s } as u8;
        if !in_charset(c, WHITESPACE) && c != 0 {
            return Errno::EINVAL.to_neg_errno();
        }
        if !ret.is_null() {
            // SAFETY: the caller guarantees non-null ret is writable.
            unsafe { *ret = USEC_INFINITY };
        }
        return 0;
    }

    let mut usec: u64 = 0;
    let mut something = false;

    loop {
        let mut multiplier = default_unit;

        // SAFETY: p remains within the caller's C string.
        p = unsafe { skip_leading_chars(p, std::ptr::null()) };
        // SAFETY: p remains within the caller's C string.
        if unsafe { *p } == 0 {
            if !something {
                return Errno::EINVAL.to_neg_errno();
            }
            break;
        }

        // Don't allow "-0"
        // SAFETY: p remains within the caller's C string.
        if unsafe { *p } == b'-' as c_char {
            return Errno::ERANGE.to_neg_errno();
        }

        // SAFETY: p remains within the caller's live C string.
        let (l, endptr) = match unsafe { parse_nonnegative_decimal(p) } {
            Ok(v) => v,
            Err(e) => return e,
        };

        // SAFETY: parse_nonnegative_decimal returns an in-bounds pointer.
        let had_dot = unsafe { *endptr } == b'.' as c_char;
        if had_dot {
            // Skip past dot and any digits after it
            p = endptr;
            // SAFETY: the dot is a non-NUL byte within the caller's C string.
            p = unsafe { p.add(1) };
            // SAFETY: p remains in the C string and strspn_chars returns an in-bounds count.
            let digit_count = unsafe { strspn_chars(p, DIGITS) };
            // SAFETY: digit_count was measured from p within the same string.
            p = unsafe { p.add(digit_count) };
        } else {
            p = endptr;
        }

        // Try to extract multiplier suffix
        // SAFETY: p remains within the caller's C string.
        let ws_len = unsafe { strspn_chars(p, WHITESPACE) };
        // SAFETY: ws_len was measured from p within the same string.
        let before_whitespace = p;
        let mut p2 = unsafe { p.add(ws_len) };
        // SAFETY: p2 is in-bounds and multiplier is a live writable u64.
        p2 = unsafe { extract_multiplier(p2, &mut multiplier) };

        // Don't allow '12.34.56', but accept '12.34 .56' or '12.34s.56'
        // SAFETY: p2 is an in-bounds pointer returned by extract_multiplier.
        if p2 == before_whitespace && unsafe { *p2 } != 0 {
            return Errno::EINVAL.to_neg_errno();
        }

        p = p2;

        if l >= USEC_INFINITY / multiplier {
            return Errno::ERANGE.to_neg_errno();
        }

        let k = l * multiplier;
        if k >= USEC_INFINITY - usec {
            return Errno::ERANGE.to_neg_errno();
        }

        usec += k;
        something = true;

        if had_dot {
            let mut m = multiplier / 10;
            let mut b = endptr;
            // SAFETY: endptr points at the known dot within the C string.
            b = unsafe { b.add(1) };
            let dot_start = b;

            // SAFETY: b remains within the caller's NUL-terminated C string.
            while unsafe { *b } != 0 {
                // SAFETY: b currently points before the terminating NUL.
                let c = unsafe { *b } as u8;
                if c < b'0' || c > b'9' {
                    break;
                }
                let k = (c - b'0') as u64 * m;
                if k >= USEC_INFINITY - usec {
                    return Errno::ERANGE.to_neg_errno();
                }
                usec += k;
                m /= 10;
                // SAFETY: advancing from a digit remains within the C string.
                b = unsafe { b.add(1) };
            }

            // Don't allow "0.-0", "3.+1", "3. 1", "3.sec" or "3.hoge"
            if b == dot_start {
                return Errno::EINVAL.to_neg_errno();
            }
        }
    }

    if !ret.is_null() {
        // SAFETY: the caller guarantees non-null ret is writable.
        unsafe { *ret = usec };
    }
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
    unsafe { rs_parse_time(t, ret, USEC_PER_SEC) }
}

/// Safe Rust facade for systemd's `parse_sec()` duration grammar.
///
/// The returned value is measured in microseconds. Errors are negative errno
/// values so Rust callers can preserve the exact parser result without
/// crossing the pointer-oriented C ABI.
pub fn parse_sec(value: &str) -> Result<u64, i32> {
    let value = std::ffi::CString::new(value).map_err(|_| Errno::EINVAL.to_neg_errno())?;
    let mut parsed = 0;
    // SAFETY: `value` is NUL-terminated and `parsed` is a live writable u64.
    let result = unsafe { rs_parse_sec(value.as_ptr(), &mut parsed) };
    if result < 0 { Err(result) } else { Ok(parsed) }
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
    let r = unsafe { rs_parse_sec(t, &mut k) };
    if r < 0 {
        return r;
    }

    // SAFETY: ret is non-null and writable by the caller contract.
    unsafe { *ret = if k == 0 { USEC_INFINITY } else { k } };
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

    // SAFETY: t is a caller-validated C string.
    let ws_len = unsafe { strspn_chars(t, WHITESPACE) };
    // SAFETY: ws_len was measured from t within the same string.
    let trimmed = unsafe { t.add(ws_len) };
    // SAFETY: trimmed remains within the caller's C string.
    if unsafe { *trimmed } == 0 {
        // SAFETY: ret is non-null and writable by the caller contract.
        unsafe { *ret = USEC_INFINITY };
        return 0;
    }

    // SAFETY: this function forwards the same validated input/output contracts.
    unsafe { rs_parse_sec(t, ret) }
}
