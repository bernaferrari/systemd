// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.time-util; authority=src/basic/time-util.c,src/basic/time-util.h
//
// String-table, timezone-offset, and timespan formatting helpers.

use std::ffi::c_long;

use libc::c_char;

use crate::ffi::Errno;

use super::types::{
    USEC_INFINITY, USEC_PER_DAY, USEC_PER_HOUR, USEC_PER_MINUTE, USEC_PER_MONTH, USEC_PER_SEC,
    USEC_PER_WEEK, USEC_PER_YEAR,
};

// Matches timestamp_style_table in time-util.c.
// PRETTY=0, US=1, UTC=2, US_UTC=3, UNIX=4
// Note: TIMESTAMP_DATE=5 intentionally has no to_string representation in C

const TIMESTAMP_STYLE_NAMES: [&[u8]; 5] = [b"pretty\0", b"us\0", b"utc\0", b"us+utc\0", b"unix\0"];

// SAFETY: Each non-null pointer must address a readable, NUL-terminated C
// string; both byte walks stop at those terminators without writing memory.
unsafe fn streq_ptr(a: *const c_char, b: *const c_char) -> bool {
    if a.is_null() && b.is_null() {
        return true;
    }
    if a.is_null() || b.is_null() {
        return false;
    }
    let mut i: usize = 0;
    loop {
        // SAFETY: the caller guarantees both strings are readable through their NUL bytes.
        let (a_byte, b_byte) = unsafe { (*a.add(i), *b.add(i)) };
        if a_byte != b_byte {
            return false;
        }
        if a_byte == 0 {
            return true;
        }
        i += 1;
    }
}

// SAFETY: This validates only the scalar index and returns either null or a
// pointer to immutable static NUL-terminated storage; no caller memory is read.
#[unsafe(no_mangle)]
pub extern "C" fn rs_timestamp_style_to_string(t: i32) -> *const c_char {
    let idx = t as usize;
    if idx < TIMESTAMP_STYLE_NAMES.len() {
        return TIMESTAMP_STYLE_NAMES[idx].as_ptr() as *const c_char;
    }
    std::ptr::null()
}

// SAFETY: A non-null s must be a readable, NUL-terminated C string for the
// byte comparisons; null is explicitly rejected before dereference.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_timestamp_style_from_string(s: *const c_char) -> i32 {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }
    for (idx, name) in TIMESTAMP_STYLE_NAMES.iter().enumerate() {
        // SAFETY: the caller guarantees s is a live C string; name is static and NUL-terminated.
        if unsafe { streq_ptr(s, name.as_ptr() as *const c_char) } {
            return idx as i32;
        }
    }
    // SAFETY: s is caller-validated and both comparison literals are NUL-terminated.
    if unsafe { streq_ptr(s, [0xC2u8, 0xB5, b's', 0].as_ptr() as *const c_char) }
        // SAFETY: same inputs as the preceding comparison.
        || unsafe { streq_ptr(s, [0xCEu8, 0xBC, b's', 0].as_ptr() as *const c_char) }
    {
        return 1;
    }
    // SAFETY: s is caller-validated and both comparison literals are NUL-terminated.
    if unsafe {
        streq_ptr(
            s,
            [0xC2u8, 0xB5, b's', b'+', b'u', b't', b'c', 0].as_ptr() as *const c_char,
        )
        // SAFETY: same inputs as the preceding comparison.
    } || unsafe {
        streq_ptr(
            s,
            [0xCEu8, 0xBC, b's', b'+', b'u', b't', b'c', 0].as_ptr() as *const c_char,
        )
    } {
        return 3;
    }
    Errno::EINVAL.to_neg_errno()
}

// ── parse_gmtoff ────────────────────────────────────────────────────────────
// From src/basic/time-util.c
//
// Parses a timezone offset string like "+0900", "+09:00", "-14:00", "+09" into seconds.
// Ported: the musl fallback path (strptime %z may not be available).

/// Shadow of C parse_gmtoff()
// SAFETY: A non-null t must be a readable, NUL-terminated C string; ret is
// either null or a valid writable c_long location for the final result.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_gmtoff(t: *const c_char, ret: *mut c_long) -> i32 {
    if t.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let mut pos: usize = 0;

    // Expect leading + or -
    // SAFETY: the caller guarantees t is readable through its NUL terminator.
    let positive = match unsafe { *t.add(pos) } as u8 {
        b'+' => {
            pos += 1;
            true
        }
        b'-' => {
            pos += 1;
            false
        }
        _ => return Errno::EINVAL.to_neg_errno(),
    };

    // Parse first two digits (hours * 10)
    // SAFETY: t remains within the validated C string.
    let d0 = undecchar(unsafe { *t.add(pos) });
    if d0 < 0 {
        return Errno::EINVAL.to_neg_errno();
    }
    let mut u: u64 = (d0 as u64) * 10 * USEC_PER_HOUR;
    pos += 1;

    // SAFETY: t remains within the validated C string.
    let d1 = undecchar(unsafe { *t.add(pos) });
    if d1 < 0 {
        return Errno::EINVAL.to_neg_errno();
    }
    u += (d1 as u64) * USEC_PER_HOUR;
    pos += 1;

    // End of string → 2-digit case (e.g. "+09")
    // SAFETY: t remains within the validated C string.
    if unsafe { *t.add(pos) } == 0 {
        // SAFETY: ret has the optional writable-output contract of this function.
        return unsafe { finish_gmtoff(u, positive, ret) };
    }

    // Optional colon
    // SAFETY: t remains within the validated C string.
    if (unsafe { *t.add(pos) } as u8) == b':' {
        pos += 1;
    }

    // Parse third digit (tens of minutes)
    // SAFETY: t remains within the validated C string.
    let d2 = undecchar(unsafe { *t.add(pos) });
    if d2 < 0 {
        return Errno::EINVAL.to_neg_errno();
    }
    if (d2 as u64) >= 6 {
        return Errno::EINVAL.to_neg_errno(); // minutes >= 60
    }
    u += (d2 as u64) * 10 * USEC_PER_MINUTE;
    pos += 1;

    // Parse fourth digit (units of minutes)
    // SAFETY: t remains within the validated C string.
    let d3 = undecchar(unsafe { *t.add(pos) });
    if d3 < 0 {
        return Errno::EINVAL.to_neg_errno();
    }
    u += (d3 as u64) * USEC_PER_MINUTE;
    pos += 1;

    // SAFETY: t remains within the validated C string.
    if unsafe { *t.add(pos) } != 0 {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: ret has the optional writable-output contract of this function.
    unsafe { finish_gmtoff(u, positive, ret) }
}

// SAFETY: ret is either null or the writable c_long output promised by
// rs_parse_gmtoff; this helper writes it only after all scalar validation.
unsafe fn finish_gmtoff(u: u64, positive: bool, ret: *mut c_long) -> i32 {
    if u > USEC_PER_DAY {
        return Errno::EINVAL.to_neg_errno();
    }

    if !ret.is_null() {
        let gmtoff = (u / USEC_PER_SEC) as c_long;
        // SAFETY: the caller guarantees non-null ret is writable.
        unsafe { *ret = if positive { gmtoff } else { -gmtoff } };
    }

    0
}

// SAFETY: This consumes only its scalar argument and dereferences no pointer;
// its unsafe signature keeps the C-string parser helpers uniform.
fn undecchar(c: c_char) -> i32 {
    let b = c as u8;
    if b >= b'0' && b <= b'9' {
        (b - b'0') as i32
    } else {
        -1
    }
}

// ── format_timespan ──────────────────────────────────────────────────────────
// From src/basic/time-util.c
//
// Formats a timespan (in microseconds) into a human-readable string.
// Writes into caller-provided buffer (C convention).

struct TimespanEntry {
    suffix: &'static [u8],
    usec: u64,
}

static TIMESPAN_TABLE: &[TimespanEntry] = &[
    TimespanEntry {
        suffix: b"y",
        usec: USEC_PER_YEAR,
    },
    TimespanEntry {
        suffix: b"month",
        usec: USEC_PER_MONTH,
    },
    TimespanEntry {
        suffix: b"w",
        usec: USEC_PER_WEEK,
    },
    TimespanEntry {
        suffix: b"d",
        usec: USEC_PER_DAY,
    },
    TimespanEntry {
        suffix: b"h",
        usec: USEC_PER_HOUR,
    },
    TimespanEntry {
        suffix: b"min",
        usec: USEC_PER_MINUTE,
    },
    TimespanEntry {
        suffix: b"s",
        usec: USEC_PER_SEC,
    },
    TimespanEntry {
        suffix: b"ms",
        usec: 1_000,
    },
    TimespanEntry {
        suffix: b"us",
        usec: 1,
    },
];

fn append_u64_decimal(output: &mut [u8], used: &mut usize, value: u64, width: usize) {
    let mut digits = [0u8; 20];
    let mut cursor = digits.len();
    let mut remaining = value;
    loop {
        cursor -= 1;
        digits[cursor] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            break;
        }
    }

    let digit_count = digits.len() - cursor;
    for _ in 0..width.saturating_sub(digit_count) {
        if *used < output.len() {
            output[*used] = b'0';
            *used += 1;
        }
    }
    let copied = (output.len() - *used).min(digit_count);
    output[*used..*used + copied].copy_from_slice(&digits[cursor..cursor + copied]);
    *used += copied;
}

fn format_timespan_segment(
    output: &mut [u8; 64],
    separated: bool,
    value: u64,
    fractional: Option<(u64, usize)>,
    suffix: &[u8],
) -> usize {
    let mut used = 0usize;
    if separated {
        output[used] = b' ';
        used += 1;
    }
    append_u64_decimal(output, &mut used, value, 0);
    if let Some((fraction, width)) = fractional {
        output[used] = b'.';
        used += 1;
        append_u64_decimal(output, &mut used, fraction, width);
    }
    let copied = (output.len() - used).min(suffix.len());
    output[used..used + copied].copy_from_slice(&suffix[..copied]);
    used + copied
}

/// Shadow of C format_timespan()
/// Formats a timespan into a human-readable string. Writes into caller-provided buffer.
// SAFETY: A non-null buf must designate l bytes of writable storage, exclusive
// for this call; every copy is bounded by l minus the trailing NUL byte.
///
/// # Safety
/// Every non-null input pointer must be valid and properly aligned for all
/// reads performed by this call, and every non-null output pointer must be
/// valid and properly aligned for all writes. Pointer ranges must not alias
/// in ways forbidden by the operation's documented ownership contract.
/// C-string inputs must remain NUL-terminated and live for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_format_timespan(
    buf: *mut c_char,
    l: usize,
    t: u64,
    accuracy: u64,
) -> *mut c_char {
    if buf.is_null() || l == 0 {
        return std::ptr::null_mut();
    }

    if t == USEC_INFINITY {
        let bytes = b"infinity";
        let copy_len = bytes.len().min(l - 1);
        // SAFETY: buf is writable for l bytes; copy_len <= l-1 and bytes is disjoint.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buf, copy_len);
            *buf.add(copy_len) = 0;
        }
        return buf;
    }

    if t == 0 {
        if l > 1 {
            // SAFETY: l > 1 guarantees both output bytes are writable.
            unsafe {
                *buf = b'0' as c_char;
                *buf.add(1) = 0;
            }
        } else {
            // SAFETY: l == 1 and buf is writable for that byte.
            unsafe { *buf = 0 };
        }
        return buf;
    }

    let mut remaining = t;
    let mut used = 0usize;
    let mut something = false;
    // SAFETY: l > 0 and buf is writable.
    unsafe { *buf = 0 };
    for entry in TIMESPAN_TABLE {
        if remaining == 0 {
            break;
        }
        if remaining < accuracy && something {
            break;
        }
        if remaining < entry.usec {
            continue;
        }
        if l - used <= 1 {
            break;
        }

        let value = remaining / entry.usec;
        let mut remainder = remaining % entry.usec;
        let mut fractional = None;
        if remaining < USEC_PER_MINUTE && remainder > 0 {
            let mut width = 0i32;
            let mut scale = entry.usec;
            while scale > 1 {
                scale /= 10;
                width += 1;
            }
            let mut precision = accuracy;
            while precision > 1 {
                remainder /= 10;
                width -= 1;
                precision /= 10;
            }
            if width > 0 {
                fractional = Some((remainder, width as usize));
                remaining = 0;
            }
        }

        let mut segment = [0u8; 64];
        let segment_len =
            format_timespan_segment(&mut segment, something, value, fractional, entry.suffix);
        let copied = segment_len.min(l - used - 1);
        // SAFETY: the capacity check bounds this disjoint copy and the segment
        // length is bounded by the fixed local buffer.
        unsafe {
            std::ptr::copy_nonoverlapping(segment.as_ptr().cast::<c_char>(), buf.add(used), copied)
        };
        used += copied;
        // SAFETY: one byte was reserved for the terminating NUL.
        unsafe { *buf.add(used) = 0 };

        if fractional.is_none() {
            remaining = remainder;
        }
        something = true;
    }

    buf
}
