// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.time-util; authority=src/basic/time-util.c,src/basic/time-util.h
//
// String-table, timezone-offset, and timespan formatting helpers.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use std::ffi::{CStr, c_long};

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

fn timestamp_style_from_bytes(bytes: &[u8]) -> Option<i32> {
    if let Some((index, _)) = TIMESTAMP_STYLE_NAMES
        .iter()
        .enumerate()
        .find(|(_, name)| bytes == &name[..name.len() - 1])
    {
        return Some(index as i32);
    }
    match bytes {
        b"\xc2\xb5s" | b"\xce\xbcs" => Some(1),
        b"\xc2\xb5s+utc" | b"\xce\xbcs+utc" => Some(3),
        _ => None,
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
    // SAFETY: `s` is a readable NUL-terminated C string by this ABI contract.
    timestamp_style_from_bytes(unsafe_ffi!(CStr::from_ptr(s)).to_bytes())
        .unwrap_or_else(|| Errno::EINVAL.to_neg_errno())
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

    // SAFETY: `t` is a readable NUL-terminated C string by this ABI contract.
    let gmtoff = match parse_gmtoff_bytes(unsafe_ffi!(CStr::from_ptr(t)).to_bytes()) {
        Ok(gmtoff) => gmtoff,
        Err(errno) => return errno.to_neg_errno(),
    };
    if !ret.is_null() {
        // SAFETY: the ABI contract makes a non-null `ret` writable.
        unsafe_ffi!(*ret = gmtoff);
    }
    0
}

fn parse_gmtoff_bytes(text: &[u8]) -> Result<c_long, Errno> {
    let (&sign, digits) = text.split_first().ok_or(Errno::EINVAL)?;
    let positive = match sign {
        b'+' => true,
        b'-' => false,
        _ => return Err(Errno::EINVAL),
    };
    let (hours, minutes) = match digits {
        [h0, h1] => (decimal_pair(*h0, *h1)?, 0),
        [h0, h1, m0, m1] => (decimal_pair(*h0, *h1)?, decimal_pair(*m0, *m1)?),
        [h0, h1, b':', m0, m1] => (decimal_pair(*h0, *h1)?, decimal_pair(*m0, *m1)?),
        _ => return Err(Errno::EINVAL),
    };
    if minutes >= 60 {
        return Err(Errno::EINVAL);
    }
    let usec = hours as u64 * USEC_PER_HOUR + minutes as u64 * USEC_PER_MINUTE;
    if usec > USEC_PER_DAY {
        return Err(Errno::EINVAL);
    }
    let seconds = (usec / USEC_PER_SEC) as c_long;
    Ok(if positive { seconds } else { -seconds })
}

fn decimal_pair(tens: u8, units: u8) -> Result<u8, Errno> {
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        _ => Err(Errno::EINVAL),
    };
    Ok(digit(tens)? * 10 + digit(units)?)
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

/// Caller-contract-validated C output buffer. Formatting builds every segment
/// with safe slices and uses this single adapter to publish bounded bytes.
struct CBuffer {
    ptr: *mut c_char,
    len: usize,
}

impl CBuffer {
    fn from_contract(ptr: *mut c_char, len: usize) -> Self {
        Self { ptr, len }
    }

    fn write(&self, offset: usize, bytes: &[u8]) {
        if offset >= self.len {
            return;
        }
        let count = bytes.len().min(self.len.saturating_sub(offset));
        // SAFETY: callers establish `ptr` as writable for `len` bytes; the
        // checked count keeps the destination within that range.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr().cast::<c_char>(),
                self.ptr.add(offset),
                count,
            )
        };
    }
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

    let output = CBuffer::from_contract(buf, l);
    if t == USEC_INFINITY {
        let bytes = b"infinity";
        let copy_len = bytes.len().min(l - 1);
        output.write(0, &bytes[..copy_len]);
        output.write(copy_len, b"\0");
        return buf;
    }

    if t == 0 {
        if l > 1 {
            output.write(0, b"0\0");
        } else {
            output.write(0, b"\0");
        }
        return buf;
    }

    let mut remaining = t;
    let mut used = 0usize;
    let mut something = false;
    output.write(0, b"\0");
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
        output.write(used, &segment[..copied]);
        used += copied;
        output.write(used, b"\0");

        if fractional.is_none() {
            remaining = remainder;
        }
        something = true;
    }

    buf
}

// /// Safe internal implementation helpers are deliberately allocation-free.
