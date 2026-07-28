// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.format-util; authority=src/basic/format-util.c,src/basic/format-util.h
//
// Byte formatting utilities — pure Rust.

use libc::{c_char, c_int};

pub const FORMAT_BYTES_USE_IEC: u32 = 1 << 0;
pub const FORMAT_BYTES_BELOW_POINT: u32 = 1 << 1;
pub const FORMAT_BYTES_ALWAYS_POINT: u32 = 1 << 2;
pub const FORMAT_BYTES_TRAILING_B: u32 = 1 << 3;

struct SuffixEntry {
    suffix: &'static str,
    factor: u64,
}

static TABLE_IEC: &[SuffixEntry] = &[
    SuffixEntry {
        suffix: "E",
        factor: 1024 * 1024 * 1024 * 1024 * 1024 * 1024,
    },
    SuffixEntry {
        suffix: "P",
        factor: 1024 * 1024 * 1024 * 1024 * 1024,
    },
    SuffixEntry {
        suffix: "T",
        factor: 1024 * 1024 * 1024 * 1024,
    },
    SuffixEntry {
        suffix: "G",
        factor: 1024 * 1024 * 1024,
    },
    SuffixEntry {
        suffix: "M",
        factor: 1024 * 1024,
    },
    SuffixEntry {
        suffix: "K",
        factor: 1024,
    },
];

static TABLE_SI: &[SuffixEntry] = &[
    SuffixEntry {
        suffix: "E",
        factor: 1000 * 1000 * 1000 * 1000 * 1000 * 1000,
    },
    SuffixEntry {
        suffix: "P",
        factor: 1000 * 1000 * 1000 * 1000 * 1000,
    },
    SuffixEntry {
        suffix: "T",
        factor: 1000 * 1000 * 1000 * 1000,
    },
    SuffixEntry {
        suffix: "G",
        factor: 1000 * 1000 * 1000,
    },
    SuffixEntry {
        suffix: "M",
        factor: 1000 * 1000,
    },
    SuffixEntry {
        suffix: "K",
        factor: 1000,
    },
];

/// Format a byte count with SI/IEC suffix.
/// Mirrors C `format_bytes_full()`.
/// Returns `None` when `t == u64::MAX` (sentinel).
pub fn format_bytes_full(t: u64, flag: u32) -> Option<String> {
    let mut output = [0_u8; FORMAT_BYTES_MAX];
    let length = format_bytes_into(t, flag, &mut output)?;
    // The formatter writes only ASCII decimal punctuation and suffix bytes.
    Some(String::from_utf8(output[..length].to_vec()).expect("ASCII byte formatter"))
}

/// Format bytes with default flags (IEC + below-point + trailing-B).
/// Mirrors C `format_bytes()` macro.
pub fn format_bytes(t: u64) -> Option<String> {
    format_bytes_full(
        t,
        FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT | FORMAT_BYTES_TRAILING_B,
    )
}

const FORMAT_BYTES_MAX: usize = 16;

fn write_u64_decimal(mut value: u64, output: &mut [u8]) -> usize {
    let mut reversed = [0_u8; 20];
    let mut length = 0;

    loop {
        reversed[length] = b'0' + (value % 10) as u8;
        length += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }

    for (destination, source) in output[..length]
        .iter_mut()
        .zip(reversed[..length].iter().rev())
    {
        *destination = *source;
    }
    length
}

/// Format the C `format_bytes_full()` surface into its bounded stack buffer.
///
/// This preserves C's wrapping unsigned arithmetic in the final suffix bucket,
/// rather than allowing a debug-build Rust overflow to change the ABI result.
fn format_bytes_into(t: u64, flag: u32, output: &mut [u8; FORMAT_BYTES_MAX]) -> Option<usize> {
    if t == u64::MAX {
        return None;
    }

    let table = if flag & FORMAT_BYTES_USE_IEC != 0 {
        TABLE_IEC
    } else {
        TABLE_SI
    };
    for (index, entry) in table.iter().enumerate() {
        if t < entry.factor {
            continue;
        }

        let quotient = t / entry.factor;
        let remainder = if index != table.len() - 1 {
            ((t / table[index + 1].factor).wrapping_mul(10) / table[table.len() - 1].factor) % 10
        } else {
            (t.wrapping_mul(10) / entry.factor) % 10
        };
        let mut length = write_u64_decimal(quotient, output);
        if flag & FORMAT_BYTES_ALWAYS_POINT != 0
            || (flag & FORMAT_BYTES_BELOW_POINT != 0 && remainder > 0)
        {
            output[length] = b'.';
            output[length + 1] = b'0' + remainder as u8;
            length += 2;
        }
        output[length] = entry.suffix.as_bytes()[0];
        return Some(length + 1);
    }

    let mut length = write_u64_decimal(t, output);
    if flag & FORMAT_BYTES_TRAILING_B != 0 {
        output[length] = b'B';
        length += 1;
    }
    Some(length)
}

/// Formats the inline `format_bytes()` ABI surface without allocating.
fn format_bytes_default_into(t: u64, output: &mut [u8; FORMAT_BYTES_MAX]) -> Option<usize> {
    format_bytes_into(
        t,
        FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT | FORMAT_BYTES_TRAILING_B,
        output,
    )
}

/// C ABI facade for `format_bytes_full()`.
///
/// # Safety
/// `buf` must be non-null and point to at least `l` writable bytes, where
/// `l >= 1`. The returned pointer aliases `buf`; no allocation occurs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_format_bytes_full(
    buf: *mut c_char,
    l: usize,
    t: u64,
    flag: c_int,
) -> *mut c_char {
    if buf.is_null() || l == 0 {
        return std::ptr::null_mut();
    }

    let mut formatted = [0_u8; FORMAT_BYTES_MAX];
    let Some(length) = format_bytes_into(t, flag as u32, &mut formatted) else {
        return std::ptr::null_mut();
    };
    let copied = length.min(l - 1);

    // SAFETY: the C ABI contract provides `l` writable bytes at `buf`.
    unsafe {
        std::ptr::copy_nonoverlapping(formatted.as_ptr().cast::<c_char>(), buf, copied);
        *buf.add(copied) = 0;
    }
    buf
}

/// C ABI facade for the inline `format_bytes()` convenience wrapper.
///
/// # Safety
/// `buf` must point to at least `l` writable bytes when `l` is non-zero.
#[unsafe(export_name = "rs_format_bytes")]
pub unsafe extern "C" fn rs_format_bytes(buf: *mut c_char, l: usize, t: u64) -> *mut c_char {
    if buf.is_null() || l == 0 {
        return std::ptr::null_mut();
    }

    let mut formatted = [0_u8; FORMAT_BYTES_MAX];
    let Some(length) = format_bytes_default_into(t, &mut formatted) else {
        return std::ptr::null_mut();
    };
    let copied = length.min(l - 1);

    // SAFETY: the C ABI contract provides `l` writable bytes at `buf`.
    unsafe {
        std::ptr::copy_nonoverlapping(formatted.as_ptr().cast::<c_char>(), buf, copied);
        *buf.add(copied) = 0;
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes_default_1536_is_1_5k() {
        assert_eq!(format_bytes(1536), Some("1.5K".to_string()));
    }

    #[test]
    fn test_format_bytes_default_below_unit() {
        assert_eq!(format_bytes(999), Some("999B".to_string()));
    }

    #[test]
    fn test_format_bytes_default_zero() {
        assert_eq!(format_bytes(0), Some("0B".to_string()));
    }

    #[test]
    fn test_format_bytes_si_1000() {
        assert_eq!(format_bytes_full(1000, 0), Some("1K".to_string()));
    }

    #[test]
    fn test_format_bytes_si_1m() {
        assert_eq!(format_bytes_full(1_000_000, 0), Some("1M".to_string()));
    }

    #[test]
    fn test_format_bytes_si_1g() {
        assert_eq!(format_bytes_full(1_000_000_000, 0), Some("1G".to_string()));
    }

    #[test]
    fn test_format_bytes_iec_1024() {
        assert_eq!(
            format_bytes_full(1024, FORMAT_BYTES_USE_IEC),
            Some("1K".to_string())
        );
    }

    #[test]
    fn test_format_bytes_iec_with_decimal() {
        let result =
            format_bytes_full(1536, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_BELOW_POINT).unwrap();
        assert_eq!(result, "1.5K");
    }

    #[test]
    fn test_format_bytes_always_point() {
        let result =
            format_bytes_full(1024, FORMAT_BYTES_USE_IEC | FORMAT_BYTES_ALWAYS_POINT).unwrap();
        assert_eq!(result, "1.0K");
    }

    #[test]
    fn test_format_bytes_max_returns_none() {
        assert!(format_bytes_full(u64::MAX, 0).is_none());
    }

    #[test]
    fn test_format_bytes_trailing_b() {
        let result = format_bytes_full(100, FORMAT_BYTES_TRAILING_B).unwrap();
        assert_eq!(result, "100B");
    }

    #[test]
    fn test_format_bytes_no_trailing_b() {
        let result = format_bytes_full(100, 0).unwrap();
        assert_eq!(result, "100");
    }

    #[test]
    fn test_format_bytes_si_1k() {
        assert_eq!(format_bytes_full(1000, 0), Some("1K".to_string()));
    }

    #[test]
    fn test_format_bytes_si_1t() {
        assert_eq!(
            format_bytes_full(1_000_000_000_000, 0),
            Some("1T".to_string())
        );
    }

    #[test]
    fn test_format_bytes_si_1p() {
        assert_eq!(
            format_bytes_full(1_000_000_000_000_000, 0),
            Some("1P".to_string())
        );
    }

    #[test]
    fn test_format_bytes_iec_1m() {
        assert_eq!(
            format_bytes_full(1024 * 1024, FORMAT_BYTES_USE_IEC),
            Some("1M".to_string())
        );
    }

    #[test]
    fn test_format_bytes_iec_1g() {
        assert_eq!(
            format_bytes_full(1024 * 1024 * 1024, FORMAT_BYTES_USE_IEC),
            Some("1G".to_string())
        );
    }

    #[test]
    fn test_format_bytes_large_si_value() {
        let result = format_bytes_full(1_500_000_000, FORMAT_BYTES_BELOW_POINT).unwrap();
        assert!(result.starts_with('1'));
        assert!(result.contains('G'));
    }

    #[test]
    fn test_format_bytes_exact_multiple_si() {
        assert_eq!(format_bytes_full(2000, 0), Some("2K".to_string()));
    }

    #[test]
    fn test_format_bytes_below_smallest_with_b() {
        assert_eq!(
            format_bytes_full(42, FORMAT_BYTES_TRAILING_B),
            Some("42B".to_string())
        );
    }
}
