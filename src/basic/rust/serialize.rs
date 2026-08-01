// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.serialize; authority=src/shared/serialize.c,src/shared/serialize.h
//
// Serialization format deserialization utilities and C ABI facades.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use crate::ffi::Errno;
use crate::time_util::DualTimestamp as CDualTimestamp;
use libc::{c_char, c_int, c_ulonglong};

// ── Types ──────────────────────────────────────────────────────────────────

/// Dual timestamp holding realtime and monotonic usec values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DualTimestamp {
    pub realtime: u64,
    pub monotonic: u64,
}

impl DualTimestamp {
    pub const fn zero() -> Self {
        DualTimestamp {
            realtime: 0,
            monotonic: 0,
        }
    }
}

// ── Error type ─────────────────────────────────────────────────────────────

/// Errors for deserialization operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializeError {
    /// Invalid argument (malformed input, empty string, etc.)
    InvalidArgument,
    /// Numeric overflow
    Overflow,
}

impl SerializeError {
    pub const fn to_errno(self) -> Errno {
        match self {
            SerializeError::InvalidArgument => Errno::EINVAL,
            SerializeError::Overflow => Errno::ERANGE,
        }
    }
}

impl From<SerializeError> for Errno {
    fn from(e: SerializeError) -> Self {
        e.to_errno()
    }
}

// ── Internal helpers ───────────────────────────────────────────────────────

fn is_whitespace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

/// Parse an ASCII decimal u64 from a byte slice starting at `pos`.
/// Returns (value, new_pos) on success, or SerializeError on failure.
fn parse_u64_from_bytes(bytes: &[u8], pos: usize) -> Result<(u64, usize), SerializeError> {
    if pos >= bytes.len() {
        return Err(SerializeError::InvalidArgument);
    }

    let mut result: u64 = 0;
    let mut i = pos;
    let mut found = false;

    while i < bytes.len() && bytes[i].is_ascii_digit() {
        let digit = (bytes[i] - b'0') as u64;
        result = result
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or(SerializeError::Overflow)?;
        i += 1;
        found = true;
    }

    if !found {
        return Err(SerializeError::InvalidArgument);
    }

    Ok((result, i))
}

// ── Public API ─────────────────────────────────────────────────────────────

/// Parse a microsecond value from a string.
///
/// Port of `deserialize_usec()` from serialize.c.
/// Calls through to safe u64 parsing — equivalent to `safe_atou64(value, ret)`.
pub fn deserialize_usec(value: &str) -> Result<u64, SerializeError> {
    if value.is_empty() {
        return Err(SerializeError::InvalidArgument);
    }

    let bytes = value.as_bytes();

    // Leading whitespace is not allowed (matches C safe_atou64 which skips whitespace,
    // but sscanf-style parsing in deserialize_usec does not)
    if is_whitespace(bytes[0]) {
        return Err(SerializeError::InvalidArgument);
    }

    // Must not start with '-'
    if bytes[0] == b'-' {
        return Err(SerializeError::InvalidArgument);
    }

    let (result, end_pos) = parse_u64_from_bytes(bytes, 0)?;

    // No trailing characters allowed
    if end_pos != bytes.len() {
        return Err(SerializeError::InvalidArgument);
    }

    Ok(result)
}

/// Parse "realtime monotonic" from a string into a `DualTimestamp`.
///
/// Port of `deserialize_dual_timestamp()` from serialize.c.
/// The input string must contain two unsigned 64-bit integers separated
/// by whitespace. Leading whitespace is skipped. No trailing characters allowed.
pub fn deserialize_dual_timestamp(value: &str) -> Result<DualTimestamp, SerializeError> {
    if value.is_empty() {
        return Err(SerializeError::InvalidArgument);
    }

    let bytes = value.as_bytes();
    let mut pos = 0;

    // Skip leading whitespace
    while pos < bytes.len() && is_whitespace(bytes[pos]) {
        pos += 1;
    }

    // First number must not start with '-'
    if pos >= bytes.len() || bytes[pos] == b'-' {
        return Err(SerializeError::InvalidArgument);
    }

    // Parse first u64
    let (realtime, next_pos) = parse_u64_from_bytes(bytes, pos)?;
    pos = next_pos;

    // Skip whitespace between numbers
    while pos < bytes.len() && is_whitespace(bytes[pos]) {
        pos += 1;
    }

    // Second number must not start with '-'
    if pos >= bytes.len() || bytes[pos] == b'-' {
        return Err(SerializeError::InvalidArgument);
    }

    // Parse second u64
    let (monotonic, next_pos) = parse_u64_from_bytes(bytes, pos)?;
    pos = next_pos;

    // Skip trailing whitespace
    while pos < bytes.len() && is_whitespace(bytes[pos]) {
        pos += 1;
    }

    // No trailing non-whitespace characters allowed
    if pos != bytes.len() {
        return Err(SerializeError::InvalidArgument);
    }

    Ok(DualTimestamp {
        realtime,
        monotonic,
    })
}

// ── C ABI facades ─────────────────────────────────────────────────────────

/// C ABI facade for `deserialize_usec()`.
///
/// `value` and `ret` must be non-null; `value` must designate a live,
/// NUL-terminated byte string and `ret` writable `uint64_t` storage. The
/// output is published only after successful parsing. This delegates to the
/// raw-byte `safe_atou64()` port, retaining the C parser's base-zero grammar
/// and errno-derived negative return values.
///
/// # Safety
///
/// `value` must point to a live NUL-terminated byte string and `ret` to
/// writable `uint64_t` storage for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_deserialize_usec(value: *const c_char, ret: *mut u64) -> c_int {
    if value.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: the facade's pointer contract is exactly that of rs_safe_atou64().
    unsafe_ffi!(crate::parse_util::rs_safe_atou64(value, ret))
}

/// C ABI facade for `deserialize_dual_timestamp()`.
///
/// `value` and `ret` must be non-null; `value` must designate a live,
/// NUL-terminated byte string and `ret` writable `dual_timestamp` storage.
/// The input is deliberately parsed through the same `strspn()`/`sscanf()`
/// sequence as the C authority, so raw-byte, whitespace, sign, overflow, and
/// libc-specific conversion behavior remain unchanged. `*ret` is assigned
/// only after all parsing checks succeed.
///
/// # Safety
///
/// `value` must point to a live NUL-terminated byte string and `ret` to
/// writable `dual_timestamp` storage for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_deserialize_dual_timestamp(
    value: *const c_char,
    ret: *mut CDualTimestamp,
) -> c_int {
    if value.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    let whitespace = c" \t\n\r";
    let digits = c"0123456789";
    let mut a: c_ulonglong = 0;
    let mut b: c_ulonglong = 0;

    // Keep `pos` as C `int`, including for the `%n` conversion below, to
    // match the authority's storage and subsequent indexing contract.
    // SAFETY: `value` is a live NUL-terminated string by this facade's
    // contract, and `whitespace` is a static NUL-terminated C string.
    let mut pos = unsafe_ffi!(libc::strspn(value, whitespace.as_ptr()) as c_int);
    // SAFETY: `pos` was measured within `value` above.
    if unsafe_ffi!(*value.add(pos as usize)) == b'-' as c_char {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: `pos` was measured within `value` above; `digits` is static.
    pos += unsafe_ffi!(libc::strspn(value.add(pos as usize), digits.as_ptr()) as c_int);
    // SAFETY: `pos` remains within the C string after the previous span.
    pos += unsafe_ffi!(libc::strspn(value.add(pos as usize), whitespace.as_ptr()) as c_int);
    // SAFETY: `pos` was measured within `value` above.
    if unsafe_ffi!(*value.add(pos as usize)) == b'-' as c_char {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: all pointers meet sscanf's C contracts. `%llu` receives
    // c_ulonglong storage, and `%n` receives C int storage.
    let scanned = unsafe_ffi!(libc::sscanf(
        value,
        c"%llu %llu%n".as_ptr(),
        &mut a,
        &mut b,
        &mut pos
    ));
    if scanned != 2 {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: successful `%n` reports an offset within `value`.
    if unsafe_ffi!(*value.add(pos as usize)) != 0 {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: `ret` is writable by this facade's pointer contract. Publish
    // only after every authority check above has succeeded.
    unsafe_ffi!({
        *ret = CDualTimestamp {
            realtime: a as u64,
            monotonic: b as u64,
        };
    });
    0
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── deserialize_usec tests ───────────────────────────────────────────

    #[test]
    fn test_deserialize_usec_zero() {
        assert_eq!(deserialize_usec("0"), Ok(0u64));
    }

    #[test]
    fn test_deserialize_usec_one() {
        assert_eq!(deserialize_usec("1"), Ok(1u64));
    }

    #[test]
    fn test_deserialize_usec_large() {
        assert_eq!(deserialize_usec("1000000"), Ok(1_000_000u64));
    }

    #[test]
    fn test_deserialize_usec_max() {
        assert_eq!(deserialize_usec("18446744073709551615"), Ok(u64::MAX));
    }

    #[test]
    fn test_deserialize_usec_empty() {
        assert_eq!(deserialize_usec(""), Err(SerializeError::InvalidArgument));
    }

    #[test]
    fn test_deserialize_usec_alpha() {
        assert_eq!(
            deserialize_usec("abc"),
            Err(SerializeError::InvalidArgument)
        );
    }

    #[test]
    fn test_deserialize_usec_negative() {
        assert_eq!(deserialize_usec("-1"), Err(SerializeError::InvalidArgument));
    }

    #[test]
    fn test_deserialize_usec_trailing_chars() {
        assert_eq!(
            deserialize_usec("12abc"),
            Err(SerializeError::InvalidArgument)
        );
    }

    #[test]
    fn test_deserialize_usec_leading_whitespace() {
        assert_eq!(
            deserialize_usec("  123"),
            Err(SerializeError::InvalidArgument)
        );
    }

    #[test]
    fn test_deserialize_usec_overflow() {
        // u64::MAX + 1 as a string would be 18446744073709551616
        assert_eq!(
            deserialize_usec("18446744073709551616"),
            Err(SerializeError::Overflow)
        );
    }

    #[test]
    fn test_deserialize_usec_plus_sign() {
        assert_eq!(deserialize_usec("+5"), Err(SerializeError::InvalidArgument));
    }

    #[test]
    fn test_deserialize_usec_simple_42() {
        assert_eq!(deserialize_usec("42"), Ok(42u64));
    }

    // ── deserialize_dual_timestamp tests ─────────────────────────────────

    #[test]
    fn test_dual_timestamp_zero_zero() {
        let ts = deserialize_dual_timestamp("0 0").unwrap();
        assert_eq!(ts.realtime, 0);
        assert_eq!(ts.monotonic, 0);
    }

    #[test]
    fn test_dual_timestamp_basic() {
        let ts = deserialize_dual_timestamp("100 200").unwrap();
        assert_eq!(ts.realtime, 100);
        assert_eq!(ts.monotonic, 200);
    }

    #[test]
    fn test_dual_timestamp_leading_whitespace() {
        let ts = deserialize_dual_timestamp("  100  200  ").unwrap();
        assert_eq!(ts.realtime, 100);
        assert_eq!(ts.monotonic, 200);
    }

    #[test]
    fn test_dual_timestamp_tab_separated() {
        let ts = deserialize_dual_timestamp("\t100\t200\n").unwrap();
        assert_eq!(ts.realtime, 100);
        assert_eq!(ts.monotonic, 200);
    }

    #[test]
    fn test_dual_timestamp_max_realtime() {
        let ts = deserialize_dual_timestamp("18446744073709551615 0").unwrap();
        assert_eq!(ts.realtime, u64::MAX);
        assert_eq!(ts.monotonic, 0);
    }

    #[test]
    fn test_dual_timestamp_empty() {
        assert_eq!(
            deserialize_dual_timestamp(""),
            Err(SerializeError::InvalidArgument)
        );
    }

    #[test]
    fn test_dual_timestamp_alpha() {
        assert_eq!(
            deserialize_dual_timestamp("abc def"),
            Err(SerializeError::InvalidArgument)
        );
    }

    #[test]
    fn test_dual_timestamp_negative_first() {
        assert_eq!(
            deserialize_dual_timestamp("-1 100"),
            Err(SerializeError::InvalidArgument)
        );
    }

    #[test]
    fn test_dual_timestamp_negative_second() {
        assert_eq!(
            deserialize_dual_timestamp("100 -1"),
            Err(SerializeError::InvalidArgument)
        );
    }

    #[test]
    fn test_dual_timestamp_only_one_number() {
        assert_eq!(
            deserialize_dual_timestamp("100"),
            Err(SerializeError::InvalidArgument)
        );
    }

    #[test]
    fn test_dual_timestamp_trailing_garbage() {
        assert_eq!(
            deserialize_dual_timestamp("100 200 extra"),
            Err(SerializeError::InvalidArgument)
        );
    }

    #[test]
    fn test_dual_timestamp_trailing_alpha_first() {
        assert_eq!(
            deserialize_dual_timestamp("100abc 200"),
            Err(SerializeError::InvalidArgument)
        );
    }

    #[test]
    fn test_dual_timestamp_trailing_alpha_second() {
        assert_eq!(
            deserialize_dual_timestamp("100 200abc"),
            Err(SerializeError::InvalidArgument)
        );
    }

    #[test]
    fn test_dual_timestamp_large_values() {
        let ts = deserialize_dual_timestamp("999999999 888888888").unwrap();
        assert_eq!(ts.realtime, 999999999);
        assert_eq!(ts.monotonic, 888888888);
    }

    #[test]
    fn test_dual_timestamp_struct_zero() {
        let ts = DualTimestamp::zero();
        assert_eq!(ts.realtime, 0);
        assert_eq!(ts.monotonic, 0);
    }
}
