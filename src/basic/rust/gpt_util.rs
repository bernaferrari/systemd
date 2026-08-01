// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.gpt-abi; authority=src/shared/gpt.c,src/shared/gpt.h,src/shared/vlan-util.c,src/shared/vlan-util.h
//
// This is the small basic-crate ABI surface used by the C shadow tests.  It is
// deliberately independent of shared/rust/gpt, which owns the generated GPT
// partition-type table and lookup API.  The core below operates on Rust
// integers and byte slices; only the exported adapters touch C pointers.

use std::ffi::{CStr, c_char, c_int};

use crate::ffi::Errno;

pub const GPT_HEADER_SIZE: usize = 92;
pub const GPT_LABEL_MAX: usize = 36;
pub const VLANID_MAX: u16 = 4094;

const PARTITION_ROOT: c_int = 0;
const PARTITION_USR: c_int = 1;
const PARTITION_HOME: c_int = 2;
const PARTITION_SRV: c_int = 3;
const PARTITION_ESP: c_int = 4;
const PARTITION_XBOOTLDR: c_int = 5;
const PARTITION_SWAP: c_int = 6;
const PARTITION_ROOT_VERITY: c_int = 7;
const PARTITION_USR_VERITY: c_int = 8;
const PARTITION_ROOT_VERITY_SIG: c_int = 9;
const PARTITION_USR_VERITY_SIG: c_int = 10;
const PARTITION_TMP: c_int = 11;
const PARTITION_VAR: c_int = 12;
const PARTITION_DESIGNATOR_INVALID: c_int = Errno::EINVAL.to_neg_errno();

const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
const GPT_REVISION_1_0: u32 = 0x0001_0000;

const MOUNT_ROOT: &[u8] = b"/\0";
const MOUNT_USR: &[u8] = b"/usr\0";
const MOUNT_HOME: &[u8] = b"/home\0";
const MOUNT_SRV: &[u8] = b"/srv\0";
// C represents this entry as the NUL-separated string "/efi\0/boot\0".
// The string-table to_string helper returns the first entry.
const MOUNT_ESP: &[u8] = b"/efi\0";
const MOUNT_XBOOTLDR: &[u8] = b"/boot\0";
const MOUNT_TMP: &[u8] = b"/var/tmp\0";
const MOUNT_VAR: &[u8] = b"/var\0";

/// ABI-stable raw mirror of C's `GptPartitionType`.
///
/// The property predicates intentionally read only `designator`. Keeping the
/// UUID, borrowed name pointer, and architecture as their native raw fields
/// preserves the by-value C ABI without ever constructing a Rust enum from an
/// arbitrary caller-provided discriminant.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GptPartitionType {
    pub uuid: [u8; 16],
    pub name: *const c_char,
    pub arch: c_int,
    pub designator: c_int,
}

/// C's `gpt_partition_type_knows_read_only()` set over a raw designator.
pub const fn gpt_partition_type_knows_read_only_designator(designator: c_int) -> bool {
    matches!(
        designator,
        PARTITION_ROOT
            | PARTITION_USR
            | PARTITION_ROOT_VERITY
            | PARTITION_USR_VERITY
            | PARTITION_ROOT_VERITY_SIG
            | PARTITION_USR_VERITY_SIG
            | PARTITION_HOME
            | PARTITION_SRV
            | PARTITION_VAR
            | PARTITION_TMP
            | PARTITION_XBOOTLDR
    )
}

/// C's `gpt_partition_type_knows_growfs()` set over a raw designator.
pub const fn gpt_partition_type_knows_growfs_designator(designator: c_int) -> bool {
    matches!(
        designator,
        PARTITION_ROOT
            | PARTITION_USR
            | PARTITION_HOME
            | PARTITION_SRV
            | PARTITION_VAR
            | PARTITION_TMP
            | PARTITION_XBOOTLDR
    )
}

/// C's `gpt_partition_type_knows_no_auto()` set over a raw designator.
pub const fn gpt_partition_type_knows_no_auto_designator(designator: c_int) -> bool {
    matches!(
        designator,
        PARTITION_ROOT
            | PARTITION_ROOT_VERITY
            | PARTITION_USR
            | PARTITION_USR_VERITY
            | PARTITION_HOME
            | PARTITION_SRV
            | PARTITION_VAR
            | PARTITION_TMP
            | PARTITION_XBOOTLDR
            | PARTITION_SWAP
    )
}

/// C's `gpt_partition_type_has_filesystem()` set over a raw designator.
pub const fn gpt_partition_type_has_filesystem_designator(designator: c_int) -> bool {
    matches!(
        designator,
        PARTITION_ROOT
            | PARTITION_USR
            | PARTITION_HOME
            | PARTITION_SRV
            | PARTITION_ESP
            | PARTITION_XBOOTLDR
            | PARTITION_TMP
            | PARTITION_VAR
    )
}

/// Exact by-value C ABI for `gpt_partition_type_knows_read_only()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_gpt_partition_type_knows_read_only(type_: GptPartitionType) -> bool {
    gpt_partition_type_knows_read_only_designator(type_.designator)
}

/// Exact by-value C ABI for `gpt_partition_type_knows_growfs()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_gpt_partition_type_knows_growfs(type_: GptPartitionType) -> bool {
    gpt_partition_type_knows_growfs_designator(type_.designator)
}

/// Exact by-value C ABI for `gpt_partition_type_knows_no_auto()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_gpt_partition_type_knows_no_auto(type_: GptPartitionType) -> bool {
    gpt_partition_type_knows_no_auto_designator(type_.designator)
}

/// Exact by-value C ABI for `gpt_partition_type_has_filesystem()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_gpt_partition_type_has_filesystem(type_: GptPartitionType) -> bool {
    gpt_partition_type_has_filesystem_designator(type_.designator)
}

/// Returns whether the designator has versioned-image semantics.
pub const fn partition_designator_is_versioned(designator: c_int) -> bool {
    matches!(
        designator,
        PARTITION_ROOT
            | PARTITION_USR
            | PARTITION_ROOT_VERITY
            | PARTITION_USR_VERITY
            | PARTITION_ROOT_VERITY_SIG
            | PARTITION_USR_VERITY_SIG
    )
}

/// Maps a data partition designator to its verity-hash partition.
pub const fn partition_verity_hash_of(designator: c_int) -> c_int {
    match designator {
        PARTITION_ROOT => PARTITION_ROOT_VERITY,
        PARTITION_USR => PARTITION_USR_VERITY,
        _ => PARTITION_DESIGNATOR_INVALID,
    }
}

/// Maps a data partition designator to its verity-signature partition.
pub const fn partition_verity_sig_of(designator: c_int) -> c_int {
    match designator {
        PARTITION_ROOT => PARTITION_ROOT_VERITY_SIG,
        PARTITION_USR => PARTITION_USR_VERITY_SIG,
        _ => PARTITION_DESIGNATOR_INVALID,
    }
}

/// Maps a verity-hash designator to its data partition.
pub const fn partition_verity_hash_to_data(designator: c_int) -> c_int {
    match designator {
        PARTITION_ROOT_VERITY => PARTITION_ROOT,
        PARTITION_USR_VERITY => PARTITION_USR,
        _ => PARTITION_DESIGNATOR_INVALID,
    }
}

/// Maps a verity-signature designator to its data partition.
pub const fn partition_verity_sig_to_data(designator: c_int) -> c_int {
    match designator {
        PARTITION_ROOT_VERITY_SIG => PARTITION_ROOT,
        PARTITION_USR_VERITY_SIG => PARTITION_USR,
        _ => PARTITION_DESIGNATOR_INVALID,
    }
}

/// Maps either kind of verity designator to its data partition.
pub const fn partition_verity_to_data(designator: c_int) -> c_int {
    let data = partition_verity_hash_to_data(designator);
    if data >= 0 {
        data
    } else {
        partition_verity_sig_to_data(designator)
    }
}

/// Returns the first mountpoint in C's NUL-separated mountpoint entry.
pub const fn partition_mountpoint_to_string(designator: c_int) -> Option<&'static [u8]> {
    match designator {
        PARTITION_ROOT => Some(MOUNT_ROOT),
        PARTITION_USR => Some(MOUNT_USR),
        PARTITION_HOME => Some(MOUNT_HOME),
        PARTITION_SRV => Some(MOUNT_SRV),
        PARTITION_ESP => Some(MOUNT_ESP),
        PARTITION_XBOOTLDR => Some(MOUNT_XBOOTLDR),
        PARTITION_TMP => Some(MOUNT_TMP),
        PARTITION_VAR => Some(MOUNT_VAR),
        _ => None,
    }
}

/// Returns whether a designator denotes a verity-hash partition.
pub const fn partition_designator_is_verity_hash(designator: c_int) -> bool {
    partition_verity_hash_to_data(designator) >= 0
}

/// Returns whether a designator denotes a verity-signature partition.
pub const fn partition_designator_is_verity_sig(designator: c_int) -> bool {
    partition_verity_sig_to_data(designator) >= 0
}

/// Returns whether a designator denotes either kind of verity partition.
pub const fn partition_designator_is_verity(designator: c_int) -> bool {
    partition_verity_to_data(designator) >= 0
}

/// Checks all fields examined by C's `gpt_header_has_signature()`.
///
/// This only needs the bytes C reads (through `my_lba` at offset 24), but it
/// enforces C's full header-size policy: revision 1.0, 92..=4096 bytes, and
/// a primary-header LBA of one.
pub fn gpt_header_has_signature(bytes: &[u8]) -> bool {
    if bytes.len() < 32 || bytes[..8] != GPT_SIGNATURE[..] {
        return false;
    }

    let revision = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if revision != GPT_REVISION_1_0 {
        return false;
    }

    let header_size = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    if !(GPT_HEADER_SIZE as u32..=4096).contains(&header_size) {
        return false;
    }

    u64::from_le_bytes([
        bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
    ]) == 1
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlanIdError {
    Invalid,
    Range,
}

impl VlanIdError {
    pub const fn errno(self) -> c_int {
        match self {
            Self::Invalid => Errno::EINVAL.to_neg_errno(),
            Self::Range => Errno::ERANGE.to_neg_errno(),
        }
    }
}

const fn ascii_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

const fn digit_value(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some((byte - b'0') as u32),
        b'a'..=b'z' => Some((byte - b'a' + 10) as u32),
        b'A'..=b'Z' => Some((byte - b'A' + 10) as u32),
        _ => None,
    }
}

/// Parses exactly the `safe_atou16()` subset used by C's `parse_vlanid()`.
///
/// In particular, C's base-zero spelling is retained: decimal by default,
/// octal for a leading zero, hexadecimal for `0x`, and systemd's `0b`/`0o`
/// extensions. The returned value has already passed the VLAN upper bound.
pub fn parse_vlanid(bytes: &[u8]) -> Result<u16, VlanIdError> {
    let mut index = 0;
    while index < bytes.len() && ascii_whitespace(bytes[index]) {
        index += 1;
    }

    let negative = match bytes.get(index) {
        Some(b'+') => {
            index += 1;
            false
        }
        Some(b'-') => {
            index += 1;
            true
        }
        _ => false,
    };

    let mut base = 10;
    if bytes.get(index) == Some(&b'0') {
        match bytes.get(index + 1) {
            Some(b'x') | Some(b'X') => {
                base = 16;
                index += 2;
            }
            Some(b'b') | Some(b'B') => {
                base = 2;
                index += 2;
            }
            Some(b'o') | Some(b'O') => {
                base = 8;
                index += 2;
            }
            _ => {
                base = 8;
                // Keep the leading zero as a digit. This matches `strtoul`
                // base-zero parsing, including the valid one-byte spelling
                // "0" (and the special negative-zero case below).
            }
        }
    }

    let first_digit = index;
    let mut value = 0_u32;
    while let Some(&byte) = bytes.get(index) {
        let Some(digit) = digit_value(byte) else {
            break;
        };
        if digit >= base {
            break;
        }
        value = value
            .checked_mul(base)
            .and_then(|current| current.checked_add(digit))
            .ok_or(VlanIdError::Range)?;
        index += 1;
    }

    if index == first_digit || index != bytes.len() {
        return Err(VlanIdError::Invalid);
    }
    if negative && value != 0 {
        return Err(VlanIdError::Range);
    }
    if value > u16::MAX as u32 || value > VLANID_MAX as u32 {
        return Err(VlanIdError::Range);
    }

    Ok(value as u16)
}

const fn utf8_encoded_expected_len(byte: u8) -> usize {
    if byte < 0x80 {
        1
    } else if byte & 0xe0 == 0xc0 {
        2
    } else if byte & 0xf0 == 0xe0 {
        3
    } else if byte & 0xf8 == 0xf0 {
        4
    } else if byte & 0xfc == 0xf8 {
        5
    } else if byte & 0xfe == 0xfc {
        6
    } else {
        0
    }
}

/// Counts UTF-16 units exactly as C's `utf8_to_utf16()` does for a C string.
///
/// The C conversion is deliberately permissive: malformed or truncated bytes
/// are copied as individual 16-bit units, while invalid decoded scalar values
/// consume their complete UTF-8-looking sequence but produce no unit. Keeping
/// that distinction preserves existing GPT-label compatibility without an
/// allocation or a lossy Rust UTF-8 conversion.
pub fn gpt_partition_label_valid(bytes: &[u8]) -> bool {
    let mut index = 0;
    let mut units = 0_usize;

    while index < bytes.len() {
        let length = utf8_encoded_expected_len(bytes[index]);
        if length <= 1 || index + length > bytes.len() {
            units = units.saturating_add(1);
            if units > GPT_LABEL_MAX {
                return false;
            }
            index += 1;
            continue;
        }

        let mut codepoint = match length {
            2 => (bytes[index] & 0x1f) as u32,
            3 => (bytes[index] & 0x0f) as u32,
            4 => (bytes[index] & 0x07) as u32,
            5 => (bytes[index] & 0x03) as u32,
            6 => (bytes[index] & 0x01) as u32,
            _ => {
                // Keep the core total even if the expected-length helper is
                // changed in the future: C's fallback consumes one byte.
                units = units.saturating_add(1);
                if units > GPT_LABEL_MAX {
                    return false;
                }
                index += 1;
                continue;
            }
        };
        if !(1..length).all(|offset| bytes[index + offset] & 0xc0 == 0x80) {
            units = units.saturating_add(1);
            if units > GPT_LABEL_MAX {
                return false;
            }
            index += 1;
            continue;
        }

        for offset in 1..length {
            codepoint = (codepoint << 6) | (bytes[index + offset] & 0x3f) as u32;
        }
        // C's utf16_encode_unichar writes U+0000 as a zero char16_t. The
        // follow-up char16_strlen then stops there, so an overlong UTF-8 NUL
        // has the same observable effect as an early logical terminator.
        if codepoint == 0 {
            return units <= GPT_LABEL_MAX;
        }
        units = units.saturating_add(match codepoint {
            0..=0xd7ff | 0xe000..=0xffff => 1,
            0x10000..=0x10ffff => 2,
            _ => 0,
        });
        if units > GPT_LABEL_MAX {
            return false;
        }
        index += length;
    }

    units <= GPT_LABEL_MAX
}

/// C ABI adapter for `gpt_header_has_signature`.
///
/// # Safety
/// `p` must be null or point to at least 32 readable bytes. The function never
/// writes through it. A null pointer is rejected with `false`, rather than
/// reproducing C's assertion failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_gpt_header_has_signature(p: *const u8) -> bool {
    if p.is_null() {
        return false;
    }

    // SAFETY: guaranteed by this adapter's documented contract; the safe core
    // only examines the 32 bytes C reads while checking the packed header.
    let header = unsafe_ffi!(std::slice::from_raw_parts(p, 32));
    gpt_header_has_signature(header)
}

/// C ABI adapter for `partition_designator_is_versioned`.
///
/// # Safety
/// This has no pointer arguments; `unsafe` marks the stable C ABI boundary.
#[unsafe(no_mangle)]
pub extern "C" fn rs_partition_designator_is_versioned(designator: c_int) -> bool {
    partition_designator_is_versioned(designator)
}

/// C ABI adapter for `partition_verity_hash_of`.
///
/// # Safety
/// This has no pointer arguments; `unsafe` marks the stable C ABI boundary.
#[unsafe(no_mangle)]
pub extern "C" fn rs_partition_verity_hash_of(designator: c_int) -> c_int {
    partition_verity_hash_of(designator)
}

/// C ABI adapter for `partition_verity_sig_of`.
///
/// # Safety
/// This has no pointer arguments; `unsafe` marks the stable C ABI boundary.
#[unsafe(no_mangle)]
pub extern "C" fn rs_partition_verity_sig_of(designator: c_int) -> c_int {
    partition_verity_sig_of(designator)
}

/// C ABI adapter for `partition_verity_hash_to_data`.
///
/// # Safety
/// This has no pointer arguments; `unsafe` marks the stable C ABI boundary.
#[unsafe(no_mangle)]
pub extern "C" fn rs_partition_verity_hash_to_data(designator: c_int) -> c_int {
    partition_verity_hash_to_data(designator)
}

/// C ABI adapter for `partition_verity_sig_to_data`.
///
/// # Safety
/// This has no pointer arguments; `unsafe` marks the stable C ABI boundary.
#[unsafe(no_mangle)]
pub extern "C" fn rs_partition_verity_sig_to_data(designator: c_int) -> c_int {
    partition_verity_sig_to_data(designator)
}

/// C ABI adapter for `partition_verity_to_data`.
///
/// # Safety
/// This has no pointer arguments; `unsafe` marks the stable C ABI boundary.
#[unsafe(no_mangle)]
pub extern "C" fn rs_partition_verity_to_data(designator: c_int) -> c_int {
    partition_verity_to_data(designator)
}

/// C ABI adapter for `partition_mountpoint_to_string`.
///
/// # Safety
/// The returned non-null pointer is a process-lifetime NUL-terminated static
/// string. Callers must not modify or free it.
#[unsafe(no_mangle)]
pub extern "C" fn rs_partition_mountpoint_to_string(designator: c_int) -> *const c_char {
    partition_mountpoint_to_string(designator)
        .map(|mountpoint| mountpoint.as_ptr().cast())
        .unwrap_or(std::ptr::null())
}

/// C ABI adapter for `parse_vlanid`.
///
/// # Safety
/// `p` must be null or a valid NUL-terminated C string; `ret` must be null or
/// a valid writable `uint16_t`. Both null pointers fail closed with `-EINVAL`.
/// On every failure `ret` is left untouched; on success it receives the parsed
/// value exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_parse_vlanid(p: *const c_char, ret: *mut u16) -> c_int {
    if p.is_null() || ret.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: guaranteed by this adapter's documented contract. CStr accepts
    // arbitrary bytes, preserving C's non-UTF-8 parsing semantics.
    let text = unsafe_ffi!(CStr::from_ptr(p)).to_bytes();
    match parse_vlanid(text) {
        Ok(value) => {
            // SAFETY: `ret` is non-null and writable by this adapter contract.
            unsafe_ffi!(ret.write(value));
            0
        }
        Err(error) => error.errno(),
    }
}

/// C ABI adapter for `gpt_partition_label_valid`.
///
/// # Safety
/// `s` must be null or a valid NUL-terminated C string. A null pointer returns
/// `-EINVAL`; otherwise the result is `0` or `1`. Unlike C this no-allocation
/// implementation cannot return `-ENOMEM` after a valid input is borrowed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_gpt_partition_label_valid(s: *const c_char) -> c_int {
    if s.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: guaranteed by this adapter's documented contract.
    let text = unsafe_ffi!(CStr::from_ptr(s)).to_bytes();
    if gpt_partition_label_valid(text) {
        1
    } else {
        0
    }
}

/// C ABI adapter for `partition_designator_is_verity_hash`.
///
/// # Safety
/// This has no pointer arguments; `unsafe` marks the stable C ABI boundary.
#[unsafe(no_mangle)]
pub extern "C" fn rs_partition_designator_is_verity_hash(designator: c_int) -> bool {
    partition_designator_is_verity_hash(designator)
}

/// C ABI adapter for `partition_designator_is_verity_sig`.
///
/// # Safety
/// This has no pointer arguments; `unsafe` marks the stable C ABI boundary.
#[unsafe(no_mangle)]
pub extern "C" fn rs_partition_designator_is_verity_sig(designator: c_int) -> bool {
    partition_designator_is_verity_sig(designator)
}

/// C ABI adapter for `partition_designator_is_verity`.
///
/// # Safety
/// This has no pointer arguments; `unsafe` marks the stable C ABI boundary.
#[unsafe(no_mangle)]
pub extern "C" fn rs_partition_designator_is_verity(designator: c_int) -> bool {
    partition_designator_is_verity(designator)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vlanid_keeps_c_base_zero_spellings() {
        assert_eq!(parse_vlanid(b"4094"), Ok(4094));
        assert_eq!(parse_vlanid(b"  42"), Ok(42));
        assert_eq!(parse_vlanid(b"077"), Ok(63));
        assert_eq!(parse_vlanid(b"0x10"), Ok(16));
        assert_eq!(parse_vlanid(b"0b10"), Ok(2));
        assert_eq!(parse_vlanid(b"0o10"), Ok(8));
        assert_eq!(parse_vlanid(b"4095"), Err(VlanIdError::Range));
        assert_eq!(parse_vlanid(b"09"), Err(VlanIdError::Invalid));
    }

    #[test]
    fn labels_count_utf16_units_and_c_fallback_bytes() {
        assert!(gpt_partition_label_valid(&[b'a'; GPT_LABEL_MAX]));
        assert!(!gpt_partition_label_valid(&[b'a'; GPT_LABEL_MAX + 1]));
        assert!(gpt_partition_label_valid("😀".as_bytes()));
        assert!(gpt_partition_label_valid(&[0x80; GPT_LABEL_MAX]));
    }

    #[test]
    fn overlong_nul_matches_c_utf16_terminator_behavior() {
        let mut label = [b'a'; GPT_LABEL_MAX + 1];
        label[18] = 0xc0;
        label[19] = 0x80;
        assert!(gpt_partition_label_valid(&label));
    }
}
