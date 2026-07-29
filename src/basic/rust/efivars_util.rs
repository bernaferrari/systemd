// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.efivars-util; authority=src/fundamental/efivars.c,src/fundamental/efivars.h,src/basic/efivars.c,src/basic/efivars.h,src/shared/efi-api.c,src/shared/efi-api.h
//
// UEFI Secure Boot mode string table, state machine decoder,
// backslash-to-slash conversion, and GUID/ID128 byte-order conversion.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

// ── Secure boot mode enum ────────────────────────────────────────────────

/// UEFI Secure Boot modes (mirrors `SecureBootMode` from efivars.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SecureBootMode {
    Unsupported = 0,
    Disabled = 1,
    Unknown = 2,
    Audit = 3,
    Deployed = 4,
    Setup = 5,
    User = 6,
    Tainted = 7,
}

/// Error value for invalid GUID operations.
const EINVAL: i32 = -22;

// ── secure_boot_mode_to_string ───────────────────────────────────────────

const SECURE_BOOT_STRINGS: [&str; 8] = [
    "unsupported",
    "disabled",
    "unknown",
    "audit",
    "deployed",
    "setup",
    "user",
    "tainted",
];

/// Convert a secure boot mode to its string name.
/// Mirrors `secure_boot_mode_to_string()` from efivars.c.
pub fn secure_boot_mode_to_string(m: SecureBootMode) -> Option<&'static str> {
    let idx = m as usize;
    if idx < SECURE_BOOT_STRINGS.len() {
        Some(SECURE_BOOT_STRINGS[idx])
    } else {
        None
    }
}

/// Convert a raw i32 to a secure boot mode string (for interop with C integer values).
pub fn secure_boot_mode_to_string_from_i32(m: i32) -> Option<&'static str> {
    if m >= 0 && (m as usize) < SECURE_BOOT_STRINGS.len() {
        Some(SECURE_BOOT_STRINGS[m as usize])
    } else {
        None
    }
}

// ── decode_secure_boot_mode ──────────────────────────────────────────────

/// Decode UEFI Secure Boot state into a `SecureBootMode` value.
/// Mirrors `decode_secure_boot_mode()` from efivars.c.
///
/// The priority order matches the UEFI Specification 2.9 Figure 32-4.
pub fn decode_secure_boot_mode(
    secure: bool,
    audit: bool,
    deployed: bool,
    setup: bool,
    moksb: bool,
) -> SecureBootMode {
    if secure && moksb {
        return SecureBootMode::Tainted;
    }
    if secure && deployed && !audit && !setup {
        return SecureBootMode::Deployed;
    }
    if secure && !deployed && !audit && !setup {
        return SecureBootMode::User;
    }
    if !secure && !deployed && audit && setup {
        return SecureBootMode::Audit;
    }
    if !secure && !deployed && !audit && setup {
        return SecureBootMode::Setup;
    }
    if !secure && !deployed && !audit && !setup {
        return SecureBootMode::Disabled;
    }
    SecureBootMode::Unknown
}

// ── efi_tilt_backslashes ────────────────────────────────────────────────

/// Replace all backslashes with forward slashes in a string.
/// Mirrors `efi_tilt_backslashes()` from efivars.c (which calls `string_replace_char(s, '\\', '/')`).
pub fn efi_tilt_backslashes(s: &str) -> String {
    s.replace('\\', "/")
}

/// In-place backslash replacement for a mutable byte buffer.
pub fn efi_tilt_backslashes_in_place(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        if *b == b'\\' {
            *b = b'/';
        }
    }
}

// ── GUID ↔ ID128 conversion ─────────────────────────────────────────────

/// EFI GUID struct layout (mixed-endian): Data1(u32), Data2(u16), Data3(u16), Data4([u8;8]).
/// Total: 16 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct EfiGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// sd_id128_t representation: 16 bytes in big-endian display order.
pub type Id128 = [u8; 16];

/// Convert an EFI GUID to ID128 format (mixed-endian to big-endian byte order).
/// Mirrors `efi_guid_to_id128()` from efi-api.c.
///
/// Data1/Data2/Data3 are native-endian integer fields in the EFI_GUID struct.
/// We convert their numeric values to big-endian byte order for display/storage.
pub fn efi_guid_to_id128(guid: &EfiGuid) -> Id128 {
    let mut result = [0u8; 16];

    let d1 = guid.data1;
    let d2 = guid.data2;
    let d3 = guid.data3;

    result[0] = ((d1 >> 24) & 0xff) as u8;
    result[1] = ((d1 >> 16) & 0xff) as u8;
    result[2] = ((d1 >> 8) & 0xff) as u8;
    result[3] = (d1 & 0xff) as u8;
    result[4] = ((d2 >> 8) & 0xff) as u8;
    result[5] = (d2 & 0xff) as u8;
    result[6] = ((d3 >> 8) & 0xff) as u8;
    result[7] = (d3 & 0xff) as u8;
    result[8..16].copy_from_slice(&guid.data4);

    result
}

/// Convert raw GUID bytes (as laid out in memory) to ID128 format.
/// The raw bytes are interpreted as: Data1[4] + Data2[2] + Data3[2] + Data4[8] in native endian.
pub fn efi_guid_bytes_to_id128(guid_bytes: &[u8; 16]) -> Result<Id128, i32> {
    let d1 = u32::from_ne_bytes([guid_bytes[0], guid_bytes[1], guid_bytes[2], guid_bytes[3]]);
    let d2 = u16::from_ne_bytes([guid_bytes[4], guid_bytes[5]]);
    let d3 = u16::from_ne_bytes([guid_bytes[6], guid_bytes[7]]);

    let mut result = [0u8; 16];
    result[0] = ((d1 >> 24) & 0xff) as u8;
    result[1] = ((d1 >> 16) & 0xff) as u8;
    result[2] = ((d1 >> 8) & 0xff) as u8;
    result[3] = (d1 & 0xff) as u8;
    result[4] = ((d2 >> 8) & 0xff) as u8;
    result[5] = (d2 & 0xff) as u8;
    result[6] = ((d3 >> 8) & 0xff) as u8;
    result[7] = (d3 & 0xff) as u8;
    result[8..16].copy_from_slice(&guid_bytes[8..16]);

    Ok(result)
}

/// Convert ID128 format to EFI GUID (big-endian to mixed-endian byte order).
/// Mirrors `efi_id128_to_guid()` from efi-api.c.
pub fn efi_id128_to_guid(id: &Id128) -> EfiGuid {
    let d1 = (u32::from(id[0]) << 24)
        | (u32::from(id[1]) << 16)
        | (u32::from(id[2]) << 8)
        | u32::from(id[3]);
    let d2 = (u16::from(id[4]) << 8) | u16::from(id[5]);
    let d3 = (u16::from(id[6]) << 8) | u16::from(id[7]);

    let mut data4 = [0u8; 8];
    data4.copy_from_slice(&id[8..16]);

    EfiGuid {
        data1: d1,
        data2: d2,
        data3: d3,
        data4,
    }
}

/// Convert ID128 to raw GUID bytes (as laid out in memory).
pub fn efi_id128_to_guid_bytes(id: &Id128) -> [u8; 16] {
    let guid = efi_id128_to_guid(id);
    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&guid.data1.to_ne_bytes());
    result[4..6].copy_from_slice(&guid.data2.to_ne_bytes());
    result[6..8].copy_from_slice(&guid.data3.to_ne_bytes());
    result[8..16].copy_from_slice(&guid.data4);
    result
}

// ── C ABI ────────────────────────────────────────────────────────────────

/// C ABI mirror of `secure_boot_mode_to_string()`.
///
/// The returned pointer is borrowed immutable static storage and is null for
/// values outside the C enum's valid range.
#[unsafe(no_mangle)]
pub extern "C" fn rs_secure_boot_mode_to_string(m: c_int) -> *const c_char {
    match m {
        0 => c"unsupported".as_ptr(),
        1 => c"disabled".as_ptr(),
        2 => c"unknown".as_ptr(),
        3 => c"audit".as_ptr(),
        4 => c"deployed".as_ptr(),
        5 => c"setup".as_ptr(),
        6 => c"user".as_ptr(),
        7 => c"tainted".as_ptr(),
        _ => ptr::null(),
    }
}

/// C ABI mirror of `decode_secure_boot_mode()`.
#[unsafe(no_mangle)]
pub extern "C" fn rs_decode_secure_boot_mode(
    secure: bool,
    audit: bool,
    deployed: bool,
    setup: bool,
    moksb: bool,
) -> c_int {
    decode_secure_boot_mode(secure, audit, deployed, setup, moksb) as c_int
}

/// C ABI mirror of `efi_tilt_backslashes()`.
///
/// A null input is outside the C function's asserted contract; it returns null
/// here as a fail-closed extension. Otherwise `s` must name a writable,
/// NUL-terminated C byte string for the duration of this call.
///
/// # Safety
/// `s` must satisfy the writable C-string requirement above whenever non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_efi_tilt_backslashes(s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }

    let mut cursor = s.cast::<u8>();
    loop {
        // SAFETY: the C ABI contract requires a readable NUL-terminated string
        // and writable bytes through that terminator; `cursor` advances within it.
        let byte = unsafe { *cursor };
        if byte == 0 {
            return s;
        }
        if byte == b'\\' {
            // SAFETY: this is the current byte of the writable C string above.
            unsafe { *cursor = b'/' };
        }
        // SAFETY: `cursor` has not reached the required terminating NUL.
        cursor = unsafe { cursor.add(1) };
    }
}

/// C ABI facade for `efi_guid_to_id128()` using output storage instead of the
/// C function's by-value union return. The input may be unaligned, just as C's
/// `memcpy`-based implementation permits.
///
/// Null pointers are outside C's asserted contract and return `-EINVAL` here.
///
/// # Safety
/// Non-null `guid` and `ret` must respectively name 16 readable and 16
/// writable bytes for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_efi_guid_to_id128(guid: *const c_void, ret: *mut u8) -> c_int {
    if guid.is_null() || ret.is_null() {
        return EINVAL;
    }

    let mut raw_guid = [0u8; 16];
    // SAFETY: the C ABI requires `guid` to name 16 readable bytes. The local
    // array is distinct, aligned storage and therefore also handles unaligned input.
    unsafe { ptr::copy_nonoverlapping(guid.cast::<u8>(), raw_guid.as_mut_ptr(), raw_guid.len()) };
    let id = efi_guid_bytes_to_id128(&raw_guid).expect("fixed-size GUID conversion cannot fail");
    // SAFETY: the C ABI requires `ret` to name 16 writable bytes; `id` is local.
    unsafe { ptr::copy_nonoverlapping(id.as_ptr(), ret, id.len()) };
    0
}

/// C ABI facade for `efi_id128_to_guid()` using an ID128 byte pointer.
///
/// Null pointers are outside C's asserted contract and are a no-op extension
/// because this void-returning ABI has no error channel.
///
/// # Safety
/// Non-null `id` and `ret_guid` must respectively name 16 readable and 16
/// writable bytes for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_efi_id128_to_guid(id: *const u8, ret_guid: *mut c_void) {
    if id.is_null() || ret_guid.is_null() {
        return;
    }

    let mut id_bytes = [0u8; 16];
    // SAFETY: the C ABI requires 16 readable bytes at `id`; the local is distinct.
    unsafe { ptr::copy_nonoverlapping(id, id_bytes.as_mut_ptr(), id_bytes.len()) };
    let guid = efi_id128_to_guid_bytes(&id_bytes);
    // SAFETY: the C ABI requires 16 writable bytes at `ret_guid`; `guid` is local.
    unsafe { ptr::copy_nonoverlapping(guid.as_ptr(), ret_guid.cast::<u8>(), guid.len()) };
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_boot_mode_to_string_all() {
        assert_eq!(
            secure_boot_mode_to_string(SecureBootMode::Unsupported),
            Some("unsupported")
        );
        assert_eq!(
            secure_boot_mode_to_string(SecureBootMode::Disabled),
            Some("disabled")
        );
        assert_eq!(
            secure_boot_mode_to_string(SecureBootMode::Unknown),
            Some("unknown")
        );
        assert_eq!(
            secure_boot_mode_to_string(SecureBootMode::Audit),
            Some("audit")
        );
        assert_eq!(
            secure_boot_mode_to_string(SecureBootMode::Deployed),
            Some("deployed")
        );
        assert_eq!(
            secure_boot_mode_to_string(SecureBootMode::Setup),
            Some("setup")
        );
        assert_eq!(
            secure_boot_mode_to_string(SecureBootMode::User),
            Some("user")
        );
        assert_eq!(
            secure_boot_mode_to_string(SecureBootMode::Tainted),
            Some("tainted")
        );
    }

    #[test]
    fn test_secure_boot_mode_to_string_from_i32() {
        assert_eq!(secure_boot_mode_to_string_from_i32(0), Some("unsupported"));
        assert_eq!(secure_boot_mode_to_string_from_i32(7), Some("tainted"));
        assert_eq!(secure_boot_mode_to_string_from_i32(-1), None);
        assert_eq!(secure_boot_mode_to_string_from_i32(8), None);
        assert_eq!(secure_boot_mode_to_string_from_i32(100), None);
    }

    #[test]
    fn test_decode_secure_boot_deployed() {
        assert_eq!(
            decode_secure_boot_mode(true, false, true, false, false),
            SecureBootMode::Deployed
        );
    }

    #[test]
    fn test_decode_secure_boot_user() {
        assert_eq!(
            decode_secure_boot_mode(true, false, false, false, false),
            SecureBootMode::User
        );
    }

    #[test]
    fn test_decode_secure_boot_audit() {
        assert_eq!(
            decode_secure_boot_mode(false, true, false, true, false),
            SecureBootMode::Audit
        );
    }

    #[test]
    fn test_decode_secure_boot_setup() {
        assert_eq!(
            decode_secure_boot_mode(false, false, false, true, false),
            SecureBootMode::Setup
        );
    }

    #[test]
    fn test_decode_secure_boot_disabled() {
        assert_eq!(
            decode_secure_boot_mode(false, false, false, false, false),
            SecureBootMode::Disabled
        );
    }

    #[test]
    fn test_decode_secure_boot_tainted() {
        assert_eq!(
            decode_secure_boot_mode(true, false, false, false, true),
            SecureBootMode::Tainted
        );
    }

    #[test]
    fn test_decode_secure_boot_tainted_overrides_deployed() {
        assert_eq!(
            decode_secure_boot_mode(true, false, true, false, true),
            SecureBootMode::Tainted
        );
    }

    #[test]
    fn test_decode_secure_boot_unknown() {
        assert_eq!(
            decode_secure_boot_mode(true, true, false, false, false),
            SecureBootMode::Unknown
        );
    }

    #[test]
    fn test_efi_tilt_backslashes() {
        assert_eq!(efi_tilt_backslashes("hi"), "hi");
        assert_eq!(efi_tilt_backslashes(r"a\b"), "a/b");
        assert_eq!(efi_tilt_backslashes(r"\foo\bar"), "/foo/bar");
        assert_eq!(efi_tilt_backslashes(""), "");
        assert_eq!(efi_tilt_backslashes(r"\\\"), "///");
        assert_eq!(efi_tilt_backslashes("/a/b"), "/a/b");
    }

    #[test]
    fn test_efi_tilt_backslashes_in_place() {
        let mut buf = [b'a', b'\\', b'b'];
        efi_tilt_backslashes_in_place(&mut buf);
        assert_eq!(&buf, b"a/b");

        let mut buf2 = [b'\\', b'\\', b'\\'];
        efi_tilt_backslashes_in_place(&mut buf2);
        assert_eq!(&buf2, b"///");

        let mut empty: [u8; 0] = [];
        efi_tilt_backslashes_in_place(&mut empty);
    }

    #[test]
    fn test_efi_guid_to_id128_zero() {
        let guid = EfiGuid {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0u8; 8],
        };
        let result = efi_guid_to_id128(&guid);
        assert_eq!(result, [0u8; 16]);
    }

    #[test]
    fn test_efi_guid_to_id128_known() {
        // These are native integer fields, matching the C EFI_GUID struct.
        let guid = EfiGuid {
            data1: 0x8bf06e4f,
            data2: 0x3412,
            data3: 0x5678,
            data4: [0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78],
        };
        let result = efi_guid_to_id128(&guid);
        assert_eq!(result[0], 0x8b);
        assert_eq!(result[1], 0xf0);
        assert_eq!(result[2], 0x6e);
        assert_eq!(result[3], 0x4f);
        assert_eq!(result[4], 0x34);
        assert_eq!(result[5], 0x12);
        assert_eq!(result[6], 0x56);
        assert_eq!(result[7], 0x78);
        assert_eq!(
            &result[8..16],
            &[0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78]
        );
    }

    #[test]
    fn test_efi_guid_bytes_to_id128() {
        let mut guid_bytes = [0u8; 16];
        guid_bytes[..4].copy_from_slice(&0x8bf06e4fu32.to_ne_bytes());
        guid_bytes[4..6].copy_from_slice(&0x3412u16.to_ne_bytes());
        guid_bytes[6..8].copy_from_slice(&0x5678u16.to_ne_bytes());
        guid_bytes[8..].copy_from_slice(&[0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78]);
        let result = efi_guid_bytes_to_id128(&guid_bytes).unwrap();
        assert_eq!(
            result,
            [
                0x8b, 0xf0, 0x6e, 0x4f, 0x34, 0x12, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
                0x56, 0x78,
            ]
        );
    }

    #[test]
    fn test_efi_id128_to_guid_zero() {
        let id = [0u8; 16];
        let guid = efi_id128_to_guid(&id);
        assert_eq!(guid.data1, 0);
        assert_eq!(guid.data2, 0);
        assert_eq!(guid.data3, 0);
        assert_eq!(guid.data4, [0u8; 8]);
    }

    #[test]
    fn test_efi_id128_to_guid_known() {
        let id: Id128 = [
            0x8b, 0xf0, 0x6e, 0x4f, 0x34, 0x12, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
            0x56, 0x78,
        ];
        let guid = efi_id128_to_guid(&id);
        assert_eq!(guid.data1, 0x8bf06e4f);
        assert_eq!(guid.data2, 0x3412);
        assert_eq!(guid.data3, 0x7856);
        assert_eq!(guid.data4, [0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_efi_guid_id128_roundtrip() {
        let original: Id128 = [
            0x8b, 0xf0, 0x6e, 0x4f, 0x34, 0x12, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
            0x56, 0x78,
        ];
        let guid = efi_id128_to_guid(&original);
        let result = efi_guid_to_id128(&guid);
        assert_eq!(result, original);
    }

    #[test]
    fn test_efi_guid_bytes_roundtrip() {
        let original: Id128 = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let guid_bytes = efi_id128_to_guid_bytes(&original);
        let result = efi_guid_bytes_to_id128(&guid_bytes).unwrap();
        assert_eq!(result, original);
    }
}
