// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/efivars.c (secure_boot_mode_to_string, decode_secure_boot_mode)
//            src/basic/efivars.c (efi_tilt_backslashes)
//            src/shared/efi-api.c (efi_guid_to_id128, efi_id128_to_guid)
//
// UEFI Secure Boot mode string table, state machine decoder,
// backslash-to-slash conversion, and GUID/ID128 byte-order conversion.

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

static SECURE_BOOT_STRINGS: [&str; 8] = [
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
#[repr(C, packed)]
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
/// Data1/Data2/Data3 are stored as native-endian in the EFI_GUID struct.
/// We convert them to big-endian byte order for display/storage.
pub fn efi_guid_to_id128(guid: &EfiGuid) -> Id128 {
    let mut result = [0u8; 16];

    let d1 = u32::from_le(guid.data1);
    let d2 = u16::from_le(guid.data2);
    let d3 = u16::from_le(guid.data3);

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
    // On a little-endian system (which Linux targets are), the EFI_GUID struct
    // has Data1/Data2/Data3 stored as little-endian integers.
    let d1 = u32::from_le_bytes([guid_bytes[0], guid_bytes[1], guid_bytes[2], guid_bytes[3]]);
    let d2 = u16::from_le_bytes([guid_bytes[4], guid_bytes[5]]);
    let d3 = u16::from_le_bytes([guid_bytes[6], guid_bytes[7]]);

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
        data1: u32::to_le(d1),
        data2: u16::to_le(d2),
        data3: u16::to_le(d3),
        data4,
    }
}

/// Convert ID128 to raw GUID bytes (as laid out in memory).
pub fn efi_id128_to_guid_bytes(id: &Id128) -> [u8; 16] {
    let guid = efi_id128_to_guid(id);
    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&guid.data1.to_le_bytes());
    result[4..6].copy_from_slice(&guid.data2.to_le_bytes());
    result[6..8].copy_from_slice(&guid.data3.to_le_bytes());
    result[8..16].copy_from_slice(&guid.data4);
    result
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
        // Construct GUID with native-endian fields matching C struct layout:
        // Data1=0x8bf06e4f → in LE memory: 4f 6e f0 8b
        // Data2=0x3412 → in LE memory: 12 34
        // Data3=0x5678 → in LE memory: 78 56
        let guid = EfiGuid {
            data1: u32::to_le(0x8bf06e4f),
            data2: u16::to_le(0x3412),
            data3: u16::to_le(0x5678),
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
        // Same test as above but using raw bytes (LE layout)
        let guid_bytes: [u8; 16] = [
            0x4f, 0x6e, 0xf0, 0x8b, 0x12, 0x34, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
            0x56, 0x78,
        ];
        let result = efi_guid_bytes_to_id128(&guid_bytes).unwrap();
        assert_eq!(result[0], 0x8b);
        assert_eq!(result[1], 0xf0);
        assert_eq!(result[2], 0x6e);
        assert_eq!(result[3], 0x4f);
        assert_eq!(&result[8..16], &guid_bytes[8..16]);
    }

    #[test]
    fn test_efi_id128_to_guid_zero() {
        let id = [0u8; 16];
        let guid = efi_id128_to_guid(&id);
        assert_eq!(u32::from_le(guid.data1), 0);
        assert_eq!(u16::from_le(guid.data2), 0);
        assert_eq!(u16::from_le(guid.data3), 0);
        assert_eq!(guid.data4, [0u8; 8]);
    }

    #[test]
    fn test_efi_id128_to_guid_known() {
        let id: Id128 = [
            0x8b, 0xf0, 0x6e, 0x4f, 0x34, 0x12, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
            0x56, 0x78,
        ];
        let guid = efi_id128_to_guid(&id);
        assert_eq!(u32::from_le(guid.data1), 0x8bf06e4f);
        assert_eq!(u16::from_le(guid.data2), 0x3412);
        assert_eq!(u16::from_le(guid.data3), 0x7856);
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
