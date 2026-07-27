// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/chid.h, src/fundamental/chid.c
//
// CHID (Component Hardware ID) calculation based on SMBIOS fields.
// Uses SHA-1 to generate deterministic GUIDs from hardware identifiers.

use crate::efi_guid::EfiGuid;
use crate::sha1::Sha1State;

pub const CHID_TYPES_MAX: usize = 18;
pub const EXTRA_CHID_BASE: usize = 15;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChidSmbiosFields {
    Manufacturer = 0,
    Family = 1,
    ProductName = 2,
    ProductSku = 3,
    BaseboardManufacturer = 4,
    BaseboardProduct = 5,
    BiosVendor = 6,
    BiosVersion = 7,
    BiosMajor = 8,
    BiosMinor = 9,
    EnclosureType = 10,
    EdidPanel = 11,
    Max = 12,
}

const CHID_SMBIOS_FIELDS_MAX: usize = ChidSmbiosFields::Max as usize + 1;

/// SMBIOS field combination masks for each CHID type.
pub const CHID_SMBIOS_TABLE: [u32; CHID_TYPES_MAX] = {
    let mut table = [0u32; CHID_TYPES_MAX];

    table[0] = (1 << ChidSmbiosFields::Manufacturer as u32)
        | (1 << ChidSmbiosFields::Family as u32)
        | (1 << ChidSmbiosFields::ProductName as u32)
        | (1 << ChidSmbiosFields::ProductSku as u32)
        | (1 << ChidSmbiosFields::BiosVendor as u32)
        | (1 << ChidSmbiosFields::BiosVersion as u32)
        | (1 << ChidSmbiosFields::BiosMajor as u32)
        | (1 << ChidSmbiosFields::BiosMinor as u32);

    table[1] = (1 << ChidSmbiosFields::Manufacturer as u32)
        | (1 << ChidSmbiosFields::Family as u32)
        | (1 << ChidSmbiosFields::ProductName as u32)
        | (1 << ChidSmbiosFields::BiosVendor as u32)
        | (1 << ChidSmbiosFields::BiosVersion as u32)
        | (1 << ChidSmbiosFields::BiosMajor as u32)
        | (1 << ChidSmbiosFields::BiosMinor as u32);

    table[2] = (1 << ChidSmbiosFields::Manufacturer as u32)
        | (1 << ChidSmbiosFields::ProductName as u32)
        | (1 << ChidSmbiosFields::BiosVendor as u32)
        | (1 << ChidSmbiosFields::BiosVersion as u32)
        | (1 << ChidSmbiosFields::BiosMajor as u32)
        | (1 << ChidSmbiosFields::BiosMinor as u32);

    table[3] = (1 << ChidSmbiosFields::Manufacturer as u32)
        | (1 << ChidSmbiosFields::Family as u32)
        | (1 << ChidSmbiosFields::ProductName as u32)
        | (1 << ChidSmbiosFields::ProductSku as u32)
        | (1 << ChidSmbiosFields::BaseboardManufacturer as u32)
        | (1 << ChidSmbiosFields::BaseboardProduct as u32);

    table[4] = (1 << ChidSmbiosFields::Manufacturer as u32)
        | (1 << ChidSmbiosFields::Family as u32)
        | (1 << ChidSmbiosFields::ProductName as u32)
        | (1 << ChidSmbiosFields::ProductSku as u32);

    table[5] = (1 << ChidSmbiosFields::Manufacturer as u32)
        | (1 << ChidSmbiosFields::Family as u32)
        | (1 << ChidSmbiosFields::ProductName as u32);

    table[6] = (1 << ChidSmbiosFields::Manufacturer as u32)
        | (1 << ChidSmbiosFields::ProductSku as u32)
        | (1 << ChidSmbiosFields::BaseboardManufacturer as u32)
        | (1 << ChidSmbiosFields::BaseboardProduct as u32);

    table[7] =
        (1 << ChidSmbiosFields::Manufacturer as u32) | (1 << ChidSmbiosFields::ProductSku as u32);

    table[8] = (1 << ChidSmbiosFields::Manufacturer as u32)
        | (1 << ChidSmbiosFields::ProductName as u32)
        | (1 << ChidSmbiosFields::BaseboardManufacturer as u32)
        | (1 << ChidSmbiosFields::BaseboardProduct as u32);

    table[9] =
        (1 << ChidSmbiosFields::Manufacturer as u32) | (1 << ChidSmbiosFields::ProductName as u32);

    table[10] = (1 << ChidSmbiosFields::Manufacturer as u32)
        | (1 << ChidSmbiosFields::Family as u32)
        | (1 << ChidSmbiosFields::BaseboardManufacturer as u32)
        | (1 << ChidSmbiosFields::BaseboardProduct as u32);

    table[11] =
        (1 << ChidSmbiosFields::Manufacturer as u32) | (1 << ChidSmbiosFields::Family as u32);

    table[12] = (1 << ChidSmbiosFields::Manufacturer as u32)
        | (1 << ChidSmbiosFields::EnclosureType as u32);

    table[13] = (1 << ChidSmbiosFields::Manufacturer as u32)
        | (1 << ChidSmbiosFields::BaseboardManufacturer as u32)
        | (1 << ChidSmbiosFields::BaseboardProduct as u32);

    table[14] = (1 << ChidSmbiosFields::Manufacturer as u32);

    // Extra non-standard CHIDs
    table[EXTRA_CHID_BASE + 0] = (1 << ChidSmbiosFields::Manufacturer as u32)
        | (1 << ChidSmbiosFields::Family as u32)
        | (1 << ChidSmbiosFields::ProductName as u32)
        | (1 << ChidSmbiosFields::EdidPanel as u32);

    table[EXTRA_CHID_BASE + 1] = (1 << ChidSmbiosFields::Manufacturer as u32)
        | (1 << ChidSmbiosFields::Family as u32)
        | (1 << ChidSmbiosFields::EdidPanel as u32);

    table[EXTRA_CHID_BASE + 2] = (1 << ChidSmbiosFields::Manufacturer as u32)
        | (1 << ChidSmbiosFields::ProductSku as u32)
        | (1 << ChidSmbiosFields::EdidPanel as u32);

    table
};

/// Namespace GUID for CHID generation (stored big-endian).
const CHID_NAMESPACE: [u8; 16] = [
    0x12, 0xd8, 0xff, 0x70, 0x7f, 0x4c, 0x7d, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Separator for joining SMBIOS fields in the hash input.
const CHID_SEPARATOR: [u16; 1] = [b'&' as u16];

fn get_chid(smbios_fields: &[Option<&[u16]>], mask: u32) -> EfiGuid {
    let mut ctx = Sha1State::new();
    ctx.update(&CHID_NAMESPACE);

    for i in 0..CHID_SMBIOS_FIELDS_MAX {
        if mask & (1 << i) == 0 {
            continue;
        }

        let Some(field) = smbios_fields[i] else {
            // Missing SMBIOS field — return zero GUID per spec
            return EfiGuid::new(0, 0, 0, [0; 8]);
        };

        if i > 0 {
            // SAFETY: `CHID_SEPARATOR` is a fixed initialized `[u16; 1]`; viewing its bytes as `u8` with `len * 2` is in-bounds.
            ctx.update(unsafe {
                core::slice::from_raw_parts(
                    CHID_SEPARATOR.as_ptr() as *const u8,
                    CHID_SEPARATOR.len() * 2,
                )
            });
        }

        // SAFETY: `field` is a live initialized `[u16]`; viewing exactly `field.len() * 2` bytes as `u8` is in-bounds.
        ctx.update(unsafe {
            core::slice::from_raw_parts(field.as_ptr() as *const u8, field.len() * 2)
        });
    }

    let hash = ctx.finish();

    // Convert to EFI_GUID (first 16 bytes of hash)
    let mut data4 = [0u8; 8];
    data4.copy_from_slice(&hash[8..16]);

    let mut data1 = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]);
    let mut data2 = u16::from_be_bytes([hash[4], hash[5]]);
    let mut data3 = u16::from_be_bytes([hash[6], hash[7]]);

    // Convert back to little-endian for EFI_GUID
    data1 = data1.swap_bytes();
    data2 = data2.swap_bytes();
    data3 = data3.swap_bytes();

    // Set RFC4122 version 5 bits
    data3 = (data3 & 0x0fff) | (5 << 12);
    data4[0] = (data4[0] & 0x3f) | 0x80;

    EfiGuid::new(data1, data2, data3, data4)
}

/// Calculate all CHIDs from SMBIOS fields.
pub fn chid_calculate(smbios_fields: &[Option<&[u16]>]) -> [EfiGuid; CHID_TYPES_MAX] {
    let mut ret_chids = [EfiGuid::new(0, 0, 0, [0; 8]); CHID_TYPES_MAX];

    for i in 0..CHID_TYPES_MAX {
        if CHID_SMBIOS_TABLE[i] == 0 {
            continue;
        }
        ret_chids[i] = get_chid(smbios_fields, CHID_SMBIOS_TABLE[i]);
    }

    ret_chids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chid_table_entries() {
        // Verify that standard entries have masks
        assert_ne!(CHID_SMBIOS_TABLE[0], 0);
        assert_ne!(CHID_SMBIOS_TABLE[14], 0);
        // Verify extra entries
        assert_ne!(CHID_SMBIOS_TABLE[EXTRA_CHID_BASE], 0);
    }

    #[test]
    fn test_chid_calculate_produces_guids() {
        let fields: [Option<&[u16]>; CHID_SMBIOS_FIELDS_MAX] = [
            Some(&[b'D' as u16, b'E' as u16, b'L' as u16, 0]), // Manufacturer
            Some(&[b'X' as u16, b'P' as u16, b'S' as u16, 0]), // Family
            Some(&[
                b'P' as u16,
                b'r' as u16,
                b'e' as u16,
                b'c' as u16,
                b'i' as u16,
                b's' as u16,
                b'i' as u16,
                b'o' as u16,
                b'n' as u16,
                0,
            ]), // ProductName
            Some(&[b'1' as u16, b'2' as u16, b'3' as u16, 0]), // ProductSku
            None,                                              // BaseboardManufacturer
            None,                                              // BaseboardProduct
            Some(&[b'A' as u16, b'M' as u16, b'I' as u16, 0]), // BiosVendor
            Some(&[b'1' as u16, b'.' as u16, b'0' as u16, 0]), // BiosVersion
            Some(&[b'1' as u16, 0]),                           // BiosMajor
            Some(&[b'0' as u16, 0]),                           // BiosMinor
            None,                                              // EnclosureType
            None,                                              // EdidPanel
            None,                                              // Max (sentinel)
        ];

        let chids = chid_calculate(&fields);

        // Type 0 should produce a valid GUID (all required fields present)
        assert_ne!(chids[0], EfiGuid::new(0, 0, 0, [0; 8]));

        // Type 3 should produce zero GUID (missing BaseboardManufacturer)
        assert_eq!(chids[3], EfiGuid::new(0, 0, 0, [0; 8]));
    }
}
