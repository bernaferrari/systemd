// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/fundamental/edid.c
//
// EDID header parsing functions.
// Pure computation — no I/O, no syscalls.

use crate::ffi::Errno;

// ── Constants ─────────────────────────────────────────────────────────────

const LOWERCASE_HEXDIGITS: &[u8] = b"0123456789abcdef";
const EDID_FIXED_HEADER_PATTERN: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

// ── Types ─────────────────────────────────────────────────────────────────

/// Parsed EDID header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdidHeader {
    pub manufacturer_id: u16,
    pub manufacturer_product_code: u16,
    pub serial_number: u32,
    pub week_of_manufacture: u8,
    pub year_of_manufacture: u8,
    pub edid_version: u8,
    pub edid_revision: u8,
}

// ── Parsing ───────────────────────────────────────────────────────────────

/// Parse an EDID blob into an EdidHeader.
///
/// Port of C `edid_parse_blob()` from `src/fundamental/edid.c`.
/// Returns `Err(Errno::EINVAL)` if the blob is too small or has a bad header pattern.
pub fn edid_parse_blob(blob: &[u8]) -> Result<EdidHeader, Errno> {
    if blob.len() < 128 {
        return Err(Errno::EINVAL);
    }

    if blob[..8] != EDID_FIXED_HEADER_PATTERN {
        return Err(Errno::EINVAL);
    }

    Ok(EdidHeader {
        manufacturer_id: u16::from_be_bytes([blob[8], blob[9]]),
        manufacturer_product_code: u16::from_le_bytes([blob[10], blob[11]]),
        serial_number: u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]),
        week_of_manufacture: blob[16],
        year_of_manufacture: blob[17],
        edid_version: blob[18],
        edid_revision: blob[19],
    })
}

// ── Panel ID ──────────────────────────────────────────────────────────────

/// Extract the panel ID string from an EDID header.
///
/// Port of C `edid_get_panel_id()` from `src/fundamental/edid.c`.
/// Returns an array of 8 u16 values (3 letter code + 4 hex digits + NUL).
pub fn edid_get_panel_id(header: &EdidHeader) -> Result<[u16; 8], Errno> {
    let mut panel = [0u16; 8];

    for i in 0..3usize {
        let letter = (header.manufacturer_id >> (5 * i)) & 0x1F;
        if letter > 0x1A {
            return Err(Errno::EINVAL);
        }
        panel[2 - i] = (letter as u16) + (b'A' as u16) - 1;
    }

    panel[3] =
        LOWERCASE_HEXDIGITS[((header.manufacturer_product_code >> 12) & 0x0F) as usize] as u16;
    panel[4] =
        LOWERCASE_HEXDIGITS[((header.manufacturer_product_code >> 8) & 0x0F) as usize] as u16;
    panel[5] =
        LOWERCASE_HEXDIGITS[((header.manufacturer_product_code >> 4) & 0x0F) as usize] as u16;
    panel[6] =
        LOWERCASE_HEXDIGITS[((header.manufacturer_product_code >> 0) & 0x0F) as usize] as u16;
    panel[7] = 0;

    Ok(panel)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_edid_blob(manufacturer_id_be: [u8; 2], product_code_le: [u8; 2]) -> [u8; 128] {
        let mut blob = [0u8; 128];
        blob[0] = 0x00;
        blob[1..8].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        blob[8..10].copy_from_slice(&manufacturer_id_be);
        blob[10..12].copy_from_slice(&product_code_le);
        blob
    }

    #[test]
    fn test_parse_blob_too_small() {
        let blob = [0u8; 64];
        assert_eq!(edid_parse_blob(&blob), Err(Errno::EINVAL));
    }

    #[test]
    fn test_parse_blob_exactly_127() {
        let mut blob = [0u8; 127];
        blob[..8].copy_from_slice(&EDID_FIXED_HEADER_PATTERN);
        assert_eq!(edid_parse_blob(&blob), Err(Errno::EINVAL));
    }

    #[test]
    fn test_parse_blob_bad_pattern_first_byte() {
        let mut blob = [0u8; 128];
        blob[0] = 0x01;
        assert_eq!(edid_parse_blob(&blob), Err(Errno::EINVAL));
    }

    #[test]
    fn test_parse_blob_bad_pattern_middle() {
        let mut blob = [0u8; 128];
        blob[0] = 0x00;
        blob[1..8].fill(0xFF);
        blob[7] = 0x01; // last byte should be 0x00
        assert_eq!(edid_parse_blob(&blob), Err(Errno::EINVAL));
    }

    #[test]
    fn test_parse_blob_valid_sam() {
        let mut blob = make_edid_blob([0x4C, 0x2D], [0x34, 0x12]);
        blob[12..16].copy_from_slice(&[0x78, 0x56, 0x34, 0x12]);
        blob[16] = 42;
        blob[17] = 33;
        blob[18] = 1;
        blob[19] = 4;

        let header = edid_parse_blob(&blob).unwrap();
        assert_eq!(header.manufacturer_id, 0x4C2D);
        assert_eq!(header.manufacturer_product_code, 0x1234);
        assert_eq!(header.serial_number, 0x12345678);
        assert_eq!(header.week_of_manufacture, 42);
        assert_eq!(header.year_of_manufacture, 33);
        assert_eq!(header.edid_version, 1);
        assert_eq!(header.edid_revision, 4);
    }

    #[test]
    fn test_parse_blob_minimal_valid() {
        let mut blob = [0u8; 128];
        blob[..8].copy_from_slice(&EDID_FIXED_HEADER_PATTERN);
        // All other fields zero
        let header = edid_parse_blob(&blob).unwrap();
        assert_eq!(header.manufacturer_id, 0);
        assert_eq!(header.manufacturer_product_code, 0);
        assert_eq!(header.serial_number, 0);
    }

    #[test]
    fn test_get_panel_id_sam() {
        let header = EdidHeader {
            manufacturer_id: 0x4C2D,
            manufacturer_product_code: 0x1234,
            serial_number: 0,
            week_of_manufacture: 0,
            year_of_manufacture: 0,
            edid_version: 0,
            edid_revision: 0,
        };

        let panel = edid_get_panel_id(&header).unwrap();
        assert_eq!(panel[0], 'S' as u16);
        assert_eq!(panel[1], 'A' as u16);
        assert_eq!(panel[2], 'M' as u16);
        assert_eq!(panel[3], '1' as u16);
        assert_eq!(panel[4], '2' as u16);
        assert_eq!(panel[5], '3' as u16);
        assert_eq!(panel[6], '4' as u16);
        assert_eq!(panel[7], 0);
    }

    #[test]
    fn test_get_panel_id_invalid_letter_high() {
        let header = EdidHeader {
            manufacturer_id: 0x1B << 10, // letter 27 > 26
            manufacturer_product_code: 0,
            serial_number: 0,
            week_of_manufacture: 0,
            year_of_manufacture: 0,
            edid_version: 0,
            edid_revision: 0,
        };
        assert_eq!(edid_get_panel_id(&header), Err(Errno::EINVAL));
    }

    #[test]
    fn test_get_panel_id_invalid_letter_all_bits_set() {
        let header = EdidHeader {
            manufacturer_id: 0xFFFF,
            manufacturer_product_code: 0,
            serial_number: 0,
            week_of_manufacture: 0,
            year_of_manufacture: 0,
            edid_version: 0,
            edid_revision: 0,
        };
        assert_eq!(edid_get_panel_id(&header), Err(Errno::EINVAL));
    }

    #[test]
    fn test_get_panel_id_all_zeros() {
        let header = EdidHeader {
            manufacturer_id: 0,
            manufacturer_product_code: 0,
            serial_number: 0,
            week_of_manufacture: 0,
            year_of_manufacture: 0,
            edid_version: 0,
            edid_revision: 0,
        };
        let panel = edid_get_panel_id(&header).unwrap();
        // manufacturer_id = 0: each 5-bit field is 0, so letter = 0 + 'A' - 1 = '@' (0x40)
        // Actually letter 0 means 0 + 'A' - 1 = 64 = '@', letter > 0x1A would be 0 which is fine
        assert_eq!(panel[0], (0u16 + b'A' as u16 - 1)); // letter 0 → '@'
        assert_eq!(panel[3], '0' as u16);
        assert_eq!(panel[7], 0);
    }

    #[test]
    fn test_get_panel_id_product_code_hex() {
        let header = EdidHeader {
            manufacturer_id: 0x4C2D, // SAM
            manufacturer_product_code: 0xABCD,
            serial_number: 0,
            week_of_manufacture: 0,
            year_of_manufacture: 0,
            edid_version: 0,
            edid_revision: 0,
        };

        let panel = edid_get_panel_id(&header).unwrap();
        assert_eq!(panel[3], 'a' as u16);
        assert_eq!(panel[4], 'b' as u16);
        assert_eq!(panel[5], 'c' as u16);
        assert_eq!(panel[6], 'd' as u16);
    }

    #[test]
    fn test_parse_blob_and_panel_id_roundtrip() {
        // IBM: I=9, B=2, M=13 → (9<<10)|(2<<5)|13 = 9216+64+13 = 9293 = 0x244D
        let mut blob = [0u8; 128];
        blob[..8].copy_from_slice(&EDID_FIXED_HEADER_PATTERN);
        blob[8..10].copy_from_slice(&[0x24, 0x4D]); // IBM big-endian
        blob[10..12].copy_from_slice(&[0x00, 0x56]); // product code 0x5600 LE

        let header = edid_parse_blob(&blob).unwrap();
        assert_eq!(header.manufacturer_id, 0x244D);

        let panel = edid_get_panel_id(&header).unwrap();
        assert_eq!(panel[0], 'I' as u16);
        assert_eq!(panel[1], 'B' as u16);
        assert_eq!(panel[2], 'M' as u16);
        assert_eq!(panel[3], '5' as u16);
        assert_eq!(panel[4], '6' as u16);
        assert_eq!(panel[5], '0' as u16);
        assert_eq!(panel[6], '0' as u16);
    }

    #[test]
    fn test_parse_blob_256_bytes_ok() {
        let mut blob = [0u8; 256];
        blob[..8].copy_from_slice(&EDID_FIXED_HEADER_PATTERN);
        let header = edid_parse_blob(&blob).unwrap();
        assert_eq!(header.manufacturer_id, 0);
    }
}
