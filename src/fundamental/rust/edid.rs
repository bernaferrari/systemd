// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=fundamental.edid; authority=src/fundamental/edid.c,src/fundamental/edid.h
//
// EDID (Extended Display Identification Data) parsing.

use crate::macro_fundamental::LOWERCASE_HEXDIGITS;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EdidHeader {
    pub pattern: [u8; 8],
    pub manufacturer_id: u16,
    pub manufacturer_product_code: u16,
    pub serial_number: u32,
    pub week_of_manufacture: u8,
    pub year_of_manufacture: u8,
    pub edid_version: u8,
    pub edid_revision: u8,
}

const _: () = assert!(core::mem::size_of::<EdidHeader>() == 20);
const _: () = assert!(core::mem::align_of::<EdidHeader>() == 1);
const _: () = assert!(core::mem::offset_of!(EdidHeader, pattern) == 0);
const _: () = assert!(core::mem::offset_of!(EdidHeader, manufacturer_id) == 8);
const _: () = assert!(core::mem::offset_of!(EdidHeader, manufacturer_product_code) == 10);
const _: () = assert!(core::mem::offset_of!(EdidHeader, serial_number) == 12);
const _: () = assert!(core::mem::offset_of!(EdidHeader, week_of_manufacture) == 16);
const _: () = assert!(core::mem::offset_of!(EdidHeader, year_of_manufacture) == 17);
const _: () = assert!(core::mem::offset_of!(EdidHeader, edid_version) == 18);
const _: () = assert!(core::mem::offset_of!(EdidHeader, edid_revision) == 19);

const EDID_FIXED_HEADER_PATTERN: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdidError {
    InvalidSize,
    InvalidHeader,
    InvalidManufacturerId,
}
pub type Result<T> = core::result::Result<T, EdidError>;

pub fn edid_parse_blob(blob: &[u8]) -> Result<EdidHeader> {
    if blob.len() < 128 {
        return Err(EdidError::InvalidSize);
    }
    if blob[..8] != EDID_FIXED_HEADER_PATTERN {
        return Err(EdidError::InvalidHeader);
    }
    Ok(EdidHeader {
        pattern: EDID_FIXED_HEADER_PATTERN,
        manufacturer_id: u16::from_be_bytes([blob[8], blob[9]]),
        manufacturer_product_code: u16::from_le_bytes([blob[10], blob[11]]),
        serial_number: u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]),
        week_of_manufacture: blob[16],
        year_of_manufacture: blob[17],
        edid_version: blob[18],
        edid_revision: blob[19],
    })
}

pub fn edid_get_panel_id(edid_header: &EdidHeader) -> Result<[u16; 8]> {
    let mut ret_panel = [0u16; 8];
    for i in 0..3 {
        let letter = (edid_header.manufacturer_id >> (5 * i)) & 0b11111;
        if letter > 0b11010 {
            return Err(EdidError::InvalidManufacturerId);
        }
        ret_panel[2 - i] = (letter + b'A' as u16 - 1) as u16;
    }
    let product = edid_header.manufacturer_product_code;
    ret_panel[3] = LOWERCASE_HEXDIGITS.as_bytes()[((product >> 12) & 0x0F) as usize] as u16;
    ret_panel[4] = LOWERCASE_HEXDIGITS.as_bytes()[((product >> 8) & 0x0F) as usize] as u16;
    ret_panel[5] = LOWERCASE_HEXDIGITS.as_bytes()[((product >> 4) & 0x0F) as usize] as u16;
    ret_panel[6] = LOWERCASE_HEXDIGITS.as_bytes()[(product & 0x0F) as usize] as u16;
    Ok(ret_panel)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_valid_edid_blob() {
        let mut blob = [0u8; 128];
        blob[..8].copy_from_slice(&EDID_FIXED_HEADER_PATTERN);
        blob[8] = 0x4c;
        blob[9] = 0x2d;
        blob[10] = 0x34;
        blob[11] = 0x12;
        blob[12..16].copy_from_slice(&[0x78, 0x56, 0x34, 0x12]);
        blob[16] = 42;
        blob[17] = 33;
        blob[18] = 1;
        blob[19] = 4;

        let header = edid_parse_blob(&blob).unwrap();
        let manufacturer_id = header.manufacturer_id;
        let manufacturer_product_code = header.manufacturer_product_code;
        let serial_number = header.serial_number;

        assert_eq!(header.pattern, EDID_FIXED_HEADER_PATTERN);
        assert_eq!(manufacturer_id, 0x4c2d);
        assert_eq!(manufacturer_product_code, 0x1234);
        assert_eq!(serial_number, 0x1234_5678);
        assert_eq!(header.week_of_manufacture, 42);
        assert_eq!(header.year_of_manufacture, 33);
        assert_eq!(header.edid_version, 1);
        assert_eq!(header.edid_revision, 4);
    }
    #[test]
    fn rejects_short_blob() {
        assert_eq!(edid_parse_blob(&[0u8; 8]), Err(EdidError::InvalidSize));
    }

    #[test]
    fn rejects_127_byte_blob_even_when_header_is_valid() {
        let mut blob = [0u8; 127];
        blob[..8].copy_from_slice(&EDID_FIXED_HEADER_PATTERN);

        assert_eq!(edid_parse_blob(&blob), Err(EdidError::InvalidSize));
    }
    #[test]
    fn rejects_invalid_header() {
        assert_eq!(edid_parse_blob(&[0u8; 128]), Err(EdidError::InvalidHeader));
    }
    #[test]
    fn builds_nul_terminated_panel_id() {
        let header = EdidHeader {
            pattern: EDID_FIXED_HEADER_PATTERN,
            manufacturer_id: 0x4c2d,
            manufacturer_product_code: 0xabcd,
            serial_number: 0,
            week_of_manufacture: 0,
            year_of_manufacture: 0,
            edid_version: 1,
            edid_revision: 4,
        };
        let panel = edid_get_panel_id(&header).unwrap();
        assert_eq!(
            panel,
            [
                u16::from(b'S'),
                u16::from(b'A'),
                u16::from(b'M'),
                u16::from(b'a'),
                u16::from(b'b'),
                u16::from(b'c'),
                u16::from(b'd'),
                0,
            ]
        );
    }

    #[test]
    fn rejects_out_of_range_manufacturer_letters() {
        let header = EdidHeader {
            pattern: EDID_FIXED_HEADER_PATTERN,
            manufacturer_id: 0x1b << 5,
            manufacturer_product_code: 0,
            serial_number: 0,
            week_of_manufacture: 0,
            year_of_manufacture: 0,
            edid_version: 1,
            edid_revision: 4,
        };

        assert_eq!(
            edid_get_panel_id(&header),
            Err(EdidError::InvalidManufacturerId)
        );
    }

    #[test]
    fn zero_manufacturer_letters_match_c_at_sign_output() {
        let header = EdidHeader {
            pattern: EDID_FIXED_HEADER_PATTERN,
            manufacturer_id: 0,
            manufacturer_product_code: 0,
            serial_number: 0,
            week_of_manufacture: 0,
            year_of_manufacture: 0,
            edid_version: 1,
            edid_revision: 4,
        };

        assert_eq!(
            edid_get_panel_id(&header).unwrap(),
            [
                u16::from(b'@'),
                u16::from(b'@'),
                u16::from(b'@'),
                u16::from(b'0'),
                u16::from(b'0'),
                u16::from(b'0'),
                u16::from(b'0'),
                0,
            ]
        );
    }
}
