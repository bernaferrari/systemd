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
        blob[8] = 0x04;
        blob[9] = 0x43;
        blob[10] = 0x34;
        blob[11] = 0x12;
        let header = edid_parse_blob(&blob).unwrap();
        {
            let code = header.manufacturer_product_code;
            assert_eq!(code, 0x1234);
        }
    }
    #[test]
    fn rejects_short_blob() {
        assert_eq!(edid_parse_blob(&[0u8; 8]), Err(EdidError::InvalidSize));
    }
    #[test]
    fn rejects_invalid_header() {
        assert_eq!(edid_parse_blob(&[0u8; 128]), Err(EdidError::InvalidHeader));
    }
    #[test]
    fn builds_panel_id() {
        let header = EdidHeader {
            pattern: EDID_FIXED_HEADER_PATTERN,
            manufacturer_id: 0x0443,
            manufacturer_product_code: 0x1234,
            serial_number: 0,
            week_of_manufacture: 0,
            year_of_manufacture: 0,
            edid_version: 1,
            edid_revision: 4,
        };
        let panel = edid_get_panel_id(&header).unwrap();
        assert_eq!(panel[3], b'1' as u16);
        assert_eq!(panel[6], b'4' as u16);
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
