// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=fundamental.edid; authority=src/fundamental/edid.c,src/fundamental/edid.h
//
// EDID header parsing functions.
// Pure computation — no I/O, no syscalls.

use std::ffi::c_void;
use std::mem::{align_of, size_of};
use std::ptr;

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

/// Exact ABI mirror of C's packed `EdidHeader`.
///
/// Keep this separate from the ergonomic, naturally aligned `EdidHeader`
/// returned by the safe Rust API. Raw packed fields must only be accessed with
/// unaligned reads and writes.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EdidHeaderAbi {
    pattern: [u8; 8],
    manufacturer_id: u16,
    manufacturer_product_code: u16,
    serial_number: u32,
    week_of_manufacture: u8,
    year_of_manufacture: u8,
    edid_version: u8,
    edid_revision: u8,
}

const _: () = assert!(size_of::<EdidHeaderAbi>() == 20);
const _: () = assert!(align_of::<EdidHeaderAbi>() == 1);

// ── Parsing ───────────────────────────────────────────────────────────────

fn parse_edid_prefix(prefix: &[u8; 20]) -> Result<EdidHeader, Errno> {
    if prefix[..8] != EDID_FIXED_HEADER_PATTERN {
        return Err(Errno::EINVAL);
    }

    Ok(EdidHeader {
        manufacturer_id: u16::from_be_bytes([prefix[8], prefix[9]]),
        manufacturer_product_code: u16::from_le_bytes([prefix[10], prefix[11]]),
        serial_number: u32::from_le_bytes([prefix[12], prefix[13], prefix[14], prefix[15]]),
        week_of_manufacture: prefix[16],
        year_of_manufacture: prefix[17],
        edid_version: prefix[18],
        edid_revision: prefix[19],
    })
}

/// Parse an EDID blob into an EdidHeader.
///
/// Port of C `edid_parse_blob()` from `src/fundamental/edid.c`.
/// Returns `Err(Errno::EINVAL)` if the blob is too small or has a bad header pattern.
pub fn edid_parse_blob(blob: &[u8]) -> Result<EdidHeader, Errno> {
    if blob.len() < 128 {
        return Err(Errno::EINVAL);
    }

    let prefix: &[u8; 20] = blob[..20].try_into().expect("fixed-size EDID prefix");
    parse_edid_prefix(prefix)
}

// ── Panel ID ──────────────────────────────────────────────────────────────

fn write_panel_id(
    manufacturer_id: u16,
    manufacturer_product_code: u16,
    mut write: impl FnMut(usize, u16),
) -> Result<(), Errno> {
    for i in 0..3usize {
        let letter = (manufacturer_id >> (5 * i)) & 0x1F;
        if letter > 0x1A {
            return Err(Errno::EINVAL);
        }
        write(2 - i, letter + u16::from(b'A') - 1);
    }

    write(
        3,
        u16::from(LOWERCASE_HEXDIGITS[((manufacturer_product_code >> 12) & 0x0F) as usize]),
    );
    write(
        4,
        u16::from(LOWERCASE_HEXDIGITS[((manufacturer_product_code >> 8) & 0x0F) as usize]),
    );
    write(
        5,
        u16::from(LOWERCASE_HEXDIGITS[((manufacturer_product_code >> 4) & 0x0F) as usize]),
    );
    write(
        6,
        u16::from(LOWERCASE_HEXDIGITS[(manufacturer_product_code & 0x0F) as usize]),
    );
    write(7, 0);

    Ok(())
}

/// Extract the panel ID string from an EDID header.
///
/// Port of C `edid_get_panel_id()` from `src/fundamental/edid.c`.
/// Returns an array of 8 u16 values (3 letter code + 4 hex digits + NUL).
pub fn edid_get_panel_id(header: &EdidHeader) -> Result<[u16; 8], Errno> {
    let mut panel = [0u16; 8];
    write_panel_id(
        header.manufacturer_id,
        header.manufacturer_product_code,
        |index, value| panel[index] = value,
    )?;
    Ok(panel)
}

/// C ABI mirror of `edid_parse_blob()`.
///
/// Like the C authority, this validates the advertised 128-byte minimum before
/// reading only the 20-byte fixed header and leaves `ret_header` untouched on
/// failure.
///
/// # Safety
///
/// When `blob_size >= 128`, `blob` must point to at least 128 readable bytes.
/// `ret_header` must point to writable storage for one packed C `EdidHeader`.
/// Null `ret_header`, and null `blob` with a sufficient advertised size, are
/// invalid in the C API; this facade returns `-EINVAL` instead of triggering a
/// C assertion.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_edid_parse_blob(
    blob: *const c_void,
    blob_size: usize,
    ret_header: *mut EdidHeaderAbi,
) -> i32 {
    if ret_header.is_null() || blob_size < 128 {
        return Errno::EINVAL.to_neg_errno();
    }
    if blob.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: after the size and null checks, the entry-point contract
    // guarantees at least 128 readable bytes; copying the 20-byte prefix is
    // sufficient and does not impose alignment on the opaque input pointer.
    let prefix = unsafe { ptr::read_unaligned(blob.cast::<[u8; 20]>()) };
    let parsed = match parse_edid_prefix(&prefix) {
        Ok(parsed) => parsed,
        Err(error) => return error.to_neg_errno(),
    };

    let output = EdidHeaderAbi {
        pattern: EDID_FIXED_HEADER_PATTERN,
        manufacturer_id: parsed.manufacturer_id,
        manufacturer_product_code: parsed.manufacturer_product_code,
        serial_number: parsed.serial_number,
        week_of_manufacture: parsed.week_of_manufacture,
        year_of_manufacture: parsed.year_of_manufacture,
        edid_version: parsed.edid_version,
        edid_revision: parsed.edid_revision,
    };

    // SAFETY: the entry-point contract guarantees writable storage for the
    // packed output. `write_unaligned` avoids assuming more than C's alignment.
    unsafe { ptr::write_unaligned(ret_header, output) };
    0
}

/// C ABI mirror of `edid_get_panel_id()`.
///
/// Output is published in the same order as C. In particular, an invalid
/// manufacturer letter can leave characters from earlier loop iterations in
/// `ret_panel`; the remaining elements stay untouched.
///
/// # Safety
///
/// `edid_header` must point to a live packed C `EdidHeader`, and `ret_panel`
/// must point to at least eight writable C `char16_t` elements. The regions
/// must not overlap. Null pointers are invalid in the C API; this facade
/// returns `-EINVAL` instead of triggering a C assertion.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_edid_get_panel_id(
    edid_header: *const EdidHeaderAbi,
    ret_panel: *mut u16,
) -> i32 {
    if edid_header.is_null() || ret_panel.is_null() {
        return Errno::EINVAL.to_neg_errno();
    }

    // SAFETY: the entry-point contract guarantees a readable packed header.
    // Copying it unaligned prevents references to packed fields.
    let header = unsafe { ptr::read_unaligned(edid_header) };
    let manufacturer_id = header.manufacturer_id;
    let manufacturer_product_code = header.manufacturer_product_code;

    match write_panel_id(
        manufacturer_id,
        manufacturer_product_code,
        |index, value| {
            // SAFETY: the entry-point contract guarantees eight writable
            // char16_t elements. Each index is in 0..8 and written at most once.
            unsafe { ptr::write_unaligned(ret_panel.add(index), value) };
        },
    ) {
        Ok(()) => 0,
        Err(error) => error.to_neg_errno(),
    }
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
