// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/edid.c
//
// EDID (Extended Display Identification Data) parsing and panel identification.
//
// Parses EDID blobs from the EFI_EDID_DISCOVERED_PROTOCOL to extract
// display panel information including manufacturer and product codes.

// ── Constants ─────────────────────────────────────────────────────────────

/// EDID header magic bytes (bytes 0-7 of a valid EDID blob).
pub const EDID_HEADER_MAGIC: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

/// Minimum size of a valid EDID block (128 bytes for EDID v1).
pub const EDID_MIN_SIZE: usize = 128;

/// EDID version 1 major number.
const EDID_VERSION_1: u8 = 1;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors that can occur during EDID parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdidError {
    /// The EDID blob is too small to contain a valid header.
    BlobTooSmall,
    /// The EDID magic bytes do not match the expected pattern.
    InvalidMagic,
    /// The EDID version is not supported (only version 1.x).
    UnsupportedVersion,
    /// The panel ID could not be extracted (e.g. invalid manufacturer chars).
    InvalidPanelId,
    /// EDID data pointer is null / empty.
    NoData,
    /// EDID size field is zero.
    ZeroSize,
}

impl std::fmt::Display for EdidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdidError::BlobTooSmall => write!(f, "EDID blob too small"),
            EdidError::InvalidMagic => write!(f, "Invalid EDID magic bytes"),
            EdidError::UnsupportedVersion => write!(f, "Unsupported EDID version"),
            EdidError::InvalidPanelId => write!(f, "Invalid panel ID"),
            EdidError::NoData => write!(f, "No EDID data"),
            EdidError::ZeroSize => write!(f, "EDID size is zero"),
        }
    }
}

impl std::error::Error for EdidError {}

// ── Data structures ──────────────────────────────────────────────────────

/// Parsed EDID header information.
///
/// Mirrors the `EdidHeader` structure used in the C source for passing
/// parsed EDID data between functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdidHeader {
    /// Manufacturer ID encoded as 3 uppercase ASCII characters.
    pub manufacturer: [u8; 3],
    /// Manufacturer-assigned product code (little-endian u16 from blob).
    pub product_code: u16,
    /// EDID major version number.
    pub version: u8,
    /// EDID minor revision number.
    pub revision: u8,
}

// ── Parsing functions ────────────────────────────────────────────────────

/// Validate and parse an EDID blob, extracting the header information.
///
/// Faithfully replicates the validation logic from `edid_parse_blob` in
/// `src/boot/edid.c`.  Checks magic bytes, version, and extracts the
/// manufacturer / product-code fields.
///
/// # Errors
///
/// Returns `EdidError::BlobTooSmall` if fewer than 128 bytes,
/// `EdidError::InvalidMagic` if the 8-byte header does not match,
/// `EdidError::UnsupportedVersion` if the major version is not 1.
pub fn edid_parse_blob(data: &[u8]) -> Result<EdidHeader, EdidError> {
    if data.len() < EDID_MIN_SIZE {
        return Err(EdidError::BlobTooSmall);
    }

    // Check magic header bytes (bytes 0..8)
    if data[0..8] != EDID_HEADER_MAGIC {
        return Err(EdidError::InvalidMagic);
    }

    let version = data[18];
    let revision = data[19];

    if version != EDID_VERSION_1 {
        return Err(EdidError::UnsupportedVersion);
    }

    // Manufacturer is stored in bytes 8-9 as a big-endian u16.
    // Three 5-bit fields, each offset from '@' (0x40) to produce A-Z.
    let mfg_raw = u16::from_be_bytes([data[8], data[9]]);
    let manufacturer = [
        b'@' + ((mfg_raw >> 10) & 0x1F) as u8,
        b'@' + ((mfg_raw >> 5) & 0x1F) as u8,
        b'@' + (mfg_raw & 0x1F) as u8,
    ];

    // Product code: bytes 10-11, little-endian.
    let product_code = u16::from_le_bytes([data[10], data[11]]);

    Ok(EdidHeader {
        manufacturer,
        product_code,
        version,
        revision,
    })
}

/// Generate a panel ID string from a parsed EDID header.
///
/// Mirrors `edid_get_panel_id` in the C source — returns a string of the
/// form `"MAN1234"` (three-letter manufacturer code + 4-hex-digit product
/// code).
///
/// # Errors
///
/// Returns `EdidError::InvalidPanelId` if the manufacturer bytes are not
/// in the range `A..=Z`.
pub fn edid_get_panel_id(header: &EdidHeader) -> Result<String, EdidError> {
    for &c in &header.manufacturer {
        if !c.is_ascii_uppercase() {
            return Err(EdidError::InvalidPanelId);
        }
    }

    let mfg = std::str::from_utf8(&header.manufacturer).map_err(|_| EdidError::InvalidPanelId)?;

    Ok(format!("{}{:04x}", mfg, header.product_code))
}

/// High-level entry point: discover the panel ID from raw EDID data.
///
/// Mirrors `edid_get_discovered_panel_id` in the C source.  Validates
/// the blob is non-empty, parses the header, and returns the panel ID
/// string.
pub fn edid_get_discovered_panel_id(edid_data: &[u8]) -> Result<String, EdidError> {
    if edid_data.is_empty() {
        return Err(EdidError::ZeroSize);
    }

    let header = edid_parse_blob(edid_data)?;
    edid_get_panel_id(&header)
}

/// Compute a valid EDID checksum for the given 128-byte block.
///
/// The checksum byte (byte 127) is chosen so the sum of all 128 bytes
/// modulo 256 equals zero.
pub fn edid_checksum(block: &[u8; 128]) -> u8 {
    let sum: u8 = block[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    (256u16 - sum as u16) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid 128-byte EDID blob with the given manufacturer
    /// bytes (big-endian) and product code bytes (little-endian).
    fn make_valid_edid(mfg_be: [u8; 2], product_le: [u8; 2]) -> [u8; 128] {
        let mut edid = [0u8; 128];
        edid[0..8].copy_from_slice(&EDID_HEADER_MAGIC);
        edid[8] = mfg_be[0];
        edid[9] = mfg_be[1];
        edid[10] = product_le[0];
        edid[11] = product_le[1];
        edid[18] = 1; // version
        edid[19] = 4; // revision
        edid[127] = edid_checksum(&edid);
        edid
    }

    #[test]
    fn test_parse_valid_edid() {
        // 'T' = 20, 'S' = 19, 'T' = 20  →  (20<<10)|(19<<5)|20 = 21108 = 0x5274
        let edid = make_valid_edid([0x52, 0x74], [0x34, 0x12]);
        let header = edid_parse_blob(&edid).unwrap();
        assert_eq!(header.version, 1);
        assert_eq!(header.revision, 4);
        assert_eq!(&header.manufacturer, b"TST");
        assert_eq!(header.product_code, 0x1234);
    }

    #[test]
    fn test_parse_blob_too_small() {
        assert_eq!(edid_parse_blob(&[0u8; 64]), Err(EdidError::BlobTooSmall));
        assert_eq!(edid_parse_blob(&[]), Err(EdidError::BlobTooSmall));
    }

    #[test]
    fn test_parse_blob_invalid_magic() {
        let mut data = [0u8; 128];
        data[0] = 0xFF; // wrong first byte
        assert_eq!(edid_parse_blob(&data), Err(EdidError::InvalidMagic));
    }

    #[test]
    fn test_parse_blob_unsupported_version() {
        let mut edid = make_valid_edid([0, 0], [0, 0]);
        edid[18] = 2; // version 2 not supported
        assert_eq!(edid_parse_blob(&edid), Err(EdidError::UnsupportedVersion));
    }

    #[test]
    fn test_get_panel_id_valid() {
        let header = EdidHeader {
            manufacturer: *b"ABC",
            product_code: 0x1234,
            version: 1,
            revision: 4,
        };
        assert_eq!(edid_get_panel_id(&header).unwrap(), "ABC1234");
    }

    #[test]
    fn test_get_panel_id_zero_product() {
        let header = EdidHeader {
            manufacturer: *b"XYZ",
            product_code: 0x0000,
            version: 1,
            revision: 0,
        };
        assert_eq!(edid_get_panel_id(&header).unwrap(), "XYZ0000");
    }

    #[test]
    fn test_get_panel_id_invalid_manufacturer() {
        let header = EdidHeader {
            manufacturer: *b"123",
            product_code: 0,
            version: 1,
            revision: 4,
        };
        assert_eq!(edid_get_panel_id(&header), Err(EdidError::InvalidPanelId));
    }

    #[test]
    fn test_discovered_panel_id_empty() {
        assert_eq!(edid_get_discovered_panel_id(&[]), Err(EdidError::ZeroSize));
    }

    #[test]
    fn test_discovered_panel_id_valid() {
        // 'D'=4, 'E'=5, 'L'=12 → (4<<10)|(5<<5)|12 = 4268 = 0x10AC
        let edid = make_valid_edid([0x10, 0xAC], [0xCD, 0xAB]);
        let id = edid_get_discovered_panel_id(&edid).unwrap();
        assert_eq!(id, "DELabcd");
    }

    #[test]
    fn test_manufacturer_roundtrip() {
        // 'S'=19, 'D'=4, 'C'=3 → (19<<10)|(4<<5)|3 = 19587 = 0x4C83
        let edid = make_valid_edid([0x4C, 0x83], [0, 1]);
        let header = edid_parse_blob(&edid).unwrap();
        assert_eq!(&header.manufacturer, b"SDC");
        let id = edid_get_panel_id(&header).unwrap();
        assert!(id.starts_with("SDC"));
    }

    #[test]
    fn test_checksum() {
        let mut block = [0u8; 128];
        block[0..8].copy_from_slice(&EDID_HEADER_MAGIC);
        block[127] = edid_checksum(&block);
        let sum: u8 = block.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0, "EDID checksum should make total sum zero");
    }
}
