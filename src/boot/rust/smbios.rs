// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/smbios.c
//
// SMBIOS/DMI table parsing for system information retrieval.
//
// Supports SMBIOS 2.x and 3.x entry points, table enumeration by type,
// string extraction from formatted+unformatted areas, and hypervisor
// detection via BIOS characteristics extension bits.

// ── Constants ─────────────────────────────────────────────────────────────

/// End-of-table marker type.
pub const SMBIOS_END_OF_TABLE: u8 = 127;

/// Bit position for hypervisor flag in BIOS characteristics ext byte 1.
pub const HYPERVISOR_BIT: u8 = 4;

/// SMBIOS anchor strings.
pub const SMBIOS3_ANCHOR: &[u8; 5] = b"_SM3_";
pub const SMBIOS_ANCHOR: &[u8; 4] = b"_SM_";

// ── Types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmbiosHeader {
    pub type_: u8,
    pub length: u8,
    pub handle: u16,
}

#[derive(Debug, Clone, Default)]
pub struct SmbiosEntryPoint {
    pub table_length: u32,
    pub table_address: u64,
}

#[derive(Debug, Clone, Default)]
pub struct RawSmbiosInfo {
    pub manufacturer: Option<String>,
    pub product_name: Option<String>,
    pub product_sku: Option<String>,
    pub family: Option<String>,
    pub baseboard_manufacturer: Option<String>,
    pub baseboard_product: Option<String>,
}

/// Error for SMBIOS operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmbiosError {
    /// Table not found or too small.
    TableNotFound,
    /// Entry point anchor string mismatch.
    BadAnchor,
    /// Entry point length exceeds expected size.
    EntryTooLarge,
    /// Requested table smaller than minimum expected size.
    TableTooSmall,
    /// Malformed string area (unterminated).
    MalformedStrings,
    /// No more data to iterate.
    EndOfTable,
}

impl std::fmt::Display for SmbiosError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmbiosError::TableNotFound => write!(f, "SMBIOS table not found"),
            SmbiosError::BadAnchor => write!(f, "bad SMBIOS anchor string"),
            SmbiosError::EntryTooLarge => write!(f, "SMBIOS entry too large"),
            SmbiosError::TableTooSmall => write!(f, "SMBIOS table too small"),
            SmbiosError::MalformedStrings => write!(f, "malformed SMBIOS string area"),
            SmbiosError::EndOfTable => write!(f, "end of SMBIOS table"),
        }
    }
}

impl std::error::Error for SmbiosError {}

// ── Parse entry point ─────────────────────────────────────────────────────

/// Validate SMBIOS 3.x entry point and return table info.
pub fn parse_smbios3_entry(data: &[u8]) -> Result<SmbiosEntryPoint, SmbiosError> {
    if data.len() < 5 || &data[0..5] != SMBIOS3_ANCHOR {
        return Err(SmbiosError::BadAnchor);
    }
    // Smbios3EntryPoint is 26 bytes
    if data.len() < 26 {
        return Err(SmbiosError::EntryTooLarge);
    }
    let entry_length = data[8];
    if entry_length as usize > 26 {
        return Err(SmbiosError::EntryTooLarge);
    }
    let table_max_size = u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let table_address = u64::from_le_bytes([
        data[20], data[21], data[22], data[23], data[24], data[25], 0, 0,
    ]);
    Ok(SmbiosEntryPoint {
        table_length: table_max_size,
        table_address,
    })
}

/// Validate SMBIOS 2.x entry point and return table info.
pub fn parse_smbios_entry(data: &[u8]) -> Result<SmbiosEntryPoint, SmbiosError> {
    if data.len() < 4 || &data[0..4] != SMBIOS_ANCHOR {
        return Err(SmbiosError::BadAnchor);
    }
    // SmbiosEntryPoint is 31 bytes
    if data.len() < 31 {
        return Err(SmbiosError::EntryTooLarge);
    }
    let entry_length = data[6];
    if entry_length as usize > 31 {
        return Err(SmbiosError::EntryTooLarge);
    }
    let table_length = u16::from_le_bytes([data[22], data[23]]) as u32;
    let table_address = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as u64;
    Ok(SmbiosEntryPoint {
        table_length,
        table_address,
    })
}

/// Try SMBIOS 3.x first, then fall back to 2.x.
pub fn find_configuration_table(
    entry3: Option<&[u8]>,
    entry: Option<&[u8]>,
) -> Option<SmbiosEntryPoint> {
    if let Some(e3) = entry3 {
        if let Ok(ep) = parse_smbios3_entry(e3) {
            return Some(ep);
        }
    }
    if let Some(e) = entry {
        if let Ok(ep) = parse_smbios_entry(e) {
            return Some(ep);
        }
    }
    None
}

// ── Table enumeration ─────────────────────────────────────────────────────

/// Find an SMBIOS table by type in the raw table data.
///
/// Returns (header, remaining_data_starting_at_header) on success.
/// Mirrors `get_smbios_table()` in C, which iterates through the table
/// entries skipping string tables.
pub fn get_smbios_table<'a>(
    data: &'a [u8],
    type_: u8,
    min_size: usize,
) -> Result<(SmbiosHeader, &'a [u8]), SmbiosError> {
    let mut pos = 0;
    let size = data.len();

    loop {
        if pos + 4 > size {
            return Err(SmbiosError::TableNotFound);
        }

        // Parse header
        let hdr_type = data[pos];
        let hdr_length = data[pos + 1] as usize;
        let hdr_handle = u16::from_le_bytes([data[pos + 2], data[pos + 3]]);

        if hdr_type == SMBIOS_END_OF_TABLE {
            return Err(SmbiosError::TableNotFound);
        }

        if pos + hdr_length > size {
            return Err(SmbiosError::TableNotFound);
        }

        if hdr_type == type_ {
            if hdr_length < min_size {
                return Err(SmbiosError::TableTooSmall);
            }
            let header = SmbiosHeader {
                type_: hdr_type,
                length: hdr_length as u8,
                handle: hdr_handle,
            };
            return Ok((header, &data[pos..size]));
        }

        // Skip formatted area
        pos += hdr_length;

        // Skip string table (double NUL terminated)
        pos = skip_string_table(data, pos, size)?;
    }
}

/// Skip the unformatted string table area (double-NUL terminated).
fn skip_string_table(data: &[u8], start: usize, limit: usize) -> Result<usize, SmbiosError> {
    // Check for empty string table (two consecutive NULs)
    if start + 2 <= limit && data[start] == 0 && data[start + 1] == 0 {
        return Ok(start + 2);
    }

    let mut pos = start;
    let mut first = true;
    loop {
        if pos >= limit {
            return Err(SmbiosError::MalformedStrings);
        }
        let nul_pos = match data[pos..limit].iter().position(|&b| b == 0) {
            Some(p) => p,
            None => return Err(SmbiosError::MalformedStrings),
        };

        if !first && nul_pos == 0 {
            // Double NUL - end of string table
            return Ok(pos + 1);
        }

        pos += nul_pos + 1;
        first = false;
    }
}

// ── String extraction ─────────────────────────────────────────────────────

/// Extract the Nth string from a table's string area.
///
/// Mirrors `smbios_get_string()` in C. `nr` is 1-based.
/// `header_length` is the length of the formatted area to skip.
pub fn smbios_get_string(data: &[u8], header_length: usize, nr: usize) -> Option<&str> {
    if nr == 0 {
        return None;
    }
    if data.len() < header_length {
        return None;
    }

    let string_area = &data[header_length..];
    let mut index = 1usize;
    let mut pos = 0;

    while index <= nr && pos < string_area.len() {
        let nul_pos = string_area[pos..].iter().position(|&b| b == 0)?;

        if index == nr {
            return std::str::from_utf8(&string_area[pos..pos + nul_pos]).ok();
        }

        pos += nul_pos + 1;
        index += 1;
    }

    None
}

// ── Hypervisor detection ──────────────────────────────────────────────────

/// Check if bit 4 of the second BIOS characteristics extension byte is set,
/// indicating we are running in a hypervisor.
///
/// Mirrors `smbios_in_hypervisor()` in C.
pub fn is_in_hypervisor(bios_chars_ext_byte1: u8) -> bool {
    bios_chars_ext_byte1 & (1 << HYPERVISOR_BIT) != 0
}

// ── OEM string lookup ─────────────────────────────────────────────────────

/// Find an OEM string by key prefix in SMBIOS Type 11 data.
///
/// Mirrors `smbios_find_oem_string()` in C.
pub fn find_oem_string(type11_data: &[u8], header_length: usize, name: &str) -> Option<String> {
    if type11_data.len() <= header_length {
        return None;
    }

    let string_area = &type11_data[header_length..];

    for substring in split_null_strings(string_area) {
        if let Some(suffix) = substring.strip_prefix(name) {
            if !suffix.is_empty() {
                return Some(suffix.to_string());
            }
        }
    }

    None
}

/// Split a double-NUL-terminated byte area into null-separated UTF-8 strings.
fn split_null_strings(data: &[u8]) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0;

    while start < data.len() {
        let end = data[start..].iter().position(|&b| b == 0);
        match end {
            Some(0) => break, // Double NUL
            Some(n) => {
                if let Ok(s) = std::str::from_utf8(&data[start..start + n]) {
                    result.push(s);
                }
                start += n + 1;
            }
            None => break,
        }
    }

    result
}

// ── Raw info population ───────────────────────────────────────────────────

/// Populate RawSmbiosInfo from Type 1 and Type 2 SMBIOS tables.
///
/// Mirrors `smbios_raw_info_populate()` in C.
pub fn raw_info_populate(
    type1_data: Option<&[u8]>,
    type1_header_length: usize,
    type2_data: Option<&[u8]>,
    type2_header_length: usize,
) -> RawSmbiosInfo {
    let mut info = RawSmbiosInfo::default();

    if let Some(data) = type1_data {
        // Type 1 offsets: manufacturer(1), product_name(2), version(3), serial(4), uuid(5..20),
        // wake_up_type(21), sku_number(22), family(23)
        if data.len() > type1_header_length {
            info.manufacturer = smbios_get_string(data, type1_header_length, 1).map(String::from);
            info.product_name = smbios_get_string(data, type1_header_length, 2).map(String::from);
            info.product_sku = smbios_get_string(data, type1_header_length, 22).map(String::from);
            info.family = smbios_get_string(data, type1_header_length, 23).map(String::from);
        }
    }

    if let Some(data) = type2_data {
        if data.len() > type2_header_length {
            info.baseboard_manufacturer =
                smbios_get_string(data, type2_header_length, 1).map(String::from);
            info.baseboard_product =
                smbios_get_string(data, type2_header_length, 2).map(String::from);
        }
    }

    info
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_type0_data(bios_chars_ext_byte1: u8) -> Vec<u8> {
        let mut data = vec![
            0u8, // type = 0 (BIOS Information)
            0u8, // length (placeholder)
            0u8,
            0u8, // handle
            1u8, // vendor string index
            2u8, // bios version string index
            0u8,
            0u8, // bios segment
            3u8, // bios release date string index
            0u8, // bios size
            0u8,
            0u8,
            0u8,
            0u8,
            0u8,
            0u8,
            0u8,
            0u8,                  // bios characteristics (8 bytes)
            0u8,                  // bios_characteristics_ext[0]
            bios_chars_ext_byte1, // bios_characteristics_ext[1]
        ];
        data[1] = data.len() as u8;
        // Append strings: "Vendor\0", "1.0\0", "2024-01-01\0\0"
        data.extend_from_slice(b"Vendor\0");
        data.extend_from_slice(b"1.0\0");
        data.extend_from_slice(b"2024-01-01\0\0");
        data
    }

    fn make_type1_data() -> Vec<u8> {
        let mut data = vec![
            1u8,  // type = 1 (System Information)
            27u8, // length
            0u8, 0u8, // handle
            1u8, // manufacturer
            2u8, // product_name
            3u8, // version
            4u8, // serial_number
            // uuid (16 bytes)
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, // wake_up_type
            5u8, // sku_number
            6u8, // family
        ];
        data.extend_from_slice(b"TestVendor\0");
        data.extend_from_slice(b"TestProduct\0");
        data.extend_from_slice(b"1.0\0");
        data.extend_from_slice(b"SN123\0");
        data.extend_from_slice(b"SKU001\0");
        data.extend_from_slice(b"TestFamily\0\0");
        data
    }

    fn make_type11_data(strings: &[&[u8]]) -> Vec<u8> {
        let mut data = vec![
            11u8, // type = 11 (OEM Strings)
            5u8,  // length
            0u8,
            0u8,                 // handle
            strings.len() as u8, // count
        ];
        for s in strings {
            data.extend_from_slice(s);
            data.push(0);
        }
        data.push(0); // Double NUL terminator
        data
    }

    #[test]
    fn test_parse_smbios3_entry_valid() {
        let mut data = vec![0u8; 26];
        data[0..5].copy_from_slice(b"_SM3_");
        data[8] = 24; // entry length
        data[16..20].copy_from_slice(&1024u32.to_le_bytes());
        data[20..26].copy_from_slice(&0xDEADu64.to_le_bytes()[..6]);
        let ep = parse_smbios3_entry(&data).unwrap();
        assert_eq!(ep.table_length, 1024);
    }

    #[test]
    fn test_parse_smbios3_entry_bad_anchor() {
        let data = vec![0u8; 26];
        assert!(parse_smbios3_entry(&data).is_err());
    }

    #[test]
    fn test_parse_smbios_entry_valid() {
        let mut data = vec![0u8; 31];
        data[0..4].copy_from_slice(b"_SM_");
        data[6] = 31; // entry length
        data[22..24].copy_from_slice(&512u16.to_le_bytes());
        data[24..28].copy_from_slice(&0xCAFEu32.to_le_bytes());
        let ep = parse_smbios_entry(&data).unwrap();
        assert_eq!(ep.table_length, 512);
    }

    #[test]
    fn test_find_configuration_table_prefers_v3() {
        let mut v3 = vec![0u8; 26];
        v3[0..5].copy_from_slice(b"_SM3_");
        v3[8] = 24;
        let mut v2 = vec![0u8; 31];
        v2[0..4].copy_from_slice(b"_SM_");
        v2[6] = 31;
        let result = find_configuration_table(Some(&v3), Some(&v2));
        assert!(result.is_some());
    }

    #[test]
    fn test_is_in_hypervisor() {
        assert!(is_in_hypervisor(0x10)); // bit 4 set
        assert!(!is_in_hypervisor(0x00));
        assert!(!is_in_hypervisor(0x01));
        assert!(is_in_hypervisor(0xFF));
    }

    #[test]
    fn test_get_smbios_table_found() {
        let data = make_type0_data(0);
        let result = get_smbios_table(&data, 0, 4);
        assert!(result.is_ok());
        let (header, _) = result.unwrap();
        assert_eq!(header.type_, 0);
    }

    #[test]
    fn test_get_smbios_table_not_found() {
        let data = make_type0_data(0);
        let result = get_smbios_table(&data, 42, 4);
        assert!(result.is_err());
    }

    #[test]
    fn test_smbios_get_string() {
        let data = make_type1_data();
        let s = smbios_get_string(&data, 27, 1);
        assert_eq!(s, Some("TestVendor"));
        let s = smbios_get_string(&data, 27, 2);
        assert_eq!(s, Some("TestProduct"));
        let s = smbios_get_string(&data, 27, 6);
        assert_eq!(s, Some("TestFamily"));
        let s = smbios_get_string(&data, 27, 99);
        assert_eq!(s, None);
    }

    #[test]
    fn test_find_oem_string() {
        let data = make_type11_data(&[
            b"io.systemd.stub.kernel-cmdline-extra=root=/dev/sda2",
            b"io.systemd.other=value",
        ]);
        let result = find_oem_string(&data, 5, "io.systemd.stub.kernel-cmdline-extra=");
        assert_eq!(result, Some("root=/dev/sda2".to_string()));
    }

    #[test]
    fn test_find_oem_string_not_found() {
        let data = make_type11_data(&[b"other.key=value"]);
        let result = find_oem_string(&data, 5, "io.systemd.stub.kernel-cmdline-extra=");
        assert_eq!(result, None);
    }

    #[test]
    fn test_raw_info_populate() {
        let type1 = make_type1_data();
        let info = raw_info_populate(Some(&type1), 27, None, 0);
        assert_eq!(info.manufacturer, Some("TestVendor".to_string()));
        assert_eq!(info.product_name, Some("TestProduct".to_string()));
        assert!(info.baseboard_manufacturer.is_none());
    }

    #[test]
    fn test_raw_info_populate_no_data() {
        let info = raw_info_populate(None, 0, None, 0);
        assert!(info.manufacturer.is_none());
        assert!(info.product_name.is_none());
    }
}
