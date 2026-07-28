// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/part-discovery.c
//
// GPT partition discovery and device path handling.
//
// Provides functions for finding EFI system partitions by GUID type,
// reading and validating GPT headers, and locating XBOOT loader
// partitions. Implements fallback GPT reading (primary → backup → last LBA).

// ── Constants ─────────────────────────────────────────────────────────────

/// GPT header signature "EFI PART"
pub const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
/// Expected GPT revision (1.0)
pub const GPT_REVISION: u32 = 0x00010000;
/// Minimum valid GPT header size
pub const GPT_HEADER_SIZE_MIN: u32 = 92;
/// Maximum valid GPT header size
pub const GPT_HEADER_SIZE_MAX: u32 = 512;
/// Maximum number of partition entries
pub const GPT_MAX_PARTITIONS: u32 = 1024;
/// Size of a GPT partition entry
pub const EFI_PARTITION_ENTRY_SIZE: usize = 128;

// ── Types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartDiscoveryError {
    NotFound,
    InvalidGpt,
    CrcError,
    IoError,
    NoMedium,
    InvalidParameter,
}

impl std::fmt::Display for PartDiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PartDiscoveryError::NotFound => write!(f, "partition not found"),
            PartDiscoveryError::InvalidGpt => write!(f, "invalid GPT header"),
            PartDiscoveryError::CrcError => write!(f, "CRC mismatch"),
            PartDiscoveryError::IoError => write!(f, "I/O error"),
            PartDiscoveryError::NoMedium => write!(f, "no medium present"),
            PartDiscoveryError::InvalidParameter => write!(f, "invalid parameter"),
        }
    }
}

impl std::error::Error for PartDiscoveryError {}

/// Represents a parsed GPT header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptHeader {
    pub signature: [u8; 8],
    pub revision: u32,
    pub header_size: u32,
    pub header_crc32: u32,
    pub my_lba: u64,
    pub alternate_lba: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub disk_guid: [u8; 16],
    pub partition_entry_lba: u64,
    pub number_of_partition_entries: u32,
    pub size_of_partition_entry: u32,
    pub partition_entry_array_crc32: u32,
}

/// Represents a GPT partition entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionEntry {
    pub partition_type_guid: [u8; 16],
    pub unique_partition_guid: [u8; 16],
    pub starting_lba: u64,
    pub ending_lba: u64,
    pub attributes: u64,
    pub partition_name: [u16; 36],
}

impl PartitionEntry {
    pub fn is_valid(&self) -> bool {
        self.ending_lba >= self.starting_lba
    }
}

/// Simulated block device for testing
#[derive(Debug, Clone)]
pub struct BlockDevice {
    pub media_present: bool,
    pub logical_partition: bool,
    pub last_block: u64,
    pub gpt_header: Option<GptHeader>,
    pub partitions: Vec<PartitionEntry>,
}

impl Default for BlockDevice {
    fn default() -> Self {
        Self {
            media_present: true,
            logical_partition: false,
            last_block: 1024,
            gpt_header: None,
            partitions: Vec::new(),
        }
    }
}

impl BlockDevice {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_media(mut self, present: bool) -> Self {
        self.media_present = present;
        self
    }

    pub fn with_logical_partition(mut self, is_partition: bool) -> Self {
        self.logical_partition = is_partition;
        self
    }

    pub fn is_valid_for_gpt(&self) -> bool {
        !self.logical_partition && self.media_present && self.last_block > 1
    }
}

// ── GPT header validation ─────────────────────────────────────────────────

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// Compute the CRC-32/ISO-HDLC value used by EFI `CalculateCrc32()`.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Parse the fixed GPT header fields without assuming alignment or native
/// endianness.
pub fn parse_gpt_header(raw: &[u8]) -> Result<GptHeader, PartDiscoveryError> {
    let fixed = raw
        .get(..GPT_HEADER_SIZE_MIN as usize)
        .ok_or(PartDiscoveryError::InvalidGpt)?;
    let mut signature = [0u8; 8];
    signature.copy_from_slice(&fixed[..8]);
    let mut disk_guid = [0u8; 16];
    disk_guid.copy_from_slice(&fixed[56..72]);

    Ok(GptHeader {
        signature,
        revision: read_u32_le(fixed, 8).ok_or(PartDiscoveryError::InvalidGpt)?,
        header_size: read_u32_le(fixed, 12).ok_or(PartDiscoveryError::InvalidGpt)?,
        header_crc32: read_u32_le(fixed, 16).ok_or(PartDiscoveryError::InvalidGpt)?,
        my_lba: read_u64_le(fixed, 24).ok_or(PartDiscoveryError::InvalidGpt)?,
        alternate_lba: read_u64_le(fixed, 32).ok_or(PartDiscoveryError::InvalidGpt)?,
        first_usable_lba: read_u64_le(fixed, 40).ok_or(PartDiscoveryError::InvalidGpt)?,
        last_usable_lba: read_u64_le(fixed, 48).ok_or(PartDiscoveryError::InvalidGpt)?,
        disk_guid,
        partition_entry_lba: read_u64_le(fixed, 72).ok_or(PartDiscoveryError::InvalidGpt)?,
        number_of_partition_entries: read_u32_le(fixed, 80)
            .ok_or(PartDiscoveryError::InvalidGpt)?,
        size_of_partition_entry: read_u32_le(fixed, 84).ok_or(PartDiscoveryError::InvalidGpt)?,
        partition_entry_array_crc32: read_u32_le(fixed, 88)
            .ok_or(PartDiscoveryError::InvalidGpt)?,
    })
}

/// Validate raw GPT header bytes (matches C `verify_gpt`).
pub fn verify_gpt(raw: &[u8], lba_expected: u64) -> Result<GptHeader, PartDiscoveryError> {
    let header = parse_gpt_header(raw)?;
    if &header.signature != GPT_SIGNATURE {
        return Err(PartDiscoveryError::InvalidGpt);
    }

    if header.header_size < GPT_HEADER_SIZE_MIN || header.header_size > GPT_HEADER_SIZE_MAX {
        return Err(PartDiscoveryError::InvalidGpt);
    }

    if header.revision != GPT_REVISION {
        return Err(PartDiscoveryError::InvalidGpt);
    }

    let header_size =
        usize::try_from(header.header_size).map_err(|_| PartDiscoveryError::InvalidGpt)?;
    let mut crc_input = raw
        .get(..header_size)
        .ok_or(PartDiscoveryError::InvalidGpt)?
        .to_vec();
    crc_input[16..20].fill(0);
    if crc32(&crc_input) != header.header_crc32 {
        return Err(PartDiscoveryError::CrcError);
    }

    if header.my_lba != lba_expected {
        return Err(PartDiscoveryError::InvalidGpt);
    }

    if (header.size_of_partition_entry as usize % EFI_PARTITION_ENTRY_SIZE) != 0 {
        return Err(PartDiscoveryError::InvalidGpt);
    }

    if header.number_of_partition_entries == 0
        || header.number_of_partition_entries > GPT_MAX_PARTITIONS
    {
        return Err(PartDiscoveryError::InvalidGpt);
    }

    if header.size_of_partition_entry as u64 > u64::MAX / header.number_of_partition_entries as u64
    {
        return Err(PartDiscoveryError::InvalidGpt);
    }

    Ok(header)
}

// ── Partition search ──────────────────────────────────────────────────────

/// Search for a partition by type GUID
pub fn find_partition_by_type<'a>(
    partitions: &'a [PartitionEntry],
    entry_size: u32,
    type_guid: &[u8; 16],
) -> Option<(usize, &'a PartitionEntry)> {
    for (i, entry) in partitions.iter().enumerate() {
        if entry.partition_type_guid != *type_guid {
            continue;
        }
        if !entry.is_valid() {
            continue;
        }
        return Some((i, entry));
    }
    None
}

/// LBA locations to try for GPT headers (primary, backup, last block)
pub fn gpt_lba_candidates(backup_lba: u64, last_block: u64) -> Vec<(usize, u64)> {
    let mut candidates = Vec::new();

    candidates.push((0, 1));

    if backup_lba != 0 {
        candidates.push((1, backup_lba));
    }

    if backup_lba != last_block {
        candidates.push((2, last_block));
    }

    candidates
}

fn parse_partition_entry(raw: &[u8]) -> Result<PartitionEntry, PartDiscoveryError> {
    let fixed = raw
        .get(..EFI_PARTITION_ENTRY_SIZE)
        .ok_or(PartDiscoveryError::InvalidGpt)?;
    let mut partition_type_guid = [0u8; 16];
    partition_type_guid.copy_from_slice(&fixed[..16]);
    let mut unique_partition_guid = [0u8; 16];
    unique_partition_guid.copy_from_slice(&fixed[16..32]);
    let mut partition_name = [0u16; 36];
    for (index, code_unit) in partition_name.iter_mut().enumerate() {
        let offset = 56 + index * 2;
        *code_unit = u16::from_le_bytes([fixed[offset], fixed[offset + 1]]);
    }

    Ok(PartitionEntry {
        partition_type_guid,
        unique_partition_guid,
        starting_lba: read_u64_le(fixed, 32).ok_or(PartDiscoveryError::InvalidGpt)?,
        ending_lba: read_u64_le(fixed, 40).ok_or(PartDiscoveryError::InvalidGpt)?,
        attributes: read_u64_le(fixed, 48).ok_or(PartDiscoveryError::InvalidGpt)?,
        partition_name,
    })
}

/// Verify and search raw GPT partition-entry bytes (matches core `try_gpt`).
///
/// The returned entry is parsed only after the exact byte range read and
/// checksummed by the canonical implementation has passed CRC validation.
pub fn try_find_partition(
    header: &GptHeader,
    raw_entries: &[u8],
    type_guid: &[u8; 16],
) -> Result<Option<(usize, PartitionEntry)>, PartDiscoveryError> {
    let entry_size = usize::try_from(header.size_of_partition_entry)
        .map_err(|_| PartDiscoveryError::InvalidGpt)?;
    if entry_size == 0 || entry_size % EFI_PARTITION_ENTRY_SIZE != 0 {
        return Err(PartDiscoveryError::InvalidGpt);
    }
    let entry_count = usize::try_from(header.number_of_partition_entries)
        .map_err(|_| PartDiscoveryError::InvalidGpt)?;
    if entry_count == 0 || entry_count > GPT_MAX_PARTITIONS as usize {
        return Err(PartDiscoveryError::InvalidGpt);
    }
    let bytes = entry_size
        .checked_mul(entry_count)
        .ok_or(PartDiscoveryError::InvalidGpt)?;
    let crc_size = bytes
        .checked_add(511)
        .map(|size| size & !511)
        .ok_or(PartDiscoveryError::InvalidGpt)?;
    let crc_input = raw_entries
        .get(..crc_size)
        .ok_or(PartDiscoveryError::InvalidGpt)?;
    if crc32(crc_input) != header.partition_entry_array_crc32 {
        return Err(PartDiscoveryError::CrcError);
    }

    for index in 0..entry_count {
        let offset = index
            .checked_mul(entry_size)
            .ok_or(PartDiscoveryError::InvalidGpt)?;
        let end = offset
            .checked_add(entry_size)
            .ok_or(PartDiscoveryError::InvalidGpt)?;
        let entry = parse_partition_entry(
            raw_entries
                .get(offset..end)
                .ok_or(PartDiscoveryError::InvalidGpt)?,
        )?;
        if entry.partition_type_guid == *type_guid && entry.is_valid() {
            return Ok(Some((index, entry)));
        }
    }
    Ok(None)
}

// ── GUID formatting ───────────────────────────────────────────────────────

/// Format a GUID as a string (matches C GUID_FORMAT_STR output)
pub fn format_guid(guid: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid[3],
        guid[2],
        guid[1],
        guid[0],
        guid[5],
        guid[4],
        guid[7],
        guid[6],
        guid[8],
        guid[9],
        guid[10],
        guid[11],
        guid[12],
        guid[13],
        guid[14],
        guid[15]
    )
}

/// Check if two GUIDs are equal
pub fn guid_equal(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a == b
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_gpt_header() -> GptHeader {
        GptHeader {
            signature: *GPT_SIGNATURE,
            revision: GPT_REVISION,
            header_size: 92,
            header_crc32: 0,
            my_lba: 1,
            alternate_lba: 1023,
            first_usable_lba: 34,
            last_usable_lba: 990,
            disk_guid: [0u8; 16],
            partition_entry_lba: 2,
            number_of_partition_entries: 128,
            size_of_partition_entry: EFI_PARTITION_ENTRY_SIZE as u32,
            partition_entry_array_crc32: 0,
        }
    }

    fn encode_gpt_header(header: &GptHeader) -> Vec<u8> {
        let mut raw = vec![0u8; (GPT_HEADER_SIZE_MAX as usize).max(header.header_size as usize)];
        raw[..8].copy_from_slice(&header.signature);
        raw[8..12].copy_from_slice(&header.revision.to_le_bytes());
        raw[12..16].copy_from_slice(&header.header_size.to_le_bytes());
        raw[24..32].copy_from_slice(&header.my_lba.to_le_bytes());
        raw[32..40].copy_from_slice(&header.alternate_lba.to_le_bytes());
        raw[40..48].copy_from_slice(&header.first_usable_lba.to_le_bytes());
        raw[48..56].copy_from_slice(&header.last_usable_lba.to_le_bytes());
        raw[56..72].copy_from_slice(&header.disk_guid);
        raw[72..80].copy_from_slice(&header.partition_entry_lba.to_le_bytes());
        raw[80..84].copy_from_slice(&header.number_of_partition_entries.to_le_bytes());
        raw[84..88].copy_from_slice(&header.size_of_partition_entry.to_le_bytes());
        raw[88..92].copy_from_slice(&header.partition_entry_array_crc32.to_le_bytes());
        let checksum = crc32(&raw[..header.header_size as usize]);
        raw[16..20].copy_from_slice(&checksum.to_le_bytes());
        raw
    }

    #[test]
    fn test_crc32_standard_vector() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn test_verify_gpt_valid() {
        let raw = encode_gpt_header(&make_valid_gpt_header());
        assert_eq!(verify_gpt(&raw, 1).unwrap().my_lba, 1);
    }

    #[test]
    fn test_verify_gpt_bad_signature() {
        let mut header = make_valid_gpt_header();
        header.signature = *b"BAD SIG!";
        assert_eq!(
            verify_gpt(&encode_gpt_header(&header), 1),
            Err(PartDiscoveryError::InvalidGpt)
        );
    }

    #[test]
    fn test_verify_gpt_wrong_revision() {
        let mut header = make_valid_gpt_header();
        header.revision = 0x00020000;
        assert_eq!(
            verify_gpt(&encode_gpt_header(&header), 1),
            Err(PartDiscoveryError::InvalidGpt)
        );
    }

    #[test]
    fn test_verify_gpt_header_size_too_small() {
        let mut header = make_valid_gpt_header();
        header.header_size = 64;
        assert_eq!(
            verify_gpt(&encode_gpt_header(&header), 1),
            Err(PartDiscoveryError::InvalidGpt)
        );
    }

    #[test]
    fn test_verify_gpt_header_size_too_large() {
        let mut header = make_valid_gpt_header();
        header.header_size = 1024;
        let raw = encode_gpt_header(&header);
        assert_eq!(verify_gpt(&raw, 1), Err(PartDiscoveryError::InvalidGpt));
    }

    #[test]
    fn test_verify_gpt_wrong_lba() {
        let raw = encode_gpt_header(&make_valid_gpt_header());
        assert_eq!(verify_gpt(&raw, 2), Err(PartDiscoveryError::InvalidGpt));
    }

    #[test]
    fn test_verify_gpt_bad_crc() {
        let mut raw = encode_gpt_header(&make_valid_gpt_header());
        raw[40] ^= 1;
        assert_eq!(verify_gpt(&raw, 1), Err(PartDiscoveryError::CrcError));
    }

    #[test]
    fn test_verify_gpt_zero_partitions() {
        let mut header = make_valid_gpt_header();
        header.number_of_partition_entries = 0;
        assert_eq!(
            verify_gpt(&encode_gpt_header(&header), 1),
            Err(PartDiscoveryError::InvalidGpt)
        );
    }

    #[test]
    fn test_verify_gpt_too_many_partitions() {
        let mut header = make_valid_gpt_header();
        header.number_of_partition_entries = 2048;
        assert_eq!(
            verify_gpt(&encode_gpt_header(&header), 1),
            Err(PartDiscoveryError::InvalidGpt)
        );
    }

    #[test]
    fn test_partition_entry_is_valid() {
        let entry = PartitionEntry {
            partition_type_guid: [0u8; 16],
            unique_partition_guid: [0u8; 16],
            starting_lba: 100,
            ending_lba: 200,
            attributes: 0,
            partition_name: [0u16; 36],
        };
        assert!(entry.is_valid());
    }

    #[test]
    fn test_partition_entry_invalid_lba() {
        let entry = PartitionEntry {
            partition_type_guid: [0u8; 16],
            unique_partition_guid: [0u8; 16],
            starting_lba: 200,
            ending_lba: 100,
            attributes: 0,
            partition_name: [0u16; 36],
        };
        assert!(!entry.is_valid());
    }

    #[test]
    fn test_find_partition_by_type() {
        let mut entry = PartitionEntry {
            partition_type_guid: [0xAA; 16],
            unique_partition_guid: [0u8; 16],
            starting_lba: 100,
            ending_lba: 200,
            attributes: 0,
            partition_name: [0u16; 36],
        };
        let partitions = vec![entry];
        let guid = [0xAAu8; 16];
        let result = find_partition_by_type(&partitions, 128, &guid);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, 0);
    }

    #[test]
    fn test_find_partition_not_found() {
        let entry = PartitionEntry {
            partition_type_guid: [0xAA; 16],
            unique_partition_guid: [0u8; 16],
            starting_lba: 100,
            ending_lba: 200,
            attributes: 0,
            partition_name: [0u16; 36],
        };
        let partitions = vec![entry];
        let guid = [0xBBu8; 16];
        assert!(find_partition_by_type(&partitions, 128, &guid).is_none());
    }

    fn raw_partition_table(type_guid: [u8; 16]) -> Vec<u8> {
        let mut raw = vec![0u8; 512];
        raw[..16].copy_from_slice(&type_guid);
        raw[16..32].copy_from_slice(&[0x55; 16]);
        raw[32..40].copy_from_slice(&100u64.to_le_bytes());
        raw[40..48].copy_from_slice(&200u64.to_le_bytes());
        raw
    }

    #[test]
    fn test_try_find_partition_requires_valid_entry_crc() {
        let guid = [0xAA; 16];
        let raw = raw_partition_table(guid);
        let mut header = make_valid_gpt_header();
        header.number_of_partition_entries = 1;
        header.partition_entry_array_crc32 = crc32(&raw);

        let (index, entry) = try_find_partition(&header, &raw, &guid).unwrap().unwrap();
        assert_eq!(index, 0);
        assert_eq!(entry.partition_type_guid, guid);
        assert_eq!(entry.starting_lba, 100);
        assert_eq!(entry.ending_lba, 200);
    }

    #[test]
    fn test_try_find_partition_rejects_corrupt_entry_array() {
        let guid = [0xAA; 16];
        let mut raw = raw_partition_table(guid);
        let mut header = make_valid_gpt_header();
        header.number_of_partition_entries = 1;
        header.partition_entry_array_crc32 = crc32(&raw);
        raw[40] ^= 1;

        assert_eq!(
            try_find_partition(&header, &raw, &guid),
            Err(PartDiscoveryError::CrcError)
        );
    }

    #[test]
    fn test_gpt_lba_candidates() {
        let candidates = gpt_lba_candidates(1023, 1024);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0], (0, 1));
        assert_eq!(candidates[1], (1, 1023));
        assert_eq!(candidates[2], (2, 1024));
    }

    #[test]
    fn test_format_guid() {
        let guid: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let formatted = format_guid(&guid);
        assert_eq!(formatted, "04030201-0605-0807-090a-0b0c0d0e0f10");
    }

    #[test]
    fn test_guid_equal() {
        let a = [1u8; 16];
        let b = [1u8; 16];
        let c = [2u8; 16];
        assert!(guid_equal(&a, &b));
        assert!(!guid_equal(&a, &c));
    }

    #[test]
    fn test_block_device_valid_for_gpt() {
        let bd = BlockDevice::new();
        assert!(bd.is_valid_for_gpt());
    }

    #[test]
    fn test_block_device_logical_partition_rejected() {
        let bd = BlockDevice::new().with_logical_partition(true);
        assert!(!bd.is_valid_for_gpt());
    }

    #[test]
    fn test_block_device_no_media_rejected() {
        let bd = BlockDevice::new().with_media(false);
        assert!(!bd.is_valid_for_gpt());
    }
}
