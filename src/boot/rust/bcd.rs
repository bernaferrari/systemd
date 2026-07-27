// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/boot/bcd.c
//
// Windows Boot Configuration Data (BCD) parser.
//
// Parses a Windows registry hive to extract boot entry titles.
// The BCD store is a regular Windows registry hive with a specific
// internal key structure used for boot configuration.

// ── Constants ─────────────────────────────────────────────────────────────

/// Registry hive base block signature ("regf").
const SIG_BASE_BLOCK: u32 = 1718052210;
/// Registry key node signature ("nk").
const SIG_KEY: u16 = 27502;
/// Registry subkey fast index signature ("lf").
const SIG_SUBKEY_FAST: u16 = 26220;
/// Registry key value signature ("vk").
const SIG_KEY_VALUE: u16 = 27510;

/// Registry type: null-terminated string.
const REG_SZ: u32 = 1;
/// Registry type: multiple null-terminated strings.
const REG_MULTI_SZ: u32 = 7;

/// Size of the base block (hive header).
const BASE_BLOCK_SIZE: usize = 4096;
/// Offset to first hive cell (past base block + cell size u32).
const HIVE_CELL_OFFSET: usize = BASE_BLOCK_SIZE + 4;

/// The bootmgr GUID used to look up the display order.
const BOOTMGR_GUID: &str = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}";

// ── Error type ────────────────────────────────────────────────────────────

/// Errors that can occur during BCD parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BcdError {
    /// The input data is too short.
    BufferTooShort,
    /// The base block signature is invalid.
    InvalidBaseBlock,
    /// The hive version is unsupported.
    UnsupportedVersion,
    /// The hive type is invalid.
    InvalidType,
    /// The sequence numbers don't match (corrupt hive).
    SequenceMismatch,
    /// A required key was not found.
    KeyNotFound,
    /// A required value was not found.
    ValueNotFound,
    /// The BCD store is multi-boot (contains multiple GUIDs).
    MultiBoot,
    /// A GUID character is invalid.
    InvalidGuid,
    /// Alignment requirement not met.
    BadAlignment,
    /// The data type is unexpected.
    UnexpectedDataType,
    /// The data size is invalid.
    InvalidDataSize,
    /// Allocating a safe owned title copy failed.
    AllocationFailed,
}

impl std::fmt::Display for BcdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BcdError::BufferTooShort => write!(f, "BCD data buffer too short"),
            BcdError::InvalidBaseBlock => write!(f, "invalid base block signature"),
            BcdError::UnsupportedVersion => write!(f, "unsupported hive version"),
            BcdError::InvalidType => write!(f, "invalid hive type"),
            BcdError::SequenceMismatch => write!(f, "primary/secondary sequence mismatch"),
            BcdError::KeyNotFound => write!(f, "key not found"),
            BcdError::ValueNotFound => write!(f, "value not found"),
            BcdError::MultiBoot => write!(f, "BCD is multi-boot"),
            BcdError::InvalidGuid => write!(f, "invalid GUID character"),
            BcdError::BadAlignment => write!(f, "alignment requirement not met"),
            BcdError::UnexpectedDataType => write!(f, "unexpected data type"),
            BcdError::InvalidDataSize => write!(f, "invalid data size"),
            BcdError::AllocationFailed => write!(f, "failed to allocate BCD title"),
        }
    }
}

impl std::error::Error for BcdError {}

// ── Data structures ───────────────────────────────────────────────────────

/// Parsed registry hive base-block fields.
///
/// This is a Rust data-transfer object, not an overlay of the on-disk packed
/// header. `validate_base_block()` performs explicit little-endian reads.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BaseBlock {
    pub sig: u32,
    pub primary_seqnum: u32,
    pub secondary_seqnum: u32,
    // _pad1: u64  -- offset 16..24, skipped
    pub version_major: u32,
    pub version_minor: u32,
    pub type_: u32,
    // _pad2: u32  -- offset 32..36, skipped
    pub root_cell_offset: u32,
}

// ── Helper functions ──────────────────────────────────────────────────────

/// Check if an offset + length would exceed the buffer bounds.
#[cfg(test)]
fn bad_offset(offset: u64, len: u64, max: u64) -> bool {
    offset > max || len > max - offset
}

/// Check if a struct at the given offset would fit within bounds.
#[cfg(test)]
fn bad_struct(offset: u64, struct_size: usize, max: u64) -> bool {
    bad_offset(offset, struct_size as u64, max)
}

/// Check if an array within a struct would fit within bounds.
#[cfg(test)]
fn bad_array(
    offset: u64,
    array_offset: usize,
    element_size: usize,
    array_len: u64,
    max: u64,
) -> bool {
    let Some(start) = offset.checked_add(array_offset as u64) else {
        return true;
    };
    let Some(len) = (element_size as u64).checked_mul(array_len) else {
        return true;
    };
    bad_offset(start, len, max)
}

/// Case-insensitive comparison of two byte strings up to `len` bytes.
fn strncaseeq(a: &[u8], b: &[u8], len: usize) -> bool {
    if a.len() < len || b.len() < len {
        return false;
    }

    a[..len]
        .iter()
        .zip(b[..len].iter())
        .all(|(ca, cb)| ca.to_ascii_lowercase() == cb.to_ascii_lowercase())
}

/// Check if a character is valid in a GUID string.
fn is_valid_guid_char(c: u16) -> bool {
    matches!(c, 0x2d | 0x7b | 0x7d | 0x30..=0x39 | 0x61..=0x66 | 0x41..=0x46)
}

// ── Core parsing ──────────────────────────────────────────────────────────

/// Parse and validate the base block of the registry hive.
fn validate_base_block(data: &[u8]) -> Result<BaseBlock, BcdError> {
    if data.len() < BASE_BLOCK_SIZE {
        return Err(BcdError::BufferTooShort);
    }

    let sig = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if sig != SIG_BASE_BLOCK {
        return Err(BcdError::InvalidBaseBlock);
    }

    let primary_seqnum = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let secondary_seqnum = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

    let version_major = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let version_minor = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);

    let type_ = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
    let root_cell_offset = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);

    if version_major != 1 || version_minor != 3 {
        return Err(BcdError::UnsupportedVersion);
    }
    if type_ != 0 {
        return Err(BcdError::InvalidType);
    }
    if primary_seqnum != secondary_seqnum {
        return Err(BcdError::SequenceMismatch);
    }

    Ok(BaseBlock {
        sig,
        primary_seqnum,
        secondary_seqnum,
        version_major,
        version_minor,
        type_,
        root_cell_offset,
    })
}

/// Extract a null-separated path component from a lookup key string.
/// The C code uses NUL bytes as path separators in the key name.
#[cfg(test)]
fn parse_key_path(path: &[u8]) -> Vec<&[u8]> {
    path.split(|&b| b == 0).filter(|s| !s.is_empty()).collect()
}

/// Look up a key in the registry hive by following a null-separated path.
///
/// The `name` parameter uses NUL bytes as path separators.
/// To start from the root, begin name with a NUL byte.
/// Name must end with two NUL bytes.
fn get_key(bcd: &[u8], offset: u32, name: &[u8]) -> Result<KeyInfo, BcdError> {
    let mut key = key_at(bcd, offset)?;
    let mut path = name.split(|byte| *byte == 0);

    if let Some(first) = path.next() {
        if !first.is_empty() && !key_name_eq(&key, first) {
            return Err(BcdError::KeyNotFound);
        }
    }

    for component in path.filter(|component| !component.is_empty()) {
        key = get_subkey(bcd, key.subkeys_offset, component)?;
    }

    Ok(key)
}

/// Information extracted from a parsed key node.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyInfo {
    subkeys_offset: u32,
    n_key_values: u32,
    key_values_offset: u32,
    key_name: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
struct KeyValueInfo {
    data_size: u32,
    data_offset: u32,
    data_type: u32,
}

const KEY_HEADER_SIZE: usize = 76;
const SUBKEY_FAST_HEADER_SIZE: usize = 4;
const SUBKEY_FAST_ENTRY_SIZE: usize = 8;
const KEY_VALUE_HEADER_SIZE: usize = 20;
const KEY_VALUE_NAME_OFFSET: usize = 20;
const ORDER_GUID_LEN: usize = "{00000000-0000-0000-0000-000000000000}".len();
const ORDER_GUID_DATA_LEN: usize = (ORDER_GUID_LEN + 2) * std::mem::size_of::<u16>();

fn bytes_at(data: &[u8], offset: u32, len: usize) -> Result<&[u8], BcdError> {
    let start = offset as usize;
    let end = start.checked_add(len).ok_or(BcdError::BufferTooShort)?;
    data.get(start..end).ok_or(BcdError::BufferTooShort)
}

fn read_u16(data: &[u8], offset: u32) -> Result<u16, BcdError> {
    let bytes = bytes_at(data, offset, std::mem::size_of::<u16>())?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Mirror the C parser's alignment gate without ever dereferencing an
/// unaligned typed pointer. Offsets alone are insufficient because a caller
/// may pass a subslice whose base address is odd.
fn bytes_are_aligned(data: &[u8], offset: u32, alignment: usize) -> bool {
    (data.as_ptr() as usize)
        .checked_add(offset as usize)
        .is_some_and(|address| address % alignment == 0)
}

fn key_at(hive: &[u8], offset: u32) -> Result<KeyInfo, BcdError> {
    let header = bytes_at(hive, offset, KEY_HEADER_SIZE)?;
    if u16::from_le_bytes([header[0], header[1]]) != SIG_KEY {
        return Err(BcdError::KeyNotFound);
    }

    let key_name_len = u16::from_le_bytes([header[72], header[73]]) as usize;
    let name_offset = offset
        .checked_add(KEY_HEADER_SIZE as u32)
        .ok_or(BcdError::BufferTooShort)?;
    let key_name_bytes = bytes_at(hive, name_offset, key_name_len)?;
    let mut key_name = Vec::new();
    key_name
        .try_reserve_exact(key_name_len)
        .map_err(|_| BcdError::AllocationFailed)?;
    key_name.extend_from_slice(key_name_bytes);

    Ok(KeyInfo {
        subkeys_offset: u32::from_le_bytes([header[28], header[29], header[30], header[31]]),
        n_key_values: u32::from_le_bytes([header[36], header[37], header[38], header[39]]),
        key_values_offset: u32::from_le_bytes([header[40], header[41], header[42], header[43]]),
        key_name,
    })
}

fn key_name_eq(key: &KeyInfo, name: &[u8]) -> bool {
    key.key_name.len() == name.len() && strncaseeq(&key.key_name, name, name.len())
}

fn subkey_hint_matches(name: &[u8], hint: &[u8]) -> bool {
    name.len() >= hint.len() && strncaseeq(name, hint, hint.len())
}

fn get_subkey(hive: &[u8], offset: u32, name: &[u8]) -> Result<KeyInfo, BcdError> {
    let header = bytes_at(hive, offset, SUBKEY_FAST_HEADER_SIZE)?;
    if u16::from_le_bytes([header[0], header[1]]) != SIG_SUBKEY_FAST {
        return Err(BcdError::KeyNotFound);
    }

    let n_entries = u16::from_le_bytes([header[2], header[3]]) as usize;
    let entries_len = n_entries
        .checked_mul(SUBKEY_FAST_ENTRY_SIZE)
        .ok_or(BcdError::BufferTooShort)?;
    let entries_offset = offset
        .checked_add(SUBKEY_FAST_HEADER_SIZE as u32)
        .ok_or(BcdError::BufferTooShort)?;
    let entries = bytes_at(hive, entries_offset, entries_len)?;

    for entry in entries.chunks_exact(SUBKEY_FAST_ENTRY_SIZE) {
        if !subkey_hint_matches(name, &entry[4..8]) {
            continue;
        }

        let key_offset = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
        match key_at(hive, key_offset) {
            Ok(key) if key_name_eq(&key, name) => return Ok(key),
            Ok(_) | Err(BcdError::KeyNotFound) => continue,
            // get_key() in the C authority returns NULL for every malformed
            // candidate. Keep searching: several lf entries may share the
            // same four-byte hint, and a later entry can still be valid.
            Err(_) => continue,
        }
    }

    Err(BcdError::KeyNotFound)
}

fn get_subkey_path(hive: &[u8], offset: u32, path: &[&[u8]]) -> Result<KeyInfo, BcdError> {
    let (first, rest) = path.split_first().ok_or(BcdError::KeyNotFound)?;
    let mut key = get_subkey(hive, offset, first)?;
    for name in rest {
        key = get_subkey(hive, key.subkeys_offset, name)?;
    }
    Ok(key)
}

fn get_key_value(hive: &[u8], key: &KeyInfo, name: &[u8]) -> Result<KeyValueInfo, BcdError> {
    if key.n_key_values == 0 {
        return Err(BcdError::ValueNotFound);
    }
    if !bytes_are_aligned(hive, key.key_values_offset, std::mem::align_of::<u32>()) {
        return Err(BcdError::BadAlignment);
    }

    let list_len = (key.n_key_values as usize)
        .checked_mul(std::mem::size_of::<u32>())
        .ok_or(BcdError::BufferTooShort)?;
    let list = bytes_at(hive, key.key_values_offset, list_len)?;

    for offset in list.chunks_exact(std::mem::size_of::<u32>()) {
        let value_offset = u32::from_le_bytes([offset[0], offset[1], offset[2], offset[3]]);
        let header = match bytes_at(hive, value_offset, KEY_VALUE_HEADER_SIZE) {
            Ok(header) => header,
            Err(_) => continue,
        };
        if u16::from_le_bytes([header[0], header[1]]) != SIG_KEY_VALUE {
            continue;
        }

        let name_len = u16::from_le_bytes([header[2], header[3]]) as usize;
        let name_offset = match value_offset.checked_add(KEY_VALUE_NAME_OFFSET as u32) {
            Some(offset) => offset,
            None => continue,
        };
        let value_name = match bytes_at(hive, name_offset, name_len) {
            Ok(value_name) => value_name,
            Err(_) => continue,
        };
        let data_size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        if data_size & (1 << 31) != 0 {
            continue;
        }
        let data_offset = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
        if bytes_at(hive, data_offset, data_size as usize).is_err() {
            continue;
        }

        if value_name.len() == name.len() && strncaseeq(value_name, name, name.len()) {
            return Ok(KeyValueInfo {
                data_size,
                data_offset,
                data_type: u32::from_le_bytes([header[12], header[13], header[14], header[15]]),
            });
        }
    }

    Err(BcdError::ValueNotFound)
}

/// Extract the BCD title from a registry hive blob.
///
/// Follows the displayorder of {bootmgr} to find the default entry,
/// then returns its description as an owned, NUL-terminated UTF-16 buffer.
///
/// This deliberately preserves the code units found in the hive. The C
/// function returns a `char16_t *` into a mutable input buffer and overwrites
/// its final code unit with NUL; accepting arbitrary UTF-16 is therefore part
/// of its observable behavior. Returning an owned buffer preserves that
/// behavior without mutating an immutable Rust input slice or pretending that
/// all Windows strings are valid Rust UTF-8.
pub fn get_bcd_title(bcd: &[u8]) -> Result<Vec<u16>, BcdError> {
    let base_block = validate_base_block(bcd)?;

    if HIVE_CELL_OFFSET >= bcd.len() {
        return Err(BcdError::BufferTooShort);
    }

    // Work with the portion after the base block
    let hive_data = &bcd[HIVE_CELL_OFFSET..];
    let objects_key = get_key(hive_data, base_block.root_cell_offset, b"\0Objects\0\0")?;
    let displayorder_key = get_subkey_path(
        hive_data,
        objects_key.subkeys_offset,
        &[BOOTMGR_GUID.as_bytes(), b"Elements", b"24000001"],
    )?;
    let displayorder_value = get_key_value(hive_data, &displayorder_key, b"Element")?;

    // A display order containing anything other than exactly one GUID is
    // deliberately treated as multiboot, matching the C implementation.
    if displayorder_value.data_type != REG_MULTI_SZ
        || displayorder_value.data_size as usize != ORDER_GUID_DATA_LEN
    {
        return Err(BcdError::MultiBoot);
    }
    if !bytes_are_aligned(
        hive_data,
        displayorder_value.data_offset,
        std::mem::align_of::<u16>(),
    ) {
        return Err(BcdError::MultiBoot);
    }

    let mut order_guid = Vec::with_capacity(ORDER_GUID_LEN);
    for index in 0..ORDER_GUID_LEN {
        let offset = displayorder_value
            .data_offset
            .checked_add((index * std::mem::size_of::<u16>()) as u32)
            .ok_or(BcdError::BufferTooShort)?;
        let character = read_u16(hive_data, offset)?;
        if !is_valid_guid_char(character) {
            return Err(BcdError::InvalidGuid);
        }
        order_guid.push(character as u8);
    }

    let default_key = get_subkey(hive_data, objects_key.subkeys_offset, &order_guid)?;
    let description_key = get_subkey_path(
        hive_data,
        default_key.subkeys_offset,
        &[b"Elements", b"12000004"],
    )?;
    let description_value = get_key_value(hive_data, &description_key, b"Element")?;

    if description_value.data_type != REG_SZ {
        return Err(BcdError::UnexpectedDataType);
    }
    if description_value.data_size < std::mem::size_of::<u16>() as u32
        || description_value.data_size % std::mem::size_of::<u16>() as u32 != 0
    {
        return Err(BcdError::InvalidDataSize);
    }
    if !bytes_are_aligned(
        hive_data,
        description_value.data_offset,
        std::mem::align_of::<u16>(),
    ) {
        return Err(BcdError::BadAlignment);
    }

    // C force-terminates the last UTF-16 code unit before returning the
    // title. Read the same prefix without mutating an immutable input slice.
    let code_units = description_value.data_size as usize / std::mem::size_of::<u16>();
    let mut title = Vec::new();
    title
        .try_reserve_exact(code_units)
        .map_err(|_| BcdError::AllocationFailed)?;
    for index in 0..code_units {
        let offset = description_value
            .data_offset
            .checked_add((index * std::mem::size_of::<u16>()) as u32)
            .ok_or(BcdError::BufferTooShort)?;
        title.push(read_u16(hive_data, offset)?);
    }
    // The C authority force-terminates the final unit, even if the hive did
    // not provide a terminator. This includes a one-unit empty title.
    debug_assert!(!title.is_empty());
    *title
        .last_mut()
        .expect("description has at least one UTF-16 unit") = 0;

    Ok(title)
}

/// Convert a BCD title to display text explicitly and lossily.
///
/// Callers that need the C-compatible title must use [`get_bcd_title`] and
/// retain the UTF-16 units. This helper is only for output intended for a
/// Rust text interface.
pub fn bcd_title_to_string_lossy(title: &[u16]) -> String {
    let length = title
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(title.len());
    String::from_utf16_lossy(&title[..length])
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_KEY_OFFSET: usize = 0;
    const ROOT_INDEX_OFFSET: usize = 100;
    const OBJECTS_KEY_OFFSET: usize = 200;
    const OBJECTS_INDEX_OFFSET: usize = 300;
    const BOOTMGR_KEY_OFFSET: usize = 400;
    const BOOTMGR_INDEX_OFFSET: usize = 550;
    const BOOTMGR_ELEMENTS_KEY_OFFSET: usize = 600;
    const BOOTMGR_ELEMENTS_INDEX_OFFSET: usize = 700;
    const DISPLAYORDER_KEY_OFFSET: usize = 800;
    const DISPLAYORDER_VALUES_OFFSET: usize = 900;
    const DISPLAYORDER_VALUE_OFFSET: usize = 920;
    const DISPLAYORDER_DATA_OFFSET: usize = 1000;
    const LOADER_KEY_OFFSET: usize = 1200;
    const LOADER_INDEX_OFFSET: usize = 1350;
    const LOADER_ELEMENTS_KEY_OFFSET: usize = 1400;
    const LOADER_ELEMENTS_INDEX_OFFSET: usize = 1500;
    const DESCRIPTION_KEY_OFFSET: usize = 1600;
    const DESCRIPTION_VALUES_OFFSET: usize = 1700;
    const DESCRIPTION_VALUE_OFFSET: usize = 1720;
    const DESCRIPTION_DATA_OFFSET: usize = 1800;

    const TEST_LOADER_GUID: &str = "{11111111-2222-3333-4444-555555555555}";

    fn put_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_key(
        hive: &mut [u8],
        offset: usize,
        name: &[u8],
        subkeys_offset: usize,
        n_key_values: u32,
        key_values_offset: usize,
    ) {
        put_u16(hive, offset, SIG_KEY);
        put_u32(hive, offset + 28, subkeys_offset as u32);
        put_u32(hive, offset + 36, n_key_values);
        put_u32(hive, offset + 40, key_values_offset as u32);
        put_u16(hive, offset + 72, name.len() as u16);
        hive[offset + KEY_HEADER_SIZE..offset + KEY_HEADER_SIZE + name.len()].copy_from_slice(name);
    }

    fn put_index(hive: &mut [u8], offset: usize, entries: &[(usize, &[u8])]) {
        put_u16(hive, offset, SIG_SUBKEY_FAST);
        put_u16(hive, offset + 2, entries.len() as u16);
        for (index, (key_offset, hint)) in entries.iter().enumerate() {
            let entry_offset = offset + SUBKEY_FAST_HEADER_SIZE + index * SUBKEY_FAST_ENTRY_SIZE;
            put_u32(hive, entry_offset, *key_offset as u32);
            hive[entry_offset + 4..entry_offset + 8].copy_from_slice(&hint[..4]);
        }
    }

    fn put_value(
        hive: &mut [u8],
        offset: usize,
        name: &[u8],
        data_type: u32,
        data_offset: usize,
        data_size: usize,
    ) {
        put_u16(hive, offset, SIG_KEY_VALUE);
        put_u16(hive, offset + 2, name.len() as u16);
        put_u32(hive, offset + 4, data_size as u32);
        put_u32(hive, offset + 8, data_offset as u32);
        put_u32(hive, offset + 12, data_type);
        hive[offset + KEY_VALUE_NAME_OFFSET..offset + KEY_VALUE_NAME_OFFSET + name.len()]
            .copy_from_slice(name);
    }

    fn put_utf16(hive: &mut [u8], offset: usize, value: &[u16]) {
        for (index, code_unit) in value.iter().enumerate() {
            put_u16(
                hive,
                offset + index * std::mem::size_of::<u16>(),
                *code_unit,
            );
        }
    }

    fn sample_bcd() -> Vec<u8> {
        let mut bcd = vec![0u8; HIVE_CELL_OFFSET + 2400];
        put_u32(&mut bcd, 0, SIG_BASE_BLOCK);
        put_u32(&mut bcd, 4, 1);
        put_u32(&mut bcd, 8, 1);
        put_u32(&mut bcd, 20, 1);
        put_u32(&mut bcd, 24, 3);
        put_u32(&mut bcd, 28, 0);
        put_u32(&mut bcd, 36, ROOT_KEY_OFFSET as u32);

        let hive = &mut bcd[HIVE_CELL_OFFSET..];
        put_key(hive, ROOT_KEY_OFFSET, b"ROOT", ROOT_INDEX_OFFSET, 0, 0);
        put_index(hive, ROOT_INDEX_OFFSET, &[(OBJECTS_KEY_OFFSET, b"Obje")]);
        put_key(
            hive,
            OBJECTS_KEY_OFFSET,
            b"Objects",
            OBJECTS_INDEX_OFFSET,
            0,
            0,
        );
        put_index(
            hive,
            OBJECTS_INDEX_OFFSET,
            &[
                (BOOTMGR_KEY_OFFSET, BOOTMGR_GUID.as_bytes()),
                (LOADER_KEY_OFFSET, TEST_LOADER_GUID.as_bytes()),
            ],
        );
        put_key(
            hive,
            BOOTMGR_KEY_OFFSET,
            BOOTMGR_GUID.as_bytes(),
            BOOTMGR_INDEX_OFFSET,
            0,
            0,
        );
        put_index(
            hive,
            BOOTMGR_INDEX_OFFSET,
            &[(BOOTMGR_ELEMENTS_KEY_OFFSET, b"Elem")],
        );
        put_key(
            hive,
            BOOTMGR_ELEMENTS_KEY_OFFSET,
            b"Elements",
            BOOTMGR_ELEMENTS_INDEX_OFFSET,
            0,
            0,
        );
        put_index(
            hive,
            BOOTMGR_ELEMENTS_INDEX_OFFSET,
            &[(DISPLAYORDER_KEY_OFFSET, b"2400")],
        );
        put_key(
            hive,
            DISPLAYORDER_KEY_OFFSET,
            b"24000001",
            0,
            1,
            DISPLAYORDER_VALUES_OFFSET,
        );
        put_u32(
            hive,
            DISPLAYORDER_VALUES_OFFSET,
            DISPLAYORDER_VALUE_OFFSET as u32,
        );

        let mut order: Vec<u16> = TEST_LOADER_GUID.encode_utf16().collect();
        order.extend([0, 0]);
        assert_eq!(
            order.len() * std::mem::size_of::<u16>(),
            ORDER_GUID_DATA_LEN
        );
        put_value(
            hive,
            DISPLAYORDER_VALUE_OFFSET,
            b"Element",
            REG_MULTI_SZ,
            DISPLAYORDER_DATA_OFFSET,
            ORDER_GUID_DATA_LEN,
        );
        put_utf16(hive, DISPLAYORDER_DATA_OFFSET, &order);

        put_key(
            hive,
            LOADER_KEY_OFFSET,
            TEST_LOADER_GUID.as_bytes(),
            LOADER_INDEX_OFFSET,
            0,
            0,
        );
        put_index(
            hive,
            LOADER_INDEX_OFFSET,
            &[(LOADER_ELEMENTS_KEY_OFFSET, b"Elem")],
        );
        put_key(
            hive,
            LOADER_ELEMENTS_KEY_OFFSET,
            b"Elements",
            LOADER_ELEMENTS_INDEX_OFFSET,
            0,
            0,
        );
        put_index(
            hive,
            LOADER_ELEMENTS_INDEX_OFFSET,
            &[(DESCRIPTION_KEY_OFFSET, b"1200")],
        );
        put_key(
            hive,
            DESCRIPTION_KEY_OFFSET,
            b"12000004",
            0,
            1,
            DESCRIPTION_VALUES_OFFSET,
        );
        put_u32(
            hive,
            DESCRIPTION_VALUES_OFFSET,
            DESCRIPTION_VALUE_OFFSET as u32,
        );
        let mut description: Vec<u16> = "Windows 10".encode_utf16().collect();
        description.push(0);
        put_value(
            hive,
            DESCRIPTION_VALUE_OFFSET,
            b"Element",
            REG_SZ,
            DESCRIPTION_DATA_OFFSET,
            description.len() * std::mem::size_of::<u16>(),
        );
        put_utf16(hive, DESCRIPTION_DATA_OFFSET, &description);

        bcd
    }

    #[test]
    fn test_bad_offset_within_bounds() {
        assert!(!bad_offset(0, 10, 100));
        assert!(!bad_offset(50, 10, 100));
    }

    #[test]
    fn test_bad_offset_out_of_bounds() {
        assert!(!bad_offset(90, 10, 100));
        assert!(bad_offset(91, 10, 100));
        assert!(!bad_offset(0, 100, 100));
        assert!(bad_offset(u64::MAX, 1, u64::MAX));
    }

    #[test]
    fn test_bad_struct_within_bounds() {
        assert!(!bad_struct(0, 40, 100));
    }

    #[test]
    fn test_bad_struct_out_of_bounds() {
        assert!(bad_struct(90, 40, 100));
    }

    #[test]
    fn test_strncaseeq_matching() {
        assert!(strncaseeq(b"Hello", b"hello", 5));
        assert!(strncaseeq(b"ABC", b"abc", 3));
    }

    #[test]
    fn test_strncaseeq_not_matching() {
        assert!(!strncaseeq(b"Hello", b"World", 5));
    }

    #[test]
    fn test_is_valid_guid_char() {
        assert!(is_valid_guid_char(b'-' as u16));
        assert!(is_valid_guid_char(b'{' as u16));
        assert!(is_valid_guid_char(b'}' as u16));
        assert!(is_valid_guid_char(b'0' as u16));
        assert!(is_valid_guid_char(b'9' as u16));
        assert!(is_valid_guid_char(b'a' as u16));
        assert!(is_valid_guid_char(b'F' as u16));
        assert!(!is_valid_guid_char(b'g' as u16));
        assert!(!is_valid_guid_char(b' ' as u16));
    }

    #[test]
    fn test_parse_key_path() {
        let path = b"\0Objects\0";
        let components = parse_key_path(path);
        assert_eq!(components, vec![b"Objects".as_slice()]);
    }

    #[test]
    fn test_parse_key_path_multiple() {
        let path = b"\0First\0Second\0Third\0\0";
        let components = parse_key_path(path);
        assert_eq!(
            components,
            vec![
                b"First".as_slice(),
                b"Second".as_slice(),
                b"Third".as_slice()
            ]
        );
    }

    #[test]
    fn test_validate_base_block_too_short() {
        let data = [0u8; 100];
        assert_eq!(validate_base_block(&data), Err(BcdError::BufferTooShort));
    }

    #[test]
    fn test_validate_base_block_bad_sig() {
        let mut data = [0u8; BASE_BLOCK_SIZE];
        // Wrong signature
        data[0..4].copy_from_slice(b"XXXX");
        // Set matching seqnums
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(validate_base_block(&data), Err(BcdError::InvalidBaseBlock));
    }

    #[test]
    fn test_validate_base_block_version_check() {
        let mut data = [0u8; BASE_BLOCK_SIZE];
        data[0..4].copy_from_slice(&SIG_BASE_BLOCK.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        // version_major=2 at offset 20
        data[20..24].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            validate_base_block(&data),
            Err(BcdError::UnsupportedVersion)
        );
    }

    #[test]
    fn test_error_display() {
        assert!(!BcdError::BufferTooShort.to_string().is_empty());
        assert!(!BcdError::MultiBoot.to_string().is_empty());
        assert!(!BcdError::InvalidGuid.to_string().is_empty());
    }

    #[test]
    fn title_traversal_returns_the_single_loader_description() {
        assert_eq!(
            get_bcd_title(&sample_bcd()).map(|title| bcd_title_to_string_lossy(&title)),
            Ok("Windows 10".to_string())
        );
    }

    #[test]
    fn title_traversal_reports_multiboot_display_order() {
        let mut bcd = sample_bcd();
        let hive = &mut bcd[HIVE_CELL_OFFSET..];
        put_u32(hive, DISPLAYORDER_VALUE_OFFSET + 12, REG_SZ);
        assert_eq!(get_bcd_title(&bcd), Err(BcdError::MultiBoot));
    }

    #[test]
    fn title_traversal_rejects_invalid_guid_data() {
        let mut bcd = sample_bcd();
        let hive = &mut bcd[HIVE_CELL_OFFSET..];
        put_u16(hive, DISPLAYORDER_DATA_OFFSET, b'g' as u16);
        assert_eq!(get_bcd_title(&bcd), Err(BcdError::InvalidGuid));

        // Values whose low byte is an ASCII digit must not be accepted as a
        // GUID character. The C switch compares the full char16_t value.
        let mut bcd = sample_bcd();
        let hive = &mut bcd[HIVE_CELL_OFFSET..];
        put_u16(hive, DISPLAYORDER_DATA_OFFSET, 0x0130);
        assert_eq!(get_bcd_title(&bcd), Err(BcdError::InvalidGuid));
    }

    #[test]
    fn title_traversal_rejects_malformed_description() {
        let mut bcd = sample_bcd();
        let hive = &mut bcd[HIVE_CELL_OFFSET..];
        put_u32(hive, DESCRIPTION_VALUE_OFFSET + 12, REG_MULTI_SZ);
        assert_eq!(get_bcd_title(&bcd), Err(BcdError::UnexpectedDataType));

        let mut bcd = sample_bcd();
        let hive = &mut bcd[HIVE_CELL_OFFSET..];
        put_u32(hive, DESCRIPTION_VALUE_OFFSET + 4, 1);
        assert_eq!(get_bcd_title(&bcd), Err(BcdError::InvalidDataSize));
    }

    #[test]
    fn title_traversal_preserves_empty_and_non_unicode_utf16() {
        let mut bcd = sample_bcd();
        let hive = &mut bcd[HIVE_CELL_OFFSET..];
        put_u32(hive, DESCRIPTION_VALUE_OFFSET + 4, 2);
        put_u16(hive, DESCRIPTION_DATA_OFFSET, 0);
        assert_eq!(get_bcd_title(&bcd), Ok(vec![0]));

        let mut bcd = sample_bcd();
        let hive = &mut bcd[HIVE_CELL_OFFSET..];
        put_u16(hive, DESCRIPTION_DATA_OFFSET, 0xd800);
        let title = get_bcd_title(&bcd).unwrap();
        assert_eq!(title[0], 0xd800);
        assert_eq!(title.last(), Some(&0));
        assert_eq!(bcd_title_to_string_lossy(&title), "\u{fffd}indows 10");
    }

    #[test]
    fn malformed_same_hint_candidate_does_not_hide_valid_key() {
        let mut bcd = sample_bcd();
        let hive = &mut bcd[HIVE_CELL_OFFSET..];
        put_index(
            hive,
            BOOTMGR_ELEMENTS_INDEX_OFFSET,
            &[(2390, b"2400"), (DISPLAYORDER_KEY_OFFSET, b"2400")],
        );

        assert_eq!(
            get_bcd_title(&bcd).map(|title| bcd_title_to_string_lossy(&title)),
            Ok("Windows 10".to_string())
        );
    }

    #[test]
    fn alignment_checks_include_the_input_slice_base_address() {
        let bcd = sample_bcd();
        let mut unaligned = Vec::with_capacity(bcd.len() + 1);
        unaligned.push(0);
        unaligned.extend_from_slice(&bcd);

        // The key-value list is offset 900, so a one-byte-shifted input is
        // not u32 aligned. The C parser rejects this before casting it.
        assert_eq!(get_bcd_title(&unaligned[1..]), Err(BcdError::BadAlignment));
    }
}
