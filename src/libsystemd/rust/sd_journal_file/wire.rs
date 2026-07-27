// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/journal-file.c, src/libsystemd/sd-journal/journal-def.h
//

use crate::id128_util::SdId128;
use crate::sd_journal_lookup3::jenkins_hashlittle2;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use systemd_basic_rs::siphash24::siphash24;

pub const DEFAULT_DATA_HASH_TABLE_SIZE: u32 = 2047;
pub const DEFAULT_FIELD_HASH_TABLE_SIZE: u32 = 1023;
pub const DEFAULT_COMPRESS_THRESHOLD: u32 = 512;
pub const MIN_COMPRESS_THRESHOLD: u32 = 8;
pub const JOURNAL_FILE_SIZE_MIN: u64 = 512 * 1024;
pub const JOURNAL_COMPACT_SIZE_MAX: u64 = u32::MAX as u64;
pub const MAX_USE_LOWER: u64 = 1024 * 1024;
pub const MAX_USE_UPPER: u64 = 4 * 1024 * 1024 * 1024;
pub const MIN_USE_LOW: u64 = 1024 * 1024;
pub const MIN_USE_HIGH: u64 = 16 * 1024 * 1024;
pub const MAX_SIZE_UPPER: u64 = 128 * 1024 * 1024;
pub const KEEP_FREE_UPPER: u64 = 4 * 1024 * 1024 * 1024;
pub const DEFAULT_KEEP_FREE: u64 = 1024 * 1024;
pub const DEFAULT_N_MAX_FILES: u64 = 100;
pub const FILE_SIZE_INCREASE: u64 = 8 * 1024 * 1024;
pub const LAST_STAT_REFRESH_USEC: u64 = 5_000_000;
pub const HASH_CHAIN_DEPTH_MAX: u32 = 100;
pub const HEADER_SIGNATURE: [u8; 8] = *b"LPKSHHRH";

pub const STATE_OFFLINE: u8 = 0;
pub const STATE_ONLINE: u8 = 1;
pub const STATE_ARCHIVED: u8 = 2;
pub const STATE_MAX: u8 = 3;

pub const OBJECT_UNUSED: u8 = 0;
pub const OBJECT_DATA: u8 = 1;
pub const OBJECT_FIELD: u8 = 2;
pub const OBJECT_ENTRY: u8 = 3;
pub const OBJECT_DATA_HASH_TABLE: u8 = 4;
pub const OBJECT_FIELD_HASH_TABLE: u8 = 5;
pub const OBJECT_ENTRY_ARRAY: u8 = 6;
pub const OBJECT_TAG: u8 = 7;
pub const OBJECT_COMPRESSED_XZ: u8 = 1 << 0;
pub const OBJECT_COMPRESSED_LZ4: u8 = 1 << 1;
pub const OBJECT_COMPRESSED_ZSTD: u8 = 1 << 2;
pub const OBJECT_COMPRESSED_MASK: u8 =
    OBJECT_COMPRESSED_XZ | OBJECT_COMPRESSED_LZ4 | OBJECT_COMPRESSED_ZSTD;
pub const HEADER_COMPATIBLE_SEALED: u32 = 1 << 0;
pub const HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID: u32 = 1 << 1;
pub const HEADER_COMPATIBLE_SEALED_CONTINUOUS: u32 = 1 << 2;
pub const HEADER_COMPATIBLE_SUPPORTED: u32 = HEADER_COMPATIBLE_SEALED
    | HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID
    | HEADER_COMPATIBLE_SEALED_CONTINUOUS;
pub const HEADER_INCOMPATIBLE_COMPRESSED_XZ: u32 = 1 << 0;
pub const HEADER_INCOMPATIBLE_COMPRESSED_LZ4: u32 = 1 << 1;
pub const HEADER_INCOMPATIBLE_KEYED_HASH: u32 = 1 << 2;
pub const HEADER_INCOMPATIBLE_COMPRESSED_ZSTD: u32 = 1 << 3;
pub const HEADER_INCOMPATIBLE_COMPACT: u32 = 1 << 4;
pub const HEADER_INCOMPATIBLE_SUPPORTED: u32 =
    HEADER_INCOMPATIBLE_KEYED_HASH | HEADER_INCOMPATIBLE_COMPACT;
pub const DATA_OBJECT_STATIC_SIZE: u64 = 64;
pub const COMPACT_DATA_OBJECT_STATIC_SIZE: u64 = 72;
pub const FIELD_OBJECT_STATIC_SIZE: u64 = 40;
pub const ENTRY_OBJECT_STATIC_SIZE: u64 = 64;
pub const REGULAR_ENTRY_ITEM_SIZE: u64 = 16;
pub const COMPACT_ENTRY_ITEM_SIZE: u64 = 4;
pub const DATA_NEXT_HASH_OFFSET_OFFSET: u64 = 24;
pub const DATA_NEXT_FIELD_OFFSET_OFFSET: u64 = 32;
pub const DATA_ENTRY_OFFSET_OFFSET: u64 = 40;
pub const DATA_ENTRY_ARRAY_OFFSET_OFFSET: u64 = 48;
pub const DATA_N_ENTRIES_OFFSET_OFFSET: u64 = 56;
pub const COMPACT_DATA_TAIL_ENTRY_ARRAY_OFFSET_OFFSET: u64 = 64;
pub const COMPACT_DATA_TAIL_ENTRY_ARRAY_N_ENTRIES_OFFSET_OFFSET: u64 = 68;
pub const FIELD_NEXT_HASH_OFFSET_OFFSET: u64 = 24;
pub const FIELD_HEAD_DATA_OFFSET_OFFSET: u64 = 32;
pub const ENTRY_ARRAY_OBJECT_STATIC_SIZE: u64 = 24;
pub const ENTRY_ARRAY_NEXT_OFFSET_OFFSET: u64 = 16;
pub const ENTRY_ARRAY_ITEMS_OFFSET: u64 = 24;

#[inline]
pub const fn align64(value: u64) -> u64 {
    (value + 7) & !7
}

#[inline]
pub const fn valid64(value: u64) -> bool {
    value & 7 == 0
}

pub fn jenkins_hash64(data: &[u8]) -> u64 {
    let (a, b) = jenkins_hashlittle2(data, 0, 0);
    ((a as u64) << 32) | (b as u64)
}

pub fn journal_hash_data(header: &Header, data: &[u8]) -> io::Result<u64> {
    if header.incompatible_flags & HEADER_INCOMPATIBLE_KEYED_HASH != 0 {
        return Ok(siphash24(data, &header.file_id.0));
    }

    Ok(jenkins_hash64(data))
}

pub(crate) fn valid_realtime(value: u64) -> bool {
    value > 0 && value < (1u64 << 55)
}

pub(crate) fn valid_monotonic(value: u64) -> bool {
    value < (1u64 << 55)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectHeader {
    pub type_: u8,
    pub flags: u8,
    pub reserved: [u8; 6],
    pub size: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashItem {
    pub head_hash_offset: u64,
    pub tail_hash_offset: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub signature: [u8; 8],
    pub compatible_flags: u32,
    pub incompatible_flags: u32,
    pub state: u8,
    pub reserved: [u8; 7],
    pub file_id: SdId128,
    pub machine_id: SdId128,
    pub tail_entry_boot_id: SdId128,
    pub seqnum_id: SdId128,
    pub header_size: u64,
    pub arena_size: u64,
    pub data_hash_table_offset: u64,
    pub data_hash_table_size: u64,
    pub field_hash_table_offset: u64,
    pub field_hash_table_size: u64,
    pub tail_object_offset: u64,
    pub n_objects: u64,
    pub n_entries: u64,
    pub tail_entry_seqnum: u64,
    pub head_entry_seqnum: u64,
    pub entry_array_offset: u64,
    pub head_entry_realtime: u64,
    pub tail_entry_realtime: u64,
    pub tail_entry_monotonic: u64,
    pub n_data: u64,
    pub n_fields: u64,
    pub n_tags: u64,
    pub n_entry_arrays: u64,
    pub data_hash_chain_depth: u64,
    pub field_hash_chain_depth: u64,
    pub tail_entry_array_offset: u32,
    pub tail_entry_array_n_entries: u32,
    pub tail_entry_offset: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalObject {
    pub header: ObjectHeader,
    pub payload_len: u64,
}

impl JournalObject {
    pub fn hash_table_items(&self) -> u64 {
        self.payload_len / std::mem::size_of::<HashItem>() as u64
    }

    pub fn entry_items(&self, item_size: u64) -> u64 {
        self.payload_len / item_size
    }

    pub fn tail_end(&self, offset: u64) -> Option<u64> {
        offset.checked_add(align64(self.header.size))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmptyJournalFileLayout {
    pub header: Header,
    pub bytes: Vec<u8>,
    pub data_hash_items: u64,
    pub field_hash_items: u64,
    pub data_hash_object_offset: u64,
    pub field_hash_object_offset: u64,
}

#[derive(Debug)]
pub struct JournalFileOnDisk {
    pub path: PathBuf,
    pub file: File,
    pub header: Header,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalEntryItem {
    pub object_offset: u64,
    pub hash: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalAppendResult {
    pub entry_offset: u64,
    pub seqnum: u64,
    pub xor_hash: u64,
    pub data_offsets: Vec<u64>,
    pub field_offsets: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalRecord {
    pub seqnum: u64,
    pub realtime: u64,
    pub monotonic: u64,
    pub boot_id: SdId128,
    pub xor_hash: u64,
    pub fields: Vec<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct JournalVerifyStats {
    pub n_objects: u64,
    pub n_entries: u64,
    pub n_data: u64,
    pub n_fields: u64,
    pub n_tags: u64,
    pub n_entry_arrays: u64,
    pub n_data_hash_tables: u64,
    pub n_field_hash_tables: u64,
}

impl ObjectHeader {
    pub const SERIALIZED_LEN: usize = 16;

    pub fn encode_le(&self, out: &mut Vec<u8>) {
        out.push(self.type_);
        out.push(self.flags);
        out.extend_from_slice(&self.reserved);
        out.extend_from_slice(&self.size.to_le_bytes());
    }
}

impl HashItem {
    pub const SERIALIZED_LEN: usize = 16;

    pub fn encode_le(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.head_hash_offset.to_le_bytes());
        out.extend_from_slice(&self.tail_hash_offset.to_le_bytes());
    }
}

impl Header {
    pub const SERIALIZED_LEN: usize = 272;

    pub fn encode_le_bytes(&self) -> [u8; Self::SERIALIZED_LEN] {
        let mut out = Vec::with_capacity(Self::SERIALIZED_LEN);
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.compatible_flags.to_le_bytes());
        out.extend_from_slice(&self.incompatible_flags.to_le_bytes());
        out.push(self.state);
        out.extend_from_slice(&self.reserved);
        out.extend_from_slice(&self.file_id.0);
        out.extend_from_slice(&self.machine_id.0);
        out.extend_from_slice(&self.tail_entry_boot_id.0);
        out.extend_from_slice(&self.seqnum_id.0);
        out.extend_from_slice(&self.header_size.to_le_bytes());
        out.extend_from_slice(&self.arena_size.to_le_bytes());
        out.extend_from_slice(&self.data_hash_table_offset.to_le_bytes());
        out.extend_from_slice(&self.data_hash_table_size.to_le_bytes());
        out.extend_from_slice(&self.field_hash_table_offset.to_le_bytes());
        out.extend_from_slice(&self.field_hash_table_size.to_le_bytes());
        out.extend_from_slice(&self.tail_object_offset.to_le_bytes());
        out.extend_from_slice(&self.n_objects.to_le_bytes());
        out.extend_from_slice(&self.n_entries.to_le_bytes());
        out.extend_from_slice(&self.tail_entry_seqnum.to_le_bytes());
        out.extend_from_slice(&self.head_entry_seqnum.to_le_bytes());
        out.extend_from_slice(&self.entry_array_offset.to_le_bytes());
        out.extend_from_slice(&self.head_entry_realtime.to_le_bytes());
        out.extend_from_slice(&self.tail_entry_realtime.to_le_bytes());
        out.extend_from_slice(&self.tail_entry_monotonic.to_le_bytes());
        out.extend_from_slice(&self.n_data.to_le_bytes());
        out.extend_from_slice(&self.n_fields.to_le_bytes());
        out.extend_from_slice(&self.n_tags.to_le_bytes());
        out.extend_from_slice(&self.n_entry_arrays.to_le_bytes());
        out.extend_from_slice(&self.data_hash_chain_depth.to_le_bytes());
        out.extend_from_slice(&self.field_hash_chain_depth.to_le_bytes());
        out.extend_from_slice(&self.tail_entry_array_offset.to_le_bytes());
        out.extend_from_slice(&self.tail_entry_array_n_entries.to_le_bytes());
        out.extend_from_slice(&self.tail_entry_offset.to_le_bytes());

        out.try_into().expect("header serialization length drift")
    }

    pub fn decode_le_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < Self::SERIALIZED_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated journal header",
            ));
        }

        let mut offset = 0;
        let signature = read_array::<8>(bytes, &mut offset)?;
        let compatible_flags = read_u32_le(bytes, &mut offset)?;
        let incompatible_flags = read_u32_le(bytes, &mut offset)?;
        let state = read_u8(bytes, &mut offset)?;
        let reserved = read_array::<7>(bytes, &mut offset)?;
        let file_id = SdId128(read_array::<16>(bytes, &mut offset)?);
        let machine_id = SdId128(read_array::<16>(bytes, &mut offset)?);
        let tail_entry_boot_id = SdId128(read_array::<16>(bytes, &mut offset)?);
        let seqnum_id = SdId128(read_array::<16>(bytes, &mut offset)?);
        let header_size = read_u64_le(bytes, &mut offset)?;
        let arena_size = read_u64_le(bytes, &mut offset)?;
        let data_hash_table_offset = read_u64_le(bytes, &mut offset)?;
        let data_hash_table_size = read_u64_le(bytes, &mut offset)?;
        let field_hash_table_offset = read_u64_le(bytes, &mut offset)?;
        let field_hash_table_size = read_u64_le(bytes, &mut offset)?;
        let tail_object_offset = read_u64_le(bytes, &mut offset)?;
        let n_objects = read_u64_le(bytes, &mut offset)?;
        let n_entries = read_u64_le(bytes, &mut offset)?;
        let tail_entry_seqnum = read_u64_le(bytes, &mut offset)?;
        let head_entry_seqnum = read_u64_le(bytes, &mut offset)?;
        let entry_array_offset = read_u64_le(bytes, &mut offset)?;
        let head_entry_realtime = read_u64_le(bytes, &mut offset)?;
        let tail_entry_realtime = read_u64_le(bytes, &mut offset)?;
        let tail_entry_monotonic = read_u64_le(bytes, &mut offset)?;
        let n_data = read_u64_le(bytes, &mut offset)?;
        let n_fields = read_u64_le(bytes, &mut offset)?;
        let n_tags = read_u64_le(bytes, &mut offset)?;
        let n_entry_arrays = read_u64_le(bytes, &mut offset)?;
        let data_hash_chain_depth = read_u64_le(bytes, &mut offset)?;
        let field_hash_chain_depth = read_u64_le(bytes, &mut offset)?;
        let tail_entry_array_offset = read_u32_le(bytes, &mut offset)?;
        let tail_entry_array_n_entries = read_u32_le(bytes, &mut offset)?;
        let tail_entry_offset = read_u64_le(bytes, &mut offset)?;

        Ok(Self {
            signature,
            compatible_flags,
            incompatible_flags,
            state,
            reserved,
            file_id,
            machine_id,
            tail_entry_boot_id,
            seqnum_id,
            header_size,
            arena_size,
            data_hash_table_offset,
            data_hash_table_size,
            field_hash_table_offset,
            field_hash_table_size,
            tail_object_offset,
            n_objects,
            n_entries,
            tail_entry_seqnum,
            head_entry_seqnum,
            entry_array_offset,
            head_entry_realtime,
            tail_entry_realtime,
            tail_entry_monotonic,
            n_data,
            n_fields,
            n_tags,
            n_entry_arrays,
            data_hash_chain_depth,
            field_hash_chain_depth,
            tail_entry_array_offset,
            tail_entry_array_n_entries,
            tail_entry_offset,
        })
    }

    pub fn has_valid_signature(&self) -> bool {
        self.signature == HEADER_SIGNATURE
    }
}

pub(crate) fn read_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> io::Result<[u8; N]> {
    let end = offset.saturating_add(N);
    let slice = bytes
        .get(*offset..end)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated journal field"))?;
    *offset = end;
    slice
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "journal header width mismatch"))
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> io::Result<u8> {
    Ok(read_array::<1>(bytes, offset)?[0])
}

pub(crate) fn read_u32_le(bytes: &[u8], offset: &mut usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(read_array::<4>(bytes, offset)?))
}

pub(crate) fn read_u64_le(bytes: &[u8], offset: &mut usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(read_array::<8>(bytes, offset)?))
}

pub fn default_data_hash_table_items(max_size: u64) -> u64 {
    (max_size.saturating_mul(4) / 768 / 3).max(DEFAULT_DATA_HASH_TABLE_SIZE as u64)
}

pub fn hash_table_payload_size(items: u64) -> u64 {
    items.saturating_mul(std::mem::size_of::<HashItem>() as u64)
}

pub fn hash_table_object_size(items: u64) -> u64 {
    std::mem::size_of::<ObjectHeader>() as u64 + hash_table_payload_size(items)
}

pub fn build_empty_journal_file(
    max_size: u64,
    file_id: SdId128,
    machine_id: SdId128,
    seqnum_id: SdId128,
    compatible_flags: u32,
    incompatible_flags: u32,
) -> EmptyJournalFileLayout {
    let header_size = align64(std::mem::size_of::<Header>() as u64);
    let data_hash_items = default_data_hash_table_items(max_size);
    let field_hash_items = DEFAULT_FIELD_HASH_TABLE_SIZE as u64;
    let data_hash_object_offset = header_size;
    let data_hash_object_size = hash_table_object_size(data_hash_items);
    let field_hash_object_offset = data_hash_object_offset + data_hash_object_size;
    let field_hash_object_size = hash_table_object_size(field_hash_items);
    let arena_size = data_hash_object_size + field_hash_object_size;

    let header = Header {
        signature: HEADER_SIGNATURE,
        compatible_flags,
        incompatible_flags,
        state: STATE_OFFLINE,
        reserved: [0; 7],
        file_id,
        machine_id,
        tail_entry_boot_id: SdId128::null(),
        seqnum_id,
        header_size,
        arena_size,
        data_hash_table_offset: data_hash_object_offset
            + std::mem::size_of::<ObjectHeader>() as u64,
        data_hash_table_size: hash_table_payload_size(data_hash_items),
        field_hash_table_offset: field_hash_object_offset
            + std::mem::size_of::<ObjectHeader>() as u64,
        field_hash_table_size: hash_table_payload_size(field_hash_items),
        tail_object_offset: field_hash_object_offset,
        n_objects: 2,
        n_entries: 0,
        tail_entry_seqnum: 0,
        head_entry_seqnum: 0,
        entry_array_offset: 0,
        head_entry_realtime: 0,
        tail_entry_realtime: 0,
        tail_entry_monotonic: 0,
        n_data: 0,
        n_fields: 0,
        n_tags: 0,
        n_entry_arrays: 0,
        data_hash_chain_depth: 0,
        field_hash_chain_depth: 0,
        tail_entry_array_offset: 0,
        tail_entry_array_n_entries: 0,
        tail_entry_offset: 0,
    };

    let mut bytes = Vec::with_capacity((header_size + arena_size) as usize);
    bytes.extend_from_slice(&header.encode_le_bytes());

    let data_header = ObjectHeader {
        type_: OBJECT_DATA_HASH_TABLE,
        flags: 0,
        reserved: [0; 6],
        size: data_hash_object_size,
    };
    data_header.encode_le(&mut bytes);
    for _ in 0..data_hash_items {
        HashItem {
            head_hash_offset: 0,
            tail_hash_offset: 0,
        }
        .encode_le(&mut bytes);
    }

    let field_header = ObjectHeader {
        type_: OBJECT_FIELD_HASH_TABLE,
        flags: 0,
        reserved: [0; 6],
        size: field_hash_object_size,
    };
    field_header.encode_le(&mut bytes);
    for _ in 0..field_hash_items {
        HashItem {
            head_hash_offset: 0,
            tail_hash_offset: 0,
        }
        .encode_le(&mut bytes);
    }

    EmptyJournalFileLayout {
        header,
        bytes,
        data_hash_items,
        field_hash_items,
        data_hash_object_offset,
        field_hash_object_offset,
    }
}

pub fn read_journal_header(file: &mut File) -> io::Result<Header> {
    let mut bytes = [0u8; Header::SERIALIZED_LEN];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut bytes)?;
    Header::decode_le_bytes(&bytes)
}

pub(crate) fn read_u64_at(file: &mut File, offset: u64) -> io::Result<u64> {
    let mut bytes = [0u8; 8];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

pub(crate) fn write_u64_at(file: &mut File, offset: u64, value: u64) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&value.to_le_bytes())
}

pub(crate) fn read_u32_at(file: &mut File, offset: u64) -> io::Result<u32> {
    let mut bytes = [0u8; 4];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

pub(crate) fn write_u32_at(file: &mut File, offset: u64, value: u32) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&value.to_le_bytes())
}

pub fn write_journal_header(file: &mut File, header: &Header) -> io::Result<()> {
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header.encode_le_bytes())
}

pub fn next_object_offset(header: &Header) -> io::Result<u64> {
    header
        .header_size
        .checked_add(header.arena_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "journal arena size overflow"))
}

pub fn append_raw_object(
    file: &mut File,
    header: &mut Header,
    object_type: u8,
    flags: u8,
    payload: &[u8],
) -> io::Result<u64> {
    let object_offset = next_object_offset(header)?;
    let payload_len = u64::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "payload too large"))?;
    let object_size = (ObjectHeader::SERIALIZED_LEN as u64)
        .checked_add(payload_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "object size overflow"))?;
    let aligned_size = object_size
        .checked_add(7)
        .map(|size| size & !7)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "aligned object size overflow")
        })?;
    let aligned_len = usize::try_from(aligned_size)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "object does not fit memory"))?;

    let object_header = ObjectHeader {
        type_: object_type,
        flags,
        reserved: [0; 6],
        size: object_size,
    };

    let mut bytes = Vec::with_capacity(aligned_len);
    object_header.encode_le(&mut bytes);
    bytes.extend_from_slice(payload);
    bytes.resize(aligned_len, 0);

    file.seek(SeekFrom::Start(object_offset))?;
    file.write_all(&bytes)?;

    header.tail_object_offset = object_offset;
    header.n_objects = header.n_objects.checked_add(1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "journal object count overflow")
    })?;
    header.arena_size = object_offset
        .checked_add(aligned_size)
        .and_then(|end| end.checked_sub(header.header_size))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "journal arena update overflow")
        })?;
    write_journal_header(file, header)?;

    Ok(object_offset)
}

pub fn journal_uses_compact(header: &Header) -> bool {
    header.incompatible_flags & HEADER_INCOMPATIBLE_COMPACT != 0
}

pub fn entry_array_item_size(header: &Header) -> u64 {
    if journal_uses_compact(header) {
        COMPACT_ENTRY_ITEM_SIZE
    } else {
        8
    }
}

pub(crate) fn read_object_size(file: &mut File, object_offset: u64) -> io::Result<u64> {
    read_u64_at(file, object_offset + 8)
}

pub(crate) fn read_object_header_at(
    file: &mut File,
    object_offset: u64,
) -> io::Result<ObjectHeader> {
    let mut bytes = [0u8; ObjectHeader::SERIALIZED_LEN];
    file.seek(SeekFrom::Start(object_offset))?;
    file.read_exact(&mut bytes)?;
    Ok(ObjectHeader {
        type_: bytes[0],
        flags: bytes[1],
        reserved: bytes[2..8].try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "object reserved width mismatch")
        })?,
        size: u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "object size width mismatch")
        })?),
    })
}

pub(crate) fn read_object_payload_bytes(
    file: &mut File,
    object_offset: u64,
    payload_offset_within_object: u64,
) -> io::Result<Vec<u8>> {
    let object_size = read_object_size(file, object_offset)?;
    if object_size < payload_offset_within_object {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "object payload offset exceeds object size",
        ));
    }
    let payload_len = usize::try_from(object_size - payload_offset_within_object)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "object payload is too large"))?;
    let mut payload = vec![0u8; payload_len];
    file.seek(SeekFrom::Start(
        object_offset
            .checked_add(payload_offset_within_object)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "payload seek overflow"))?,
    ))?;
    file.read_exact(&mut payload)?;
    Ok(payload)
}
