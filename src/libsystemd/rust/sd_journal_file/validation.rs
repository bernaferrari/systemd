// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/journal-file.c, src/libsystemd/sd-journal/journal-def.h
//

use super::wire::{
    entry_array_item_size, journal_hash_data, journal_uses_compact, read_object_payload_bytes,
    read_u32_le, read_u64_le, valid_monotonic, valid_realtime, HashItem, Header, ObjectHeader,
    COMPACT_DATA_OBJECT_STATIC_SIZE, COMPACT_ENTRY_ITEM_SIZE, DATA_OBJECT_STATIC_SIZE,
    ENTRY_ARRAY_OBJECT_STATIC_SIZE, ENTRY_OBJECT_STATIC_SIZE, FIELD_OBJECT_STATIC_SIZE,
    HASH_CHAIN_DEPTH_MAX, HEADER_COMPATIBLE_SEALED, HEADER_COMPATIBLE_SEALED_CONTINUOUS,
    HEADER_COMPATIBLE_SUPPORTED, HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
    HEADER_INCOMPATIBLE_SUPPORTED, OBJECT_COMPRESSED_MASK, OBJECT_DATA, OBJECT_DATA_HASH_TABLE,
    OBJECT_ENTRY, OBJECT_ENTRY_ARRAY, OBJECT_FIELD, OBJECT_FIELD_HASH_TABLE, OBJECT_TAG,
    REGULAR_ENTRY_ITEM_SIZE, STATE_MAX, STATE_OFFLINE,
};
use std::fs::File;
use std::io;

fn offset_is_valid(offset: u64, header_size: u64, tail_object_offset: u64) -> bool {
    if offset == 0 {
        return true;
    }

    valid_aligned_offset(offset) && offset >= header_size && offset <= tail_object_offset
}

fn hash_table_is_valid(
    offset: u64,
    size: u64,
    header_size: u64,
    arena_size: u64,
    tail_object_offset: u64,
) -> bool {
    if (offset == 0) != (size == 0) {
        return false;
    }
    if offset == 0 {
        return true;
    }
    if size % HashItem::SERIALIZED_LEN as u64 != 0 {
        return false;
    }
    if offset <= std::mem::size_of::<ObjectHeader>() as u64 {
        return false;
    }
    let object_offset = offset - std::mem::size_of::<ObjectHeader>() as u64;
    if !offset_is_valid(object_offset, header_size, tail_object_offset) {
        return false;
    }
    if object_offset > header_size.saturating_add(arena_size) {
        return false;
    }
    size <= header_size
        .saturating_add(arena_size)
        .saturating_sub(object_offset)
}

pub(crate) fn minimum_object_size_for_type(header: &Header, object_type: u8) -> Option<u64> {
    match object_type {
        OBJECT_DATA => Some(if journal_uses_compact(header) {
            COMPACT_DATA_OBJECT_STATIC_SIZE
        } else {
            DATA_OBJECT_STATIC_SIZE
        }),
        OBJECT_FIELD => Some(FIELD_OBJECT_STATIC_SIZE),
        OBJECT_ENTRY => Some(ENTRY_OBJECT_STATIC_SIZE),
        OBJECT_DATA_HASH_TABLE | OBJECT_FIELD_HASH_TABLE => {
            Some(ObjectHeader::SERIALIZED_LEN as u64)
        }
        OBJECT_ENTRY_ARRAY => Some(ENTRY_ARRAY_OBJECT_STATIC_SIZE),
        OBJECT_TAG => Some(ObjectHeader::SERIALIZED_LEN as u64),
        _ => None,
    }
}

fn valid_epoch(value: u64) -> bool {
    value < (1u64 << 55)
}

fn valid_aligned_offset(value: u64) -> bool {
    value & 7 == 0
}

fn verify_hash_table_object_identity(
    header: &Header,
    offset: u64,
    object_header: &ObjectHeader,
) -> io::Result<()> {
    let expected = match object_header.type_ {
        OBJECT_DATA_HASH_TABLE => {
            Some((header.data_hash_table_offset, header.data_hash_table_size))
        }
        OBJECT_FIELD_HASH_TABLE => {
            Some((header.field_hash_table_offset, header.field_hash_table_size))
        }
        _ => None,
    };
    let Some((table_offset, table_size)) = expected else {
        return Ok(());
    };

    let expected_object_offset = table_offset
        .checked_sub(std::mem::size_of::<ObjectHeader>() as u64)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "hash table offset underflows object header",
            )
        })?;
    if offset != expected_object_offset {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hash table object offset does not match header",
        ));
    }

    let payload_size = object_header
        .size
        .checked_sub(std::mem::size_of::<ObjectHeader>() as u64)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "hash table object smaller than header",
            )
        })?;
    if payload_size != table_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hash table object size does not match header",
        ));
    }

    Ok(())
}

pub(crate) fn verify_object_shallow(
    file: &mut File,
    header: &Header,
    offset: u64,
    object_header: &ObjectHeader,
) -> io::Result<()> {
    if object_header.flags & OBJECT_COMPRESSED_MASK != 0 && object_header.type_ != OBJECT_DATA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed object must be a data object",
        ));
    }

    match object_header.type_ {
        OBJECT_DATA => {
            let static_size = if journal_uses_compact(header) {
                COMPACT_DATA_OBJECT_STATIC_SIZE
            } else {
                DATA_OBJECT_STATIC_SIZE
            };
            if object_header.size <= static_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "data object is too small for payload",
                ));
            }
            let payload =
                read_object_payload_bytes(file, offset, ObjectHeader::SERIALIZED_LEN as u64)?;
            let payload_field_offset = (static_size - ObjectHeader::SERIALIZED_LEN as u64) as usize;
            let mut cursor = 0;
            let stored_hash = read_u64_le(&payload, &mut cursor)?;
            let next_hash_offset = read_u64_le(&payload, &mut cursor)?;
            let next_field_offset = read_u64_le(&payload, &mut cursor)?;
            let entry_offset = read_u64_le(&payload, &mut cursor)?;
            let entry_array_offset = read_u64_le(&payload, &mut cursor)?;
            let n_entries = read_u64_le(&payload, &mut cursor)?;
            if (entry_offset == 0) != (n_entries == 0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "data object entry linkage is inconsistent",
                ));
            }
            for candidate in [
                next_hash_offset,
                next_field_offset,
                entry_offset,
                entry_array_offset,
            ] {
                if !valid_aligned_offset(candidate) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "data object contains an unaligned offset",
                    ));
                }
            }
            let expected_hash = journal_hash_data(header, &payload[payload_field_offset..])?;
            if stored_hash != expected_hash {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "data object hash does not match payload",
                ));
            }
        }
        OBJECT_FIELD => {
            if object_header.size <= FIELD_OBJECT_STATIC_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "field object is too small for payload",
                ));
            }
            let payload =
                read_object_payload_bytes(file, offset, ObjectHeader::SERIALIZED_LEN as u64)?;
            let mut cursor = 0;
            let stored_hash = read_u64_le(&payload, &mut cursor)?;
            let next_hash_offset = read_u64_le(&payload, &mut cursor)?;
            let head_data_offset = read_u64_le(&payload, &mut cursor)?;
            for candidate in [next_hash_offset, head_data_offset] {
                if !valid_aligned_offset(candidate) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "field object contains an unaligned offset",
                    ));
                }
            }
            let expected_hash = journal_hash_data(header, &payload[24..])?;
            if stored_hash != expected_hash {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "field object hash does not match payload",
                ));
            }
        }
        OBJECT_ENTRY => {
            let item_size = if journal_uses_compact(header) {
                COMPACT_ENTRY_ITEM_SIZE
            } else {
                REGULAR_ENTRY_ITEM_SIZE
            };
            if object_header.size <= ENTRY_OBJECT_STATIC_SIZE
                || (object_header.size - ENTRY_OBJECT_STATIC_SIZE) % item_size != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "entry object has an invalid item layout",
                ));
            }
            let item_count = (object_header.size - ENTRY_OBJECT_STATIC_SIZE) / item_size;
            if item_count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "entry object must contain at least one item",
                ));
            }
            let payload =
                read_object_payload_bytes(file, offset, ObjectHeader::SERIALIZED_LEN as u64)?;
            let mut cursor = 0;
            let seqnum = read_u64_le(&payload, &mut cursor)?;
            let realtime = read_u64_le(&payload, &mut cursor)?;
            let monotonic = read_u64_le(&payload, &mut cursor)?;
            let boot_id_is_null = payload[24..40].iter().all(|byte| *byte == 0);
            if seqnum == 0
                || !valid_realtime(realtime)
                || !valid_monotonic(monotonic)
                || boot_id_is_null
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "entry object contains invalid sequence, timestamps, or boot ID",
                ));
            }
            let items = &payload
                [(ENTRY_OBJECT_STATIC_SIZE - ObjectHeader::SERIALIZED_LEN as u64) as usize..];
            if journal_uses_compact(header) {
                for chunk in items.chunks_exact(COMPACT_ENTRY_ITEM_SIZE as usize) {
                    let object_offset = read_u32_le(chunk, &mut 0)? as u64;
                    if object_offset == 0 || !valid_aligned_offset(object_offset) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "entry object references an invalid data offset",
                        ));
                    }
                }
            } else {
                for chunk in items.chunks_exact(REGULAR_ENTRY_ITEM_SIZE as usize) {
                    let object_offset = read_u64_le(chunk, &mut 0)?;
                    if object_offset == 0 || !valid_aligned_offset(object_offset) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "entry object references an invalid data offset",
                        ));
                    }
                }
            }
        }
        OBJECT_DATA_HASH_TABLE | OBJECT_FIELD_HASH_TABLE => {
            verify_hash_table_object_identity(header, offset, object_header)?;
            let payload =
                read_object_payload_bytes(file, offset, ObjectHeader::SERIALIZED_LEN as u64)?;
            let mut chunks = payload.chunks_exact(HashItem::SERIALIZED_LEN);
            if chunks.len() == 0 || !chunks.remainder().is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "hash table payload is malformed",
                ));
            }
            for chunk in &mut chunks {
                let mut cursor = 0;
                let head_hash_offset = read_u64_le(chunk, &mut cursor)?;
                let tail_hash_offset = read_u64_le(chunk, &mut cursor)?;
                if !valid_aligned_offset(head_hash_offset)
                    || !valid_aligned_offset(tail_hash_offset)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "hash table contains an unaligned bucket offset",
                    ));
                }
                if (head_hash_offset == 0) != (tail_hash_offset == 0) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "hash table bucket head/tail linkage is inconsistent",
                    ));
                }
            }
        }
        OBJECT_ENTRY_ARRAY => {
            let item_size = entry_array_item_size(header);
            if object_header.size <= ENTRY_ARRAY_OBJECT_STATIC_SIZE
                || (object_header.size - ENTRY_ARRAY_OBJECT_STATIC_SIZE) % item_size != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "entry array object has an invalid layout",
                ));
            }
            let payload =
                read_object_payload_bytes(file, offset, ObjectHeader::SERIALIZED_LEN as u64)?;
            let next_entry_array_offset = read_u64_le(&payload, &mut 0)?;
            if !valid_aligned_offset(next_entry_array_offset)
                || (next_entry_array_offset != 0 && next_entry_array_offset <= offset)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "entry array next pointer is invalid",
                ));
            }
            let items = &payload[8..];
            if journal_uses_compact(header) {
                for chunk in items.chunks_exact(COMPACT_ENTRY_ITEM_SIZE as usize) {
                    let entry_offset = read_u32_le(chunk, &mut 0)? as u64;
                    if entry_offset != 0 && !valid_aligned_offset(entry_offset) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "entry array contains an invalid compact entry offset",
                        ));
                    }
                }
            } else {
                for chunk in items.chunks_exact(8) {
                    let entry_offset = read_u64_le(chunk, &mut 0)?;
                    if entry_offset != 0 && !valid_aligned_offset(entry_offset) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "entry array contains an invalid entry offset",
                        ));
                    }
                }
            }
        }
        OBJECT_TAG => {
            if object_header.size != ObjectHeader::SERIALIZED_LEN as u64 + 8 + 8 + 32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tag object has an unexpected size",
                ));
            }
            let payload =
                read_object_payload_bytes(file, offset, ObjectHeader::SERIALIZED_LEN as u64)?;
            let epoch = read_u64_le(&payload, &mut 8)?;
            if !valid_epoch(epoch) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tag object epoch is invalid",
                ));
            }
        }
        _ => {}
    }

    Ok(())
}

pub fn validate_journal_header(header: &Header, file_len: u64, writable: bool) -> io::Result<()> {
    if !header.has_valid_signature() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid journal header signature",
        ));
    }
    if writable && header.compatible_flags & !HEADER_COMPATIBLE_SUPPORTED != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal uses unknown compatible flags",
        ));
    }
    if header.incompatible_flags & !HEADER_INCOMPATIBLE_SUPPORTED != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal uses unsupported incompatible flags",
        ));
    }
    if header.compatible_flags & HEADER_COMPATIBLE_SEALED_CONTINUOUS != 0
        && header.compatible_flags & HEADER_COMPATIBLE_SEALED == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "continuous sealing flag requires sealing",
        ));
    }
    if header.state >= STATE_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal state is invalid",
        ));
    }
    if header.reserved.iter().any(|byte| *byte != 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal reserved header bytes must be zero",
        ));
    }

    let header_size = header.header_size;
    if header_size < Header::SERIALIZED_LEN as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal header smaller than minimum header size",
        ));
    }
    if writable && header_size != std::mem::size_of::<Header>() as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "writable journal header does not match current header size",
        ));
    }
    if writable && header.compatible_flags & HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "writable journal lacks tail-entry boot-ID semantics",
        ));
    }
    if writable && header.compatible_flags & HEADER_COMPATIBLE_SEALED != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sealed journals are read-only until authentication is implemented",
        ));
    }
    if writable && header.state != STATE_OFFLINE {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "writable journal is not offline",
        ));
    }

    let arena_end = header
        .header_size
        .checked_add(header.arena_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "journal arena size overflow"))?;
    if arena_end > file_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal arena exceeds file length",
        ));
    }

    let tail_object_offset = header.tail_object_offset;
    if !offset_is_valid(tail_object_offset, header_size, u64::MAX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal tail object offset is out of bounds",
        ));
    }
    if tail_object_offset > arena_end {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal tail object offset exceeds arena end",
        ));
    }
    if tail_object_offset != 0
        && arena_end.saturating_sub(tail_object_offset) < ObjectHeader::SERIALIZED_LEN as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal tail object does not fit in arena",
        ));
    }

    if !hash_table_is_valid(
        header.data_hash_table_offset,
        header.data_hash_table_size,
        header_size,
        header.arena_size,
        tail_object_offset,
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal data hash table is invalid",
        ));
    }
    if !hash_table_is_valid(
        header.field_hash_table_offset,
        header.field_hash_table_size,
        header_size,
        header.arena_size,
        tail_object_offset,
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal field hash table is invalid",
        ));
    }
    if !offset_is_valid(header.entry_array_offset, header_size, tail_object_offset) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal entry array offset is invalid",
        ));
    }
    if !offset_is_valid(header.tail_entry_offset, header_size, tail_object_offset) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal tail entry offset is invalid",
        ));
    }
    let tail_array_offset = u64::from(header.tail_entry_array_offset);
    let tail_array_entries = u64::from(header.tail_entry_array_n_entries);
    if !offset_is_valid(tail_array_offset, header_size, tail_object_offset)
        || header.entry_array_offset > tail_array_offset
        || (header.entry_array_offset == 0 && tail_array_offset != 0)
        || ((tail_array_offset == 0) != (tail_array_entries == 0))
        || tail_array_entries > header.n_entries
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal tail entry-array state is inconsistent",
        ));
    }
    if tail_array_offset != 0 {
        let tail_items_size = tail_array_entries
            .checked_mul(entry_array_item_size(header))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "tail entry-array size overflow")
            })?;
        if tail_items_size > arena_end.saturating_sub(tail_array_offset) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal tail entry-array index exceeds the arena",
            ));
        }
    }
    if header.tail_entry_offset == 0 {
        if header.compatible_flags & HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID != 0
            && !header.tail_entry_boot_id.is_null()
            || header.head_entry_realtime != 0
            || header.tail_entry_realtime != 0
            || header.tail_entry_monotonic != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty journal has non-empty tail-entry metadata",
            ));
        }
    } else if header.tail_entry_boot_id.is_null()
        || !valid_realtime(header.head_entry_realtime)
        || !valid_realtime(header.tail_entry_realtime)
        || !valid_monotonic(header.tail_entry_monotonic)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal tail-entry metadata is incomplete",
        ));
    }
    if header.n_objects > header.arena_size / ObjectHeader::SERIALIZED_LEN as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal object count cannot fit in the arena",
        ));
    }
    if header.n_entries > header.n_objects
        || header.n_data > header.n_objects
        || header.n_fields > header.n_objects
        || header.n_tags > header.n_objects
        || header.n_entry_arrays > header.n_objects
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal object counters exceed total objects",
        ));
    }
    if header.data_hash_chain_depth > HASH_CHAIN_DEPTH_MAX as u64 * 1024
        || header.field_hash_chain_depth > HASH_CHAIN_DEPTH_MAX as u64 * 1024
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal hash chain depth is implausible",
        ));
    }
    if writable && (header.data_hash_table_size == 0 || header.field_hash_table_size == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "writable journal has an empty hash table",
        ));
    }

    Ok(())
}

pub fn journal_file_rotate_suggested(
    header: &Header,
    max_file_usec: Option<u64>,
    now_realtime_usec: u64,
) -> bool {
    if header.header_size < std::mem::size_of::<Header>() as u64 {
        return true;
    }

    let data_hash_items = header.data_hash_table_size / HashItem::SERIALIZED_LEN as u64;
    if data_hash_items > 0 && header.n_data.saturating_mul(4) > data_hash_items.saturating_mul(3) {
        return true;
    }
    let field_hash_items = header.field_hash_table_size / HashItem::SERIALIZED_LEN as u64;
    if field_hash_items > 0
        && header.n_fields.saturating_mul(4) > field_hash_items.saturating_mul(3)
    {
        return true;
    }
    if header.data_hash_chain_depth > HASH_CHAIN_DEPTH_MAX as u64
        || header.field_hash_chain_depth > HASH_CHAIN_DEPTH_MAX as u64
    {
        return true;
    }
    if header.n_data > 0 && header.n_fields == 0 {
        return true;
    }
    if let Some(max_file_usec) = max_file_usec {
        if header.head_entry_realtime > 0
            && now_realtime_usec > header.head_entry_realtime.saturating_add(max_file_usec)
        {
            return true;
        }
    }

    false
}
