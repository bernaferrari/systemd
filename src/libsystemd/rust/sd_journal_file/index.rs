// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/journal-file.c, src/libsystemd/sd-journal/journal-def.h
//

use super::wire::{
    COMPACT_DATA_OBJECT_STATIC_SIZE, COMPACT_DATA_TAIL_ENTRY_ARRAY_N_ENTRIES_OFFSET_OFFSET,
    COMPACT_DATA_TAIL_ENTRY_ARRAY_OFFSET_OFFSET, COMPACT_ENTRY_ITEM_SIZE,
    DATA_ENTRY_ARRAY_OFFSET_OFFSET, DATA_ENTRY_OFFSET_OFFSET, DATA_N_ENTRIES_OFFSET_OFFSET,
    DATA_NEXT_FIELD_OFFSET_OFFSET, DATA_NEXT_HASH_OFFSET_OFFSET, DATA_OBJECT_STATIC_SIZE,
    ENTRY_ARRAY_ITEMS_OFFSET, ENTRY_ARRAY_NEXT_OFFSET_OFFSET, ENTRY_ARRAY_OBJECT_STATIC_SIZE,
    ENTRY_OBJECT_STATIC_SIZE, FIELD_HEAD_DATA_OFFSET_OFFSET, FIELD_NEXT_HASH_OFFSET_OFFSET,
    FIELD_OBJECT_STATIC_SIZE, HashItem, Header, JournalEntryItem, OBJECT_DATA, OBJECT_ENTRY,
    OBJECT_ENTRY_ARRAY, OBJECT_FIELD, REGULAR_ENTRY_ITEM_SIZE, append_raw_object,
    entry_array_item_size, journal_uses_compact, read_object_header_at, read_object_payload_bytes,
    read_object_size, read_u32_at, read_u64_at, valid_monotonic, valid_realtime,
    write_journal_header, write_u32_at, write_u64_at,
};
use crate::id128_util::SdId128;
use std::fs::File;
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntryArrayLinkState {
    first: u64,
    idx: u64,
    tail: Option<u32>,
    tail_idx: Option<u32>,
}

fn read_entry_array_capacity(
    file: &mut File,
    header: &Header,
    array_offset: u64,
) -> io::Result<u64> {
    let object_size = read_object_size(file, array_offset)?;
    let item_size = entry_array_item_size(header);
    if object_size < ENTRY_ARRAY_OBJECT_STATIC_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "entry array object smaller than header",
        ));
    }
    Ok((object_size - ENTRY_ARRAY_OBJECT_STATIC_SIZE) / item_size)
}

fn read_entry_array_next_offset(file: &mut File, array_offset: u64) -> io::Result<u64> {
    read_u64_at(file, array_offset + ENTRY_ARRAY_NEXT_OFFSET_OFFSET)
}

fn write_entry_array_next_offset(
    file: &mut File,
    array_offset: u64,
    next_offset: u64,
) -> io::Result<()> {
    write_u64_at(
        file,
        array_offset + ENTRY_ARRAY_NEXT_OFFSET_OFFSET,
        next_offset,
    )
}

fn write_entry_array_item(
    file: &mut File,
    header: &Header,
    array_offset: u64,
    index: u64,
    object_offset: u64,
) -> io::Result<()> {
    let item_offset = array_offset
        .checked_add(ENTRY_ARRAY_ITEMS_OFFSET)
        .and_then(|offset| {
            index
                .checked_mul(entry_array_item_size(header))
                .and_then(|item_offset| offset.checked_add(item_offset))
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "entry array item offset overflow",
            )
        })?;
    if journal_uses_compact(header) {
        let narrowed = u32::try_from(object_offset).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "entry array item offset does not fit compact format",
            )
        })?;
        write_u32_at(file, item_offset, narrowed)
    } else {
        write_u64_at(file, item_offset, object_offset)
    }
}

pub fn append_entry_array_object(
    file: &mut File,
    header: &mut Header,
    capacity: u64,
) -> io::Result<u64> {
    let item_size = entry_array_item_size(header);
    let payload_size = capacity
        .checked_mul(item_size)
        .and_then(|items_size| 8u64.checked_add(items_size))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "entry array payload overflow")
        })?;
    let payload_len = usize::try_from(payload_size).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "entry array payload does not fit memory",
        )
    })?;
    let mut payload = vec![0u8; payload_len];
    let offset = append_raw_object(file, header, OBJECT_ENTRY_ARRAY, 0, &payload)?;
    payload.clear();
    header.n_entry_arrays = header
        .n_entry_arrays
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "entry array count overflow"))?;
    write_journal_header(file, header)?;
    Ok(offset)
}

fn link_entry_into_array(
    file: &mut File,
    header: &mut Header,
    mut state: EntryArrayLinkState,
    object_offset: u64,
) -> io::Result<EntryArrayLinkState> {
    let mut capacity = 0u64;
    let mut previous_array_offset = 0u64;
    let mut array_offset = state.tail.map(u64::from).unwrap_or(state.first);
    let current_total = state.idx;
    let mut index_in_array = state.tail_idx.map(u64::from).unwrap_or(current_total);

    while array_offset > 0 {
        capacity = read_entry_array_capacity(file, header, array_offset)?;
        if index_in_array < capacity {
            write_entry_array_item(file, header, array_offset, index_in_array, object_offset)?;
            state.idx = current_total + 1;
            if let Some(tail_idx) = &mut state.tail_idx {
                *tail_idx = tail_idx.saturating_add(1);
            }
            if let Some(tail) = &mut state.tail {
                *tail = u32::try_from(array_offset).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "entry array offset exceeds u32")
                })?;
            }
            return Ok(state);
        }

        index_in_array -= capacity;
        previous_array_offset = array_offset;
        array_offset = read_entry_array_next_offset(file, array_offset)?;
    }

    let mut new_capacity = if current_total > capacity {
        (current_total + 1).saturating_mul(2)
    } else {
        capacity.saturating_mul(2)
    };
    if new_capacity < 4 {
        new_capacity = 4;
    }

    let new_array_offset = append_entry_array_object(file, header, new_capacity)?;
    write_entry_array_item(
        file,
        header,
        new_array_offset,
        index_in_array,
        object_offset,
    )?;

    if previous_array_offset == 0 {
        state.first = new_array_offset;
    } else {
        write_entry_array_next_offset(file, previous_array_offset, new_array_offset)?;
    }

    if let Some(tail) = &mut state.tail {
        *tail = u32::try_from(new_array_offset).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "entry array offset exceeds u32")
        })?;
    }
    if let Some(tail_idx) = &mut state.tail_idx {
        *tail_idx = 1;
    }
    state.idx = current_total + 1;
    Ok(state)
}

fn link_entry_into_array_plus_one(
    file: &mut File,
    header: &mut Header,
    extra: u64,
    state: EntryArrayLinkState,
    object_offset: u64,
) -> io::Result<(u64, EntryArrayLinkState)> {
    if state.idx == u64::MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "entry array index overflow",
        ));
    }

    if state.idx == 0 {
        Ok((object_offset, EntryArrayLinkState { idx: 1, ..state }))
    } else {
        let idx = state.idx;
        let mut state = EntryArrayLinkState {
            idx: idx - 1,
            ..state
        };
        state = link_entry_into_array(file, header, state, object_offset)?;
        state.idx = idx + 1;
        Ok((extra, state))
    }
}

pub fn read_hash_item_at(
    file: &mut File,
    table_offset: u64,
    bucket_index: u64,
) -> io::Result<HashItem> {
    let item_offset = table_offset
        .checked_add(
            bucket_index
                .checked_mul(HashItem::SERIALIZED_LEN as u64)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "hash item index overflow")
                })?,
        )
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "hash item offset overflow"))?;
    Ok(HashItem {
        head_hash_offset: read_u64_at(file, item_offset)?,
        tail_hash_offset: read_u64_at(file, item_offset + 8)?,
    })
}

pub fn write_hash_item_at(
    file: &mut File,
    table_offset: u64,
    bucket_index: u64,
    item: HashItem,
) -> io::Result<()> {
    let item_offset = table_offset
        .checked_add(
            bucket_index
                .checked_mul(HashItem::SERIALIZED_LEN as u64)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "hash item index overflow")
                })?,
        )
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "hash item offset overflow"))?;
    write_u64_at(file, item_offset, item.head_hash_offset)?;
    write_u64_at(file, item_offset + 8, item.tail_hash_offset)
}

fn link_hash_bucket(
    file: &mut File,
    table_offset: u64,
    table_size: u64,
    object_offset: u64,
    hash: u64,
    next_hash_offset_within_object: u64,
) -> io::Result<u64> {
    let bucket_count = table_size / HashItem::SERIALIZED_LEN as u64;
    if bucket_count == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hash table is empty",
        ));
    }

    let bucket_index = hash % bucket_count;
    let mut bucket = read_hash_item_at(file, table_offset, bucket_index)?;
    if bucket.tail_hash_offset == 0 {
        bucket.head_hash_offset = object_offset;
    } else {
        write_u64_at(
            file,
            bucket
                .tail_hash_offset
                .checked_add(next_hash_offset_within_object)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "next-hash patch offset overflow",
                    )
                })?,
            object_offset,
        )?;
    }
    bucket.tail_hash_offset = object_offset;
    write_hash_item_at(file, table_offset, bucket_index, bucket)?;
    Ok(bucket_index)
}

pub fn append_field_object(
    file: &mut File,
    header: &mut Header,
    hash: u64,
    payload: &[u8],
) -> io::Result<u64> {
    let mut object_payload =
        Vec::with_capacity((FIELD_OBJECT_STATIC_SIZE - 16) as usize + payload.len());
    object_payload.extend_from_slice(&hash.to_le_bytes());
    object_payload.extend_from_slice(&0u64.to_le_bytes());
    object_payload.extend_from_slice(&0u64.to_le_bytes());
    object_payload.extend_from_slice(payload);

    let offset = append_raw_object(file, header, OBJECT_FIELD, 0, &object_payload)?;
    header.n_fields = header.n_fields.checked_add(1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "journal field count overflow")
    })?;
    write_journal_header(file, header)?;
    Ok(offset)
}

pub fn link_field_object(
    file: &mut File,
    header: &Header,
    field_offset: u64,
    hash: u64,
) -> io::Result<u64> {
    link_hash_bucket(
        file,
        header.field_hash_table_offset,
        header.field_hash_table_size,
        field_offset,
        hash,
        FIELD_NEXT_HASH_OFFSET_OFFSET,
    )
}

pub fn append_data_object(
    file: &mut File,
    header: &mut Header,
    hash: u64,
    payload: &[u8],
) -> io::Result<u64> {
    let compact = journal_uses_compact(header);
    let static_size = if compact {
        COMPACT_DATA_OBJECT_STATIC_SIZE
    } else {
        DATA_OBJECT_STATIC_SIZE
    };
    let mut object_payload = Vec::with_capacity((static_size - 16) as usize + payload.len());
    object_payload.extend_from_slice(&hash.to_le_bytes());
    object_payload.extend_from_slice(&0u64.to_le_bytes());
    object_payload.extend_from_slice(&0u64.to_le_bytes());
    object_payload.extend_from_slice(&0u64.to_le_bytes());
    object_payload.extend_from_slice(&0u64.to_le_bytes());
    object_payload.extend_from_slice(&0u64.to_le_bytes());
    if compact {
        object_payload.extend_from_slice(&0u32.to_le_bytes());
        object_payload.extend_from_slice(&0u32.to_le_bytes());
    }
    object_payload.extend_from_slice(payload);

    let offset = append_raw_object(file, header, OBJECT_DATA, 0, &object_payload)?;
    header.n_data = header
        .n_data
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "journal data count overflow"))?;
    write_journal_header(file, header)?;
    Ok(offset)
}

pub fn link_data_object(
    file: &mut File,
    header: &Header,
    data_offset: u64,
    hash: u64,
) -> io::Result<u64> {
    link_hash_bucket(
        file,
        header.data_hash_table_offset,
        header.data_hash_table_size,
        data_offset,
        hash,
        DATA_NEXT_HASH_OFFSET_OFFSET,
    )
}

pub fn link_data_object_into_field(
    file: &mut File,
    data_offset: u64,
    field_offset: u64,
) -> io::Result<u64> {
    let previous_head = read_u64_at(file, field_offset + FIELD_HEAD_DATA_OFFSET_OFFSET)?;
    write_u64_at(
        file,
        data_offset + DATA_NEXT_FIELD_OFFSET_OFFSET,
        previous_head,
    )?;
    write_u64_at(
        file,
        field_offset + FIELD_HEAD_DATA_OFFSET_OFFSET,
        data_offset,
    )?;
    Ok(previous_head)
}

pub fn find_field_object_with_hash(
    file: &mut File,
    header: &Header,
    payload: &[u8],
    hash: u64,
) -> io::Result<Option<u64>> {
    let bucket_count = header.field_hash_table_size / HashItem::SERIALIZED_LEN as u64;
    if bucket_count == 0 {
        return Ok(None);
    }

    let bucket = read_hash_item_at(file, header.field_hash_table_offset, hash % bucket_count)?;
    let mut offset = bucket.head_hash_offset;
    let mut remaining = header.n_fields.saturating_add(1);
    while offset != 0 {
        if remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "field hash chain exceeds the journal field count",
            ));
        }
        remaining -= 1;
        if read_object_header_at(file, offset)?.type_ != OBJECT_FIELD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "field hash chain references a non-field object",
            ));
        }
        let stored_hash = read_u64_at(file, offset + 16)?;
        if stored_hash == hash {
            let stored_payload = read_object_payload_bytes(file, offset, FIELD_OBJECT_STATIC_SIZE)?;
            if stored_payload == payload {
                return Ok(Some(offset));
            }
        }
        offset = read_u64_at(file, offset + FIELD_NEXT_HASH_OFFSET_OFFSET)?;
    }

    Ok(None)
}

pub fn find_data_object_with_hash(
    file: &mut File,
    header: &Header,
    payload: &[u8],
    hash: u64,
) -> io::Result<Option<u64>> {
    let bucket_count = header.data_hash_table_size / HashItem::SERIALIZED_LEN as u64;
    if bucket_count == 0 {
        return Ok(None);
    }

    let bucket = read_hash_item_at(file, header.data_hash_table_offset, hash % bucket_count)?;
    let mut offset = bucket.head_hash_offset;
    let payload_offset = if journal_uses_compact(header) {
        COMPACT_DATA_OBJECT_STATIC_SIZE
    } else {
        DATA_OBJECT_STATIC_SIZE
    };
    let mut remaining = header.n_data.saturating_add(1);
    while offset != 0 {
        if remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "data hash chain exceeds the journal data count",
            ));
        }
        remaining -= 1;
        if read_object_header_at(file, offset)?.type_ != OBJECT_DATA {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "data hash chain references a non-data object",
            ));
        }
        let stored_hash = read_u64_at(file, offset + 16)?;
        if stored_hash == hash {
            let stored_payload = read_object_payload_bytes(file, offset, payload_offset)?;
            if stored_payload == payload {
                return Ok(Some(offset));
            }
        }
        offset = read_u64_at(file, offset + DATA_NEXT_HASH_OFFSET_OFFSET)?;
    }

    Ok(None)
}

// The journal's on-disk entry fields deliberately remain explicit in this API.
#[allow(clippy::too_many_arguments)]
pub fn append_entry_object(
    file: &mut File,
    header: &mut Header,
    seqnum: u64,
    realtime: u64,
    monotonic: u64,
    boot_id: SdId128,
    xor_hash: u64,
    items: &[JournalEntryItem],
) -> io::Result<u64> {
    if seqnum == 0
        || !valid_realtime(realtime)
        || !valid_monotonic(monotonic)
        || boot_id.is_null()
        || items.is_empty()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "entry requires a sequence number, timestamps, boot ID, and data items",
        ));
    }
    let compact = journal_uses_compact(header);
    let item_size = if compact {
        COMPACT_ENTRY_ITEM_SIZE
    } else {
        REGULAR_ENTRY_ITEM_SIZE
    };
    let mut object_payload = Vec::with_capacity(
        (ENTRY_OBJECT_STATIC_SIZE - 16 + item_size * items.len() as u64) as usize,
    );
    object_payload.extend_from_slice(&seqnum.to_le_bytes());
    object_payload.extend_from_slice(&realtime.to_le_bytes());
    object_payload.extend_from_slice(&monotonic.to_le_bytes());
    object_payload.extend_from_slice(&boot_id.0);
    object_payload.extend_from_slice(&xor_hash.to_le_bytes());
    for item in items {
        if compact {
            let object_offset = u32::try_from(item.object_offset).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "entry item offset does not fit compact journal format",
                )
            })?;
            object_payload.extend_from_slice(&object_offset.to_le_bytes());
        } else {
            object_payload.extend_from_slice(&item.object_offset.to_le_bytes());
            object_payload.extend_from_slice(&item.hash.to_le_bytes());
        }
    }

    let offset = append_raw_object(file, header, OBJECT_ENTRY, 0, &object_payload)?;
    header.n_entries = header.n_entries.checked_add(1).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "journal entry count overflow")
    })?;
    if header.head_entry_seqnum == 0 {
        header.head_entry_seqnum = seqnum;
    }
    if header.head_entry_realtime == 0 {
        header.head_entry_realtime = realtime;
    }
    header.tail_entry_seqnum = seqnum;
    header.tail_entry_realtime = realtime;
    header.tail_entry_monotonic = monotonic;
    header.tail_entry_boot_id = boot_id;
    header.tail_entry_offset = offset;
    write_journal_header(file, header)?;
    Ok(offset)
}

pub fn link_data_object_to_entry(
    file: &mut File,
    header: &mut Header,
    data_offset: u64,
    entry_offset: u64,
) -> io::Result<()> {
    let extra = read_u64_at(file, data_offset + DATA_ENTRY_OFFSET_OFFSET)?;
    let first = read_u64_at(file, data_offset + DATA_ENTRY_ARRAY_OFFSET_OFFSET)?;
    let idx = read_u64_at(file, data_offset + DATA_N_ENTRIES_OFFSET_OFFSET)?;
    let tail = if journal_uses_compact(header) {
        Some(read_u32_at(
            file,
            data_offset + COMPACT_DATA_TAIL_ENTRY_ARRAY_OFFSET_OFFSET,
        )?)
    } else {
        None
    };
    let tail_idx = if journal_uses_compact(header) {
        Some(read_u32_at(
            file,
            data_offset + COMPACT_DATA_TAIL_ENTRY_ARRAY_N_ENTRIES_OFFSET_OFFSET,
        )?)
    } else {
        None
    };

    let (new_extra, state) = link_entry_into_array_plus_one(
        file,
        header,
        extra,
        EntryArrayLinkState {
            first,
            idx,
            tail,
            tail_idx,
        },
        entry_offset,
    )?;
    write_u64_at(file, data_offset + DATA_ENTRY_OFFSET_OFFSET, new_extra)?;
    write_u64_at(
        file,
        data_offset + DATA_ENTRY_ARRAY_OFFSET_OFFSET,
        state.first,
    )?;
    write_u64_at(file, data_offset + DATA_N_ENTRIES_OFFSET_OFFSET, state.idx)?;
    if journal_uses_compact(header) {
        write_u32_at(
            file,
            data_offset + COMPACT_DATA_TAIL_ENTRY_ARRAY_OFFSET_OFFSET,
            state.tail.unwrap_or(0),
        )?;
        write_u32_at(
            file,
            data_offset + COMPACT_DATA_TAIL_ENTRY_ARRAY_N_ENTRIES_OFFSET_OFFSET,
            state.tail_idx.unwrap_or(0),
        )?;
    }
    Ok(())
}

pub fn link_entry_object(
    file: &mut File,
    header: &mut Header,
    entry_offset: u64,
    items: &[JournalEntryItem],
) -> io::Result<()> {
    let state = link_entry_into_array(
        file,
        header,
        EntryArrayLinkState {
            first: header.entry_array_offset,
            idx: header.n_entries.saturating_sub(1),
            tail: Some(header.tail_entry_array_offset),
            tail_idx: Some(header.tail_entry_array_n_entries),
        },
        entry_offset,
    )?;
    header.entry_array_offset = state.first;
    header.tail_entry_array_offset = state.tail.unwrap_or(0);
    header.tail_entry_array_n_entries = state.tail_idx.unwrap_or(0);
    write_journal_header(file, header)?;

    for item in items {
        link_data_object_to_entry(file, header, item.object_offset, entry_offset)?;
    }

    Ok(())
}
