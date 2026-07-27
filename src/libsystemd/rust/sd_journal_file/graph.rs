// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/journal-verify.c
//

use super::records::open_journal_file_at;
use super::validation::{
    minimum_object_size_for_type, validate_journal_header, verify_object_shallow,
};
use super::wire::{
    align64, read_object_header_at, read_object_payload_bytes, read_u64_le, JournalVerifyStats,
    ObjectHeader, HEADER_COMPATIBLE_SEALED, HEADER_COMPATIBLE_SUPPORTED, OBJECT_DATA,
    OBJECT_DATA_HASH_TABLE, OBJECT_ENTRY, OBJECT_ENTRY_ARRAY, OBJECT_FIELD,
    OBJECT_FIELD_HASH_TABLE, OBJECT_TAG,
};
use std::io;
use std::path::Path;

pub fn verify_journal_file(path: &Path) -> io::Result<JournalVerifyStats> {
    let mut journal = open_journal_file_at(path, false)?;
    if journal.header.compatible_flags & !HEADER_COMPATIBLE_SUPPORTED != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cannot verify journal with unknown compatible extensions",
        ));
    }
    let file_len = journal.file.metadata()?.len();
    validate_journal_header(&journal.header, file_len, false)?;

    let mut stats = JournalVerifyStats::default();
    let mut found_tail = journal.header.tail_object_offset == 0;
    let mut offset = journal.header.header_size;
    let end = journal
        .header
        .header_size
        .checked_add(journal.header.arena_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "journal arena end overflow"))?;

    while offset < end {
        let object_header = read_object_header_at(&mut journal.file, offset)?;
        let Some(min_size) = minimum_object_size_for_type(&journal.header, object_header.type_)
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal object type is invalid",
            ));
        };
        if object_header.size < min_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal object is smaller than its minimum size",
            ));
        }
        verify_object_shallow(&mut journal.file, &journal.header, offset, &object_header)?;

        stats.n_objects += 1;
        match object_header.type_ {
            OBJECT_DATA => stats.n_data += 1,
            OBJECT_FIELD => stats.n_fields += 1,
            OBJECT_ENTRY => {
                if journal.header.compatible_flags & HEADER_COMPATIBLE_SEALED != 0
                    && stats.n_tags == 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "sealed journal contains an entry before its first tag",
                    ));
                }
                stats.n_entries += 1;
            }
            OBJECT_DATA_HASH_TABLE => stats.n_data_hash_tables += 1,
            OBJECT_FIELD_HASH_TABLE => stats.n_field_hash_tables += 1,
            OBJECT_ENTRY_ARRAY => stats.n_entry_arrays += 1,
            OBJECT_TAG => {
                if journal.header.compatible_flags & HEADER_COMPATIBLE_SEALED == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsealed journal contains a tag object",
                    ));
                }
                let payload = read_object_payload_bytes(
                    &mut journal.file,
                    offset,
                    ObjectHeader::SERIALIZED_LEN as u64,
                )?;
                let seqnum = read_u64_le(&payload, &mut 0)?;
                if seqnum != stats.n_tags + 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tag sequence number is out of order",
                    ));
                }
                stats.n_tags += 1;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "journal object walk encountered an unknown object type",
                ));
            }
        }
        if offset == journal.header.tail_object_offset {
            found_tail = true;
        }

        let next = offset
            .checked_add(align64(object_header.size))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "journal object walk overflow")
            })?;
        if next <= offset || next > end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal object extends beyond arena",
            ));
        }
        offset = next;
    }

    if offset != end {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal object walk does not terminate at arena end",
        ));
    }
    if !found_tail {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal tail object offset does not reference the last object",
        ));
    }
    if stats.n_data_hash_tables != 1 || stats.n_field_hash_tables != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal must contain exactly one data and one field hash table",
        ));
    }
    if journal.header.tail_entry_offset != 0 {
        let tail_entry =
            read_object_header_at(&mut journal.file, journal.header.tail_entry_offset)?;
        if tail_entry.type_ != OBJECT_ENTRY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal tail entry offset does not reference an entry object",
            ));
        }
    }
    if journal.header.entry_array_offset != 0 {
        let entry_array =
            read_object_header_at(&mut journal.file, journal.header.entry_array_offset)?;
        if entry_array.type_ != OBJECT_ENTRY_ARRAY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal entry array offset does not reference an entry array object",
            ));
        }
    }
    if stats.n_objects != journal.header.n_objects
        || stats.n_entries != journal.header.n_entries
        || stats.n_data != journal.header.n_data
        || stats.n_fields != journal.header.n_fields
        || stats.n_tags != journal.header.n_tags
        || stats.n_entry_arrays != journal.header.n_entry_arrays
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal header counters do not match object walk",
        ));
    }

    Ok(stats)
}
