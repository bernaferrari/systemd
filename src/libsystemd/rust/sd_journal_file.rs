// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/journal-file.c, src/libsystemd/sd-journal/journal-def.h
//

mod graph;
mod index;
mod records;
mod validation;
mod wire;

pub use index::{
    append_data_object, append_entry_array_object, append_entry_object, append_field_object,
    find_data_object_with_hash, find_field_object_with_hash, link_data_object,
    link_data_object_into_field, link_data_object_to_entry, link_entry_object, link_field_object,
    read_hash_item_at, write_hash_item_at,
};
pub use records::{
    append_journal_record_unindexed, create_empty_journal_file_at, open_journal_file_at,
    read_journal_records, render_journal_file_as_text,
};
pub use validation::{journal_file_rotate_suggested, validate_journal_header};
pub use wire::{
    align64, append_raw_object, build_empty_journal_file, default_data_hash_table_items,
    entry_array_item_size, hash_table_object_size, hash_table_payload_size, jenkins_hash64,
    journal_hash_data, journal_uses_compact, next_object_offset, read_journal_header, valid64,
    write_journal_header, EmptyJournalFileLayout, HashItem, Header, JournalAppendResult,
    JournalEntryItem, JournalFileOnDisk, JournalObject, JournalRecord, JournalVerifyStats,
    ObjectHeader, COMPACT_DATA_OBJECT_STATIC_SIZE,
    COMPACT_DATA_TAIL_ENTRY_ARRAY_N_ENTRIES_OFFSET_OFFSET,
    COMPACT_DATA_TAIL_ENTRY_ARRAY_OFFSET_OFFSET, COMPACT_ENTRY_ITEM_SIZE,
    DATA_ENTRY_ARRAY_OFFSET_OFFSET, DATA_ENTRY_OFFSET_OFFSET, DATA_NEXT_FIELD_OFFSET_OFFSET,
    DATA_NEXT_HASH_OFFSET_OFFSET, DATA_N_ENTRIES_OFFSET_OFFSET, DATA_OBJECT_STATIC_SIZE,
    DEFAULT_COMPRESS_THRESHOLD, DEFAULT_DATA_HASH_TABLE_SIZE, DEFAULT_FIELD_HASH_TABLE_SIZE,
    DEFAULT_KEEP_FREE, DEFAULT_N_MAX_FILES, ENTRY_ARRAY_ITEMS_OFFSET,
    ENTRY_ARRAY_NEXT_OFFSET_OFFSET, ENTRY_ARRAY_OBJECT_STATIC_SIZE, ENTRY_OBJECT_STATIC_SIZE,
    FIELD_HEAD_DATA_OFFSET_OFFSET, FIELD_NEXT_HASH_OFFSET_OFFSET, FIELD_OBJECT_STATIC_SIZE,
    FILE_SIZE_INCREASE, HASH_CHAIN_DEPTH_MAX, HEADER_COMPATIBLE_SEALED,
    HEADER_COMPATIBLE_SEALED_CONTINUOUS, HEADER_COMPATIBLE_SUPPORTED,
    HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID, HEADER_INCOMPATIBLE_COMPACT,
    HEADER_INCOMPATIBLE_COMPRESSED_LZ4, HEADER_INCOMPATIBLE_COMPRESSED_XZ,
    HEADER_INCOMPATIBLE_COMPRESSED_ZSTD, HEADER_INCOMPATIBLE_KEYED_HASH,
    HEADER_INCOMPATIBLE_SUPPORTED, HEADER_SIGNATURE, JOURNAL_COMPACT_SIZE_MAX,
    JOURNAL_FILE_SIZE_MIN, KEEP_FREE_UPPER, LAST_STAT_REFRESH_USEC, MAX_SIZE_UPPER, MAX_USE_LOWER,
    MAX_USE_UPPER, MIN_COMPRESS_THRESHOLD, MIN_USE_HIGH, MIN_USE_LOW, OBJECT_COMPRESSED_LZ4,
    OBJECT_COMPRESSED_MASK, OBJECT_COMPRESSED_XZ, OBJECT_COMPRESSED_ZSTD, OBJECT_DATA,
    OBJECT_DATA_HASH_TABLE, OBJECT_ENTRY, OBJECT_ENTRY_ARRAY, OBJECT_FIELD,
    OBJECT_FIELD_HASH_TABLE, OBJECT_TAG, OBJECT_UNUSED, REGULAR_ENTRY_ITEM_SIZE, STATE_ARCHIVED,
    STATE_MAX, STATE_OFFLINE, STATE_ONLINE,
};

#[cfg(test)]
mod tests;
pub use graph::verify_journal_file;
