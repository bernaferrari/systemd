// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/journal-file.c, src/libsystemd/sd-journal/journal-def.h
//

use super::wire::{read_u64_at, write_u64_at};
use super::*;
use crate::id128_util::SdId128;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use systemd_basic_rs::siphash24::siphash24;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{unique}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn aligns_to_eight_bytes() {
    assert_eq!(align64(9), 16);
}

#[test]
fn valid64_matches_c_alignment_predicate() {
    assert!(valid64(0));
    assert!(valid64(8));
    assert!(!valid64(1));
}

#[test]
fn signature_matches_c_header() {
    assert_eq!(HEADER_SIGNATURE, *b"LPKSHHRH");
}

#[test]
fn header_size_matches_c_layout() {
    assert_eq!(std::mem::size_of::<Header>(), 272);
}

#[test]
fn hash_table_items_use_payload_size() {
    let object = JournalObject {
        header: ObjectHeader {
            type_: OBJECT_DATA_HASH_TABLE,
            flags: 0,
            reserved: [0; 6],
            size: 64,
        },
        payload_len: 32,
    };
    assert_eq!(object.hash_table_items(), 2);
}

#[test]
fn entry_items_divide_payload() {
    let object = JournalObject {
        header: ObjectHeader {
            type_: OBJECT_ENTRY,
            flags: 0,
            reserved: [0; 6],
            size: 64,
        },
        payload_len: 24,
    };
    assert_eq!(object.entry_items(8), 3);
}

#[test]
fn tail_end_aligns_size() {
    let object = JournalObject {
        header: ObjectHeader {
            type_: OBJECT_DATA,
            flags: 0,
            reserved: [0; 6],
            size: 13,
        },
        payload_len: 0,
    };
    assert_eq!(object.tail_end(100), Some(116));
}

#[test]
fn state_constants_match_c_values() {
    assert_eq!((STATE_OFFLINE, STATE_ONLINE, STATE_ARCHIVED), (0, 1, 2));
}

#[test]
fn default_data_hash_table_items_never_drop_below_c_default() {
    assert_eq!(
        default_data_hash_table_items(0),
        DEFAULT_DATA_HASH_TABLE_SIZE as u64
    );
    assert!(default_data_hash_table_items(16 * 1024 * 1024) >= DEFAULT_DATA_HASH_TABLE_SIZE as u64);
}

#[test]
fn builds_empty_file_with_two_hash_table_objects() {
    let layout = build_empty_journal_file(
        64 * 1024 * 1024,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        HEADER_INCOMPATIBLE_KEYED_HASH,
    );

    assert_eq!(
        layout.header.header_size,
        align64(std::mem::size_of::<Header>() as u64)
    );
    assert_eq!(layout.header.n_objects, 2);
    assert_eq!(
        layout.header.data_hash_table_offset,
        layout.data_hash_object_offset + ObjectHeader::SERIALIZED_LEN as u64
    );
    assert_eq!(
        layout.header.field_hash_table_offset,
        layout.field_hash_object_offset + ObjectHeader::SERIALIZED_LEN as u64
    );
    assert_eq!(
        layout.header.tail_object_offset,
        layout.field_hash_object_offset
    );
    assert_eq!(
        layout.bytes.len() as u64,
        layout.header.header_size + layout.header.arena_size
    );
}

#[test]
fn empty_file_serialization_uses_header_signature_and_zeroed_hash_buckets() {
    let layout = build_empty_journal_file(
        8 * 1024 * 1024,
        SdId128([0xAA; 16]),
        SdId128([0xBB; 16]),
        SdId128([0xCC; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        HEADER_INCOMPATIBLE_KEYED_HASH | HEADER_INCOMPATIBLE_COMPACT,
    );

    assert_eq!(&layout.bytes[..8], &HEADER_SIGNATURE);
    let first_bucket_offset = layout.header.data_hash_table_offset as usize;
    assert_eq!(
        &layout.bytes[first_bucket_offset..first_bucket_offset + HashItem::SERIALIZED_LEN],
        &[0; HashItem::SERIALIZED_LEN]
    );
    let field_object_offset = layout.field_hash_object_offset as usize;
    assert_eq!(layout.bytes[field_object_offset], OBJECT_FIELD_HASH_TABLE);
}

#[test]
fn header_round_trips_through_le_codec() {
    let original = build_empty_journal_file(
        4 * 1024 * 1024,
        SdId128([0x01; 16]),
        SdId128([0x02; 16]),
        SdId128([0x03; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        HEADER_INCOMPATIBLE_KEYED_HASH,
    )
    .header;
    let decoded = Header::decode_le_bytes(&original.encode_le_bytes()).unwrap();
    assert_eq!(decoded, original);
    assert!(decoded.has_valid_signature());
}

#[test]
fn create_empty_journal_file_at_writes_binary_file_and_reopens() {
    let temp = TempDir::new("sd-journal-file-create");
    let path = temp.path().join("system.journal");

    let created = create_empty_journal_file_at(
        &path,
        0o640,
        16 * 1024 * 1024,
        SdId128([0x10; 16]),
        SdId128([0x20; 16]),
        SdId128([0x30; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        HEADER_INCOMPATIBLE_KEYED_HASH,
    )
    .unwrap();

    assert!(created.path.exists());
    let metadata = created.file.metadata().unwrap();
    assert_eq!(
        metadata.len(),
        created.header.header_size + created.header.arena_size
    );

    let reopened = open_journal_file_at(&path, false).unwrap();
    assert_eq!(reopened.header, created.header);
    assert_eq!(reopened.path, path);
}

#[test]
fn open_journal_file_at_rejects_invalid_signature() {
    let temp = TempDir::new("sd-journal-file-invalid");
    let path = temp.path().join("broken.journal");
    fs::write(&path, [0u8; Header::SERIALIZED_LEN]).unwrap();

    let error = open_journal_file_at(&path, false).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn append_raw_object_updates_header_and_writes_aligned_payload() {
    let temp = TempDir::new("sd-journal-file-append");
    let path = temp.path().join("append.journal");

    let mut created = create_empty_journal_file_at(
        &path,
        0o640,
        16 * 1024 * 1024,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        HEADER_INCOMPATIBLE_KEYED_HASH,
    )
    .unwrap();

    let mut header = created.header;
    let offset = append_raw_object(
        &mut created.file,
        &mut header,
        OBJECT_DATA,
        0,
        b"MESSAGE=hello",
    )
    .unwrap();

    assert_eq!(
        offset,
        created.header.header_size + created.header.arena_size
    );
    assert_eq!(header.n_objects, created.header.n_objects + 1);
    assert_eq!(header.tail_object_offset, offset);

    let reopened = open_journal_file_at(&path, false).unwrap();
    assert_eq!(reopened.header, header);

    let mut raw = vec![0u8; align64(ObjectHeader::SERIALIZED_LEN as u64 + 13) as usize];
    let mut file = reopened.file;
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.read_exact(&mut raw).unwrap();

    assert_eq!(raw[0], OBJECT_DATA);
    assert_eq!(
        u64::from_le_bytes(raw[8..16].try_into().unwrap()),
        (ObjectHeader::SERIALIZED_LEN as u64) + 13
    );
    assert_eq!(&raw[16..29], b"MESSAGE=hello");
    assert!(raw[29..].iter().all(|byte| *byte == 0));
}

#[test]
fn append_field_object_updates_header_and_serializes_payload() {
    let temp = TempDir::new("sd-journal-file-field");
    let path = temp.path().join("field.journal");
    let mut created = create_empty_journal_file_at(
        &path,
        0o640,
        16 * 1024 * 1024,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        HEADER_INCOMPATIBLE_KEYED_HASH,
    )
    .unwrap();

    let mut header = created.header;
    let offset = append_field_object(&mut created.file, &mut header, 0x1234, b"MESSAGE").unwrap();
    assert_eq!(header.n_fields, 1);

    let mut raw = vec![0u8; align64(FIELD_OBJECT_STATIC_SIZE + 7) as usize];
    created.file.seek(SeekFrom::Start(offset)).unwrap();
    created.file.read_exact(&mut raw).unwrap();
    assert_eq!(raw[0], OBJECT_FIELD);
    assert_eq!(u64::from_le_bytes(raw[16..24].try_into().unwrap()), 0x1234);
    assert_eq!(&raw[40..47], b"MESSAGE");
}

#[test]
fn append_data_object_updates_header_and_serializes_payload() {
    let temp = TempDir::new("sd-journal-file-data");
    let path = temp.path().join("data.journal");
    let mut created = create_empty_journal_file_at(
        &path,
        0o640,
        16 * 1024 * 1024,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        HEADER_INCOMPATIBLE_KEYED_HASH,
    )
    .unwrap();

    let mut header = created.header;
    let offset =
        append_data_object(&mut created.file, &mut header, 0x99, b"MESSAGE=hello").unwrap();
    assert_eq!(header.n_data, 1);

    let mut raw = vec![0u8; align64(DATA_OBJECT_STATIC_SIZE + 13) as usize];
    created.file.seek(SeekFrom::Start(offset)).unwrap();
    created.file.read_exact(&mut raw).unwrap();
    assert_eq!(raw[0], OBJECT_DATA);
    assert_eq!(u64::from_le_bytes(raw[16..24].try_into().unwrap()), 0x99);
    assert_eq!(&raw[64..77], b"MESSAGE=hello");
}

#[test]
fn append_entry_object_updates_entry_header_counters() {
    let temp = TempDir::new("sd-journal-file-entry");
    let path = temp.path().join("entry.journal");
    let mut created = create_empty_journal_file_at(
        &path,
        0o640,
        16 * 1024 * 1024,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        HEADER_INCOMPATIBLE_KEYED_HASH,
    )
    .unwrap();

    let mut header = created.header;
    let items = [
        JournalEntryItem {
            object_offset: 0x1000,
            hash: 0xAAAA,
        },
        JournalEntryItem {
            object_offset: 0x2000,
            hash: 0xBBBB,
        },
    ];
    let boot_id = SdId128([0x44; 16]);
    let offset = append_entry_object(
        &mut created.file,
        &mut header,
        7,
        100,
        50,
        boot_id,
        0x7777,
        &items,
    )
    .unwrap();

    assert_eq!(header.n_entries, 1);
    assert_eq!(header.head_entry_seqnum, 7);
    assert_eq!(header.tail_entry_seqnum, 7);
    assert_eq!(header.head_entry_realtime, 100);
    assert_eq!(header.tail_entry_realtime, 100);
    assert_eq!(header.tail_entry_monotonic, 50);
    assert_eq!(header.tail_entry_boot_id, boot_id);
    assert_eq!(header.tail_entry_offset, offset);

    let mut raw =
        vec![0u8; align64(ENTRY_OBJECT_STATIC_SIZE + 2 * REGULAR_ENTRY_ITEM_SIZE) as usize];
    created.file.seek(SeekFrom::Start(offset)).unwrap();
    created.file.read_exact(&mut raw).unwrap();
    assert_eq!(raw[0], OBJECT_ENTRY);
    assert_eq!(u64::from_le_bytes(raw[16..24].try_into().unwrap()), 7);
    assert_eq!(u64::from_le_bytes(raw[24..32].try_into().unwrap()), 100);
    assert_eq!(u64::from_le_bytes(raw[32..40].try_into().unwrap()), 50);
    assert_eq!(&raw[40..56], &boot_id.0);
    assert_eq!(u64::from_le_bytes(raw[56..64].try_into().unwrap()), 0x7777);
    assert_eq!(u64::from_le_bytes(raw[64..72].try_into().unwrap()), 0x1000);
    assert_eq!(u64::from_le_bytes(raw[72..80].try_into().unwrap()), 0xAAAA);
}

#[test]
fn link_field_object_updates_bucket_chain() {
    let temp = TempDir::new("sd-journal-file-link-field");
    let path = temp.path().join("field-link.journal");
    let mut created = create_empty_journal_file_at(
        &path,
        0o640,
        16 * 1024 * 1024,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        HEADER_INCOMPATIBLE_KEYED_HASH,
    )
    .unwrap();

    let mut header = created.header;
    let hash = 0x1234;
    let first = append_field_object(&mut created.file, &mut header, hash, b"MESSAGE").unwrap();
    let bucket = link_field_object(&mut created.file, &header, first, hash).unwrap();
    let item =
        read_hash_item_at(&mut created.file, header.field_hash_table_offset, bucket).unwrap();
    assert_eq!(item.head_hash_offset, first);
    assert_eq!(item.tail_hash_offset, first);

    let second = append_field_object(&mut created.file, &mut header, hash, b"PRIORITY").unwrap();
    link_field_object(&mut created.file, &header, second, hash).unwrap();
    let item =
        read_hash_item_at(&mut created.file, header.field_hash_table_offset, bucket).unwrap();
    assert_eq!(item.head_hash_offset, first);
    assert_eq!(item.tail_hash_offset, second);
    assert_eq!(
        read_u64_at(&mut created.file, first + FIELD_NEXT_HASH_OFFSET_OFFSET).unwrap(),
        second
    );
}

#[test]
fn link_data_object_updates_bucket_chain() {
    let temp = TempDir::new("sd-journal-file-link-data");
    let path = temp.path().join("data-link.journal");
    let mut created = create_empty_journal_file_at(
        &path,
        0o640,
        16 * 1024 * 1024,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        HEADER_INCOMPATIBLE_KEYED_HASH,
    )
    .unwrap();

    let mut header = created.header;
    let hash = 0x7777;
    let first = append_data_object(&mut created.file, &mut header, hash, b"MESSAGE=hello").unwrap();
    let bucket = link_data_object(&mut created.file, &header, first, hash).unwrap();
    let second =
        append_data_object(&mut created.file, &mut header, hash, b"MESSAGE=again").unwrap();
    link_data_object(&mut created.file, &header, second, hash).unwrap();

    let item = read_hash_item_at(&mut created.file, header.data_hash_table_offset, bucket).unwrap();
    assert_eq!(item.head_hash_offset, first);
    assert_eq!(item.tail_hash_offset, second);
    assert_eq!(
        read_u64_at(&mut created.file, first + DATA_NEXT_HASH_OFFSET_OFFSET).unwrap(),
        second
    );
}

#[test]
fn link_data_object_into_field_sets_head_and_next_field_offset() {
    let temp = TempDir::new("sd-journal-file-link-data-field");
    let path = temp.path().join("data-field-link.journal");
    let mut created = create_empty_journal_file_at(
        &path,
        0o640,
        16 * 1024 * 1024,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        HEADER_INCOMPATIBLE_KEYED_HASH,
    )
    .unwrap();

    let mut header = created.header;
    let field = append_field_object(&mut created.file, &mut header, 0x1111, b"MESSAGE").unwrap();
    let first = append_data_object(&mut created.file, &mut header, 0x2222, b"MESSAGE=one").unwrap();
    let previous = link_data_object_into_field(&mut created.file, first, field).unwrap();
    assert_eq!(previous, 0);
    assert_eq!(
        read_u64_at(&mut created.file, field + FIELD_HEAD_DATA_OFFSET_OFFSET).unwrap(),
        first
    );

    let second =
        append_data_object(&mut created.file, &mut header, 0x3333, b"MESSAGE=two").unwrap();
    let previous = link_data_object_into_field(&mut created.file, second, field).unwrap();
    assert_eq!(previous, first);
    assert_eq!(
        read_u64_at(&mut created.file, field + FIELD_HEAD_DATA_OFFSET_OFFSET).unwrap(),
        second
    );
    assert_eq!(
        read_u64_at(&mut created.file, second + DATA_NEXT_FIELD_OFFSET_OFFSET).unwrap(),
        first
    );
}

#[test]
fn append_journal_record_unindexed_appends_field_data_and_entry_objects() {
    let temp = TempDir::new("sd-journal-file-record");
    let path = temp.path().join("record.journal");
    let mut created = create_empty_journal_file_at(
        &path,
        0o640,
        16 * 1024 * 1024,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        0,
    )
    .unwrap();

    let mut header = created.header;
    let boot_id = SdId128([0x55; 16]);
    let result = append_journal_record_unindexed(
        &mut created.file,
        &mut header,
        1000,
        200,
        boot_id,
        &[b"MESSAGE=hello", b"PRIORITY=6"],
    )
    .unwrap();

    assert_eq!(result.seqnum, 1);
    assert_eq!(result.data_offsets.len(), 2);
    assert_eq!(result.field_offsets.len(), 2);
    assert_eq!(header.n_fields, 2);
    assert_eq!(header.n_data, 2);
    assert_eq!(header.n_entries, 1);
    assert_eq!(header.n_objects, 8);
    assert_eq!(header.tail_entry_seqnum, 1);
    assert_eq!(header.tail_entry_realtime, 1000);
    assert_eq!(header.tail_entry_monotonic, 200);
    assert_eq!(header.tail_entry_boot_id, boot_id);
    assert_eq!(header.tail_entry_offset, result.entry_offset);
    assert!(header.entry_array_offset > 0);
    assert_eq!(header.n_entry_arrays, 1);
    assert_eq!(
        header.tail_entry_array_offset as u64,
        header.entry_array_offset
    );
    assert_eq!(header.tail_entry_array_n_entries, 1);
}

#[test]
fn link_data_object_to_entry_uses_inline_then_spill_array() {
    let temp = TempDir::new("sd-journal-file-data-entry-link");
    let path = temp.path().join("data-entry-link.journal");
    let mut created = create_empty_journal_file_at(
        &path,
        0o640,
        16 * 1024 * 1024,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        0,
    )
    .unwrap();

    let mut header = created.header;
    let data_offset =
        append_data_object(&mut created.file, &mut header, 0x1234, b"MESSAGE=hello").unwrap();

    link_data_object_to_entry(&mut created.file, &mut header, data_offset, 0xAAA).unwrap();
    assert_eq!(
        read_u64_at(&mut created.file, data_offset + DATA_ENTRY_OFFSET_OFFSET).unwrap(),
        0xAAA
    );
    assert_eq!(
        read_u64_at(
            &mut created.file,
            data_offset + DATA_ENTRY_ARRAY_OFFSET_OFFSET
        )
        .unwrap(),
        0
    );
    assert_eq!(
        read_u64_at(
            &mut created.file,
            data_offset + DATA_N_ENTRIES_OFFSET_OFFSET
        )
        .unwrap(),
        1
    );

    link_data_object_to_entry(&mut created.file, &mut header, data_offset, 0xBBB).unwrap();
    let entry_array_offset = read_u64_at(
        &mut created.file,
        data_offset + DATA_ENTRY_ARRAY_OFFSET_OFFSET,
    )
    .unwrap();
    assert!(entry_array_offset > 0);
    assert_eq!(
        read_u64_at(&mut created.file, data_offset + DATA_ENTRY_OFFSET_OFFSET).unwrap(),
        0xAAA
    );
    assert_eq!(
        read_u64_at(
            &mut created.file,
            data_offset + DATA_N_ENTRIES_OFFSET_OFFSET
        )
        .unwrap(),
        2
    );
    assert_eq!(header.n_entry_arrays, 1);
    assert_eq!(
        read_u64_at(
            &mut created.file,
            entry_array_offset + ENTRY_ARRAY_ITEMS_OFFSET
        )
        .unwrap(),
        0xBBB
    );
}

#[test]
fn append_journal_record_unindexed_supports_keyed_hash_files() {
    let temp = TempDir::new("sd-journal-file-record-keyed");
    let path = temp.path().join("record-keyed.journal");
    let mut created = create_empty_journal_file_at(
        &path,
        0o640,
        16 * 1024 * 1024,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        HEADER_INCOMPATIBLE_KEYED_HASH,
    )
    .unwrap();

    let mut header = created.header;
    let result = append_journal_record_unindexed(
        &mut created.file,
        &mut header,
        1000,
        200,
        SdId128([0x55; 16]),
        &[b"MESSAGE=hello"],
    )
    .unwrap();
    assert_eq!(result.seqnum, 1);
    assert_eq!(header.n_data, 1);
    assert_eq!(header.n_fields, 1);
}

#[test]
fn append_journal_record_unindexed_reuses_existing_field_and_data_objects() {
    let temp = TempDir::new("sd-journal-file-record-dedup");
    let path = temp.path().join("record-dedup.journal");
    let mut created = create_empty_journal_file_at(
        &path,
        0o640,
        16 * 1024 * 1024,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        0,
    )
    .unwrap();

    let mut header = created.header;
    let boot_id = SdId128([0x55; 16]);
    let first = append_journal_record_unindexed(
        &mut created.file,
        &mut header,
        1000,
        200,
        boot_id,
        &[b"MESSAGE=hello", b"PRIORITY=6"],
    )
    .unwrap();
    let second = append_journal_record_unindexed(
        &mut created.file,
        &mut header,
        1001,
        201,
        boot_id,
        &[b"MESSAGE=hello", b"PRIORITY=6"],
    )
    .unwrap();

    assert_eq!(first.field_offsets, second.field_offsets);
    assert_eq!(first.data_offsets, second.data_offsets);
    assert_eq!(header.n_fields, 2);
    assert_eq!(header.n_data, 2);
    assert_eq!(header.n_entries, 2);
    assert_eq!(header.n_objects, 11);
    assert_eq!(header.n_entry_arrays, 3);
}

#[test]
fn journal_hash_data_uses_file_id_key_when_keyed_hash_is_enabled() {
    let mut header = build_empty_journal_file(
        JOURNAL_FILE_SIZE_MIN,
        SdId128([0x11; 16]),
        SdId128::null(),
        SdId128::null(),
        0,
        HEADER_INCOMPATIBLE_KEYED_HASH,
    )
    .header;
    let payload = b"MESSAGE=hello";
    let keyed = journal_hash_data(&header, payload).unwrap();
    assert_eq!(keyed, siphash24(payload, &header.file_id.0));

    header.incompatible_flags = 0;
    assert_eq!(
        journal_hash_data(&header, payload).unwrap(),
        jenkins_hash64(payload)
    );
}

#[test]
fn verify_journal_file_accepts_valid_binary_journal() {
    let temp = TempDir::new("sd-journal-file-verify-valid");
    let path = temp.path().join("verify-valid.journal");
    let mut created = create_empty_journal_file_at(
        &path,
        0o644,
        JOURNAL_FILE_SIZE_MIN,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        0,
    )
    .unwrap();
    append_journal_record_unindexed(
        &mut created.file,
        &mut created.header,
        10,
        20,
        SdId128([0x55; 16]),
        &[b"MESSAGE=hello", b"PRIORITY=6"],
    )
    .unwrap();
    created.file.sync_all().unwrap();

    let stats = verify_journal_file(&path).unwrap();
    assert_eq!(stats.n_objects, created.header.n_objects);
    assert_eq!(stats.n_entries, 1);
    assert_eq!(stats.n_data, 2);
    assert_eq!(stats.n_fields, 2);
}

#[test]
fn open_journal_file_at_rejects_invalid_header_layout() {
    let temp = TempDir::new("sd-journal-file-invalid-layout");
    let path = temp.path().join("broken-layout.journal");
    let mut created = create_empty_journal_file_at(
        &path,
        0o644,
        JOURNAL_FILE_SIZE_MIN,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        0,
    )
    .unwrap();
    created.header.n_entries = created.header.n_objects + 1;
    write_journal_header(&mut created.file, &created.header).unwrap();
    created.file.sync_all().unwrap();
    drop(created);

    let error = open_journal_file_at(&path, false).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn open_journal_file_at_accepts_supported_sealing_flag() {
    let temp = TempDir::new("sd-journal-file-sealed-compatible");
    let path = temp.path().join("sealed-compatible.journal");
    let mut created = create_empty_journal_file_at(
        &path,
        0o644,
        JOURNAL_FILE_SIZE_MIN,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        0,
    )
    .unwrap();
    created.header.compatible_flags |= HEADER_COMPATIBLE_SEALED;
    write_journal_header(&mut created.file, &created.header).unwrap();
    created.file.sync_all().unwrap();
    drop(created);

    let reopened = open_journal_file_at(&path, false).unwrap();
    assert_eq!(
        reopened.header.compatible_flags & HEADER_COMPATIBLE_SEALED,
        HEADER_COMPATIBLE_SEALED
    );
}

#[test]
fn verify_journal_file_uses_c_tag_layout() {
    let temp = TempDir::new("sd-journal-file-tag-layout");
    let path = temp.path().join("tag-layout.journal");
    let mut created = create_empty_journal_file_at(
        &path,
        0o644,
        JOURNAL_FILE_SIZE_MIN,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        0,
    )
    .unwrap();
    created.header.compatible_flags |= HEADER_COMPATIBLE_SEALED;
    let mut payload = Vec::with_capacity(48);
    payload.extend_from_slice(&1u64.to_le_bytes());
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.extend_from_slice(&[0xAA; 32]);
    append_raw_object(
        &mut created.file,
        &mut created.header,
        OBJECT_TAG,
        0,
        &payload,
    )
    .unwrap();
    created.header.n_tags = 1;
    write_journal_header(&mut created.file, &created.header).unwrap();
    created.file.sync_all().unwrap();
    drop(created);

    let stats = verify_journal_file(&path).unwrap();
    assert_eq!(stats.n_tags, 1);
}

#[test]
fn verify_journal_file_rejects_hash_table_type_mismatch() {
    let temp = TempDir::new("sd-journal-file-verify-hash-table-type");
    let path = temp.path().join("broken-hash-table-type.journal");
    let mut created = create_empty_journal_file_at(
        &path,
        0o644,
        JOURNAL_FILE_SIZE_MIN,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        0,
    )
    .unwrap();
    created
        .file
        .seek(SeekFrom::Start(
            created.header.data_hash_table_offset - ObjectHeader::SERIALIZED_LEN as u64,
        ))
        .unwrap();
    created.file.write_all(&[OBJECT_FIELD_HASH_TABLE]).unwrap();
    created.file.sync_all().unwrap();
    drop(created);

    let error = verify_journal_file(&path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn verify_journal_file_rejects_data_hash_mismatch() {
    let temp = TempDir::new("sd-journal-file-verify-data-hash");
    let path = temp.path().join("broken-data-hash.journal");
    let mut created = create_empty_journal_file_at(
        &path,
        0o644,
        JOURNAL_FILE_SIZE_MIN,
        SdId128([0x11; 16]),
        SdId128([0x22; 16]),
        SdId128([0x33; 16]),
        HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID,
        0,
    )
    .unwrap();
    let appended = append_journal_record_unindexed(
        &mut created.file,
        &mut created.header,
        10,
        20,
        SdId128([0x55; 16]),
        &[b"MESSAGE=hello"],
    )
    .unwrap();
    write_u64_at(
        &mut created.file,
        appended.data_offsets[0] + ObjectHeader::SERIALIZED_LEN as u64,
        0,
    )
    .unwrap();
    created.file.sync_all().unwrap();
    drop(created);

    let error = verify_journal_file(&path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn journal_file_rotate_suggested_matches_core_header_pressure_cases() {
    let mut header = build_empty_journal_file(
        JOURNAL_FILE_SIZE_MIN,
        SdId128([0x11; 16]),
        SdId128::null(),
        SdId128::null(),
        0,
        0,
    )
    .header;
    assert!(!journal_file_rotate_suggested(&header, None, 0));

    header.header_size = Header::SERIALIZED_LEN as u64 - 8;
    assert!(journal_file_rotate_suggested(&header, None, 0));

    let mut pressure = build_empty_journal_file(
        JOURNAL_FILE_SIZE_MIN,
        SdId128([0x11; 16]),
        SdId128::null(),
        SdId128::null(),
        0,
        0,
    )
    .header;
    let items = pressure.data_hash_table_size / HashItem::SERIALIZED_LEN as u64;
    pressure.n_data = (items * 3) / 4 + 1;
    assert!(journal_file_rotate_suggested(&pressure, None, 0));

    let mut collisions = pressure;
    collisions.n_data = 0;
    collisions.data_hash_chain_depth = HASH_CHAIN_DEPTH_MAX as u64 + 1;
    assert!(journal_file_rotate_suggested(&collisions, None, 0));

    let mut aged = build_empty_journal_file(
        JOURNAL_FILE_SIZE_MIN,
        SdId128([0x11; 16]),
        SdId128::null(),
        SdId128::null(),
        0,
        0,
    )
    .header;
    aged.head_entry_realtime = 10;
    assert!(journal_file_rotate_suggested(&aged, Some(5), 20));
}
