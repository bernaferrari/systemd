// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/journal-verify.c

use std::collections::{BTreeMap, BTreeSet};

const NEG_EBADMSG: i32 = -(libc::EBADMSG as i32);
const NEG_ENOKEY: i32 = -126; // ENOKEY = 126 (Linux)
const NEG_EOPNOTSUPP: i32 = -(libc::EOPNOTSUPP as i32);

pub const OBJECT_COMPRESSED_XZ: u8 = 1;
pub const OBJECT_COMPRESSED_LZ4: u8 = 2;
pub const OBJECT_COMPRESSED_ZSTD: u8 = 4;
pub const HEADER_COMPATIBLE_COMPRESSED_XZ: u32 = 1 << 0;
pub const HEADER_COMPATIBLE_COMPRESSED_LZ4: u32 = 1 << 1;
pub const HEADER_COMPATIBLE_COMPRESSED_ZSTD: u32 = 1 << 2;
pub const HEADER_COMPATIBLE_SEALED: u32 = 1 << 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectType {
    Data,
    Field,
    Entry,
    DataHashTable,
    FieldHashTable,
    EntryArray,
    Tag,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalObject {
    pub offset: u64,
    pub object_type: ObjectType,
    pub flags: u8,
    pub hash: u64,
    pub refs: Vec<u64>,
    pub seqnum: u64,
    pub realtime: u64,
    pub monotonic: u64,
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalFile {
    pub compatible_flags: u32,
    pub objects: Vec<JournalObject>,
    pub main_entry_array: Vec<u64>,
    pub data_hash_buckets: Vec<Vec<u64>>,
    pub tail_entry_seqnum: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifyStats {
    pub n_objects: u64,
    pub n_entries: u64,
    pub n_data: u64,
    pub n_fields: u64,
    pub n_entry_arrays: u64,
    pub n_tags: u64,
}

fn compression_allowed(file: &JournalFile, flags: u8) -> bool {
    (!matches!(flags & OBJECT_COMPRESSED_XZ, 0)
        || file.compatible_flags & HEADER_COMPATIBLE_COMPRESSED_XZ != 0)
        && (!matches!(flags & OBJECT_COMPRESSED_LZ4, 0)
            || file.compatible_flags & HEADER_COMPATIBLE_COMPRESSED_LZ4 != 0)
        && (!matches!(flags & OBJECT_COMPRESSED_ZSTD, 0)
            || file.compatible_flags & HEADER_COMPATIBLE_COMPRESSED_ZSTD != 0)
}

pub fn journal_file_verify(file: &JournalFile, key: Option<&str>) -> Result<VerifyStats, i32> {
    if key.is_some() && file.compatible_flags & HEADER_COMPATIBLE_SEALED == 0 {
        return Err(NEG_EOPNOTSUPP);
    }
    if key.is_none() && file.compatible_flags & HEADER_COMPATIBLE_SEALED != 0 {
        return Err(NEG_ENOKEY);
    }

    let by_offset = file
        .objects
        .iter()
        .map(|o| (o.offset, o))
        .collect::<BTreeMap<_, _>>();
    let mut stats = VerifyStats::default();
    let mut entry_offsets = BTreeSet::new();
    let mut data_offsets = BTreeSet::new();
    let mut last_seqnum = 0;

    for object in &file.objects {
        stats.n_objects += 1;
        if object.flags & (OBJECT_COMPRESSED_XZ | OBJECT_COMPRESSED_LZ4 | OBJECT_COMPRESSED_ZSTD)
            != 0
        {
            if object.object_type != ObjectType::Data || !compression_allowed(file, object.flags) {
                return Err(NEG_EBADMSG);
            }
        }

        match object.object_type {
            ObjectType::Data => {
                stats.n_data += 1;
                data_offsets.insert(object.offset);
            }
            ObjectType::Field => stats.n_fields += 1,
            ObjectType::Entry => {
                if object.seqnum == 0 || object.seqnum <= last_seqnum {
                    return Err(NEG_EBADMSG);
                }
                last_seqnum = object.seqnum;
                entry_offsets.insert(object.offset);
                stats.n_entries += 1;
            }
            ObjectType::EntryArray => stats.n_entry_arrays += 1,
            ObjectType::Tag => stats.n_tags += 1,
            ObjectType::DataHashTable | ObjectType::FieldHashTable => {}
        }
    }

    if last_seqnum != file.tail_entry_seqnum {
        return Err(NEG_EBADMSG);
    }

    let mut last = 0;
    for offset in &file.main_entry_array {
        if *offset <= last || !entry_offsets.contains(offset) {
            return Err(NEG_EBADMSG);
        }
        let entry = by_offset.get(offset).ok_or(NEG_EBADMSG)?;
        for data_ref in &entry.refs {
            if !data_offsets.contains(data_ref) {
                return Err(NEG_EBADMSG);
            }
        }
        last = *offset;
    }

    for data in file
        .objects
        .iter()
        .filter(|o| o.object_type == ObjectType::Data)
    {
        let bucket = if file.data_hash_buckets.is_empty() {
            0
        } else {
            (data.hash as usize) % file.data_hash_buckets.len()
        };
        if !file
            .data_hash_buckets
            .get(bucket)
            .is_some_and(|items| items.contains(&data.offset))
        {
            return Err(NEG_EBADMSG);
        }
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_file() -> JournalFile {
        JournalFile {
            compatible_flags: HEADER_COMPATIBLE_SEALED,
            tail_entry_seqnum: 2,
            main_entry_array: vec![30, 40],
            data_hash_buckets: vec![vec![10], vec![20]],
            objects: vec![
                JournalObject {
                    offset: 10,
                    object_type: ObjectType::Data,
                    flags: 0,
                    hash: 0,
                    refs: vec![],
                    seqnum: 0,
                    realtime: 0,
                    monotonic: 0,
                    epoch: 0,
                },
                JournalObject {
                    offset: 20,
                    object_type: ObjectType::Data,
                    flags: 0,
                    hash: 1,
                    refs: vec![],
                    seqnum: 0,
                    realtime: 0,
                    monotonic: 0,
                    epoch: 0,
                },
                JournalObject {
                    offset: 30,
                    object_type: ObjectType::Entry,
                    flags: 0,
                    hash: 0,
                    refs: vec![10],
                    seqnum: 1,
                    realtime: 10,
                    monotonic: 10,
                    epoch: 0,
                },
                JournalObject {
                    offset: 40,
                    object_type: ObjectType::Entry,
                    flags: 0,
                    hash: 0,
                    refs: vec![20],
                    seqnum: 2,
                    realtime: 20,
                    monotonic: 20,
                    epoch: 0,
                },
                JournalObject {
                    offset: 50,
                    object_type: ObjectType::Tag,
                    flags: 0,
                    hash: 0,
                    refs: vec![],
                    seqnum: 0,
                    realtime: 0,
                    monotonic: 0,
                    epoch: 1,
                },
            ],
        }
    }

    #[test]
    fn sealed_file_requires_key() {
        assert_eq!(journal_file_verify(&good_file(), None), Err(NEG_ENOKEY));
    }

    #[test]
    fn unsealed_file_rejects_verification_key() {
        let mut file = good_file();
        file.compatible_flags = 0;
        assert_eq!(journal_file_verify(&file, Some("key")), Err(NEG_EOPNOTSUPP));
    }

    #[test]
    fn valid_file_returns_stats() {
        let stats = journal_file_verify(&good_file(), Some("key")).unwrap();
        assert_eq!(stats.n_objects, 5);
        assert_eq!(stats.n_entries, 2);
        assert_eq!(stats.n_data, 2);
    }

    #[test]
    fn compressed_non_data_object_is_rejected() {
        let mut file = good_file();
        file.objects[2].flags = OBJECT_COMPRESSED_XZ;
        assert_eq!(journal_file_verify(&file, Some("key")), Err(NEG_EBADMSG));
    }

    #[test]
    fn missing_compression_capability_is_rejected() {
        let mut file = good_file();
        file.objects[0].flags = OBJECT_COMPRESSED_XZ;
        file.compatible_flags &= !HEADER_COMPATIBLE_COMPRESSED_XZ;
        assert_eq!(journal_file_verify(&file, Some("key")), Err(NEG_EBADMSG));
    }

    #[test]
    fn entry_seqnums_must_increase() {
        let mut file = good_file();
        file.objects[3].seqnum = 1;
        file.tail_entry_seqnum = 1;
        assert_eq!(journal_file_verify(&file, Some("key")), Err(NEG_EBADMSG));
    }

    #[test]
    fn main_entry_array_must_be_sorted_and_valid() {
        let mut file = good_file();
        file.main_entry_array = vec![40, 30];
        assert_eq!(journal_file_verify(&file, Some("key")), Err(NEG_EBADMSG));
    }

    #[test]
    fn entry_data_reference_must_exist() {
        let mut file = good_file();
        file.objects[2].refs = vec![999];
        assert_eq!(journal_file_verify(&file, Some("key")), Err(NEG_EBADMSG));
    }

    #[test]
    fn data_object_must_appear_in_hash_bucket() {
        let mut file = good_file();
        file.data_hash_buckets = vec![vec![], vec![20]];
        assert_eq!(journal_file_verify(&file, Some("key")), Err(NEG_EBADMSG));
    }
}
