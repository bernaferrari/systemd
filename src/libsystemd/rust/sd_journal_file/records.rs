// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/journal-file.c, src/libsystemd/sd-journal/journal-def.h
//

use super::index::{
    append_data_object, append_entry_object, append_field_object, find_data_object_with_hash,
    find_field_object_with_hash, link_data_object, link_data_object_into_field, link_entry_object,
    link_field_object,
};
use super::validation::validate_journal_header;
use super::wire::{
    COMPACT_DATA_OBJECT_STATIC_SIZE, COMPACT_ENTRY_ITEM_SIZE, DATA_OBJECT_STATIC_SIZE,
    ENTRY_OBJECT_STATIC_SIZE, HEADER_COMPATIBLE_SEALED, HEADER_COMPATIBLE_SEALED_CONTINUOUS,
    HEADER_COMPATIBLE_SUPPORTED, HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID, HEADER_INCOMPATIBLE_COMPACT,
    HEADER_INCOMPATIBLE_KEYED_HASH, HEADER_INCOMPATIBLE_SUPPORTED, Header,
    JOURNAL_COMPACT_SIZE_MAX, JournalAppendResult, JournalEntryItem, JournalFileOnDisk,
    JournalRecord, OBJECT_DATA, OBJECT_ENTRY, ObjectHeader, REGULAR_ENTRY_ITEM_SIZE, align64,
    build_empty_journal_file, jenkins_hash64, journal_hash_data, journal_uses_compact, read_array,
    read_journal_header, read_object_header_at, read_object_payload_bytes, read_u32_le,
    read_u64_le,
};
use crate::id128_util::SdId128;
use crate::sd_id128_api::{NEG_ENOMEDIUM, NEG_ENOPKG, sd_id128_get_machine};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub fn append_journal_record_unindexed(
    file: &mut File,
    header: &mut Header,
    realtime: u64,
    monotonic: u64,
    boot_id: SdId128,
    fields: &[&[u8]],
) -> io::Result<JournalAppendResult> {
    if fields.is_empty() || fields.len() > 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal entry field count is outside the canonical range",
        ));
    }
    if !super::wire::valid_realtime(realtime)
        || !super::wire::valid_monotonic(monotonic)
        || boot_id.is_null()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal entry has invalid timestamps or an empty boot ID",
        ));
    }

    let seqnum = header
        .tail_entry_seqnum
        .checked_add(1)
        .filter(|value| *value > 0)
        .unwrap_or(1);
    let mut xor_hash = 0u64;
    let mut items = Vec::with_capacity(fields.len());
    let mut data_offsets = Vec::with_capacity(fields.len());
    let mut field_offsets = Vec::with_capacity(fields.len());

    for field in fields {
        let Some(eq_index) = field.iter().position(|byte| *byte == b'=') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "journal field is missing '=' separator",
            ));
        };
        if eq_index == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "journal field name is empty",
            ));
        }

        let field_name = &field[..eq_index];
        if field_name.len() > 64
            || field_name[0].is_ascii_digit()
            || field_name
                .iter()
                .any(|byte| !byte.is_ascii_uppercase() && !byte.is_ascii_digit() && *byte != b'_')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "journal field name is invalid",
            ));
        }
        let field_hash = journal_hash_data(header, field_name)?;
        let data_hash = journal_hash_data(header, field)?;
        let existing_data = find_data_object_with_hash(file, header, field, data_hash)?;
        let (field_offset, data_offset) = if let Some(data_offset) = existing_data {
            let field_offset = find_field_object_with_hash(file, header, field_name, field_hash)?
                .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "data object exists without its field object",
                )
            })?;
            (field_offset, data_offset)
        } else {
            let field_offset = if let Some(existing) =
                find_field_object_with_hash(file, header, field_name, field_hash)?
            {
                existing
            } else {
                let offset = append_field_object(file, header, field_hash, field_name)?;
                link_field_object(file, header, offset, field_hash)?;
                offset
            };

            let data_offset = append_data_object(file, header, data_hash, field)?;
            link_data_object(file, header, data_offset, data_hash)?;
            link_data_object_into_field(file, data_offset, field_offset)?;
            (field_offset, data_offset)
        };

        xor_hash ^= if header.incompatible_flags & HEADER_INCOMPATIBLE_KEYED_HASH != 0 {
            jenkins_hash64(field)
        } else {
            data_hash
        };
        items.push(JournalEntryItem {
            object_offset: data_offset,
            hash: data_hash,
        });
        data_offsets.push(data_offset);
        field_offsets.push(field_offset);
    }

    items.sort_unstable_by_key(|item| item.object_offset);
    items.dedup_by_key(|item| item.object_offset);

    let entry_offset = append_entry_object(
        file, header, seqnum, realtime, monotonic, boot_id, xor_hash, &items,
    )?;
    link_entry_object(file, header, entry_offset, &items)?;

    Ok(JournalAppendResult {
        entry_offset,
        seqnum,
        xor_hash,
        data_offsets,
        field_offsets,
    })
}

pub fn read_journal_records(path: &Path) -> io::Result<Vec<JournalRecord>> {
    let mut journal = open_journal_file_at(path, false)?;
    let mut data_payloads = BTreeMap::<u64, Vec<u8>>::new();
    let mut records = Vec::new();
    let mut offset = journal.header.header_size;
    let end = journal
        .header
        .header_size
        .checked_add(journal.header.arena_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "journal arena end overflow"))?;

    while offset < end {
        let object_header = read_object_header_at(&mut journal.file, offset)?;
        if object_header.size < ObjectHeader::SERIALIZED_LEN as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal object smaller than object header",
            ));
        }

        match object_header.type_ {
            OBJECT_DATA => {
                let payload_offset = if journal_uses_compact(&journal.header) {
                    COMPACT_DATA_OBJECT_STATIC_SIZE
                } else {
                    DATA_OBJECT_STATIC_SIZE
                };
                let payload = read_object_payload_bytes(&mut journal.file, offset, payload_offset)?;
                data_payloads.insert(offset, payload);
            }
            OBJECT_ENTRY => {
                let payload = read_object_payload_bytes(
                    &mut journal.file,
                    offset,
                    ObjectHeader::SERIALIZED_LEN as u64,
                )?;
                let static_payload_size =
                    (ENTRY_OBJECT_STATIC_SIZE - ObjectHeader::SERIALIZED_LEN as u64) as usize;
                if payload.len() < static_payload_size {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "entry object smaller than fixed payload",
                    ));
                }

                let mut cursor = 0;
                let seqnum = read_u64_le(&payload, &mut cursor)?;
                let realtime = read_u64_le(&payload, &mut cursor)?;
                let monotonic = read_u64_le(&payload, &mut cursor)?;
                let boot_id = SdId128(read_array::<16>(&payload, &mut cursor)?);
                let xor_hash = read_u64_le(&payload, &mut cursor)?;
                let items = &payload[static_payload_size..];
                let mut fields = Vec::new();

                if journal_uses_compact(&journal.header) {
                    let mut chunks = items.chunks_exact(COMPACT_ENTRY_ITEM_SIZE as usize);
                    for chunk in &mut chunks {
                        let data_offset = read_u32_le(chunk, &mut 0)? as u64;
                        let field = data_payloads.get(&data_offset).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "entry references missing data object",
                            )
                        })?;
                        fields.push(field.clone());
                    }
                    if !chunks.remainder().is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "compact entry items have trailing bytes",
                        ));
                    }
                } else {
                    let mut chunks = items.chunks_exact(REGULAR_ENTRY_ITEM_SIZE as usize);
                    for chunk in &mut chunks {
                        let data_offset = read_u64_le(chunk, &mut 0)?;
                        let field = data_payloads.get(&data_offset).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "entry references missing data object",
                            )
                        })?;
                        fields.push(field.clone());
                    }
                    if !chunks.remainder().is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "entry items have trailing bytes",
                        ));
                    }
                }

                records.push(JournalRecord {
                    seqnum,
                    realtime,
                    monotonic,
                    boot_id,
                    xor_hash,
                    fields,
                });
            }
            _ => {}
        }

        let next = offset
            .checked_add(align64(object_header.size))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "journal object walk overflow")
            })?;
        if next <= offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal object walk did not advance",
            ));
        }
        offset = next;
    }

    Ok(records)
}

pub fn render_journal_file_as_text(path: &Path) -> io::Result<String> {
    let mut out = String::new();
    for record in read_journal_records(path)? {
        let mut first = true;
        for field in &record.fields {
            if !first {
                out.push('|');
            }
            first = false;
            out.push_str(&String::from_utf8_lossy(field));
        }
        out.push('\n');
    }
    Ok(out)
}

// The on-disk creation API needs each independently validated journal-file input.
#[allow(clippy::too_many_arguments)]
pub fn create_empty_journal_file_at(
    path: &Path,
    mode: u32,
    max_size: u64,
    file_id: SdId128,
    machine_id: SdId128,
    seqnum_id: SdId128,
    compatible_flags: u32,
    incompatible_flags: u32,
) -> io::Result<JournalFileOnDisk> {
    if file_id.is_null() || seqnum_id.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal file and sequence-number IDs must be non-null",
        ));
    }
    if compatible_flags & HEADER_COMPATIBLE_TAIL_ENTRY_BOOT_ID == 0
        || compatible_flags & !HEADER_COMPATIBLE_SUPPORTED != 0
        || incompatible_flags & !HEADER_INCOMPATIBLE_SUPPORTED != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "journal creation flags are unsupported or omit tail-entry boot-ID semantics",
        ));
    }
    if compatible_flags & (HEADER_COMPATIBLE_SEALED | HEADER_COMPATIBLE_SEALED_CONTINUOUS) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "cannot create a sealed journal without authentication support",
        ));
    }
    if incompatible_flags & HEADER_INCOMPATIBLE_COMPACT != 0 && max_size > JOURNAL_COMPACT_SIZE_MAX
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "compact journal maximum size exceeds the 32-bit offset format",
        ));
    }

    let layout = build_empty_journal_file(
        max_size,
        file_id,
        machine_id,
        seqnum_id,
        compatible_flags,
        incompatible_flags,
    );

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(&layout.bytes)?;
    file.sync_all()?;

    Ok(JournalFileOnDisk {
        path: path.to_path_buf(),
        file,
        header: layout.header,
    })
}

pub fn open_journal_file_at(path: &Path, writable: bool) -> io::Result<JournalFileOnDisk> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    if writable {
        options.write(true);
    }

    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.nlink() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal path is not a linked regular file",
        ));
    }
    let header = read_journal_header(&mut file)?;
    let file_len = metadata.len();
    validate_journal_header(&header, file_len, writable)?;
    if writable {
        let machine_id = match sd_id128_get_machine() {
            Ok(machine_id) => machine_id,
            Err(errno) if errno == NEG_ENOMEDIUM || errno == NEG_ENOPKG => SdId128::null(),
            Err(errno) => return Err(io::Error::from_raw_os_error(-errno)),
        };
        if machine_id != header.machine_id {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "refusing to write a journal owned by another machine",
            ));
        }
    }

    Ok(JournalFileOnDisk {
        path: path.to_path_buf(),
        file,
        header,
    })
}
