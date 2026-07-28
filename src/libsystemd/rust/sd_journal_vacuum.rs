// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/journal-vacuum.c

use std::cmp::Ordering;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::sd_journal_file::Header;

const NEG_EINVAL: i32 = -(libc::EINVAL as i32);
const NEG_EIO: i32 = -(libc::EIO as i32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VacuumInfo {
    pub usage: u64,
    pub filename: String,
    pub realtime: u64,
    pub seqnum_id: [u8; 16],
    pub seqnum: u64,
    pub have_seqnum: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VacuumReport {
    pub freed: u64,
    pub deleted: Vec<String>,
    pub oldest_remaining: Option<u64>,
}

pub fn vacuum_info_compare(a: &VacuumInfo, b: &VacuumInfo) -> Ordering {
    if a.have_seqnum && b.have_seqnum && a.seqnum_id == b.seqnum_id {
        return a.seqnum.cmp(&b.seqnum);
    }
    a.realtime.cmp(&b.realtime).then_with(|| {
        if a.have_seqnum && b.have_seqnum {
            a.seqnum_id.cmp(&b.seqnum_id)
        } else {
            a.filename.cmp(&b.filename)
        }
    })
}

fn hex_decode_16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (idx, chunk) in s.as_bytes().chunks(2).enumerate() {
        let byte = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
        out[idx] = byte;
    }
    Some(out)
}

fn usage_from_stat(meta: &fs::Metadata) -> u64 {
    512u64.saturating_mul(meta.blocks())
}

fn header_n_entries_offset() -> usize {
    let header = std::mem::MaybeUninit::<Header>::uninit();
    let base = header.as_ptr();
    // SAFETY: no read occurs, we only compute field offset from an uninitialized repr(C) value.
    let field = unsafe { std::ptr::addr_of!((*base).n_entries) as usize };
    field - (base as usize)
}

fn journal_file_empty(path: &Path) -> Result<bool, i32> {
    let meta =
        fs::metadata(path).map_err(|e| -(e.raw_os_error().unwrap_or(libc::ENOENT) as i32))?;
    let min_header = std::mem::size_of::<Header>() as u64;
    if meta.len() < min_header {
        return Ok(true);
    }
    let bytes = fs::read(path).map_err(|_| NEG_EIO)?;
    let n_entries_offset = header_n_entries_offset();
    let Some(raw) = bytes.get(n_entries_offset..n_entries_offset + 8) else {
        return Err(NEG_EIO);
    };
    let mut buf = [0u8; 8];
    buf.copy_from_slice(raw);
    let n_entries = u64::from_le_bytes(buf);
    Ok(n_entries == 0)
}

fn patch_realtime(meta: &fs::Metadata, parsed_realtime: u64) -> u64 {
    fn to_usec(secs: i64, nanos: i64) -> Option<u64> {
        if secs < 0 || nanos < 0 {
            return None;
        }
        (secs as u64)
            .checked_mul(1_000_000)
            .and_then(|s| s.checked_add((nanos as u64) / 1_000))
    }

    let mut realtime = parsed_realtime;
    for candidate in [
        to_usec(meta.ctime(), meta.ctime_nsec()),
        to_usec(meta.atime(), meta.atime_nsec()),
        to_usec(meta.mtime(), meta.mtime_nsec()),
    ] {
        if let Some(ts) = candidate {
            realtime = realtime.min(ts);
        }
    }

    realtime
}

enum FileKind {
    Archived(VacuumInfo),
    ActiveJournalLike,
    Ignore,
}

fn parse_archived(name: &str, usage: u64) -> FileKind {
    if let Some(core) = name.strip_suffix(".journal") {
        if core.len() < 67 {
            return FileKind::ActiveJournalLike;
        }

        let at = core.len() - 67;
        let bytes = core.as_bytes();
        if bytes[at] != b'@' || bytes[at + 33] != b'-' || bytes[at + 50] != b'-' {
            return FileKind::ActiveJournalLike;
        }

        let Some(seqnum_id) = hex_decode_16(&core[at + 1..at + 33]) else {
            return FileKind::ActiveJournalLike;
        };
        let Ok(seqnum) = u64::from_str_radix(&core[at + 34..at + 50], 16) else {
            return FileKind::ActiveJournalLike;
        };
        let Ok(realtime) = u64::from_str_radix(&core[at + 51..at + 67], 16) else {
            return FileKind::ActiveJournalLike;
        };

        return FileKind::Archived(VacuumInfo {
            usage,
            filename: name.into(),
            realtime,
            seqnum_id,
            seqnum,
            have_seqnum: true,
        });
    }

    if let Some(core) = name.strip_suffix(".journal~") {
        if core.len() < 34 {
            return FileKind::ActiveJournalLike;
        }

        let at = core.len() - 34;
        let bytes = core.as_bytes();
        if bytes[at] != b'@' || bytes[at + 17] != b'-' {
            return FileKind::ActiveJournalLike;
        }

        let Ok(realtime) = u64::from_str_radix(&core[at + 1..at + 17], 16) else {
            return FileKind::ActiveJournalLike;
        };
        if u64::from_str_radix(&core[at + 18..at + 34], 16).is_err() {
            return FileKind::ActiveJournalLike;
        }

        return FileKind::Archived(VacuumInfo {
            usage,
            filename: name.into(),
            realtime,
            seqnum_id: [0; 16],
            seqnum: 0,
            have_seqnum: false,
        });
    }

    FileKind::Ignore
}

pub fn journal_directory_vacuum(
    directory: &Path,
    max_use: u64,
    n_max_files: u64,
    max_retention_usec: u64,
    now_usec: u64,
) -> Result<VacuumReport, i32> {
    let mut active_usage = 0u64;
    let mut active_files = 0u64;
    let mut archived = Vec::new();
    let mut report = VacuumReport::default();
    let retention_limit = if max_retention_usec > 0 {
        now_usec.saturating_sub(max_retention_usec)
    } else {
        0
    };

    for entry in
        fs::read_dir(directory).map_err(|e| -(e.raw_os_error().unwrap_or(libc::ENOENT) as i32))?
    {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let usage = usage_from_stat(&meta);
        match parse_archived(&name, usage) {
            FileKind::Archived(mut info) => match journal_file_empty(&path) {
                Ok(true) => match fs::remove_file(&path) {
                    Ok(()) => {
                        report.freed += usage;
                        report.deleted.push(name);
                    }
                    Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {}
                    Err(err) => return Err(-(err.raw_os_error().unwrap_or(libc::EIO) as i32)),
                },
                Ok(false) => {
                    info.realtime = patch_realtime(&meta, info.realtime);
                    archived.push(info);
                }
                Err(_) => {}
            },
            FileKind::ActiveJournalLike => {
                active_usage = active_usage.saturating_add(usage);
                active_files = active_files.saturating_add(1);
            }
            FileKind::Ignore => {}
        }
    }

    archived.sort_by(vacuum_info_compare);
    let mut archived_usage: u64 = archived.iter().map(|v| v.usage).sum();

    for (idx, info) in archived.iter().enumerate() {
        let left = active_files + (archived.len() - idx) as u64;
        let within_retention = max_retention_usec == 0 || info.realtime >= retention_limit;
        let within_size = max_use == 0 || active_usage + archived_usage <= max_use;
        let within_count = n_max_files == 0 || left <= n_max_files;
        if within_retention && within_size && within_count {
            report.oldest_remaining = Some(info.realtime);
            break;
        }

        let target: PathBuf = directory.join(info.filename.as_str());
        match fs::remove_file(&target) {
            Ok(()) => {
                report.freed = report.freed.saturating_add(info.usage);
                report.deleted.push(info.filename.clone());
                archived_usage = archived_usage.saturating_sub(info.usage);
            }
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {}
            Err(err) => return Err(-(err.raw_os_error().unwrap_or(libc::EIO) as i32)),
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmpdir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sd-journal-vacuum-{nonce}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn write_file(dir: &Path, name: &str, size: usize, n_entries: u64) {
        let mut data = vec![b'X'; size.max(std::mem::size_of::<Header>())];
        let offset = header_n_entries_offset();
        data[offset..offset + 8].copy_from_slice(&n_entries.to_le_bytes());
        fs::write(dir.join(name), data).unwrap();
    }

    fn file_usage(dir: &Path, name: &str) -> u64 {
        usage_from_stat(&fs::metadata(dir.join(name)).unwrap())
    }

    #[test]
    fn comparison_prefers_seqnum_with_same_id() {
        let a = VacuumInfo {
            usage: 1,
            filename: "a".into(),
            realtime: 5,
            seqnum_id: [1; 16],
            seqnum: 1,
            have_seqnum: true,
        };
        let b = VacuumInfo {
            usage: 1,
            filename: "b".into(),
            realtime: 1,
            seqnum_id: [1; 16],
            seqnum: 2,
            have_seqnum: true,
        };
        assert_eq!(vacuum_info_compare(&a, &b), Ordering::Less);
    }

    #[test]
    fn empty_archived_files_are_removed_unconditionally() {
        let dir = tmpdir();
        write_file(
            &dir,
            "x@11111111111111111111111111111111-0000000000000001-0000000000000001.journal",
            300,
            0,
        );
        let report = journal_directory_vacuum(&dir, 0, 0, 1, 10).unwrap();
        assert_eq!(report.deleted.len(), 1);
        assert!(report.freed > 0);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
    }

    #[test]
    fn active_files_are_preserved() {
        let dir = tmpdir();
        write_file(&dir, "system.journal", 300, 1);
        let report = journal_directory_vacuum(&dir, 1, 1, 1, 10).unwrap();
        assert_eq!(report.freed, 0);
        assert!(dir.join("system.journal").exists());
    }

    #[test]
    fn size_limit_deletes_oldest_archived_file() {
        let dir = tmpdir();
        write_file(
            &dir,
            "x@11111111111111111111111111111111-0000000000000001-0000000000000001.journal",
            300,
            1,
        );
        write_file(
            &dir,
            "x@11111111111111111111111111111111-0000000000000002-0000000000000002.journal",
            300,
            1,
        );
        let limit = file_usage(
            &dir,
            "x@11111111111111111111111111111111-0000000000000002-0000000000000002.journal",
        );
        let report = journal_directory_vacuum(&dir, limit, 0, 0, 10).unwrap();
        assert_eq!(report.deleted.len(), 1);
    }

    #[test]
    fn count_limit_deletes_until_limit_is_met() {
        let dir = tmpdir();
        write_file(
            &dir,
            "x@11111111111111111111111111111111-0000000000000001-0000000000000001.journal",
            300,
            1,
        );
        write_file(
            &dir,
            "x@11111111111111111111111111111111-0000000000000002-0000000000000002.journal",
            300,
            1,
        );
        write_file(&dir, "system.journal", 300, 1);
        let report = journal_directory_vacuum(&dir, 0, 2, 0, 10).unwrap();
        assert_eq!(report.deleted.len(), 1);
    }

    #[test]
    fn retention_limit_deletes_old_entries() {
        let dir = tmpdir();
        write_file(
            &dir,
            "x@11111111111111111111111111111111-0000000000000001-0000000000000001.journal",
            300,
            1,
        );
        write_file(
            &dir,
            "x@11111111111111111111111111111111-0000000000000002-0000000000000064.journal",
            300,
            1,
        );
        let report = journal_directory_vacuum(&dir, 0, 0, 10, 100).unwrap();
        assert_eq!(report.deleted.len(), 1);
    }

    #[test]
    fn oldest_remaining_is_reported() {
        let dir = tmpdir();
        write_file(
            &dir,
            "x@11111111111111111111111111111111-0000000000000001-0000000000000064.journal",
            300,
            1,
        );
        let report = journal_directory_vacuum(&dir, 0, 0, 1000, 100).unwrap();
        assert_eq!(report.oldest_remaining, Some(100));
    }

    #[test]
    fn unknown_files_are_ignored_for_limits() {
        let dir = tmpdir();
        write_file(&dir, "README.txt", 8192, 1);
        write_file(
            &dir,
            "x@11111111111111111111111111111111-0000000000000001-0000000000000001.journal",
            512,
            1,
        );
        write_file(
            &dir,
            "x@11111111111111111111111111111111-0000000000000002-0000000000000002.journal",
            512,
            1,
        );
        let limit = file_usage(
            &dir,
            "x@11111111111111111111111111111111-0000000000000002-0000000000000002.journal",
        );
        let report = journal_directory_vacuum(&dir, limit, 0, 0, 10).unwrap();
        assert_eq!(report.deleted.len(), 1);
        assert!(dir.join("README.txt").exists());
    }

    #[test]
    fn bad_directory_returns_errno() {
        assert!(journal_directory_vacuum(Path::new("/definitely/missing"), 0, 0, 0, 0).is_err());
    }
}
