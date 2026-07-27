// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/libsystemd/sd-journal/test-journal-file.c

use libc::uid_t;

const NEG_EINVAL: i32 = -(libc::EINVAL as i32);
const NEG_EISDIR: i32 = -(libc::EISDIR as i32);
const NEG_ENXIO: i32 = -(libc::ENXIO as i32);
const NEG_EREMOTE: i32 = -(libc::EREMOTE as i32);

pub const UID_INVALID: uid_t = uid_t::MAX;

pub fn journal_file_parse_uid_from_filename(path: &str) -> Result<uid_t, i32> {
    if path.is_empty() || path.ends_with('/') {
        return Err(NEG_EISDIR);
    }

    let filename = path.rsplit('/').next().unwrap_or(path);
    let Some(uid_part) = filename.strip_prefix("user-") else {
        return Err(NEG_EREMOTE);
    };
    let Some(uid_part) = uid_part.strip_suffix(".journal") else {
        return Err(NEG_EREMOTE);
    };
    if uid_part.is_empty() || uid_part.contains('@') {
        return Err(NEG_EREMOTE);
    }

    let uid = uid_part.parse::<uid_t>().map_err(|_| NEG_EINVAL)?;
    if uid == 65535 {
        return Err(NEG_ENXIO);
    }
    Ok(uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_path_is_rejected() {
        assert_eq!(
            journal_file_parse_uid_from_filename("/var/log/journal/"),
            Err(NEG_EISDIR)
        );
    }

    #[test]
    fn unknown_name_shape_is_remote() {
        assert_eq!(
            journal_file_parse_uid_from_filename("system.journal"),
            Err(NEG_EREMOTE)
        );
    }

    #[test]
    fn archived_user_journal_is_remote() {
        assert_eq!(
            journal_file_parse_uid_from_filename("user-1000@dead-beef.journal~"),
            Err(NEG_EREMOTE)
        );
    }

    #[test]
    fn malformed_user_journal_is_remote() {
        assert_eq!(
            journal_file_parse_uid_from_filename("user-1000@xxx-yyy-zzz.journal"),
            Err(NEG_EREMOTE)
        );
    }

    #[test]
    fn valid_online_user_journal_parses_uid() {
        assert_eq!(
            journal_file_parse_uid_from_filename("user-1000.journal"),
            Ok(1000)
        );
    }

    #[test]
    fn non_numeric_uid_is_invalid() {
        assert_eq!(
            journal_file_parse_uid_from_filename("user-foo.journal"),
            Err(NEG_EINVAL)
        );
    }

    #[test]
    fn reserved_uid_is_rejected() {
        assert_eq!(
            journal_file_parse_uid_from_filename("user-65535.journal"),
            Err(NEG_ENXIO)
        );
    }

    #[test]
    fn nested_path_uses_basename() {
        assert_eq!(
            journal_file_parse_uid_from_filename("/var/log/journal/user-42.journal"),
            Ok(42)
        );
    }
}
