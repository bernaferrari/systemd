// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/open-file.c, src/shared/open-file.h
//
// Open file descriptor specification parsing, validation, and serialization.
//
// Handles the `OpenFile=` unit setting format: `/path:fdname:read-only,append,...`

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum length for a file descriptor name (same as Linux's `FDNAME_MAX`).
const FDNAME_MAX: usize = 255;

// ── Enums ─────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling how a file is opened when passed to a service.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OpenFileFlags: u32 {
        const READ_ONLY = 1 << 0;
        const APPEND    = 1 << 1;
        const TRUNCATE  = 1 << 2;
        const GRACEFUL  = 1 << 3;
    }
}

// ── Structs ───────────────────────────────────────────────────────────────

/// Parsed representation of an `OpenFile=` specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenFile {
    /// Absolute path to the file on the host.
    pub path: String,
    /// Name exposed as `FDNAME` in the file-descriptor store.
    pub fdname: String,
    /// Bitmask of [`OpenFileFlags`].
    pub flags: OpenFileFlags,
}

// ── Validation helpers ────────────────────────────────────────────────────

/// Check whether a byte is a valid fdname character.
///
/// Valid fdname characters are ASCII alphanumeric, hyphen, and underscore.
fn is_fdname_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.'
}

/// Check whether a string is a valid file descriptor name.
///
/// A valid fdname is non-empty, at most `FDNAME_MAX` bytes, and contains
/// only ASCII alphanumeric characters, hyphens, and underscores.
fn fdname_is_valid(s: &str) -> bool {
    !s.is_empty() && s.len() <= FDNAME_MAX && s.bytes().all(is_fdname_char)
}

/// Check whether a path is syntactically valid and absolute.
///
/// A valid path is non-empty, does not contain a NUL byte, and starts
/// with `/`.
fn path_is_valid_absolute(p: &str) -> bool {
    !p.is_empty() && p.starts_with('/') && !p.contains('\0')
}

// ── Flag name table ──────────────────────────────────────────────────────

static FLAG_NAMES: &[(OpenFileFlags, &str)] = &[
    (OpenFileFlags::READ_ONLY, "read-only"),
    (OpenFileFlags::APPEND, "append"),
    (OpenFileFlags::TRUNCATE, "truncate"),
    (OpenFileFlags::GRACEFUL, "graceful"),
];

/// Parse a single flag name into its flag value.
fn parse_flag_name(s: &str) -> Result<OpenFileFlags, i32> {
    for &(flag, name) in FLAG_NAMES {
        if s == name {
            return Ok(flag);
        }
    }
    Err(-libc::EINVAL)
}

// ── Escape helper ────────────────────────────────────────────────────────

/// Escape colons in a path string, mirroring the C `xescape(path, ":")`.
fn escape_colons(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch == ':' {
            out.push_str("\\x3a");
        } else if ch == '\\' {
            out.push_str("\\x5c");
        } else {
            out.push(ch);
        }
    }
    out
}

/// Extract the filename component from a path (equivalent to `path_extract_filename`).
fn path_extract_filename(p: &str) -> Option<&str> {
    let trimmed = p.trim_end_matches('/');
    if trimmed.is_empty() || !trimmed.contains('/') {
        return None;
    }
    trimmed.rsplit('/').next()
}

// ── Public API ───────────────────────────────────────────────────────────

/// Validate an [`OpenFile`] record.
///
/// Returns `Ok(())` when the record is well-formed, or `Err(-EINVAL)` otherwise.
pub fn open_file_validate(of: &OpenFile) -> Result<(), i32> {
    if !path_is_valid_absolute(&of.path) {
        return Err(-libc::EINVAL);
    }

    if !fdname_is_valid(&of.fdname) {
        return Err(-libc::EINVAL);
    }

    // At most one of read-only / append / truncate may be set.
    let exclusive_count = [
        OpenFileFlags::READ_ONLY,
        OpenFileFlags::APPEND,
        OpenFileFlags::TRUNCATE,
    ]
    .iter()
    .filter(|flag| of.flags.contains(**flag))
    .count();

    if exclusive_count > 1 {
        return Err(-libc::EINVAL);
    }

    // Reject unknown / internal flags.
    let public = OpenFileFlags::READ_ONLY
        | OpenFileFlags::APPEND
        | OpenFileFlags::TRUNCATE
        | OpenFileFlags::GRACEFUL;

    if !of.flags.difference(public).is_empty() {
        return Err(-libc::EINVAL);
    }

    Ok(())
}

/// Parse an `OpenFile=` specification string.
///
/// Format: `/path[:fdname][:flags]` where `flags` is a comma-separated list
/// drawn from `read-only`, `append`, `truncate`, `graceful`.
///
/// If `fdname` is omitted, the filename portion of `path` is used.
pub fn open_file_parse(text: &str) -> Result<OpenFile, i32> {
    // Split into at most 3 colon-separated fields.
    // The C code uses EXTRACT_DONT_COALESCE_SEPARATORS, meaning consecutive
    // colons produce empty fields (not skipped).
    let mut iter = text.splitn(4, ':');
    let path = iter.next().ok_or(-libc::EINVAL)?;
    if path.is_empty() {
        return Err(-libc::EINVAL);
    }

    let fdname_raw = iter.next().unwrap_or("");
    let options_raw = iter.next().unwrap_or("");

    // Enforce at most 3 colon-separated words (C rejects leftover text).
    if iter.next().is_some() {
        return Err(-libc::EINVAL);
    }

    // Parse comma-separated flags.
    let mut flags = OpenFileFlags::empty();
    if !options_raw.is_empty() {
        for word in options_raw.split(',') {
            if word.is_empty() {
                continue;
            }
            let flag = parse_flag_name(word)?;
            if flags.intersects(flag) {
                return Err(-libc::EINVAL);
            }
            flags |= flag;
        }
    }

    // Resolve fdname: if empty, derive from path filename.
    let fdname = if fdname_raw.is_empty() {
        path_extract_filename(path).ok_or(-libc::EINVAL)?.to_owned()
    } else {
        fdname_raw.to_owned()
    };

    let of = OpenFile {
        path: path.to_owned(),
        fdname,
        flags,
    };

    open_file_validate(&of)?;
    Ok(of)
}

/// Serialize an [`OpenFile`] back to its string representation.
///
/// Produces a string that, when passed to [`open_file_parse`], yields an
/// equivalent record.
pub fn open_file_to_string(of: &OpenFile) -> String {
    let mut s = escape_colons(&of.path);

    let filename = path_extract_filename(&of.path);
    let has_fdname = filename.map_or(true, |f| f != of.fdname);

    // Build option string.
    let opts: Vec<&str> = FLAG_NAMES
        .iter()
        .filter(|(flag, _)| of.flags.contains(*flag))
        .map(|(_, name)| *name)
        .collect();

    if has_fdname && opts.is_empty() {
        s.push(':');
        s.push_str(&of.fdname);
    } else if has_fdname && !opts.is_empty() {
        s.push(':');
        s.push_str(&of.fdname);
        s.push(':');
        s.push_str(&opts.join(","));
    } else if !has_fdname && !opts.is_empty() {
        s.push_str("::");
        s.push_str(&opts.join(","));
    }

    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Validation ──────────────────────────────────────────────────────

    #[test]
    fn test_validate_ok() {
        let of = OpenFile {
            path: "/tmp/log.txt".into(),
            fdname: "log".into(),
            flags: OpenFileFlags::APPEND,
        };
        assert!(open_file_validate(&of).is_ok());
    }

    #[test]
    fn test_validate_rejects_relative_path() {
        let of = OpenFile {
            path: "relative/path".into(),
            fdname: "log".into(),
            flags: OpenFileFlags::empty(),
        };
        assert_eq!(open_file_validate(&of), Err(-libc::EINVAL));
    }

    #[test]
    fn test_validate_rejects_empty_path() {
        let of = OpenFile {
            path: String::new(),
            fdname: "log".into(),
            flags: OpenFileFlags::empty(),
        };
        assert_eq!(open_file_validate(&of), Err(-libc::EINVAL));
    }

    #[test]
    fn test_validate_rejects_bad_fdname() {
        let of = OpenFile {
            path: "/tmp/log".into(),
            fdname: "has/slash".into(),
            flags: OpenFileFlags::empty(),
        };
        assert_eq!(open_file_validate(&of), Err(-libc::EINVAL));
    }

    #[test]
    fn test_validate_rejects_exclusive_flags() {
        let of = OpenFile {
            path: "/tmp/log".into(),
            fdname: "log".into(),
            flags: OpenFileFlags::READ_ONLY | OpenFileFlags::APPEND,
        };
        assert_eq!(open_file_validate(&of), Err(-libc::EINVAL));
    }

    #[test]
    fn test_validate_rejects_three_exclusive_flags() {
        let of = OpenFile {
            path: "/tmp/log".into(),
            fdname: "log".into(),
            flags: OpenFileFlags::READ_ONLY | OpenFileFlags::APPEND | OpenFileFlags::TRUNCATE,
        };
        assert_eq!(open_file_validate(&of), Err(-libc::EINVAL));
    }

    // ── Parse ───────────────────────────────────────────────────────────

    #[test]
    fn test_parse_path_only() {
        let of = open_file_parse("/tmp/out.log").unwrap();
        assert_eq!(of.path, "/tmp/out.log");
        assert_eq!(of.fdname, "out.log");
        assert_eq!(of.flags, OpenFileFlags::empty());
    }

    #[test]
    fn test_parse_path_and_fdname() {
        let of = open_file_parse("/tmp/out.log:mylog").unwrap();
        assert_eq!(of.path, "/tmp/out.log");
        assert_eq!(of.fdname, "mylog");
    }

    #[test]
    fn test_parse_all_fields() {
        let of = open_file_parse("/tmp/out.log:log:append,graceful").unwrap();
        assert_eq!(of.path, "/tmp/out.log");
        assert_eq!(of.fdname, "log");
        assert!(of.flags.contains(OpenFileFlags::APPEND));
        assert!(of.flags.contains(OpenFileFlags::GRACEFUL));
        assert!(!of.flags.contains(OpenFileFlags::READ_ONLY));
    }

    #[test]
    fn test_parse_options_without_fdname() {
        let of = open_file_parse("/tmp/out.log::read-only").unwrap();
        assert_eq!(of.path, "/tmp/out.log");
        assert_eq!(of.fdname, "out.log");
        assert!(of.flags.contains(OpenFileFlags::READ_ONLY));
    }

    #[test]
    fn test_parse_rejects_too_many_colons() {
        assert!(open_file_parse("/tmp/a:b:c:d").is_err());
    }

    #[test]
    fn test_parse_rejects_empty_input() {
        assert!(open_file_parse("").is_err());
    }

    #[test]
    fn test_parse_rejects_duplicate_flag() {
        assert!(open_file_parse("/tmp/a:log:append,append").is_err());
    }

    #[test]
    fn test_parse_rejects_unknown_flag() {
        assert!(open_file_parse("/tmp/a:log:nope").is_err());
    }

    #[test]
    fn test_parse_rejects_non_absolute_path() {
        assert!(open_file_parse("relative:log").is_err());
    }

    // ── Serialize ───────────────────────────────────────────────────────

    #[test]
    fn test_to_string_path_only() {
        let of = OpenFile {
            path: "/tmp/out.log".into(),
            fdname: "out.log".into(),
            flags: OpenFileFlags::empty(),
        };
        assert_eq!(open_file_to_string(&of), "/tmp/out.log");
    }

    #[test]
    fn test_to_string_with_fdname() {
        let of = OpenFile {
            path: "/tmp/out.log".into(),
            fdname: "mylog".into(),
            flags: OpenFileFlags::empty(),
        };
        assert_eq!(open_file_to_string(&of), "/tmp/out.log:mylog");
    }

    #[test]
    fn test_to_string_with_options_no_fdname() {
        let of = OpenFile {
            path: "/tmp/out.log".into(),
            fdname: "out.log".into(),
            flags: OpenFileFlags::APPEND,
        };
        assert_eq!(open_file_to_string(&of), "/tmp/out.log::append");
    }

    #[test]
    fn test_to_string_with_fdname_and_options() {
        let of = OpenFile {
            path: "/tmp/out.log".into(),
            fdname: "log".into(),
            flags: OpenFileFlags::APPEND | OpenFileFlags::GRACEFUL,
        };
        assert_eq!(open_file_to_string(&of), "/tmp/out.log:log:append,graceful");
    }

    // ── Roundtrip ───────────────────────────────────────────────────────

    #[test]
    fn test_roundtrip_full() {
        let of = open_file_parse("/tmp/out.log:log:append,graceful").unwrap();
        let s = open_file_to_string(&of);
        let of2 = open_file_parse(&s).unwrap();
        assert_eq!(of, of2);
    }

    #[test]
    fn test_roundtrip_path_only() {
        let of = open_file_parse("/var/log/journal").unwrap();
        let s = open_file_to_string(&of);
        let of2 = open_file_parse(&s).unwrap();
        assert_eq!(of, of2);
    }

    #[test]
    fn test_roundtrip_options_no_fdname() {
        let of = open_file_parse("/tmp/f::truncate").unwrap();
        let s = open_file_to_string(&of);
        let of2 = open_file_parse(&s).unwrap();
        assert_eq!(of, of2);
    }

    // ── fdname validation ───────────────────────────────────────────────

    #[test]
    fn test_fdname_valid() {
        assert!(fdname_is_valid("foo"));
        assert!(fdname_is_valid("foo_bar"));
        assert!(fdname_is_valid("foo-bar"));
        assert!(fdname_is_valid("ABC123"));
        assert!(fdname_is_valid(&"a".repeat(FDNAME_MAX)));
    }

    #[test]
    fn test_fdname_invalid() {
        assert!(!fdname_is_valid(""));
        assert!(!fdname_is_valid("foo/bar"));
        assert!(!fdname_is_valid(&"a".repeat(FDNAME_MAX + 1)));
        assert!(!fdname_is_valid("has space"));
    }

    // ── Escape ──────────────────────────────────────────────────────────

    #[test]
    fn test_escape_colons() {
        assert_eq!(escape_colons("/tmp/a:b"), "/tmp/a\\x3ab");
        assert_eq!(escape_colons("/tmp/a"), "/tmp/a");
        assert_eq!(escape_colons("/tmp\\a"), "/tmp\\x5ca");
    }
}
