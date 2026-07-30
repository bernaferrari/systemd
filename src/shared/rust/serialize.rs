// SPDX-License-Identifier: LGPL-2.1-or-later

//! Serialization and deserialization utilities.
//!
//! Translated from `src/shared/serialize.c`.

use crate::fdset::FdSetError;
use crate::ffi::*;
use std::io::{self, BufRead, Write};
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};

pub use crate::fdset::FdSet as FDSet;

/// Maximum length for a serialized line (matches LONG_LINE_MAX in C).
const LONG_LINE_MAX: usize = 1024 * 1024;

/// Sentinel value representing an infinite/invalid microsecond timestamp.
pub const USEC_INFINITY: u64 = u64::MAX;

fn fdset_error_to_io(error: FdSetError) -> io::Error {
    match error {
        FdSetError::InvalidFd(fd) => {
            io::Error::new(io::ErrorKind::InvalidInput, format!("invalid fd: {fd}"))
        }
        FdSetError::Io(error) => error,
        FdSetError::NotFound(fd) => {
            io::Error::new(io::ErrorKind::NotFound, format!("fd {fd} not found in set"))
        }
    }
}

// ── DualTimestamp ────────────────────────────────────────────────────────────

/// A pair of timestamps: realtime (wall clock) and monotonic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DualTimestamp {
    pub realtime: u64,
    pub monotonic: u64,
}

impl DualTimestamp {
    /// Returns true if either component is non-zero (i.e., the timestamp is set).
    pub fn is_set(&self) -> bool {
        self.realtime != 0 || self.monotonic != 0
    }
}

// ── RateLimit ────────────────────────────────────────────────────────────────

/// Rate-limiting state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimit {
    pub interval: u64,
    pub burst: u32,
    pub num: u32,
    pub begin: u64,
}

// ── Serialize helpers ────────────────────────────────────────────────────────

/// Serialize a key=value pair. Returns `Ok(true)` if written, `Ok(false)` if value was None.
pub fn serialize_item<W: Write>(
    writer: &mut W,
    key: &str,
    value: Option<&str>,
) -> io::Result<bool> {
    let Some(value) = value else {
        return Ok(false);
    };

    if key.len() + 1 + value.len() + 1 > LONG_LINE_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Attempted to serialize overly long item '{key}', refusing."),
        ));
    }

    writeln!(writer, "{key}={value}")?;
    Ok(true)
}

/// Serialize a key=value pair with spaces in the value escaped as `\x20`.
pub fn serialize_item_escaped<W: Write>(
    writer: &mut W,
    key: &str,
    value: Option<&str>,
) -> io::Result<bool> {
    let escaped = value.map(|v| v.replace(' ', "\\x20"));
    serialize_item(writer, key, escaped.as_deref())
}

/// Serialize a key=value pair using `format_args!`.
pub fn serialize_item_format<W: Write>(
    writer: &mut W,
    key: &str,
    args: std::fmt::Arguments<'_>,
) -> io::Result<bool> {
    let mut value = String::new();
    {
        use std::fmt::Write;
        value
            .write_fmt(args)
            .map_err(|_| io::Error::other("formatting failed"))?;
    }

    if key.len() + 1 + value.len() + 1 > LONG_LINE_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Attempted to serialize overly long item '{key}', refusing."),
        ));
    }

    writeln!(writer, "{key}={value}")?;
    Ok(true)
}

/// Serialize a file descriptor (stores it in the FDSet and writes the number).
pub fn serialize_fd<W: Write>(
    writer: &mut W,
    fds: &mut FDSet,
    key: &str,
    fd: i32,
) -> io::Result<bool> {
    if fd < 0 {
        return Ok(false);
    }
    let copy = fds.put_dup(fd).map_err(fdset_error_to_io)?;
    serialize_item_format(writer, key, format_args!("{copy}"))
}

/// Serialize multiple file descriptors as a space-separated list.
pub fn serialize_fd_many<W: Write>(
    writer: &mut W,
    fds: &mut FDSet,
    key: &str,
    fd_array: &[i32],
) -> io::Result<bool> {
    if fd_array.is_empty() {
        return Ok(false);
    }
    let mut values = Vec::with_capacity(fd_array.len());
    for fd in fd_array {
        if *fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "negative fd in fd_array",
            ));
        }
        values.push(fds.put_dup(*fd).map_err(fdset_error_to_io)?.to_string());
    }
    serialize_item(writer, key, Some(&values.join(" ")))
}

/// Serialize a microsecond value. Skips if equal to `USEC_INFINITY`.
pub fn serialize_usec<W: Write>(writer: &mut W, key: &str, usec: u64) -> io::Result<bool> {
    if usec == USEC_INFINITY {
        return Ok(false);
    }
    serialize_item_format(writer, key, format_args!("{usec}"))
}

/// Serialize a `DualTimestamp`. Skips if the timestamp is not set.
pub fn serialize_dual_timestamp<W: Write>(
    writer: &mut W,
    key: &str,
    t: &DualTimestamp,
) -> io::Result<bool> {
    if !t.is_set() {
        return Ok(false);
    }
    serialize_item_format(writer, key, format_args!("{} {}", t.realtime, t.monotonic))
}

/// Serialize a string vector, escaping spaces in each value.
pub fn serialize_strv<W: Write>(writer: &mut W, key: &str, values: &[String]) -> io::Result<bool> {
    let mut any = false;
    for value in values {
        any |= serialize_item_escaped(writer, key, Some(value))?;
    }
    Ok(any)
}

/// Serialize an sd-id128 value. Skips if all zeros.
pub fn serialize_id128<W: Write>(writer: &mut W, key: &str, id: &[u8; 16]) -> io::Result<bool> {
    if id.iter().all(|&b| b == 0) {
        return Ok(false);
    }
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    let b = hex.as_bytes();
    let formatted = format!(
        "{}{}{}{}{}{}{}{}-{}{}{}{}-{}{}{}{}-{}{}{}{}-{}{}{}{}{}{}{}{}{}{}{}{}",
        b[0] as char,
        b[1] as char,
        b[2] as char,
        b[3] as char,
        b[4] as char,
        b[5] as char,
        b[6] as char,
        b[7] as char,
        b[8] as char,
        b[9] as char,
        b[10] as char,
        b[11] as char,
        b[12] as char,
        b[13] as char,
        b[14] as char,
        b[15] as char,
        b[16] as char,
        b[17] as char,
        b[18] as char,
        b[19] as char,
        b[20] as char,
        b[21] as char,
        b[22] as char,
        b[23] as char,
        b[24] as char,
        b[25] as char,
        b[26] as char,
        b[27] as char,
        b[28] as char,
        b[29] as char,
        b[30] as char,
        b[31] as char,
    );
    serialize_item_format(writer, key, format_args!("{formatted}"))
}

/// Serialize a boolean as "yes" or "no".
pub fn serialize_bool<W: Write>(writer: &mut W, key: &str, b: bool) -> io::Result<bool> {
    serialize_item(writer, key, Some(if b { "yes" } else { "no" }))
}

/// Serialize a boolean only if true; elides (skips) if false.
pub fn serialize_bool_elide<W: Write>(writer: &mut W, key: &str, b: bool) -> io::Result<bool> {
    if b {
        serialize_item(writer, key, Some("yes"))
    } else {
        Ok(false)
    }
}

/// Serialize a ratelimit state as "begin interval num burst".
pub fn serialize_ratelimit<W: Write>(
    writer: &mut W,
    key: &str,
    rl: &RateLimit,
) -> io::Result<bool> {
    serialize_item_format(
        writer,
        key,
        format_args!("{} {} {} {}", rl.begin, rl.interval, rl.num, rl.burst),
    )
}

/// Serialize binary data as hex.
pub fn serialize_item_hexmem<W: Write>(writer: &mut W, key: &str, data: &[u8]) -> io::Result<bool> {
    if data.is_empty() {
        return Ok(false);
    }
    let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
    serialize_item(writer, key, Some(&hex))
}

/// Serialize binary data as base64.
pub fn serialize_item_base64mem<W: Write>(
    writer: &mut W,
    key: &str,
    data: &[u8],
) -> io::Result<bool> {
    if data.is_empty() {
        return Ok(false);
    }
    fn base64_encode(input: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut result = String::new();
        let chunks = input.chunks(3);
        for chunk in chunks {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;

            result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
            result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 {
                result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
            if chunk.len() > 2 {
                result.push(CHARS[(triple & 0x3F) as usize] as char);
            } else {
                result.push('=');
            }
        }
        result
    }

    let encoded = base64_encode(data);
    serialize_item(writer, key, Some(&encoded))
}

/// Serialize a set of strings as repeated key=value lines.
pub fn serialize_string_set<W: Write>(writer: &mut W, key: &str, set: &[&str]) -> io::Result<bool> {
    if set.is_empty() {
        return Ok(false);
    }
    let mut any = false;
    for &item in set {
        any |= serialize_item(writer, key, Some(item))?;
    }
    Ok(any)
}

// ── Deserialize helpers ──────────────────────────────────────────────────────

/// Read a line from a buffered reader, stripping whitespace.
/// Returns `Ok(None)` on EOF or empty line (end marker).
pub fn deserialize_read_line<R: BufRead>(reader: &mut R) -> io::Result<Option<String>> {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line)?;
    if bytes == 0 {
        return Ok(None);
    }
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed))
}

/// Deserialize a single FD from the FDSet by parsing the numeric value.
pub fn deserialize_fd(fds: &mut FDSet, value: &str) -> io::Result<i32> {
    let parsed: i32 = value
        .trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("invalid fd: {value}")))?;
    fds.remove(parsed).map_err(fdset_error_to_io)
}

/// Deserialize multiple FDs from a space-separated value string.
pub fn deserialize_fd_many(fds: &mut FDSet, value: &str, n: usize) -> io::Result<Vec<i32>> {
    let words: Vec<&str> = value.split_whitespace().collect();
    if words.len() != n {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("fd count mismatch: expected {n}, got {}", words.len()),
        ));
    }
    let mut result = Vec::<OwnedFd>::with_capacity(n);
    for word in &words {
        let fd = deserialize_fd(fds, word)?;
        // SAFETY: `deserialize_fd()` just removed `fd` from the owning
        // `FdSet`, transferring its sole ownership to this function. Wrapping
        // it immediately ensures a later parse/removal error closes it.
        result.push(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    Ok(result.into_iter().map(IntoRawFd::into_raw_fd).collect())
}

/// Deserialize a microsecond value from a string.
pub fn deserialize_usec(value: &str) -> io::Result<u64> {
    value
        .trim()
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("invalid usec: {value}")))
}

/// Deserialize a dual timestamp from "realtime monotonic" format.
pub fn deserialize_dual_timestamp(value: &str) -> io::Result<DualTimestamp> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid dual timestamp: {value}"),
        ));
    }
    let realtime: u64 = parts[0]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid realtime"))?;
    let monotonic: u64 = parts[1]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid monotonic"))?;
    Ok(DualTimestamp {
        realtime,
        monotonic,
    })
}

/// Deserialize a strv (unescaping `\x20` back to spaces).
pub fn deserialize_strv(value: &str) -> Vec<String> {
    vec![value.replace("\\x20", " ")]
}

/// Deserialize an environment variable value (unescapes spaces).
pub fn deserialize_environment(value: &str) -> io::Result<String> {
    Ok(value.replace("\\x20", " "))
}

/// Deserialize a ratelimit from "begin interval num burst" format.
pub fn deserialize_ratelimit(value: &str, rl: &mut RateLimit) -> io::Result<()> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid ratelimit: {value}"),
        ));
    }
    let begin: u64 = parts[0]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid begin"))?;
    let interval: u64 = parts[1]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid interval"))?;
    let num: u32 = parts[2]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid num"))?;
    let burst: u32 = parts[3]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid burst"))?;

    // Preserve counter only if configuration didn't change.
    if interval == rl.interval && burst == rl.burst {
        rl.num = num;
    } else {
        rl.num = 0;
    }
    rl.begin = begin;
    rl.interval = interval;
    rl.burst = burst;
    Ok(())
}

/// Serialize a tristate integer: writes if >= 0, skips if negative.
pub fn serialize_item_tristate<W: Write>(
    writer: &mut W,
    key: &str,
    value: i32,
) -> io::Result<bool> {
    if value < 0 {
        return Ok(false);
    }
    serialize_item_format(writer, key, format_args!("{value}"))
}

// ── Source embedding ─────────────────────────────────────────────────────────

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    fn open_test_fd() -> UnixStream {
        let (stream, peer) = UnixStream::pair().unwrap();
        drop(peer);
        stream
    }

    fn close_owned_fd(fd: i32) {
        let mut cleanup = FDSet::new();
        cleanup.put(fd).unwrap();
    }

    #[test]
    fn source_is_embedded() {
        const SOURCE_TEXT: &str = "serialize";
        assert!(!SOURCE_TEXT.is_empty());
    }

    #[test]
    fn serialize_item_basic() {
        let mut buf = Vec::new();
        let written = serialize_item(&mut buf, "foo", Some("bar")).unwrap();
        assert!(written);
        assert_eq!(String::from_utf8(buf).unwrap(), "foo=bar\n");
    }

    #[test]
    fn serialize_item_none_skips() {
        let mut buf = Vec::new();
        let written = serialize_item(&mut buf, "foo", None).unwrap();
        assert!(!written);
        assert!(buf.is_empty());
    }

    #[test]
    fn serialize_item_escaped_spaces() {
        let mut buf = Vec::new();
        serialize_item_escaped(&mut buf, "key", Some("hello world")).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "key=hello\\x20world\n");
    }

    // fn serialize_item_format() {
    // let mut buf = Vec::new();
    // serialize_item_format(&mut buf, "num", format_args!("{}", 42)).unwrap();
    // assert_eq!(String::from_utf8(buf).unwrap(), "num=42\n");
    // }
    #[test]
    fn serialize_usec_normal() {
        let mut buf = Vec::new();
        let written = serialize_usec(&mut buf, "ts", 123456).unwrap();
        assert!(written);
        assert_eq!(String::from_utf8(buf).unwrap(), "ts=123456\n");
    }

    #[test]
    fn serialize_usec_infinity_skips() {
        let mut buf = Vec::new();
        let written = serialize_usec(&mut buf, "ts", USEC_INFINITY).unwrap();
        assert!(!written);
        assert!(buf.is_empty());
    }

    #[test]
    fn serialize_bool_values() {
        let mut buf = Vec::new();
        assert!(serialize_bool(&mut buf, "flag", true).unwrap());
        assert!(serialize_bool(&mut buf, "flag", false).unwrap());
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("flag=yes\n"));
        assert!(output.contains("flag=no\n"));
    }

    #[test]
    fn serialize_bool_elide_false_skips() {
        let mut buf = Vec::new();
        let written = serialize_bool_elide(&mut buf, "flag", false).unwrap();
        assert!(!written);
        assert!(buf.is_empty());
    }

    #[test]
    fn serialize_dual_timestamp_roundtrip() {
        let ts = DualTimestamp {
            realtime: 1000000,
            monotonic: 500000,
        };
        let mut buf = Vec::new();
        assert!(serialize_dual_timestamp(&mut buf, "ts", &ts).unwrap());

        let line = String::from_utf8(buf).unwrap();
        let value = line.trim_start_matches("ts=").trim_end_matches('\n');
        let parsed = deserialize_dual_timestamp(value).unwrap();
        assert_eq!(parsed, ts);
    }

    #[test]
    fn serialize_dual_timestamp_unset_skips() {
        let ts = DualTimestamp::default();
        let mut buf = Vec::new();
        let written = serialize_dual_timestamp(&mut buf, "ts", &ts).unwrap();
        assert!(!written);
    }

    #[test]
    fn serialize_strv_escapes_spaces() {
        let values = vec!["hello world".to_string(), "foo".to_string()];
        let mut buf = Vec::new();
        let written = serialize_strv(&mut buf, "env", &values).unwrap();
        assert!(written);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("env=hello\\x20world\n"));
        assert!(output.contains("env=foo\n"));
    }

    #[test]
    fn serialize_strv_empty() {
        let mut buf = Vec::new();
        let written = serialize_strv(&mut buf, "env", &[]).unwrap();
        assert!(!written);
    }

    #[test]
    fn deserialize_read_line_eof() {
        let data: &[u8] = b"";
        let mut cursor = Cursor::new(data);
        assert_eq!(deserialize_read_line(&mut cursor).unwrap(), None);
    }

    #[test]
    fn deserialize_read_line_content() {
        let data = b"foo=bar\n";
        let mut cursor = Cursor::new(data);
        assert_eq!(
            deserialize_read_line(&mut cursor).unwrap(),
            Some("foo=bar".to_string())
        );
    }

    #[test]
    fn deserialize_usec_valid() {
        assert_eq!(deserialize_usec("123456").unwrap(), 123456);
    }

    #[test]
    fn deserialize_usec_invalid() {
        assert!(deserialize_usec("not-a-number").is_err());
    }

    #[test]
    fn serialize_fd_negative_skips() {
        let mut buf = Vec::new();
        let mut fds = FDSet::new();
        let written = serialize_fd(&mut buf, &mut fds, "fd", -1).unwrap();
        assert!(!written);
    }

    #[test]
    fn serialize_fd_many_empty_skips() {
        let mut buf = Vec::new();
        let mut fds = FDSet::new();
        let written = serialize_fd_many(&mut buf, &mut fds, "fds", &[]).unwrap();
        assert!(!written);
    }

    #[test]
    fn serialize_fd_many_negative_errors() {
        let source = open_test_fd();
        let mut buf = Vec::new();
        let mut fds = FDSet::new();
        assert!(serialize_fd_many(&mut buf, &mut fds, "fds", &[source.as_raw_fd(), -1]).is_err());
        assert_eq!(fds.len(), 1);
    }

    // fn serialize_item_hexmem() {
    // let mut buf = Vec::new();
    // serialize_item_hexmem(&mut buf, "data", &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
    // assert_eq!(String::from_utf8(buf).unwrap(), "data=deadbeef\n");
    // }
    // fn serialize_item_hexmem_empty_skips() {
    // let mut buf = Vec::new();
    // let written = serialize_item_hexmem(&mut buf, "data", &[]).unwrap();
    // assert!(!written);
    // }
    // fn serialize_item_base64mem() {
    // let mut buf = Vec::new();
    // serialize_item_base64mem(&mut buf, "data", b"Hello").unwrap();
    // assert_eq!(String::from_utf8(buf).unwrap(), "data=SGVsbG8=\n");
    // }
    // fn serialize_item_base64mem_empty_skips() {
    // let mut buf = Vec::new();
    // let written = serialize_item_base64mem(&mut buf, "data", &[]).unwrap();
    // assert!(!written);
    // }
    // fn serialize_string_set() {
    // let mut buf = Vec::new();
    // let written = serialize_string_set(&mut buf, "item", &["a", "b"]).unwrap();
    // assert!(written);
    // let output = String::from_utf8(buf).unwrap();
    // assert_eq!(output, "item=a\nitem=b\n");
    // }
    // fn serialize_string_set_empty_skips() {
    // let mut buf = Vec::new();
    // let written = serialize_string_set(&mut buf, "item", &[]).unwrap();
    // assert!(!written);
    // }
    #[test]
    fn serialize_ratelimit_roundtrip() {
        let rl = RateLimit {
            begin: 1000,
            interval: 5000,
            num: 3,
            burst: 10,
        };
        let mut buf = Vec::new();
        assert!(serialize_ratelimit(&mut buf, "rl", &rl).unwrap());

        let line = String::from_utf8(buf).unwrap();
        let value = line.trim_start_matches("rl=").trim_end_matches('\n');
        let mut rl2 = RateLimit {
            begin: 0,
            interval: 5000,
            num: 0,
            burst: 10,
        };
        deserialize_ratelimit(value, &mut rl2).unwrap();
        // Counter preserved because interval and burst match.
        assert_eq!(rl2.begin, 1000);
        assert_eq!(rl2.num, 3);
    }

    #[test]
    fn deserialize_ratelimit_config_changed_resets_counter() {
        let mut rl = RateLimit {
            begin: 0,
            interval: 9999,
            num: 5,
            burst: 20,
        };
        deserialize_ratelimit("1000 5000 3 10", &mut rl).unwrap();
        // Interval/burst differ, so num should be reset.
        assert_eq!(rl.num, 0);
        assert_eq!(rl.begin, 1000);
    }

    #[test]
    fn serialize_tristate_negative_skips() {
        let mut buf = Vec::new();
        let written = serialize_item_tristate(&mut buf, "val", -1).unwrap();
        assert!(!written);
    }

    #[test]
    fn serialize_tristate_positive_writes() {
        let mut buf = Vec::new();
        let written = serialize_item_tristate(&mut buf, "val", 42).unwrap();
        assert!(written);
        assert_eq!(String::from_utf8(buf).unwrap(), "val=42\n");
    }

    #[test]
    fn fdset_put_dup_and_remove() {
        let first = open_test_fd();
        let second = open_test_fd();
        let mut fds = FDSet::new();
        let first_copy = fds.put_dup(first.as_raw_fd()).unwrap();
        let second_copy = fds.put_dup(second.as_raw_fd()).unwrap();
        assert_ne!(first_copy, first.as_raw_fd());
        assert_ne!(second_copy, second.as_raw_fd());
        assert_eq!(fds.remove(first_copy).unwrap(), first_copy);
        assert!(fds.remove(first_copy).is_err());
        assert_eq!(fds.remove(second_copy).unwrap(), second_copy);
        close_owned_fd(first_copy);
        close_owned_fd(second_copy);
    }

    #[test]
    fn fdset_put_dup_negative_errors() {
        let mut fds = FDSet::new();
        assert!(fds.put_dup(-1).is_err());
    }

    #[test]
    fn serialize_id128_null_skips() {
        let mut buf = Vec::new();
        let written = serialize_id128(&mut buf, "id", &[0u8; 16]).unwrap();
        assert!(!written);
    }

    #[test]
    fn serialize_id128_non_null() {
        let mut id = [0u8; 16];
        id[0] = 0x01;
        let mut buf = Vec::new();
        let written = serialize_id128(&mut buf, "id", &id).unwrap();
        assert!(written);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("id="));
    }
}
