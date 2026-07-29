// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/clock-util.c, src/shared/clock-util.h
//
// Clock utility functions for determining hardware clock mode (UTC vs local)
// and setting the system timezone from the kernel's perspective.

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::mem::MaybeUninit;
use std::path::Path;

// ── Constants ─────────────────────────────────────────────────────────────

/// Default path to the adjtime configuration file.
pub const DEFAULT_ADJTIME_PATH: &str = "/etc/adjtime";

/// Path to the clock epoch file.
pub const EPOCH_CLOCK_FILE: &str = "/usr/lib/clock-epoch";

/// Directory containing the timesyncd clock file.
pub const TIMESYNCD_CLOCK_FILE_DIR: &str = "/var/lib/systemd/timesync/";

/// Path to the timesyncd clock file.
pub const TIMESYNCD_CLOCK_FILE: &str = "/var/lib/systemd/timesync/clock";

/// Maximum adjtime line length, matching C's `LONG_LINE_MAX`.
const ADJTIME_LINE_MAX: usize = 1024 * 1024;

const EOL_CR: u8 = 1;
const EOL_LF: u8 = 2;
const EOL_NUL: u8 = 4;

/// Read one `read_line()`-compatible byte line from an adjtime file.
///
/// The C authority accepts CR, LF, and NUL line delimiters (including a
/// mixed CRLF/NUL terminator), excludes delimiters from the returned line,
/// and rejects a line that reaches `LONG_LINE_MAX`. `BufRead::lines()` is
/// deliberately not used: it would accept an unbounded line, treat only LF
/// as a delimiter, and decode arbitrary file bytes as UTF-8.
fn read_adjtime_line<R: BufRead>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let mut previous_eol = 0;
    let mut consumed = false;

    loop {
        // C's read_line_full() checks the byte limit before examining the
        // next byte, including a possible trailing delimiter.
        if line.len() >= ADJTIME_LINE_MAX {
            return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
        }

        let byte = match reader.fill_buf()? {
            [] => break,
            bytes => bytes[0],
        };
        let eol = match byte {
            b'\r' => EOL_CR,
            b'\n' => EOL_LF,
            0 => EOL_NUL,
            _ => 0,
        };

        // Keep the first non-delimiter after a completed terminator for the
        // next call. This mirrors C's ungetc() path for CR/LF/NUL sequences.
        if previous_eol & EOL_NUL != 0
            || (eol == 0 && previous_eol != 0)
            || (eol != 0 && previous_eol & eol != 0)
        {
            break;
        }

        reader.consume(1);
        consumed = true;
        if eol != 0 {
            previous_eol |= eol;
        } else {
            line.push(byte);
        }
    }

    if consumed { Ok(Some(line)) } else { Ok(None) }
}

// ── clock_is_localtime ────────────────────────────────────────────────────

/// Determines whether the hardware (RTC) clock is set to local time.
///
/// Reads `/etc/adjtime` (or the provided path) and checks the third line.
/// The file format is:
/// ```text
/// 0.0 0 0
/// 0
/// UTC
/// ```
///
/// Returns `Ok(true)` if the third line is exactly `"LOCAL"`, `Ok(false)` if
/// the file is missing or the third line is `"UTC"` or absent (defaulting to UTC).
///
/// # Errors
///
/// Returns an I/O error if the file exists but cannot be read (permissions, etc.).
/// A missing file is **not** an error — it defaults to `false` (UTC).
pub fn clock_is_localtime<P: AsRef<Path>>(adjtime_path: Option<P>) -> io::Result<bool> {
    let path = adjtime_path
        .as_ref()
        .map(|p| p.as_ref())
        .unwrap_or(Path::new(DEFAULT_ADJTIME_PATH));

    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };

    let mut reader = BufReader::new(file);

    // Skip the first two lines (adjustment data and drift factor).
    for _ in 0..2 {
        if read_adjtime_line(&mut reader)?.is_none() {
            return Ok(false); // fewer than three lines → default to UTC
        }
    }

    // The third line contains "UTC", "LOCAL", or nothing.
    // `read_line()` in the C authority removes only the line terminator;
    // `streq()` then requires an exact byte token. Do not accept leading or
    // trailing whitespace, or invalid UTF-8, here.
    Ok(read_adjtime_line(&mut reader)?.as_deref() == Some(b"LOCAL"))
}

// ── clock_set_timezone ────────────────────────────────────────────────────

/// Result of setting the system timezone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimezoneInfo {
    /// Offset from UTC in minutes (positive east of Greenwich).
    pub minutes_delta: i32,
}

/// Sets the kernel timezone based on the current local time offset.
///
/// Retrieves the current local time, computes the UTC offset in minutes,
/// and calls `settimeofday(NULL, &tz)` to inform the kernel of the timezone
/// without changing the system clock.
///
/// This is needed when the RTC runs in local time rather than UTC: the first
/// call to `settimeofday` sets the kernel's timezone and warps the system clock
/// so it runs in UTC instead.
///
/// # Returns
///
/// `Ok(TimezoneInfo)` on success with the computed UTC offset in minutes.
///
/// # Errors
///
/// Returns an error if the local time cannot be determined or if `settimeofday`
/// fails.
///
/// # Platform support
///
/// Only available on Linux. On other platforms, returns an error with
/// `ErrorKind::Unsupported`.
#[cfg(target_os = "linux")]
pub fn clock_set_timezone() -> io::Result<TimezoneInfo> {
    // SAFETY: `time(NULL)` has no pointer precondition and the returned
    // scalar is checked for its documented error sentinel before use.
    let now_epoch = unsafe { libc::time(std::ptr::null_mut()) };
    if now_epoch == -1 {
        return Err(io::Error::last_os_error());
    }

    let mut tm = MaybeUninit::<libc::tm>::uninit();
    // SAFETY: `now_epoch` and the uninitialized output storage both live for
    // the full call; `localtime_r()` initializes the storage on non-null
    // success and avoids `localtime()`'s shared static buffer.
    let raw_tm = unsafe { libc::localtime_r(&now_epoch, tm.as_mut_ptr()) };
    if raw_tm.is_null() {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: the successful `localtime_r()` result above guarantees that
    // the `MaybeUninit<tm>` output is fully initialized.
    let tm = unsafe { tm.assume_init() };
    let minutes_delta = (tm.tm_gmtoff / 60) as i32;

    let tz = libc::timezone {
        tz_minuteswest: -minutes_delta,
        tz_dsttime: 0, // DST_NONE
    };

    // SAFETY: the null timeval requests no clock update and `tz` is a live,
    // correctly initialized timezone structure for the duration of the call.
    let ret = unsafe { libc::settimeofday(std::ptr::null(), &tz) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(TimezoneInfo { minutes_delta })
}

/// Non-Linux fallback: always returns an error.
#[cfg(not(target_os = "linux"))]
pub fn clock_set_timezone() -> io::Result<TimezoneInfo> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "clock_set_timezone is only supported on Linux",
    ))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use tempfile::NamedTempFile;

    // Helper: write an adjtime file with the given third line (or no third line).
    fn write_adjtime(third_line: Option<&str>) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "0.0 0 0").unwrap();
        writeln!(f, "0").unwrap();
        if let Some(line) = third_line {
            writeln!(f, "{}", line).unwrap();
        }
        f
    }

    // ── clock_is_localtime tests ──────────────────────────────────────────

    #[test]
    fn test_localtime_utc_returns_false() {
        let f = write_adjtime(Some("UTC"));
        assert_eq!(clock_is_localtime(Some(f.path())).unwrap(), false);
    }

    #[test]
    fn test_localtime_local_returns_true() {
        let f = write_adjtime(Some("LOCAL"));
        assert_eq!(clock_is_localtime(Some(f.path())).unwrap(), true);
    }

    #[test]
    fn test_localtime_missing_file_defaults_utc() {
        let result = clock_is_localtime(Some("/nonexistent/path/adjtime"));
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_localtime_none_path_uses_default() {
        // With no /etc/adjtime present (or inaccessible), defaults to UTC.
        let result = clock_is_localtime::<&str>(None);
        // This may succeed with false (file missing) or fail (permission denied).
        // Either way, we just check it doesn't panic.
        let _ = result;
    }

    #[test]
    fn test_localtime_only_two_lines_defaults_utc() {
        let f = write_adjtime(None);
        assert_eq!(clock_is_localtime(Some(f.path())).unwrap(), false);
    }

    #[test]
    fn test_localtime_empty_file_defaults_utc() {
        let f = NamedTempFile::new().unwrap();
        assert_eq!(clock_is_localtime(Some(f.path())).unwrap(), false);
    }

    #[test]
    fn test_localtime_third_line_with_whitespace() {
        let f = write_adjtime(Some("  LOCAL  "));
        assert_eq!(clock_is_localtime(Some(f.path())).unwrap(), false);
    }

    #[test]
    fn test_localtime_third_line_random_text() {
        let f = write_adjtime(Some("FOOBAR"));
        assert_eq!(clock_is_localtime(Some(f.path())).unwrap(), false);
    }

    #[test]
    fn test_localtime_single_line_defaults_utc() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "0.0 0 0").unwrap();
        assert_eq!(clock_is_localtime(Some(f.path())).unwrap(), false);
    }

    #[test]
    fn test_localtime_io_error_propagates() {
        // Create a directory at the path to trigger a permission-like error
        // (is-a-directory is not NotFound, so it should propagate).
        let dir = tempfile::tempdir().unwrap();
        let result = clock_is_localtime(Some(dir.path()));
        assert!(result.is_err());
    }

    #[test]
    fn test_adjtime_reader_matches_c_line_delimiters() {
        let mut input = Cursor::new(b"first\r\nsecond\0third\rnext".as_slice());
        assert_eq!(
            read_adjtime_line(&mut input).unwrap(),
            Some(b"first".to_vec())
        );
        assert_eq!(
            read_adjtime_line(&mut input).unwrap(),
            Some(b"second".to_vec())
        );
        assert_eq!(
            read_adjtime_line(&mut input).unwrap(),
            Some(b"third".to_vec())
        );
        assert_eq!(
            read_adjtime_line(&mut input).unwrap(),
            Some(b"next".to_vec())
        );
        assert_eq!(read_adjtime_line(&mut input).unwrap(), None);
    }

    #[test]
    fn test_adjtime_reader_rejects_c_maximum_line_length() {
        let mut input = Cursor::new(vec![b'x'; ADJTIME_LINE_MAX]);
        let error = read_adjtime_line(&mut input).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOBUFS));
    }

    // ── Constants tests ───────────────────────────────────────────────────

    #[test]
    fn test_constants_match_c_header() {
        assert_eq!(EPOCH_CLOCK_FILE, "/usr/lib/clock-epoch");
        assert_eq!(TIMESYNCD_CLOCK_FILE_DIR, "/var/lib/systemd/timesync/");
        assert_eq!(TIMESYNCD_CLOCK_FILE, "/var/lib/systemd/timesync/clock");
        assert_eq!(DEFAULT_ADJTIME_PATH, "/etc/adjtime");
    }

    #[test]
    fn test_timesync_clock_file_is_under_dir() {
        assert!(TIMESYNCD_CLOCK_FILE.starts_with(TIMESYNCD_CLOCK_FILE_DIR));
    }

    // ── TimezoneInfo tests ────────────────────────────────────────────────

    #[test]
    fn test_timezone_info_fields() {
        let info = TimezoneInfo { minutes_delta: 60 };
        assert_eq!(info.minutes_delta, 60);
    }

    #[test]
    fn test_timezone_info_equality() {
        let a = TimezoneInfo {
            minutes_delta: -300,
        };
        let b = TimezoneInfo {
            minutes_delta: -300,
        };
        let c = TimezoneInfo { minutes_delta: 0 };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_timezone_info_clone() {
        let info = TimezoneInfo { minutes_delta: 120 };
        let cloned = info.clone();
        assert_eq!(info, cloned);
    }
}
