// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/printk-util.c
//
// Kernel printk level sysctl helpers.
//
// Reads and writes /proc/sys/kernel/printk to get/set the kernel
// console log level. The sysctl file contains four space-separated
// integer values: console_loglevel, default_message_loglevel,
// minimum_console_loglevel, and boot_console_loglevel.

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::Errno;

// ── Constants ─────────────────────────────────────────────────────────────

/// Sysfs path for the kernel printk level.
const PRINTK_SYSCTL_PATH: &str = "/proc/sys/kernel/printk";

/// Minimum valid kernel log level.
const KERN_LOGLEVEL_MIN: i32 = 0;

/// Maximum valid kernel log level (KERN_DEBUG).
const KERN_LOGLEVEL_MAX: i32 = 7;

/// Number of fields expected in the kernel.printk sysctl output.
const PRINTK_SYSCTL_FIELDS: usize = 4;

// ── Error helpers ─────────────────────────────────────────────────────────

/// Map an I/O error to an [`Errno`].
fn io_to_errno(e: std::io::Error) -> Errno {
    match e.raw_os_error() {
        Some(code) => match code {
            libc::EPERM => Errno::EPERM,
            libc::ENOENT => Errno::ENOENT,
            libc::EIO => Errno::EIO,
            libc::EACCES => Errno::EACCES,
            libc::EINVAL => Errno::EINVAL,
            _ => Errno::EINVAL,
        },
        None => match e.kind() {
            std::io::ErrorKind::PermissionDenied => Errno::EACCES,
            std::io::ErrorKind::NotFound => Errno::ENOENT,
            _ => Errno::EINVAL,
        },
    }
}

// ── Public API ────────────────────────────────────────────────────────────

/// Read the current kernel console log level from `kernel.printk`.
///
/// The sysctl file `/proc/sys/kernel/printk` contains four space-separated
/// integers. This function returns the **first** value (the current console
/// log level).
///
/// # Errors
///
/// Returns [`Errno`] if the sysctl file cannot be read, is empty, or
/// contains non-numeric content.
pub fn sysctl_printk_read() -> Result<i32, Errno> {
    let content = fs::read_to_string(PRINTK_SYSCTL_PATH).map_err(io_to_errno)?;

    let first_value = content.split_whitespace().next().ok_or(Errno::EINVAL)?;

    first_value.parse::<i32>().map_err(|_| Errno::EINVAL)
}

/// Write a new kernel console log level to `kernel.printk`.
///
/// Only the first field (console log level) is written. Valid levels are
/// 0 (KERN_EMERG) through 7 (KERN_DEBUG).
///
/// # Errors
///
/// Returns [`Errno::EINVAL`] if `level` is outside the valid range.
/// Returns other [`Errno`] values for I/O failures (e.g. [`Errno::EPERM`]
/// when not running as root, [`Errno::ENOENT`] if the sysctl path is
/// missing).
pub fn sysctl_printk_write(level: i32) -> Result<(), Errno> {
    if !(KERN_LOGLEVEL_MIN..=KERN_LOGLEVEL_MAX).contains(&level) {
        return Err(Errno::EINVAL);
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(PRINTK_SYSCTL_PATH)
        .map_err(io_to_errno)?;

    // Write just the console_loglevel (first field).
    writeln!(file, "{level}").map_err(io_to_errno)?;

    Ok(())
}

// ── Parsing helpers (tested independently) ────────────────────────────────

/// Parse all four fields from the kernel.printk sysctl content.
///
/// Returns `(console_loglevel, default_message_loglevel,
/// minimum_console_loglevel, boot_console_loglevel)`.
///
/// # Errors
///
/// Returns [`Errno::EINVAL`] if the content does not contain exactly four
/// parseable integers.
pub fn parse_printk_sysctl(content: &str) -> Result<[i32; PRINTK_SYSCTL_FIELDS], Errno> {
    let fields: Vec<&str> = content.split_whitespace().collect();
    if fields.len() != PRINTK_SYSCTL_FIELDS {
        return Err(Errno::EINVAL);
    }

    let mut result = [0i32; PRINTK_SYSCTL_FIELDS];
    for (i, field) in fields.iter().enumerate() {
        result[i] = field.parse::<i32>().map_err(|_| Errno::EINVAL)?;
    }

    Ok(result)
}

/// Validate that a log level value is within the kernel-accepted range.
pub fn is_valid_log_level(level: i32) -> bool {
    (KERN_LOGLEVEL_MIN..=KERN_LOGLEVEL_MAX).contains(&level)
}

/// Extract only the first (console) log level from sysctl content.
///
/// This is the internal logic behind [`sysctl_printk_read`], factored out
/// for testability without filesystem access.
pub fn extract_console_log_level(content: &str) -> Result<i32, Errno> {
    let first = content.split_whitespace().next().ok_or(Errno::EINVAL)?;
    first.parse::<i32>().map_err(|_| Errno::EINVAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_console_log_level ──────────────────────────────────────────

    #[test]
    fn test_extract_console_log_level_standard() {
        // Typical /proc/sys/kernel/printk output
        assert_eq!(extract_console_log_level("4 4 1 7").unwrap(), 4);
    }

    #[test]
    fn test_extract_console_log_level_zero() {
        assert_eq!(extract_console_log_level("0 4 1 7").unwrap(), 0);
    }

    #[test]
    fn test_extract_console_log_level_seven() {
        assert_eq!(extract_console_log_level("7 7 7 7").unwrap(), 7);
    }

    #[test]
    fn test_extract_console_log_level_empty() {
        assert_eq!(extract_console_log_level(""), Err(Errno::EINVAL));
    }

    #[test]
    fn test_extract_console_log_level_whitespace_only() {
        assert_eq!(extract_console_log_level("   \n\t  "), Err(Errno::EINVAL));
    }

    #[test]
    fn test_extract_console_log_level_non_numeric() {
        assert_eq!(extract_console_log_level("abc 4 1 7"), Err(Errno::EINVAL));
    }

    #[test]
    fn test_extract_console_log_level_trailing_newline() {
        assert_eq!(extract_console_log_level("4 4 1 7\n").unwrap(), 4);
    }

    #[test]
    fn test_extract_console_log_level_extra_whitespace() {
        assert_eq!(extract_console_log_level("  4   4  1   7  \n"), Ok(4));
    }

    // ── parse_printk_sysctl ────────────────────────────────────────────────

    #[test]
    fn test_parse_printk_sysctl_standard() {
        let result = parse_printk_sysctl("4 4 1 7").unwrap();
        assert_eq!(result, [4, 4, 1, 7]);
    }

    #[test]
    fn test_parse_printk_sysctl_all_same() {
        assert_eq!(parse_printk_sysctl("7 7 7 7").unwrap(), [7, 7, 7, 7]);
    }

    #[test]
    fn test_parse_printk_sysctl_too_few_fields() {
        assert_eq!(parse_printk_sysctl("4 4 1"), Err(Errno::EINVAL));
    }

    #[test]
    fn test_parse_printk_sysctl_too_many_fields() {
        assert_eq!(parse_printk_sysctl("4 4 1 7 0"), Err(Errno::EINVAL));
    }

    #[test]
    fn test_parse_printk_sysctl_empty() {
        assert_eq!(parse_printk_sysctl(""), Err(Errno::EINVAL));
    }

    #[test]
    fn test_parse_printk_sysctl_non_numeric() {
        assert_eq!(parse_printk_sysctl("a b c d"), Err(Errno::EINVAL));
    }

    // ── is_valid_log_level ─────────────────────────────────────────────────

    #[test]
    fn test_is_valid_log_level_range() {
        for level in 0..=7 {
            assert!(is_valid_log_level(level));
        }
    }

    #[test]
    fn test_is_valid_log_level_below_min() {
        assert!(!is_valid_log_level(-1));
        assert!(!is_valid_log_level(i32::MIN));
    }

    #[test]
    fn test_is_valid_log_level_above_max() {
        assert!(!is_valid_log_level(8));
        assert!(!is_valid_log_level(100));
        assert!(!is_valid_log_level(i32::MAX));
    }

    // ── io_to_errno ────────────────────────────────────────────────────────

    #[test]
    fn test_io_to_errno_with_os_error() {
        let io_err = std::io::Error::from_raw_os_error(13); // EACCES
        assert_eq!(io_to_errno(io_err), Errno::EACCES);
    }

    #[test]
    fn test_io_to_errno_without_os_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "custom");
        assert_eq!(io_to_errno(io_err), Errno::EINVAL);
    }

    // ── sysctl_printk_write validation ─────────────────────────────────────

    #[test]
    fn test_sysctl_printk_write_rejects_negative() {
        assert_eq!(sysctl_printk_write(-1), Err(Errno::EINVAL));
    }

    #[test]
    fn test_sysctl_printk_write_rejects_above_seven() {
        assert_eq!(sysctl_printk_write(8), Err(Errno::EINVAL));
        assert_eq!(sysctl_printk_write(100), Err(Errno::EINVAL));
    }

    #[test]
    fn test_sysctl_printk_write_rejects_i32_max() {
        assert_eq!(sysctl_printk_write(i32::MAX), Err(Errno::EINVAL));
    }
}
