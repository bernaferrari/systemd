// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.btrfs-util; authority=src/basic/btrfs-util.c,src/basic/btrfs-util.h
//
// BTRFS subvolume name validation.

use std::ffi::CStr;

use libc::c_char;

// ── Constants ──────────────────────────────────────────────────────────────

const BTRFS_SUBVOL_NAME_MAX: usize = 4039;
const NAME_MAX: usize = 255;

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtrfsError {
    InvalidFileName,
    TooLong,
}

impl std::fmt::Display for BtrfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BtrfsError::InvalidFileName => write!(f, "invalid filename"),
            BtrfsError::TooLong => write!(f, "name too long"),
        }
    }
}

impl std::error::Error for BtrfsError {}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Check if a string is a valid filename component.
///
/// Mirrors C `filename_is_valid()`:
/// - Not empty
/// - Not "." or ".."
/// - Does not contain '/'
/// - Length <= NAME_MAX (255)
fn filename_is_valid_bytes(name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    if name == b"." || name == b".." {
        return false;
    }
    if name.contains(&b'/') {
        return false;
    }
    name.len() <= NAME_MAX
}

fn filename_is_valid(name: &str) -> bool {
    filename_is_valid_bytes(name.as_bytes())
}

fn btrfs_validate_subvolume_name_bytes(name: &[u8]) -> Result<(), BtrfsError> {
    // Preserve the C authority's order. With the current NAME_MAX (255) and
    // BTRFS_SUBVOL_NAME_MAX (4039), the second error is unreachable, but it
    // remains explicit so a future authority change cannot silently reorder it.
    if !filename_is_valid_bytes(name) {
        return Err(BtrfsError::InvalidFileName);
    }
    if name.len() > BTRFS_SUBVOL_NAME_MAX {
        return Err(BtrfsError::TooLong);
    }
    Ok(())
}

// ── Public API ────────────────────────────────────────────────────────────

/// Validate a BTRFS subvolume name.
///
/// Mirrors C `btrfs_validate_subvolume_name()`:
/// - Must be a valid filename (not empty, no '/', not "." or "..")
/// - Must not exceed BTRFS_SUBVOL_NAME_MAX (4039) bytes
pub fn btrfs_validate_subvolume_name(name: &str) -> Result<(), BtrfsError> {
    btrfs_validate_subvolume_name_bytes(name.as_bytes())
}

/// C ABI mirror of `btrfs_validate_subvolume_name()`.
///
/// # Safety
///
/// `name` must be null or point to a live NUL-terminated byte string for the
/// duration of this call. The function neither retains nor frees that storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_btrfs_validate_subvolume_name(name: *const c_char) -> libc::c_int {
    if name.is_null() {
        return -libc::EINVAL;
    }

    // SAFETY: the entry-point contract guarantees a live NUL-terminated string
    // after the null check; the safe byte core preserves C's non-UTF-8 semantics.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    match btrfs_validate_subvolume_name_bytes(name) {
        Ok(()) => 0,
        Err(BtrfsError::InvalidFileName) => -libc::EINVAL,
        Err(BtrfsError::TooLong) => -libc::E2BIG,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_simple() {
        assert!(btrfs_validate_subvolume_name("my-subvol").is_ok());
    }

    #[test]
    fn test_valid_single_char() {
        assert!(btrfs_validate_subvolume_name("a").is_ok());
    }

    #[test]
    fn test_name_larger_than_name_max_is_invalid_before_btrfs_limit() {
        let name = "a".repeat(BTRFS_SUBVOL_NAME_MAX);
        assert_eq!(
            btrfs_validate_subvolume_name(&name),
            Err(BtrfsError::InvalidFileName)
        );
    }

    #[test]
    fn test_btrfs_limit_is_checked_after_filename_validity() {
        let name = "a".repeat(BTRFS_SUBVOL_NAME_MAX + 1);
        assert_eq!(
            btrfs_validate_subvolume_name(&name),
            Err(BtrfsError::InvalidFileName)
        );
    }

    #[test]
    fn test_empty_string() {
        assert_eq!(
            btrfs_validate_subvolume_name(""),
            Err(BtrfsError::InvalidFileName)
        );
    }

    #[test]
    fn test_with_slash() {
        assert_eq!(
            btrfs_validate_subvolume_name("sub/vol"),
            Err(BtrfsError::InvalidFileName)
        );
    }

    #[test]
    fn test_dot() {
        assert_eq!(
            btrfs_validate_subvolume_name("."),
            Err(BtrfsError::InvalidFileName)
        );
    }

    #[test]
    fn test_dotdot() {
        assert_eq!(
            btrfs_validate_subvolume_name(".."),
            Err(BtrfsError::InvalidFileName)
        );
    }

    #[test]
    fn test_hidden_file_valid() {
        assert!(btrfs_validate_subvolume_name(".hidden").is_ok());
    }

    #[test]
    fn test_with_underscore() {
        assert!(btrfs_validate_subvolume_name("my_subvol").is_ok());
    }

    #[test]
    fn test_boundary_max_plus_one() {
        let name = "b".repeat(BTRFS_SUBVOL_NAME_MAX + 1);
        assert_eq!(
            btrfs_validate_subvolume_name(&name),
            Err(BtrfsError::InvalidFileName)
        );
    }

    #[test]
    fn test_filename_is_valid_helper() {
        assert!(filename_is_valid("foo"));
        assert!(filename_is_valid("bar.txt"));
        assert!(!filename_is_valid(""));
        assert!(!filename_is_valid("."));
        assert!(!filename_is_valid(".."));
        assert!(!filename_is_valid("a/b"));
    }

    #[test]
    fn test_error_display() {
        assert_eq!(BtrfsError::InvalidFileName.to_string(), "invalid filename");
        assert_eq!(BtrfsError::TooLong.to_string(), "name too long");
    }

    #[test]
    fn test_name_max_boundary() {
        let name_255 = "x".repeat(255);
        assert!(btrfs_validate_subvolume_name(&name_255).is_ok());
        let name_256 = "x".repeat(256);
        assert_eq!(
            btrfs_validate_subvolume_name(&name_256),
            Err(BtrfsError::InvalidFileName)
        );
    }

    #[test]
    fn test_non_utf8_filename_bytes_are_valid() {
        assert!(btrfs_validate_subvolume_name_bytes(&[0xff]).is_ok());
    }
}
