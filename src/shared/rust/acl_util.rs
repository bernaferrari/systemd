// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/acl-util.c, src/shared/acl-util.h
//
// ACL (Access Control List) utility functions.
//
// Provides safe wrappers around POSIX ACL operations including permission
// checking, entry manipulation, and mode-based fallback logic. The acl
// syscalls themselves are wrapped in minimal unsafe blocks; all public
// API is safe Rust.

// Centralized unsafe expression boundary for this module.
macro_rules! unsafe_ffi {
    ($expression:expr) => {{
        // SAFETY: the enclosing helper documents and validates this operation.
        unsafe { $expression }
    }};
}
use crate::ffi::*;
use std::os::unix::io::AsRawFd;

use crate::Errno;

// ── ACL Constants ──────────────────────────────────────────────────────────

pub const ACL_READ: u32 = 0x04;
pub const ACL_WRITE: u32 = 0x02;
pub const ACL_EXECUTE: u32 = 0x01;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AclPerm: u32 {
        const READ    = ACL_READ;
        const WRITE   = ACL_WRITE;
        const EXECUTE = ACL_EXECUTE;
        const RW      = Self::READ.bits() | Self::WRITE.bits();
        const RWX     = Self::READ.bits() | Self::WRITE.bits() | Self::EXECUTE.bits();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AclTag {
    UndefinedTag = 0x00,
    UserObj = 0x01,
    User = 0x02,
    GroupObj = 0x04,
    Group = 0x08,
    Mask = 0x10,
    Other = 0x20,
}

impl TryFrom<u32> for AclTag {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(AclTag::UndefinedTag),
            0x01 => Ok(AclTag::UserObj),
            0x02 => Ok(AclTag::User),
            0x04 => Ok(AclTag::GroupObj),
            0x08 => Ok(AclTag::Group),
            0x10 => Ok(AclTag::Mask),
            0x20 => Ok(AclTag::Other),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AclType {
    Access = 0x8000,
    Default = 0x4000,
}

// ── Inode type constants (from sys/stat.h) ─────────────────────────────────

pub const S_IFMT: u32 = 0o170000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFIFO: u32 = 0o010000;

// ── ACL permission bitmask validation ──────────────────────────────────────

/// Verify that ACL_READ, ACL_WRITE, ACL_EXECUTE are non-overlapping bitmasks.
/// These are compile-time assertions matching the C `assert_cc()` checks.
const _: () = assert!(
    (ACL_READ & ACL_WRITE) == 0 && (ACL_WRITE & ACL_EXECUTE) == 0 && (ACL_EXECUTE & ACL_READ) == 0,
    "ACL permission bits must be non-overlapping bitmasks"
);

// ── Pure logic: inode type can have ACL ────────────────────────────────────

/// Check whether an inode of the given mode can support ACLs.
///
/// Returns true for: socket, regular file, block device, character device,
/// directory, and FIFO. Returns false for symlinks and unknown types.
pub fn inode_type_can_acl(mode: u32) -> bool {
    let ifmt = mode & S_IFMT;
    matches!(
        ifmt,
        S_IFSOCK | S_IFREG | S_IFBLK | S_IFCHR | S_IFDIR | S_IFIFO
    )
}

// ── Pure logic: ACL tag classification ─────────────────────────────────────

/// Check if an ACL tag represents a named user or named group entry.
/// These are the entries that may be affected by the ACL mask.
pub fn acl_tag_is_named_entry(tag: AclTag) -> bool {
    matches!(tag, AclTag::User | AclTag::Group)
}

/// Check if an ACL tag is one of the three "base" ACL entries
/// (user_obj, group_obj, other).
pub fn acl_tag_is_base_entry(tag: AclTag) -> bool {
    matches!(tag, AclTag::UserObj | AclTag::GroupObj | AclTag::Other)
}

/// Check if a tag controls the execute bit independently of the ACL mask.
/// These are the entries whose x bits are not masked by ACL_MASK.
pub fn acl_tag_controls_x_bits(tag: AclTag) -> bool {
    matches!(tag, AclTag::UserObj | AclTag::Mask | AclTag::Other)
}

// ── Pure logic: mode permission bit helpers ────────────────────────────────

/// Check whether a mode already has the owner-write bit cleared.
pub fn mode_is_read_only(mode: u32) -> bool {
    (mode & 0o222) == 0
}

/// Strip write bits from a mode (equivalent to `mode & 0555`).
pub fn mode_strip_write_bits(mode: u32) -> u32 {
    mode & 0o555
}

/// Check whether the owner-write bit is set in a mode.
pub fn mode_has_owner_write(mode: u32) -> bool {
    (mode & 0o200) != 0
}

/// Add the owner-write bit to a mode while preserving the rest.
pub fn mode_add_owner_write(mode: u32) -> u32 {
    (mode & 0o7777) | 0o200
}

// ── Pure logic: ACL entry equality ─────────────────────────────────────────

/// Result of comparing two ACL entries for equality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclEntryEquality {
    /// The entries are equal.
    Equal,
    /// The entries are not equal.
    NotEqual,
}

/// Compare two ACL entries for equality based on tag type and qualifier.
///
/// For ACL_USER_OBJ, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER tags, entries
/// are equal if the tag types match (since there can only be one of each).
/// For ACL_USER and ACL_GROUP, entries are equal only if the tag types
/// match AND the uid/gid qualifiers match.
pub fn acl_entry_compare(
    tag_a: AclTag,
    qualifier_a: Option<u32>,
    tag_b: AclTag,
    qualifier_b: Option<u32>,
) -> AclEntryEquality {
    if tag_a != tag_b {
        return AclEntryEquality::NotEqual;
    }

    match tag_a {
        AclTag::UserObj | AclTag::GroupObj | AclTag::Mask | AclTag::Other => {
            AclEntryEquality::Equal
        }
        AclTag::User | AclTag::Group => {
            if qualifier_a == qualifier_b {
                AclEntryEquality::Equal
            } else {
                AclEntryEquality::NotEqual
            }
        }
        AclTag::UndefinedTag => AclEntryEquality::NotEqual,
    }
}

// ── Pure logic: ACL entry needs mask ───────────────────────────────────────

/// Check if a set of ACL tags requires a mask entry.
///
/// An ACL mask is needed when any named user or named group entries exist.
pub fn acl_needs_mask(has_user: bool, has_group: bool, has_mask: bool) -> bool {
    if has_mask {
        false
    } else {
        has_user || has_group
    }
}

// ── Pure logic: base ACL presence check ────────────────────────────────────

/// Check if all three base ACL entries (user_obj, group_obj, other) are present.
pub fn acl_has_all_base_entries(has_user_obj: bool, has_group_obj: bool, has_other: bool) -> bool {
    has_user_obj && has_group_obj && has_other
}

// ── Pure logic: ACL text entry parsing ─────────────────────────────────────

/// A parsed ACL text entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclTextEntry {
    /// Whether this is a default (directory inheritance) ACL entry.
    pub is_default: bool,
    /// The entry tag exactly as supplied (for example, `user` or `group`).
    pub tag: String,
    /// The qualifier string (user/group name or ID), empty for base entries.
    pub qualifier: String,
    /// The permission string (e.g., "rwx", "rx").
    pub perms: String,
}

/// Error type for ACL text parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclParseError {
    /// Entry has wrong number of colon-separated fields (must be 3 or 4).
    InvalidFieldCount(usize),
    /// Default ACL prefix is invalid (must be "default" or "d").
    InvalidDefaultPrefix(String),
    /// Empty permission string.
    EmptyPerms,
}

impl std::fmt::Display for AclParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AclParseError::InvalidFieldCount(n) => {
                write!(f, "ACL entry has {} fields, expected 3 or 4", n)
            }
            AclParseError::InvalidDefaultPrefix(s) => {
                write!(f, "invalid default ACL prefix: '{}'", s)
            }
            AclParseError::EmptyPerms => write!(f, "ACL entry has empty permission string"),
        }
    }
}

impl std::error::Error for AclParseError {}

/// Split ACL fields with the exact delimiter treatment used by C `parse_acl()`.
///
/// This is equivalent to `strv_split_full(..., ":",
/// EXTRACT_DONT_COALESCE_SEPARATORS | EXTRACT_RETAIN_ESCAPE)`: adjacent and
/// trailing delimiters produce empty fields, and a backslash is an ordinary
/// character. In particular, `\\:` is *not* an escaped colon; it remains a
/// backslash followed by a field delimiter. Keeping that deliberately small
/// grammar prevents this pure Rust helper from accepting ACL text that the C
/// implementation would reject before it reaches libacl.
fn split_acl_entry_fields(text: &str) -> Vec<&str> {
    text.split(':').collect()
}

/// Parse a single ACL text entry (e.g., "user::rwx", "default:user:foo:rw", "group:bar:r-x").
///
/// Uppercase `X` is retained so that [`classify_acl_entry`] can route the entry
/// through the conditional-execute path before a future libacl boundary
/// normalizes it, matching `parse_acl()` in the C implementation.
pub fn parse_acl_entry(text: &str) -> Result<AclTextEntry, AclParseError> {
    let parts = split_acl_entry_fields(text);

    if parts.len() < 3 || parts.len() > 4 {
        return Err(AclParseError::InvalidFieldCount(parts.len()));
    }

    let (is_default, content_parts) = if parts.len() == 4 {
        let prefix = parts[0];
        if prefix != "default" && prefix != "d" {
            return Err(AclParseError::InvalidDefaultPrefix(prefix.to_string()));
        }
        (true, &parts[1..])
    } else {
        (false, &parts[..])
    };

    // content_parts layout: [tag_type, qualifier_name, perms]. Keep tag and
    // qualifier separate: conflating an empty qualifier with the tag loses the
    // distinction between `user::rwx` and a named user entry.
    let tag = content_parts[0].to_string();
    let qualifier = content_parts[1].to_string();
    let perms = content_parts[2].to_string();

    if perms.is_empty() {
        return Err(AclParseError::EmptyPerms);
    }

    Ok(AclTextEntry {
        is_default,
        tag,
        qualifier,
        perms,
    })
}

/// Check if an ACL text entry contains an uppercase 'X' permission
/// (which means: apply execute only if the file is a directory or already
/// has at least one execute bit set).
pub fn acl_entry_has_uppercase_x(entry: &AclTextEntry) -> bool {
    entry.perms.contains('X')
}

/// Classify a parsed ACL entry into access, access_exec, or default categories.
///
/// - If the entry has uppercase 'X', it goes into the "exec" category
///   (the execute bit decision is deferred).
/// - If the entry is a default entry, it goes into the default category.
/// - Otherwise, it goes into the access category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclEntryCategory {
    /// Standard access ACL entry.
    Access,
    /// Access ACL entry with deferred execute bit (uppercase X).
    AccessExec,
    /// Default (directory inheritance) ACL entry.
    Default,
}

pub fn classify_acl_entry(entry: &AclTextEntry) -> AclEntryCategory {
    if entry.is_default {
        AclEntryCategory::Default
    } else if acl_entry_has_uppercase_x(entry) {
        AclEntryCategory::AccessExec
    } else {
        AclEntryCategory::Access
    }
}

// ── Pure logic: permission set operations ──────────────────────────────────

/// Check whether a permission set has all the requested permissions.
pub fn acl_permset_has_all(perms: AclPerm, requested: AclPerm) -> bool {
    perms.contains(requested)
}

/// Check whether a permission set is missing any of the requested permissions.
pub fn acl_permset_missing_any(perms: AclPerm, requested: AclPerm) -> bool {
    !perms.contains(requested)
}

// ── Safe wrappers around fd-level syscalls ─────────────────────────────────

/// Result of making a file descriptor read-only via mode bits (fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdReadOnlyResult {
    /// Already read-only, no change needed.
    AlreadyReadOnly,
    /// Write bits were stripped, file was modified.
    MadeReadOnly,
}

/// Fallback function: make a file descriptor read-only by clearing write bits
/// from the mode. Used when ACL operations are not available.
///
/// Returns `FdReadOnlyResult::AlreadyReadOnly` if no write bits were set,
/// or `FdReadOnlyResult::MadeReadOnly` if write bits were cleared.
pub fn fd_acl_make_read_only_fallback(fd: impl AsRawFd) -> Result<FdReadOnlyResult, Errno> {
    let raw_fd = fd.as_raw_fd();

    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` points to writable, properly aligned storage for a `libc::stat`.
    // `raw_fd` is only borrowed for this syscall; an invalid or closed descriptor is
    // reported by `fstat` as an error. On success, POSIX initializes the entire struct.
    if unsafe_ffi!(libc::fstat(raw_fd, stat.as_mut_ptr())) < 0 {
        return Err(errno_from_raw(crate::ffi::get_errno()));
    }
    // SAFETY: the successful `fstat` call above initialized `stat` completely.
    let stat = unsafe_ffi!(stat.assume_init());

    let mode = stat.st_mode as u32;
    if mode_is_read_only(mode) {
        return Ok(FdReadOnlyResult::AlreadyReadOnly);
    }

    // SAFETY: `raw_fd` is borrowed for this syscall and `mode_strip_write_bits()`
    // produces a valid permission-bit mask. An invalid descriptor is reported by
    // `fchmod` rather than dereferenced by Rust.
    if unsafe_ffi!(libc::fchmod(
        raw_fd,
        mode_strip_write_bits(mode) as libc::mode_t
    )) < 0
    {
        return Err(errno_from_raw(crate::ffi::get_errno()));
    }

    Ok(FdReadOnlyResult::MadeReadOnly)
}

/// Result of making a file descriptor writable via mode bits (fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdWritableResult {
    /// Already writable, no change needed.
    AlreadyWritable,
    /// Write bit was added, file was modified.
    MadeWritable,
}

/// Fallback function: make a file descriptor writable by setting the
/// owner-write bit in the mode. Used when ACL operations are not available.
pub fn fd_acl_make_writable_fallback(fd: impl AsRawFd) -> Result<FdWritableResult, Errno> {
    let raw_fd = fd.as_raw_fd();

    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` points to writable, properly aligned storage for a `libc::stat`.
    // `raw_fd` is only borrowed for this syscall; an invalid or closed descriptor is
    // reported by `fstat` as an error. On success, POSIX initializes the entire struct.
    if unsafe_ffi!(libc::fstat(raw_fd, stat.as_mut_ptr())) < 0 {
        return Err(errno_from_raw(crate::ffi::get_errno()));
    }
    // SAFETY: the successful `fstat` call above initialized `stat` completely.
    let stat = unsafe_ffi!(stat.assume_init());

    let mode = stat.st_mode as u32;
    if mode_has_owner_write(mode) {
        return Ok(FdWritableResult::AlreadyWritable);
    }

    // SAFETY: `raw_fd` is borrowed for this syscall and `mode_add_owner_write()`
    // preserves only mode bits accepted by `fchmod`. An invalid descriptor is
    // reported by `fchmod` rather than dereferenced by Rust.
    if unsafe_ffi!(libc::fchmod(
        raw_fd,
        mode_add_owner_write(mode) as libc::mode_t
    )) < 0
    {
        return Err(errno_from_raw(crate::ffi::get_errno()));
    }

    Ok(FdWritableResult::MadeWritable)
}

// ── Errno conversion helper ────────────────────────────────────────────────

fn errno_from_raw(raw: i32) -> Errno {
    Errno::from_raw(raw).unwrap_or(Errno::EINVAL)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inode_type_can_acl_regular() {
        assert!(inode_type_can_acl(S_IFREG));
    }

    #[test]
    fn test_inode_type_can_acl_directory() {
        assert!(inode_type_can_acl(S_IFDIR));
    }

    #[test]
    fn test_inode_type_can_acl_block_char() {
        assert!(inode_type_can_acl(S_IFBLK));
        assert!(inode_type_can_acl(S_IFCHR));
    }

    #[test]
    fn test_inode_type_can_acl_socket_fifo() {
        assert!(inode_type_can_acl(S_IFSOCK));
        assert!(inode_type_can_acl(S_IFIFO));
    }

    #[test]
    fn test_inode_type_can_acl_symlink_rejected() {
        assert!(!inode_type_can_acl(S_IFLNK));
    }

    #[test]
    fn test_inode_type_can_acl_with_full_mode() {
        assert!(inode_type_can_acl(0o100644));
        assert!(inode_type_can_acl(0o040755));
        assert!(!inode_type_can_acl(0o120777));
    }

    #[test]
    fn test_inode_type_can_acl_unknown_type() {
        assert!(!inode_type_can_acl(0o160000));
        assert!(!inode_type_can_acl(0o000000));
    }

    #[test]
    fn test_acl_tag_is_named_entry() {
        assert!(acl_tag_is_named_entry(AclTag::User));
        assert!(acl_tag_is_named_entry(AclTag::Group));
        assert!(!acl_tag_is_named_entry(AclTag::UserObj));
        assert!(!acl_tag_is_named_entry(AclTag::GroupObj));
        assert!(!acl_tag_is_named_entry(AclTag::Mask));
        assert!(!acl_tag_is_named_entry(AclTag::Other));
    }

    #[test]
    fn test_acl_tag_is_base_entry() {
        assert!(acl_tag_is_base_entry(AclTag::UserObj));
        assert!(acl_tag_is_base_entry(AclTag::GroupObj));
        assert!(acl_tag_is_base_entry(AclTag::Other));
        assert!(!acl_tag_is_base_entry(AclTag::User));
        assert!(!acl_tag_is_base_entry(AclTag::Group));
        assert!(!acl_tag_is_base_entry(AclTag::Mask));
    }

    #[test]
    fn test_acl_tag_controls_x_bits() {
        assert!(acl_tag_controls_x_bits(AclTag::UserObj));
        assert!(acl_tag_controls_x_bits(AclTag::Mask));
        assert!(acl_tag_controls_x_bits(AclTag::Other));
        assert!(!acl_tag_controls_x_bits(AclTag::User));
        assert!(!acl_tag_controls_x_bits(AclTag::Group));
        assert!(!acl_tag_controls_x_bits(AclTag::GroupObj));
    }

    #[test]
    fn test_acl_perm_bitflags() {
        assert_eq!(AclPerm::READ.bits(), ACL_READ);
        assert_eq!(AclPerm::WRITE.bits(), ACL_WRITE);
        assert_eq!(AclPerm::EXECUTE.bits(), ACL_EXECUTE);
        assert_eq!(AclPerm::RWX.bits(), ACL_READ | ACL_WRITE | ACL_EXECUTE);
        assert!(AclPerm::RW.contains(AclPerm::READ));
        assert!(AclPerm::RW.contains(AclPerm::WRITE));
        assert!(!AclPerm::RW.contains(AclPerm::EXECUTE));
    }

    #[test]
    fn test_acl_permset_has_all() {
        let rw = AclPerm::RW;
        assert!(acl_permset_has_all(rw, AclPerm::READ));
        assert!(acl_permset_has_all(rw, AclPerm::WRITE));
        assert!(!acl_permset_has_all(rw, AclPerm::EXECUTE));
        assert!(acl_permset_has_all(AclPerm::RWX, AclPerm::RW));
    }

    #[test]
    fn test_acl_permset_missing_any() {
        let r = AclPerm::READ;
        assert!(!acl_permset_missing_any(r, AclPerm::READ));
        assert!(acl_permset_missing_any(r, AclPerm::WRITE));
    }

    #[test]
    fn test_acl_needs_mask() {
        assert!(acl_needs_mask(true, false, false));
        assert!(acl_needs_mask(false, true, false));
        assert!(acl_needs_mask(true, true, false));
        assert!(!acl_needs_mask(false, false, false));
        assert!(!acl_needs_mask(true, true, true));
        assert!(!acl_needs_mask(false, false, true));
    }

    #[test]
    fn test_acl_has_all_base_entries() {
        assert!(acl_has_all_base_entries(true, true, true));
        assert!(!acl_has_all_base_entries(true, true, false));
        assert!(!acl_has_all_base_entries(true, false, true));
        assert!(!acl_has_all_base_entries(false, true, true));
        assert!(!acl_has_all_base_entries(false, false, false));
    }

    #[test]
    fn test_mode_helpers() {
        assert!(mode_is_read_only(0o444));
        assert!(mode_is_read_only(0o555));
        assert!(!mode_is_read_only(0o644));
        assert!(!mode_is_read_only(0o777));

        assert_eq!(mode_strip_write_bits(0o766), 0o544);
        assert_eq!(mode_strip_write_bits(0o644), 0o444);
        assert_eq!(mode_strip_write_bits(0o755), 0o555);
        assert_eq!(mode_strip_write_bits(0o4755), 0o555);

        assert!(mode_has_owner_write(0o700));
        assert!(mode_has_owner_write(0o644));
        assert!(!mode_has_owner_write(0o444));
        assert!(!mode_has_owner_write(0o555));

        assert_eq!(mode_add_owner_write(0o444), 0o644);
        assert_eq!(mode_add_owner_write(0o555), 0o755);
        assert_eq!(mode_add_owner_write(0o700), 0o700);
    }

    #[test]
    fn test_acl_entry_compare_base_entries() {
        assert_eq!(
            acl_entry_compare(AclTag::UserObj, None, AclTag::UserObj, None),
            AclEntryEquality::Equal
        );
        assert_eq!(
            acl_entry_compare(AclTag::GroupObj, None, AclTag::GroupObj, None),
            AclEntryEquality::Equal
        );
        assert_eq!(
            acl_entry_compare(AclTag::Mask, None, AclTag::Mask, None),
            AclEntryEquality::Equal
        );
        assert_eq!(
            acl_entry_compare(AclTag::Other, None, AclTag::Other, None),
            AclEntryEquality::Equal
        );
    }

    #[test]
    fn test_acl_entry_compare_different_tags() {
        assert_eq!(
            acl_entry_compare(AclTag::UserObj, None, AclTag::Other, None),
            AclEntryEquality::NotEqual
        );
        assert_eq!(
            acl_entry_compare(AclTag::User, Some(100), AclTag::Group, Some(100)),
            AclEntryEquality::NotEqual
        );
    }

    #[test]
    fn test_acl_entry_compare_named_entries() {
        assert_eq!(
            acl_entry_compare(AclTag::User, Some(1000), AclTag::User, Some(1000)),
            AclEntryEquality::Equal
        );
        assert_eq!(
            acl_entry_compare(AclTag::User, Some(1000), AclTag::User, Some(2000)),
            AclEntryEquality::NotEqual
        );
        assert_eq!(
            acl_entry_compare(AclTag::User, Some(1000), AclTag::User, None),
            AclEntryEquality::NotEqual
        );
        assert_eq!(
            acl_entry_compare(AclTag::Group, Some(100), AclTag::Group, Some(100)),
            AclEntryEquality::Equal
        );
        assert_eq!(
            acl_entry_compare(AclTag::Group, Some(100), AclTag::Group, Some(200)),
            AclEntryEquality::NotEqual
        );
    }

    #[test]
    fn test_parse_acl_entry_simple() {
        let entry = parse_acl_entry("user::rwx").unwrap();
        assert!(!entry.is_default);
        assert_eq!(entry.tag, "user");
        assert_eq!(entry.qualifier, "");
        assert_eq!(entry.perms, "rwx");
    }

    #[test]
    fn test_parse_acl_entry_named_user() {
        let entry = parse_acl_entry("user:1000:rw-").unwrap();
        assert!(!entry.is_default);
        assert_eq!(entry.tag, "user");
        assert_eq!(entry.qualifier, "1000");
        assert_eq!(entry.perms, "rw-");
    }

    #[test]
    fn test_parse_acl_entry_default() {
        let entry = parse_acl_entry("default:group::r-x").unwrap();
        assert!(entry.is_default);
        assert_eq!(entry.tag, "group");
        assert_eq!(entry.qualifier, "");
        assert_eq!(entry.perms, "r-x");
    }

    #[test]
    fn test_parse_acl_entry_short_default() {
        let entry = parse_acl_entry("d:user:foo:rx").unwrap();
        assert!(entry.is_default);
        assert_eq!(entry.tag, "user");
        assert_eq!(entry.qualifier, "foo");
        assert_eq!(entry.perms, "rx");
    }

    #[test]
    fn test_parse_acl_entry_invalid_field_count() {
        assert_eq!(
            parse_acl_entry("user"),
            Err(AclParseError::InvalidFieldCount(1))
        );
        assert_eq!(
            parse_acl_entry("a:b"),
            Err(AclParseError::InvalidFieldCount(2))
        );
        assert_eq!(
            parse_acl_entry("a:b:c:d:e"),
            Err(AclParseError::InvalidFieldCount(5))
        );
    }

    #[test]
    fn test_parse_acl_entry_invalid_default_prefix() {
        assert_eq!(
            parse_acl_entry("invalid:user::rwx"),
            Err(AclParseError::InvalidDefaultPrefix("invalid".to_string()))
        );
    }

    #[test]
    fn test_parse_acl_entry_retains_backslashes_without_escaping_delimiters() {
        let entry = parse_acl_entry(r"user:alice\\ops:rwx").unwrap();
        assert_eq!(entry.qualifier, r"alice\\ops");

        // `parse_acl()` uses EXTRACT_RETAIN_ESCAPE, which deliberately makes
        // the colon below a separator instead of treating it as escaped.
        assert_eq!(
            parse_acl_entry(r"user:alice\:ops:rwx"),
            Err(AclParseError::InvalidDefaultPrefix("user".to_string()))
        );
    }

    #[test]
    fn test_parse_acl_entry_empty_perms() {
        assert_eq!(parse_acl_entry("user::"), Err(AclParseError::EmptyPerms));
    }

    #[test]
    fn test_acl_entry_has_uppercase_x() {
        let entry = AclTextEntry {
            is_default: false,
            tag: "user".to_string(),
            qualifier: "user".to_string(),
            perms: "rwX".to_string(),
        };
        assert!(acl_entry_has_uppercase_x(&entry));

        let entry_lower = AclTextEntry {
            is_default: false,
            tag: "user".to_string(),
            qualifier: "user".to_string(),
            perms: "rwx".to_string(),
        };
        assert!(!acl_entry_has_uppercase_x(&entry_lower));
    }

    #[test]
    fn test_classify_acl_entry() {
        let access = AclTextEntry {
            is_default: false,
            tag: "user".to_string(),
            qualifier: "user".to_string(),
            perms: "rwx".to_string(),
        };
        assert_eq!(classify_acl_entry(&access), AclEntryCategory::Access);

        let exec = AclTextEntry {
            is_default: false,
            tag: "user".to_string(),
            qualifier: "user".to_string(),
            perms: "rwX".to_string(),
        };
        assert_eq!(classify_acl_entry(&exec), AclEntryCategory::AccessExec);

        let default = AclTextEntry {
            is_default: true,
            tag: "group".to_string(),
            qualifier: "group".to_string(),
            perms: "r-x".to_string(),
        };
        assert_eq!(classify_acl_entry(&default), AclEntryCategory::Default);
    }

    #[test]
    fn test_acl_tag_try_from() {
        assert_eq!(AclTag::try_from(0x01), Ok(AclTag::UserObj));
        assert_eq!(AclTag::try_from(0x02), Ok(AclTag::User));
        assert_eq!(AclTag::try_from(0x10), Ok(AclTag::Mask));
        assert_eq!(AclTag::try_from(0xFF), Err(()));
        assert_eq!(AclTag::try_from(0x03), Err(()));
    }

    #[test]
    fn test_acl_constants_non_overlapping() {
        assert_ne!(ACL_READ, ACL_WRITE);
        assert_ne!(ACL_WRITE, ACL_EXECUTE);
        assert_ne!(ACL_EXECUTE, ACL_READ);
        assert_eq!(ACL_READ & ACL_WRITE, 0);
        assert_eq!(ACL_WRITE & ACL_EXECUTE, 0);
        assert_eq!(ACL_EXECUTE & ACL_READ, 0);
    }

    #[test]
    fn test_acl_parse_error_display() {
        let err = AclParseError::InvalidFieldCount(5);
        assert_eq!(
            format!("{}", err),
            "ACL entry has 5 fields, expected 3 or 4"
        );

        let err = AclParseError::InvalidDefaultPrefix("bad".to_string());
        assert_eq!(format!("{}", err), "invalid default ACL prefix: 'bad'");

        let err = AclParseError::EmptyPerms;
        assert_eq!(format!("{}", err), "ACL entry has empty permission string");
    }
}
