// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: scope=basic.dirent-util; authority=src/basic/dirent-util.c,src/basic/dirent-util.h,src/basic/path-util.c,src/basic/path-util.h
//
// Dirent classification utilities.

// ── Constants ─────────────────────────────────────────────────────────────

/// Directory entry is a regular file.
pub const DT_REG: u8 = 8;
/// Directory entry is a symbolic link.
pub const DT_LNK: u8 = 10;
/// Directory entry type is unknown (filesystem may not support d_type).
pub const DT_UNKNOWN: u8 = 0;
/// Directory entry is a directory.
pub const DT_DIR: u8 = 4;

// ── Internal helpers ──────────────────────────────────────────────────────

/// Check if a filename is hidden (starts with '.') or is a backup file.
/// Port of C `hidden_or_backup_file()` from `src/basic/path-util.c`.
fn hidden_or_backup_file(name: &str) -> bool {
    hidden_or_backup_file_bytes(name.as_bytes())
}

/// Check if d_type indicates a file-like entry (regular file, symlink, or unknown).
fn is_file_like_type(d_type: u8) -> bool {
    d_type == DT_REG || d_type == DT_LNK || d_type == DT_UNKNOWN
}

/// Byte-preserving implementation of C's `hidden_or_backup_file()`.
///
/// Directory entry names are native C byte strings; they are not necessarily
/// UTF-8. Keep the FFI path byte-oriented so a non-UTF-8 entry cannot change
/// the classification merely because Rust attempted to decode it.
fn hidden_or_backup_file_bytes(name: &[u8]) -> bool {
    name.starts_with(b".")
        || matches!(name, b"lost+found" | b"aquota.user" | b"aquota.group")
        || name.ends_with(b"~")
        || name
            .iter()
            .rposition(|byte| *byte == b'.')
            .is_some_and(|dot| {
                let suffix = &name[dot + 1..];
                matches!(
                    suffix,
                    b"ignore"
                        | b"rpmnew"
                        | b"rpmsave"
                        | b"rpmorig"
                        | b"dpkg-old"
                        | b"dpkg-new"
                        | b"dpkg-tmp"
                        | b"dpkg-dist"
                        | b"dpkg-bak"
                        | b"dpkg-backup"
                        | b"dpkg-remove"
                        | b"ucf-new"
                        | b"ucf-old"
                        | b"ucf-dist"
                        | b"swp"
                        | b"bak"
                        | b"old"
                        | b"new"
                )
            })
}

// ── Public API ────────────────────────────────────────────────────────────

/// Check if a directory entry represents a regular file or symlink that is not
/// hidden or a backup file.
///
/// Port of C `dirent_is_file()`.
/// `d_type` should be the `d_type` field from the dirent struct.
/// `name` is the filename (d_name).
pub fn dirent_is_file(name: &str, d_type: u8) -> bool {
    if !is_file_like_type(d_type) {
        return false;
    }

    if hidden_or_backup_file(name) {
        return false;
    }

    true
}

/// Check if a directory entry is a regular file or symlink with a given suffix.
///
/// Port of C `dirent_is_file_with_suffix()`.
/// Hidden files (starting with '.') are always rejected regardless of suffix.
/// If `suffix` is `None`, any non-hidden file-like entry passes.
pub fn dirent_is_file_with_suffix(name: &str, d_type: u8, suffix: Option<&str>) -> bool {
    if !is_file_like_type(d_type) {
        return false;
    }

    // Reject hidden files (starts with '.')
    if !name.is_empty() && name.as_bytes()[0] == b'.' {
        return false;
    }

    match suffix {
        None => true,
        Some(suf) => name.ends_with(suf),
    }
}

/// C ABI mirror of `dirent_is_file()`.
///
/// # Safety
///
/// `de` must be null or point to a readable `struct dirent` whose `d_name`
/// field contains a NUL-terminated name within its native array. The pointer
/// and its name are borrowed for this call only. C asserts a non-null input;
/// this facade instead fails closed for null so it never unwinds across C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dirent_is_file(de: *const libc::dirent) -> bool {
    if de.is_null() {
        return false;
    }

    // SAFETY: the entry-point contract guarantees a readable dirent with a
    // NUL-terminated d_name array for this call.
    let entry = unsafe { &*de };
    // SAFETY: d_name is a C NUL-terminated byte string by the entry contract.
    let name = unsafe { std::ffi::CStr::from_ptr(entry.d_name.as_ptr()) }.to_bytes();
    is_file_like_type(entry.d_type) && !hidden_or_backup_file_bytes(name)
}

/// C ABI mirror of `dirent_is_file_with_suffix()`.
///
/// # Safety
///
/// `de` has the same borrowed `struct dirent` contract as
/// [`rs_dirent_is_file`]. `suffix`, when non-null, must point to a live
/// NUL-terminated byte string. C asserts a non-null directory entry; this
/// facade returns false for null instead of unwinding across C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rs_dirent_is_file_with_suffix(
    de: *const libc::dirent,
    suffix: *const libc::c_char,
) -> bool {
    if de.is_null() {
        return false;
    }

    // SAFETY: the entry-point contract guarantees a readable dirent with a
    // NUL-terminated d_name array for this call.
    let entry = unsafe { &*de };
    // SAFETY: d_name is a C NUL-terminated byte string by the entry contract.
    let name = unsafe { std::ffi::CStr::from_ptr(entry.d_name.as_ptr()) }.to_bytes();
    if !is_file_like_type(entry.d_type) || name.starts_with(b".") {
        return false;
    }

    if suffix.is_null() {
        return true;
    }
    // SAFETY: the entry-point contract guarantees a live C string when the
    // optional suffix pointer is non-null.
    let suffix = unsafe { std::ffi::CStr::from_ptr(suffix) }.to_bytes();
    name.ends_with(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── dirent_is_file tests ──────────────────────────────────────────

    #[test]
    fn is_file_regular() {
        assert!(dirent_is_file("test.txt", DT_REG));
    }

    #[test]
    fn is_file_symlink() {
        assert!(dirent_is_file("link.txt", DT_LNK));
    }

    #[test]
    fn is_file_unknown_type() {
        assert!(dirent_is_file("file", DT_UNKNOWN));
    }

    #[test]
    fn is_file_directory_rejected() {
        assert!(!dirent_is_file("dir", DT_DIR));
    }

    #[test]
    fn is_file_fifo_rejected() {
        assert!(!dirent_is_file("pipe", 1)); // DT_FIFO
    }

    #[test]
    fn is_file_socket_rejected() {
        assert!(!dirent_is_file("sock", 12)); // DT_SOCK
    }

    #[test]
    fn is_file_char_device_rejected() {
        assert!(!dirent_is_file("chardev", 2)); // DT_CHR
    }

    #[test]
    fn is_file_block_device_rejected() {
        assert!(!dirent_is_file("blockdev", 6)); // DT_BLK
    }

    #[test]
    fn is_file_hidden_rejected() {
        assert!(!dirent_is_file(".hidden", DT_REG));
        assert!(!dirent_is_file(".bashrc", DT_REG));
    }

    #[test]
    fn is_file_backup_tilde_rejected() {
        assert!(!dirent_is_file("file~", DT_REG));
    }

    #[test]
    fn is_file_lost_found_rejected() {
        assert!(!dirent_is_file("lost+found", DT_REG));
    }

    #[test]
    fn is_file_backup_suffix_rejected() {
        assert!(!dirent_is_file("file.bak", DT_REG));
        assert!(!dirent_is_file("file.old", DT_REG));
        assert!(!dirent_is_file("file.rpmnew", DT_REG));
        assert!(!dirent_is_file("file.dpkg-dist", DT_REG));
        assert!(!dirent_is_file(".swp", DT_LNK)); // hidden by dot, not by suffix
    }

    #[test]
    fn is_file_normal_names_accepted() {
        assert!(dirent_is_file("config.yaml", DT_REG));
        assert!(dirent_is_file("README", DT_REG));
        assert!(dirent_is_file("my-script.sh", DT_LNK));
    }

    // ── dirent_is_file_with_suffix tests ──────────────────────────────

    #[test]
    fn with_suffix_null_suffix_accepts() {
        assert!(dirent_is_file_with_suffix("test.txt", DT_REG, None));
    }

    #[test]
    fn with_suffix_matching_suffix() {
        assert!(dirent_is_file_with_suffix("test.txt", DT_REG, Some(".txt")));
    }

    #[test]
    fn with_suffix_non_matching_rejected() {
        assert!(!dirent_is_file_with_suffix(
            "test.txt",
            DT_REG,
            Some(".log")
        ));
    }

    #[test]
    fn with_suffix_hidden_rejected() {
        assert!(!dirent_is_file_with_suffix(
            ".hidden.txt",
            DT_REG,
            Some(".txt")
        ));
    }

    #[test]
    fn with_suffix_directory_rejected() {
        assert!(!dirent_is_file_with_suffix("dir", DT_DIR, Some("")));
    }

    #[test]
    fn with_suffix_empty_name_rejected() {
        // Empty name doesn't start with '.', but also doesn't end with suffix
        assert!(!dirent_is_file_with_suffix("", DT_REG, Some(".txt")));
    }

    #[test]
    fn with_suffix_empty_suffix_accepts() {
        assert!(dirent_is_file_with_suffix("anyfile", DT_REG, Some("")));
    }

    #[test]
    fn with_suffix_non_file_type_rejected() {
        assert!(!dirent_is_file_with_suffix(
            "test.txt",
            DT_DIR,
            Some(".txt")
        ));
        assert!(!dirent_is_file_with_suffix("test.txt", 1, Some(".txt")));
    }

    #[test]
    fn with_suffix_partial_match_rejected() {
        assert!(!dirent_is_file_with_suffix(
            "test.txt.bak",
            DT_REG,
            Some(".txt")
        ));
        assert!(dirent_is_file_with_suffix(
            "test.txt.bak",
            DT_REG,
            Some(".bak")
        ));
    }

    #[test]
    fn with_suffix_multiple_dots() {
        assert!(dirent_is_file_with_suffix(
            "archive.tar.gz",
            DT_REG,
            Some(".tar.gz")
        ));
    }

    #[test]
    fn with_suffix_unknown_type_accepts() {
        assert!(dirent_is_file_with_suffix(
            "file.conf",
            DT_UNKNOWN,
            Some(".conf")
        ));
    }
}
