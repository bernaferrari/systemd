// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/basic/dirent-util.c (dirent_is_file, dirent_is_file_with_suffix)
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
    if name.is_empty() {
        return false;
    }

    // Hidden files start with '.'
    if name.as_bytes()[0] == b'.' {
        return true;
    }

    // Special filenames
    if name == "lost+found" || name == "aquota.user" || name == "aquota.group" {
        return true;
    }

    // Backup suffix: trailing '~'
    if name.as_bytes().last() == Some(&b'~') {
        return true;
    }

    // Check suffix after last '.'
    let dot_pos = match name.rfind('.') {
        Some(p) => p,
        None => return false,
    };
    let suffix = &name[dot_pos + 1..];

    const BACKUP_SUFFIXES: &[&str] = &[
        "ignore",
        "rpmnew",
        "rpmsave",
        "rpmorig",
        "dpkg-old",
        "dpkg-new",
        "dpkg-tmp",
        "dpkg-dist",
        "dpkg-bak",
        "dpkg-backup",
        "dpkg-remove",
        "ucf-new",
        "ucf-old",
        "ucf-dist",
        "swp",
        "bak",
        "old",
        "new",
    ];

    BACKUP_SUFFIXES.contains(&suffix)
}

/// Check if d_type indicates a file-like entry (regular file, symlink, or unknown).
fn is_file_like_type(d_type: u8) -> bool {
    d_type == DT_REG || d_type == DT_LNK || d_type == DT_UNKNOWN
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
