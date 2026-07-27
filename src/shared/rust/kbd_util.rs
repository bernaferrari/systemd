// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/kbd-util.c, src/shared/kbd-util.h
//
// Keyboard keymap utilities — keymap directory resolution, keymap
// validation, keymap enumeration, and keymap existence checking.
//
// Provides functions to discover system keymap directories (from the
// environment or built-in defaults), enumerate all available keymaps
// by recursively scanning those directories, validate keymap names, and
// test whether a specific keymap is present on the system.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

// ── Constants ─────────────────────────────────────────────────────────────

/// Default keymap search directories (matches C `KBD_KEYMAP_DIRS`).
const KBD_KEYMAP_DIRS: &[&str] = &[
    "/usr/share/keymaps/",
    "/usr/share/kbd/keymaps/",
    "/usr/lib/kbd/keymaps/",
];

/// Maximum allowed length for a keymap name (matches C `strlen(name) >= 128`).
const KEYMAP_NAME_MAX_LEN: usize = 127;

/// Environment variable override for keymap directories.
const KEYMAP_DIRS_ENV: &str = "SYSTEMD_KEYMAP_DIRECTORIES";

/// File extensions recognized as keymap files.
const KEYMAP_EXTENSIONS: &[&str] = &[".map", ".map.gz"];

// ── Public API ────────────────────────────────────────────────────────────

/// Return the list of keymap directories to search.
///
/// If the `SYSTEMD_KEYMAP_DIRECTORIES` environment variable is set and
/// non-empty, it is parsed as a colon-separated path list. Otherwise the
/// built-in defaults are returned.
pub fn keymap_directories() -> Vec<PathBuf> {
    env::var(KEYMAP_DIRS_ENV)
        .ok()
        .filter(|v| !v.is_empty())
        .map(|value| {
            value
                .split(':')
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_else(|| KBD_KEYMAP_DIRS.iter().map(PathBuf::from).collect())
}

/// Check whether a keymap name is valid.
///
/// A valid keymap name must:
/// - be non-empty and shorter than 128 characters,
/// - be a valid filename component (no `/`, not `.`, not `..`),
/// - contain only safe characters (no ASCII control chars or DEL).
pub fn keymap_is_valid(name: &str) -> bool {
    if name.is_empty() || name.len() > KEYMAP_NAME_MAX_LEN {
        return false;
    }
    if !filename_is_valid(name) {
        return false;
    }
    if !string_is_safe(name) {
        return false;
    }
    true
}

/// Recursively scan all keymap directories and return the sorted list of
/// unique, valid keymap names.
///
/// Returns [`io::ErrorKind::NotFound`] when no keymap directories exist or
/// no keymaps were found.
pub fn get_keymaps() -> io::Result<Vec<String>> {
    let mut acc = BTreeSet::new();

    for dir in keymap_directories() {
        if !dir.as_os_str().is_empty() && dir.exists() {
            // Silently ignore individual directory errors, matching C behaviour
            // where non-resource errors are logged at debug level and skipped.
            let _ = collect_keymaps(&dir, &mut acc);
        }
    }

    if acc.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no keymaps found"));
    }

    Ok(acc.into_iter().collect())
}

/// Check whether a keymap with the given name exists in any of the
/// configured keymap directories.
///
/// Returns [`io::ErrorKind::InvalidInput`] for invalid keymap names.
pub fn keymap_exists(name: &str) -> io::Result<bool> {
    if !keymap_is_valid(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid keymap name",
        ));
    }

    for dir in keymap_directories() {
        if !dir.as_os_str().is_empty() && dir.exists() {
            if keymap_exists_in_dir(&dir, name)? {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

// ── Internal helpers ──────────────────────────────────────────────────────

/// Check whether `name` is a valid filename component.
///
/// Mirrors systemd's `filename_is_valid()`:
/// - not empty, not `.`, not `..`
/// - no `/` characters
fn filename_is_valid(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains('/')
}

/// Check whether `name` contains only "safe" characters.
///
/// Mirrors systemd's `string_is_safe()`: rejects ASCII control characters
/// (U+0000–U+001F) and DEL (U+007F). All other characters — including
/// non-ASCII Unicode — are accepted.
fn string_is_safe(name: &str) -> bool {
    name.chars().all(|c| !((c as u32) <= 0x1f || c == '\x7f'))
}

/// Strip a recognized keymap file extension from `file_name`.
///
/// Returns `Some(stem)` if the file name ends with `.map` or `.map.gz`,
/// otherwise `None`.
fn strip_keymap_extension(file_name: &str) -> Option<&str> {
    KEYMAP_EXTENSIONS
        .iter()
        .find_map(|ext| file_name.strip_suffix(ext))
}

/// Recursively walk `dir` and collect valid keymap names into `acc`.
fn collect_keymaps(dir: &Path, acc: &mut BTreeSet<String>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            let _ = collect_keymaps(&path, acc);
            continue;
        }

        if !file_type.is_file() && !file_type.is_symlink() {
            continue;
        }

        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        let Some(stem) = strip_keymap_extension(file_name) else {
            continue;
        };

        if keymap_is_valid(stem) {
            acc.insert(stem.to_string());
        }
    }
    Ok(())
}

/// Search `dir` recursively for a keymap with the exact given `name`.
///
/// Returns `Ok(true)` as soon as the keymap is found, allowing
/// [`keymap_exists`] to short-circuit without scanning remaining directories.
fn keymap_exists_in_dir(dir: &Path, name: &str) -> io::Result<bool> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            if keymap_exists_in_dir(&path, name)? {
                return Ok(true);
            }
            continue;
        }

        if !file_type.is_file() && !file_type.is_symlink() {
            continue;
        }

        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        let Some(stem) = strip_keymap_extension(file_name) else {
            continue;
        };

        if stem == name {
            return Ok(true);
        }
    }
    Ok(false)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- keymap_is_valid --

    #[test]
    fn test_keymap_valid_simple_names() {
        assert!(keymap_is_valid("us"));
        assert!(keymap_is_valid("dvorak"));
        assert!(keymap_is_valid("fr-latin9"));
        assert!(keymap_is_valid("jp106"));
    }

    #[test]
    fn test_keymap_valid_empty_rejected() {
        assert!(!keymap_is_valid(""));
    }

    #[test]
    fn test_keymap_valid_too_long_rejected() {
        assert!(!keymap_is_valid(&"a".repeat(128)));
    }

    #[test]
    fn test_keymap_valid_max_length_accepted() {
        assert!(keymap_is_valid(&"a".repeat(127)));
    }

    #[test]
    fn test_keymap_valid_boundary_length() {
        // One character over the limit.
        assert!(!keymap_is_valid(&"x".repeat(128)));
        // Exactly at the limit.
        assert!(keymap_is_valid(&"x".repeat(127)));
    }

    #[test]
    fn test_keymap_valid_control_chars_rejected() {
        assert!(!keymap_is_valid("us\x01map"));
        assert!(!keymap_is_valid("us\x1fmap"));
        assert!(!keymap_is_valid("us\x7fmap"));
    }

    #[test]
    fn test_keymap_valid_dot_entries_rejected() {
        assert!(!keymap_is_valid("."));
        assert!(!keymap_is_valid(".."));
    }

    #[test]
    fn test_keymap_valid_path_separator_rejected() {
        assert!(!keymap_is_valid("path/to/keymap"));
        assert!(!keymap_is_valid("/absolute"));
    }

    #[test]
    fn test_keymap_valid_spaces_accepted() {
        assert!(keymap_is_valid("us map"));
    }

    #[test]
    fn test_keymap_valid_non_ascii_accepted() {
        // C's string_is_safe() allows bytes > 127, so non-ASCII UTF-8 passes.
        assert!(keymap_is_valid("café"));
    }

    // -- strip_keymap_extension --

    #[test]
    fn test_strip_keymap_extension() {
        assert_eq!(strip_keymap_extension("us.map"), Some("us"));
        assert_eq!(strip_keymap_extension("us.map.gz"), Some("us"));
        assert_eq!(strip_keymap_extension("us.kmap"), None);
        assert_eq!(strip_keymap_extension("us"), None);
        assert_eq!(strip_keymap_extension(".map"), Some(""));
        assert_eq!(strip_keymap_extension(""), None);
    }

    // -- keymap_directories --

    #[test]
    fn test_keymap_directories_default_count() {
        env::remove_var(KEYMAP_DIRS_ENV);
        let dirs = keymap_directories();
        assert_eq!(dirs.len(), 3);
    }

    #[test]
    fn test_keymap_directories_default_paths() {
        env::remove_var(KEYMAP_DIRS_ENV);
        let dirs = keymap_directories();
        let strs: Vec<&str> = dirs.iter().map(|d| d.to_str().unwrap()).collect();
        assert!(strs.contains(&"/usr/share/keymaps/"));
        assert!(strs.contains(&"/usr/share/kbd/keymaps/"));
        assert!(strs.contains(&"/usr/lib/kbd/keymaps/"));
    }

    // -- filename_is_valid --

    #[test]
    fn test_filename_is_valid() {
        assert!(filename_is_valid("us"));
        assert!(filename_is_valid("fr-latin9"));
        assert!(!filename_is_valid(""));
        assert!(!filename_is_valid("."));
        assert!(!filename_is_valid(".."));
        assert!(!filename_is_valid("a/b"));
    }

    // -- string_is_safe --

    #[test]
    fn test_string_is_safe() {
        assert!(string_is_safe("us"));
        assert!(string_is_safe("dvorak"));
        assert!(string_is_safe("Hello World 123"));
        assert!(string_is_safe("café")); // non-ASCII is allowed
        assert!(!string_is_safe("us\x01map")); // control char
        assert!(!string_is_safe("us\x1fmap")); // control char
        assert!(!string_is_safe("us\x7fmap")); // DEL
    }
}
