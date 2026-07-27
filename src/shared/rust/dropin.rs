// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/dropin.c, src/shared/dropin.h
//
// Drop-in configuration file path construction and management.
//
// Handles generation of drop-in directory and file paths for systemd units,
// including path escaping and filename validation. Drop-in files allow
// overriding or extending unit configuration without modifying the original
// unit file.

use crate::ffi::*;
use std::fmt;
use std::path::Path;

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum filename length (Linux NAME_MAX, excludes NUL terminator).
const NAME_MAX: usize = 255;

/// Sentinel value indicating "no level" in drop-in file naming.
/// Mirrors UINT_MAX usage in the C code where `level == UINT_MAX` means
/// no level prefix is prepended.
pub const DROPIN_LEVEL_NONE: Option<u32> = None;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors returned by drop-in operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropinError {
    /// One of the required string arguments was empty.
    EmptyArgument(&'static str),
    /// The escaped name is not a valid filename (empty, contains '/', too long, or is "." / "..").
    InvalidFilename(String),
    /// An I/O or filesystem error occurred.
    Io(String),
    /// A unit name was invalid.
    InvalidUnitName(String),
    /// Failed to derive a unit type or prefix.
    InvalidUnitType(String),
    /// Allocation failure (mirrors C's -ENOMEM).
    OutOfMemory,
}

impl std::fmt::Display for DropinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DropinError::EmptyArgument(arg) => write!(f, "required argument '{arg}' is empty"),
            DropinError::InvalidFilename(name) => {
                write!(f, "escaped name is not a valid filename: {name}")
            }
            DropinError::Io(msg) => write!(f, "I/O error: {msg}"),
            DropinError::InvalidUnitName(name) => {
                write!(f, "invalid unit name: {name}")
            }
            DropinError::InvalidUnitType(msg) => write!(f, "invalid unit type: {msg}"),
            DropinError::OutOfMemory => write!(f, "out of memory"),
        }
    }
}

impl std::error::Error for DropinError {}

// ── Escape logic ──────────────────────────────────────────────────────────

/// Escape characters that are problematic in filenames.
///
/// Mirrors the C `xescape(name, "/.")` call in `drop_in_file`. Characters
/// in `bad` are escaped as `\xHH` hex sequences, along with backslash and
/// control characters (< 0x20, >= 0x7F).
///
/// # Arguments
/// * `s`    - The input string to escape.
/// * `bad`  - Additional characters that should be hex-escaped.
pub fn xescape(s: &str, bad: &str) -> String {
    let bad_bytes: Vec<u8> = bad.bytes().collect();
    let mut out = String::with_capacity(s.len());

    for b in s.bytes() {
        let needs_escape = b < b' ' || b >= 0x7F || b == b'\\' || bad_bytes.contains(&b);

        if needs_escape {
            out.push_str(&format!("\\x{:02x}", b));
        } else {
            out.push(b as char);
        }
    }

    out
}

// ── Filename validation ───────────────────────────────────────────────────

/// Check whether a string is valid for use as a complete filename.
///
/// Mirrors the C `filename_is_valid()`. A valid filename:
/// - is not empty
/// - is not "." or ".."
/// - does not contain '/'
/// - is not longer than `NAME_MAX` (255) bytes
pub fn filename_is_valid(p: &str) -> bool {
    if p.is_empty() {
        return false;
    }
    if p == "." || p == ".." {
        return false;
    }
    if p.contains('/') {
        return false;
    }
    // NAME_MAX counts without the trailing NUL byte
    if p.len() > NAME_MAX {
        return false;
    }
    true
}

/// Check whether a string is valid as a *part* of a filename (no '/' or
/// length constraint only).
///
/// Mirrors the C `filename_part_is_valid()`. Unlike `filename_is_valid`,
/// empty strings, ".", and ".." are accepted.
pub fn filename_part_is_valid(p: &str) -> bool {
    if p.contains('/') {
        return false;
    }
    if p.len() > NAME_MAX {
        return false;
    }
    true
}

// ── Core drop-in path construction ────────────────────────────────────────

/// Result of [`drop_in_file`]: the unit drop-in directory and the full path
/// to a specific `.conf` file inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropInPaths {
    /// `<dir>/<unit>.d`
    pub unit_dir: String,
    /// `<dir>/<unit>.d/[<level>-]<escaped_name>.conf`
    pub path: String,
}

/// Construct the directory and file paths for a drop-in configuration file.
///
/// This is the idiomatic Rust equivalent of the C `drop_in_file()`.
///
/// # Arguments
/// * `dir`   - Base directory (e.g. `"/etc/systemd/system"`).
/// * `unit`  - Unit name (e.g. `"foo.service"`).
/// * `level` - Optional priority level. When `Some(n)`, the filename is
///             prefixed with `"<n>-"`. Pass `None` for no prefix.
/// * `name`  - Drop-in name (will be escaped).
///
/// # Errors
/// Returns [`DropinError::EmptyArgument`] if `dir`, `unit`, or `name` is empty.
/// Returns [`DropinError::InvalidFilename`] if the escaped name is not a valid filename.
pub fn drop_in_file(
    dir: &str,
    unit: &str,
    level: Option<u32>,
    name: &str,
) -> Result<DropInPaths, DropinError> {
    if dir.is_empty() {
        return Err(DropinError::EmptyArgument("dir"));
    }
    if unit.is_empty() {
        return Err(DropinError::EmptyArgument("unit"));
    }
    if name.is_empty() {
        return Err(DropinError::EmptyArgument("name"));
    }

    // Escape characters '/', '.' in the name — mirrors xescape(name, "/.")
    let escaped = xescape(name, "/.");
    if !filename_is_valid(&escaped) {
        return Err(DropinError::InvalidFilename(escaped));
    }

    let unit_dir = format!("{dir}/{unit}.d");

    let prefix = match level {
        Some(lv) => format!("{lv}-"),
        None => String::new(),
    };

    let path = format!("{unit_dir}/{prefix}{escaped}.conf");

    Ok(DropInPaths { unit_dir, path })
}

// ── Drop-in writing ───────────────────────────────────────────────────────

/// Write content to a drop-in configuration file.
///
/// This is the idiomatic Rust equivalent of the C `write_drop_in()`.
/// It constructs the drop-in file path and writes `data` to it, creating
/// parent directories as needed.
///
/// **Note:** In the full systemd integration this would call through to the
/// C `write_string_file()` with appropriate flags. This pure-Rust version
/// uses `std::fs` directly.
///
/// # Arguments
/// * `dir`   - Base directory.
/// * `unit`  - Unit name.
/// * `level` - Optional priority level.
/// * `name`  - Drop-in name.
/// * `data`  - Content to write.
pub fn write_drop_in(
    dir: &str,
    unit: &str,
    level: Option<u32>,
    name: &str,
    data: &str,
) -> Result<(), DropinError> {
    if data.is_empty() {
        return Err(DropinError::EmptyArgument("data"));
    }

    let paths = drop_in_file(dir, unit, level, name)?;

    // Ensure parent directory exists
    let parent = Path::new(&paths.path)
        .parent()
        .ok_or_else(|| DropinError::Io("no parent directory".into()))?;

    std::fs::create_dir_all(parent)
        .map_err(|e| DropinError::Io(format!("failed to create directory: {e}")))?;

    std::fs::write(&paths.path, data)
        .map_err(|e| DropinError::Io(format!("failed to write file: {e}")))?;

    Ok(())
}

/// Write a formatted string to a drop-in configuration file.
///
/// This is the idiomatic Rust equivalent of the C `write_drop_in_format()`.
///
/// # Arguments
/// * `dir`   - Base directory.
/// * `unit`  - Unit name.
/// * `level` - Optional priority level.
/// * `name`  - Drop-in name.
/// * `fmt`   - Format arguments (use `format_args!` or a format string).
pub fn write_drop_in_formatted(
    dir: &str,
    unit: &str,
    level: Option<u32>,
    name: &str,
    args: fmt::Arguments<'_>,
) -> Result<(), DropinError> {
    let content = fmt::format(args);
    write_drop_in(dir, unit, level, name, &content)
}

// ── Unit name helpers (pure logic) ────────────────────────────────────────

/// Check whether a unit name represents an instanced unit (contains `@`).
///
/// Mirrors `unit_name_is_valid(name, UNIT_NAME_INSTANCE)`.
pub fn unit_name_is_instance(name: &str) -> bool {
    let Some(at) = name.find('@') else {
        return false;
    };
    // Must have a dot suffix after the instance part
    let rest = &name[at + 1..];
    rest.contains('.') && !rest.starts_with('.')
}

/// Extract the template name from an instanced unit name.
///
/// For `"foo@bar.service"` returns `"foo@.service"`.
/// Returns `None` if the name is not an instanced unit.
pub fn unit_name_template(name: &str) -> Option<String> {
    let at = name.find('@')?;
    let after_at = &name[at + 1..];
    let dot = after_at.find('.')?;
    let suffix = &after_at[dot..]; // e.g. ".service"
    Some(format!("{}@{suffix}", &name[..at]))
}

/// Extract the prefix from a unit name (everything before the type suffix).
///
/// For `"foo-bar.service"` returns `"foo-bar"`.
/// Returns `None` if the name has no dot suffix.
pub fn unit_name_to_prefix(name: &str) -> Option<&str> {
    let last_dot = name.rfind('.')?;
    if last_dot == 0 {
        return None;
    }
    Some(&name[..last_dot])
}

/// Extract the type suffix from a unit name.
///
/// For `"foo.service"` returns `"service"`.
/// Returns `None` if no dot suffix exists.
pub fn unit_name_to_suffix(name: &str) -> Option<&str> {
    let last_dot = name.rfind('.')?;
    if last_dot + 1 >= name.len() {
        return None;
    }
    Some(&name[last_dot + 1..])
}

/// Extract the instance part from an instanced unit name.
///
/// For `"foo@bar.service"` returns `"bar"`.
/// Returns `None` if not instanced.
pub fn unit_name_to_instance(name: &str) -> Option<&str> {
    let at = name.find('@')?;
    let after_at = &name[at + 1..];
    let dot = after_at.find('.')?;
    if dot == 0 {
        return None;
    }
    Some(&after_at[..dot])
}

/// Build a unit name from components.
///
/// For prefix `"foo"`, instance `Some("bar")`, suffix `"service"` returns `"foo@bar.service"`.
/// For prefix `"foo"`, instance `None`, suffix `"service"` returns `"foo.service"`.
pub fn unit_name_build(prefix: &str, instance: Option<&str>, suffix: &str) -> String {
    match instance {
        Some(inst) => format!("{prefix}@{inst}.{suffix}"),
        None => format!("{prefix}.{suffix}"),
    }
}

/// Check whether a string is a valid unit name prefix.
///
/// Mirrors `unit_prefix_is_valid()` — a valid prefix is non-empty, doesn't
/// start with a dot, and is a valid filename part.
pub fn unit_prefix_is_valid(prefix: &str) -> bool {
    if prefix.is_empty() {
        return false;
    }
    if prefix.starts_with('.') {
        return false;
    }
    filename_part_is_valid(prefix)
}

/// Known systemd unit type suffixes.
const UNIT_TYPE_SUFFIXES: &[&str] = &[
    "service",
    "socket",
    "device",
    "mount",
    "automount",
    "swap",
    "target",
    "path",
    "timer",
    "snapshot",
    "slice",
    "scope",
];

/// Check whether a unit name is a top-level type name (e.g. `"service"`).
///
/// Mirrors `unit_type_from_string(name) >= 0`.
pub fn unit_name_is_type(name: &str) -> bool {
    UNIT_TYPE_SUFFIXES.contains(&name)
}

/// Resolve the unit type suffix from a full unit name.
///
/// Returns `None` if the suffix is not a recognized unit type.
pub fn unit_name_type(name: &str) -> Option<&str> {
    let suffix = unit_name_to_suffix(name)?;
    if UNIT_TYPE_SUFFIXES.contains(&suffix) {
        Some(suffix)
    } else {
        None
    }
}

// ── Drop-in directory discovery ───────────────────────────────────────────

/// Find the last dash-separated component in a prefix and chop it.
///
/// Given `"foo-bar-waldo"`, returns `Some("foo-bar-")` (the prefix with the
/// last component truncated after the dash).
///
/// This mirrors the prefix-chopping logic in `unit_file_find_dirs()`.
fn chop_prefix_at_last_dash(prefix: &str) -> Option<String> {
    // Find the last '-' that isn't at position 0
    let last_dash = prefix.rfind('-')?;
    if last_dash == 0 {
        return None;
    }

    let n = last_dash;
    let after_dash = &prefix[n + 1..];

    // If the part after the dash is empty ("trailing dash"), chop the dash
    // and try one position earlier — but only once (mirrors `chopped` logic).
    if after_dash.is_empty() {
        // Try one more dash back
        let rest = &prefix[..n];
        let prev_dash = rest.rfind('-')?;
        if prev_dash == 0 {
            return None;
        }
        let mut result = prefix[..=prev_dash].to_owned();
        result.truncate(prev_dash + 1);
        return Some(result);
    }

    // Normal case: chop after the dash
    Some(format!("{}-", &prefix[..n]))
}

/// Determine the "parent" unit name for dash-wildcard drop-in resolution.
///
/// Given `"foo-bar-waldo.service"`, returns `"foo-bar-.service"`.
/// Returns `None` if there is no dash-separated prefix to recurse into,
/// or if the resulting prefix is not valid.
pub fn parent_unit_from_dash_prefix(name: &str) -> Option<String> {
    let prefix = unit_name_to_prefix(name)?;
    let suffix = unit_name_to_suffix(name)?;

    // Don't recurse for top-level type names
    if unit_name_is_type(name) {
        return None;
    }

    // Get the prefix with the trailing `-` after the last non-trailing dash
    let chopped = chop_prefix_at_last_dash(prefix)?;

    // Strip trailing `-` to get the actual prefix to validate
    let check_prefix = chopped.trim_end_matches('-');
    if !unit_prefix_is_valid(check_prefix) {
        return None;
    }

    // For instance units, preserve the instance
    let instance = unit_name_to_instance(name);
    Some(unit_name_build(&chopped, instance, suffix))
}

/// Collect all drop-in directory search paths for a given unit name.
///
/// This mirrors the recursive logic of `unit_file_find_dirs()`. For a given
/// unit name it collects:
/// 1. `<unit_path>/<name><dir_suffix>` — the direct drop-in directory
/// 2. If instanced, the template's drop-in directory (recursively)
/// 3. Parent dash-wildcard unit drop-in directories (recursively)
///
/// # Arguments
/// * `unit_path`  - A single search root (e.g. `"/etc/systemd/system"`).
/// * `name`       - The unit name (e.g. `"foo-bar.service"`).
/// * `dir_suffix` - Typically `".d"` — appended to the unit name to form the
///                  drop-in directory name.
/// * `existing_dirs` - Set of paths known to exist (mirrors `unit_path_cache`).
///                      Pass `None` to skip existence checks.
///
/// # Returns
/// A vector of directory paths to search (not filtered for existence here;
/// that is the caller's responsibility).
pub fn find_dropin_dirs(
    unit_path: &str,
    name: &str,
    dir_suffix: &str,
    existing_dirs: Option<&std::collections::HashSet<String>>,
) -> Vec<String> {
    let mut dirs = Vec::new();
    find_dropin_dirs_recursive(unit_path, name, dir_suffix, existing_dirs, &mut dirs);
    dirs
}

fn find_dropin_dirs_recursive(
    unit_path: &str,
    name: &str,
    dir_suffix: &str,
    existing_dirs: Option<&std::collections::HashSet<String>>,
    dirs: &mut Vec<String>,
) {
    let path = format!("{unit_path}/{name}{dir_suffix}");

    let should_add = match existing_dirs {
        Some(cache) => cache.contains(&path),
        None => true,
    };

    if should_add {
        dirs.push(path);
    }

    // If this is an instance unit, also search the template
    if unit_name_is_instance(name) {
        if let Some(template) = unit_name_template(name) {
            find_dropin_dirs_recursive(unit_path, &template, dir_suffix, existing_dirs, dirs);
        }
    }

    // Don't recurse for top-level type names
    if unit_name_is_type(name) {
        return;
    }

    // Try the parent dash-wildcard unit
    if let Some(parent) = parent_unit_from_dash_prefix(name) {
        find_dropin_dirs_recursive(unit_path, &parent, dir_suffix, existing_dirs, dirs);
    }
}

/// Top-level function to find all drop-in configuration file paths for a unit.
///
/// This is the idiomatic Rust equivalent of `unit_file_find_dropin_paths()`.
///
/// # Arguments
/// * `lookup_paths` - List of search roots (e.g. `["/etc/systemd/system", "/usr/lib/systemd/system"]`).
/// * `dir_suffix`   - Drop-in directory suffix (typically `".d"`).
/// * `name`         - Primary unit name (may be `None`).
/// * `aliases`      - Additional alias names for the unit.
/// * `existing_dirs` - Set of paths known to exist, or `None` to skip checks.
///
/// # Returns
/// A vector of `.conf` file paths found across all drop-in directories, or an
/// empty vector if none exist. The files are collected from all lookup paths
/// for the unit name, its aliases, its template (if instanced), dash-wildcard
/// parents, and the top-level type drop-in directory.
pub fn unit_file_find_dropin_paths(
    lookup_paths: &[&str],
    dir_suffix: &str,
    name: Option<&str>,
    aliases: &[String],
    existing_dirs: Option<&std::collections::HashSet<String>>,
) -> Vec<String> {
    let mut all_dirs: Vec<String> = Vec::new();

    // Collect drop-in directories for the primary name
    if let Some(n) = name {
        for p in lookup_paths {
            let mut sub = find_dropin_dirs(p, n, dir_suffix, existing_dirs);
            all_dirs.append(&mut sub);
        }
    }

    // Collect drop-in directories for all aliases
    for alias in aliases {
        for p in lookup_paths {
            let mut sub = find_dropin_dirs(p, alias, dir_suffix, existing_dirs);
            all_dirs.append(&mut sub);
        }
    }

    // Add the top-level type drop-in directory (most generic, added last)
    let effective_name = name.or_else(|| aliases.first().map(|s| s.as_str()));
    if let Some(n) = effective_name {
        if let Some(unit_type) = unit_name_type(n) {
            for p in lookup_paths {
                let mut sub = find_dropin_dirs(p, unit_type, dir_suffix, existing_dirs);
                all_dirs.append(&mut sub);
            }
        }
    }

    if all_dirs.is_empty() {
        return Vec::new();
    }

    // Deduplicate (order-preserving)
    let mut seen = std::collections::HashSet::new();
    all_dirs.retain(|d| seen.insert(d.clone()));

    // In a full integration, conf_files_list_strv would scan each dir for
    // *.conf files and return sorted paths. Here we return the directory list;
    // file enumeration would be a separate concern.
    all_dirs
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── xescape tests ──────────────────────────────────────────────────

    #[test]
    fn test_xescape_nothing_to_escape() {
        assert_eq!(xescape("hello", "/."), "hello");
    }

    #[test]
    fn test_xescape_slash_and_dot() {
        // '/' = 0x2F, '.' = 0x2E
        assert_eq!(xescape("a/b.c", "/."), "a\\x2fb\\x2ec");
    }

    #[test]
    fn test_xescape_backslash() {
        // '\\' = 0x5C
        assert_eq!(xescape("a\\b", "/."), "a\\x5cb");
    }

    #[test]
    fn test_xescape_control_chars() {
        // '\n' = 0x0A, '\t' = 0x09
        assert_eq!(xescape("a\nb\tc", "/."), "a\\x0ab\\x09c");
    }

    #[test]
    fn test_xescape_high_bytes() {
        // 0xFF byte in UTF-8 is invalid; use a byte string approach
        let input = "abc";
        assert_eq!(xescape(input, ""), "abc");
    }

    #[test]
    fn test_xescape_empty_input() {
        assert_eq!(xescape("", "/."), "");
    }

    // ── filename_is_valid tests ────────────────────────────────────────

    #[test]
    fn test_filename_is_valid_normal() {
        assert!(filename_is_valid("local.conf"));
        assert!(filename_is_valid("a"));
    }

    #[test]
    fn test_filename_is_valid_rejects_empty() {
        assert!(!filename_is_valid(""));
    }

    #[test]
    fn test_filename_is_valid_rejects_dot() {
        assert!(!filename_is_valid("."));
        assert!(!filename_is_valid(".."));
    }

    #[test]
    fn test_filename_is_valid_rejects_slash() {
        assert!(!filename_is_valid("a/b"));
    }

    #[test]
    fn test_filename_is_valid_rejects_too_long() {
        let long_name = "a".repeat(256);
        assert!(!filename_is_valid(&long_name));
        let max_name = "a".repeat(255);
        assert!(filename_is_valid(&max_name));
    }

    // ── filename_part_is_valid tests ───────────────────────────────────

    #[test]
    fn test_filename_part_is_valid_allows_dot_and_empty() {
        assert!(filename_part_is_valid("."));
        assert!(filename_part_is_valid(".."));
        assert!(filename_part_is_valid(""));
    }

    #[test]
    fn test_filename_part_is_valid_rejects_slash() {
        assert!(!filename_part_is_valid("a/b"));
    }

    // ── drop_in_file tests ─────────────────────────────────────────────

    #[test]
    fn test_drop_in_file_with_level() {
        let result =
            drop_in_file("/etc/systemd/system", "a.service", Some(10), "local.conf").unwrap();
        assert_eq!(result.unit_dir, "/etc/systemd/system/a.service.d");
        // '/' and '.' in "local.conf" get escaped
        assert_eq!(
            result.path,
            "/etc/systemd/system/a.service.d/10-local\\x2econf.conf"
        );
    }

    #[test]
    fn test_drop_in_file_without_level() {
        let result = drop_in_file("/etc/systemd/system", "a.service", None, "override").unwrap();
        assert_eq!(result.unit_dir, "/etc/systemd/system/a.service.d");
        assert_eq!(result.path, "/etc/systemd/system/a.service.d/override.conf");
    }

    #[test]
    fn test_drop_in_file_empty_dir_rejected() {
        assert_eq!(
            drop_in_file("", "a.service", None, "x").unwrap_err(),
            DropinError::EmptyArgument("dir")
        );
    }

    #[test]
    fn test_drop_in_file_empty_unit_rejected() {
        assert_eq!(
            drop_in_file("/etc", "", None, "x").unwrap_err(),
            DropinError::EmptyArgument("unit")
        );
    }

    #[test]
    fn test_drop_in_file_empty_name_rejected() {
        assert_eq!(
            drop_in_file("/etc", "a.service", None, "").unwrap_err(),
            DropinError::EmptyArgument("name")
        );
    }

    #[test]
    fn test_drop_in_file_level_zero() {
        let result = drop_in_file("/etc", "b.service", Some(0), "name").unwrap();
        assert!(result.path.contains("/0-name.conf"));
    }

    // ── unit name helper tests ─────────────────────────────────────────

    #[test]
    fn test_unit_name_is_instance() {
        assert!(unit_name_is_instance("foo@bar.service"));
        assert!(!unit_name_is_instance("foo.service"));
        assert!(!unit_name_is_instance("foo@.service"));
    }

    #[test]
    fn test_unit_name_template() {
        assert_eq!(
            unit_name_template("foo@bar.service"),
            Some("foo@.service".to_owned())
        );
        assert_eq!(unit_name_template("foo.service"), None);
    }

    #[test]
    fn test_unit_name_to_prefix() {
        assert_eq!(unit_name_to_prefix("foo-bar.service"), Some("foo-bar"));
        assert_eq!(unit_name_to_prefix("foo.service"), Some("foo"));
        assert_eq!(unit_name_to_prefix("nosuffix"), None);
    }

    #[test]
    fn test_unit_name_to_suffix() {
        assert_eq!(unit_name_to_suffix("foo.service"), Some("service"));
        assert_eq!(unit_name_to_suffix("bar.mount"), Some("mount"));
        assert_eq!(unit_name_to_suffix("nosuffix"), None);
    }

    #[test]
    fn test_unit_name_to_instance() {
        assert_eq!(unit_name_to_instance("foo@bar.service"), Some("bar"));
        assert_eq!(unit_name_to_instance("foo.service"), None);
        assert_eq!(unit_name_to_instance("foo@.service"), None);
    }

    #[test]
    fn test_unit_name_build() {
        assert_eq!(
            unit_name_build("foo", Some("bar"), "service"),
            "foo@bar.service"
        );
        assert_eq!(unit_name_build("foo", None, "service"), "foo.service");
    }

    #[test]
    fn test_unit_prefix_is_valid() {
        assert!(unit_prefix_is_valid("foo"));
        assert!(unit_prefix_is_valid("foo-bar"));
        assert!(!unit_prefix_is_valid(""));
        assert!(!unit_prefix_is_valid(".hidden"));
        assert!(!unit_prefix_is_valid("a/b"));
    }

    #[test]
    fn test_unit_name_is_type() {
        assert!(unit_name_is_type("service"));
        assert!(unit_name_is_type("socket"));
        assert!(!unit_name_is_type("foo"));
        assert!(!unit_name_is_type("bar"));
    }

    #[test]
    fn test_unit_name_type() {
        assert_eq!(unit_name_type("foo.service"), Some("service"));
        assert_eq!(unit_name_type("bar.socket"), Some("socket"));
        assert_eq!(unit_name_type("baz.xyz"), None);
    }

    // ── chop_prefix_at_last_dash tests ─────────────────────────────────

    #[test]
    fn test_chop_prefix_basic() {
        // "foo-bar-waldo" → last dash before "waldo", result "foo-bar-"
        assert_eq!(
            chop_prefix_at_last_dash("foo-bar-waldo"),
            Some("foo-bar-".to_owned())
        );
    }

    #[test]
    fn test_chop_prefix_single_dash() {
        assert_eq!(chop_prefix_at_last_dash("foo-bar"), Some("foo-".to_owned()));
    }

    #[test]
    fn test_chop_prefix_no_dash() {
        assert_eq!(chop_prefix_at_last_dash("foobar"), None);
    }

    #[test]
    fn test_chop_prefix_leading_dash() {
        assert_eq!(chop_prefix_at_last_dash("-foo"), None);
    }

    // ── parent_unit_from_dash_prefix tests ─────────────────────────────

    #[test]
    fn test_parent_unit_from_dash_prefix_multi() {
        // "foo-bar-waldo.service" → prefix "foo-bar-waldo" → chop to "foo-bar-"
        // check_prefix = "foo-bar" → result "foo-bar-.service"
        assert_eq!(
            parent_unit_from_dash_prefix("foo-bar-waldo.service"),
            Some("foo-bar-.service".to_owned())
        );
    }

    #[test]
    fn test_parent_unit_from_dash_prefix_single() {
        // "foo-bar.service" → prefix "foo-bar" → chop to "foo-"
        // check_prefix = "foo" → result "foo-.service"
        assert_eq!(
            parent_unit_from_dash_prefix("foo-bar.service"),
            Some("foo-.service".to_owned())
        );
    }

    #[test]
    fn test_parent_unit_from_dash_prefix_no_dash() {
        assert_eq!(parent_unit_from_dash_prefix("foobar.service"), None);
    }

    #[test]
    fn test_parent_unit_from_dash_prefix_type_name() {
        assert_eq!(parent_unit_from_dash_prefix("service"), None);
    }

    // ── find_dropin_dirs tests ─────────────────────────────────────────

    #[test]
    fn test_find_dropin_dirs_simple() {
        let dirs = find_dropin_dirs("/etc/systemd/system", "foo.service", ".d", None);
        assert!(dirs.contains(&"/etc/systemd/system/foo.service.d".to_owned()));
    }

    #[test]
    fn test_find_dropin_dirs_with_dash_prefix() {
        let dirs = find_dropin_dirs("/etc/systemd/system", "foo-bar.service", ".d", None);
        // Should contain both the direct dir and the wildcard parent
        assert!(dirs.contains(&"/etc/systemd/system/foo-bar.service.d".to_owned()));
        assert!(dirs.contains(&"/etc/systemd/system/foo-.service.d".to_owned()));
    }

    #[test]
    fn test_find_dropin_dirs_instance() {
        let dirs = find_dropin_dirs("/etc/systemd/system", "foo@bar.service", ".d", None);
        assert!(dirs.contains(&"/etc/systemd/system/foo@bar.service.d".to_owned()));
        assert!(dirs.contains(&"/etc/systemd/system/foo@.service.d".to_owned()));
    }

    // ── unit_file_find_dropin_paths tests ──────────────────────────────

    #[test]
    fn test_find_dropin_paths_basic() {
        let paths = unit_file_find_dropin_paths(
            &["/etc/systemd/system"],
            ".d",
            Some("foo.service"),
            &[],
            None,
        );
        assert!(!paths.is_empty());
        assert!(paths.iter().any(|p| p.contains("foo.service.d")));
        // Also includes the type-level dir
        assert!(paths.iter().any(|p| p.contains("service.d")));
    }

    #[test]
    fn test_find_dropin_paths_with_aliases() {
        let aliases = vec!["bar.service".to_owned()];
        let paths = unit_file_find_dropin_paths(
            &["/etc/systemd/system"],
            ".d",
            Some("foo.service"),
            &aliases,
            None,
        );
        assert!(paths.iter().any(|p| p.contains("foo.service.d")));
        assert!(paths.iter().any(|p| p.contains("bar.service.d")));
    }

    #[test]
    fn test_find_dropin_paths_no_name_no_aliases() {
        let paths = unit_file_find_dropin_paths(&["/etc/systemd/system"], ".d", None, &[], None);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_find_dropin_paths_with_existing_dirs_filter() {
        let mut existing = std::collections::HashSet::new();
        existing.insert("/etc/systemd/system/foo.service.d".to_owned());

        let paths = unit_file_find_dropin_paths(
            &["/etc/systemd/system"],
            ".d",
            Some("foo.service"),
            &[],
            Some(&existing),
        );
        // Only the dir that exists in the cache should be present
        assert!(paths.contains(&"/etc/systemd/system/foo.service.d".to_owned()));
        // The type-level "service.d" is NOT in the cache, so it should be excluded
        assert!(!paths
            .iter()
            .any(|p| p.contains("service.d") && !p.contains("foo.service")));
    }

    // ── write_drop_in tests (uses tempdir) ─────────────────────────────

    #[test]
    fn test_write_drop_in_creates_file() {
        let tmp = std::env::temp_dir().join("dropin_test_write");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let dir = tmp.to_str().unwrap();
        write_drop_in(dir, "test.service", Some(5), "override", "key=value\n").unwrap();

        let paths = drop_in_file(dir, "test.service", Some(5), "override").unwrap();
        let content = std::fs::read_to_string(&paths.path).unwrap();
        assert_eq!(content, "key=value\n");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_write_drop_in_formatted() {
        let tmp = std::env::temp_dir().join("dropin_test_fmt");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let dir = tmp.to_str().unwrap();
        write_drop_in_formatted(
            dir,
            "test.service",
            None,
            "override",
            format_args!("[Unit]\nDescription={}\n", "hello"),
        )
        .unwrap();

        let paths = drop_in_file(dir, "test.service", None, "override").unwrap();
        let content = std::fs::read_to_string(&paths.path).unwrap();
        assert!(content.contains("Description=hello"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_drop_in_paths_equality() {
        let a = DropInPaths {
            unit_dir: "/etc/a.d".to_owned(),
            path: "/etc/a.d/10-x.conf".to_owned(),
        };
        let b = DropInPaths {
            unit_dir: "/etc/a.d".to_owned(),
            path: "/etc/a.d/10-x.conf".to_owned(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_dropin_error_display() {
        let err = DropinError::EmptyArgument("dir");
        assert!(err.to_string().contains("dir"));

        let err = DropinError::InvalidFilename("bad/name".to_owned());
        assert!(err.to_string().contains("bad/name"));

        let err = DropinError::InvalidUnitName("@@@".to_owned());
        assert!(err.to_string().contains("@@@"));
    }
}
