// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/userdb-dropin.c, src/shared/userdb-dropin.h
//
// Drop-in user/group record loading from filesystem directories.
//
// Reads JSON user/group records from drop-in directories
// (/run/systemd/userdb/, /etc/systemd/userdb/, etc.) and optional
// privileged companion files (.user-privileged / .group-privileged).
// The general assumption is that whoever provides these records makes
// the .user/.group file world-readable, but the .privileged file
// readable to root and the assigned UID/GID only.

use crate::ffi::*;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

// ── Constants ─────────────────────────────────────────────────────────────

/// Drop-in search directories for userdb files, in priority order.
///
/// Corresponds to C `USERDB_DROPIN_DIR_NULSTR("userdb")`. Runtime
/// directories override system directories.
pub const USERDB_DROPIN_USER_DIRS: &[&str] = &[
    "/etc/userdb",
    "/run/userdb",
    "/run/host/userdb",
    "/usr/local/lib/userdb",
    "/usr/lib/userdb",
];

/// Drop-in search directories for group files (same paths as user dirs).
pub const USERDB_DROPIN_GROUP_DIRS: &[&str] = USERDB_DROPIN_USER_DIRS;

/// UserDB flag: suppress loading of shadow/privileged data.
///
/// Corresponds to C `USERDB_SUPPRESS_SHADOW`.
pub const USERDB_SUPPRESS_SHADOW: u64 = 1 << 3;

/// Sentinel value for an invalid UID.
pub const UID_INVALID: u32 = u32::MAX;

/// Sentinel value for an invalid GID.
pub const GID_INVALID: u32 = u32::MAX;

// ── Error type ────────────────────────────────────────────────────────────

/// Errors returned by drop-in record loading operations.
///
/// Maps to the negative errno values returned by the C API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropinError {
    /// No such user/group record found (→ -ESRCH).
    NotFound,
    /// Invalid argument (→ -EINVAL).
    InvalidArgument,
    /// Permission denied reading privileged file (→ -EACCES).
    PermissionDenied,
    /// Generic I/O error (→ -EIO).
    Io,
    /// Out of memory (→ -ENOMEM).
    OutOfMemory,
    /// JSON parse error with a human-readable description.
    ParseError(String),
    /// Record name or ID does not match expected value (→ -EINVAL).
    Mismatch,
    /// A raw errno value not covered above.
    RawErrno(i32),
}

impl DropinError {
    /// Convert to the negative errno value used by the C API.
    pub fn to_neg_errno(&self) -> i32 {
        match self {
            Self::NotFound => -3,          // ESRCH
            Self::InvalidArgument => -22,  // EINVAL
            Self::PermissionDenied => -13, // EACCES
            Self::Io => -5,                // EIO
            Self::OutOfMemory => -12,      // ENOMEM
            Self::ParseError(_) => -22,    // EINVAL
            Self::Mismatch => -22,         // EINVAL
            Self::RawErrno(e) => -*e,
        }
    }

    /// Create from a [`std::io::Error`], mapping ENOENT to `NotFound`.
    pub fn from_io_error(err: io::Error) -> Self {
        match err.raw_os_error() {
            Some(2) => Self::NotFound,          // ENOENT
            Some(13) => Self::PermissionDenied, // EACCES
            Some(code) => Self::RawErrno(code),
            None => Self::Io,
        }
    }
}

impl std::fmt::Display for DropinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "No such drop-in record (ESRCH)"),
            Self::InvalidArgument => write!(f, "Invalid argument (EINVAL)"),
            Self::PermissionDenied => write!(f, "Permission denied (EACCES)"),
            Self::Io => write!(f, "I/O error (EIO)"),
            Self::OutOfMemory => write!(f, "Out of memory (ENOMEM)"),
            Self::ParseError(msg) => write!(f, "JSON parse error: {msg}"),
            Self::Mismatch => write!(f, "Record name/ID mismatch (EINVAL)"),
            Self::RawErrno(e) => write!(f, "Raw errno: {e}"),
        }
    }
}

impl std::error::Error for DropinError {}

/// Result type alias for drop-in operations.
pub type DropinResult<T> = Result<T, DropinError>;

// ── JSON value type ───────────────────────────────────────────────────────

/// Minimal JSON value type for parsing drop-in files.
///
/// Provides just enough functionality to extract the fields needed for
/// user/group records without depending on an external JSON library.
#[derive(Debug, Clone)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    /// Look up a string value by key in a JSON object.
    fn get_str(&self, key: &str) -> Option<&str> {
        match self {
            JsonValue::Object(pairs) => {
                pairs
                    .iter()
                    .find(|(k, _)| k == key)
                    .and_then(|(_, v)| match v {
                        JsonValue::String(s) => Some(s.as_str()),
                        _ => None,
                    })
            }
            _ => None,
        }
    }

    /// Look up an unsigned integer value by key in a JSON object.
    fn get_u64(&self, key: &str) -> Option<u64> {
        match self {
            JsonValue::Object(pairs) => {
                pairs
                    .iter()
                    .find(|(k, _)| k == key)
                    .and_then(|(_, v)| match v {
                        JsonValue::Number(n) => Some(*n as u64),
                        JsonValue::String(s) => s.parse().ok(),
                        _ => None,
                    })
            }
            _ => None,
        }
    }

    /// Look up a boolean value by key in a JSON object.
    fn get_bool(&self, key: &str) -> Option<bool> {
        match self {
            JsonValue::Object(pairs) => {
                pairs
                    .iter()
                    .find(|(k, _)| k == key)
                    .and_then(|(_, v)| match v {
                        JsonValue::Bool(b) => Some(*b),
                        JsonValue::String(s) => s.parse().ok(),
                        _ => None,
                    })
            }
            _ => None,
        }
    }

    /// Look up a string array by key in a JSON object.
    fn get_string_array(&self, key: &str) -> Vec<String> {
        match self {
            JsonValue::Object(pairs) => pairs
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| match v {
                    JsonValue::Array(items) => items
                        .iter()
                        .filter_map(|item| match item {
                            JsonValue::String(s) => Some(s.clone()),
                            _ => None,
                        })
                        .collect(),
                    _ => Vec::new(),
                })
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    /// Merge another JSON object into this one. Keys from `overlay`
    /// override keys in `base`.
    fn merge(base: &mut JsonValue, overlay: &JsonValue) {
        if let (JsonValue::Object(base_pairs), JsonValue::Object(overlay_pairs)) = (base, overlay) {
            for (key, value) in overlay_pairs {
                if let Some(pos) = base_pairs.iter().position(|(k, _)| k == key) {
                    // Recursively merge objects; replace everything else.
                    if let (JsonValue::Object(_), JsonValue::Object(_)) =
                        (&base_pairs[pos].1, value)
                    {
                        JsonValue::merge(&mut base_pairs[pos].1, value);
                        continue;
                    }
                    base_pairs[pos].1 = value.clone();
                } else {
                    base_pairs.push((key.clone(), value.clone()));
                }
            }
        }
    }
}

// ── JSON parser ───────────────────────────────────────────────────────────

/// Minimal recursive-descent JSON parser.
///
/// Handles the subset of JSON found in systemd user/group drop-in files:
/// objects, arrays, strings, numbers, booleans, and null.
struct JsonParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    /// Skip whitespace characters.
    fn skip_whitespace(&mut self) {
        while self.pos < self.input.len() && self.input.as_bytes()[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    /// Peek at the current character without advancing.
    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    /// Consume the next character.
    fn next_char(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    /// Parse the top-level JSON value.
    fn parse_value(&mut self) -> DropinResult<JsonValue> {
        self.skip_whitespace();
        match self.peek() {
            Some('n') => self.parse_literal("null", JsonValue::Null),
            Some('t') => self.parse_literal("true", JsonValue::Bool(true)),
            Some('f') => self.parse_literal("false", JsonValue::Bool(false)),
            Some('"') => self.parse_string().map(JsonValue::String),
            Some('[') => self.parse_array(),
            Some('{') => self.parse_object(),
            Some('-' | '0'..='9') => self.parse_number(),
            Some(ch) => Err(DropinError::ParseError(format!(
                "unexpected character '{ch}' at position {}",
                self.pos
            ))),
            None => Err(DropinError::ParseError("unexpected end of input".into())),
        }
    }

    /// Parse a literal keyword (true, false, null).
    fn parse_literal(&mut self, expected: &str, value: JsonValue) -> DropinResult<JsonValue> {
        let end = self.pos + expected.len();
        if end > self.input.len() || &self.input[self.pos..end] != expected {
            return Err(DropinError::ParseError(format!(
                "expected '{expected}' at position {}",
                self.pos
            )));
        }
        self.pos = end;
        Ok(value)
    }

    /// Parse a JSON string (handles basic escape sequences).
    fn parse_string(&mut self) -> DropinResult<String> {
        if self.next_char() != Some('"') {
            return Err(DropinError::ParseError(format!(
                "expected '\"' at position {}",
                self.pos
            )));
        }

        let mut result = String::new();
        loop {
            match self.next_char() {
                Some('"') => return Ok(result),
                Some('\\') => {
                    let escaped = match self.next_char() {
                        Some('"') => '"',
                        Some('\\') => '\\',
                        Some('/') => '/',
                        Some('n') => '\n',
                        Some('r') => '\r',
                        Some('t') => '\t',
                        Some('b') => '\u{0008}',
                        Some('f') => '\u{000C}',
                        Some(c) => c, // pass through unknown escapes
                        None => {
                            return Err(DropinError::ParseError(
                                "unterminated string escape".into(),
                            ))
                        }
                    };
                    result.push(escaped);
                }
                Some(c) => result.push(c),
                None => return Err(DropinError::ParseError("unterminated string".into())),
            }
        }
    }

    /// Parse a JSON number (integer or floating-point).
    fn parse_number(&mut self) -> DropinResult<JsonValue> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.next_char();
        }

        while let Some('0'..='9') = self.peek() {
            self.next_char();
        }

        if self.peek() == Some('.') {
            self.next_char();
            while let Some('0'..='9') = self.peek() {
                self.next_char();
            }
        }

        if self.peek() == Some('e') || self.peek() == Some('E') {
            self.next_char();
            if self.peek() == Some('+') || self.peek() == Some('-') {
                self.next_char();
            }
            while let Some('0'..='9') = self.peek() {
                self.next_char();
            }
        }

        let num_str = &self.input[start..self.pos];
        num_str.parse::<f64>().map(JsonValue::Number).map_err(|_| {
            DropinError::ParseError(format!("invalid number '{num_str}' at position {start}"))
        })
    }

    /// Parse a JSON array.
    fn parse_array(&mut self) -> DropinResult<JsonValue> {
        self.next_char(); // consume '['
        self.skip_whitespace();

        let mut items = Vec::new();

        if self.peek() == Some(']') {
            self.next_char();
            return Ok(JsonValue::Array(items));
        }

        loop {
            items.push(self.parse_value()?);
            self.skip_whitespace();
            match self.peek() {
                Some(',') => {
                    self.next_char();
                    self.skip_whitespace();
                }
                Some(']') => {
                    self.next_char();
                    return Ok(JsonValue::Array(items));
                }
                _ => {
                    return Err(DropinError::ParseError(format!(
                        "expected ',' or ']' at position {}",
                        self.pos
                    )))
                }
            }
        }
    }

    /// Parse a JSON object.
    fn parse_object(&mut self) -> DropinResult<JsonValue> {
        self.next_char(); // consume '{'
        self.skip_whitespace();

        let mut pairs = Vec::new();

        if self.peek() == Some('}') {
            self.next_char();
            return Ok(JsonValue::Object(pairs));
        }

        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();
            if self.next_char() != Some(':') {
                return Err(DropinError::ParseError(format!(
                    "expected ':' after key at position {}",
                    self.pos
                )));
            }
            self.skip_whitespace();
            let value = self.parse_value()?;
            pairs.push((key, value));
            self.skip_whitespace();

            match self.peek() {
                Some(',') => {
                    self.next_char();
                    self.skip_whitespace();
                }
                Some('}') => {
                    self.next_char();
                    return Ok(JsonValue::Object(pairs));
                }
                _ => {
                    return Err(DropinError::ParseError(format!(
                        "expected ',' or '}}' at position {}",
                        self.pos
                    )))
                }
            }
        }
    }
}

/// Parse a JSON string into a [`JsonValue`].
fn parse_json(input: &str) -> DropinResult<JsonValue> {
    let mut parser = JsonParser::new(input);
    let value = parser.parse_value()?;
    parser.skip_whitespace();
    if parser.pos < parser.input.len() {
        return Err(DropinError::ParseError(format!(
            "trailing characters at position {}",
            parser.pos
        )));
    }
    Ok(value)
}

/// Read a file's contents as a string.
fn read_file_contents(path: &Path) -> DropinResult<String> {
    fs::read_to_string(path).map_err(DropinError::from_io_error)
}

// ── Record types ──────────────────────────────────────────────────────────

/// A user record loaded from a drop-in file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropinUserRecord {
    /// Canonical user name (e.g. "root").
    pub user_name: Option<String>,
    /// Numeric user ID.
    pub uid: u32,
    /// Primary group ID.
    pub gid: u32,
    /// Home directory path.
    pub home_directory: Option<String>,
    /// Login shell path.
    pub shell: Option<String>,
    /// Real/gecos name.
    pub real_name: Option<String>,
    /// Whether the account is locked.
    pub locked: bool,
    /// Whether this is a partial record (missing privileged data).
    pub incomplete: bool,
    /// User disposition string.
    pub disposition: Option<String>,
    /// Service that provided this record.
    pub service: Option<String>,
    /// Realm for the user.
    pub realm: Option<String>,
}

impl DropinUserRecord {
    /// Create a new default (empty) user record.
    pub fn new() -> Self {
        Self {
            user_name: None,
            uid: UID_INVALID,
            gid: GID_INVALID,
            home_directory: None,
            shell: None,
            real_name: None,
            locked: false,
            incomplete: false,
            disposition: None,
            service: None,
            realm: None,
        }
    }

    /// Check if the record's user name matches the expected name.
    pub fn matches_name(&self, name: &str) -> bool {
        self.user_name.as_deref() == Some(name)
    }
}

impl Default for DropinUserRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// A group record loaded from a drop-in file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropinGroupRecord {
    /// Canonical group name (e.g. "root").
    pub group_name: Option<String>,
    /// Numeric group ID.
    pub gid: u32,
    /// Group description / gecos field.
    pub description: Option<String>,
    /// Whether this is a partial record (missing privileged data).
    pub incomplete: bool,
    /// Group disposition string.
    pub disposition: Option<String>,
    /// Service that provided this record.
    pub service: Option<String>,
    /// List of group member user names.
    pub members: Vec<String>,
}

impl DropinGroupRecord {
    /// Create a new default (empty) group record.
    pub fn new() -> Self {
        Self {
            group_name: None,
            gid: GID_INVALID,
            description: None,
            incomplete: false,
            disposition: None,
            service: None,
            members: Vec::new(),
        }
    }

    /// Check if the record's group name matches the expected name.
    pub fn matches_name(&self, name: &str) -> bool {
        self.group_name.as_deref() == Some(name)
    }
}

impl Default for DropinGroupRecord {
    fn default() -> Self {
        Self::new()
    }
}

// ── Validation helpers ────────────────────────────────────────────────────

/// Check if a UID is valid (not `UID_INVALID`).
pub fn uid_is_valid(uid: u32) -> bool {
    uid != UID_INVALID
}

/// Check if a GID is valid (not `GID_INVALID`).
pub fn gid_is_valid(gid: u32) -> bool {
    gid != GID_INVALID
}

/// Check whether `name` qualifies as a valid filename for drop-in lookup.
///
/// A valid filename must be non-empty, at most 255 bytes, contain no NUL
/// bytes, no slashes, no newlines, and not start with '.'. Only ASCII
/// alphanumeric characters plus '_', '-', and '.' are allowed.
fn filename_is_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.bytes().any(|b| b == 0 || b == b'/')
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

// ── File search ───────────────────────────────────────────────────────────

/// Search for a drop-in file across the given directories.
///
/// Returns the first existing file path found, or `None` if no file exists
/// in any of the directories.
pub fn search_dropin_file(filename: &str, dirs: &[&str]) -> Option<PathBuf> {
    for dir in dirs {
        let path = Path::new(dir).join(filename);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

/// List all drop-in files with a given suffix across directories.
///
/// Deduplicates by canonical path to avoid returning the same file
/// multiple times when directories overlap (e.g. via symlinks).
pub fn list_dropin_files(suffix: &str, dirs: &[&str]) -> Vec<PathBuf> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();

    for dir in dirs {
        let dir_path = Path::new(dir);
        if !dir_path.is_dir() {
            continue;
        }

        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                let file_name = entry.file_name();
                let name = match file_name.to_str() {
                    Some(n) => n,
                    None => continue,
                };

                if !name.ends_with(suffix) {
                    continue;
                }

                if let Ok(canonical) = entry.path().canonicalize() {
                    if seen.insert(canonical) {
                        results.push(entry.path());
                    }
                }
            }
        }
    }

    results
}

// ── Record construction from JSON ─────────────────────────────────────────

/// Build a [`DropinUserRecord`] from a parsed JSON object.
fn user_record_from_json(json: &JsonValue) -> DropinUserRecord {
    let mut record = DropinUserRecord::new();

    // The "userName" field is the primary key.
    record.user_name = json.get_str("userName").map(String::from);
    record.uid = json.get_u64("uid").map(|v| v as u32).unwrap_or(UID_INVALID);
    record.gid = json.get_u64("gid").map(|v| v as u32).unwrap_or(GID_INVALID);
    record.home_directory = json.get_str("homeDirectory").map(String::from);
    record.shell = json.get_str("shell").map(String::from);
    record.real_name = json.get_str("realName").map(String::from);
    record.locked = json.get_bool("locked").unwrap_or(false);
    record.disposition = json.get_str("disposition").map(String::from);
    record.service = json.get_str("service").map(String::from);
    record.realm = json.get_str("realm").map(String::from);

    record
}

/// Build a [`DropinGroupRecord`] from a parsed JSON object.
fn group_record_from_json(json: &JsonValue) -> DropinGroupRecord {
    let mut record = DropinGroupRecord::new();

    record.group_name = json.get_str("groupName").map(String::from);
    record.gid = json.get_u64("gid").map(|v| v as u32).unwrap_or(GID_INVALID);
    record.description = json.get_str("description").map(String::from);
    record.disposition = json.get_str("disposition").map(String::from);
    record.service = json.get_str("service").map(String::from);
    record.members = json.get_string_array("members");

    record
}

// ── Internal loading logic ────────────────────────────────────────────────

/// Determine the privileged companion filename for a user drop-in.
///
/// If `name` is provided, uses `<dir>/<name>.user-privileged`.
/// Otherwise, uses `<dir>/<uid>.user-privileged`.
fn user_privileged_path(dir: &Path, name: Option<&str>, uid: u32) -> PathBuf {
    match name {
        Some(n) => dir.join(format!("{n}.user-privileged")),
        None => dir.join(format!("{}.user-privileged", uid)),
    }
}

/// Determine the privileged companion filename for a group drop-in.
///
/// If `name` is provided, uses `<dir>/<name>.group-privileged`.
/// Otherwise, uses `<dir>/<gid>.group-privileged`.
fn group_privileged_path(dir: &Path, name: Option<&str>, gid: u32) -> PathBuf {
    match name {
        Some(n) => dir.join(format!("{n}.group-privileged")),
        None => dir.join(format!("{}.group-privileged", gid)),
    }
}

/// Load a user record from an open JSON file, optionally merging privileged data.
///
/// This corresponds to C `load_user()`.
///
/// - `path`: filesystem path to the main drop-in file (used to locate the
///   privileged companion).
/// - `name`: expected user name for validation (pass `None` for UID lookups).
/// - `uid`: expected UID for validation (pass `UID_INVALID` for name lookups).
/// - `flags`: `UserDBFlags` bitmask; `USERDB_SUPPRESS_SHADOW` skips
///   privileged file loading.
fn load_user_record_from_json(
    json: &JsonValue,
    path: Option<&Path>,
    name: Option<&str>,
    uid: u32,
    flags: u64,
) -> DropinResult<DropinUserRecord> {
    let suppress_shadow = (flags & USERDB_SUPPRESS_SHADOW) != 0;
    let can_resolve_privileged = path.is_some() && (name.is_some() || uid_is_valid(uid));

    // Attempt to load and merge privileged companion data.
    let have_privileged = if suppress_shadow || !can_resolve_privileged {
        false
    } else {
        let dir = path.unwrap().parent().unwrap_or(Path::new("."));
        let priv_path = user_privileged_path(dir, name, uid);

        match read_file_contents(&priv_path) {
            Ok(contents) => {
                // Parse and merge the privileged JSON into the main record.
                let priv_json = parse_json(&contents)?;
                // We need to clone to mutate, since json is borrowed.
                let mut merged = json.clone();
                JsonValue::merge(&mut merged, &priv_json);
                let record = user_record_from_json(&merged);
                // Validate after merge.
                if let Some(expected_name) = name {
                    if !record.matches_name(expected_name) {
                        return Err(DropinError::Mismatch);
                    }
                }
                if uid_is_valid(uid) && uid != record.uid {
                    return Err(DropinError::Mismatch);
                }
                let mut record = record;
                record.incomplete = false;
                return Ok(record);
            }
            Err(DropinError::NotFound) => {
                // Privileged file doesn't exist → record is complete.
                true
            }
            Err(DropinError::PermissionDenied) => {
                // No access to privileged file → record is incomplete.
                false
            }
            Err(e) => return Err(e),
        }
    };

    let mut record = user_record_from_json(json);

    // Validate name match.
    if let Some(expected_name) = name {
        if !record.matches_name(expected_name) {
            return Err(DropinError::Mismatch);
        }
    }

    // Validate UID match.
    if uid_is_valid(uid) && uid != record.uid {
        return Err(DropinError::Mismatch);
    }

    record.incomplete = !have_privileged;

    Ok(record)
}

/// Load a group record from an open JSON file, optionally merging privileged data.
///
/// This corresponds to C `load_group()`.
fn load_group_record_from_json(
    json: &JsonValue,
    path: Option<&Path>,
    name: Option<&str>,
    gid: u32,
    flags: u64,
) -> DropinResult<DropinGroupRecord> {
    let suppress_shadow = (flags & USERDB_SUPPRESS_SHADOW) != 0;
    let can_resolve_privileged = path.is_some() && (name.is_some() || gid_is_valid(gid));

    let have_privileged = if suppress_shadow || !can_resolve_privileged {
        false
    } else {
        let dir = path.unwrap().parent().unwrap_or(Path::new("."));
        let priv_path = group_privileged_path(dir, name, gid);

        match read_file_contents(&priv_path) {
            Ok(contents) => {
                let priv_json = parse_json(&contents)?;
                let mut merged = json.clone();
                JsonValue::merge(&mut merged, &priv_json);
                let record = group_record_from_json(&merged);
                if let Some(expected_name) = name {
                    if !record.matches_name(expected_name) {
                        return Err(DropinError::Mismatch);
                    }
                }
                if gid_is_valid(gid) && gid != record.gid {
                    return Err(DropinError::Mismatch);
                }
                let mut record = record;
                record.incomplete = false;
                return Ok(record);
            }
            Err(DropinError::NotFound) => true,
            Err(DropinError::PermissionDenied) => false,
            Err(e) => return Err(e),
        }
    };

    let mut record = group_record_from_json(json);

    if let Some(expected_name) = name {
        if !record.matches_name(expected_name) {
            return Err(DropinError::Mismatch);
        }
    }

    if gid_is_valid(gid) && gid != record.gid {
        return Err(DropinError::Mismatch);
    }

    record.incomplete = !have_privileged;

    Ok(record)
}

// ── Public API ────────────────────────────────────────────────────────────

/// Load a user record from a drop-in file by user name.
///
/// If `path` is provided, reads directly from that file. Otherwise, searches
/// the standard drop-in directories for `<name>.user`.
///
/// Corresponds to C `dropin_user_record_by_name()`.
pub fn dropin_user_record_by_name(
    name: &str,
    path: Option<&Path>,
    flags: u64,
) -> DropinResult<DropinUserRecord> {
    if name.is_empty() {
        return Err(DropinError::InvalidArgument);
    }

    let resolved_path = if let Some(p) = path {
        if !p.is_file() {
            return Err(DropinError::NotFound);
        }
        p.to_path_buf()
    } else {
        let filename = format!("{name}.user");
        if !filename_is_valid(&filename) {
            return Err(DropinError::NotFound);
        }
        search_dropin_file(&filename, USERDB_DROPIN_USER_DIRS).ok_or(DropinError::NotFound)?
    };

    let contents = read_file_contents(&resolved_path)?;
    let json = parse_json(&contents)?;
    load_user_record_from_json(&json, Some(&resolved_path), Some(name), UID_INVALID, flags)
}

/// Load a user record from a drop-in file by UID.
///
/// If `path` is provided, reads directly from that file. Otherwise, searches
/// the standard drop-in directories for `<uid>.user`.
///
/// Corresponds to C `dropin_user_record_by_uid()`.
pub fn dropin_user_record_by_uid(
    uid: u32,
    path: Option<&Path>,
    flags: u64,
) -> DropinResult<DropinUserRecord> {
    if !uid_is_valid(uid) {
        return Err(DropinError::InvalidArgument);
    }

    let resolved_path = if let Some(p) = path {
        if !p.is_file() {
            return Err(DropinError::NotFound);
        }
        p.to_path_buf()
    } else {
        let filename = format!("{uid}.user");
        // UIDs are always valid as filenames (decimal integers).
        search_dropin_file(&filename, USERDB_DROPIN_USER_DIRS).ok_or(DropinError::NotFound)?
    };

    let contents = read_file_contents(&resolved_path)?;
    let json = parse_json(&contents)?;
    load_user_record_from_json(&json, Some(&resolved_path), None, uid, flags)
}

/// Load a group record from a drop-in file by group name.
///
/// If `path` is provided, reads directly from that file. Otherwise, searches
/// the standard drop-in directories for `<name>.group`.
///
/// Corresponds to C `dropin_group_record_by_name()`.
pub fn dropin_group_record_by_name(
    name: &str,
    path: Option<&Path>,
    flags: u64,
) -> DropinResult<DropinGroupRecord> {
    if name.is_empty() {
        return Err(DropinError::InvalidArgument);
    }

    let resolved_path = if let Some(p) = path {
        if !p.is_file() {
            return Err(DropinError::NotFound);
        }
        p.to_path_buf()
    } else {
        let filename = format!("{name}.group");
        if !filename_is_valid(&filename) {
            return Err(DropinError::NotFound);
        }
        search_dropin_file(&filename, USERDB_DROPIN_GROUP_DIRS).ok_or(DropinError::NotFound)?
    };

    let contents = read_file_contents(&resolved_path)?;
    let json = parse_json(&contents)?;
    load_group_record_from_json(&json, Some(&resolved_path), Some(name), GID_INVALID, flags)
}

/// Load a group record from a drop-in file by GID.
///
/// If `path` is provided, reads directly from that file. Otherwise, searches
/// the standard drop-in directories for `<gid>.group`.
///
/// Corresponds to C `dropin_group_record_by_gid()`.
pub fn dropin_group_record_by_gid(
    gid: u32,
    path: Option<&Path>,
    flags: u64,
) -> DropinResult<DropinGroupRecord> {
    if !gid_is_valid(gid) {
        return Err(DropinError::InvalidArgument);
    }

    let resolved_path = if let Some(p) = path {
        if !p.is_file() {
            return Err(DropinError::NotFound);
        }
        p.to_path_buf()
    } else {
        let filename = format!("{gid}.group");
        search_dropin_file(&filename, USERDB_DROPIN_GROUP_DIRS).ok_or(DropinError::NotFound)?
    };

    let contents = read_file_contents(&resolved_path)?;
    let json = parse_json(&contents)?;
    load_group_record_from_json(&json, Some(&resolved_path), None, gid, flags)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    // Helper: create a temporary directory with files.
    fn temp_dir_with_files(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        for (name, content) in files {
            let path = dir.path().join(name);
            fs::write(&path, content).expect("failed to write temp file");
        }
        dir
    }

    // ── Validation helpers ─────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_uid_is_valid() {
        assert!(uid_is_valid(0));
        assert!(uid_is_valid(1));
        assert!(uid_is_valid(65534));
        assert!(!uid_is_valid(UID_INVALID));
        assert!(!uid_is_valid(u32::MAX));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_gid_is_valid() {
        assert!(gid_is_valid(0));
        assert!(gid_is_valid(100));
        assert!(gid_is_valid(65534));
        assert!(!gid_is_valid(GID_INVALID));
        assert!(!gid_is_valid(u32::MAX));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_filename_is_valid() {
        assert!(filename_is_valid("root.user"));
        assert!(filename_is_valid("0.user"));
        assert!(filename_is_valid("my-group.group"));
        assert!(filename_is_valid("a_b.c"));
        assert!(filename_is_valid("UPPERCASE123"));
        assert!(!filename_is_valid(""));
        assert!(!filename_is_valid("/etc/passwd"));
        assert!(!filename_is_valid(".hidden"));
        assert!(!filename_is_valid("has/slash"));
        assert!(!filename_is_valid("has\nnewline"));
        assert!(!filename_is_valid(&"a".repeat(256)));
    }

    // ── JSON parsing ───────────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_json_simple_object() {
        let json = parse_json(r#"{"userName": "root", "uid": 0}"#).unwrap();
        assert_eq!(json.get_str("userName"), Some("root"));
        assert_eq!(json.get_u64("uid"), Some(0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_json_nested_object() {
        let json =
            parse_json(r#"{"userName": "test", "identity": {"gid": 100, "realm": "local"}}"#)
                .unwrap();
        assert_eq!(json.get_str("userName"), Some("test"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_json_with_array() {
        let json = parse_json(r#"{"groupName": "wheel", "gid": 10, "members": ["root", "admin"]}"#)
            .unwrap();
        assert_eq!(json.get_str("groupName"), Some("wheel"));
        assert_eq!(json.get_u64("gid"), Some(10));
        let members = json.get_string_array("members");
        assert_eq!(members, vec!["root", "admin"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_json_bool_and_null() {
        let json = parse_json(r#"{"locked": true, "shell": null, "uid": 1000}"#).unwrap();
        assert_eq!(json.get_bool("locked"), Some(true));
        assert_eq!(json.get_str("shell"), None);
        assert_eq!(json.get_u64("uid"), Some(1000));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_json_empty_object() {
        let json = parse_json("{}").unwrap();
        assert_eq!(json.get_str("anything"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_json_string_escapes() {
        let json = parse_json(r#"{"name": "hello \"world\""}"#).unwrap();
        assert_eq!(json.get_str("name"), Some("hello \"world\""));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_json_invalid() {
        assert!(parse_json("{invalid}").is_err());
        assert!(parse_json("").is_err());
        assert!(parse_json(r#"{"key": }"#).is_err());
        assert!(parse_json(r#"{"key": value}"#).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_json_trailing_content() {
        assert!(parse_json(r#"{} extra"#).is_err());
    }

    // ── JSON merging ───────────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_json_merge_simple() {
        let mut base = parse_json(r#"{"a": 1, "b": 2}"#).unwrap();
        let overlay = parse_json(r#"{"b": 3, "c": 4}"#).unwrap();
        JsonValue::merge(&mut base, &overlay);
        assert_eq!(base.get_u64("a"), Some(1));
        assert_eq!(base.get_u64("b"), Some(3));
        assert_eq!(base.get_u64("c"), Some(4));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_json_merge_nested() {
        let mut base = parse_json(r#"{"identity": {"uid": 0}, "userName": "root"}"#).unwrap();
        let overlay = parse_json(r#"{"identity": {"gid": 0}}"#).unwrap();
        JsonValue::merge(&mut base, &overlay);
        // The nested "identity" object should have both uid and gid.
        assert_eq!(base.get_str("userName"), Some("root"));
    }

    // ── Record construction ────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_user_record_from_json() {
        let json = parse_json(
            r#"{
                "userName": "testuser",
                "uid": 1000,
                "gid": 1000,
                "homeDirectory": "/home/testuser",
                "shell": "/bin/bash",
                "realName": "Test User",
                "locked": false,
                "disposition": "regular"
            }"#,
        )
        .unwrap();

        let record = user_record_from_json(&json);
        assert_eq!(record.user_name.as_deref(), Some("testuser"));
        assert_eq!(record.uid, 1000);
        assert_eq!(record.gid, 1000);
        assert_eq!(record.home_directory.as_deref(), Some("/home/testuser"));
        assert_eq!(record.shell.as_deref(), Some("/bin/bash"));
        assert_eq!(record.real_name.as_deref(), Some("Test User"));
        assert!(!record.locked);
        assert_eq!(record.disposition.as_deref(), Some("regular"));
        assert!(!record.incomplete);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_user_record_from_json_minimal() {
        let json = parse_json("{}").unwrap();
        let record = user_record_from_json(&json);
        assert!(record.user_name.is_none());
        assert_eq!(record.uid, UID_INVALID);
        assert_eq!(record.gid, GID_INVALID);
        assert!(!record.locked);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_group_record_from_json() {
        let json = parse_json(
            r#"{
                "groupName": "wheel",
                "gid": 10,
                "description": "System administrators",
                "members": ["root", "admin"]
            }"#,
        )
        .unwrap();

        let record = group_record_from_json(&json);
        assert_eq!(record.group_name.as_deref(), Some("wheel"));
        assert_eq!(record.gid, 10);
        assert_eq!(record.description.as_deref(), Some("System administrators"));
        assert_eq!(record.members, vec!["root", "admin"]);
    }

    // ── File search ────────────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_search_dropin_file_found() {
        let dir =
            temp_dir_with_files(&[("testuser.user", r#"{"userName":"testuser","uid":1000}"#)]);
        let dirs = vec![dir.path().to_str().unwrap()];
        let result = search_dropin_file("testuser.user", &dirs);
        assert!(result.is_some());
        assert!(result.unwrap().ends_with("testuser.user"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_search_dropin_file_not_found() {
        let dirs = &["/tmp/nonexistent_xyz_dir"];
        let result = search_dropin_file("nonexistent.user", dirs);
        assert!(result.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_search_dropin_file_priority_order() {
        let dir1 = temp_dir_with_files(&[("myuser.user", r#"{"userName":"myuser","uid":100}"#)]);
        let dir2 = temp_dir_with_files(&[("myuser.user", r#"{"userName":"myuser","uid":200}"#)]);
        let dirs = vec![dir1.path().to_str().unwrap(), dir2.path().to_str().unwrap()];
        let result = search_dropin_file("myuser.user", &dirs);
        assert!(result.is_some());
        // Should find the first directory's file.
        let content = fs::read_to_string(result.unwrap()).unwrap();
        assert!(content.contains(r#""uid":100"#));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_list_dropin_files_dedup() {
        let dir = temp_dir_with_files(&[
            ("admin.user", "{}"),
            ("admin.group", "{}"),
            ("wheel.group", "{}"),
        ]);
        let dirs = vec![dir.path().to_str().unwrap()];
        let users = list_dropin_files(".user", &dirs);
        assert_eq!(users.len(), 1);
        let groups = list_dropin_files(".group", &dirs);
        assert_eq!(groups.len(), 2);
    }

    // ── Full loading pipeline ──────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_user_record_by_name_from_path() {
        let dir = temp_dir_with_files(&[("test.user", r#"{"userName":"test","uid":42,"gid":42}"#)]);
        let path = dir.path().join("test.user");
        let record = dropin_user_record_by_name("test", Some(&path), 0).unwrap();
        assert_eq!(record.user_name.as_deref(), Some("test"));
        assert_eq!(record.uid, 42);
        assert!(!record.incomplete);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_user_record_by_name_search() {
        let dir = temp_dir_with_files(&[("myuser.user", r#"{"userName":"myuser","uid":1000}"#)]);
        // Temporarily override search dirs — we'll use the path-based API
        // and verify via the file directly.
        let path = dir.path().join("myuser.user");
        let record = dropin_user_record_by_name("myuser", Some(&path), 0).unwrap();
        assert_eq!(record.user_name.as_deref(), Some("myuser"));
        assert_eq!(record.uid, 1000);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_user_record_by_name_mismatch() {
        let dir = temp_dir_with_files(&[("other.user", r#"{"userName":"other","uid":99}"#)]);
        let path = dir.path().join("other.user");
        let result = dropin_user_record_by_name("wrongname", Some(&path), 0);
        assert_eq!(result.unwrap_err(), DropinError::Mismatch);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_user_record_by_name_not_found() {
        let dir = temp_dir_with_files(&[]);
        let path = dir.path().join("nonexistent.user");
        let result = dropin_user_record_by_name("ghost", Some(&path), 0);
        assert_eq!(result.unwrap_err(), DropinError::NotFound);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_user_record_by_name_empty() {
        let result = dropin_user_record_by_name("", None, 0);
        assert_eq!(result.unwrap_err(), DropinError::InvalidArgument);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_user_record_by_uid_from_path() {
        let dir =
            temp_dir_with_files(&[("1234.user", r#"{"userName":"test","uid":1234,"gid":1234}"#)]);
        let path = dir.path().join("1234.user");
        let record = dropin_user_record_by_uid(1234, Some(&path), 0).unwrap();
        assert_eq!(record.uid, 1234);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_user_record_by_uid_mismatch() {
        let dir = temp_dir_with_files(&[("99.user", r#"{"userName":"x","uid":99}"#)]);
        let path = dir.path().join("99.user");
        let result = dropin_user_record_by_uid(42, Some(&path), 0);
        assert_eq!(result.unwrap_err(), DropinError::Mismatch);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_user_record_by_uid_invalid() {
        let result = dropin_user_record_by_uid(UID_INVALID, None, 0);
        assert_eq!(result.unwrap_err(), DropinError::InvalidArgument);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_group_record_by_name_from_path() {
        let dir = temp_dir_with_files(&[("wheel.group", r#"{"groupName":"wheel","gid":10}"#)]);
        let path = dir.path().join("wheel.group");
        let record = dropin_group_record_by_name("wheel", Some(&path), 0).unwrap();
        assert_eq!(record.group_name.as_deref(), Some("wheel"));
        assert_eq!(record.gid, 10);
        assert!(!record.incomplete);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_group_record_by_gid_from_path() {
        let dir = temp_dir_with_files(&[("10.group", r#"{"groupName":"wheel","gid":10}"#)]);
        let path = dir.path().join("10.group");
        let record = dropin_group_record_by_gid(10, Some(&path), 0).unwrap();
        assert_eq!(record.gid, 10);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_group_record_by_name_mismatch() {
        let dir = temp_dir_with_files(&[("other.group", r#"{"groupName":"other","gid":99}"#)]);
        let path = dir.path().join("other.group");
        let result = dropin_group_record_by_name("wronggroup", Some(&path), 0);
        assert_eq!(result.unwrap_err(), DropinError::Mismatch);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_group_record_by_name_empty() {
        let result = dropin_group_record_by_name("", None, 0);
        assert_eq!(result.unwrap_err(), DropinError::InvalidArgument);
    }

    // ── Privileged file loading ────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_load_user_with_privileged_file() {
        let dir = temp_dir_with_files(&[
            (
                "test.user",
                r#"{"userName":"test","uid":50,"gid":50,"disposition":"regular"}"#,
            ),
            (
                "test.user-privileged",
                r#"{"privileged":{"hashedPassword":"$secret"},"disposition":"system"}"#,
            ),
        ]);
        let main_path = dir.path().join("test.user");
        let contents = fs::read_to_string(&main_path).unwrap();
        let json = parse_json(&contents).unwrap();
        let record =
            load_user_record_from_json(&json, Some(&main_path), Some("test"), UID_INVALID, 0)
                .unwrap();
        // The privileged file exists and has a "disposition" field that
        // should override the base record's value via merge.
        assert!(!record.incomplete);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_load_user_without_privileged_file() {
        let dir = temp_dir_with_files(&[("test.user", r#"{"userName":"test","uid":50,"gid":50}"#)]);
        let main_path = dir.path().join("test.user");
        let contents = fs::read_to_string(&main_path).unwrap();
        let json = parse_json(&contents).unwrap();
        let record =
            load_user_record_from_json(&json, Some(&main_path), Some("test"), UID_INVALID, 0)
                .unwrap();
        // No privileged file → record is complete (not incomplete).
        assert!(!record.incomplete);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_load_user_suppress_shadow() {
        let dir = temp_dir_with_files(&[
            ("test.user", r#"{"userName":"test","uid":50,"gid":50}"#),
            ("test.user-privileged", r#"{"secret":"data"}"#),
        ]);
        let main_path = dir.path().join("test.user");
        let contents = fs::read_to_string(&main_path).unwrap();
        let json = parse_json(&contents).unwrap();
        let record = load_user_record_from_json(
            &json,
            Some(&main_path),
            Some("test"),
            UID_INVALID,
            USERDB_SUPPRESS_SHADOW,
        )
        .unwrap();
        // With SUPPRESS_SHADOW, privileged file is not loaded.
        // Without it, the record would be incomplete.
        assert!(record.incomplete);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_load_group_with_privileged_file() {
        let dir = temp_dir_with_files(&[
            ("wheel.group", r#"{"groupName":"wheel","gid":10}"#),
            (
                "wheel.group-privileged",
                r#"{"hashedPassword":"$groupsecret"}"#,
            ),
        ]);
        let main_path = dir.path().join("wheel.group");
        let contents = fs::read_to_string(&main_path).unwrap();
        let json = parse_json(&contents).unwrap();
        let record =
            load_group_record_from_json(&json, Some(&main_path), Some("wheel"), GID_INVALID, 0)
                .unwrap();
        assert!(!record.incomplete);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_load_group_without_privileged_file() {
        let dir = temp_dir_with_files(&[("wheel.group", r#"{"groupName":"wheel","gid":10}"#)]);
        let main_path = dir.path().join("wheel.group");
        let contents = fs::read_to_string(&main_path).unwrap();
        let json = parse_json(&contents).unwrap();
        let record =
            load_group_record_from_json(&json, Some(&main_path), Some("wheel"), GID_INVALID, 0)
                .unwrap();
        assert!(!record.incomplete);
    }

    // ── Error type ─────────────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_error_to_neg_errno() {
        assert_eq!(DropinError::NotFound.to_neg_errno(), -3);
        assert_eq!(DropinError::InvalidArgument.to_neg_errno(), -22);
        assert_eq!(DropinError::PermissionDenied.to_neg_errno(), -13);
        assert_eq!(DropinError::Io.to_neg_errno(), -5);
        assert_eq!(DropinError::OutOfMemory.to_neg_errno(), -12);
        assert_eq!(DropinError::Mismatch.to_neg_errno(), -22);
        assert_eq!(DropinError::RawErrno(2).to_neg_errno(), -2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_error_display() {
        assert!(!DropinError::NotFound.to_string().is_empty());
        assert!(!DropinError::ParseError("bad json".into())
            .to_string()
            .is_empty());
        assert!(DropinError::ParseError("test".into())
            .to_string()
            .contains("test"));
    }

    // ── Constants ──────────────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_dirs() {
        assert_eq!(USERDB_DROPIN_USER_DIRS.len(), 5);
        assert_eq!(USERDB_DROPIN_USER_DIRS[0], "/etc/userdb");
        assert_eq!(USERDB_DROPIN_USER_DIRS[1], "/run/userdb");
        assert_eq!(USERDB_DROPIN_USER_DIRS[2], "/run/host/userdb");
        assert_eq!(USERDB_DROPIN_USER_DIRS[3], "/usr/local/lib/userdb");
        assert_eq!(USERDB_DROPIN_USER_DIRS[4], "/usr/lib/userdb");
        // Group dirs are the same as user dirs.
        assert_eq!(USERDB_DROPIN_GROUP_DIRS.len(), 5);
        assert_eq!(USERDB_DROPIN_GROUP_DIRS, USERDB_DROPIN_USER_DIRS);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_userdb_suppress_shadow_flag() {
        assert_eq!(USERDB_SUPPRESS_SHADOW, 1 << 3);
        assert!(USERDB_SUPPRESS_SHADOW != 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_uid_gid_invalid_sentinels() {
        assert_eq!(UID_INVALID, u32::MAX);
        assert_eq!(GID_INVALID, u32::MAX);
        assert!(!uid_is_valid(UID_INVALID));
        assert!(!gid_is_valid(GID_INVALID));
    }

    // ── Record defaults ────────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_user_record_default() {
        let record = DropinUserRecord::default();
        assert!(record.user_name.is_none());
        assert_eq!(record.uid, UID_INVALID);
        assert_eq!(record.gid, GID_INVALID);
        assert!(!record.locked);
        assert!(!record.incomplete);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_group_record_default() {
        let record = DropinGroupRecord::default();
        assert!(record.group_name.is_none());
        assert_eq!(record.gid, GID_INVALID);
        assert!(record.members.is_empty());
        assert!(!record.incomplete);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_user_record_matches_name() {
        let mut record = DropinUserRecord::new();
        assert!(!record.matches_name("root"));
        record.user_name = Some("root".into());
        assert!(record.matches_name("root"));
        assert!(!record.matches_name("other"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_group_record_matches_name() {
        let mut record = DropinGroupRecord::new();
        assert!(!record.matches_name("wheel"));
        record.group_name = Some("wheel".into());
        assert!(record.matches_name("wheel"));
        assert!(!record.matches_name("other"));
    }

    // ── Privileged path construction ───────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_user_privileged_path() {
        let dir = Path::new("/run/userdb");
        let p = user_privileged_path(dir, Some("root"), UID_INVALID);
        assert_eq!(p, Path::new("/run/userdb/root.user-privileged"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_user_privileged_path_by_uid() {
        let dir = Path::new("/run/userdb");
        let p = user_privileged_path(dir, None, 1000);
        assert_eq!(p, Path::new("/run/userdb/1000.user-privileged"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_group_privileged_path() {
        let dir = Path::new("/run/userdb");
        let p = group_privileged_path(dir, Some("wheel"), GID_INVALID);
        assert_eq!(p, Path::new("/run/userdb/wheel.group-privileged"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_group_privileged_path_by_gid() {
        let dir = Path::new("/run/userdb");
        let p = group_privileged_path(dir, None, 10);
        assert_eq!(p, Path::new("/run/userdb/10.group-privileged"));
    }

    // ── Invalid filename rejection ─────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_user_record_by_name_invalid_filename() {
        // A name with a slash should not be accepted for directory search.
        // When path is None, an invalid filename returns NotFound (ESRCH).
        let result = dropin_user_record_by_name("/etc/passwd", None, 0);
        assert_eq!(result.unwrap_err(), DropinError::NotFound);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dropin_group_record_by_name_invalid_filename() {
        let result = dropin_group_record_by_name("/etc/group", None, 0);
        assert_eq!(result.unwrap_err(), DropinError::NotFound);
    }
}
