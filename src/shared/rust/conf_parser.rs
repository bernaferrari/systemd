// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/conf-parser.c, src/shared/conf-parser.h
//
// systemd-style configuration file parser.
//
// Parses INI-style configuration files with sections, key=value pairs,
// continuation lines (trailing backslash), BOM handling, and various
// value type parsers (bool, int, size, string, etc.).

use crate::ffi::*;
use std::collections::HashMap;
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::str::FromStr;

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum line length (matching LONG_LINE_MAX in C).
pub const MAX_LINE_LENGTH: usize = 1024 * 1024;

/// Characters that begin a comment line.
const COMMENT_CHARS: &[char] = &['#', ';'];

/// UTF-8 byte order mark.
const BOM: char = '\u{FEFF}';

// ── Error types ───────────────────────────────────────────────────────────

/// Configuration parser error.
#[derive(Debug)]
pub enum ConfigParseError {
    /// I/O error reading the file.
    Io(io::Error),
    /// A line exceeded the maximum allowed length.
    LineTooLong { line: usize },
    /// Syntax error in the configuration file.
    Syntax { line: usize, message: String },
    /// Invalid UTF-8 in the configuration file.
    InvalidUtf8 { line: usize },
    /// An assignment appeared before any section header.
    AssignmentOutsideSection { line: usize },
}

impl fmt::Display for ConfigParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigParseError::Io(e) => write!(f, "I/O error: {}", e),
            ConfigParseError::LineTooLong { line } => {
                write!(
                    f,
                    "Line {} too long (exceeds {} bytes)",
                    line, MAX_LINE_LENGTH
                )
            }
            ConfigParseError::Syntax { line, message } => {
                write!(f, "Syntax error at line {}: {}", line, message)
            }
            ConfigParseError::InvalidUtf8 { line } => {
                write!(f, "Invalid UTF-8 at line {}", line)
            }
            ConfigParseError::AssignmentOutsideSection { line } => {
                write!(f, "Assignment outside of section at line {}", line)
            }
        }
    }
}

impl std::error::Error for ConfigParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigParseError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ConfigParseError {
    fn from(e: io::Error) -> Self {
        ConfigParseError::Io(e)
    }
}

// ── Parse result ──────────────────────────────────────────────────────────

/// Result of attempting to parse a value. Mirrors the C convention where
/// `Ok(Some(()))` means "value was set", `Ok(None)` means "ignored", and
/// `Err` means a hard failure.
pub type ParseResult = Result<Option<()>, ConfigParseError>;

// ── Parse flags ───────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling parser behaviour (mirrors C `ConfigParseFlags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ConfigParseFlags: u32 {
        /// Do not warn about unknown fields.
        const RELAXED     = 1 << 0;
        /// Emit warnings on parse errors.
        const WARN        = 1 << 1;
    }
}

impl Default for ConfigParseFlags {
    fn default() -> Self {
        Self::WARN
    }
}

// ── Data types ────────────────────────────────────────────────────────────

/// A parsed configuration entry.
#[derive(Debug, Clone)]
pub struct ConfigEntry {
    /// The section this entry belongs to (e.g. `"Service"`).
    pub section: Option<String>,
    /// The key name (left of `=`).
    pub key: String,
    /// The raw value string (right of `=`).
    pub value: String,
    /// 1-based line number in the source file.
    pub line_number: usize,
}

/// File statistics associated with a parsed config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStats {
    /// Inode number.
    pub ino: u64,
    /// Device number.
    pub dev: u64,
    /// File size in bytes.
    pub size: u64,
    /// Last modification time (seconds since epoch).
    pub mtime: u64,
}

impl FileStats {
    /// Returns `true` if both stats refer to the same inode and have
    /// the same modification time (mirrors `stat_inode_unmodified`).
    pub fn inode_unmodified(&self, other: &Self) -> bool {
        self.ino == other.ino && self.dev == other.dev && self.mtime == other.mtime
    }
}

/// A config section identified by filename + line number
/// (mirrors C `ConfigSection`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConfigSection {
    /// Source filename.
    pub filename: String,
    /// 1-based line number where the section header appears.
    pub line: u32,
}

// ── Value parsers ─────────────────────────────────────────────────────────

/// Parse a boolean value (matching systemd's `parse_boolean`).
///
/// Accepts: `1`, `yes`, `true`, `on` → true; `0`, `no`, `false`, `off` → false.
pub fn parse_bool(value: &str) -> Option<bool> {
    match value.trim() {
        "" => None,
        v if ["1", "yes", "true", "on", "Yes", "True", "YES", "TRUE", "ON"]
            .iter()
            .any(|&p| p == v) =>
        {
            Some(true)
        }
        v if [
            "0", "no", "false", "off", "No", "False", "NO", "FALSE", "OFF",
        ]
        .iter()
        .any(|&p| p == v) =>
        {
            Some(false)
        }
        _ => None,
    }
}

/// Parse an unsigned integer.
pub fn parse_uint(value: &str) -> Option<u64> {
    value.trim().parse().ok()
}

/// Parse a signed integer.
pub fn parse_int(value: &str) -> Option<i64> {
    value.trim().parse().ok()
}

/// Parse a size string with IEC (1024) suffixes (e.g. `"4K"`, `"1M"`, `"2G"`).
pub fn parse_iec_size(value: &str) -> Option<u64> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }

    let (num_str, suffix) = match v.chars().last() {
        Some('B') => {
            let base = &v[..v.len() - 1];
            match base.chars().last() {
                Some('i') => (&base[..base.len() - 1], Some('B')),
                Some(c) if c.is_ascii_alphabetic() => (base, Some(c)),
                _ => (v, None),
            }
        }
        Some(c) if c.is_ascii_alphabetic() => (&v[..v.len() - 1], Some(c)),
        _ => (v, None),
    };

    let num: f64 = num_str.trim().parse().ok()?;
    let multiplier = match suffix
        .map(|c| c.to_uppercase().next().unwrap_or(c))
        .as_ref()
    {
        Some('K') => 1024u64,
        Some('M') => 1024 * 1024,
        Some('G') => 1024 * 1024 * 1024,
        Some('T') => 1024 * 1024 * 1024 * 1024,
        Some('P') => 1024 * 1024 * 1024 * 1024 * 1024,
        Some('E') => 1024 * 1024 * 1024 * 1024 * 1024 * 1024,
        Some('B') => 1u64,
        _ => 1,
    };

    Some((num * multiplier as f64) as u64)
}

/// Parse a size string with SI (1000) suffixes.
pub fn parse_si_size(value: &str) -> Option<u64> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }

    let (num_str, suffix) = match v.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => (&v[..v.len() - 1], Some(c)),
        _ => (v, None),
    };

    let num: f64 = num_str.trim().parse().ok()?;
    let suffix = match suffix {
        Some(c) => c.to_uppercase().next().unwrap_or(c),
        None => return Some(num as u64),
    };

    let multiplier = match suffix {
        'K' => 1000u64,
        'M' => 1_000_000,
        'G' => 1_000_000_000,
        'T' => 1_000_000_000_000,
        _ => return None,
    };

    Some((num * multiplier as f64) as u64)
}

/// Parse a mode_t (octal) value.
pub fn parse_mode(value: &str) -> Option<u32> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    if v.starts_with('0') {
        u32::from_str_radix(v, 8).ok()
    } else {
        v.parse().ok()
    }
}

/// Parse a tristate: `true`/`false`/empty → `Some(1)`/`Some(0)`/`None` (unset).
pub fn parse_tristate(value: &str) -> Option<i32> {
    match value.trim() {
        "" => Some(-1), // unset
        v => parse_bool(v).map(|b| if b { 1 } else { 0 }),
    }
}

/// Parse a signal name or number (e.g. `"SIGTERM"`, `"15"`).
pub fn parse_signal(value: &str) -> Option<i32> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }

    // Try as number first
    if let Ok(n) = v.parse::<i32>() {
        if n > 0 {
            return Some(n);
        }
    }

    // Common signal names
    let num = match v.to_uppercase().as_str() {
        "HUP" | "SIGHUP" => 1,
        "INT" | "SIGINT" => 2,
        "QUIT" | "SIGQUIT" => 3,
        "ILL" | "SIGILL" => 4,
        "ABRT" | "SIGABRT" => 6,
        "FPE" | "SIGFPE" => 8,
        "KILL" | "SIGKILL" => 9,
        "SEGV" | "SIGSEGV" => 11,
        "PIPE" | "SIGPIPE" => 13,
        "ALRM" | "SIGALRM" => 14,
        "TERM" | "SIGTERM" => 15,
        "USR1" | "SIGUSR1" => 10,
        "USR2" | "SIGUSR2" => 12,
        _ => return None,
    };
    Some(num)
}

/// Parse an IP port number.
pub fn parse_ip_port(value: &str) -> Option<u16> {
    let v = value.trim();
    if v.is_empty() {
        return Some(0);
    }
    v.parse().ok()
}

/// Parse a string, validating that it contains only safe characters
/// (printable ASCII, no control characters).
pub fn parse_string_safe(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() {
        return Some(String::new());
    }
    if v.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        Some(v.to_string())
    } else {
        None
    }
}

/// Parse a space-separated string list (mirrors `config_parse_strv`).
pub fn parse_strv(value: &str) -> Vec<String> {
    value.split_whitespace().map(|s| s.to_string()).collect()
}

/// Parse an unsigned integer bounded between `min` and `max`.
pub fn parse_uint_bounded(value: &str, min: u64, max: u64) -> Option<u64> {
    let v = parse_uint(value)?;
    if v >= min && v <= max { Some(v) } else { None }
}

/// Parse a permille value (0–1000, or with `%` suffix).
pub fn parse_permille(value: &str) -> Option<u32> {
    let v = value.trim().trim_end_matches('%');
    let n: u32 = v.trim().parse().ok()?;
    if n <= 1000 { Some(n) } else { None }
}

/// Parse an unsigned integer with optional `infinity` keyword.
pub fn parse_uint64_infinity(value: &str) -> Option<u64> {
    let v = value.trim();
    if v.eq_ignore_ascii_case("infinity") {
        return Some(u64::MAX);
    }
    parse_uint(value)
}

// ── Section name validation ───────────────────────────────────────────────

/// Check if a section name contains only "safe" characters.
/// In systemd this means printable ASCII that is not whitespace
/// and not a control character (mirrors `string_is_safe`).
pub fn section_name_is_safe(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

// ── ConfigParser ──────────────────────────────────────────────────────────

/// The main configuration file parser.
///
/// Parses systemd-style INI files with support for:
/// - `[Section]` headers
/// - `key = value` assignments
/// - Line continuation via trailing `\`
/// - `#` and `;` comment lines
/// - UTF-8 BOM on the first line
/// - Sections allowlist
#[derive(Debug)]
pub struct ConfigParser {
    /// All parsed entries in order.
    pub entries: Vec<ConfigEntry>,
    /// Current section name (set by `[Section]` headers).
    current_section: Option<String>,
    /// Current section's 1-based line number.
    section_line: usize,
    /// Whether the current section is in the allowlist.
    section_ignored: bool,
    /// Parse flags.
    flags: ConfigParseFlags,
    /// If set, only these sections are accepted.
    allowed_sections: Option<Vec<String>>,
    /// Whether we've seen the BOM yet.
    bom_seen: bool,
}

impl ConfigParser {
    /// Create a new parser with the given flags.
    pub fn new(flags: ConfigParseFlags) -> Self {
        Self {
            entries: Vec::new(),
            current_section: None,
            section_line: 0,
            section_ignored: false,
            flags,
            allowed_sections: None,
            bom_seen: false,
        }
    }

    /// Restrict parsing to only the given section names.
    pub fn with_sections(mut self, sections: Vec<String>) -> Self {
        self.allowed_sections = Some(sections);
        self
    }

    /// Parse a configuration file by path.
    pub fn parse_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), ConfigParseError> {
        let file = std::fs::File::open(path)?;
        self.parse_reader(file)
    }

    /// Parse configuration from any `Read` source.
    pub fn parse_reader<R: Read>(&mut self, reader: R) -> Result<(), ConfigParseError> {
        let buf_reader = BufReader::new(reader);
        let mut continuation: Option<String> = None;

        for (line_idx, line_result) in buf_reader.lines().enumerate() {
            let line_number = line_idx + 1;
            let mut line = line_result?;

            // Handle BOM on first line
            if !self.bom_seen {
                if line.starts_with(BOM) {
                    line = line.trim_start_matches(BOM).to_string();
                }
                self.bom_seen = true;
            }

            // Check line length
            let total_len = continuation.as_ref().map_or(0, |c| c.len()) + line.len();
            if total_len > MAX_LINE_LENGTH {
                return Err(ConfigParseError::LineTooLong { line: line_number });
            }

            // Skip comment lines (only when not in a continuation)
            if continuation.is_none() {
                let trimmed_start = line.trim_start();
                if trimmed_start.starts_with(COMMENT_CHARS) {
                    continue;
                }
            }

            // Join with continuation buffer
            let merged = if let Some(prev) = continuation.take() {
                format!("{}{}", prev, line)
            } else {
                line
            };

            // Check for trailing backslash (line continuation)
            if let Some(stripped) = merged.strip_suffix('\\') {
                continuation = Some(stripped.to_string());
                continue;
            }

            // Parse the complete logical line
            self.parse_line(&merged, line_number)?;
        }

        // Handle any remaining continuation
        if let Some(cont) = continuation {
            self.parse_line(&cont, self.entries.last().map_or(1, |e| e.line_number) + 1)?;
        }

        Ok(())
    }

    /// Parse a single logical line.
    fn parse_line(&mut self, line: &str, line_number: usize) -> Result<(), ConfigParseError> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(());
        }

        // Validate UTF-8 (std::str already guarantees this, but we check
        // for replacement characters that indicate original bad UTF-8)
        if line.contains('\u{FFFD}') {
            return Err(ConfigParseError::InvalidUtf8 { line: line_number });
        }

        // Section header: [SectionName]
        if let Some(rest) = line.strip_prefix('[') {
            if !rest.ends_with(']') {
                return Err(ConfigParseError::Syntax {
                    line: line_number,
                    message: format!("Invalid section header '{}', missing closing ']'", line),
                });
            }

            let section_name = rest[..rest.len() - 1].trim();

            if section_name.is_empty() {
                return Err(ConfigParseError::Syntax {
                    line: line_number,
                    message: "Empty section header".to_string(),
                });
            }

            if !section_name_is_safe(section_name) {
                return Err(ConfigParseError::Syntax {
                    line: line_number,
                    message: format!("Bad characters in section header '{}'", section_name),
                });
            }

            // Check against allowlist
            if let Some(ref allowed) = self.allowed_sections {
                let is_allowed = allowed.iter().any(|a| a == section_name)
                    || section_name.starts_with("X-")
                    || self.flags.contains(ConfigParseFlags::RELAXED);

                if !is_allowed {
                    // Check for negated sections (prefix with "-")
                    let is_negated = allowed
                        .iter()
                        .any(|a| a.starts_with('-') && a[1..] == *section_name);

                    if !is_negated && self.flags.contains(ConfigParseFlags::WARN) {
                        // Unknown section – silently ignore in library mode
                    }

                    self.current_section = None;
                    self.section_line = 0;
                    self.section_ignored = true;
                    return Ok(());
                }
            }

            self.current_section = Some(section_name.to_string());
            self.section_line = line_number;
            self.section_ignored = false;
            return Ok(());
        }

        // If we have an allowed-sections list and no current section, skip
        if self.allowed_sections.is_some()
            && self.current_section.is_none()
            && !self.section_ignored
        {
            if !self.flags.contains(ConfigParseFlags::RELAXED) {
                return Err(ConfigParseError::AssignmentOutsideSection { line: line_number });
            }
            return Ok(());
        }

        // Skip entries in ignored sections
        if self.section_ignored {
            return Ok(());
        }

        // Key=value assignment
        let (key, value) = match line.split_once('=') {
            Some(pair) => pair,
            None => {
                return Err(ConfigParseError::Syntax {
                    line: line_number,
                    message: "Missing '=', ignoring line".to_string(),
                });
            }
        };

        let key = key.trim();
        let value = value.trim();

        if key.is_empty() {
            return Err(ConfigParseError::Syntax {
                line: line_number,
                message: "Missing key name before '='".to_string(),
            });
        }

        self.entries.push(ConfigEntry {
            section: self.current_section.clone(),
            key: key.to_string(),
            value: value.to_string(),
            line_number,
        });

        Ok(())
    }

    // ── Query methods ─────────────────────────────────────────────────

    /// Get all entries belonging to a section.
    pub fn section_entries(&self, section: &str) -> Vec<&ConfigEntry> {
        self.entries
            .iter()
            .filter(|e| e.section.as_deref() == Some(section))
            .collect()
    }

    /// Look up the value for a specific key in a specific section.
    pub fn get(&self, section: Option<&str>, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .rfind(|e| e.section.as_deref() == section && e.key == key)
            .map(|e| e.value.as_str())
    }

    /// Convert all entries to a `HashMap` with `"Section.key"` keys.
    pub fn to_hashmap(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for entry in &self.entries {
            let full_key = match &entry.section {
                Some(s) => format!("{}.{}", s, entry.key),
                None => entry.key.clone(),
            };
            // Last entry wins (like systemd's drop-in override behaviour)
            map.insert(full_key, entry.value.clone());
        }
        map
    }
}

// ── Convenience functions ─────────────────────────────────────────────────

/// Parse a configuration file and return all entries.
pub fn parse_config_file<P: AsRef<Path>>(path: P) -> Result<Vec<ConfigEntry>, ConfigParseError> {
    let mut parser = ConfigParser::new(ConfigParseFlags::default());
    parser.parse_file(path)?;
    Ok(parser.entries)
}

/// Write config entries back to a writer in INI format.
pub fn write_config<W: Write>(entries: &[ConfigEntry], writer: &mut W) -> io::Result<()> {
    let mut current_section: Option<&str> = None;

    for entry in entries {
        if entry.section.as_deref() != current_section {
            if let Some(section) = &entry.section {
                writeln!(writer)?;
                writeln!(writer, "[{}]", section)?;
            }
            current_section = entry.section.as_deref();
        }
        writeln!(writer, "{}={}", entry.key, entry.value)?;
    }

    Ok(())
}

/// Merge multiple config entry lists.
/// Later configs override earlier ones for the same (section, key) pair.
pub fn merge_configs(configs: Vec<Vec<ConfigEntry>>) -> Vec<ConfigEntry> {
    let mut result = Vec::new();
    let mut seen: HashMap<(Option<String>, String), usize> = HashMap::new();

    for config in configs {
        for entry in config {
            let key = (entry.section.clone(), entry.key.clone());
            if let Some(&idx) = seen.get(&key) {
                result[idx] = entry;
            } else {
                seen.insert(key, result.len());
                result.push(entry);
            }
        }
    }

    result
}

/// Stats-by-path map for tracking file modification times across reloads.
pub type StatsByPath = HashMap<String, FileStats>;

/// Check if two stats maps are equivalent
/// (mirrors C `stats_by_path_equal`).
pub fn stats_by_path_equal(a: &StatsByPath, b: &StatsByPath) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (path, st_a) in a {
        if let Some(st_b) = b.get(path) {
            if !st_a.inode_unmodified(st_b) {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}

/// Find the next unused line number for entries from a given filename
/// (mirrors C `hashmap_by_section_find_unused_line`).
pub fn find_unused_line(sections: &[ConfigSection], filename: Option<&str>) -> Option<u32> {
    let mut max_line: u32 = 0;
    for cs in sections {
        if filename.map_or(true, |f| cs.filename == f) {
            max_line = max_line.max(cs.line);
        }
    }
    if max_line == u32::MAX {
        None
    } else {
        Some(max_line + 1)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ── Basic parsing ────────────────────────────────────────────────

    #[test]
    fn test_parse_simple_key_value() {
        let input = "key1=value1\nkey2=value2\n";
        let mut parser = ConfigParser::new(ConfigParseFlags::default());
        parser.parse_reader(Cursor::new(input)).unwrap();

        assert_eq!(parser.entries.len(), 2);
        assert_eq!(parser.entries[0].key, "key1");
        assert_eq!(parser.entries[0].value, "value1");
        assert_eq!(parser.entries[1].key, "key2");
        assert_eq!(parser.entries[1].value, "value2");
    }

    #[test]
    fn test_parse_with_sections() {
        let input = "\
[Section1]
key1=value1

[Section2]
key2=value2
";
        let mut parser = ConfigParser::new(ConfigParseFlags::default());
        parser.parse_reader(Cursor::new(input)).unwrap();

        assert_eq!(parser.entries.len(), 2);
        assert_eq!(parser.entries[0].section.as_deref(), Some("Section1"));
        assert_eq!(parser.entries[1].section.as_deref(), Some("Section2"));
    }

    #[test]
    fn test_parse_comments_and_empty_lines() {
        let input = "\
# This is a comment
; Another comment
key1=value1

key2=value2
";
        let mut parser = ConfigParser::new(ConfigParseFlags::default());
        parser.parse_reader(Cursor::new(input)).unwrap();

        assert_eq!(parser.entries.len(), 2);
    }

    #[test]
    fn test_parse_bom() {
        let mut input = String::new();
        input.push(BOM);
        input.push_str("key=value\n");
        let mut parser = ConfigParser::new(ConfigParseFlags::default());
        parser.parse_reader(Cursor::new(input)).unwrap();

        assert_eq!(parser.entries.len(), 1);
        assert_eq!(parser.entries[0].key, "key");
        assert_eq!(parser.entries[0].value, "value");
    }

    #[test]
    fn test_parse_continuation_lines() {
        let input = "key=longvalue\\\n  continued\n";
        let mut parser = ConfigParser::new(ConfigParseFlags::default());
        parser.parse_reader(Cursor::new(input)).unwrap();

        assert_eq!(parser.entries.len(), 1);
        assert_eq!(parser.entries[0].value, "longvalue  continued");
    }

    // ── Error cases ──────────────────────────────────────────────────

    #[test]
    fn test_error_missing_equals() {
        let input = "invalid_line_no_equals\n";
        let mut parser = ConfigParser::new(ConfigParseFlags::default());
        let result = parser.parse_reader(Cursor::new(input));

        assert!(result.is_err());
    }

    #[test]
    fn test_error_missing_closing_bracket() {
        let input = "[BadSection\n";
        let mut parser = ConfigParser::new(ConfigParseFlags::default());
        let result = parser.parse_reader(Cursor::new(input));

        assert!(result.is_err());
    }

    #[test]
    fn test_error_empty_key() {
        let input = "[S]\n=value\n";
        let mut parser = ConfigParser::new(ConfigParseFlags::default());
        let result = parser.parse_reader(Cursor::new(input));

        assert!(result.is_err());
    }

    #[test]
    fn test_assignment_outside_section_with_allowlist() {
        let input = "key=value\n";
        let mut parser = ConfigParser::new(ConfigParseFlags::default())
            .with_sections(vec!["Service".to_string()]);
        let result = parser.parse_reader(Cursor::new(input));

        assert!(result.is_err());
    }

    // ── Query methods ────────────────────────────────────────────────

    #[test]
    fn test_get_value() {
        let input = "\
[Section]
key1=value1
key2=value2
";
        let mut parser = ConfigParser::new(ConfigParseFlags::default());
        parser.parse_reader(Cursor::new(input)).unwrap();

        assert_eq!(parser.get(Some("Section"), "key1"), Some("value1"));
        assert_eq!(parser.get(Some("Section"), "key2"), Some("value2"));
        assert_eq!(parser.get(Some("Section"), "missing"), None);
        assert_eq!(parser.get(Some("Other"), "key1"), None);
    }

    #[test]
    fn test_to_hashmap() {
        let input = "\
[Section]
key1=value1
key2=value2
";
        let mut parser = ConfigParser::new(ConfigParseFlags::default());
        parser.parse_reader(Cursor::new(input)).unwrap();

        let map = parser.to_hashmap();
        assert_eq!(map.get("Section.key1").unwrap(), "value1");
        assert_eq!(map.get("Section.key2").unwrap(), "value2");
    }

    // ── Value parsers ────────────────────────────────────────────────

    #[test]
    fn test_parse_bool_variants() {
        assert_eq!(parse_bool("yes"), Some(true));
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("1"), Some(true));
        assert_eq!(parse_bool("on"), Some(true));
        assert_eq!(parse_bool("no"), Some(false));
        assert_eq!(parse_bool("false"), Some(false));
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool("off"), Some(false));
        assert_eq!(parse_bool("maybe"), None);
    }

    #[test]
    fn test_parse_iec_size() {
        assert_eq!(parse_iec_size("1024"), Some(1024));
        assert_eq!(parse_iec_size("4K"), Some(4096));
        assert_eq!(parse_iec_size("1M"), Some(1024 * 1024));
        assert_eq!(parse_iec_size("2G"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_iec_size(""), None);
    }

    #[test]
    fn test_parse_uint_bounded() {
        assert_eq!(parse_uint_bounded("50", 0, 100), Some(50));
        assert_eq!(parse_uint_bounded("0", 0, 100), Some(0));
        assert_eq!(parse_uint_bounded("100", 0, 100), Some(100));
        assert_eq!(parse_uint_bounded("101", 0, 100), None);
        assert_eq!(parse_uint_bounded("-1", 0, 100), None);
    }

    #[test]
    fn test_parse_signal() {
        assert_eq!(parse_signal("SIGTERM"), Some(15));
        assert_eq!(parse_signal("TERM"), Some(15));
        assert_eq!(parse_signal("15"), Some(15));
        assert_eq!(parse_signal("SIGKILL"), Some(9));
        assert_eq!(parse_signal("0"), None);
        assert_eq!(parse_signal(""), None);
    }

    #[test]
    fn test_parse_tristate() {
        assert_eq!(parse_tristate(""), Some(-1));
        assert_eq!(parse_tristate("yes"), Some(1));
        assert_eq!(parse_tristate("no"), Some(0));
    }

    #[test]
    fn test_parse_uint64_infinity() {
        assert_eq!(parse_uint64_infinity("infinity"), Some(u64::MAX));
        assert_eq!(parse_uint64_infinity("Infinity"), Some(u64::MAX));
        assert_eq!(parse_uint64_infinity("42"), Some(42));
        assert_eq!(parse_uint64_infinity(""), None);
    }

    // ── Section name validation ──────────────────────────────────────

    #[test]
    fn test_section_name_is_safe() {
        assert!(section_name_is_safe("Service"));
        assert!(section_name_is_safe("Install"));
        assert!(section_name_is_safe("X-Special"));
        assert!(!section_name_is_safe(""));
        assert!(!section_name_is_safe("bad\tname"));
    }

    // ── Merge configs ────────────────────────────────────────────────

    #[test]
    fn test_merge_configs_override() {
        let c1 = vec![ConfigEntry {
            section: Some("S".into()),
            key: "k".into(),
            value: "v1".into(),
            line_number: 1,
        }];
        let c2 = vec![ConfigEntry {
            section: Some("S".into()),
            key: "k".into(),
            value: "v2".into(),
            line_number: 1,
        }];

        let merged = merge_configs(vec![c1, c2]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].value, "v2");
    }

    // ── Write config ─────────────────────────────────────────────────

    #[test]
    fn test_write_config_roundtrip() {
        let input = "\
[Section]
key1=value1
key2=value2
";
        let mut parser = ConfigParser::new(ConfigParseFlags::default());
        parser.parse_reader(Cursor::new(input)).unwrap();

        let mut output = Vec::new();
        write_config(&parser.entries, &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();

        assert!(output_str.contains("[Section]"));
        assert!(output_str.contains("key1=value1"));
        assert!(output_str.contains("key2=value2"));
    }

    // ── Stats by path ────────────────────────────────────────────────

    #[test]
    fn test_stats_by_path_equal() {
        let mut a = StatsByPath::new();
        a.insert(
            "/etc/systemd/system.conf".into(),
            FileStats {
                ino: 100,
                dev: 8,
                size: 500,
                mtime: 1000,
            },
        );

        let mut b = a.clone();
        assert!(stats_by_path_equal(&a, &b));

        b.get_mut("/etc/systemd/system.conf").unwrap().mtime = 2000;
        assert!(!stats_by_path_equal(&a, &b));
    }

    // ── Find unused line ─────────────────────────────────────────────

    #[test]
    fn test_find_unused_line() {
        let sections = vec![
            ConfigSection {
                filename: "a.conf".into(),
                line: 5,
            },
            ConfigSection {
                filename: "a.conf".into(),
                line: 12,
            },
            ConfigSection {
                filename: "b.conf".into(),
                line: 20,
            },
        ];

        assert_eq!(find_unused_line(&sections, Some("a.conf")), Some(13));
        assert_eq!(find_unused_line(&sections, Some("b.conf")), Some(21));
        assert_eq!(find_unused_line(&sections, Some("c.conf")), Some(1));
        assert_eq!(find_unused_line(&sections, None), Some(21));
    }

    // ── Allowed sections ─────────────────────────────────────────────

    #[test]
    fn test_allowed_sections() {
        let input = "\
[Service]
ExecStart=/bin/true

[Install]
WantedBy=multi-user.target

[Unknown]
Key=value
";
        let mut parser = ConfigParser::new(ConfigParseFlags::default())
            .with_sections(vec!["Service".into(), "Install".into()]);
        parser.parse_reader(Cursor::new(input)).unwrap();

        // Unknown section entries should be ignored
        assert_eq!(parser.entries.len(), 2);
        assert_eq!(parser.entries[0].key, "ExecStart");
        assert_eq!(parser.entries[1].key, "WantedBy");
    }

    #[test]
    fn test_x_prefix_sections_always_allowed() {
        let input = "\
[X-Special]
Key=value
";
        let mut parser =
            ConfigParser::new(ConfigParseFlags::default()).with_sections(vec!["Service".into()]);
        parser.parse_reader(Cursor::new(input)).unwrap();

        assert_eq!(parser.entries.len(), 1);
        assert_eq!(parser.entries[0].section.as_deref(), Some("X-Special"));
    }
}
