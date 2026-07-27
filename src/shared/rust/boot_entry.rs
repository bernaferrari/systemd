// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/boot-entry.c, src/shared/boot-entry.h
//
// Boot entry token management for BLS (Boot Loader Specification).

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootEntryError {
    InvalidToken(String),
    InvalidType(String),
    NoTokenAvailable(String),
    Io(String),
}

impl fmt::Display for BootEntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidToken(msg) => write!(f, "invalid entry token: {msg}"),
            Self::InvalidType(msg) => write!(f, "invalid token type: {msg}"),
            Self::NoTokenAvailable(msg) => write!(f, "no token available: {msg}"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for BootEntryError {}

impl From<io::Error> for BootEntryError {
    fn from(e: io::Error) -> Self {
        BootEntryError::Io(e.to_string())
    }
}

// ── Token type ─────────────────────────────────────────────────────────────

/// Boot entry token source type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootEntryTokenType {
    MachineId,
    OsImageId,
    OsId,
    Literal,
    Auto,
}

static TOKEN_TYPE_TABLE: &[(BootEntryTokenType, &str)] = &[
    (BootEntryTokenType::MachineId, "machine-id"),
    (BootEntryTokenType::OsImageId, "os-image-id"),
    (BootEntryTokenType::OsId, "os-id"),
    (BootEntryTokenType::Literal, "literal"),
    (BootEntryTokenType::Auto, "auto"),
];

impl BootEntryTokenType {
    pub fn to_str(self) -> &'static str {
        TOKEN_TYPE_TABLE
            .iter()
            .find(|(t, _)| *t == self)
            .map(|(_, s)| *s)
            .unwrap_or("auto")
    }

    pub fn from_str(s: &str) -> Result<Self, BootEntryError> {
        TOKEN_TYPE_TABLE
            .iter()
            .find(|(_, name)| *name == s)
            .map(|(t, _)| *t)
            .ok_or_else(|| BootEntryError::InvalidType(format!("unexpected token type: {s}")))
    }
}

// ── Resolved token ─────────────────────────────────────────────────────────

/// A fully resolved boot entry token with its source type and value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootEntryToken {
    pub token_type: BootEntryTokenType,
    pub token: String,
}

// ── Token validation ───────────────────────────────────────────────────────

/// Maximum length for a boot entry token (NAME_MAX on Linux).
const TOKEN_MAX_LEN: usize = 255;

/// Check if a token string is valid for use as a boot entry token.
///
/// A valid token must be non-empty, not "." or "..", contain no slashes
/// or control characters, and be at most 255 bytes.
pub fn boot_entry_token_valid(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= TOKEN_MAX_LEN
        && token != "."
        && token != ".."
        && !token.contains('/')
        && !token.chars().any(|c| c.is_control())
}

// ── CLI parsing ────────────────────────────────────────────────────────────

/// Parsed result of a `--entry-token=` command-line argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedTokenArg {
    /// A named source type with no literal value (e.g., "machine-id", "os-id").
    Type(BootEntryTokenType),
    /// A literal token value (e.g., "literal:my-token").
    Literal(String),
}

/// Parse a boot entry token type from a command-line string.
///
/// Recognized inputs: "auto", "machine-id", "os-image-id", "os-id",
/// and "literal:<value>".
pub fn parse_boot_entry_token_type(s: &str) -> Result<ParsedTokenArg, BootEntryError> {
    match s {
        "auto" => Ok(ParsedTokenArg::Type(BootEntryTokenType::Auto)),
        "machine-id" => Ok(ParsedTokenArg::Type(BootEntryTokenType::MachineId)),
        "os-image-id" => Ok(ParsedTokenArg::Type(BootEntryTokenType::OsImageId)),
        "os-id" => Ok(ParsedTokenArg::Type(BootEntryTokenType::OsId)),
        _ => {
            if let Some(literal) = s.strip_prefix("literal:") {
                if !boot_entry_token_valid(literal) {
                    return Err(BootEntryError::InvalidToken(
                        "invalid entry token literal specified for --entry-token=".into(),
                    ));
                }
                Ok(ParsedTokenArg::Literal(literal.to_owned()))
            } else {
                Err(BootEntryError::InvalidType(format!(
                    "unexpected parameter for --entry-token=: {s}"
                )))
            }
        }
    }
}

// ── File system abstraction ────────────────────────────────────────────────

const ENTRY_TOKEN_FILE: &str = "entry-token";
const KERNEL_DIRS: &[&str] = &["/etc/kernel", "/usr/lib/kernel"];

/// Trait for file system operations needed by token resolution.
pub trait BootEntryFs {
    fn read_line(&self, path: &Path) -> Result<Option<String>, BootEntryError>;
    fn read_os_release_fields(&self) -> Result<(Option<String>, Option<String>), BootEntryError>;
}

/// Default implementation using the real filesystem.
pub struct RealBootEntryFs;

impl BootEntryFs for RealBootEntryFs {
    fn read_line(&self, path: &Path) -> Result<Option<String>, BootEntryError> {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(BootEntryError::Io(e.to_string())),
        };
        let line = content.lines().next().unwrap_or("");
        if line.is_empty() {
            Ok(None)
        } else {
            Ok(Some(line.to_owned()))
        }
    }

    fn read_os_release_fields(&self) -> Result<(Option<String>, Option<String>), BootEntryError> {
        let content = match fs::read_to_string("/etc/os-release") {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((None, None)),
            Err(e) => return Err(BootEntryError::Io(e.to_string())),
        };

        let mut image_id = None;
        let mut id = None;

        for line in content.lines() {
            let line = line.trim();
            if let Some(val) = line.strip_prefix("IMAGE_ID=") {
                image_id = Some(unquote_os_release_val(val).to_owned());
            } else if let Some(val) = line.strip_prefix("ID=") {
                id = Some(unquote_os_release_val(val).to_owned());
            }
        }

        Ok((image_id, id))
    }
}

/// Strip surrounding quotes from an os-release field value.
fn unquote_os_release_val(val: &str) -> &str {
    val.strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(val)
}

// ── Token resolution ───────────────────────────────────────────────────────

/// Try to load an entry token from a file in the given directory.
fn entry_token_load_one(fs: &dyn BootEntryFs, dir: &str) -> Result<Option<String>, BootEntryError> {
    let path = Path::new(dir).join(ENTRY_TOKEN_FILE);
    match fs.read_line(&path)? {
        Some(buf) if boot_entry_token_valid(&buf) => Ok(Some(buf)),
        _ => Ok(None),
    }
}

/// Try to load an entry token from configured or default kernel directories.
fn entry_token_load(
    fs: &dyn BootEntryFs,
    conf_root: Option<&str>,
) -> Result<Option<String>, BootEntryError> {
    if let Some(root) = conf_root {
        return entry_token_load_one(fs, root);
    }
    for dir in KERNEL_DIRS {
        if let Some(token) = entry_token_load_one(fs, dir)? {
            return Ok(Some(token));
        }
    }
    Ok(None)
}

/// Try to derive a token from the machine ID.
fn entry_token_from_machine_id(machine_id: &[u8; 16]) -> Result<Option<String>, BootEntryError> {
    if machine_id.iter().all(|&b| b == 0) {
        return Ok(None);
    }
    let hex: String = machine_id.iter().map(|b| format!("{b:02x}")).collect();
    Ok(Some(hex))
}

/// Try to derive a token from os-release fields.
fn entry_token_from_os_release(
    fs: &dyn BootEntryFs,
    prefer: BootEntryTokenType,
) -> Result<Option<(String, BootEntryTokenType)>, BootEntryError> {
    let (image_id, id) = fs.read_os_release_fields()?;

    match prefer {
        BootEntryTokenType::Auto => {
            if let Some(ref val) = image_id {
                if boot_entry_token_valid(val) {
                    return Ok(Some((val.clone(), BootEntryTokenType::OsImageId)));
                }
            }
            if let Some(ref val) = id {
                if boot_entry_token_valid(val) {
                    return Ok(Some((val.clone(), BootEntryTokenType::OsId)));
                }
            }
        }
        BootEntryTokenType::OsImageId => {
            if let Some(ref val) = image_id {
                if boot_entry_token_valid(val) {
                    return Ok(Some((val.clone(), BootEntryTokenType::OsImageId)));
                }
            }
        }
        BootEntryTokenType::OsId => {
            if let Some(ref val) = id {
                if boot_entry_token_valid(val) {
                    return Ok(Some((val.clone(), BootEntryTokenType::OsId)));
                }
            }
        }
        _ => {}
    }

    Ok(None)
}

/// Resolve a boot entry token based on the given type and available sources.
pub fn boot_entry_token_ensure(
    token_type: BootEntryTokenType,
    existing_token: Option<&str>,
    conf_root: Option<&str>,
    machine_id: &[u8; 16],
    machine_id_is_random: bool,
    fs: &dyn BootEntryFs,
) -> Result<BootEntryToken, BootEntryError> {
    if let Some(token) = existing_token {
        return Ok(BootEntryToken {
            token_type,
            token: token.to_owned(),
        });
    }

    match token_type {
        BootEntryTokenType::Auto => {
            if let Some(token) = entry_token_load(fs, conf_root)? {
                return Ok(BootEntryToken {
                    token_type: BootEntryTokenType::Literal,
                    token,
                });
            }

            if !machine_id_is_random {
                if let Some(token) = entry_token_from_machine_id(machine_id)? {
                    return Ok(BootEntryToken {
                        token_type: BootEntryTokenType::MachineId,
                        token,
                    });
                }
            }

            if let Some((token, tt)) = entry_token_from_os_release(fs, BootEntryTokenType::Auto)? {
                return Ok(BootEntryToken {
                    token_type: tt,
                    token,
                });
            }

            if machine_id_is_random {
                if let Some(token) = entry_token_from_machine_id(machine_id)? {
                    return Ok(BootEntryToken {
                        token_type: BootEntryTokenType::MachineId,
                        token,
                    });
                }
            }

            Err(BootEntryError::NoTokenAvailable(
                "no machine ID set, and /etc/os-release carries no ID=/IMAGE_ID= fields".into(),
            ))
        }
        BootEntryTokenType::MachineId => {
            if let Some(token) = entry_token_from_machine_id(machine_id)? {
                return Ok(BootEntryToken {
                    token_type: BootEntryTokenType::MachineId,
                    token,
                });
            }
            Err(BootEntryError::NoTokenAvailable("no machine ID set".into()))
        }
        BootEntryTokenType::OsImageId => {
            if let Some((token, _)) =
                entry_token_from_os_release(fs, BootEntryTokenType::OsImageId)?
            {
                return Ok(BootEntryToken {
                    token_type: BootEntryTokenType::OsImageId,
                    token,
                });
            }
            Err(BootEntryError::NoTokenAvailable(
                "IMAGE_ID= field not set in /etc/os-release".into(),
            ))
        }
        BootEntryTokenType::OsId => {
            if let Some((token, _)) = entry_token_from_os_release(fs, BootEntryTokenType::OsId)? {
                return Ok(BootEntryToken {
                    token_type: BootEntryTokenType::OsId,
                    token,
                });
            }
            Err(BootEntryError::NoTokenAvailable(
                "ID= field not set in /etc/os-release".into(),
            ))
        }
        BootEntryTokenType::Literal => Err(BootEntryError::NoTokenAvailable(
            "literal token indicated but not specified".into(),
        )),
    }
}

// ── Machine ID formatting ──────────────────────────────────────────────────

/// Format a 16-byte machine ID as a 32-character lowercase hex string (no dashes).
pub fn format_machine_id(machine_id: &[u8; 16]) -> String {
    machine_id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a 32-character hex string into a 16-byte machine ID.
pub fn parse_machine_id(s: &str) -> Result<[u8; 16], BootEntryError> {
    let s: String = s.chars().filter(|c| *c != '-').collect();
    if s.len() != 32 {
        return Err(BootEntryError::InvalidToken(format!(
            "machine ID must be 32 hex chars, got {}",
            s.len()
        )));
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| {
            BootEntryError::InvalidToken(format!("invalid hex in machine ID at position {i}"))
        })?;
    }
    Ok(bytes)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Mock filesystem backed by an in-memory map of path → file contents.
    struct MockFs {
        files: HashMap<String, String>,
    }

    impl MockFs {
        fn new() -> Self {
            Self {
                files: HashMap::new(),
            }
        }

        fn with_file(mut self, path: &str, content: &str) -> Self {
            self.files.insert(path.to_owned(), content.to_owned());
            self
        }
    }

    impl BootEntryFs for MockFs {
        fn read_line(&self, path: &Path) -> Result<Option<String>, BootEntryError> {
            let key = path.to_string_lossy().to_string();
            match self.files.get(&key) {
                Some(content) => {
                    let line = content.lines().next().unwrap_or("");
                    if line.is_empty() {
                        Ok(None)
                    } else {
                        Ok(Some(line.to_owned()))
                    }
                }
                None => Ok(None),
            }
        }

        fn read_os_release_fields(
            &self,
        ) -> Result<(Option<String>, Option<String>), BootEntryError> {
            let content = match self.files.get("/etc/os-release") {
                Some(c) => c.clone(),
                None => return Ok((None, None)),
            };

            let mut image_id = None;
            let mut id = None;

            for line in content.lines() {
                let line = line.trim();
                if let Some(val) = line.strip_prefix("IMAGE_ID=") {
                    image_id = Some(unquote_os_release_val(val).to_owned());
                } else if let Some(val) = line.strip_prefix("ID=") {
                    id = Some(unquote_os_release_val(val).to_owned());
                }
            }

            Ok((image_id, id))
        }
    }

    fn null_machine_id() -> [u8; 16] {
        [0u8; 16]
    }

    fn test_machine_id() -> [u8; 16] {
        let mut id = [0u8; 16];
        id[0] = 0xc9;
        id[1] = 0x6b;
        id[2] = 0x5d;
        id[3] = 0x3b;
        id[4..16].copy_from_slice(b"abcdef012345");
        id
    }

    #[test]
    fn test_boot_entry_token_valid_basic() {
        assert!(boot_entry_token_valid("my-token"));
        assert!(boot_entry_token_valid("abc123"));
        assert!(boot_entry_token_valid("a_b-c"));
        assert!(boot_entry_token_valid("fedora"));
    }

    #[test]
    fn test_boot_entry_token_valid_rejects_empty() {
        assert!(!boot_entry_token_valid(""));
    }

    #[test]
    fn test_boot_entry_token_valid_rejects_dot() {
        assert!(!boot_entry_token_valid("."));
        assert!(!boot_entry_token_valid(".."));
    }

    #[test]
    fn test_boot_entry_token_valid_rejects_slash() {
        assert!(!boot_entry_token_valid("foo/bar"));
        assert!(!boot_entry_token_valid("/etc/kernel"));
    }

    #[test]
    fn test_boot_entry_token_valid_rejects_control_chars() {
        assert!(!boot_entry_token_valid("foo\nbar"));
        assert!(!boot_entry_token_valid("foo\tbar"));
        assert!(!boot_entry_token_valid("foo\x00bar"));
        assert!(!boot_entry_token_valid("foo\x1bbar"));
    }

    #[test]
    fn test_boot_entry_token_valid_rejects_too_long() {
        let long = "a".repeat(256);
        assert!(!boot_entry_token_valid(&long));

        let ok = "a".repeat(255);
        assert!(boot_entry_token_valid(&ok));
    }

    #[test]
    fn test_boot_entry_token_valid_allows_spaces() {
        assert!(boot_entry_token_valid("my token"));
    }

    #[test]
    fn test_token_type_to_str() {
        assert_eq!(BootEntryTokenType::MachineId.to_str(), "machine-id");
        assert_eq!(BootEntryTokenType::OsImageId.to_str(), "os-image-id");
        assert_eq!(BootEntryTokenType::OsId.to_str(), "os-id");
        assert_eq!(BootEntryTokenType::Literal.to_str(), "literal");
        assert_eq!(BootEntryTokenType::Auto.to_str(), "auto");
    }

    #[test]
    fn test_token_type_from_str() {
        assert_eq!(
            BootEntryTokenType::from_str("machine-id").unwrap(),
            BootEntryTokenType::MachineId
        );
        assert_eq!(
            BootEntryTokenType::from_str("os-image-id").unwrap(),
            BootEntryTokenType::OsImageId
        );
        assert_eq!(
            BootEntryTokenType::from_str("os-id").unwrap(),
            BootEntryTokenType::OsId
        );
        assert_eq!(
            BootEntryTokenType::from_str("literal").unwrap(),
            BootEntryTokenType::Literal
        );
        assert_eq!(
            BootEntryTokenType::from_str("auto").unwrap(),
            BootEntryTokenType::Auto
        );
    }

    #[test]
    fn test_token_type_from_str_invalid() {
        assert!(BootEntryTokenType::from_str("bogus").is_err());
        assert!(BootEntryTokenType::from_str("").is_err());
    }

    #[test]
    fn test_parse_boot_entry_token_type_named() {
        assert_eq!(
            parse_boot_entry_token_type("auto").unwrap(),
            ParsedTokenArg::Type(BootEntryTokenType::Auto)
        );
        assert_eq!(
            parse_boot_entry_token_type("machine-id").unwrap(),
            ParsedTokenArg::Type(BootEntryTokenType::MachineId)
        );
        assert_eq!(
            parse_boot_entry_token_type("os-image-id").unwrap(),
            ParsedTokenArg::Type(BootEntryTokenType::OsImageId)
        );
        assert_eq!(
            parse_boot_entry_token_type("os-id").unwrap(),
            ParsedTokenArg::Type(BootEntryTokenType::OsId)
        );
    }

    #[test]
    fn test_parse_boot_entry_token_type_literal() {
        assert_eq!(
            parse_boot_entry_token_type("literal:my-token").unwrap(),
            ParsedTokenArg::Literal("my-token".to_owned())
        );
    }

    #[test]
    fn test_parse_boot_entry_token_type_literal_invalid() {
        assert!(parse_boot_entry_token_type("literal:foo/bar").is_err());
        assert!(parse_boot_entry_token_type("literal:").is_err());
    }

    #[test]
    fn test_parse_boot_entry_token_type_invalid() {
        assert!(parse_boot_entry_token_type("bogus").is_err());
        assert!(parse_boot_entry_token_type("").is_err());
    }

    #[test]
    fn test_ensure_returns_existing() {
        let fs = MockFs::new();
        let result = boot_entry_token_ensure(
            BootEntryTokenType::Auto,
            Some("already-set"),
            None,
            &null_machine_id(),
            false,
            &fs,
        );
        let token = result.unwrap();
        assert_eq!(token.token, "already-set");
        assert_eq!(token.token_type, BootEntryTokenType::Auto);
    }

    #[test]
    fn test_ensure_machine_id_type() {
        let fs = MockFs::new();
        let result = boot_entry_token_ensure(
            BootEntryTokenType::MachineId,
            None,
            None,
            &test_machine_id(),
            false,
            &fs,
        );
        let token = result.unwrap();
        assert_eq!(token.token_type, BootEntryTokenType::MachineId);
        assert_eq!(token.token.len(), 32);
    }

    #[test]
    fn test_ensure_machine_id_null_fails() {
        let fs = MockFs::new();
        let result = boot_entry_token_ensure(
            BootEntryTokenType::MachineId,
            None,
            None,
            &null_machine_id(),
            false,
            &fs,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            BootEntryError::NoTokenAvailable(msg) => {
                assert!(msg.contains("no machine ID"));
            }
            e => panic!("expected NoTokenAvailable, got {e:?}"),
        }
    }

    #[test]
    fn test_ensure_os_image_id_from_release() {
        let fs = MockFs::new().with_file("/etc/os-release", "IMAGE_ID=fedora\nID=fedora\n");
        let result = boot_entry_token_ensure(
            BootEntryTokenType::OsImageId,
            None,
            None,
            &null_machine_id(),
            false,
            &fs,
        );
        let token = result.unwrap();
        assert_eq!(token.token_type, BootEntryTokenType::OsImageId);
        assert_eq!(token.token, "fedora");
    }

    #[test]
    fn test_ensure_os_id_from_release() {
        let fs = MockFs::new().with_file("/etc/os-release", "ID=ubuntu\n");
        let result = boot_entry_token_ensure(
            BootEntryTokenType::OsId,
            None,
            None,
            &null_machine_id(),
            false,
            &fs,
        );
        let token = result.unwrap();
        assert_eq!(token.token_type, BootEntryTokenType::OsId);
        assert_eq!(token.token, "ubuntu");
    }

    #[test]
    fn test_ensure_auto_cascade_entry_token_file() {
        let fs = MockFs::new().with_file("/etc/kernel/entry-token", "my-loader-token\n");
        let result = boot_entry_token_ensure(
            BootEntryTokenType::Auto,
            None,
            None,
            &null_machine_id(),
            false,
            &fs,
        );
        let token = result.unwrap();
        assert_eq!(token.token_type, BootEntryTokenType::Literal);
        assert_eq!(token.token, "my-loader-token");
    }

    #[test]
    fn test_ensure_auto_cascade_machine_id() {
        let fs = MockFs::new();
        let result = boot_entry_token_ensure(
            BootEntryTokenType::Auto,
            None,
            None,
            &test_machine_id(),
            false,
            &fs,
        );
        let token = result.unwrap();
        assert_eq!(token.token_type, BootEntryTokenType::MachineId);
    }

    #[test]
    fn test_ensure_auto_cascade_os_release() {
        let fs = MockFs::new().with_file("/etc/os-release", "IMAGE_ID=debian\n");
        let result = boot_entry_token_ensure(
            BootEntryTokenType::Auto,
            None,
            None,
            &null_machine_id(),
            false,
            &fs,
        );
        let token = result.unwrap();
        assert_eq!(token.token_type, BootEntryTokenType::OsImageId);
        assert_eq!(token.token, "debian");
    }

    #[test]
    fn test_ensure_auto_cascade_random_machine_id_fallback() {
        let fs = MockFs::new();
        let result = boot_entry_token_ensure(
            BootEntryTokenType::Auto,
            None,
            None,
            &test_machine_id(),
            true,
            &fs,
        );
        let token = result.unwrap();
        assert_eq!(token.token_type, BootEntryTokenType::MachineId);
    }

    #[test]
    fn test_ensure_auto_all_fail() {
        let fs = MockFs::new();
        let result = boot_entry_token_ensure(
            BootEntryTokenType::Auto,
            None,
            None,
            &null_machine_id(),
            false,
            &fs,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_ensure_literal_no_existing_fails() {
        let fs = MockFs::new();
        let result = boot_entry_token_ensure(
            BootEntryTokenType::Literal,
            None,
            None,
            &null_machine_id(),
            false,
            &fs,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_ensure_with_conf_root() {
        let fs = MockFs::new().with_file("/custom/kernel/entry-token", "custom-token\n");
        let result = boot_entry_token_ensure(
            BootEntryTokenType::Auto,
            None,
            Some("/custom/kernel"),
            &null_machine_id(),
            false,
            &fs,
        );
        let token = result.unwrap();
        assert_eq!(token.token, "custom-token");
    }

    #[test]
    fn test_ensure_invalid_entry_token_ignored() {
        let fs = MockFs::new()
            .with_file("/etc/kernel/entry-token", "foo/bar\n")
            .with_file("/etc/os-release", "ID=arch\n");
        let result = boot_entry_token_ensure(
            BootEntryTokenType::Auto,
            None,
            None,
            &null_machine_id(),
            false,
            &fs,
        );
        let token = result.unwrap();
        assert_eq!(token.token_type, BootEntryTokenType::OsId);
        assert_eq!(token.token, "arch");
    }

    #[test]
    fn test_ensure_os_release_image_id_preferred_over_id() {
        let fs =
            MockFs::new().with_file("/etc/os-release", "IMAGE_ID=opensuse\nID=opensuse-leap\n");
        let result = boot_entry_token_ensure(
            BootEntryTokenType::Auto,
            None,
            None,
            &null_machine_id(),
            false,
            &fs,
        );
        let token = result.unwrap();
        assert_eq!(token.token_type, BootEntryTokenType::OsImageId);
        assert_eq!(token.token, "opensuse");
    }

    #[test]
    fn test_ensure_os_release_quoted_values() {
        let fs = MockFs::new().with_file("/etc/os-release", r#"IMAGE_ID="ubuntu24.04""#);
        let result = boot_entry_token_ensure(
            BootEntryTokenType::OsImageId,
            None,
            None,
            &null_machine_id(),
            false,
            &fs,
        );
        let token = result.unwrap();
        assert_eq!(token.token, "ubuntu24.04");
    }

    #[test]
    fn test_format_machine_id() {
        let id = test_machine_id();
        let formatted = format_machine_id(&id);
        assert_eq!(formatted.len(), 32);
        assert_eq!(&formatted[..4], "c96b");
    }

    #[test]
    fn test_format_null_machine_id() {
        let formatted = format_machine_id(&null_machine_id());
        assert_eq!(formatted, "00000000000000000000000000000000");
    }

    #[test]
    fn test_parse_machine_id() {
        let hex = "c96b5d3babcdef0123456789abcdef01";
        let bytes = parse_machine_id(hex).unwrap();
        assert_eq!(bytes[0], 0xc9);
        assert_eq!(bytes[1], 0x6b);
        assert_eq!(bytes[2], 0x5d);
        assert_eq!(bytes[3], 0x3b);
    }

    #[test]
    fn test_parse_machine_id_with_dashes() {
        let hex = "c96b5d3b-abcdef01-23456789-abcdef01";
        let bytes = parse_machine_id(hex).unwrap();
        assert_eq!(bytes[0], 0xc9);
    }

    #[test]
    fn test_parse_machine_id_invalid() {
        assert!(parse_machine_id("too-short").is_err());
        assert!(parse_machine_id("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }

    #[test]
    fn test_unquote_os_release_val() {
        assert_eq!(unquote_os_release_val("fedora"), "fedora");
        assert_eq!(unquote_os_release_val("\"ubuntu\""), "ubuntu");
        assert_eq!(unquote_os_release_val("\"multi-word\""), "multi-word");
        assert_eq!(unquote_os_release_val("\""), "\"");
    }
}
