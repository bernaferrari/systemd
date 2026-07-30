// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/machine-credential.c, src/shared/machine-credential.h
//
// Machine credential management for containers and VMs.
//
// Provides a credential store (MachineCredentialContext) that holds named
// credential blobs. Credentials can be set inline via --set-credential= or
// loaded from files / the system credentials directory via --load-credential=.
//
// Ported from C: machine_credential_context_done, machine_credential_find,
// machine_credential_add, machine_credential_add_and_log,
// machine_credential_set, machine_credential_load.

use crate::ffi::*;
use std::path::{Path, PathBuf};

use crate::creds_util::{
    CREDENTIAL_NAME_MAX, CredentialsDir, credential_name_valid, get_credentials_dir,
    read_credential_path,
};
use crate::secret_bytes::{SecretBytes, SecretBytesFinalizeError};
use systemd_basic_rs::escape::{UnescapeFlags, try_cunescape_into};

// ── Error type ─────────────────────────────────────────────────────────────

/// Errors produced by machine credential operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineCredentialError {
    /// The credential name is not valid.
    InvalidName(String),
    /// A credential with this id already exists.
    AlreadyExists(String),
    /// A credential was not found.
    NotFound(String),
    /// Missing value after the ':' separator in a credential string.
    MissingValue(String),
    /// Failed to unescape credential data.
    UnescapeError,
    /// Failed to read a credential file.
    ReadError { path: PathBuf, detail: String },
    /// Credential source is neither a valid path nor a credential name.
    InvalidSource(String),
    /// No credentials directory available.
    NoCredentialsDir,
    /// Memory could not be reserved without panicking on a fallible path.
    OutOfMemory,
}

impl std::fmt::Display for MachineCredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName(id) => {
                write!(f, "Credential name is not valid: {id}")
            }
            Self::AlreadyExists(id) => {
                write!(f, "Duplicated credential '{id}', refusing.")
            }
            Self::NotFound(id) => {
                write!(f, "Credential '{id}' not found.")
            }
            Self::MissingValue(s) => {
                write!(f, "Missing value for --{s}=.")
            }
            Self::UnescapeError => {
                write!(f, "Failed to unescape credential data (contents redacted)")
            }
            Self::ReadError { path, detail } => {
                write!(
                    f,
                    "Failed to read credential '{}': {}",
                    path.display(),
                    detail
                )
            }
            Self::InvalidSource(s) => {
                write!(
                    f,
                    "Credential source appears to be neither a valid path nor a credential name: {s}"
                )
            }
            Self::NoCredentialsDir => {
                write!(f, "Credential not available (no credentials passed at all)")
            }
            Self::OutOfMemory => write!(f, "Out of memory while storing credential"),
        }
    }
}

impl std::error::Error for MachineCredentialError {}

// ── Data types ─────────────────────────────────────────────────────────────

/// A single credential entry holding an id and opaque binary data.
///
/// The `data` field uses the crate-wide non-cloneable `SecretBytes` owner so
/// credential memory is securely erased before deallocation.
#[derive(Debug)]
pub struct MachineCredential {
    /// Credential identifier (valid credential name).
    pub id: String,
    /// Opaque credential data.
    pub data: SecretBytes,
}

impl MachineCredential {
    /// Create a new credential with the given id and data.
    fn new(id: String, data: SecretBytes) -> Self {
        Self { id, data }
    }
}

// ── Context ────────────────────────────────────────────────────────────────

/// A collection of machine credentials.
///
/// This is the Rust equivalent of the C `MachineCredentialContext` struct.
/// It owns all credential data and securely erases it on drop.
#[derive(Debug, Default)]
pub struct MachineCredentialContext {
    credentials: Vec<MachineCredential>,
}

impl MachineCredentialContext {
    /// Create an empty credential context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of credentials stored.
    pub fn len(&self) -> usize {
        self.credentials.len()
    }

    /// Whether the context holds no credentials.
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    /// Find a credential by id. Returns a reference if found.
    pub fn find(&self, id: &str) -> Option<&MachineCredential> {
        self.credentials.iter().find(|c| c.id == id)
    }

    /// Find a credential by id. Returns a mutable reference if found.
    pub fn find_mut(&mut self, id: &str) -> Option<&mut MachineCredential> {
        self.credentials.iter_mut().find(|c| c.id == id)
    }

    fn insert_owned(&mut self, id: &str, data: SecretBytes) -> Result<(), MachineCredentialError> {
        if !credential_name_valid(id) {
            return Err(MachineCredentialError::InvalidName(id.to_owned()));
        }

        if self.find(id).is_some() {
            return Err(MachineCredentialError::AlreadyExists(id.to_owned()));
        }

        let mut owned_id = String::new();
        owned_id
            .try_reserve_exact(id.len())
            .map_err(|_| MachineCredentialError::OutOfMemory)?;
        owned_id.push_str(id);
        self.credentials
            .try_reserve(1)
            .map_err(|_| MachineCredentialError::OutOfMemory)?;
        self.credentials
            .push(MachineCredential::new(owned_id, data));
        Ok(())
    }

    /// Add a credential with the given id and exact byte value.
    ///
    /// Rust slices already carry their length. Keeping a second caller-supplied
    /// size would either permit an out-of-bounds read or silently truncate the
    /// value, neither of which is a sound safe-Rust mirror of C's pointer/size
    /// contract.
    /// Returns an error if the name is invalid or already exists.
    pub fn add(&mut self, id: &str, value: &[u8]) -> Result<(), MachineCredentialError> {
        if !credential_name_valid(id) {
            return Err(MachineCredentialError::InvalidName(id.to_owned()));
        }

        if self.find(id).is_some() {
            return Err(MachineCredentialError::AlreadyExists(id.to_owned()));
        }

        let mut data = SecretBytes::try_zeroed(value.len())
            .map_err(|_| MachineCredentialError::OutOfMemory)?;
        data.as_mut_bytes().copy_from_slice(value);
        self.insert_owned(id, data)
    }

    /// Parse and set a credential from a `"id:value"` string.
    ///
    /// The value portion is C-unescaped (supporting `\n`, `\t`, `\\`, `\0`,
    /// and hex escapes `\xHH`).
    pub fn set(&mut self, cred_str: &str) -> Result<(), MachineCredentialError> {
        let (id, escaped_value) = split_credential_pair(cred_str, "set-credential")?;

        if !credential_name_valid(id) {
            return Err(MachineCredentialError::InvalidName(id.to_owned()));
        }

        let data = cunescape(escaped_value).map_err(|error| {
            if error == Errno::ENOMEM.to_neg_errno() {
                MachineCredentialError::OutOfMemory
            } else {
                MachineCredentialError::UnescapeError
            }
        })?;

        self.insert_owned(id, data)
    }

    /// Load a credential from a file path or system credentials directory.
    ///
    /// The `cred_path` string must be in `"id:source"` format where `source`
    /// is either an absolute file path or a credential name to look up in
    /// the system credentials directory (`/run/systemd/credentials/`).
    pub fn load(&mut self, cred_path: &str) -> Result<(), MachineCredentialError> {
        let (id, source) = split_credential_pair(cred_path, "load-credential")?;

        if !credential_name_valid(id) {
            return Err(MachineCredentialError::InvalidName(id.to_owned()));
        }

        let data = if looks_like_path(source) {
            let path = Path::new(source);
            if !is_path_valid(path) {
                return Err(MachineCredentialError::InvalidSource(source.to_owned()));
            }
            read_credential_path(path, true).map_err(|error| MachineCredentialError::ReadError {
                path: path.to_path_buf(),
                detail: errno_detail(error),
            })?
        } else if credential_name_valid(source) {
            let directory_path =
                get_credentials_dir().map_err(|_| MachineCredentialError::NoCredentialsDir)?;
            let diagnostic_path = directory_path.join(source);
            let directory = CredentialsDir::open_path(directory_path).map_err(|error| {
                MachineCredentialError::ReadError {
                    path: diagnostic_path.clone(),
                    detail: errno_detail(error),
                }
            })?;
            directory
                .read_name(source)
                .map_err(|error| MachineCredentialError::ReadError {
                    path: diagnostic_path,
                    detail: errno_detail(error),
                })?
        } else {
            return Err(MachineCredentialError::InvalidSource(source.to_owned()));
        };

        self.insert_owned(id, data)
    }

    /// Iterate over all credentials.
    pub fn iter(&self) -> impl Iterator<Item = &MachineCredential> {
        self.credentials.iter()
    }
}

// ── C-unescaping ───────────────────────────────────────────────────────────

/// Unescape a C-style string with the canonical basic escape policy.
///
/// Current C calls `cunescape(..., UNESCAPE_ACCEPT_NUL, ...)` here. Decode
/// directly into a fixed zeroizing owner so neither successful plaintext nor
/// a partially decoded failure ever passes through an ordinary `Vec`.
pub fn cunescape(s: &str) -> Result<SecretBytes, i32> {
    let mut result = SecretBytes::try_zeroed(s.len()).map_err(|_| Errno::ENOMEM.to_neg_errno())?;
    let written = try_cunescape_into(
        s.as_bytes(),
        &[],
        UnescapeFlags::ACCEPT_NUL,
        result.as_mut_bytes(),
    )?;
    result
        .finalize_prefix(written)
        .map_err(|error| match error {
            SecretBytesFinalizeError::InvalidLength => Errno::EIO.to_neg_errno(),
            SecretBytesFinalizeError::OutOfMemory => Errno::ENOMEM.to_neg_errno(),
        })
}

// ── Internal helpers ───────────────────────────────────────────────────────

/// Split a credential string on the first ':' into (id, value).
fn split_credential_pair<'a>(
    s: &'a str,
    param_name: &str,
) -> Result<(&'a str, &'a str), MachineCredentialError> {
    let colon = s
        .find(':')
        .ok_or_else(|| MachineCredentialError::MissingValue(param_name.to_owned()))?;

    let id = &s[..colon];
    let value = &s[colon + 1..];

    Ok((id, value))
}

/// Determine whether `source` looks like a filesystem path.
fn looks_like_path(s: &str) -> bool {
    // Current C `is_path()` is intentionally syntactic: any slash means path.
    // A dot-prefixed filename without a slash remains a credential name.
    s.contains('/')
}

fn errno_detail(error: i32) -> String {
    let errno = error
        .checked_neg()
        .filter(|errno| *errno > 0)
        .unwrap_or(Errno::EIO as i32);
    std::io::Error::from_raw_os_error(errno).to_string()
}

/// Check if a path is syntactically valid (no NUL bytes, not too long, etc.).
#[cfg(unix)]
fn is_path_valid(p: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;

    let bytes = p.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= libc::PATH_MAX as usize || bytes.contains(&0) {
        return false;
    }

    bytes
        .split(|byte| *byte == b'/')
        .all(|component| component.is_empty() || component.len() <= libc::NAME_MAX as usize)
}

#[cfg(not(unix))]
fn is_path_valid(p: &Path) -> bool {
    let Some(text) = p.to_str() else {
        return false;
    };
    !text.is_empty()
        && text.len() < libc::PATH_MAX as usize
        && !text.contains('\0')
        && text
            .split('/')
            .all(|component| component.is_empty() || component.len() <= CREDENTIAL_NAME_MAX)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_secret_bytes_borrowed_access() {
        let sv = SecretBytes::from_vec(vec![b'A', b'B', b'C']);
        assert_eq!(sv.as_bytes(), b"ABC");
        assert_eq!(sv.len(), 3);
        assert!(!sv.is_empty());
    }

    #[test]
    fn test_credential_name_valid_basic() {
        assert!(credential_name_valid("foo"));
        assert!(credential_name_valid("foo.bar_baz"));
        assert!(credential_name_valid("my-credential"));
        assert!(credential_name_valid("A"));
    }

    #[test]
    fn test_credential_name_valid_rejects_invalid() {
        assert!(!credential_name_valid(""));
        assert!(credential_name_valid(".hidden"));
        assert!(!credential_name_valid("has/slash"));
        assert!(credential_name_valid("has space"));
    }

    #[test]
    fn test_credential_name_max_length() {
        let long_name = "a".repeat(CREDENTIAL_NAME_MAX + 1);
        assert!(!credential_name_valid(&long_name));
        let ok_name = "a".repeat(CREDENTIAL_NAME_MAX);
        assert!(credential_name_valid(&ok_name));
    }

    #[test]
    fn test_context_new_empty() {
        let ctx = MachineCredentialContext::new();
        assert!(ctx.is_empty());
        assert_eq!(ctx.len(), 0);
        assert!(ctx.find("anything").is_none());
    }

    #[test]
    fn test_add_and_find() {
        let mut ctx = MachineCredentialContext::new();
        ctx.add("test_cred", b"secret_data").unwrap();
        assert_eq!(ctx.len(), 1);

        let found = ctx.find("test_cred").unwrap();
        assert_eq!(found.id, "test_cred");
        assert_eq!(found.data.as_bytes(), b"secret_data");
    }

    #[test]
    fn test_add_duplicate_rejected() {
        let mut ctx = MachineCredentialContext::new();
        ctx.add("dup", b"v1").unwrap();
        let err = ctx.add("dup", b"v2").unwrap_err();
        assert_eq!(err, MachineCredentialError::AlreadyExists("dup".to_owned()));
    }

    #[test]
    fn test_add_invalid_name_rejected() {
        let mut ctx = MachineCredentialContext::new();
        let err = ctx.add(".", b"v").unwrap_err();
        assert_eq!(err, MachineCredentialError::InvalidName(".".to_owned()));
    }

    #[test]
    fn test_add_empty_value() {
        let mut ctx = MachineCredentialContext::new();
        ctx.add("empty", b"").unwrap();
        let found = ctx.find("empty").unwrap();
        assert_eq!(found.data.len(), 0);
        assert!(found.data.is_empty());
    }

    #[test]
    fn test_add_multiple() {
        let mut ctx = MachineCredentialContext::new();
        for i in 0..10 {
            let id = format!("cred_{i}");
            let val = format!("val_{i}");
            ctx.add(&id, val.as_bytes()).unwrap();
        }
        assert_eq!(ctx.len(), 10);
        for i in 0..10 {
            let id = format!("cred_{i}");
            assert!(ctx.find(&id).is_some());
        }
    }

    #[test]
    fn test_find_nonexistent() {
        let ctx = MachineCredentialContext::new();
        assert!(ctx.find("nope").is_none());
    }

    #[test]
    fn test_set_valid() {
        let mut ctx = MachineCredentialContext::new();
        ctx.set("mykey:myvalue").unwrap();
        let found = ctx.find("mykey").unwrap();
        assert_eq!(found.data.as_bytes(), b"myvalue");
    }

    #[test]
    fn test_set_with_escapes() {
        let mut ctx = MachineCredentialContext::new();
        ctx.set("key:hello\\nworld").unwrap();
        let found = ctx.find("key").unwrap();
        assert_eq!(found.data.as_bytes(), b"hello\nworld");
    }

    #[test]
    fn test_set_hex_escape() {
        let mut ctx = MachineCredentialContext::new();
        ctx.set("key:\\x41\\x42\\x43").unwrap();
        let found = ctx.find("key").unwrap();
        assert_eq!(found.data.as_bytes(), b"ABC");
    }

    #[test]
    fn test_set_no_colon() {
        let mut ctx = MachineCredentialContext::new();
        let err = ctx.set("noequals").unwrap_err();
        assert!(matches!(err, MachineCredentialError::MissingValue(_)));
    }

    #[test]
    fn test_set_empty_value() {
        let mut ctx = MachineCredentialContext::new();
        ctx.set("key:").unwrap();
        assert!(ctx.find("key").unwrap().data.is_empty());
    }

    #[test]
    fn test_set_duplicate_rejected() {
        let mut ctx = MachineCredentialContext::new();
        ctx.set("k:v").unwrap();
        let err = ctx.set("k:v2").unwrap_err();
        assert_eq!(err, MachineCredentialError::AlreadyExists("k".to_owned()));
    }

    #[test]
    fn test_load_from_file() {
        let dir = std::env::temp_dir().join("systemd_test_creds");
        let _ = std::fs::create_dir_all(&dir);

        let file_path = dir.join("testcred");
        std::fs::write(&file_path, "file_contents").unwrap();

        let mut ctx = MachineCredentialContext::new();
        ctx.load(&format!("myid:{}", file_path.display())).unwrap();

        let found = ctx.find("myid").unwrap();
        assert_eq!(found.data.as_bytes(), b"file_contents");

        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_load_nonexistent_file() {
        let mut ctx = MachineCredentialContext::new();
        let result = ctx.load("id:/nonexistent/path/credential");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MachineCredentialError::ReadError { .. }
        ));
    }

    #[test]
    fn test_load_no_colon() {
        let mut ctx = MachineCredentialContext::new();
        let err = ctx.load("no_colon_here").unwrap_err();
        assert!(matches!(err, MachineCredentialError::MissingValue(_)));
    }

    #[test]
    fn test_load_empty_value() {
        let mut ctx = MachineCredentialContext::new();
        let err = ctx.load("key:").unwrap_err();
        assert!(matches!(err, MachineCredentialError::InvalidSource(_)));
    }

    #[test]
    fn test_cunescape_basic() {
        assert_eq!(cunescape("hello").unwrap().as_bytes(), b"hello");
        assert_eq!(
            cunescape("hello\\nworld").unwrap().as_bytes(),
            b"hello\nworld"
        );
        assert_eq!(cunescape("tab\\there").unwrap().as_bytes(), b"tab\there");
        assert_eq!(cunescape("quote\\\"").unwrap().as_bytes(), b"quote\"");
        assert_eq!(cunescape("apos\\'").unwrap().as_bytes(), b"apos'");
        assert_eq!(
            cunescape("back\\\\slash").unwrap().as_bytes(),
            b"back\\slash"
        );
        assert_eq!(cunescape("cr\\r").unwrap().as_bytes(), b"cr\r");
    }

    #[test]
    fn test_cunescape_nul() {
        assert_eq!(cunescape("nul\\0byte").unwrap().as_bytes(), b"nul\0byte");
    }

    #[test]
    fn test_cunescape_hex() {
        assert_eq!(cunescape("\\x00").unwrap().as_bytes(), &[0x00]);
        assert_eq!(cunescape("\\xff").unwrap().as_bytes(), &[0xff]);
        assert_eq!(cunescape("\\x41\\x42").unwrap().as_bytes(), b"AB");
        assert_eq!(cunescape("\\x4e").unwrap().as_bytes(), b"N");
    }

    #[test]
    fn test_cunescape_uppercase_hex() {
        assert_eq!(cunescape("\\xAB").unwrap().as_bytes(), &[0xAB]);
        assert_eq!(cunescape("\\xF0").unwrap().as_bytes(), &[0xF0]);
    }

    #[test]
    fn test_cunescape_uses_full_basic_escape_policy() {
        assert_eq!(cunescape("\\101\\102\\103").unwrap().as_bytes(), b"ABC");
        assert_eq!(cunescape("\\u20ac").unwrap().as_bytes(), "€".as_bytes());
        assert_eq!(
            cunescape("\\U0001f642").unwrap().as_bytes(),
            "🙂".as_bytes()
        );
    }

    #[test]
    fn test_cunescape_invalid() {
        // Trailing backslash
        assert!(cunescape("hello\\").is_err());
        // Invalid hex
        assert!(cunescape("\\xGG").is_err());
        // Single hex digit
        assert!(cunescape("\\xA").is_err());
        // Unknown escape
        assert!(cunescape("\\z").is_err());
    }

    #[test]
    fn test_parse_errors_do_not_retain_secret_text() {
        let mut ctx = MachineCredentialContext::new();

        let unescape = ctx.set("key:\\zdo-not-log").unwrap_err();
        assert_eq!(unescape, MachineCredentialError::UnescapeError);
        assert!(!unescape.to_string().contains("do-not-log"));

        let missing_id = ctx.set(":do-not-log").unwrap_err();
        assert!(matches!(missing_id, MachineCredentialError::InvalidName(_)));
        assert!(!missing_id.to_string().contains("do-not-log"));
    }

    #[test]
    fn test_split_credential_pair_valid() {
        let (id, val) = split_credential_pair("myid:myval", "test").unwrap();
        assert_eq!(id, "myid");
        assert_eq!(val, "myval");
    }

    #[test]
    fn test_split_credential_pair_with_colon_in_value() {
        let (id, val) = split_credential_pair("id:val:ue:extra", "test").unwrap();
        assert_eq!(id, "id");
        assert_eq!(val, "val:ue:extra");
    }

    #[test]
    fn test_split_credential_pair_no_colon() {
        let result = split_credential_pair("nocolon", "test");
        assert!(matches!(
            result,
            Err(MachineCredentialError::MissingValue(_))
        ));
    }

    #[test]
    fn test_split_credential_pair_empty_id() {
        let (id, value) = split_credential_pair(":value", "test").unwrap();
        assert_eq!(id, "");
        assert_eq!(value, "value");
    }

    #[test]
    fn test_split_credential_pair_empty_value() {
        let (id, value) = split_credential_pair("id:", "test").unwrap();
        assert_eq!(id, "id");
        assert_eq!(value, "");
    }

    #[test]
    fn test_looks_like_path() {
        assert!(looks_like_path("/abs/path"));
        assert!(looks_like_path("./rel/path"));
        assert!(looks_like_path("../parent"));
        assert!(looks_like_path("relative/path"));
        assert!(!looks_like_path("credname"));
        assert!(!looks_like_path("my-credential"));
        assert!(!looks_like_path(".hidden-credential"));
    }

    #[test]
    fn test_is_path_valid() {
        assert!(is_path_valid(Path::new("/tmp/foo")));
        assert!(is_path_valid(Path::new("/")));
        assert!(is_path_valid(Path::new("relative/path")));
        assert!(is_path_valid(Path::new("./relative//path")));
        assert!(!is_path_valid(Path::new("")));

        let oversized = format!("relative/{}", "x".repeat(libc::NAME_MAX as usize + 1));
        assert!(!is_path_valid(Path::new(&oversized)));
    }

    #[test]
    fn test_error_display_messages() {
        assert_eq!(
            MachineCredentialError::InvalidName("bad".to_owned()).to_string(),
            "Credential name is not valid: bad"
        );
        assert_eq!(
            MachineCredentialError::AlreadyExists("dup".to_owned()).to_string(),
            "Duplicated credential 'dup', refusing."
        );
        assert_eq!(
            MachineCredentialError::NotFound("x".to_owned()).to_string(),
            "Credential 'x' not found."
        );
        assert_eq!(
            MachineCredentialError::NoCredentialsDir.to_string(),
            "Credential not available (no credentials passed at all)"
        );
        assert_eq!(
            MachineCredentialError::ReadError {
                path: PathBuf::from("/run/credential"),
                detail: "permission denied".to_owned(),
            }
            .to_string(),
            "Failed to read credential '/run/credential': permission denied"
        );
    }

    #[test]
    fn test_iter_credentials() {
        let mut ctx = MachineCredentialContext::new();
        ctx.add("a", b"1").unwrap();
        ctx.add("b", b"2").unwrap();
        let ids: Vec<&str> = ctx.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[test]
    fn test_find_mut() {
        let mut ctx = MachineCredentialContext::new();
        ctx.add("x", b"old").unwrap();
        if let Some(cred) = ctx.find_mut("x") {
            cred.data = SecretBytes::from_vec(b"new".to_vec());
        }
        assert_eq!(ctx.find("x").unwrap().data.as_bytes(), b"new");
    }
}
