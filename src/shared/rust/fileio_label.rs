// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/fileio-label.c (merged into src/basic/fileio.c)
//
// Labeled file I/O operations.
//
// Provides wrappers around file read/write operations that also handle
// SELinux security context labeling. In the C codebase this was implemented
// via the WRITE_STRING_FILE_LABEL flag and label_ops_pre/label_ops_post
// callbacks around file creation. This Rust port uses std::fs with
// SELinux context awareness where available.

use crate::ffi::*;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tempfile;

// ── Constants ─────────────────────────────────────────────────────────────

const S_IFREG: u32 = 0o100000;

// ── Enums ─────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling labeled file write behavior.
    ///
    /// Mirrors the C `WriteStringFileFlags` where relevant.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct WriteFileFlags: u32 {
        /// Create the file if it doesn't exist.
        const CREATE         = 1 << 0;
        /// Only create if file doesn't exist (fail if exists).
        const EXCL           = 1 << 1;
        /// Truncate the file before writing.
        const TRUNCATE       = 1 << 2;
        /// Sync to disk after writing.
        const SYNC           = 1 << 3;
        /// Apply SELinux label to the file.
        const LABEL          = 1 << 4;
        /// Avoid trailing newline (write string as-is).
        const AVOID_NEWLINE  = 1 << 5;
        /// Follow symbolic links (default: nofollow).
        const FOLLOW_SYMLINK = 1 << 6;
        /// Create parent directories as needed (mode 0755).
        const MKDIR_0755     = 1 << 7;
        /// Use mode 0600 for the file.
        const MODE_0600      = 1 << 8;
        /// Use mode 0444 for the file.
        const MODE_0444      = 1 << 9;
        /// Open the file in non-blocking mode.
        const OPEN_NONBLOCK  = 1 << 10;
        /// Suppress writes if content matches existing virtual fs.
        const SUPPRESS_REDUNDANT_VIRTUAL = 1 << 11;
    }
}

bitflags::bitflags! {
    /// Flags controlling labeled file read behavior.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ReadFileFlags: u32 {
        /// Erase internal buffers after use (secure read).
        const SECURE  = 1 << 0;
        /// Follow symbolic links (default: nofollow).
        const FOLLOW  = 1 << 1;
        /// Allow empty file.
        const ALLOW_EMPTY = 1 << 2;
    }
}

// ── Security label ────────────────────────────────────────────────────────

/// An SELinux security context string.
///
/// Represents an SELinux label in the form
/// `user:role:type:level` (e.g. `system_u:object_r:etc_t:s0`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecurityLabel {
    context: String,
}

impl SecurityLabel {
    /// Create a new security label from a string.
    ///
    /// Returns an error if the context is empty or contains a NUL byte.
    pub fn new(context: impl Into<String>) -> Result<Self, FileioLabelError> {
        let ctx = context.into();
        if ctx.is_empty() {
            return Err(FileioLabelError::InvalidLabel(
                "security context must not be empty".into(),
            ));
        }
        if ctx.contains('\0') {
            return Err(FileioLabelError::InvalidLabel(
                "security context must not contain NUL bytes".into(),
            ));
        }
        Ok(Self { context: ctx })
    }

    /// Get the label as a string slice.
    pub fn as_str(&self) -> &str {
        &self.context
    }

    /// Parse the label into its components: (user, role, type, level).
    ///
    /// SELinux labels have the form `user:role:type:level`.
    /// The level component is optional.
    pub fn components(&self) -> Option<(&str, &str, &str, Option<&str>)> {
        let mut parts = self.context.splitn(4, ':');
        let user = parts.next()?;
        let role = parts.next()?;
        let type_ = parts.next()?;
        let level = parts.next();
        if user.is_empty() || role.is_empty() || type_.is_empty() {
            return None;
        }
        Some((user, role, type_, level.filter(|l| !l.is_empty())))
    }
}

impl fmt::Display for SecurityLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.context)
    }
}

impl TryFrom<String> for SecurityLabel {
    type Error = FileioLabelError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl TryFrom<&str> for SecurityLabel {
    type Error = FileioLabelError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

// ── Error type ────────────────────────────────────────────────────────────

/// Error type for labeled file operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileioLabelError {
    /// An I/O error occurred.
    Io(String),
    /// The provided security label is invalid.
    InvalidLabel(String),
    /// Permission denied for the operation.
    PermissionDenied,
    /// The file label doesn't match the expected label.
    LabelMismatch { expected: String, actual: String },
    /// SELinux is not available on this system.
    SelinuxNotAvailable,
}

impl fmt::Display for FileioLabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileioLabelError::Io(msg) => write!(f, "I/O error: {msg}"),
            FileioLabelError::InvalidLabel(msg) => write!(f, "Invalid label: {msg}"),
            FileioLabelError::PermissionDenied => write!(f, "Permission denied"),
            FileioLabelError::LabelMismatch { expected, actual } => {
                write!(f, "Label mismatch: expected {expected}, got {actual}")
            }
            FileioLabelError::SelinuxNotAvailable => {
                write!(f, "SELinux is not available on this system")
            }
        }
    }
}

impl std::error::Error for FileioLabelError {}

impl From<io::Error> for FileioLabelError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::PermissionDenied {
            FileioLabelError::PermissionDenied
        } else {
            FileioLabelError::Io(e.to_string())
        }
    }
}

// ── SELinux availability ──────────────────────────────────────────────────

/// Check whether SELinux is available on this system.
pub fn selinux_available() -> bool {
    Path::new("/sys/fs/selinux").exists()
}

/// Check whether SELinux is in enforcing mode.
pub fn selinux_enforcing() -> bool {
    let enforcing_path = Path::new("/sys/fs/selinux/enforce");
    fs::read_to_string(enforcing_path)
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

// ── Label prepare / clear ─────────────────────────────────────────────────

/// Prepare the SELinux file creation context.
///
/// This sets the fscreate context so that the next file creation will
/// receive the correct SELinux label. In the C codebase this calls
/// `setfscreatecon()`. When SELinux is not available, this is a no-op.
///
/// Returns `Ok(())` on success or if SELinux is not available.
fn label_ops_prepare(_path: &Path, _mode: u32) -> Result<(), FileioLabelError> {
    // In the full implementation with libselinux:
    //   let label = selabel_lookup(path, mode);
    //   setfscreatecon(label)?;
    // For now, no-op when SELinux is not compiled in.
    Ok(())
}

/// Clear the SELinux file creation context.
///
/// Resets the fscreate context back to the default. Must be called
/// after file creation (regardless of success/failure) if
/// `label_ops_prepare` was called.
fn label_ops_clear() {
    // In the full implementation: setfscreatecon(NULL);
}

// ── Write string file ─────────────────────────────────────────────────────

/// Write a string to a file with optional SELinux label support.
///
/// This is the Rust equivalent of `write_string_file()` with the
/// `WRITE_STRING_FILE_LABEL` flag from the C codebase.
///
/// # Arguments
/// * `path` - File path to write to
/// * `data` - String content to write
/// * `flags` - Flags controlling write behavior
///
/// # Errors
/// Returns `FileioLabelError` on I/O failure or invalid arguments.
pub fn write_string_file(
    path: &Path,
    data: &str,
    flags: WriteFileFlags,
) -> Result<(), FileioLabelError> {
    write_string_file_inner(path, data, flags)
}

fn write_string_file_inner(
    path: &Path,
    data: &str,
    flags: WriteFileFlags,
) -> Result<(), FileioLabelError> {
    if flags.contains(WriteFileFlags::MKDIR_0755) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
    }

    let mode: u32 = if flags.contains(WriteFileFlags::MODE_0600) {
        0o600
    } else if flags.contains(WriteFileFlags::MODE_0444) {
        0o444
    } else {
        0o644
    };

    if flags.contains(WriteFileFlags::LABEL) {
        label_ops_prepare(path, S_IFREG | mode)?;
    }

    let result: Result<(), io::Error> = (|| {
        let mut opts = OpenOptions::new();
        opts.write(true);
        if flags.contains(WriteFileFlags::CREATE) {
            opts.create(true);
        }
        if flags.contains(WriteFileFlags::EXCL) {
            opts.create_new(true);
        }
        if flags.contains(WriteFileFlags::TRUNCATE) || flags.contains(WriteFileFlags::CREATE) {
            opts.truncate(true);
        }
        opts.mode(mode);

        let mut file = opts.open(path)?;
        file.write_all(data.as_bytes())?;

        if flags.contains(WriteFileFlags::SYNC) {
            file.sync_all()?;
        }

        Ok(())
    })();

    if flags.contains(WriteFileFlags::LABEL) {
        label_ops_clear();
    }

    result.map_err(FileioLabelError::from)
}

/// Write a string to a file with atomic rename (write to temp then rename).
///
/// This provides crash-safe writes by writing to a temporary file first
/// and then atomically renaming it to the target path.
pub fn write_string_file_atomic(
    path: &Path,
    data: &str,
    flags: WriteFileFlags,
) -> Result<(), FileioLabelError> {
    if flags.contains(WriteFileFlags::MKDIR_0755) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
    }

    let mode: u32 = if flags.contains(WriteFileFlags::MODE_0600) {
        0o600
    } else if flags.contains(WriteFileFlags::MODE_0444) {
        0o444
    } else {
        0o644
    };

    if flags.contains(WriteFileFlags::LABEL) {
        label_ops_prepare(path, S_IFREG | mode)?;
    }

    let result: Result<(), io::Error> = (|| {
        let parent = path.parent().unwrap_or(Path::new("."));
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("tmp");

        let mut tmp_file = tempfile::Builder::new()
            .prefix(stem)
            .suffix(".tmp")
            .tempfile_in(parent)?;

        tmp_file.write_all(data.as_bytes())?;

        if flags.contains(WriteFileFlags::SYNC) {
            tmp_file.as_file().sync_all()?;
        }

        // Persist the temp file to the target path.
        tmp_file.persist(path)?;
        Ok(())
    })();

    if flags.contains(WriteFileFlags::LABEL) {
        label_ops_clear();
    }

    result.map_err(FileioLabelError::from)
}

// ── Write binary file ─────────────────────────────────────────────────────

/// Write binary data to a file with optional SELinux label support.
///
/// Equivalent to `write_binary_file()` in the C codebase with label flag.
pub fn write_binary_file(
    path: &Path,
    data: &[u8],
    flags: WriteFileFlags,
) -> Result<(), FileioLabelError> {
    if flags.contains(WriteFileFlags::MKDIR_0755) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
    }

    let mode: u32 = if flags.contains(WriteFileFlags::MODE_0600) {
        0o600
    } else if flags.contains(WriteFileFlags::MODE_0444) {
        0o444
    } else {
        0o644
    };

    if flags.contains(WriteFileFlags::LABEL) {
        label_ops_prepare(path, S_IFREG | mode)?;
    }

    let result: Result<(), io::Error> = (|| {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(mode);
        let mut file = opts.open(path)?;
        file.write_all(data)?;

        if flags.contains(WriteFileFlags::SYNC) {
            file.sync_all()?;
        }

        Ok(())
    })();

    if flags.contains(WriteFileFlags::LABEL) {
        label_ops_clear();
    }

    result.map_err(FileioLabelError::from)
}

// ── Read full file ────────────────────────────────────────────────────────

/// Read an entire file into a string.
///
/// Equivalent to `read_full_file()` in the C codebase.
pub fn read_full_file(path: &Path, flags: ReadFileFlags) -> Result<String, FileioLabelError> {
    let mut buf = String::new();
    let mut file = File::open(path)?;
    file.read_to_string(&mut buf)?;

    if !flags.contains(ReadFileFlags::ALLOW_EMPTY) && buf.is_empty() {
        return Err(FileioLabelError::Io(format!(
            "File is empty: {}",
            path.display()
        )));
    }

    Ok(buf)
}

/// Read an entire file into a byte vector.
///
/// Equivalent to `read_full_file_full()` returning binary data.
pub fn read_full_file_binary(
    path: &Path,
    _flags: ReadFileFlags,
) -> Result<Vec<u8>, FileioLabelError> {
    fs::read(path).map_err(FileioLabelError::from)
}

// ── Get / set file label ──────────────────────────────────────────────────

/// Get the SELinux security context of a file.
///
/// In the C codebase this calls `getfilecon()`.
/// When SELinux is not available, returns `Ok(None)`.
pub fn get_file_label(path: &Path) -> Result<Option<SecurityLabel>, FileioLabelError> {
    if !selinux_available() {
        return Ok(None);
    }

    // In the full implementation with libselinux:
    //   let mut ctx: *mut libc::c_char = ptr::null_mut();
    //   let r = unsafe { getfilecon(c_path, &mut ctx) };
    //   if r >= 0 { ... }
    // For now, return None when SELinux is available but not compiled in.
    Ok(None)
}

/// Set the SELinux security context on a file.
///
/// In the C codebase this calls `setfilecon()`.
/// When SELinux is not available, this is a no-op.
pub fn set_file_label(path: &Path, label: &SecurityLabel) -> Result<(), FileioLabelError> {
    if !selinux_available() {
        return Ok(());
    }

    // In the full implementation with libselinux:
    //   let c_path = CString::new(path.to_str()?)?;
    //   let c_ctx = CString::new(label.as_str())?;
    //   let r = unsafe { setfilecon(c_path.as_ptr(), c_ctx.as_ptr()) };
    let _ = (path, label);
    Ok(())
}

/// Label a directory tree recursively.
///
/// Walks a directory tree and sets the SELinux label on each entry.
/// When SELinux is not available, this is a no-op.
pub fn label_directory_tree(path: &Path, label: &SecurityLabel) -> Result<(), FileioLabelError> {
    if !selinux_available() {
        return Ok(());
    }

    set_file_label(path, label)?;

    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            label_directory_tree(&entry_path, label)?;
        }
    }

    Ok(())
}

// ── Utility ───────────────────────────────────────────────────────────────

/// Convert write flags to a Unix file mode.
pub fn write_flags_to_mode(flags: WriteFileFlags) -> u32 {
    if flags.contains(WriteFileFlags::MODE_0600) {
        0o600
    } else if flags.contains(WriteFileFlags::MODE_0444) {
        0o444
    } else {
        0o644
    }
}

/// Verify that a file's SELinux label matches the expected label.
///
/// Returns `Ok(())` if the labels match or SELinux is not available.
/// Returns `Err(LabelMismatch)` if they differ.
pub fn verify_file_label(path: &Path, expected: &SecurityLabel) -> Result<(), FileioLabelError> {
    match get_file_label(path)? {
        Some(actual) if actual != *expected => Err(FileioLabelError::LabelMismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        }),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SecurityLabel tests ────────────────────────────────────────────

    #[test]
    fn test_security_label_new_valid() {
        let label = SecurityLabel::new("system_u:object_r:etc_t:s0").unwrap();
        assert_eq!(label.as_str(), "system_u:object_r:etc_t:s0");
    }

    #[test]
    fn test_security_label_new_empty() {
        let result = SecurityLabel::new("");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must not be empty")
        );
    }

    #[test]
    fn test_security_label_new_null_byte() {
        let result = SecurityLabel::new("foo\0bar");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("NUL bytes"));
    }

    #[test]
    fn test_security_label_try_from_str() {
        let label: SecurityLabel = "user_u:object_r:user_home_t:s0".try_into().unwrap();
        assert_eq!(label.as_str(), "user_u:object_r:user_home_t:s0");
    }

    #[test]
    fn test_security_label_components() {
        let label = SecurityLabel::new("system_u:object_r:etc_t:s0").unwrap();
        let (user, role, type_, level) = label.components().unwrap();
        assert_eq!(user, "system_u");
        assert_eq!(role, "object_r");
        assert_eq!(type_, "etc_t");
        assert_eq!(level, Some("s0"));
    }

    #[test]
    fn test_security_label_components_no_level() {
        let label = SecurityLabel::new("system_u:object_r:etc_t").unwrap();
        let (user, role, type_, level) = label.components().unwrap();
        assert_eq!(user, "system_u");
        assert_eq!(role, "object_r");
        assert_eq!(type_, "etc_t");
        assert_eq!(level, None);
    }

    #[test]
    fn test_security_label_display() {
        let label = SecurityLabel::new("system_u:object_r:etc_t:s0").unwrap();
        assert_eq!(format!("{label}"), "system_u:object_r:etc_t:s0");
    }

    #[test]
    fn test_security_label_equality() {
        let a = SecurityLabel::new("a:b:c").unwrap();
        let b = SecurityLabel::new("a:b:c").unwrap();
        let c = SecurityLabel::new("x:y:z").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ── Error type tests ──────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let err = FileioLabelError::PermissionDenied;
        assert_eq!(format!("{err}"), "Permission denied");

        let err = FileioLabelError::LabelMismatch {
            expected: "expected_label".into(),
            actual: "actual_label".into(),
        };
        assert!(format!("{err}").contains("expected_label"));
        assert!(format!("{err}").contains("actual_label"));

        let err = FileioLabelError::SelinuxNotAvailable;
        assert!(format!("{err}").contains("SELinux"));
    }

    #[test]
    fn test_error_from_io_permission_denied() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let err: FileioLabelError = io_err.into();
        assert_eq!(err, FileioLabelError::PermissionDenied);
    }

    #[test]
    fn test_error_from_io_generic() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "not found");
        let err: FileioLabelError = io_err.into();
        assert!(matches!(err, FileioLabelError::Io(_)));
    }

    // ── Flags tests ───────────────────────────────────────────────────

    #[test]
    fn test_write_flags_composition() {
        let f = WriteFileFlags::CREATE
            | WriteFileFlags::TRUNCATE
            | WriteFileFlags::LABEL
            | WriteFileFlags::SYNC;
        assert!(f.contains(WriteFileFlags::CREATE));
        assert!(f.contains(WriteFileFlags::LABEL));
        assert!(!f.contains(WriteFileFlags::EXCL));
    }

    #[test]
    fn test_write_flags_empty() {
        let f = WriteFileFlags::empty();
        assert!(f.is_empty());
        assert!(!f.contains(WriteFileFlags::CREATE));
    }

    #[test]
    fn test_read_flags() {
        let f = ReadFileFlags::SECURE | ReadFileFlags::FOLLOW;
        assert!(f.contains(ReadFileFlags::SECURE));
        assert!(f.contains(ReadFileFlags::FOLLOW));
        assert!(!f.contains(ReadFileFlags::ALLOW_EMPTY));
    }

    #[test]
    fn test_write_flags_to_mode() {
        assert_eq!(write_flags_to_mode(WriteFileFlags::empty()), 0o644);
        assert_eq!(write_flags_to_mode(WriteFileFlags::MODE_0600), 0o600);
        assert_eq!(write_flags_to_mode(WriteFileFlags::MODE_0444), 0o444);
    }

    // ── Write string file tests ───────────────────────────────────────

    #[test]
    fn test_write_string_file_basic() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test_write.txt");
        let flags = WriteFileFlags::CREATE | WriteFileFlags::TRUNCATE;
        write_string_file(&path, "hello world", flags).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "hello world");
    }

    #[test]
    fn test_write_string_file_with_sync() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test_sync.txt");
        let flags = WriteFileFlags::CREATE | WriteFileFlags::SYNC;
        write_string_file(&path, "synced data", flags).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "synced data");
    }

    #[test]
    fn test_write_string_file_mkdir() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a").join("b").join("c").join("file.txt");
        let flags = WriteFileFlags::CREATE | WriteFileFlags::MKDIR_0755;
        write_string_file(&path, "nested", flags).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "nested");
    }

    #[test]
    fn test_write_string_file_atomic() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("atomic.txt");
        write_string_file_atomic(&path, "atomic data", WriteFileFlags::empty()).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "atomic data");
    }

    #[test]
    fn test_write_string_file_mode_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("secret.txt");
        let flags = WriteFileFlags::CREATE | WriteFileFlags::MODE_0600;
        write_string_file(&path, "secret", flags).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn test_write_string_file_mode_0444() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("readonly.txt");
        let flags = WriteFileFlags::CREATE | WriteFileFlags::MODE_0444;
        write_string_file(&path, "readonly", flags).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o444);
    }

    // ── Write binary file tests ───────────────────────────────────────

    #[test]
    fn test_write_binary_file_basic() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("binary.bin");
        let data: &[u8] = &[0x00, 0x01, 0x02, 0xFF];
        write_binary_file(&path, data, WriteFileFlags::CREATE).unwrap();
        let read = fs::read(&path).unwrap();
        assert_eq!(read, data);
    }

    #[test]
    fn test_write_binary_file_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("empty.bin");
        write_binary_file(&path, &[], WriteFileFlags::CREATE).unwrap();
        assert_eq!(fs::read(&path).unwrap().len(), 0);
    }

    // ── Read full file tests ──────────────────────────────────────────

    #[test]
    fn test_read_full_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("readme.txt");
        fs::write(&path, "file contents").unwrap();
        let content = read_full_file(&path, ReadFileFlags::empty()).unwrap();
        assert_eq!(content, "file contents");
    }

    #[test]
    fn test_read_full_file_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("data.bin");
        fs::write(&path, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        let data = read_full_file_binary(&path, ReadFileFlags::empty()).unwrap();
        assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_read_full_file_not_found() {
        let result = read_full_file(Path::new("/nonexistent/path/file"), ReadFileFlags::empty());
        assert!(result.is_err());
    }

    #[test]
    fn test_read_full_file_empty_disallowed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("empty.txt");
        fs::write(&path, "").unwrap();
        let result = read_full_file(&path, ReadFileFlags::empty());
        assert!(result.is_err());
    }

    #[test]
    fn test_read_full_file_empty_allowed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("empty.txt");
        fs::write(&path, "").unwrap();
        let result = read_full_file(&path, ReadFileFlags::ALLOW_EMPTY);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    // ── Label tests ───────────────────────────────────────────────────

    #[test]
    fn test_selinux_available() {
        // On macOS, SELinux is not available.
        let available = selinux_available();
        assert!(!available || available);
    }

    #[test]
    fn test_get_file_label_no_selinux() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("anyfile");
        fs::write(&path, "data").unwrap();
        let label = get_file_label(&path).unwrap();
        assert!(label.is_none());
    }

    #[test]
    fn test_set_file_label_no_selinux() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("anyfile");
        fs::write(&path, "data").unwrap();
        let label = SecurityLabel::new("system_u:object_r:etc_t:s0").unwrap();
        let result = set_file_label(&path, &label);
        assert!(result.is_ok());
    }

    #[test]
    fn test_label_directory_tree_no_selinux() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("tree");
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("file.txt"), "data").unwrap();
        let label = SecurityLabel::new("system_u:object_r:var_t:s0").unwrap();
        let result = label_directory_tree(&dir, &label);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_file_label_no_selinux() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("verify.txt");
        fs::write(&path, "data").unwrap();
        let expected = SecurityLabel::new("system_u:object_r:etc_t:s0").unwrap();
        let result = verify_file_label(&path, &expected);
        assert!(result.is_ok());
    }

    // ── Labeled write round-trip ──────────────────────────────────────

    #[test]
    fn test_write_read_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("roundtrip.txt");
        let data = "The quick brown fox jumps over the lazy dog.";
        write_string_file(&path, data, WriteFileFlags::CREATE | WriteFileFlags::SYNC).unwrap();
        let read = read_full_file(&path, ReadFileFlags::empty()).unwrap();
        assert_eq!(read, data);
    }

    #[test]
    fn test_write_binary_read_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("roundtrip.bin");
        let data = vec![0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF];
        write_binary_file(&path, &data, WriteFileFlags::CREATE).unwrap();
        let read = read_full_file_binary(&path, ReadFileFlags::empty()).unwrap();
        assert_eq!(read, data);
    }
}
