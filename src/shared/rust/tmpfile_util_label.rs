// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/tmpfile-util.c, src/shared/tmpfile-util.h
//
// SELinux-aware temporary file creation utilities.
//
// These functions wrap tmpfile-util with SELinux label preparation.
// They are split out to optimize linking: callers that need SELinux
// can link against these, others don't need -lselinux.
//
// Faithfully mirrors the C implementation:
//   fopen_temporary_at_label()  →  fopen_temporary_at_label()
//   fopen_temporary_label()     →  fopen_temporary_label()
// with proper RAII cleanup of the SELinux context via PrepareGuard.

use crate::ffi::*;
use std::error::Error;
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::label_util::FileMode;
use crate::selinux_util::{
    AT_FDCWD, ContextError, mac_selinux_create_file_clear, mac_selinux_create_file_prepare,
};

// ── Constants ─────────────────────────────────────────────────────────────

/// Hidden prefix for temporary filenames (mirrors C `.#` convention).
const HIDDEN_TMP_PREFIX: &[u8] = b".#";

/// Length of the random hex suffix appended to temp filenames.
const RANDOM_SUFFIX_LEN: usize = 16;

/// Maximum filename length in bytes on Linux.
const NAME_MAX_BYTES: usize = 255;

/// openat(2) flags: CLOEXEC, no TTY assignment, read-write, create, exclusive.
const OPEN_FLAGS: i32 =
    libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_RDWR | libc::O_CREAT | libc::O_EXCL;

/// Permission mode for temporary files: owner read/write only.
const TEMP_MODE: libc::mode_t = 0o600;

// ── Error types ──────────────────────────────────────────────────────────

/// Errors that can occur during SELinux-labeled temporary file creation.
#[derive(Debug)]
pub enum TempFileLabelError {
    /// An invalid argument was provided (e.g. null path, bad dir_fd).
    InvalidArgument(&'static str),
    /// An I/O error occurred during file creation.
    Io(io::Error),
    /// An SELinux context error occurred.
    Selinux(ContextError),
}

impl fmt::Display for TempFileLabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::Io(err) => err.fmt(f),
            Self::Selinux(err) => err.fmt(f),
        }
    }
}

impl Error for TempFileLabelError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidArgument(_) => None,
            Self::Io(err) => Some(err),
            Self::Selinux(err) => Some(err),
        }
    }
}

impl From<io::Error> for TempFileLabelError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ContextError> for TempFileLabelError {
    fn from(value: ContextError) -> Self {
        Self::Selinux(value)
    }
}

// ── TemporaryFile ────────────────────────────────────────────────────────

/// A temporary file with its on-disk path.
///
/// Holds both the open [`File`] handle and the [`PathBuf`] to the
/// temporary file. When dropped, the file is NOT automatically deleted —
/// callers should unlink or rename as appropriate (matching C behavior
/// where the caller manages the lifetime via `unlink_tempfilep`).
#[derive(Debug)]
pub struct TemporaryFile {
    file: File,
    temp_path: PathBuf,
}

impl TemporaryFile {
    /// Create a new `TemporaryFile` from an open file and its path.
    pub fn new(file: File, temp_path: PathBuf) -> Self {
        Self { file, temp_path }
    }

    /// Access the underlying file handle.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Access the temporary file's path on disk.
    pub fn temp_path(&self) -> &Path {
        &self.temp_path
    }

    /// Consume and return both the file and path.
    pub fn into_parts(self) -> (File, PathBuf) {
        (self.file, self.temp_path)
    }

    /// Get the raw file descriptor.
    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

// ── Backend trait ────────────────────────────────────────────────────────

/// Trait for pluggable SELinux labeling backends.
///
/// Allows injecting mock or alternative labeling strategies for testing
/// or environments without SELinux.
pub trait TempFileLabelBackend {
    /// Prepare the SELinux file creation context for the given target path.
    fn prepare_file_at(
        &self,
        dir_fd: RawFd,
        target: Option<&Path>,
        mode: FileMode,
    ) -> Result<(), TempFileLabelError>;

    /// Clear the SELinux file creation context.
    fn clear_file(&self);
}

/// The system SELinux backend using real libselinux calls.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemTempFileLabelBackend;

impl TempFileLabelBackend for SystemTempFileLabelBackend {
    fn prepare_file_at(
        &self,
        dir_fd: RawFd,
        target: Option<&Path>,
        mode: FileMode,
    ) -> Result<(), TempFileLabelError> {
        let Some(target) = target else {
            return Ok(());
        };

        let resolved = resolve_target_path(dir_fd, target)?;
        let target_str = resolved
            .to_str()
            .ok_or(TempFileLabelError::InvalidArgument(
                "target path is not valid UTF-8",
            ))?;

        mac_selinux_create_file_prepare(target_str, mode.as_raw()).map_err(Into::into)
    }

    fn clear_file(&self) {
        mac_selinux_create_file_clear();
    }
}

// ── RAII guard ───────────────────────────────────────────────────────────

/// RAII guard that ensures the SELinux file-creation context is cleared
/// when it goes out of scope, even if the operation between prepare and
/// clear panics.
///
/// This mirrors the C pattern of calling `mac_selinux_create_file_prepare_at()`
/// followed by `mac_selinux_create_file_clear()`, but in an unwind-safe way.
struct PrepareGuard<'a, B: TempFileLabelBackend + ?Sized> {
    backend: &'a B,
}

impl<'a, B: TempFileLabelBackend + ?Sized> PrepareGuard<'a, B> {
    fn new(backend: &'a B) -> Self {
        Self { backend }
    }
}

impl<B: TempFileLabelBackend + ?Sized> Drop for PrepareGuard<'_, B> {
    fn drop(&mut self) {
        self.backend.clear_file();
    }
}

// ── Public API ───────────────────────────────────────────────────────────

/// Create a temporary file with SELinux label preparation at a given
/// directory file descriptor.
///
/// This is the Rust equivalent of `fopen_temporary_at_label()` from
/// `src/shared/tmpfile-util-label.c`.
///
/// The function:
/// 1. Prepares the SELinux file creation context for `target` with
///    mode `S_IFREG` (regular file).
/// 2. Creates a temporary file via `fopen_temporary_at()`.
/// 3. Clears the SELinux file creation context (regardless of success
///    or failure of step 2).
///
/// # Arguments
///
/// * `dir_fd` - Directory file descriptor, or `AT_FDCWD` for the current
///   working directory.
/// * `target` - The path whose SELinux context to use for the new file.
///   Pass `None` if no specific SELinux context is needed.
/// * `path` - The base path for the temporary file. The temporary file
///   will be created in the same directory with a random hidden name.
pub fn fopen_temporary_at_label(
    dir_fd: RawFd,
    target: Option<&Path>,
    path: &Path,
) -> Result<TemporaryFile, TempFileLabelError> {
    fopen_temporary_at_label_with(dir_fd, target, path, &SystemTempFileLabelBackend)
}

/// Create a temporary file with SELinux label preparation relative to
/// the current working directory.
///
/// This is the Rust equivalent of the C inline `fopen_temporary_label()`.
/// It is a convenience wrapper that passes `AT_FDCWD`.
///
/// See [`fopen_temporary_at_label`] for full documentation.
pub fn fopen_temporary_label(
    target: Option<&Path>,
    path: &Path,
) -> Result<TemporaryFile, TempFileLabelError> {
    fopen_temporary_at_label(AT_FDCWD, target, path)
}

/// Create a temporary file with SELinux labeling using a custom backend.
///
/// This is the most flexible entry point, allowing callers to inject
/// their own labeling strategy. The guard pattern ensures `clear_file()`
/// is always called after `prepare_file_at()`, mirroring the C behavior
/// of calling `mac_selinux_create_file_clear()` regardless of whether
/// `fopen_temporary_at()` succeeds.
pub fn fopen_temporary_at_label_with<B: TempFileLabelBackend + ?Sized>(
    dir_fd: RawFd,
    target: Option<&Path>,
    path: &Path,
    backend: &B,
) -> Result<TemporaryFile, TempFileLabelError> {
    validate_dir_fd(dir_fd)?;
    validate_requested_path(path)?;

    backend.prepare_file_at(dir_fd, target, FileMode::Regular)?;
    let _guard = PrepareGuard::new(backend);

    fopen_temporary_at(dir_fd, path)
}

/// Create a temporary file with SELinux labeling using a custom backend,
/// relative to the current working directory.
pub fn fopen_temporary_label_with<B: TempFileLabelBackend + ?Sized>(
    target: Option<&Path>,
    path: &Path,
    backend: &B,
) -> Result<TemporaryFile, TempFileLabelError> {
    fopen_temporary_at_label_with(AT_FDCWD, target, path, backend)
}

// ── Internal: core temporary file creation ───────────────────────────────

/// Create a temporary file at a given directory file descriptor.
///
/// This is the Rust equivalent of `fopen_temporary_at()` from
/// `src/basic/tmpfile-util.c`. It generates a random hidden filename
/// in the same directory as `path`, opens it with `O_CLOEXEC | O_NOCTTY
/// | O_RDWR | O_CREAT | O_EXCL` and mode `0600`.
fn fopen_temporary_at(dir_fd: RawFd, path: &Path) -> Result<TemporaryFile, TempFileLabelError> {
    let temp_path = tempfn_random(path)?;
    let file = fopen_temporary_internal(dir_fd, &temp_path)?;
    Ok(TemporaryFile::new(file, temp_path))
}

/// Low-level file creation via `openat(2)`.
///
/// # Safety
///
/// Uses `libc::openat` which is a POSIX syscall. The file descriptor
/// returned by openat is assumed valid (checked for < 0).
fn fopen_temporary_internal(dir_fd: RawFd, path: &Path) -> Result<File, TempFileLabelError> {
    let c_path = path_to_cstring(path)?;

    // SAFETY: openat(2) is a POSIX syscall. c_path is a valid NUL-terminated
    // string. dir_fd is validated by the caller.
    let fd = unsafe { libc::openat(dir_fd, c_path.as_ptr(), OPEN_FLAGS, TEMP_MODE as u32) };

    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }

    // SAFETY: fd is valid (just returned by openat, checked > 0).
    let file = unsafe { File::from_raw_fd(fd) };

    Ok(file)
}

// ── Path helpers ─────────────────────────────────────────────────────────

/// Generate a random temporary filename from a base path.
///
/// Mirrors the C `tempfn_random()` function: given a path like
/// `/etc/hostname`, produces a hidden temporary name like
/// `/etc/.#hostname<16 hex chars>`.
fn tempfn_random(path: &Path) -> Result<PathBuf, TempFileLabelError> {
    validate_requested_path(path)?;

    let file_name = path.file_name().ok_or(TempFileLabelError::InvalidArgument(
        "path must include a final filename component",
    ))?;

    let mut file_name_bytes = file_name.as_bytes().to_vec();

    // Truncate if the resulting name would exceed NAME_MAX_BYTES
    let max_name_len = NAME_MAX_BYTES - HIDDEN_TMP_PREFIX.len() - RANDOM_SUFFIX_LEN;
    if file_name_bytes.len() > max_name_len {
        file_name_bytes.truncate(max_name_len);
    }

    let mut mangled =
        Vec::with_capacity(HIDDEN_TMP_PREFIX.len() + file_name_bytes.len() + RANDOM_SUFFIX_LEN);
    mangled.extend_from_slice(HIDDEN_TMP_PREFIX);
    mangled.extend_from_slice(&file_name_bytes);
    mangled.extend_from_slice(random_hex_suffix()?.as_bytes());

    let mangled_name = std::ffi::OsString::from_vec(mangled);
    let temp_path = match path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => parent.join(mangled_name),
        None => PathBuf::from(mangled_name),
    };

    Ok(temp_path)
}

/// Resolve a potentially relative target path against a directory fd.
///
/// If `target` is absolute or `dir_fd` is `AT_FDCWD`, returns the target
/// as-is. Otherwise, resolves via `/proc/self/fd/{dir_fd}`.
fn resolve_target_path(dir_fd: RawFd, target: &Path) -> Result<PathBuf, TempFileLabelError> {
    if target.is_absolute() || dir_fd == AT_FDCWD {
        return Ok(target.to_path_buf());
    }

    let proc_fd_path = PathBuf::from(format!("/proc/self/fd/{dir_fd}"));
    let directory = std::fs::read_link(proc_fd_path)?;
    Ok(directory.join(target))
}

/// Validate that a directory file descriptor is valid or `AT_FDCWD`.
///
/// Mirrors the C assertion: `assert(dir_fd >= 0 || dir_fd == AT_FDCWD)`.
fn validate_dir_fd(dir_fd: RawFd) -> Result<(), TempFileLabelError> {
    if dir_fd >= 0 || dir_fd == AT_FDCWD {
        Ok(())
    } else {
        Err(TempFileLabelError::InvalidArgument(
            "dir_fd must be a valid descriptor or AT_FDCWD",
        ))
    }
}

/// Validate that a requested path is non-empty and has a filename component.
///
/// Mirrors the C assertion: `assert(path)`.
fn validate_requested_path(path: &Path) -> Result<(), TempFileLabelError> {
    if path.as_os_str().is_empty() {
        return Err(TempFileLabelError::InvalidArgument(
            "path must not be empty",
        ));
    }

    // A trailing '/' means the path is directory-only (e.g. "/tmp/") even
    // though Rust's Path::file_name() normalises the slash away.
    let bytes = path.as_os_str().as_bytes();
    if bytes.last() == Some(&b'/') {
        return Err(TempFileLabelError::InvalidArgument(
            "path must include a final filename component",
        ));
    }

    if path.file_name().is_none() {
        return Err(TempFileLabelError::InvalidArgument(
            "path must include a final filename component",
        ));
    }

    Ok(())
}

/// Convert a Rust path to a NUL-terminated C string.
fn path_to_cstring(path: &Path) -> Result<CString, TempFileLabelError> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| TempFileLabelError::InvalidArgument("path contains an interior NUL byte"))
}

/// Generate a 16-character random hex suffix from `/dev/urandom`.
fn random_hex_suffix() -> Result<String, TempFileLabelError> {
    let mut bytes = [0u8; 8];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(format!("{:016x}", u64::from_ne_bytes(bytes)))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::{Cell, RefCell};
    use std::fs::OpenOptions;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    use tempfile::tempdir;

    // ── Mock backend for testing ──────────────────────────────────────

    /// A mock backend that records calls and can inject failures.
    #[derive(Debug, Default)]
    struct MockBackend {
        prepare_calls: RefCell<Vec<(RawFd, Option<PathBuf>, FileMode)>>,
        prepare_error: RefCell<Option<TempFileLabelError>>,
        clear_calls: Cell<usize>,
    }

    impl MockBackend {
        fn clear_count(&self) -> usize {
            self.clear_calls.get()
        }
    }

    impl TempFileLabelBackend for MockBackend {
        fn prepare_file_at(
            &self,
            dir_fd: RawFd,
            target: Option<&Path>,
            mode: FileMode,
        ) -> Result<(), TempFileLabelError> {
            self.prepare_calls
                .borrow_mut()
                .push((dir_fd, target.map(Path::to_path_buf), mode));

            if let Some(err) = self.prepare_error.borrow_mut().take() {
                return Err(err);
            }

            Ok(())
        }

        fn clear_file(&self) {
            self.clear_calls.set(self.clear_calls.get() + 1);
        }
    }

    // ── Constant validation ───────────────────────────────────────────

    #[test]
    fn test_constants_hidden_prefix() {
        assert_eq!(HIDDEN_TMP_PREFIX, b".#");
    }

    #[test]
    fn test_constants_random_suffix_length() {
        assert_eq!(RANDOM_SUFFIX_LEN, 16);
    }

    #[test]
    fn test_constants_name_max() {
        assert_eq!(NAME_MAX_BYTES, 255);
    }

    #[test]
    fn test_constants_temp_mode() {
        assert_eq!(TEMP_MODE, 0o600);
    }

    #[test]
    fn test_constants_open_flags_nonzero() {
        assert_ne!(OPEN_FLAGS, 0);
    }

    // ── Validation ────────────────────────────────────────────────────

    #[test]
    fn test_validate_dir_fd_valid() {
        assert!(validate_dir_fd(AT_FDCWD).is_ok());
        assert!(validate_dir_fd(0).is_ok());
        assert!(validate_dir_fd(42).is_ok());
    }

    #[test]
    fn test_validate_dir_fd_invalid() {
        assert!(validate_dir_fd(-1).is_err());
        assert!(validate_dir_fd(-2).is_err());
        assert!(validate_dir_fd(-999).is_err());
    }

    #[test]
    fn test_validate_requested_path_valid() {
        assert!(validate_requested_path(Path::new("file.txt")).is_ok());
        assert!(validate_requested_path(Path::new("/tmp/file.txt")).is_ok());
        assert!(validate_requested_path(Path::new("dir/file")).is_ok());
    }

    #[test]
    fn test_validate_requested_path_empty() {
        let err = validate_requested_path(Path::new("")).unwrap_err();
        assert!(matches!(err, TempFileLabelError::InvalidArgument(_)));
    }

    #[test]
    fn test_validate_requested_path_directory_only() {
        let err = validate_requested_path(Path::new("/tmp/")).unwrap_err();
        assert!(matches!(err, TempFileLabelError::InvalidArgument(_)));
    }

    // ── Path helpers ──────────────────────────────────────────────────

    #[test]
    fn test_path_to_cstring_valid() {
        let cstr = path_to_cstring(Path::new("/tmp/test.txt")).unwrap();
        assert_eq!(cstr.to_str().unwrap(), "/tmp/test.txt");
    }

    #[test]
    fn test_path_to_cstring_with_nul() {
        let bad = PathBuf::from(std::ffi::OsString::from_vec(b"bad\0name".to_vec()));
        assert!(path_to_cstring(&bad).is_err());
    }

    #[test]
    fn test_resolve_target_path_absolute() {
        let path = Path::new("/tmp/absolute-target");
        assert_eq!(resolve_target_path(AT_FDCWD, path).unwrap(), path);
        assert_eq!(resolve_target_path(42, path).unwrap(), path);
    }

    // ── tempfn_random ─────────────────────────────────────────────────

    #[test]
    fn test_tempfn_random_uses_hidden_prefix_and_hex_suffix() {
        let temp_path = tempfn_random(Path::new("waldo")).unwrap();
        let name = temp_path.file_name().unwrap().to_str().unwrap();

        assert!(name.starts_with(".#waldo"));
        assert_eq!(name.len(), 2 + "waldo".len() + RANDOM_SUFFIX_LEN);
        assert!(
            name[2 + "waldo".len()..]
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );
    }

    #[test]
    fn test_tempfn_random_preserves_parent_directory() {
        let temp_path = tempfn_random(Path::new("/tmp/example")).unwrap();
        assert_eq!(temp_path.parent(), Some(Path::new("/tmp")));
    }

    #[test]
    fn test_tempfn_random_truncates_long_file_names_to_name_max() {
        let long_name = "x".repeat(400);
        let temp_path = tempfn_random(Path::new(&long_name)).unwrap();
        let name_len = temp_path.file_name().unwrap().as_bytes().len();

        assert_eq!(name_len, NAME_MAX_BYTES);
    }

    #[test]
    fn test_tempfn_random_rejects_directory_only_path() {
        let err = tempfn_random(Path::new("/tmp/")).unwrap_err();
        assert!(matches!(err, TempFileLabelError::InvalidArgument(_)));
    }

    #[test]
    fn test_tempfn_random_rejects_empty_path() {
        let err = tempfn_random(Path::new("")).unwrap_err();
        assert!(matches!(err, TempFileLabelError::InvalidArgument(_)));
    }

    #[test]
    fn test_temp_path_file_name_matches_expected_shape_for_relative_dirfd_case() {
        let temporary = tempfn_random(Path::new("child")).unwrap();
        let name = temporary.file_name().unwrap().to_str().unwrap();

        assert!(name.starts_with(".#child"));
        assert_eq!(name.len(), 2 + "child".len() + RANDOM_SUFFIX_LEN);
    }

    // ── TemporaryFile struct ──────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_temporary_file_new_and_accessors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("accessor_test");
        let file = File::create(&path).unwrap();
        let tf = TemporaryFile::new(file, path.clone());

        assert_eq!(tf.temp_path(), path.as_path());
        assert!(tf.as_raw_fd() >= 0);
        assert!(tf.file().metadata().unwrap().is_file());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_temporary_file_into_parts() {
        let dir = tempdir().unwrap();
        let requested = dir.path().join("parts");
        let temporary = fopen_temporary_label(None, &requested).unwrap();

        let (file, path) = temporary.into_parts();
        let metadata = file.metadata().unwrap();

        assert!(metadata.is_file());
        assert!(path.exists());
    }

    // ── Error types ───────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let e = TempFileLabelError::InvalidArgument("bad arg");
        assert_eq!(format!("{e}"), "invalid argument: bad arg");

        let e = TempFileLabelError::InvalidArgument("path contains an interior NUL byte");
        assert!(format!("{e}").contains("NUL"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "not found");
        let e: TempFileLabelError = io_err.into();
        assert!(matches!(e, TempFileLabelError::Io(_)));
    }

    #[test]
    fn test_error_from_selinux() {
        let se = ContextError::EmptyContext;
        let e: TempFileLabelError = se.into();
        assert!(matches!(e, TempFileLabelError::Selinux(_)));
    }

    #[test]
    fn test_error_source_chain() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let e = TempFileLabelError::Io(io_err);
        assert!(e.source().is_some());

        let e2 = TempFileLabelError::InvalidArgument("test");
        assert!(e2.source().is_none());
    }

    // ── fopen_temporary_at_label: validation errors ───────────────────

    #[test]
    fn test_fopen_temporary_at_label_empty_path() {
        let err = fopen_temporary_at_label(AT_FDCWD, None, Path::new("")).unwrap_err();
        assert!(matches!(err, TempFileLabelError::InvalidArgument(_)));
    }

    #[test]
    fn test_fopen_temporary_label_empty_path() {
        let err = fopen_temporary_label(None, Path::new("")).unwrap_err();
        assert!(matches!(err, TempFileLabelError::InvalidArgument(_)));
    }

    #[test]
    fn test_fopen_temporary_at_label_with_empty_path() {
        let backend = MockBackend::default();
        let err =
            fopen_temporary_at_label_with(AT_FDCWD, None, Path::new(""), &backend).unwrap_err();
        assert!(matches!(err, TempFileLabelError::InvalidArgument(_)));
    }

    #[test]
    fn test_validate_dir_fd_rejects_invalid_negative_fd() {
        let err =
            fopen_temporary_at_label_with(-2, None, Path::new("file"), &MockBackend::default())
                .unwrap_err();
        assert!(matches!(err, TempFileLabelError::InvalidArgument(_)));
    }

    #[test]
    fn test_path_with_interior_nul_is_rejected() {
        let bad = PathBuf::from(std::ffi::OsString::from_vec(b"bad\0name".to_vec()));
        let err = fopen_temporary_label(None, &bad).unwrap_err();
        assert!(matches!(err, TempFileLabelError::InvalidArgument(_)));
    }

    // ── fopen_temporary_at_label: real file creation ──────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_fopen_temporary_at_label_creates_file_and_returns_hidden_path() {
        let dir = tempdir().unwrap();
        let requested = dir.path().join("target");
        let backend = MockBackend::default();

        let temporary =
            fopen_temporary_at_label_with(AT_FDCWD, Some(&requested), &requested, &backend)
                .unwrap();

        assert!(temporary.temp_path().starts_with(dir.path()));
        assert!(
            temporary
                .temp_path()
                .file_name()
                .unwrap()
                .as_bytes()
                .starts_with(HIDDEN_TMP_PREFIX)
        );
        assert!(temporary.temp_path().exists());
        assert_eq!(backend.clear_count(), 1);
        assert_eq!(backend.prepare_calls.borrow().len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_fopen_temporary_label_wrapper_uses_at_fdcwd() {
        let dir = tempdir().unwrap();
        let requested = dir.path().join("wrapper");
        let backend = MockBackend::default();

        let temporary = fopen_temporary_label_with(Some(&requested), &requested, &backend).unwrap();

        assert!(temporary.temp_path().exists());
        let recorded = backend.prepare_calls.borrow();
        assert_eq!(recorded[0].0, AT_FDCWD);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_created_file_has_mode_0600() {
        let dir = tempdir().unwrap();
        let requested = dir.path().join("mode-check");
        let temporary = fopen_temporary_label(None, &requested).unwrap();
        let mode = temporary.file().metadata().unwrap().permissions().mode() & 0o777;

        assert_eq!(mode, 0o600);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_created_file_is_empty_regular_file() {
        let dir = tempdir().unwrap();
        let requested = dir.path().join("empty-file");
        let temporary = fopen_temporary_label(None, &requested).unwrap();
        let metadata = temporary.file().metadata().unwrap();

        assert!(metadata.is_file());
        assert_eq!(metadata.len(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_target_none_still_creates_temporary_file() {
        let dir = tempdir().unwrap();
        let requested = dir.path().join("none-target");
        let backend = MockBackend::default();

        let temporary =
            fopen_temporary_at_label_with(AT_FDCWD, None, &requested, &backend).unwrap();

        assert!(temporary.temp_path().exists());
        let recorded = backend.prepare_calls.borrow();
        assert_eq!(recorded[0].1, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_repeated_calls_choose_different_temp_paths() {
        let dir = tempdir().unwrap();
        let requested = dir.path().join("repeat");

        let first = fopen_temporary_label(None, &requested).unwrap();
        let second = fopen_temporary_label(None, &requested).unwrap();

        assert_ne!(first.temp_path(), second.temp_path());
    }

    // ── Backend trait: guard behavior ─────────────────────────────────

    #[test]
    fn test_clear_is_not_called_when_prepare_fails() {
        let backend = MockBackend::default();
        *backend.prepare_error.borrow_mut() = Some(TempFileLabelError::InvalidArgument("boom"));

        let err = fopen_temporary_at_label_with(
            AT_FDCWD,
            Some(Path::new("target")),
            Path::new("target"),
            &backend,
        )
        .unwrap_err();

        assert!(matches!(err, TempFileLabelError::InvalidArgument("boom")));
        assert_eq!(backend.clear_count(), 0);
    }

    #[test]
    fn test_clear_is_called_when_open_fails_after_prepare() {
        let backend = MockBackend::default();
        let err = fopen_temporary_at_label_with(
            AT_FDCWD,
            Some(Path::new("missing/final")),
            Path::new("missing/final"),
            &backend,
        )
        .unwrap_err();

        assert!(matches!(err, TempFileLabelError::Io(_)));
        assert_eq!(backend.clear_count(), 1);
    }

    // ── dir_fd relative creation ──────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dir_fd_relative_creation_works() {
        let dir = tempdir().unwrap();
        let dir_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(dir.path())
            .unwrap();
        let backend = MockBackend::default();

        let temporary = fopen_temporary_at_label_with(
            dir_file.as_raw_fd(),
            None,
            Path::new("relative-name"),
            &backend,
        )
        .unwrap();

        let name = temporary.temp_path().file_name().unwrap().to_str().unwrap();
        assert!(
            temporary
                .temp_path()
                .parent()
                .is_none_or(|p| p.as_os_str().is_empty())
        );
        assert!(name.starts_with(".#relative-name"));
        assert_eq!(name.len(), 2 + "relative-name".len() + RANDOM_SUFFIX_LEN);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dir_fd_relative_creation_places_file_in_directory() {
        let dir = tempdir().unwrap();
        let dir_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open(dir.path())
            .unwrap();

        let temporary = fopen_temporary_at_label_with(
            dir_file.as_raw_fd(),
            None,
            Path::new("child"),
            &MockBackend::default(),
        )
        .unwrap();
        let created = dir.path().join(temporary.temp_path());

        assert!(created.exists());
    }
}
