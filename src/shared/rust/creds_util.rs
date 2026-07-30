// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/creds-util.c, src/shared/creds-util.h
//
// Credential handling utilities for systemd services.
//
// Provides validation of credential names and glob patterns, resolution of
// credential directories (per-service, system, and encrypted variants),
// reading credentials from disk, and Varlink error definitions.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::ffi::Errno;
pub use crate::secret_bytes::SecretBytes;
use crate::secret_bytes::SecretBytesFinalizeError;
pub use systemd_basic_rs::credential_validators::{
    credential_glob_valid, credential_name_valid, fdname_is_valid, filename_is_valid,
};

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum length of a credential name (matches `NAME_MAX` in C).
pub const CREDENTIAL_NAME_MAX: usize = 255;

/// Maximum size of a single credential in bytes (1 MiB).
pub const CREDENTIAL_SIZE_MAX: u64 = 1024 * 1024;

/// Maximum total size for all credentials combined (1 MiB).
pub const CREDENTIALS_TOTAL_SIZE_MAX: u64 = CREDENTIAL_SIZE_MAX;

/// Maximum size of an encrypted credential, including overhead (1 MiB + 128 KiB).
pub const CREDENTIAL_ENCRYPTED_SIZE_MAX: u64 = CREDENTIAL_SIZE_MAX + 128 * 1024;

/// Default system credentials directory path.
pub const SYSTEM_CREDENTIALS_DIRECTORY: &str = "/run/credentials/@system";

/// Default encrypted system credentials directory path.
pub const ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY: &str = "/run/credentials/@encrypted";

/// Maximum length for file descriptor names.
pub const FDNAME_MAX: usize = 255;

// ── Flags ─────────────────────────────────────────────────────────────────

/// Flags controlling secret credential behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialSecretFlags(pub u32);

impl CredentialSecretFlags {
    pub const GENERATE: u32 = 1 << 0;
    pub const WARN_NOT_ENCRYPTED: u32 = 1 << 1;
    pub const FAIL_ON_TEMPORARY_FS: u32 = 1 << 2;
}

/// Flags controlling credential access behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialFlags(pub u32);

impl CredentialFlags {
    pub const ALLOW_NULL: u32 = 1 << 0;
    pub const REFUSE_NULL: u32 = 1 << 1;
    pub const ANY_SCOPE: u32 = 1 << 2;
    pub const IPC_ALLOW_INTERACTIVE: u32 = 1 << 3;
}

// ── Varlink Errors ────────────────────────────────────────────────────────

/// A single Varlink error definition for the Credentials interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialsVarlinkError {
    pub id: &'static str,
    pub errnum: i32,
    pub msg: &'static str,
}

/// All Varlink error definitions for the Credentials interface.
pub const CREDENTIALS_VARLINK_ERRORS: &[CredentialsVarlinkError] = &[
    CredentialsVarlinkError {
        id: "io.systemd.Credentials.BadFormat",
        errnum: libc::EBADMSG,
        msg: "Bad credential format.",
    },
    CredentialsVarlinkError {
        id: "io.systemd.Credentials.NameMismatch",
        errnum: libc::EDESTADDRREQ,
        msg: "Name in credential doesn't match expectations.",
    },
    CredentialsVarlinkError {
        id: "io.systemd.Credentials.TimeMismatch",
        errnum: libc::ESTALE,
        msg: "Outside of credential validity time window.",
    },
    CredentialsVarlinkError {
        id: "io.systemd.Credentials.NoSuchUser",
        errnum: libc::ESRCH,
        msg: "No such user.",
    },
    CredentialsVarlinkError {
        id: "io.systemd.Credentials.BadScope",
        errnum: libc::EMEDIUMTYPE,
        msg: "Scope mismatch.",
    },
    CredentialsVarlinkError {
        id: "io.systemd.Credentials.CantFindPCRSignature",
        errnum: libc::EHOSTDOWN,
        msg: "PCR signature required for decryption, but could not be found.",
    },
    CredentialsVarlinkError {
        id: "io.systemd.Credentials.NullKeyNotAllowed",
        errnum: libc::EHWPOISON,
        msg: "The key was encrypted with a null key, but that's not allowed during decryption.",
    },
    CredentialsVarlinkError {
        id: "io.systemd.Credentials.KeyBelongsToOtherTPM",
        errnum: libc::EREMOTE,
        msg: "The TPM integrity check failed; the key may belong to another TPM or be corrupted.",
    },
    CredentialsVarlinkError {
        id: "io.systemd.Credentials.TPMInDictionaryLockout",
        errnum: libc::ENOLCK,
        msg: "The TPM is in dictionary lockout mode.",
    },
    CredentialsVarlinkError {
        id: "io.systemd.Credentials.UnexpectedPCRState",
        errnum: libc::EUCLEAN,
        msg: "Unexpected TPM PCR state of the system.",
    },
    CredentialsVarlinkError {
        id: "io.systemd.Credentials.NVIndexUnusable",
        errnum: libc::EADDRNOTAVAIL,
        msg: "The referenced TPM NV index is missing, unwritten, or unusable.",
    },
];

/// Look up a Varlink error by its string id.
pub fn credentials_varlink_error_by_id(id: &str) -> Option<&'static CredentialsVarlinkError> {
    CREDENTIALS_VARLINK_ERRORS.iter().find(|e| e.id == id)
}

/// Look up a Varlink error by its errno value.
pub fn credentials_varlink_error_by_errno(errnum: i32) -> Option<&'static CredentialsVarlinkError> {
    CREDENTIALS_VARLINK_ERRORS
        .iter()
        .find(|e| e.errnum == errnum)
}

// ── Path Helpers ──────────────────────────────────────────────────────────

/// Check whether a path is normalized.
///
/// A normalized credential-directory path is absolute, within `PATH_MAX`, and
/// contains no oversized, redundant, current, or parent components. Unix
/// paths are byte strings; do not reject a valid credential directory merely
/// because it is not UTF-8.
#[cfg(unix)]
fn path_is_normalized(p: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;

    let bytes = p.as_bytes();
    if bytes.is_empty()
        || bytes.first() != Some(&b'/')
        || bytes.len() >= libc::PATH_MAX as usize
        || bytes.contains(&0)
        || bytes.windows(2).any(|window| window == b"//")
    {
        return false;
    }

    bytes.split(|byte| *byte == b'/').all(|component| {
        component.is_empty()
            || (component != b"."
                && component != b".."
                && component.len() <= libc::NAME_MAX as usize)
    })
}

#[cfg(not(unix))]
fn path_is_normalized(p: &OsStr) -> bool {
    let path = Path::new(p);
    let Some(text) = p.to_str() else {
        return false;
    };
    !text.is_empty()
        && path.is_absolute()
        && text.len() < libc::PATH_MAX as usize
        && !text.contains('\0')
        && !text.contains("//")
        && text.split('/').all(|component| {
            component.is_empty()
                || (component != "."
                    && component != ".."
                    && component.len() <= libc::NAME_MAX as usize)
        })
}

// ── Credential Directory Resolution ───────────────────────────────────────

/// Internal helper: read and validate a credentials directory from an env var.
///
/// Returns the directory path on success, or a negated errno on failure.
#[cfg(target_os = "linux")]
fn secure_environment_variable(envvar: &str) -> Result<Option<OsString>, i32> {
    // AT_SECURE is a fixed kernel auxiliary-vector key. Refusing all
    // environment input in secure-execution mode mirrors secure_getenv()
    // without exposing a borrowed libc environment pointer to Rust.
    // SAFETY: getauxval() has no pointer arguments or ownership transfer.
    if unsafe { libc::getauxval(libc::AT_SECURE) } != 0 {
        return Ok(None);
    }

    Ok(std::env::var_os(envvar))
}

#[cfg(not(target_os = "linux"))]
fn secure_environment_variable(_envvar: &str) -> Result<Option<OsString>, i32> {
    Err(Errno::ENOSYS.to_neg_errno())
}

fn get_credentials_dir_internal(envvar: &str) -> Result<PathBuf, i32> {
    let e = secure_environment_variable(envvar)?.ok_or(Errno::ENXIO.to_neg_errno())?;

    if !Path::new(&e).is_absolute() || !path_is_normalized(&e) {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    Ok(PathBuf::from(e))
}

/// Resolve the per-service credentials directory from `CREDENTIALS_DIRECTORY`.
pub fn get_credentials_dir() -> Result<PathBuf, i32> {
    get_credentials_dir_internal("CREDENTIALS_DIRECTORY")
}

/// Resolve the encrypted credentials directory from `ENCRYPTED_CREDENTIALS_DIRECTORY`.
pub fn get_encrypted_credentials_dir() -> Result<PathBuf, i32> {
    get_credentials_dir_internal("ENCRYPTED_CREDENTIALS_DIRECTORY")
}

/// Resolve the system credentials directory.
///
/// Falls back to `SYSTEM_CREDENTIALS_DIRECTORY` if the env var is unset.
pub fn get_system_credentials_dir() -> Result<PathBuf, i32> {
    match get_credentials_dir_internal("SYSTEMD_SYSTEM_CREDENTIALS_DIRECTORY") {
        Ok(directory) => Ok(directory),
        Err(error) if error == Errno::ENXIO.to_neg_errno() => {
            Ok(PathBuf::from(SYSTEM_CREDENTIALS_DIRECTORY))
        }
        Err(error) => Err(error),
    }
}

/// Resolve the encrypted system credentials directory.
///
/// Falls back to `ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY` if the env var is unset.
pub fn get_encrypted_system_credentials_dir() -> Result<PathBuf, i32> {
    match get_credentials_dir_internal("SYSTEMD_ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY") {
        Ok(directory) => Ok(directory),
        Err(error) if error == Errno::ENXIO.to_neg_errno() => {
            Ok(PathBuf::from(ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY))
        }
        Err(error) => Err(error),
    }
}

// ── Credential Reading ────────────────────────────────────────────────────

/// An opened, descriptor-owned view of the current service's credentials.
///
/// Keeping the directory descriptor and its diagnostic path together avoids
/// resolving the environment-provided directory again between validation and
/// opening an individual credential.
#[derive(Debug)]
pub struct CredentialsDir {
    directory: File,
    path: PathBuf,
}

impl CredentialsDir {
    /// Resolve and pin the current credentials directory.
    pub fn open() -> Result<Self, i32> {
        let path = get_credentials_dir()?;
        Self::open_path(path)
    }

    pub(crate) fn open_path(path: PathBuf) -> Result<Self, i32> {
        let directory = open_directory(&path)?;
        Ok(Self { directory, path })
    }

    /// The path used to open this capability, for diagnostics only.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Open a validated credential name relative to the pinned directory.
    #[cfg(unix)]
    fn open_name(&self, name: &str) -> Result<File, i32> {
        use std::os::fd::{AsRawFd, FromRawFd};

        if !credential_name_valid(name) {
            return Err(Errno::EINVAL.to_neg_errno());
        }

        // credential_name_valid() limits names to NAME_MAX printable ASCII,
        // excluding NUL and '/'. A fixed buffer therefore avoids a fallible
        // CString allocation at this low-level boundary.
        let mut nul_terminated = [0_u8; CREDENTIAL_NAME_MAX + 1];
        nul_terminated[..name.len()].copy_from_slice(name.as_bytes());

        // Current C follows the final symlink here. Preserve that behavior,
        // but pin the parent directory and set close-on-exec atomically.
        // SAFETY: the directory fd is live, the stack name is NUL-terminated,
        // and openat retains neither pointer. A non-negative result transfers
        // one newly owned descriptor to File.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                nul_terminated.as_ptr().cast(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io_error(io::Error::last_os_error()));
        }
        // SAFETY: `fd` is the unique successful openat result.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    #[cfg(not(unix))]
    fn open_name(&self, _name: &str) -> Result<File, i32> {
        Err(Errno::ENOSYS.to_neg_errno())
    }

    pub(crate) fn read_name(&self, name: &str) -> Result<SecretBytes, i32> {
        let mut file = self.open_name(name)?;
        read_secret_bounded(&mut file, CREDENTIAL_SIZE_MAX)
    }
}

fn open_directory(path: &Path) -> Result<File, i32> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY);
    }
    options.open(path).map_err(io_error)
}

/// Open the credentials directory for the current service.
pub fn open_credentials_dir() -> Result<CredentialsDir, i32> {
    CredentialsDir::open()
}

fn read_secret_bounded(reader: &mut impl Read, maximum_size: u64) -> Result<SecretBytes, i32> {
    let read_limit = maximum_size
        .checked_add(1)
        .ok_or(Errno::EFBIG.to_neg_errno())?;
    let capacity = usize::try_from(read_limit).map_err(|_| Errno::EFBIG.to_neg_errno())?;
    let mut data = SecretBytes::try_zeroed(capacity).map_err(|_| Errno::ENOMEM.to_neg_errno())?;
    let mut limited = reader.take(read_limit);
    let mut length = 0;
    while length < capacity {
        let bytes_read = match limited.read(&mut data.as_mut_bytes()[length..]) {
            Ok(bytes_read) => bytes_read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_error(error)),
        };
        if bytes_read == 0 {
            break;
        }
        length += bytes_read;
    }
    if length as u64 > maximum_size {
        return Err(Errno::EFBIG.to_neg_errno());
    }
    data.finalize_prefix(length).map_err(|error| match error {
        SecretBytesFinalizeError::InvalidLength => Errno::EIO.to_neg_errno(),
        SecretBytesFinalizeError::OutOfMemory => Errno::ENOMEM.to_neg_errno(),
    })
}

/// Read an explicit machine-credential path, optionally matching current C's
/// AF_UNIX socket fallback after Linux returns ENXIO for open(2).
pub(crate) fn read_credential_path(path: &Path, connect_socket: bool) -> Result<SecretBytes, i32> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC);
    }

    match options.open(path) {
        Ok(mut file) => read_secret_bounded(&mut file, CREDENTIAL_SIZE_MAX),
        Err(error) if connect_socket && error.raw_os_error() == Some(libc::ENXIO) => {
            #[cfg(unix)]
            {
                use std::net::Shutdown;
                use std::os::unix::net::UnixStream;

                let mut socket = UnixStream::connect(path).map_err(|error| {
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ENOTSOCK) | Some(libc::EINVAL)
                    ) {
                        Errno::ENXIO.to_neg_errno()
                    } else {
                        io_error(error)
                    }
                })?;
                socket.shutdown(Shutdown::Write).map_err(io_error)?;
                read_secret_bounded(&mut socket, CREDENTIAL_SIZE_MAX)
            }
            #[cfg(not(unix))]
            {
                Err(Errno::ENOSYS.to_neg_errno())
            }
        }
        Err(error) => Err(io_error(error)),
    }
}

/// Read a credential by name from the credentials directory.
///
/// Returns the credential contents in a non-cloneable, zeroizing owner, or a
/// negated errno on failure. Returns `-EINVAL` if the name is invalid,
/// `-EFBIG` if the credential exceeds `CREDENTIAL_SIZE_MAX`.
pub fn read_credential(name: &str) -> Result<SecretBytes, i32> {
    if !credential_name_valid(name) {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    CredentialsDir::open()?.read_name(name)
}

/// Allocation-free byte form of current C `parse_boolean()`.
///
/// `read_full_file_full()` gives C a trailing NUL and `parse_boolean()` sees
/// bytes only through the first embedded NUL. It performs ASCII case-folding
/// but does not trim whitespace.
fn parse_boolean(s: &[u8]) -> Option<bool> {
    let s = s.split(|byte| *byte == 0).next().unwrap_or_default();
    if [b"1".as_slice(), b"yes", b"y", b"true", b"t", b"on"]
        .iter()
        .any(|candidate| s.eq_ignore_ascii_case(candidate))
    {
        Some(true)
    } else if [b"0".as_slice(), b"no", b"n", b"false", b"f", b"off"]
        .iter()
        .any(|candidate| s.eq_ignore_ascii_case(candidate))
    {
        Some(false)
    } else {
        None
    }
}

/// Read a credential as a boolean value.
///
/// If the credential does not exist, returns `Ok(false)`. On other errors,
/// propagates the error. If the credential content is not a valid boolean
/// string, returns `-EINVAL`.
pub fn read_credential_bool(name: &str) -> Result<bool, i32> {
    match read_credential(name) {
        Ok(data) => parse_boolean(data.as_bytes()).ok_or(Errno::EINVAL.to_neg_errno()),
        Err(e) if e == Errno::ENXIO.to_neg_errno() || e == Errno::ENOENT.to_neg_errno() => {
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

fn reject_unported_encrypted_credential(path: &Path) -> Result<Option<SecretBytes>, i32> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => Err(Errno::EISDIR.to_neg_errno()),
        Ok(_) => Err(Errno::EOPNOTSUPP.to_neg_errno()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(-error.raw_os_error().unwrap_or(Errno::EIO as i32)),
    }
}

/// Read a plaintext credential, detecting but not pretending to decrypt an
/// encrypted fallback.
///
/// The C implementation authenticates and decrypts the encrypted file through
/// OpenSSL/TPM2 or the credentials Varlink service. That architecture is not
/// ported here, so returning the ciphertext would be a dangerous false success.
/// Existing encrypted data therefore fails closed with `-EOPNOTSUPP`.
pub fn read_credential_with_decryption(name: &str) -> Result<Option<SecretBytes>, i32> {
    if !credential_name_valid(name) {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    match read_credential(name) {
        Ok(data) => Ok(Some(data)),
        Err(e) if e == Errno::ENXIO.to_neg_errno() || e == Errno::ENOENT.to_neg_errno() => {
            match get_encrypted_credentials_dir() {
                Ok(d) => {
                    let path = d.join(name);
                    reject_unported_encrypted_credential(&path)
                }
                Err(error) if error == Errno::ENXIO.to_neg_errno() => Ok(None),
                Err(error) => Err(error),
            }
        }
        Err(e) => Err(e),
    }
}

/// Look up a user's password via credentials.
///
/// First tries `passwd.hashed-password.<username>`, then falls back to
/// `passwd.plaintext-password.<username>` only when the hashed credential is
/// absent. As in C, missing credentials and directory-resolution failures are
/// returned as errors.
pub fn get_credential_user_password(username: &str) -> Result<(Option<SecretBytes>, bool), i32> {
    fn password_bytes(data: SecretBytes) -> Result<SecretBytes, i32> {
        if data.contains(0) {
            return Err(Errno::EBADMSG.to_neg_errno());
        }
        Ok(data)
    }

    let hashed_name = format!("passwd.hashed-password.{}", username);
    match read_credential(&hashed_name) {
        Ok(data) => {
            let password = password_bytes(data)?;
            Ok((Some(password), true))
        }
        Err(e) if e == Errno::ENOENT.to_neg_errno() => {
            let plain_name = format!("passwd.plaintext-password.{}", username);
            match read_credential(&plain_name) {
                Ok(data) => {
                    let password = password_bytes(data)?;
                    Ok((Some(password), false))
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

// ── Pick-Up Credentials ───────────────────────────────────────────────────

/// Descriptor for a credential to pick up from the credentials directory.
pub struct PickUpCredential<'a> {
    /// Prefix that credential names must start with.
    pub credential_prefix: &'a str,
    /// Target directory to copy credentials into.
    pub target_dir: &'a str,
    /// Filename suffix for the destination file.
    pub filename_suffix: &'a str,
}

/// Copy credentials matching the given table entries from the credentials
/// directory to their target locations.
pub fn pick_up_credentials(table: &[PickUpCredential<'_>]) -> Result<(), i32> {
    let source = match get_credentials_dir() {
        Ok(source) => source,
        // An unset credentials environment is explicitly a no-op. In
        // particular, do not turn it into an empty path and scan the CWD.
        Err(error) if error == Errno::ENXIO.to_neg_errno() => return Ok(()),
        Err(error) => return Err(error),
    };

    match pick_up_credentials_from_dir(&source, table) {
        Ok(()) => Ok(()),
        // `open_credentials_dir()` in C treats a vanished or absent directory
        // as "no credentials", but every other directory error is material.
        Err(error) if error == Errno::ENOENT.to_neg_errno() => Ok(()),
        Err(error) => Err(error),
    }
}

fn io_error(error: io::Error) -> i32 {
    error
        .raw_os_error()
        .and_then(i32::checked_neg)
        .unwrap_or(Errno::EIO.to_neg_errno())
}

#[cfg(unix)]
fn filename_from_credential(
    credential_name: &std::ffi::OsStr,
    table_entry: &PickUpCredential<'_>,
) -> Result<Option<std::ffi::OsString>, i32> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let credential_name = credential_name.as_bytes();
    let Some(remainder) = credential_name.strip_prefix(table_entry.credential_prefix.as_bytes())
    else {
        return Ok(None);
    };

    let mut filename = Vec::with_capacity(remainder.len() + table_entry.filename_suffix.len());
    filename.extend_from_slice(remainder);
    filename.extend_from_slice(table_entry.filename_suffix.as_bytes());

    if filename.is_empty()
        || filename.len() > CREDENTIAL_NAME_MAX
        || filename == b"."
        || filename == b".."
        || filename.contains(&b'/')
        || filename.contains(&b'\0')
    {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    Ok(Some(std::ffi::OsString::from_vec(filename)))
}

#[cfg(not(unix))]
fn filename_from_credential(
    credential_name: &std::ffi::OsStr,
    table_entry: &PickUpCredential<'_>,
) -> Result<Option<std::ffi::OsString>, i32> {
    let Some(credential_name) = credential_name.to_str() else {
        return Ok(None);
    };
    let Some(remainder) = credential_name.strip_prefix(table_entry.credential_prefix) else {
        return Ok(None);
    };
    let filename = format!("{remainder}{}", table_entry.filename_suffix);
    if !filename_is_valid(&filename) {
        return Err(Errno::EINVAL.to_neg_errno());
    }
    Ok(Some(std::ffi::OsString::from(filename)))
}

fn create_pickup_target_dir(target_dir: &Path) -> Result<(), i32> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        builder.mode(0o755);
    }
    builder.create(target_dir).map_err(io_error)
}

fn copy_pickup_credential(source: &Path, target: &Path) -> Result<(), i32> {
    let mut source_file = fs::File::open(source).map_err(io_error)?;
    if !source_file.metadata().map_err(io_error)?.is_file() {
        return Err(Errno::EINVAL.to_neg_errno());
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        // `copy_file_at()` creates a new target as 0644 and does not change
        // the permissions of an existing regular target.
        options.mode(0o644);
    }
    let mut target_file = options.open(target).map_err(io_error)?;

    // C's `copy_file_at(..., 0, 0644, 0)` overwrites from the start but does
    // not request O_TRUNC. Keep that behavior instead of using `fs::copy`.
    io::copy(&mut source_file, &mut target_file).map_err(io_error)?;
    Ok(())
}

fn pick_up_credential_one(
    source_dir: &Path,
    credential_name: &std::ffi::OsStr,
    table_entry: &PickUpCredential<'_>,
) -> Result<bool, i32> {
    let Some(filename) = filename_from_credential(credential_name, table_entry)? else {
        return Ok(false);
    };

    let target_dir = Path::new(table_entry.target_dir);
    create_pickup_target_dir(target_dir)?;
    copy_pickup_credential(
        &source_dir.join(credential_name),
        &target_dir.join(filename),
    )?;
    Ok(true)
}

fn pick_up_credentials_from_dir(
    source_dir: &Path,
    table: &[PickUpCredential<'_>],
) -> Result<(), i32> {
    let mut credentials = Vec::new();
    for entry in fs::read_dir(source_dir).map_err(io_error)? {
        credentials.push(entry.map_err(io_error)?);
    }

    #[cfg(unix)]
    credentials.sort_by(|left, right| {
        use std::os::unix::ffi::OsStrExt;

        left.file_name()
            .as_bytes()
            .cmp(right.file_name().as_bytes())
    });
    #[cfg(not(unix))]
    credentials.sort_by_key(|entry| entry.file_name());

    let mut first_error = None;
    for credential in credentials {
        let name = credential.file_name();
        #[cfg(unix)]
        let is_dot_file = {
            use std::os::unix::ffi::OsStrExt;

            name.as_bytes().first() == Some(&b'.')
        };
        #[cfg(not(unix))]
        let is_dot_file = name.to_string_lossy().starts_with('.');
        if is_dot_file {
            continue;
        }

        // This matches RECURSE_DIR_MUST_BE_REGULAR: do not follow a symlink
        // merely because its target happens to be a regular file.
        match fs::symlink_metadata(credential.path()) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_error(error)),
        }

        for table_entry in table {
            match pick_up_credential_one(source_dir, &name, table_entry) {
                Ok(false) => continue,
                // A matching entry consumes this credential, exactly like the
                // C loop's `break` after any non-zero result.
                Ok(true) => break,
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    break;
                }
            }
        }
    }

    first_error.map_or(Ok(()), Err)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- fdname_is_valid --

    #[test]
    fn test_fdname_is_valid_basic() {
        assert!(fdname_is_valid("foo"));
        assert!(fdname_is_valid("foo_bar"));
        assert!(fdname_is_valid("foo-bar"));
        assert!(fdname_is_valid("foo.bar"));
        assert!(fdname_is_valid("foo/bar"));
        assert!(fdname_is_valid("with space"));
        assert!(fdname_is_valid(""));
        assert!(fdname_is_valid("a"));
        assert!(fdname_is_valid("ABC123"));
    }

    #[test]
    fn test_fdname_is_valid_rejects_separator_and_controls() {
        assert!(!fdname_is_valid("foo:bar"));
        assert!(!fdname_is_valid("foo\nbar"));
        assert!(!fdname_is_valid("fóo"));
    }

    #[test]
    fn test_fdname_is_valid_rejects_too_long() {
        assert!(!fdname_is_valid(&"a".repeat(FDNAME_MAX + 1)));
    }

    #[test]
    fn test_fdname_is_valid_at_max_length() {
        assert!(fdname_is_valid(&"a".repeat(FDNAME_MAX)));
    }

    // -- filename_is_valid --

    #[test]
    fn test_filename_is_valid_basic() {
        assert!(filename_is_valid("foo"));
        assert!(filename_is_valid("foo-bar_baz.qux"));
        assert!(filename_is_valid("a"));
    }

    #[test]
    fn test_filename_is_valid_rejects_dot_components() {
        assert!(!filename_is_valid("."));
        assert!(!filename_is_valid(".."));
    }

    #[test]
    fn test_filename_is_valid_rejects_empty() {
        assert!(!filename_is_valid(""));
    }

    #[test]
    fn test_filename_is_valid_rejects_slash() {
        assert!(!filename_is_valid("foo/bar"));
    }

    #[test]
    fn test_filename_is_valid_rejects_nul() {
        assert!(!filename_is_valid("foo\0bar"));
    }

    // -- credential_name_valid --

    #[test]
    fn test_credential_name_valid_basic() {
        assert!(credential_name_valid("foo"));
        assert!(credential_name_valid("foo-bar_baz"));
        assert!(credential_name_valid("a"));
        assert!(credential_name_valid("credential.name"));
        assert!(credential_name_valid("foo bar"));
        assert!(credential_name_valid("foo*bar"));
        assert!(credential_name_valid(".hidden"));
    }

    #[test]
    fn test_credential_name_valid_rejects_invalid() {
        assert!(!credential_name_valid(""));
        assert!(!credential_name_valid("foo/bar"));
        assert!(!credential_name_valid("foo:bar"));
        assert!(!credential_name_valid("foo\nbar"));
        assert!(!credential_name_valid("foo\0bar"));
        assert!(!credential_name_valid(&"a".repeat(256)));
    }

    #[test]
    fn test_credential_name_valid_rejects_slash() {
        assert!(!credential_name_valid("path/to/cred"));
    }

    // -- credential_glob_valid --

    #[test]
    fn test_credential_glob_valid_trailing_asterisk() {
        assert!(credential_glob_valid("foo*"));
        assert!(credential_glob_valid("*"));
    }

    #[test]
    fn test_credential_glob_valid_rejects_non_asterisk_globs() {
        assert!(!credential_glob_valid("foo?"));
        assert!(!credential_glob_valid("foo[bar]"));
        assert!(!credential_glob_valid("foo*bar*"));
    }

    #[test]
    fn test_credential_glob_valid_accepts_plain_name() {
        assert!(credential_glob_valid("foo"));
    }

    #[test]
    fn test_credential_glob_valid_rejects_empty() {
        assert!(!credential_glob_valid(""));
    }

    #[test]
    fn test_credential_glob_valid_rejects_slash() {
        assert!(!credential_glob_valid("foo/bar*"));
    }

    #[test]
    fn test_credential_glob_valid_prefix_too_long() {
        // FDNAME_MAX + 2 chars total (prefix of FDNAME_MAX+1 chars + "*")
        let long_name = "a".repeat(FDNAME_MAX + 2);
        assert!(!credential_glob_valid(&format!("{}*", long_name)));
    }

    // -- path_is_normalized --

    #[test]
    fn test_path_is_normalized_basic() {
        assert!(path_is_normalized(OsStr::new("/")));
        assert!(path_is_normalized(OsStr::new("/foo/bar")));
        assert!(path_is_normalized(OsStr::new("/foo/bar/")));
    }

    #[test]
    fn test_path_is_normalized_rejects_relative() {
        assert!(!path_is_normalized(OsStr::new("")));
        assert!(!path_is_normalized(OsStr::new("foo/bar")));
    }

    #[test]
    fn test_path_is_normalized_rejects_escaping() {
        assert!(!path_is_normalized(OsStr::new("/foo/../bar")));
        assert!(!path_is_normalized(OsStr::new("/..")));
        assert!(!path_is_normalized(OsStr::new("/foo/./bar")));
        assert!(!path_is_normalized(OsStr::new("/foo//bar")));
        assert!(!path_is_normalized(OsStr::new("/foo\0bar")));
    }

    // -- parse_boolean --

    #[test]
    fn test_parse_boolean_true_values() {
        assert_eq!(parse_boolean(b"1"), Some(true));
        assert_eq!(parse_boolean(b"yes"), Some(true));
        assert_eq!(parse_boolean(b"true"), Some(true));
        assert_eq!(parse_boolean(b"t"), Some(true));
        assert_eq!(parse_boolean(b"on"), Some(true));
        assert_eq!(parse_boolean(b"y"), Some(true));
        assert_eq!(parse_boolean(b"True"), Some(true));
        assert_eq!(parse_boolean(b"YES\0ignored"), Some(true));
    }

    #[test]
    fn test_parse_boolean_false_values() {
        assert_eq!(parse_boolean(b"0"), Some(false));
        assert_eq!(parse_boolean(b"no"), Some(false));
        assert_eq!(parse_boolean(b"false"), Some(false));
        assert_eq!(parse_boolean(b"f"), Some(false));
        assert_eq!(parse_boolean(b"off"), Some(false));
        assert_eq!(parse_boolean(b"n"), Some(false));
    }

    #[test]
    fn test_parse_boolean_invalid() {
        assert_eq!(parse_boolean(b"  YES  "), None);
        assert_eq!(parse_boolean(b"  NO  "), None);
        assert_eq!(parse_boolean(b"maybe"), None);
        assert_eq!(parse_boolean(b""), None);
        assert_eq!(parse_boolean(b"2"), None);
        assert_eq!(parse_boolean(b"\xff"), None);
    }

    #[test]
    fn test_encrypted_credential_fallback_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing");
        assert!(matches!(
            reject_unported_encrypted_credential(&missing),
            Ok(None)
        ));

        let encrypted = directory.path().join("encrypted");
        fs::write(&encrypted, b"ciphertext").unwrap();
        assert!(matches!(
            reject_unported_encrypted_credential(&encrypted),
            Err(error) if error == Errno::EOPNOTSUPP.to_neg_errno()
        ));

        assert!(matches!(
            reject_unported_encrypted_credential(directory.path()),
            Err(error) if error == Errno::EISDIR.to_neg_errno()
        ));
    }

    // -- pick_up_credentials --

    #[test]
    fn test_pick_up_credentials_uses_remainder_suffix_and_first_match() {
        let source = tempfile::tempdir().unwrap();
        let targets = tempfile::tempdir().unwrap();
        let first_target = targets.path().join("first");
        let second_target = targets.path().join("second");

        fs::write(source.path().join("network.conf.dhcp"), b"[DHCP]\n").unwrap();
        fs::write(source.path().join(".network.conf.hidden"), b"hidden").unwrap();
        fs::create_dir(source.path().join("network.conf.directory")).unwrap();

        let first_target_str = first_target.to_str().unwrap();
        let second_target_str = second_target.to_str().unwrap();
        let table = [
            PickUpCredential {
                credential_prefix: "network.conf.",
                target_dir: first_target_str,
                filename_suffix: ".conf",
            },
            PickUpCredential {
                credential_prefix: "network.",
                target_dir: second_target_str,
                filename_suffix: ".second",
            },
        ];

        assert_eq!(pick_up_credentials_from_dir(source.path(), &table), Ok(()));
        assert_eq!(
            fs::read(first_target.join("dhcp.conf")).unwrap(),
            b"[DHCP]\n"
        );
        assert!(!first_target.join(".conf").exists());
        assert!(!first_target.join("directory.conf").exists());
        assert!(!second_target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_pick_up_credentials_skips_symlinks() {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let backing_file = source.path().join("backing");
        fs::write(&backing_file, b"not a credential").unwrap();
        std::os::unix::fs::symlink(&backing_file, source.path().join("match.alias")).unwrap();

        let target_str = target.path().to_str().unwrap();
        let table = [PickUpCredential {
            credential_prefix: "match.",
            target_dir: target_str,
            filename_suffix: ".conf",
        }];

        assert_eq!(pick_up_credentials_from_dir(source.path(), &table), Ok(()));
        assert!(!target.path().join("alias.conf").exists());
    }

    #[test]
    fn test_pick_up_credentials_rejects_invalid_destination_filename() {
        let source = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let target_dir = target.path().join("not-created");
        fs::write(source.path().join("match.name"), b"credential").unwrap();

        let target_dir_str = target_dir.to_str().unwrap();
        let table = [PickUpCredential {
            credential_prefix: "match.",
            target_dir: target_dir_str,
            filename_suffix: "/escape",
        }];

        assert_eq!(
            pick_up_credentials_from_dir(source.path(), &table),
            Err(Errno::EINVAL.to_neg_errno())
        );
        // C validates the generated filename before mkdir_p_label().
        assert!(!target_dir.exists());
    }

    // -- constants --

    #[test]
    fn test_constants() {
        assert_eq!(CREDENTIAL_NAME_MAX, 255);
        assert_eq!(CREDENTIAL_SIZE_MAX, 1024 * 1024);
        assert_eq!(CREDENTIALS_TOTAL_SIZE_MAX, CREDENTIAL_SIZE_MAX);
        const { assert!(CREDENTIAL_ENCRYPTED_SIZE_MAX > CREDENTIAL_SIZE_MAX) };
        assert_eq!(
            CREDENTIAL_ENCRYPTED_SIZE_MAX,
            CREDENTIAL_SIZE_MAX + 128 * 1024
        );
    }

    // -- credential flags --

    // fn test_credential_secret_flags() {
    // assert_eq!(CredentialSecretFlags::GENERATE.0, 1);
    // assert_eq!(CredentialSecretFlags::WARN_NOT_ENCRYPTED.0, 2);
    // assert_eq!(CredentialSecretFlags::FAIL_ON_TEMPORARY_FS.0, 4);
    // }
    // fn test_credential_flags() {
    // assert_eq!(CredentialFlags::ALLOW_NULL.0, 1);
    // assert_eq!(CredentialFlags::REFUSE_NULL.0, 2);
    // assert_eq!(CredentialFlags::ANY_SCOPE.0, 4);
    // assert_eq!(CredentialFlags::IPC_ALLOW_INTERACTIVE.0, 8);
    // }

    // -- varlink errors --
    #[test]
    fn test_varlink_error_by_id() {
        let err = credentials_varlink_error_by_id("io.systemd.Credentials.BadFormat");
        assert!(err.is_some());
        assert_eq!(err.unwrap().errnum, libc::EBADMSG);
        assert_eq!(err.unwrap().msg, "Bad credential format.");
    }

    #[test]
    fn test_varlink_error_by_errno() {
        let err = credentials_varlink_error_by_errno(libc::EBADMSG);
        assert!(err.is_some());
        assert_eq!(err.unwrap().id, "io.systemd.Credentials.BadFormat");

        let err2 = credentials_varlink_error_by_errno(libc::EADDRNOTAVAIL);
        assert!(err2.is_some());
        assert_eq!(err2.unwrap().id, "io.systemd.Credentials.NVIndexUnusable");
    }

    #[test]
    fn test_varlink_error_missing() {
        assert!(credentials_varlink_error_by_id("nonexistent").is_none());
        assert!(credentials_varlink_error_by_errno(9999).is_none());
    }

    // -- system credentials dir --

    #[test]
    fn test_system_credentials_dir_default() {
        // When env var is unset, falls back to default
        let dir = get_system_credentials_dir().unwrap();
        assert_eq!(dir, Path::new(SYSTEM_CREDENTIALS_DIRECTORY));
    }

    #[test]
    fn test_encrypted_system_credentials_dir_default() {
        let dir = get_encrypted_system_credentials_dir().unwrap();
        assert_eq!(dir, Path::new(ENCRYPTED_SYSTEM_CREDENTIALS_DIRECTORY));
    }

    #[cfg(unix)]
    #[test]
    fn credential_directory_normalization_is_byte_oriented() {
        use std::os::unix::ffi::OsStrExt;

        assert!(path_is_normalized(OsStr::from_bytes(
            b"/run/credentials/\xff"
        )));
        assert!(!path_is_normalized(OsStr::from_bytes(b"/run//credentials")));
        assert!(!path_is_normalized(OsStr::from_bytes(
            b"/run/../credentials"
        )));

        let mut oversized_component = b"/run/".to_vec();
        oversized_component.extend(std::iter::repeat_n(b'x', libc::NAME_MAX as usize + 1));
        assert!(!path_is_normalized(OsStr::from_bytes(&oversized_component)));
    }

    // -- credential_name_valid accepts dot in name but not dot components --

    #[test]
    fn test_credential_name_valid_dot_in_name() {
        assert!(credential_name_valid("foo.bar.baz"));
        assert!(!credential_name_valid("."));
        assert!(!credential_name_valid(".."));
    }
}
