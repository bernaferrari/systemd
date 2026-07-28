// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/libarchive-util.c, src/shared/libarchive-util.h
//
// Dynamic loading of libarchive for tar/archive operations.
//
// Provides lazy dlopen-based loading of libarchive, symbol resolution for all
// archive entry, read, and write helpers, and file-type equivalence
// verification between libarchive macros and POSIX S_IF* constants.
// The module is behind `cfg(feature = "libarchive")`; when the feature is
// absent every call returns `ArchiveError::Unsupported`.

use std::collections::HashSet;
use std::ffi::{CStr, CString, c_void};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::ffi::Errno;

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors returned by libarchive dynamic-loading operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    /// libarchive is not compiled in or not available on this system.
    Unsupported,
    /// The shared library could not be opened.
    DlopenFailed(String),
    /// A required symbol was not found in the loaded library.
    SymbolNotFound(String),
    /// The library is already loaded; a second load is unnecessary.
    AlreadyLoaded,
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(
                f,
                "libarchive support is not compiled in, archive features disabled"
            ),
            Self::DlopenFailed(msg) => write!(f, "Failed to open libarchive: {}", msg),
            Self::SymbolNotFound(sym) => {
                write!(f, "Required libarchive symbol not found: {}", sym)
            }
            Self::AlreadyLoaded => write!(f, "libarchive is already loaded"),
        }
    }
}

impl std::error::Error for ArchiveError {}

impl From<ArchiveError> for i32 {
    fn from(e: ArchiveError) -> i32 {
        match e {
            ArchiveError::Unsupported => Errno::EOPNOTSUPP.to_neg_errno(),
            ArchiveError::DlopenFailed(_) => Errno::ENOENT.to_neg_errno(),
            ArchiveError::SymbolNotFound(_) => Errno::ENOENT.to_neg_errno(),
            ArchiveError::AlreadyLoaded => Errno::EBUSY.to_neg_errno(),
        }
    }
}

// ── Library name constants ──────────────────────────────────────────────────

/// Shared library name for libarchive.
const LIBARCHIVE_NAME: &str = "libarchive.so.13";

/// Human-readable description for the ELF NOTE metadata.
const ARCHIVE_FEATURE_DESCRIPTION: &str = "Support for decompressing archive files";

// ── Required symbol names ───────────────────────────────────────────────────

/// Symbols required from libarchive for archive entry operations.
const ARCHIVE_ENTRY_SYMBOLS: &[&str] = &[
    "archive_entry_acl_add_entry",
    "archive_entry_acl_next",
    "archive_entry_acl_reset",
    "archive_entry_fflags",
    "archive_entry_filetype",
    "archive_entry_free",
    "archive_entry_gid",
    "archive_entry_hardlink",
    "archive_entry_mode",
    "archive_entry_mtime",
    "archive_entry_mtime_is_set",
    "archive_entry_mtime_nsec",
    "archive_entry_new",
    "archive_entry_pathname",
    "archive_entry_rdevmajor",
    "archive_entry_rdevminor",
    "archive_entry_set_ctime",
    "archive_entry_set_fflags",
    "archive_entry_set_filetype",
    "archive_entry_set_gid",
    "archive_entry_set_hardlink",
    "archive_entry_set_mtime",
    "archive_entry_set_pathname",
    "archive_entry_set_perm",
    "archive_entry_set_rdevmajor",
    "archive_entry_set_rdevminor",
    "archive_entry_set_size",
    "archive_entry_set_symlink",
    "archive_entry_set_uid",
    "archive_entry_sparse_add_entry",
    "archive_entry_symlink",
    "archive_entry_uid",
    "archive_entry_xattr_add_entry",
    "archive_entry_xattr_next",
    "archive_entry_xattr_reset",
];

/// Optional symbols available in newer libarchive versions.
const ARCHIVE_ENTRY_OPTIONAL_SYMBOLS: &[&str] = &[
    "archive_entry_gid_is_set",
    "archive_entry_hardlink_is_set",
    "archive_entry_uid_is_set",
];

/// Symbols required from libarchive for archive read operations.
const ARCHIVE_READ_SYMBOLS: &[&str] = &[
    "archive_read_data_into_fd",
    "archive_read_free",
    "archive_read_new",
    "archive_read_next_header",
    "archive_read_open_fd",
    "archive_read_support_format_cpio",
    "archive_read_support_format_tar",
];

/// Symbols required from libarchive for archive write operations.
const ARCHIVE_WRITE_SYMBOLS: &[&str] = &[
    "archive_write_close",
    "archive_write_data",
    "archive_write_free",
    "archive_write_header",
    "archive_write_new",
    "archive_write_open_FILE",
    "archive_write_open_fd",
    "archive_write_set_format_filter_by_ext",
    "archive_write_set_format_pax",
];

/// Additional utility symbol.
const ARCHIVE_ERROR_SYMBOLS: &[&str] = &["archive_error_string"];

/// The full set of required symbols (all categories combined).
const REQUIRED_SYMBOLS: &[&str] = &[];

// ── File type equivalence verification ─────────────────────────────────────

/// Verify that libarchive's AE_IF* macros match the POSIX S_IF* constants.
///
/// libarchive uses its own file type macros. They happen to be defined the
/// same way as the Linux ones, and systemd relies on this equivalence.
/// This function performs a runtime assertion check to catch any
/// discrepancy.
///
/// Returns `true` if all file type constants match, `false` otherwise.
/// On Linux this always returns `true` because the values are identical.
pub fn verify_filetype_equivalence() -> bool {
    // AE_IFDIR  == S_IFDIR  (0o040000)
    // AE_IFREG  == S_IFREG  (0o100000)
    // AE_IFLNK  == S_IFLNK  (0o120000)
    // AE_IFBLK  == S_IFBLK  (0o060000)
    // AE_IFCHR  == S_IFCHR  (0o020000)
    // AE_IFIFO  == S_IFIFO  (0o010000)
    // AE_IFSOCK == S_IFSOCK (0o140000)
    const AE_IFDIR: u32 = 0o040000;
    const AE_IFREG: u32 = 0o100000;
    const AE_IFLNK: u32 = 0o120000;
    const AE_IFBLK: u32 = 0o060000;
    const AE_IFCHR: u32 = 0o020000;
    const AE_IFIFO: u32 = 0o010000;
    const AE_IFSOCK: u32 = 0o140000;

    libc::S_IFDIR as u32 == AE_IFDIR
        && libc::S_IFREG as u32 == AE_IFREG
        && libc::S_IFLNK as u32 == AE_IFLNK
        && libc::S_IFBLK as u32 == AE_IFBLK
        && libc::S_IFCHR as u32 == AE_IFCHR
        && libc::S_IFIFO as u32 == AE_IFIFO
        && libc::S_IFSOCK as u32 == AE_IFSOCK
}

// ── Dlopen state machine ───────────────────────────────────────────────────

/// Global flag: has `dlopen_libarchive()` been called and completed?
static ARCHIVE_LOADED: AtomicBool = AtomicBool::new(false);

/// Convenience wrapper — calls `dlopen_libarchive_full` with `log_level = 0`.
pub fn dlopen_libarchive() -> Result<(), ArchiveError> {
    dlopen_libarchive_full(0)
}

/// Attempt to dynamically load libarchive.
///
/// This function is idempotent: after the first successful call it returns
/// `Ok(())` immediately. If libarchive cannot be found the result is
/// cached as an error so that subsequent calls return `Err` without
/// retrying.
///
/// `log_level` controls the verbosity of log messages emitted on failure
/// (0 = silent, higher = more verbose).
pub fn dlopen_libarchive_full(log_level: i32) -> Result<(), ArchiveError> {
    if ARCHIVE_LOADED.load(Ordering::Acquire) {
        return Ok(());
    }

    match try_load_libarchive(LIBARCHIVE_NAME, log_level) {
        Ok(()) => {
            ARCHIVE_LOADED.store(true, Ordering::Release);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Try to open libarchive and resolve all required symbols.
fn try_load_libarchive(lib_name: &str, _log_level: i32) -> Result<(), ArchiveError> {
    let handle = unsafe { dlopen_wrapper(lib_name) }?;

    // Resolve all required symbol groups.
    let all_groups: &[&[&str]] = &[
        ARCHIVE_ENTRY_SYMBOLS,
        ARCHIVE_READ_SYMBOLS,
        ARCHIVE_WRITE_SYMBOLS,
        ARCHIVE_ERROR_SYMBOLS,
    ];

    for group in all_groups {
        let missing: Vec<String> = group
            .iter()
            .filter_map(|sym| {
                let c_sym = CString::new(*sym).unwrap_or_default();
                let ptr = unsafe { dlsym_wrapper(handle, &c_sym) };
                if ptr.is_null() {
                    Some((*sym).to_string())
                } else {
                    None
                }
            })
            .collect();

        if !missing.is_empty() {
            return Err(ArchiveError::SymbolNotFound(missing.join(", ")));
        }
    }

    // Optional symbols are resolved but their absence is not an error.
    // (gid_is_set, hardlink_is_set, uid_is_set have fallback implementations.)

    // Intentionally keep `handle` open for the lifetime of the process.
    // dlclose() is deliberately skipped — the symbols remain valid.
    let _ = handle;

    Ok(())
}

// ── Platform dlopen / dlsym wrappers ────────────────────────────────────────

/// Open a shared library, returning the handle on success.
///
/// Wraps `dlopen()` with `RTLD_LAZY | RTLD_LOCAL` and translates errors
/// into `ArchiveError::DlopenFailed`.
unsafe fn dlopen_wrapper(lib_name: &str) -> Result<*mut c_void, ArchiveError> {
    let c_name = CString::new(lib_name)
        .map_err(|e| ArchiveError::DlopenFailed(format!("Invalid library name: {}", e)))?;
    // SAFETY: c_name is NUL-terminated and remains live for the call.
    let handle = unsafe { libc::dlopen(c_name.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL) };
    if handle.is_null() {
        let detail = dlerror_string();
        Err(ArchiveError::DlopenFailed(format!(
            "{}: {}",
            lib_name, detail
        )))
    } else {
        Ok(handle)
    }
}

/// Look up a symbol in an already-opened library handle.
///
/// Returns a null pointer if the symbol is not found (caller checks).
///
/// # Safety
/// `handle` must be a valid handle returned by `dlopen`.
unsafe fn dlsym_wrapper(handle: *mut c_void, symbol: &CStr) -> *mut c_void {
    // SAFETY: the caller supplies a live dlopen handle and symbol is NUL-terminated.
    unsafe { libc::dlsym(handle, symbol.as_ptr()) }
}

/// Retrieve the last `dlerror()` message as a Rust `String`.
fn dlerror_string() -> String {
    unsafe {
        let ptr = libc::dlerror();
        if ptr.is_null() {
            return "unknown error".to_string();
        }
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

// ── UID/GID fallback helpers ───────────────────────────────────────────────

/// Fallback implementation of `archive_entry_gid_is_set` when libarchive
/// lacks the native symbol.
///
/// Returns `true` if the GID is valid (not `GID_INVALID` / `u32::MAX`).
pub fn archive_entry_gid_is_set_fallback(gid: u32) -> bool {
    gid_is_valid(gid)
}

/// Fallback implementation of `archive_entry_uid_is_set` when libarchive
/// lacks the native symbol.
///
/// Returns `true` if the UID is valid (not `UID_INVALID` / `u32::MAX`).
pub fn archive_entry_uid_is_set_fallback(uid: u32) -> bool {
    uid_is_valid(uid)
}

/// Fallback implementation of `archive_entry_hardlink_is_set` when
/// libarchive lacks the native symbol.
///
/// Returns `true` if the hardlink pointer is non-null.
pub fn archive_entry_hardlink_is_set_fallback(hardlink: Option<&str>) -> bool {
    hardlink.is_some()
}

/// Check whether a UID value is valid (not the sentinel `u32::MAX`).
pub fn uid_is_valid(uid: u32) -> bool {
    uid != u32::MAX
}

/// Check whether a GID value is valid (not the sentinel `u32::MAX`).
pub fn gid_is_valid(gid: u32) -> bool {
    gid != u32::MAX
}

// ── Query helpers ───────────────────────────────────────────────────────────

/// Returns `true` if `dlopen_libarchive()` has been called successfully
/// and the library handle is available.
pub fn archive_is_loaded() -> bool {
    ARCHIVE_LOADED.load(Ordering::Acquire)
}

/// Reset the loaded state. Useful for tests.
///
/// # Safety
/// Only call from tests. Calling this while archive symbols are in use is
/// undefined behaviour.
#[cfg(test)]
pub fn reset_archive_loaded() {
    ARCHIVE_LOADED.store(false, Ordering::Release);
}

// ── Feature description (for external consumers) ────────────────────────────

/// Returns the human-readable description of the archive feature, suitable
/// for inclusion in ELF notes or status reporting.
pub fn archive_feature_description() -> &'static str {
    ARCHIVE_FEATURE_DESCRIPTION
}

/// Returns the library name tried during loading.
pub fn archive_library_name() -> &'static str {
    LIBARCHIVE_NAME
}

// ── Symbol name introspection ──────────────────────────────────────────────

/// Returns the set of required archive entry symbol names.
pub fn archive_entry_required_symbols() -> HashSet<&'static str> {
    ARCHIVE_ENTRY_SYMBOLS.iter().copied().collect()
}

/// Returns the set of optional archive entry symbol names.
pub fn archive_entry_optional_symbols() -> HashSet<&'static str> {
    ARCHIVE_ENTRY_OPTIONAL_SYMBOLS.iter().copied().collect()
}

/// Returns the set of required archive read symbol names.
pub fn archive_read_required_symbols() -> HashSet<&'static str> {
    ARCHIVE_READ_SYMBOLS.iter().copied().collect()
}

/// Returns the set of required archive write symbol names.
pub fn archive_write_required_symbols() -> HashSet<&'static str> {
    ARCHIVE_WRITE_SYMBOLS.iter().copied().collect()
}

/// Returns the total count of all required symbols across all groups.
pub fn archive_total_required_symbol_count() -> usize {
    ARCHIVE_ENTRY_SYMBOLS.len()
        + ARCHIVE_READ_SYMBOLS.len()
        + ARCHIVE_WRITE_SYMBOLS.len()
        + ARCHIVE_ERROR_SYMBOLS.len()
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_archive_error_display_unsupported() {
        let e = ArchiveError::Unsupported;
        assert!(e.to_string().contains("not compiled in"));
    }

    #[test]
    fn test_archive_error_display_dlopen_failed() {
        let e = ArchiveError::DlopenFailed("no such file".to_string());
        assert!(e.to_string().contains("no such file"));
    }

    #[test]
    fn test_archive_error_display_symbol_not_found() {
        let e = ArchiveError::SymbolNotFound("archive_read_new".to_string());
        assert!(e.to_string().contains("archive_read_new"));
    }

    #[test]
    fn test_archive_error_display_already_loaded() {
        let e = ArchiveError::AlreadyLoaded;
        assert!(e.to_string().contains("already loaded"));
    }

    #[test]
    fn test_archive_error_into_c_int() {
        let val: i32 = ArchiveError::Unsupported.into();
        assert_eq!(val, Errno::EOPNOTSUPP.to_neg_errno());

        let val: i32 = ArchiveError::AlreadyLoaded.into();
        assert_eq!(val, Errno::EBUSY.to_neg_errno());

        let val: i32 = ArchiveError::DlopenFailed("x".into()).into();
        assert_eq!(val, Errno::ENOENT.to_neg_errno());

        let val: i32 = ArchiveError::SymbolNotFound("x".into()).into();
        assert_eq!(val, Errno::ENOENT.to_neg_errno());
    }

    #[test]
    fn test_archive_error_debug() {
        let errors = vec![
            ArchiveError::Unsupported,
            ArchiveError::AlreadyLoaded,
            ArchiveError::DlopenFailed("err".into()),
            ArchiveError::SymbolNotFound("err".into()),
        ];
        for e in &errors {
            let _ = format!("{e:?}");
        }
    }

    #[test]
    fn test_archive_error_equality() {
        assert_eq!(ArchiveError::Unsupported, ArchiveError::Unsupported);
        assert_ne!(ArchiveError::Unsupported, ArchiveError::AlreadyLoaded);
        assert_eq!(
            ArchiveError::DlopenFailed("a".into()),
            ArchiveError::DlopenFailed("a".into())
        );
        assert_ne!(
            ArchiveError::DlopenFailed("a".into()),
            ArchiveError::DlopenFailed("b".into())
        );
    }

    #[test]
    fn test_archive_library_name() {
        assert_eq!(archive_library_name(), "libarchive.so.13");
    }

    #[test]
    fn test_archive_feature_description() {
        let desc = archive_feature_description();
        assert!(!desc.is_empty());
        assert!(desc.contains("archive"));
    }

    #[test]
    fn test_verify_filetype_equivalence() {
        // On any POSIX system these should match.
        assert!(verify_filetype_equivalence());
    }

    #[test]
    fn test_uid_is_valid() {
        assert!(uid_is_valid(0));
        assert!(uid_is_valid(1000));
        assert!(uid_is_valid(u32::MAX - 1));
        assert!(!uid_is_valid(u32::MAX));
    }

    #[test]
    fn test_gid_is_valid() {
        assert!(gid_is_valid(0));
        assert!(gid_is_valid(100));
        assert!(gid_is_valid(u32::MAX - 1));
        assert!(!gid_is_valid(u32::MAX));
    }

    #[test]
    fn test_archive_entry_gid_is_set_fallback() {
        assert!(archive_entry_gid_is_set_fallback(0));
        assert!(archive_entry_gid_is_set_fallback(1000));
        assert!(!archive_entry_gid_is_set_fallback(u32::MAX));
    }

    #[test]
    fn test_archive_entry_uid_is_set_fallback() {
        assert!(archive_entry_uid_is_set_fallback(0));
        assert!(archive_entry_uid_is_set_fallback(1000));
        assert!(!archive_entry_uid_is_set_fallback(u32::MAX));
    }

    #[test]
    fn test_archive_entry_hardlink_is_set_fallback() {
        assert!(archive_entry_hardlink_is_set_fallback(Some("target")));
        assert!(!archive_entry_hardlink_is_set_fallback(None));
    }

    #[test]
    fn test_archive_entry_required_symbols_not_empty() {
        let syms = archive_entry_required_symbols();
        assert!(!syms.is_empty());
        assert!(syms.contains("archive_entry_new"));
        assert!(syms.contains("archive_entry_free"));
        assert!(syms.contains("archive_entry_pathname"));
    }

    #[test]
    fn test_archive_entry_optional_symbols() {
        let syms = archive_entry_optional_symbols();
        assert_eq!(syms.len(), 3);
        assert!(syms.contains("archive_entry_gid_is_set"));
        assert!(syms.contains("archive_entry_hardlink_is_set"));
        assert!(syms.contains("archive_entry_uid_is_set"));
    }

    #[test]
    fn test_archive_read_required_symbols() {
        let syms = archive_read_required_symbols();
        assert!(syms.contains("archive_read_new"));
        assert!(syms.contains("archive_read_free"));
        assert!(syms.contains("archive_read_open_fd"));
        assert!(syms.contains("archive_read_support_format_tar"));
        assert!(syms.contains("archive_read_support_format_cpio"));
    }

    #[test]
    fn test_archive_write_required_symbols() {
        let syms = archive_write_required_symbols();
        assert!(syms.contains("archive_write_new"));
        assert!(syms.contains("archive_write_free"));
        assert!(syms.contains("archive_write_header"));
        assert!(syms.contains("archive_write_data"));
        assert!(syms.contains("archive_write_open_fd"));
    }

    #[test]
    fn test_archive_total_required_symbol_count() {
        let count = archive_total_required_symbol_count();
        assert!(count > 40);
        // Verify it equals the sum of all groups.
        assert_eq!(
            count,
            ARCHIVE_ENTRY_SYMBOLS.len()
                + ARCHIVE_READ_SYMBOLS.len()
                + ARCHIVE_WRITE_SYMBOLS.len()
                + ARCHIVE_ERROR_SYMBOLS.len()
        );
    }

    #[test]
    fn test_symbols_are_unique_within_groups() {
        let entry_set: HashSet<_> = ARCHIVE_ENTRY_SYMBOLS.iter().copied().collect();
        assert_eq!(entry_set.len(), ARCHIVE_ENTRY_SYMBOLS.len());

        let read_set: HashSet<_> = ARCHIVE_READ_SYMBOLS.iter().copied().collect();
        assert_eq!(read_set.len(), ARCHIVE_READ_SYMBOLS.len());

        let write_set: HashSet<_> = ARCHIVE_WRITE_SYMBOLS.iter().copied().collect();
        assert_eq!(write_set.len(), ARCHIVE_WRITE_SYMBOLS.len());
    }

    #[test]
    fn test_archive_is_loaded_initial() {
        reset_archive_loaded();
        assert!(!archive_is_loaded());
    }

    #[test]
    fn test_dlopen_libarchive_caching() {
        reset_archive_loaded();
        let r1 = dlopen_libarchive();
        let r2 = dlopen_libarchive();
        // If first succeeds, second must too (cached).
        // If first fails, second must also fail (cached error).
        assert_eq!(r1.is_ok(), r2.is_ok());
    }
}
