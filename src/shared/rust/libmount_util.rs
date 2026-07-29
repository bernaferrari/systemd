// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/libmount-util.c, src/shared/libmount-util.h
//
// libmount utilities — mount table parsing via dlopen of libmount,
// mnt_table_find_target, mnt_table_next_fs, mount info from /proc/self/mountinfo.

use crate::ffi::*;
use std::ffi::{CStr, CString, c_void};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use systemd_basic_rs::dlfcn_util::{PublishedDlopenHandle, UnpublishedDlopenHandle};

// ── Constants ─────────────────────────────────────────────────────────────

/// Forward iteration direction for mount table traversal.
pub const MNT_ITER_FORWARD: i32 = 0;
/// Backward iteration direction for mount table traversal.
pub const MNT_ITER_BACKWARD: i32 = 1;
/// Default libmount shared library soname.
pub const LIBMOUNT_SONAME: &str = "libmount.so.1";

/// Symbols required for core mount table operations.
#[cfg(target_os = "linux")]
const REQUIRED_SYMBOLS: &[&[u8]] = &[
    b"mnt_new_table\0",
    b"mnt_free_table\0",
    b"mnt_new_iter\0",
    b"mnt_free_iter\0",
    b"mnt_table_parse_file\0",
    b"mnt_table_parse_mtab\0",
    b"mnt_table_next_fs\0",
    b"mnt_table_find_target\0",
    b"mnt_table_find_devno\0",
    b"mnt_table_next_child_fs\0",
    b"mnt_fs_get_source\0",
    b"mnt_fs_get_target\0",
    b"mnt_fs_get_fstype\0",
    b"mnt_fs_get_options\0",
    b"mnt_fs_get_vfs_options\0",
    b"mnt_fs_get_fs_options\0",
    b"mnt_fs_get_id\0",
    b"mnt_fs_get_passno\0",
    b"mnt_fs_get_propagation\0",
    b"mnt_fs_get_option\0",
    b"mnt_optstr_get_flags\0",
    b"mnt_get_builtin_optmap\0",
    b"mnt_init_debug\0",
    b"mnt_new_monitor\0",
    b"mnt_unref_monitor\0",
    b"mnt_monitor_enable_kernel\0",
    b"mnt_monitor_enable_userspace\0",
    b"mnt_monitor_get_fd\0",
    b"mnt_monitor_next_change\0",
    b"mnt_table_parse_stream\0",
    b"mnt_table_parse_swaps\0",
];

// ── Error types ───────────────────────────────────────────────────────────

/// Errors from libmount operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LibmountError {
    /// libmount shared library could not be loaded.
    DlopenFailed(String),
    /// A required symbol was not found in libmount.
    SymbolNotFound(String),
    /// A libmount operation returned an error code.
    OperationFailed(i32, String),
    /// Memory allocation failure.
    OutOfMemory,
    /// I/O error reading mount data.
    Io(io::ErrorKind, String),
    /// Invalid argument passed to a function.
    InvalidArgument(String),
    /// Operation not supported (e.g. libmount not available).
    NotSupported,
}

impl fmt::Display for LibmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DlopenFailed(msg) => write!(f, "failed to dlopen libmount: {msg}"),
            Self::SymbolNotFound(name) => write!(f, "symbol not found in libmount: {name}"),
            Self::OperationFailed(rc, msg) => {
                write!(f, "libmount operation failed ({rc}): {msg}")
            }
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::Io(kind, msg) => write!(f, "I/O error ({kind}): {msg}"),
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::NotSupported => write!(f, "libmount not supported"),
        }
    }
}

impl std::error::Error for LibmountError {}

impl From<io::Error> for LibmountError {
    fn from(e: io::Error) -> Self {
        LibmountError::Io(e.kind(), e.to_string())
    }
}

// ── Iteration direction ───────────────────────────────────────────────────

/// Direction for mount table iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IterDirection {
    /// Iterate from first to last entry.
    Forward,
    /// Iterate from last to first entry.
    Backward,
}

impl IterDirection {
    /// Convert to the libmount `i32` constant.
    pub fn as_raw(self) -> i32 {
        match self {
            Self::Forward => MNT_ITER_FORWARD,
            Self::Backward => MNT_ITER_BACKWARD,
        }
    }
}

impl TryFrom<i32> for IterDirection {
    type Error = LibmountError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            MNT_ITER_FORWARD => Ok(Self::Forward),
            MNT_ITER_BACKWARD => Ok(Self::Backward),
            _ => Err(LibmountError::InvalidArgument(format!(
                "invalid iteration direction: {value}"
            ))),
        }
    }
}

// ── Mount info entry ──────────────────────────────────────────────────────

/// A parsed entry from `/proc/self/mountinfo`.
///
/// Each line in mountinfo has the format:
/// ```text
/// mount_id parent_id major:minor root mount_point options [optional...] - fs_type source super_opts
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountInfoEntry {
    /// Unique mount identifier assigned by the kernel.
    pub mount_id: u64,
    /// Mount identifier of the parent mount (0 for root).
    pub parent_id: u64,
    /// Major device number.
    pub major: u32,
    /// Minor device number.
    pub minor: u32,
    /// Path of the directory in the filesystem forming the root of this mount.
    pub root: String,
    /// Path of the mount point relative to the process root.
    pub mount_point: String,
    /// Per-mount options (e.g. "rw,noatime").
    pub mount_options: String,
    /// Optional tag=value fields between options and the " - " separator.
    pub optional_fields: Vec<String>,
    /// Filesystem type (e.g. "ext4", "tmpfs").
    pub fs_type: String,
    /// Mount source (device name, label, UUID, etc.).
    pub mount_source: String,
    /// Superblock options.
    pub super_options: String,
}

impl MountInfoEntry {
    /// Parse a single line from `/proc/self/mountinfo`.
    ///
    /// # Errors
    /// Returns `LibmountError::InvalidArgument` if the line format is invalid.
    pub fn parse_line(line: &str) -> Result<Self, LibmountError> {
        let line = line.trim();
        if line.is_empty() {
            return Err(LibmountError::InvalidArgument(
                "empty mountinfo line".into(),
            ));
        }

        // The " - " separator divides optional fields from trailing fields.
        let sep_pos = line.find(" - ").ok_or_else(|| {
            LibmountError::InvalidArgument("missing ' - ' separator in mountinfo line".into())
        })?;

        let before_sep = &line[..sep_pos];
        let after_sep = &line[sep_pos + 3..];

        // Mandatory fields before separator:
        //   mount_id parent_id major:minor root mount_point options
        let before: Vec<&str> = before_sep.split_whitespace().collect();
        if before.len() < 6 {
            return Err(LibmountError::InvalidArgument(format!(
                "expected at least 6 fields before ' - ', got {}",
                before.len()
            )));
        }

        let mount_id = before[0].parse::<u64>().map_err(|_| {
            LibmountError::InvalidArgument(format!("invalid mount_id: {}", before[0]))
        })?;
        let parent_id = before[1].parse::<u64>().map_err(|_| {
            LibmountError::InvalidArgument(format!("invalid parent_id: {}", before[1]))
        })?;
        let (major, minor) = parse_devno(before[2])?;
        let root = before[3].to_string();
        let mount_point = before[4].to_string();
        let mount_options = before[5].to_string();

        // Fields from index 6 onward are optional tag=value pairs.
        let optional_fields: Vec<String> = before[6..].iter().map(|s| s.to_string()).collect();

        // Trailing fields after " - ": fs_type mount_source super_options
        let after: Vec<&str> = after_sep.split_whitespace().collect();
        if after.len() < 3 {
            return Err(LibmountError::InvalidArgument(format!(
                "expected at least 3 fields after ' - ', got {}",
                after.len()
            )));
        }

        Ok(MountInfoEntry {
            mount_id,
            parent_id,
            major,
            minor,
            root,
            mount_point,
            mount_options,
            optional_fields,
            fs_type: after[0].to_string(),
            mount_source: after[1].to_string(),
            super_options: after[2..].join(" "),
        })
    }

    /// Parse all entries from mountinfo file content.
    pub fn parse_all(content: &str) -> Result<Vec<Self>, LibmountError> {
        let mut entries = Vec::new();
        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            entries.push(
                Self::parse_line(trimmed)
                    .map_err(|e| LibmountError::InvalidArgument(format!("line {}: {e}", i + 1)))?,
            );
        }
        Ok(entries)
    }

    /// Read and parse `/proc/self/mountinfo`.
    #[cfg(target_os = "linux")]
    pub fn read_mountinfo() -> Result<Vec<Self>, LibmountError> {
        let content = std::fs::read_to_string("/proc/self/mountinfo")?;
        Self::parse_all(&content)
    }

    /// Check whether this mount is a leaf (has no child mounts) in the given
    /// entry list.
    ///
    /// A leaf mount is one where no other entry's `parent_id` equals this
    /// entry's `mount_id`.
    pub fn is_leaf_in(&self, entries: &[Self]) -> bool {
        let my_id = self.mount_id;
        !entries
            .iter()
            .any(|e| e.parent_id == my_id && e.mount_id != my_id)
    }

    /// Return the device number as `(major, minor)`.
    pub fn devno(&self) -> (u32, u32) {
        (self.major, self.minor)
    }
}

/// Parse a `"major:minor"` device number string.
fn parse_devno(s: &str) -> Result<(u32, u32), LibmountError> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(LibmountError::InvalidArgument(format!(
            "invalid device number '{s}', expected 'major:minor'"
        )));
    }
    let major = parts[0].parse::<u32>().map_err(|_| {
        LibmountError::InvalidArgument(format!("invalid major number: {}", parts[0]))
    })?;
    let minor = parts[1].parse::<u32>().map_err(|_| {
        LibmountError::InvalidArgument(format!("invalid minor number: {}", parts[1]))
    })?;
    Ok((major, minor))
}

// ── Directional iterator ──────────────────────────────────────────────────

/// Iterator over mount table entries in either forward or backward order.
pub enum MountIter<'a> {
    Forward(std::slice::Iter<'a, MountInfoEntry>),
    Backward(std::iter::Rev<std::slice::Iter<'a, MountInfoEntry>>),
}

impl<'a> Iterator for MountIter<'a> {
    type Item = &'a MountInfoEntry;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Forward(inner) => inner.next(),
            Self::Backward(inner) => inner.next(),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Forward(inner) => inner.size_hint(),
            Self::Backward(inner) => inner.size_hint(),
        }
    }
}

// ── Mount table ───────────────────────────────────────────────────────────

/// A collection of parsed mount entries with lookup capabilities.
///
/// Provides the same query interface as libmnt_table (find_target,
/// find_devno, next_fs iteration) but backed by pure Rust data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountTable {
    entries: Vec<MountInfoEntry>,
}

impl MountTable {
    /// Create a new empty mount table.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Build a mount table from a pre-parsed entry list.
    pub fn from_entries(entries: Vec<MountInfoEntry>) -> Self {
        Self { entries }
    }

    /// Parse a mount table from the textual content of a mountinfo file.
    pub fn parse(content: &str) -> Result<Self, LibmountError> {
        Ok(Self {
            entries: MountInfoEntry::parse_all(content)?,
        })
    }

    /// Read and parse `/proc/self/mountinfo` into a mount table.
    #[cfg(target_os = "linux")]
    pub fn from_mountinfo() -> Result<Self, LibmountError> {
        Ok(Self {
            entries: MountInfoEntry::read_mountinfo()?,
        })
    }

    /// Find an entry by mount point path.
    pub fn find_target(&self, target: &str) -> Option<&MountInfoEntry> {
        self.entries.iter().find(|e| e.mount_point == target)
    }

    /// Find an entry by device number `(major, minor)`.
    pub fn find_devno(&self, major: u32, minor: u32) -> Option<&MountInfoEntry> {
        self.entries
            .iter()
            .find(|e| e.major == major && e.minor == minor)
    }

    /// Iterate entries in the given direction.
    pub fn iter_dir(&self, direction: IterDirection) -> MountIter<'_> {
        match direction {
            IterDirection::Forward => MountIter::Forward(self.entries.iter()),
            IterDirection::Backward => MountIter::Backward(self.entries.iter().rev()),
        }
    }

    /// Number of entries in the table.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Access the underlying entry slice.
    pub fn entries(&self) -> &[MountInfoEntry] {
        &self.entries
    }

    /// Check whether a mount entry is a leaf in this table.
    pub fn is_leaf(&self, entry: &MountInfoEntry) -> bool {
        entry.is_leaf_in(&self.entries)
    }
}

impl Default for MountTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── libmount dlopen wrapper ───────────────────────────────────────────────

/// Handle to the dynamically loaded libmount shared library.
///
/// The handle follows C's `dlopen_many_sym_or_warn()` lifetime: once every
/// required symbol has been validated, its reference is retained for the
/// process lifetime. Function-pointer calls remain encapsulated behind the
/// typed operations below.
#[cfg(target_os = "linux")]
pub struct LibmountLibrary {
    handle: PublishedDlopenHandle,
}

/// C's `dlopen_libmount()` stores one successful handle in a static variable
/// and retries only failures. Keep the same success-only cache: callers share
/// the process-lifetime reference, while a temporary loader failure does not
/// prevent a later retry after the environment has changed.
#[cfg(target_os = "linux")]
static LIBMOUNT_HANDLE: OnceLock<Mutex<Option<PublishedDlopenHandle>>> = OnceLock::new();

#[cfg(target_os = "linux")]
impl LibmountLibrary {
    /// Open `libmount.so.1` through systemd's loader policy and verify that
    /// all required symbols are resolvable.
    ///
    /// Equivalent to the C `dlopen_libmount()`.
    ///
    /// # Errors
    /// - `DlopenFailed` if the shared library cannot be loaded.
    /// - `SymbolNotFound` if any required symbol is missing.
    pub fn open() -> Result<Self, LibmountError> {
        let cache = LIBMOUNT_HANDLE.get_or_init(|| Mutex::new(None));
        // A panic while loading cannot invalidate a published handle: it is
        // immutable and deliberately process-lifetime. Retain such a value
        // rather than turning an unrelated historical panic into a loader
        // failure for every subsequent caller.
        let mut cache = cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(handle) = *cache {
            return Ok(Self { handle });
        }

        let handle = UnpublishedDlopenHandle::open(LIBMOUNT_SONAME)
            .map_err(|error| LibmountError::DlopenFailed(error.to_string()))?;

        // Verify all required symbols upfront (mirrors the C dlopen_many_sym_or_warn).
        for &name in REQUIRED_SYMBOLS {
            let symbol = Self::symbol_name(name)?;
            handle
                .resolve_required(symbol)
                .map_err(|error| LibmountError::SymbolNotFound(error.to_string()))?;
        }

        let handle = handle.publish();
        *cache = Some(handle);
        Ok(Self { handle })
    }

    /// Check whether libmount is available and initialize its shared loader
    /// cache on the first successful call.
    ///
    /// Returns `Ok(true)` if the library can be loaded and all required
    /// symbols are present, `Ok(false)` if loading fails gracefully, or
    /// `Err` for unexpected failures.
    pub fn is_available() -> Result<bool, LibmountError> {
        match Self::open() {
            Ok(_) => Ok(true),
            Err(LibmountError::DlopenFailed(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    // ── internal symbol resolution ──────────────────────────────────────

    /// Interpret a static NUL-terminated libmount symbol spelling as UTF-8.
    fn symbol_name(name: &[u8]) -> Result<&str, LibmountError> {
        CStr::from_bytes_until_nul(name)
            .ok()
            .and_then(|name| name.to_str().ok())
            .ok_or_else(|| LibmountError::InvalidArgument(format!("invalid symbol name: {name:?}")))
    }

    /// Resolve a NUL-terminated symbol name through the retained loader
    /// handle. The returned pointer is not callable until the caller selects
    /// and validates its exact C function signature.
    fn resolve_raw(&self, name: &[u8]) -> Result<*mut c_void, LibmountError> {
        let symbol = Self::symbol_name(name)?;
        self.handle
            .resolve_required(symbol)
            .map(|pointer| pointer.as_ptr())
            .map_err(|error| LibmountError::SymbolNotFound(error.to_string()))
    }

    /// Transmute a raw symbol pointer to a typed function pointer.
    ///
    /// # Safety
    /// `T` must exactly match the C function's signature.
    unsafe fn resolve_fn<T>(&self, name: &[u8]) -> Result<T, LibmountError> {
        // SAFETY: the caller guarantees T matches the named symbol's signature.
        let ptr = self.resolve_raw(name)?;
        // SAFETY: the same caller contract covers the pointer-to-function conversion.
        Ok(unsafe { std::mem::transmute_copy(&ptr) })
    }

    /// Read a `const char *` return from a libmnt_fs accessor.
    ///
    /// # Safety
    /// `fs` must be a valid pointer to a `libmnt_fs` and `symbol_name`
    /// must name a function with signature `const char *(*)(struct libmnt_fs *)`.
    unsafe fn fs_get_string(
        &self,
        fs: *mut c_void,
        symbol_name: &[u8],
    ) -> Result<String, LibmountError> {
        // SAFETY: `fs_get_string` only accepts the five libmnt_fs accessors
        // declared in REQUIRED_SYMBOLS, all of which have this signature in
        // libmount.h.
        let func: extern "C" fn(*mut c_void) -> *const libc::c_char =
            // SAFETY: the caller guarantees symbol_name identifies this exact accessor signature.
            unsafe { self.resolve_fn(symbol_name) }?;
        // SAFETY: the caller guarantees fs is a live libmnt_fs pointer.
        let ptr = func(fs);
        if ptr.is_null() {
            Ok(String::new())
        } else {
            // SAFETY: a non-null accessor result is a NUL-terminated string owned by libmount.
            Ok(unsafe { CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned())
        }
    }

    // ── public table operations ────────────────────────────────────────

    /// Parse a mount table from a file path or from the system mtab.
    ///
    /// Equivalent to the C `libmount_parse_full()`.
    ///
    /// - `path`: File to parse.  If `None`, falls back to `mnt_table_parse_mtab`.
    /// - `direction`: Iteration order for subsequent traversal.
    ///
    /// Returns a [`MountTable`] containing all parsed entries converted to
    /// native Rust types.
    pub fn parse_full(
        &self,
        path: Option<&str>,
        direction: IterDirection,
    ) -> Result<MountTable, LibmountError> {
        // ── create table + iter via libmount ───────────────────────────
        // SAFETY: mnt_new_table has this no-argument pointer-returning
        // signature in libmount.h.
        let new_table: extern "C" fn() -> *mut c_void =
            unsafe { self.resolve_fn(b"mnt_new_table\0") }?;
        // SAFETY: mnt_new_iter takes libmount's integer direction constant
        // and returns an owned iterator pointer.
        let new_iter: extern "C" fn(i32) -> *mut c_void =
            unsafe { self.resolve_fn(b"mnt_new_iter\0") }?;
        // SAFETY: mnt_free_table consumes a table allocated by mnt_new_table.
        let free_table: extern "C" fn(*mut c_void) =
            unsafe { self.resolve_fn(b"mnt_free_table\0") }?;
        // SAFETY: mnt_free_iter consumes an iterator allocated by mnt_new_iter.
        let free_iter: extern "C" fn(*mut c_void) = unsafe { self.resolve_fn(b"mnt_free_iter\0") }?;
        // SAFETY: mnt_table_next_fs has this table/iterator/output-pointer
        // signature in libmount.h.
        let next_fs: extern "C" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> i32 =
            unsafe { self.resolve_fn(b"mnt_table_next_fs\0") }?;

        // SAFETY: new_table has the documented libmount signature and has
        // been resolved from the validated process-lifetime library.
        let table_ptr = new_table();
        if table_ptr.is_null() {
            return Err(LibmountError::OutOfMemory);
        }
        // SAFETY: new_iter has the documented libmount signature and
        // direction is one of libmount's two iteration constants.
        let iter_ptr = new_iter(direction.as_raw());
        if iter_ptr.is_null() {
            // SAFETY: table_ptr was returned by mnt_new_table above and has
            // not been released yet.
            free_table(table_ptr);
            return Err(LibmountError::OutOfMemory);
        }

        let result = (|| {
            // ── parse source ───────────────────────────────────────────
            let rc = if let Some(p) = path {
                let c_path = CString::new(p)
                    .map_err(|_| LibmountError::InvalidArgument("NUL in path".into()))?;
                // SAFETY: mnt_table_parse_file takes a live table and a
                // NUL-terminated path, exactly as supplied below.
                let parse_file: extern "C" fn(*mut c_void, *const libc::c_char) -> i32 =
                    unsafe { self.resolve_fn(b"mnt_table_parse_file\0") }?;
                // SAFETY: table_ptr is valid, c_path is NUL-terminated.
                parse_file(table_ptr, c_path.as_ptr())
            } else {
                // SAFETY: mnt_table_parse_mtab takes a live table and an
                // optional path pointer; NULL requests the system mtab.
                let parse_mtab: extern "C" fn(*mut c_void, *const libc::c_char) -> i32 =
                    unsafe { self.resolve_fn(b"mnt_table_parse_mtab\0") }?;
                // SAFETY: table_ptr is valid, NULL path means "use default mtab".
                parse_mtab(table_ptr, std::ptr::null())
            };

            if rc < 0 {
                return Err(LibmountError::OperationFailed(
                    rc,
                    "mnt_table_parse_file/mtab".into(),
                ));
            }

            // ── iterate all entries → Rust ─────────────────────────────
            let mut entries = Vec::new();
            loop {
                let mut fs: *mut c_void = std::ptr::null_mut();
                // SAFETY: table_ptr, iter_ptr, and the writable `fs` output
                // slot remain valid for this call.
                let rc = next_fs(table_ptr, iter_ptr, &mut fs);
                if rc < 0 {
                    return Err(LibmountError::OperationFailed(
                        rc,
                        "mnt_table_next_fs".into(),
                    ));
                }
                if rc > 0 {
                    break;
                }
                if fs.is_null() {
                    return Err(LibmountError::OperationFailed(
                        -libc::EIO,
                        "mnt_table_next_fs returned a null filesystem".into(),
                    ));
                }

                // SAFETY: next_fs returned a live filesystem owned by
                // table_ptr, which remains allocated until after this closure.
                let source = unsafe { self.fs_get_string(fs, b"mnt_fs_get_source\0") }?;
                // SAFETY: same live libmnt_fs object as above.
                let target = unsafe { self.fs_get_string(fs, b"mnt_fs_get_target\0") }?;
                // SAFETY: same live libmnt_fs object as above.
                let fstype = unsafe { self.fs_get_string(fs, b"mnt_fs_get_fstype\0") }?;
                // SAFETY: same live libmnt_fs object as above.
                let options = unsafe { self.fs_get_string(fs, b"mnt_fs_get_options\0") }?;
                // SAFETY: same live libmnt_fs object as above.
                let vfs_opts = unsafe { self.fs_get_string(fs, b"mnt_fs_get_vfs_options\0") }?;

                entries.push(MountInfoEntry {
                    mount_id: 0,
                    parent_id: 0,
                    major: 0,
                    minor: 0,
                    root: String::new(),
                    mount_point: target,
                    mount_options: options,
                    optional_fields: Vec::new(),
                    fs_type: fstype,
                    mount_source: source,
                    super_options: vfs_opts,
                });
            }

            Ok(MountTable::from_entries(entries))
        })();

        // Both allocations succeeded above and their contents are no longer
        // borrowed once the closure has returned, regardless of error.
        free_table(table_ptr);
        free_iter(iter_ptr);

        result
    }

    /// Parse the system fstab using libmount.
    ///
    /// Equivalent to the C `libmount_parse_fstab()`.
    pub fn parse_fstab(&self) -> Result<MountTable, LibmountError> {
        let path = crate::fstab_util::fstab_path();
        let s = path.to_str().ok_or_else(|| {
            LibmountError::InvalidArgument("fstab path is not valid UTF-8".into())
        })?;
        self.parse_full(Some(s), IterDirection::Forward)
    }

    /// Parse `/proc/self/mountinfo` via libmount.
    ///
    /// Equivalent to the C inline `libmount_parse_mountinfo()`.
    pub fn parse_mountinfo(&self) -> Result<MountTable, LibmountError> {
        self.parse_full(Some("/proc/self/mountinfo"), IterDirection::Forward)
    }

    /// Parse the system mtab with utab (uses `mnt_table_parse_mtab`).
    ///
    /// Equivalent to the C inline `libmount_parse_with_utab()`.
    pub fn parse_with_utab(&self) -> Result<MountTable, LibmountError> {
        self.parse_full(None, IterDirection::Forward)
    }

    /// Check whether a filesystem entry is a leaf mount (has no children).
    ///
    /// Equivalent to the C `libmount_is_leaf()`.
    ///
    /// This method operates directly on the libmount table and uses
    /// `mnt_table_next_child_fs` internally.
    /// # Safety
    /// `table_ptr` and `fs_ptr` must be live libmount objects associated with
    /// this loaded library for the duration of the call.
    pub unsafe fn is_leaf(
        &self,
        table_ptr: *mut c_void,
        fs_ptr: *mut c_void,
    ) -> Result<bool, LibmountError> {
        // SAFETY: mnt_new_iter takes a libmount iteration direction and
        // returns an owned iterator pointer.
        let new_iter: extern "C" fn(i32) -> *mut c_void =
            unsafe { self.resolve_fn(b"mnt_new_iter\0") }?;
        // SAFETY: mnt_free_iter consumes an iterator allocated by mnt_new_iter.
        let free_iter: extern "C" fn(*mut c_void) = unsafe { self.resolve_fn(b"mnt_free_iter\0") }?;
        // SAFETY: mnt_table_next_child_fs has this table/iterator/filesystem/
        // output-pointer signature in libmount.h.
        let next_child: extern "C" fn(
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut *mut c_void,
            // SAFETY: resolve_fn is given the exact signature declared for
            // mnt_table_next_child_fs in libmount.h.
        ) -> i32 = unsafe { self.resolve_fn(b"mnt_table_next_child_fs\0") }?;

        // SAFETY: all symbols resolved in open().
        let iter_ptr = new_iter(MNT_ITER_FORWARD);
        if iter_ptr.is_null() {
            return Err(LibmountError::OutOfMemory);
        }

        let mut child: *mut c_void = std::ptr::null_mut();
        // SAFETY: caller's contract makes table_ptr and fs_ptr live libmount
        // objects, iter_ptr is live, and child is writable for this call.
        let rc = next_child(table_ptr, iter_ptr, fs_ptr, &mut child);

        // SAFETY: iter_ptr was returned by mnt_new_iter and has not been freed.
        free_iter(iter_ptr);

        if rc < 0 {
            Err(LibmountError::OperationFailed(
                rc,
                "mnt_table_next_child_fs".into(),
            ))
        } else {
            // rc == 1  →  no children found  →  leaf
            Ok(rc == 1)
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Realistic multi-line mountinfo sample.
    const SAMPLE_MOUNTINFO: &str = "\
18 1 0:17 / /sys rw,nosuid,nodev,noexec,relatime shared:2 - sysfs sysfs rw
19 1 0:3 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw
20 1 0:5 / /dev rw,nosuid,relatime shared:2 - devtmpfs devtmpfs rw,size=8113764k,nr_inodes=2028441,mode=755
21 1 8:1 / /boot rw,relatime shared:1 - ext4 /dev/sda1 rw
72 21 8:1 / /boot/efi rw,relatime shared:31 - vfat /dev/sda2 rw,fmask=0077,dmask=0077
";

    // Nested mount tree for leaf tests.
    const NESTED_MOUNTINFO: &str = "\
1 0 0:1 / / rw - rootfs rootfs rw
2 1 0:2 / /proc rw - proc proc rw
3 2 0:3 / /proc/sys fs - proc proc rw
4 1 0:4 / /sys rw - sysfs sysfs rw
";

    // ── MountInfoEntry parsing ─────────────────────────────────────────

    #[test]
    fn test_parse_line_basic() {
        let e = MountInfoEntry::parse_line("36 35 98:0 /mnt1 /mnt2 rw,noatime - ext3 /dev/root rw")
            .unwrap();
        assert_eq!(e.mount_id, 36);
        assert_eq!(e.parent_id, 35);
        assert_eq!(e.major, 98);
        assert_eq!(e.minor, 0);
        assert_eq!(e.root, "/mnt1");
        assert_eq!(e.mount_point, "/mnt2");
        assert_eq!(e.mount_options, "rw,noatime");
        assert!(e.optional_fields.is_empty());
        assert_eq!(e.fs_type, "ext3");
        assert_eq!(e.mount_source, "/dev/root");
        assert_eq!(e.super_options, "rw");
    }

    #[test]
    fn test_parse_line_with_optional_fields() {
        let e = MountInfoEntry::parse_line(
            "18 1 0:17 / /sys rw,nosuid,nodev,noexec,relatime shared:2 - sysfs sysfs rw",
        )
        .unwrap();
        assert_eq!(e.optional_fields, vec!["shared:2"]);
        assert_eq!(e.fs_type, "sysfs");
        assert_eq!(e.mount_source, "sysfs");
        assert_eq!(e.super_options, "rw");
    }

    #[test]
    fn test_parse_line_multiple_optional_fields() {
        let e = MountInfoEntry::parse_line(
            "20 1 0:5 / /dev rw,nosuid,relatime shared:2 master:7 - devtmpfs devtmpfs rw,size=8113764k,nr_inodes=2028441,mode=755",
        )
        .unwrap();
        assert_eq!(e.optional_fields, vec!["shared:2", "master:7"]);
        assert_eq!(
            e.super_options,
            "rw,size=8113764k,nr_inodes=2028441,mode=755"
        );
    }

    #[test]
    fn test_parse_line_nested_boot_efi() {
        let e = MountInfoEntry::parse_line(
            "72 21 8:1 / /boot/efi rw,relatime shared:31 - vfat /dev/sda2 rw,fmask=0077,dmask=0077",
        )
        .unwrap();
        assert_eq!(e.mount_id, 72);
        assert_eq!(e.parent_id, 21);
        assert_eq!(e.mount_point, "/boot/efi");
        assert_eq!(e.fs_type, "vfat");
    }

    #[test]
    fn test_parse_line_empty() {
        assert!(matches!(
            MountInfoEntry::parse_line(""),
            Err(LibmountError::InvalidArgument(_))
        ));
        assert!(matches!(
            MountInfoEntry::parse_line("   "),
            Err(LibmountError::InvalidArgument(_))
        ));
    }

    #[test]
    fn test_parse_line_missing_separator() {
        assert!(
            MountInfoEntry::parse_line("36 35 98:0 /mnt1 /mnt2 rw,noatime ext3 /dev/root rw")
                .is_err()
        );
    }

    #[test]
    fn test_parse_line_too_few_before_sep() {
        assert!(MountInfoEntry::parse_line("36 35 - ext3 /dev/root rw").is_err());
    }

    #[test]
    fn test_parse_line_invalid_mount_id() {
        assert!(MountInfoEntry::parse_line("abc 35 98:0 / /mnt rw - ext3 /dev/root rw").is_err());
    }

    #[test]
    fn test_parse_line_invalid_devno_format() {
        assert!(MountInfoEntry::parse_line("36 35 98 / /mnt rw - ext3 /dev/root rw").is_err());
        assert!(MountInfoEntry::parse_line("36 35 98:0:1 / /mnt rw - ext3 /dev/root rw").is_err());
    }

    #[test]
    fn test_parse_line_invalid_devno_values() {
        assert!(MountInfoEntry::parse_line("36 35 abc:def / /mnt rw - ext3 /dev/root rw").is_err());
    }

    #[test]
    fn test_parse_line_too_few_after_sep() {
        assert!(MountInfoEntry::parse_line("36 35 98:0 / /mnt rw - ext3").is_err());
    }

    // ── parse_all ──────────────────────────────────────────────────────

    #[test]
    fn test_parse_all_multiple() {
        let entries = MountInfoEntry::parse_all(SAMPLE_MOUNTINFO).unwrap();
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].mount_point, "/sys");
        assert_eq!(entries[1].mount_point, "/proc");
        assert_eq!(entries[2].mount_point, "/dev");
        assert_eq!(entries[3].mount_point, "/boot");
        assert_eq!(entries[4].mount_point, "/boot/efi");
    }

    #[test]
    fn test_parse_all_empty() {
        let entries = MountInfoEntry::parse_all("").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_all_skips_blank_lines() {
        let content = "\n\n36 35 98:0 / /mnt rw - ext3 /dev/root rw\n\n";
        let entries = MountInfoEntry::parse_all(content).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].mount_point, "/mnt");
    }

    #[test]
    fn test_parse_all_propagates_line_error() {
        let content = "36 35 98:0 /mnt1 /mnt2 rw - ext3 /dev/root rw\nbad line\n";
        let err = MountInfoEntry::parse_all(content).unwrap_err();
        assert!(matches!(err, LibmountError::InvalidArgument(msg) if msg.starts_with("line 2:")));
    }

    // ── is_leaf ─────────────────────────────────────────────────────────

    #[test]
    fn test_is_leaf_true() {
        let entries = MountInfoEntry::parse_all(NESTED_MOUNTINFO).unwrap();
        // /proc/sys (id=3) has no children → leaf
        assert!(entries[2].is_leaf_in(&entries));
        // /sys (id=4) has no children → leaf
        assert!(entries[3].is_leaf_in(&entries));
    }

    #[test]
    fn test_is_leaf_false() {
        let entries = MountInfoEntry::parse_all(NESTED_MOUNTINFO).unwrap();
        // / (id=1) is parent of entries 2,4 → not a leaf
        assert!(!entries[0].is_leaf_in(&entries));
        // /proc (id=2) is parent of entry 3 → not a leaf
        assert!(!entries[1].is_leaf_in(&entries));
    }

    #[test]
    fn test_is_leaf_single_entry() {
        let e = MountInfoEntry::parse_line("1 0 0:1 / / rw - rootfs rootfs rw").unwrap();
        assert!(e.is_leaf_in(&[e.clone()]));
    }

    // ── devno helper ───────────────────────────────────────────────────

    #[test]
    fn test_parse_devno_valid() {
        assert_eq!(parse_devno("98:0").unwrap(), (98, 0));
        assert_eq!(parse_devno("0:17").unwrap(), (0, 17));
        assert_eq!(parse_devno("8:1").unwrap(), (8, 1));
    }

    #[test]
    fn test_parse_devno_invalid() {
        assert!(parse_devno("98").is_err());
        assert!(parse_devno("98:0:1").is_err());
        assert!(parse_devno("abc:def").is_err());
        assert!(parse_devno("").is_err());
    }

    #[test]
    fn test_mount_info_entry_devno() {
        let e = MountInfoEntry::parse_line("36 35 98:0 / /mnt rw - ext3 /dev/root rw").unwrap();
        assert_eq!(e.devno(), (98, 0));
    }

    // ── MountTable ──────────────────────────────────────────────────────

    #[test]
    fn test_mount_table_new_and_default() {
        let t = MountTable::new();
        assert!(t.is_empty());
        let t2 = MountTable::default();
        assert_eq!(t2.len(), 0);
    }

    #[test]
    fn test_mount_table_parse() {
        let t = MountTable::parse(SAMPLE_MOUNTINFO).unwrap();
        assert_eq!(t.len(), 5);
        assert!(!t.is_empty());
    }

    #[test]
    fn test_mount_table_find_target_hit() {
        let t = MountTable::parse(SAMPLE_MOUNTINFO).unwrap();
        let e = t.find_target("/boot").unwrap();
        assert_eq!(e.fs_type, "ext4");
        assert_eq!(e.mount_source, "/dev/sda1");
    }

    #[test]
    fn test_mount_table_find_target_miss() {
        let t = MountTable::parse(SAMPLE_MOUNTINFO).unwrap();
        assert!(t.find_target("/nonexistent").is_none());
    }

    #[test]
    fn test_mount_table_find_devno_hit() {
        let t = MountTable::parse(SAMPLE_MOUNTINFO).unwrap();
        let e = t.find_devno(8, 1).unwrap();
        assert_eq!(e.mount_point, "/boot");
    }

    #[test]
    fn test_mount_table_find_devno_miss() {
        let t = MountTable::parse(SAMPLE_MOUNTINFO).unwrap();
        assert!(t.find_devno(99, 99).is_none());
    }

    #[test]
    fn test_mount_table_iter_forward() {
        let t = MountTable::parse(SAMPLE_MOUNTINFO).unwrap();
        let pts: Vec<&str> = t
            .iter_dir(IterDirection::Forward)
            .map(|e| e.mount_point.as_str())
            .collect();
        assert_eq!(pts, ["/sys", "/proc", "/dev", "/boot", "/boot/efi"]);
    }

    #[test]
    fn test_mount_table_iter_backward() {
        let t = MountTable::parse(SAMPLE_MOUNTINFO).unwrap();
        let pts: Vec<&str> = t
            .iter_dir(IterDirection::Backward)
            .map(|e| e.mount_point.as_str())
            .collect();
        assert_eq!(pts, ["/boot/efi", "/boot", "/dev", "/proc", "/sys"]);
    }

    #[test]
    fn test_mount_table_is_leaf() {
        let t = MountTable::parse(NESTED_MOUNTINFO).unwrap();
        // /proc (id=2) has child /proc/sys (id=3)
        assert!(!t.is_leaf(&t.entries()[1]));
        // /proc/sys (id=3) has no children
        assert!(t.is_leaf(&t.entries()[2]));
    }

    #[test]
    fn test_mount_table_entries_slice() {
        let t = MountTable::parse(SAMPLE_MOUNTINFO).unwrap();
        let slice = t.entries();
        assert_eq!(slice.len(), 5);
    }

    // ── IterDirection ───────────────────────────────────────────────────

    #[test]
    fn test_iter_direction_as_raw() {
        assert_eq!(IterDirection::Forward.as_raw(), 0);
        assert_eq!(IterDirection::Backward.as_raw(), 1);
    }

    #[test]
    fn test_iter_direction_try_from_ok() {
        assert_eq!(IterDirection::try_from(0).unwrap(), IterDirection::Forward);
        assert_eq!(IterDirection::try_from(1).unwrap(), IterDirection::Backward);
    }

    #[test]
    fn test_iter_direction_try_from_err() {
        assert!(IterDirection::try_from(42).is_err());
        assert!(IterDirection::try_from(-1).is_err());
    }

    // ── LibmountError ───────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", LibmountError::DlopenFailed("not found".into())),
            "failed to dlopen libmount: not found"
        );
        let e = LibmountError::SymbolNotFound("mnt_new_table".into());
        let s = format!("{e}");
        assert!(s.contains("mnt_new_table"));

        let e = LibmountError::OperationFailed(-12, "oom".into());
        assert!(format!("{e}").contains("-12"));

        assert_eq!(format!("{}", LibmountError::OutOfMemory), "out of memory");
        assert_eq!(
            format!("{}", LibmountError::NotSupported),
            "libmount not supported"
        );
    }

    #[test]
    fn test_error_equality() {
        assert_eq!(
            LibmountError::DlopenFailed("a".into()),
            LibmountError::DlopenFailed("a".into())
        );
        assert_ne!(
            LibmountError::DlopenFailed("a".into()),
            LibmountError::DlopenFailed("b".into())
        );
        assert_eq!(LibmountError::OutOfMemory, LibmountError::OutOfMemory);
        assert_ne!(LibmountError::OutOfMemory, LibmountError::NotSupported);
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file missing");
        let lm: LibmountError = io_err.into();
        assert!(matches!(lm, LibmountError::Io(io::ErrorKind::NotFound, _)));
        assert!(format!("{lm}").contains("file missing"));
    }

    #[test]
    fn test_error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(LibmountError::NotSupported);
        assert!(format!("{e}").contains("not supported"));
    }

    // ── Constants ───────────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert_eq!(MNT_ITER_FORWARD, 0);
        assert_eq!(MNT_ITER_BACKWARD, 1);
        assert_eq!(LIBMOUNT_SONAME, "libmount.so.1");
    }
}
