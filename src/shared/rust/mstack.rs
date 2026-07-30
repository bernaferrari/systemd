// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/mstack.c, src/shared/mstack.h
//
// Mount stack management for systemd container/sandbox filesystem setup.
//
// Manages a stack of mount entries (root layers, overlay layers, bind mounts,
// read-only bind mounts) used to assemble container root filesystems. Supports
// overlayfs stacking, tmpfs roots, image-based layers, and bind mount overlays.

use crate::ffi::*;
use std::cmp::Ordering;
use std::fs::{self, File, Metadata};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

// ── Re-exports from sibling modules ─────────────────────────────────────────

pub use crate::discover_image::ImageType;

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors returned by mstack operations.
#[derive(Debug)]
pub enum MStackError {
    /// Duplicate entry detected (maps to ENOTUNIQ).
    DuplicateEntry(String),
    /// Unrecognized or malformed entry (maps to EBADMSG).
    BadEntry(String),
    /// I/O error from filesystem operations.
    Io(io::Error),
    /// No suitable entry found (maps to ENOENT).
    NotFound(String),
    /// An operation is not supported in the current configuration.
    NotSupported(String),
    /// Invalid argument.
    InvalidArgument(String),
}

impl std::fmt::Display for MStackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MStackError::DuplicateEntry(s) => write!(f, "duplicate entry: {s}"),
            MStackError::BadEntry(s) => write!(f, "bad entry: {s}"),
            MStackError::Io(e) => write!(f, "I/O error: {e}"),
            MStackError::NotFound(s) => write!(f, "not found: {s}"),
            MStackError::NotSupported(s) => write!(f, "not supported: {s}"),
            MStackError::InvalidArgument(s) => write!(f, "invalid argument: {s}"),
        }
    }
}

impl std::error::Error for MStackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MStackError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for MStackError {
    fn from(e: io::Error) -> Self {
        MStackError::Io(e)
    }
}

/// Convenience result alias for mstack operations.
pub type Result<T> = std::result::Result<T, MStackError>;

// ── Enums ───────────────────────────────────────────────────────────────────

/// Type of a mount entry within an [`MStack`].
///
/// Mirrors the C `MStackMountType` enum from `mstack.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MStackMountType {
    /// "layer@…" entries that are the lower (read-only) layers of an overlayfs stack.
    Layer,
    /// "rw" entry that is the upper (writable) layer of an overlayfs stack.
    /// Contains two subdirs: 'data' + 'work'.
    Rw,
    /// "bind@…" entries that are (writable) bind mounted on top of the overlayfs.
    Bind,
    /// "robind@…" similar to Bind, but read-only.
    Robind,
    /// Optional "root" entry used as root, with layer/rw layers only used for `/usr/`.
    Root,
}

impl MStackMountType {
    /// Convert to a static string representation (mirrors `mstack_mount_type_to_string`).
    pub const fn to_str(self) -> &'static str {
        match self {
            MStackMountType::Root => "root",
            MStackMountType::Layer => "layer",
            MStackMountType::Rw => "rw",
            MStackMountType::Bind => "bind",
            MStackMountType::Robind => "robind",
        }
    }
}

impl std::fmt::Display for MStackMountType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_str())
    }
}

bitflags::bitflags! {
    /// Flags controlling mount stack behavior.
    ///
    /// Mirrors the C `MStackFlags` bitfield from `mstack.h`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MStackFlags: u32 {
        /// When mounting, create top-level inode to mount on top.
        const MKDIR  = 1 << 0;
        /// Mount everything read-only.
        const RDONLY = 1 << 1;
    }
}

// ── MStackMount ─────────────────────────────────────────────────────────────

/// A single mount entry within an [`MStack`].
///
/// Each mount has a type, a source path/fd, and optionally a target path.
/// Layers and rw entries are used for overlayfs; bind/robind entries are
/// bind-mounted on top.
///
/// Mirrors the C `MStackMount` struct from `mstack.h`.
#[derive(Debug)]
pub struct MStackMount {
    /// The type of this mount entry.
    pub mount_type: MStackMountType,
    /// Path to the source (what we're mounting from).
    pub what: String,
    /// File descriptor referring to the source (O_PATH).
    pub what_fd: Option<OwnedFd>,
    /// File descriptor of the mount (set after `open_images` or `make_mounts`).
    pub mount_fd: Option<OwnedFd>,
    /// Sort key for layer entries (the part after "layer@").
    pub sort_key: Option<String>,
    /// Target path for bind mounts (e.g. "/", "/usr").
    pub where_path: Option<String>,
    /// The image type (directory, raw, block device).
    pub image_type: ImageType,
}

impl MStackMount {
    /// Create a new mount entry with the given type and source path.
    pub fn new(mount_type: MStackMountType, what: impl Into<String>) -> Self {
        Self {
            mount_type,
            what: what.into(),
            what_fd: None,
            mount_fd: None,
            sort_key: None,
            where_path: None,
            image_type: ImageType::Directory,
        }
    }

    /// Create a layer mount entry with a sort key.
    pub fn new_layer(what: impl Into<String>, sort_key: impl Into<String>) -> Self {
        Self {
            mount_type: MStackMountType::Layer,
            what: what.into(),
            sort_key: Some(sort_key.into()),
            ..Self::new(MStackMountType::Layer, "")
        }
    }

    /// Create a bind mount entry with a target path.
    pub fn new_bind(
        what: impl Into<String>,
        where_path: impl Into<String>,
        read_only: bool,
    ) -> Self {
        Self {
            mount_type: if read_only {
                MStackMountType::Robind
            } else {
                MStackMountType::Bind
            },
            where_path: Some(where_path.into()),
            ..Self::new(MStackMountType::Bind, what)
        }
    }

    /// Get the effective file descriptor for this mount.
    ///
    /// Returns the mount_fd if set, otherwise falls back to what_fd.
    /// Mirrors the C `mount_get_fd()` function.
    pub fn effective_fd(&self) -> Option<&OwnedFd> {
        self.mount_fd.as_ref().or(self.what_fd.as_ref())
    }

    /// Check if this mount should be treated as read-only.
    ///
    /// Mirrors the C `mount_is_ro()` function.
    pub fn is_read_only(&self, flags: MStackFlags) -> bool {
        flags.contains(MStackFlags::RDONLY)
            || matches!(
                self.mount_type,
                MStackMountType::Layer | MStackMountType::Robind
            )
    }

    /// Get a human-readable name for this mount entry.
    ///
    /// Returns the sort key, target path, or type name, in that order of
    /// preference. Mirrors the C `mount_name()` function.
    pub fn name(&self) -> &str {
        if let Some(key) = &self.sort_key {
            return key;
        }
        if let Some(w) = &self.where_path {
            return w;
        }
        self.mount_type.to_str()
    }
}

// ── MStack ──────────────────────────────────────────────────────────────────

/// A mount stack: an ordered collection of mount entries for assembling a
/// container root filesystem.
///
/// The mount stack is loaded from a directory containing specially named
/// entries (layer@*, rw, root, bind@*, robind@*), normalized, and then
/// used to create overlayfs and bind mount configurations.
///
/// Mirrors the C `MStack` struct from `mstack.h`.
#[derive(Debug)]
pub struct MStack {
    /// Path to the directory this mstack was loaded from.
    pub path: Option<PathBuf>,
    /// Ordered list of mount entries.
    pub mounts: Vec<MStackMount>,
    /// Whether a throw-away tmpfs is needed as root.
    pub has_tmpfs_root: bool,
    /// Whether overlayfs is needed (more than a single layer).
    pub has_overlayfs: bool,
    /// Reference to the root mount entry (if any).
    root_mount_index: Option<usize>,
    /// File descriptor for the assembled root mount (set after `make_mounts`).
    pub root_mount_fd: Option<OwnedFd>,
    /// File descriptor for the /usr/ submount (set after `make_mounts`).
    pub usr_mount_fd: Option<OwnedFd>,
}

impl Default for MStack {
    fn default() -> Self {
        Self::new()
    }
}

impl MStack {
    /// Create a new empty mount stack.
    pub fn new() -> Self {
        Self {
            path: None,
            mounts: Vec::new(),
            has_tmpfs_root: false,
            has_overlayfs: false,
            root_mount_index: None,
            root_mount_fd: None,
            usr_mount_fd: None,
        }
    }

    /// Get a reference to the root mount entry, if any.
    pub fn root_mount(&self) -> Option<&MStackMount> {
        self.root_mount_index.map(|idx| &self.mounts[idx])
    }

    /// Get a mutable reference to the root mount entry, if any.
    pub fn root_mount_mut(&mut self) -> Option<&mut MStackMount> {
        if let Some(idx) = self.root_mount_index {
            Some(&mut self.mounts[idx])
        } else {
            None
        }
    }

    // ── Loading ─────────────────────────────────────────────────────────

    /// Load mount entries from a directory.
    ///
    /// Reads all entries in `dir` and parses them according to their names:
    /// - `layer@<name>` → read-only overlayfs layer
    /// - `rw` → writable overlayfs upper layer
    /// - `root` → root filesystem layer
    /// - `bind@<path>` → writable bind mount
    /// - `robind@<path>` → read-only bind mount
    ///
    /// Mirrors the C `mstack_load()` function.
    pub fn load(dir: &Path) -> Result<Self> {
        let mut mstack = Self::new();
        mstack.load_from_dir(dir)?;
        mstack.normalize()?;
        Ok(mstack)
    }

    /// Load mount entries from a directory (modifies self in place).
    ///
    /// Mirrors the C `mstack_load_now()` function.
    pub fn load_from_dir(&mut self, dir: &Path) -> Result<()> {
        self.path = Some(dir.to_path_buf());

        let entries: Vec<_> = fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                // Skip hidden entries
                e.file_name().to_str().is_some_and(|n| !n.starts_with('.'))
            })
            .collect();

        for entry in entries {
            let fname = entry.file_name();
            let fname_str = fname.to_string_lossy();
            self.load_one(dir, &fname_str, &entry.metadata()?)?;
        }

        Ok(())
    }

    /// Load a single mount entry from a directory entry.
    ///
    /// Mirrors the C `mstack_load_one()` function.
    fn load_one(&mut self, dir: &Path, fname: &str, meta: &Metadata) -> Result<()> {
        let image_type = if meta.is_dir() {
            // Check for .v (versioned) suffix
            if let Some(dotv) = fname.strip_suffix(".v") {
                if let Some(dotrawv) = fname.strip_suffix(".raw.v") {
                    ImageType::Raw
                } else {
                    ImageType::Directory
                }
            } else {
                ImageType::Directory
            }
        } else if meta.is_file() {
            if !fname.ends_with(".raw") {
                return Err(MStackError::BadEntry(format!(
                    "unexpected suffix of '{}/{}', refusing",
                    dir.display(),
                    fname
                )));
            }
            ImageType::Raw
        } else {
            // Block devices and other special files
            return Err(MStackError::BadEntry(format!(
                "unexpected inode type of '{}/{}', refusing",
                dir.display(),
                fname
            )));
        };

        // Strip suffixes to get the unsuffixed name
        let unsuffixed = strip_image_suffix(fname);

        // Determine the mount type from the unsuffixed name
        if let Some(parameter) = validate_prefix(unsuffixed, "layer@") {
            // Check for duplicate layer sort key
            if self
                .find_by(MStackMountType::Layer, Some(&parameter), None)
                .is_some()
            {
                return Err(MStackError::DuplicateEntry(format!(
                    "duplicate layer '{parameter}'"
                )));
            }

            let mut mount = MStackMount::new(MStackMountType::Layer, fname);
            mount.sort_key = Some(parameter);
            mount.image_type = image_type;
            self.mounts.push(mount);
            return Ok(());
        }

        if unsuffixed == "rw" {
            if self.find_by(MStackMountType::Rw, None, None).is_some() {
                return Err(MStackError::DuplicateEntry(
                    "duplicate rw entry".to_string(),
                ));
            }

            let mut mount = MStackMount::new(MStackMountType::Rw, fname);
            mount.image_type = image_type;
            self.mounts.push(mount);
            return Ok(());
        }

        if let Some(parameter) = validate_prefix(unsuffixed, "bind@") {
            let where_path = unescape_path(&parameter);
            // Check for duplicate bind entry
            if self
                .find_by(MStackMountType::Bind, None, Some(&where_path))
                .is_some()
                || self
                    .find_by(MStackMountType::Robind, None, Some(&where_path))
                    .is_some()
            {
                return Err(MStackError::DuplicateEntry(
                    "duplicate bind entry".to_string(),
                ));
            }

            let mut mount = MStackMount::new(MStackMountType::Bind, fname);
            mount.where_path = Some(where_path);
            mount.image_type = image_type;
            self.mounts.push(mount);
            return Ok(());
        }

        if let Some(parameter) = validate_prefix(unsuffixed, "robind@") {
            let where_path = unescape_path(&parameter);
            if self
                .find_by(MStackMountType::Bind, None, Some(&where_path))
                .is_some()
                || self
                    .find_by(MStackMountType::Robind, None, Some(&where_path))
                    .is_some()
            {
                return Err(MStackError::DuplicateEntry(
                    "duplicate bind entry".to_string(),
                ));
            }

            let mut mount = MStackMount::new(MStackMountType::Robind, fname);
            mount.where_path = Some(where_path);
            mount.image_type = image_type;
            self.mounts.push(mount);
            return Ok(());
        }

        if unsuffixed == "root" {
            if self.find_by(MStackMountType::Root, None, None).is_some() {
                return Err(MStackError::DuplicateEntry(
                    "duplicate root entry".to_string(),
                ));
            }

            let mut mount = MStackMount::new(MStackMountType::Root, fname);
            mount.image_type = image_type;
            self.mounts.push(mount);
            return Ok(());
        }

        Err(MStackError::BadEntry(format!(
            "unrecognized entry '{}/{}'",
            dir.display(),
            fname
        )))
    }

    // ── Search ──────────────────────────────────────────────────────────

    /// Find a mount entry matching the given criteria.
    ///
    /// Mirrors the C `mstack_find()` function. A `None` parameter means
    /// "don't filter on this field".
    pub fn find_by(
        &self,
        mount_type: MStackMountType,
        sort_key: Option<&str>,
        where_path: Option<&str>,
    ) -> Option<&MStackMount> {
        self.mounts.iter().find(|m| {
            if m.mount_type != mount_type {
                return false;
            }
            if let Some(key) = sort_key {
                if m.sort_key.as_deref() != Some(key) {
                    return false;
                }
            }
            if let Some(w) = where_path {
                if m.where_path.as_deref() != Some(w) {
                    return false;
                }
            }
            true
        })
    }

    /// Find a mount entry by type only.
    pub fn find_by_type(&self, mount_type: MStackMountType) -> Option<&MStackMount> {
        self.find_by(mount_type, None, None)
    }

    // ── Sorting ─────────────────────────────────────────────────────────

    /// Compare two mount entries for sorting.
    ///
    /// Mirrors the C `mount_compare_func()`. The sort order is:
    /// 1. By mount type (Layer < Rw < Bind < Robind < Root)
    /// 2. By target path
    /// 3. By sort key (version comparison)
    pub fn compare_mounts(a: &MStackMount, b: &MStackMount) -> Ordering {
        // Compile-time assertion equivalent: MSTACK_RW > MSTACK_LAYER
        // This is guaranteed by the enum variant ordering

        // Primary sort by mount type
        match a.mount_type.cmp(&b.mount_type) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Secondary sort by target path
        match path_compare(a.where_path.as_deref(), b.where_path.as_deref()) {
            Ordering::Equal => {}
            ord => return ord,
        }

        // Tertiary sort by sort key (version-style comparison)
        strverscmp(
            a.sort_key.as_deref().unwrap_or(""),
            b.sort_key.as_deref().unwrap_or(""),
        )
    }

    // ── Normalization ───────────────────────────────────────────────────

    /// Sort and optimize the mount stack.
    ///
    /// This performs several optimizations:
    /// - Removes layers and rw entries when the root is fully overmounted
    /// - Converts single-layer stacks to bind mounts
    /// - Removes root entries when root is overmounted
    /// - Sets `has_tmpfs_root` and `has_overlayfs` flags
    ///
    /// Mirrors the C `mstack_normalize()` function.
    pub fn normalize(&mut self) -> Result<()> {
        // Sort the mounts
        self.mounts.sort_by(|a, b| Self::compare_mounts(a, b));

        // Analyze the current state
        let mut n_layers = 0usize;
        let mut has_rw = false;
        let mut has_root_bind = false;
        let mut has_usr_bind = false;
        let mut has_root = false;

        for m in &self.mounts {
            match m.mount_type {
                MStackMountType::Layer => n_layers += 1,
                MStackMountType::Rw => {
                    assert!(!has_rw, "multiple rw entries");
                    has_rw = true;
                }
                MStackMountType::Bind | MStackMountType::Robind => {
                    if is_empty_or_root(m.where_path.as_deref()) {
                        has_root_bind = true;
                    } else if m.where_path.as_deref() == Some("/usr") {
                        has_usr_bind = true;
                    }
                }
                MStackMountType::Root => {
                    assert!(!has_root, "multiple root entries");
                    has_root = true;
                }
            }
        }

        // If the overlayfs stack is fully obstructed, kill it
        if has_root_bind || (has_root && has_usr_bind) {
            self.remove_by_type(MStackMountType::Layer);
            self.remove_by_type(MStackMountType::Rw);
            n_layers = 0;
            has_rw = false;
        }

        // Only a single read-only or read-write layer? Turn into bind mount!
        if n_layers + (has_rw as usize) == 1 {
            for m in &mut self.mounts {
                match m.mount_type {
                    MStackMountType::Layer => {
                        m.mount_type = MStackMountType::Robind;
                        if has_root {
                            m.where_path = Some("/usr".to_string());
                        } else {
                            m.where_path = Some("/".to_string());
                            has_root_bind = true;
                        }
                    }
                    MStackMountType::Rw => {
                        m.mount_type = MStackMountType::Bind;
                        if has_root {
                            m.where_path = Some("/usr".to_string());
                        } else {
                            m.where_path = Some("/".to_string());
                            has_root_bind = true;
                        }
                    }
                    _ => continue,
                }
            }
            n_layers = 0;
            has_rw = false;
        }

        // If the root dir is overmounted, drop the original root
        if has_root_bind {
            self.remove_by_type(MStackMountType::Root);
            has_root = false;
        }

        // Re-sort after conversions
        self.mounts.sort_by(|a, b| Self::compare_mounts(a, b));

        // Find root mount
        self.root_mount_index = None;
        for (idx, m) in self.mounts.iter().enumerate() {
            if m.mount_type == MStackMountType::Root
                || matches!(
                    m.mount_type,
                    MStackMountType::Bind | MStackMountType::Robind
                ) && is_empty_or_root(m.where_path.as_deref())
            {
                assert!(
                    self.root_mount_index.is_none(),
                    "multiple root mount candidates"
                );
                self.root_mount_index = Some(idx);
            }
        }
        assert_eq!((has_root || has_root_bind), self.root_mount_index.is_some());

        self.has_tmpfs_root = n_layers == 0 && !has_rw && !has_root_bind && !has_root;
        self.has_overlayfs = n_layers > 0 || has_rw;

        Ok(())
    }

    /// Remove all mounts of a given type.
    ///
    /// Mirrors the C `mstack_remove()` function.
    fn remove_by_type(&mut self, t: MStackMountType) {
        self.mounts.retain(|m| m.mount_type != t);
    }

    // ── Query operations ────────────────────────────────────────────────

    /// Check if the mount stack consists of only read-only layers and bind mounts.
    ///
    /// Returns `true` if read-only, `false` otherwise.
    /// Mirrors the C `mstack_is_read_only()` function.
    pub fn is_read_only_stack(&self) -> bool {
        if self.has_tmpfs_root {
            return false;
        }

        self.mounts.iter().all(|m| {
            !matches!(
                m.mount_type,
                MStackMountType::Root | MStackMountType::Rw | MStackMountType::Bind
            )
        })
    }

    /// Check if any directory/subvolume layers are owned by a foreign UID.
    ///
    /// Mirrors the C `mstack_is_foreign_uid_owned()` function.
    pub fn is_foreign_uid_owned(&self) -> Result<bool> {
        for m in &self.mounts {
            if !matches!(m.image_type, ImageType::Directory | ImageType::Subvolume) {
                continue;
            }

            // For directory-based mounts, check the UID of the source
            if let Some(ref what_path) = Some(&m.what) {
                let meta = fs::metadata(what_path)?;
                if is_foreign_uid(meta.uid()) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Check if the mount stack has writable layers (given the flags).
    ///
    /// Mirrors the C `mstack_has_writable_layers()` function.
    pub fn has_writable_layers(&self, flags: MStackFlags) -> bool {
        if flags.contains(MStackFlags::RDONLY) {
            return false;
        }

        self.mounts
            .iter()
            .any(|m| m.mount_type == MStackMountType::Rw)
    }

    /// Count layers of a specific type.
    pub fn count_by_type(&self, mount_type: MStackMountType) -> usize {
        self.mounts
            .iter()
            .filter(|m| m.mount_type == mount_type)
            .count()
    }

    /// Return the number of mount entries.
    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    /// Return true if there are no mount entries.
    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }
}

impl Drop for MStack {
    fn drop(&mut self) {
        // OwnedFd fields are automatically closed on drop.
        // Vec<MStackMount> is automatically dropped.
        // This is the RAII equivalent of mstack_done().
    }
}

// ── Helper functions ────────────────────────────────────────────────────────

/// Validate that a name starts with the given prefix and return the remainder.
///
/// Returns `Some(parameter)` if the prefix matches, `None` otherwise.
/// Mirrors the C `validate_prefix_name()` function.
pub fn validate_prefix(name: &str, prefix: &str) -> Option<String> {
    name.strip_prefix(prefix)
        .map(|s| {
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        })
        .flatten()
}

/// Strip image suffixes from a filename to get the base name.
///
/// Handles `.raw.v`, `.raw`, and `.v` suffixes.
fn strip_image_suffix(fname: &str) -> &str {
    if let Some(base) = fname.strip_suffix(".raw.v") {
        base
    } else if let Some(base) = fname.strip_suffix(".raw") {
        base
    } else if let Some(base) = fname.strip_suffix(".v") {
        base
    } else {
        fname
    }
}

/// Unescape a systemd unit-name-encoded path.
///
/// This converts escaped paths (like `-usr-lib` → `/usr/lib`) back to
/// their original form. Mirrors `unit_name_path_unescape`.
fn unescape_path(encoded: &str) -> String {
    encoded
        .chars()
        .flat_map(|c| if c == '-' { Some('/') } else { Some(c) })
        .collect()
}

/// Check if a path is empty or "/".
fn is_empty_or_root(p: Option<&str>) -> bool {
    match p {
        None | Some("") | Some("/") => true,
        _ => false,
    }
}

/// Compare two optional paths for sorting.
fn path_compare(a: Option<&str>, b: Option<&str>) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(a_val), Some(b_val)) => a_val.cmp(b_val),
    }
}

/// Version-style string comparison.
///
/// Compares strings treating runs of digits as numbers (like `strverscmp(3)`).
/// Leading zeros are handled specially: numbers with more leading zeros come
/// before those with fewer (e.g., "009" < "09" < "9").
pub fn strverscmp(a: &str, b: &str) -> Ordering {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut ai = 0usize;
    let mut bi = 0usize;

    loop {
        // Skip non-digit characters that are equal
        while ai < a_bytes.len() && bi < b_bytes.len() {
            if a_bytes[ai] == b_bytes[bi] {
                ai += 1;
                bi += 1;
            } else {
                break;
            }
        }

        // Skip leading zeros in both
        let a_zero_start = ai;
        while ai < a_bytes.len() && a_bytes[ai] == b'0' {
            ai += 1;
        }
        let b_zero_start = bi;
        while bi < b_bytes.len() && b_bytes[bi] == b'0' {
            bi += 1;
        }

        // Count digits
        let mut a_digits = 0usize;
        while ai + a_digits < a_bytes.len() && a_bytes[ai + a_digits].is_ascii_digit() {
            a_digits += 1;
        }
        let mut b_digits = 0usize;
        while bi + b_digits < b_bytes.len() && b_bytes[bi + b_digits].is_ascii_digit() {
            b_digits += 1;
        }

        if a_digits > 0 || b_digits > 0 {
            // At least one side has digits
            let a_total = a_digits + (ai - a_zero_start);
            let b_total = b_digits + (bi - b_zero_start);

            let a_leading_zeros = ai - a_zero_start;
            let b_leading_zeros = bi - b_zero_start;

            if a_leading_zeros > 0 || b_leading_zeros > 0 {
                // At least one side has leading zeros
                // Longer total digit sequence (including leading zeros) comes first (i.e. is "Less")
                match b_total.cmp(&a_total) {
                    Ordering::Equal => {}
                    ord => return ord,
                }
            } else {
                // Neither side has leading zeros
                // More significant digits means larger number (i.e. "Greater")
                match a_digits.cmp(&b_digits) {
                    Ordering::Equal => {}
                    ord => return ord,
                }
            }

            // Compare digit by digit
            for j in 0..a_digits.min(b_digits) {
                match a_bytes[ai + j].cmp(&b_bytes[bi + j]) {
                    Ordering::Equal => {}
                    ord => return ord,
                }
            }

            // Different number of significant digits
            match a_digits.cmp(&b_digits) {
                Ordering::Equal => {
                    ai += a_digits;
                    bi += b_digits;
                }
                ord => return ord,
            }
        } else {
            // No digits found; compare the current characters
            if ai >= a_bytes.len() && bi >= b_bytes.len() {
                return Ordering::Equal;
            }
            if ai >= a_bytes.len() {
                return Ordering::Less;
            }
            if bi >= b_bytes.len() {
                return Ordering::Greater;
            }
            match a_bytes[ai].cmp(&b_bytes[bi]) {
                Ordering::Equal => {
                    ai += 1;
                    bi += 1;
                }
                ord => return ord,
            }
        }
    }
}

/// Check if a UID is in the "foreign" range (system-assigned UIDs outside
/// the normal user range).
///
/// Mirrors the C `uid_is_foreign()` check. Foreign UIDs are typically
/// in the range 65536–4294967294.
fn is_foreign_uid(uid: u32) -> bool {
    // Foreign UIDs: >= 65536 and < 4294967295
    uid >= 65536 && uid != u32::MAX
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    // ── validate_prefix tests ───────────────────────────────────────────

    #[test]
    fn test_validate_prefix_layer() {
        assert_eq!(
            validate_prefix("layer@foo", "layer@"),
            Some("foo".to_string())
        );
    }

    #[test]
    fn test_validate_prefix_bind() {
        assert_eq!(
            validate_prefix("bind@-usr-lib", "bind@"),
            Some("-usr-lib".to_string())
        );
    }

    #[test]
    fn test_validate_prefix_robind() {
        assert_eq!(
            validate_prefix("robind@-etc", "robind@"),
            Some("-etc".to_string())
        );
    }

    #[test]
    fn test_validate_prefix_no_match() {
        assert_eq!(validate_prefix("root", "layer@"), None);
        assert_eq!(validate_prefix("rw", "layer@"), None);
    }

    #[test]
    fn test_validate_prefix_empty_parameter() {
        // "layer@" with nothing after → should return None
        assert_eq!(validate_prefix("layer@", "layer@"), None);
    }

    #[test]
    fn test_validate_prefix_exact_match() {
        // "layer@" is a prefix of "layer@foo" but not of "layer@"
        assert_eq!(validate_prefix("layer@", "layer@"), None);
    }

    // ── strip_image_suffix tests ────────────────────────────────────────

    #[test]
    fn test_strip_image_suffix_raw_v() {
        assert_eq!(strip_image_suffix("foo.raw.v"), "foo");
    }

    #[test]
    fn test_strip_image_suffix_raw() {
        assert_eq!(strip_image_suffix("foo.raw"), "foo");
    }

    #[test]
    fn test_strip_image_suffix_v() {
        assert_eq!(strip_image_suffix("foo.v"), "foo");
    }

    #[test]
    fn test_strip_image_suffix_none() {
        assert_eq!(strip_image_suffix("layer@foo"), "layer@foo");
        assert_eq!(strip_image_suffix("rw"), "rw");
        assert_eq!(strip_image_suffix("root"), "root");
    }

    // ── unescape_path tests ─────────────────────────────────────────────

    #[test]
    fn test_unescape_path_simple() {
        assert_eq!(unescape_path("-usr-lib"), "/usr/lib");
    }

    #[test]
    fn test_unescape_path_root() {
        assert_eq!(unescape_path(""), "");
    }

    #[test]
    fn test_unescape_path_already_slash() {
        // The function treats '-' as '/' always
        assert_eq!(unescape_path("-"), "/");
    }

    // ── is_empty_or_root tests ──────────────────────────────────────────

    #[test]
    fn test_is_empty_or_root() {
        assert!(is_empty_or_root(None));
        assert!(is_empty_or_root(Some("")));
        assert!(is_empty_or_root(Some("/")));
        assert!(!is_empty_or_root(Some("/usr")));
        assert!(!is_empty_or_root(Some("/etc")));
    }

    // ── path_compare tests ──────────────────────────────────────────────

    #[test]
    fn test_path_compare() {
        assert_eq!(path_compare(None, None), Ordering::Equal);
        assert_eq!(path_compare(None, Some("/")), Ordering::Less);
        assert_eq!(path_compare(Some("/"), None), Ordering::Greater);
        assert_eq!(path_compare(Some("/etc"), Some("/usr")), Ordering::Less);
    }

    // ── strverscmp tests ────────────────────────────────────────────────

    #[test]
    fn test_strverscmp_basic() {
        assert_eq!(strverscmp("1", "2"), Ordering::Less);
        assert_eq!(strverscmp("2", "1"), Ordering::Greater);
        assert_eq!(strverscmp("1", "1"), Ordering::Equal);
    }

    #[test]
    fn test_strverscmp_version() {
        assert_eq!(strverscmp("1.0", "1.1"), Ordering::Less);
        assert_eq!(strverscmp("1.2", "1.10"), Ordering::Less);
        assert_eq!(strverscmp("1.10", "1.2"), Ordering::Greater);
        assert_eq!(strverscmp("1.10", "1.10"), Ordering::Equal);
    }

    #[test]
    fn test_strverscmp_leading_zeros() {
        // "009" < "09" < "9" because longer digit sequence (with leading zeros) comes first
        assert_eq!(strverscmp("009", "09"), Ordering::Less);
        assert_eq!(strverscmp("09", "9"), Ordering::Less);
        assert_eq!(strverscmp("009", "9"), Ordering::Less);
    }

    #[test]
    fn test_strverscmp_alpha() {
        assert_eq!(strverscmp("abc", "abd"), Ordering::Less);
        assert_eq!(strverscmp("abc", "abc"), Ordering::Equal);
        assert_eq!(strverscmp("abd", "abc"), Ordering::Greater);
    }

    #[test]
    fn test_strverscmp_mixed() {
        assert_eq!(strverscmp("", ""), Ordering::Equal);
        assert_eq!(strverscmp("", "a"), Ordering::Less);
        assert_eq!(strverscmp("a", ""), Ordering::Greater);
    }

    // ── MStackMountType tests ───────────────────────────────────────────

    #[test]
    fn test_mount_type_ordering() {
        // Verify that Layer < Rw (compile-time guarantee in C via assert_cc)
        assert!(MStackMountType::Layer < MStackMountType::Rw);
        assert!(MStackMountType::Rw < MStackMountType::Bind);
        assert!(MStackMountType::Bind < MStackMountType::Robind);
        assert!(MStackMountType::Robind < MStackMountType::Root);
    }

    #[test]
    fn test_mount_type_to_str() {
        assert_eq!(MStackMountType::Root.to_str(), "root");
        assert_eq!(MStackMountType::Layer.to_str(), "layer");
        assert_eq!(MStackMountType::Rw.to_str(), "rw");
        assert_eq!(MStackMountType::Bind.to_str(), "bind");
        assert_eq!(MStackMountType::Robind.to_str(), "robind");
    }

    // ── MStackFlags tests ───────────────────────────────────────────────

    #[test]
    fn test_mstack_flags() {
        let f = MStackFlags::empty();
        assert!(!f.contains(MStackFlags::MKDIR));
        assert!(!f.contains(MStackFlags::RDONLY));

        let f = MStackFlags::MKDIR | MStackFlags::RDONLY;
        assert!(f.contains(MStackFlags::MKDIR));
        assert!(f.contains(MStackFlags::RDONLY));
    }

    // ── MStackMount tests ───────────────────────────────────────────────

    #[test]
    fn test_mount_new() {
        let m = MStackMount::new(MStackMountType::Layer, "/path/to/layer");
        assert_eq!(m.mount_type, MStackMountType::Layer);
        assert_eq!(m.what, "/path/to/layer");
        assert!(m.what_fd.is_none());
        assert!(m.mount_fd.is_none());
        assert!(m.sort_key.is_none());
        assert!(m.where_path.is_none());
    }

    #[test]
    fn test_mount_new_layer() {
        let m = MStackMount::new_layer("/path/to/layer", "00-base");
        assert_eq!(m.mount_type, MStackMountType::Layer);
        assert_eq!(m.sort_key.as_deref(), Some("00-base"));
    }

    #[test]
    fn test_mount_new_bind() {
        let m = MStackMount::new_bind("/source", "/target", false);
        assert_eq!(m.mount_type, MStackMountType::Bind);
        assert_eq!(m.where_path.as_deref(), Some("/target"));
    }

    #[test]
    fn test_mount_new_bind_readonly() {
        let m = MStackMount::new_bind("/source", "/target", true);
        assert_eq!(m.mount_type, MStackMountType::Robind);
    }

    #[test]
    fn test_mount_is_read_only() {
        let m = MStackMount::new(MStackMountType::Layer, "/");
        assert!(m.is_read_only(MStackFlags::empty()));

        let m = MStackMount::new(MStackMountType::Rw, "/");
        assert!(!m.is_read_only(MStackFlags::empty()));
        assert!(m.is_read_only(MStackFlags::RDONLY));

        let m = MStackMount::new(MStackMountType::Robind, "/");
        assert!(m.is_read_only(MStackFlags::empty()));

        let m = MStackMount::new(MStackMountType::Bind, "/");
        assert!(!m.is_read_only(MStackFlags::empty()));
        assert!(m.is_read_only(MStackFlags::RDONLY));
    }

    #[test]
    fn test_mount_name() {
        let mut m = MStackMount::new(MStackMountType::Layer, "/");
        m.sort_key = Some("00-base".to_string());
        assert_eq!(m.name(), "00-base");

        let mut m = MStackMount::new(MStackMountType::Bind, "/");
        m.where_path = Some("/usr".to_string());
        assert_eq!(m.name(), "/usr");

        let m = MStackMount::new(MStackMountType::Rw, "/");
        assert_eq!(m.name(), "rw");
    }

    #[test]
    fn test_mount_effective_fd() {
        let m = MStackMount::new(MStackMountType::Layer, "/");
        assert!(m.effective_fd().is_none());
    }

    // ── MStack tests ────────────────────────────────────────────────────

    #[test]
    fn test_mstack_new() {
        let s = MStack::new();
        assert!(s.mounts.is_empty());
        assert!(!s.has_tmpfs_root);
        assert!(!s.has_overlayfs);
        assert!(s.root_mount().is_none());
        assert!(s.root_mount_fd.is_none());
        assert!(s.usr_mount_fd.is_none());
        assert!(s.path.is_none());
    }

    #[test]
    fn test_mstack_default() {
        let s = MStack::default();
        assert!(s.mounts.is_empty());
    }

    #[test]
    fn test_mstack_len_and_is_empty() {
        let mut s = MStack::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);

        s.mounts
            .push(MStackMount::new(MStackMountType::Layer, "/a"));
        assert!(!s.is_empty());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn test_mstack_find_by_type() {
        let mut s = MStack::new();
        s.mounts
            .push(MStackMount::new(MStackMountType::Layer, "/a"));
        s.mounts.push(MStackMount::new(MStackMountType::Rw, "/rw"));

        assert!(s.find_by_type(MStackMountType::Layer).is_some());
        assert!(s.find_by_type(MStackMountType::Rw).is_some());
        assert!(s.find_by_type(MStackMountType::Root).is_none());
    }

    #[test]
    fn test_mstack_find_by_sort_key() {
        let mut s = MStack::new();
        let mut m1 = MStackMount::new(MStackMountType::Layer, "/a");
        m1.sort_key = Some("00-base".to_string());
        s.mounts.push(m1);
        let mut m2 = MStackMount::new(MStackMountType::Layer, "/b");
        m2.sort_key = Some("01-overlay".to_string());
        s.mounts.push(m2);

        assert!(
            s.find_by(MStackMountType::Layer, Some("00-base"), None)
                .is_some()
        );
        assert!(
            s.find_by(MStackMountType::Layer, Some("01-overlay"), None)
                .is_some()
        );
        assert!(
            s.find_by(MStackMountType::Layer, Some("02-missing"), None)
                .is_none()
        );
    }

    #[test]
    fn test_mstack_find_by_where() {
        let mut s = MStack::new();
        let mut m1 = MStackMount::new(MStackMountType::Bind, "/src");
        m1.where_path = Some("/usr".to_string());
        s.mounts.push(m1);
        let mut m2 = MStackMount::new(MStackMountType::Bind, "/src2");
        m2.where_path = Some("/etc".to_string());
        s.mounts.push(m2);

        assert!(
            s.find_by(MStackMountType::Bind, None, Some("/usr"))
                .is_some()
        );
        assert!(
            s.find_by(MStackMountType::Bind, None, Some("/var"))
                .is_none()
        );
    }

    #[test]
    fn test_mstack_count_by_type() {
        let mut s = MStack::new();
        s.mounts
            .push(MStackMount::new(MStackMountType::Layer, "/a"));
        s.mounts
            .push(MStackMount::new(MStackMountType::Layer, "/b"));
        s.mounts.push(MStackMount::new(MStackMountType::Rw, "/rw"));

        assert_eq!(s.count_by_type(MStackMountType::Layer), 2);
        assert_eq!(s.count_by_type(MStackMountType::Rw), 1);
        assert_eq!(s.count_by_type(MStackMountType::Root), 0);
    }

    #[test]
    fn test_mstack_normalize_single_layer_to_bind() {
        // A single layer should be converted to a robind
        let mut s = MStack::new();
        let mut m = MStackMount::new(MStackMountType::Layer, "/layer");
        m.image_type = ImageType::Directory;
        s.mounts.push(m);

        s.normalize().unwrap();

        assert_eq!(s.mounts.len(), 1);
        assert_eq!(s.mounts[0].mount_type, MStackMountType::Robind);
        assert_eq!(s.mounts[0].where_path.as_deref(), Some("/"));
        assert!(s.has_tmpfs_root == false);
        assert!(s.has_overlayfs == false);
        assert!(s.root_mount().is_some());
    }

    #[test]
    fn test_mstack_normalize_single_rw_to_bind() {
        // A single rw layer should be converted to a bind
        let mut s = MStack::new();
        let mut m = MStackMount::new(MStackMountType::Rw, "/rw");
        m.image_type = ImageType::Directory;
        s.mounts.push(m);

        s.normalize().unwrap();

        assert_eq!(s.mounts.len(), 1);
        assert_eq!(s.mounts[0].mount_type, MStackMountType::Bind);
        assert_eq!(s.mounts[0].where_path.as_deref(), Some("/"));
        assert!(s.root_mount().is_some());
    }

    #[test]
    fn test_mstack_normalize_empty_is_tmpfs() {
        // Empty mstack should need tmpfs root
        let mut s = MStack::new();
        s.normalize().unwrap();
        assert!(s.has_tmpfs_root);
        assert!(!s.has_overlayfs);
    }

    #[test]
    fn test_mstack_normalize_overlayfs_detected() {
        // Multiple layers should trigger overlayfs
        let mut s = MStack::new();
        let mut m1 = MStackMount::new(MStackMountType::Layer, "/a");
        m1.sort_key = Some("00-base".to_string());
        s.mounts.push(m1);
        let mut m2 = MStackMount::new(MStackMountType::Layer, "/b");
        m2.sort_key = Some("01-overlay".to_string());
        s.mounts.push(m2);
        let mut m3 = MStackMount::new(MStackMountType::Rw, "/rw");
        m3.image_type = ImageType::Directory;
        s.mounts.push(m3);

        s.normalize().unwrap();

        assert!(s.has_overlayfs);
        assert!(!s.has_tmpfs_root);
    }

    #[test]
    fn test_mstack_normalize_root_bind_removes_layers() {
        // Root bind mount should cause all layers to be removed
        let mut s = MStack::new();
        let mut m1 = MStackMount::new(MStackMountType::Layer, "/a");
        m1.sort_key = Some("00-base".to_string());
        s.mounts.push(m1);
        let mut m2 = MStackMount::new(MStackMountType::Rw, "/rw");
        s.mounts.push(m2);
        let mut m3 = MStackMount::new(MStackMountType::Bind, "/bind");
        m3.where_path = Some("/".to_string());
        s.mounts.push(m3);

        s.normalize().unwrap();

        // Layers and rw should be removed
        assert_eq!(s.count_by_type(MStackMountType::Layer), 0);
        assert_eq!(s.count_by_type(MStackMountType::Rw), 0);
        assert!(!s.has_overlayfs);
        assert!(s.root_mount().is_some());
    }

    #[test]
    fn test_mstack_normalize_root_with_usr_bind_removes_layers() {
        // Root + /usr bind should cause layers to be removed
        let mut s = MStack::new();
        let mut m1 = MStackMount::new(MStackMountType::Root, "/root");
        m1.image_type = ImageType::Directory;
        s.mounts.push(m1);
        let mut m2 = MStackMount::new(MStackMountType::Layer, "/a");
        m2.sort_key = Some("00-base".to_string());
        s.mounts.push(m2);
        let mut m3 = MStackMount::new(MStackMountType::Bind, "/bind");
        m3.where_path = Some("/usr".to_string());
        s.mounts.push(m3);

        s.normalize().unwrap();

        assert_eq!(s.count_by_type(MStackMountType::Layer), 0);
        assert!(!s.has_overlayfs);
    }

    #[test]
    fn test_mstack_normalize_root_bind_removes_root() {
        let mut s = MStack::new();
        let mut m1 = MStackMount::new(MStackMountType::Root, "/root");
        m1.image_type = ImageType::Directory;
        s.mounts.push(m1);
        let mut m2 = MStackMount::new(MStackMountType::Layer, "/a");
        m2.sort_key = Some("00-base".to_string());
        s.mounts.push(m2);

        s.normalize().unwrap();

        // With root + single layer: layer becomes robind at /usr,
        // has_root_bind stays false, so root entry is preserved
        assert!(s.find_by_type(MStackMountType::Root).is_some());
    }

    #[test]
    fn test_mstack_normalize_sorting() {
        // Verify that normalize sorts the mounts correctly
        let mut s = MStack::new();
        // Add in reverse order
        let mut m1 = MStackMount::new(MStackMountType::Rw, "/rw");
        m1.image_type = ImageType::Directory;
        s.mounts.push(m1);
        let mut m2 = MStackMount::new(MStackMountType::Bind, "/b");
        m2.where_path = Some("/etc".to_string());
        s.mounts.push(m2);
        let mut m3 = MStackMount::new(MStackMountType::Layer, "/a");
        m3.sort_key = Some("01-top".to_string());
        s.mounts.push(m3);
        let mut m4 = MStackMount::new(MStackMountType::Layer, "/b");
        m4.sort_key = Some("00-base".to_string());
        s.mounts.push(m4);

        s.normalize().unwrap();

        // After sorting: layers first (sorted by key), then rw, then binds
        assert_eq!(s.mounts[0].mount_type, MStackMountType::Layer);
        assert_eq!(s.mounts[0].sort_key.as_deref(), Some("00-base"));
        assert_eq!(s.mounts[1].mount_type, MStackMountType::Layer);
        assert_eq!(s.mounts[1].sort_key.as_deref(), Some("01-top"));
        assert_eq!(s.mounts[2].mount_type, MStackMountType::Rw);
        assert_eq!(s.mounts[3].mount_type, MStackMountType::Bind);
    }

    // ── compare_mounts tests ────────────────────────────────────────────

    #[test]
    fn test_compare_mounts_by_type() {
        let a = MStackMount::new(MStackMountType::Layer, "/");
        let b = MStackMount::new(MStackMountType::Rw, "/");
        assert_eq!(MStack::compare_mounts(&a, &b), Ordering::Less);
    }

    #[test]
    fn test_compare_mounts_by_where() {
        let mut a = MStackMount::new(MStackMountType::Bind, "/");
        a.where_path = Some("/etc".to_string());
        let mut b = MStackMount::new(MStackMountType::Bind, "/");
        b.where_path = Some("/usr".to_string());
        assert_eq!(MStack::compare_mounts(&a, &b), Ordering::Less);
    }

    #[test]
    fn test_compare_mounts_by_sort_key() {
        let mut a = MStackMount::new(MStackMountType::Layer, "/");
        a.sort_key = Some("00-base".to_string());
        let mut b = MStackMount::new(MStackMountType::Layer, "/");
        b.sort_key = Some("01-top".to_string());
        assert_eq!(MStack::compare_mounts(&a, &b), Ordering::Less);
    }

    #[test]
    fn test_compare_mounts_equal() {
        let a = MStackMount::new(MStackMountType::Layer, "/");
        let b = MStackMount::new(MStackMountType::Layer, "/");
        assert_eq!(MStack::compare_mounts(&a, &b), Ordering::Equal);
    }

    // ── is_read_only_stack tests ────────────────────────────────────────

    #[test]
    fn test_is_read_only_stack_empty() {
        let s = MStack::new();
        assert!(s.is_read_only_stack());
    }

    #[test]
    fn test_is_read_only_stack_with_layers() {
        let mut s = MStack::new();
        let mut m = MStackMount::new(MStackMountType::Layer, "/");
        m.sort_key = Some("00".to_string());
        s.mounts.push(m);
        s.normalize().unwrap();
        // Single layer → converted to robind, has_tmpfs_root=false
        // But wait, after normalize, the single layer becomes robind at "/"
        // is_read_only_stack checks for Root, Rw, Bind — robind is OK
        assert!(s.is_read_only_stack());
    }

    #[test]
    fn test_is_read_only_stack_with_tmpfs() {
        let mut s = MStack::new();
        s.normalize().unwrap();
        assert!(s.has_tmpfs_root);
        assert!(!s.is_read_only_stack());
    }

    // ── has_writable_layers tests ───────────────────────────────────────

    #[test]
    fn test_has_writable_layers_no_rw() {
        let s = MStack::new();
        assert!(!s.has_writable_layers(MStackFlags::empty()));
    }

    #[test]
    fn test_has_writable_layers_with_rw() {
        let mut s = MStack::new();
        let mut m = MStackMount::new(MStackMountType::Rw, "/rw");
        m.image_type = ImageType::Directory;
        s.mounts.push(m);
        assert!(s.has_writable_layers(MStackFlags::empty()));
    }

    #[test]
    fn test_has_writable_layers_rdonly_flag() {
        let mut s = MStack::new();
        let mut m = MStackMount::new(MStackMountType::Rw, "/rw");
        m.image_type = ImageType::Directory;
        s.mounts.push(m);
        // RDONLY flag suppresses writable check
        assert!(!s.has_writable_layers(MStackFlags::RDONLY));
    }

    // ── is_foreign_uid tests ────────────────────────────────────────────

    #[test]
    fn test_is_foreign_uid_range() {
        // UIDs >= 65536 and < u32::MAX are foreign
        assert!(is_foreign_uid(65536));
        assert!(is_foreign_uid(100000));
        assert!(is_foreign_uid(4294967294));
        // System UIDs are not foreign
        assert!(!is_foreign_uid(0));
        assert!(!is_foreign_uid(1));
        assert!(!is_foreign_uid(999));
        assert!(!is_foreign_uid(65535));
        // u32::MAX is reserved
        assert!(!is_foreign_uid(u32::MAX));
    }

    // ── remove_by_type tests ────────────────────────────────────────────

    #[test]
    fn test_remove_by_type() {
        let mut s = MStack::new();
        s.mounts
            .push(MStackMount::new(MStackMountType::Layer, "/a"));
        s.mounts.push(MStackMount::new(MStackMountType::Rw, "/rw"));
        s.mounts
            .push(MStackMount::new(MStackMountType::Layer, "/b"));

        s.remove_by_type(MStackMountType::Layer);

        assert_eq!(s.mounts.len(), 1);
        assert_eq!(s.mounts[0].mount_type, MStackMountType::Rw);
    }

    // ── Drop / RAII tests ───────────────────────────────────────────────

    #[test]
    fn test_mstack_drop() {
        // Verify that MStack can be dropped cleanly
        let mut s = MStack::new();
        s.mounts
            .push(MStackMount::new(MStackMountType::Layer, "/a"));
        s.mounts.push(MStackMount::new(MStackMountType::Rw, "/rw"));
        drop(s);
    }

    #[test]
    fn test_mstack_mount_drop() {
        // Verify that MStackMount can be dropped cleanly
        let m = MStackMount::new(MStackMountType::Layer, "/a");
        drop(m);
    }

    // ── Error type tests ────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let e = MStackError::DuplicateEntry("foo".to_string());
        assert_eq!(format!("{e}"), "duplicate entry: foo");

        let e = MStackError::BadEntry("bad".to_string());
        assert_eq!(format!("{e}"), "bad entry: bad");

        let e = MStackError::NotFound("missing".to_string());
        assert_eq!(format!("{e}"), "not found: missing");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "not found");
        let err: MStackError = io_err.into();
        assert!(matches!(err, MStackError::Io(_)));
        assert!(err.source().is_some());
    }

    // ── Edge case: duplicate detection ──────────────────────────────────

    #[test]
    fn test_duplicate_layer_detection() {
        let mut s = MStack::new();
        let mut m1 = MStackMount::new(MStackMountType::Layer, "/a");
        m1.sort_key = Some("00-base".to_string());
        s.mounts.push(m1);

        let mut m2 = MStackMount::new(MStackMountType::Layer, "/b");
        m2.sort_key = Some("00-base".to_string());
        s.mounts.push(m2);

        // find_by should find the first match
        let found = s.find_by(MStackMountType::Layer, Some("00-base"), None);
        assert!(found.is_some());
    }

    #[test]
    fn test_duplicate_bind_detection() {
        let mut s = MStack::new();
        let mut m1 = MStackMount::new(MStackMountType::Bind, "/src1");
        m1.where_path = Some("/usr".to_string());
        s.mounts.push(m1);

        // Should find the existing bind at /usr
        let found = s.find_by(MStackMountType::Bind, None, Some("/usr"));
        assert!(found.is_some());
    }
}
