// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/shared/mkfs-util.c, src/shared/mkfs-util.h
//
// Filesystem creation utilities.
//
// Provides functions for checking mkfs tool availability, mangling filesystem
// labels, building mkfs command lines, and executing mkfs tools via fork/exec.
// Supports ext2/3/4, btrfs, f2fs, xfs, vfat, swap, squashfs, erofs, and
// generic fallback to mkfs.<fstype>.

use crate::ffi::*;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum label length for ext2/ext3/ext4.
const EXT_LABEL_MAX: usize = 16;

/// Maximum label length for xfs.
const XFS_LABEL_MAX: usize = 12;

/// Maximum label length for swap.
const SWAP_LABEL_MAX: usize = 15;

/// Maximum label length for vfat (11 chars, uppercase).
const VFAT_LABEL_MAX: usize = 11;

/// Characters disallowed in vfat labels.
const VFAT_DISALLOWED: &[u8] = b"*?.,;:/\\|+=<>[]\"";

/// Read-only filesystem types (necessarily read-only on Linux).
const READONLY_FSTYPES: &[&str] = &["DM_verity_hash", "cramfs", "erofs", "iso9660", "squashfs"];

/// Filesystem types that are not real filesystems and should be refused early.
const RESERVED_FSTYPES: &[&str] = &["auto", "swap"];

/// Filesystem types known to support populating from a source tree.
const ROOT_SUPPORTED_FSTYPES: &[&str] = &["ext2", "ext3", "ext4", "btrfs", "vfat", "xfs"];

/// Minimum btrfs sector size in bytes.
const BTRFS_MIN_SECTOR_SIZE: u64 = 4096;

// ── Error types ───────────────────────────────────────────────────────────

/// Errors returned by mkfs utilities.
#[derive(Debug)]
pub enum MkfsError {
    /// Invalid argument (e.g. "auto" or "swap" fstype passed to mkfs_exists).
    InvalidArgument(String),
    /// mkfs binary not found in PATH.
    NotFound(String),
    /// I/O or OS error during filesystem creation.
    Io(std::io::Error),
    /// UTF-8 encoding error in label.
    InvalidUtf8,
    /// mkfs child process exited with non-zero status.
    ChildFailed(i32),
    /// Unsupported operation for the given filesystem type.
    Unsupported(String),
}

impl std::fmt::Display for MkfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MkfsError::InvalidArgument(msg) => write!(f, "Invalid argument: {msg}"),
            MkfsError::NotFound(msg) => write!(f, "Not found: {msg}"),
            MkfsError::Io(e) => write!(f, "I/O error: {e}"),
            MkfsError::InvalidUtf8 => write!(f, "Invalid UTF-8 in label"),
            MkfsError::ChildFailed(code) => {
                write!(f, "mkfs child process failed with exit code {code}")
            }
            MkfsError::Unsupported(msg) => write!(f, "Unsupported: {msg}"),
        }
    }
}

impl std::error::Error for MkfsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MkfsError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for MkfsError {
    fn from(e: std::io::Error) -> Self {
        MkfsError::Io(e)
    }
}

// ── Result type alias ────────────────────────────────────────────────────

/// Result type for mkfs utility functions.
pub type MkfsResult<T> = Result<T, MkfsError>;

// ── Flags ─────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Flags controlling filesystem creation behavior.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MakeFileSystemFlags: u32 {
        /// Suppress mkfs command output.
        const QUIET     = 1 << 0;
        /// Enable discard mode on the filesystem.
        const DISCARD   = 1 << 1;
        /// Enable fs-verity support on the filesystem.
        const FS_VERITY = 1 << 2;
    }
}

// ── UUID type ────────────────────────────────────────────────────────────

/// A 128-bit ID matching sd_id128_t layout (16 bytes, big-endian).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SdId128(pub [u8; 16]);

impl SdId128 {
    /// All-zero (null) UUID.
    pub const NULL: SdId128 = SdId128([0u8; 16]);

    /// Create from a byte array.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        SdId128(bytes)
    }

    /// Format as a UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
    pub fn to_uuid_string(&self) -> String {
        let b = &self.0;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3],
            b[4], b[5],
            b[6], b[7],
            b[8], b[9],
            b[10], b[11], b[12], b[13], b[14], b[15],
        )
    }

    /// Format as a lowercase hex string without separators (32 chars).
    pub fn to_hex_string(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// ── Label mangling ───────────────────────────────────────────────────────

/// Mangle a label for Linux filesystems (ext2/ext3/ext4, xfs, swap).
///
/// Truncates the label at UTF-8 character boundaries so that it fits within
/// `max_len` bytes. Returns the mangled label string on success.
fn mangle_linux_fs_label(s: &str, max_len: usize) -> MkfsResult<String> {
    if max_len == 0 {
        return Err(MkfsError::InvalidArgument("max_len must be > 0".into()));
    }

    let mut end = 0usize;
    let mut iter = s.char_indices().peekable();

    while let Some((start, ch)) = iter.next() {
        let ch_len = ch.len_utf8();
        if end + ch_len > max_len {
            break;
        }
        end = start + ch_len;
    }

    Ok(s[..end].to_owned())
}

/// Mangle a label for FAT filesystems.
///
/// Converts to ASCII (replacing non-ASCII with '_'), truncates to 11 characters,
/// uppercases, and replaces disallowed characters with '_'.
fn mangle_fat_label(s: &str) -> MkfsResult<String> {
    let ascii: String = s
        .chars()
        .map(|c| if c.is_ascii() { c } else { '_' })
        .collect();

    let mut label = ascii;
    // Truncate to 11 characters at char boundary
    if label.chars().count() > VFAT_LABEL_MAX {
        label = label.chars().take(VFAT_LABEL_MAX).collect();
    }

    // Uppercase
    label = label.to_ascii_uppercase();

    // Replace disallowed characters and control chars
    let mut result = String::with_capacity(label.len());
    for ch in label.chars() {
        if VFAT_DISALLOWED.contains(&(ch as u8)) || ch.is_ascii_control() {
            result.push('_');
        } else {
            result.push(ch);
        }
    }

    Ok(result)
}

// ── mkfs binary detection ───────────────────────────────────────────────

/// Check if a mkfs binary for the given filesystem type exists in PATH.
///
/// Returns `Ok(true)` if found, `Ok(false)` if not found, or an error for
/// invalid filesystem types.
///
/// Refuses "auto" and "swap" as they are not real filesystem types, and
/// rejects types containing slashes or other path-traversal characters.
pub fn mkfs_exists(fstype: &str) -> MkfsResult<bool> {
    if RESERVED_FSTYPES.contains(&fstype) {
        return Err(MkfsError::InvalidArgument(format!(
            "Filesystem type '{fstype}' is reserved"
        )));
    }

    let mkfs_name = format!("mkfs.{fstype}");

    // Refuse filesystem types with slashes or path separators
    if mkfs_name.contains('/') || mkfs_name.contains('\0') || mkfs_name.contains("..") {
        return Err(MkfsError::InvalidArgument(format!(
            "Filesystem type '{fstype}' contains invalid characters"
        )));
    }

    // Check if the filename component is valid (no path separators, etc.)
    let name = Path::new(&mkfs_name);
    if name.components().count() != 1 {
        return Err(MkfsError::InvalidArgument(format!(
            "Filesystem type '{fstype}' is not a valid filename component"
        )));
    }

    find_executable_in_path(&mkfs_name)
        .map(|_| true)
        .or_else(|e| match e {
            MkfsError::NotFound(_) => Ok(false),
            other => Err(other),
        })
}

/// Check whether a filesystem type supports the root directory population option.
///
/// Returns true for read-only filesystems and for filesystem types that
/// natively support populating from a source tree.
pub fn mkfs_supports_root_option(fstype: &str) -> bool {
    fstype_is_ro(fstype) || ROOT_SUPPORTED_FSTYPES.contains(&fstype)
}

/// Check if a filesystem type is necessarily read-only.
pub fn fstype_is_ro(fstype: &str) -> bool {
    READONLY_FSTYPES.contains(&fstype)
}

// ── Executable lookup ────────────────────────────────────────────────────

/// Find an executable in PATH. Returns the path if found.
fn find_executable_in_path(name: &str) -> MkfsResult<PathBuf> {
    if name.is_empty() {
        return Err(MkfsError::NotFound(name.to_owned()));
    }

    let path = Path::new(name);
    if path.is_absolute() {
        if is_executable(path) {
            return Ok(path.to_owned());
        }
        return Err(MkfsError::NotFound(name.to_owned()));
    }

    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Ok(candidate);
        }
    }

    Err(MkfsError::NotFound(name.to_owned()))
}

/// Check if a path refers to an executable file.
fn is_executable(path: &Path) -> bool {
    path.is_file() && {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = path.metadata().map(|m| m.permissions().mode()).unwrap_or(0);
            mode & 0o111 != 0
        }
        #[cfg(not(unix))]
        {
            path.metadata()
                .map(|m| !m.permissions().readonly())
                .unwrap_or(false)
        }
    }
}

// ── Build mkfs commands ─────────────────────────────────────────────────

/// Resolved mkfs tool name and its command-line arguments plus environment.
#[derive(Debug)]
struct MkfsCommand {
    /// Path to the mkfs binary.
    tool: PathBuf,
    /// Arguments to pass to the tool (not including argv[0]).
    args: Vec<OsString>,
    /// Extra environment variables to set (KEY=VALUE pairs).
    env: Vec<(OsString, OsString)>,
    /// Whether to redirect stdout to /dev/null (for tools without --quiet).
    suppress_stdout: bool,
    /// Whether this is a block device that needs a new mount namespace (btrfs).
    needs_mount_ns: bool,
}

/// Build the mkfs command for a given filesystem type.
///
/// This constructs the full argument list, environment variables, and flags
/// needed to create the filesystem, but does NOT execute it.
fn build_mkfs_command(
    node: &str,
    fstype: &str,
    label: &str,
    root: Option<&str>,
    uuid: SdId128,
    flags: MakeFileSystemFlags,
    sector_size: u64,
    compression: Option<&str>,
    compression_level: Option<&str>,
    extra_mkfs_args: &[String],
) -> MkfsResult<MkfsCommand> {
    // Read-only filesystems require a source tree.
    if fstype_is_ro(fstype) && root.is_none() {
        return Err(MkfsError::InvalidArgument(format!(
            "Cannot generate read-only filesystem {fstype} without a source tree"
        )));
    }

    let mut suppress_stdout = false;
    let mut needs_mount_ns = false;

    // Determine the tool name and build the command.
    let (tool_name, args, env) = match fstype {
        "swap" => {
            if root.is_some() {
                return Err(MkfsError::InvalidArgument(
                    "A swap filesystem can't be populated".into(),
                ));
            }
            let tool = find_executable_in_path("mkswap")?;
            let mangled = mangle_linux_fs_label(label, SWAP_LABEL_MAX)?;
            let vol_id = uuid.to_uuid_string();
            let mut a = vec![os("-L"), os(&mangled), os("-U"), os(&vol_id), os(node)];
            if flags.contains(MakeFileSystemFlags::QUIET) {
                suppress_stdout = true;
            }
            (tool, a, vec![])
        }
        "squashfs" => {
            let tool = find_executable_in_path("mksquashfs")?;
            let root_path = root.ok_or_else(|| {
                MkfsError::InvalidArgument(format!(
                    "Cannot generate read-only filesystem {fstype} without a source tree"
                ))
            })?;
            let mut a = vec![os(root_path), os(node), os("-noappend")];
            if let Some(comp) = compression {
                a.push(os("-comp"));
                a.push(os(comp));
                if let Some(level) = compression_level {
                    a.push(os("-Xcompression-level"));
                    a.push(os(level));
                }
            }
            if flags.contains(MakeFileSystemFlags::QUIET) {
                suppress_stdout = true;
            }
            (tool, a, vec![])
        }
        "erofs" => {
            let tool = find_executable_in_path("mkfs.erofs")?;
            let vol_id = uuid.to_uuid_string();
            let mut a = vec![os("-U"), os(&vol_id)];
            if flags.contains(MakeFileSystemFlags::QUIET) {
                a.push(os("--quiet"));
            }
            if let Some(comp) = compression {
                let mut c = format!("-z{comp}");
                if let Some(level) = compression_level {
                    c.push_str(&format!(",level={level}"));
                }
                a.push(os(&c));
            }
            let root_path = root.ok_or_else(|| {
                MkfsError::InvalidArgument(format!(
                    "Cannot generate read-only filesystem {fstype} without a source tree"
                ))
            })?;
            a.push(os(node));
            a.push(os(root_path));
            (tool, a, vec![])
        }
        ro if fstype_is_ro(ro) => {
            return Err(MkfsError::Unsupported(format!(
                "Don't know how to create read-only file system '{ro}'"
            )));
        }
        other => {
            // Check mkfs binary exists
            if !mkfs_exists(other)? {
                return Err(MkfsError::NotFound(format!(
                    "mkfs binary for {other} is not available"
                )));
            }
            let tool = find_executable_in_path(&format!("mkfs.{other}"))?;

            if root.is_some() && !mkfs_supports_root_option(other) {
                return Err(MkfsError::Unsupported(format!(
                    "Populating with source tree is not supported for {other}"
                )));
            }

            let (a, e) = build_rw_mkfs_args(
                other,
                &tool,
                node,
                label,
                root,
                uuid,
                flags,
                sector_size,
                compression,
                compression_level,
            )?;

            if other == "btrfs" {
                // btrfs may need new mount namespace for block devices
                needs_mount_ns = true;
            }
            if other == "vfat" || (other == "btrfs" && flags.contains(MakeFileSystemFlags::QUIET)) {
                suppress_stdout = true;
            }

            (tool, a, e)
        }
    };

    // Append extra mkfs args
    let mut final_args = args;
    for arg in extra_mkfs_args {
        final_args.push(os(arg));
    }

    Ok(MkfsCommand {
        tool: tool_name,
        args: final_args,
        env,
        suppress_stdout,
        needs_mount_ns,
    })
}

/// Build arguments for read-write filesystem types (ext2/3/4, btrfs, f2fs, xfs, vfat, etc.).
fn build_rw_mkfs_args(
    fstype: &str,
    mkfs_path: &Path,
    node: &str,
    label: &str,
    root: Option<&str>,
    uuid: SdId128,
    flags: MakeFileSystemFlags,
    sector_size: u64,
    compression: Option<&str>,
    compression_level: Option<&str>,
) -> MkfsResult<(Vec<OsString>, Vec<(OsString, OsString)>)> {
    let vol_id = uuid.to_uuid_string();
    let mut env = vec![];

    match fstype {
        "ext2" | "ext3" | "ext4" => {
            let mangled = mangle_linux_fs_label(label, EXT_LABEL_MAX)?;
            let discard = if flags.contains(MakeFileSystemFlags::DISCARD) {
                "discard"
            } else {
                "nodiscard"
            };
            let ext_e_opts = format!("{discard},lazy_itable_init=1,hash_seed={vol_id}");

            let mut a = vec![
                os(mkfs_path),
                os("-L"),
                os(&mangled),
                os("-U"),
                os(&vol_id),
                os("-I"),
                os("256"),
                os("-m"),
                os("0"),
                os("-E"),
                os(&ext_e_opts),
                os("-b"),
                os("4096"),
                os("-T"),
                os("default"),
            ];

            if let Some(root_path) = root {
                a.push(os("-d"));
                a.push(os(root_path));
            }

            if flags.contains(MakeFileSystemFlags::QUIET) {
                a.push(os("-q"));
            }

            if flags.contains(MakeFileSystemFlags::FS_VERITY) {
                a.push(os("-O"));
                a.push(os("verity"));
            }

            a.push(os(node));

            // Sector size environment variable for mke2fs
            if sector_size > 0 {
                env.push((os("MKE2FS_DEVICE_SECTSIZE"), os(&sector_size.to_string())));
            }

            // E2FSPROGS_FAKE_TIME from SOURCE_DATE_EPOCH
            if std::env::var("E2FSPROGS_FAKE_TIME").is_err() {
                if let Ok(sde) = std::env::var("SOURCE_DATE_EPOCH") {
                    env.push((os("E2FSPROGS_FAKE_TIME"), os(&sde)));
                }
            }

            Ok((a, env))
        }
        "btrfs" => {
            let mangled = mangle_linux_fs_label(label, EXT_LABEL_MAX)?;
            let mut a = vec![os(mkfs_path), os("-L"), os(&mangled), os("-U"), os(&vol_id)];

            if !flags.contains(MakeFileSystemFlags::DISCARD) {
                a.push(os("--nodiscard"));
            }

            if let Some(root_path) = root {
                a.push(os("-r"));
                a.push(os(root_path));
            }

            if flags.contains(MakeFileSystemFlags::QUIET) {
                a.push(os("-q"));
            }

            if let Some(comp) = compression {
                if root.is_none() {
                    // Warning: compression ignored without CopyFiles=
                } else {
                    let mut c = comp.to_owned();
                    if let Some(level) = compression_level {
                        c.push_str(":");
                        c.push_str(level);
                    }
                    a.push(os("--compress"));
                    a.push(os(&c));
                }
            }

            // btrfs expects sector size of at least 4k
            if sector_size > 0 {
                let effective = std::cmp::max(sector_size, BTRFS_MIN_SECTOR_SIZE);
                a.push(os(&format!("--sectorsize={effective}")));
            }

            a.push(os(node));
            Ok((a, env))
        }
        "f2fs" => {
            let mangled = mangle_linux_fs_label(label, EXT_LABEL_MAX)?;
            let discard_flag = if flags.contains(MakeFileSystemFlags::DISCARD) {
                "1"
            } else {
                "0"
            };

            let mut a = vec![
                os(mkfs_path),
                os("-g"), // default options
                os("-f"), // force override
                os("-l"),
                os(&mangled),
                os("-U"),
                os(&vol_id),
                os("-t"),
                os(discard_flag),
            ];

            if flags.contains(MakeFileSystemFlags::QUIET) {
                a.push(os("-q"));
            }

            if flags.contains(MakeFileSystemFlags::FS_VERITY) {
                a.push(os("-O"));
                a.push(os("verity"));
            }

            if sector_size > 0 {
                a.push(os("-w"));
                a.push(os(&sector_size.to_string()));
            }

            a.push(os(node));
            Ok((a, env))
        }
        "xfs" => {
            let mangled = mangle_linux_fs_label(label, XFS_LABEL_MAX)?;
            let uuid_meta = format!("uuid={vol_id}");

            let mut a = vec![
                os(mkfs_path),
                os("-L"),
                os(&mangled),
                os("-m"),
                os(&uuid_meta),
                os("-m"),
                os("reflink=1"),
            ];

            if !flags.contains(MakeFileSystemFlags::DISCARD) {
                a.push(os("-K"));
            }

            if let Some(root_path) = root {
                a.push(os("-p"));
                a.push(os(root_path));
            }

            if sector_size > 0 {
                a.push(os("-s"));
                a.push(os(&format!("size={sector_size}")));
            }

            if flags.contains(MakeFileSystemFlags::QUIET) {
                a.push(os("-q"));
            }

            a.push(os(node));
            Ok((a, env))
        }
        "vfat" => {
            // VFAT uses a truncated volume ID from the first 4 bytes of the UUID
            let vol_id_vfat = format!(
                "{:08x}",
                ((uuid.0[0] as u32) << 24)
                    | ((uuid.0[1] as u32) << 16)
                    | ((uuid.0[2] as u32) << 8)
                    | (uuid.0[3] as u32),
            );
            let mangled = mangle_fat_label(label)?;

            let mut a = vec![
                os(mkfs_path),
                os("-i"),
                os(&vol_id_vfat),
                os("-n"),
                os(&mangled),
                os("-F"),
                os("32"), // force FAT32
            ];

            if sector_size > 0 {
                a.push(os("-S"));
                a.push(os(&sector_size.to_string()));
            }

            a.push(os(node));

            if flags.contains(MakeFileSystemFlags::QUIET) {
                // vfat has no --quiet, we'll handle via suppress_stdout
            }

            Ok((a, env))
        }
        // Generic fallback for all other filesystem types
        _ => {
            let a = vec![os(mkfs_path), os(node)];
            Ok((a, env))
        }
    }
}

// ── mkfs execution ──────────────────────────────────────────────────────

/// Execute an mkfs command by forking and exec'ing the tool.
///
/// This is the core execution function that handles the actual process
/// spawning. Uses `Command` for safe process management.
fn execute_mkfs_command(cmd: &MkfsCommand) -> MkfsResult<()> {
    use std::process::Stdio;

    let mut process = std::process::Command::new(&cmd.tool);
    process.args(&cmd.args);

    // Set extra environment variables
    for (key, value) in &cmd.env {
        process.env(key, value);
    }

    // Configure stdio
    process.stderr(Stdio::inherit());
    if cmd.suppress_stdout {
        process.stdout(Stdio::null());
    } else {
        process.stdout(Stdio::inherit());
    }

    // Execute
    let status = process.status()?;

    if status.success() {
        Ok(())
    } else {
        Err(MkfsError::ChildFailed(status.code().unwrap_or(-1)))
    }
}

// ── mcopy execution ─────────────────────────────────────────────────────

/// Execute mcopy to populate a VFAT filesystem with files from a root directory.
///
/// This handles the special case where mkfs.vfat cannot populate the filesystem
/// itself, so we use mcopy (from mtools) to copy files after formatting.
fn do_mcopy(node: &str, root: &str) -> MkfsResult<()> {
    let mcopy_path = find_executable_in_path("mcopy").map_err(|_| {
        MkfsError::Unsupported("Could not find mcopy binary (needed for populating vfat)".into())
    })?;

    // Check if root directory is empty
    if dir_is_empty(root) {
        return Ok(());
    }

    // Build mcopy arguments
    let mut args: Vec<OsString> = vec![
        os(&mcopy_path),
        os("-s"),
        os("-p"),
        os("-Q"),
        os("-m"),
        os("-i"),
        os(node),
    ];

    // Add entries from root directory
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() && !file_type.is_dir() {
            continue;
        }
        args.push(os(entry.path()));
    }

    args.push(os("::"));

    // Execute mcopy with MTOOLS_SKIP_CHECK=1 and TZ=UTC
    let status = std::process::Command::new(&mcopy_path)
        .args(&args[1..]) // skip argv[0] since Command::new already provides it
        .env("MTOOLS_SKIP_CHECK", "1")
        .env("TZ", "UTC")
        .stderr(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(MkfsError::ChildFailed(status.code().unwrap_or(-1)))
    }
}

/// Check if a directory is empty.
fn dir_is_empty(path: &str) -> bool {
    std::fs::read_dir(path)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(true)
}

// ── Public API: make_filesystem ──────────────────────────────────────────

/// Create a filesystem on a device node.
///
/// This is the main entry point that:
/// 1. Validates arguments
/// 2. Builds the mkfs command line
/// 3. Executes the mkfs tool
/// 4. For vfat, optionally runs mcopy to populate the filesystem
///
/// # Arguments
///
/// * `node` - Device node path (e.g., /dev/sda1)
/// * `fstype` - Filesystem type (ext4, btrfs, xfs, vfat, etc.)
/// * `label` - Filesystem label
/// * `root` - Optional source directory for populating the filesystem
/// * `uuid` - 128-bit UUID for the filesystem
/// * `flags` - Creation flags (quiet, discard, fs-verity)
/// * `sector_size` - Sector size in bytes (0 for default)
/// * `compression` - Compression algorithm name (for btrfs, squashfs, erofs)
/// * `compression_level` - Compression level string
/// * `extra_mkfs_args` - Additional arguments to pass to the mkfs tool
pub fn make_filesystem(
    node: &str,
    fstype: &str,
    label: &str,
    root: Option<&str>,
    uuid: SdId128,
    flags: MakeFileSystemFlags,
    sector_size: u64,
    compression: Option<&str>,
    compression_level: Option<&str>,
    extra_mkfs_args: &[String],
) -> MkfsResult<()> {
    let cmd = build_mkfs_command(
        node,
        fstype,
        label,
        root,
        uuid,
        flags,
        sector_size,
        compression,
        compression_level,
        extra_mkfs_args,
    )?;

    execute_mkfs_command(&cmd)?;

    // For vfat with root, run mcopy to populate
    if fstype == "vfat" {
        if let Some(root_path) = root {
            do_mcopy(node, root_path)?;
        }
    }

    Ok(())
}

// ── Environment variable options ─────────────────────────────────────────

/// Read mkfs options from an environment variable.
///
/// The environment variable name is constructed as:
/// `SYSTEMD_{COMPONENT}_MKFS_OPTIONS_{FSTYPE}` (uppercased).
///
/// Returns a vector of argument strings parsed from the environment variable
/// value, split by whitespace.
pub fn mkfs_options_from_env(component: &str, fstype: &str) -> MkfsResult<Vec<String>> {
    let env_name = format!("SYSTEMD_{component}_MKFS_OPTIONS_{fstype}").to_ascii_uppercase();

    match std::env::var(&env_name) {
        Ok(value) => {
            let args: Vec<String> = value.split_whitespace().map(String::from).collect();
            Ok(args)
        }
        Err(_) => Ok(vec![]),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Convert a &str to an OsString.
fn os(s: impl AsRef<OsStr>) -> OsString {
    s.as_ref().to_os_string()
}

/// Get the mkfs binary name for a filesystem type.
/// Returns "mkswap" for swap, "mksquashfs" for squashfs, "mkfs.erofs" for erofs,
/// or "mkfs.{fstype}" for everything else.
pub fn mkfs_binary_name(fstype: &str) -> &'static str {
    match fstype {
        "swap" => "mkswap",
        "squashfs" => "mksquashfs",
        "erofs" => "mkfs.erofs",
        _ => "mkfs",
    }
}

/// Get the mkfs tool prefix for a filesystem type.
/// Returns the expected binary name (e.g., "mkfs.ext4").
pub fn mkfs_tool_name(fstype: &str) -> String {
    match fstype {
        "swap" => "mkswap".to_owned(),
        "squashfs" => "mksquashfs".to_owned(),
        "erofs" => "mkfs.erofs".to_owned(),
        other => format!("mkfs.{other}"),
    }
}

/// Determine the volume ID string for a filesystem type.
///
/// For most filesystems this is the full UUID string.
/// For vfat, it's the truncated 8-character hex from the first 4 bytes.
pub fn volume_id_for_fstype(fstype: &str, uuid: SdId128) -> String {
    match fstype {
        "vfat" => format!(
            "{:08x}",
            ((uuid.0[0] as u32) << 24)
                | ((uuid.0[1] as u32) << 16)
                | ((uuid.0[2] as u32) << 8)
                | (uuid.0[3] as u32),
        ),
        _ => uuid.to_uuid_string(),
    }
}

/// Get the expected label length for a filesystem type.
pub fn label_max_len(fstype: &str) -> Option<usize> {
    match fstype {
        "ext2" | "ext3" | "ext4" | "btrfs" => Some(EXT_LABEL_MAX),
        "xfs" => Some(XFS_LABEL_MAX),
        "swap" => Some(SWAP_LABEL_MAX),
        "vfat" => Some(VFAT_LABEL_MAX),
        _ => None,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fstype_is_ro() {
        assert!(fstype_is_ro("erofs"));
        assert!(fstype_is_ro("squashfs"));
        assert!(fstype_is_ro("cramfs"));
        assert!(fstype_is_ro("iso9660"));
        assert!(fstype_is_ro("DM_verity_hash"));
        assert!(!fstype_is_ro("ext4"));
        assert!(!fstype_is_ro("btrfs"));
        assert!(!fstype_is_ro("xfs"));
        assert!(!fstype_is_ro("vfat"));
        assert!(!fstype_is_ro("f2fs"));
    }

    #[test]
    fn test_mkfs_supports_root_option() {
        assert!(mkfs_supports_root_option("ext4"));
        assert!(mkfs_supports_root_option("ext3"));
        assert!(mkfs_supports_root_option("ext2"));
        assert!(mkfs_supports_root_option("btrfs"));
        assert!(mkfs_supports_root_option("vfat"));
        assert!(mkfs_supports_root_option("xfs"));
        assert!(mkfs_supports_root_option("erofs")); // read-only
        assert!(mkfs_supports_root_option("squashfs")); // read-only
        assert!(!mkfs_supports_root_option("f2fs"));
        assert!(!mkfs_supports_root_option("swap"));
    }

    #[test]
    fn test_mangle_linux_fs_label_short() {
        let result = mangle_linux_fs_label("hello", 16).unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_mangle_linux_fs_label_exact_fit() {
        let result = mangle_linux_fs_label("0123456789abcdef", 16).unwrap();
        assert_eq!(result, "0123456789abcdef");
    }

    #[test]
    fn test_mangle_linux_fs_label_truncate_at_char_boundary() {
        // "日本語" is 9 bytes, should truncate cleanly at 6 bytes (2 chars)
        let result = mangle_linux_fs_label("日本語", 6).unwrap();
        assert_eq!(result, "日本");
    }

    #[test]
    fn test_mangle_linux_fs_label_truncate_preserves_valid_utf8() {
        // "aébç" is 5 bytes (a=1, é=2, b=1, ç=2), truncate to 4 bytes -> "aéb"
        let result = mangle_linux_fs_label("aébç", 4).unwrap();
        assert_eq!(result, "aéb");
    }

    #[test]
    fn test_mangle_linux_fs_label_zero_max_len() {
        let result = mangle_linux_fs_label("test", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_mangle_linux_fs_label_empty_string() {
        let result = mangle_linux_fs_label("", 16).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_mangle_fat_label_basic() {
        let result = mangle_fat_label("mydisk").unwrap();
        assert_eq!(result, "MYDISK");
    }

    #[test]
    fn test_mangle_fat_label_truncates() {
        let result = mangle_fat_label("this_is_a_very_long_label").unwrap();
        assert_eq!(result.len(), VFAT_LABEL_MAX);
        assert_eq!(result, "THIS_IS_A_V");
    }

    #[test]
    fn test_mangle_fat_label_replaces_disallowed() {
        let result = mangle_fat_label("test*label?with/bad").unwrap();
        assert_eq!(result, "TEST_LABEL_");
    }

    #[test]
    fn test_mangle_fat_label_replaces_non_ascii() {
        let result = mangle_fat_label("café").unwrap();
        assert_eq!(result, "CAF_");
    }

    #[test]
    fn test_mangle_fat_label_empty() {
        let result = mangle_fat_label("").unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_mkfs_exists_refuses_auto() {
        let result = mkfs_exists("auto");
        assert!(result.is_err());
        match result.unwrap_err() {
            MkfsError::InvalidArgument(msg) => assert!(msg.contains("reserved")),
            other => panic!("Expected InvalidArgument, got: {other}"),
        }
    }

    #[test]
    fn test_mkfs_exists_refuses_swap() {
        let result = mkfs_exists("swap");
        assert!(result.is_err());
        match result.unwrap_err() {
            MkfsError::InvalidArgument(msg) => assert!(msg.contains("reserved")),
            other => panic!("Expected InvalidArgument, got: {other}"),
        }
    }

    #[test]
    fn test_mkfs_exists_refuses_slash() {
        let result = mkfs_exists("../../bin/sh");
        assert!(result.is_err());
    }

    #[test]
    fn test_mkfs_binary_name() {
        assert_eq!(mkfs_binary_name("swap"), "mkswap");
        assert_eq!(mkfs_binary_name("squashfs"), "mksquashfs");
        assert_eq!(mkfs_binary_name("erofs"), "mkfs.erofs");
        assert_eq!(mkfs_binary_name("ext4"), "mkfs");
        assert_eq!(mkfs_binary_name("btrfs"), "mkfs");
    }

    #[test]
    fn test_mkfs_tool_name() {
        assert_eq!(mkfs_tool_name("swap"), "mkswap");
        assert_eq!(mkfs_tool_name("squashfs"), "mksquashfs");
        assert_eq!(mkfs_tool_name("erofs"), "mkfs.erofs");
        assert_eq!(mkfs_tool_name("ext4"), "mkfs.ext4");
        assert_eq!(mkfs_tool_name("btrfs"), "mkfs.btrfs");
        assert_eq!(mkfs_tool_name("xfs"), "mkfs.xfs");
    }

    #[test]
    fn test_volume_id_for_fstype() {
        let uuid = SdId128::from_bytes([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]);

        // vfat: truncated to first 4 bytes
        let vfat_id = volume_id_for_fstype("vfat", uuid);
        assert_eq!(vfat_id, "01234567");

        // ext4: full UUID string
        let ext4_id = volume_id_for_fstype("ext4", uuid);
        assert_eq!(ext4_id, "01234567-89ab-cdef-fedc-ba9876543210");
    }

    #[test]
    fn test_label_max_len() {
        assert_eq!(label_max_len("ext4"), Some(EXT_LABEL_MAX));
        assert_eq!(label_max_len("xfs"), Some(XFS_LABEL_MAX));
        assert_eq!(label_max_len("swap"), Some(SWAP_LABEL_MAX));
        assert_eq!(label_max_len("vfat"), Some(VFAT_LABEL_MAX));
        assert_eq!(label_max_len("ext2"), Some(EXT_LABEL_MAX));
        assert_eq!(label_max_len("ext3"), Some(EXT_LABEL_MAX));
        assert_eq!(label_max_len("btrfs"), Some(EXT_LABEL_MAX));
        assert_eq!(label_max_len("f2fs"), None);
        assert_eq!(label_max_len("erofs"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_mkfs_options_from_env_not_set() {
        let result = mkfs_options_from_env("TESTCOMP", "ext4").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_mkfs_options_from_env_set() {
        std::env::set_var(
            "SYSTEMD_TESTCOMP_MKFS_OPTIONS_EXT4",
            "-O ^has_journal -b 4096",
        );
        let result = mkfs_options_from_env("TESTCOMP", "ext4").unwrap();
        assert_eq!(result, vec!["-O", "^has_journal", "-b", "4096"]);
        std::env::remove_var("SYSTEMD_TESTCOMP_MKFS_OPTIONS_EXT4");
    }

    #[test]
    fn test_mkfs_options_from_env_case_insensitive() {
        // The component/fstype are uppercased
        std::env::set_var("SYSTEMD_TEST_MKFS_OPTIONS_XFS", "-f");
        let result = mkfs_options_from_env("test", "xfs").unwrap();
        assert_eq!(result, vec!["-f"]);
        std::env::remove_var("SYSTEMD_TEST_MKFS_OPTIONS_XFS");
    }

    #[test]
    fn test_sd_id128_null() {
        assert_eq!(SdId128::NULL.0, [0u8; 16]);
    }

    #[test]
    fn test_sd_id128_to_uuid_string() {
        let uuid = SdId128::from_bytes([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]);
        assert_eq!(
            uuid.to_uuid_string(),
            "01234567-89ab-cdef-fedc-ba9876543210"
        );
    }

    #[test]
    fn test_sd_id128_to_hex_string() {
        let uuid = SdId128::from_bytes([
            0xaa, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]);
        assert_eq!(uuid.to_hex_string(), "aabb0000000000000000000000000000");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_build_mkfs_command_swap_no_root() {
        let uuid = SdId128::NULL;
        let result = build_mkfs_command(
            "/dev/sda1",
            "swap",
            "myswap",
            None,
            uuid,
            MakeFileSystemFlags::empty(),
            0,
            None,
            None,
            &[],
        );
        assert!(result.is_ok());
        let cmd = result.unwrap();
        assert!(cmd.tool.to_string_lossy().contains("mkswap"));
    }

    #[test]
    fn test_build_mkfs_command_swap_with_root_fails() {
        let uuid = SdId128::NULL;
        let result = build_mkfs_command(
            "/dev/sda1",
            "swap",
            "myswap",
            Some("/root"),
            uuid,
            MakeFileSystemFlags::empty(),
            0,
            None,
            None,
            &[],
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            MkfsError::InvalidArgument(msg) => assert!(msg.contains("populated")),
            other => panic!("Expected InvalidArgument, got: {other}"),
        }
    }

    #[test]
    fn test_build_mkfs_command_ro_without_root_fails() {
        let uuid = SdId128::NULL;
        let result = build_mkfs_command(
            "/dev/sda1",
            "erofs",
            "mylabel",
            None,
            uuid,
            MakeFileSystemFlags::empty(),
            0,
            None,
            None,
            &[],
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            MkfsError::InvalidArgument(msg) => {
                assert!(msg.contains("source tree"))
            }
            other => panic!("Expected InvalidArgument, got: {other}"),
        }
    }

    #[test]
    fn test_build_mkfs_command_unknown_ro_fails() {
        let uuid = SdId128::NULL;
        let result = build_mkfs_command(
            "/dev/sda1",
            "cramfs",
            "mylabel",
            Some("/root"),
            uuid,
            MakeFileSystemFlags::empty(),
            0,
            None,
            None,
            &[],
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            MkfsError::Unsupported(msg) => assert!(msg.contains("read-only")),
            other => panic!("Expected Unsupported, got: {other}"),
        }
    }

    #[test]
    fn test_flags() {
        let f = MakeFileSystemFlags::QUIET | MakeFileSystemFlags::DISCARD;
        assert!(f.contains(MakeFileSystemFlags::QUIET));
        assert!(f.contains(MakeFileSystemFlags::DISCARD));
        assert!(!f.contains(MakeFileSystemFlags::FS_VERITY));
    }

    #[test]
    fn test_readonly_fstypes_completeness() {
        // Verify all expected read-only types are present
        assert!(READONLY_FSTYPES.contains(&"erofs"));
        assert!(READONLY_FSTYPES.contains(&"squashfs"));
        assert!(READONLY_FSTYPES.contains(&"cramfs"));
        assert!(READONLY_FSTYPES.contains(&"iso9660"));
        assert!(READONLY_FSTYPES.contains(&"DM_verity_hash"));
    }

    #[test]
    fn test_reserved_fstypes_completeness() {
        assert!(RESERVED_FSTYPES.contains(&"auto"));
        assert!(RESERVED_FSTYPES.contains(&"swap"));
        assert_eq!(RESERVED_FSTYPES.len(), 2);
    }

    #[test]
    fn test_root_supported_fstypes_completeness() {
        for fst in &["ext2", "ext3", "ext4", "btrfs", "vfat", "xfs"] {
            assert!(ROOT_SUPPORTED_FSTYPES.contains(fst), "Missing {fst}");
        }
    }

    #[test]
    fn test_error_display() {
        let e = MkfsError::InvalidArgument("bad arg".into());
        assert_eq!(format!("{e}"), "Invalid argument: bad arg");

        let e = MkfsError::NotFound("mkfs.ext4".into());
        assert_eq!(format!("{e}"), "Not found: mkfs.ext4");

        let e = MkfsError::Unsupported("f2fs".into());
        assert_eq!(format!("{e}"), "Unsupported: f2fs");

        let e = MkfsError::ChildFailed(1);
        assert!(format!("{e}").contains("exit code 1"));
    }
}
