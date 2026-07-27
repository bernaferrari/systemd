// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/mount/mount-tool.c
//
// Mount and unmount operations for systemd-mount.
//
// Provides types and utilities for transiently establishing mount or
// automount points, validating paths, and inspecting mount options.

// ── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

pub type Result<T> = std::result::Result<T, Errno>;

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum filesystem type name length.
pub const FSTYPE_MAX_LEN: usize = 128;

/// Maximum mount path length.
pub const MOUNT_PATH_MAX_LEN: usize = 4096;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Actions that `systemd-mount` / `systemd-umount` can perform.
///
/// Mirrors the `arg_action` enum in the C source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountAction {
    Default,
    Mount,
    Automount,
    Umount,
    List,
}

// ── Mount point ───────────────────────────────────────────────────────────

/// A parsed mount specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountPoint {
    /// Device or source path (`What`).
    pub what: String,
    /// Target mount directory (`Where`).
    pub where_path: String,
    /// Filesystem type.
    pub fstype: Option<String>,
    /// Mount options string.
    pub options: Option<String>,
}

impl MountPoint {
    pub fn new(what: &str, where_path: &str) -> Self {
        Self {
            what: what.to_string(),
            where_path: where_path.to_string(),
            fstype: None,
            options: None,
        }
    }

    pub fn with_fstype(mut self, fstype: &str) -> Self {
        self.fstype = Some(fstype.to_string());
        self
    }

    pub fn with_options(mut self, options: &str) -> Self {
        self.options = Some(options.to_string());
        self
    }

    /// Return `true` if this looks like a tmpfs mount.
    pub fn is_tmpfs(&self) -> bool {
        self.fstype.as_deref() == Some("tmpfs") || self.what == "tmpfs"
    }
}

// ── Path validation ──────────────────────────────────────────────────────

/// Validate and normalise a mount target path.
///
/// The path must be absolute (start with `/`) and non-empty.
/// Corresponds to `parse_where()` in the C source.
pub fn parse_mount_where(input: &str) -> Result<String> {
    let path = input.trim();
    if path.is_empty() {
        return Err(Errno(-22)); // -EINVAL
    }
    if !path.starts_with('/') {
        return Err(Errno(-22));
    }
    Ok(path.to_string())
}

/// Check whether a path ends with the `.automount` unit suffix.
pub fn is_automount_path(path: &str) -> bool {
    path.ends_with(".automount")
}

/// Check whether a path ends with the `.mount` unit suffix.
pub fn is_mount_path(path: &str) -> bool {
    path.ends_with(".mount")
}

// ── Option parsing ────────────────────────────────────────────────────────

/// Check whether a comma-separated options string contains a specific option.
pub fn mount_option_contains(options: &str, opt: &str) -> bool {
    options.split(',').any(|o| o.trim() == opt)
}

/// Check whether the options indicate a read-only mount.
pub fn mount_option_ro(options: &str) -> bool {
    mount_option_contains(options, "ro")
}

/// Check whether the options indicate a read-write mount.
pub fn mount_option_rw(options: &str) -> bool {
    mount_option_contains(options, "rw")
}

/// Check whether the `noauto` option is set.
pub fn mount_option_noauto(options: &str) -> bool {
    mount_option_contains(options, "noauto")
}

/// Check whether the `nofail` option is set.
pub fn mount_option_nofail(options: &str) -> bool {
    mount_option_contains(options, "nofail")
}

/// Check whether the `noatime` option is set.
pub fn mount_option_noatime(options: &str) -> bool {
    mount_option_contains(options, "noatime")
}

// ── Validation helpers ────────────────────────────────────────────────────

/// Validate a filesystem type name: non-empty, not too long, safe characters.
pub fn is_valid_fstype(fs: &str) -> bool {
    !fs.is_empty()
        && fs.len() < FSTYPE_MAX_LEN
        && fs
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// Validate a mount target path for basic sanity.
pub fn is_valid_mount_path(path: &str) -> bool {
    !path.is_empty() && path.len() < MOUNT_PATH_MAX_LEN && path.starts_with('/')
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_where_absolute() {
        assert_eq!(parse_mount_where("/mnt/data").unwrap(), "/mnt/data");
    }

    #[test]
    fn parse_where_trims_whitespace() {
        assert_eq!(parse_mount_where("  /mnt/data  ").unwrap(), "/mnt/data");
    }

    #[test]
    fn parse_where_relative_rejects() {
        assert!(parse_mount_where("mnt/data").is_err());
    }

    #[test]
    fn parse_where_empty_rejects() {
        assert!(parse_mount_where("").is_err());
        assert!(parse_mount_where("   ").is_err());
    }

    #[test]
    fn mount_point_builder() {
        let mp = MountPoint::new("/dev/sda1", "/mnt/data")
            .with_fstype("ext4")
            .with_options("noatime");
        assert_eq!(mp.what, "/dev/sda1");
        assert_eq!(mp.where_path, "/mnt/data");
        assert_eq!(mp.fstype.as_deref(), Some("ext4"));
        assert_eq!(mp.options.as_deref(), Some("noatime"));
    }

    #[test]
    fn mount_point_is_tmpfs() {
        let mp = MountPoint::new("tmpfs", "/run/tmp").with_fstype("tmpfs");
        assert!(mp.is_tmpfs());
        let mp2 = MountPoint::new("/dev/sda1", "/mnt");
        assert!(!mp2.is_tmpfs());
    }

    #[test]
    fn mount_option_checks() {
        assert!(mount_option_ro("ro,nodev"));
        assert!(!mount_option_ro("rw,nodev"));
        assert!(mount_option_rw("rw,noatime"));
        assert!(!mount_option_rw("ro"));
        assert!(mount_option_noauto("noauto"));
        assert!(mount_option_nofail("nofail,ro"));
        assert!(mount_option_noatime("rw,noatime"));
    }

    #[test]
    fn is_automount_path() {
        assert!(is_automount_path("/mnt/data.automount"));
        assert!(!is_automount_path("/mnt/data.mount"));
    }

    #[test]
    fn is_mount_path() {
        assert!(is_mount_path("/mnt/data.mount"));
        assert!(!is_mount_path("/mnt/data.automount"));
    }

    #[test]
    fn is_valid_fstype() {
        assert!(is_valid_fstype("ext4"));
        assert!(is_valid_fstype("xfs"));
        assert!(is_valid_fstype("vfat"));
        assert!(!is_valid_fstype(""));
        assert!(!is_valid_fstype("a b"));
        assert!(!is_valid_fstype("a/b"));
    }

    #[test]
    fn is_valid_mount_path() {
        assert!(is_valid_mount_path("/mnt/data"));
        assert!(is_valid_mount_path("/"));
        assert!(!is_valid_mount_path("relative"));
        assert!(!is_valid_mount_path(""));
    }

    #[test]
    fn mount_action_variants() {
        assert_ne!(MountAction::Mount, MountAction::Umount);
        assert_ne!(MountAction::Automount, MountAction::List);
    }
}
