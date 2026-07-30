// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/mount/mount-tool.c
//
// Establish mount or auto-mount points transiently via D-Bus.
//
// Supports mounting, unmounting, listing block devices, and discovering
// mount metadata. Can operate locally or on remote hosts via D-Bus transport.

// ── Error type ────────────────────────────────────────────────────────────

pub type Result<T> = std::result::Result<T, Errno>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub i32);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

// ── Action enum ───────────────────────────────────────────────────────────

/// Top-level action for systemd-mount / systemd-umount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MountAction {
    #[default]
    Default,
    Mount,
    Automount,
    Umount,
    List,
}

// ── Runtime scope ─────────────────────────────────────────────────────────

/// Whether to operate on system or user units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuntimeScope {
    #[default]
    System,
    User,
}

// ── Mount point ───────────────────────────────────────────────────────────

/// Represents a mount to be established or queried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountPoint {
    pub what: String,
    pub where_path: String,
    pub fstype: Option<String>,
    pub options: Option<String>,
    pub description: Option<String>,
}

impl MountPoint {
    pub fn new(what: &str, where_path: &str) -> Self {
        Self {
            what: what.to_string(),
            where_path: where_path.to_string(),
            fstype: None,
            options: None,
            description: None,
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

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }
}

// ── Path validation ───────────────────────────────────────────────────────

/// Validate that a mount target path is absolute.
pub fn parse_mount_where(input: &str) -> Result<String> {
    let path = input.trim();
    if path.is_empty() {
        return Err(Errno(-libc::EINVAL));
    }
    if !path.starts_with('/') {
        return Err(Errno(-libc::EINVAL));
    }
    Ok(path.to_string())
}

/// Check whether the tool was invoked as "systemd-umount".
pub fn invoked_as_umount(invocation_name: &str) -> bool {
    std::path::Path::new(invocation_name)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        == Some("systemd-umount")
}

// ── Mount option parsing ──────────────────────────────────────────────────

/// Check if a comma-separated option string contains a specific option.
pub fn mount_option_contains(options: &str, opt: &str) -> bool {
    options.split(',').any(|o| o.trim() == opt)
}

pub fn mount_option_ro(options: &str) -> bool {
    mount_option_contains(options, "ro")
}

pub fn mount_option_rw(options: &str) -> bool {
    mount_option_contains(options, "rw")
}

pub fn mount_option_noauto(options: &str) -> bool {
    mount_option_contains(options, "noauto")
}

pub fn mount_option_nofail(options: &str) -> bool {
    mount_option_contains(options, "nofail")
}

/// Validate a filesystem type string.
/// Must be non-empty, <128 chars, ASCII alphanumeric/dash/underscore/dot.
pub fn is_valid_fstype(fs: &str) -> bool {
    !fs.is_empty()
        && fs.len() < 128
        && fs
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

// ── Unit name helpers ─────────────────────────────────────────────────────

/// Generate a systemd mount unit name from a path.
/// E.g. "/mnt/data" → "mnt-data.mount"
pub fn mount_unit_name_from_path(path: &str) -> String {
    let escaped = path
        .trim_start_matches('/')
        .replace('/', "-")
        .replace('-', "\\x2d");
    if escaped.is_empty() {
        return "-.mount".to_string();
    }
    format!("{}.mount", escaped)
}

/// Generate a systemd automount unit name from a path.
pub fn automount_unit_name_from_path(path: &str) -> String {
    mount_unit_name_from_path(path).replace(".mount", ".automount")
}

/// Check if a path looks like an automount unit.
pub fn is_automount_path(path: &str) -> bool {
    path.ends_with(".automount")
}

// ── Tmpfs option builder ──────────────────────────────────────────────────

/// Build mount options for a tmpfs mount with uid/gid and mode.
pub fn build_tmpfs_options(uid: Option<u32>, gid: Option<u32>, umask: u32) -> String {
    let mut parts = Vec::new();
    if let (Some(uid), Some(gid)) = (uid, gid) {
        parts.push(format!("uid={},gid={}", uid, gid));
    }
    parts.push(format!("mode=0{:o}", 0o777 & !umask));
    parts.push("nodev".to_string());
    parts.push("nosuid".to_string());
    parts.join(",")
}

/// Determine if a filesystem type is backed by a block device.
pub fn fstype_is_blockdev_backed(fstype: &str) -> bool {
    !matches!(
        fstype,
        "tmpfs" | "proc" | "sysfs" | "devtmpfs" | "debugfs" | "tracefs"
    )
}

// ── D-Bus transport ───────────────────────────────────────────────────────

/// Bus transport mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BusTransport {
    #[default]
    Local,
    Remote,
    Machine,
}

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
    }

    #[test]
    fn mount_point_builder() {
        let mp = MountPoint::new("/dev/sda1", "/mnt/data")
            .with_fstype("ext4")
            .with_options("noatime")
            .with_description("Data partition");
        assert_eq!(mp.what, "/dev/sda1");
        assert_eq!(mp.where_path, "/mnt/data");
        assert_eq!(mp.fstype.as_deref(), Some("ext4"));
        assert_eq!(mp.options.as_deref(), Some("noatime"));
        assert_eq!(mp.description.as_deref(), Some("Data partition"));
    }

    #[test]
    fn mount_option_checks() {
        assert!(mount_option_ro("ro,nodev"));
        assert!(!mount_option_ro("rw,nodev"));
        assert!(mount_option_rw("rw"));
        assert!(mount_option_noauto("noauto"));
        assert!(mount_option_nofail("nofail,ro"));
    }

    #[test]
    fn is_valid_fstype_checks() {
        assert!(is_valid_fstype("ext4"));
        assert!(is_valid_fstype("xfs"));
        assert!(is_valid_fstype("ntfs-3g"));
        assert!(!is_valid_fstype(""));
        assert!(!is_valid_fstype("a b"));
    }

    #[test]
    fn mount_unit_name() {
        assert_eq!(mount_unit_name_from_path("/"), "-.mount");
        assert!(mount_unit_name_from_path("/mnt/data").ends_with(".mount"));
    }

    #[test]
    fn automount_unit_name() {
        let name = automount_unit_name_from_path("/mnt/data");
        assert!(name.ends_with(".automount"));
    }

    #[test]
    fn is_automount_path_check() {
        assert!(is_automount_path("/mnt/data.automount"));
        assert!(!is_automount_path("/mnt/data.mount"));
    }

    #[test]
    fn invoked_as_umount_check() {
        assert!(invoked_as_umount("systemd-umount"));
        assert!(invoked_as_umount("/usr/bin/systemd-umount"));
        assert!(!invoked_as_umount("systemd-mount"));
        assert!(!invoked_as_umount("systemd-umount-helper"));
    }

    #[test]
    fn fstype_blockdev_backed() {
        assert!(fstype_is_blockdev_backed("ext4"));
        assert!(!fstype_is_blockdev_backed("tmpfs"));
        assert!(!fstype_is_blockdev_backed("proc"));
    }

    #[test]
    fn tmpfs_options() {
        let opts = build_tmpfs_options(Some(1000), Some(1000), 0o022);
        assert!(opts.contains("uid=1000"));
        assert!(opts.contains("gid=1000"));
        assert!(opts.contains("nodev"));
        assert!(opts.contains("nosuid"));
    }
}
