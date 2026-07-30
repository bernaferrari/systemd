// SPDX-License-Identifier: LGPL-2.1-or-later
#![deny(unsafe_op_in_unsafe_fn)]
//
// PORT-SYNC: src/mstack/mstack-tool.c
//
// Inspect, mount, or unmount overlayfs-based stacked mounts (mstack).
//
// An mstack is a directory containing mount configuration entries that
// describe how to assemble a layered filesystem. This tool supports
// three actions: inspect (show entries), mount (apply), and umount
// (tear down).

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

/// Top-level action for the mstack tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MstackAction {
    #[default]
    Inspect,
    Mount,
    Umount,
}

// ── Configuration ─────────────────────────────────────────────────────────

/// Parsed command-line configuration for mstack operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MstackConfig {
    pub action: MstackAction,
    pub source_path: Option<String>,
    pub target_path: Option<String>,
    pub read_only: bool,
    pub mkdir: bool,
    pub rmdir: bool,
    pub json_format: bool,
    pub no_legend: bool,
}

impl Default for MstackConfig {
    fn default() -> Self {
        Self {
            action: MstackAction::Inspect,
            source_path: None,
            target_path: None,
            read_only: false,
            mkdir: false,
            rmdir: false,
            json_format: false,
            no_legend: false,
        }
    }
}

impl MstackConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate that the configuration is consistent for the chosen action.
    pub fn validate(&self) -> Result<()> {
        match self.action {
            MstackAction::Inspect => {
                if self.source_path.is_none() {
                    return Err(Errno(-libc::EINVAL));
                }
            }
            MstackAction::Mount => {
                if self.source_path.is_none() || self.target_path.is_none() {
                    return Err(Errno(-libc::EINVAL));
                }
            }
            MstackAction::Umount => {
                if self.target_path.is_none() {
                    return Err(Errno(-libc::EINVAL));
                }
            }
        }
        Ok(())
    }
}

// ── Mount entry representation ────────────────────────────────────────────

/// A single entry in the mstack, describing one layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MstackEntry {
    pub mount_type: String,
    pub what: String,
    pub image_type: String,
    pub what_fd_path: Option<String>,
    pub where_path: Option<String>,
    pub sort_key: Option<String>,
}

impl MstackEntry {
    pub fn new(mount_type: &str, what: &str) -> Self {
        Self {
            mount_type: mount_type.to_string(),
            what: what.to_string(),
            image_type: String::new(),
            what_fd_path: None,
            where_path: None,
            sort_key: None,
        }
    }

    /// Resolve the effective mount target: entry-specific path or default.
    pub fn effective_where<'a>(&'a self, default: &'a str) -> &'a str {
        self.where_path.as_deref().unwrap_or(default)
    }
}

// ── Validation helpers ────────────────────────────────────────────────────

/// Validate a mstack prefix/directory name.
/// Must be non-empty, ≤255 chars, and contain only alphanumeric, dash, or underscore.
pub fn validate_prefix_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 255 {
        return Err(Errno(-libc::EINVAL));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Errno(-libc::EINVAL));
    }
    Ok(())
}

/// Validate a mount option string.
pub fn is_known_mount_option(opt: &str) -> bool {
    matches!(opt, "ro" | "rw")
}

/// Parse a comma-separated mount option string into individual options.
pub fn parse_mount_options(options: &str) -> Vec<&str> {
    options
        .split(',')
        .map(|o| o.trim())
        .filter(|o| !o.is_empty())
        .collect()
}

// ── Overlay option builder ────────────────────────────────────────────────

/// Build overlay mount options from lower directories.
pub fn build_overlay_options(lower_dirs: &[String], read_only: bool) -> String {
    if lower_dirs.is_empty() {
        return String::new();
    }
    let lower = lower_dirs.join(":");
    if read_only {
        format!("lowerdir={}", lower)
    } else {
        format!("lowerdir={},upperdir=upper,workdir=work", lower)
    }
}

// ── Action parsing from command-line arguments ────────────────────────────

/// Parse the shortcut flag combinations:
/// -M = --mount --mkdir, -U = --umount --rmdir
pub fn parse_shortcut_flags(flag: char, config: &mut MstackConfig) -> Result<()> {
    match flag {
        'M' => {
            config.action = MstackAction::Mount;
            config.mkdir = true;
        }
        'U' => {
            config.action = MstackAction::Umount;
            config.rmdir = true;
        }
        _ => return Err(Errno(-libc::EINVAL)),
    }
    Ok(())
}

/// Determine the number of positional arguments expected for the action.
pub fn expected_arg_count(action: MstackAction) -> usize {
    match action {
        MstackAction::Inspect => 1,
        MstackAction::Mount => 2,
        MstackAction::Umount => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_inspect() {
        let cfg = MstackConfig::new();
        assert_eq!(cfg.action, MstackAction::Inspect);
        assert!(cfg.source_path.is_none());
        assert!(!cfg.read_only);
    }

    #[test]
    fn validate_inspect_needs_source() {
        let cfg = MstackConfig::new();
        assert!(cfg.validate().is_err());
        let mut cfg2 = MstackConfig::new();
        cfg2.source_path = Some("/path".into());
        assert!(cfg2.validate().is_ok());
    }

    #[test]
    fn validate_mount_needs_both() {
        let mut cfg = MstackConfig {
            action: MstackAction::Mount,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
        cfg.source_path = Some("/src".into());
        assert!(cfg.validate().is_err());
        cfg.target_path = Some("/tgt".into());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_umount_needs_target() {
        let cfg = MstackConfig {
            action: MstackAction::Umount,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
        let mut cfg2 = cfg.clone();
        cfg2.target_path = Some("/tgt".into());
        assert!(cfg2.validate().is_ok());
    }

    #[test]
    fn validate_prefix_name_valid() {
        assert!(validate_prefix_name("my-layer").is_ok());
        assert!(validate_prefix_name("layer_1").is_ok());
        assert!(validate_prefix_name("ABC123").is_ok());
    }

    #[test]
    fn validate_prefix_name_invalid() {
        assert!(validate_prefix_name("").is_err());
        assert!(validate_prefix_name("a b").is_err());
        assert!(validate_prefix_name("a/b").is_err());
    }

    #[test]
    fn parse_mount_options_basic() {
        let opts = parse_mount_options("ro,nodev,nosuid");
        assert_eq!(opts, vec!["ro", "nodev", "nosuid"]);
    }

    #[test]
    fn known_mount_options() {
        assert!(is_known_mount_option("ro"));
        assert!(is_known_mount_option("rw"));
        assert!(!is_known_mount_option("nodev"));
    }

    #[test]
    fn build_overlay_options_ro() {
        let opts = build_overlay_options(&["/a".into(), "/b".into()], true);
        assert_eq!(opts, "lowerdir=/a:/b");
    }

    #[test]
    fn build_overlay_options_rw() {
        let opts = build_overlay_options(&["/lower".into()], false);
        assert!(opts.contains("upperdir=upper"));
        assert!(opts.contains("workdir=work"));
        assert!(opts.contains("lowerdir=/lower"));
    }

    #[test]
    fn shortcut_flags() {
        let mut cfg = MstackConfig::new();
        parse_shortcut_flags('M', &mut cfg).unwrap();
        assert_eq!(cfg.action, MstackAction::Mount);
        assert!(cfg.mkdir);

        let mut cfg2 = MstackConfig::new();
        parse_shortcut_flags('U', &mut cfg2).unwrap();
        assert_eq!(cfg2.action, MstackAction::Umount);
        assert!(cfg2.rmdir);
    }

    #[test]
    fn expected_arg_counts() {
        assert_eq!(expected_arg_count(MstackAction::Inspect), 1);
        assert_eq!(expected_arg_count(MstackAction::Mount), 2);
        assert_eq!(expected_arg_count(MstackAction::Umount), 1);
    }

    #[test]
    fn mstack_entry_effective_where() {
        let entry = MstackEntry::new("bind", "/dev/sda1");
        assert_eq!(entry.effective_where("/usr"), "/usr");

        let mut entry2 = entry.clone();
        entry2.where_path = Some("/custom".into());
        assert_eq!(entry2.effective_where("/usr"), "/custom");
    }
}
