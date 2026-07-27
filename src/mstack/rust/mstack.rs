// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/mstack/mstack-tool.c
//
// Overlayfs mount stack management (mstack).
//
// Provides types and utilities for inspecting, mounting, and unmounting
// `.mstack/` overlay-based layered filesystem stacks used by containers
// and virtual machines.

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

/// Maximum prefix name length.
pub const PREFIX_NAME_MAX_LEN: usize = 255;

// ── Enums ─────────────────────────────────────────────────────────────────

/// Actions that `systemd-mstack` can perform.
///
/// Mirrors the `arg_action` enum in the C source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MstackAction {
    Inspect,
    Mount,
    Umount,
}

impl MstackAction {
    /// Parse an action from its string name.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "inspect" => Some(MstackAction::Inspect),
            "mount" => Some(MstackAction::Mount),
            "umount" => Some(MstackAction::Umount),
            _ => None,
        }
    }
}

/// Flags controlling mstack mount behaviour.
///
/// Mirrors `MStackFlags` / `MSTACK_RDONLY`, `MSTACK_MKDIR` from the C header.
bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MstackFlags: u32 {
        /// Mount the stack read-only.
        const RDONLY = 1 << 0;
        /// Create the target directory before mounting.
        const MKDIR = 1 << 1;
    }
}

// ── Configuration ─────────────────────────────────────────────────────────

/// Parsed command-line arguments for `systemd-mstack`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MstackConfig {
    /// Source image or `.mstack/` directory path (`arg_what`).
    pub source_path: Option<String>,
    /// Target mount directory (`arg_where`).
    pub target_path: Option<String>,
    /// Lower overlay directories.
    pub lower_dirs: Vec<String>,
    /// Mount flags.
    pub flags: MstackFlags,
    /// Remove mount directory after unmounting (`arg_rmdir`).
    pub rmdir: bool,
}

impl Default for MstackConfig {
    fn default() -> Self {
        Self {
            source_path: None,
            target_path: None,
            lower_dirs: Vec::new(),
            flags: MstackFlags::empty(),
            rmdir: false,
        }
    }
}

impl MstackConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Basic validation: at least a source or lower directories must be set.
    pub fn validate(&self) -> Result<()> {
        if self.source_path.is_none() && self.lower_dirs.is_empty() {
            return Err(Errno(-22)); // -EINVAL
        }
        Ok(())
    }

    pub fn add_lower_dir(&mut self, dir: &str) {
        self.lower_dirs.push(dir.to_string());
    }

    /// Check whether the mount should be read-only.
    pub fn is_readonly(&self) -> bool {
        self.flags.contains(MstackFlags::RDONLY)
    }

    /// Check whether the target directory should be created.
    pub fn should_mkdir(&self) -> bool {
        self.flags.contains(MstackFlags::MKDIR)
    }
}

// ── Name validation ───────────────────────────────────────────────────────

/// Validate a prefix/layer name: non-empty, bounded length, safe characters.
///
/// Mirrors the validation that would be applied to mstack layer identifiers.
pub fn validate_prefix_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > PREFIX_NAME_MAX_LEN {
        return Err(Errno(-22)); // -EINVAL
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Errno(-22));
    }
    Ok(())
}

// ── Overlay option construction ───────────────────────────────────────────

/// Build overlayfs mount options from lower directories and read-only flag.
///
/// For read-write mounts, also adds `upperdir` and `workdir` placeholders.
pub fn build_overlay_options(lower_dirs: &[String], read_only: bool) -> String {
    let lower = lower_dirs.join(":");
    if read_only {
        format!("lowerdir={}", lower)
    } else {
        format!("lowerdir={},upperdir=upper,workdir=work", lower)
    }
}

/// Build the full overlay mount options including any extra systemd options.
pub fn build_full_overlay_options(
    lower_dirs: &[String],
    read_only: bool,
    extra_opts: Option<&str>,
) -> String {
    let mut opts = build_overlay_options(lower_dirs, read_only);
    if let Some(extra) = extra_opts {
        if !extra.is_empty() {
            opts.push(',');
            opts.push_str(extra);
        }
    }
    opts
}

// ── Path utilities ────────────────────────────────────────────────────────

/// Check whether a path looks like an mstack directory (ends with `.mstack/` or `.mstack`).
pub fn is_mstack_path(path: &str) -> bool {
    let trimmed = path.trim_end_matches('/');
    trimmed.ends_with(".mstack")
}

/// Derive a sensible target path from a source path.
///
/// Strips the `.mstack` suffix and leading path components.
pub fn derive_target_from_source(source: &str) -> Option<String> {
    let trimmed = source.trim_end_matches('/');
    if !trimmed.ends_with(".mstack") {
        return None;
    }
    let base = trimmed.strip_suffix(".mstack")?;
    let name = base.rsplit('/').next()?;
    Some(format!("/mnt/{}", name))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = MstackConfig::new();
        assert!(cfg.source_path.is_none());
        assert!(cfg.lower_dirs.is_empty());
        assert!(!cfg.is_readonly());
        assert!(!cfg.should_mkdir());
        assert!(!cfg.rmdir);
    }

    #[test]
    fn validate_ok_with_source() {
        let mut cfg = MstackConfig::new();
        cfg.source_path = Some("/path/to/image".into());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_ok_with_lower_dirs() {
        let mut cfg = MstackConfig::new();
        cfg.add_lower_dir("/lower");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_no_source_no_dirs() {
        let cfg = MstackConfig::new();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_prefix_name_valid() {
        assert!(validate_prefix_name("my-layer").is_ok());
        assert!(validate_prefix_name("layer_1").is_ok());
        assert!(validate_prefix_name("abc123").is_ok());
    }

    #[test]
    fn validate_prefix_name_invalid() {
        assert!(validate_prefix_name("").is_err());
        assert!(validate_prefix_name("a b").is_err());
        assert!(validate_prefix_name("a/b").is_err());
        assert!(validate_prefix_name("a.b").is_err());
    }

    #[test]
    fn build_overlay_options_ro() {
        let opts = build_overlay_options(&["/lower1".into(), "/lower2".into()], true);
        assert_eq!(opts, "lowerdir=/lower1:/lower2");
    }

    #[test]
    fn build_overlay_options_rw() {
        let opts = build_overlay_options(&["/lower".into()], false);
        assert!(opts.contains("upperdir=upper"));
        assert!(opts.contains("workdir=work"));
        assert!(opts.contains("lowerdir=/lower"));
    }

    #[test]
    fn add_lower_dir() {
        let mut cfg = MstackConfig::new();
        cfg.add_lower_dir("/a");
        cfg.add_lower_dir("/b");
        assert_eq!(cfg.lower_dirs.len(), 2);
    }

    #[test]
    fn mstack_flags() {
        let flags = MstackFlags::RDONLY | MstackFlags::MKDIR;
        assert!(flags.contains(MstackFlags::RDONLY));
        assert!(flags.contains(MstackFlags::MKDIR));
        assert!(!flags.contains(MstackFlags::empty()));
    }

    #[test]
    fn is_mstack_path() {
        assert!(is_mstack_path("/path/to/image.mstack"));
        assert!(is_mstack_path("/path/to/image.mstack/"));
        assert!(!is_mstack_path("/path/to/image.raw"));
    }

    #[test]
    fn derive_target_from_source() {
        assert_eq!(
            derive_target_from_source("/images/base.mstack"),
            Some("/mnt/base".into())
        );
        assert_eq!(
            derive_target_from_source("/images/base.mstack/"),
            Some("/mnt/base".into())
        );
        assert!(derive_target_from_source("/images/base.raw").is_none());
    }

    #[test]
    fn mstack_action_from_str() {
        assert_eq!(
            MstackAction::from_str("inspect"),
            Some(MstackAction::Inspect)
        );
        assert_eq!(MstackAction::from_str("mount"), Some(MstackAction::Mount));
        assert_eq!(MstackAction::from_str("umount"), Some(MstackAction::Umount));
        assert_eq!(MstackAction::from_str("bogus"), None);
    }

    #[test]
    fn build_full_overlay_options_with_extra() {
        let opts = build_full_overlay_options(&["/lower".into()], true, Some("noatime"));
        assert!(opts.contains("noatime"));
    }
}
