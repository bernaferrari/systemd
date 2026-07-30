// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/home/homework-mount.c, src/home/homework-mount.h

use std::env;

use crate::home_util::supported_fstype;

pub const HOME_RUNTIME_WORK_DIR: &str = "/run/systemd/user-home-mount";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountError {
    UnsupportedFsType(String),
    InvalidNode,
    InvalidTarget,
    InvalidUidRange,
}

impl std::fmt::Display for MountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedFsType(value) => write!(f, "unsupported fs type: {value}"),
            Self::InvalidNode => write!(f, "mount node must not be empty"),
            Self::InvalidTarget => write!(f, "mount target must not be empty"),
            Self::InvalidUidRange => write!(f, "invalid identity range"),
        }
    }
}

impl std::error::Error for MountError {}

pub fn mount_options_for_fstype(fstype: &str) -> Option<String> {
    let env_key = format!("SYSTEMD_HOME_MOUNT_OPTIONS_{}", fstype.to_ascii_uppercase());
    if let Ok(value) = env::var(&env_key)
        && !value.is_empty()
    {
        return Some(value);
    }

    match fstype {
        "ext4" => Some("noquota,user_xattr".into()),
        "xfs" => Some("noquota".into()),
        "btrfs" => Some("compress=zstd:1,noacl,user_subvol_rm_allowed".into()),
        _ => None,
    }
}

pub fn home_mount_node(
    node: &str,
    fstype: &str,
    discard: bool,
    extra_mount_options: Option<&str>,
) -> Result<String, MountError> {
    if node.is_empty() {
        return Err(MountError::InvalidNode);
    }
    if !supported_fstype(fstype) {
        return Err(MountError::UnsupportedFsType(fstype.to_string()));
    }

    let mut options = Vec::new();
    if let Some(defaults) = mount_options_for_fstype(fstype) {
        options.push(defaults);
    }
    options.push(if discard {
        "discard".into()
    } else {
        "nodiscard".into()
    });
    if let Some(extra) = extra_mount_options
        && !extra.is_empty()
    {
        options.push(extra.to_string());
    }

    Ok(options.join(","))
}

pub fn home_unshare_and_mkdir() -> String {
    HOME_RUNTIME_WORK_DIR.to_string()
}

pub fn home_unshare_and_mount(
    node: &str,
    fstype: &str,
    discard: bool,
    extra_mount_options: Option<&str>,
) -> Result<String, MountError> {
    let options = home_mount_node(node, fstype, discard, extra_mount_options)?;
    Ok(format!("{}:{}", home_unshare_and_mkdir(), options))
}

pub fn home_move_mount(mount_suffix: Option<&str>, target: &str) -> Result<String, MountError> {
    if target.is_empty() {
        return Err(MountError::InvalidTarget);
    }

    Ok(match mount_suffix {
        Some(suffix) if !suffix.is_empty() => format!("{HOME_RUNTIME_WORK_DIR}/{suffix}->{target}"),
        _ => format!("{HOME_RUNTIME_WORK_DIR}->{target}"),
    })
}

pub fn append_identity_range(
    text: &mut String,
    start: u32,
    next_start: u32,
    exclude: u32,
) -> Result<(), MountError> {
    if next_start < start {
        return Err(MountError::InvalidUidRange);
    }
    if next_start == start {
        return Ok(());
    }

    let mut push_range = |a: u32, b: u32| {
        if b > a {
            text.push_str(&format!("{a} {a} {}\n", b - a));
        }
    };

    if exclude < start || exclude >= next_start {
        push_range(start, next_start);
    } else {
        push_range(start, exclude);
        push_range(exclude.saturating_add(1), next_start);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_options_use_builtin_defaults() {
        assert_eq!(
            mount_options_for_fstype("ext4"),
            Some("noquota,user_xattr".into())
        );
    }

    #[test]
    fn mount_options_unknown_fs_returns_none() {
        assert_eq!(mount_options_for_fstype("tmpfs"), None);
    }

    #[test]
    fn home_mount_node_requires_supported_fs() {
        assert_eq!(
            home_mount_node("/dev/loop0", "tmpfs", true, None),
            Err(MountError::UnsupportedFsType("tmpfs".into()))
        );
    }

    #[test]
    fn home_mount_node_builds_option_string() {
        let value = home_mount_node("/dev/loop0", "ext4", true, Some("x-test=1")).unwrap();
        assert_eq!(value, "noquota,user_xattr,discard,x-test=1");
    }

    #[test]
    fn unshare_returns_runtime_dir() {
        assert_eq!(home_unshare_and_mkdir(), HOME_RUNTIME_WORK_DIR);
    }

    #[test]
    fn unshare_and_mount_includes_options() {
        let value = home_unshare_and_mount("/dev/loop0", "xfs", false, None).unwrap();
        assert!(value.contains("nodiscard"));
    }

    #[test]
    fn move_mount_requires_target() {
        assert_eq!(home_move_mount(None, ""), Err(MountError::InvalidTarget));
    }

    #[test]
    fn move_mount_supports_suffix() {
        let value = home_move_mount(Some("inner"), "/home/alice").unwrap();
        assert_eq!(value, "/run/systemd/user-home-mount/inner->/home/alice");
    }

    #[test]
    fn append_identity_range_skips_excluded_uid() {
        let mut text = String::new();
        append_identity_range(&mut text, 10, 13, 11).unwrap();
        assert_eq!(text, "10 10 1\n12 12 1\n");
    }

    #[test]
    fn append_identity_range_rejects_reverse_range() {
        let mut text = String::new();
        assert_eq!(
            append_identity_range(&mut text, 13, 10, 11),
            Err(MountError::InvalidUidRange)
        );
    }
}
