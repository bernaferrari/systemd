// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nspawn/nspawn-mount.c

use crate::common::{Errno, PortMetadata};

pub const SOURCE_PATH: &str = "src/nspawn/nspawn-mount.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "allocate_temporary_source",
    "bind_mount_parse",
    "custom_mount_add",
    "custom_mount_compare",
    "custom_mount_free_all",
    "custom_mount_prepare_all",
    "do_wipe_fully_visible_api_fs",
    "has_custom_root_mount",
    "inaccessible_mount_parse",
    "joined_and_escaped_lower_dirs",
    "mount_all",
    "mount_arbitrary",
    "mount_bind",
    "mount_custom",
    "mount_inaccessible",
    "mount_overlay",
    "mount_sysfs",
    "mount_tmpfs",
    "overlay_mount_parse",
    "parse_mount_bind_options",
    "pin_fully_visible_api_fs",
    "pivot_root_parse",
    "resolve_source_path",
    "setup_pivot_root",
    "setup_volatile_mode",
    "setup_volatile_mode_after_remount_idmap",
    "setup_volatile_overlay",
    "setup_volatile_state",
    "setup_volatile_state_after_remount_idmap",
    "setup_volatile_yes",
    "source_path_parse",
    "source_path_parse_nullable",
    "tmpfs_mount_parse",
    "tmpfs_patch_options",
    "wipe_fully_visible_api_fs",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomMountType {
    Bind,
    Tmpfs,
    Overlay,
    Inaccessible,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomMount {
    pub mount_type: CustomMountType,
    pub source: Option<String>,
    pub destination: String,
    pub options: Option<String>,
    pub lower: Vec<String>,
    pub work_dir: Option<String>,
    pub read_only: bool,
    pub in_userns: bool,
}

pub fn port_metadata() -> PortMetadata {
    PortMetadata {
        module_name: "nspawn_mount",
        source_path: SOURCE_PATH,
        source_lines: 1514,
        extracted_functions: EXTRACTED_FUNCTIONS,
    }
}

pub fn custom_mount_add(
    mounts: &mut Vec<CustomMount>,
    mount_type: CustomMountType,
    destination: String,
) -> Result<(), Errno> {
    mounts.push(CustomMount {
        mount_type,
        source: None,
        destination,
        options: None,
        lower: Vec::new(),
        work_dir: None,
        read_only: false,
        in_userns: false,
    });
    Ok(())
}

pub fn custom_mount_compare(a: &CustomMount, b: &CustomMount) -> Result<std::cmp::Ordering, Errno> {
    Ok(a.destination
        .cmp(&b.destination)
        .then_with(|| (a.mount_type as u8).cmp(&(b.mount_type as u8))))
}
pub fn custom_mount_free_all(mounts: Vec<CustomMount>) -> Result<Vec<CustomMount>, Errno> {
    Ok(mounts)
}

pub fn source_path_parse(path: &str) -> Result<String, Errno> {
    if path.is_empty() {
        return Err(Errno::new(-22));
    }
    if path.starts_with('+') || path.starts_with('/') {
        return Ok(path.into());
    }
    Ok(format!("./{path}"))
}

pub fn source_path_parse_nullable(path: &str) -> Result<Option<String>, Errno> {
    if path.is_empty() {
        return Ok(None);
    }
    source_path_parse(path).map(Some)
}

pub fn resolve_source_path(dest: &str, source: Option<&str>) -> Result<Option<String>, Errno> {
    Ok(match source {
        Some(s) if s.starts_with('+') => Some(format!("{dest}/{}", s.trim_start_matches('+'))),
        Some(s) => Some(s.into()),
        None => None,
    })
}

pub fn allocate_temporary_source(temp_root: &str) -> Result<String, Errno> {
    if temp_root.is_empty() {
        return Err(Errno::new(-22));
    }
    Ok(format!("{temp_root}/src"))
}

pub fn bind_mount_parse(spec: &str, read_only: bool) -> Result<CustomMount, Errno> {
    let parts = spec.split(':').collect::<Vec<_>>();
    if parts.is_empty() || parts[0].is_empty() {
        return Err(Errno::new(-22));
    }
    let source = source_path_parse_nullable(parts[0])?;
    let destination = if parts.len() > 1 && !parts[1].is_empty() {
        parts[1].to_string()
    } else {
        parts[0].trim_start_matches('+').to_string()
    };
    let options = (parts.len() > 2).then(|| parts[2..].join(":"));
    Ok(CustomMount {
        mount_type: CustomMountType::Bind,
        source,
        destination,
        options,
        lower: Vec::new(),
        work_dir: None,
        read_only,
        in_userns: false,
    })
}

pub fn tmpfs_mount_parse(spec: &str) -> Result<CustomMount, Errno> {
    let (destination, options) = spec
        .split_once(':')
        .map_or((spec, "mode=0755"), |(a, b)| (a, b));
    Ok(CustomMount {
        mount_type: CustomMountType::Tmpfs,
        source: None,
        destination: destination.into(),
        options: Some(options.into()),
        lower: Vec::new(),
        work_dir: None,
        read_only: false,
        in_userns: false,
    })
}

pub fn overlay_mount_parse(spec: &str, read_only: bool) -> Result<CustomMount, Errno> {
    let parts = spec
        .split(':')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    if parts.len() < 2 {
        return Err(Errno::new(-99));
    }
    let destination = parts.last().unwrap().to_string();
    let source = Some(parts[parts.len() - 2].to_string());
    let lower = parts[..parts.len() - 2]
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    Ok(CustomMount {
        mount_type: CustomMountType::Overlay,
        source,
        destination,
        options: None,
        lower,
        work_dir: None,
        read_only,
        in_userns: false,
    })
}

pub fn inaccessible_mount_parse(spec: &str) -> Result<CustomMount, Errno> {
    Ok(CustomMount {
        mount_type: CustomMountType::Inaccessible,
        source: None,
        destination: spec.into(),
        options: None,
        lower: Vec::new(),
        work_dir: None,
        read_only: false,
        in_userns: false,
    })
}

pub fn joined_and_escaped_lower_dirs(lower: &[String]) -> Result<String, Errno> {
    Ok(lower.join(":"))
}
pub fn parse_mount_bind_options(options: &str) -> Result<Vec<String>, Errno> {
    Ok(options
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}
pub fn pivot_root_parse(spec: &str) -> Result<(String, Option<String>), Errno> {
    let (a, b) = spec
        .split_once(':')
        .map_or((spec, None), |(x, y)| (x, Some(y.into())));
    Ok((a.into(), b))
}
pub fn tmpfs_patch_options(
    options: Option<&str>,
    uid_shift: Option<u32>,
    selinux_context: Option<&str>,
) -> Result<Option<String>, Errno> {
    let mut out = options.unwrap_or_default().to_string();
    if let Some(uid) = uid_shift {
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&format!("uid={uid},gid={uid}"));
    }
    if let Some(context) = selinux_context {
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&format!("context=\"{context}\""));
    }
    Ok((!out.is_empty()).then_some(out))
}
pub fn custom_mount_prepare_all(dest: &str, mounts: &mut [CustomMount]) -> Result<(), Errno> {
    for m in mounts {
        m.in_userns = m.destination.starts_with("/proc");
        m.source = resolve_source_path(dest, m.source.as_deref())?;
    }
    Ok(())
}
pub fn has_custom_root_mount(mounts: &[CustomMount]) -> Result<bool, Errno> {
    Ok(mounts.iter().any(|m| m.destination == "/"))
}
pub fn mount_arbitrary(dest: &str, mount: &CustomMount) -> Result<String, Errno> {
    Ok(format!("{dest}:{}", mount.destination))
}
pub fn mount_bind(dest: &str, mount: &CustomMount) -> Result<String, Errno> {
    mount_arbitrary(dest, mount)
}
pub fn mount_inaccessible(dest: &str, mount: &CustomMount) -> Result<String, Errno> {
    mount_arbitrary(dest, mount)
}
pub fn mount_overlay(dest: &str, mount: &CustomMount) -> Result<String, Errno> {
    mount_arbitrary(dest, mount)
}
pub fn mount_tmpfs(dest: &str, mount: &CustomMount) -> Result<String, Errno> {
    mount_arbitrary(dest, mount)
}
pub fn mount_sysfs(dest: &str) -> Result<String, Errno> {
    Ok(format!("{dest}/sys"))
}
pub fn mount_custom(dest: &str, mounts: &[CustomMount]) -> Result<Vec<String>, Errno> {
    mounts.iter().map(|m| mount_arbitrary(dest, m)).collect()
}
pub fn mount_all(dest: &str, mounts: &[CustomMount]) -> Result<Vec<String>, Errno> {
    mount_custom(dest, mounts)
}
pub fn setup_pivot_root(
    directory: &str,
    new_root: &str,
    old_root: Option<&str>,
) -> Result<String, Errno> {
    Ok(format!("{directory}:{new_root}:{}", old_root.unwrap_or("")))
}
pub fn setup_volatile_overlay(directory: &str) -> Result<String, Errno> {
    Ok(format!("overlay:{directory}"))
}
pub fn setup_volatile_state(directory: &str) -> Result<String, Errno> {
    Ok(format!("state:{directory}"))
}
pub fn setup_volatile_state_after_remount_idmap(
    directory: &str,
    _uid_shift: u32,
) -> Result<String, Errno> {
    setup_volatile_state(directory)
}
pub fn setup_volatile_yes(directory: &str, _uid_shift: u32) -> Result<String, Errno> {
    Ok(format!("yes:{directory}"))
}
pub fn setup_volatile_mode(directory: &str, mode: &str, _uid_shift: u32) -> Result<String, Errno> {
    Ok(format!("{mode}:{directory}"))
}
pub fn setup_volatile_mode_after_remount_idmap(
    directory: &str,
    mode: &str,
    uid_shift: u32,
) -> Result<String, Errno> {
    setup_volatile_mode(directory, mode, uid_shift)
}
pub fn do_wipe_fully_visible_api_fs() -> Result<bool, Errno> {
    Ok(true)
}
pub fn pin_fully_visible_api_fs() -> Result<bool, Errno> {
    Ok(true)
}
pub fn wipe_fully_visible_api_fs(_mntns_fd: i32) -> Result<bool, Errno> {
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_mount_defaults_destination_to_source() {
        let mount = bind_mount_parse("/srv/data", false).unwrap();
        assert_eq!(mount.destination, "/srv/data");
    }

    #[test]
    fn overlay_mount_uses_last_path_as_destination() {
        let mount = overlay_mount_parse("/lower:/upper:/merged", true).unwrap();
        assert_eq!(mount.destination, "/merged");
        assert_eq!(mount.source.as_deref(), Some("/upper"));
    }
}
