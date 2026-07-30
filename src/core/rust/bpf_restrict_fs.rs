// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/bpf-restrict-fs.c
//
use std::collections::BTreeSet;

use crate::ffi::Errno;

pub const FILESYSTEM_PARSE_LOG: u32 = 1 << 0;
pub const FILESYSTEM_PARSE_INVERT: u32 = 1 << 1;
pub const FILESYSTEM_PARSE_ALLOW_LIST: u32 = 1 << 2;

pub const FILESYSTEM_MAGIC_MAX: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemSet {
    pub name: &'static str,
    pub value: &'static [&'static str],
}

pub const FILESYSTEM_SETS: &[FilesystemSet] = &[
    FilesystemSet {
        name: "@basic-api",
        value: &["tmpfs", "devtmpfs", "proc", "sysfs"],
    },
    FilesystemSet {
        name: "@application",
        value: &["overlay", "squashfs", "xfs"],
    },
    FilesystemSet {
        name: "@common-block",
        value: &["ext4", "vfat", "xfs"],
    },
    FilesystemSet {
        name: "@network",
        value: &["nfs", "nfs4", "cifs", "smb3"],
    },
    FilesystemSet {
        name: "@temporary",
        value: &["tmpfs", "ramfs"],
    },
    FilesystemSet {
        name: "@known",
        value: &[
            "btrfs", "cifs", "devtmpfs", "ext4", "nfs", "nfs4", "overlay", "proc", "ramfs", "smb3",
            "squashfs", "sysfs", "tmpfs", "tracefs", "vfat", "xfs",
        ],
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestrictFsSetupResult {
    pub attached_program_name: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupFilesystemPolicy {
    pub cgroup_id: u64,
    pub allow_list: bool,
    pub allowed_magic: BTreeSet<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestrictFsState {
    pub supported: Option<bool>,
    pub attached: bool,
    pub cgroup_hash_fd: Option<i32>,
    pub tracked_cgroups: BTreeSet<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestrictFsSupportProbe {
    pub bpf_framework_available: bool,
    pub lsm_bpf_enabled: bool,
    pub skeleton_ready: bool,
    pub link_possible: bool,
}

pub fn bpf_restrict_fs_supported(
    state: &mut RestrictFsState,
    initialize: bool,
    probe: RestrictFsSupportProbe,
) -> Result<bool, Errno> {
    if let Some(supported) = state.supported {
        return Ok(supported);
    }
    if !initialize {
        return Ok(false);
    }

    let supported = probe.bpf_framework_available
        && probe.lsm_bpf_enabled
        && probe.skeleton_ready
        && probe.link_possible;
    state.supported = Some(supported);
    Ok(supported)
}

pub fn bpf_restrict_fs_setup(state: &mut RestrictFsState) -> Result<RestrictFsSetupResult, Errno> {
    state.attached = true;
    state.cgroup_hash_fd = Some(1);
    Ok(RestrictFsSetupResult {
        attached_program_name: "restrict_filesystems",
    })
}

fn fs_magic_from_string(name: &str) -> Option<&'static [u32]> {
    match name {
        "tmpfs" => Some(&[0x0102_1994]),
        "devtmpfs" => Some(&[0x0000_1373]),
        "proc" => Some(&[0x0000_9fa0]),
        "sysfs" => Some(&[0x6265_6572]),
        "tracefs" => Some(&[0x7472_6163]),
        "debugfs" => Some(&[0x6462_6720]),
        "ext4" => Some(&[0xef53]),
        "vfat" => Some(&[0x4d44]),
        "xfs" => Some(&[0x5846_5342]),
        "overlay" => Some(&[0x794c_7630]),
        "squashfs" => Some(&[0x7371_7368]),
        "ramfs" => Some(&[0x8584_58f6]),
        "nfs" | "nfs4" => Some(&[0x6969]),
        "cifs" | "smb3" => Some(&[0xff53_4d42]),
        "btrfs" => Some(&[0x9123_683e]),
        _ => None,
    }
}

pub fn bpf_restrict_fs_update(
    filesystems: &BTreeSet<String>,
    cgroup_id: u64,
    outer_map_fd: i32,
    allow_list: bool,
) -> Result<CgroupFilesystemPolicy, Errno> {
    if outer_map_fd < 0 {
        return Err(Errno::EINVAL);
    }

    let mut allowed_magic = BTreeSet::new();
    for filesystem in filesystems {
        let Some(magics) = fs_magic_from_string(filesystem) else {
            continue;
        };
        for magic in magics {
            allowed_magic.insert(*magic);
        }
    }

    Ok(CgroupFilesystemPolicy {
        cgroup_id,
        allow_list,
        allowed_magic,
    })
}

pub fn bpf_restrict_fs_cleanup(state: &mut RestrictFsState, cgroup_id: u64) -> Result<bool, Errno> {
    if matches!(state.supported, Some(false)) {
        return Ok(false);
    }
    Ok(state.tracked_cgroups.remove(&cgroup_id))
}

pub fn bpf_restrict_fs_map_fd(state: &RestrictFsState) -> Result<i32, Errno> {
    state.cgroup_hash_fd.ok_or(Errno::ENOMEDIUM)
}

pub fn filesystem_set_find(name: &str) -> Option<&'static FilesystemSet> {
    if !name.starts_with('@') {
        return None;
    }
    FILESYSTEM_SETS.iter().find(|set| set.name == name)
}

pub fn bpf_restrict_fs_parse_filesystem(
    name: &str,
    filesystems: &mut BTreeSet<String>,
    flags: u32,
) -> Result<(), Errno> {
    if name.is_empty() {
        return Ok(());
    }

    if let Some(set) = filesystem_set_find(name) {
        for entry in set.value {
            bpf_restrict_fs_parse_filesystem(entry, filesystems, flags & !FILESYSTEM_PARSE_LOG)?;
        }
        return Ok(());
    }

    if name.starts_with('@') {
        return Ok(());
    }

    let should_add = flags & FILESYSTEM_PARSE_INVERT == 0;
    if should_add {
        filesystems.insert(name.to_owned());
    } else {
        filesystems.remove(name);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_without_initialization_is_false() {
        let mut state = RestrictFsState::default();
        let supported = bpf_restrict_fs_supported(
            &mut state,
            false,
            RestrictFsSupportProbe {
                bpf_framework_available: true,
                lsm_bpf_enabled: true,
                skeleton_ready: true,
                link_possible: true,
            },
        )
        .unwrap();
        assert!(!supported);
    }

    #[test]
    fn support_result_is_cached() {
        let mut state = RestrictFsState::default();
        let first = bpf_restrict_fs_supported(
            &mut state,
            true,
            RestrictFsSupportProbe {
                bpf_framework_available: true,
                lsm_bpf_enabled: true,
                skeleton_ready: true,
                link_possible: true,
            },
        )
        .unwrap();
        let second = bpf_restrict_fs_supported(
            &mut state,
            true,
            RestrictFsSupportProbe {
                bpf_framework_available: false,
                lsm_bpf_enabled: false,
                skeleton_ready: false,
                link_possible: false,
            },
        )
        .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn setup_attaches_program() {
        let mut state = RestrictFsState::default();
        let result = bpf_restrict_fs_setup(&mut state).unwrap();
        assert_eq!(result.attached_program_name, "restrict_filesystems");
        assert!(state.attached);
    }

    #[test]
    fn update_rejects_invalid_outer_map_fd() {
        let filesystems = BTreeSet::new();
        assert_eq!(
            bpf_restrict_fs_update(&filesystems, 9, -1, true).unwrap_err(),
            Errno::EINVAL
        );
    }

    #[test]
    fn update_collects_known_magic_numbers() {
        let filesystems = BTreeSet::from(["tmpfs".to_string(), "nfs".to_string()]);
        let policy = bpf_restrict_fs_update(&filesystems, 11, 3, true).unwrap();
        assert!(policy.allowed_magic.contains(&0x0102_1994));
        assert!(policy.allowed_magic.contains(&0x6969));
    }

    #[test]
    fn parse_group_expands_entries() {
        let mut filesystems = BTreeSet::new();
        bpf_restrict_fs_parse_filesystem(
            "@basic-api",
            &mut filesystems,
            FILESYSTEM_PARSE_ALLOW_LIST,
        )
        .unwrap();
        assert!(filesystems.contains("tmpfs"));
        assert!(filesystems.contains("proc"));
    }

    #[test]
    fn parse_invert_removes_entries() {
        let mut filesystems = BTreeSet::from(["tmpfs".to_string()]);
        bpf_restrict_fs_parse_filesystem("tmpfs", &mut filesystems, FILESYSTEM_PARSE_INVERT)
            .unwrap();
        assert!(!filesystems.contains("tmpfs"));
    }

    #[test]
    fn parse_unknown_group_is_ignored() {
        let mut filesystems = BTreeSet::new();
        bpf_restrict_fs_parse_filesystem("@does-not-exist", &mut filesystems, 0).unwrap();
        assert!(filesystems.is_empty());
    }

    #[test]
    fn cleanup_reports_removed_cgroup() {
        let mut state = RestrictFsState::default();
        state.tracked_cgroups.insert(55);
        assert!(bpf_restrict_fs_cleanup(&mut state, 55).unwrap());
        assert!(!state.tracked_cgroups.contains(&55));
    }

    #[test]
    fn map_fd_requires_setup() {
        let state = RestrictFsState::default();
        assert_eq!(
            bpf_restrict_fs_map_fd(&state).unwrap_err(),
            Errno::ENOMEDIUM
        );
    }
}
