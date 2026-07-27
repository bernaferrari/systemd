// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nspawn/nspawn-cgroup.c

use crate::common::{Errno, PortMetadata};
pub const SOURCE_PATH: &str = "src/nspawn/nspawn-cgroup.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "bind_mount_cgroup_hierarchy",
    "chown_cgroup_path",
    "create_subcgroup",
    "mount_cgroups",
];
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubcgroupPlan {
    pub delegated_path: String,
    pub payload_path: String,
    pub supervisor_path: Option<String>,
}
pub fn port_metadata() -> PortMetadata {
    PortMetadata {
        module_name: "nspawn_cgroup",
        source_path: SOURCE_PATH,
        source_lines: 196,
        extracted_functions: EXTRACTED_FUNCTIONS,
    }
}
pub fn chown_cgroup_path(path: &str, uid_shift: u32) -> Result<Vec<String>, Errno> {
    if path.is_empty() {
        return Err(Errno::new(-22));
    }
    Ok([
        ".",
        "cgroup.controllers",
        "cgroup.events",
        "cgroup.procs",
        "cgroup.stat",
        "cgroup.subtree_control",
        "cgroup.threads",
        "memory.oom.group",
        "memory.reclaim",
    ]
    .iter()
    .map(|n| format!("{path}/{n}:{uid_shift}"))
    .collect())
}
pub fn create_subcgroup(cgroup: &str, keep_unit: bool) -> Result<SubcgroupPlan, Errno> {
    if cgroup.is_empty() {
        return Err(Errno::new(-22));
    }
    Ok(SubcgroupPlan {
        delegated_path: cgroup.into(),
        payload_path: format!("{cgroup}/payload"),
        supervisor_path: keep_unit.then(|| format!("{cgroup}/supervisor")),
    })
}
pub fn mount_cgroups(
    _dest: &str,
    accept_existing: bool,
    already_mounted: bool,
    unified: bool,
) -> Result<bool, Errno> {
    if already_mounted && !accept_existing {
        return Err(Errno::new(-17));
    }
    if already_mounted && !unified {
        return Err(Errno::new(-22));
    }
    Ok(!already_mounted)
}
pub fn bind_mount_cgroup_hierarchy(path: &str) -> Result<bool, Errno> {
    Ok(path != "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_path() {
        assert_eq!(port_metadata().source_path, SOURCE_PATH);
    }
    #[test]
    fn empty_path_rejected() {
        assert!(chown_cgroup_path("", 1).is_err());
    }
    #[test]
    fn chown_list_contains_payload_files() {
        assert!(chown_cgroup_path("/x", 1)
            .unwrap()
            .iter()
            .any(|s| s.contains("cgroup.procs")));
    }
    #[test]
    fn create_subcgroup_payload() {
        assert_eq!(
            create_subcgroup("/m", false).unwrap().payload_path,
            "/m/payload"
        );
    }
    #[test]
    fn create_subcgroup_supervisor() {
        assert_eq!(
            create_subcgroup("/m", true)
                .unwrap()
                .supervisor_path
                .as_deref(),
            Some("/m/supervisor")
        );
    }
    #[test]
    fn existing_mount_rejected() {
        assert!(mount_cgroups("/x", false, true, true).is_err());
    }
    #[test]
    fn non_unified_existing_rejected() {
        assert!(mount_cgroups("/x", true, true, false).is_err());
    }
    #[test]
    fn new_mount_needed() {
        assert_eq!(mount_cgroups("/x", true, false, true).unwrap(), true);
    }
    #[test]
    fn bind_mount_skipped_for_root() {
        assert!(!bind_mount_cgroup_hierarchy("/").unwrap());
    }
    #[test]
    fn bind_mount_required_for_subtree() {
        assert!(bind_mount_cgroup_hierarchy("/machine.slice").unwrap());
    }
}
