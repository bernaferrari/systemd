// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/bpf-restrict-ifaces.c
//
use std::collections::BTreeSet;

use crate::ffi::Errno;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestrictIfacesConfig {
    pub is_allow_list: bool,
    pub interfaces: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestrictIfacesRuntime {
    pub cgroup_path: String,
    pub ingress_link: Option<BpfCgroupLink>,
    pub egress_link: Option<BpfCgroupLink>,
    pub initial_link_fds: BTreeSet<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfCgroupLink {
    pub direction: TrafficDirection,
    pub cgroup_path: String,
    pub indexes: BTreeSet<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficDirection {
    Ingress,
    Egress,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializedLink {
    pub key: &'static str,
    pub direction: TrafficDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestrictIfacesSupportProbe {
    pub bpf_framework_available: bool,
    pub skeleton_ready: bool,
    pub link_possible: bool,
}

pub fn bpf_restrict_ifaces_supported(probe: RestrictIfacesSupportProbe) -> Result<bool, Errno> {
    Ok(probe.bpf_framework_available && probe.skeleton_ready && probe.link_possible)
}

pub fn bpf_restrict_ifaces_install(
    config: &RestrictIfacesConfig,
    runtime: &mut RestrictIfacesRuntime,
    resolve_interface: impl Fn(&str) -> Option<i32>,
) -> Result<(), Errno> {
    if runtime.cgroup_path.is_empty() {
        return Err(Errno::EINVAL);
    }
    if config.interfaces.is_empty() {
        runtime.initial_link_fds.clear();
        return Ok(());
    }

    let mut indexes = BTreeSet::new();
    for interface in &config.interfaces {
        if let Some(index) = resolve_interface(interface) {
            indexes.insert(index);
        }
    }

    if indexes.is_empty() {
        runtime.initial_link_fds.clear();
        return Ok(());
    }

    runtime.ingress_link = Some(BpfCgroupLink {
        direction: TrafficDirection::Ingress,
        cgroup_path: runtime.cgroup_path.clone(),
        indexes: indexes.clone(),
    });
    runtime.egress_link = Some(BpfCgroupLink {
        direction: TrafficDirection::Egress,
        cgroup_path: runtime.cgroup_path.clone(),
        indexes,
    });
    runtime.initial_link_fds.clear();
    Ok(())
}

pub fn bpf_restrict_ifaces_serialize(
    runtime: &RestrictIfacesRuntime,
) -> Result<Vec<SerializedLink>, Errno> {
    if runtime.cgroup_path.is_empty() {
        return Err(Errno::EINVAL);
    }

    let mut serialized = Vec::new();
    if runtime.ingress_link.is_some() {
        serialized.push(SerializedLink {
            key: "restrict-ifaces-bpf-fd",
            direction: TrafficDirection::Ingress,
        });
    }
    if runtime.egress_link.is_some() {
        serialized.push(SerializedLink {
            key: "restrict-ifaces-bpf-fd",
            direction: TrafficDirection::Egress,
        });
    }
    Ok(serialized)
}

pub fn bpf_restrict_ifaces_add_initial_link_fd(
    runtime: &mut RestrictIfacesRuntime,
    fd: i32,
) -> Result<(), Errno> {
    if fd < 0 {
        return Err(Errno::EINVAL);
    }
    runtime.initial_link_fds.insert(fd);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> RestrictIfacesRuntime {
        RestrictIfacesRuntime {
            cgroup_path: "/sys/fs/cgroup/test".into(),
            ingress_link: None,
            egress_link: None,
            initial_link_fds: BTreeSet::new(),
        }
    }

    fn config(names: &[&str]) -> RestrictIfacesConfig {
        RestrictIfacesConfig {
            is_allow_list: true,
            interfaces: names.iter().map(|name| (*name).to_string()).collect(),
        }
    }

    #[test]
    fn support_requires_all_checks() {
        let supported = bpf_restrict_ifaces_supported(RestrictIfacesSupportProbe {
            bpf_framework_available: true,
            skeleton_ready: true,
            link_possible: false,
        })
        .unwrap();
        assert!(!supported);
    }

    #[test]
    fn support_reports_success() {
        let supported = bpf_restrict_ifaces_supported(RestrictIfacesSupportProbe {
            bpf_framework_available: true,
            skeleton_ready: true,
            link_possible: true,
        })
        .unwrap();
        assert!(supported);
    }

    #[test]
    fn install_skips_empty_configuration() {
        let mut runtime = runtime();
        bpf_restrict_ifaces_install(&config(&[]), &mut runtime, |_| Some(3)).unwrap();
        assert!(runtime.ingress_link.is_none());
        assert!(runtime.egress_link.is_none());
    }

    #[test]
    fn install_rejects_empty_cgroup_path() {
        let mut runtime = runtime();
        runtime.cgroup_path.clear();
        assert_eq!(
            bpf_restrict_ifaces_install(&config(&["eth0"]), &mut runtime, |_| Some(2)).unwrap_err(),
            Errno::EINVAL
        );
    }

    #[test]
    fn install_ignores_unknown_interfaces() {
        let mut runtime = runtime();
        bpf_restrict_ifaces_install(&config(&["eth0"]), &mut runtime, |_| None).unwrap();
        assert!(runtime.ingress_link.is_none());
    }

    #[test]
    fn install_creates_both_links() {
        let mut runtime = runtime();
        bpf_restrict_ifaces_install(&config(&["eth0", "wlan0"]), &mut runtime, |name| {
            Some(if name == "eth0" { 2 } else { 9 })
        })
        .unwrap();
        assert_eq!(runtime.ingress_link.as_ref().unwrap().indexes.len(), 2);
        assert_eq!(
            runtime.egress_link.as_ref().unwrap().direction,
            TrafficDirection::Egress
        );
    }

    #[test]
    fn serialize_only_returns_present_links() {
        let mut runtime = runtime();
        runtime.ingress_link = Some(BpfCgroupLink {
            direction: TrafficDirection::Ingress,
            cgroup_path: runtime.cgroup_path.clone(),
            indexes: BTreeSet::from([2]),
        });
        let serialized = bpf_restrict_ifaces_serialize(&runtime).unwrap();
        assert_eq!(serialized.len(), 1);
        assert_eq!(serialized[0].direction, TrafficDirection::Ingress);
    }

    #[test]
    fn add_initial_fd_rejects_negative_values() {
        let mut runtime = runtime();
        assert_eq!(
            bpf_restrict_ifaces_add_initial_link_fd(&mut runtime, -1).unwrap_err(),
            Errno::EINVAL
        );
    }

    #[test]
    fn add_initial_fd_tracks_unique_fds() {
        let mut runtime = runtime();
        bpf_restrict_ifaces_add_initial_link_fd(&mut runtime, 11).unwrap();
        bpf_restrict_ifaces_add_initial_link_fd(&mut runtime, 11).unwrap();
        assert_eq!(runtime.initial_link_fds.len(), 1);
    }

    #[test]
    fn install_clears_restored_fds() {
        let mut runtime = runtime();
        runtime.initial_link_fds.insert(18);
        bpf_restrict_ifaces_install(&config(&["eth0"]), &mut runtime, |_| Some(4)).unwrap();
        assert!(runtime.initial_link_fds.is_empty());
    }
}
