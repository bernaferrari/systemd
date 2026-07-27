// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/bpf-bind-iface.c
//
use crate::ffi::Errno;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindInterfaceConfig {
    pub bind_network_interface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    pub config: BindInterfaceConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGroupRuntime {
    pub cgroup_path: String,
    pub installed_link: Option<BpfLink>,
    pub initial_link_fd: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfLink {
    pub interface_name: String,
    pub ifindex: i32,
    pub cgroup_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializedLink {
    pub key: &'static str,
    pub ifindex: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupportProbe {
    pub bpf_framework_available: bool,
    pub skeleton_open_succeeds: bool,
    pub skeleton_load_succeeds: bool,
    pub link_supported: bool,
}

pub fn bpf_bind_network_interface_supported(probe: SupportProbe) -> Result<bool, Errno> {
    if !probe.bpf_framework_available {
        return Ok(false);
    }
    if !probe.skeleton_open_succeeds || !probe.skeleton_load_succeeds {
        return Ok(false);
    }
    Ok(probe.link_supported)
}

pub fn bpf_bind_network_interface_install(
    unit: &Unit,
    runtime: &mut CGroupRuntime,
    resolve_interface: impl FnOnce(&str) -> Option<i32>,
) -> Result<(), Errno> {
    let Some(interface_name) = unit.config.bind_network_interface.as_deref() else {
        runtime.initial_link_fd = None;
        return Ok(());
    };

    if interface_name.is_empty() || runtime.cgroup_path.is_empty() {
        return Err(Errno::EINVAL);
    }

    let Some(ifindex) = resolve_interface(interface_name) else {
        runtime.initial_link_fd = None;
        return Ok(());
    };

    runtime.installed_link = Some(BpfLink {
        interface_name: interface_name.to_owned(),
        ifindex,
        cgroup_path: runtime.cgroup_path.clone(),
    });
    runtime.initial_link_fd = None;
    Ok(())
}

pub fn bpf_bind_network_interface_serialize(
    runtime: &CGroupRuntime,
) -> Result<Option<SerializedLink>, Errno> {
    if runtime.cgroup_path.is_empty() {
        return Err(Errno::EINVAL);
    }

    Ok(runtime.installed_link.as_ref().map(|link| SerializedLink {
        key: "bind-iface-bpf-fd",
        ifindex: link.ifindex,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_unit(name: Option<&str>) -> Unit {
        Unit {
            config: BindInterfaceConfig {
                bind_network_interface: name.map(str::to_owned),
            },
        }
    }

    fn sample_runtime() -> CGroupRuntime {
        CGroupRuntime {
            cgroup_path: "/sys/fs/cgroup/demo".into(),
            installed_link: None,
            initial_link_fd: Some(17),
        }
    }

    #[test]
    fn support_requires_framework() {
        let supported = bpf_bind_network_interface_supported(SupportProbe {
            bpf_framework_available: false,
            skeleton_open_succeeds: true,
            skeleton_load_succeeds: true,
            link_supported: true,
        })
        .unwrap();
        assert!(!supported);
    }

    #[test]
    fn support_requires_open_and_load() {
        let supported = bpf_bind_network_interface_supported(SupportProbe {
            bpf_framework_available: true,
            skeleton_open_succeeds: true,
            skeleton_load_succeeds: false,
            link_supported: true,
        })
        .unwrap();
        assert!(!supported);
    }

    #[test]
    fn support_reports_success() {
        let supported = bpf_bind_network_interface_supported(SupportProbe {
            bpf_framework_available: true,
            skeleton_open_succeeds: true,
            skeleton_load_succeeds: true,
            link_supported: true,
        })
        .unwrap();
        assert!(supported);
    }

    #[test]
    fn install_skips_when_interface_is_unset() {
        let unit = sample_unit(None);
        let mut runtime = sample_runtime();
        bpf_bind_network_interface_install(&unit, &mut runtime, |_| Some(2)).unwrap();
        assert!(runtime.installed_link.is_none());
        assert_eq!(runtime.initial_link_fd, None);
    }

    #[test]
    fn install_ignores_unknown_interface() {
        let unit = sample_unit(Some("vrf-blue"));
        let mut runtime = sample_runtime();
        bpf_bind_network_interface_install(&unit, &mut runtime, |_| None).unwrap();
        assert!(runtime.installed_link.is_none());
        assert_eq!(runtime.initial_link_fd, None);
    }

    #[test]
    fn install_records_link_when_interface_resolves() {
        let unit = sample_unit(Some("vrf-blue"));
        let mut runtime = sample_runtime();
        bpf_bind_network_interface_install(&unit, &mut runtime, |_| Some(42)).unwrap();

        let link = runtime.installed_link.as_ref().unwrap();
        assert_eq!(link.interface_name, "vrf-blue");
        assert_eq!(link.ifindex, 42);
    }

    #[test]
    fn install_rejects_empty_cgroup_path() {
        let unit = sample_unit(Some("eth0"));
        let mut runtime = sample_runtime();
        runtime.cgroup_path.clear();
        assert_eq!(
            bpf_bind_network_interface_install(&unit, &mut runtime, |_| Some(7)).unwrap_err(),
            Errno::EINVAL
        );
    }

    #[test]
    fn serialize_returns_none_without_link() {
        let runtime = sample_runtime();
        assert_eq!(
            bpf_bind_network_interface_serialize(&runtime).unwrap(),
            None
        );
    }

    #[test]
    fn serialize_uses_expected_key() {
        let mut runtime = sample_runtime();
        runtime.installed_link = Some(BpfLink {
            interface_name: "eth0".into(),
            ifindex: 5,
            cgroup_path: runtime.cgroup_path.clone(),
        });
        let serialized = bpf_bind_network_interface_serialize(&runtime)
            .unwrap()
            .unwrap();
        assert_eq!(serialized.key, "bind-iface-bpf-fd");
        assert_eq!(serialized.ifindex, 5);
    }

    #[test]
    fn serialize_rejects_empty_cgroup_path() {
        let runtime = CGroupRuntime {
            cgroup_path: String::new(),
            installed_link: None,
            initial_link_fd: None,
        };
        assert_eq!(
            bpf_bind_network_interface_serialize(&runtime).unwrap_err(),
            Errno::EINVAL
        );
    }
}
