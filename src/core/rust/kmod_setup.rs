// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/kmod-setup.c
//

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Virtualization {
    #[default]
    None,
    Kvm,
    Qemu,
    Vmware,
    Microsoft,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleCondition {
    Always,
    HasVirtioRng,
    MayHaveVirtio,
    MayHaveVsockLoopback,
    InVmware,
    InHyperV,
    InQemu,
    HasVirtioPci,
    HasTpm2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleEntry {
    pub module: &'static str,
    pub path: Option<&'static str>,
    pub warn_if_unavailable: bool,
    pub warn_if_module: bool,
    pub condition: ModuleCondition,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KmodEnvironment {
    pub have_kmod: bool,
    pub has_cap_sys_module: bool,
    pub virtualization: Virtualization,
    pub existing_paths: BTreeSet<String>,
    pub virtio_rng_present: bool,
    pub virtio_pci_present: bool,
    pub efi_has_tpm2: bool,
    pub have_tpm2: bool,
}

pub fn default_kmod_table(have_tpm2: bool) -> Vec<ModuleEntry> {
    let mut modules = vec![
        ModuleEntry {
            module: "autofs4",
            path: Some("/sys/class/misc/autofs"),
            warn_if_unavailable: true,
            warn_if_module: false,
            condition: ModuleCondition::Always,
        },
        ModuleEntry {
            module: "ipv6",
            path: Some("/sys/module/ipv6"),
            warn_if_unavailable: false,
            warn_if_module: true,
            condition: ModuleCondition::Always,
        },
        ModuleEntry {
            module: "virtio_rng",
            path: None,
            warn_if_unavailable: false,
            warn_if_module: false,
            condition: ModuleCondition::HasVirtioRng,
        },
        ModuleEntry {
            module: "virtio_console",
            path: None,
            warn_if_unavailable: false,
            warn_if_module: false,
            condition: ModuleCondition::MayHaveVirtio,
        },
        ModuleEntry {
            module: "vmw_vsock_virtio_transport",
            path: None,
            warn_if_unavailable: false,
            warn_if_module: false,
            condition: ModuleCondition::MayHaveVirtio,
        },
        ModuleEntry {
            module: "vsock_loopback",
            path: Some("/sys/module/vsock_loopback"),
            warn_if_unavailable: false,
            warn_if_module: false,
            condition: ModuleCondition::MayHaveVsockLoopback,
        },
        ModuleEntry {
            module: "vmw_vsock_vmci_transport",
            path: None,
            warn_if_unavailable: false,
            warn_if_module: false,
            condition: ModuleCondition::InVmware,
        },
        ModuleEntry {
            module: "hv_sock",
            path: None,
            warn_if_unavailable: false,
            warn_if_module: false,
            condition: ModuleCondition::InHyperV,
        },
        ModuleEntry {
            module: "virtiofs",
            path: Some("/sys/module/virtiofs"),
            warn_if_unavailable: false,
            warn_if_module: false,
            condition: ModuleCondition::MayHaveVirtio,
        },
        ModuleEntry {
            module: "virtio_pci",
            path: Some("/sys/module/virtio_pci"),
            warn_if_unavailable: false,
            warn_if_module: false,
            condition: ModuleCondition::HasVirtioPci,
        },
        ModuleEntry {
            module: "qemu_fw_cfg",
            path: Some("/sys/firmware/qemu_fw_cfg"),
            warn_if_unavailable: false,
            warn_if_module: false,
            condition: ModuleCondition::InQemu,
        },
        ModuleEntry {
            module: "dmi-sysfs",
            path: Some("/sys/firmware/dmi/entries"),
            warn_if_unavailable: false,
            warn_if_module: false,
            condition: ModuleCondition::Always,
        },
    ];

    if have_tpm2 {
        modules.push(ModuleEntry {
            module: "tpm",
            path: Some("/sys/class/tpmrm"),
            warn_if_unavailable: false,
            warn_if_module: false,
            condition: ModuleCondition::HasTpm2,
        });
    }

    modules
}

pub fn modules_to_load(env: &KmodEnvironment) -> Vec<&'static str> {
    if !env.have_kmod || !env.has_cap_sys_module {
        return Vec::new();
    }

    default_kmod_table(env.have_tpm2)
        .into_iter()
        .filter(|entry| {
            !entry
                .path
                .is_some_and(|path| env.existing_paths.contains(path))
        })
        .filter(|entry| condition_matches(entry.condition, env))
        .map(|entry| entry.module)
        .collect()
}

fn condition_matches(condition: ModuleCondition, env: &KmodEnvironment) -> bool {
    match condition {
        ModuleCondition::Always => true,
        ModuleCondition::HasVirtioRng => env.virtio_rng_present,
        ModuleCondition::MayHaveVirtio => env.virtio_pci_present,
        ModuleCondition::MayHaveVsockLoopback => {
            env.virtio_pci_present || env.virtualization == Virtualization::Vmware
        }
        ModuleCondition::InVmware => env.virtualization == Virtualization::Vmware,
        ModuleCondition::InHyperV => env.virtualization == Virtualization::Microsoft,
        ModuleCondition::InQemu => matches!(
            env.virtualization,
            Virtualization::Kvm | Virtualization::Qemu
        ),
        ModuleCondition::HasVirtioPci => env.virtio_pci_present,
        ModuleCondition::HasTpm2 => env.efi_has_tpm2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_everything_without_capability() {
        let env = KmodEnvironment {
            have_kmod: true,
            has_cap_sys_module: false,
            ..Default::default()
        };

        assert!(modules_to_load(&env).is_empty());
    }

    #[test]
    fn skips_modules_with_existing_probe_paths() {
        let env = KmodEnvironment {
            have_kmod: true,
            has_cap_sys_module: true,
            existing_paths: [
                "/sys/class/misc/autofs".to_string(),
                "/sys/firmware/dmi/entries".to_string(),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };

        let modules = modules_to_load(&env);
        assert!(!modules.contains(&"autofs4"));
        assert!(!modules.contains(&"dmi-sysfs"));
    }

    #[test]
    fn loads_virtio_modules_when_virtio_is_present() {
        let env = KmodEnvironment {
            have_kmod: true,
            has_cap_sys_module: true,
            virtio_pci_present: true,
            virtio_rng_present: true,
            ..Default::default()
        };

        let modules = modules_to_load(&env);
        assert!(modules.contains(&"virtio_rng"));
        assert!(modules.contains(&"virtio_console"));
        assert!(modules.contains(&"virtio_pci"));
    }

    #[test]
    fn vmware_enables_loopback_and_vmci_transport() {
        let env = KmodEnvironment {
            have_kmod: true,
            has_cap_sys_module: true,
            virtualization: Virtualization::Vmware,
            ..Default::default()
        };

        let modules = modules_to_load(&env);
        assert!(modules.contains(&"vsock_loopback"));
        assert!(modules.contains(&"vmw_vsock_vmci_transport"));
    }

    #[test]
    fn qemu_detection_matches_kvm_and_qemu() {
        let qemu = KmodEnvironment {
            have_kmod: true,
            has_cap_sys_module: true,
            virtualization: Virtualization::Qemu,
            ..Default::default()
        };
        let kvm = KmodEnvironment {
            virtualization: Virtualization::Kvm,
            ..qemu.clone()
        };

        assert!(modules_to_load(&qemu).contains(&"qemu_fw_cfg"));
        assert!(modules_to_load(&kvm).contains(&"qemu_fw_cfg"));
    }

    #[test]
    fn tpm_module_is_only_listed_when_built_and_present() {
        let env = KmodEnvironment {
            have_kmod: true,
            has_cap_sys_module: true,
            have_tpm2: true,
            efi_has_tpm2: true,
            ..Default::default()
        };

        assert!(modules_to_load(&env).contains(&"tpm"));
        assert!(
            !default_kmod_table(false)
                .iter()
                .any(|entry| entry.module == "tpm")
        );
    }
}
