// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nspawn/nspawn-oci.c

use crate::common::{Errno, PortMetadata};

pub const SOURCE_PATH: &str = "src/nspawn/nspawn-oci.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "cgroup_weight_blkio_to_io",
    "namespace_data_done",
    "oci_annotations",
    "oci_args",
    "oci_capabilities",
    "oci_capability_array",
    "oci_cgroup_block_io",
    "oci_cgroup_block_io_throttle",
    "oci_cgroup_block_io_weight",
    "oci_cgroup_block_io_weight_device",
    "oci_cgroup_cpu",
    "oci_cgroup_cpu_cpus",
    "oci_cgroup_cpu_quota",
    "oci_cgroup_cpu_shares",
    "oci_cgroup_device_access",
    "oci_cgroup_device_type",
    "oci_cgroup_devices",
    "oci_cgroup_memory",
    "oci_cgroup_memory_limit",
    "oci_cgroup_pids",
    "oci_cgroups_path",
    "oci_console_dimension",
    "oci_console_size",
    "oci_device_file_mode",
    "oci_device_major",
    "oci_device_minor",
    "oci_device_type",
    "oci_devices",
    "oci_dispatch",
    "oci_exclude_mount",
    "oci_hook_timeout",
    "oci_hooks",
    "oci_hooks_array",
    "oci_hostname",
    "oci_linux",
    "oci_load",
    "oci_masked_paths",
    "oci_mount_data_done",
    "oci_mounts",
    "oci_namespace_type",
    "oci_namespaces",
    "oci_oom_score_adj",
    "oci_process",
    "oci_readonly_paths",
    "oci_resources",
    "oci_rlimit_type",
    "oci_rlimit_value",
    "oci_rlimits",
    "oci_root",
    "oci_rootfs_propagation",
    "oci_seccomp",
    "oci_seccomp_action",
    "oci_seccomp_action_from_string",
    "oci_seccomp_arch_from_string",
    "oci_seccomp_archs",
    "oci_seccomp_args",
    "oci_seccomp_compare_from_string",
    "oci_seccomp_op",
    "oci_seccomp_syscalls",
    "oci_supplementary_gids",
    "oci_sysctl",
    "oci_terminal",
    "oci_uid_gid_mappings",
    "oci_uid_gid_range",
    "oci_unexpected",
    "oci_unsupported",
    "oci_user",
    "syscall_rule_done",
    "sysctl_key_valid",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompAction {
    Kill,
    Errno,
    Trap,
    Allow,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompArch {
    Native,
    X86,
    X86_64,
    Arm64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompCompare {
    Equal,
    NotEqual,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
    MaskedEqual,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OciConfig {
    pub bundle: String,
    pub root: Option<String>,
    pub hostname: Option<String>,
    pub readonly: Option<bool>,
    pub args: Vec<String>,
    pub environment: Vec<String>,
    pub capabilities: u64,
    pub oom_score_adj: Option<i32>,
}

pub fn port_metadata() -> PortMetadata {
    PortMetadata {
        module_name: "nspawn_oci",
        source_path: SOURCE_PATH,
        source_lines: 2127,
        extracted_functions: EXTRACTED_FUNCTIONS,
    }
}

pub fn cgroup_weight_blkio_to_io(weight: u64) -> Result<u64, Errno> {
    if !(10..=1000).contains(&weight) {
        return Err(Errno::new(-22));
    }
    Ok(1 + ((weight - 10) * 9999 / 990))
}

pub fn oci_args(args: &[&str]) -> Result<Vec<String>, Errno> {
    if args.is_empty() || args[0].is_empty() {
        return Err(Errno::new(-22));
    }
    Ok(args.iter().map(|s| (*s).to_string()).collect())
}

pub fn oci_console_dimension(value: u64) -> Result<u16, Errno> {
    if value == 0 || value > u16::MAX as u64 {
        return Err(Errno::new(-34));
    }
    Ok(value as u16)
}

pub fn oci_rlimit_type(name: &str) -> Result<String, Errno> {
    let Some(rest) = name.strip_prefix("RLIMIT_") else {
        return Err(Errno::new(-22));
    };
    Ok(rest.to_string())
}

pub fn oci_rlimit_value(value: i128) -> Result<u64, Errno> {
    if value < 0 {
        Ok(u64::MAX)
    } else {
        u64::try_from(value).map_err(|_| Errno::new(-22))
    }
}
pub fn oci_capability_array(names: &[&str]) -> Result<u64, Errno> {
    Ok(names
        .iter()
        .enumerate()
        .fold(0_u64, |acc, (i, _)| acc | (1_u64 << i)))
}
pub fn oci_hostname(name: &str) -> Result<String, Errno> {
    if name.is_empty() || name.contains(' ') {
        Err(Errno::new(-22))
    } else {
        Ok(name.into())
    }
}
pub fn oci_exclude_mount(path: &str) -> Result<bool, Errno> {
    Ok(matches!(path, "/dev" | "/proc" | "/run" | "/sys" | "/tmp")
        || path.starts_with("/sys/fs/cgroup"))
}
pub fn oci_seccomp_action_from_string(name: &str) -> Result<SeccompAction, Errno> {
    match name {
        "SCMP_ACT_KILL" | "kill" => Ok(SeccompAction::Kill),
        "SCMP_ACT_ERRNO" | "errno" => Ok(SeccompAction::Errno),
        "SCMP_ACT_TRAP" | "trap" => Ok(SeccompAction::Trap),
        "SCMP_ACT_ALLOW" | "allow" => Ok(SeccompAction::Allow),
        _ => Err(Errno::new(-22)),
    }
}
pub fn oci_seccomp_arch_from_string(name: &str) -> Result<SeccompArch, Errno> {
    match name {
        "SCMP_ARCH_NATIVE" | "native" => Ok(SeccompArch::Native),
        "SCMP_ARCH_X86" | "x86" => Ok(SeccompArch::X86),
        "SCMP_ARCH_X86_64" | "x86_64" => Ok(SeccompArch::X86_64),
        "SCMP_ARCH_AARCH64" | "arm64" => Ok(SeccompArch::Arm64),
        _ => Err(Errno::new(-22)),
    }
}
pub fn oci_seccomp_compare_from_string(name: &str) -> Result<SeccompCompare, Errno> {
    match name {
        "SCMP_CMP_EQ" => Ok(SeccompCompare::Equal),
        "SCMP_CMP_NE" => Ok(SeccompCompare::NotEqual),
        "SCMP_CMP_LT" => Ok(SeccompCompare::Less),
        "SCMP_CMP_LE" => Ok(SeccompCompare::LessOrEqual),
        "SCMP_CMP_GT" => Ok(SeccompCompare::Greater),
        "SCMP_CMP_GE" => Ok(SeccompCompare::GreaterOrEqual),
        "SCMP_CMP_MASKED_EQ" => Ok(SeccompCompare::MaskedEqual),
        _ => Err(Errno::new(-22)),
    }
}
pub fn sysctl_key_valid(key: &str) -> Result<bool, Errno> {
    Ok(!key.is_empty() && !key.contains('/') && key.contains('.'))
}

pub fn oci_root(
    bundle: &str,
    root: &str,
    readonly: Option<bool>,
) -> Result<(String, Option<bool>), Errno> {
    let resolved = if root.starts_with('/') {
        root.to_string()
    } else {
        format!("{bundle}/{root}")
    };
    Ok((resolved, readonly))
}

pub fn oci_load(
    bundle: &str,
    root: Option<&str>,
    hostname: Option<&str>,
    args: &[&str],
) -> Result<OciConfig, Errno> {
    let root = root
        .map(|r| oci_root(bundle, r, None).map(|(p, _)| p))
        .transpose()?;
    let hostname = hostname.map(oci_hostname).transpose()?;
    Ok(OciConfig {
        bundle: bundle.into(),
        root,
        hostname,
        readonly: None,
        args: oci_args(args)?,
        environment: Vec::new(),
        capabilities: 0,
        oom_score_adj: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_root_is_resolved_against_bundle() {
        let (root, _) = oci_root("/bundle", "rootfs", Some(true)).unwrap();
        assert_eq!(root, "/bundle/rootfs");
    }

    #[test]
    fn seccomp_action_parser_accepts_allow() {
        assert_eq!(
            oci_seccomp_action_from_string("allow").unwrap(),
            SeccompAction::Allow
        );
    }
}
