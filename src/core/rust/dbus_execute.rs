// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-execute.c

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const SOURCE_PATH: &str = "src/core/dbus-execute.c";

pub type Result<T> = std::result::Result<T, DbusExecuteError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbusExecuteError {
    UnknownStdioProperty(String),
}

impl fmt::Display for DbusExecuteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownStdioProperty(name) => write!(f, "unknown stdio property: {name}"),
        }
    }
}

impl std::error::Error for DbusExecuteError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecCommand {
    pub path: String,
    pub argv: Vec<String>,
    pub ignore_failure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    pub source: String,
    pub destination: String,
    pub ignore_enoent: bool,
    pub read_only: bool,
    pub recursive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporaryFilesystem {
    pub path: String,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecContext {
    pub environment_files: Vec<String>,
    pub cpu_affinity_from_numa: bool,
    pub cpu_set: BTreeSet<u32>,
    pub numa_nodes: BTreeSet<u32>,
    pub numa_policy: i32,
    pub syscall_allow_list: bool,
    pub syscall_filter: Vec<String>,
    pub syscall_log_allow_list: bool,
    pub syscall_log: Vec<String>,
    pub syscall_archs: Vec<String>,
    pub selinux_context_ignore: bool,
    pub selinux_context: String,
    pub apparmor_profile_ignore: bool,
    pub apparmor_profile: String,
    pub smack_process_label_ignore: bool,
    pub smack_process_label: String,
    pub address_families_allow_list: bool,
    pub address_families: Vec<String>,
    pub working_directory_home: bool,
    pub working_directory: String,
    pub working_directory_missing_ok: bool,
    pub fd_names: BTreeMap<i32, String>,
    pub stdin_data: Vec<u8>,
    pub restrict_filesystems_allow_list: bool,
    pub restrict_filesystems: Vec<String>,
    pub bind_mounts: Vec<BindMount>,
    pub temporary_filesystems: Vec<TemporaryFilesystem>,
}

pub fn bus_property_get_exec_command(command: &ExecCommand) -> Result<(String, Vec<String>, bool)> {
    Ok((
        command.path.clone(),
        command.argv.clone(),
        command.ignore_failure,
    ))
}

pub fn bus_property_get_exec_command_list(
    commands: &[ExecCommand],
) -> Result<Vec<(String, Vec<String>, bool)>> {
    commands.iter().map(bus_property_get_exec_command).collect()
}

pub fn property_get_environment_files(context: &ExecContext) -> Vec<(String, bool)> {
    context
        .environment_files
        .iter()
        .map(|entry| match entry.strip_prefix('-') {
            Some(path) => (path.to_string(), true),
            None => (entry.clone(), false),
        })
        .collect()
}

pub fn property_get_cpu_affinity(context: &ExecContext) -> Vec<u8> {
    let set = if context.cpu_affinity_from_numa {
        &context.numa_nodes
    } else {
        &context.cpu_set
    };
    encode_cpu_set(set)
}

pub fn property_get_numa_mask(context: &ExecContext) -> Vec<u8> {
    encode_cpu_set(&context.numa_nodes)
}

pub fn property_get_numa_policy(context: &ExecContext) -> i32 {
    context.numa_policy
}

pub fn property_get_syscall_filter(context: &ExecContext) -> (bool, Vec<String>) {
    (context.syscall_allow_list, context.syscall_filter.clone())
}

pub fn property_get_syscall_log(context: &ExecContext) -> (bool, Vec<String>) {
    (context.syscall_log_allow_list, context.syscall_log.clone())
}

pub fn property_get_syscall_archs(context: &ExecContext) -> Vec<String> {
    context.syscall_archs.clone()
}

pub fn property_get_selinux_context(context: &ExecContext) -> (bool, String) {
    (
        context.selinux_context_ignore,
        context.selinux_context.clone(),
    )
}

pub fn property_get_apparmor_profile(context: &ExecContext) -> (bool, String) {
    (
        context.apparmor_profile_ignore,
        context.apparmor_profile.clone(),
    )
}

pub fn property_get_smack_process_label(context: &ExecContext) -> (bool, String) {
    (
        context.smack_process_label_ignore,
        context.smack_process_label.clone(),
    )
}

pub fn property_get_address_families(context: &ExecContext) -> (bool, Vec<String>) {
    (
        context.address_families_allow_list,
        context.address_families.clone(),
    )
}

pub fn property_get_working_directory(context: &ExecContext) -> String {
    let base = if context.working_directory_home {
        "~".to_string()
    } else {
        context.working_directory.clone()
    };

    if context.working_directory_missing_ok {
        format!("!{base}")
    } else {
        base
    }
}

pub fn property_get_stdio_fdname(context: &ExecContext, property: &str) -> Result<String> {
    let fileno = match property {
        "StandardInputFileDescriptorName" => 0,
        "StandardOutputFileDescriptorName" => 1,
        "StandardErrorFileDescriptorName" => 2,
        other => return Err(DbusExecuteError::UnknownStdioProperty(other.into())),
    };

    Ok(context.fd_names.get(&fileno).cloned().unwrap_or_default())
}

pub fn property_get_input_data(context: &ExecContext) -> Vec<u8> {
    context.stdin_data.clone()
}

pub fn property_get_restrict_filesystems(context: &ExecContext) -> (bool, Vec<String>) {
    (
        context.restrict_filesystems_allow_list,
        context.restrict_filesystems.clone(),
    )
}

pub fn property_get_bind_paths(
    context: &ExecContext,
    read_only: bool,
) -> Vec<(String, String, bool, u64)> {
    context
        .bind_mounts
        .iter()
        .filter(|mount| mount.read_only == read_only)
        .map(|mount| {
            (
                mount.source.clone(),
                mount.destination.clone(),
                mount.ignore_enoent,
                if mount.recursive { 1 } else { 0 },
            )
        })
        .collect()
}

pub fn property_get_temporary_filesystems(context: &ExecContext) -> Vec<(String, Vec<String>)> {
    context
        .temporary_filesystems
        .iter()
        .map(|mount| (mount.path.clone(), mount.options.clone()))
        .collect()
}

fn encode_cpu_set(set: &BTreeSet<u32>) -> Vec<u8> {
    let Some(max) = set.iter().max().copied() else {
        return Vec::new();
    };

    let mut bytes = vec![0u8; (max as usize / 8) + 1];
    for cpu in set {
        let index = (*cpu as usize) / 8;
        let bit = (*cpu as usize) % 8;
        bytes[index] |= 1 << bit;
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_context() -> ExecContext {
        ExecContext {
            environment_files: vec!["-/etc/default/app".into(), "/etc/app.env".into()],
            cpu_affinity_from_numa: false,
            cpu_set: BTreeSet::from([0, 2, 7]),
            numa_nodes: BTreeSet::from([1, 3]),
            numa_policy: 2,
            syscall_allow_list: true,
            syscall_filter: vec!["read".into(), "write".into()],
            syscall_log_allow_list: false,
            syscall_log: vec!["mount".into()],
            syscall_archs: vec!["x86-64".into()],
            selinux_context_ignore: true,
            selinux_context: "system_u:system_r:init_t:s0".into(),
            apparmor_profile_ignore: false,
            apparmor_profile: "systemd".into(),
            smack_process_label_ignore: true,
            smack_process_label: "System".into(),
            address_families_allow_list: true,
            address_families: vec!["AF_UNIX".into(), "AF_INET".into()],
            working_directory_home: false,
            working_directory: "/srv/app".into(),
            working_directory_missing_ok: true,
            fd_names: BTreeMap::from([(0, "stdin-cache".into()), (2, "stderr-log".into())]),
            stdin_data: vec![1, 2, 3],
            restrict_filesystems_allow_list: false,
            restrict_filesystems: vec!["ext4".into()],
            bind_mounts: vec![
                BindMount {
                    source: "/src".into(),
                    destination: "/dst".into(),
                    ignore_enoent: false,
                    read_only: true,
                    recursive: true,
                },
                BindMount {
                    source: "/rw-src".into(),
                    destination: "/rw-dst".into(),
                    ignore_enoent: true,
                    read_only: false,
                    recursive: false,
                },
            ],
            temporary_filesystems: vec![TemporaryFilesystem {
                path: "/tmp".into(),
                options: vec!["size=64M".into()],
            }],
        }
    }

    #[test]
    fn exec_command_list_roundtrips() {
        let commands = vec![ExecCommand {
            path: "/usr/bin/echo".into(),
            argv: vec!["echo".into(), "hi".into()],
            ignore_failure: true,
        }];
        assert_eq!(
            bus_property_get_exec_command_list(&commands).unwrap().len(),
            1
        );
    }

    #[test]
    fn environment_files_preserve_ignore_prefix() {
        let ctx = sample_context();
        assert_eq!(
            property_get_environment_files(&ctx),
            vec![
                ("/etc/default/app".into(), true),
                ("/etc/app.env".into(), false)
            ]
        );
    }

    #[test]
    fn cpu_affinity_and_numa_masks_are_encoded() {
        let ctx = sample_context();
        assert_eq!(property_get_cpu_affinity(&ctx), vec![0b1000_0101]);
        assert_eq!(property_get_numa_mask(&ctx), vec![0b0000_1010]);
    }

    #[test]
    fn syscall_and_address_family_properties_keep_list_polarity() {
        let ctx = sample_context();
        assert_eq!(property_get_syscall_filter(&ctx).0, true);
        assert_eq!(property_get_syscall_log(&ctx).0, false);
        assert_eq!(property_get_address_families(&ctx).1.len(), 2);
    }

    #[test]
    fn lsm_context_properties_are_marshaled_as_pairs() {
        let ctx = sample_context();
        assert_eq!(property_get_selinux_context(&ctx).0, true);
        assert_eq!(property_get_apparmor_profile(&ctx).1, "systemd");
        assert_eq!(property_get_smack_process_label(&ctx).1, "System");
    }

    #[test]
    fn working_directory_and_stdio_names_follow_c_rules() {
        let ctx = sample_context();
        assert_eq!(property_get_working_directory(&ctx), "!/srv/app");
        assert_eq!(
            property_get_stdio_fdname(&ctx, "StandardInputFileDescriptorName").unwrap(),
            "stdin-cache"
        );
        assert_eq!(
            property_get_stdio_fdname(&ctx, "StandardOutputFileDescriptorName").unwrap(),
            ""
        );
    }

    #[test]
    fn input_data_and_restricted_filesystems_roundtrip() {
        let ctx = sample_context();
        assert_eq!(property_get_input_data(&ctx), vec![1, 2, 3]);
        assert_eq!(property_get_restrict_filesystems(&ctx).1, vec!["ext4"]);
    }

    #[test]
    fn bind_paths_filter_on_read_only_flag() {
        let ctx = sample_context();
        assert_eq!(property_get_bind_paths(&ctx, true).len(), 1);
        assert_eq!(property_get_bind_paths(&ctx, false).len(), 1);
        assert_eq!(property_get_bind_paths(&ctx, true)[0].3, 1);
    }

    #[test]
    fn temporary_filesystems_and_unknown_stdio_property() {
        let ctx = sample_context();
        assert_eq!(property_get_temporary_filesystems(&ctx).len(), 1);
        assert!(matches!(
            property_get_stdio_fdname(&ctx, "StandardFoo"),
            Err(DbusExecuteError::UnknownStdioProperty(_))
        ));
    }
}
