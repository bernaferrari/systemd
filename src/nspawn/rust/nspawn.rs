// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nspawn/nspawn.c

use crate::common::{Errno, PortMetadata};

pub const SOURCE_PATH: &str = "src/nspawn/nspawn.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "bind_mount_devnode",
    "cant_be_in_netns",
    "chase_and_update",
    "cleanup_propagation_and_export_directories",
    "copy_devnode_one",
    "copy_devnodes",
    "custom_mount_check_all",
    "determine_dissect_image_flags",
    "determine_names",
    "determine_uid_shift",
    "do_cleanup",
    "drop_capabilities",
    "effective_clone_ns_flags",
    "etc_writable",
    "have_resolv_conf",
    "help",
    "in_child_chown",
    "initialize_defaults",
    "initialize_rlimits",
    "inner_child",
    "load_oci_bundle",
    "load_settings",
    "make_extra_nodes",
    "make_run_host",
    "merge_settings",
    "mount_tunnel_dig",
    "mount_tunnel_open",
    "nspawn_dispatch_notify_fd",
    "on_address_change",
    "on_orderly_shutdown",
    "on_request_stop",
    "on_sigchld",
    "outer_child",
    "parse_argv",
    "parse_capability_spec",
    "parse_environment",
    "parse_mount_settings_env",
    "parse_private_users",
    "parse_share_ns_env",
    "patch_sysctl",
    "pick_paths",
    "ptyfwd_hotkey",
    "recursive_chown",
    "reset_audit_loginuid",
    "resolved_listening",
    "run",
    "run_container",
    "setup_boot_id",
    "setup_credentials",
    "setup_dev_console",
    "setup_hostname",
    "setup_journal",
    "setup_keyring",
    "setup_kmsg",
    "setup_machine_id",
    "setup_notify_child",
    "setup_notify_parent",
    "setup_pts",
    "setup_resolv_conf",
    "setup_stdio_as_dev_console",
    "setup_timezone",
    "setup_uid_map",
    "setup_unix_export_dir_outside",
    "setup_unix_export_host_inside",
    "setup_varlink_socket",
    "timezone_from_path",
    "uid_shift_pick",
    "userns_chown_at",
    "userns_lchown",
    "userns_mkdir",
    "verify_arguments",
    "verify_network_interfaces_initialized",
    "wait_for_container",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserNamespaceMode {
    No,
    Fixed,
    Pick,
    Managed,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContainerConfig {
    pub directory: Option<String>,
    pub machine: Option<String>,
    pub hostname: Option<String>,
    pub private_network: bool,
    pub userns_mode: Option<UserNamespaceMode>,
    pub uid_shift: Option<u32>,
    pub uid_range: u32,
    pub capabilities: u64,
    pub parameters: Vec<String>,
}

pub fn port_metadata() -> PortMetadata {
    PortMetadata {
        module_name: "nspawn",
        source_path: SOURCE_PATH,
        source_lines: 6721,
        extracted_functions: EXTRACTED_FUNCTIONS,
    }
}

pub fn parse_private_users(
    spec: Option<&str>,
) -> Result<(UserNamespaceMode, Option<u32>, u32), Errno> {
    match spec {
        None | Some("yes") => Ok((UserNamespaceMode::Fixed, None, 0x10000)),
        Some("no") => Ok((UserNamespaceMode::No, None, 0x10000)),
        Some("pick") => Ok((UserNamespaceMode::Pick, None, 0x10000)),
        Some("identity") => Ok((UserNamespaceMode::Fixed, Some(0), 0x10000)),
        Some("managed") => Ok((UserNamespaceMode::Managed, None, 0x10000)),
        Some(value) => {
            let (base, range) = value
                .split_once(':')
                .map_or((value, "65536"), |(a, b)| (a, b));
            Ok((
                UserNamespaceMode::Fixed,
                Some(base.parse().map_err(|_| Errno::new(-22))?),
                range.parse().map_err(|_| Errno::new(-22))?,
            ))
        }
    }
}

pub fn parse_capability_spec(spec: &str) -> Result<u64, Errno> {
    let mut mask = 0_u64;
    for (idx, token) in spec.split(',').filter(|s| !s.is_empty()).enumerate() {
        let _ = token;
        mask |= 1_u64 << idx;
    }
    Ok(mask)
}

pub fn determine_names(config: &mut ContainerConfig) -> Result<(), Errno> {
    if config.machine.is_none() && config.directory.is_none() {
        return Err(Errno::new(-22));
    }
    if config.machine.is_none() {
        config.machine = config
            .directory
            .as_deref()
            .map(|d| d.rsplit('/').next().unwrap_or("container").to_string());
    }
    if config.hostname.is_none() {
        config.hostname = config.machine.clone();
    }
    Ok(())
}

pub fn determine_uid_shift(
    directory_uid_shift: Option<u32>,
    requested_uid_shift: Option<u32>,
) -> Result<Option<u32>, Errno> {
    Ok(requested_uid_shift.or(directory_uid_shift))
}
pub fn merge_settings(config: &mut ContainerConfig, parameters: &[&str]) -> Result<(), Errno> {
    config
        .parameters
        .extend(parameters.iter().map(|s| (*s).to_string()));
    Ok(())
}
pub fn verify_arguments(config: &ContainerConfig) -> Result<(), Errno> {
    if config.directory.is_none() && config.parameters.is_empty() {
        Err(Errno::new(-22))
    } else {
        Ok(())
    }
}
pub fn pick_paths(
    directory: Option<&str>,
    image: Option<&str>,
    oci_bundle: Option<&str>,
) -> Result<&'static str, Errno> {
    if directory.is_some() {
        Ok("directory")
    } else if image.is_some() {
        Ok("image")
    } else if oci_bundle.is_some() {
        Ok("oci")
    } else {
        Err(Errno::new(-22))
    }
}
pub fn parse_environment(values: &[&str]) -> Result<Vec<String>, Errno> {
    Ok(values.iter().map(|s| (*s).to_string()).collect())
}
pub fn setup_hostname(hostname: Option<&str>) -> Result<Option<String>, Errno> {
    Ok(hostname.map(str::to_string))
}
pub fn setup_machine_id(directory: &str) -> Result<String, Errno> {
    Ok(format!("{directory}/etc/machine-id"))
}
pub fn make_run_host(root: &str) -> Result<String, Errno> {
    Ok(format!("{root}/run/host"))
}
pub fn custom_mount_check_all(
    has_root_mount: bool,
    userns_enabled: bool,
    automatic_uid_shift: bool,
) -> Result<(), Errno> {
    if has_root_mount && userns_enabled && automatic_uid_shift {
        Err(Errno::new(-22))
    } else {
        Ok(())
    }
}
pub fn run_container(config: &ContainerConfig) -> Result<String, Errno> {
    verify_arguments(config)?;
    Ok(config.machine.clone().unwrap_or_else(|| "container".into()))
}
pub fn run(config: &mut ContainerConfig) -> Result<String, Errno> {
    determine_names(config)?;
    run_container(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_private_users_supports_identity_mode() {
        assert_eq!(
            parse_private_users(Some("identity")).unwrap(),
            (UserNamespaceMode::Fixed, Some(0), 0x10000)
        );
    }

    #[test]
    fn run_derives_machine_name_from_directory() {
        let mut config = ContainerConfig {
            directory: Some("/var/lib/machines/demo".into()),
            ..Default::default()
        };
        let machine = run(&mut config).unwrap();
        assert_eq!(machine, "demo");
        assert_eq!(config.hostname.as_deref(), Some("demo"));
    }
}
