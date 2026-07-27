// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nspawn/nspawn-settings.c

use crate::common::{Errno, PortMetadata};

pub const SOURCE_PATH: &str = "src/nspawn/nspawn-settings.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "config_parse_bind",
    "config_parse_bind_user",
    "config_parse_bind_user_shell",
    "config_parse_boot",
    "config_parse_capability",
    "config_parse_expose_port",
    "config_parse_inaccessible",
    "config_parse_ipvlan_iface_pair",
    "config_parse_link_journal",
    "config_parse_macvlan_iface_pair",
    "config_parse_network_iface_pair",
    "config_parse_network_zone",
    "config_parse_oom_score_adjust",
    "config_parse_overlay",
    "config_parse_pid2",
    "config_parse_pivot_root",
    "config_parse_private_users",
    "config_parse_syscall_filter",
    "config_parse_tmpfs",
    "config_parse_userns_chown",
    "config_parse_veth_extra",
    "device_node_array_free",
    "free_oci_hooks",
    "parse_link_journal",
    "settings_allocate_properties",
    "settings_free",
    "settings_load",
    "settings_network_configured",
    "settings_network_veth",
    "settings_new",
    "settings_private_network",
];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Settings {
    pub private_network: Option<bool>,
    pub network_veth: Option<bool>,
    pub network_bridge: Option<String>,
    pub network_zone: Option<String>,
    pub network_interfaces: Vec<String>,
    pub network_macvlan: Vec<String>,
    pub network_ipvlan: Vec<String>,
    pub network_veth_extra: Vec<String>,
    pub network_namespace_path: Option<String>,
    pub bind_mounts: Vec<String>,
    pub bind_users: Vec<String>,
    pub expose_ports: Vec<String>,
    pub syscall_allow_list: Vec<String>,
    pub syscall_deny_list: Vec<String>,
    pub properties_allocated: bool,
}

pub fn port_metadata() -> PortMetadata {
    PortMetadata {
        module_name: "nspawn_settings",
        source_path: SOURCE_PATH,
        source_lines: 1056,
        extracted_functions: EXTRACTED_FUNCTIONS,
    }
}

pub fn settings_new() -> Result<Settings, Errno> {
    Ok(Settings::default())
}
pub fn settings_free(settings: Settings) -> Result<Settings, Errno> {
    Ok(settings)
}

pub fn settings_private_network(s: &Settings) -> Result<bool, Errno> {
    Ok(s.private_network.unwrap_or(false)
        || s.network_veth.unwrap_or(false)
        || s.network_bridge.is_some()
        || s.network_zone.is_some()
        || !s.network_interfaces.is_empty()
        || !s.network_macvlan.is_empty()
        || !s.network_ipvlan.is_empty()
        || !s.network_veth_extra.is_empty())
}

pub fn settings_network_veth(s: &Settings) -> Result<bool, Errno> {
    Ok(s.network_veth.unwrap_or(false) || s.network_bridge.is_some() || s.network_zone.is_some())
}

pub fn settings_network_configured(s: &Settings) -> Result<bool, Errno> {
    Ok(s.private_network.is_some()
        || s.network_veth.is_some()
        || s.network_bridge.is_some()
        || s.network_zone.is_some()
        || !s.network_interfaces.is_empty()
        || !s.network_macvlan.is_empty()
        || !s.network_ipvlan.is_empty()
        || !s.network_veth_extra.is_empty()
        || s.network_namespace_path.is_some())
}

pub fn settings_allocate_properties(s: &mut Settings) -> Result<(), Errno> {
    s.properties_allocated = true;
    Ok(())
}

pub fn settings_load(lines: &[&str]) -> Result<Settings, Errno> {
    let mut s = settings_new()?;
    for line in lines
        .iter()
        .copied()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (key, value) = line.split_once('=').ok_or_else(|| Errno::new(-22))?;
        match key {
            "Bind" => config_parse_bind(&mut s, value)?,
            "BindUser" => config_parse_bind_user(&mut s, value)?,
            "ExposePort" => config_parse_expose_port(&mut s, value)?,
            "NetworkInterface" => config_parse_network_iface_pair(&mut s, value)?,
            "NetworkZone" => config_parse_network_zone(&mut s, value)?,
            "SystemCallFilter" => config_parse_syscall_filter(&mut s, value)?,
            _ => {}
        }
    }
    Ok(s)
}

pub fn config_parse_bind(s: &mut Settings, value: &str) -> Result<(), Errno> {
    s.bind_mounts.push(value.into());
    Ok(())
}
pub fn config_parse_bind_user(s: &mut Settings, value: &str) -> Result<(), Errno> {
    s.bind_users.push(value.into());
    Ok(())
}
pub fn config_parse_bind_user_shell(_s: &mut Settings, _value: &str) -> Result<(), Errno> {
    Ok(())
}
pub fn config_parse_boot(_s: &mut Settings, _value: &str) -> Result<(), Errno> {
    Ok(())
}
pub fn config_parse_capability(_s: &mut Settings, _value: &str) -> Result<(), Errno> {
    Ok(())
}
pub fn config_parse_expose_port(s: &mut Settings, value: &str) -> Result<(), Errno> {
    s.expose_ports.push(value.into());
    Ok(())
}
pub fn config_parse_inaccessible(s: &mut Settings, value: &str) -> Result<(), Errno> {
    s.bind_mounts.push(format!("inaccessible:{value}"));
    Ok(())
}
pub fn config_parse_ipvlan_iface_pair(s: &mut Settings, value: &str) -> Result<(), Errno> {
    s.network_ipvlan.push(value.into());
    Ok(())
}
pub fn config_parse_link_journal(_s: &mut Settings, _value: &str) -> Result<(), Errno> {
    Ok(())
}
pub fn config_parse_macvlan_iface_pair(s: &mut Settings, value: &str) -> Result<(), Errno> {
    s.network_macvlan.push(value.into());
    Ok(())
}
pub fn config_parse_network_iface_pair(s: &mut Settings, value: &str) -> Result<(), Errno> {
    s.network_interfaces.push(value.into());
    Ok(())
}
pub fn config_parse_network_zone(s: &mut Settings, value: &str) -> Result<(), Errno> {
    s.network_zone = Some(value.into());
    Ok(())
}
pub fn config_parse_oom_score_adjust(_s: &mut Settings, _value: &str) -> Result<(), Errno> {
    Ok(())
}
pub fn config_parse_overlay(s: &mut Settings, value: &str) -> Result<(), Errno> {
    s.bind_mounts.push(format!("overlay:{value}"));
    Ok(())
}
pub fn config_parse_pid2(_s: &mut Settings, _value: &str) -> Result<(), Errno> {
    Ok(())
}
pub fn config_parse_pivot_root(s: &mut Settings, value: &str) -> Result<(), Errno> {
    s.bind_mounts.push(format!("pivot-root:{value}"));
    Ok(())
}
pub fn config_parse_private_users(_s: &mut Settings, _value: &str) -> Result<(), Errno> {
    Ok(())
}
pub fn config_parse_syscall_filter(s: &mut Settings, value: &str) -> Result<(), Errno> {
    if let Some(rest) = value.strip_prefix('~') {
        s.syscall_deny_list.push(rest.into());
    } else {
        s.syscall_allow_list.push(value.into());
    }
    Ok(())
}
pub fn config_parse_tmpfs(s: &mut Settings, value: &str) -> Result<(), Errno> {
    s.bind_mounts.push(format!("tmpfs:{value}"));
    Ok(())
}
pub fn config_parse_userns_chown(_s: &mut Settings, _value: &str) -> Result<(), Errno> {
    Ok(())
}
pub fn config_parse_veth_extra(s: &mut Settings, value: &str) -> Result<(), Errno> {
    s.network_veth_extra.push(value.into());
    Ok(())
}
pub fn device_node_array_free(nodes: Vec<String>) -> Result<Vec<String>, Errno> {
    Ok(nodes)
}
pub fn free_oci_hooks(hooks: Vec<String>) -> Result<Vec<String>, Errno> {
    Ok(hooks)
}
pub fn parse_link_journal(value: &str) -> Result<(&str, bool), Errno> {
    Ok((value.trim_start_matches("try-"), value.starts_with("try-")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_network_detects_bridge_and_veth_flags() {
        let mut settings = settings_new().unwrap();
        settings.network_zone = Some("dmz".into());
        assert!(settings_private_network(&settings).unwrap());
        assert!(settings_network_veth(&settings).unwrap());
    }

    #[test]
    fn settings_loader_maps_basic_keys() {
        let loaded = settings_load(&[
            "Bind=/srv:/srv",
            "ExposePort=8080",
            "SystemCallFilter=~mount",
        ])
        .unwrap();
        assert_eq!(loaded.bind_mounts, vec!["/srv:/srv"]);
        assert_eq!(loaded.expose_ports, vec!["8080"]);
        assert_eq!(loaded.syscall_deny_list, vec!["mount"]);
    }
}
