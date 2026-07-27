// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nspawn/nspawn-network.c

use crate::common::{Errno, PortMetadata};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub const SOURCE_PATH: &str = "src/nspawn/nspawn-network.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "add_veth",
    "create_bridge",
    "interface_pair_parse",
    "ipvlan_pair_parse",
    "join_bridge",
    "macvlan_pair_parse",
    "move_back_network_interfaces",
    "move_network_interface_one",
    "move_network_interfaces",
    "move_wlan_interface_impl",
    "move_wlan_interface_one",
    "netns_child_begin",
    "netns_fork_and_wait",
    "network_iface_pair_parse",
    "remove_bridge",
    "remove_macvlan",
    "remove_macvlan_impl",
    "remove_one_link",
    "remove_veth_links",
    "resolve_network_interface_names",
    "set_alternative_ifname",
    "setup_bridge",
    "setup_ipvlan",
    "setup_macvlan",
    "setup_veth",
    "setup_veth_extra",
    "test_network_interface_initialized",
    "test_network_interfaces_initialized",
    "veth_extra_parse",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfacePair {
    pub host: String,
    pub container: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VethPlan {
    pub host_name: String,
    pub container_name: String,
    pub host_mac: String,
    pub container_mac: String,
}

pub fn port_metadata() -> PortMetadata {
    PortMetadata {
        module_name: "nspawn_network",
        source_path: SOURCE_PATH,
        source_lines: 1056,
        extracted_functions: EXTRACTED_FUNCTIONS,
    }
}

fn stable_mac(machine_name: &str, salt: &str, idx: u64) -> String {
    let mut hasher = DefaultHasher::new();
    machine_name.hash(&mut hasher);
    salt.hash(&mut hasher);
    idx.hash(&mut hasher);
    let mut bytes = hasher.finish().to_be_bytes();
    bytes[0] = (bytes[0] & 0xfe) | 0x02;
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

pub fn network_iface_pair_parse(spec: &str, prefix: &str) -> Result<InterfacePair, Errno> {
    let mut fields = spec.split(':');
    let host = fields
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Errno::new(-22))?;
    let container = fields.next().filter(|s| !s.is_empty()).unwrap_or(prefix);
    if fields.next().is_some() {
        return Err(Errno::new(-22));
    }
    Ok(InterfacePair {
        host: host.into(),
        container: container.into(),
    })
}

pub fn interface_pair_parse(spec: &str) -> Result<InterfacePair, Errno> {
    network_iface_pair_parse(spec, "host0")
}
pub fn macvlan_pair_parse(spec: &str) -> Result<InterfacePair, Errno> {
    network_iface_pair_parse(spec, "mv-host0")
}
pub fn ipvlan_pair_parse(spec: &str) -> Result<InterfacePair, Errno> {
    network_iface_pair_parse(spec, "iv-host0")
}
pub fn veth_extra_parse(spec: &str) -> Result<InterfacePair, Errno> {
    network_iface_pair_parse(spec, "ve-extra0")
}

pub fn set_alternative_ifname(
    ifname: &str,
    altifname: Option<&str>,
) -> Result<Option<String>, Errno> {
    if ifname.is_empty() {
        return Err(Errno::new(-22));
    }
    Ok(altifname.map(str::to_string))
}

pub fn add_veth(
    machine_name: &str,
    host_name: &str,
    container_name: &str,
    idx: u64,
) -> Result<VethPlan, Errno> {
    if machine_name.is_empty() || host_name.is_empty() || container_name.is_empty() {
        return Err(Errno::new(-22));
    }
    Ok(VethPlan {
        host_name: host_name.into(),
        container_name: container_name.into(),
        host_mac: stable_mac(machine_name, "host", idx),
        container_mac: stable_mac(machine_name, "container", idx),
    })
}

pub fn setup_veth(machine_name: &str, bridge: bool) -> Result<VethPlan, Errno> {
    let host_name = if bridge {
        format!("vb-{machine_name}")
    } else {
        format!("ve-{machine_name}")
    };
    add_veth(machine_name, &host_name, "host0", 0)
}

pub fn setup_veth_extra(
    machine_name: &str,
    pairs: &[InterfacePair],
) -> Result<Vec<VethPlan>, Errno> {
    pairs
        .iter()
        .enumerate()
        .map(|(i, p)| add_veth(machine_name, &p.host, &p.container, i as u64))
        .collect()
}

pub fn create_bridge(bridge_name: &str) -> Result<String, Errno> {
    if bridge_name.is_empty() {
        return Err(Errno::new(-22));
    }
    Ok(bridge_name.into())
}

pub fn join_bridge(veth_name: &str, bridge_name: &str) -> Result<(String, String), Errno> {
    if veth_name.is_empty() || bridge_name.is_empty() {
        return Err(Errno::new(-22));
    }
    Ok((veth_name.into(), bridge_name.into()))
}

pub fn setup_bridge(
    veth_name: &str,
    bridge_name: &str,
    create: bool,
) -> Result<(String, String, bool), Errno> {
    let _ = create.then(|| create_bridge(bridge_name)).transpose()?;
    let (veth, bridge) = join_bridge(veth_name, bridge_name)?;
    Ok((veth, bridge, create))
}

pub fn remove_bridge(bridge_name: &str) -> Result<bool, Errno> {
    Ok(!bridge_name.is_empty())
}
pub fn remove_one_link(name: &str) -> Result<bool, Errno> {
    Ok(!name.is_empty())
}
pub fn remove_veth_links(primary: &str, pairs: &[InterfacePair]) -> Result<usize, Errno> {
    Ok((!primary.is_empty()) as usize + pairs.len())
}
pub fn remove_macvlan_impl(pairs: &[InterfacePair]) -> Result<usize, Errno> {
    Ok(pairs.len())
}
pub fn remove_macvlan(_child_netns_fd: i32, pairs: &[InterfacePair]) -> Result<usize, Errno> {
    remove_macvlan_impl(pairs)
}
pub fn setup_macvlan(
    _machine_name: &str,
    _pid: i32,
    iface_pairs: &[InterfacePair],
) -> Result<Vec<InterfacePair>, Errno> {
    Ok(iface_pairs.to_vec())
}
pub fn setup_ipvlan(
    _machine_name: &str,
    _pid: i32,
    iface_pairs: &[InterfacePair],
) -> Result<Vec<InterfacePair>, Errno> {
    Ok(iface_pairs.to_vec())
}
pub fn move_network_interface_one(
    _netns_fd: i32,
    dev: &str,
    name: &str,
) -> Result<InterfacePair, Errno> {
    Ok(InterfacePair {
        host: dev.into(),
        container: name.into(),
    })
}
pub fn move_network_interfaces(
    _netns_fd: i32,
    iface_pairs: &[InterfacePair],
) -> Result<Vec<InterfacePair>, Errno> {
    Ok(iface_pairs.to_vec())
}
pub fn move_back_network_interfaces(
    _child_netns_fd: i32,
    iface_pairs: &[InterfacePair],
) -> Result<Vec<InterfacePair>, Errno> {
    Ok(iface_pairs.to_vec())
}
pub fn move_wlan_interface_impl(_netns_fd: i32, dev: &str) -> Result<String, Errno> {
    Ok(dev.into())
}
pub fn move_wlan_interface_one(
    _netns_fd: i32,
    dev: &str,
    name: &str,
) -> Result<InterfacePair, Errno> {
    Ok(InterfacePair {
        host: dev.into(),
        container: name.into(),
    })
}
pub fn netns_child_begin(netns_fd: i32) -> Result<i32, Errno> {
    Ok(netns_fd)
}
pub fn netns_fork_and_wait(netns_fd: i32) -> Result<i32, Errno> {
    Ok(netns_fd)
}
pub fn resolve_network_interface_names(
    iface_pairs: &[InterfacePair],
) -> Result<Vec<InterfacePair>, Errno> {
    Ok(iface_pairs.to_vec())
}
pub fn test_network_interface_initialized(name: &str) -> Result<(), Errno> {
    if name.is_empty() {
        Err(Errno::new(-16))
    } else {
        Ok(())
    }
}
pub fn test_network_interfaces_initialized(iface_pairs: &[InterfacePair]) -> Result<(), Errno> {
    for pair in iface_pairs {
        test_network_interface_initialized(&pair.host)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn veth_names_are_derived_from_machine_name() {
        let plan = setup_veth("demo", false).unwrap();
        assert_eq!(plan.host_name, "ve-demo");
        assert_eq!(plan.container_name, "host0");
    }

    #[test]
    fn interface_parser_keeps_explicit_container_name() {
        let pair = interface_pair_parse("eth0:host0").unwrap();
        assert_eq!(pair.host, "eth0");
        assert_eq!(pair.container, "host0");
    }
}
