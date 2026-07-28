// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/nspawn/nspawn-register.c

use crate::common::{Errno, PortMetadata};
pub const SOURCE_PATH: &str = "src/nspawn/nspawn-register.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "allocate_scope",
    "append_controller_property",
    "append_machine_properties",
    "can_set_coredump_receive",
    "register_machine",
    "register_machine_ex",
    "terminate_scope",
    "unregister_machine",
];
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineRegistration {
    pub machine_name: String,
    pub service: String,
    pub root_directory: Option<String>,
    pub network_interfaces: Vec<i32>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeAllocation {
    pub scope_name: String,
    pub description: String,
    pub properties: Vec<(String, String)>,
}
pub fn port_metadata() -> PortMetadata {
    PortMetadata {
        module_name: "nspawn_register",
        source_path: SOURCE_PATH,
        source_lines: 448,
        extracted_functions: EXTRACTED_FUNCTIONS,
    }
}
pub fn append_machine_properties(
    kill_signal: i32,
    coredump_receive: bool,
) -> Result<Vec<(String, String)>, Errno> {
    let mut p = vec![
        ("DevicePolicy".into(), "closed".into()),
        ("DeviceAllow".into(), "/dev/net/tun:rwm".into()),
        ("DeviceAllow".into(), "char-pts:rw".into()),
        ("DeviceAllow".into(), "/dev/fuse:rwm".into()),
    ];
    if kill_signal != 0 {
        p.push(("KillSignal".into(), kill_signal.to_string()));
        p.push(("KillMode".into(), "mixed".into()));
    }
    if coredump_receive {
        p.push(("CoredumpReceive".into(), "true".into()));
    }
    Ok(p)
}
pub fn append_controller_property(unique: &str) -> Result<(String, String), Errno> {
    if unique.is_empty() {
        Err(Errno::new(-22))
    } else {
        Ok(("Controller".into(), unique.into()))
    }
}
pub fn can_set_coredump_receive(scope_supports: bool) -> Result<bool, Errno> {
    Ok(scope_supports)
}
pub fn register_machine_ex(
    machine_name: &str,
    directory: Option<&str>,
    ifindex: i32,
    service: &str,
) -> Result<MachineRegistration, Errno> {
    if machine_name.is_empty() || service.is_empty() {
        return Err(Errno::new(-22));
    }
    Ok(MachineRegistration {
        machine_name: machine_name.into(),
        service: service.into(),
        root_directory: directory.map(str::to_string),
        network_interfaces: if ifindex > 0 {
            vec![ifindex]
        } else {
            Vec::new()
        },
    })
}
pub fn register_machine(
    machine_name: &str,
    directory: Option<&str>,
    ifindex: i32,
    service: &str,
) -> Result<MachineRegistration, Errno> {
    register_machine_ex(machine_name, directory, ifindex, service)
}
pub fn unregister_machine(machine_name: &str) -> Result<bool, Errno> {
    if machine_name.is_empty() {
        Err(Errno::new(-22))
    } else {
        Ok(true)
    }
}
pub fn terminate_scope(machine_name: &str) -> Result<bool, Errno> {
    unregister_machine(machine_name)
}
pub fn allocate_scope(
    machine_name: &str,
    slice: Option<&str>,
    kill_signal: i32,
    coredump_receive: bool,
    controller: &str,
) -> Result<ScopeAllocation, Errno> {
    let mut p = append_machine_properties(kill_signal, coredump_receive)?;
    p.push(append_controller_property(controller)?);
    p.push(("Slice".into(), slice.unwrap_or("machine.slice").into()));
    Ok(ScopeAllocation {
        scope_name: format!("{machine_name}.scope"),
        description: format!("Container {machine_name}"),
        properties: p,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_lines() {
        assert_eq!(port_metadata().source_lines, 448);
    }
    #[test]
    fn properties_include_device_policy() {
        assert!(
            append_machine_properties(0, false)
                .unwrap()
                .iter()
                .any(|p| p.0 == "DevicePolicy")
        );
    }
    #[test]
    fn properties_include_kill_signal() {
        assert!(
            append_machine_properties(9, false)
                .unwrap()
                .iter()
                .any(|p| p.0 == "KillSignal")
        );
    }
    #[test]
    fn controller_property_requires_name() {
        assert!(append_controller_property("").is_err());
    }
    #[test]
    fn register_requires_machine_name() {
        assert!(register_machine_ex("", None, 0, "svc").is_err());
    }
    #[test]
    fn register_keeps_ifindex() {
        assert_eq!(
            register_machine_ex("m", None, 5, "svc")
                .unwrap()
                .network_interfaces,
            vec![5]
        );
    }
    #[test]
    fn unregister_empty_name_fails() {
        assert!(unregister_machine("").is_err());
    }
    #[test]
    fn terminate_delegates() {
        assert!(terminate_scope("m").unwrap());
    }
    #[test]
    fn allocate_scope_name() {
        assert_eq!(
            allocate_scope("m", None, 0, false, "u").unwrap().scope_name,
            "m.scope"
        );
    }
    #[test]
    fn allocate_scope_adds_slice() {
        assert!(
            allocate_scope("m", Some("custom.slice"), 0, false, "u")
                .unwrap()
                .properties
                .iter()
                .any(|p| p.1 == "custom.slice")
        );
    }
}
