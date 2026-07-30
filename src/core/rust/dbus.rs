// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus.c
//
//! Compiled-but-disconnected D-Bus policy model.
//!
//! This value model is not a second live manager; a production transport must
//! enqueue commands for [`crate::runtime_manager::RuntimeManager`]. Its
//! `api_bus_ready` state only preserves the narrow queue-ordering invariant
//! from the C manager; it does not implement the asynchronous `GetId`,
//! subscription coldplug, or sd-event lifecycle that establishes that state.

use std::collections::{BTreeMap, BTreeSet};

pub const SOURCE_PATH: &str = "src/core/dbus.c";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Bool(bool),
    Number(u64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbusError {
    ActivationDenied(String),
    UnknownUnit(String),
    UnknownBus(String),
    UnknownPath(String),
    InterfaceMismatch { expected: String, got: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BusConnection {
    pub name: String,
    pub queued_writes: u64,
    pub connected: bool,
    pub subscribed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitRecord {
    pub path: String,
    pub id: String,
    pub interface: String,
    pub refuse_manual_start: bool,
    pub has_cgroup_context: bool,
    pub has_exec_context: bool,
    pub has_kill_context: bool,
    pub process_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRecord {
    pub path: String,
    pub unit_path: String,
}

#[derive(Debug, Default)]
pub struct Manager {
    pub pending_reload_message: Option<String>,
    pub api_bus_connected: bool,
    /// Set only after the current API bus has completed setup. While an API
    /// bus is connected but not ready, reload messages must remain queued so
    /// subscribers restored across reexec cannot miss them.
    pub api_bus_ready: bool,
    pub system_bus_connected: bool,
    pub dbus_socket_active: bool,
    pub dbus_service_active: bool,
    pub private_buses: BTreeMap<String, BusConnection>,
    pub units: BTreeMap<String, UnitRecord>,
    pub jobs: BTreeMap<String, JobRecord>,
    pub activation_queue: Vec<String>,
    pub event_log: Vec<String>,
    pub exported_interfaces: BTreeSet<String>,
}

impl Manager {
    pub fn add_unit(&mut self, unit: UnitRecord) {
        self.units.insert(unit.path.clone(), unit);
    }

    pub fn add_private_bus(&mut self, bus: BusConnection) {
        self.private_buses.insert(bus.name.clone(), bus);
    }
}

pub fn bus_send_pending_reload_message(manager: &mut Manager) -> Result<Option<String>, DbusError> {
    // C performs this guard in manager_dispatch_dbus_queue(). This small
    // model has no event queue, so keep the pending reload message here until
    // API setup finishes instead of falsely claiming it was dispatched.
    if manager.api_bus_connected && !manager.api_bus_ready {
        manager
            .event_log
            .push("postponed queued reload message until api bus is ready".into());
        return Ok(None);
    }

    let message = manager.pending_reload_message.take();
    if message.is_some() {
        manager.event_log.push("sent queued reload message".into());
    }
    Ok(message)
}

pub fn signal_disconnected(manager: &mut Manager, bus_name: &str) -> Result<(), DbusError> {
    match bus_name {
        "api" => {
            manager.api_bus_connected = false;
            manager.api_bus_ready = false;
            manager.event_log.push("api disconnected".into());
            Ok(())
        }
        "system" => {
            manager.system_bus_connected = false;
            manager.event_log.push("system disconnected".into());
            Ok(())
        }
        other => {
            if manager.private_buses.remove(other).is_some() {
                manager
                    .event_log
                    .push(format!("private bus {other} disconnected"));
                Ok(())
            } else {
                Err(DbusError::UnknownBus(other.into()))
            }
        }
    }
}

pub fn signal_activation_request(manager: &mut Manager, unit_name: &str) -> Result<(), DbusError> {
    if !manager.dbus_socket_active || !manager.dbus_service_active {
        return Err(DbusError::ActivationDenied("D-Bus is shutting down".into()));
    }

    let unit = manager
        .units
        .values()
        .find(|unit| unit.id == unit_name)
        .ok_or_else(|| DbusError::UnknownUnit(unit_name.into()))?;

    if unit.refuse_manual_start {
        return Err(DbusError::ActivationDenied(unit.id.clone()));
    }

    manager.activation_queue.push(unit.id.clone());
    Ok(())
}

pub fn find_unit(
    manager: &Manager,
    path: &str,
    sender_pid: Option<u32>,
) -> Result<Option<UnitRecord>, DbusError> {
    if path == "/org/freedesktop/systemd1/unit/self" {
        let Some(pid) = sender_pid else {
            return Ok(None);
        };

        return Ok(manager
            .units
            .values()
            .find(|unit| unit.process_id == Some(pid))
            .cloned());
    }

    Ok(manager.units.get(path).cloned())
}

pub fn bus_unit_find(
    manager: &Manager,
    path: &str,
    sender_pid: Option<u32>,
) -> Result<Option<UnitRecord>, DbusError> {
    find_unit(manager, path, sender_pid)
}

pub fn bus_unit_interface_find(
    manager: &Manager,
    path: &str,
    interface: &str,
    sender_pid: Option<u32>,
) -> Result<Option<UnitRecord>, DbusError> {
    let Some(unit) = find_unit(manager, path, sender_pid)? else {
        return Ok(None);
    };
    if unit.interface != interface {
        return Ok(None);
    }
    Ok(Some(unit))
}

pub fn bus_unit_cgroup_find(
    manager: &Manager,
    path: &str,
    interface: &str,
    sender_pid: Option<u32>,
) -> Result<Option<UnitRecord>, DbusError> {
    let Some(unit) = bus_unit_interface_find(manager, path, interface, sender_pid)? else {
        return Ok(None);
    };
    Ok(unit.has_cgroup_context.then_some(unit))
}

pub fn bus_unit_exec_context_find(
    manager: &Manager,
    path: &str,
    interface: &str,
    sender_pid: Option<u32>,
) -> Result<Option<UnitRecord>, DbusError> {
    let Some(unit) = bus_unit_interface_find(manager, path, interface, sender_pid)? else {
        return Ok(None);
    };
    Ok(unit.has_exec_context.then_some(unit))
}

pub fn bus_kill_context_find(
    manager: &Manager,
    path: &str,
    interface: &str,
    sender_pid: Option<u32>,
) -> Result<Option<UnitRecord>, DbusError> {
    let Some(unit) = bus_unit_interface_find(manager, path, interface, sender_pid)? else {
        return Ok(None);
    };
    Ok(unit.has_kill_context.then_some(unit))
}

pub fn bus_unit_enumerate(manager: &Manager, prefix: &str) -> Result<Vec<String>, DbusError> {
    Ok(manager
        .units
        .keys()
        .filter(|path| path.starts_with(prefix))
        .cloned()
        .collect())
}

pub fn bus_setup_api_vtables(manager: &mut Manager) -> Result<(), DbusError> {
    manager.exported_interfaces.extend([
        "org.freedesktop.systemd1.Manager".into(),
        "org.freedesktop.systemd1.Unit".into(),
    ]);
    manager.api_bus_ready = true;
    Ok(())
}

pub fn bus_setup_disconnected_match(
    manager: &mut Manager,
    bus_name: &str,
) -> Result<(), DbusError> {
    if bus_name == "api" || bus_name == "system" || manager.private_buses.contains_key(bus_name) {
        manager
            .event_log
            .push(format!("match installed for {bus_name}"));
        Ok(())
    } else {
        Err(DbusError::UnknownBus(bus_name.into()))
    }
}

pub fn manager_bus_n_queued_write(manager: &Manager) -> u64 {
    manager
        .private_buses
        .values()
        .map(|bus| bus.queued_writes)
        .sum()
}

pub fn dump_bus_properties(manager: &Manager) -> JsonValue {
    let mut object = BTreeMap::new();
    object.insert(
        "apiConnected".into(),
        JsonValue::Bool(manager.api_bus_connected),
    );
    object.insert(
        "systemConnected".into(),
        JsonValue::Bool(manager.system_bus_connected),
    );
    object.insert(
        "queuedWrites".into(),
        JsonValue::Number(manager_bus_n_queued_write(manager)),
    );
    object.insert(
        "interfaces".into(),
        JsonValue::Array(
            manager
                .exported_interfaces
                .iter()
                .cloned()
                .map(JsonValue::string)
                .collect(),
        ),
    );
    JsonValue::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_unit() -> UnitRecord {
        UnitRecord {
            path: "/org/freedesktop/systemd1/unit/demo_2eservice".into(),
            id: "demo.service".into(),
            interface: "org.freedesktop.systemd1.Service".into(),
            refuse_manual_start: false,
            has_cgroup_context: true,
            has_exec_context: true,
            has_kill_context: false,
            process_id: Some(42),
        }
    }

    #[test]
    fn reload_message_is_taken_once() {
        let mut manager = Manager {
            pending_reload_message: Some("reload".into()),
            ..Manager::default()
        };
        assert_eq!(
            bus_send_pending_reload_message(&mut manager).unwrap(),
            Some("reload".into())
        );
        assert_eq!(bus_send_pending_reload_message(&mut manager).unwrap(), None);
    }

    #[test]
    fn reload_message_waits_for_connected_api_bus_setup() {
        let mut manager = Manager {
            pending_reload_message: Some("reload".into()),
            api_bus_connected: true,
            ..Manager::default()
        };

        assert_eq!(bus_send_pending_reload_message(&mut manager).unwrap(), None);
        assert_eq!(manager.pending_reload_message.as_deref(), Some("reload"));

        bus_setup_api_vtables(&mut manager).unwrap();
        assert_eq!(
            bus_send_pending_reload_message(&mut manager).unwrap(),
            Some("reload".into())
        );
    }

    #[test]
    fn api_disconnect_clears_readiness() {
        let mut manager = Manager {
            api_bus_connected: true,
            api_bus_ready: true,
            ..Manager::default()
        };

        signal_disconnected(&mut manager, "api").unwrap();
        assert!(!manager.api_bus_ready);
    }

    #[test]
    fn activation_rejects_units_that_refuse_manual_start() {
        let mut manager = Manager {
            dbus_socket_active: true,
            dbus_service_active: true,
            ..Manager::default()
        };
        let mut unit = sample_unit();
        unit.refuse_manual_start = true;
        manager.add_unit(unit);

        assert!(signal_activation_request(&mut manager, "demo.service").is_err());
    }

    #[test]
    fn self_lookup_uses_sender_pid() {
        let mut manager = Manager::default();
        manager.add_unit(sample_unit());
        let unit = find_unit(&manager, "/org/freedesktop/systemd1/unit/self", Some(42))
            .unwrap()
            .unwrap();
        assert_eq!(unit.id, "demo.service");
    }

    #[test]
    fn queued_writes_are_summed_across_private_buses() {
        let mut manager = Manager::default();
        manager.add_private_bus(BusConnection {
            name: "private-a".into(),
            queued_writes: 3,
            connected: true,
            subscribed: false,
        });
        manager.add_private_bus(BusConnection {
            name: "private-b".into(),
            queued_writes: 7,
            connected: true,
            subscribed: false,
        });

        assert_eq!(manager_bus_n_queued_write(&manager), 10);
    }
}
