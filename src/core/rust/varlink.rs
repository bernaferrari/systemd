// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/varlink.c

use std::collections::{BTreeMap, BTreeSet};

use crate::ffi::Errno;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Bool(bool),
    Unsigned(u64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarlinkError {
    InvalidArgument,
    NotSupported,
    PermissionDenied,
    SubscriptionTaken,
}

impl VarlinkError {
    pub const fn errno(self) -> i32 {
        match self {
            Self::InvalidArgument => Errno::EINVAL.to_neg_errno(),
            Self::NotSupported => Errno::EOPNOTSUPP.to_neg_errno(),
            Self::PermissionDenied => Errno::EACCES.to_neg_errno(),
            Self::SubscriptionTaken => Errno::EBUSY.to_neg_errno(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedOomMode {
    Auto,
    Kill,
}

impl ManagedOomMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Kill => "kill",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGroupContext {
    pub moom_swap: ManagedOomMode,
    pub moom_mem_pressure: ManagedOomMode,
    pub moom_mem_pressure_limit: Option<u64>,
    pub moom_mem_pressure_duration_usec: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CGroupRuntime {
    pub cgroup_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unit {
    pub id: String,
    pub active: bool,
    pub can_set_managed_oom: bool,
    pub cgroup_context: Option<CGroupContext>,
    pub cgroup_runtime: Option<CGroupRuntime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerMode {
    System,
    User,
    Test,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarlinkManager {
    pub mode: ManagerMode,
    pub units: Vec<Unit>,
    pub managed_oom_connected: bool,
    pub managed_oom_subscriber: Option<String>,
    pub varlink_addresses: BTreeSet<String>,
    pub metrics_addresses: BTreeSet<String>,
    pub pending_reload_message: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarlinkMessage {
    pub method: String,
    pub parameters: JsonValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyFlags {
    None,
    ErrorOrLocalDisconnect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionResult {
    Reply(JsonValue),
    Notify(JsonValue),
}

pub const MANAGED_OOM_MODE_PROPERTIES: [&str; 2] = ["ManagedOOMSwap", "ManagedOOMMemoryPressure"];

pub fn build_managed_oom_json_array_element(
    unit: &Unit,
    property: &str,
) -> Result<JsonValue, VarlinkError> {
    if !unit.can_set_managed_oom {
        return Err(VarlinkError::NotSupported);
    }

    let context = unit
        .cgroup_context
        .as_ref()
        .ok_or(VarlinkError::InvalidArgument)?;
    let runtime = unit
        .cgroup_runtime
        .as_ref()
        .ok_or(VarlinkError::InvalidArgument)?;
    let path = runtime
        .cgroup_path
        .clone()
        .ok_or(VarlinkError::InvalidArgument)?;

    let mut object = BTreeMap::new();
    let mode = if !unit.active {
        ManagedOomMode::Auto
    } else {
        match property {
            "ManagedOOMSwap" => context.moom_swap,
            "ManagedOOMMemoryPressure" => context.moom_mem_pressure,
            _ => return Err(VarlinkError::InvalidArgument),
        }
    };
    object.insert("mode".into(), JsonValue::String(mode.as_str().into()));
    object.insert("path".into(), JsonValue::String(path));
    object.insert("property".into(), JsonValue::String(property.into()));

    if property == "ManagedOOMMemoryPressure" {
        if let Some(limit) = context.moom_mem_pressure_limit.filter(|limit| *limit > 0) {
            object.insert("limit".into(), JsonValue::Unsigned(limit));
        }
        if let Some(duration) = context.moom_mem_pressure_duration_usec {
            object.insert("duration".into(), JsonValue::Unsigned(duration));
        }
    }

    Ok(JsonValue::Object(object))
}

pub fn build_managed_oom_cgroups_json(
    manager: &VarlinkManager,
    allow_empty: bool,
) -> Result<Option<JsonValue>, VarlinkError> {
    let mut array = Vec::new();

    for unit in &manager.units {
        if !unit.active || !unit.can_set_managed_oom {
            continue;
        }

        let Some(context) = unit.cgroup_context.as_ref() else {
            continue;
        };
        let Some(runtime) = unit.cgroup_runtime.as_ref() else {
            continue;
        };
        if runtime.cgroup_path.is_none() {
            continue;
        }

        for property in MANAGED_OOM_MODE_PROPERTIES {
            let enabled = matches!(property, "ManagedOOMSwap")
                && context.moom_swap == ManagedOomMode::Kill
                || matches!(property, "ManagedOOMMemoryPressure")
                    && context.moom_mem_pressure == ManagedOomMode::Kill;
            if !enabled {
                continue;
            }

            array.push(build_managed_oom_json_array_element(unit, property)?);
        }
    }

    if array.is_empty() && !allow_empty {
        return Ok(None);
    }

    Ok(Some(JsonValue::Object(BTreeMap::from([(
        "cgroups".into(),
        JsonValue::Array(array),
    )]))))
}

pub fn manager_varlink_send_managed_oom_initial(
    manager: &VarlinkManager,
) -> Result<Option<VarlinkMessage>, VarlinkError> {
    if manager.mode != ManagerMode::User || matches!(manager.mode, ManagerMode::Test) {
        return Ok(None);
    }
    if !manager.managed_oom_connected {
        return Ok(None);
    }

    let Some(parameters) = build_managed_oom_cgroups_json(manager, false)? else {
        return Ok(None);
    };
    Ok(Some(VarlinkMessage {
        method: "io.systemd.oom.ReportManagedOOMCGroups".into(),
        parameters,
    }))
}

pub fn manager_varlink_managed_oom_connect(
    manager: &mut VarlinkManager,
) -> Result<bool, VarlinkError> {
    if manager.managed_oom_connected {
        return Ok(true);
    }
    if manager.mode == ManagerMode::System {
        return Err(VarlinkError::InvalidArgument);
    }
    if manager.mode == ManagerMode::Test {
        return Ok(false);
    }

    manager.managed_oom_connected = true;
    Ok(true)
}

pub fn managed_oom_vl_reply(
    manager: &mut VarlinkManager,
    flags: ReplyFlags,
) -> Result<bool, VarlinkError> {
    if matches!(flags, ReplyFlags::ErrorOrLocalDisconnect) {
        manager.managed_oom_connected = false;
        return manager_varlink_managed_oom_connect(manager);
    }

    Ok(true)
}

pub fn manager_varlink_send_managed_oom_update(
    manager: &mut VarlinkManager,
    unit: &Unit,
) -> Result<Option<VarlinkMessage>, VarlinkError> {
    if !unit.can_set_managed_oom {
        return Ok(None);
    }
    if manager.mode == ManagerMode::Test {
        return Ok(None);
    }

    if manager.mode == ManagerMode::System {
        if !manager.managed_oom_connected {
            return Ok(None);
        }
    } else if !manager_varlink_managed_oom_connect(manager)? {
        return Ok(None);
    }

    let mut array = Vec::new();
    for property in MANAGED_OOM_MODE_PROPERTIES {
        array.push(build_managed_oom_json_array_element(unit, property)?);
    }

    let parameters = JsonValue::Object(BTreeMap::from([(
        "cgroups".into(),
        JsonValue::Array(array),
    )]));
    Ok(Some(VarlinkMessage {
        method: "io.systemd.oom.ReportManagedOOMCGroups".into(),
        parameters,
    }))
}

pub fn subscribe_managed_oom_cgroups(
    manager: &mut VarlinkManager,
    requester_unit_id: &str,
    more: bool,
) -> Result<SubscriptionResult, VarlinkError> {
    if requester_unit_id != "systemd-oomd.service" {
        return Err(VarlinkError::PermissionDenied);
    }
    if more && manager.managed_oom_subscriber.is_some() {
        return Err(VarlinkError::SubscriptionTaken);
    }

    let payload = build_managed_oom_cgroups_json(manager, true)?.unwrap_or(JsonValue::Object(
        BTreeMap::from([("cgroups".into(), JsonValue::Array(Vec::new()))]),
    ));

    if !more {
        return Ok(SubscriptionResult::Reply(payload));
    }

    manager.managed_oom_connected = true;
    manager.managed_oom_subscriber = Some(requester_unit_id.into());
    Ok(SubscriptionResult::Notify(payload))
}

pub fn vl_disconnect(manager: &mut VarlinkManager, subscriber: &str) {
    if manager.managed_oom_subscriber.as_deref() == Some(subscriber) {
        manager.managed_oom_subscriber = None;
        manager.managed_oom_connected = false;
    }
}

pub fn varlink_server_listen_many_idempotent(
    known_fresh: bool,
    prefix: Option<&str>,
    existing: &mut BTreeSet<String>,
    addresses: impl IntoIterator<Item = &'static str>,
) -> Vec<String> {
    let mut added = Vec::new();
    for address in addresses {
        let full = match prefix {
            Some(prefix) => format!("{prefix}/{address}"),
            None => address.to_string(),
        };

        if !known_fresh && existing.contains(&full) {
            continue;
        }

        existing.insert(full.clone());
        added.push(full);
    }
    added
}

pub fn manager_varlink_init_system_api(
    manager: &mut VarlinkManager,
) -> Result<Vec<String>, VarlinkError> {
    if manager.mode == ManagerMode::Test {
        return Ok(Vec::new());
    }
    Ok(varlink_server_listen_many_idempotent(
        manager.varlink_addresses.is_empty(),
        None,
        &mut manager.varlink_addresses,
        [
            "/run/systemd/io.systemd.Manager",
            "/run/systemd/userdb/io.systemd.DynamicUser",
            "/run/systemd/io.systemd.ManagedOOM",
        ],
    ))
}

pub fn manager_varlink_init_user_api(
    manager: &mut VarlinkManager,
    runtime_prefix: &str,
) -> Result<Vec<String>, VarlinkError> {
    if manager.mode == ManagerMode::Test {
        return Ok(Vec::new());
    }

    let added = varlink_server_listen_many_idempotent(
        manager.varlink_addresses.is_empty(),
        Some(runtime_prefix),
        &mut manager.varlink_addresses,
        ["systemd/io.systemd.Manager"],
    );
    let _ = manager_varlink_managed_oom_connect(manager)?;
    Ok(added)
}

pub fn manager_varlink_init_metrics(
    manager: &mut VarlinkManager,
    runtime_prefix: &str,
) -> Result<Vec<String>, VarlinkError> {
    if manager.mode == ManagerMode::Test {
        return Ok(Vec::new());
    }
    Ok(varlink_server_listen_many_idempotent(
        manager.metrics_addresses.is_empty(),
        Some(runtime_prefix),
        &mut manager.metrics_addresses,
        ["systemd/report/io.systemd.Manager"],
    ))
}

pub fn manager_varlink_init(
    manager: &mut VarlinkManager,
    runtime_prefix: &str,
) -> Result<(), VarlinkError> {
    match manager.mode {
        ManagerMode::System => {
            let _ = manager_varlink_init_system_api(manager)?;
        }
        ManagerMode::User | ManagerMode::Test => {
            let _ = manager_varlink_init_user_api(manager, runtime_prefix)?;
        }
    }
    let _ = manager_varlink_init_metrics(manager, runtime_prefix)?;
    Ok(())
}

pub fn manager_varlink_done(manager: &mut VarlinkManager) {
    manager.managed_oom_connected = false;
    manager.managed_oom_subscriber = None;
    manager.varlink_addresses.clear();
    manager.metrics_addresses.clear();
}

pub fn manager_varlink_send_pending_reload_message(manager: &mut VarlinkManager) -> bool {
    if !manager.pending_reload_message {
        return false;
    }
    manager.pending_reload_message = false;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed_unit(active: bool) -> Unit {
        Unit {
            id: "demo.service".into(),
            active,
            can_set_managed_oom: true,
            cgroup_context: Some(CGroupContext {
                moom_swap: ManagedOomMode::Kill,
                moom_mem_pressure: ManagedOomMode::Kill,
                moom_mem_pressure_limit: Some(50),
                moom_mem_pressure_duration_usec: Some(70),
            }),
            cgroup_runtime: Some(CGroupRuntime {
                cgroup_path: Some("/sys/fs/cgroup/demo.service".into()),
            }),
        }
    }

    fn manager(mode: ManagerMode) -> VarlinkManager {
        VarlinkManager {
            mode,
            units: vec![managed_unit(true)],
            managed_oom_connected: false,
            managed_oom_subscriber: None,
            varlink_addresses: BTreeSet::new(),
            metrics_addresses: BTreeSet::new(),
            pending_reload_message: true,
        }
    }

    #[test]
    fn json_array_element_contains_mode_path_and_property() {
        let JsonValue::Object(object) =
            build_managed_oom_json_array_element(&managed_unit(true), "ManagedOOMSwap").unwrap()
        else {
            panic!("expected object");
        };
        assert!(object.contains_key("mode"));
        assert!(object.contains_key("path"));
        assert!(object.contains_key("property"));
    }

    #[test]
    fn inactive_units_report_auto_mode() {
        let JsonValue::Object(object) =
            build_managed_oom_json_array_element(&managed_unit(false), "ManagedOOMSwap").unwrap()
        else {
            panic!("expected object");
        };
        assert_eq!(object.get("mode"), Some(&JsonValue::String("auto".into())));
    }

    #[test]
    fn managed_oom_cgroups_json_is_none_when_no_units_match() {
        let manager = VarlinkManager {
            units: vec![],
            ..manager(ManagerMode::User)
        };
        assert_eq!(
            build_managed_oom_cgroups_json(&manager, false).unwrap(),
            None
        );
    }

    #[test]
    fn managed_oom_connect_is_user_only() {
        assert!(manager_varlink_managed_oom_connect(&mut manager(ManagerMode::User)).unwrap());
        assert_eq!(
            manager_varlink_managed_oom_connect(&mut manager(ManagerMode::System)).unwrap_err(),
            VarlinkError::InvalidArgument
        );
    }

    #[test]
    fn reply_error_reconnects_user_manager() {
        let mut manager = manager(ManagerMode::User);
        manager.managed_oom_connected = true;
        assert!(managed_oom_vl_reply(&mut manager, ReplyFlags::ErrorOrLocalDisconnect).unwrap());
        assert!(manager.managed_oom_connected);
    }

    #[test]
    fn subscribe_requires_systemd_oomd_service() {
        let mut manager = manager(ManagerMode::System);
        assert_eq!(
            subscribe_managed_oom_cgroups(&mut manager, "other.service", false).unwrap_err(),
            VarlinkError::PermissionDenied
        );
    }

    #[test]
    fn subscribe_more_takes_single_subscriber() {
        let mut manager = manager(ManagerMode::System);
        let result =
            subscribe_managed_oom_cgroups(&mut manager, "systemd-oomd.service", true).unwrap();
        assert!(matches!(result, SubscriptionResult::Notify(_)));
        assert_eq!(
            subscribe_managed_oom_cgroups(&mut manager, "systemd-oomd.service", true).unwrap_err(),
            VarlinkError::SubscriptionTaken
        );
    }

    #[test]
    fn listen_many_is_idempotent() {
        let mut existing = BTreeSet::new();
        let first =
            varlink_server_listen_many_idempotent(false, Some("/run"), &mut existing, ["a", "b"]);
        let second =
            varlink_server_listen_many_idempotent(false, Some("/run"), &mut existing, ["a", "b"]);
        assert_eq!(first.len(), 2);
        assert!(second.is_empty());
    }

    #[test]
    fn manager_init_and_done_manage_addresses() {
        let mut manager = manager(ManagerMode::User);
        manager_varlink_init(&mut manager, "/run/user/1000").unwrap();
        assert!(!manager.varlink_addresses.is_empty());
        assert!(!manager.metrics_addresses.is_empty());
        manager_varlink_done(&mut manager);
        assert!(manager.varlink_addresses.is_empty());
        assert!(manager.metrics_addresses.is_empty());
    }

    #[test]
    fn pending_reload_message_is_consumed_once() {
        let mut manager = manager(ManagerMode::User);
        assert!(manager_varlink_send_pending_reload_message(&mut manager));
        assert!(!manager_varlink_send_pending_reload_message(&mut manager));
    }
}
