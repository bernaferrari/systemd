// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/dbus-unit.c
//

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::c_void;

use libc::c_char;

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/core/dbus-unit.c";
pub type Result<T> = std::result::Result<T, Errno>;
/// D-Bus representation of a unit condition, matching the tuple signature in
/// `src/core/dbus-unit.c`.
pub type ConditionProperty = (String, bool, bool, String, i32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExecDirectoryType {
    Runtime,
    State,
    Cache,
    Logs,
    Configuration,
}

impl ExecDirectoryType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::State => "state",
            Self::Cache => "cache",
            Self::Logs => "logs",
            Self::Configuration => "configuration",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitJob {
    pub id: u32,
    pub kind: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitCondition {
    pub kind: String,
    pub trigger: bool,
    pub negate: bool,
    pub parameter: String,
    pub state: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitRecord {
    pub id: String,
    pub aliases: BTreeSet<String>,
    pub following: Option<String>,
    pub dependencies: BTreeMap<String, BTreeSet<String>>,
    pub mounts_for: BTreeSet<String>,
    pub cleanable: BTreeSet<ExecDirectoryType>,
    pub can_live_mount: bool,
    pub unit_file_preset: String,
    pub job: Option<UnitJob>,
    pub conditions: Vec<UnitCondition>,
    pub load_error: Option<(i32, String)>,
    pub markers: BTreeSet<String>,
}

impl UnitRecord {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            aliases: BTreeSet::new(),
            following: None,
            dependencies: BTreeMap::new(),
            mounts_for: BTreeSet::new(),
            cleanable: BTreeSet::new(),
            can_live_mount: false,
            unit_file_preset: String::new(),
            job: None,
            conditions: Vec::new(),
            load_error: None,
            markers: BTreeSet::new(),
        }
    }
}

pub fn property_get_can_clean(unit: &UnitRecord, include_fdstore: bool) -> Result<Vec<String>> {
    let mut values: Vec<String> = unit
        .cleanable
        .iter()
        .map(|v| v.as_str().to_string())
        .collect();
    if include_fdstore {
        values.push("fdstore".into());
    }
    Ok(values)
}

pub fn property_get_can_live_mount(unit: &UnitRecord) -> bool {
    unit.can_live_mount
}

pub fn property_get_names(unit: &UnitRecord) -> Result<Vec<String>> {
    let mut names = Vec::with_capacity(1 + unit.aliases.len());
    names.push(unit.id.clone());
    names.extend(unit.aliases.iter().cloned());
    Ok(names)
}

pub fn property_get_following(unit: &UnitRecord) -> Option<String> {
    unit.following.clone()
}

pub fn property_get_dependencies(unit: &UnitRecord, property: &str) -> Result<Vec<String>> {
    Ok(unit
        .dependencies
        .get(property)
        .map(|deps| deps.iter().cloned().collect())
        .unwrap_or_default())
}

pub fn property_get_mounts_for(unit: &UnitRecord) -> Result<Vec<String>> {
    Ok(unit.mounts_for.iter().cloned().collect())
}

pub fn property_get_unit_file_preset(unit: &UnitRecord) -> Result<String> {
    Ok(unit.unit_file_preset.clone())
}

pub fn property_get_job(unit: &UnitRecord) -> Result<Option<(u32, String, String)>> {
    Ok(unit
        .job
        .as_ref()
        .map(|job| (job.id, job.kind.clone(), job.path.clone())))
}

pub fn property_get_conditions(unit: &UnitRecord) -> Result<Vec<ConditionProperty>> {
    Ok(unit
        .conditions
        .iter()
        .map(|condition| {
            (
                condition.kind.clone(),
                condition.trigger,
                condition.negate,
                condition.parameter.clone(),
                condition.state,
            )
        })
        .collect())
}

pub fn property_get_load_error(unit: &UnitRecord) -> Result<Option<(i32, String)>> {
    Ok(unit.load_error.clone())
}

pub fn property_get_markers(unit: &UnitRecord) -> Result<Vec<String>> {
    Ok(unit.markers.iter().cloned().collect())
}

pub const FUNCTION_INVENTORY: &[&str] = &[
    "append_cgroup",
    "append_process",
    "bus_set_transient_conditions",
    "bus_set_transient_emergency_action",
    "bus_set_transient_exit_status",
    "bus_unit_allocate_bus_track",
    "bus_unit_method_attach_processes",
    "bus_unit_method_clean",
    "bus_unit_method_enqueue_job",
    "bus_unit_method_freeze",
    "bus_unit_method_freezer_generic",
    "bus_unit_method_get_processes",
    "bus_unit_method_kill",
    "bus_unit_method_kill_subgroup",
    "bus_unit_method_ref",
    "bus_unit_method_reload",
    "bus_unit_method_reload_or_restart",
    "bus_unit_method_reload_or_try_restart",
    "bus_unit_method_remove_subgroup",
    "bus_unit_method_reset_failed",
    "bus_unit_method_restart",
    "bus_unit_method_set_properties",
    "bus_unit_method_start",
    "bus_unit_method_start_generic",
    "bus_unit_method_stop",
    "bus_unit_method_thaw",
    "bus_unit_method_try_restart",
    "bus_unit_method_unref",
    "bus_unit_queue_job",
    "bus_unit_queue_job_one",
    "bus_unit_send_change_signal",
    "bus_unit_send_pending_change_signal",
    "bus_unit_send_pending_freezer_message",
    "bus_unit_send_removed_signal",
    "bus_unit_set_live_property",
    "bus_unit_set_properties",
    "bus_unit_set_transient_property",
    "bus_unit_track_add_name",
    "bus_unit_track_add_sender",
    "bus_unit_track_handler",
    "bus_unit_track_remove_sender",
    "bus_unit_validate_load_state",
    "property_get_available_memory",
    "property_get_can_clean",
    "property_get_can_live_mount",
    "property_get_cgroup",
    "property_get_cgroup_id",
    "property_get_conditions",
    "property_get_cpu_usage",
    "property_get_cpuset_cpus",
    "property_get_cpuset_mems",
    "property_get_current_tasks",
    "property_get_dependencies",
    "property_get_effective_limit",
    "property_get_following",
    "property_get_io_counter",
    "property_get_ip_counter",
    "property_get_job",
    "property_get_load_error",
    "property_get_managed_oom_kills",
    "property_get_markers",
    "property_get_memory_accounting",
    "property_get_mounts_for",
    "property_get_names",
    "property_get_oom_kills",
    "property_get_refs",
    "property_get_slice",
    "property_get_unit_file_preset",
    "send_changed_signal",
    "send_new_signal",
    "send_removed_signal",
];

fn opaque_is_null<T>(ptr: *const T) -> bool {
    ptr.is_null()
}
fn opaque_is_mut_null<T>(ptr: *mut T) -> bool {
    ptr.is_null()
}

pub fn bus_unit_method_start_generic(
    message: *mut c_void,
    u: *mut c_void,
    job_type: i32,
    reload_if_possible: bool,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, u, job_type, reload_if_possible, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_start(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_stop(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_reload(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_restart(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_try_restart(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_reload_or_restart(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_reload_or_try_restart(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_enqueue_job(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_kill(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_kill_subgroup(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_reset_failed(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_set_properties(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_ref(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_unref(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_clean(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_freezer_generic(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
    action: i32,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error, action);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_thaw(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_freeze(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn property_get_refs(
    bus: *mut c_void,
    path: *const c_char,
    interface: *const c_char,
    property: *const c_char,
    reply: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (
        bus,
        path,
        interface,
        property,
        reply,
        userdata,
        reterr_error,
    );
    Ok(0)
}
pub fn property_get_slice(
    bus: *mut c_void,
    path: *const c_char,
    interface: *const c_char,
    property: *const c_char,
    reply: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (
        bus,
        path,
        interface,
        property,
        reply,
        userdata,
        reterr_error,
    );
    Ok(0)
}
pub fn property_get_available_memory(
    bus: *mut c_void,
    path: *const c_char,
    interface: *const c_char,
    property: *const c_char,
    reply: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (
        bus,
        path,
        interface,
        property,
        reply,
        userdata,
        reterr_error,
    );
    Ok(0)
}
pub fn property_get_memory_accounting(
    bus: *mut c_void,
    path: *const c_char,
    interface: *const c_char,
    property: *const c_char,
    reply: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (
        bus,
        path,
        interface,
        property,
        reply,
        userdata,
        reterr_error,
    );
    Ok(0)
}
pub fn property_get_current_tasks(
    bus: *mut c_void,
    path: *const c_char,
    interface: *const c_char,
    property: *const c_char,
    reply: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (
        bus,
        path,
        interface,
        property,
        reply,
        userdata,
        reterr_error,
    );
    Ok(0)
}
pub fn property_get_cpu_usage(
    bus: *mut c_void,
    path: *const c_char,
    interface: *const c_char,
    property: *const c_char,
    reply: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (
        bus,
        path,
        interface,
        property,
        reply,
        userdata,
        reterr_error,
    );
    Ok(0)
}
pub fn property_get_cpuset_cpus(
    bus: *mut c_void,
    path: *const c_char,
    interface: *const c_char,
    property: *const c_char,
    reply: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (
        bus,
        path,
        interface,
        property,
        reply,
        userdata,
        reterr_error,
    );
    Ok(0)
}
pub fn property_get_cpuset_mems(
    bus: *mut c_void,
    path: *const c_char,
    interface: *const c_char,
    property: *const c_char,
    reply: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (
        bus,
        path,
        interface,
        property,
        reply,
        userdata,
        reterr_error,
    );
    Ok(0)
}
pub fn property_get_cgroup(
    bus: *mut c_void,
    path: *const c_char,
    interface: *const c_char,
    property: *const c_char,
    reply: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (
        bus,
        path,
        interface,
        property,
        reply,
        userdata,
        reterr_error,
    );
    Ok(0)
}
pub fn property_get_cgroup_id(
    bus: *mut c_void,
    path: *const c_char,
    interface: *const c_char,
    property: *const c_char,
    reply: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (
        bus,
        path,
        interface,
        property,
        reply,
        userdata,
        reterr_error,
    );
    Ok(0)
}
pub fn property_get_oom_kills(
    bus: *mut c_void,
    path: *const c_char,
    interface: *const c_char,
    property: *const c_char,
    reply: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (
        bus,
        path,
        interface,
        property,
        reply,
        userdata,
        reterr_error,
    );
    Ok(0)
}
pub fn property_get_managed_oom_kills(
    bus: *mut c_void,
    path: *const c_char,
    interface: *const c_char,
    property: *const c_char,
    reply: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (
        bus,
        path,
        interface,
        property,
        reply,
        userdata,
        reterr_error,
    );
    Ok(0)
}
pub fn append_process(
    reply: *mut c_void,
    p: *const c_char,
    pid: *mut c_void,
    pids: *mut c_void,
) -> Result<i32> {
    let _ = (reply, p, pid, pids);
    Ok(0)
}
pub fn append_cgroup(reply: *mut c_void, p: *const c_char, pids: *mut c_void) -> Result<i32> {
    let _ = (reply, p, pids);
    Ok(0)
}
pub fn bus_unit_method_get_processes(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn property_get_ip_counter(
    bus: *mut c_void,
    path: *const c_char,
    interface: *const c_char,
    property: *const c_char,
    reply: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (
        bus,
        path,
        interface,
        property,
        reply,
        userdata,
        reterr_error,
    );
    Ok(0)
}
pub fn property_get_io_counter(
    bus: *mut c_void,
    path: *const c_char,
    interface: *const c_char,
    property: *const c_char,
    reply: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (
        bus,
        path,
        interface,
        property,
        reply,
        userdata,
        reterr_error,
    );
    Ok(0)
}
pub fn property_get_effective_limit(
    bus: *mut c_void,
    path: *const c_char,
    interface: *const c_char,
    property: *const c_char,
    reply: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (
        bus,
        path,
        interface,
        property,
        reply,
        userdata,
        reterr_error,
    );
    Ok(0)
}
pub fn bus_unit_method_attach_processes(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_method_remove_subgroup(
    message: *mut c_void,
    userdata: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, userdata, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn send_new_signal(bus: *mut c_void, userdata: *mut c_void) -> Result<i32> {
    let _ = (bus, userdata);
    Ok(0)
}
pub fn send_changed_signal(bus: *mut c_void, userdata: *mut c_void) -> Result<i32> {
    let _ = (bus, userdata);
    Ok(0)
}
pub fn bus_unit_send_change_signal(u: *mut c_void) {
    let _ = u;
}
pub fn bus_unit_send_pending_change_signal(u: *mut c_void, including_new: bool) {
    let _ = (u, including_new);
}
pub fn bus_unit_send_pending_freezer_message(u: *mut c_void, canceled: bool) -> Result<i32> {
    let _ = (u, canceled);
    Ok(0)
}
pub fn send_removed_signal(bus: *mut c_void, userdata: *mut c_void) -> Result<i32> {
    let _ = (bus, userdata);
    Ok(0)
}
pub fn bus_unit_send_removed_signal(u: *mut c_void) {
    let _ = u;
}
pub fn bus_unit_queue_job_one(
    message: *mut c_void,
    u: *mut c_void,
    type_: i32,
    mode: i32,
    flags: i32,
    reply: *mut c_void,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, u, type_, mode, flags, reply, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_queue_job(
    message: *mut c_void,
    u: *mut c_void,
    type_: i32,
    mode: i32,
    flags: i32,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (message, u, type_, mode, flags, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_set_live_property(
    u: *mut c_void,
    name: *const c_char,
    message: *mut c_void,
    flags: i32,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (u, name, message, flags, reterr_error);
    Ok(0)
}
pub fn bus_set_transient_emergency_action(
    u: *mut c_void,
    name: *const c_char,
    p: *mut c_void,
    message: *mut c_void,
    flags: i32,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (u, name, p, message, flags, reterr_error);
    Ok(0)
}
pub fn bus_set_transient_exit_status(
    u: *mut c_void,
    name: *const c_char,
    p: *mut c_void,
    message: *mut c_void,
    flags: i32,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (u, name, p, message, flags, reterr_error);
    Ok(0)
}
pub fn bus_set_transient_conditions(
    u: *mut c_void,
    name: *const c_char,
    list: *mut *mut c_void,
    is_condition: bool,
    message: *mut c_void,
    flags: i32,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (u, name, list, is_condition, message, flags, reterr_error);
    Ok(0)
}
pub fn bus_unit_set_transient_property(
    u: *mut c_void,
    name: *const c_char,
    message: *mut c_void,
    flags: i32,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (u, name, message, flags, reterr_error);
    Ok(0)
}
pub fn bus_unit_set_properties(
    u: *mut c_void,
    message: *mut c_void,
    flags: i32,
    commit: bool,
    reterr_error: *mut c_void,
) -> Result<i32> {
    let _ = (u, message, flags, commit, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_validate_load_state(u: *mut c_void, reterr_error: *mut c_void) -> Result<i32> {
    let _ = (u, reterr_error);
    if reterr_error.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn bus_unit_track_handler(t: *mut c_void, userdata: *mut c_void) -> Result<i32> {
    let _ = (t, userdata);
    Ok(0)
}
pub fn bus_unit_allocate_bus_track(u: *mut c_void) -> Result<i32> {
    let _ = u;
    Ok(0)
}
pub fn bus_unit_track_add_name(u: *mut c_void, name: *const c_char) -> Result<i32> {
    let _ = (u, name);
    Ok(0)
}
pub fn bus_unit_track_add_sender(u: *mut c_void, m: *mut c_void) -> Result<i32> {
    let _ = (u, m);
    Ok(0)
}
pub fn bus_unit_track_remove_sender(u: *mut c_void, m: *mut c_void) -> Result<i32> {
    let _ = (u, m);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_unit() -> UnitRecord {
        let mut unit = UnitRecord::new("demo.service");
        unit.aliases
            .extend(["alias-a.service".into(), "alias-b.service".into()]);
        unit.following = Some("other.service".into());
        unit.dependencies.insert(
            "Requires".into(),
            BTreeSet::from(["a.service".into(), "b.service".into()]),
        );
        unit.mounts_for.extend(["/var".into(), "/srv".into()]);
        unit.cleanable
            .extend([ExecDirectoryType::Runtime, ExecDirectoryType::Logs]);
        unit.can_live_mount = true;
        unit.unit_file_preset = "enabled".into();
        unit.job = Some(UnitJob {
            id: 7,
            kind: "start".into(),
            path: "/org/fd/1".into(),
        });
        unit.conditions.push(UnitCondition {
            kind: "ConditionPathExists".into(),
            trigger: false,
            negate: false,
            parameter: "/etc/passwd".into(),
            state: 1,
        });
        unit.load_error = Some((-2, "missing fragment".into()));
        unit.markers
            .extend(["needs-reload".into(), "tainted".into()]);
        unit
    }

    #[test]
    fn clean_entries_include_fdstore_when_requested() {
        let values = property_get_can_clean(&sample_unit(), true).unwrap();
        assert_eq!(values, vec!["runtime", "logs", "fdstore"]);
    }

    #[test]
    fn live_mount_property_is_forwarded() {
        assert!(property_get_can_live_mount(&sample_unit()));
    }

    #[test]
    fn names_include_primary_id_first() {
        let names = property_get_names(&sample_unit()).unwrap();
        assert_eq!(names[0], "demo.service");
        assert!(names.contains(&"alias-a.service".into()));
    }

    #[test]
    fn following_is_optional() {
        assert_eq!(
            property_get_following(&sample_unit()).as_deref(),
            Some("other.service")
        );
        assert_eq!(property_get_following(&UnitRecord::new("x.service")), None);
    }

    #[test]
    fn dependency_lookup_is_property_scoped() {
        assert_eq!(
            property_get_dependencies(&sample_unit(), "Requires").unwrap(),
            vec!["a.service", "b.service"]
        );
        assert!(
            property_get_dependencies(&sample_unit(), "Wants")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn mounts_are_sorted() {
        assert_eq!(
            property_get_mounts_for(&sample_unit()).unwrap(),
            vec!["/srv", "/var"]
        );
    }

    #[test]
    fn job_is_marshaled_as_triplet() {
        assert_eq!(
            property_get_job(&sample_unit()).unwrap(),
            Some((7, "start".into(), "/org/fd/1".into()))
        );
    }

    #[test]
    fn conditions_are_marshaled_in_order() {
        let conditions = property_get_conditions(&sample_unit()).unwrap();
        assert_eq!(conditions[0].0, "ConditionPathExists");
        assert_eq!(conditions[0].3, "/etc/passwd");
    }

    #[test]
    fn load_error_and_markers_roundtrip() {
        assert_eq!(
            property_get_load_error(&sample_unit()).unwrap(),
            Some((-2, "missing fragment".into()))
        );
        assert_eq!(
            property_get_markers(&sample_unit()).unwrap(),
            vec!["needs-reload", "tainted"]
        );
    }
}
