// SPDX-License-Identifier: LGPL-2.1-or-later

use std::collections::{BTreeMap, BTreeSet};

use super::Result;
use crate::ffi::Errno;
use crate::job::Job;
use crate::runtime_manager::RuntimeManager;
use crate::transaction::JobMode;
use crate::unit::{
    ActiveState, LoadState, PidRef, Unit, unit_dbus_path, unit_dbus_path_invocation_id,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Virtualization {
    None,
    Vm(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidentialVirtualization {
    None,
    Mode(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ManagerRecord {
    pub log_target: Option<String>,
    pub log_level: Option<String>,
    pub environment: Vec<String>,
    pub subscribed: bool,
    pub show_status: bool,
    pub runtime_watchdog_usec: u64,
    pub pretimeout_watchdog_usec: u64,
    pub pretimeout_watchdog_governor: Option<String>,
    pub reboot_watchdog_usec: u64,
    pub kexec_watchdog_usec: u64,
    pub change_signal_count: u64,
    pub reloading_signal_state: Option<bool>,
    pub finished_signals: Vec<(u64, u64, u64, u64, u64, u64)>,
}

pub fn property_get_virtualization(value: Virtualization) -> Option<&'static str> {
    match value {
        Virtualization::None => None,
        Virtualization::Vm(name) => Some(name),
    }
}

pub fn property_get_confidential_virtualization(
    value: ConfidentialVirtualization,
) -> Option<&'static str> {
    match value {
        ConfidentialVirtualization::None => None,
        ConfidentialVirtualization::Mode(name) => Some(name),
    }
}

pub fn property_get_tainted(flags: &BTreeSet<String>) -> Result<String> {
    Ok(flags.iter().cloned().collect::<Vec<_>>().join(":"))
}

pub fn property_set_log_target(manager: &mut ManagerRecord, value: &str) -> Result<()> {
    manager.log_target = if value.is_empty() {
        None
    } else {
        Some(value.into())
    };
    Ok(())
}

pub fn property_set_log_level(manager: &mut ManagerRecord, value: &str) -> Result<()> {
    manager.log_level = if value.is_empty() {
        None
    } else {
        Some(value.into())
    };
    Ok(())
}

pub fn property_get_environment(manager: &ManagerRecord) -> Result<Vec<String>> {
    Ok(manager.environment.clone())
}

pub fn property_get_show_status(manager: &ManagerRecord) -> bool {
    manager.show_status
}

pub fn property_get_runtime_watchdog(manager: &ManagerRecord) -> u64 {
    manager.runtime_watchdog_usec
}

pub fn property_get_pretimeout_watchdog(manager: &ManagerRecord) -> u64 {
    manager.pretimeout_watchdog_usec
}

pub fn property_get_pretimeout_watchdog_governor(manager: &ManagerRecord) -> Option<String> {
    manager.pretimeout_watchdog_governor.clone()
}

pub fn property_get_reboot_watchdog(manager: &ManagerRecord) -> u64 {
    manager.reboot_watchdog_usec
}

pub fn property_get_kexec_watchdog(manager: &ManagerRecord) -> u64 {
    manager.kexec_watchdog_usec
}

pub fn property_set_watchdog(current: &mut u64, value: u64) -> Result<()> {
    *current = value;
    Ok(())
}

pub type ManagerUnitTuple = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    u32,
    String,
    String,
);
pub type ManagerJobTuple = (u32, String, String, String, String, String);

fn encode_unit_name(name: &str) -> String {
    name.replace('.', "_2e")
        .replace('-', "_2d")
        .replace('/', "_2f")
        .replace('\\', "_5c")
}

fn unit_object_path(name: &str) -> String {
    format!("/org/freedesktop/systemd1/unit/{}", encode_unit_name(name))
}

fn job_object_path(id: u32) -> String {
    format!("/org/freedesktop/systemd1/job/{id}")
}

fn parse_job_mode(mode: &str) -> Result<JobMode> {
    match mode {
        "replace" => Ok(JobMode::Replace),
        "replace-irreversibly" => Ok(JobMode::ReplaceIrreversibly),
        "fail" => Ok(JobMode::Fail),
        "isolate" => Ok(JobMode::Isolate),
        "ignore-dependencies" => Ok(JobMode::IgnoreDependencies),
        "ignore-requirements" => Ok(JobMode::IgnoreRequirements),
        "triggering" | "trigger" => Ok(JobMode::Triggering),
        "restart-dependencies" => Ok(JobMode::RestartDependencies),
        _ => Err(Errno::EINVAL),
    }
}

fn active_state_to_str(state: ActiveState) -> &'static str {
    match state {
        ActiveState::Inactive => "inactive",
        ActiveState::Activating => "activating",
        ActiveState::Active => "active",
        ActiveState::Refreshing => "refreshing",
        ActiveState::Reloading => "reloading",
        ActiveState::Deactivating => "deactivating",
        ActiveState::Failed => "failed",
        ActiveState::Maintenance => "maintenance",
        ActiveState::Frozen => "frozen",
    }
}

fn load_state_to_str(state: LoadState) -> &'static str {
    match state {
        LoadState::Stub => "stub",
        LoadState::Loaded => "loaded",
        LoadState::Error => "error",
        LoadState::Merged => "merged",
    }
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let mut dp = vec![vec![false; t.len() + 1]; p.len() + 1];
    dp[0][0] = true;

    for i in 1..=p.len() {
        if p[i - 1] == b'*' {
            dp[i][0] = dp[i - 1][0];
        }
    }
    for i in 1..=p.len() {
        for j in 1..=t.len() {
            dp[i][j] = match p[i - 1] {
                b'*' => dp[i - 1][j] || dp[i][j - 1],
                b'?' => dp[i - 1][j - 1],
                c => dp[i - 1][j - 1] && c == t[j - 1],
            };
        }
    }

    dp[p.len()][t.len()]
}

fn unit_matches_patterns(unit_name: &str, patterns: &[String]) -> bool {
    patterns.is_empty()
        || patterns
            .iter()
            .any(|pattern| wildcard_match(pattern, unit_name))
}

fn unit_matches_states(unit: &ManagerUnitTuple, states: &[String]) -> bool {
    states.is_empty()
        || states
            .iter()
            .any(|state| state == &unit.2 || state == &unit.3 || state == &unit.4)
}

fn installed_job_to_dbus_tuple(runtime: &RuntimeManager, job: &Job) -> ManagerJobTuple {
    let unit_path = runtime
        .get_unit(&job.unit)
        .and_then(|unit| unit_dbus_path(unit).ok())
        .unwrap_or_else(|| unit_object_path(&job.unit));

    (
        job.id,
        job.unit.clone(),
        job.kind.to_string_val().unwrap_or("invalid").to_string(),
        job.state.to_string_val().unwrap_or("invalid").to_string(),
        job_object_path(job.id),
        unit_path,
    )
}

pub fn manager_get_unit_path(runtime: &RuntimeManager, name: &str) -> Result<String> {
    if name.trim().is_empty() {
        return Err(Errno::EINVAL);
    }
    let unit = runtime.get_unit(name).ok_or(Errno::ENOENT)?;
    unit_dbus_path(unit).map_err(|_| Errno::EINVAL)
}

fn unit_matches_pid(unit: &Unit, pid: u32) -> bool {
    unit.main_pid.map(|p| p.0) == Some(pid)
        || unit.control_pid.map(|p| p.0) == Some(pid)
        || unit.watched_pids.contains(&PidRef(pid))
}

pub fn manager_get_unit_path_by_pid(runtime: &RuntimeManager, pid: u32) -> Result<String> {
    let unit = runtime
        .list_units()
        .into_iter()
        .find(|unit| unit_matches_pid(unit, pid))
        .ok_or(Errno::ENOENT)?;
    unit_dbus_path(unit).map_err(|_| Errno::EINVAL)
}

fn parse_invocation_id_hex(input: &str) -> Option<[u8; 16]> {
    let normalized: String = input.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if normalized.len() != 32 {
        return None;
    }

    let mut out = [0u8; 16];
    for (i, chunk) in normalized.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

pub fn manager_get_unit_path_by_invocation_id(
    runtime: &RuntimeManager,
    invocation_id: &str,
) -> Result<String> {
    let parsed = parse_invocation_id_hex(invocation_id).ok_or(Errno::EINVAL)?;
    let unit = runtime
        .list_units()
        .into_iter()
        .find(|unit| unit.invocation_id == Some(parsed))
        .ok_or(Errno::ENOENT)?;
    unit_dbus_path(unit).map_err(|_| Errno::EINVAL)
}

/// Resolve an already-loaded unit by its binary invocation ID and return the
/// invocation-ID-stable object path. This is deliberately distinct from the
/// legacy string helper above: the D-Bus API carries `sd_id128_t` as `ay`, not
/// as a printable string, and C returns a path keyed by that ID rather than
/// the unit's mutable name.
pub fn manager_get_unit_invocation_path_by_id(
    runtime: &RuntimeManager,
    invocation_id: [u8; 16],
) -> Result<String> {
    let unit = runtime
        .list_units()
        .into_iter()
        .find(|unit| unit.invocation_id == Some(invocation_id))
        .ok_or(Errno::ENOENT)?;
    unit_dbus_path_invocation_id(unit).map_err(|_| Errno::EINVAL)
}

/// Resolve an already-loaded unit by PID and return its invocation-ID-stable
/// object path. The caller supplies a kernel-authenticated PID when this is
/// used for the all-zero invocation ID D-Bus convention.
pub fn manager_get_unit_invocation_path_by_pid(
    runtime: &RuntimeManager,
    pid: u32,
) -> Result<String> {
    let unit = runtime
        .list_units()
        .into_iter()
        .find(|unit| unit_matches_pid(unit, pid))
        .ok_or(Errno::ENOENT)?;
    unit_dbus_path_invocation_id(unit).map_err(|_| Errno::EINVAL)
}

pub fn manager_get_unit_path_by_control_group(
    runtime: &RuntimeManager,
    cgroup: &str,
) -> Result<String> {
    if cgroup.trim().is_empty() {
        return Err(Errno::EINVAL);
    }

    let unit = runtime
        .list_units()
        .into_iter()
        .filter(|unit| {
            unit.id
                .as_deref()
                .map(|id| cgroup.contains(id))
                .unwrap_or(false)
        })
        .max_by_key(|unit| unit.id.as_ref().map(|id| id.len()).unwrap_or(0))
        .ok_or(Errno::ENOENT)?;
    unit_dbus_path(unit).map_err(|_| Errno::EINVAL)
}

pub fn manager_list_units(runtime: &RuntimeManager) -> Vec<ManagerUnitTuple> {
    let mut units = runtime.list_units();
    units.sort_by(|a, b| a.id.as_deref().cmp(&b.id.as_deref()));

    units
        .into_iter()
        .map(|unit| {
            let name = unit.id.clone().unwrap_or_default();
            let description = unit.description.clone().unwrap_or_default();
            let path = unit_dbus_path(unit).unwrap_or_else(|_| unit_object_path(&name));

            let (job_id, job_type, job_path) = runtime
                .installed_job_for_unit(&name)
                .map(|job| {
                    (
                        job.id,
                        job.kind.to_string_val().unwrap_or("invalid").to_string(),
                        job_object_path(job.id),
                    )
                })
                .unwrap_or((0, String::new(), "/".to_string()));

            (
                name,
                description,
                load_state_to_str(unit.load_state).to_string(),
                active_state_to_str(unit.active_state).to_string(),
                unit.sub_state.clone(),
                unit.merged_into.clone().unwrap_or_default(),
                path,
                job_id,
                job_type,
                job_path,
            )
        })
        .collect()
}

pub fn manager_get_job_path(runtime: &RuntimeManager, id: u32) -> Result<String> {
    if runtime.installed_job(id).is_none() {
        return Err(Errno::ENOENT);
    }
    Ok(job_object_path(id))
}

pub fn manager_list_jobs(runtime: &RuntimeManager) -> Vec<ManagerJobTuple> {
    runtime
        .installed_jobs()
        .into_iter()
        .map(|job| installed_job_to_dbus_tuple(runtime, job))
        .collect()
}

pub fn manager_subscribe(manager: &mut ManagerRecord) {
    manager.subscribed = true;
}

pub fn manager_unsubscribe(manager: &mut ManagerRecord) {
    manager.subscribed = false;
}

fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn env_assignment_name(entry: &str) -> Option<&str> {
    let (name, _) = entry.split_once('=')?;
    valid_env_name(name).then_some(name)
}

fn env_assignments_are_valid(entries: &[String]) -> bool {
    entries
        .iter()
        .all(|entry| env_assignment_name(entry.as_str()).is_some())
}

fn env_names_or_assignments_are_valid(entries: &[String]) -> bool {
    entries.iter().all(|entry| {
        valid_env_name(entry)
            || entry
                .split_once('=')
                .map(|(name, _)| valid_env_name(name))
                .unwrap_or(false)
    })
}

fn env_key(entry: &str) -> Option<&str> {
    if let Some((name, _)) = entry.split_once('=') {
        valid_env_name(name).then_some(name)
    } else {
        valid_env_name(entry).then_some(entry)
    }
}

fn manager_client_environment_modify(
    manager: &mut ManagerRecord,
    minus: Option<&[String]>,
    plus: Option<&[String]>,
) -> Result<()> {
    if let Some(minus_entries) = minus {
        for entry in minus_entries {
            let key = env_key(entry).ok_or(Errno::EINVAL)?;
            manager.environment.retain(|existing| {
                env_assignment_name(existing)
                    .map(|name| name != key)
                    .unwrap_or(true)
            });
        }
    }

    if let Some(plus_entries) = plus {
        for entry in plus_entries {
            let key = env_assignment_name(entry).ok_or(Errno::EINVAL)?;
            manager.environment.retain(|existing| {
                env_assignment_name(existing)
                    .map(|name| name != key)
                    .unwrap_or(true)
            });
            manager.environment.push(entry.clone());
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagerRequest {
    GetUnit {
        name: String,
    },
    GetUnitByPid {
        pid: u32,
    },
    GetUnitByInvocationId {
        invocation_id: String,
    },
    GetUnitByControlGroup {
        cgroup: String,
    },
    GetUnitByPidFd {
        pidfd: i32,
    },
    LoadUnit {
        name: String,
    },
    ListUnits,
    ListUnitsByNames {
        names: Vec<String>,
    },
    ListUnitsFiltered {
        states: Vec<String>,
        patterns: Vec<String>,
    },
    ListUnitsByPatterns {
        patterns: Vec<String>,
    },
    GetJob {
        id: u32,
    },
    ListJobs,
    StartUnit {
        name: String,
        mode: String,
    },
    StopUnit {
        name: String,
        mode: String,
    },
    ReloadUnit {
        name: String,
        mode: String,
    },
    RestartUnit {
        name: String,
        mode: String,
    },
    TryRestartUnit {
        name: String,
        mode: String,
    },
    ReloadOrRestartUnit {
        name: String,
        mode: String,
    },
    ReloadOrTryRestartUnit {
        name: String,
        mode: String,
    },
    Reload,
    Reexecute,
    Exit,
    Reboot,
    SoftReboot {
        root: Option<String>,
    },
    Poweroff,
    Halt,
    Kexec,
    SwitchRoot {
        root: String,
        init: String,
    },
    SetEnvironment {
        plus: Vec<String>,
    },
    UnsetEnvironment {
        minus: Vec<String>,
    },
    UnsetAndSetEnvironment {
        minus: Vec<String>,
        plus: Vec<String>,
    },
    SetExitCode {
        code: u8,
    },
    Subscribe,
    Unsubscribe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagerReply {
    UnitPath(String),
    Units(Vec<ManagerUnitTuple>),
    JobPath(String),
    Jobs(Vec<ManagerJobTuple>),
    Done,
}

pub fn manager_dispatch(
    runtime: &mut RuntimeManager,
    manager: &mut ManagerRecord,
    request: ManagerRequest,
) -> Result<ManagerReply> {
    match request {
        ManagerRequest::GetUnit { name } => {
            manager_get_unit_path(runtime, &name).map(ManagerReply::UnitPath)
        }
        ManagerRequest::GetUnitByPid { pid } => {
            manager_get_unit_path_by_pid(runtime, pid).map(ManagerReply::UnitPath)
        }
        ManagerRequest::GetUnitByInvocationId { invocation_id } => {
            manager_get_unit_path_by_invocation_id(runtime, &invocation_id)
                .map(ManagerReply::UnitPath)
        }
        ManagerRequest::GetUnitByControlGroup { cgroup } => {
            manager_get_unit_path_by_control_group(runtime, &cgroup).map(ManagerReply::UnitPath)
        }
        ManagerRequest::GetUnitByPidFd { pidfd } => {
            if pidfd <= 0 {
                return Err(Errno::EINVAL);
            }
            // Resolving a pidfd requires querying the kernel for the referenced task.
            // A descriptor number is not a process ID and must never be treated as one.
            Err(Errno::EOPNOTSUPP)
        }
        ManagerRequest::LoadUnit { name } => {
            runtime.load_unit(&name)?;
            manager_get_unit_path(runtime, &name).map(ManagerReply::UnitPath)
        }
        ManagerRequest::ListUnits => Ok(ManagerReply::Units(manager_list_units(runtime))),
        ManagerRequest::ListUnitsByNames { names } => {
            let by_name: BTreeMap<String, ManagerUnitTuple> = manager_list_units(runtime)
                .into_iter()
                .map(|tuple| (tuple.0.clone(), tuple))
                .collect();
            let filtered = names
                .into_iter()
                .filter_map(|name| by_name.get(&name).cloned())
                .collect();
            Ok(ManagerReply::Units(filtered))
        }
        ManagerRequest::ListUnitsFiltered { states, patterns } => {
            let filtered = manager_list_units(runtime)
                .into_iter()
                .filter(|unit| unit_matches_states(unit, &states))
                .filter(|unit| unit_matches_patterns(&unit.0, &patterns))
                .collect();
            Ok(ManagerReply::Units(filtered))
        }
        ManagerRequest::ListUnitsByPatterns { patterns } => {
            let filtered = manager_list_units(runtime)
                .into_iter()
                .filter(|unit| unit_matches_patterns(&unit.0, &patterns))
                .collect();
            Ok(ManagerReply::Units(filtered))
        }
        ManagerRequest::GetJob { id } => {
            manager_get_job_path(runtime, id).map(ManagerReply::JobPath)
        }
        ManagerRequest::ListJobs => Ok(ManagerReply::Jobs(manager_list_jobs(runtime))),
        ManagerRequest::StartUnit { name, mode } => {
            let job_mode = parse_job_mode(&mode)?;
            runtime
                .start_unit_async(&name, job_mode)
                .map(|id| ManagerReply::JobPath(job_object_path(id)))
        }
        ManagerRequest::StopUnit { name, mode } => {
            let job_mode = parse_job_mode(&mode)?;
            runtime
                .stop_unit_async(&name, job_mode)
                .map(|id| ManagerReply::JobPath(job_object_path(id)))
        }
        ManagerRequest::ReloadUnit { name, mode } => {
            let _ = parse_job_mode(&mode)?;
            runtime
                .reload_unit_async(&name)
                .map(|id| ManagerReply::JobPath(job_object_path(id)))
        }
        ManagerRequest::RestartUnit { name, mode } => {
            let job_mode = parse_job_mode(&mode)?;
            runtime
                .restart_unit_async(&name, job_mode)
                .map(|id| ManagerReply::JobPath(job_object_path(id)))
        }
        ManagerRequest::TryRestartUnit { name, mode } => {
            let job_mode = parse_job_mode(&mode)?;
            if runtime
                .get_unit(&name)
                .map(|u| u.active_state.is_active_or_activating())
                .unwrap_or(false)
            {
                runtime
                    .restart_unit_async(&name, job_mode)
                    .map(|id| ManagerReply::JobPath(job_object_path(id)))
            } else {
                Ok(ManagerReply::JobPath("/".to_string()))
            }
        }
        ManagerRequest::ReloadOrRestartUnit { name, mode } => {
            let job_mode = parse_job_mode(&mode)?;
            if runtime
                .get_unit(&name)
                .map(|u| u.active_state.is_active_or_reloading())
                .unwrap_or(false)
            {
                runtime
                    .reload_unit_async(&name)
                    .map(|id| ManagerReply::JobPath(job_object_path(id)))
            } else {
                runtime
                    .restart_unit_async(&name, job_mode)
                    .map(|id| ManagerReply::JobPath(job_object_path(id)))
            }
        }
        ManagerRequest::ReloadOrTryRestartUnit { name, mode } => {
            let job_mode = parse_job_mode(&mode)?;
            let state = runtime.get_unit(&name).map(|unit| unit.active_state);
            if state.is_some_and(ActiveState::is_active_or_reloading) {
                runtime
                    .reload_unit_async(&name)
                    .map(|id| ManagerReply::JobPath(job_object_path(id)))
            } else if state.is_some_and(ActiveState::is_active_or_activating) {
                runtime
                    .restart_unit_async(&name, job_mode)
                    .map(|id| ManagerReply::JobPath(job_object_path(id)))
            } else {
                Ok(ManagerReply::JobPath("/".to_string()))
            }
        }
        ManagerRequest::Reload
        | ManagerRequest::Reexecute
        | ManagerRequest::Exit
        | ManagerRequest::Reboot
        | ManagerRequest::Poweroff
        | ManagerRequest::Halt
        | ManagerRequest::Kexec => Err(Errno::EOPNOTSUPP),
        ManagerRequest::SoftReboot { root } => {
            if let Some(path) = root.as_deref()
                && !path.starts_with('/')
            {
                return Err(Errno::EINVAL);
            }

            Err(Errno::EOPNOTSUPP)
        }
        ManagerRequest::SwitchRoot { root, init } => {
            let root = if root.is_empty() {
                "/sysroot".to_string()
            } else {
                root
            };
            if !root.starts_with('/') || root == "/" {
                return Err(Errno::EINVAL);
            }
            if !init.is_empty() && !init.starts_with('/') {
                return Err(Errno::EINVAL);
            }

            Err(Errno::EOPNOTSUPP)
        }
        ManagerRequest::SetEnvironment { plus } => {
            if !env_assignments_are_valid(&plus) {
                return Err(Errno::EINVAL);
            }
            manager_client_environment_modify(manager, None, Some(&plus))?;
            Ok(ManagerReply::Done)
        }
        ManagerRequest::UnsetEnvironment { minus } => {
            if !env_names_or_assignments_are_valid(&minus) {
                return Err(Errno::EINVAL);
            }
            manager_client_environment_modify(manager, Some(&minus), None)?;
            Ok(ManagerReply::Done)
        }
        ManagerRequest::UnsetAndSetEnvironment { minus, plus } => {
            if !env_names_or_assignments_are_valid(&minus) || !env_assignments_are_valid(&plus) {
                return Err(Errno::EINVAL);
            }
            manager_client_environment_modify(manager, Some(&minus), Some(&plus))?;
            Ok(ManagerReply::Done)
        }
        ManagerRequest::SetExitCode { .. } => Err(Errno::EOPNOTSUPP),
        ManagerRequest::Subscribe => {
            manager_subscribe(manager);
            Ok(ManagerReply::Done)
        }
        ManagerRequest::Unsubscribe => {
            manager_unsubscribe(manager);
            Ok(ManagerReply::Done)
        }
    }
}
