// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/unit.c
//
use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::hash::{Hash, Hasher};

use super::lifecycle::{unit_can_isolate, unit_kill, unit_release_resources};
use super::model::{
    ActiveState, CgroupContext, CgroupRuntime, DependencyKind, DependencyMask, ExecContext,
    ExecQuotaStats, ExecRuntime, FreezerState, KillContext, LoadState, PidRef, Result, Unit,
    UnitError, UnitFileState, UnitMarker, UnitMountDependencyType, UnitType, current_unit_path,
    is_canonical_path,
};
use super::relationships::unit_add_dependency_by_name;

pub fn unit_patch_contexts(unit: &mut Unit) {
    if unit.exec_context.is_none() {
        unit.exec_context = Some(ExecContext::default());
    }
    if unit.kill_context.is_none() {
        unit.kill_context = Some(KillContext::default());
    }
    if unit.cgroup_context.is_none() {
        unit.cgroup_context = Some(CgroupContext::default());
    }
}

pub fn unit_get_exec_context(unit: &Unit) -> Option<&ExecContext> {
    unit.exec_context.as_ref()
}
pub fn unit_get_kill_context(unit: &Unit) -> Option<&KillContext> {
    unit.kill_context.as_ref()
}
pub fn unit_get_cgroup_context(unit: &Unit) -> Option<&CgroupContext> {
    unit.cgroup_context.as_ref()
}
pub fn unit_get_exec_runtime(unit: &Unit) -> Option<&ExecRuntime> {
    unit.exec_runtime.as_ref()
}
pub fn unit_get_cgroup_runtime(unit: &Unit) -> Option<&CgroupRuntime> {
    unit.cgroup_runtime.as_ref()
}

pub fn unit_escape_setting(value: &str, shell_escape: bool) -> String {
    if shell_escape {
        value.replace(' ', "\\ ")
    } else {
        value.to_string()
    }
}

pub fn unit_concat_strv(values: &[String], shell_escape: bool) -> String {
    values
        .iter()
        .map(|v| unit_escape_setting(v, shell_escape))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn unit_write_setting(unit: &mut Unit, _flags: u32, name: &str, data: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(UnitError::Invalid);
    }
    unit.push_status(format!("setting:{name}={data}"));
    Ok(())
}

pub fn unit_write_settingf(
    unit: &mut Unit,
    flags: u32,
    name: &str,
    data: impl fmt::Display,
) -> Result<()> {
    unit_write_setting(unit, flags, name, &data.to_string())
}

pub fn unit_make_transient(unit: &mut Unit) {
    unit.transient = true;
    unit.unit_file_state = UnitFileState::Transient;
}

pub fn unit_kill_context(unit: &mut Unit, signal: i32) -> Result<usize> {
    unit_kill(unit, signal)
}

pub fn unit_add_mounts_for(
    unit: &mut Unit,
    path: &str,
    _mask: DependencyMask,
    dep_type: UnitMountDependencyType,
) -> Result<()> {
    if !is_canonical_path(path) {
        return Err(UnitError::Invalid);
    }
    let dep = match dep_type {
        UnitMountDependencyType::Wants => DependencyKind::Wants,
        UnitMountDependencyType::Requires => DependencyKind::Requires,
    };
    unit_add_dependency_by_name(
        unit,
        dep,
        &format!("{}.mount", path.trim_start_matches('/').replace('/', "-")),
        true,
        0,
    )
}

pub fn unit_setup_exec_runtime(unit: &mut Unit) {
    unit.exec_runtime = Some(ExecRuntime {
        prepared: true,
        invocation_path: unit_get_invocation_path(unit).ok(),
    });
}

pub fn unit_setup_cgroup_runtime(unit: &mut Unit) {
    unit.cgroup_runtime = Some(CgroupRuntime { ready: true });
}

pub fn unit_type_supported(_unit_type: UnitType) -> bool {
    true
}

pub fn unit_warn_if_dir_nonempty(unit: &mut Unit, path: &str) {
    unit.push_status(format!("warn-nonempty:{path}"));
}

pub fn unit_log_noncanonical_mount_path(unit: &mut Unit, path: &str) -> Result<()> {
    if is_canonical_path(path) {
        return Ok(());
    }
    unit.push_status(format!("noncanonical-mount:{path}"));
    Err(UnitError::Invalid)
}

pub fn unit_fail_if_noncanonical_mount_path(unit: &mut Unit, path: &str) -> Result<()> {
    unit_log_noncanonical_mount_path(unit, path)
}

pub fn unit_is_pristine(unit: &Unit) -> bool {
    unit.aliases.is_empty()
        && unit.description.is_none()
        && unit.dependencies.is_empty()
        && unit.status_history.is_empty()
        && !unit.transient
}

pub fn unit_control_pid(unit: &Unit) -> Option<PidRef> {
    unit.control_pid
}

pub fn unit_main_pid_full(unit: &Unit) -> (Option<PidRef>, bool) {
    (unit.main_pid, unit.main_pid_alien)
}

pub fn unit_unref_uid_gid(unit: &mut Unit, destroy_now: bool) {
    unit.ref_uid = None;
    unit.ref_gid = None;
    if destroy_now {
        unit_release_resources(unit);
    }
}

pub fn unit_ref_uid_gid(unit: &mut Unit, uid: u32, gid: u32) {
    unit.ref_uid = Some(uid);
    unit.ref_gid = Some(gid);
}

pub fn unit_notify_user_lookup(unit: &mut Unit, uid: u32, gid: u32) {
    unit_ref_uid_gid(unit, uid, gid);
}

pub fn unit_acquire_invocation_id(unit: &mut Unit) -> Result<[u8; 16]> {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    unit.id.hash(&mut hasher);
    current_unit_path().hash(&mut hasher);
    let first = hasher.finish();
    let second = first.rotate_left(13) ^ 0x9e37_79b9_7f4a_7c15;
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&first.to_le_bytes());
    id[8..].copy_from_slice(&second.to_le_bytes());
    unit.invocation_id = Some(id);
    Ok(id)
}

pub fn unit_set_exec_params(unit: &mut Unit, nice: i32, log_level_max: i32) {
    let ctx = unit.exec_context.get_or_insert_with(ExecContext::default);
    ctx.nice = nice;
    ctx.log_level_max = log_level_max;
}

pub fn unit_fork_helper_process_full(
    unit: &mut Unit,
    name: &str,
    into_cgroup: bool,
    flags: u32,
) -> PidRef {
    let pid = unit.new_pid();
    unit.control_pid = Some(pid);
    unit.push_status(format!("helper:{name}:{into_cgroup}:{flags}"));
    pid
}

pub fn unit_fork_helper_process(unit: &mut Unit, name: &str, into_cgroup: bool) -> PidRef {
    unit_fork_helper_process_full(unit, name, into_cgroup, 0)
}

pub fn unit_fork_and_watch_rm_rf(unit: &mut Unit, paths: &[String]) -> PidRef {
    let pid = unit.new_pid();
    unit.watched_pids.insert(pid);
    unit.push_status(format!("rm-rf:{}", paths.join(",")));
    pid
}

pub fn unit_remove_dependencies(unit: &mut Unit, _mask: DependencyMask) {
    unit.dependencies.clear();
}

pub fn unit_export_state_files(unit: &mut Unit) {
    if let Some(id) = &unit.id {
        unit.state_files.insert(format!("{id}.state"));
    }
}

pub fn unit_unlink_state_files(unit: &mut Unit) {
    unit.state_files.clear();
}

pub fn unit_set_debug_invocation(unit: &mut Unit, enable: bool) {
    unit.debug_invocation = enable;
}

pub fn unit_prepare_exec(unit: &mut Unit) {
    unit_setup_exec_runtime(unit);
    unit_setup_cgroup_runtime(unit);
}

pub fn unit_warn_leftover_processes(unit: &mut Unit, start: bool) -> Result<()> {
    if unit.watched_pids.is_empty() {
        return Ok(());
    }
    unit.push_status(format!("leftover:{start}:{}", unit.watched_pids.len()));
    Err(UnitError::Busy)
}

pub fn unit_needs_console(unit: &Unit) -> bool {
    unit.debug_invocation
}

pub fn unit_pid_attachable(unit: &Unit, pid: PidRef) -> Result<()> {
    if unit.watched_pids.contains(&pid) {
        Err(UnitError::Exists)
    } else {
        Ok(())
    }
}

pub fn unit_get_log_level_max(unit: &Unit) -> i32 {
    unit.exec_context
        .as_ref()
        .map(|ctx| ctx.log_level_max)
        .unwrap_or_default()
}

pub fn unit_log_level_test(unit: &Unit, level: i32) -> bool {
    level <= unit_get_log_level_max(unit)
}

pub fn unit_log_success(unit: &mut Unit) {
    unit.push_status("result:success");
}
pub fn unit_log_failure(unit: &mut Unit, result: &str) {
    unit.push_status(format!("result:failure:{result}"));
}
pub fn unit_log_skip(unit: &mut Unit, result: &str) {
    unit.push_status(format!("result:skip:{result}"));
}

pub fn unit_log_process_exit(
    unit: &mut Unit,
    kind: &str,
    command: &str,
    success: bool,
    code: i32,
    status: i32,
) {
    unit.push_status(format!(
        "process-exit:{kind}:{command}:{success}:{code}:{status}"
    ));
}

pub fn unit_exit_status(unit: &Unit) -> i32 {
    unit.exit_status
}
pub fn unit_failure_action_exit_status(unit: &Unit) -> i32 {
    unit.failure_action_exit_status
}
pub fn unit_success_action_exit_status(unit: &Unit) -> i32 {
    unit.success_action_exit_status
}
pub fn unit_test_trigger_loaded(unit: &Unit) -> Result<()> {
    if unit.load_state == LoadState::Loaded {
        Ok(())
    } else {
        Err(UnitError::Missing)
    }
}

pub fn unit_destroy_runtime_data(unit: &mut Unit, destroy_runtime_dir: bool) {
    unit.exec_runtime = None;
    if destroy_runtime_dir {
        unit.state_files.clear();
    }
}

pub fn unit_clean(unit: &mut Unit) {
    unit_destroy_runtime_data(unit, true);
    unit_release_resources(unit);
}

pub fn unit_can_clean(unit: &Unit) -> bool {
    !unit_is_pristine(unit)
}
pub fn unit_can_start_refuse_manual(unit: &Unit) -> bool {
    unit.markers.contains(&UnitMarker::RefuseManualStart)
}
pub fn unit_can_stop_refuse_manual(unit: &Unit) -> bool {
    unit.markers.contains(&UnitMarker::RefuseManualStop)
}
pub fn unit_can_isolate_refuse_manual(unit: &Unit) -> bool {
    !unit_can_isolate(unit)
}

pub fn unit_next_freezer_state(unit: &Unit, freeze: bool) -> FreezerState {
    match (unit.freezer_state, freeze) {
        (FreezerState::Running, true) => FreezerState::Freezing,
        (FreezerState::Frozen, false) => FreezerState::Thawing,
        (state, _) => state,
    }
}

pub fn unit_can_freeze(unit: &Unit) -> bool {
    matches!(unit.active_state, ActiveState::Active | ActiveState::Frozen)
}
pub fn unit_set_freezer_state(unit: &mut Unit, state: FreezerState) {
    unit.freezer_state = state;
}
pub fn unit_freezer_complete(unit: &mut Unit, frozen: bool) {
    unit.freezer_state = if frozen {
        FreezerState::Frozen
    } else {
        FreezerState::Running
    };
}
pub fn unit_freezer_action(unit: &mut Unit, freeze: bool) {
    unit_set_freezer_state(unit, unit_next_freezer_state(unit, freeze));
}
pub fn unit_find_failed_condition(unit: &Unit) -> Option<&str> {
    if unit.active_state == ActiveState::Failed {
        Some("failed")
    } else {
        None
    }
}
pub fn unit_can_live_mount(unit: &Unit) -> bool {
    unit.unit_type == UnitType::Mount && unit.active_state == ActiveState::Active
}
pub fn unit_live_mount(unit: &mut Unit, path: &str) -> Result<()> {
    unit_add_mounts_for(unit, path, 0, UnitMountDependencyType::Requires)
}
pub fn unit_has_dependency(unit: &Unit, dep: DependencyKind, other: &str) -> bool {
    unit.dependencies
        .get(&dep)
        .is_some_and(|set| set.contains(other))
}
pub fn unit_get_dependency_array(unit: &Unit, dep: DependencyKind) -> Vec<String> {
    unit.dependencies
        .get(&dep)
        .map(|set| set.iter().cloned().collect())
        .unwrap_or_default()
}
pub fn unit_get_transitive_dependency_set(unit: &Unit) -> BTreeSet<String> {
    unit.dependencies
        .values()
        .flat_map(|set| set.iter().cloned())
        .collect()
}
pub fn unit_arm_timer(unit: &mut Unit, label: &str, usec: u64) {
    unit.push_status(format!("timer:{label}:{usec}"));
}
pub fn unit_passes_filter<F: Fn(&Unit) -> bool>(unit: &Unit, filter: F) -> bool {
    filter(unit)
}
pub fn unit_get_exec_quota_stats(unit: &Unit) -> ExecQuotaStats {
    ExecQuotaStats {
        nice: unit_get_nice(unit),
        cpu_weight: unit_get_cpu_weight(unit),
    }
}
pub fn unit_get_invocation_path(unit: &Unit) -> Result<String> {
    Ok(format!(
        "/run/systemd/invocation/{}",
        unit.id.as_deref().ok_or(UnitError::Missing)?
    ))
}
pub fn unit_get_nice(unit: &Unit) -> i32 {
    unit.exec_context
        .as_ref()
        .map(|ctx| ctx.nice)
        .unwrap_or_default()
}
pub fn unit_get_cpu_weight(unit: &Unit) -> u64 {
    unit.cpu_weight
}
pub fn unit_compare_priority(a: &Unit, b: &Unit) -> std::cmp::Ordering {
    b.unit_type
        .cmp(&a.unit_type)
        .then_with(|| unit_get_cpu_weight(b).cmp(&unit_get_cpu_weight(a)))
        .then_with(|| unit_get_nice(a).cmp(&unit_get_nice(b)))
        .then_with(|| a.id.cmp(&b.id))
}
pub fn unit_log_field(unit: &Unit) -> String {
    format!("UNIT={}", unit.id.clone().unwrap_or_default())
}
pub fn unit_invocation_log_field(unit: &Unit) -> Option<String> {
    unit.invocation_id
        .map(|id| format!("INVOCATION_ID={:02x?}", id))
}
