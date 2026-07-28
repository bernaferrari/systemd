// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/unit.c
//
use std::collections::BTreeSet;
use std::fmt;

use super::model::{
    ActiveState, DependencyKind, JobKind, LoadState, ManagerRecord, PidRef, PresetAction,
    QueueKind, Result, Unit, UnitError, UnitFileState, UnitMarker, UnitRef, UnitStatusType,
    UnitType, is_valid_unit_name,
};
use super::relationships::{unit_add_dependency_by_name, unit_add_two_dependencies_by_name};

pub fn unit_new(manager: ManagerRecord, unit_type: UnitType) -> Unit {
    Unit::new(manager, unit_type)
}

pub fn unit_new_for_name(manager: ManagerRecord, unit_type: UnitType, name: &str) -> Result<Unit> {
    let mut unit = unit_new(manager, unit_type);
    unit_add_name(&mut unit, name)?;
    unit_choose_id(&mut unit, name)?;
    Ok(unit)
}

pub fn unit_has_name(unit: &Unit, name: &str) -> bool {
    unit.id.as_deref() == Some(name) || unit.aliases.contains(name)
}

pub fn unit_add_name(unit: &mut Unit, text: &str) -> Result<()> {
    if !is_valid_unit_name(text) {
        return Err(UnitError::Invalid);
    }
    if unit.id.is_none() {
        unit.id = Some(text.to_string());
        unit.manager.known_units.insert(text.to_string());
        return Ok(());
    }
    if !unit.aliases.insert(text.to_string()) {
        return Ok(());
    }
    unit.manager.known_units.insert(text.to_string());
    Ok(())
}

pub fn unit_choose_id(unit: &mut Unit, name: &str) -> Result<()> {
    if !is_valid_unit_name(name) || !unit_has_name(unit, name) {
        return Err(UnitError::Missing);
    }
    unit.id = Some(name.to_string());
    Ok(())
}

pub fn unit_set_description(unit: &mut Unit, description: impl Into<String>) -> Result<()> {
    let description = description.into();
    if description.trim().is_empty() {
        return Err(UnitError::Invalid);
    }
    unit.description = Some(description);
    Ok(())
}

pub fn unit_release_resources(unit: &mut Unit) {
    unit.exec_runtime = None;
    unit.cgroup_runtime = None;
    unit.control_pid = None;
    unit.push_status("release-resources");
}

pub fn unit_may_gc(unit: &Unit) -> bool {
    unit.active_state == ActiveState::Inactive
        && unit.watched_pids.is_empty()
        && unit.queues.is_empty()
}

macro_rules! queue_functions {
    ($($name:ident => $kind:expr),+ $(,)?) => {$(
        pub fn $name(unit: &mut Unit) {
            unit.queue($kind);
        }
    )+};
}

queue_functions!(
    unit_add_to_load_queue => QueueKind::Load,
    unit_add_to_cleanup_queue => QueueKind::Cleanup,
    unit_add_to_gc_queue => QueueKind::Gc,
    unit_add_to_dbus_queue => QueueKind::Dbus,
    unit_submit_to_stop_when_unneeded_queue => QueueKind::StopWhenUnneeded,
    unit_submit_to_start_when_upheld_queue => QueueKind::StartWhenUpheld,
    unit_submit_to_stop_when_bound_queue => QueueKind::StopWhenBound,
    unit_submit_to_release_resources_queue => QueueKind::ReleaseResources,
    unit_add_to_stop_notify_queue => QueueKind::StopNotify,
    unit_add_to_target_deps_queue => QueueKind::TargetDeps,
);

pub fn unit_remove_from_stop_notify_queue(unit: &mut Unit) {
    unit.queues.remove(&QueueKind::StopNotify);
}

pub fn unit_free(_unit: Unit) {}

pub fn unit_active_state(unit: &Unit) -> ActiveState {
    unit.active_state
}

pub fn unit_sub_state_to_string(unit: &Unit) -> &str {
    &unit.sub_state
}

pub fn unit_merge(unit: &mut Unit, other: &Unit) -> Result<()> {
    if unit.unit_type != other.unit_type {
        return Err(UnitError::Invalid);
    }
    unit.aliases.extend(other.aliases.iter().cloned());
    if let Some(id) = &other.id {
        unit.aliases.insert(id.clone());
        unit.merged_into = Some(id.clone());
    }
    for (kind, set) in &other.dependencies {
        unit.dependencies
            .entry(*kind)
            .or_default()
            .extend(set.iter().cloned());
    }
    Ok(())
}

pub fn unit_merge_by_name(unit: &mut Unit, name: &str) -> Result<()> {
    if !unit.manager.known_units.contains(name) {
        return Err(UnitError::Missing);
    }
    unit.merged_into = Some(name.to_string());
    unit.load_state = LoadState::Merged;
    Ok(())
}

pub fn unit_follow_merge(unit: &Unit) -> Option<&str> {
    unit.merged_into.as_deref()
}

pub fn unit_add_exec_dependencies(unit: &mut Unit, target_name: &str) -> Result<()> {
    unit_add_two_dependencies_by_name(
        unit,
        DependencyKind::Requires,
        DependencyKind::After,
        target_name,
        true,
        0,
    )
}

pub fn unit_description(unit: &Unit) -> Option<&str> {
    unit.description.as_deref()
}

pub fn unit_status_string(unit: &Unit) -> String {
    match unit_description(unit) {
        Some(description) => format!("{} ({})", unit.sub_state, description),
        None => unit.sub_state.clone(),
    }
}

pub fn unit_load_fragment_and_dropin(unit: &mut Unit, fragment_required: bool) -> Result<()> {
    if fragment_required && unit.id.is_none() {
        unit.load_state = LoadState::Error;
        return Err(UnitError::Missing);
    }
    unit.load_state = LoadState::Loaded;
    Ok(())
}

pub fn unit_add_default_target_dependency(unit: &mut Unit, target: &str) -> Result<()> {
    if !unit.default_dependencies {
        return Ok(());
    }
    unit_add_dependency_by_name(unit, DependencyKind::After, target, true, 0)
}

pub fn unit_load(unit: &mut Unit) -> Result<()> {
    unit_load_fragment_and_dropin(unit, true)
}

pub fn unit_status_printf(
    unit: &mut Unit,
    status_type: UnitStatusType,
    status: &str,
    detail: impl fmt::Display,
) {
    unit.push_status(format!("{:?}:{}:{}", status_type, status, detail));
}

pub fn unit_test_start_limit(unit: &mut Unit, now_usec: u64) -> Result<()> {
    unit.start_ratelimit.check(now_usec)
}

pub fn unit_start(unit: &mut Unit, now_usec: u64) -> Result<()> {
    unit_test_start_limit(unit, now_usec)?;
    unit.active_state = ActiveState::Active;
    unit.sub_state = "running".into();
    unit.stop_pending = false;
    Ok(())
}

pub fn unit_can_start(unit: &Unit) -> bool {
    !unit.markers.contains(&UnitMarker::RefuseManualStart)
        && !unit.active_state.is_active_or_reloading()
}

pub fn unit_can_isolate(unit: &Unit) -> bool {
    unit.markers.contains(&UnitMarker::AllowIsolate)
}

pub fn unit_stop(unit: &mut Unit) -> Result<()> {
    if !unit_can_stop(unit) {
        return Err(UnitError::Busy);
    }
    unit.active_state = ActiveState::Inactive;
    unit.sub_state = "dead".into();
    unit.stop_pending = false;
    Ok(())
}

pub fn unit_can_stop(unit: &Unit) -> bool {
    !unit.markers.contains(&UnitMarker::RefuseManualStop)
        && unit.active_state != ActiveState::Inactive
}

pub fn unit_reload(unit: &mut Unit) -> Result<()> {
    if !unit_can_reload(unit) {
        return Err(UnitError::Busy);
    }
    unit.active_state = ActiveState::Reloading;
    unit.sub_state = "reloading".into();
    Ok(())
}

pub fn unit_can_reload(unit: &Unit) -> bool {
    unit.active_state.is_active_or_reloading()
}

pub fn unit_is_unneeded(unit: &Unit) -> bool {
    unit.active_state == ActiveState::Inactive && unit.dependencies.values().all(BTreeSet::is_empty)
}

pub fn unit_is_upheld_by_active(unit: &Unit) -> bool {
    unit.active_state.is_active_or_reloading()
        && unit.dependencies.contains_key(&DependencyKind::Upholds)
}

pub fn unit_is_bound_by_inactive(unit: &Unit) -> bool {
    unit.active_state == ActiveState::Inactive
        && unit.dependencies.contains_key(&DependencyKind::BindsTo)
}

pub fn unit_start_on_termination_deps(unit: &mut Unit, dependency: DependencyKind) {
    if dependency == DependencyKind::OnFailure || dependency == DependencyKind::OnSuccess {
        unit.queue(QueueKind::TargetDeps);
    }
}

pub fn unit_trigger_notify(unit: &mut Unit) {
    unit.push_status("notify-trigger");
}

pub fn unit_notify(
    unit: &mut Unit,
    old_state: ActiveState,
    new_state: ActiveState,
    reload_success: bool,
) {
    unit.push_status(format!(
        "notify:{old_state:?}->{new_state:?}:{reload_success}"
    ));
    unit.active_state = new_state;
}

pub fn unit_watch_pidref(unit: &mut Unit, pid: PidRef, exclusive: bool) -> Result<()> {
    if exclusive && !unit.watched_pids.is_empty() {
        return Err(UnitError::Busy);
    }
    unit.watched_pids.insert(pid);
    Ok(())
}

pub fn unit_unwatch_pidref(unit: &mut Unit, pid: PidRef) {
    unit.watched_pids.remove(&pid);
}

pub fn unit_unwatch_all_pids(unit: &mut Unit) {
    unit.watched_pids.clear();
}

pub fn unit_unwatch_pidref_done(unit: &mut Unit, pid: PidRef) {
    unit_unwatch_pidref(unit, pid);
}

pub fn unit_job_is_applicable(unit: &Unit, job: JobKind) -> bool {
    match job {
        JobKind::Start => unit_can_start(unit),
        JobKind::Stop => unit_can_stop(unit),
        JobKind::Reload => unit_can_reload(unit),
        JobKind::Restart => unit_can_stop(unit) || unit_can_start(unit),
        JobKind::VerifyActive => unit.active_state.is_active_or_reloading(),
    }
}

pub fn unit_coldplug(unit: &mut Unit) -> Result<()> {
    unit_load(unit)?;
    unit.queue(QueueKind::Load);
    Ok(())
}

pub fn unit_catchup(unit: &mut Unit) {
    unit.push_status("catchup");
}

pub fn unit_need_daemon_reload(unit: &Unit) -> bool {
    unit.markers.contains(&UnitMarker::NeedsDaemonReload) || unit.load_state == LoadState::Error
}

pub fn unit_reset_failed(unit: &mut Unit) {
    if unit.active_state == ActiveState::Failed {
        unit.active_state = ActiveState::Inactive;
        unit.sub_state = "dead".into();
    }
}

pub fn unit_following(unit: &Unit) -> Option<&str> {
    unit.merged_into.as_deref().or(unit.slice.as_deref())
}

pub fn unit_stop_pending(unit: &Unit) -> bool {
    unit.stop_pending
}

pub fn unit_inactive_or_pending(unit: &Unit) -> bool {
    unit.active_state == ActiveState::Inactive || unit.stop_pending
}

pub fn unit_active_or_pending(unit: &Unit) -> bool {
    unit.active_state == ActiveState::Active || unit.stop_pending
}

pub fn unit_will_restart_default(unit: &Unit) -> bool {
    unit.markers.contains(&UnitMarker::RestartScheduled)
}

pub fn unit_will_restart(unit: &Unit) -> bool {
    unit_will_restart_default(unit)
}

pub fn unit_notify_cgroup_oom(unit: &mut Unit, managed_oom: bool) {
    if managed_oom {
        unit.markers.insert(UnitMarker::OomEvent);
    }
}

pub fn unit_kill(unit: &mut Unit, signo: i32) -> Result<usize> {
    if unit.watched_pids.is_empty() && unit.main_pid.is_none() && unit.control_pid.is_none() {
        return Err(UnitError::Missing);
    }
    let count = unit.watched_pids.len()
        + usize::from(unit.main_pid.is_some())
        + usize::from(unit.control_pid.is_some());
    unit.push_status(format!("kill:{signo}:{count}"));
    unit.stop_pending = true;
    Ok(count)
}

pub fn unit_following_set(unit: &Unit) -> BTreeSet<String> {
    unit_following(unit)
        .into_iter()
        .map(str::to_string)
        .collect()
}

pub fn unit_get_unit_file_state(unit: &Unit) -> UnitFileState {
    unit.unit_file_state
}

pub fn unit_get_unit_file_preset(unit: &Unit) -> PresetAction {
    unit.unit_file_preset
}

pub fn unit_ref_set(reference: &mut Option<UnitRef>, source: &str, target: &str) {
    *reference = Some(UnitRef {
        source: source.into(),
        target: target.into(),
    });
}

pub fn unit_ref_unset(reference: &mut Option<UnitRef>) {
    *reference = None;
}
