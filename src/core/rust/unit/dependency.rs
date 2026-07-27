// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/unit.c
//
use std::collections::BTreeSet;

use super::lifecycle::{
    unit_add_name, unit_is_bound_by_inactive, unit_is_unneeded, unit_is_upheld_by_active,
};
use super::model::{
    ActiveState, DependencyKind, QueueKind, Result, Unit, UnitError, UnitMarker,
    UnitMountDependencyType,
};
use super::relationships::{unit_add_dependency, unit_add_dependency_by_name};
use super::runtime::{unit_add_mounts_for, unit_patch_contexts};

pub fn unit_init(unit: &mut Unit) {
    unit_patch_contexts(unit);
}
pub fn unit_add_alias(unit: &mut Unit, alias: &str) -> Result<()> {
    unit_add_name(unit, alias)
}
pub fn unit_success_failure_handler_has_jobs(unit: &Unit) -> bool {
    unit.dependencies.contains_key(&DependencyKind::OnFailure)
        || unit.dependencies.contains_key(&DependencyKind::OnSuccess)
}
pub fn unit_can_release_resources(unit: &Unit) -> bool {
    unit.exec_runtime.is_some() || unit.cgroup_runtime.is_some()
}
pub fn unit_clear_dependencies(unit: &mut Unit) {
    unit.dependencies.clear();
}
pub fn unit_remove_transient(unit: &mut Unit) {
    unit.transient = false;
}
pub fn unit_free_mounts_for(unit: &mut Unit) {
    unit.dependencies.remove(&DependencyKind::Wants);
    unit.dependencies.remove(&DependencyKind::Requires);
}
pub fn unit_done(unit: &mut Unit) {
    unit.active_state = ActiveState::Inactive;
    unit.sub_state = "dead".into();
}
pub fn unit_merge_names(unit: &mut Unit, other: &Unit) {
    unit.aliases.extend(other.aliases.iter().cloned());
}
pub fn unit_reserve_dependencies(unit: &mut Unit) {
    unit.dependencies.entry(DependencyKind::After).or_default();
}
pub fn unit_should_warn_about_dependency(_unit: &Unit, dependency: DependencyKind) -> bool {
    matches!(
        dependency,
        DependencyKind::Requires | DependencyKind::Requisite
    )
}
pub fn unit_per_dependency_type_hashmap_update(
    unit: &mut Unit,
    dependency: DependencyKind,
    other: &str,
) {
    let _ = unit_add_dependency(unit, dependency, other, true, 0);
}
pub fn unit_merge_dependencies(unit: &mut Unit, other: &Unit) {
    for (kind, set) in &other.dependencies {
        unit.dependencies
            .entry(*kind)
            .or_default()
            .extend(set.iter().cloned());
    }
}
pub fn unit_add_slice_dependencies(unit: &mut Unit) {
    if let Some(slice) = unit.slice.clone() {
        let _ = unit_add_dependency_by_name(unit, DependencyKind::After, &slice, true, 0);
    }
}
pub fn unit_add_mount_dependencies(unit: &mut Unit, paths: &[&str]) {
    for path in paths {
        let _ = unit_add_mounts_for(unit, path, 0, UnitMountDependencyType::Requires);
    }
}
pub fn unit_add_oomd_dependencies(unit: &mut Unit) {
    if unit.markers.contains(&UnitMarker::OomEvent) {
        let _ = unit_add_dependency_by_name(
            unit,
            DependencyKind::After,
            "systemd-oomd.service",
            true,
            0,
        );
    }
}
pub fn unit_add_startup_units(unit: &mut Unit, units: &[&str]) {
    for other in units {
        let _ = unit_add_dependency_by_name(unit, DependencyKind::Wants, other, true, 0);
    }
}
pub fn check_unneeded_dependencies(unit: &Unit) -> bool {
    unit_is_unneeded(unit)
}
pub fn check_uphold_dependencies(unit: &Unit) -> bool {
    unit_is_upheld_by_active(unit)
}
pub fn check_bound_by_dependencies(unit: &Unit) -> bool {
    unit_is_bound_by_inactive(unit)
}
pub fn retroactively_start_dependencies(unit: &mut Unit) {
    if unit.active_state == ActiveState::Active {
        unit.queue(QueueKind::TargetDeps);
    }
}
pub fn retroactively_stop_dependencies(unit: &mut Unit) {
    if unit.active_state == ActiveState::Inactive {
        unit.queue(QueueKind::StopWhenBound);
    }
}
pub fn unit_get_dependency_hashmap_per_type(
    unit: &Unit,
    dependency: DependencyKind,
) -> BTreeSet<String> {
    unit.dependencies
        .get(&dependency)
        .cloned()
        .unwrap_or_default()
}
pub fn unit_add_dependency_impl(
    unit: &mut Unit,
    dependency: DependencyKind,
    other: &str,
) -> Result<()> {
    unit_add_dependency(unit, dependency, other, true, 0)
}
pub fn unit_update_dependency_mask(_unit: &mut Unit, _other: &str, _dependency_index: u64) {}
