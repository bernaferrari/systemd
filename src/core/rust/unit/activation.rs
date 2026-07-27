// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/unit.c
//
use std::collections::BTreeSet;
use std::fmt::Write as _;

use super::lifecycle::{unit_can_start, unit_job_is_applicable};
use super::model::{
    ActivationDetails, CollectMode, DependencyKind, JobKind, OomPolicy, Result, Unit, UnitError,
    UnitMarker, UnitMountDependencyType,
};

pub fn activation_details_new() -> ActivationDetails {
    ActivationDetails::default()
}

pub fn activation_details_serialize(details: &ActivationDetails) -> String {
    let mut out = String::new();
    for (key, value) in &details.env {
        let _ = writeln!(&mut out, "env:{key}={value}");
    }
    for (key, value) in &details.pairs {
        let _ = writeln!(&mut out, "pair:{key}={value}");
    }
    out
}

pub fn activation_details_deserialize(text: &str) -> ActivationDetails {
    let mut details = ActivationDetails::default();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("env:") {
            if let Some((k, v)) = rest.split_once('=') {
                details.env.insert(k.into(), v.into());
            }
        } else if let Some(rest) = line.strip_prefix("pair:") {
            if let Some((k, v)) = rest.split_once('=') {
                details.pairs.push((k.into(), v.into()));
            }
        }
    }
    details
}

pub fn activation_details_append_env(details: &mut ActivationDetails, key: &str, value: &str) {
    details.env.insert(key.into(), value.into());
}

pub fn activation_details_append_pair(details: &mut ActivationDetails, key: &str, value: &str) {
    details.pairs.push((key.into(), value.into()));
}

pub fn activation_details_ref(details: &ActivationDetails) -> ActivationDetails {
    details.clone()
}
pub fn activation_details_unref(_details: ActivationDetails) {}
pub fn activation_details_free(details: ActivationDetails) -> ActivationDetails {
    details
}

pub fn collect_mode_to_string(mode: CollectMode) -> &'static str {
    match mode {
        CollectMode::Inactive => "inactive",
        CollectMode::InactiveOrFailed => "inactive-or-failed",
    }
}

pub fn collect_mode_from_string(name: &str) -> Result<CollectMode> {
    match name {
        "inactive" => Ok(CollectMode::Inactive),
        "inactive-or-failed" => Ok(CollectMode::InactiveOrFailed),
        _ => Err(UnitError::Invalid),
    }
}

pub fn unit_mount_dependency_type_to_string(dep: UnitMountDependencyType) -> &'static str {
    match dep {
        UnitMountDependencyType::Wants => "WantsMountsFor",
        UnitMountDependencyType::Requires => "RequiresMountsFor",
    }
}

pub fn unit_mount_dependency_type_from_string(name: &str) -> Result<UnitMountDependencyType> {
    match name {
        "WantsMountsFor" => Ok(UnitMountDependencyType::Wants),
        "RequiresMountsFor" => Ok(UnitMountDependencyType::Requires),
        _ => Err(UnitError::Invalid),
    }
}

pub fn oom_policy_to_string(policy: OomPolicy) -> &'static str {
    match policy {
        OomPolicy::Continue => "continue",
        OomPolicy::Stop => "stop",
        OomPolicy::Kill => "kill",
    }
}

pub fn oom_policy_from_string(name: &str) -> Result<OomPolicy> {
    match name {
        "continue" => Ok(OomPolicy::Continue),
        "stop" => Ok(OomPolicy::Stop),
        "kill" => Ok(OomPolicy::Kill),
        _ => Err(UnitError::Invalid),
    }
}

pub fn unit_mount_dependency_type_to_dependency_type(
    dep: UnitMountDependencyType,
) -> DependencyKind {
    match dep {
        UnitMountDependencyType::Wants => DependencyKind::Wants,
        UnitMountDependencyType::Requires => DependencyKind::Requires,
    }
}

pub fn unit_queue_job_check_and_mangle_type(unit: &Unit, job: JobKind) -> Result<JobKind> {
    if unit_job_is_applicable(unit, job) {
        Ok(job)
    } else if matches!(job, JobKind::Reload) && unit_can_start(unit) {
        Ok(JobKind::Start)
    } else {
        Err(UnitError::Busy)
    }
}

pub fn parse_unit_marker(name: &str) -> Result<UnitMarker> {
    match name {
        "needs-daemon-reload" => Ok(UnitMarker::NeedsDaemonReload),
        "refuse-manual-start" => Ok(UnitMarker::RefuseManualStart),
        "refuse-manual-stop" => Ok(UnitMarker::RefuseManualStop),
        "allow-isolate" => Ok(UnitMarker::AllowIsolate),
        "restart-scheduled" => Ok(UnitMarker::RestartScheduled),
        "oom-event" => Ok(UnitMarker::OomEvent),
        _ => Err(UnitError::Invalid),
    }
}

pub fn unit_normalize_markers(markers: &[&str]) -> Result<BTreeSet<UnitMarker>> {
    markers
        .iter()
        .map(|marker| parse_unit_marker(marker))
        .collect()
}
