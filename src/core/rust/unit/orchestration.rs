// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/unit.c
//
use super::activation::unit_queue_job_check_and_mangle_type;
use super::dependency::unit_success_failure_handler_has_jobs;
use super::lifecycle::{unit_reload, unit_start, unit_stop};
use super::model::{ActiveState, JobKind, QueueKind, Result, Unit, UnitError};
use super::runtime::{unit_get_nice, unit_set_exec_params};

pub fn unit_validate_on_termination_job_modes(unit: &Unit) -> Result<()> {
    if unit_success_failure_handler_has_jobs(unit) {
        Ok(())
    } else {
        Err(UnitError::Missing)
    }
}
pub fn log_unit_internal(unit: &mut Unit, message: &str) {
    unit.push_status(message);
}
pub fn unit_test_condition(unit: &Unit) -> Result<()> {
    if unit.id.is_some() {
        Ok(())
    } else {
        Err(UnitError::Missing)
    }
}
pub fn unit_test_assert(unit: &Unit) -> Result<()> {
    unit_test_condition(unit)
}
pub fn unit_verify_deps(unit: &Unit) -> Result<()> {
    if unit
        .dependencies
        .values()
        .any(|s| s.contains(unit.id.as_deref().unwrap_or_default()))
    {
        Err(UnitError::Invalid)
    } else {
        Ok(())
    }
}
pub fn raise_level(unit: &mut Unit, new_level: i32) {
    unit_set_exec_params(unit, unit_get_nice(unit), new_level);
}
pub fn unit_log_resources(unit: &mut Unit) {
    unit.push_status(format!("resources:cpu_weight={}", unit.cpu_weight));
}
pub fn unit_update_on_console(unit: &mut Unit, enabled: bool) {
    unit.debug_invocation = enabled;
}
pub fn unit_emit_audit_start(unit: &mut Unit) {
    unit.push_status("audit:start");
}
pub fn unit_emit_audit_stop(unit: &mut Unit) {
    unit.push_status("audit:stop");
}
pub fn unit_process_job(unit: &mut Unit, job: JobKind) -> Result<()> {
    match unit_queue_job_check_and_mangle_type(unit, job)? {
        JobKind::Start => unit_start(unit, 0),
        JobKind::Stop => unit_stop(unit),
        JobKind::Reload => unit_reload(unit),
        JobKind::Restart => {
            unit_stop(unit)?;
            unit_start(unit, 0)
        }
        JobKind::VerifyActive => unit_test_condition(unit),
    }
}
pub fn unit_recursive_add_to_run_queue(unit: &mut Unit) {
    unit.queue(QueueKind::Load);
    unit.queue(QueueKind::TargetDeps);
}
pub fn unit_check_concurrency_limit(unit: &Unit, limit: usize) -> Result<()> {
    if unit.watched_pids.len() > limit {
        Err(UnitError::Busy)
    } else {
        Ok(())
    }
}
