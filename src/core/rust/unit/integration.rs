// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/unit.c
//
use std::collections::BTreeSet;

use super::lifecycle::unit_kill;
use super::model::{PidRef, Result, Unit, UnitError};
use super::runtime::{
    unit_get_log_level_max, unit_invocation_log_field, unit_log_field, unit_ref_uid_gid,
};

pub fn resolve_template(template: &str, instance: &str) -> String {
    template.replace('@', instance)
}
pub fn fragment_mtime_newer(fragment_mtime: u64, source_mtime: u64) -> bool {
    fragment_mtime > source_mtime
}
pub fn signal_name_owner_changed_install_handler(bus_name: &str) -> String {
    format!("handler:{bus_name}")
}
pub fn signal_name_owner_changed(unit: &mut Unit, bus_name: &str) -> bool {
    unit.bus_names.contains(bus_name)
}
pub fn get_name_owner_handler(unit: &Unit, bus_name: &str) -> bool {
    unit.bus_names.contains(bus_name)
}
pub fn user_from_unit_name(name: &str) -> Option<String> {
    name.split('@')
        .nth(1)
        .and_then(|v| v.split('.').next())
        .map(str::to_string)
}
pub fn unit_verify_contexts(unit: &Unit) -> Result<()> {
    if unit.exec_context.is_some() && unit.kill_context.is_some() && unit.cgroup_context.is_some() {
        Ok(())
    } else {
        Err(UnitError::Missing)
    }
}
pub fn unit_get_private_var_tmp(unit: &Unit) -> Result<String> {
    Ok(format!(
        "/var/tmp/private/{}",
        unit.id.as_deref().ok_or(UnitError::Missing)?
    ))
}
pub fn unit_get_private_tmp(unit: &Unit) -> Result<String> {
    Ok(format!(
        "/tmp/private/{}",
        unit.id.as_deref().ok_or(UnitError::Missing)?
    ))
}
pub fn unit_drop_in_dir(unit: &Unit) -> Result<String> {
    Ok(format!(
        "/etc/systemd/system/{}.d",
        unit.id.as_deref().ok_or(UnitError::Missing)?
    ))
}
pub fn ignore_leftover_process(pid: PidRef) -> bool {
    pid.0 == 1
}
pub fn log_kill(unit: &mut Unit, pid: PidRef, signal: i32) {
    unit.push_status(format!("kill-log:{}:{}", pid.0, signal));
}
pub fn operation_to_signal(operation: &str) -> i32 {
    if operation == "reload" {
        1
    } else {
        15
    }
}
pub fn unit_kill_context_one(unit: &mut Unit, pid: PidRef, signal: i32) {
    log_kill(unit, pid, signal);
}
pub fn unit_pid_set(unit: &Unit) -> BTreeSet<PidRef> {
    unit.watched_pids.clone()
}
pub fn kill_common_log(unit: &mut Unit, signal: i32) {
    unit.push_status(format!("kill-common:{signal}"));
}
pub fn kill_or_sigqueue(unit: &mut Unit, signal: i32) -> Result<usize> {
    unit_kill(unit, signal)
}
pub fn unit_kill_one(unit: &mut Unit, pid: PidRef, signal: i32) {
    unit.watched_pids.remove(&pid);
    log_kill(unit, pid, signal);
}
pub fn unit_modify_user_nft_set(unit: &mut Unit, key: &str, enable: bool) {
    unit.push_status(format!("nft:{key}:{enable}"));
}
pub fn unit_unref_uid_internal(unit: &mut Unit) {
    unit.ref_uid = None;
}
pub fn unit_unref_uid(unit: &mut Unit) {
    unit_unref_uid_internal(unit);
}
pub fn unit_unref_gid(unit: &mut Unit) {
    unit.ref_gid = None;
}
pub fn unit_ref_uid_internal(unit: &mut Unit, uid: u32) {
    unit.ref_uid = Some(uid);
}
pub fn unit_ref_uid(unit: &mut Unit, uid: u32) {
    unit_ref_uid_internal(unit, uid);
}
pub fn unit_ref_gid(unit: &mut Unit, gid: u32) {
    unit.ref_gid = Some(gid);
}
pub fn unit_ref_uid_gid_internal(unit: &mut Unit, uid: u32, gid: u32) {
    unit_ref_uid_gid(unit, uid, gid);
}
pub fn unit_export_invocation_id(unit: &Unit) -> Result<String> {
    unit.invocation_id
        .map(|id| format!("{:02x?}", id))
        .ok_or(UnitError::Missing)
}
pub fn unit_export_log_level_max(unit: &Unit, overwrite: bool) -> String {
    format!(
        "LOG_LEVEL_MAX={} overwrite={overwrite}",
        unit_get_log_level_max(unit)
    )
}
pub fn unit_export_log_extra_fields(unit: &Unit) -> Vec<String> {
    vec![unit_log_field(unit)]
        .into_iter()
        .chain(unit_invocation_log_field(unit))
        .collect()
}
pub fn unit_export_log_ratelimit_interval(unit: &Unit) -> u64 {
    unit.start_ratelimit.interval_usec
}
pub fn unit_export_log_ratelimit_burst(unit: &Unit) -> usize {
    unit.start_ratelimit.burst
}
pub fn unit_log_leftover_process_start(unit: &mut Unit, pid: PidRef, signal: i32) {
    unit.push_status(format!("leftover-start:{}:{}", pid.0, signal));
}
pub fn unit_log_leftover_process_stop(unit: &mut Unit, pid: PidRef, signal: i32) {
    unit.push_status(format!("leftover-stop:{}:{}", pid.0, signal));
}
