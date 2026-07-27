// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/manager.c
//

//! Compiled-but-disconnected manager policy model.
//!
//! `ManagerRecord` is a small scalar test model, not the live
//! [`crate::runtime_manager::RuntimeManager`] owner.

use std::cmp::Ordering;
use std::ffi::c_void;

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/core/manager.c";
pub type Result<T> = std::result::Result<T, Errno>;

pub const JOBS_IN_PROGRESS_WAIT_USEC: u64 = 2_000_000;
pub const JOBS_IN_PROGRESS_QUIET_WAIT_USEC: u64 = 25_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShowStatus {
    Auto,
    Temporary,
    Off,
    On,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRecord {
    pub id: u32,
    pub priority: i32,
    pub running: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ManagerRecord {
    pub is_user: bool,
    pub show_status: ShowStatus,
    pub confirm_spawn: bool,
    pub jobs_running: usize,
    pub finished_units: usize,
    pub total_units: usize,
    pub runtime_watchdog_usec: u64,
}

impl Default for ManagerRecord {
    fn default() -> Self {
        Self {
            is_user: false,
            show_status: ShowStatus::Auto,
            confirm_spawn: true,
            jobs_running: 0,
            finished_units: 0,
            total_units: 0,
            runtime_watchdog_usec: 0,
        }
    }
}

pub fn manager_watch_jobs_next_time(manager: &ManagerRecord, now_usec: u64) -> u64 {
    let timeout = if manager.is_user {
        JOBS_IN_PROGRESS_WAIT_USEC * 2 / 3
    } else if manager_get_show_status_on(manager) {
        JOBS_IN_PROGRESS_WAIT_USEC
    } else {
        JOBS_IN_PROGRESS_QUIET_WAIT_USEC
    };
    now_usec + timeout
}

pub fn manager_is_confirm_spawn_disabled(manager: &ManagerRecord, marker_exists: bool) -> bool {
    !manager.confirm_spawn || marker_exists
}

pub fn manager_flip_auto_status(manager: &mut ManagerRecord, enable: bool) {
    match (enable, manager.show_status) {
        (true, ShowStatus::Auto) => manager.show_status = ShowStatus::Temporary,
        (false, ShowStatus::Temporary) => manager.show_status = ShowStatus::Auto,
        _ => {}
    }
}

pub fn compare_job_priority(a: &JobRecord, b: &JobRecord) -> Ordering {
    b.priority.cmp(&a.priority).then_with(|| a.id.cmp(&b.id))
}

pub fn manager_get_progress(manager: &ManagerRecord) -> f64 {
    if manager.total_units == 0 {
        1.0
    } else {
        manager.finished_units as f64 / manager.total_units as f64
    }
}

pub fn manager_default_timeout(scope: i32) -> u64 {
    if scope == 0 {
        90_000_000
    } else {
        120_000_000
    }
}

pub fn manager_get_show_status_on(manager: &ManagerRecord) -> bool {
    matches!(manager.show_status, ShowStatus::On | ShowStatus::Temporary)
}

pub fn manager_set_watchdog(manager: &mut ManagerRecord, value: u64) {
    manager.runtime_watchdog_usec = value;
}

pub fn manager_get_watchdog(manager: &ManagerRecord) -> u64 {
    manager.runtime_watchdog_usec
}

pub const FUNCTION_INVENTORY: &[&str] = &[
    "build_generator_environment",
    "compare_job_priority",
    "disable_printk_ratelimit",
    "generator_path_any",
    "have_ask_password",
    "log_taint_string",
    "manager_add_job",
    "manager_add_job_by_name",
    "manager_add_job_by_name_or_warn",
    "manager_add_job_full",
    "manager_allocate_idle_pipe",
    "manager_catchup",
    "manager_check_ask_password",
    "manager_check_basic_target",
    "manager_check_finished",
    "manager_clear_jobs",
    "manager_clear_jobs_and_units",
    "manager_client_environment_modify",
    "manager_close_ask_password",
    "manager_close_idle_pipe",
    "manager_coldplug",
    "manager_dbus_is_running",
    "manager_default_environment",
    "manager_default_timeout",
    "manager_disable_confirm_spawn",
    "manager_dispatch_ask_password_fd",
    "manager_dispatch_cleanup_queue",
    "manager_dispatch_dbus_queue",
    "manager_dispatch_gc_job_queue",
    "manager_dispatch_gc_unit_queue",
    "manager_dispatch_handoff_timestamp_fd",
    "manager_dispatch_idle_pipe_fd",
    "manager_dispatch_jobs_in_progress",
    "manager_dispatch_load_queue",
    "manager_dispatch_notify_fd",
    "manager_dispatch_pidref_transport_fd",
    "manager_dispatch_release_resources_queue",
    "manager_dispatch_run_queue",
    "manager_dispatch_sigchld",
    "manager_dispatch_signal_fd",
    "manager_dispatch_start_when_upheld_queue",
    "manager_dispatch_stop_notify_queue",
    "manager_dispatch_stop_when_bound_queue",
    "manager_dispatch_stop_when_unneeded_queue",
    "manager_dispatch_target_deps_queue",
    "manager_dispatch_time_change_fd",
    "manager_dispatch_timezone_change",
    "manager_dispatch_user_lookup_fd",
    "manager_distribute_fds",
    "manager_enable_special_signals",
    "manager_enumerate",
    "manager_enumerate_perpetual",
    "manager_execute_generators",
    "manager_find_credentials_dirs",
    "manager_flip_auto_status",
    "manager_free",
    "manager_free_unit_name_maps",
    "manager_get_confirm_spawn",
    "manager_get_effective_environment",
    "manager_get_executor_log_target",
    "manager_get_job",
    "manager_get_job_from_dbus_path",
    "manager_get_progress",
    "manager_get_show_status",
    "manager_get_show_status_on",
    "manager_get_unit",
    "manager_get_units_for_pidref",
    "manager_get_units_needing_mounts_for",
    "manager_get_watchdog",
    "manager_handle_ctrl_alt_del",
    "manager_invoke_notify_message",
    "manager_invoke_sigchld_event",
    "manager_is_confirm_spawn_disabled",
    "manager_journal_is_running",
    "manager_load_startable_unit_or_warn",
    "manager_load_unit",
    "manager_load_unit_from_dbus_path",
    "manager_load_unit_prepare",
    "manager_log_caller",
    "manager_loop",
    "manager_make_runtime_dir",
    "manager_new",
    "manager_notify_finished",
    "manager_override_log_level",
    "manager_override_log_target",
    "manager_override_show_status",
    "manager_override_watchdog",
    "manager_override_watchdog_pretimeout_governor",
    "manager_preset_all",
    "manager_print_jobs_in_progress",
    "manager_process_barrier_fd",
    "manager_propagate_reload",
    "manager_ratelimit_check_and_queue",
    "manager_ratelimit_requeue",
    "manager_read_timezone_stat",
    "manager_ready",
    "manager_recheck_dbus",
    "manager_recheck_journal",
    "manager_ref_console",
    "manager_ref_gid",
    "manager_ref_uid",
    "manager_ref_uid_internal",
    "manager_reload",
    "manager_reloading_start",
    "manager_reloading_stopp",
    "manager_reset_failed",
    "manager_restore_original_log_level",
    "manager_restore_original_log_target",
    "manager_run_environment_generators",
    "manager_run_generators",
    "manager_send_ready_on_basic_target",
    "manager_send_ready_on_idle",
    "manager_send_reloading",
    "manager_send_unit_audit",
    "manager_send_unit_plymouth",
    "manager_send_unit_supervisor",
    "manager_set_first_boot",
    "manager_set_show_status",
    "manager_set_switching_root",
    "manager_set_unit_defaults",
    "manager_set_watchdog",
    "manager_set_watchdog_pretimeout_governor",
    "manager_setup_bus",
    "manager_setup_handoff_timestamp_fd",
    "manager_setup_memory_pressure_event_source",
    "manager_setup_notify",
    "manager_setup_pidref_transport_fd",
    "manager_setup_prefix",
    "manager_setup_run_queue",
    "manager_setup_sigchld_event_source",
    "manager_setup_signals",
    "manager_setup_time_change",
    "manager_setup_timezone_change",
    "manager_setup_user_lookup_fd",
    "manager_should_show_status",
    "manager_start_special",
    "manager_startup",
    "manager_state",
    "manager_status_printf",
    "manager_timestamp_initrd_mangle",
    "manager_transient_environment_add",
    "manager_trigger_run_queue",
    "manager_unit_cache_should_retry_load",
    "manager_unit_inactive_or_pending",
    "manager_unref_console",
    "manager_unref_gid",
    "manager_unref_uid",
    "manager_unref_uid_internal",
    "manager_unwatch_pidref",
    "manager_update_failed_units",
    "manager_vacuum",
    "manager_vacuum_gid_refs",
    "manager_vacuum_uid_refs",
    "manager_vacuum_uid_refs_internal",
    "manager_watch_idle_pipe",
    "manager_watch_jobs_in_progress",
    "manager_watch_jobs_next_time",
    "sanitize_environment",
    "set_show_status_marker",
    "unit_defaults_done",
    "unit_defaults_init",
    "unit_gc_mark_good",
    "unit_gc_sweep",
];

fn opaque_is_null<T>(ptr: *const T) -> bool {
    ptr.is_null()
}
fn opaque_is_mut_null<T>(ptr: *mut T) -> bool {
    ptr.is_null()
}

pub fn manager_watch_jobs_in_progress(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_print_jobs_in_progress(m: *mut c_void) {
    let _ = (m);
}
pub fn have_ask_password() -> Result<i32> {
    Ok(0)
}
pub fn manager_dispatch_ask_password_fd(
    source: *mut c_void,
    fd: i32,
    revents: u32,
    userdata: *mut c_void,
) -> Result<i32> {
    let _ = (source, fd, revents, userdata);
    Ok(0)
}
pub fn manager_close_ask_password(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_check_ask_password(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_watch_idle_pipe(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_close_idle_pipe(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_setup_time_change(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_read_timezone_stat(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_setup_timezone_change(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_enable_special_signals(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_setup_signals(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn sanitize_environment(l: *mut *mut libc::c_char) -> *mut *mut libc::c_char {
    let _ = (l);
    std::ptr::null_mut::<*mut libc::c_char>()
}
pub fn manager_setup_prefix(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_free_unit_name_maps(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_setup_run_queue(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_setup_sigchld_event_source(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_find_credentials_dirs(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_setup_notify(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_setup_user_lookup_fd(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_setup_handoff_timestamp_fd(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_setup_pidref_transport_fd(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_dispatch_cleanup_queue(m: *mut c_void) -> u32 {
    let _ = (m);
    0
}
pub fn manager_dispatch_release_resources_queue(m: *mut c_void) -> u32 {
    let _ = (m);
    0
}
pub fn unit_gc_mark_good(u: *mut c_void, gc_marker: u32) {
    let _ = (u, gc_marker);
}
pub fn unit_gc_sweep(u: *mut c_void, gc_marker: u32) {
    let _ = (u, gc_marker);
}
pub fn manager_dispatch_gc_unit_queue(m: *mut c_void) -> u32 {
    let _ = (m);
    0
}
pub fn manager_dispatch_gc_job_queue(m: *mut c_void) -> u32 {
    let _ = (m);
    0
}
pub fn manager_ratelimit_requeue(s: *mut c_void, usec: u64, userdata: *mut c_void) -> Result<i32> {
    let _ = (s, usec, userdata);
    Ok(0)
}
pub fn manager_ratelimit_check_and_queue(u: *mut c_void) -> Result<i32> {
    let _ = (u);
    Ok(0)
}
pub fn manager_dispatch_stop_when_unneeded_queue(m: *mut c_void) -> u32 {
    let _ = (m);
    0
}
pub fn manager_dispatch_start_when_upheld_queue(m: *mut c_void) -> u32 {
    let _ = (m);
    0
}
pub fn manager_dispatch_stop_when_bound_queue(m: *mut c_void) -> u32 {
    let _ = (m);
    0
}
pub fn manager_dispatch_stop_notify_queue(m: *mut c_void) -> u32 {
    let _ = (m);
    0
}
pub fn manager_clear_jobs_and_units(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_enumerate_perpetual(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_enumerate(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_coldplug(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_catchup(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_distribute_fds(m: *mut c_void, fds: *mut c_void) {
    let _ = (m, fds);
}
pub fn manager_dbus_is_running(m: *mut c_void, deserialized: bool) -> bool {
    let _ = (m, deserialized);
    false
}
pub fn manager_setup_bus(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_preset_all(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_ready(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_make_runtime_dir(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_dispatch_target_deps_queue(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_dispatch_run_queue(source: *mut c_void, userdata: *mut c_void) -> Result<i32> {
    let _ = (source, userdata);
    Ok(0)
}
pub fn manager_dispatch_dbus_queue(m: *mut c_void) -> u32 {
    let _ = (m);
    0
}
pub fn manager_process_barrier_fd(tags: *const *mut libc::c_char, fds: *mut c_void) -> bool {
    let _ = (tags, fds);
    false
}
pub fn manager_invoke_notify_message(
    m: *mut c_void,
    u: *mut c_void,
    pidref: *mut c_void,
    ucred: *const c_void,
    tags: *const *mut libc::c_char,
    fds: *mut c_void,
) {
    let _ = (m, u, pidref, ucred, tags, fds);
}
pub fn manager_get_units_for_pidref(
    m: *mut c_void,
    pidref: *const c_void,
    ret_units: *mut *mut *mut c_void,
) -> Result<i32> {
    let _ = (m, pidref, ret_units);
    if ret_units.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn manager_dispatch_notify_fd(
    source: *mut c_void,
    fd: i32,
    revents: u32,
    userdata: *mut c_void,
) -> Result<i32> {
    let _ = (source, fd, revents, userdata);
    Ok(0)
}
pub fn manager_invoke_sigchld_event(m: *mut c_void, u: *mut c_void, si: *const c_void) {
    let _ = (m, u, si);
}
pub fn manager_dispatch_sigchld(source: *mut c_void, userdata: *mut c_void) -> Result<i32> {
    let _ = (source, userdata);
    Ok(0)
}
pub fn manager_start_special(m: *mut c_void, name: *const libc::c_char, mode: i32) {
    let _ = (m, name, mode);
}
pub fn manager_handle_ctrl_alt_del(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_dispatch_signal_fd(
    source: *mut c_void,
    fd: i32,
    revents: u32,
    userdata: *mut c_void,
) -> Result<i32> {
    let _ = (source, fd, revents, userdata);
    Ok(0)
}
pub fn manager_dispatch_time_change_fd(
    source: *mut c_void,
    fd: i32,
    revents: u32,
    userdata: *mut c_void,
) -> Result<i32> {
    let _ = (source, fd, revents, userdata);
    Ok(0)
}
pub fn manager_dispatch_timezone_change(
    source: *mut c_void,
    e: *const c_void,
    userdata: *mut c_void,
) -> Result<i32> {
    let _ = (source, e, userdata);
    Ok(0)
}
pub fn manager_dispatch_idle_pipe_fd(
    source: *mut c_void,
    fd: i32,
    revents: u32,
    userdata: *mut c_void,
) -> Result<i32> {
    let _ = (source, fd, revents, userdata);
    Ok(0)
}
pub fn manager_dispatch_jobs_in_progress(
    source: *mut c_void,
    usec: u64,
    userdata: *mut c_void,
) -> Result<i32> {
    let _ = (source, usec, userdata);
    Ok(0)
}
pub fn log_taint_string(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_notify_finished(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_send_ready_on_basic_target(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_send_ready_on_idle(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_check_basic_target(m: *mut c_void) {
    let _ = (m);
}
pub fn generator_path_any(paths: *const *mut libc::c_char) -> bool {
    let _ = (paths);
    false
}
pub fn manager_run_environment_generators(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn build_generator_environment(
    m: *mut c_void,
    ret: *mut *mut *mut libc::c_char,
) -> Result<i32> {
    let _ = (m, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn manager_execute_generators(
    m: *mut c_void,
    paths: *const *mut libc::c_char,
    remount_ro: bool,
) -> Result<i32> {
    let _ = (m, paths, remount_ro);
    Ok(0)
}
pub fn manager_run_generators(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_journal_is_running(m: *mut c_void) -> bool {
    let _ = (m);
    false
}
pub fn manager_get_show_status(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn set_show_status_marker(b: bool) {
    let _ = (b);
}
pub fn manager_should_show_status(m: *mut c_void, status_type: i32) -> bool {
    let _ = (m, status_type);
    false
}
pub fn manager_unref_uid_internal(
    uid_refs: *mut c_void,
    uid: u32,
    destroy_now: bool,
    clean_ipc: *const c_void,
) {
    let _ = (uid_refs, uid, destroy_now, clean_ipc);
}
pub fn manager_ref_uid_internal(
    uid_refs: *mut *mut c_void,
    uid: u32,
    clean_ipc: bool,
) -> Result<i32> {
    let _ = (uid_refs, uid, clean_ipc);
    Ok(0)
}
pub fn manager_vacuum_uid_refs_internal(uid_refs: *mut c_void, clean_ipc: *const c_void) {
    let _ = (uid_refs, clean_ipc);
}
pub fn manager_vacuum_uid_refs(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_vacuum_gid_refs(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_vacuum(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_dispatch_user_lookup_fd(
    source: *mut c_void,
    fd: i32,
    revents: u32,
    userdata: *mut c_void,
) -> Result<i32> {
    let _ = (source, fd, revents, userdata);
    Ok(0)
}
pub fn manager_dispatch_handoff_timestamp_fd(
    source: *mut c_void,
    fd: i32,
    revents: u32,
    userdata: *mut c_void,
) -> Result<i32> {
    let _ = (source, fd, revents, userdata);
    Ok(0)
}
pub fn manager_dispatch_pidref_transport_fd(
    source: *mut c_void,
    fd: i32,
    revents: u32,
    userdata: *mut c_void,
) -> Result<i32> {
    let _ = (source, fd, revents, userdata);
    Ok(0)
}
pub fn manager_default_environment(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_setup_memory_pressure_event_source(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_set_switching_root(m: *mut c_void, switching_root: bool) {
    let _ = (m, switching_root);
}
pub fn manager_new(scope: i32, test_run_flags: i32, ret: *mut *mut c_void) -> Result<i32> {
    let _ = (scope, test_run_flags, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn manager_free(m: *mut c_void) -> *mut c_void {
    let _ = (m);
    std::ptr::null_mut::<c_void>()
}
pub fn manager_reloading_start(m: *mut c_void) -> *mut c_void {
    let _ = (m);
    std::ptr::null_mut::<c_void>()
}
pub fn manager_reloading_stopp(m: *mut *mut c_void) {
    let _ = (m);
}
pub fn manager_startup(
    m: *mut c_void,
    serialization: *mut c_void,
    fds: *mut c_void,
    named_listen_fds: *mut c_void,
    root: *const libc::c_char,
) -> Result<i32> {
    let _ = (m, serialization, fds, named_listen_fds, root);
    Ok(0)
}
pub fn manager_add_job_full(
    m: *mut c_void,
    type_: i32,
    unit: *mut c_void,
    mode: i32,
    extra_flags: u32,
    affected_jobs: *mut c_void,
    error: *mut c_void,
    ret: *mut *mut c_void,
) -> Result<i32> {
    let _ = (m, type_, unit, mode, extra_flags, affected_jobs, error, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn manager_add_job(
    m: *mut c_void,
    type_: i32,
    unit: *mut c_void,
    mode: i32,
    error: *mut c_void,
    ret: *mut *mut c_void,
) -> Result<i32> {
    let _ = (m, type_, unit, mode, error, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn manager_add_job_by_name(
    m: *mut c_void,
    type_: i32,
    name: *const libc::c_char,
    mode: i32,
    affected_jobs: *mut c_void,
    error: *mut c_void,
    ret: *mut *mut c_void,
) -> Result<i32> {
    let _ = (m, type_, name, mode, affected_jobs, error, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn manager_add_job_by_name_or_warn(
    m: *mut c_void,
    type_: i32,
    name: *const libc::c_char,
    mode: i32,
    affected_jobs: *mut c_void,
    ret: *mut *mut c_void,
) -> Result<i32> {
    let _ = (m, type_, name, mode, affected_jobs, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn manager_propagate_reload(m: *mut c_void, unit: *mut c_void, active_state: i32) {
    let _ = (m, unit, active_state);
}
pub fn manager_get_job(m: *mut c_void, id: u32) -> *mut c_void {
    let _ = (m, id);
    std::ptr::null_mut::<c_void>()
}
pub fn manager_get_unit(m: *mut c_void, name: *const libc::c_char) -> *mut c_void {
    let _ = (m, name);
    std::ptr::null_mut::<c_void>()
}
pub fn manager_dispatch_load_queue(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_unit_cache_should_retry_load(u: *mut c_void) -> bool {
    let _ = (u);
    false
}
pub fn manager_load_unit_prepare(
    m: *mut c_void,
    name: *const libc::c_char,
    path: *const libc::c_char,
    error: *mut c_void,
    ret: *mut *mut c_void,
) -> Result<i32> {
    let _ = (m, name, path, error, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn manager_load_unit(
    m: *mut c_void,
    name: *const libc::c_char,
    path: *const libc::c_char,
    error: *mut c_void,
    ret: *mut *mut c_void,
) -> Result<i32> {
    let _ = (m, name, path, error, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn manager_load_startable_unit_or_warn(
    m: *mut c_void,
    name: *const libc::c_char,
    path: *const libc::c_char,
    log_level: i32,
    ret: *mut *mut c_void,
) -> Result<i32> {
    let _ = (m, name, path, log_level, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn manager_clear_jobs(m: *mut c_void, mode: i32) {
    let _ = (m, mode);
}
pub fn manager_unwatch_pidref(m: *mut c_void, pidref: *mut c_void) {
    let _ = (m, pidref);
}
pub fn manager_trigger_run_queue(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_loop(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_load_unit_from_dbus_path(
    m: *mut c_void,
    path: *const libc::c_char,
    error: *mut c_void,
    ret: *mut *mut c_void,
) -> Result<i32> {
    let _ = (m, path, error, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn manager_get_job_from_dbus_path(
    m: *mut c_void,
    path: *const libc::c_char,
    ret: *mut *mut c_void,
) -> Result<i32> {
    let _ = (m, path, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn manager_send_unit_audit(m: *mut c_void, u: *mut c_void, job_type: i32, success: bool) {
    let _ = (m, u, job_type, success);
}
pub fn manager_send_unit_plymouth(m: *mut c_void, u: *mut c_void) {
    let _ = (m, u);
}
pub fn manager_send_unit_supervisor(m: *mut c_void, u: *mut c_void, active: bool) {
    let _ = (m, u, active);
}
pub fn manager_override_watchdog(m: *mut c_void, wd: i32, usec: u64) {
    let _ = (m, wd, usec);
}
pub fn manager_set_watchdog_pretimeout_governor(
    m: *mut c_void,
    governor: *const libc::c_char,
) -> Result<i32> {
    let _ = (m, governor);
    Ok(0)
}
pub fn manager_override_watchdog_pretimeout_governor(
    m: *mut c_void,
    governor: *const libc::c_char,
) -> Result<i32> {
    let _ = (m, governor);
    Ok(0)
}
pub fn manager_reload(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_reset_failed(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_unit_inactive_or_pending(m: *mut c_void, u: *mut c_void) -> Result<i32> {
    let _ = (m, u);
    Ok(0)
}
pub fn manager_check_finished(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_send_reloading(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_transient_environment_add(
    m: *mut c_void,
    plus: *mut *mut libc::c_char,
) -> Result<i32> {
    let _ = (m, plus);
    Ok(0)
}
pub fn manager_client_environment_modify(
    m: *mut c_void,
    minus: *mut *mut libc::c_char,
    plus: *mut *mut libc::c_char,
) -> Result<i32> {
    let _ = (m, minus, plus);
    Ok(0)
}
pub fn manager_get_effective_environment(
    m: *mut c_void,
    ret: *mut *mut *mut libc::c_char,
) -> Result<i32> {
    let _ = (m, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn manager_set_unit_defaults(m: *mut c_void, u: *mut c_void, mask: i32) {
    let _ = (m, u, mask);
}
pub fn manager_recheck_dbus(m: *mut c_void) {
    let _ = (m);
}
pub fn disable_printk_ratelimit() {}
pub fn manager_recheck_journal(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_set_show_status(m: *mut c_void, s: i32) {
    let _ = (m, s);
}
pub fn manager_override_show_status(m: *mut c_void, s: i32, source: *const libc::c_char) {
    let _ = (m, s, source);
}
pub fn manager_get_confirm_spawn(m: *mut c_void) -> bool {
    let _ = (m);
    false
}
pub fn manager_set_first_boot(m: *mut c_void, b: bool) {
    let _ = (m, b);
}
pub fn manager_disable_confirm_spawn(m: *mut c_void) {
    let _ = (m);
}
/// Mirrors the fixed C parameters; C varargs require a C-compatible wrapper.
pub fn manager_status_printf(
    m: *mut c_void,
    status_type: i32,
    status: *const libc::c_char,
    format: *const libc::c_char,
) {
    let _ = (m, status_type, status, format);
}
/// Returns the borrowed, nullable `Set *` held by the C manager.
pub fn manager_get_units_needing_mounts_for(
    m: *mut c_void,
    path: *const libc::c_char,
    mount_dependency_type: i32,
) -> *mut c_void {
    let _ = (m, path, mount_dependency_type);
    std::ptr::null_mut()
}
pub fn manager_update_failed_units(m: *mut c_void, u: *mut c_void, state: i32) {
    let _ = (m, u, state);
}
pub fn manager_state(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_unref_uid(m: *mut c_void, uid: u32) {
    let _ = (m, uid);
}
pub fn manager_unref_gid(m: *mut c_void, gid: u32) {
    let _ = (m, gid);
}
pub fn manager_ref_uid(m: *mut c_void, uid: u32, clean_ipc: bool) -> Result<i32> {
    let _ = (m, uid, clean_ipc);
    Ok(0)
}
pub fn manager_ref_gid(m: *mut c_void, gid: u32, clean_ipc: bool) -> Result<i32> {
    let _ = (m, gid, clean_ipc);
    Ok(0)
}
pub fn manager_ref_console(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_unref_console(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_override_log_level(m: *mut c_void, level: i32) {
    let _ = (m, level);
}
pub fn manager_restore_original_log_level(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_override_log_target(m: *mut c_void, target: i32) {
    let _ = (m, target);
}
pub fn manager_restore_original_log_target(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_timestamp_initrd_mangle(m: *mut c_void) {
    let _ = (m);
}
pub fn manager_allocate_idle_pipe(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn unit_defaults_init(d: *mut c_void) {
    let _ = (d);
}
pub fn unit_defaults_done(d: *mut c_void) {
    let _ = (d);
}
pub fn manager_get_executor_log_target(m: *mut c_void) -> Result<i32> {
    let _ = (m);
    Ok(0)
}
pub fn manager_log_caller(m: *mut c_void, caller: *mut c_void, method: *const libc::c_char) {
    let _ = (m, caller, method);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_jobs_uses_shorter_timeout_for_user_manager() {
        let manager = ManagerRecord {
            is_user: true,
            ..Default::default()
        };
        assert_eq!(
            manager_watch_jobs_next_time(&manager, 10),
            10 + JOBS_IN_PROGRESS_WAIT_USEC * 2 / 3
        );
    }

    #[test]
    fn watch_jobs_uses_quiet_timeout_when_status_is_off() {
        let manager = ManagerRecord {
            show_status: ShowStatus::Off,
            ..Default::default()
        };
        assert_eq!(
            manager_watch_jobs_next_time(&manager, 10),
            10 + JOBS_IN_PROGRESS_QUIET_WAIT_USEC
        );
    }

    #[test]
    fn confirm_spawn_can_be_disabled_by_state_or_marker() {
        assert!(manager_is_confirm_spawn_disabled(
            &ManagerRecord {
                confirm_spawn: false,
                ..Default::default()
            },
            false
        ));
        assert!(manager_is_confirm_spawn_disabled(
            &ManagerRecord::default(),
            true
        ));
        assert!(!manager_is_confirm_spawn_disabled(
            &ManagerRecord::default(),
            false
        ));
    }

    #[test]
    fn auto_status_flips_to_temporary_and_back() {
        let mut manager = ManagerRecord::default();
        manager_flip_auto_status(&mut manager, true);
        assert_eq!(manager.show_status, ShowStatus::Temporary);
        manager_flip_auto_status(&mut manager, false);
        assert_eq!(manager.show_status, ShowStatus::Auto);
    }

    #[test]
    fn higher_priority_jobs_sort_first() {
        let a = JobRecord {
            id: 1,
            priority: 10,
            running: true,
        };
        let b = JobRecord {
            id: 2,
            priority: 20,
            running: true,
        };
        assert_eq!(compare_job_priority(&a, &b), Ordering::Greater);
    }

    #[test]
    fn progress_defaults_to_complete_with_no_units() {
        assert_eq!(manager_get_progress(&ManagerRecord::default()), 1.0);
    }

    #[test]
    fn progress_is_fraction_of_finished_units() {
        let manager = ManagerRecord {
            finished_units: 2,
            total_units: 5,
            ..Default::default()
        };
        assert!((manager_get_progress(&manager) - 0.4).abs() < f64::EPSILON);
    }

    #[test]
    fn default_timeout_depends_on_scope() {
        assert_eq!(manager_default_timeout(0), 90_000_000);
        assert_eq!(manager_default_timeout(1), 120_000_000);
    }

    #[test]
    fn show_status_on_includes_temporary() {
        assert!(manager_get_show_status_on(&ManagerRecord {
            show_status: ShowStatus::Temporary,
            ..Default::default()
        }));
        assert!(!manager_get_show_status_on(&ManagerRecord {
            show_status: ShowStatus::Off,
            ..Default::default()
        }));
    }

    #[test]
    fn watchdog_roundtrips() {
        let mut manager = ManagerRecord::default();
        manager_set_watchdog(&mut manager, 123);
        assert_eq!(manager_get_watchdog(&manager), 123);
    }
}
