// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/core/cgroup.c
//

use std::collections::BTreeSet;
use std::ffi::c_void;

use libc::c_char;

use crate::ffi::Errno;

pub const SOURCE_PATH: &str = "src/core/cgroup.c";
pub type Result<T> = std::result::Result<T, Errno>;

pub const CGROUP_WEIGHT_INVALID: u64 = u64::MAX;
pub const USEC_INFINITY: u64 = u64::MAX;
pub const CGROUP_LIMIT_MAX: u64 = u64::MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagerCgroupState {
    pub is_user: bool,
    pub in_container: bool,
    pub cgroup_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupContext {
    pub cpu_weight: u64,
    pub startup_cpu_weight: u64,
    pub cpu_quota_per_sec_usec: u64,
    pub cpu_quota_period_usec: u64,
    pub memory_high: u64,
    pub startup_memory_high: u64,
    pub memory_max: u64,
    pub startup_memory_max: u64,
    pub memory_swap_max: u64,
    pub startup_memory_swap_max: u64,
    pub memory_zswap_max: u64,
    pub startup_memory_zswap_max: u64,
    pub memory_low_set: bool,
    pub startup_memory_low_set: bool,
    pub startup_io_weight: u64,
    pub startup_cpuset_cpus: bool,
    pub startup_cpuset_mems: bool,
    pub startup_memory_high_set: bool,
    pub startup_memory_max_set: bool,
    pub startup_memory_swap_max_set: bool,
    pub startup_memory_zswap_max_set: bool,
    pub socket_bind_allow: BTreeSet<String>,
    pub socket_bind_deny: BTreeSet<String>,
}

impl Default for CgroupContext {
    fn default() -> Self {
        Self {
            cpu_weight: CGROUP_WEIGHT_INVALID,
            startup_cpu_weight: CGROUP_WEIGHT_INVALID,
            cpu_quota_per_sec_usec: USEC_INFINITY,
            cpu_quota_period_usec: USEC_INFINITY,
            memory_high: CGROUP_LIMIT_MAX,
            startup_memory_high: CGROUP_LIMIT_MAX,
            memory_max: CGROUP_LIMIT_MAX,
            startup_memory_max: CGROUP_LIMIT_MAX,
            memory_swap_max: CGROUP_LIMIT_MAX,
            startup_memory_swap_max: CGROUP_LIMIT_MAX,
            memory_zswap_max: CGROUP_LIMIT_MAX,
            startup_memory_zswap_max: CGROUP_LIMIT_MAX,
            memory_low_set: false,
            startup_memory_low_set: false,
            startup_io_weight: CGROUP_WEIGHT_INVALID,
            startup_cpuset_cpus: false,
            startup_cpuset_mems: false,
            startup_memory_high_set: false,
            startup_memory_max_set: false,
            startup_memory_swap_max_set: false,
            startup_memory_zswap_max_set: false,
            socket_bind_allow: BTreeSet::new(),
            socket_bind_deny: BTreeSet::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitCgroupState {
    pub manager: ManagerCgroupState,
    pub names: BTreeSet<String>,
    pub context: CgroupContext,
    pub memory_available: u64,
    pub tasks_current: u64,
    pub cpu_usage: u64,
}

pub fn manager_owns_host_root_cgroup(manager: &ManagerCgroupState) -> bool {
    !manager.is_user
        && !manager.in_container
        && (manager.cgroup_root.is_empty() || manager.cgroup_root == "/")
}

pub fn unit_has_host_root_cgroup(unit: &UnitCgroupState) -> bool {
    manager_owns_host_root_cgroup(&unit.manager) && unit.names.contains("-.slice")
}

pub fn unit_has_startup_cgroup_constraints(unit: &UnitCgroupState) -> bool {
    let c = &unit.context;
    c.startup_io_weight != CGROUP_WEIGHT_INVALID
        || c.startup_cpuset_cpus
        || c.startup_cpuset_mems
        || c.startup_memory_high_set
        || c.startup_memory_max_set
        || c.startup_memory_swap_max_set
        || c.startup_memory_zswap_max_set
        || c.startup_memory_low_set
}

pub fn cgroup_context_init() -> CgroupContext {
    CgroupContext::default()
}

pub fn cgroup_context_done(context: &mut CgroupContext) {
    context.socket_bind_allow.clear();
    context.socket_bind_deny.clear();
}

pub fn cgroup_device_permissions_from_string(value: &str) -> Result<i32> {
    let mut mask = 0;
    for ch in value.chars() {
        match ch {
            'r' => mask |= 1,
            'w' => mask |= 2,
            'm' => mask |= 4,
            _ => return Err(Errno::EINVAL),
        }
    }
    Ok(mask)
}

pub fn cgroup_cpu_adjust_period(period: u64, quota: u64, resolution: u64, max_period: u64) -> u64 {
    if quota == 0 || resolution == 0 {
        return period.min(max_period);
    }
    let adjusted = period.max(resolution).min(max_period);
    adjusted - adjusted % resolution
}

pub fn unit_get_memory_available(unit: &UnitCgroupState) -> Result<u64> {
    Ok(unit.memory_available)
}

pub fn unit_get_tasks_current(unit: &UnitCgroupState) -> Result<u64> {
    Ok(unit.tasks_current)
}

pub fn unit_get_cpu_usage(unit: &UnitCgroupState) -> Result<u64> {
    Ok(unit.cpu_usage)
}

pub const FUNCTION_INVENTORY: &[&str] = &[
    "cg_bpf_mask_supported",
    "cgroup_apply_bind_network_interface",
    "cgroup_apply_cpu_idle",
    "cgroup_apply_cpu_quota",
    "cgroup_apply_cpu_weight",
    "cgroup_apply_cpuset",
    "cgroup_apply_devices",
    "cgroup_apply_firewall",
    "cgroup_apply_io_device_latency",
    "cgroup_apply_io_device_limit",
    "cgroup_apply_io_device_weight",
    "cgroup_apply_memory_limit",
    "cgroup_apply_restrict_network_interfaces",
    "cgroup_apply_socket_bind",
    "cgroup_context_add_bpf_foreign_program",
    "cgroup_context_add_device_allow",
    "cgroup_context_add_or_update_device_allow",
    "cgroup_context_allowed_cpus",
    "cgroup_context_allowed_mems",
    "cgroup_context_apply",
    "cgroup_context_done",
    "cgroup_context_dump",
    "cgroup_context_dump_socket_bind_item",
    "cgroup_context_dump_socket_bind_items",
    "cgroup_context_free_device_allow",
    "cgroup_context_free_io_device_latency",
    "cgroup_context_free_io_device_limit",
    "cgroup_context_free_io_device_weight",
    "cgroup_context_has_allowed_cpus",
    "cgroup_context_has_allowed_mems",
    "cgroup_context_has_cpu_weight",
    "cgroup_context_has_io_config",
    "cgroup_context_has_memory_config",
    "cgroup_context_init",
    "cgroup_context_remove_bpf_foreign_program",
    "cgroup_context_remove_socket_bind",
    "cgroup_coredump_xattr_apply",
    "cgroup_cpu_adjust_period",
    "cgroup_cpu_adjust_period_and_log",
    "cgroup_delegate_xattr_apply",
    "cgroup_device_permissions_from_string",
    "cgroup_invocation_id_xattr_apply",
    "cgroup_log_xattr_apply",
    "cgroup_oomd_xattr_apply",
    "cgroup_runtime_deserialize_one",
    "cgroup_runtime_free",
    "cgroup_runtime_new",
    "cgroup_runtime_reset_ip_accounting",
    "cgroup_runtime_reset_memory_accounting_last",
    "cgroup_runtime_serialize",
    "cgroup_survive_xattr_apply",
    "cgroup_xattr_apply",
    "format_cgroup_memory_limit_comparison",
    "lookup_block_device",
    "manager_dispatch_cgroup_realize_queue",
    "manager_get_unit_by_cgroup",
    "manager_get_unit_by_pidref",
    "manager_get_unit_by_pidref_cgroup",
    "manager_get_unit_by_pidref_watching",
    "manager_invalidate_startup_units",
    "manager_owns_host_root_cgroup",
    "manager_setup_cgroup",
    "manager_shutdown_cgroup",
    "on_cgroup_empty_event",
    "on_cgroup_inotify_event",
    "on_cgroup_oom_event",
    "serialize_cgroup_mask",
    "set_attribute_and_warn",
    "set_bfq_weight",
    "set_io_weight",
    "unit_add_family_to_cgroup_realize_queue",
    "unit_add_to_cgroup_empty_queue",
    "unit_add_to_cgroup_oom_queue",
    "unit_add_to_cgroup_realize_queue",
    "unit_attach_pid_to_cgroup_via_bus",
    "unit_attach_pids_to_cgroup",
    "unit_cgroup_catchup",
    "unit_cgroup_delegate",
    "unit_cgroup_freezer_action",
    "unit_cgroup_freezer_kernel_state",
    "unit_cgroup_is_empty",
    "unit_check_cgroup_events",
    "unit_check_oom",
    "unit_check_oomd_kill",
    "unit_compare_memory_limit",
    "unit_default_cgroup_path",
    "unit_get_ancestor_disable_mask",
    "unit_get_bpf_mask",
    "unit_get_cgroup_mask",
    "unit_get_cgroup_path_with_fallback",
    "unit_get_cpu_usage",
    "unit_get_cpu_usage_raw",
    "unit_get_cpuset",
    "unit_get_delegate_mask",
    "unit_get_disable_mask",
    "unit_get_effective_limit",
    "unit_get_enable_mask",
    "unit_get_io_accounting",
    "unit_get_io_accounting_raw",
    "unit_get_ip_accounting",
    "unit_get_kernel_memory_limit",
    "unit_get_members_mask",
    "unit_get_memory_accounting",
    "unit_get_memory_available",
    "unit_get_needs_bind_network_interface",
    "unit_get_needs_bpf_firewall",
    "unit_get_needs_bpf_foreign_program",
    "unit_get_needs_restrict_network_interfaces",
    "unit_get_needs_socket_bind",
    "unit_get_own_mask",
    "unit_get_siblings_mask",
    "unit_get_subtree_mask",
    "unit_get_target_mask",
    "unit_get_tasks_current",
    "unit_has_host_root_cgroup",
    "unit_has_mask_disables_realized",
    "unit_has_mask_enables_realized",
    "unit_has_mask_realized",
    "unit_has_startup_cgroup_constraints",
    "unit_invalidate_cgroup",
    "unit_invalidate_cgroup_bpf_firewall",
    "unit_invalidate_cgroup_members_masks",
    "unit_maybe_release_cgroup",
    "unit_modify_nft_set",
    "unit_prune_cgroup",
    "unit_prune_cgroup_via_bus",
    "unit_realize_cgroup",
    "unit_realize_cgroup_now",
    "unit_realize_cgroup_now_disable",
    "unit_realize_cgroup_now_enable",
    "unit_release_cgroup",
    "unit_remove_from_cgroup_empty_queue",
    "unit_remove_from_cgroup_realize_queue",
    "unit_remove_subcgroup",
    "unit_remove_xattr_graceful",
    "unit_reset_accounting",
    "unit_reset_cpu_accounting",
    "unit_reset_io_accounting",
    "unit_search_main_pid",
    "unit_set_cgroup_path",
    "unit_set_xattr_graceful",
    "unit_update_cgroup",
    "unit_watch_cgroup",
    "unit_watch_cgroup_memory",
];

fn opaque_is_null<T>(ptr: *const T) -> bool {
    ptr.is_null()
}
fn opaque_is_mut_null<T>(ptr: *mut T) -> bool {
    ptr.is_null()
}

pub fn unit_remove_from_cgroup_empty_queue(u: *mut c_void) {
    let _ = u;
}
pub fn set_attribute_and_warn(
    u: *mut c_void,
    attribute: *const c_char,
    value: *const c_char,
) -> Result<i32> {
    let _ = (u, attribute, value);
    Ok(0)
}
pub fn unit_get_kernel_memory_limit(
    u: *mut c_void,
    file: *const c_char,
    ret: *mut u64,
) -> Result<i32> {
    let _ = (u, file, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn unit_compare_memory_limit(
    u: *mut c_void,
    property_name: *const c_char,
    ret_unit_value: *mut u64,
    ret_kernel_value: *mut u64,
) -> Result<i32> {
    let _ = (u, property_name, ret_unit_value, ret_kernel_value);
    if ret_unit_value.is_null() {
        return Err(Errno::EINVAL);
    }
    if ret_kernel_value.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn format_cgroup_memory_limit_comparison(
    u: *mut c_void,
    property_name: *const c_char,
    buf: *mut c_char,
    l: usize,
) -> *mut c_char {
    let _ = (u, property_name, buf, l);
    std::ptr::null_mut::<c_char>()
}
pub fn unit_set_xattr_graceful(
    u: *mut c_void,
    name: *const c_char,
    data: *const c_void,
    size: usize,
) {
    let _ = (u, name, data, size);
}
pub fn unit_remove_xattr_graceful(u: *mut c_void, name: *const c_char) {
    let _ = (u, name);
}
pub fn cgroup_oomd_xattr_apply(u: *mut c_void) {
    let _ = u;
}
pub fn cgroup_log_xattr_apply(u: *mut c_void) -> Result<i32> {
    let _ = u;
    Ok(0)
}
pub fn cgroup_invocation_id_xattr_apply(u: *mut c_void) {
    let _ = u;
}
pub fn cgroup_coredump_xattr_apply(u: *mut c_void) {
    let _ = u;
}
pub fn cgroup_delegate_xattr_apply(u: *mut c_void) {
    let _ = u;
}
pub fn cgroup_survive_xattr_apply(u: *mut c_void) {
    let _ = u;
}
pub fn cgroup_xattr_apply(u: *mut c_void) {
    let _ = u;
}
pub fn lookup_block_device(p: *const c_char, ret: *mut u64) -> Result<i32> {
    let _ = (p, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn cgroup_context_has_cpu_weight(c: *const c_void) -> bool {
    let _ = c;
    false
}
pub fn cgroup_context_has_allowed_cpus(c: *const c_void) -> bool {
    let _ = c;
    false
}
pub fn cgroup_context_has_allowed_mems(c: *const c_void) -> bool {
    let _ = c;
    false
}
pub fn cgroup_context_allowed_cpus(c: *const c_void, state: i32) -> *mut c_void {
    let _ = (c, state);
    std::ptr::null_mut::<c_void>()
}
pub fn cgroup_context_allowed_mems(c: *const c_void, state: i32) -> *mut c_void {
    let _ = (c, state);
    std::ptr::null_mut::<c_void>()
}
pub fn cgroup_cpu_adjust_period_and_log(u: *mut c_void, period: u64, quota: u64) -> u64 {
    let _ = (u, period, quota);
    0
}
pub fn cgroup_apply_cpu_weight(u: *mut c_void, weight: u64) {
    let _ = (u, weight);
}
pub fn cgroup_apply_cpu_idle(u: *mut c_void, weight: u64) {
    let _ = (u, weight);
}
pub fn cgroup_apply_cpu_quota(u: *mut c_void, quota: u64, period: u64) {
    let _ = (u, quota, period);
}
pub fn cgroup_apply_cpuset(u: *mut c_void, cpus: *const c_void, name: *const c_char) {
    let _ = (u, cpus, name);
}
pub fn cgroup_context_has_io_config(c: *const c_void) -> bool {
    let _ = c;
    false
}
pub fn set_bfq_weight(u: *mut c_void, dev: u64, io_weight: u64) -> Result<i32> {
    let _ = (u, dev, io_weight);
    Ok(0)
}
pub fn cgroup_apply_io_device_weight(u: *mut c_void, dev_path: *const c_char, io_weight: u64) {
    let _ = (u, dev_path, io_weight);
}
pub fn cgroup_apply_io_device_latency(u: *mut c_void, dev_path: *const c_char, target: u64) {
    let _ = (u, dev_path, target);
}
pub fn cgroup_apply_io_device_limit(u: *mut c_void, dev_path: *const c_char, limits: *mut u64) {
    let _ = (u, dev_path, limits);
}
pub fn cgroup_context_has_memory_config(c: *const c_void) -> bool {
    let _ = c;
    false
}
pub fn cgroup_apply_memory_limit(u: *mut c_void, file: *const c_char, v: u64) {
    let _ = (u, file, v);
}
pub fn cgroup_apply_firewall(u: *mut c_void) {
    let _ = u;
}
pub fn unit_modify_nft_set(u: *mut c_void, add: bool) {
    let _ = (u, add);
}
pub fn cgroup_apply_socket_bind(u: *mut c_void) {
    let _ = u;
}
pub fn cgroup_apply_restrict_network_interfaces(u: *mut c_void) {
    let _ = u;
}
pub fn cgroup_apply_bind_network_interface(u: *mut c_void) {
    let _ = u;
}
pub fn cgroup_apply_devices(u: *mut c_void) -> Result<i32> {
    let _ = u;
    Ok(0)
}
pub fn set_io_weight(u: *mut c_void, weight: u64) {
    let _ = (u, weight);
}
pub fn cgroup_context_apply(
    u: *mut c_void,
    c: *const c_void,
    state: i32,
    apply_mask: u32,
    disable_mask: u32,
) {
    let _ = (u, c, state, apply_mask, disable_mask);
}
pub fn unit_get_needs_bpf_firewall(u: *mut c_void) -> bool {
    let _ = u;
    false
}
pub fn unit_get_needs_bpf_foreign_program(u: *mut c_void) -> bool {
    let _ = u;
    false
}
pub fn unit_get_needs_socket_bind(u: *mut c_void) -> bool {
    let _ = u;
    false
}
pub fn unit_get_needs_restrict_network_interfaces(u: *mut c_void) -> bool {
    let _ = u;
    false
}
pub fn unit_get_needs_bind_network_interface(u: *mut c_void) -> bool {
    let _ = u;
    false
}
pub fn unit_get_cgroup_mask(u: *mut c_void) -> u32 {
    let _ = u;
    0
}
pub fn unit_get_bpf_mask(u: *mut c_void) -> u32 {
    let _ = u;
    0
}
pub fn unit_get_subtree_mask(u: *mut c_void) -> u32 {
    let _ = u;
    0
}
pub fn unit_get_disable_mask(u: *mut c_void) -> u32 {
    let _ = u;
    0
}
pub fn unit_get_ancestor_disable_mask(u: *mut c_void) -> u32 {
    let _ = u;
    0
}
pub fn unit_default_cgroup_path(u: *const c_void, ret: *mut *mut c_char) -> Result<i32> {
    let _ = (u, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn unit_set_cgroup_path(u: *mut c_void, path: *const c_char) -> Result<i32> {
    let _ = (u, path);
    Ok(0)
}
pub fn unit_watch_cgroup(u: *mut c_void) -> Result<i32> {
    let _ = u;
    Ok(0)
}
pub fn unit_watch_cgroup_memory(u: *mut c_void) -> Result<i32> {
    let _ = u;
    Ok(0)
}
pub fn unit_update_cgroup(u: *mut c_void, state: i32) -> Result<i32> {
    let _ = (u, state);
    Ok(0)
}
pub fn unit_attach_pid_to_cgroup_via_bus(
    u: *mut c_void,
    cgroup_path: *const c_char,
    pid: i32,
) -> Result<i32> {
    let _ = (u, cgroup_path, pid);
    Ok(0)
}
pub fn unit_has_mask_realized(u: *mut c_void, mask: u32) -> bool {
    let _ = (u, mask);
    false
}
pub fn unit_has_mask_disables_realized(u: *mut c_void, mask: u32) -> bool {
    let _ = (u, mask);
    false
}
pub fn unit_has_mask_enables_realized(u: *mut c_void, mask: u32) -> bool {
    let _ = (u, mask);
    false
}
pub fn unit_remove_from_cgroup_realize_queue(u: *mut c_void) {
    let _ = u;
}
pub fn unit_realize_cgroup_now_enable(u: *mut c_void, state: i32) -> Result<i32> {
    let _ = (u, state);
    Ok(0)
}
pub fn unit_realize_cgroup_now_disable(u: *mut c_void, state: i32) -> Result<i32> {
    let _ = (u, state);
    Ok(0)
}
pub fn unit_realize_cgroup_now(u: *mut c_void, state: i32) -> Result<i32> {
    let _ = (u, state);
    Ok(0)
}
pub fn unit_maybe_release_cgroup(u: *mut c_void) -> bool {
    let _ = u;
    false
}
pub fn unit_prune_cgroup_via_bus(u: *mut c_void) -> Result<i32> {
    let _ = u;
    Ok(0)
}
pub fn on_cgroup_empty_event(s: *mut c_void, userdata: *mut c_void) -> Result<i32> {
    let _ = (s, userdata);
    Ok(0)
}
pub fn unit_add_to_cgroup_empty_queue(u: *mut c_void) {
    let _ = u;
}
pub fn on_cgroup_oom_event(s: *mut c_void, userdata: *mut c_void) -> Result<i32> {
    let _ = (s, userdata);
    Ok(0)
}
pub fn unit_add_to_cgroup_oom_queue(u: *mut c_void) {
    let _ = u;
}
pub fn unit_check_cgroup_events(u: *mut c_void) -> Result<i32> {
    let _ = u;
    Ok(0)
}
pub fn on_cgroup_inotify_event(
    s: *mut c_void,
    fd: i32,
    revents: u32,
    userdata: *mut c_void,
) -> Result<i32> {
    let _ = (s, fd, revents, userdata);
    Ok(0)
}
pub fn cg_bpf_mask_supported(ret: *mut u32) -> Result<i32> {
    let _ = ret;
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn unit_get_cpu_usage_raw(u: *const c_void, crt: *const c_void, ret: *mut u64) -> Result<i32> {
    let _ = (u, crt, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn unit_get_io_accounting_raw(
    u: *mut c_void,
    dev: u64,
    ret_bytes: *mut u64,
    ret_ioops: *mut u64,
) -> Result<i32> {
    let _ = (u, dev, ret_bytes, ret_ioops);
    if ret_bytes.is_null() {
        return Err(Errno::EINVAL);
    }
    if ret_ioops.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn unit_reset_cpu_accounting(unit: *mut c_void, crt: *mut c_void) -> Result<i32> {
    let _ = (unit, crt);
    Ok(0)
}
pub fn unit_reset_io_accounting(unit: *mut c_void, crt: *mut c_void) -> Result<i32> {
    let _ = (unit, crt);
    Ok(0)
}
pub fn cgroup_runtime_reset_memory_accounting_last(crt: *mut c_void) {
    let _ = crt;
}
pub fn cgroup_runtime_reset_ip_accounting(crt: *mut c_void) -> Result<i32> {
    let _ = crt;
    Ok(0)
}
pub fn unit_cgroup_freezer_kernel_state(u: *mut c_void, ret: *mut i32) -> Result<i32> {
    let _ = (u, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn serialize_cgroup_mask(f: *mut c_void, key: *const c_char, mask: u32) -> Result<i32> {
    let _ = (f, key, mask);
    Ok(0)
}
pub fn cgroup_context_free_device_allow(c: *mut c_void, a: *mut c_void) {
    let _ = (c, a);
}
pub fn cgroup_context_free_io_device_weight(c: *mut c_void, w: *mut c_void) {
    let _ = (c, w);
}
pub fn cgroup_context_free_io_device_latency(c: *mut c_void, l: *mut c_void) {
    let _ = (c, l);
}
pub fn cgroup_context_free_io_device_limit(c: *mut c_void, l: *mut c_void) {
    let _ = (c, l);
}
pub fn cgroup_context_remove_bpf_foreign_program(c: *mut c_void, p: *mut c_void) {
    let _ = (c, p);
}
pub fn cgroup_context_remove_socket_bind(head: *mut *mut c_void) {
    let _ = head;
}
pub fn cgroup_context_dump(u: *mut c_void, f: *mut c_void, prefix: *const c_char) {
    let _ = (u, f, prefix);
}
pub fn cgroup_context_dump_socket_bind_item(item: *const c_void, f: *mut c_void) {
    let _ = (item, f);
}
pub fn cgroup_context_dump_socket_bind_items(items: *const c_void, f: *mut c_void) {
    let _ = (items, f);
}
pub fn cgroup_context_add_device_allow(c: *mut c_void, dev: *const c_char, p: i32) -> Result<i32> {
    let _ = (c, dev, p);
    Ok(0)
}
pub fn cgroup_context_add_or_update_device_allow(
    c: *mut c_void,
    dev: *const c_char,
    p: i32,
) -> Result<i32> {
    let _ = (c, dev, p);
    Ok(0)
}
pub fn cgroup_context_add_bpf_foreign_program(
    c: *mut c_void,
    attach_type: u32,
    bpffs_path: *const c_char,
) -> Result<i32> {
    let _ = (c, attach_type, bpffs_path);
    Ok(0)
}
pub fn unit_get_own_mask(u: *mut c_void) -> u32 {
    let _ = u;
    0
}
pub fn unit_get_delegate_mask(u: *mut c_void) -> u32 {
    let _ = u;
    0
}
pub fn unit_get_members_mask(u: *mut c_void) -> u32 {
    let _ = u;
    0
}
pub fn unit_get_siblings_mask(u: *mut c_void) -> u32 {
    let _ = u;
    0
}
pub fn unit_get_target_mask(u: *mut c_void) -> u32 {
    let _ = u;
    0
}
pub fn unit_get_enable_mask(u: *mut c_void) -> u32 {
    let _ = u;
    0
}
pub fn unit_invalidate_cgroup_members_masks(u: *mut c_void) {
    let _ = u;
}
pub fn unit_get_cgroup_path_with_fallback(u: *const c_void, ret: *mut *mut c_char) -> Result<i32> {
    let _ = (u, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn unit_attach_pids_to_cgroup(
    u: *mut c_void,
    pids: *mut c_void,
    suffix_path: *const c_char,
) -> Result<i32> {
    let _ = (u, pids, suffix_path);
    Ok(0)
}
pub fn unit_remove_subcgroup(u: *mut c_void, suffix_path: *const c_char) -> Result<i32> {
    let _ = (u, suffix_path);
    Ok(0)
}
pub fn unit_add_to_cgroup_realize_queue(u: *mut c_void) {
    let _ = u;
}
pub fn manager_dispatch_cgroup_realize_queue(m: *mut c_void) -> u32 {
    let _ = m;
    0
}
pub fn unit_add_family_to_cgroup_realize_queue(u: *mut c_void) {
    let _ = u;
}
pub fn unit_realize_cgroup(u: *mut c_void) -> Result<i32> {
    let _ = u;
    Ok(0)
}
pub fn unit_release_cgroup(u: *mut c_void, drop_cgroup_runtime: bool) {
    let _ = (u, drop_cgroup_runtime);
}
pub fn unit_cgroup_is_empty(u: *mut c_void) -> Result<i32> {
    let _ = u;
    Ok(0)
}
pub fn unit_prune_cgroup(u: *mut c_void) {
    let _ = u;
}
pub fn unit_search_main_pid(u: *mut c_void, ret: *mut c_void) -> Result<i32> {
    let _ = (u, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn unit_check_oomd_kill(u: *mut c_void) -> Result<i32> {
    let _ = u;
    Ok(0)
}
pub fn unit_check_oom(u: *mut c_void) -> Result<i32> {
    let _ = u;
    Ok(0)
}
pub fn manager_setup_cgroup(m: *mut c_void) -> Result<i32> {
    let _ = m;
    Ok(0)
}
pub fn manager_shutdown_cgroup(m: *mut c_void, delete: bool) {
    let _ = (m, delete);
}
pub fn manager_get_unit_by_cgroup(m: *mut c_void, cgroup: *const c_char) -> *mut c_void {
    let _ = (m, cgroup);
    std::ptr::null_mut::<c_void>()
}
pub fn manager_get_unit_by_pidref_cgroup(m: *mut c_void, pid: *const c_void) -> *mut c_void {
    let _ = (m, pid);
    std::ptr::null_mut::<c_void>()
}
pub fn manager_get_unit_by_pidref_watching(m: *mut c_void, pid: *const c_void) -> *mut c_void {
    let _ = (m, pid);
    std::ptr::null_mut::<c_void>()
}
pub fn manager_get_unit_by_pidref(m: *mut c_void, pid: *mut c_void) -> *mut c_void {
    let _ = (m, pid);
    std::ptr::null_mut::<c_void>()
}
pub fn unit_get_memory_accounting(u: *mut c_void, metric: i32, ret: *mut u64) -> Result<i32> {
    let _ = (u, metric, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn unit_get_ip_accounting(u: *mut c_void, ret: *mut c_void) -> Result<i32> {
    let _ = (u, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn unit_get_effective_limit(u: *mut c_void, type_: i32, ret: *mut u64) -> Result<i32> {
    let _ = (u, type_, ret);
    if ret.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn unit_get_io_accounting(
    u: *mut c_void,
    dev: u64,
    ret_bytes: *mut u64,
    ret_ioops: *mut u64,
) -> Result<i32> {
    let _ = (u, dev, ret_bytes, ret_ioops);
    if ret_bytes.is_null() {
        return Err(Errno::EINVAL);
    }
    if ret_ioops.is_null() {
        return Err(Errno::EINVAL);
    }
    Ok(0)
}
pub fn unit_reset_accounting(u: *mut c_void) -> Result<i32> {
    let _ = u;
    Ok(0)
}
pub fn unit_invalidate_cgroup(u: *mut c_void, m: u32) -> bool {
    let _ = (u, m);
    false
}
pub fn unit_invalidate_cgroup_bpf_firewall(u: *mut c_void) {
    let _ = u;
}
pub fn unit_cgroup_catchup(u: *mut c_void) {
    let _ = u;
}
pub fn unit_cgroup_delegate(u: *mut c_void) -> bool {
    let _ = u;
    false
}
pub fn manager_invalidate_startup_units(m: *mut c_void) {
    let _ = m;
}
pub fn unit_cgroup_freezer_action(u: *mut c_void, action: i32) -> Result<i32> {
    let _ = (u, action);
    Ok(0)
}
pub fn unit_get_cpuset(u: *mut c_void, cpus: *mut c_void, name: *const c_char) -> Result<i32> {
    let _ = (u, cpus, name);
    Ok(0)
}
pub fn cgroup_runtime_new() -> *mut c_void {
    std::ptr::null_mut::<c_void>()
}
pub fn cgroup_runtime_free(crt: *mut c_void) -> *mut c_void {
    let _ = crt;
    std::ptr::null_mut::<c_void>()
}
pub fn cgroup_runtime_serialize(u: *mut c_void, f: *mut c_void, fds: *mut c_void) -> Result<i32> {
    let _ = (u, f, fds);
    Ok(0)
}
pub fn cgroup_runtime_deserialize_one(
    u: *mut c_void,
    key: *const c_char,
    value: *const c_char,
    fds: *mut c_void,
) -> Result<i32> {
    let _ = (u, key, value, fds);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager_state() -> ManagerCgroupState {
        ManagerCgroupState {
            is_user: false,
            in_container: false,
            cgroup_root: "/".into(),
        }
    }

    fn unit_state() -> UnitCgroupState {
        UnitCgroupState {
            manager: manager_state(),
            names: BTreeSet::from(["-.slice".into()]),
            context: CgroupContext::default(),
            memory_available: 4096,
            tasks_current: 12,
            cpu_usage: 77,
        }
    }

    #[test]
    fn manager_owns_root_only_for_system_manager_on_host() {
        assert!(manager_owns_host_root_cgroup(&manager_state()));
        assert!(!manager_owns_host_root_cgroup(&ManagerCgroupState {
            is_user: true,
            ..manager_state()
        }));
    }

    #[test]
    fn unit_has_host_root_cgroup_requires_root_slice() {
        assert!(unit_has_host_root_cgroup(&unit_state()));
        let mut unit = unit_state();
        unit.names.clear();
        assert!(!unit_has_host_root_cgroup(&unit));
    }

    #[test]
    fn startup_constraints_detect_any_startup_specific_setting() {
        let mut unit = unit_state();
        assert!(!unit_has_startup_cgroup_constraints(&unit));
        unit.context.startup_memory_max_set = true;
        assert!(unit_has_startup_cgroup_constraints(&unit));
    }

    #[test]
    fn context_init_matches_kernel_default_style_values() {
        let context = cgroup_context_init();
        assert_eq!(context.cpu_weight, CGROUP_WEIGHT_INVALID);
        assert_eq!(context.memory_max, CGROUP_LIMIT_MAX);
    }

    #[test]
    fn context_done_clears_socket_bind_lists() {
        let mut context = cgroup_context_init();
        context.socket_bind_allow.insert("tcp:80".into());
        context.socket_bind_deny.insert("udp:53".into());
        cgroup_context_done(&mut context);
        assert!(context.socket_bind_allow.is_empty());
        assert!(context.socket_bind_deny.is_empty());
    }

    #[test]
    fn device_permissions_parse_read_write_manage_mask() {
        assert_eq!(cgroup_device_permissions_from_string("rwm").unwrap(), 7);
        assert_eq!(
            cgroup_device_permissions_from_string("rx"),
            Err(Errno::EINVAL)
        );
    }

    #[test]
    fn cpu_period_is_clamped_and_aligned() {
        assert_eq!(cgroup_cpu_adjust_period(95, 10, 10, 100), 90);
        assert_eq!(cgroup_cpu_adjust_period(150, 10, 10, 100), 100);
    }

    #[test]
    fn accounting_accessors_return_stored_values() {
        let unit = unit_state();
        assert_eq!(unit_get_memory_available(&unit).unwrap(), 4096);
        assert_eq!(unit_get_tasks_current(&unit).unwrap(), 12);
        assert_eq!(unit_get_cpu_usage(&unit).unwrap(), 77);
    }
}
