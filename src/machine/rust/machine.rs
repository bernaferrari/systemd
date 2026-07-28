// SPDX-License-Identifier: LGPL-2.1-or-later
//
// PORT-SYNC: src/machine/machine.c
//
// Safe Rust synchronization metadata for the matching machine module.

use crate::common::{
    Errno, PortMetadata, count_port_source_lines, read_port_source, verify_extracted_functions,
};

pub const SOURCE_PATH: &str = "src/machine/machine.c";
pub const EXTRACTED_FUNCTIONS: &[&str] = &[
    "machine_add_to_gc_queue",
    "machine_bus_new",
    "machine_copy_from_to_operation",
    "machine_default_shell_args",
    "machine_dispatch_cgroup_empty",
    "machine_dispatch_leader_pidfd",
    "machine_dispatch_supervisor_pidfd",
    "machine_ensure_scope",
    "machine_finalize",
    "machine_free",
    "machine_get_state",
    "machine_get_uid_shift",
    "machine_kill",
    "machine_link",
    "machine_load",
    "machine_may_gc",
    "machine_new",
    "machine_open_root_directory",
    "machine_openpt",
    "machine_owns_gid",
    "machine_owns_uid",
    "machine_owns_uid_internal",
    "machine_release_unit",
    "machine_save",
    "machine_start",
    "machine_start_getty",
    "machine_start_scope",
    "machine_start_shell",
    "machine_stop",
    "machine_translate_gid",
    "machine_translate_uid",
    "machine_translate_uid_internal",
    "machine_unlink",
    "machine_watch_cgroup",
    "machine_watch_pidfd",
    "parse_pid_and_pidfdid",
];

pub fn metadata() -> Result<PortMetadata, Errno> {
    Ok(PortMetadata {
        module_name: module_path!(),
        source_path: SOURCE_PATH,
        source_lines: count_port_source_lines(SOURCE_PATH)?,
        extracted_functions: EXTRACTED_FUNCTIONS,
    })
}

pub fn read_source() -> Result<String, Errno> {
    read_port_source(SOURCE_PATH)
}

pub fn source_lines() -> Result<usize, Errno> {
    count_port_source_lines(SOURCE_PATH)
}

pub fn has_function(name: &str) -> bool {
    EXTRACTED_FUNCTIONS.contains(&name)
}

pub fn verify_port_sync() -> Result<(), Errno> {
    verify_extracted_functions(SOURCE_PATH, EXTRACTED_FUNCTIONS)
}
