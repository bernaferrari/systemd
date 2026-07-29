/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* PORT-SYNC: scope=basic.unit-def; authority=src/basic/unit-def.c,src/basic/unit-def.h */
#pragma once

#include <stdbool.h>

/* unit-def string tables */
const char *rs_unit_type_to_string(int v);
int rs_unit_type_from_string(const char *s);
const char *rs_unit_load_state_to_string(int v);
int rs_unit_load_state_from_string(const char *s);
const char *rs_unit_active_state_to_string(int v);
int rs_unit_active_state_from_string(const char *s);
const char *rs_freezer_state_to_string(int v);
int rs_freezer_state_from_string(const char *s);
int rs_freezer_state_finish(int state);
int rs_freezer_state_objective(int state);
const char *rs_unit_marker_to_string(int v);
int rs_unit_marker_from_string(const char *s);
const char *rs_automount_state_to_string(int v);
int rs_automount_state_from_string(const char *s);
const char *rs_device_state_to_string(int v);
int rs_device_state_from_string(const char *s);
const char *rs_mount_state_to_string(int v);
int rs_mount_state_from_string(const char *s);
const char *rs_path_state_to_string(int v);
int rs_path_state_from_string(const char *s);
const char *rs_scope_state_to_string(int v);
int rs_scope_state_from_string(const char *s);
const char *rs_service_state_to_string(int v);
int rs_service_state_from_string(const char *s);
const char *rs_slice_state_to_string(int v);
int rs_slice_state_from_string(const char *s);
const char *rs_socket_state_to_string(int v);
int rs_socket_state_from_string(const char *s);
const char *rs_swap_state_to_string(int v);
int rs_swap_state_from_string(const char *s);
const char *rs_target_state_to_string(int v);
int rs_target_state_from_string(const char *s);
const char *rs_timer_state_to_string(int v);
int rs_timer_state_from_string(const char *s);
const char *rs_unit_dependency_to_string(int v);
int rs_unit_dependency_from_string(const char *s);
const char *rs_notify_access_to_string(int v);
int rs_notify_access_from_string(const char *s);
const char *rs_job_mode_to_string(int v);
int rs_job_mode_from_string(const char *s);
const char *rs_exec_directory_type_to_string(int v);
int rs_exec_directory_type_from_string(const char *s);

/* D-Bus path/interface helpers */
char *rs_unit_dbus_path_from_name(const char *name);
int rs_unit_name_from_dbus_path(const char *path, char **name);
const char *rs_unit_dbus_interface_from_type(int t);
const char *rs_unit_dbus_interface_from_name(const char *name);

/* cgroup-util string tables */
const char *rs_cgroup_io_limit_type_to_string(int v);
int rs_cgroup_io_limit_type_from_string(const char *s);
const char *rs_cgroup_controller_to_string(int v);
int rs_cgroup_controller_from_string(const char *s);
const char *rs_managed_oom_mode_to_string(int v);
int rs_managed_oom_mode_from_string(const char *s);
const char *rs_managed_oom_preference_to_string(int v);
int rs_managed_oom_preference_from_string(const char *s);

/* cgroup-util escape functions */
bool rs_cg_needs_escape(const char *p);
char *rs_cg_unescape(const char *p);

/* cgroup-util allocation-owning helpers; non-null results use free(3). */
int rs_cg_mask_to_string(unsigned int mask, char **ret);
int rs_cg_mask_from_string(const char *s, unsigned int *ret);
int rs_cg_split_spec(const char *spec, char **ret_controller, char **ret_path);
