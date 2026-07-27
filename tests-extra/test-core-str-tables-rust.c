/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <string.h>

#include "tests.h"
#include "rust/core_str_tables.h"

/* ── execute.c ──────────────────────────────────────────────────────────── */

TEST(exec_input_roundtrip) {
        const char *s = rs_exec_input_to_string(0);
        assert_se(s);
        ASSERT_STREQ(s, "null");
        assert_se(rs_exec_input_to_string(1) && streq(rs_exec_input_to_string(1), "tty"));
        assert_se(rs_exec_input_to_string(4) && streq(rs_exec_input_to_string(4), "socket"));
        assert_se(rs_exec_input_to_string(99) == NULL);
        assert_se(rs_exec_input_from_string("tty-force") == 2);
        assert_se(rs_exec_input_from_string("data") == 6);
        assert_se(rs_exec_input_from_string(NULL) < 0);
        assert_se(rs_exec_input_from_string("bogus") < 0);
}

TEST(exec_output_roundtrip) {
        assert_se(rs_exec_output_to_string(0) && streq(rs_exec_output_to_string(0), "inherit"));
        assert_se(rs_exec_output_to_string(4) && streq(rs_exec_output_to_string(4), "kmsg+console"));
        assert_se(rs_exec_output_to_string(11) && streq(rs_exec_output_to_string(11), "truncate"));
        assert_se(rs_exec_output_to_string(99) == NULL);
        assert_se(rs_exec_output_from_string("journal") == 5);
        assert_se(rs_exec_output_from_string("file") == 9);
        assert_se(rs_exec_output_from_string("append") == 10);
}

TEST(exec_preserve_mode_boolean) {
        assert_se(rs_exec_preserve_mode_from_string("yes") == 1);
        assert_se(rs_exec_preserve_mode_from_string("no") == 0);
        assert_se(rs_exec_preserve_mode_from_string("restart") == 2);
        assert_se(rs_exec_preserve_mode_to_string(1) && streq(rs_exec_preserve_mode_to_string(1), "yes"));
}

TEST(exec_resource_type) {
        assert_se(rs_exec_resource_type_to_string(0) && streq(rs_exec_resource_type_to_string(0), "runtime"));
        assert_se(rs_exec_resource_type_from_string("state") == 1);
        assert_se(rs_exec_resource_type_from_string("logs") == 3);
}

TEST(exec_keyring_mode) {
        assert_se(rs_exec_keyring_mode_from_string("inherit") == 0);
        assert_se(rs_exec_keyring_mode_from_string("private") == 1);
        assert_se(rs_exec_keyring_mode_from_string("shared") == 2);
}

TEST(memory_thp) {
        assert_se(rs_memory_thp_from_string("inherit") == 0);
        assert_se(rs_memory_thp_from_string("system") == 3);
}

/* ── kill.c ─────────────────────────────────────────────────────────────── */

TEST(kill_mode) {
        assert_se(rs_kill_mode_to_string(0) && streq(rs_kill_mode_to_string(0), "control-group"));
        assert_se(rs_kill_mode_from_string("process") == 1);
        assert_se(rs_kill_mode_from_string("mixed") == 2);
        assert_se(rs_kill_mode_from_string("none") == 3);
}

TEST(kill_whom) {
        assert_se(rs_kill_whom_to_string(0) && streq(rs_kill_whom_to_string(0), "main"));
        assert_se(rs_kill_whom_from_string("control") == 1);
        assert_se(rs_kill_whom_from_string("all") == 2);
        assert_se(rs_kill_whom_from_string("cgroup") == 6);
        assert_se(rs_kill_whom_from_string("cgroup-fail") == 7);
}

/* ── job.c ──────────────────────────────────────────────────────────────── */

TEST(job_type) {
        assert_se(rs_job_type_from_string("start") == 0);
        assert_se(rs_job_type_from_string("stop") == 2);
        assert_se(rs_job_type_from_string("reload-or-start") == 4);
        assert_se(rs_job_type_from_string("nop") == 8);
        assert_se(rs_job_type_to_string(5) && streq(rs_job_type_to_string(5), "restart"));
}

TEST(job_result) {
        assert_se(rs_job_result_from_string("done") == 0);
        assert_se(rs_job_result_from_string("timeout") == 2);
        assert_se(rs_job_result_from_string("concurrency") == 12);
        assert_se(rs_job_result_to_string(9) && streq(rs_job_result_to_string(9), "collected"));
}

/* ── emergency-action.c ─────────────────────────────────────────────────── */

TEST(emergency_action) {
        assert_se(rs_emergency_action_from_string("none") == 0);
        assert_se(rs_emergency_action_from_string("reboot") == 3);
        assert_se(rs_emergency_action_from_string("poweroff-immediate") == 8);
        assert_se(rs_emergency_action_from_string("halt-immediate") == 15);
        assert_se(rs_emergency_action_to_string(9) && streq(rs_emergency_action_to_string(9), "soft-reboot"));
}

/* ── namespace.c ────────────────────────────────────────────────────────── */

TEST(protect_home_boolean) {
        assert_se(rs_protect_home_from_string("yes") == 1);
        assert_se(rs_protect_home_from_string("no") == 0);
        assert_se(rs_protect_home_from_string("read-only") == 2);
        assert_se(rs_protect_home_from_string("tmpfs") == 3);
}

TEST(protect_system_boolean) {
        assert_se(rs_protect_system_from_string("yes") == 1);
        assert_se(rs_protect_system_from_string("full") == 2);
        assert_se(rs_protect_system_from_string("strict") == 3);
}

TEST(protect_proc) {
        assert_se(rs_protect_proc_from_string("default") == 0);
        assert_se(rs_protect_proc_from_string("invisible") == 2);
}

TEST(private_tmp_boolean) {
        assert_se(rs_private_tmp_from_string("yes") == 1);
        assert_se(rs_private_tmp_from_string("no") == 0);
        assert_se(rs_private_tmp_from_string("connected") == 1);
        assert_se(rs_private_tmp_from_string("disconnected") == 2);
}

TEST(private_users_boolean) {
        assert_se(rs_private_users_from_string("yes") == 1);
        assert_se(rs_private_users_from_string("no") == 0);
        assert_se(rs_private_users_from_string("identity") == 2);
        assert_se(rs_private_users_from_string("full") == 3);
}

/* ── cgroup.c ───────────────────────────────────────────────────────────── */

TEST(cgroup_device_policy) {
        assert_se(rs_cgroup_device_policy_from_string("auto") == 0);
        assert_se(rs_cgroup_device_policy_from_string("strict") == 2);
}

TEST(cgroup_pressure_watch_boolean) {
        assert_se(rs_cgroup_pressure_watch_from_string("yes") == 1);
        assert_se(rs_cgroup_pressure_watch_from_string("auto") == 2);
        assert_se(rs_cgroup_pressure_watch_from_string("skip") == 3);
}

TEST(cgroup_ip_accounting_metric) {
        assert_se(rs_cgroup_ip_accounting_metric_from_string("IPIngressBytes") == 0);
        assert_se(rs_cgroup_ip_accounting_metric_from_string("IPEgressPackets") == 3);
}

TEST(cgroup_io_accounting_metric) {
        assert_se(rs_cgroup_io_accounting_metric_from_string("IOReadBytes") == 0);
        assert_se(rs_cgroup_io_accounting_metric_from_string("IOWriteOperations") == 3);
}

TEST(cgroup_memory_accounting_metric) {
        assert_se(rs_cgroup_memory_accounting_metric_from_string("MemoryCurrent") == 0);
        assert_se(rs_cgroup_memory_accounting_metric_from_string("MemoryZSwapCurrent") == 4);
}

TEST(cgroup_effective_limit_type) {
        assert_se(rs_cgroup_effective_limit_type_from_string("EffectiveMemoryMax") == 0);
        assert_se(rs_cgroup_effective_limit_type_from_string("EffectiveTasksMax") == 2);
}

/* ── manager.c ──────────────────────────────────────────────────────────── */

TEST(manager_state) {
        assert_se(rs_manager_state_from_string("running") == 2);
        assert_se(rs_manager_state_from_string("degraded") == 3);
}

TEST(manager_objective) {
        assert_se(rs_manager_objective_from_string("ok") == 0);
        assert_se(rs_manager_objective_from_string("reboot") == 4);
        assert_se(rs_manager_objective_from_string("switch-root") == 9);
}

/* ── unit state results ─────────────────────────────────────────────────── */

TEST(service_type) {
        assert_se(rs_service_type_from_string("simple") == 0);
        assert_se(rs_service_type_from_string("notify-reload") == 5);
        assert_se(rs_service_type_from_string("exec") == 7);
}

TEST(service_result) {
        assert_se(rs_service_result_from_string("success") == 0);
        assert_se(rs_service_result_from_string("watchdog") == 7);
        assert_se(rs_service_result_from_string("oom-kill") == 9);
        assert_se(rs_service_result_from_string("exec-condition") == 10);
}

TEST(notify_state) {
        assert_se(rs_notify_state_from_string("ready") == 0);
        assert_se(rs_notify_state_from_string("reload-ready") == 2);
        assert_se(rs_notify_state_from_string("stopping") == 3);
}

TEST(socket_result) {
        assert_se(rs_socket_result_from_string("success") == 0);
        assert_se(rs_socket_result_from_string("trigger-limit-hit") == 7);
}

TEST(swap_result) {
        assert_se(rs_swap_result_from_string("success") == 0);
        assert_se(rs_swap_result_from_string("start-limit-hit") == 6);
}

TEST(timer_base) {
        assert_se(rs_timer_base_from_string("OnActiveSec") == 0);
        assert_se(rs_timer_base_from_string("OnCalendar") == 5);
}

TEST(oom_policy) {
        assert_se(rs_oom_policy_from_string("continue") == 0);
        assert_se(rs_oom_policy_from_string("kill") == 2);
}

TEST(collect_mode) {
        assert_se(rs_collect_mode_from_string("inactive") == 0);
        assert_se(rs_collect_mode_from_string("inactive-or-failed") == 1);
}

/* ── main ───────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
