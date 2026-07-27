/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "rust/unit_def.h"

/* C references */
#include "unit-def.h"
#include "cgroup-util.h"
#include "string-util.h"

/* Compare every live C table member, reverse lookup, NULL input and both
 * invalid numeric boundaries. Keeping the expected entries in C avoids a
 * second hand-maintained source of truth in the shadow fixture. */
#define ASSERT_FULL_CGROUP_STRING_TABLE(name, count)                           \
        do {                                                                    \
                for (int i = 0; i < (count); i++) {                            \
                        const char *c_value = name##_to_string(i);             \
                        const char *r_value = rs_##name##_to_string(i);        \
                        assert_se(c_value && r_value);                         \
                        assert_se(streq(c_value, r_value));                    \
                        assert_se(name##_from_string(c_value) == i);           \
                        assert_se(rs_##name##_from_string(c_value) == i);      \
                }                                                               \
                assert_se(name##_to_string(-1) == NULL);                      \
                assert_se(rs_##name##_to_string(-1) == NULL);                 \
                assert_se(name##_to_string(count) == NULL);                   \
                assert_se(rs_##name##_to_string(count) == NULL);              \
                assert_se(name##_from_string("not-a-systemd-table-value") < 0); \
                assert_se(rs_##name##_from_string("not-a-systemd-table-value") < 0); \
                assert_se(name##_from_string(NULL) < 0);                      \
                assert_se(rs_##name##_from_string(NULL) < 0);                 \
        } while (false)

static void test_all_cgroup_string_tables(void) {
        ASSERT_FULL_CGROUP_STRING_TABLE(cgroup_io_limit_type, 4);
        ASSERT_FULL_CGROUP_STRING_TABLE(cgroup_controller, 14);
        ASSERT_FULL_CGROUP_STRING_TABLE(managed_oom_mode, 2);
        ASSERT_FULL_CGROUP_STRING_TABLE(managed_oom_preference, 3);
}

/* ── unit_type ─────────────────────────────────────────────────────────── */

static void test_unit_type(void) {
        const char *c_ret, *r_ret;
        UnitType cv;
        int rv;

        c_ret = unit_type_to_string(UNIT_SERVICE);
        r_ret = rs_unit_type_to_string(UNIT_SERVICE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = unit_type_to_string(UNIT_TIMER);
        r_ret = rs_unit_type_to_string(UNIT_TIMER);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = unit_type_to_string(UNIT_SCOPE);
        r_ret = rs_unit_type_to_string(UNIT_SCOPE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = unit_type_to_string(-1);
        r_ret = rs_unit_type_to_string(-1);
        assert_se(streq_ptr(c_ret, r_ret));

        cv = unit_type_from_string("service");
        rv = rs_unit_type_from_string("service");
        assert_se((int)cv == rv);
        assert_se(cv == UNIT_SERVICE);

        cv = unit_type_from_string("mount");
        rv = rs_unit_type_from_string("mount");
        assert_se((int)cv == rv);
        assert_se(cv == UNIT_MOUNT);

        cv = unit_type_from_string("bogus");
        rv = rs_unit_type_from_string("bogus");
        assert_se((int)cv == rv);

        cv = unit_type_from_string(NULL);
        rv = rs_unit_type_from_string(NULL);
        assert_se((int)cv == rv);
}

/* ── unit_active_state ─────────────────────────────────────────────────── */

static void test_unit_active_state(void) {
        const char *c_ret, *r_ret;
        UnitActiveState cv;
        int rv;

        c_ret = unit_active_state_to_string(UNIT_ACTIVE);
        r_ret = rs_unit_active_state_to_string(UNIT_ACTIVE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = unit_active_state_to_string(UNIT_FAILED);
        r_ret = rs_unit_active_state_to_string(UNIT_FAILED);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = unit_active_state_to_string(UNIT_REFRESHING);
        r_ret = rs_unit_active_state_to_string(UNIT_REFRESHING);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = unit_active_state_from_string("inactive");
        rv = rs_unit_active_state_from_string("inactive");
        assert_se((int)cv == rv);
        assert_se(cv == UNIT_INACTIVE);

        cv = unit_active_state_from_string("maintenance");
        rv = rs_unit_active_state_from_string("maintenance");
        assert_se((int)cv == rv);
        assert_se(cv == UNIT_MAINTENANCE);

        cv = unit_active_state_from_string("bogus");
        rv = rs_unit_active_state_from_string("bogus");
        assert_se((int)cv == rv);
}

/* ── service_state ─────────────────────────────────────────────────────── */

static void test_service_state(void) {
        const char *c_ret, *r_ret;
        ServiceState cv;
        int rv;

        c_ret = service_state_to_string(SERVICE_DEAD);
        r_ret = rs_service_state_to_string(SERVICE_DEAD);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = service_state_to_string(SERVICE_RUNNING);
        r_ret = rs_service_state_to_string(SERVICE_RUNNING);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = service_state_to_string(SERVICE_AUTO_RESTART_QUEUED);
        r_ret = rs_service_state_to_string(SERVICE_AUTO_RESTART_QUEUED);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = service_state_from_string("failed");
        rv = rs_service_state_from_string("failed");
        assert_se((int)cv == rv);
        assert_se(cv == SERVICE_FAILED);

        cv = service_state_from_string("stop-sigterm");
        rv = rs_service_state_from_string("stop-sigterm");
        assert_se((int)cv == rv);
        assert_se(cv == SERVICE_STOP_SIGTERM);

        cv = service_state_from_string("bogus");
        rv = rs_service_state_from_string("bogus");
        assert_se((int)cv == rv);
}

/* ── mount_state ──────────────────────────────────────────────────────── */

static void test_mount_state(void) {
        const char *c_ret, *r_ret;
        MountState cv;
        int rv;

        c_ret = mount_state_to_string(MOUNT_MOUNTED);
        r_ret = rs_mount_state_to_string(MOUNT_MOUNTED);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = mount_state_to_string(MOUNT_REMOUNTING_SIGKILL);
        r_ret = rs_mount_state_to_string(MOUNT_REMOUNTING_SIGKILL);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = mount_state_from_string("mounting-done");
        rv = rs_mount_state_from_string("mounting-done");
        assert_se((int)cv == rv);
        assert_se(cv == MOUNT_MOUNTING_DONE);

        cv = mount_state_from_string("cleaning");
        rv = rs_mount_state_from_string("cleaning");
        assert_se((int)cv == rv);
        assert_se(cv == MOUNT_CLEANING);

        cv = mount_state_from_string("bogus");
        rv = rs_mount_state_from_string("bogus");
        assert_se((int)cv == rv);
}

/* ── unit_dependency ──────────────────────────────────────────────────── */

static void test_unit_dependency(void) {
        const char *c_ret, *r_ret;
        UnitDependency cv;
        int rv;

        c_ret = unit_dependency_to_string(UNIT_REQUIRES);
        r_ret = rs_unit_dependency_to_string(UNIT_REQUIRES);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = unit_dependency_to_string(UNIT_AFTER);
        r_ret = rs_unit_dependency_to_string(UNIT_AFTER);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = unit_dependency_to_string(UNIT_SLICE_OF);
        r_ret = rs_unit_dependency_to_string(UNIT_SLICE_OF);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = unit_dependency_from_string("Wants");
        rv = rs_unit_dependency_from_string("Wants");
        assert_se((int)cv == rv);
        assert_se(cv == UNIT_WANTS);

        cv = unit_dependency_from_string("Before");
        rv = rs_unit_dependency_from_string("Before");
        assert_se((int)cv == rv);
        assert_se(cv == UNIT_BEFORE);

        cv = unit_dependency_from_string("bogus");
        rv = rs_unit_dependency_from_string("bogus");
        assert_se((int)cv == rv);
}

/* ── job_mode ─────────────────────────────────────────────────────────── */

static void test_job_mode(void) {
        const char *c_ret, *r_ret;
        JobMode cv;
        int rv;

        c_ret = job_mode_to_string(JOB_REPLACE);
        r_ret = rs_job_mode_to_string(JOB_REPLACE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = job_mode_to_string(JOB_ISOLATE);
        r_ret = rs_job_mode_to_string(JOB_ISOLATE);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = job_mode_from_string("fail");
        rv = rs_job_mode_from_string("fail");
        assert_se((int)cv == rv);
        assert_se(cv == JOB_FAIL);

        cv = job_mode_from_string("restart-dependencies");
        rv = rs_job_mode_from_string("restart-dependencies");
        assert_se((int)cv == rv);
        assert_se(cv == JOB_RESTART_DEPENDENCIES);

        cv = job_mode_from_string("bogus");
        rv = rs_job_mode_from_string("bogus");
        assert_se((int)cv == rv);
}

/* ── freezer_state helpers ────────────────────────────────────────────── */

static void test_freezer_state_helpers(void) {
        int c_ret, r_ret;

        c_ret = freezer_state_finish(FREEZER_FREEZING);
        r_ret = rs_freezer_state_finish(FREEZER_FREEZING);
        assert_se(c_ret == r_ret);
        assert_se(c_ret == FREEZER_FROZEN);

        c_ret = freezer_state_finish(FREEZER_THAWING);
        r_ret = rs_freezer_state_finish(FREEZER_THAWING);
        assert_se(c_ret == r_ret);
        assert_se(c_ret == FREEZER_RUNNING);

        c_ret = freezer_state_finish(FREEZER_FROZEN);
        r_ret = rs_freezer_state_finish(FREEZER_FROZEN);
        assert_se(c_ret == r_ret);

        c_ret = freezer_state_objective(FREEZER_FREEZING);
        r_ret = rs_freezer_state_objective(FREEZER_FREEZING);
        assert_se(c_ret == r_ret);

        c_ret = freezer_state_objective(FREEZER_FREEZING_BY_PARENT);
        r_ret = rs_freezer_state_objective(FREEZER_FREEZING_BY_PARENT);
        assert_se(c_ret == r_ret);
        assert_se(c_ret == FREEZER_FROZEN); /* maps to FROZEN */
}

/* ── cgroup_controller ────────────────────────────────────────────────── */

static void test_cgroup_controller(void) {
        const char *c_ret, *r_ret;
        CGroupController cv;
        int rv;

        c_ret = cgroup_controller_to_string(CGROUP_CONTROLLER_CPU);
        r_ret = rs_cgroup_controller_to_string(CGROUP_CONTROLLER_CPU);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = cgroup_controller_to_string(CGROUP_CONTROLLER_MEMORY);
        r_ret = rs_cgroup_controller_to_string(CGROUP_CONTROLLER_MEMORY);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = cgroup_controller_to_string(CGROUP_CONTROLLER_BPF_FIREWALL);
        r_ret = rs_cgroup_controller_to_string(CGROUP_CONTROLLER_BPF_FIREWALL);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = cgroup_controller_from_string("cpu");
        rv = rs_cgroup_controller_from_string("cpu");
        assert_se((int)cv == rv);
        assert_se(cv == CGROUP_CONTROLLER_CPU);

        cv = cgroup_controller_from_string("memory");
        rv = rs_cgroup_controller_from_string("memory");
        assert_se((int)cv == rv);
        assert_se(cv == CGROUP_CONTROLLER_MEMORY);

        cv = cgroup_controller_from_string("bogus");
        rv = rs_cgroup_controller_from_string("bogus");
        assert_se((int)cv == rv);
}

/* ── managed_oom ──────────────────────────────────────────────────────── */

static void test_managed_oom(void) {
        const char *c_ret, *r_ret;
        ManagedOOMMode cv;
        ManagedOOMPreference pv;
        int rv;

        c_ret = managed_oom_mode_to_string(MANAGED_OOM_AUTO);
        r_ret = rs_managed_oom_mode_to_string(MANAGED_OOM_AUTO);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = managed_oom_mode_to_string(MANAGED_OOM_KILL);
        r_ret = rs_managed_oom_mode_to_string(MANAGED_OOM_KILL);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        cv = managed_oom_mode_from_string("auto");
        rv = rs_managed_oom_mode_from_string("auto");
        assert_se((int)cv == rv);

        c_ret = managed_oom_preference_to_string(MANAGED_OOM_PREFERENCE_AVOID);
        r_ret = rs_managed_oom_preference_to_string(MANAGED_OOM_PREFERENCE_AVOID);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        pv = managed_oom_preference_from_string("omit");
        rv = rs_managed_oom_preference_from_string("omit");
        assert_se((int)pv == rv);
        assert_se(pv == MANAGED_OOM_PREFERENCE_OMIT);
}

/* ── cgroup_io_limit_type ─────────────────────────────────────────────── */

static void test_cgroup_io_limit_type(void) {
        const char *c_ret, *r_ret;
        int cv, rv;

        c_ret = cgroup_io_limit_type_to_string(0);
        r_ret = rs_cgroup_io_limit_type_to_string(0);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        c_ret = cgroup_io_limit_type_to_string(1);
        r_ret = rs_cgroup_io_limit_type_to_string(1);
        assert_se(c_ret && r_ret);
        assert_se(streq(c_ret, r_ret));

        /* Invalid */
        c_ret = cgroup_io_limit_type_to_string(-1);
        r_ret = rs_cgroup_io_limit_type_to_string(-1);
        assert_se(streq_ptr(c_ret, r_ret));

        cv = cgroup_io_limit_type_from_string("IOReadBandwidthMax");
        rv = rs_cgroup_io_limit_type_from_string("IOReadBandwidthMax");
        assert_se(cv == rv);

        cv = cgroup_io_limit_type_from_string("IOWriteBandwidthMax");
        rv = rs_cgroup_io_limit_type_from_string("IOWriteBandwidthMax");
        assert_se(cv == rv);

        cv = cgroup_io_limit_type_from_string("bogus");
        rv = rs_cgroup_io_limit_type_from_string("bogus");
        assert_se(cv == rv);
}

int main(int argc, char **argv) {
        test_all_cgroup_string_tables();
        test_unit_type();
        test_unit_active_state();
        test_service_state();
        test_mount_state();
        test_unit_dependency();
        test_job_mode();
        test_freezer_state_helpers();
        test_cgroup_controller();
        test_managed_oom();
        test_cgroup_io_limit_type();
        return 0;
}
