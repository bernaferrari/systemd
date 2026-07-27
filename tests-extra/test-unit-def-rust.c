/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C unit-def string tables vs Rust */

#include "tests.h"
#include "unit-def.h"
#include "string-util.h"

/* Rust FFI */
#include "rust/unit_def.h"

/* Exercise every valid enum discriminant, both invalid boundaries, and the
 * byte-preserving reverse lookup. This intentionally compares the live C
 * authority rather than duplicating any table literals in the fixture. */
#define ASSERT_FULL_STRING_TABLE(name, count)                                  \
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

static void test_all_unit_def_string_tables(void) {
        ASSERT_FULL_STRING_TABLE(unit_type, 11);
        ASSERT_FULL_STRING_TABLE(unit_load_state, 7);
        ASSERT_FULL_STRING_TABLE(unit_active_state, 8);
        ASSERT_FULL_STRING_TABLE(freezer_state, 6);
        ASSERT_FULL_STRING_TABLE(unit_marker, 4);
        ASSERT_FULL_STRING_TABLE(automount_state, 4);
        ASSERT_FULL_STRING_TABLE(device_state, 3);
        ASSERT_FULL_STRING_TABLE(mount_state, 12);
        ASSERT_FULL_STRING_TABLE(path_state, 4);
        ASSERT_FULL_STRING_TABLE(scope_state, 7);
        ASSERT_FULL_STRING_TABLE(service_state, 29);
        ASSERT_FULL_STRING_TABLE(slice_state, 2);
        ASSERT_FULL_STRING_TABLE(socket_state, 16);
        ASSERT_FULL_STRING_TABLE(swap_state, 9);
        ASSERT_FULL_STRING_TABLE(target_state, 2);
        ASSERT_FULL_STRING_TABLE(timer_state, 5);
        ASSERT_FULL_STRING_TABLE(unit_dependency, 31);
        ASSERT_FULL_STRING_TABLE(notify_access, 4);
        ASSERT_FULL_STRING_TABLE(job_mode, 10);
        ASSERT_FULL_STRING_TABLE(exec_directory_type, 5);
}

/* ── unit_type ───────────────────────────────────────────────────────── */

static void test_unit_type(void) {
        const char *cv, *rv;
        int c, r;

        cv = unit_type_to_string(UNIT_SERVICE);
        rv = rs_unit_type_to_string(UNIT_SERVICE);
        assert_se(cv && rv);
        assert_se(streq(cv, rv));
        assert_se(streq(cv, "service"));

        cv = unit_type_to_string(UNIT_SOCKET);
        rv = rs_unit_type_to_string(UNIT_SOCKET);
        assert_se(streq(cv, rv));

        cv = unit_type_to_string(UNIT_MOUNT);
        rv = rs_unit_type_to_string(UNIT_MOUNT);
        assert_se(streq(cv, rv));

        cv = unit_type_to_string(UNIT_SCOPE);
        rv = rs_unit_type_to_string(UNIT_SCOPE);
        assert_se(streq(cv, rv));

        /* Invalid */
        cv = unit_type_to_string(-1);
        rv = rs_unit_type_to_string(-1);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        /* from_string */
        c = unit_type_from_string("service");
        r = rs_unit_type_from_string("service");
        assert_se(c == r);
        assert_se(c == UNIT_SERVICE);

        c = unit_type_from_string("bogus");
        r = rs_unit_type_from_string("bogus");
        assert_se(c < 0);
        assert_se(r < 0);
}

/* ── unit_load_state ─────────────────────────────────────────────────── */

static void test_unit_load_state(void) {
        const char *cv, *rv;
        int c, r;

        cv = unit_load_state_to_string(UNIT_LOADED);
        rv = rs_unit_load_state_to_string(UNIT_LOADED);
        assert_se(cv && rv);
        assert_se(streq(cv, rv));

        cv = unit_load_state_to_string(UNIT_NOT_FOUND);
        rv = rs_unit_load_state_to_string(UNIT_NOT_FOUND);
        assert_se(streq(cv, rv));

        /* Invalid */
        cv = unit_load_state_to_string(99);
        rv = rs_unit_load_state_to_string(99);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        /* from_string */
        c = unit_load_state_from_string("loaded");
        r = rs_unit_load_state_from_string("loaded");
        assert_se(c == r);
        assert_se(c == UNIT_LOADED);

        c = unit_load_state_from_string("bogus");
        r = rs_unit_load_state_from_string("bogus");
        assert_se(c < 0);
        assert_se(r < 0);
}

/* ── unit_active_state ───────────────────────────────────────────────── */

static void test_unit_active_state(void) {
        const char *cv, *rv;
        int c, r;

        cv = unit_active_state_to_string(UNIT_ACTIVE);
        rv = rs_unit_active_state_to_string(UNIT_ACTIVE);
        assert_se(cv && rv);
        assert_se(streq(cv, rv));
        assert_se(streq(cv, "active"));

        cv = unit_active_state_to_string(UNIT_INACTIVE);
        rv = rs_unit_active_state_to_string(UNIT_INACTIVE);
        assert_se(streq(cv, rv));

        cv = unit_active_state_to_string(UNIT_FAILED);
        rv = rs_unit_active_state_to_string(UNIT_FAILED);
        assert_se(streq(cv, rv));

        /* Invalid */
        cv = unit_active_state_to_string(-1);
        rv = rs_unit_active_state_to_string(-1);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        /* from_string */
        c = unit_active_state_from_string("active");
        r = rs_unit_active_state_from_string("active");
        assert_se(c == r);
        assert_se(c == UNIT_ACTIVE);

        c = unit_active_state_from_string("bogus");
        r = rs_unit_active_state_from_string("bogus");
        assert_se(c < 0);
        assert_se(r < 0);
}

/* ── service_state ───────────────────────────────────────────────────── */

static void test_service_state(void) {
        const char *cv, *rv;
        int c, r;

        cv = service_state_to_string(SERVICE_DEAD);
        rv = rs_service_state_to_string(SERVICE_DEAD);
        assert_se(cv && rv);
        assert_se(streq(cv, rv));

        cv = service_state_to_string(SERVICE_RUNNING);
        rv = rs_service_state_to_string(SERVICE_RUNNING);
        assert_se(streq(cv, rv));

        cv = service_state_to_string(SERVICE_EXITED);
        rv = rs_service_state_to_string(SERVICE_EXITED);
        assert_se(streq(cv, rv));

        /* Invalid */
        cv = service_state_to_string(99);
        rv = rs_service_state_to_string(99);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        /* from_string */
        c = service_state_from_string("dead");
        r = rs_service_state_from_string("dead");
        assert_se(c == r);
        assert_se(c == SERVICE_DEAD);

        c = service_state_from_string("running");
        r = rs_service_state_from_string("running");
        assert_se(c == r);
        assert_se(c == SERVICE_RUNNING);

        c = service_state_from_string("bogus");
        r = rs_service_state_from_string("bogus");
        assert_se(c < 0);
        assert_se(r < 0);
}

/* ── freezer_state ───────────────────────────────────────────────────── */

static void test_freezer_state(void) {
        const char *cv, *rv;
        int c, r;

        cv = freezer_state_to_string(FREEZER_RUNNING);
        rv = rs_freezer_state_to_string(FREEZER_RUNNING);
        assert_se(cv && rv);
        assert_se(streq(cv, rv));

        cv = freezer_state_to_string(FREEZER_FROZEN);
        rv = rs_freezer_state_to_string(FREEZER_FROZEN);
        assert_se(streq(cv, rv));

        cv = freezer_state_to_string(FREEZER_FREEZING);
        rv = rs_freezer_state_to_string(FREEZER_FREEZING);
        assert_se(streq(cv, rv));

        cv = freezer_state_to_string(FREEZER_THAWING);
        rv = rs_freezer_state_to_string(FREEZER_THAWING);
        assert_se(streq(cv, rv));

        /* Invalid */
        cv = freezer_state_to_string(99);
        rv = rs_freezer_state_to_string(99);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        /* from_string */
        c = freezer_state_from_string("running");
        r = rs_freezer_state_from_string("running");
        assert_se(c == r);
        assert_se(c == FREEZER_RUNNING);

        c = freezer_state_from_string("frozen");
        r = rs_freezer_state_from_string("frozen");
        assert_se(c == r);
        assert_se(c == FREEZER_FROZEN);

        c = freezer_state_from_string("bogus");
        r = rs_freezer_state_from_string("bogus");
        assert_se(c < 0);
        assert_se(r < 0);

        /* freezer_state_finish */
        c = freezer_state_finish(FREEZER_RUNNING);
        r = rs_freezer_state_finish(FREEZER_RUNNING);
        assert_se(c == r);

        c = freezer_state_finish(FREEZER_FROZEN);
        r = rs_freezer_state_finish(FREEZER_FROZEN);
        assert_se(c == r);

        c = freezer_state_finish(FREEZER_FREEZING);
        r = rs_freezer_state_finish(FREEZER_FREEZING);
        assert_se(c == r);

        c = freezer_state_finish(FREEZER_THAWING);
        r = rs_freezer_state_finish(FREEZER_THAWING);
        assert_se(c == r);

        /* freezer_state_objective */
        c = freezer_state_objective(FREEZER_RUNNING);
        r = rs_freezer_state_objective(FREEZER_RUNNING);
        assert_se(c == r);

        c = freezer_state_objective(FREEZER_FROZEN);
        r = rs_freezer_state_objective(FREEZER_FROZEN);
        assert_se(c == r);

        c = freezer_state_objective(FREEZER_FREEZING);
        r = rs_freezer_state_objective(FREEZER_FREEZING);
        assert_se(c == r);

        c = freezer_state_objective(FREEZER_THAWING);
        r = rs_freezer_state_objective(FREEZER_THAWING);
        assert_se(c == r);
}

/* ── job_mode ────────────────────────────────────────────────────────── */

static void test_job_mode(void) {
        const char *cv, *rv;
        int c, r;

        cv = job_mode_to_string(JOB_FAIL);
        rv = rs_job_mode_to_string(JOB_FAIL);
        assert_se(cv && rv);
        assert_se(streq(cv, rv));

        cv = job_mode_to_string(JOB_REPLACE);
        rv = rs_job_mode_to_string(JOB_REPLACE);
        assert_se(streq(cv, rv));

        cv = job_mode_to_string(JOB_ISOLATE);
        rv = rs_job_mode_to_string(JOB_ISOLATE);
        assert_se(streq(cv, rv));

        /* Invalid */
        cv = job_mode_to_string(99);
        rv = rs_job_mode_to_string(99);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        /* from_string */
        c = job_mode_from_string("fail");
        r = rs_job_mode_from_string("fail");
        assert_se(c == r);
        assert_se(c == JOB_FAIL);

        c = job_mode_from_string("replace");
        r = rs_job_mode_from_string("replace");
        assert_se(c == r);
        assert_se(c == JOB_REPLACE);

        c = job_mode_from_string("bogus");
        r = rs_job_mode_from_string("bogus");
        assert_se(c < 0);
        assert_se(r < 0);
}

/* ── exec_directory_type ─────────────────────────────────────────────── */

static void test_exec_directory_type(void) {
        const char *cv, *rv;
        int c, r;

        cv = exec_directory_type_to_string(EXEC_DIRECTORY_RUNTIME);
        rv = rs_exec_directory_type_to_string(EXEC_DIRECTORY_RUNTIME);
        assert_se(cv && rv);
        assert_se(streq(cv, rv));
        assert_se(streq(cv, "RuntimeDirectory"));

        cv = exec_directory_type_to_string(EXEC_DIRECTORY_STATE);
        rv = rs_exec_directory_type_to_string(EXEC_DIRECTORY_STATE);
        assert_se(streq(cv, rv));

        cv = exec_directory_type_to_string(EXEC_DIRECTORY_LOGS);
        rv = rs_exec_directory_type_to_string(EXEC_DIRECTORY_LOGS);
        assert_se(streq(cv, rv));

        /* Invalid */
        cv = exec_directory_type_to_string(99);
        rv = rs_exec_directory_type_to_string(99);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        /* from_string */
        c = exec_directory_type_from_string("RuntimeDirectory");
        r = rs_exec_directory_type_from_string("RuntimeDirectory");
        assert_se(c == r);
        assert_se(c == EXEC_DIRECTORY_RUNTIME);

        c = exec_directory_type_from_string("StateDirectory");
        r = rs_exec_directory_type_from_string("StateDirectory");
        assert_se(c == r);
        assert_se(c == EXEC_DIRECTORY_STATE);

        c = exec_directory_type_from_string("bogus");
        r = rs_exec_directory_type_from_string("bogus");
        assert_se(c < 0);
        assert_se(r < 0);
}

/* ── notify_access ───────────────────────────────────────────────────── */

static void test_notify_access(void) {
        const char *cv, *rv;
        int c, r;

        cv = notify_access_to_string(NOTIFY_NONE);
        rv = rs_notify_access_to_string(NOTIFY_NONE);
        assert_se(cv && rv);
        assert_se(streq(cv, rv));

        cv = notify_access_to_string(NOTIFY_MAIN);
        rv = rs_notify_access_to_string(NOTIFY_MAIN);
        assert_se(streq(cv, rv));

        cv = notify_access_to_string(NOTIFY_ALL);
        rv = rs_notify_access_to_string(NOTIFY_ALL);
        assert_se(streq(cv, rv));

        /* Invalid */
        cv = notify_access_to_string(99);
        rv = rs_notify_access_to_string(99);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        /* from_string */
        c = notify_access_from_string("none");
        r = rs_notify_access_from_string("none");
        assert_se(c == r);
        assert_se(c == NOTIFY_NONE);

        c = notify_access_from_string("main");
        r = rs_notify_access_from_string("main");
        assert_se(c == r);
        assert_se(c == NOTIFY_MAIN);

        c = notify_access_from_string("bogus");
        r = rs_notify_access_from_string("bogus");
        assert_se(c < 0);
        assert_se(r < 0);
}

/* ── unit_dependency ─────────────────────────────────────────────────── */

static void test_unit_dependency(void) {
        const char *cv, *rv;
        int c, r;

        cv = unit_dependency_to_string(UNIT_REQUIRES);
        rv = rs_unit_dependency_to_string(UNIT_REQUIRES);
        assert_se(cv && rv);
        assert_se(streq(cv, rv));

        cv = unit_dependency_to_string(UNIT_WANTS);
        rv = rs_unit_dependency_to_string(UNIT_WANTS);
        assert_se(streq(cv, rv));

        cv = unit_dependency_to_string(UNIT_AFTER);
        rv = rs_unit_dependency_to_string(UNIT_AFTER);
        assert_se(streq(cv, rv));

        /* Invalid */
        cv = unit_dependency_to_string(99);
        rv = rs_unit_dependency_to_string(99);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        /* from_string */
        c = unit_dependency_from_string("Requires");
        r = rs_unit_dependency_from_string("Requires");
        assert_se(c == r);
        assert_se(c == UNIT_REQUIRES);

        c = unit_dependency_from_string("Wants");
        r = rs_unit_dependency_from_string("Wants");
        assert_se(c == r);
        assert_se(c == UNIT_WANTS);

        c = unit_dependency_from_string("bogus");
        r = rs_unit_dependency_from_string("bogus");
        assert_se(c < 0);
        assert_se(r < 0);
}

/* ── unit_marker ─────────────────────────────────────────────────────── */

static void test_unit_marker(void) {
        const char *cv, *rv;
        int c, r;

        cv = unit_marker_to_string(UNIT_MARKER_NEEDS_RELOAD);
        rv = rs_unit_marker_to_string(UNIT_MARKER_NEEDS_RELOAD);
        assert_se(cv && rv);
        assert_se(streq(cv, rv));
        assert_se(streq(cv, "needs-reload"));

        cv = unit_marker_to_string(UNIT_MARKER_NEEDS_RESTART);
        rv = rs_unit_marker_to_string(UNIT_MARKER_NEEDS_RESTART);
        assert_se(streq(cv, rv));

        /* Invalid */
        cv = unit_marker_to_string(99);
        rv = rs_unit_marker_to_string(99);
        assert_se(cv == NULL);
        assert_se(rv == NULL);

        /* from_string */
        c = unit_marker_from_string("needs-reload");
        r = rs_unit_marker_from_string("needs-reload");
        assert_se(c == r);
        assert_se(c == UNIT_MARKER_NEEDS_RELOAD);

        c = unit_marker_from_string("bogus");
        r = rs_unit_marker_from_string("bogus");
        assert_se(c < 0);
        assert_se(r < 0);
}

int main(int argc, char **argv) {
        test_all_unit_def_string_tables();
        test_unit_type();
        test_unit_load_state();
        test_unit_active_state();
        test_service_state();
        test_freezer_state();
        test_job_mode();
        test_exec_directory_type();
        test_notify_access();
        test_unit_dependency();
        test_unit_marker();
        return 0;
}
