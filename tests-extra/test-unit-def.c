/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "tests.h"
#include "unit-def.h"
#include "glyph-util.h"

TEST(unit_type_to_string) {
        ASSERT_STREQ(unit_type_to_string(UNIT_SERVICE), "service");
        ASSERT_STREQ(unit_type_to_string(UNIT_MOUNT), "mount");
        ASSERT_STREQ(unit_type_to_string(UNIT_SOCKET), "socket");
        ASSERT_STREQ(unit_type_to_string(UNIT_TARGET), "target");
        ASSERT_STREQ(unit_type_to_string(UNIT_DEVICE), "device");
        ASSERT_STREQ(unit_type_to_string(UNIT_AUTOMOUNT), "automount");
        ASSERT_STREQ(unit_type_to_string(UNIT_SWAP), "swap");
        ASSERT_STREQ(unit_type_to_string(UNIT_TIMER), "timer");
        ASSERT_STREQ(unit_type_to_string(UNIT_PATH), "path");
        ASSERT_STREQ(unit_type_to_string(UNIT_SLICE), "slice");
        ASSERT_STREQ(unit_type_to_string(UNIT_SCOPE), "scope");
}

TEST(unit_type_from_string) {
        ASSERT_EQ(unit_type_from_string("service"), UNIT_SERVICE);
        ASSERT_EQ(unit_type_from_string("mount"), UNIT_MOUNT);
        ASSERT_EQ(unit_type_from_string("socket"), UNIT_SOCKET);
        ASSERT_EQ(unit_type_from_string("target"), UNIT_TARGET);
        ASSERT_EQ(unit_type_from_string("invalid"), _UNIT_TYPE_INVALID);
}

TEST(unit_load_state) {
        ASSERT_STREQ(unit_load_state_to_string(UNIT_LOADED), "loaded");
        ASSERT_STREQ(unit_load_state_to_string(UNIT_NOT_FOUND), "not-found");
        ASSERT_STREQ(unit_load_state_to_string(UNIT_MASKED), "masked");
        ASSERT_STREQ(unit_load_state_to_string(UNIT_STUB), "stub");
        ASSERT_STREQ(unit_load_state_to_string(UNIT_ERROR), "error");
        ASSERT_STREQ(unit_load_state_to_string(UNIT_MERGED), "merged");
        ASSERT_STREQ(unit_load_state_to_string(UNIT_BAD_SETTING), "bad-setting");

        ASSERT_EQ(unit_load_state_from_string("loaded"), UNIT_LOADED);
        ASSERT_EQ(unit_load_state_from_string("masked"), UNIT_MASKED);
        ASSERT_EQ(unit_load_state_from_string("invalid"), _UNIT_LOAD_STATE_INVALID);
}

TEST(unit_active_state) {
        ASSERT_STREQ(unit_active_state_to_string(UNIT_ACTIVE), "active");
        ASSERT_STREQ(unit_active_state_to_string(UNIT_INACTIVE), "inactive");
        ASSERT_STREQ(unit_active_state_to_string(UNIT_FAILED), "failed");
        ASSERT_STREQ(unit_active_state_to_string(UNIT_RELOADING), "reloading");
        ASSERT_STREQ(unit_active_state_to_string(UNIT_ACTIVATING), "activating");
        ASSERT_STREQ(unit_active_state_to_string(UNIT_DEACTIVATING), "deactivating");
        ASSERT_STREQ(unit_active_state_to_string(UNIT_MAINTENANCE), "maintenance");
        ASSERT_STREQ(unit_active_state_to_string(UNIT_REFRESHING), "refreshing");

        ASSERT_EQ(unit_active_state_from_string("active"), UNIT_ACTIVE);
        ASSERT_EQ(unit_active_state_from_string("failed"), UNIT_FAILED);
        ASSERT_EQ(unit_active_state_from_string("invalid"), _UNIT_ACTIVE_STATE_INVALID);
}

TEST(freezer_state) {
        ASSERT_STREQ(freezer_state_to_string(FREEZER_RUNNING), "running");
        ASSERT_STREQ(freezer_state_to_string(FREEZER_FREEZING), "freezing");
        ASSERT_STREQ(freezer_state_to_string(FREEZER_FROZEN), "frozen");
        ASSERT_STREQ(freezer_state_to_string(FREEZER_THAWING), "thawing");
        ASSERT_STREQ(freezer_state_to_string(FREEZER_FREEZING_BY_PARENT), "freezing-by-parent");
        ASSERT_STREQ(freezer_state_to_string(FREEZER_FROZEN_BY_PARENT), "frozen-by-parent");

        ASSERT_EQ(freezer_state_finish(FREEZER_FREEZING), FREEZER_FROZEN);
        ASSERT_EQ(freezer_state_finish(FREEZER_FREEZING_BY_PARENT), FREEZER_FROZEN_BY_PARENT);
        ASSERT_EQ(freezer_state_finish(FREEZER_THAWING), FREEZER_RUNNING);
        ASSERT_EQ(freezer_state_finish(FREEZER_RUNNING), FREEZER_RUNNING);
        ASSERT_EQ(freezer_state_finish(FREEZER_FROZEN), FREEZER_FROZEN);

        ASSERT_EQ(freezer_state_objective(FREEZER_FREEZING), FREEZER_FROZEN);
        ASSERT_EQ(freezer_state_objective(FREEZER_FREEZING_BY_PARENT), FREEZER_FROZEN);
        ASSERT_EQ(freezer_state_objective(FREEZER_THAWING), FREEZER_RUNNING);
        ASSERT_EQ(freezer_state_objective(FREEZER_FROZEN_BY_PARENT), FREEZER_FROZEN);
}

TEST(unit_dbus_interface_from_type) {
        ASSERT_STREQ(unit_dbus_interface_from_type(UNIT_SERVICE), "org.freedesktop.systemd1.Service");
        ASSERT_STREQ(unit_dbus_interface_from_type(UNIT_SOCKET), "org.freedesktop.systemd1.Socket");
        ASSERT_STREQ(unit_dbus_interface_from_type(UNIT_TARGET), "org.freedesktop.systemd1.Target");
        ASSERT_STREQ(unit_dbus_interface_from_type(UNIT_DEVICE), "org.freedesktop.systemd1.Device");
        ASSERT_STREQ(unit_dbus_interface_from_type(UNIT_MOUNT), "org.freedesktop.systemd1.Mount");
        ASSERT_STREQ(unit_dbus_interface_from_type(UNIT_TIMER), "org.freedesktop.systemd1.Timer");
        ASSERT_STREQ(unit_dbus_interface_from_type(UNIT_PATH), "org.freedesktop.systemd1.Path");
        ASSERT_NULL(unit_dbus_interface_from_type(-1));
}

TEST(unit_dbus_path_from_name) {
        _cleanup_free_ char *p = NULL;

        p = unit_dbus_path_from_name("ssh.service");
        ASSERT_NOT_NULL(p);
        ASSERT_STREQ(p, "/org/freedesktop/systemd1/unit/ssh_2eservice");

        p = mfree(p);

        p = unit_dbus_path_from_name("user@1000.service");
        ASSERT_NOT_NULL(p);
        ASSERT_STREQ(p, "/org/freedesktop/systemd1/unit/user_401000_2eservice");
}

TEST(unit_name_from_dbus_path) {
        _cleanup_free_ char *name = NULL;

        ASSERT_OK(unit_name_from_dbus_path("/org/freedesktop/systemd1/unit/ssh_2eservice", &name));
        ASSERT_STREQ(name, "ssh.service");

        name = mfree(name);

        ASSERT_OK(unit_name_from_dbus_path("/org/freedesktop/systemd1/unit/user_401000_2eservice", &name));
        ASSERT_STREQ(name, "user@1000.service");

        /* Invalid path */
        ASSERT_EQ(unit_name_from_dbus_path("/not/a/dbus/path", &name), -EINVAL);
}

TEST(unit_dependency) {
        ASSERT_STREQ(unit_dependency_to_string(UNIT_REQUIRES), "Requires");
        ASSERT_STREQ(unit_dependency_to_string(UNIT_WANTS), "Wants");
        ASSERT_STREQ(unit_dependency_to_string(UNIT_AFTER), "After");
        ASSERT_STREQ(unit_dependency_to_string(UNIT_BEFORE), "Before");
        ASSERT_STREQ(unit_dependency_to_string(UNIT_CONFLICTS), "Conflicts");
        ASSERT_STREQ(unit_dependency_to_string(UNIT_PART_OF), "PartOf");

        ASSERT_EQ(unit_dependency_from_string("Requires"), UNIT_REQUIRES);
        ASSERT_EQ(unit_dependency_from_string("Wants"), UNIT_WANTS);
        ASSERT_EQ(unit_dependency_from_string("After"), UNIT_AFTER);
        ASSERT_EQ(unit_dependency_from_string("invalid"), _UNIT_DEPENDENCY_INVALID);
}

TEST(job_mode) {
        ASSERT_STREQ(job_mode_to_string(JOB_FAIL), "fail");
        ASSERT_STREQ(job_mode_to_string(JOB_REPLACE), "replace");
        ASSERT_STREQ(job_mode_to_string(JOB_ISOLATE), "isolate");
        ASSERT_STREQ(job_mode_to_string(JOB_FLUSH), "flush");
        ASSERT_STREQ(job_mode_to_string(JOB_IGNORE_DEPENDENCIES), "ignore-dependencies");

        ASSERT_EQ(job_mode_from_string("fail"), JOB_FAIL);
        ASSERT_EQ(job_mode_from_string("replace"), JOB_REPLACE);
        ASSERT_EQ(job_mode_from_string("invalid"), _JOB_MODE_INVALID);
}

TEST(notify_access) {
        ASSERT_STREQ(notify_access_to_string(NOTIFY_NONE), "none");
        ASSERT_STREQ(notify_access_to_string(NOTIFY_MAIN), "main");
        ASSERT_STREQ(notify_access_to_string(NOTIFY_EXEC), "exec");
        ASSERT_STREQ(notify_access_to_string(NOTIFY_ALL), "all");

        ASSERT_EQ(notify_access_from_string("none"), NOTIFY_NONE);
        ASSERT_EQ(notify_access_from_string("all"), NOTIFY_ALL);
        ASSERT_EQ(notify_access_from_string("invalid"), _NOTIFY_ACCESS_INVALID);
}

TEST(service_state) {
        ASSERT_STREQ(service_state_to_string(SERVICE_DEAD), "dead");
        ASSERT_STREQ(service_state_to_string(SERVICE_RUNNING), "running");
        ASSERT_STREQ(service_state_to_string(SERVICE_FAILED), "failed");
        ASSERT_STREQ(service_state_to_string(SERVICE_EXITED), "exited");
        ASSERT_STREQ(service_state_to_string(SERVICE_RELOAD), "reload");

        ASSERT_EQ(service_state_from_string("dead"), SERVICE_DEAD);
        ASSERT_EQ(service_state_from_string("running"), SERVICE_RUNNING);
        ASSERT_EQ(service_state_from_string("invalid"), _SERVICE_STATE_INVALID);
}

TEST(unit_active_state_to_glyph) {
        Glyph g;

        g = unit_active_state_to_glyph(UNIT_ACTIVE);
        ASSERT_EQ(g, GLYPH_BLACK_CIRCLE);

        g = unit_active_state_to_glyph(UNIT_INACTIVE);
        ASSERT_EQ(g, GLYPH_WHITE_CIRCLE);

        g = unit_active_state_to_glyph(UNIT_FAILED);
        ASSERT_EQ(g, GLYPH_MULTIPLICATION_SIGN);

        g = unit_active_state_to_glyph(UNIT_RELOADING);
        ASSERT_EQ(g, GLYPH_CIRCLE_ARROW);

        g = unit_active_state_to_glyph(UNIT_REFRESHING);
        ASSERT_EQ(g, GLYPH_CIRCLE_ARROW);

        /* Invalid */
        g = unit_active_state_to_glyph(-1);
        ASSERT_EQ(g, _GLYPH_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
