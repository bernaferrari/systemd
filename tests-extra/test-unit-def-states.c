/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "unit-def.h"
#include "tests.h"

TEST(automount_state) {
        ASSERT_STREQ(automount_state_to_string(AUTOMOUNT_DEAD), "dead");
        ASSERT_STREQ(automount_state_to_string(AUTOMOUNT_WAITING), "waiting");
        ASSERT_STREQ(automount_state_to_string(AUTOMOUNT_RUNNING), "running");
        ASSERT_STREQ(automount_state_to_string(AUTOMOUNT_FAILED), "failed");
        ASSERT_EQ(automount_state_from_string("dead"), AUTOMOUNT_DEAD);
        ASSERT_EQ(automount_state_from_string("running"), AUTOMOUNT_RUNNING);
        ASSERT_EQ(automount_state_from_string("invalid"), _AUTOMOUNT_STATE_INVALID);
}

TEST(device_state) {
        ASSERT_STREQ(device_state_to_string(DEVICE_DEAD), "dead");
        ASSERT_STREQ(device_state_to_string(DEVICE_TENTATIVE), "tentative");
        ASSERT_STREQ(device_state_to_string(DEVICE_PLUGGED), "plugged");
        ASSERT_EQ(device_state_from_string("plugged"), DEVICE_PLUGGED);
        ASSERT_EQ(device_state_from_string("invalid"), _DEVICE_STATE_INVALID);
}

TEST(exec_directory_type) {
        ASSERT_STREQ(exec_directory_type_to_string(EXEC_DIRECTORY_RUNTIME), "RuntimeDirectory");
        ASSERT_STREQ(exec_directory_type_to_string(EXEC_DIRECTORY_STATE), "StateDirectory");
        ASSERT_STREQ(exec_directory_type_to_string(EXEC_DIRECTORY_CACHE), "CacheDirectory");
        ASSERT_STREQ(exec_directory_type_to_string(EXEC_DIRECTORY_LOGS), "LogsDirectory");
        ASSERT_STREQ(exec_directory_type_to_string(EXEC_DIRECTORY_CONFIGURATION), "ConfigurationDirectory");
        ASSERT_EQ(exec_directory_type_from_string("StateDirectory"), EXEC_DIRECTORY_STATE);
        ASSERT_EQ(exec_directory_type_from_string("invalid"), _EXEC_DIRECTORY_TYPE_INVALID);
}

TEST(freezer_state) {
        ASSERT_STREQ(freezer_state_to_string(FREEZER_RUNNING), "running");
        ASSERT_STREQ(freezer_state_to_string(FREEZER_FROZEN), "frozen");
        ASSERT_STREQ(freezer_state_to_string(FREEZER_FROZEN_BY_PARENT), "frozen-by-parent");
        ASSERT_STREQ(freezer_state_to_string(FREEZER_THAWING), "thawing");
        ASSERT_EQ(freezer_state_from_string("frozen"), FREEZER_FROZEN);
        ASSERT_EQ(freezer_state_from_string("invalid"), _FREEZER_STATE_INVALID);
}

TEST(job_mode) {
        ASSERT_STREQ(job_mode_to_string(JOB_FAIL), "fail");
        ASSERT_STREQ(job_mode_to_string(JOB_REPLACE), "replace");
        ASSERT_STREQ(job_mode_to_string(JOB_ISOLATE), "isolate");
        ASSERT_STREQ(job_mode_to_string(JOB_FLUSH), "flush");
        ASSERT_EQ(job_mode_from_string("fail"), JOB_FAIL);
        ASSERT_EQ(job_mode_from_string("replace"), JOB_REPLACE);
        ASSERT_EQ(job_mode_from_string("isolate"), JOB_ISOLATE);
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

TEST(unit_marker) {
        ASSERT_STREQ(unit_marker_to_string(UNIT_MARKER_NEEDS_RELOAD), "needs-reload");
        ASSERT_STREQ(unit_marker_to_string(UNIT_MARKER_NEEDS_RESTART), "needs-restart");
        ASSERT_STREQ(unit_marker_to_string(UNIT_MARKER_NEEDS_STOP), "needs-stop");
        ASSERT_STREQ(unit_marker_to_string(UNIT_MARKER_NEEDS_START), "needs-start");
        ASSERT_EQ(unit_marker_from_string("needs-reload"), UNIT_MARKER_NEEDS_RELOAD);
        ASSERT_EQ(unit_marker_from_string("invalid"), _UNIT_MARKER_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
