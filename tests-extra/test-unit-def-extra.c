/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Additional unit-def tests for remaining string table lookups
 * not covered by test-unit-def.c */

#include "tests.h"
#include "unit-def.h"

TEST(unit_marker_to_string) {
        ASSERT_STREQ(unit_marker_to_string(UNIT_MARKER_NEEDS_RELOAD), "needs-reload");
        ASSERT_STREQ(unit_marker_to_string(UNIT_MARKER_NEEDS_RESTART), "needs-restart");
        ASSERT_STREQ(unit_marker_to_string(UNIT_MARKER_NEEDS_STOP), "needs-stop");
        ASSERT_STREQ(unit_marker_to_string(UNIT_MARKER_NEEDS_START), "needs-start");
}

TEST(unit_marker_from_string) {
        ASSERT_EQ(unit_marker_from_string("needs-reload"), UNIT_MARKER_NEEDS_RELOAD);
        ASSERT_EQ(unit_marker_from_string("needs-restart"), UNIT_MARKER_NEEDS_RESTART);
        ASSERT_EQ(unit_marker_from_string("needs-stop"), UNIT_MARKER_NEEDS_STOP);
        ASSERT_EQ(unit_marker_from_string("needs-start"), UNIT_MARKER_NEEDS_START);
        ASSERT_EQ(unit_marker_from_string("invalid"), _UNIT_MARKER_INVALID);
}

TEST(exec_directory_type_to_string) {
        ASSERT_STREQ(exec_directory_type_to_string(EXEC_DIRECTORY_RUNTIME), "RuntimeDirectory");
        ASSERT_STREQ(exec_directory_type_to_string(EXEC_DIRECTORY_STATE), "StateDirectory");
        ASSERT_STREQ(exec_directory_type_to_string(EXEC_DIRECTORY_CACHE), "CacheDirectory");
        ASSERT_STREQ(exec_directory_type_to_string(EXEC_DIRECTORY_LOGS), "LogsDirectory");
        ASSERT_STREQ(exec_directory_type_to_string(EXEC_DIRECTORY_CONFIGURATION), "ConfigurationDirectory");
}

TEST(exec_directory_type_from_string) {
        ASSERT_EQ(exec_directory_type_from_string("RuntimeDirectory"), EXEC_DIRECTORY_RUNTIME);
        ASSERT_EQ(exec_directory_type_from_string("StateDirectory"), EXEC_DIRECTORY_STATE);
        ASSERT_EQ(exec_directory_type_from_string("CacheDirectory"), EXEC_DIRECTORY_CACHE);
        ASSERT_EQ(exec_directory_type_from_string("LogsDirectory"), EXEC_DIRECTORY_LOGS);
        ASSERT_EQ(exec_directory_type_from_string("ConfigurationDirectory"), EXEC_DIRECTORY_CONFIGURATION);
        ASSERT_EQ(exec_directory_type_from_string("invalid"), _EXEC_DIRECTORY_TYPE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
