/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "exec-util.h"
#include "tests.h"

TEST(exec_command_flags_to_string) {
        ASSERT_STREQ(exec_command_flags_to_string(EXEC_COMMAND_IGNORE_FAILURE), "ignore-failure");
        ASSERT_STREQ(exec_command_flags_to_string(EXEC_COMMAND_FULLY_PRIVILEGED), "privileged");
        ASSERT_STREQ(exec_command_flags_to_string(EXEC_COMMAND_NO_SETUID), "no-setuid");
        ASSERT_STREQ(exec_command_flags_to_string(EXEC_COMMAND_NO_ENV_EXPAND), "no-env-expand");
        ASSERT_STREQ(exec_command_flags_to_string(EXEC_COMMAND_VIA_SHELL), "via-shell");
        /* No flags set returns NULL */
        ASSERT_NULL(exec_command_flags_to_string(0));
}

TEST(exec_command_flags_from_string) {
        ASSERT_EQ(exec_command_flags_from_string("ignore-failure"), EXEC_COMMAND_IGNORE_FAILURE);
        ASSERT_EQ(exec_command_flags_from_string("privileged"), EXEC_COMMAND_FULLY_PRIVILEGED);
        ASSERT_EQ(exec_command_flags_from_string("no-setuid"), EXEC_COMMAND_NO_SETUID);
        ASSERT_EQ(exec_command_flags_from_string("no-env-expand"), EXEC_COMMAND_NO_ENV_EXPAND);
        ASSERT_EQ(exec_command_flags_from_string("via-shell"), EXEC_COMMAND_VIA_SHELL);
        ASSERT_EQ(exec_command_flags_from_string("invalid"), _EXEC_COMMAND_FLAGS_INVALID);
        /* "ambient" is a compatibility alias that maps to 0 */
        ASSERT_EQ(exec_command_flags_from_string("ambient"), 0);
}

TEST(exec_command_flags_from_strv) {
        ExecCommandFlags flags;
        char *a = (char*)"ignore-failure", *b = (char*)"privileged";
        char *opts[] = { a, b, NULL };
        ASSERT_OK(exec_command_flags_from_strv(opts, &flags));
        ASSERT_TRUE(FLAGS_SET(flags, EXEC_COMMAND_IGNORE_FAILURE));
        ASSERT_TRUE(FLAGS_SET(flags, EXEC_COMMAND_FULLY_PRIVILEGED));

        /* Empty strv */
        char *empty[] = { NULL };
        ASSERT_OK(exec_command_flags_from_strv(empty, &flags));
        ASSERT_EQ(flags, 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
