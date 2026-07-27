/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "env-util.h"
#include "tests.h"

TEST(env_name_is_valid) {
        /* Valid names */
        ASSERT_TRUE(env_name_is_valid("FOO"));
        ASSERT_TRUE(env_name_is_valid("foo"));
        ASSERT_TRUE(env_name_is_valid("FOO_BAR"));
        ASSERT_TRUE(env_name_is_valid("_FOO"));
        ASSERT_TRUE(env_name_is_valid("A"));
        ASSERT_TRUE(env_name_is_valid("PATH"));

        /* Invalid: empty */
        ASSERT_FALSE(env_name_is_valid(""));

        /* Invalid: starts with digit */
        ASSERT_FALSE(env_name_is_valid("1FOO"));

        /* Invalid: contains equals */
        ASSERT_FALSE(env_name_is_valid("FOO=BAR"));

        /* Invalid: contains space */
        ASSERT_FALSE(env_name_is_valid("FOO BAR"));
}

TEST(env_value_is_valid) {
        /* Valid values */
        ASSERT_TRUE(env_value_is_valid(""));
        ASSERT_TRUE(env_value_is_valid("hello"));
        ASSERT_TRUE(env_value_is_valid("/usr/bin"));

        /* NULL is invalid */
        ASSERT_FALSE(env_value_is_valid(NULL));
}

TEST(env_assignment_is_valid) {
        /* Valid assignments */
        ASSERT_TRUE(env_assignment_is_valid("FOO=bar"));
        ASSERT_TRUE(env_assignment_is_valid("PATH=/usr/bin"));
        ASSERT_TRUE(env_assignment_is_valid("A="));

        /* Invalid: no equals */
        ASSERT_FALSE(env_assignment_is_valid("FOO"));

        /* Invalid: empty */
        ASSERT_FALSE(env_assignment_is_valid(""));

        /* Invalid: bad name (starts with digit) */
        ASSERT_FALSE(env_assignment_is_valid("1FOO=bar"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
