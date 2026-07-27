/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "unit-name.h"
#include "tests.h"

TEST(unit_name_is_valid) {
        /* Valid service names */
        ASSERT_TRUE(unit_name_is_valid("foo.service", UNIT_NAME_PLAIN));
        ASSERT_TRUE(unit_name_is_valid("foo.service", UNIT_NAME_ANY));
        ASSERT_TRUE(unit_name_is_valid("foo-bar.service", UNIT_NAME_PLAIN));

        /* Instance names */
        ASSERT_TRUE(unit_name_is_valid("foo@bar.service", UNIT_NAME_INSTANCE));
        ASSERT_TRUE(unit_name_is_valid("foo@bar.service", UNIT_NAME_ANY));

        /* Template names */
        ASSERT_TRUE(unit_name_is_valid("foo@.service", UNIT_NAME_TEMPLATE));
        ASSERT_TRUE(unit_name_is_valid("foo@.service", UNIT_NAME_ANY));

        /* Invalid: empty */
        ASSERT_FALSE(unit_name_is_valid("", UNIT_NAME_ANY));

        /* Invalid: no suffix */
        ASSERT_FALSE(unit_name_is_valid("foo", UNIT_NAME_ANY));

        /* Invalid: wrong suffix */
        ASSERT_FALSE(unit_name_is_valid("foo.wrong", UNIT_NAME_ANY));

        /* Invalid: starts with dot */
        ASSERT_FALSE(unit_name_is_valid(".service", UNIT_NAME_PLAIN));

        /* Invalid: flags=0 */
        ASSERT_FALSE(unit_name_is_valid("foo.service", 0));

        /* Valid socket, target, mount names */
        ASSERT_TRUE(unit_name_is_valid("foo.socket", UNIT_NAME_PLAIN));
        ASSERT_TRUE(unit_name_is_valid("multi-user.target", UNIT_NAME_PLAIN));
        ASSERT_TRUE(unit_name_is_valid("home.mount", UNIT_NAME_PLAIN));
}

TEST(unit_name_to_prefix) {
        _cleanup_free_ char *prefix = NULL;

        /* Plain unit */
        ASSERT_OK(unit_name_to_prefix("foo.service", &prefix));
        ASSERT_STREQ(prefix, "foo");

        prefix = mfree(prefix);
        /* Instance unit */
        ASSERT_OK(unit_name_to_prefix("foo@bar.service", &prefix));
        ASSERT_STREQ(prefix, "foo");

        prefix = mfree(prefix);
        /* Template unit */
        ASSERT_OK(unit_name_to_prefix("foo@.service", &prefix));
        ASSERT_STREQ(prefix, "foo");

        /* Invalid unit name */
        prefix = mfree(prefix);
        ASSERT_EQ(unit_name_to_prefix("invalid", &prefix), -EINVAL);
}

TEST(unit_name_from_path) {
        _cleanup_free_ char *name = NULL;

        ASSERT_OK(unit_name_from_path("/home", ".mount", &name));
        ASSERT_STREQ(name, "home.mount");

        name = mfree(name);
        ASSERT_OK(unit_name_from_path("/var/log", ".mount", &name));
        ASSERT_TRUE(endswith(name, ".mount"));
}

TEST(unit_name_path_escape) {
        _cleanup_free_ char *escaped = NULL;

        ASSERT_OK(unit_name_path_escape("/home/user", &escaped));
        /* Path should be escaped with - separators */
        ASSERT_TRUE(!startswith(escaped, "/"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
