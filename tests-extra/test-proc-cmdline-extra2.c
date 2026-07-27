/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "proc-cmdline.h"
#include "tests.h"

TEST(proc_cmdline_key_streq) {
        /* Exact match */
        ASSERT_TRUE(proc_cmdline_key_streq("foo", "foo"));

        /* Hyphen/underscore equivalence */
        ASSERT_TRUE(proc_cmdline_key_streq("foo-bar", "foo_bar"));
        ASSERT_TRUE(proc_cmdline_key_streq("foo_bar", "foo-bar"));

        /* Different */
        ASSERT_FALSE(proc_cmdline_key_streq("foo", "bar"));
        ASSERT_FALSE(proc_cmdline_key_streq("foo", "fooo"));

        /* Empty */
        ASSERT_TRUE(proc_cmdline_key_streq("", ""));
}

TEST(proc_cmdline_value_missing) {
        /* NULL value is "missing" */
        ASSERT_TRUE(proc_cmdline_value_missing("mykey", NULL));

        /* Non-NULL value is not "missing" */
        ASSERT_FALSE(proc_cmdline_value_missing("mykey", "myvalue"));
        ASSERT_FALSE(proc_cmdline_value_missing("mykey", ""));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
