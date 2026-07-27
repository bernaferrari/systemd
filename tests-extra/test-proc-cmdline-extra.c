/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "proc-cmdline.h"
#include "tests.h"

TEST(proc_cmdline_key_streq) {
        ASSERT_TRUE(proc_cmdline_key_streq("foo", "foo"));
        ASSERT_TRUE(proc_cmdline_key_streq("foo_bar", "foo-bar"));
        ASSERT_TRUE(proc_cmdline_key_streq("foo-bar", "foo_bar"));
        ASSERT_FALSE(proc_cmdline_key_streq("foo", "bar"));
        ASSERT_FALSE(proc_cmdline_key_streq("foo_bar", "foo"));
}

TEST(proc_cmdline_key_startswith) {
        const char *r;

        r = proc_cmdline_key_startswith("foo_bar=baz", "foo_bar");
        ASSERT_NOT_NULL(r);
        ASSERT_STREQ(r, "=baz");

        r = proc_cmdline_key_startswith("foo-bar=baz", "foo_bar");
        ASSERT_NOT_NULL(r);
        ASSERT_STREQ(r, "=baz");

        r = proc_cmdline_key_startswith("foo_bar=baz", "foo-bar");
        ASSERT_NOT_NULL(r);
        ASSERT_STREQ(r, "=baz");

        r = proc_cmdline_key_startswith("foobar", "foo");
        ASSERT_NOT_NULL(r);
        ASSERT_STREQ(r, "bar");

        r = proc_cmdline_key_startswith("bar", "foo");
        ASSERT_NULL(r);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
