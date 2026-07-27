/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "argv-util.h"
#include "tests.h"

TEST(invoked_as) {
        char *argv0[] = { (char*)"/usr/bin/systemctl", NULL };
        ASSERT_TRUE(invoked_as(argv0, "systemctl"));
        ASSERT_FALSE(invoked_as(argv0, "journalctl"));

        char *argv1[] = { (char*)"./mytool", NULL };
        ASSERT_TRUE(invoked_as(argv1, "mytool"));
        ASSERT_FALSE(invoked_as(argv1, "other"));
        ASSERT_FALSE(invoked_as(NULL, "tool"));
}

TEST(argv_looks_like_help) {
        char *argv_no_help[] = { (char*)"tool", (char*)"arg1", NULL };
        ASSERT_FALSE(argv_looks_like_help(2, argv_no_help));

        char *argv_help[] = { (char*)"tool", (char*)"--help", NULL };
        ASSERT_TRUE(argv_looks_like_help(2, argv_help));

        char *argv_empty[] = { (char*)"tool", NULL };
        ASSERT_TRUE(argv_looks_like_help(1, argv_empty));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
