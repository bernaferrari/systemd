/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "path-util.h"
#include "tests.h"

TEST(path_startswith) {
        const char *r;

        r = path_startswith("/usr/bin/foo", "/usr/");
        ASSERT_NOT_NULL(r);
        ASSERT_STREQ(r, "bin/foo");

        r = path_startswith("/usr/bin/foo", "/usr/bin/foo");
        ASSERT_NOT_NULL(r);
        ASSERT_STREQ(r, "");

        ASSERT_NULL(path_startswith("/usr/bin/foo", "/var/"));

        /* Empty prefix */
        r = path_startswith("/foo", "");
        /* Empty prefix may or may not match depending on implementation */
        ASSERT_NULL(path_startswith("/foo/bar", "/foo/bar/baz"));
}

TEST(path_startswith_strv) {
        const char *r;
        char *prefixes[] = { (char*)"/usr/", (char*)"/var/", (char*)"/opt/", NULL };

        r = path_startswith_strv("/usr/bin/foo", prefixes);
        ASSERT_NOT_NULL(r);
        ASSERT_STREQ(r, "bin/foo");

        r = path_startswith_strv("/var/log/syslog", prefixes);
        ASSERT_NOT_NULL(r);
        ASSERT_STREQ(r, "log/syslog");

        ASSERT_NULL(path_startswith_strv("/tmp/foo", prefixes));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
