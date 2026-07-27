/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "strv.h"
#include "tests.h"

TEST(strv_fnmatch) {
        _cleanup_strv_free_ char **patterns = NULL;

        patterns = strv_new((char*) "*.service", (char*) "*.target");
        ASSERT_NOT_NULL(patterns);

        ASSERT_TRUE(strv_fnmatch(patterns, "foo.service"));
        ASSERT_TRUE(strv_fnmatch(patterns, "multi-user.target"));
        ASSERT_FALSE(strv_fnmatch(patterns, "foo.socket"));
}

TEST(strv_overlap) {
        _cleanup_strv_free_ char **a = NULL, **b = NULL;

        a = strv_new((char*) "foo", (char*) "bar");
        b = strv_new((char*) "bar", (char*) "baz");
        ASSERT_NOT_NULL(a);
        ASSERT_NOT_NULL(b);

        /* Common element "bar" */
        ASSERT_TRUE(strv_overlap(a, b));

        _cleanup_strv_free_ char **c = strv_new((char*) "one", (char*) "two");
        ASSERT_NOT_NULL(c);

        /* No common elements */
        ASSERT_FALSE(strv_overlap(a, c));

        /* Empty */
        ASSERT_FALSE(strv_overlap(a, NULL));
        ASSERT_FALSE(strv_overlap(NULL, a));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
