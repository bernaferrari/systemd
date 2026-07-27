/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nulstr-util.h"
#include "strv.h"
#include "tests.h"

TEST(nulstr_get) {
        /* NUL-separated string: "foo\0bar\0baz\0" */
        const char nulstr[] = "foo\0bar\0baz\0";
        ASSERT_NOT_NULL(nulstr_get(nulstr, "foo"));
        ASSERT_NOT_NULL(nulstr_get(nulstr, "bar"));
        ASSERT_NOT_NULL(nulstr_get(nulstr, "baz"));
        ASSERT_NULL(nulstr_get(nulstr, "qux"));
        ASSERT_NULL(nulstr_get(nulstr, ""));
}

TEST(strv_split_nulstr) {
        _cleanup_strv_free_ char **l = NULL;
        /* NUL-separated string: "one\0two\0three\0" */
        const char s[] = "one\0two\0three\0";
        l = strv_split_nulstr(s);
        ASSERT_NOT_NULL(l);
        ASSERT_STREQ(l[0], "one");
        ASSERT_STREQ(l[1], "two");
        ASSERT_STREQ(l[2], "three");
        ASSERT_NULL(l[3]);
}

TEST(strv_make_nulstr) {
        _cleanup_free_ char *nulstr = NULL;
        size_t sz = 0;
        char *a = (char*)"x", *b = (char*)"y", *c = (char*)"z";
        char *l[] = { a, b, c, NULL };
        ASSERT_OK(strv_make_nulstr(l, &nulstr, &sz));
        ASSERT_NOT_NULL(nulstr);
        /* "x\0y\0z\0" = 6 bytes */
        ASSERT_EQ(sz, 6u);
        ASSERT_STREQ(nulstr, "x");
        ASSERT_STREQ(nulstr + 2, "y");
        ASSERT_STREQ(nulstr + 4, "z");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
