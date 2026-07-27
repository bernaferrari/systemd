/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "serialize.h"
#include "time-util.h"

TEST(deserialize_usec) {
        usec_t val;

        assert_se(deserialize_usec("1000000", &val) == 0);
        assert_se(val == 1000000);

        assert_se(deserialize_usec("0", &val) == 0);
        assert_se(val == 0);

        /* Invalid */
        assert_se(deserialize_usec("notanumber", &val) < 0);
        assert_se(deserialize_usec("", &val) < 0);
}

TEST(deserialize_dual_timestamp) {
        dual_timestamp ts;

        /* Valid: two numbers separated by whitespace */
        assert_se(deserialize_dual_timestamp("1000 2000", &ts) == 0);
        assert_se(ts.realtime == 1000);
        assert_se(ts.monotonic == 2000);

        /* Leading whitespace OK */
        assert_se(deserialize_dual_timestamp("  100 200", &ts) == 0);
        assert_se(ts.realtime == 100);
        assert_se(ts.monotonic == 200);

        /* Negative values rejected */
        assert_se(deserialize_dual_timestamp("-1 200", &ts) < 0);
        assert_se(deserialize_dual_timestamp("100 -1", &ts) < 0);

        /* Trailing garbage rejected */
        assert_se(deserialize_dual_timestamp("100 200abc", &ts) < 0);

        /* Only one number */
        assert_se(deserialize_dual_timestamp("100", &ts) < 0);

        /* Empty */
        assert_se(deserialize_dual_timestamp("", &ts) < 0);
}

TEST(deserialize_strv) {
        _cleanup_strv_free_ char **l = NULL;

        /* Simple string */
        assert_se(deserialize_strv("hello", &l) == 0);
        assert_se(strv_length(l) == 1);
        assert_se(streq(l[0], "hello"));

        /* Escaped string (space) */
        assert_se(deserialize_strv("hello\\040world", &l) == 0);
        assert_se(strv_length(l) == 2);
        assert_se(streq(l[1], "hello world"));
}

TEST(deserialize_environment) {
        _cleanup_strv_free_ char **list = NULL;

        /* Set a variable */
        assert_se(deserialize_environment("PATH=/usr/bin", &list) == 0);
        assert_se(strv_length(list) == 1);
        assert_se(streq(list[0], "PATH=/usr/bin"));

        /* Replace it */
        assert_se(deserialize_environment("PATH=/usr/sbin", &list) == 0);
        assert_se(strv_length(list) == 1);
        assert_se(streq(list[0], "PATH=/usr/sbin"));

        /* Add another */
        assert_se(deserialize_environment("HOME=/root", &list) == 0);
        assert_se(strv_length(list) == 2);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
