/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "serialize.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"

TEST(deserialize_usec) {
        usec_t val = 0;
        int r;

        r = deserialize_usec("1000000", &val);
        assert_se(r >= 0);
        assert_se(val == 1000000);

        r = deserialize_usec("0", &val);
        assert_se(r >= 0);
        assert_se(val == 0);

        r = deserialize_usec("18446744073709551615", &val); /* UINT64_MAX */
        assert_se(r >= 0);
        assert_se(val == UINT64_MAX);

        /* Invalid */
        r = deserialize_usec("not_a_number", &val);
        assert_se(r < 0);

        /* Empty */
        r = deserialize_usec("", &val);
        assert_se(r < 0);
}

TEST(deserialize_strv) {
        _cleanup_strv_free_ char **sv = NULL;
        int r;

        r = deserialize_strv("hello", &sv);
        assert_se(r >= 0);
        assert_se(strv_length(sv) == 1);
        assert_se(streq(sv[0], "hello"));

        /* Add another */
        r = deserialize_strv("world", &sv);
        assert_se(r >= 0);
        assert_se(strv_length(sv) == 2);
        assert_se(streq(sv[1], "world"));

        /* Empty string → adds empty string to strv */
        r = deserialize_strv("", &sv);
        assert_se(r >= 0);
}

TEST(deserialize_environment) {
        _cleanup_strv_free_ char **env = NULL;
        int r;

        r = deserialize_environment("PATH=/usr/bin", &env);
        assert_se(r >= 0);
        assert_se(strv_length(env) == 1);
        assert_se(streq(env[0], "PATH=/usr/bin"));

        /* Add another */
        r = deserialize_environment("HOME=/root", &env);
        assert_se(r >= 0);
        assert_se(strv_length(env) == 2);

        /* Replace existing */
        r = deserialize_environment("PATH=/usr/local/bin", &env);
        assert_se(r >= 0);
        assert_se(strv_length(env) == 2); /* same length, replaced */
        assert_se(streq(env[0], "PATH=/usr/local/bin"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
