/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "env-util.h"
#include "serialize.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"

TEST(deserialize_usec) {
        usec_t usec;
        ASSERT_OK(deserialize_usec("0", &usec));
        ASSERT_EQ(usec, UINT64_C(0));
        ASSERT_OK(deserialize_usec("123456789", &usec));
        ASSERT_EQ(usec, UINT64_C(123456789));
        ASSERT_OK(deserialize_usec("18446744073709551615", &usec));
        ASSERT_EQ(usec, UINT64_MAX);
        /* Negative values return error (ERANGE for unsigned parsing) */
        ASSERT_LT(deserialize_usec("-1", &usec), 0);
        ASSERT_EQ(deserialize_usec("abc", &usec), -EINVAL);
}

TEST(deserialize_dual_timestamp) {
        dual_timestamp ts;
        ASSERT_OK(deserialize_dual_timestamp("100 200", &ts));
        ASSERT_EQ(ts.realtime, UINT64_C(100));
        ASSERT_EQ(ts.monotonic, UINT64_C(200));

        /* Leading whitespace should be OK */
        ASSERT_OK(deserialize_dual_timestamp(" 100 200", &ts));
        ASSERT_EQ(ts.realtime, UINT64_C(100));

        /* Negative values are invalid */
        ASSERT_EQ(deserialize_dual_timestamp("-1 200", &ts), -EINVAL);
        ASSERT_EQ(deserialize_dual_timestamp("100 -200", &ts), -EINVAL);
}

TEST(deserialize_strv) {
        _cleanup_strv_free_ char **l = NULL;
        /* deserialize_strv stores the entire unescaped string as a single strv entry */
        ASSERT_OK(deserialize_strv("hello", &l));
        ASSERT_NOT_NULL(l);
        ASSERT_STREQ(l[0], "hello");
        ASSERT_NULL(l[1]);

        /* Empty string produces single empty string entry */
        l = strv_free(l);
        ASSERT_OK(deserialize_strv("", &l));
        ASSERT_NOT_NULL(l);
        ASSERT_STREQ(l[0], "");
        ASSERT_NULL(l[1]);

        /* Backslash-n is unescaped to newline */
        l = strv_free(l);
        ASSERT_OK(deserialize_strv("line1\\nline2", &l));
        ASSERT_NOT_NULL(l);
        ASSERT_STREQ(l[0], "line1\nline2");
}

TEST(deserialize_environment) {
        _cleanup_strv_free_ char **l = NULL;
        /* deserialize_environment processes one env var at a time */
        ASSERT_OK(deserialize_environment("HOME=/home/user", &l));
        ASSERT_NOT_NULL(strv_env_get(l, "HOME"));
        ASSERT_STREQ(strv_env_get(l, "HOME"), "/home/user");

        /* Replace existing value */
        ASSERT_OK(deserialize_environment("HOME=/root", &l));
        ASSERT_STREQ(strv_env_get(l, "HOME"), "/root");

        /* Add another variable */
        ASSERT_OK(deserialize_environment("PATH=/usr/bin", &l));
        ASSERT_NOT_NULL(strv_env_get(l, "PATH"));
        ASSERT_STREQ(strv_env_get(l, "PATH"), "/usr/bin");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
