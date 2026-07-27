/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "fd-util.h"
#include "ratelimit.h"
#include "serialize.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "time-util.h"

TEST(deserialize_usec) {
        usec_t val;

        assert_se(deserialize_usec("1000000", &val) == 0);
        assert_se(val == 1000000);

        assert_se(deserialize_usec("0", &val) == 0);
        assert_se(val == 0);

        assert_se(deserialize_usec("18446744073709551615", &val) == 0);
        assert_se(val == UINT64_MAX);

        assert_se(deserialize_usec("invalid", &val) < 0);
        assert_se(deserialize_usec("", &val) < 0);
        assert_se(deserialize_usec("-1", &val) < 0);
}

TEST(deserialize_dual_timestamp) {
        dual_timestamp ts;

        assert_se(deserialize_dual_timestamp("1000 2000", &ts) == 0);
        assert_se(ts.realtime == 1000);
        assert_se(ts.monotonic == 2000);

        assert_se(deserialize_dual_timestamp("0 0", &ts) == 0);
        assert_se(ts.realtime == 0);
        assert_se(ts.monotonic == 0);

        /* Leading whitespace is fine */
        assert_se(deserialize_dual_timestamp("  100 200", &ts) == 0);
        assert_se(ts.realtime == 100);
        assert_se(ts.monotonic == 200);

        /* Negative values rejected */
        assert_se(deserialize_dual_timestamp("-1 200", &ts) == -EINVAL);
        assert_se(deserialize_dual_timestamp("100 -200", &ts) == -EINVAL);

        /* Invalid formats */
        assert_se(deserialize_dual_timestamp("invalid", &ts) < 0);
        assert_se(deserialize_dual_timestamp("", &ts) < 0);
        assert_se(deserialize_dual_timestamp("100", &ts) < 0);
        assert_se(deserialize_dual_timestamp("100 200 garbage", &ts) == -EINVAL);
}

TEST(deserialize_strv_basic) {
        _cleanup_strv_free_ char **l = NULL;

        assert_se(deserialize_strv("hello", &l) == 0);
        assert_se(strv_length(l) == 1);
        assert_se(streq(l[0], "hello"));

        /* Appending to existing strv */
        assert_se(deserialize_strv("world", &l) == 0);
        assert_se(strv_length(l) == 2);
        assert_se(streq(l[1], "world"));

        /* Empty string results in an empty entry */
        l = strv_free(l);
        assert_se(deserialize_strv("", &l) == 0);
        assert_se(strv_length(l) == 1);
}

TEST(deserialize_environment_basic) {
        _cleanup_strv_free_ char **list = NULL;

        assert_se(deserialize_environment("FOO=bar", &list) == 0);
        assert_se(strv_length(list) == 1);
        assert_se(streq(list[0], "FOO=bar"));

        /* Adding another variable */
        assert_se(deserialize_environment("BAZ=qux", &list) == 0);
        assert_se(strv_length(list) == 2);

        /* Overwrite existing */
        assert_se(deserialize_environment("FOO=updated", &list) == 0);
        assert_se(strv_length(list) == 2);
        assert_se(streq(list[0], "FOO=updated"));
}

TEST(deserialize_ratelimit_basic) {
        RateLimit rl = {
                .interval = 100 * USEC_PER_SEC,
                .burst = 5,
        };

        /* Same config: counter preserved */
        deserialize_ratelimit(&rl, "test", "50000000 100000000 3 5");
        assert_se(rl.begin == 50000000);
        assert_se(rl.num == 3);
        assert_se(rl.interval == 100000000);
        assert_se(rl.burst == 5);

        /* Config changed: counter reset to 0 */
        rl = (RateLimit) {
                .interval = 100 * USEC_PER_SEC,
                .burst = 5,
        };
        deserialize_ratelimit(&rl, "test", "60000000 200000000 3 10");
        assert_se(rl.begin == 60000000);
        assert_se(rl.num == 0); /* reset because interval/burst changed */
}

TEST(deserialize_read_line) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *line = NULL;

        f = tmpfile();
        assert_se(f);
        fputs("hello=world\n\nfoo=bar\n", f);
        fflush(f);
        rewind(f);

        assert_se(deserialize_read_line(f, &line) == 1);
        assert_se(streq(line, "hello=world"));

        assert_se(deserialize_read_line(f, &line) == 0); /* empty line = end marker */
        assert_se(line == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
