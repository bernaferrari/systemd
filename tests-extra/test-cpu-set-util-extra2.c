/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cpu-set-util.h"
#include "string-util.h"
#include "tests.h"

TEST(cpu_set_add_and_to_string) {
        _cleanup_(cpu_set_done) CPUSet c = {};
        _cleanup_free_ char *str = NULL;

        assert_se(cpu_set_add(&c, 0) >= 0);
        assert_se(cpu_set_add(&c, 1) >= 0);
        assert_se(cpu_set_add(&c, 3) >= 0);

        str = cpu_set_to_string(&c);
        assert_se(str);
        assert_se(streq(str, "0 1 3"));
}

TEST(cpu_set_to_range_string) {
        _cleanup_(cpu_set_done) CPUSet c = {};
        _cleanup_free_ char *str = NULL;

        assert_se(cpu_set_add(&c, 0) >= 0);
        assert_se(cpu_set_add(&c, 1) >= 0);
        assert_se(cpu_set_add(&c, 2) >= 0);
        assert_se(cpu_set_add(&c, 5) >= 0);

        str = cpu_set_to_range_string(&c);
        assert_se(str);
        assert_se(streq(str, "0-2 5"));
}

TEST(parse_cpu_set) {
        _cleanup_(cpu_set_done) CPUSet c = {};
        _cleanup_free_ char *str = NULL;
        int r;

        r = parse_cpu_set("0 1 2", &c);
        assert_se(r >= 0);

        str = cpu_set_to_string(&c);
        assert_se(str);
        assert_se(streq(str, "0 1 2"));
        str = mfree(str);

        c = (CPUSet) {};
        r = parse_cpu_set("0-3", &c);
        assert_se(r >= 0);

        str = cpu_set_to_string(&c);
        assert_se(str);
        assert_se(streq(str, "0 1 2 3"));
}

TEST(cpu_set_add_all) {
        _cleanup_(cpu_set_done) CPUSet c = {};

        assert_se(cpu_set_add_all(&c) >= 0);
        /* Should have at least one CPU */
        assert_se(c.allocated > 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
