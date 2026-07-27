/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: additional parse-util functions vs Rust */

#include <assert.h>
#include <errno.h>
#include "tests.h"
#include "parse-util.h"
#include "rust/parse_util.h"
#include "rust/string_util.h"

static void test_parse_oom_score_adjust(void) {
        int v;

        assert_se(parse_oom_score_adjust("0", &v) == rs_parse_oom_score_adjust("0", &v));
        assert_se(v == 0);

        assert_se(parse_oom_score_adjust("-1000", &v) == rs_parse_oom_score_adjust("-1000", &v));
        assert_se(v == -1000);

        assert_se(parse_oom_score_adjust("1000", &v) == rs_parse_oom_score_adjust("1000", &v));
        assert_se(v == 1000);

        assert_se(parse_oom_score_adjust("500", &v) == rs_parse_oom_score_adjust("500", &v));
        assert_se(v == 500);

        /* Out of range */
        assert_se(parse_oom_score_adjust("-1001", &v) == rs_parse_oom_score_adjust("-1001", &v));
        assert_se(parse_oom_score_adjust("1001", &v) == rs_parse_oom_score_adjust("1001", &v));

        /* Invalid */
        assert_se(parse_oom_score_adjust("abc", &v) == rs_parse_oom_score_adjust("abc", &v));
}

static void test_parse_ip_port_range(void) {
        uint16_t lo, hi;

        assert_se(parse_ip_port_range("80-443", &lo, &hi, false) == rs_parse_ip_port_range("80-443", &lo, &hi, false));
        assert_se(lo == 80 && hi == 443);

        assert_se(parse_ip_port_range("80", &lo, &hi, false) == rs_parse_ip_port_range("80", &lo, &hi, false));
        assert_se(lo == 80 && hi == 80);

        /* Zero port not allowed */
        assert_se(parse_ip_port_range("0-80", &lo, &hi, false) == rs_parse_ip_port_range("0-80", &lo, &hi, false));

        /* Zero port allowed */
        assert_se(parse_ip_port_range("0-80", &lo, &hi, true) == rs_parse_ip_port_range("0-80", &lo, &hi, true));

        /* Out of range */
        assert_se(parse_ip_port_range("80-70000", &lo, &hi, false) == rs_parse_ip_port_range("80-70000", &lo, &hi, false));

        /* high < low */
        assert_se(parse_ip_port_range("443-80", &lo, &hi, false) == rs_parse_ip_port_range("443-80", &lo, &hi, false));

        /* Invalid */
        assert_se(parse_ip_port_range("abc", &lo, &hi, false) == rs_parse_ip_port_range("abc", &lo, &hi, false));
}

static void test_strrep(void) {
        char *c_r, *rs_r;

        c_r = strrep("ab", 3);
        rs_r = rs_strrep("ab", 3);
        assert_se(streq(c_r, rs_r));
        free(c_r);
        free(rs_r);

        c_r = strrep("x", 0);
        rs_r = rs_strrep("x", 0);
        assert_se(streq(c_r, rs_r));
        free(c_r);
        free(rs_r);

        c_r = strrep("hello", 1);
        rs_r = rs_strrep("hello", 1);
        assert_se(streq(c_r, rs_r));
        free(c_r);
        free(rs_r);

        c_r = strrep("", 5);
        rs_r = rs_strrep("", 5);
        assert_se(streq(c_r, rs_r));
        free(c_r);
        free(rs_r);
}

int main(int argc, char **argv) {
        test_parse_oom_score_adjust();
        test_parse_ip_port_range();
        test_strrep();
        return 0;
}
