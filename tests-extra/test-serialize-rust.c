/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C deserialize_usec/deserialize_dual_timestamp vs Rust */

#include <string.h>
#include "tests.h"
#include "time-util.h"
#include "serialize.h"

/* Rust FFI */
#include "rust/serialize.h"

static void test_deserialize_usec(void) {
        usec_t cr, rr;
        int c_ret, r_ret;

        /* Simple value */
        c_ret = deserialize_usec("12345", &cr);
        r_ret = rs_deserialize_usec("12345", &rr);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(cr == rr);
        assert_se(cr == 12345);

        /* Zero */
        c_ret = deserialize_usec("0", &cr);
        r_ret = rs_deserialize_usec("0", &rr);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(cr == rr);
        assert_se(cr == 0);

        /* Large value */
        c_ret = deserialize_usec("18446744073709551615", &cr);
        r_ret = rs_deserialize_usec("18446744073709551615", &rr);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(cr == rr);

        /* Leading zeros: safe_atou64 uses base=0, so "0123" is octal (83 decimal) */
        c_ret = deserialize_usec("00000123", &cr);
        r_ret = rs_deserialize_usec("00000123", &rr);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(cr == rr);
        assert_se(cr == 83); /* 0123 octal = 83 decimal */

        /* Invalid: not a number */
        c_ret = deserialize_usec("abc", &cr);
        r_ret = rs_deserialize_usec("abc", &rr);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Invalid: negative */
        c_ret = deserialize_usec("-1", &cr);
        r_ret = rs_deserialize_usec("-1", &rr);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Invalid: empty */
        c_ret = deserialize_usec("", &cr);
        r_ret = rs_deserialize_usec("", &rr);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Note: overflow behavior differs — C strtoull wraps, Rust detects. */
}

static void test_deserialize_dual_timestamp(void) {
        dual_timestamp ct, rt;
        int c_ret, r_ret;

        /* Simple values */
        c_ret = deserialize_dual_timestamp("100 200", &ct);
        r_ret = rs_deserialize_dual_timestamp("100 200", &rt);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(ct.realtime == rt.realtime);
        assert_se(ct.monotonic == rt.monotonic);
        assert_se(ct.realtime == 100);
        assert_se(ct.monotonic == 200);

        /* Both zero */
        c_ret = deserialize_dual_timestamp("0 0", &ct);
        r_ret = rs_deserialize_dual_timestamp("0 0", &rt);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(ct.realtime == rt.realtime);
        assert_se(ct.monotonic == rt.monotonic);

        /* Large values */
        c_ret = deserialize_dual_timestamp("18446744073709551615 18446744073709551614", &ct);
        r_ret = rs_deserialize_dual_timestamp("18446744073709551615 18446744073709551614", &rt);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(ct.realtime == rt.realtime);
        assert_se(ct.monotonic == rt.monotonic);

        /* Leading whitespace */
        c_ret = deserialize_dual_timestamp("  100 200", &ct);
        r_ret = rs_deserialize_dual_timestamp("  100 200", &rt);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(ct.realtime == rt.realtime);
        assert_se(ct.monotonic == rt.monotonic);

        /* Multiple spaces between values */
        c_ret = deserialize_dual_timestamp("100   200", &ct);
        r_ret = rs_deserialize_dual_timestamp("100   200", &rt);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(ct.realtime == rt.realtime);
        assert_se(ct.monotonic == rt.monotonic);

        /* Leading zeros */
        c_ret = deserialize_dual_timestamp("00100 00200", &ct);
        r_ret = rs_deserialize_dual_timestamp("00100 00200", &rt);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);
        assert_se(ct.realtime == rt.realtime);
        assert_se(ct.monotonic == rt.monotonic);

        /* Invalid: negative first number */
        c_ret = deserialize_dual_timestamp("-100 200", &ct);
        r_ret = rs_deserialize_dual_timestamp("-100 200", &rt);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Invalid: negative second number */
        c_ret = deserialize_dual_timestamp("100 -200", &ct);
        r_ret = rs_deserialize_dual_timestamp("100 -200", &rt);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Invalid: trailing garbage */
        c_ret = deserialize_dual_timestamp("100 200 abc", &ct);
        r_ret = rs_deserialize_dual_timestamp("100 200 abc", &rt);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Invalid: only one number */
        c_ret = deserialize_dual_timestamp("100", &ct);
        r_ret = rs_deserialize_dual_timestamp("100", &rt);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Invalid: empty */
        c_ret = deserialize_dual_timestamp("", &ct);
        r_ret = rs_deserialize_dual_timestamp("", &rt);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Invalid: not a number */
        c_ret = deserialize_dual_timestamp("abc def", &ct);
        r_ret = rs_deserialize_dual_timestamp("abc def", &rt);
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Note: overflow behavior differs — C sscanf wraps silently,
         * Rust detects overflow. Not tested for shadow comparison. */
}

int main(int argc, char **argv) {
        test_deserialize_usec();
        test_deserialize_dual_timestamp();
        return 0;
}
