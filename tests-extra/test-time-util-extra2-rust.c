/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: timestamp_is_set, dual_timestamp_is_set, triple_timestamp_is_set,
 * usec_add, usec_sub_unsigned, usec_sub_signed */

#include <assert.h>
#include <string.h>

#include "rust/time_util.h"
#include "tests.h"
#include "time-util.h"

static void test_timestamp_is_set(void) {
        assert_se(timestamp_is_set(100) == rs_timestamp_is_set(100));
        assert_se(timestamp_is_set(0) == rs_timestamp_is_set(0));
        assert_se(timestamp_is_set(USEC_INFINITY) == rs_timestamp_is_set(USEC_INFINITY));
}

static void test_dual_timestamp_is_set(void) {
        dual_timestamp ts;

        zero(ts);
        assert_se(dual_timestamp_is_set(&ts) == rs_dual_timestamp_is_set(&ts));

        ts.realtime = 100;
        assert_se(dual_timestamp_is_set(&ts) == rs_dual_timestamp_is_set(&ts));

        ts.monotonic = USEC_INFINITY;
        assert_se(dual_timestamp_is_set(&ts) == rs_dual_timestamp_is_set(&ts));

        ts.realtime = 0;
        assert_se(dual_timestamp_is_set(&ts) == rs_dual_timestamp_is_set(&ts));

        ts.monotonic = 0;
        assert_se(dual_timestamp_is_set(&ts) == rs_dual_timestamp_is_set(&ts));

        /* NULL — only test Rust side, C would crash (UB) */
        assert_se(!rs_dual_timestamp_is_set(NULL));
}

static void test_triple_timestamp_is_set(void) {
        triple_timestamp ts;

        zero(ts);
        assert_se(triple_timestamp_is_set(&ts) == rs_triple_timestamp_is_set(&ts));

        ts.realtime = 100;
        assert_se(triple_timestamp_is_set(&ts) == rs_triple_timestamp_is_set(&ts));

        ts.monotonic = USEC_INFINITY;
        assert_se(triple_timestamp_is_set(&ts) == rs_triple_timestamp_is_set(&ts));

        ts.boottime = 50;
        assert_se(triple_timestamp_is_set(&ts) == rs_triple_timestamp_is_set(&ts));

        ts.realtime = 0;
        ts.monotonic = 0;
        assert_se(triple_timestamp_is_set(&ts) == rs_triple_timestamp_is_set(&ts));

        ts.boottime = 0;
        assert_se(triple_timestamp_is_set(&ts) == rs_triple_timestamp_is_set(&ts));

        /* NULL — only test Rust side, C would crash (UB) */
        assert_se(!rs_triple_timestamp_is_set(NULL));
}

static void test_usec_add(void) {
        assert_se(usec_add(100, 200) == rs_usec_add(100, 200));
        assert_se(usec_add(0, 0) == rs_usec_add(0, 0));
        assert_se(usec_add(USEC_INFINITY, 100) == rs_usec_add(USEC_INFINITY, 100));
        assert_se(usec_add(100, USEC_INFINITY) == rs_usec_add(100, USEC_INFINITY));
        assert_se(usec_add(USEC_INFINITY, USEC_INFINITY) == rs_usec_add(USEC_INFINITY, USEC_INFINITY));
        /* Overflow case */
        assert_se(usec_add(UINT64_MAX, 1) == rs_usec_add(UINT64_MAX, 1));
}

static void test_usec_sub_unsigned(void) {
        assert_se(usec_sub_unsigned(500, 100) == rs_usec_sub_unsigned(500, 100));
        assert_se(usec_sub_unsigned(100, 100) == rs_usec_sub_unsigned(100, 100));
        assert_se(usec_sub_unsigned(50, 100) == rs_usec_sub_unsigned(50, 100));
        assert_se(usec_sub_unsigned(0, 0) == rs_usec_sub_unsigned(0, 0));
        assert_se(usec_sub_unsigned(USEC_INFINITY, 100) == rs_usec_sub_unsigned(USEC_INFINITY, 100));
        assert_se(usec_sub_unsigned(USEC_INFINITY, USEC_INFINITY) == rs_usec_sub_unsigned(USEC_INFINITY, USEC_INFINITY));
}

static void test_usec_sub_signed(void) {
        assert_se(usec_sub_signed(500, 100) == rs_usec_sub_signed(500, 100));
        assert_se(usec_sub_signed(500, -100) == rs_usec_sub_signed(500, -100));
        assert_se(usec_sub_signed(50, 100) == rs_usec_sub_signed(50, 100));
        assert_se(usec_sub_signed(USEC_INFINITY, 100) == rs_usec_sub_signed(USEC_INFINITY, 100));
        assert_se(usec_sub_signed(USEC_INFINITY, -100) == rs_usec_sub_signed(USEC_INFINITY, -100));
        assert_se(usec_sub_signed(USEC_INFINITY, USEC_INFINITY) == rs_usec_sub_signed(USEC_INFINITY, USEC_INFINITY));
        /* INT64_MIN case: -(INT64_MIN + 1) == INT64_MAX */
        assert_se(usec_sub_signed(100, INT64_MIN) == rs_usec_sub_signed(100, INT64_MIN));
}

int main(int argc, char **argv) {
        test_timestamp_is_set();
        test_dual_timestamp_is_set();
        test_triple_timestamp_is_set();
        test_usec_add();
        test_usec_sub_unsigned();
        test_usec_sub_signed();
        return 0;
}
