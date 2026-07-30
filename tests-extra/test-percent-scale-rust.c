/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C percent-util.h UINT32_SCALE macros vs Rust */

#include <assert.h>
#include <stdint.h>
#include <limits.h>
#include "tests.h"
#include "percent-util.h"
#include "rust/percent_util.h"

/* RUST-CONTRACT: percent-scale */

typedef uint32_t (*scale_from_fn_t)(int value);
typedef int (*scale_to_fn_t)(uint32_t value);

static void assert_full_scale_domain_parity(
                int maximum,
                scale_from_fn_t c_from,
                scale_from_fn_t rust_from,
                scale_to_fn_t c_to,
                scale_to_fn_t rust_to) {

        assert_se(c_from(INT_MIN) == rust_from(INT_MIN));
        assert_se(c_from(-1) == rust_from(-1));
        assert_se(c_from(maximum + 1) == rust_from(maximum + 1));
        assert_se(c_from(INT_MAX) == rust_from(INT_MAX));

        for (int value = 0; value <= maximum; value++) {
                uint32_t c_scale = c_from(value);
                uint32_t rust_scale = rust_from(value);

                assert_se(c_scale == rust_scale);
                assert_se(c_to(c_scale) == value);
                assert_se(rust_to(rust_scale) == value);
                assert_se(c_to(c_scale) == rust_to(rust_scale));

                if (c_scale > 0)
                        assert_se(c_to(c_scale - 1) == rust_to(c_scale - 1));
                if (c_scale < UINT32_MAX)
                        assert_se(c_to(c_scale + 1) == rust_to(c_scale + 1));
        }
}

static void test_UINT32_SCALE_FROM_PERCENT(void) {
        assert_se(UINT32_SCALE_FROM_PERCENT(0) == rs_UINT32_SCALE_FROM_PERCENT(0));
        assert_se(UINT32_SCALE_FROM_PERCENT(50) == rs_UINT32_SCALE_FROM_PERCENT(50));
        assert_se(UINT32_SCALE_FROM_PERCENT(100) == rs_UINT32_SCALE_FROM_PERCENT(100));
        assert_se(UINT32_SCALE_FROM_PERCENT(25) == rs_UINT32_SCALE_FROM_PERCENT(25));
        assert_se(UINT32_SCALE_FROM_PERCENT(75) == rs_UINT32_SCALE_FROM_PERCENT(75));
        assert_se(UINT32_SCALE_FROM_PERCENT(1) == rs_UINT32_SCALE_FROM_PERCENT(1));
        assert_se(UINT32_SCALE_FROM_PERCENT(99) == rs_UINT32_SCALE_FROM_PERCENT(99));
        /* Clamping: negative and >100 clamp to 0 and 100 */
        assert_se(UINT32_SCALE_FROM_PERCENT(-1) == rs_UINT32_SCALE_FROM_PERCENT(-1));
        assert_se(UINT32_SCALE_FROM_PERCENT(-100) == rs_UINT32_SCALE_FROM_PERCENT(-100));
        assert_se(UINT32_SCALE_FROM_PERCENT(101) == rs_UINT32_SCALE_FROM_PERCENT(101));
        assert_se(UINT32_SCALE_FROM_PERCENT(INT_MAX) == rs_UINT32_SCALE_FROM_PERCENT(INT_MAX));

        assert_full_scale_domain_parity(
                        100,
                        UINT32_SCALE_FROM_PERCENT,
                        rs_UINT32_SCALE_FROM_PERCENT,
                        UINT32_SCALE_TO_PERCENT,
                        rs_UINT32_SCALE_TO_PERCENT);
}

static void test_UINT32_SCALE_FROM_PERMILLE(void) {
        assert_se(UINT32_SCALE_FROM_PERMILLE(0) == rs_UINT32_SCALE_FROM_PERMILLE(0));
        assert_se(UINT32_SCALE_FROM_PERMILLE(500) == rs_UINT32_SCALE_FROM_PERMILLE(500));
        assert_se(UINT32_SCALE_FROM_PERMILLE(1000) == rs_UINT32_SCALE_FROM_PERMILLE(1000));
        assert_se(UINT32_SCALE_FROM_PERMILLE(250) == rs_UINT32_SCALE_FROM_PERMILLE(250));
        assert_se(UINT32_SCALE_FROM_PERMILLE(750) == rs_UINT32_SCALE_FROM_PERMILLE(750));
        assert_se(UINT32_SCALE_FROM_PERMILLE(1) == rs_UINT32_SCALE_FROM_PERMILLE(1));
        assert_se(UINT32_SCALE_FROM_PERMILLE(999) == rs_UINT32_SCALE_FROM_PERMILLE(999));
        assert_se(UINT32_SCALE_FROM_PERMILLE(-1) == rs_UINT32_SCALE_FROM_PERMILLE(-1));
        assert_se(UINT32_SCALE_FROM_PERMILLE(1001) == rs_UINT32_SCALE_FROM_PERMILLE(1001));

        assert_full_scale_domain_parity(
                        1000,
                        UINT32_SCALE_FROM_PERMILLE,
                        rs_UINT32_SCALE_FROM_PERMILLE,
                        UINT32_SCALE_TO_PERMILLE,
                        rs_UINT32_SCALE_TO_PERMILLE);
}

static void test_UINT32_SCALE_FROM_PERMYRIAD(void) {
        assert_se(UINT32_SCALE_FROM_PERMYRIAD(0) == rs_UINT32_SCALE_FROM_PERMYRIAD(0));
        assert_se(UINT32_SCALE_FROM_PERMYRIAD(5000) == rs_UINT32_SCALE_FROM_PERMYRIAD(5000));
        assert_se(UINT32_SCALE_FROM_PERMYRIAD(10000) == rs_UINT32_SCALE_FROM_PERMYRIAD(10000));
        assert_se(UINT32_SCALE_FROM_PERMYRIAD(2500) == rs_UINT32_SCALE_FROM_PERMYRIAD(2500));
        assert_se(UINT32_SCALE_FROM_PERMYRIAD(7500) == rs_UINT32_SCALE_FROM_PERMYRIAD(7500));
        assert_se(UINT32_SCALE_FROM_PERMYRIAD(1) == rs_UINT32_SCALE_FROM_PERMYRIAD(1));
        assert_se(UINT32_SCALE_FROM_PERMYRIAD(9999) == rs_UINT32_SCALE_FROM_PERMYRIAD(9999));
        assert_se(UINT32_SCALE_FROM_PERMYRIAD(-1) == rs_UINT32_SCALE_FROM_PERMYRIAD(-1));
        assert_se(UINT32_SCALE_FROM_PERMYRIAD(10001) == rs_UINT32_SCALE_FROM_PERMYRIAD(10001));

        assert_full_scale_domain_parity(
                        10000,
                        UINT32_SCALE_FROM_PERMYRIAD,
                        rs_UINT32_SCALE_FROM_PERMYRIAD,
                        UINT32_SCALE_TO_PERMYRIAD,
                        rs_UINT32_SCALE_TO_PERMYRIAD);
}

static void test_UINT32_SCALE_TO_PERCENT(void) {
        assert_se(UINT32_SCALE_TO_PERCENT(0) == rs_UINT32_SCALE_TO_PERCENT(0));
        assert_se(UINT32_SCALE_TO_PERCENT(UINT32_MAX) == rs_UINT32_SCALE_TO_PERCENT(UINT32_MAX));
        assert_se(UINT32_SCALE_TO_PERCENT(UINT32_MAX / 2) == rs_UINT32_SCALE_TO_PERCENT(UINT32_MAX / 2));
        assert_se(UINT32_SCALE_TO_PERCENT(1) == rs_UINT32_SCALE_TO_PERCENT(1));
        assert_se(UINT32_SCALE_TO_PERCENT(0xFFFFFFFF) == rs_UINT32_SCALE_TO_PERCENT(0xFFFFFFFF));
}

static void test_UINT32_SCALE_TO_PERMILLE(void) {
        assert_se(UINT32_SCALE_TO_PERMILLE(0) == rs_UINT32_SCALE_TO_PERMILLE(0));
        assert_se(UINT32_SCALE_TO_PERMILLE(UINT32_MAX) == rs_UINT32_SCALE_TO_PERMILLE(UINT32_MAX));
        assert_se(UINT32_SCALE_TO_PERMILLE(UINT32_MAX / 2) == rs_UINT32_SCALE_TO_PERMILLE(UINT32_MAX / 2));
}

static void test_UINT32_SCALE_TO_PERMYRIAD(void) {
        assert_se(UINT32_SCALE_TO_PERMYRIAD(0) == rs_UINT32_SCALE_TO_PERMYRIAD(0));
        assert_se(UINT32_SCALE_TO_PERMYRIAD(UINT32_MAX) == rs_UINT32_SCALE_TO_PERMYRIAD(UINT32_MAX));
        assert_se(UINT32_SCALE_TO_PERMYRIAD(UINT32_MAX / 2) == rs_UINT32_SCALE_TO_PERMYRIAD(UINT32_MAX / 2));
}

int main(int argc, char **argv) {
        test_UINT32_SCALE_FROM_PERCENT();
        test_UINT32_SCALE_FROM_PERMILLE();
        test_UINT32_SCALE_FROM_PERMYRIAD();
        test_UINT32_SCALE_TO_PERCENT();
        test_UINT32_SCALE_TO_PERMILLE();
        test_UINT32_SCALE_TO_PERMYRIAD();
        return 0;
}
