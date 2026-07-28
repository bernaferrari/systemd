/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C ioprio-util.h inline functions vs Rust */

#include <assert.h>
#include <limits.h>

#include "ioprio-util.h"
#include "rust/ioprio_util.h"
#include "tests.h"

/* RUST-CONTRACT: ioprio-prio-class */
static void test_ioprio_prio_class(void) {
        assert_se(ioprio_prio_class(0) == rs_ioprio_prio_class(0));
        assert_se(ioprio_prio_class(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0)) == rs_ioprio_prio_class(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0)));
        assert_se(ioprio_prio_class(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_RT, 0)) == rs_ioprio_prio_class(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_RT, 0)));
        assert_se(ioprio_prio_class(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 0)) == rs_ioprio_prio_class(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 0)));
        assert_se(ioprio_prio_class(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0)) == rs_ioprio_prio_class(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0)));
        assert_se(ioprio_prio_class(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 7)) == rs_ioprio_prio_class(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 7)));
        assert_se(ioprio_prio_class(INT_MAX) == rs_ioprio_prio_class(INT_MAX));
        assert_se(ioprio_prio_class(-1) == rs_ioprio_prio_class(-1));
}

/* RUST-CONTRACT: ioprio-prio-data */
static void test_ioprio_prio_data(void) {
        assert_se(ioprio_prio_data(0) == rs_ioprio_prio_data(0));
        assert_se(ioprio_prio_data(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 4)) == rs_ioprio_prio_data(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 4)));
        assert_se(ioprio_prio_data(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_RT, 7)) == rs_ioprio_prio_data(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_RT, 7)));
        assert_se(ioprio_prio_data(IOPRIO_PRIO_MASK) == rs_ioprio_prio_data(IOPRIO_PRIO_MASK));
        assert_se(ioprio_prio_data(0x1FFF) == rs_ioprio_prio_data(0x1FFF));
        assert_se(ioprio_prio_data(INT_MAX) == rs_ioprio_prio_data(INT_MAX));
}

/* RUST-CONTRACT: ioprio-prio-value */
static void test_ioprio_prio_value(void) {
        assert_se(ioprio_prio_value(IOPRIO_CLASS_BE, 4) == rs_ioprio_prio_value(IOPRIO_CLASS_BE, 4));
        assert_se(ioprio_prio_value(IOPRIO_CLASS_RT, 0) == rs_ioprio_prio_value(IOPRIO_CLASS_RT, 0));
        assert_se(ioprio_prio_value(IOPRIO_CLASS_RT, 7) == rs_ioprio_prio_value(IOPRIO_CLASS_RT, 7));
        assert_se(ioprio_prio_value(IOPRIO_CLASS_IDLE, 0) == rs_ioprio_prio_value(IOPRIO_CLASS_IDLE, 0));
        assert_se(ioprio_prio_value(IOPRIO_CLASS_NONE, 0) == rs_ioprio_prio_value(IOPRIO_CLASS_NONE, 0));
        /* With hints */
        assert_se(IOPRIO_PRIO_VALUE_HINT(IOPRIO_CLASS_BE, 4, 1) == rs_ioprio_prio_value(IOPRIO_CLASS_BE, (1 << 3) | 4));
        assert_se(IOPRIO_PRIO_VALUE_HINT(IOPRIO_CLASS_RT, 7, 5) == rs_ioprio_prio_value(IOPRIO_CLASS_RT, (5 << 3) | 7));
        /* ioprio_prio_value() extracts masked fields from packed data. */
        assert_se(ioprio_prio_value(IOPRIO_CLASS_BE, -1) == rs_ioprio_prio_value(IOPRIO_CLASS_BE, -1));
        assert_se(ioprio_prio_value(IOPRIO_CLASS_BE, 1 << IOPRIO_CLASS_SHIFT) == rs_ioprio_prio_value(IOPRIO_CLASS_BE, 1 << IOPRIO_CLASS_SHIFT));
        assert_se(ioprio_prio_value(IOPRIO_CLASS_BE, INT_MAX) == rs_ioprio_prio_value(IOPRIO_CLASS_BE, INT_MAX));
        /* The kernel helper rejects an out-of-range class but permits its
         * reserved INVALID value (which is still below NR_CLASSES). */
        assert_se(ioprio_prio_value(-1, 0) == rs_ioprio_prio_value(-1, 0));
        assert_se(ioprio_prio_value(IOPRIO_NR_CLASSES, 0) == rs_ioprio_prio_value(IOPRIO_NR_CLASSES, 0));
        assert_se(ioprio_prio_value(IOPRIO_CLASS_INVALID, 0) == rs_ioprio_prio_value(IOPRIO_CLASS_INVALID, 0));
}

/* RUST-CONTRACT: ioprio-normalize */
static void test_ioprio_normalize(void) {
        assert_se(ioprio_normalize(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 4)) == rs_ioprio_normalize(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 4)));
        assert_se(ioprio_normalize(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_RT, 7)) == rs_ioprio_normalize(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_RT, 7)));
        assert_se(ioprio_normalize(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0)) == rs_ioprio_normalize(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0)));
        assert_se(ioprio_normalize(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0)) == rs_ioprio_normalize(IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0)));
        assert_se(ioprio_normalize(0) == rs_ioprio_normalize(0));
}

int main(int argc, char **argv) {
        test_ioprio_prio_class();
        test_ioprio_prio_data();
        test_ioprio_prio_value();
        test_ioprio_normalize();
        return 0;
}
