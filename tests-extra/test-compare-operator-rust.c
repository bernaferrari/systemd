/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Focused coverage for the retained shared validation facade. */

#include "tests.h"
#include "compare-operator.h"
#include "rust/shared_facades/validation.h"

static void test_test_order(void) {
        int cv, rv;

        cv = test_order(-1, COMPARE_LOWER);
        rv = rs_test_order(-1, COMPARE_LOWER);
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = test_order(-1, COMPARE_LOWER_OR_EQUAL);
        rv = rs_test_order(-1, COMPARE_LOWER_OR_EQUAL);
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = test_order(-1, COMPARE_EQUAL);
        rv = rs_test_order(-1, COMPARE_EQUAL);
        assert_se(cv == rv);
        assert_se(cv == false);

        cv = test_order(-1, COMPARE_UNEQUAL);
        rv = rs_test_order(-1, COMPARE_UNEQUAL);
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = test_order(-1, COMPARE_GREATER_OR_EQUAL);
        rv = rs_test_order(-1, COMPARE_GREATER_OR_EQUAL);
        assert_se(cv == rv);
        assert_se(cv == false);

        cv = test_order(-1, COMPARE_GREATER);
        rv = rs_test_order(-1, COMPARE_GREATER);
        assert_se(cv == rv);
        assert_se(cv == false);

        cv = test_order(0, COMPARE_LOWER);
        rv = rs_test_order(0, COMPARE_LOWER);
        assert_se(cv == rv);

        cv = test_order(0, COMPARE_EQUAL);
        rv = rs_test_order(0, COMPARE_EQUAL);
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = test_order(0, COMPARE_UNEQUAL);
        rv = rs_test_order(0, COMPARE_UNEQUAL);
        assert_se(cv == rv);
        assert_se(cv == false);

        cv = test_order(1, COMPARE_GREATER);
        rv = rs_test_order(1, COMPARE_GREATER);
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = test_order(1, COMPARE_LOWER);
        rv = rs_test_order(1, COMPARE_LOWER);
        assert_se(cv == rv);
        assert_se(cv == false);

        cv = test_order(0, COMPARE_STRING_EQUAL);
        rv = rs_test_order(0, COMPARE_STRING_EQUAL);
        assert_se(cv == rv);
        assert_se(cv == -EINVAL);
}

int main(int argc, char **argv) {
        test_test_order();
        return 0;
}
