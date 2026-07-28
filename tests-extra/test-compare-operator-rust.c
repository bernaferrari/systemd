/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C test_order/version_or_fnmatch_compare vs Rust */
/* RUST-CONTRACT: compare-version-or-fnmatch */
/* RUST-CONTRACT: compare-operator-predicates */

#include "tests.h"
#include "compare-operator.h"

/* Rust FFI */
#include "rust/compare_operator.h"
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

        /* k == 0 */
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

        /* k == 1 */
        cv = test_order(1, COMPARE_GREATER);
        rv = rs_test_order(1, COMPARE_GREATER);
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = test_order(1, COMPARE_LOWER);
        rv = rs_test_order(1, COMPARE_LOWER);
        assert_se(cv == rv);
        assert_se(cv == false);

        /* Invalid operator */
        cv = test_order(0, COMPARE_STRING_EQUAL);
        rv = rs_test_order(0, COMPARE_STRING_EQUAL);
        assert_se(cv == rv);
        assert_se(cv == -EINVAL);
}

static void test_version_or_fnmatch_string(void) {
        int cv, rv;

        cv = version_or_fnmatch_compare(COMPARE_STRING_EQUAL, "abc", "abc");
        rv = rs_version_or_fnmatch_compare(COMPARE_STRING_EQUAL, "abc", "abc");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = version_or_fnmatch_compare(COMPARE_STRING_EQUAL, "abc", "def");
        rv = rs_version_or_fnmatch_compare(COMPARE_STRING_EQUAL, "abc", "def");
        assert_se(cv == rv);
        assert_se(cv == false);

        cv = version_or_fnmatch_compare(COMPARE_STRING_EQUAL, NULL, NULL);
        rv = rs_version_or_fnmatch_compare(COMPARE_STRING_EQUAL, NULL, NULL);
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = version_or_fnmatch_compare(COMPARE_STRING_EQUAL, "abc", NULL);
        rv = rs_version_or_fnmatch_compare(COMPARE_STRING_EQUAL, "abc", NULL);
        assert_se(cv == rv);
        assert_se(cv == false);

        cv = version_or_fnmatch_compare(COMPARE_STRING_UNEQUAL, "abc", "def");
        rv = rs_version_or_fnmatch_compare(COMPARE_STRING_UNEQUAL, "abc", "def");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = version_or_fnmatch_compare(COMPARE_STRING_UNEQUAL, "abc", "abc");
        rv = rs_version_or_fnmatch_compare(COMPARE_STRING_UNEQUAL, "abc", "abc");
        assert_se(cv == rv);
        assert_se(cv == false);

        static const char non_utf8[] = { 'a', (char) 0xff, 0 };
        cv = version_or_fnmatch_compare(COMPARE_STRING_EQUAL, non_utf8, non_utf8);
        rv = rs_version_or_fnmatch_compare(COMPARE_STRING_EQUAL, non_utf8, non_utf8);
        assert_se(cv == rv);
        assert_se(cv == true);
}

static void test_version_or_fnmatch_fnmatch(void) {
        int cv, rv;

        cv = version_or_fnmatch_compare(COMPARE_FNMATCH_EQUAL, "abc", "a*");
        rv = rs_version_or_fnmatch_compare(COMPARE_FNMATCH_EQUAL, "abc", "a*");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = version_or_fnmatch_compare(COMPARE_FNMATCH_EQUAL, "abc", "b*");
        rv = rs_version_or_fnmatch_compare(COMPARE_FNMATCH_EQUAL, "abc", "b*");
        assert_se(cv == rv);
        assert_se(cv == false);

        cv = version_or_fnmatch_compare(COMPARE_FNMATCH_UNEQUAL, "abc", "b*");
        rv = rs_version_or_fnmatch_compare(COMPARE_FNMATCH_UNEQUAL, "abc", "b*");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = version_or_fnmatch_compare(COMPARE_FNMATCH_UNEQUAL, "abc", "a*");
        rv = rs_version_or_fnmatch_compare(COMPARE_FNMATCH_UNEQUAL, "abc", "a*");
        assert_se(cv == rv);
        assert_se(cv == false);
}

static void test_version_or_fnmatch_order(void) {
        int cv, rv;

        cv = version_or_fnmatch_compare(COMPARE_EQUAL, "1.0", "1.0");
        rv = rs_version_or_fnmatch_compare(COMPARE_EQUAL, "1.0", "1.0");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = version_or_fnmatch_compare(COMPARE_UNEQUAL, "1.0", "2.0");
        rv = rs_version_or_fnmatch_compare(COMPARE_UNEQUAL, "1.0", "2.0");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = version_or_fnmatch_compare(COMPARE_LOWER, "1.0", "2.0");
        rv = rs_version_or_fnmatch_compare(COMPARE_LOWER, "1.0", "2.0");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = version_or_fnmatch_compare(COMPARE_GREATER, "2.0", "1.0");
        rv = rs_version_or_fnmatch_compare(COMPARE_GREATER, "2.0", "1.0");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = version_or_fnmatch_compare(COMPARE_LOWER_OR_EQUAL, "1.0", "1.0");
        rv = rs_version_or_fnmatch_compare(COMPARE_LOWER_OR_EQUAL, "1.0", "1.0");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = version_or_fnmatch_compare(COMPARE_GREATER_OR_EQUAL, "1.0", "1.0");
        rv = rs_version_or_fnmatch_compare(COMPARE_GREATER_OR_EQUAL, "1.0", "1.0");
        assert_se(cv == rv);
        assert_se(cv == true);

        /* More complex version comparisons */
        cv = version_or_fnmatch_compare(COMPARE_LOWER, "1.0~rc1", "1.0");
        rv = rs_version_or_fnmatch_compare(COMPARE_LOWER, "1.0~rc1", "1.0");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = version_or_fnmatch_compare(COMPARE_GREATER, "2.0.1", "2.0");
        rv = rs_version_or_fnmatch_compare(COMPARE_GREATER, "2.0.1", "2.0");
        assert_se(cv == rv);
        assert_se(cv == true);

        cv = version_or_fnmatch_compare(COMPARE_EQUAL, NULL, "");
        rv = rs_version_or_fnmatch_compare(COMPARE_EQUAL, NULL, "");
        assert_se(cv == rv);
        assert_se(cv == true);
}

static void test_version_or_fnmatch_invalid(void) {
        int cv, rv;

        /* Invalid operator */
        cv = version_or_fnmatch_compare(-1, "a", "b");
        rv = rs_version_or_fnmatch_compare(-1, "a", "b");
        assert_se(cv == rv);
        assert_se(cv == -EINVAL);
}

static void test_COMPARE_OPERATOR_IS_STRING(void) {
        assert_se(COMPARE_OPERATOR_IS_STRING(COMPARE_STRING_EQUAL) == rs_COMPARE_OPERATOR_IS_STRING(COMPARE_STRING_EQUAL));
        assert_se(COMPARE_OPERATOR_IS_STRING(COMPARE_STRING_UNEQUAL) == rs_COMPARE_OPERATOR_IS_STRING(COMPARE_STRING_UNEQUAL));
        assert_se(COMPARE_OPERATOR_IS_STRING(COMPARE_FNMATCH_EQUAL) == rs_COMPARE_OPERATOR_IS_STRING(COMPARE_FNMATCH_EQUAL));
        assert_se(COMPARE_OPERATOR_IS_STRING(COMPARE_LOWER_OR_EQUAL) == rs_COMPARE_OPERATOR_IS_STRING(COMPARE_LOWER_OR_EQUAL));
        assert_se(COMPARE_OPERATOR_IS_STRING(COMPARE_EQUAL) == rs_COMPARE_OPERATOR_IS_STRING(COMPARE_EQUAL));
        assert_se(COMPARE_OPERATOR_IS_STRING(-1) == rs_COMPARE_OPERATOR_IS_STRING(-1));
        assert_se(COMPARE_OPERATOR_IS_STRING(100) == rs_COMPARE_OPERATOR_IS_STRING(100));
}

static void test_COMPARE_OPERATOR_IS_FNMATCH(void) {
        assert_se(COMPARE_OPERATOR_IS_FNMATCH(COMPARE_FNMATCH_EQUAL) == rs_COMPARE_OPERATOR_IS_FNMATCH(COMPARE_FNMATCH_EQUAL));
        assert_se(COMPARE_OPERATOR_IS_FNMATCH(COMPARE_FNMATCH_UNEQUAL) == rs_COMPARE_OPERATOR_IS_FNMATCH(COMPARE_FNMATCH_UNEQUAL));
        assert_se(COMPARE_OPERATOR_IS_FNMATCH(COMPARE_STRING_EQUAL) == rs_COMPARE_OPERATOR_IS_FNMATCH(COMPARE_STRING_EQUAL));
        assert_se(COMPARE_OPERATOR_IS_FNMATCH(COMPARE_LOWER_OR_EQUAL) == rs_COMPARE_OPERATOR_IS_FNMATCH(COMPARE_LOWER_OR_EQUAL));
        assert_se(COMPARE_OPERATOR_IS_FNMATCH(-1) == rs_COMPARE_OPERATOR_IS_FNMATCH(-1));
}

static void test_COMPARE_OPERATOR_IS_ORDER(void) {
        assert_se(COMPARE_OPERATOR_IS_ORDER(COMPARE_LOWER_OR_EQUAL) == rs_COMPARE_OPERATOR_IS_ORDER(COMPARE_LOWER_OR_EQUAL));
        assert_se(COMPARE_OPERATOR_IS_ORDER(COMPARE_GREATER_OR_EQUAL) == rs_COMPARE_OPERATOR_IS_ORDER(COMPARE_GREATER_OR_EQUAL));
        assert_se(COMPARE_OPERATOR_IS_ORDER(COMPARE_LOWER) == rs_COMPARE_OPERATOR_IS_ORDER(COMPARE_LOWER));
        assert_se(COMPARE_OPERATOR_IS_ORDER(COMPARE_GREATER) == rs_COMPARE_OPERATOR_IS_ORDER(COMPARE_GREATER));
        assert_se(COMPARE_OPERATOR_IS_ORDER(COMPARE_EQUAL) == rs_COMPARE_OPERATOR_IS_ORDER(COMPARE_EQUAL));
        assert_se(COMPARE_OPERATOR_IS_ORDER(COMPARE_UNEQUAL) == rs_COMPARE_OPERATOR_IS_ORDER(COMPARE_UNEQUAL));
        assert_se(COMPARE_OPERATOR_IS_ORDER(COMPARE_STRING_EQUAL) == rs_COMPARE_OPERATOR_IS_ORDER(COMPARE_STRING_EQUAL));
        assert_se(COMPARE_OPERATOR_IS_ORDER(COMPARE_FNMATCH_EQUAL) == rs_COMPARE_OPERATOR_IS_ORDER(COMPARE_FNMATCH_EQUAL));
        assert_se(COMPARE_OPERATOR_IS_ORDER(-1) == rs_COMPARE_OPERATOR_IS_ORDER(-1));
        assert_se(COMPARE_OPERATOR_IS_ORDER(100) == rs_COMPARE_OPERATOR_IS_ORDER(100));
}

int main(int argc, char **argv) {
        test_test_order();
        test_version_or_fnmatch_string();
        test_version_or_fnmatch_fnmatch();
        test_version_or_fnmatch_order();
        test_version_or_fnmatch_invalid();
        test_COMPARE_OPERATOR_IS_STRING();
        test_COMPARE_OPERATOR_IS_FNMATCH();
        test_COMPARE_OPERATOR_IS_ORDER();
        return 0;
}
