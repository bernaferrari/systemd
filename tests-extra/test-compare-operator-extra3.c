/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "compare-operator.h"
#include "tests.h"

TEST(version_or_fnmatch_compare_string) {
        /* COMPARE_STRING_EQUAL: exact match */
        assert_se(version_or_fnmatch_compare(COMPARE_STRING_EQUAL, "abc", "abc") == true);
        assert_se(version_or_fnmatch_compare(COMPARE_STRING_EQUAL, "abc", "def") == false);
        assert_se(version_or_fnmatch_compare(COMPARE_STRING_EQUAL, NULL, NULL) == true);
        assert_se(version_or_fnmatch_compare(COMPARE_STRING_EQUAL, "abc", NULL) == false);

        /* COMPARE_STRING_UNEQUAL: not equal */
        assert_se(version_or_fnmatch_compare(COMPARE_STRING_UNEQUAL, "abc", "def") == true);
        assert_se(version_or_fnmatch_compare(COMPARE_STRING_UNEQUAL, "abc", "abc") == false);
}

TEST(version_or_fnmatch_compare_fnmatch) {
        /* COMPARE_FNMATCH_EQUAL: pattern match */
        assert_se(version_or_fnmatch_compare(COMPARE_FNMATCH_EQUAL, "abc", "a*") == true);
        assert_se(version_or_fnmatch_compare(COMPARE_FNMATCH_EQUAL, "abc", "b*") == false);

        /* COMPARE_FNMATCH_UNEQUAL: pattern does not match */
        assert_se(version_or_fnmatch_compare(COMPARE_FNMATCH_UNEQUAL, "abc", "b*") == true);
        assert_se(version_or_fnmatch_compare(COMPARE_FNMATCH_UNEQUAL, "abc", "a*") == false);
}

TEST(version_or_fnmatch_compare_order) {
        /* Version comparison with order operators */
        assert_se(version_or_fnmatch_compare(COMPARE_EQUAL, "1.0", "1.0") == true);
        assert_se(version_or_fnmatch_compare(COMPARE_UNEQUAL, "1.0", "2.0") == true);
        assert_se(version_or_fnmatch_compare(COMPARE_LOWER, "1.0", "2.0") == true);
        assert_se(version_or_fnmatch_compare(COMPARE_GREATER, "2.0", "1.0") == true);
        assert_se(version_or_fnmatch_compare(COMPARE_LOWER_OR_EQUAL, "1.0", "1.0") == true);
        assert_se(version_or_fnmatch_compare(COMPARE_GREATER_OR_EQUAL, "1.0", "1.0") == true);
}

TEST(compare_operator_is_macros) {
        assert_se(COMPARE_OPERATOR_IS_STRING(COMPARE_STRING_EQUAL));
        assert_se(COMPARE_OPERATOR_IS_STRING(COMPARE_STRING_UNEQUAL));
        assert_se(!COMPARE_OPERATOR_IS_STRING(COMPARE_EQUAL));

        assert_se(COMPARE_OPERATOR_IS_FNMATCH(COMPARE_FNMATCH_EQUAL));
        assert_se(COMPARE_OPERATOR_IS_FNMATCH(COMPARE_FNMATCH_UNEQUAL));
        assert_se(!COMPARE_OPERATOR_IS_FNMATCH(COMPARE_EQUAL));

        assert_se(COMPARE_OPERATOR_IS_ORDER(COMPARE_EQUAL));
        assert_se(COMPARE_OPERATOR_IS_ORDER(COMPARE_LOWER));
        assert_se(COMPARE_OPERATOR_IS_ORDER(COMPARE_GREATER));
        assert_se(!COMPARE_OPERATOR_IS_ORDER(COMPARE_STRING_EQUAL));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
