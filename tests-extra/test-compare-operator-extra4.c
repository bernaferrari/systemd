/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "compare-operator.h"
#include "string-util.h"
#include "tests.h"

TEST(parse_compare_operator) {
        const char *p;
        CompareOperator op;

        p = "==5";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_EQUAL);
        assert_se(streq(p, "5"));

        p = "!=3";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_UNEQUAL);
        assert_se(streq(p, "3"));

        p = "<=10";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_LOWER_OR_EQUAL);
        assert_se(streq(p, "10"));

        p = ">=10";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_GREATER_OR_EQUAL);
        assert_se(streq(p, "10"));

        p = "<5";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_LOWER);
        assert_se(streq(p, "5"));

        p = ">5";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_GREATER);
        assert_se(streq(p, "5"));

        p = "foo";
        op = parse_compare_operator(&p, 0);
        assert_se(op == _COMPARE_OPERATOR_INVALID);

        /* Textual operators need flag */
        p = "eq 5";
        op = parse_compare_operator(&p, 0);
        assert_se(op == _COMPARE_OPERATOR_INVALID);

        p = "eq 5";
        op = parse_compare_operator(&p, COMPARE_ALLOW_TEXTUAL);
        assert_se(op == COMPARE_EQUAL);
        assert_se(streq(p, " 5"));
}

TEST(test_order) {
        assert_se(test_order(-1, COMPARE_LOWER));
        assert_se(test_order(-1, COMPARE_LOWER_OR_EQUAL));
        assert_se(!test_order(-1, COMPARE_EQUAL));
        assert_se(test_order(-1, COMPARE_UNEQUAL));
        assert_se(!test_order(-1, COMPARE_GREATER_OR_EQUAL));
        assert_se(!test_order(-1, COMPARE_GREATER));

        assert_se(!test_order(0, COMPARE_LOWER));
        assert_se(test_order(0, COMPARE_LOWER_OR_EQUAL));
        assert_se(test_order(0, COMPARE_EQUAL));
        assert_se(!test_order(0, COMPARE_UNEQUAL));
        assert_se(test_order(0, COMPARE_GREATER_OR_EQUAL));
        assert_se(!test_order(0, COMPARE_GREATER));

        assert_se(!test_order(1, COMPARE_LOWER));
        assert_se(!test_order(1, COMPARE_LOWER_OR_EQUAL));
        assert_se(!test_order(1, COMPARE_EQUAL));
        assert_se(test_order(1, COMPARE_UNEQUAL));
        assert_se(test_order(1, COMPARE_GREATER_OR_EQUAL));
        assert_se(test_order(1, COMPARE_GREATER));
}

TEST(version_or_fnmatch_compare) {
        assert_se(version_or_fnmatch_compare(COMPARE_STRING_EQUAL, "foo", "foo"));
        assert_se(!version_or_fnmatch_compare(COMPARE_STRING_EQUAL, "foo", "bar"));
        assert_se(version_or_fnmatch_compare(COMPARE_STRING_UNEQUAL, "foo", "bar"));
        assert_se(!version_or_fnmatch_compare(COMPARE_STRING_UNEQUAL, "foo", "foo"));

        assert_se(version_or_fnmatch_compare(COMPARE_FNMATCH_EQUAL, "foo", "f*"));
        assert_se(!version_or_fnmatch_compare(COMPARE_FNMATCH_EQUAL, "foo", "b*"));
        assert_se(version_or_fnmatch_compare(COMPARE_FNMATCH_UNEQUAL, "foo", "b*"));
        assert_se(!version_or_fnmatch_compare(COMPARE_FNMATCH_UNEQUAL, "foo", "f*"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
