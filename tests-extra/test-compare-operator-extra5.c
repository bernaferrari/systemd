/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "compare-operator.h"
#include "string-util.h"
#include "tests.h"

TEST(parse_compare_operator_basic) {
        const char *p;
        CompareOperator op;

        /* == */
        p = "==5";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_EQUAL);
        assert_se(streq(p, "5"));

        /* != */
        p = "!=3";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_UNEQUAL);
        assert_se(streq(p, "3"));

        /* < */
        p = "<10";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_LOWER);

        /* > */
        p = ">10";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_GREATER);

        /* <= */
        p = "<=10";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_LOWER_OR_EQUAL);

        /* >= */
        p = ">=10";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_GREATER_OR_EQUAL);

        /* <> */
        p = "<>10";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_UNEQUAL);
}

TEST(parse_compare_operator_single_equal) {
        const char *p;
        CompareOperator op;

        /* Without COMPARE_EQUAL_BY_STRING: = means COMPARE_EQUAL */
        p = "=5";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_EQUAL);
        assert_se(streq(p, "5"));

        /* With COMPARE_EQUAL_BY_STRING: = means COMPARE_STRING_EQUAL */
        p = "=5";
        op = parse_compare_operator(&p, COMPARE_EQUAL_BY_STRING);
        assert_se(op == COMPARE_STRING_EQUAL);
        assert_se(streq(p, "5"));

        /* != with COMPARE_EQUAL_BY_STRING → STRING_UNEQUAL */
        p = "!=5";
        op = parse_compare_operator(&p, COMPARE_EQUAL_BY_STRING);
        assert_se(op == COMPARE_STRING_UNEQUAL);
}

TEST(parse_compare_operator_fnmatch) {
        const char *p;
        CompareOperator op;

        /* fnmatch ops need COMPARE_ALLOW_FNMATCH */
        p = "$=pattern";
        op = parse_compare_operator(&p, 0);
        assert_se(op == _COMPARE_OPERATOR_INVALID);

        p = "$=pattern";
        op = parse_compare_operator(&p, COMPARE_ALLOW_FNMATCH);
        assert_se(op == COMPARE_FNMATCH_EQUAL);
        assert_se(streq(p, "pattern"));

        p = "!$=pattern";
        op = parse_compare_operator(&p, COMPARE_ALLOW_FNMATCH);
        assert_se(op == COMPARE_FNMATCH_UNEQUAL);
}

TEST(parse_compare_operator_textual) {
        const char *p;
        CompareOperator op;

        /* Textual ops need COMPARE_ALLOW_TEXTUAL */
        p = "eq5";
        op = parse_compare_operator(&p, 0);
        assert_se(op == _COMPARE_OPERATOR_INVALID);

        p = "eq 5";
        op = parse_compare_operator(&p, COMPARE_ALLOW_TEXTUAL);
        assert_se(op == COMPARE_EQUAL);
        assert_se(streq(p, " 5"));

        p = "ne 5";
        op = parse_compare_operator(&p, COMPARE_ALLOW_TEXTUAL);
        assert_se(op == COMPARE_UNEQUAL);

        p = "lt 5";
        op = parse_compare_operator(&p, COMPARE_ALLOW_TEXTUAL);
        assert_se(op == COMPARE_LOWER);

        p = "gt 5";
        op = parse_compare_operator(&p, COMPARE_ALLOW_TEXTUAL);
        assert_se(op == COMPARE_GREATER);

        p = "le 5";
        op = parse_compare_operator(&p, COMPARE_ALLOW_TEXTUAL);
        assert_se(op == COMPARE_LOWER_OR_EQUAL);

        p = "ge 5";
        op = parse_compare_operator(&p, COMPARE_ALLOW_TEXTUAL);
        assert_se(op == COMPARE_GREATER_OR_EQUAL);
}

TEST(parse_compare_operator_null) {
        const char *p = NULL;
        CompareOperator op = parse_compare_operator(&p, 0);
        assert_se(op == _COMPARE_OPERATOR_INVALID);
}

TEST(parse_compare_operator_invalid) {
        const char *p = "nope5";
        CompareOperator op = parse_compare_operator(&p, 0);
        assert_se(op == _COMPARE_OPERATOR_INVALID);
}

TEST(test_order) {
        assert_se(test_order(-1, COMPARE_LOWER) == true);
        assert_se(test_order(0, COMPARE_LOWER) == false);
        assert_se(test_order(1, COMPARE_LOWER) == false);

        assert_se(test_order(-1, COMPARE_LOWER_OR_EQUAL) == true);
        assert_se(test_order(0, COMPARE_LOWER_OR_EQUAL) == true);
        assert_se(test_order(1, COMPARE_LOWER_OR_EQUAL) == false);

        assert_se(test_order(0, COMPARE_EQUAL) == true);
        assert_se(test_order(1, COMPARE_EQUAL) == false);
        assert_se(test_order(-1, COMPARE_EQUAL) == false);

        assert_se(test_order(0, COMPARE_UNEQUAL) == false);
        assert_se(test_order(1, COMPARE_UNEQUAL) == true);
        assert_se(test_order(-1, COMPARE_UNEQUAL) == true);

        assert_se(test_order(1, COMPARE_GREATER) == true);
        assert_se(test_order(0, COMPARE_GREATER) == false);

        assert_se(test_order(1, COMPARE_GREATER_OR_EQUAL) == true);
        assert_se(test_order(0, COMPARE_GREATER_OR_EQUAL) == true);
        assert_se(test_order(-1, COMPARE_GREATER_OR_EQUAL) == false);

        /* Invalid operator → -EINVAL */
        assert_se(test_order(0, COMPARE_STRING_EQUAL) == -EINVAL);
}

TEST(version_or_fnmatch_compare) {
        /* STRING_EQUAL */
        assert_se(version_or_fnmatch_compare(COMPARE_STRING_EQUAL, "abc", "abc") == true);
        assert_se(version_or_fnmatch_compare(COMPARE_STRING_EQUAL, "abc", "def") == false);
        assert_se(version_or_fnmatch_compare(COMPARE_STRING_EQUAL, NULL, NULL) == true);
        assert_se(version_or_fnmatch_compare(COMPARE_STRING_EQUAL, "abc", NULL) == false);

        /* STRING_UNEQUAL */
        assert_se(version_or_fnmatch_compare(COMPARE_STRING_UNEQUAL, "abc", "def") == true);
        assert_se(version_or_fnmatch_compare(COMPARE_STRING_UNEQUAL, "abc", "abc") == false);

        /* FNMATCH_EQUAL */
        assert_se(version_or_fnmatch_compare(COMPARE_FNMATCH_EQUAL, "hello.c", "*.c") == true);
        assert_se(version_or_fnmatch_compare(COMPARE_FNMATCH_EQUAL, "hello.h", "*.c") == false);

        /* FNMATCH_UNEQUAL */
        assert_se(version_or_fnmatch_compare(COMPARE_FNMATCH_UNEQUAL, "hello.h", "*.c") == true);
        assert_se(version_or_fnmatch_compare(COMPARE_FNMATCH_UNEQUAL, "hello.c", "*.c") == false);

        /* Order compare (version comparison) */
        assert_se(version_or_fnmatch_compare(COMPARE_GREATER, "2.0", "1.0") == true);
        assert_se(version_or_fnmatch_compare(COMPARE_LOWER, "1.0", "2.0") == true);
        assert_se(version_or_fnmatch_compare(COMPARE_EQUAL, "1.0", "1.0") == true);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
