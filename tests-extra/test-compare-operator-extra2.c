/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "compare-operator.h"
#include "tests.h"

TEST(parse_compare_operator_symbol) {
        const char *p;
        CompareOperator op;

        /* "==" → COMPARE_EQUAL */
        p = "==";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_EQUAL);
        assert_se(*p == '\0');

        /* "!=" → COMPARE_UNEQUAL */
        p = "!=";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_UNEQUAL);
        assert_se(*p == '\0');

        /* "<=" → COMPARE_LOWER_OR_EQUAL */
        p = "<=";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_LOWER_OR_EQUAL);
        assert_se(*p == '\0');

        /* ">=" → COMPARE_GREATER_OR_EQUAL */
        p = ">=";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_GREATER_OR_EQUAL);
        assert_se(*p == '\0');

        /* "<>" → COMPARE_UNEQUAL */
        p = "<>";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_UNEQUAL);
        assert_se(*p == '\0');

        /* "<" → COMPARE_LOWER */
        p = "<";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_LOWER);
        assert_se(*p == '\0');

        /* ">" → COMPARE_GREATER */
        p = ">";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_GREATER);
        assert_se(*p == '\0');

        /* "=" → COMPARE_EQUAL */
        p = "=";
        op = parse_compare_operator(&p, 0);
        assert_se(op == COMPARE_EQUAL);
        assert_se(*p == '\0');
}

TEST(parse_compare_operator_fnmatch) {
        const char *p;
        CompareOperator op;

        p = "$=";
        op = parse_compare_operator(&p, COMPARE_ALLOW_FNMATCH);
        assert_se(op == COMPARE_FNMATCH_EQUAL);
        assert_se(*p == '\0');

        p = "!$=";
        op = parse_compare_operator(&p, COMPARE_ALLOW_FNMATCH);
        assert_se(op == COMPARE_FNMATCH_UNEQUAL);
        assert_se(*p == '\0');
}

TEST(parse_compare_operator_textual) {
        const char *p;
        CompareOperator op;

        p = "lt";
        op = parse_compare_operator(&p, COMPARE_ALLOW_TEXTUAL);
        assert_se(op == COMPARE_LOWER);
        assert_se(*p == '\0');

        p = "le";
        op = parse_compare_operator(&p, COMPARE_ALLOW_TEXTUAL);
        assert_se(op == COMPARE_LOWER_OR_EQUAL);
        assert_se(*p == '\0');

        p = "eq";
        op = parse_compare_operator(&p, COMPARE_ALLOW_TEXTUAL);
        assert_se(op == COMPARE_EQUAL);
        assert_se(*p == '\0');

        p = "ne";
        op = parse_compare_operator(&p, COMPARE_ALLOW_TEXTUAL);
        assert_se(op == COMPARE_UNEQUAL);
        assert_se(*p == '\0');

        p = "ge";
        op = parse_compare_operator(&p, COMPARE_ALLOW_TEXTUAL);
        assert_se(op == COMPARE_GREATER_OR_EQUAL);
        assert_se(*p == '\0');

        p = "gt";
        op = parse_compare_operator(&p, COMPARE_ALLOW_TEXTUAL);
        assert_se(op == COMPARE_GREATER);
        assert_se(*p == '\0');
}

TEST(parse_compare_operator_string) {
        const char *p;
        CompareOperator op;

        p = "=";
        op = parse_compare_operator(&p, COMPARE_EQUAL_BY_STRING);
        assert_se(op == COMPARE_STRING_EQUAL);
        assert_se(*p == '\0');

        p = "!=";
        op = parse_compare_operator(&p, COMPARE_EQUAL_BY_STRING);
        assert_se(op == COMPARE_STRING_UNEQUAL);
        assert_se(*p == '\0');
}

TEST(parse_compare_operator_invalid) {
        const char *p;
        CompareOperator op;

        p = "abc";
        op = parse_compare_operator(&p, 0);
        assert_se(op == _COMPARE_OPERATOR_INVALID);
}

TEST(test_order_basic) {
        /* test_order returns bool: 1 = condition met, 0 = not met */
        assert_se(test_order(0, COMPARE_LOWER_OR_EQUAL));   /* 0 <= 0 is true */
        assert_se(test_order(-1, COMPARE_LOWER_OR_EQUAL)); /* -1 <= 0 is true */
        assert_se(!test_order(1, COMPARE_LOWER_OR_EQUAL));  /* 1 <= 0 is false */

        assert_se(test_order(0, COMPARE_GREATER_OR_EQUAL));   /* 0 >= 0 is true */
        assert_se(test_order(1, COMPARE_GREATER_OR_EQUAL));   /* 1 >= 0 is true */
        assert_se(!test_order(-1, COMPARE_GREATER_OR_EQUAL)); /* -1 >= 0 is false */

        assert_se(test_order(0, COMPARE_EQUAL));   /* 0 == 0 is true */
        assert_se(!test_order(1, COMPARE_EQUAL));  /* 1 == 0 is false */

        assert_se(test_order(1, COMPARE_UNEQUAL));  /* 1 != 0 is true */
        assert_se(!test_order(0, COMPARE_UNEQUAL)); /* 0 != 0 is false */

        assert_se(test_order(-1, COMPARE_LOWER));  /* -1 < 0 is true */
        assert_se(!test_order(0, COMPARE_LOWER));  /* 0 < 0 is false */

        assert_se(test_order(1, COMPARE_GREATER));  /* 1 > 0 is true */
        assert_se(!test_order(0, COMPARE_GREATER)); /* 0 > 0 is false */
}

DEFINE_TEST_MAIN(LOG_DEBUG);
