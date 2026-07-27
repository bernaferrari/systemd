/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: strv_split_newlines, strv_rebreak_lines */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"
#include "strv.h"
#include "rust/strv.h"

static void test_strv_split_newlines(void) {
        char **c_r, **rs_r;
        size_t i;

        /* Simple split */
        c_r = strv_split_newlines("hello\nworld\nfoo");
        rs_r = rs_strv_split_newlines("hello\nworld\nfoo");
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        for (i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        assert_se(c_r[i] == NULL);
        assert_se(rs_r[i] == NULL);
        assert_se(i == 3);
        strv_free(c_r);
        strv_free(rs_r);

        /* Trailing newline — suppresses empty entry */
        c_r = strv_split_newlines("hello\nworld\n");
        rs_r = rs_strv_split_newlines("hello\nworld\n");
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        for (i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        assert_se(i == 2);
        strv_free(c_r);
        strv_free(rs_r);

        /* Carriage return as newline */
        c_r = strv_split_newlines("hello\rworld");
        rs_r = rs_strv_split_newlines("hello\rworld");
        for (i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        assert_se(i == 2);
        strv_free(c_r);
        strv_free(rs_r);

        /* Single line no newline */
        c_r = strv_split_newlines("hello");
        rs_r = rs_strv_split_newlines("hello");
        for (i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        assert_se(i == 1);
        strv_free(c_r);
        strv_free(rs_r);

        /* Empty string */
        c_r = strv_split_newlines("");
        rs_r = rs_strv_split_newlines("");
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(c_r[0] == NULL);
        assert_se(rs_r[0] == NULL);
        strv_free(c_r);
        strv_free(rs_r);

        /* Full variant publishes the result and reports its length. */
        c_r = rs_r = NULL;
        int c_ret = strv_split_newlines_full(&c_r, "hello\nworld\n", 0);
        int rs_ret = rs_strv_split_newlines_full(&rs_r, "hello\nworld\n", 0);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 2);
        for (i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        assert_se(c_r[i] == NULL);
        assert_se(rs_r[i] == NULL);
        strv_free(c_r);
        strv_free(rs_r);
}

static void test_strv_rebreak_lines(void) {
        char *input1[] = { (char*)"hello world this is a long line", NULL };
        char **c_r = NULL, **rs_r = NULL;
        int c_ret, rs_ret;
        size_t i;

        /* Break at width 10 */
        c_ret = strv_rebreak_lines(input1, 10, &c_r);
        rs_ret = rs_strv_rebreak_lines(input1, 10, &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        for (i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        assert_se(c_r[i] == NULL);
        assert_se(rs_r[i] == NULL);
        assert_se(strv_length(c_r) > 1);
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;

        /* Width SIZE_MAX — no rebreaking */
        c_ret = strv_rebreak_lines(input1, SIZE_MAX, &c_r);
        rs_ret = rs_strv_rebreak_lines(input1, SIZE_MAX, &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(strv_length(c_r) == 1);
        assert_se(streq(c_r[0], "hello world this is a long line"));
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;

        /* NULL input — empty result */
        c_ret = strv_rebreak_lines(NULL, 10, &c_r);
        rs_ret = rs_strv_rebreak_lines(NULL, 10, &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);

        /* Already short lines — no rebreaking */
        char *short_input[] = { (char*)"hello", (char*)"world", NULL };
        c_ret = strv_rebreak_lines(short_input, 80, &c_r);
        rs_ret = rs_strv_rebreak_lines(short_input, 80, &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(strv_length(c_r) == 2);
        for (i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;

        /* Multiple newlines in line — resets counter */
        char *nl_input[] = { (char*)"ab\ncd ef gh ij kl", NULL };
        c_ret = strv_rebreak_lines(nl_input, 10, &c_r);
        rs_ret = rs_strv_rebreak_lines(nl_input, 10, &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        for (i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        assert_se(c_r[i] == NULL);
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;
}

int main(int argc, char **argv) {
        test_strv_split_newlines();
        test_strv_rebreak_lines();
        return 0;
}
