/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: strv_shell_escape vs Rust */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"
#include "strv.h"
#include "escape.h"
#include "rust/strv.h"

/* RUST-CONTRACT: strv-shell-escape */
static void test_strv_shell_escape(void) {
        /* SHELL_NEED_ESCAPE = "\"\\`$" — only these chars get escaped */
        char *c_arr[] = { strdup("hello"), strdup("foo\"bar"), strdup("it`s"), strdup("pay$"), strdup("back\\slash"), NULL };
        char *rs_arr[] = { strdup("hello"), strdup("foo\"bar"), strdup("it`s"), strdup("pay$"), strdup("back\\slash"), NULL };
        char **c_r, **rs_r;
        size_t i;

        c_r = strv_shell_escape(c_arr, SHELL_NEED_ESCAPE);
        rs_r = rs_strv_shell_escape(rs_arr, SHELL_NEED_ESCAPE);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);

        /* Compare all entries */
        for (i = 0; c_r[i] != NULL && rs_r[i] != NULL; i++) {
                assert_se(streq(c_r[i], rs_r[i]));
        }
        assert_se(c_r[i] == NULL);
        assert_se(rs_r[i] == NULL);

        /* "hello" has no special chars — should be unchanged */
        assert_se(streq(c_r[0], "hello"));

        /* "foo\"bar" should have the double-quote escaped */
        assert_se(strstr(c_r[1], "\\") != NULL);

        /* "it`s" should have the backtick escaped */
        assert_se(strstr(c_r[2], "\\") != NULL);

        /* "pay$" should have the dollar sign escaped */
        assert_se(strstr(c_r[3], "\\") != NULL);

        /* "back\\slash" should have the backslash escaped */
        assert_se(strstr(c_r[4], "\\\\") != NULL);

        /* strv_shell_escape returns the original pointer (stack array),
         * so we must free entries individually, not strv_free the array */
        for (i = 0; c_r[i]; i++)
                free(c_r[i]);
        for (i = 0; rs_r[i]; i++)
                free(rs_r[i]);
}

static void test_strv_shell_escape_null(void) {
        /* NULL array returns NULL */
        char **c_r, **rs_r;

        c_r = strv_shell_escape(NULL, SHELL_NEED_ESCAPE);
        rs_r = rs_strv_shell_escape(NULL, SHELL_NEED_ESCAPE);
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);
}

static void test_strv_shell_escape_empty(void) {
        char *c_arr[] = { NULL };
        char *rs_arr[] = { NULL };

        /* The C loop never consumes bad for an empty vector. */
        assert_se(strv_shell_escape(c_arr, NULL) == c_arr);
        assert_se(rs_strv_shell_escape(rs_arr, NULL) == rs_arr);
}

int main(int argc, char **argv) {
        test_strv_shell_escape();
        test_strv_shell_escape_null();
        test_strv_shell_escape_empty();
        return 0;
}
