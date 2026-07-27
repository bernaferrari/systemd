/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: escape functions vs Rust */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"
#include "escape.h"
#include "rust/escape.h"

static void test_octescape(void) {
        char *c_r, *rs_r;

        /* Simple ASCII */
        c_r = octescape("hello", 5);
        rs_r = rs_octescape("hello", 5);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Backslash and quote */
        c_r = octescape("hello\\world", 11);
        rs_r = rs_octescape("hello\\world", 11);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Quote and backslash */
        c_r = octescape("say \"hi\"", 8);
        rs_r = rs_octescape("say \"hi\"", 8);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Control chars */
        c_r = octescape("a\tb\nc", 5);
        rs_r = rs_octescape("a\tb\nc", 5);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Empty */
        c_r = octescape("", 0);
        rs_r = rs_octescape("", 0);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* NULL with len=0 */
        c_r = octescape(NULL, 0);
        rs_r = rs_octescape(NULL, 0);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* With SIZE_MAX */
        c_r = octescape("abc", SIZE_MAX);
        rs_r = rs_octescape("abc", SIZE_MAX);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Explicit lengths are bytes, not a UTF-8 or C-string-only API. */
        static const char binary[] = { 'a', 0, '\\', '\xff' };
        c_r = octescape(binary, sizeof(binary));
        rs_r = rs_octescape(binary, sizeof(binary));
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* This violates escape.h's nonnull-if-nonzero contract, so Rust must
         * fail closed rather than dereference it. */
        assert_se(rs_octescape(NULL, 1) == NULL);
}

static void test_decescape(void) {
        char *c_r, *rs_r;

        /* Simple ASCII */
        c_r = decescape("hello", 5, "");
        rs_r = rs_decescape("hello", 5, "");
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Backslash and quote */
        c_r = decescape("hello\\world", 11, "");
        rs_r = rs_decescape("hello\\world", 11, "");
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* With bad chars */
        c_r = decescape("a:b:c", 5, ":");
        rs_r = rs_decescape("a:b:c", 5, ":");
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Control chars */
        c_r = decescape("a\tb", 3, "");
        rs_r = rs_decescape("a\tb", 3, "");
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* NULL with len=0 */
        c_r = decescape(NULL, 0, "");
        rs_r = rs_decescape(NULL, 0, "");
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        static const char binary[] = { 'a', 0, '\\', '\xff' };
        c_r = decescape(binary, sizeof(binary), "a");
        rs_r = rs_decescape(binary, sizeof(binary), "a");
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        assert_se(rs_decescape("a", 1, NULL) == NULL);
        assert_se(rs_decescape(NULL, 1, "") == NULL);
}

static void test_shell_escape(void) {
        char *c_r, *rs_r;

        /* Simple word */
        c_r = shell_escape("hello", SHELL_NEED_ESCAPE);
        rs_r = rs_shell_escape("hello", SHELL_NEED_ESCAPE);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* With special chars */
        c_r = shell_escape("hello world", SHELL_NEED_ESCAPE);
        rs_r = rs_shell_escape("hello world", SHELL_NEED_ESCAPE);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* With quote */
        c_r = shell_escape("it's", SHELL_NEED_ESCAPE);
        rs_r = rs_shell_escape("it's", SHELL_NEED_ESCAPE);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* No special chars */
        c_r = shell_escape("hello", SHELL_NEED_ESCAPE);
        rs_r = rs_shell_escape("hello", SHELL_NEED_ESCAPE);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Invalid UTF-8 is escaped byte by byte, while a valid multibyte
         * character is copied intact. Neither path may go through Rust str. */
        static const char malformed[] = "\xc3" "(";
        c_r = shell_escape(malformed, SHELL_NEED_ESCAPE);
        rs_r = rs_shell_escape(malformed, SHELL_NEED_ESCAPE);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        c_r = shell_escape("\xc3\xa9", SHELL_NEED_ESCAPE);
        rs_r = rs_shell_escape("\xc3\xa9", SHELL_NEED_ESCAPE);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* C's utf8.c rejects Unicode noncharacters too, so this must take
         * the byte-at-a-time cescape path rather than be copied as UTF-8. */
        c_r = shell_escape("\xef\xbf\xbe", SHELL_NEED_ESCAPE);
        rs_r = rs_shell_escape("\xef\xbf\xbe", SHELL_NEED_ESCAPE);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        assert_se(rs_shell_escape(NULL, SHELL_NEED_ESCAPE) == NULL);
        assert_se(rs_shell_escape("hello", NULL) == NULL);
}

int main(int argc, char **argv) {
        test_octescape();
        test_decescape();
        test_shell_escape();
        return 0;
}
