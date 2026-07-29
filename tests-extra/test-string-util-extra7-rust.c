/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: cellescape, string_erase, strextendn, strgrowpad0, escape_non_printable_full vs Rust */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"
#include "escape.h"
#include "rust/string_util.h"

static void test_cellescape(void) {
        char c_buf[64], rs_buf[64];

        /* Simple ASCII */
        strcpy(c_buf, "AAAAAAAAAAAA");
        strcpy(rs_buf, "AAAAAAAAAAAA");
        assert_se(streq(cellescape(c_buf, sizeof(c_buf), "hello"), "hello"));
        assert_se(streq(rs_cellescape(rs_buf, sizeof(rs_buf), "hello"), "hello"));
        assert_se(streq(c_buf, rs_buf));

        /* With newline */
        strcpy(c_buf, "AAAAAAAAAAAA");
        strcpy(rs_buf, "AAAAAAAAAAAA");
        assert_se(streq(cellescape(c_buf, sizeof(c_buf), "he\nllo"), rs_cellescape(rs_buf, sizeof(rs_buf), "he\nllo")));
        assert_se(streq(c_buf, rs_buf));

        /* With tab */
        strcpy(c_buf, "AAAAAAAAAAAA");
        strcpy(rs_buf, "AAAAAAAAAAAA");
        assert_se(streq(cellescape(c_buf, sizeof(c_buf), "he\tllo"), rs_cellescape(rs_buf, sizeof(rs_buf), "he\tllo")));
        assert_se(streq(c_buf, rs_buf));

        /* Ellipsation: long string that doesn't fit */
        strcpy(c_buf, "AAAAAAAAAAAA");
        strcpy(rs_buf, "AAAAAAAAAAAA");
        assert_se(streq(cellescape(c_buf, 10, "1234567890abcdef"), rs_cellescape(rs_buf, 10, "1234567890abcdef")));
        assert_se(streq(c_buf, rs_buf));

        /* The three-byte ellipsis follows C's locale policy and may require
         * rolling back a multi-byte escape as one whole cell. */
        strcpy(c_buf, "AAAAAAAAAAAA");
        strcpy(rs_buf, "AAAAAAAAAAAA");
        assert_se(streq(cellescape(c_buf, 6, "1\020x"), rs_cellescape(rs_buf, 6, "1\020x")));
        assert_se(streq(c_buf, rs_buf));

        /* Empty string */
        strcpy(c_buf, "AAAAAAAAAAAA");
        strcpy(rs_buf, "AAAAAAAAAAAA");
        assert_se(streq(cellescape(c_buf, sizeof(c_buf), ""), ""));
        assert_se(streq(rs_cellescape(rs_buf, sizeof(rs_buf), ""), ""));
        assert_se(streq(c_buf, rs_buf));

        /* Tiny buffer */
        assert_se(streq(cellescape(c_buf, 5, "hello"), rs_cellescape(rs_buf, 5, "hello")));
        assert_se(streq(c_buf, rs_buf));
}

static void test_string_erase(void) {
        char c_buf[] = "secret12345";
        char rs_buf[] = "secret12345";

        assert_se(string_erase(c_buf) == c_buf);
        assert_se(rs_string_erase(rs_buf) == rs_buf);
        assert_se(streq(c_buf, rs_buf));
        /* Content should be zeroed */
        for (size_t i = 0; i < sizeof(c_buf); i++) {
                assert_se(c_buf[i] == '\0');
                assert_se(rs_buf[i] == '\0');
        }

        /* NULL input */
        assert_se(string_erase(NULL) == NULL);
        assert_se(rs_string_erase(NULL) == NULL);
}

static void test_strextendn(void) {
        char *c_r = NULL, *rs_r = NULL;

        /* Extend NULL */
        c_r = strextendn(&c_r, "hello", 5);
        rs_r = rs_strextendn(&rs_r, "hello", 5);
        assert_se(streq(c_r, rs_r));
        assert_se(streq(c_r, "hello"));
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* Extend existing */
        c_r = strdup("hello");
        rs_r = strdup("hello");
        c_r = strextendn(&c_r, " world", 6);
        rs_r = rs_strextendn(&rs_r, " world", 6);
        assert_se(streq(c_r, rs_r));
        assert_se(streq(c_r, "hello world"));
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* Extend with n > strlen (should use strnlen) */
        c_r = strdup("ab");
        rs_r = strdup("ab");
        c_r = strextendn(&c_r, "cd", 10);
        rs_r = rs_strextendn(&rs_r, "cd", 10);
        assert_se(streq(c_r, rs_r));
        assert_se(streq(c_r, "abcd"));
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* Extend with 0 length */
        c_r = strdup("hello");
        rs_r = strdup("hello");
        c_r = strextendn(&c_r, "world", 0);
        rs_r = rs_strextendn(&rs_r, "world", 0);
        assert_se(streq(c_r, rs_r));
        assert_se(streq(c_r, "hello"));
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* A zero-byte append still initializes a NULL destination. */
        c_r = strextendn(&c_r, NULL, 0);
        rs_r = rs_strextendn(&rs_r, NULL, 0);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r, rs_r));
        assert_se(streq(c_r, ""));
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;
}

static void test_strgrowpad0(void) {
        char *c_r = NULL, *rs_r = NULL;
        int c_ret, rs_ret;

        /* Grow NULL */
        c_ret = strgrowpad0(&c_r, 10);
        rs_ret = rs_strgrowpad0(&rs_r, 10);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        /* First byte should be NUL */
        assert_se(c_r[0] == '\0');
        assert_se(rs_r[0] == '\0');
        assert_se(streq(c_r, rs_r));
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* Grow existing */
        c_r = strdup("hi");
        rs_r = strdup("hi");
        c_ret = strgrowpad0(&c_r, 10);
        rs_ret = rs_strgrowpad0(&rs_r, 10);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(streq(c_r, rs_r));
        assert_se(streq(c_r, "hi"));
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* Never shrink */
        c_r = strdup("hello world");
        rs_r = strdup("hello world");
        c_ret = strgrowpad0(&c_r, 5);
        rs_ret = rs_strgrowpad0(&rs_r, 5);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(streq(c_r, rs_r));
        assert_se(streq(c_r, "hello world"));
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;
}

static void test_escape_non_printable_full(void) {
        char *c_r, *rs_r;

        /* Simple printable string */
        c_r = escape_non_printable_full("hello", 100, 0);
        rs_r = rs_escape_non_printable_full("hello", 100, 0);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r, rs_r));
        assert_se(streq(c_r, "hello"));
        free(c_r); free(rs_r);

        /* String with newline */
        c_r = escape_non_printable_full("he\nllo", 100, 0);
        rs_r = rs_escape_non_printable_full("he\nllo", 100, 0);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Console width truncation */
        c_r = escape_non_printable_full("hello world!", 5, 0);
        rs_r = rs_escape_non_printable_full("hello world!", 5, 0);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* With XESCAPE_8_BIT flag */
        c_r = escape_non_printable_full("hello", 100, 1);
        rs_r = rs_escape_non_printable_full("hello", 100, 1);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Zero console width */
        c_r = escape_non_printable_full("hello", 0, 0);
        rs_r = rs_escape_non_printable_full("hello", 0, 0);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r, rs_r));
        assert_se(streq(c_r, ""));
        free(c_r); free(rs_r);

        /* Invalid UTF-8 is replaced byte-wise without routing through Rust text. */
        c_r = escape_non_printable_full("\xff", 100, 0);
        rs_r = rs_escape_non_printable_full("\xff", 100, 0);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* The bit ABI also controls the C xescape path and forced ellipsis. */
        c_r = escape_non_printable_full("\xff", 100, XESCAPE_8_BIT);
        rs_r = rs_escape_non_printable_full("\xff", 100, XESCAPE_8_BIT);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        c_r = escape_non_printable_full("abc", 8, XESCAPE_FORCE_ELLIPSIS);
        rs_r = rs_escape_non_printable_full("abc", 8, XESCAPE_FORCE_ELLIPSIS);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);
}

int main(int argc, char **argv) {
        test_cellescape();
        test_string_erase();
        test_strextendn();
        test_strgrowpad0();
        test_escape_non_printable_full();
        return 0;
}
