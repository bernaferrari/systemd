/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: xescape_full, shell_maybe_quote, cunescape_length_with_prefix vs Rust */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"
#include "escape.h"
#include "rust/escape.h"

static void test_xescape_full(void) {
        char *c_r, *rs_r;

        /* Simple ASCII, no bad chars */
        c_r = xescape_full("hello", NULL, SIZE_MAX, 0);
        rs_r = rs_xescape_full("hello", NULL, SIZE_MAX, 0);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* With backslash */
        c_r = xescape_full("hello\\world", NULL, SIZE_MAX, 0);
        rs_r = rs_xescape_full("hello\\world", NULL, SIZE_MAX, 0);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* With bad chars */
        c_r = xescape_full("a:b:c", ":", SIZE_MAX, 0);
        rs_r = rs_xescape_full("a:b:c", ":", SIZE_MAX, 0);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* With control char */
        c_r = xescape_full("a\tb", NULL, SIZE_MAX, 0);
        rs_r = rs_xescape_full("a\tb", NULL, SIZE_MAX, 0);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* With 8-bit flag */
        c_r = xescape_full("café", NULL, SIZE_MAX, XESCAPE_8_BIT);
        rs_r = rs_xescape_full("café", NULL, SIZE_MAX, XESCAPE_8_BIT);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* With console_width truncation */
        c_r = xescape_full("hello world", NULL, 8, 0);
        rs_r = rs_xescape_full("hello world", NULL, 8, 0);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* With FORCE_ELLIPSIS */
        c_r = xescape_full("hello", NULL, 5, XESCAPE_FORCE_ELLIPSIS);
        rs_r = rs_xescape_full("hello", NULL, 5, XESCAPE_FORCE_ELLIPSIS);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Empty string */
        c_r = xescape_full("", NULL, SIZE_MAX, 0);
        rs_r = rs_xescape_full("", NULL, SIZE_MAX, 0);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* console_width=0 */
        c_r = xescape_full("hello", NULL, 0, 0);
        rs_r = rs_xescape_full("hello", NULL, 0, 0);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* xescape is byte-oriented, even for invalid UTF-8. */
        static const char non_ascii[] = { 'a', (char) 0x80, 'b', 0 };
        static const char bad_non_ascii[] = { (char) 0x80, 0 };
        c_r = xescape_full(non_ascii, bad_non_ascii, SIZE_MAX, 0);
        rs_r = rs_xescape_full(non_ascii, bad_non_ascii, SIZE_MAX, 0);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* C assert()s on this contract violation; Rust must fail closed. */
        assert_se(rs_xescape_full(NULL, NULL, 3, 0) == NULL);
}

static void test_shell_maybe_quote(void) {
        char *c_r, *rs_r;

        /* Simple word — no quoting needed */
        c_r = shell_maybe_quote("hello", 0);
        rs_r = rs_shell_maybe_quote("hello", 0);
        assert_se(streq(c_r, rs_r));
        assert_se(streq(c_r, "hello"));
        free(c_r); free(rs_r);

        /* Word with space */
        c_r = shell_maybe_quote("hello world", 0);
        rs_r = rs_shell_maybe_quote("hello world", 0);
        assert_se(streq(c_r, rs_r));
        assert_se(streq(c_r, "\"hello world\""));
        free(c_r); free(rs_r);

        /* Word with single quote */
        c_r = shell_maybe_quote("it's", 0);
        rs_r = rs_shell_maybe_quote("it's", 0);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Empty string with SHELL_ESCAPE_EMPTY */
        c_r = shell_maybe_quote("", SHELL_ESCAPE_EMPTY);
        rs_r = rs_shell_maybe_quote("", SHELL_ESCAPE_EMPTY);
        assert_se(streq(c_r, rs_r));
        assert_se(streq(c_r, "\"\""));
        free(c_r); free(rs_r);

        /* POSIX mode */
        c_r = shell_maybe_quote("hello world", SHELL_ESCAPE_POSIX);
        rs_r = rs_shell_maybe_quote("hello world", SHELL_ESCAPE_POSIX);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* POSIX mode with special chars */
        c_r = shell_maybe_quote("it's a test", SHELL_ESCAPE_POSIX);
        rs_r = rs_shell_maybe_quote("it's a test", SHELL_ESCAPE_POSIX);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* A malformed byte starts the escaped suffix byte-by-byte. */
        static const char malformed[] = { 'a', (char) 0xc3, '(', 0 };
        c_r = shell_maybe_quote(malformed, 0);
        rs_r = rs_shell_maybe_quote(malformed, 0);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        assert_se(rs_shell_maybe_quote(NULL, 0) == NULL);
}

static void test_cunescape_length_with_prefix(void) {
        char *c_r = NULL, *rs_r = NULL;
        ssize_t c_ret, rs_ret;

        /* Simple string with prefix */
        c_ret = cunescape_length_with_prefix("hello", 5, "prefix:", 0, &c_r);
        rs_ret = rs_cunescape_length_with_prefix("hello", 5, "prefix:", 0, &rs_r);
        assert_se(c_ret == rs_ret);
        if (c_ret >= 0) {
                assert_se(streq(c_r, rs_r));
        }
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* String with escape */
        c_ret = cunescape_length_with_prefix("a\\nb", 4, NULL, 0, &c_r);
        rs_ret = rs_cunescape_length_with_prefix("a\\nb", 4, NULL, 0, &rs_r);
        assert_se(c_ret == rs_ret);
        if (c_ret >= 0) {
                assert_se(streq(c_r, rs_r));
        }
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* With hex escape */
        c_ret = cunescape_length_with_prefix("a\\x41b", 5, NULL, 0, &c_r);
        rs_ret = rs_cunescape_length_with_prefix("a\\x41b", 5, NULL, 0, &rs_r);
        assert_se(c_ret == rs_ret);
        if (c_ret >= 0) {
                assert_se(streq(c_r, rs_r));
        }
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* With relax flag on trailing backslash */
        c_ret = cunescape_length_with_prefix("hello\\", 6, NULL, UNESCAPE_RELAX, &c_r);
        rs_ret = rs_cunescape_length_with_prefix("hello\\", 6, NULL, UNESCAPE_RELAX, &rs_r);
        assert_se(c_ret == rs_ret);
        if (c_ret >= 0) {
                assert_se(streq(c_r, rs_r));
        }
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* Empty prefix */
        c_ret = cunescape_length_with_prefix("hello", 5, "", 0, &c_r);
        rs_ret = rs_cunescape_length_with_prefix("hello", 5, "", 0, &rs_r);
        assert_se(c_ret == rs_ret);
        if (c_ret >= 0) {
                assert_se(streq(c_r, rs_r));
        }
        free(c_r); free(rs_r);

        /* Explicit length, prefix, and successful output may all contain
         * bytes that are not valid UTF-8 or printable C-string text. */
        static const char escaped_nul[] = { 'a', '\\', 'x', '0', '0', 'b' };
        static const char binary_prefix[] = { 'p', (char) 0xff, 0 };
        c_r = rs_r = NULL;
        c_ret = cunescape_length_with_prefix(escaped_nul, sizeof(escaped_nul), binary_prefix, UNESCAPE_ACCEPT_NUL, &c_r);
        rs_ret = rs_cunescape_length_with_prefix(escaped_nul, sizeof(escaped_nul), binary_prefix, UNESCAPE_ACCEPT_NUL, &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 5);
        assert_se(memcmp(c_r, rs_r, (size_t) c_ret) == 0);
        free(c_r); free(rs_r);

        /* Failure must not publish an allocation through ret. */
        static char untouched;
        rs_r = &untouched;
        rs_ret = rs_cunescape_length_with_prefix("\\q", 2, NULL, 0, &rs_r);
        assert_se(rs_ret < 0);
        assert_se(rs_r == &untouched);
        assert_se(rs_cunescape_length_with_prefix(NULL, 0, NULL, 0, &rs_r) < 0);
        assert_se(rs_cunescape_length_with_prefix("", 0, NULL, 0, NULL) < 0);
}

static void test_quote_command_line(void) {
        char *c_r, *rs_r;
        char *argv1[] = { (char*)"true", (char*)"true", NULL };
        char *argv2[] = { (char*)"true", (char*)"with a space", NULL };
        char *argv3[] = { (char*)"true", (char*)"with a 'quote'", NULL };
        char *argv4[] = { (char*)"true", (char*)"with a \"quote\"", NULL };
        char *argv5[] = { (char*)"true", (char*)"$dollar", NULL };
        char *argv6[] = { (char*)"hello", NULL };
        char *empty_argv[] = { NULL };

        c_r = quote_command_line(argv1, SHELL_ESCAPE_EMPTY);
        rs_r = rs_quote_command_line(argv1, SHELL_ESCAPE_EMPTY);
        assert_se(c_r && rs_r && streq(c_r, rs_r));
        free(c_r); free(rs_r);

        c_r = quote_command_line(argv2, SHELL_ESCAPE_EMPTY);
        rs_r = rs_quote_command_line(argv2, SHELL_ESCAPE_EMPTY);
        assert_se(c_r && rs_r && streq(c_r, rs_r));
        free(c_r); free(rs_r);

        c_r = quote_command_line(argv3, SHELL_ESCAPE_EMPTY);
        rs_r = rs_quote_command_line(argv3, SHELL_ESCAPE_EMPTY);
        assert_se(c_r && rs_r && streq(c_r, rs_r));
        free(c_r); free(rs_r);

        c_r = quote_command_line(argv4, SHELL_ESCAPE_EMPTY);
        rs_r = rs_quote_command_line(argv4, SHELL_ESCAPE_EMPTY);
        assert_se(c_r && rs_r && streq(c_r, rs_r));
        free(c_r); free(rs_r);

        c_r = quote_command_line(argv5, SHELL_ESCAPE_EMPTY);
        rs_r = rs_quote_command_line(argv5, SHELL_ESCAPE_EMPTY);
        assert_se(c_r && rs_r && streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Single argument */
        c_r = quote_command_line(argv6, SHELL_ESCAPE_EMPTY);
        rs_r = rs_quote_command_line(argv6, SHELL_ESCAPE_EMPTY);
        assert_se(c_r && rs_r && streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Empty argv — both return NULL */
        c_r = quote_command_line(empty_argv, SHELL_ESCAPE_EMPTY);
        rs_r = rs_quote_command_line(empty_argv, SHELL_ESCAPE_EMPTY);
        assert_se(c_r == NULL && rs_r == NULL);

        assert_se(rs_quote_command_line(NULL, SHELL_ESCAPE_EMPTY) == NULL);
}

int main(int argc, char **argv) {
        test_xescape_full();
        test_shell_maybe_quote();
        test_cunescape_length_with_prefix();
        test_quote_command_line();
        return 0;
}
