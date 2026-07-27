/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "escape.h"
#include "tests.h"

TEST(cescape_char) {
        char buf[8];

        /* Regular ASCII */
        ASSERT_EQ(cescape_char('A', buf), 1);
        assert_se(buf[0] == 'A');

        /* Backslash */
        ASSERT_EQ(cescape_char('\\', buf), 2);
        assert_se(buf[0] == '\\' && buf[1] == '\\');

        /* Newline */
        ASSERT_EQ(cescape_char('\n', buf), 2);
        assert_se(buf[0] == '\\' && buf[1] == 'n');

        /* Tab */
        ASSERT_EQ(cescape_char('\t', buf), 2);
        assert_se(buf[0] == '\\' && buf[1] == 't');

        /* Null byte is octal-encoded as \000 */
        ASSERT_EQ(cescape_char('\0', buf), 4);
        assert_se(buf[0] == '\\' && buf[1] == '0' && buf[2] == '0' && buf[3] == '0');

        /* Regular printable */
        ASSERT_EQ(cescape_char('z', buf), 1);
        assert_se(buf[0] == 'z');
}

TEST(cunescape_one) {
        char32_t ret;
        bool eight_bit;

        /* Non-escape character is invalid */
        ASSERT_EQ(cunescape_one("A", 1, &ret, &eight_bit, false), -EINVAL);

        /* Hex escape: x41 = 'A' (input is AFTER the backslash) */
        ASSERT_OK(cunescape_one("x41", 3, &ret, &eight_bit, false));
        ASSERT_EQ(ret, (char32_t)'A');

        /* Octal escape: 101 = 'A' */
        ASSERT_OK(cunescape_one("101", 3, &ret, &eight_bit, false));
        ASSERT_EQ(ret, (char32_t)'A');

        /* Simple escape: n = newline */
        ASSERT_OK(cunescape_one("n", 1, &ret, &eight_bit, false));
        ASSERT_EQ(ret, (char32_t)'\n');

        /* Backslash itself */
        ASSERT_OK(cunescape_one("\\", 1, &ret, &eight_bit, false));
        ASSERT_EQ(ret, (char32_t)'\\');
}

TEST(shell_escape) {
        _cleanup_free_ char *escaped = NULL;

        /* Safe string with no special chars */
        escaped = shell_escape("hello", SHELL_NEED_ESCAPE);
        ASSERT_STREQ(escaped, "hello");

        escaped = mfree(escaped);
        /* String with double quote */
        escaped = shell_escape("say \"hello\"", SHELL_NEED_ESCAPE);
        ASSERT_STREQ(escaped, "say \\\"hello\\\"");

        escaped = mfree(escaped);
        /* Empty string */
        escaped = shell_escape("", SHELL_NEED_ESCAPE);
        ASSERT_STREQ(escaped, "");
}

TEST(shell_maybe_quote) {
        _cleanup_free_ char *quoted = NULL;

        /* Safe string without special chars should not be quoted */
        quoted = shell_maybe_quote("hello", 0);
        ASSERT_STREQ(quoted, "hello");

        quoted = mfree(quoted);
        /* String with spaces should be quoted with double quotes */
        quoted = shell_maybe_quote("hello world", 0);
        ASSERT_STREQ(quoted, "\"hello world\"");

        quoted = mfree(quoted);
        /* Empty string without SHELL_ESCAPE_EMPTY flag returns empty */
        quoted = shell_maybe_quote("", 0);
        ASSERT_STREQ(quoted, "");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
