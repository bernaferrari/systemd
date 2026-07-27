/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "utf8.h"
#include "tests.h"

TEST(utf8_is_printable_newline_basic) {
        /* Regular printable string */
        assert_se(utf8_is_printable_newline("hello", 5, false));
        assert_se(utf8_is_printable_newline("hello\n", 6, true));
        assert_se(!utf8_is_printable_newline("hello\n", 6, false));
        assert_se(!utf8_is_printable_newline("hello\x01", 6, true));
}

TEST(utf8_n_codepoints_basic) {
        assert_se(utf8_n_codepoints("") == 0);
        assert_se(utf8_n_codepoints("a") == 1);
        assert_se(utf8_n_codepoints("abc") == 3);
        assert_se(utf8_n_codepoints("ä") == 1);  /* single UTF-8 codepoint */
        assert_se(utf8_n_codepoints("äbc") == 3);
}

TEST(utf8_console_width_basic) {
        assert_se(utf8_console_width("") == 0);
        assert_se(utf8_console_width("a") == 1);
        assert_se(utf8_console_width("abc") == 3);
        /* CJK characters are typically 2 cells wide */
        assert_se(utf8_console_width("\xe4\xb8\xad") == 2);  /* U+4E2D = '中' */
}

DEFINE_TEST_MAIN(LOG_DEBUG);
