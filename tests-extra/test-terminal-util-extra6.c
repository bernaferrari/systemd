/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "terminal-util.h"
#include "tests.h"

TEST(on_tty_basic) {
        /* Just verify no crash, result depends on environment */
        (void) on_tty();
}

TEST(columns_lines_cache_reset_basic) {
        /* Call reset, then columns/lines — just verify no crash */
        columns_lines_cache_reset(0);

        unsigned c = columns();
        assert_se(c > 0);

        unsigned l = lines();
        assert_se(l > 0);
}

TEST(reset_terminal_feature_caches_basic) {
        /* Just verify no crash */
        reset_terminal_feature_caches();

        /* Call twice to verify idempotency */
        reset_terminal_feature_caches();
}

TEST(getenv_columns_basic) {
        /* With COLUMNS set */
        assert_se(setenv("COLUMNS", "120", 1) >= 0);
        assert_se(getenv_columns() == 120);

        /* With invalid value */
        assert_se(setenv("COLUMNS", "abc", 1) >= 0);
        assert_se(getenv_columns() < 0);

        /* Unset */
        assert_se(unsetenv("COLUMNS") >= 0);
        (void) getenv_columns();

        /* Restore */
        assert_se(unsetenv("COLUMNS") >= 0);
}

TEST(getenv_terminal_is_dumb_basic) {
        /* TERM=dumb */
        assert_se(setenv("TERM", "dumb", 1) >= 0);
        assert_se(getenv_terminal_is_dumb());

        /* TERM=xterm */
        assert_se(setenv("TERM", "xterm", 1) >= 0);
        assert_se(!getenv_terminal_is_dumb());

        /* TERM unset */
        assert_se(unsetenv("TERM") >= 0);
        assert_se(getenv_terminal_is_dumb());

        /* Restore */
        assert_se(unsetenv("TERM") >= 0);
}

TEST(tty_is_vc_basic) {
        assert_se(!tty_is_vc("ttyS0"));
        assert_se(!tty_is_vc("pts/0"));
        assert_se(!tty_is_vc("/dev/ttyS0"));
}

TEST(tty_is_console_basic) {
        assert_se(tty_is_console("console"));
        assert_se(tty_is_console("/dev/console"));
        assert_se(!tty_is_console("tty1"));
        assert_se(!tty_is_console("/dev/tty1"));
}

TEST(vtnr_is_valid_basic) {
        assert_se(vtnr_is_valid(1));
        assert_se(vtnr_is_valid(63));
        assert_se(!vtnr_is_valid(0));
        assert_se(!vtnr_is_valid(64));
}

TEST(osc_char_is_valid_basic) {
        assert_se(osc_char_is_valid('a'));
        assert_se(osc_char_is_valid('Z'));
        assert_se(osc_char_is_valid('0'));
        assert_se(osc_char_is_valid('~'));
        assert_se(!osc_char_is_valid('\x01'));
        assert_se(!osc_char_is_valid('\x7f'));
        assert_se(osc_char_is_valid(' ')); /* space (0x20 = 32) is valid: >= 32 && < 127 */
}

DEFINE_TEST_MAIN(LOG_DEBUG);
