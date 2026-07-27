/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <syslog.h>

#include "string-util.h"
#include "terminal-util.h"
#include "tests.h"

TEST(get_log_colors_basic) {
        const char *on = NULL, *off = NULL, *highlight = NULL;

        /* LOG_ERR → red */
        get_log_colors(LOG_ERR, &on, &off, &highlight);
        assert_se(on != NULL);
        assert_se(off != NULL);
        assert_se(highlight != NULL);

        /* LOG_WARNING → yellow */
        on = off = highlight = NULL;
        get_log_colors(LOG_WARNING, &on, &off, &highlight);
        assert_se(on != NULL);

        /* LOG_NOTICE → bold */
        on = off = highlight = NULL;
        get_log_colors(LOG_NOTICE, &on, &off, &highlight);
        assert_se(on != NULL);

        /* LOG_INFO → highlight color */
        on = off = highlight = NULL;
        get_log_colors(LOG_INFO, &on, &off, &highlight);
        /* Just verify it doesn't crash — actual values depend on color mode */

        /* LOG_DEBUG → no special color */
        on = off = highlight = NULL;
        get_log_colors(LOG_DEBUG, &on, &off, &highlight);
        /* Just verify it doesn't crash */
}

TEST(getenv_terminal_is_dumb_basic) {
        /* With no TERM set, it should return true */
        unsetenv("TERM");
        assert_se(getenv_terminal_is_dumb());

        /* With TERM=dumb */
        setenv("TERM", "dumb", true);
        assert_se(getenv_terminal_is_dumb());

        /* With TERM=xterm-256color */
        setenv("TERM", "xterm-256color", true);
        assert_se(!getenv_terminal_is_dumb());

        /* Clean up */
        unsetenv("TERM");
}

TEST(terminal_is_dumb_basic) {
        /* In test environment (no real tty), this depends on context */
        /* Just verify it doesn't crash */
        (void) terminal_is_dumb();
}

TEST(getenv_columns_basic) {
        /* With COLUMNS set */
        setenv("COLUMNS", "120", true);
        assert_se(getenv_columns() == 120);
        unsetenv("COLUMNS");

        /* With invalid COLUMNS */
        setenv("COLUMNS", "abc", true);
        assert_se(getenv_columns() <= 0);
        unsetenv("COLUMNS");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
