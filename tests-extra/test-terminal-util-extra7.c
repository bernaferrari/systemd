/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <termios.h>

#include "terminal-util.h"
#include "tests.h"

TEST(isatty_safe_basic) {
        /* stdin/stdout/stderr are always valid fds for isatty_safe */
        (void) isatty_safe(STDIN_FILENO);
        (void) isatty_safe(STDOUT_FILENO);
        (void) isatty_safe(STDERR_FILENO);
}

TEST(termios_disable_echo_basic) {
        struct termios t = {};
        termios_disable_echo(&t);
        assert_se(!(t.c_lflag & ICANON));
        assert_se(!(t.c_lflag & ECHO));
        assert_se(t.c_cc[VMIN] == 1);
        assert_se(t.c_cc[VTIME] == 0);
}

TEST(get_log_colors_basic) {
        const char *on, *off, *highlight;

        get_log_colors(LOG_EMERG, &on, &off, &highlight);
        assert_se(on || !on);

        get_log_colors(LOG_WARNING, &on, &off, &highlight);
        assert_se(on || !on);

        get_log_colors(LOG_DEBUG, &on, &off, &highlight);
        assert_se(on || !on);
}

TEST(dev_console_colors_enabled_basic) {
        (void) dev_console_colors_enabled();
}

TEST(terminal_is_dumb_basic) {
        (void) terminal_is_dumb();
}

TEST(lines_columns_basic) {
        unsigned c = columns();
        unsigned l = lines();
        assert_se(c > 0);
        assert_se(l > 0);
        log_debug("columns: %u, lines: %u", c, l);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
