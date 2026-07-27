/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <termios.h>

#include "terminal-util.h"
#include "tests.h"

TEST(getenv_terminal_is_dumb) {
        const char *saved = getenv("TERM");
        char *old = saved ? strdup(saved) : NULL;

        /* TERM=dumb → true */
        setenv("TERM", "dumb", 1);
        assert_se(getenv_terminal_is_dumb());

        /* TERM unset → true */
        unsetenv("TERM");
        assert_se(getenv_terminal_is_dumb());

        /* TERM=xterm → false */
        setenv("TERM", "xterm", 1);
        assert_se(!getenv_terminal_is_dumb());

        /* Restore */
        if (old) {
                setenv("TERM", old, 1);
                free(old);
        } else
                unsetenv("TERM");
}

TEST(termios_disable_echo_basic) {
        struct termios t = {};
        /* Start with some flags set */
        t.c_lflag = ICANON | ECHO;
        t.c_cc[VMIN] = 0;
        t.c_cc[VTIME] = 0;

        termios_disable_echo(&t);

        /* ICANON and ECHO should be cleared */
        assert_se(!(t.c_lflag & ICANON));
        assert_se(!(t.c_lflag & ECHO));
        assert_se(t.c_cc[VMIN] == 1);
        assert_se(t.c_cc[VTIME] == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
