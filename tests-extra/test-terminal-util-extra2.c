/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "terminal-util.h"
#include "tests.h"

TEST(tty_is_console_basic) {
        assert_se(tty_is_console("console"));
        assert_se(tty_is_console("/dev/console"));
        assert_se(!tty_is_console("tty1"));
        assert_se(!tty_is_console("tty0"));
        assert_se(!tty_is_console("ttyS0"));
        assert_se(!tty_is_console("pts/0"));
}

TEST(tty_is_vc_basic) {
        assert_se(tty_is_vc("tty1"));
        assert_se(tty_is_vc("tty0"));
        assert_se(tty_is_vc("tty63"));
        assert_se(!tty_is_vc("ttyS0"));
        assert_se(!tty_is_vc("pts/0"));
        assert_se(!tty_is_vc("console"));
}

TEST(vtnr_from_tty_basic) {
        assert_se(vtnr_from_tty("tty1") == 1);
        assert_se(vtnr_from_tty("tty63") == 63);
        assert_se(vtnr_from_tty("/dev/tty1") == 1);
        /* tty0 is not a valid VT number (vtnr starts at 1) */
        assert_se(vtnr_from_tty("tty0") == -ERANGE);
        assert_se(vtnr_from_tty("ttyS0") == -EINVAL);
        assert_se(vtnr_from_tty("pts/0") == -EINVAL);
}

TEST(vtnr_is_valid_basic) {
        assert_se(!vtnr_is_valid(0));
        assert_se(vtnr_is_valid(1));
        assert_se(vtnr_is_valid(63));
        assert_se(!vtnr_is_valid(64));
        assert_se(!vtnr_is_valid(65535));
}

TEST(getenv_columns_basic) {
        /* Save and restore */
        const char *saved = getenv("COLUMNS");
        char *old = saved ? strdup(saved) : NULL;

        setenv("COLUMNS", "120", 1);
        assert_se(getenv_columns() == 120);

        setenv("COLUMNS", "80", 1);
        assert_se(getenv_columns() == 80);

        /* Restore */
        if (old) {
                setenv("COLUMNS", old, 1);
                free(old);
        } else
                unsetenv("COLUMNS");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
