/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "terminal-util.h"
#include "tests.h"

TEST(tty_is_console) {
        ASSERT_TRUE(tty_is_console("/dev/console"));
        ASSERT_TRUE(tty_is_console("console"));
        ASSERT_FALSE(tty_is_console("/dev/tty0"));
        ASSERT_FALSE(tty_is_console("/dev/ttyS0"));
        ASSERT_FALSE(tty_is_console("/dev/pts/0"));
}

TEST(tty_is_vc) {
        ASSERT_TRUE(tty_is_vc("/dev/tty0"));
        ASSERT_TRUE(tty_is_vc("/dev/tty1"));
        ASSERT_TRUE(tty_is_vc("/dev/tty63"));
        ASSERT_FALSE(tty_is_vc("/dev/ttyS0"));
        ASSERT_FALSE(tty_is_vc("/dev/console"));
        ASSERT_FALSE(tty_is_vc("/dev/pts/0"));
        ASSERT_FALSE(tty_is_vc("/dev/null"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
