/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "user-util.h"

TEST(uid_is_valid) {
        assert_se(uid_is_valid(0));
        assert_se(uid_is_valid(1));
        assert_se(uid_is_valid(1000));
        assert_se(uid_is_valid(65534));

        /* UID_INVALID */
        assert_se(!uid_is_valid(UID_INVALID));
        /* 16-bit -1 */
        assert_se(!uid_is_valid((uid_t) 0xFFFF));
        /* 32-bit -1 */
        assert_se(!uid_is_valid((uid_t) 0xFFFFFFFF));
}

TEST(gid_is_valid) {
        assert_se(gid_is_valid(0));
        assert_se(gid_is_valid(1000));

        assert_se(!gid_is_valid(GID_INVALID));
        assert_se(!gid_is_valid((gid_t) 0xFFFF));
}

TEST(valid_gecos_basic) {
        /* Valid GECOS */
        assert_se(valid_gecos(""));
        assert_se(valid_gecos("John Doe"));
        assert_se(valid_gecos("John Doe,Engineering"));
        assert_se(valid_gecos("root"));

        /* NULL is not valid */
        assert_se(!valid_gecos(NULL));
}

TEST(valid_home_basic) {
        /* Valid home dirs */
        assert_se(valid_home("/home/user"));
        assert_se(valid_home("/"));
        assert_se(valid_home("/root"));
        assert_se(valid_home("/var/lib/foo"));

        /* Empty is not valid */
        assert_se(!valid_home(""));

        /* Relative paths are not valid */
        assert_se(!valid_home("home/user"));

        /* Paths with colon are not valid (field separator) */
        assert_se(!valid_home("/home:user"));

        /* Paths with .. are not valid (not normalized) */
        assert_se(!valid_home("/home/../etc"));
}

TEST(valid_shell_basic) {
        /* Valid shells */
        assert_se(valid_shell("/bin/bash"));
        assert_se(valid_shell("/bin/sh"));
        assert_se(valid_shell("/usr/bin/zsh"));

        /* Trailing slash → not valid (looks like directory) */
        assert_se(!valid_shell("/bin/bash/"));

        /* Empty is not valid */
        assert_se(!valid_shell(""));

        /* Relative path is not valid */
        assert_se(!valid_shell("bash"));
}

TEST(is_nologin_shell_basic) {
        assert_se(is_nologin_shell("/sbin/nologin"));
        assert_se(is_nologin_shell("/usr/sbin/nologin"));
        assert_se(is_nologin_shell("/bin/nologin"));
        assert_se(is_nologin_shell("/usr/bin/nologin"));

        assert_se(!is_nologin_shell("/bin/bash"));
        assert_se(!is_nologin_shell("/bin/sh"));
}

TEST(shell_is_placeholder_basic) {
        /* nologin shells are placeholders */
        assert_se(shell_is_placeholder("/sbin/nologin"));

        /* Empty string is placeholder */
        assert_se(shell_is_placeholder(""));

        /* Regular shells are not */
        assert_se(!shell_is_placeholder("/bin/bash"));
}

TEST(hashed_password_is_locked_or_invalid) {
        assert_se(hashed_password_is_locked_or_invalid("!"));
        assert_se(hashed_password_is_locked_or_invalid("*"));
        assert_se(hashed_password_is_locked_or_invalid("x"));
        assert_se(hashed_password_is_locked_or_invalid("locked"));

        assert_se(!hashed_password_is_locked_or_invalid("$6$..."));
        assert_se(!hashed_password_is_locked_or_invalid("$1$..."));
        assert_se(!hashed_password_is_locked_or_invalid(NULL));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
