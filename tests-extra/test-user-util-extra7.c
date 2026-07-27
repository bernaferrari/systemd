/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "user-util.h"
#include "tests.h"

TEST(hashed_password_is_locked_or_invalid_basic) {
        /* Locked: starts with ! */
        assert_se(hashed_password_is_locked_or_invalid("!"));
        assert_se(hashed_password_is_locked_or_invalid("!!"));
        assert_se(hashed_password_is_locked_or_invalid("!$1$xyz"));

        /* Not locked: valid hash prefix (starts with $) */
        assert_se(!hashed_password_is_locked_or_invalid("$1$salt$hash"));
        assert_se(!hashed_password_is_locked_or_invalid("$6$salt$hash"));
        /* These are all locked/invalid (don't start with $) */
        assert_se(hashed_password_is_locked_or_invalid("x"));
        assert_se(hashed_password_is_locked_or_invalid("*"));
}

TEST(uid_is_valid_basic) {
        assert_se(uid_is_valid(0));
        assert_se(uid_is_valid(1000));
        assert_se(!uid_is_valid(UID_INVALID));
}

TEST(gid_is_valid_basic) {
        assert_se(gid_is_valid(0));
        assert_se(gid_is_valid(1000));
        assert_se(!gid_is_valid(GID_INVALID));
}

TEST(valid_shell_basic) {
        assert_se(valid_shell("/bin/bash"));
        assert_se(valid_shell("/usr/bin/zsh"));
        assert_se(!valid_shell("bash"));
        assert_se(!valid_shell(""));
        assert_se(!valid_shell("/bin/bash/../etc/passwd"));
}

TEST(valid_home_basic) {
        assert_se(valid_home("/home/user"));
        assert_se(valid_home("/root"));
        assert_se(!valid_home(""));
        assert_se(!valid_home("home/user"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
