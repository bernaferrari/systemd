/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "user-util.h"

TEST(is_nologin_shell) {
        assert_se(is_nologin_shell(NOLOGIN));
        assert_se(is_nologin_shell("/sbin/nologin"));
        assert_se(is_nologin_shell("/usr/sbin/nologin"));
        assert_se(!is_nologin_shell("/bin/bash"));
        assert_se(!is_nologin_shell("/bin/sh"));
        assert_se(!is_nologin_shell(""));
}

TEST(shell_is_placeholder) {
        assert_se(shell_is_placeholder(NOLOGIN));
        assert_se(shell_is_placeholder("/bin/false"));
        assert_se(shell_is_placeholder("/usr/bin/false"));
        assert_se(!shell_is_placeholder("/bin/bash"));
        /* Empty string IS a placeholder */
        assert_se(shell_is_placeholder(""));
}

TEST(hashed_password_is_locked_or_invalid) {
        /* Locked: starts with '!' or '*' */
        assert_se(hashed_password_is_locked_or_invalid("!locked"));
        assert_se(hashed_password_is_locked_or_invalid("*invalid"));
        assert_se(hashed_password_is_locked_or_invalid(PASSWORD_LOCKED_AND_INVALID));

        /* Valid: starts with '$' */
        assert_se(!hashed_password_is_locked_or_invalid("$6$hash"));

        /* NULL is not locked/invalid */
        assert_se(!hashed_password_is_locked_or_invalid(NULL));

        /* Empty is invalid (not $) */
        assert_se(hashed_password_is_locked_or_invalid(""));
}

TEST(gid_is_valid) {
        assert_se(gid_is_valid(0));
        assert_se(gid_is_valid(100));
        assert_se(gid_is_valid(GID_NOBODY));
        assert_se(!gid_is_valid(GID_INVALID));
}

TEST(parse_gid) {
        gid_t gid;

        assert_se(parse_gid("0", &gid) >= 0 && gid == 0);
        assert_se(parse_gid("100", &gid) >= 0 && gid == 100);
        assert_se(parse_gid("nobody", &gid) < 0);
        assert_se(parse_gid("-1", &gid) < 0);
        assert_se(parse_gid("", &gid) < 0);
}

TEST(uid_is_valid) {
        assert_se(uid_is_valid(0));
        assert_se(uid_is_valid(1000));
        assert_se(!uid_is_valid(UID_INVALID));
}

TEST(parse_uid) {
        uid_t uid;

        assert_se(parse_uid("0", &uid) >= 0 && uid == 0);
        assert_se(parse_uid("1000", &uid) >= 0 && uid == 1000);
        assert_se(parse_uid("root", &uid) < 0);
        assert_se(parse_uid("-1", &uid) < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
