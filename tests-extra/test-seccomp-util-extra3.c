/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "string-util.h"
#include "tests.h"
#include "seccomp-util.h"

TEST(seccomp_errno_or_action_is_valid) {
        assert_se(seccomp_errno_or_action_is_valid(SECCOMP_ERROR_NUMBER_KILL));
        assert_se(seccomp_errno_or_action_is_valid(EPERM));
        assert_se(seccomp_errno_or_action_is_valid(EACCES));
        assert_se(!seccomp_errno_or_action_is_valid(0));
        assert_se(!seccomp_errno_or_action_is_valid(9999));
}

TEST(seccomp_errno_or_action_to_string) {
        assert_se(streq(seccomp_errno_or_action_to_string(SECCOMP_ERROR_NUMBER_KILL), "kill"));
        /* Regular errno → errno name */
        assert_se(streq(seccomp_errno_or_action_to_string(EPERM), "EPERM"));
}

TEST(seccomp_parse_errno_or_action) {
        assert_se(seccomp_parse_errno_or_action("kill") == SECCOMP_ERROR_NUMBER_KILL);
        assert_se(seccomp_parse_errno_or_action("EPERM") == EPERM);
        assert_se(seccomp_parse_errno_or_action("EACCES") == EACCES);
        assert_se(seccomp_parse_errno_or_action("1") == 1);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
