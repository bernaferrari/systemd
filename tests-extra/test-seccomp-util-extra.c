/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "seccomp-util.h"
#include "tests.h"

TEST(seccomp_errno_or_action_is_valid) {
        /* Valid errno values (0 is not valid - no error/action) */
        ASSERT_FALSE(seccomp_errno_or_action_is_valid(0));
        ASSERT_TRUE(seccomp_errno_or_action_is_valid(EPERM));
        ASSERT_TRUE(seccomp_errno_or_action_is_valid(EACCES));
        ASSERT_TRUE(seccomp_errno_or_action_is_valid(ENOMEM));

        /* Negative values are invalid */
        ASSERT_FALSE(seccomp_errno_or_action_is_valid(-1));

        /* Large positive values are invalid (beyond errno range) */
        ASSERT_FALSE(seccomp_errno_or_action_is_valid(4096));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
