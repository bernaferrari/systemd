/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "exit-status.h"
#include "tests.h"

TEST(exit_status_from_string_basic) {
        assert_se(exit_status_from_string("0") == 0);
        assert_se(exit_status_from_string("1") == 1);
        assert_se(exit_status_from_string("255") == 255);
        assert_se(exit_status_from_string("SUCCESS") == 0);
        assert_se(exit_status_from_string("FAILURE") == 1);
        assert_se(exit_status_from_string("CHDIR") >= 0);
        assert_se(exit_status_from_string("EXEC") >= 0);
        assert_se(exit_status_from_string("MEMORY") >= 0);
        assert_se(exit_status_from_string("SECCOMP") >= 0);
        assert_se(exit_status_from_string("invalid") == -EINVAL);
}

TEST(exit_status_to_string_basic) {
        assert_se(streq(exit_status_to_string(0, EXIT_STATUS_FULL), "SUCCESS"));
        assert_se(streq(exit_status_to_string(1, EXIT_STATUS_FULL), "FAILURE"));
        assert_se(exit_status_to_string(200, EXIT_STATUS_FULL));
        assert_se(exit_status_to_string(78, EXIT_STATUS_FULL));
}

TEST(exit_status_from_string_classic) {
        /* Classic exit codes 0-255 should parse */
        for (int i = 0; i <= 255; i++) {
                char buf[4];
                xsprintf(buf, "%d", i);
                assert_se(exit_status_from_string(buf) == i);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
