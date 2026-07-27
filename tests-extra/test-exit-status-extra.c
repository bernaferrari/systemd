/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "exit-status.h"
#include "tests.h"

TEST(exit_status_to_string) {
        /* Standard exits */
        ASSERT_NOT_NULL(exit_status_to_string(EXIT_SUCCESS, EXIT_STATUS_FULL));
        ASSERT_STREQ(exit_status_to_string(EXIT_SUCCESS, EXIT_STATUS_FULL), "SUCCESS");

        ASSERT_NOT_NULL(exit_status_to_string(EXIT_FAILURE, EXIT_STATUS_FULL));
        ASSERT_STREQ(exit_status_to_string(EXIT_FAILURE, EXIT_STATUS_FULL), "FAILURE");

        /* Systemd-specific exits */
        ASSERT_NOT_NULL(exit_status_to_string(EXIT_INVALIDARGUMENT, EXIT_STATUS_FULL));
        ASSERT_STREQ(exit_status_to_string(EXIT_INVALIDARGUMENT, EXIT_STATUS_FULL), "INVALIDARGUMENT");

        ASSERT_NOT_NULL(exit_status_to_string(EXIT_NOTIMPLEMENTED, EXIT_STATUS_FULL));
        ASSERT_STREQ(exit_status_to_string(EXIT_NOTIMPLEMENTED, EXIT_STATUS_FULL), "NOTIMPLEMENTED");

        ASSERT_NOT_NULL(exit_status_to_string(EXIT_NOPERMISSION, EXIT_STATUS_FULL));
        ASSERT_STREQ(exit_status_to_string(EXIT_NOPERMISSION, EXIT_STATUS_FULL), "NOPERMISSION");

        /* Unknown exit code returns NULL */
        ASSERT_NULL(exit_status_to_string(999, EXIT_STATUS_FULL));
}

TEST(exit_status_class) {
        /* EXIT_SUCCESS (0) is a libc exit */
        ASSERT_STREQ(exit_status_class(EXIT_SUCCESS), "libc");
        /* EXIT_FAILURE (1) is a libc exit */
        ASSERT_STREQ(exit_status_class(EXIT_FAILURE), "libc");
        /* Systemd-specific exits are "LSB" class (2-7 are LSB exit codes) */
        ASSERT_STREQ(exit_status_class(EXIT_INVALIDARGUMENT), "LSB");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
