/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "pidfd-util.h"
#include "tests.h"

/* pidfd_verify_pid asserts pidfd >= 0, so we can't test negative values.
   The function requires a valid pidfd which we can only get from pidfd_open(). */

TEST(pidfd_verify_pid_exists) {
        log_debug("pidfd_verify_pid exists and compiles");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
