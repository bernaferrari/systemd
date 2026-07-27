/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "daemon-util.h"
#include "fd-util.h"
#include "tests.h"

TEST(close_and_notify_warn_basic) {
        /* Close a valid fd with a name */
        int fds[2];
        assert_se(pipe(fds) == 0);

        /* close_and_notify_warn closes the fd and warns on notify failure (harmless outside a service) */
        assert_se(close_and_notify_warn(fds[0], "test-fd") == -EBADF);
        close(fds[1]); /* close write end */

        /* NULL name: should still close the fd */
        assert_se(pipe(fds) == 0);
        assert_se(close_and_notify_warn(fds[0], NULL) == -EBADF);
        close(fds[1]);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
