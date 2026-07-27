/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/pidfd.h>

#include "fd-util.h"
#include "pidfd-util.h"
#include "process-util.h"
#include "tests.h"

TEST(pidfd_get_pid_self) {
        /* Open a pidfd for ourselves and verify we get our own PID */
        int fd = pidfd_open(getpid_cached(), 0);
        if (fd < 0) {
                /* Not all kernels support pidfd_open */
                log_debug("pidfd_open not supported, skipping");
                return;
        }

        pid_t pid;
        assert_se(pidfd_get_pid(fd, &pid) >= 0);
        assert_se(pid == getpid_cached());
        fd = safe_close(fd);
}

TEST(pidfd_verify_pid_self) {
        int fd = pidfd_open(getpid_cached(), 0);
        if (fd < 0) {
                log_debug("pidfd_open not supported, skipping");
                return;
        }

        assert_se(pidfd_verify_pid(fd, getpid_cached()) >= 0);
        fd = safe_close(fd);
}

TEST(pidfd_get_ppid_self) {
        int fd = pidfd_open(getpid_cached(), 0);
        if (fd < 0) {
                log_debug("pidfd_open not supported, skipping");
                return;
        }

        pid_t ppid;
        int r = pidfd_get_ppid(fd, &ppid);
        if (r < 0)
                log_debug("pidfd_get_ppid failed, skipping");
        else
                assert_se(ppid > 0);

        fd = safe_close(fd);
}

TEST(pidfd_get_inode_id_self) {
        uint64_t id;
        int r = pidfd_get_inode_id_self_cached(&id);
        if (r < 0) {
                log_debug("pidfd_get_inode_id_self_cached not available, skipping");
                return;
        }
        /* Should return a valid inode ID */
        assert_se(id > 0);

        /* Second call should return cached value */
        uint64_t id2;
        assert_se(pidfd_get_inode_id_self_cached(&id2) >= 0);
        assert_se(id == id2);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
