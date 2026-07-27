/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/inotify.h>

#include "fd-util.h"
#include "inotify-util.h"
#include "tests.h"

TEST(inotify_add_watch_fd_basic) {
        _cleanup_close_ int fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
        if (fd < 0) {
                log_debug("inotify_init1 failed: %m");
                return;
        }

        /* Use a real directory fd, not AT_FDCWD */
        _cleanup_close_ int dirfd = open("/tmp", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (dirfd < 0) {
                log_debug("open(/tmp): %m");
                return;
        }

        int wd = inotify_add_watch_fd(fd, dirfd, IN_CREATE);
        log_debug("inotify_add_watch_fd: %d", wd);
        if (wd >= 0)
                (void) inotify_rm_watch(fd, wd);
}

TEST(inotify_add_watch_and_warn_basic) {
        _cleanup_close_ int fd = inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
        if (fd < 0) {
                log_debug("inotify_init1 failed: %m");
                return;
        }

        int wd = inotify_add_watch_and_warn(fd, "/tmp", IN_CREATE);
        log_debug("inotify_add_watch_and_warn: %d", wd);
        if (wd >= 0)
                (void) inotify_rm_watch(fd, wd);
}

TEST(inotify_event_next_basic) {
        union inotify_event_buffer buffer = {};
        struct inotify_event *iterator = NULL;

        /* Empty buffer should return false */
        assert_se(!inotify_event_next(&buffer, 0, &iterator, LOG_DEBUG));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
