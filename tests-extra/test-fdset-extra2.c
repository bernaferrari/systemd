/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "fdset.h"
#include "tests.h"

TEST(fdset_new_free) {
        _cleanup_fdset_free_ FDSet *s = NULL;

        s = fdset_new();
        assert_se(s);
        assert_se(fdset_isempty(s));
        assert_se(fdset_size(s) == 0);
}

TEST(fdset_put_contains_remove) {
        _cleanup_fdset_free_ FDSet *s = NULL;
        int fd1, fd2;

        s = fdset_new();
        assert_se(s);

        fd1 = open("/dev/null", O_RDONLY|O_CLOEXEC);
        assert_se(fd1 >= 0);
        fd2 = open("/dev/null", O_RDONLY|O_CLOEXEC);
        assert_se(fd2 >= 0);

        assert_se(fdset_put(s, fd1) >= 0);
        assert_se(fdset_contains(s, fd1));
        assert_se(!fdset_contains(s, fd2));
        assert_se(fdset_size(s) == 1);

        assert_se(fdset_put(s, fd2) >= 0);
        assert_se(fdset_contains(s, fd2));
        assert_se(fdset_size(s) == 2);

        /* Remove fd1 from set → fd1 is now ours to close */
        assert_se(fdset_remove(s, fd1) >= 0);
        assert_se(!fdset_contains(s, fd1));
        assert_se(fdset_size(s) == 1);
        fd1 = safe_close(fd1);

        /* fd2 is still in the set, fdset_free will close it */
}

TEST(fdset_steal_first) {
        _cleanup_fdset_free_ FDSet *s = NULL;

        s = fdset_new();
        assert_se(s);

        assert_se(fdset_steal_first(s) < 0);

        int fd1 = open("/dev/null", O_RDONLY|O_CLOEXEC);
        assert_se(fd1 >= 0);
        assert_se(fdset_put(s, fd1) >= 0);

        int stolen = fdset_steal_first(s);
        assert_se(stolen == fd1);
        assert_se(fdset_isempty(s));
        safe_close(stolen);
}

TEST(fdset_put_dup) {
        _cleanup_fdset_free_ FDSet *s = NULL;
        _cleanup_close_ int fd1 = -EBADF;

        s = fdset_new();
        assert_se(s);

        fd1 = open("/dev/null", O_RDONLY|O_CLOEXEC);
        assert_se(fd1 >= 0);

        int dup_fd = fdset_put_dup(s, fd1);
        assert_se(dup_fd >= 0);
        assert_se(dup_fd != fd1);
        assert_se(fdset_contains(s, dup_fd));
        assert_se(!fdset_contains(s, fd1));
        /* dup_fd is owned by the set now, don't close manually */
}

DEFINE_TEST_MAIN(LOG_DEBUG);
