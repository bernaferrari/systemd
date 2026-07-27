/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "string-util.h"
#include "tests.h"

TEST(errno_is_transient) {
        assert_se(ERRNO_IS_TRANSIENT(EAGAIN));
        assert_se(ERRNO_IS_TRANSIENT(EINTR));
        assert_se(!ERRNO_IS_TRANSIENT(EINVAL));
        assert_se(!ERRNO_IS_TRANSIENT(0));
}

TEST(errno_is_disconnect) {
        assert_se(ERRNO_IS_DISCONNECT(ECONNABORTED));
        assert_se(ERRNO_IS_DISCONNECT(ECONNREFUSED));
        assert_se(ERRNO_IS_DISCONNECT(ECONNRESET));
        assert_se(ERRNO_IS_DISCONNECT(ETIMEDOUT));
        assert_se(ERRNO_IS_DISCONNECT(EPIPE));
        assert_se(!ERRNO_IS_DISCONNECT(EAGAIN));
        assert_se(!ERRNO_IS_DISCONNECT(0));
}

TEST(errno_is_not_supported) {
        assert_se(ERRNO_IS_NOT_SUPPORTED(EOPNOTSUPP));
        assert_se(ERRNO_IS_NOT_SUPPORTED(ENOSYS));
        assert_se(ERRNO_IS_NOT_SUPPORTED(ENOTTY));
        assert_se(ERRNO_IS_NOT_SUPPORTED(EAFNOSUPPORT));
        assert_se(!ERRNO_IS_NOT_SUPPORTED(EINVAL));
        assert_se(!ERRNO_IS_NOT_SUPPORTED(0));
}

TEST(errno_is_resource) {
        assert_se(ERRNO_IS_RESOURCE(EMFILE));
        assert_se(ERRNO_IS_RESOURCE(ENFILE));
        assert_se(ERRNO_IS_RESOURCE(ENOMEM));
        assert_se(!ERRNO_IS_RESOURCE(EINVAL));
}

TEST(errno_is_privilege) {
        assert_se(ERRNO_IS_PRIVILEGE(EACCES));
        assert_se(ERRNO_IS_PRIVILEGE(EPERM));
        assert_se(!ERRNO_IS_PRIVILEGE(EINVAL));
}

TEST(errno_is_disk_space) {
        assert_se(ERRNO_IS_DISK_SPACE(ENOSPC));
        assert_se(ERRNO_IS_DISK_SPACE(EDQUOT));
        assert_se(ERRNO_IS_DISK_SPACE(EFBIG));
        assert_se(!ERRNO_IS_DISK_SPACE(ENOMEM));
}

TEST(errno_is_device_absent) {
        assert_se(ERRNO_IS_DEVICE_ABSENT(ENODEV));
        assert_se(ERRNO_IS_DEVICE_ABSENT(ENXIO));
        assert_se(ERRNO_IS_DEVICE_ABSENT(ENOENT));
        assert_se(!ERRNO_IS_DEVICE_ABSENT(EEXIST));
}

TEST(errno_or_else_basic) {
        errno = ENOENT;
        assert_se(errno_or_else(EINVAL) == -ENOENT);

        errno = 0;
        assert_se(errno_or_else(EINVAL) == -EINVAL);

        errno = 0;
        assert_se(errno_or_else(ENOENT) == -ENOENT);
}

TEST(ret_gather_basic) {
        int acc = 0;
        acc = RET_GATHER(acc, 0);
        assert_se(acc == 0);

        acc = RET_GATHER(acc, -EINVAL);
        assert_se(acc == -EINVAL);

        /* First error sticks */
        acc = RET_GATHER(acc, -ENOENT);
        assert_se(acc == -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
