/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "tests.h"

TEST(ERRNO_IS_TRANSIENT) {
        assert_se(ERRNO_IS_TRANSIENT(EAGAIN));
        assert_se(ERRNO_IS_TRANSIENT(EINTR));
        assert_se(!ERRNO_IS_TRANSIENT(EINVAL));
        assert_se(!ERRNO_IS_TRANSIENT(0));
}

TEST(ERRNO_IS_NEG_TRANSIENT) {
        assert_se(ERRNO_IS_NEG_TRANSIENT(-EAGAIN));
        assert_se(ERRNO_IS_NEG_TRANSIENT(-EINTR));
        assert_se(!ERRNO_IS_NEG_TRANSIENT(-EINVAL));
        assert_se(!ERRNO_IS_NEG_TRANSIENT(0));
        assert_se(!ERRNO_IS_NEG_TRANSIENT(EAGAIN));
}

TEST(ERRNO_IS_NEG_DISCONNECT) {
        assert_se(ERRNO_IS_NEG_DISCONNECT(-ECONNRESET));
        assert_se(ERRNO_IS_NEG_DISCONNECT(-EPIPE));
        assert_se(ERRNO_IS_NEG_DISCONNECT(-ECONNREFUSED));
        assert_se(!ERRNO_IS_NEG_DISCONNECT(-EINVAL));
        assert_se(!ERRNO_IS_NEG_DISCONNECT(0));
}

TEST(ERRNO_IS_NEG_NOT_SUPPORTED) {
        assert_se(ERRNO_IS_NEG_NOT_SUPPORTED(-ENOTSUP));
        assert_se(ERRNO_IS_NEG_NOT_SUPPORTED(-EOPNOTSUPP));
        assert_se(!ERRNO_IS_NEG_NOT_SUPPORTED(-EINVAL));
}

TEST(ERRNO_IS_NEG_PRIVILEGE) {
        assert_se(ERRNO_IS_NEG_PRIVILEGE(-EPERM));
        assert_se(ERRNO_IS_NEG_PRIVILEGE(-EACCES));
        assert_se(!ERRNO_IS_NEG_PRIVILEGE(-EINVAL));
}

TEST(ERRNO_IS_NEG_DISK_SPACE) {
        assert_se(ERRNO_IS_NEG_DISK_SPACE(-ENOSPC));
        assert_se(ERRNO_IS_NEG_DISK_SPACE(-EDQUOT));
        assert_se(ERRNO_IS_NEG_DISK_SPACE(-EFBIG));
        assert_se(!ERRNO_IS_NEG_DISK_SPACE(-EINVAL));
}

TEST(ERRNO_IS_NEG_DEVICE_ABSENT) {
        assert_se(ERRNO_IS_NEG_DEVICE_ABSENT(-ENODEV));
        assert_se(ERRNO_IS_NEG_DEVICE_ABSENT(-ENXIO));
        assert_se(!ERRNO_IS_NEG_DEVICE_ABSENT(-EINVAL));
}

TEST(ERRNO_IS_NEG_XATTR_ABSENT) {
        assert_se(ERRNO_IS_NEG_XATTR_ABSENT(-ENODATA));
        assert_se(!ERRNO_IS_NEG_XATTR_ABSENT(-EINVAL));
}

TEST(errno_or_else) {
        errno = EINVAL;
        assert_se(errno_or_else(ENOENT) == -EINVAL);

        errno = 0;
        assert_se(errno_or_else(ENOENT) == -ENOENT);

        errno = ENOENT;
        assert_se(errno_or_else(ENOENT) == -ENOENT);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
