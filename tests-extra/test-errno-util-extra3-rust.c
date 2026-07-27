/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: errno-util.h inline functions (negative_errno, RET_NERRNO,
 * errno_or_else) vs Rust */

#include <assert.h>
#include <errno.h>
#include <limits.h>

#include "tests.h"
#include "errno-util.h"
#include "rust/errno_util.h"

static void test_negative_errno(void) {
        errno = EINVAL;
        assert_se(negative_errno() == rs_negative_errno());
        assert_se(negative_errno() == -EINVAL);

        errno = ENOENT;
        assert_se(negative_errno() == rs_negative_errno());
        assert_se(negative_errno() == -ENOENT);

        errno = EPERM;
        assert_se(negative_errno() == rs_negative_errno());
        assert_se(negative_errno() == -EPERM);

        /* Edge: errno=0 → C asserts, Rust returns -EINVAL */
        errno = 0;
        assert_se(rs_negative_errno() == -EINVAL);

        /* Invalid negative errno fails closed without signed overflow. */
        errno = INT_MIN;
        assert_se(rs_negative_errno() == -EINVAL);
}

static void test_RET_NERRNO(void) {
        /* Positive return → pass through */
        errno = 0;
        assert_se(RET_NERRNO(5) == rs_RET_NERRNO(5));
        assert_se(RET_NERRNO(5) == 5);

        errno = 0;
        assert_se(RET_NERRNO(0) == rs_RET_NERRNO(0));
        assert_se(RET_NERRNO(0) == 0);

        /* Negative return → convert errno */
        errno = ENOMEM;
        assert_se(RET_NERRNO(-1) == rs_RET_NERRNO(-1));
        assert_se(RET_NERRNO(-1) == -ENOMEM);

        errno = EACCES;
        assert_se(RET_NERRNO(-1) == rs_RET_NERRNO(-1));
        assert_se(RET_NERRNO(-1) == -EACCES);

        errno = INT_MIN;
        assert_se(rs_RET_NERRNO(-1) == -EINVAL);
}

static void test_errno_or_else(void) {
        /* errno is set → return -errno */
        errno = EINVAL;
        assert_se(errno_or_else(ENOTSUP) == rs_errno_or_else(ENOTSUP));
        assert_se(errno_or_else(ENOTSUP) == -EINVAL);

        errno = ENOMEM;
        assert_se(errno_or_else(EIO) == rs_errno_or_else(EIO));
        assert_se(errno_or_else(EIO) == -ENOMEM);

        /* errno is 0 → return -ABS(fallback) */
        errno = 0;
        assert_se(errno_or_else(ENOTSUP) == rs_errno_or_else(ENOTSUP));
        assert_se(errno_or_else(ENOTSUP) == -ENOTSUP);

        errno = 0;
        assert_se(errno_or_else(-EINVAL) == rs_errno_or_else(-EINVAL));
        assert_se(errno_or_else(-EINVAL) == -EINVAL);

        errno = 0;
        assert_se(errno_or_else(EINVAL) == rs_errno_or_else(EINVAL));
        assert_se(errno_or_else(EINVAL) == -EINVAL);

        /* C's ABS(INT_MIN) is undefined, so exercise only Rust's documented
         * deterministic fail-closed policy at this boundary. */
        errno = 0;
        assert_se(rs_errno_or_else(INT_MIN) == -EINVAL);
}

int main(int argc, char **argv) {
        test_negative_errno();
        test_RET_NERRNO();
        test_errno_or_else();
        return 0;
}
