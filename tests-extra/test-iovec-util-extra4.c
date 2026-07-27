/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "iovec-util.h"
#include "memory-util.h"
#include "string-util.h"
#include "tests.h"

TEST(iovec_make_byte_array_basic) {
        char data[] = "test";
        struct iovec iov = IOVEC_MAKE(data, 4);
        assert_se(iov.iov_base == data);
        assert_se(iov.iov_len == 4);
}

TEST(iovec_memdup_basic) {
        char data[] = "hello";
        struct iovec iov = {
                .iov_base = data,
                .iov_len = 5,
        };

        _cleanup_(iovec_done) struct iovec result = {};
        assert_se(iovec_memdup(&iov, &result));
        assert_se(result.iov_base);
        assert_se(result.iov_len == 5);
        assert_se(memcmp(result.iov_base, "hello", 5) == 0);
}

TEST(iovec_inc_many_basic) {
        char data[] = "hello world";
        struct iovec iov = IOVEC_MAKE(data, 11);

        /* Consume 6 bytes */
        assert_se(!iovec_inc_many(&iov, 1, 6));
        assert_se(iov.iov_len == 5);
        assert_se(memcmp(iov.iov_base, "world", 5) == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
