/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>
#include <sys/uio.h>

#include "iovec-util.h"
#include "tests.h"

TEST(iovec_total_size_basic) {
        struct iovec iov[] = {
                { .iov_base = (void*)"hello", .iov_len = 5 },
                { .iov_base = (void*)" world", .iov_len = 6 },
        };

        assert_se(iovec_total_size(iov, 2) == 11);
        assert_se(iovec_total_size(iov, 1) == 5);
        assert_se(iovec_total_size(iov, 0) == 0);
}

TEST(iovec_total_size_empty) {
        struct iovec iov = { .iov_base = NULL, .iov_len = 0 };
        assert_se(iovec_total_size(&iov, 1) == 0);
}

TEST(iovec_inc_many_consume_all) {
        char data[] = "hello";
        struct iovec iov = { .iov_base = data, .iov_len = 5 };

        /* Consume all bytes → returns true */
        assert_se(iovec_inc_many(&iov, 1, 5));
        assert_se(iov.iov_len == 0);
}

TEST(iovec_inc_many_consume_partial) {
        char data[] = "hello";
        struct iovec iov = { .iov_base = data, .iov_len = 5 };

        /* Consume 2 of 5 bytes from a single iovec, leaving work. */
        assert_se(!iovec_inc_many(&iov, 1, 2));
        assert_se(iov.iov_len == 3);
}

TEST(iovec_inc_many_zero) {
        char data[] = "test";
        struct iovec iov = { .iov_base = data, .iov_len = 4 };

        /* Consume 0 bytes → returns false (still data to send) */
        assert_se(!iovec_inc_many(&iov, 1, 0));
        assert_se(iov.iov_len == 4);
}

TEST(iovec_inc_many_multi_iovec) {
        char data1[] = "ab";
        char data2[] = "cd";
        struct iovec iov[] = {
                { .iov_base = data1, .iov_len = 2 },
                { .iov_base = data2, .iov_len = 2 },
        };

        /* Consume 3 bytes: 2 from first, 1 from second, leaving work. */
        assert_se(!iovec_inc_many(iov, 2, 3));
        assert_se(iov[0].iov_len == 0);
        assert_se(iov[1].iov_len == 1);
}

TEST(iovec_memcmp_equal) {
        struct iovec a = { .iov_base = (void*)"hello", .iov_len = 5 };
        struct iovec b = { .iov_base = (void*)"hello", .iov_len = 5 };

        assert_se(iovec_memcmp(&a, &b) == 0);
}

TEST(iovec_memcmp_different) {
        struct iovec a = { .iov_base = (void*)"hello", .iov_len = 5 };
        struct iovec b = { .iov_base = (void*)"world", .iov_len = 5 };

        assert_se(iovec_memcmp(&a, &b) != 0);
}

TEST(iovec_memcmp_null) {
        struct iovec a = { .iov_base = NULL, .iov_len = 0 };
        struct iovec b = { .iov_base = NULL, .iov_len = 0 };

        assert_se(iovec_memcmp(&a, &b) == 0);
}

TEST(iovec_memdup_basic) {
        struct iovec src = { .iov_base = (void*)"hello", .iov_len = 5 };
        struct iovec dup = {};

        assert_se(iovec_memdup(&src, &dup) != NULL);
        assert_se(dup.iov_len == 5);
        assert_se(memcmp(dup.iov_base, "hello", 5) == 0);
        free(dup.iov_base);
}

TEST(iovec_memdup_empty) {
        struct iovec src = { .iov_base = NULL, .iov_len = 0 };
        struct iovec dup = {};

        assert_se(iovec_memdup(&src, &dup) != NULL);
        assert_se(dup.iov_len == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
