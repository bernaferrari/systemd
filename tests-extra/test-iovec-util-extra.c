/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "iovec-util.h"
#include "tests.h"

TEST(iovec_total_size) {
        struct iovec iov[3];

        iov[0] = IOVEC_MAKE_STRING("hello");
        iov[1] = IOVEC_MAKE_STRING(" ");
        iov[2] = IOVEC_MAKE_STRING("world");

        ASSERT_EQ(iovec_total_size(iov, 3), 11u);
        ASSERT_EQ(iovec_total_size(iov, 0), 0u);
        ASSERT_EQ(iovec_total_size(NULL, 0), 0u);
}

TEST(iovec_inc_many) {
        struct iovec iov[2];
        const char *hello = "hello";
        const char *world = "world";

        /* k=0: returns false (still work to do) */
        iov[0] = IOVEC_MAKE_STRING("hello");
        iov[1] = IOVEC_MAKE_STRING("world");
        ASSERT_FALSE(iovec_inc_many(iov, 2, 0));
        assert_se(iov[0].iov_base == hello); /* unchanged */
        ASSERT_EQ(iov[0].iov_len, 5u);

        /* k=3: consumes 3 from iov[0], returns false (still work) */
        iov[0] = IOVEC_MAKE_STRING("hello");
        iov[1] = IOVEC_MAKE_STRING("world");
        ASSERT_FALSE(iovec_inc_many(iov, 2, 3));
        assert_se(iov[0].iov_base == hello + 3);
        ASSERT_EQ(iov[0].iov_len, 2u);
        assert_se(iov[1].iov_base == world); /* unchanged */
        ASSERT_EQ(iov[1].iov_len, 5u);

        /* k=10 (total size): consumes everything, returns true */
        iov[0] = IOVEC_MAKE_STRING("hello");
        iov[1] = IOVEC_MAKE_STRING("world");
        ASSERT_TRUE(iovec_inc_many(iov, 2, 10));
        ASSERT_EQ(iov[0].iov_len, 0u);
        ASSERT_EQ(iov[1].iov_len, 0u);
}

TEST(iovec_make_string) {
        struct iovec iov;

        iovec_make_string(&iov, "test");
        ASSERT_STREQ(iov.iov_base, "test");
        ASSERT_EQ(iov.iov_len, 4u);
}

TEST(iovec_memcmp) {
        struct iovec a[2], b[2];

        a[0] = IOVEC_MAKE_STRING("hello");
        a[1] = IOVEC_MAKE_STRING("world");
        b[0] = IOVEC_MAKE_STRING("hello");
        b[1] = IOVEC_MAKE_STRING("world");

        ASSERT_EQ(iovec_memcmp(a, b), 0);

        b[0] = IOVEC_MAKE_STRING("hellp");
        ASSERT_LT(iovec_memcmp(a, b), 0);

        b[0] = IOVEC_MAKE_STRING("hellz");
        ASSERT_LT(iovec_memcmp(a, b), 0);
}

TEST(iovec_memdup) {
        struct iovec src, dst;

        src = IOVEC_MAKE_STRING("hello");

        ASSERT_NOT_NULL(iovec_memdup(&src, &dst));
        ASSERT_EQ(dst.iov_len, 5u);
        ASSERT_STREQ(dst.iov_base, "hello");

        dst.iov_base = mfree(dst.iov_base);

        /* Empty iovec */
        src = (struct iovec){};
        ASSERT_NOT_NULL(iovec_memdup(&src, &dst));
        ASSERT_EQ(dst.iov_len, 0u);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
