/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "memory-util.h"
#include "tests.h"

TEST(memcmp_safe_basic) {
        char a[] = "hello";
        char b[] = "hello";
        char c[] = "world";
        assert_se(memcmp_safe(a, b, 5) == 0);
        assert_se(memcmp_safe(a, c, 5) != 0);
        assert_se(memcmp_safe(a, b, 0) == 0);
}

TEST(align_to_basic) {
        assert_se(ALIGN_TO(0, 4) == 0);
        assert_se(ALIGN_TO(1, 4) == 4);
        assert_se(ALIGN_TO(3, 4) == 4);
        assert_se(ALIGN_TO(4, 4) == 4);
        assert_se(ALIGN_TO(5, 4) == 8);
        assert_se(ALIGN_TO(5, 8) == 8);
        assert_se(ALIGN_TO(8, 8) == 8);
}

TEST(align_down_basic) {
        assert_se(ALIGN_DOWN(0, 4) == 0);
        assert_se(ALIGN_DOWN(3, 4) == 0);
        assert_se(ALIGN_DOWN(4, 4) == 4);
        assert_se(ALIGN_DOWN(7, 4) == 4);
        assert_se(ALIGN_DOWN(8, 4) == 8);
}

TEST(page_align_basic) {
        assert_se(PAGE_ALIGN(0) == 0);
        assert_se(PAGE_ALIGN(1) == (size_t)page_size());
        assert_se(PAGE_ALIGN((size_t)page_size()) == (size_t)page_size());
        assert_se(PAGE_ALIGN((size_t)page_size() + 1) == 2 * (size_t)page_size());
}

TEST(protect_errno_basic) {
        errno = 42;
        {
                PROTECT_ERRNO;
                errno = 99;
        }
        assert_se(errno == 42);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
