/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "uid-range.h"
#include "tests.h"

TEST(uid_range_equal) {
        _cleanup_(uid_range_freep) UIDRange *a = NULL, *b = NULL, *c = NULL;

        ASSERT_OK(uid_range_add(&a, 100, 50));
        ASSERT_OK(uid_range_add(&b, 100, 50));
        ASSERT_OK(uid_range_add(&c, 100, 51));

        ASSERT_TRUE(uid_range_equal(a, b));
        ASSERT_FALSE(uid_range_equal(a, c));
}

TEST(uid_range_is_empty) {
        _cleanup_(uid_range_freep) UIDRange *r = NULL;
        ASSERT_TRUE(uid_range_is_empty(r));
        ASSERT_OK(uid_range_add(&r, 0, 1));
        ASSERT_FALSE(uid_range_is_empty(r));
}

TEST(uid_range_contains) {
        _cleanup_(uid_range_freep) UIDRange *r = NULL;
        ASSERT_OK(uid_range_add(&r, 100, 50));

        ASSERT_TRUE(uid_range_contains(r, 100));
        ASSERT_TRUE(uid_range_contains(r, 149));
        ASSERT_FALSE(uid_range_contains(r, 99));
        ASSERT_FALSE(uid_range_contains(r, 150));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
