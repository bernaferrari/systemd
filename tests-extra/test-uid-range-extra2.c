/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "uid-range.h"
#include "tests.h"
#include "user-util.h"

TEST(uid_range_contains) {
        _cleanup_(uid_range_freep) UIDRange *range = NULL;

        ASSERT_OK(uid_range_add(&range, 100, 10));

        /* UID in range */
        ASSERT_TRUE(uid_range_contains(range, 100));
        ASSERT_TRUE(uid_range_contains(range, 105));
        ASSERT_TRUE(uid_range_contains(range, 109));

        /* UID outside range */
        ASSERT_FALSE(uid_range_contains(range, 99));
        ASSERT_FALSE(uid_range_contains(range, 110));
        ASSERT_FALSE(uid_range_contains(range, 0));

        /* NULL range */
        ASSERT_FALSE(uid_range_contains(NULL, 0));
}

TEST(uid_range_is_empty) {
        _cleanup_(uid_range_freep) UIDRange *range = NULL;
        ASSERT_TRUE(uid_range_is_empty(range));

        ASSERT_OK(uid_range_add(&range, 100, 10));
        ASSERT_FALSE(uid_range_is_empty(range));
}

TEST(uid_range_size) {
        _cleanup_(uid_range_freep) UIDRange *range = NULL;
        ASSERT_EQ(uid_range_size(range), 0u);

        ASSERT_OK(uid_range_add(&range, 100, 10));
        ASSERT_EQ(uid_range_size(range), 10u);

        ASSERT_OK(uid_range_add(&range, 200, 5));
        ASSERT_EQ(uid_range_size(range), 15u);
}

TEST(uid_range_equal) {
        _cleanup_(uid_range_freep) UIDRange *a = NULL, *b = NULL;

        /* Two NULL/empty ranges are equal */
        ASSERT_TRUE(uid_range_equal(a, b));

        /* Same range */
        ASSERT_OK(uid_range_add(&a, 100, 10));
        ASSERT_OK(uid_range_add(&b, 100, 10));
        ASSERT_TRUE(uid_range_equal(a, b));

        /* Different range */
        _cleanup_(uid_range_freep) UIDRange *c = NULL;
        ASSERT_OK(uid_range_add(&c, 100, 20));
        ASSERT_FALSE(uid_range_equal(a, c));
}

TEST(uid_range_overlaps) {
        _cleanup_(uid_range_freep) UIDRange *range = NULL;
        ASSERT_OK(uid_range_add(&range, 100, 10));

        ASSERT_TRUE(uid_range_overlaps(range, 100, 10));
        ASSERT_TRUE(uid_range_overlaps(range, 105, 10));
        ASSERT_FALSE(uid_range_overlaps(range, 110, 10));
        ASSERT_FALSE(uid_range_overlaps(range, 0, 10));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
