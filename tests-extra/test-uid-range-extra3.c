/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "uid-range.h"
#include "tests.h"

TEST(uid_range_add_covers_contains) {
        _cleanup_(uid_range_freep) UIDRange *range = NULL;
        int r;

        /* Add a range 1000-1999 */
        r = uid_range_add(&range, 1000, 1000);
        assert_se(r >= 0);

        /* Covers the range */
        assert_se(uid_range_covers(range, 1000, 1000));
        assert_se(uid_range_covers(range, 1000, 1));
        assert_se(uid_range_covers(range, 1500, 1));
        assert_se(uid_range_covers(range, 1999, 1));

        /* Does not cover outside */
        assert_se(!uid_range_covers(range, 999, 1));
        assert_se(!uid_range_covers(range, 2000, 1));
        assert_se(!uid_range_covers(range, 1000, 1001));

        /* Contains individual UIDs */
        assert_se(uid_range_contains(range, 1000));
        assert_se(uid_range_contains(range, 1500));
        assert_se(uid_range_contains(range, 1999));
        assert_se(!uid_range_contains(range, 999));
        assert_se(!uid_range_contains(range, 2000));

        /* NULL range covers nothing */
        assert_se(!uid_range_covers(NULL, 0, 1));
        assert_se(!uid_range_contains(NULL, 0));
}

TEST(uid_range_size_and_empty) {
        _cleanup_(uid_range_freep) UIDRange *range = NULL;

        /* NULL range is empty, size 0 */
        assert_se(uid_range_is_empty(NULL));
        assert_se(uid_range_size(NULL) == 0);
        assert_se(uid_range_entries(NULL) == 0);

        /* Empty allocated range */
        range = new0(UIDRange, 1);
        assert_se(range);
        assert_se(uid_range_is_empty(range));
        assert_se(uid_range_size(range) == 0);
        assert_se(uid_range_entries(range) == 0);

        /* Add ranges */
        assert_se(uid_range_add(&range, 1000, 100) >= 0);
        assert_se(!uid_range_is_empty(range));
        assert_se(uid_range_size(range) == 100);
        assert_se(uid_range_entries(range) == 1);

        /* Add non-contiguous range */
        assert_se(uid_range_add(&range, 2000, 50) >= 0);
        assert_se(uid_range_size(range) == 150);
        assert_se(uid_range_entries(range) == 2);
}

TEST(uid_range_equal) {
        _cleanup_(uid_range_freep) UIDRange *a = NULL, *b = NULL;

        /* Two NULL ranges are equal */
        assert_se(uid_range_equal(NULL, NULL));

        /* NULL and non-NULL are not equal */
        assert_se(uid_range_add(&a, 100, 10) >= 0);
        assert_se(!uid_range_equal(a, NULL));
        assert_se(!uid_range_equal(NULL, a));

        /* Same range is equal */
        assert_se(uid_range_add(&b, 100, 10) >= 0);
        assert_se(uid_range_equal(a, b));

        /* Different range is not equal */
        uid_range_free(b);
        b = NULL;
        assert_se(uid_range_add(&b, 200, 10) >= 0);
        assert_se(!uid_range_equal(a, b));
}

TEST(uid_range_overlaps) {
        _cleanup_(uid_range_freep) UIDRange *range = NULL;

        assert_se(uid_range_add(&range, 1000, 100) >= 0);

        /* Exact match overlaps */
        assert_se(uid_range_overlaps(range, 1000, 100));

        /* Partial overlap from left */
        assert_se(uid_range_overlaps(range, 950, 100));

        /* Partial overlap from right */
        assert_se(uid_range_overlaps(range, 1050, 100));

        /* Fully contained */
        assert_se(uid_range_overlaps(range, 1020, 10));

        /* No overlap */
        assert_se(!uid_range_overlaps(range, 0, 100));
        assert_se(!uid_range_overlaps(range, 1100, 100));

        /* Adjacent but not overlapping */
        assert_se(!uid_range_overlaps(range, 1100, 1));
}

TEST(uid_range_coalesce_on_add) {
        _cleanup_(uid_range_freep) UIDRange *range = NULL;

        /* Add two adjacent ranges → should coalesce */
        assert_se(uid_range_add(&range, 1000, 100) >= 0);
        assert_se(uid_range_add(&range, 1100, 100) >= 0);
        assert_se(uid_range_entries(range) == 1);
        assert_se(uid_range_size(range) == 200);
        assert_se(uid_range_contains(range, 1000));
        assert_se(uid_range_contains(range, 1199));
}

TEST(uid_range_add_str) {
        _cleanup_(uid_range_freep) UIDRange *range = NULL;

        /* "1000-1999" format */
        assert_se(uid_range_add_str(&range, "1000-1999") >= 0);
        assert_se(uid_range_size(range) == 1000);
        assert_se(uid_range_contains(range, 1000));
        assert_se(uid_range_contains(range, 1999));

        /* Single UID format */
        assert_se(uid_range_add_str(&range, "5000") >= 0);
        assert_se(uid_range_contains(range, 5000));
}

TEST(uid_range_base) {
        _cleanup_(uid_range_freep) UIDRange *range = NULL;

        /* NULL returns UID_INVALID */
        assert_se(uid_range_base(NULL) == UID_INVALID);

        assert_se(uid_range_add(&range, 1000, 100) >= 0);
        assert_se(uid_range_base(range) == 1000);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
