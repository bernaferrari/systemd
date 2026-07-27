/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bitmap.h"
#include "tests.h"

TEST(bitmap_basic) {
        _cleanup_(bitmap_freep) Bitmap *b = NULL;

        b = bitmap_new();
        assert_se(b);

        /* Empty bitmap */
        assert_se(bitmap_isclear(b));
        assert_se(!bitmap_isset(b, 0));
        assert_se(!bitmap_isset(b, 1));
        assert_se(!bitmap_isset(b, 63));
        assert_se(!bitmap_isset(b, 64));
        assert_se(!bitmap_isset(b, 1000));

        /* Set bits */
        assert_se(bitmap_set(b, 0) >= 0);
        assert_se(bitmap_isset(b, 0));
        assert_se(!bitmap_isclear(b));

        assert_se(bitmap_set(b, 63) >= 0);
        assert_se(bitmap_isset(b, 63));

        assert_se(bitmap_set(b, 64) >= 0);
        assert_se(bitmap_isset(b, 64));

        assert_se(bitmap_set(b, 200) >= 0);
        assert_se(bitmap_isset(b, 200));

        /* Unset */
        bitmap_unset(b, 200);
        assert_se(!bitmap_isset(b, 200));

        /* Clear all */
        bitmap_clear(b);
        assert_se(bitmap_isclear(b));
        assert_se(!bitmap_isset(b, 0));
        assert_se(!bitmap_isset(b, 63));
}

TEST(bitmap_iterate) {
        _cleanup_(bitmap_freep) Bitmap *b = NULL;

        b = bitmap_new();
        assert_se(b);

        assert_se(bitmap_set(b, 5) >= 0);
        assert_se(bitmap_set(b, 10) >= 0);
        assert_se(bitmap_set(b, 100) >= 0);

        unsigned n;
        Iterator i = {};
        unsigned count = 0;
        BITMAP_FOREACH(n, b) {
                assert_se(IN_SET(n, 5, 10, 100));
                count++;
        }
        assert_se(count == 3);
}

TEST(bitmap_equal) {
        _cleanup_(bitmap_freep) Bitmap *a = NULL, *b = NULL;

        a = bitmap_new();
        b = bitmap_new();
        assert_se(a && b);

        /* Two empty bitmaps are equal */
        assert_se(bitmap_equal(a, b));

        /* Set same bit in both */
        assert_se(bitmap_set(a, 42) >= 0);
        assert_se(bitmap_set(b, 42) >= 0);
        assert_se(bitmap_equal(a, b));

        /* Different bits → not equal */
        assert_se(bitmap_set(b, 99) >= 0);
        assert_se(!bitmap_equal(a, b));
}

TEST(bitmap_copy) {
        _cleanup_(bitmap_freep) Bitmap *a = NULL, *b = NULL;

        a = bitmap_new();
        assert_se(a);
        assert_se(bitmap_set(a, 10) >= 0);
        assert_se(bitmap_set(a, 20) >= 0);

        b = bitmap_copy(a);
        assert_se(b);
        assert_se(bitmap_equal(a, b));

        /* Modify copy doesn't affect original */
        assert_se(bitmap_set(b, 30) >= 0);
        assert_se(!bitmap_equal(a, b));
        assert_se(!bitmap_isset(a, 30));
        assert_se(bitmap_isset(b, 30));
}

TEST(bitmap_ensure_allocated) {
        Bitmap *b = NULL;
        assert_se(bitmap_ensure_allocated(&b) >= 0);
        assert_se(b);
        assert_se(bitmap_isclear(b));
        b = bitmap_free(b);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
