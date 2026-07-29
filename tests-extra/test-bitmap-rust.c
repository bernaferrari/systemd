/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C bitmap vs Rust rs_bitmap_* */
/* RUST-CONTRACT: bitmap-queries */
/* RUST-CONTRACT: bitmap-allocation */
/* RUST-CONTRACT: bitmap-mutation */
/* RUST-CONTRACT: bitmap-iteration */

#include <stdlib.h>
#include <string.h>

#include "log.h"

/* C header */
#include "bitmap.h"

/* Rust FFI */
#include "rust/bitmap.h"

static void test_bitmap_isset(void) {
        Bitmap *b = NULL;
        bool cv, rv;

        /* NULL bitmap */
        cv = bitmap_isset(NULL, 0);
        rv = rs_bitmap_isset(NULL, 0);
        assert_se(cv == rv);
        assert_se(!cv);

        cv = bitmap_isset(NULL, 42);
        rv = rs_bitmap_isset(NULL, 42);
        assert_se(cv == rv);

        /* Allocate and set some bits */
        assert_se(bitmap_ensure_allocated(&b) >= 0);
        assert_se(bitmap_set(b, 0) >= 0);
        assert_se(bitmap_set(b, 5) >= 0);
        assert_se(bitmap_set(b, 63) >= 0);
        assert_se(bitmap_set(b, 64) >= 0);
        assert_se(bitmap_set(b, 100) >= 0);

        /* Check set bits */
        cv = bitmap_isset(b, 0);
        rv = rs_bitmap_isset(b, 0);
        assert_se(cv == rv);
        assert_se(cv);

        cv = bitmap_isset(b, 5);
        rv = rs_bitmap_isset(b, 5);
        assert_se(cv == rv);
        assert_se(cv);

        cv = bitmap_isset(b, 63);
        rv = rs_bitmap_isset(b, 63);
        assert_se(cv == rv);
        assert_se(cv);

        cv = bitmap_isset(b, 64);
        rv = rs_bitmap_isset(b, 64);
        assert_se(cv == rv);
        assert_se(cv);

        cv = bitmap_isset(b, 100);
        rv = rs_bitmap_isset(b, 100);
        assert_se(cv == rv);
        assert_se(cv);

        /* Check unset bits */
        cv = bitmap_isset(b, 1);
        rv = rs_bitmap_isset(b, 1);
        assert_se(cv == rv);
        assert_se(!cv);

        cv = bitmap_isset(b, 3);
        rv = rs_bitmap_isset(b, 3);
        assert_se(cv == rv);
        assert_se(!cv);

        cv = bitmap_isset(b, 62);
        rv = rs_bitmap_isset(b, 62);
        assert_se(cv == rv);
        assert_se(!cv);

        cv = bitmap_isset(b, 99);
        rv = rs_bitmap_isset(b, 99);
        assert_se(cv == rv);
        assert_se(!cv);

        /* Out of range */
        cv = bitmap_isset(b, 200);
        rv = rs_bitmap_isset(b, 200);
        assert_se(cv == rv);
        assert_se(!cv);

        bitmap_free(b);
}

static void test_bitmap_isclear(void) {
        Bitmap *b = NULL;
        bool cv, rv;

        /* NULL is clear */
        cv = bitmap_isclear(NULL);
        rv = rs_bitmap_isclear(NULL);
        assert_se(cv == rv);
        assert_se(cv);

        /* Fresh bitmap is clear */
        assert_se(bitmap_ensure_allocated(&b) >= 0);
        cv = bitmap_isclear(b);
        rv = rs_bitmap_isclear(b);
        assert_se(cv == rv);
        assert_se(cv);

        /* Set a bit, not clear */
        assert_se(bitmap_set(b, 10) >= 0);
        cv = bitmap_isclear(b);
        rv = rs_bitmap_isclear(b);
        assert_se(cv == rv);
        assert_se(!cv);

        /* Unset the bit, clear again */
        bitmap_unset(b, 10);
        cv = bitmap_isclear(b);
        rv = rs_bitmap_isclear(b);
        assert_se(cv == rv);
        assert_se(cv);

        /* Set bits across multiple u64 entries */
        assert_se(bitmap_set(b, 0) >= 0);
        assert_se(bitmap_set(b, 64) >= 0);
        assert_se(bitmap_set(b, 128) >= 0);
        cv = bitmap_isclear(b);
        rv = rs_bitmap_isclear(b);
        assert_se(cv == rv);
        assert_se(!cv);

        bitmap_free(b);
}

static void test_bitmap_equal(void) {
        Bitmap *a = NULL, *b = NULL;
        bool cv, rv;

        /* NULL == NULL */
        cv = bitmap_equal(NULL, NULL);
        rv = rs_bitmap_equal(NULL, NULL);
        assert_se(cv == rv);
        assert_se(cv);

        /* NULL != non-NULL */
        assert_se(bitmap_ensure_allocated(&a) >= 0);
        cv = bitmap_equal(NULL, a);
        rv = rs_bitmap_equal(NULL, a);
        assert_se(cv == rv);
        assert_se(!cv);

        cv = bitmap_equal(a, NULL);
        rv = rs_bitmap_equal(a, NULL);
        assert_se(cv == rv);
        assert_se(!cv);

        /* Equal empty bitmaps */
        assert_se(bitmap_ensure_allocated(&b) >= 0);
        cv = bitmap_equal(a, b);
        rv = rs_bitmap_equal(a, b);
        assert_se(cv == rv);
        assert_se(cv);

        /* Same bits set */
        assert_se(bitmap_set(a, 5) >= 0);
        assert_se(bitmap_set(b, 5) >= 0);
        cv = bitmap_equal(a, b);
        rv = rs_bitmap_equal(a, b);
        assert_se(cv == rv);
        assert_se(cv);

        /* Different bits */
        assert_se(bitmap_set(a, 10) >= 0);
        cv = bitmap_equal(a, b);
        rv = rs_bitmap_equal(a, b);
        assert_se(cv == rv);
        assert_se(!cv);

        /* a == a */
        cv = bitmap_equal(a, a);
        rv = rs_bitmap_equal(a, a);
        assert_se(cv == rv);
        assert_se(cv);

        /* Different sizes, longer one has all zeros in extra */
        assert_se(bitmap_set(b, 200) >= 0);
        cv = bitmap_equal(a, b);
        rv = rs_bitmap_equal(a, b);
        assert_se(cv == rv);
        assert_se(!cv);

        bitmap_free(a);
        bitmap_free(b);
}

static void test_bitmap_new_free(void) {
        Bitmap *cb, *rb;

        /* Both return non-NULL */
        cb = bitmap_new();
        rb = rs_bitmap_new();
        assert_se(cb != NULL);
        assert_se(rb != NULL);

        /* Fresh bitmaps should be clear and equal */
        assert_se(bitmap_isclear(cb));
        assert_se(rs_bitmap_isclear(rb));
        assert_se(bitmap_equal(cb, rb));

        /* free returns NULL */
        assert_se(bitmap_free(cb) == NULL);
        assert_se(rs_bitmap_free(rb) == NULL);

        /* free(NULL) returns NULL */
        assert_se(bitmap_free(NULL) == NULL);
        assert_se(rs_bitmap_free(NULL) == NULL);
}

static void test_bitmap_copy(void) {
        Bitmap *cb = NULL;
        Bitmap *cc, *rc;

        /* Set some bits */
        assert_se(bitmap_ensure_allocated(&cb) >= 0);
        assert_se(bitmap_set(cb, 0) >= 0);
        assert_se(bitmap_set(cb, 5) >= 0);
        assert_se(bitmap_set(cb, 64) >= 0);
        assert_se(bitmap_set(cb, 200) >= 0);

        /* Copy C → C and Rust → Rust */
        cc = bitmap_copy(cb);
        rc = rs_bitmap_copy(cb); /* Use C bitmap as source for Rust copy */
        assert_se(cc != NULL);
        assert_se(rc != NULL);

        /* Copied bitmaps should equal the original */
        assert_se(bitmap_equal(cb, cc));
        assert_se(rs_bitmap_equal(cb, rc));

        /* C copy and Rust copy should be equal */
        assert_se(bitmap_equal(cc, rc));

        /* Modify original, copies should not change */
        assert_se(bitmap_set(cb, 10) >= 0);
        assert_se(!bitmap_isset(cc, 10));
        assert_se(!rs_bitmap_isset(rc, 10));

        cb = bitmap_free(cb);
        cc = bitmap_free(cc);
        rc = rs_bitmap_free(rc);

        /* Copy NULL: C bitmap_copy does NOT check for NULL (crashes), only test Rust */
        assert_se(rs_bitmap_copy(NULL) == NULL);

        /* Copy empty bitmap */
        assert_se(bitmap_ensure_allocated(&cb) >= 0);
        cc = bitmap_copy(cb);
        rc = rs_bitmap_copy(cb);
        assert_se(cc != NULL);
        assert_se(rc != NULL);
        assert_se(bitmap_isclear(cc));
        assert_se(rs_bitmap_isclear(rc));

        bitmap_free(cb);
        bitmap_free(cc);
        rs_bitmap_free(rc);
}

static void test_bitmap_ensure_allocated(void) {
        Bitmap *cb = NULL, *rb = NULL;
        int cr, rr;

        /* Allocate NULL */
        cr = bitmap_ensure_allocated(&cb);
        rr = rs_bitmap_ensure_allocated(&rb);
        assert_se(cr == rr);
        assert_se(cr == 0);
        assert_se(cb != NULL);
        assert_se(rb != NULL);

        /* Already allocated, no-op */
        cr = bitmap_ensure_allocated(&cb);
        rr = rs_bitmap_ensure_allocated(&rb);
        assert_se(cr == rr);
        assert_se(cr == 0);

        bitmap_free(cb);
        rs_bitmap_free(rb);
}

static void test_bitmap_set_unset(void) {
        Bitmap *cb = NULL, *rb = NULL;
        int cr, rr;

        assert_se(bitmap_ensure_allocated(&cb) >= 0);
        assert_se(rs_bitmap_ensure_allocated(&rb) >= 0);

        /* Set bits in both */
        cr = bitmap_set(cb, 0);
        rr = rs_bitmap_set(rb, 0);
        assert_se(cr == rr);
        assert_se(cr == 0);

        cr = bitmap_set(cb, 63);
        rr = rs_bitmap_set(rb, 63);
        assert_se(cr == rr);

        cr = bitmap_set(cb, 64);
        rr = rs_bitmap_set(rb, 64);
        assert_se(cr == rr);

        /* Compare */
        assert_se(bitmap_equal(cb, rb));

        /* Set beyond max entry → -ERANGE */
        cr = bitmap_set(cb, 0x10000);
        rr = rs_bitmap_set(rb, 0x10000);
        assert_se(cr == rr);
        assert_se(cr == -ERANGE);

        /* Unset a bit */
        bitmap_unset(cb, 0);
        rs_bitmap_unset(rb, 0);
        assert_se(!bitmap_isset(cb, 0));
        assert_se(!rs_bitmap_isset(rb, 0));
        assert_se(bitmap_equal(cb, rb));

        /* Unset on NULL is safe */
        bitmap_unset(NULL, 5);
        rs_bitmap_unset(NULL, 5);

        /* Unset out of range is safe */
        bitmap_unset(cb, 200);
        rs_bitmap_unset(rb, 200);

        bitmap_free(cb);
        rs_bitmap_free(rb);
}

static void test_bitmap_clear(void) {
        Bitmap *cb = NULL, *rb = NULL;

        assert_se(bitmap_ensure_allocated(&cb) >= 0);
        assert_se(rs_bitmap_ensure_allocated(&rb) >= 0);

        assert_se(bitmap_set(cb, 5) >= 0);
        assert_se(bitmap_set(cb, 100) >= 0);
        assert_se(rs_bitmap_set(rb, 5) >= 0);
        assert_se(rs_bitmap_set(rb, 100) >= 0);

        /* Clear both */
        bitmap_clear(cb);
        rs_bitmap_clear(rb);

        /* Should be clear */
        assert_se(bitmap_isclear(cb));
        assert_se(rs_bitmap_isclear(rb));
        assert_se(bitmap_equal(cb, rb));

        /* Can set again after clear */
        assert_se(bitmap_set(cb, 42) >= 0);
        assert_se(rs_bitmap_set(rb, 42) >= 0);
        assert_se(bitmap_isset(cb, 42));
        assert_se(rs_bitmap_isset(rb, 42));

        /* Clear on NULL is safe */
        bitmap_clear(NULL);
        rs_bitmap_clear(NULL);

        bitmap_free(cb);
        rs_bitmap_free(rb);
}

static void test_bitmap_iterate(void) {
        Bitmap *cb = NULL, *rb = NULL;
        bool cv, rv;
        unsigned cn, rn;

        /* Empty bitmap: no iterations */
        assert_se(bitmap_ensure_allocated(&cb) >= 0);
        assert_se(rs_bitmap_ensure_allocated(&rb) >= 0);

        Iterator ci = {}, ri = {};
        cv = bitmap_iterate(cb, &ci, &cn);
        rv = rs_bitmap_iterate(rb, &ri, &rn);
        assert_se(cv == rv);
        assert_se(!cv);

        /* Set some bits and iterate */
        assert_se(bitmap_set(cb, 0) >= 0);
        assert_se(bitmap_set(cb, 5) >= 0);
        assert_se(bitmap_set(cb, 63) >= 0);
        assert_se(bitmap_set(cb, 64) >= 0);
        assert_se(bitmap_set(cb, 100) >= 0);
        assert_se(rs_bitmap_set(rb, 0) >= 0);
        assert_se(rs_bitmap_set(rb, 5) >= 0);
        assert_se(rs_bitmap_set(rb, 63) >= 0);
        assert_se(rs_bitmap_set(rb, 64) >= 0);
        assert_se(rs_bitmap_set(rb, 100) >= 0);

        ci = (Iterator){};
        ri = (Iterator){};

        /* First: bit 0 */
        cv = bitmap_iterate(cb, &ci, &cn);
        rv = rs_bitmap_iterate(rb, &ri, &rn);
        assert_se(cv == rv);
        assert_se(cv);
        assert_se(cn == rn);
        assert_se(cn == 0);

        /* Second: bit 5 */
        cv = bitmap_iterate(cb, &ci, &cn);
        rv = rs_bitmap_iterate(rb, &ri, &rn);
        assert_se(cv == rv);
        assert_se(cv);
        assert_se(cn == rn);
        assert_se(cn == 5);

        /* Third: bit 63 */
        cv = bitmap_iterate(cb, &ci, &cn);
        rv = rs_bitmap_iterate(rb, &ri, &rn);
        assert_se(cv == rv);
        assert_se(cv);
        assert_se(cn == rn);
        assert_se(cn == 63);

        /* Fourth: bit 64 */
        cv = bitmap_iterate(cb, &ci, &cn);
        rv = rs_bitmap_iterate(rb, &ri, &rn);
        assert_se(cv == rv);
        assert_se(cv);
        assert_se(cn == rn);
        assert_se(cn == 64);

        /* Fifth: bit 100 */
        cv = bitmap_iterate(cb, &ci, &cn);
        rv = rs_bitmap_iterate(rb, &ri, &rn);
        assert_se(cv == rv);
        assert_se(cv);
        assert_se(cn == rn);
        assert_se(cn == 100);

        /* No more */
        cv = bitmap_iterate(cb, &ci, &cn);
        rv = rs_bitmap_iterate(rb, &ri, &rn);
        assert_se(cv == rv);
        assert_se(!cv);

        /* Iterate on NULL bitmap: false */
        ci = (Iterator){};
        ri = (Iterator){};
        cv = bitmap_iterate(NULL, &ci, &cn);
        rv = rs_bitmap_iterate(NULL, &ri, &rn);
        assert_se(cv == rv);
        assert_se(!cv);

        bitmap_free(cb);
        rs_bitmap_free(rb);
}

static void test_bitmap_iterate_using_FOREACH(void) {
        Bitmap *cb = NULL, *rb = NULL;
        unsigned cn, rn;
        unsigned count_c = 0, count_r = 0;

        assert_se(bitmap_ensure_allocated(&cb) >= 0);
        assert_se(rs_bitmap_ensure_allocated(&rb) >= 0);

        assert_se(bitmap_set(cb, 3) >= 0);
        assert_se(bitmap_set(cb, 10) >= 0);
        assert_se(bitmap_set(cb, 50) >= 0);
        assert_se(rs_bitmap_set(rb, 3) >= 0);
        assert_se(rs_bitmap_set(rb, 10) >= 0);
        assert_se(rs_bitmap_set(rb, 50) >= 0);

        /* Iterate all bits using C macro */
        BITMAP_FOREACH(cn, cb)
                count_c++;

        /* Iterate all bits using Rust function */
        Iterator ri = {};
        while (rs_bitmap_iterate(rb, &ri, &rn))
                count_r++;

        assert_se(count_c == count_r);
        assert_se(count_c == 3);

        bitmap_free(cb);
        rs_bitmap_free(rb);
}

int main(int argc, char **argv) {
        test_bitmap_isset();
        test_bitmap_isclear();
        test_bitmap_equal();
        test_bitmap_new_free();
        test_bitmap_copy();
        test_bitmap_ensure_allocated();
        test_bitmap_set_unset();
        test_bitmap_clear();
        test_bitmap_iterate();
        test_bitmap_iterate_using_FOREACH();

        return 0;
}
