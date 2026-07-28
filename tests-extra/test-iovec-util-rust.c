/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C iovec-util vs Rust rs_iovec_util */

#include <string.h>

#include "alloc-util.h"
#include "iovec-util.h"
#include "rust/iovec_util.h"

/* Helper: cast C iovec pointer to rs_IoVec pointer (same layout) */
static struct rs_IoVec* to_rs(struct iovec *v) {
        return (struct rs_IoVec*) v;
}
static const struct rs_IoVec* to_rs_c(const struct iovec *v) {
        return (const struct rs_IoVec*) v;
}

/* RUST-CONTRACT: iovec-validation */
/* ── iovec_is_set / iovec_is_valid ─────────────────────────────────────── */

static void test_iovec_is_set(void) {
        struct iovec v = {};

        /* NULL → not set */
        assert_se(!iovec_is_set(NULL));
        assert_se(!rs_iovec_is_set(NULL));

        /* zero-length → not set */
        v = (struct iovec) { .iov_base = (void*)"", .iov_len = 0 };
        assert_se(!iovec_is_set(&v));
        assert_se(!rs_iovec_is_set(to_rs_c(&v)));

        /* NULL base → not set */
        v = (struct iovec) { .iov_base = NULL, .iov_len = 5 };
        assert_se(!iovec_is_set(&v));
        assert_se(!rs_iovec_is_set(to_rs_c(&v)));

        /* valid → set */
        static char buf[] = "hello";
        v = (struct iovec) { .iov_base = buf, .iov_len = 5 };
        assert_se(iovec_is_set(&v));
        assert_se(rs_iovec_is_set(to_rs_c(&v)));
}

static void test_iovec_is_valid(void) {
        struct iovec v = {};

        /* NULL → valid */
        assert_se(iovec_is_valid(NULL));
        assert_se(rs_iovec_is_valid(NULL));

        /* zero-length with NULL base → valid */
        v = (struct iovec) { .iov_base = NULL, .iov_len = 0 };
        assert_se(iovec_is_valid(&v));
        assert_se(rs_iovec_is_valid(to_rs_c(&v)));

        /* non-NULL base → valid */
        static char buf[] = "hello";
        v = (struct iovec) { .iov_base = buf, .iov_len = 5 };
        assert_se(iovec_is_valid(&v));
        assert_se(rs_iovec_is_valid(to_rs_c(&v)));

        /* NULL base with non-zero len → NOT valid */
        v = (struct iovec) { .iov_base = NULL, .iov_len = 5 };
        assert_se(!iovec_is_valid(&v));
        assert_se(!rs_iovec_is_valid(to_rs_c(&v)));
}

/* RUST-CONTRACT: iovec-done */
/* RUST-CONTRACT: iovec-done-many-and-free */
/* ── iovec_done / iovec_done_many_and_free ────────────────────────────── */

static void test_iovec_done(void) {
        struct iovec cv = IOVEC_MAKE_STRING(strdup("owned"));
        struct rs_IoVec rv = {
                .iov_base = strdup("owned"),
                .iov_len = STRLEN("owned"),
        };

        assert_se(cv.iov_base);
        assert_se(rv.iov_base);
        iovec_done(&cv);
        rs_iovec_done(&rv);
        assert_se(cv.iov_base == NULL && cv.iov_len == 0);
        assert_se(rv.iov_base == NULL && rv.iov_len == 0);
}

static void test_iovec_done_many_and_free(void) {
        struct iovec *cv = new(struct iovec, 2);
        struct rs_IoVec *rv = new(struct rs_IoVec, 2);

        assert_se(cv);
        assert_se(rv);
        cv[0] = IOVEC_MAKE_STRING(strdup("one"));
        cv[1] = IOVEC_MAKE_STRING(strdup("two"));
        rv[0] = (struct rs_IoVec) { .iov_base = strdup("one"), .iov_len = 3 };
        rv[1] = (struct rs_IoVec) { .iov_base = strdup("two"), .iov_len = 3 };
        assert_se(cv[0].iov_base && cv[1].iov_base);
        assert_se(rv[0].iov_base && rv[1].iov_base);

        iovec_done_many_and_free(cv, 2);
        rs_iovec_done_many_and_free(rv, 2);
}

/* RUST-CONTRACT: iovec-allocation */
/* ── iovec_alloc / iovec_erase ────────────────────────────────────────── */

static void test_iovec_alloc(void) {
        struct iovec cv = {};
        struct rs_IoVec rv = {};

        assert_se(iovec_alloc(0, &cv) == 0);
        assert_se(rs_iovec_alloc(0, &rv) == 0);
        assert_se(cv.iov_base);
        assert_se(rv.iov_base);
        assert_se(cv.iov_len == 0);
        assert_se(rv.iov_len == 0);
        iovec_done(&cv);
        rs_iovec_done(&rv);

        assert_se(iovec_alloc(16, &cv) == 0);
        assert_se(rs_iovec_alloc(16, &rv) == 0);
        assert_se(cv.iov_base);
        assert_se(rv.iov_base);
        assert_se(cv.iov_len == 16);
        assert_se(rv.iov_len == 16);
        iovec_done(&cv);
        rs_iovec_done(&rv);
}

/* RUST-CONTRACT: iovec-erasure */
static void test_iovec_erase(void) {
        char c_bytes[] = "secret";
        char rust_bytes[] = "secret";
        struct iovec cv = IOVEC_MAKE(c_bytes, STRLEN("secret"));
        struct rs_IoVec rv = {
                .iov_base = rust_bytes,
                .iov_len = STRLEN("secret"),
        };

        iovec_erase(&cv);
        rs_iovec_erase(&rv);
        assert_se(memcmp(c_bytes, (char[STRLEN("secret")]) {}, STRLEN("secret")) == 0);
        assert_se(memcmp(rust_bytes, (char[STRLEN("secret")]) {}, STRLEN("secret")) == 0);
        assert_se(cv.iov_len == STRLEN("secret"));
        assert_se(rv.iov_len == STRLEN("secret"));
}

/* RUST-CONTRACT: iovec-total-size */
/* ── iovec_total_size ──────────────────────────────────────────────────── */

static void test_iovec_total_size(void) {
        struct iovec v[3];
        char a[] = "hello";
        char b[] = "world";
        char c[] = "!";

        /* Empty array → 0 */
        assert_se(iovec_total_size(NULL, 0) == 0);
        assert_se(rs_iovec_total_size(NULL, 0) == 0);

        /* Single element */
        v[0] = (struct iovec) { .iov_base = a, .iov_len = 5 };
        assert_se(iovec_total_size(v, 1) == 5);
        assert_se(rs_iovec_total_size(to_rs_c(v), 1) == 5);

        /* Multiple elements */
        v[0] = (struct iovec) { .iov_base = a, .iov_len = 5 };
        v[1] = (struct iovec) { .iov_base = b, .iov_len = 5 };
        v[2] = (struct iovec) { .iov_base = c, .iov_len = 1 };
        assert_se(iovec_total_size(v, 3) == 11);
        assert_se(rs_iovec_total_size(to_rs_c(v), 3) == 11);

        /* With zero-length elements */
        v[0] = (struct iovec) { .iov_base = a, .iov_len = 5 };
        v[1] = (struct iovec) { .iov_base = NULL, .iov_len = 0 };
        v[2] = (struct iovec) { .iov_base = c, .iov_len = 1 };
        assert_se(iovec_total_size(v, 3) == 6);
        assert_se(rs_iovec_total_size(to_rs_c(v), 3) == 6);
}

/* RUST-CONTRACT: iovec-increment */
/* ── iovec_inc_many ────────────────────────────────────────────────────── */

static void test_iovec_inc_many(void) {
        char buf[] = "hello world";
        struct iovec v[2];
        bool c_ret, r_ret;

        /* Increment 0 bytes → false (still data) */
        v[0] = (struct iovec) { .iov_base = buf, .iov_len = 11 };
        c_ret = iovec_inc_many(v, 1, 0);
        assert_se(!c_ret);
        assert_se(v[0].iov_len == 11); /* unchanged */

        v[0] = (struct iovec) { .iov_base = buf, .iov_len = 11 };
        r_ret = rs_iovec_inc_many(to_rs(v), 1, 0);
        assert_se(!r_ret);
        assert_se(v[0].iov_len == 11);

        /* Increment exactly all bytes → true */
        v[0] = (struct iovec) { .iov_base = buf, .iov_len = 5 };
        v[1] = (struct iovec) { .iov_base = buf + 6, .iov_len = 5 };
        c_ret = iovec_inc_many(v, 2, 10);
        assert_se(c_ret);

        v[0] = (struct iovec) { .iov_base = buf, .iov_len = 5 };
        v[1] = (struct iovec) { .iov_base = buf + 6, .iov_len = 5 };
        r_ret = rs_iovec_inc_many(to_rs(v), 2, 10);
        assert_se(r_ret);

        /* Increment across boundary — consume 7 of 10 bytes, leaving work */
        v[0] = (struct iovec) { .iov_base = buf, .iov_len = 5 };
        v[1] = (struct iovec) { .iov_base = buf + 6, .iov_len = 5 };
        c_ret = iovec_inc_many(v, 2, 7);
        assert_se(!c_ret);
        /* v[0] should be empty, v[1] should have 3 bytes left */
        assert_se(v[0].iov_len == 0);
        assert_se(v[1].iov_len == 3);
        assert_se(v[1].iov_base == buf + 6 + 2);

        v[0] = (struct iovec) { .iov_base = buf, .iov_len = 5 };
        v[1] = (struct iovec) { .iov_base = buf + 6, .iov_len = 5 };
        r_ret = rs_iovec_inc_many(to_rs(v), 2, 7);
        assert_se(!r_ret);
        assert_se(v[0].iov_len == 0);
        assert_se(v[1].iov_len == 3);
        assert_se(v[1].iov_base == buf + 6 + 2);

        /* Skip zero-length entries */
        v[0] = (struct iovec) { .iov_base = NULL, .iov_len = 0 };
        v[1] = (struct iovec) { .iov_base = buf, .iov_len = 5 };
        c_ret = iovec_inc_many(v, 2, 0);
        assert_se(!c_ret);

        v[0] = (struct iovec) { .iov_base = NULL, .iov_len = 0 };
        v[1] = (struct iovec) { .iov_base = buf, .iov_len = 5 };
        r_ret = rs_iovec_inc_many(to_rs(v), 2, 0);
        assert_se(!r_ret);
}

/* RUST-CONTRACT: iovec-borrowed-string */
/* ── iovec_make_string ─────────────────────────────────────────────────── */

static void test_iovec_make_string(void) {
        struct iovec v;
        struct rs_IoVec rv;
        const char *s = "hello";

        iovec_make_string(&v, s);
        rs_iovec_make_string(&rv, s);

        assert_se(v.iov_len == 5);
        assert_se(rv.iov_len == 5);
        assert_se(v.iov_base == s);
        assert_se(rv.iov_base == (void*)s);

        /* NULL string */
        iovec_make_string(&v, NULL);
        rs_iovec_make_string(&rv, NULL);
        assert_se(v.iov_len == 0);
        assert_se(rv.iov_len == 0);

        /* Empty string */
        iovec_make_string(&v, "");
        rs_iovec_make_string(&rv, "");
        assert_se(v.iov_len == 0);
        assert_se(rv.iov_len == 0);
}

/* RUST-CONTRACT: iovec-byte-comparison */
/* ── iovec_memcmp ──────────────────────────────────────────────────────── */

static void test_iovec_memcmp(void) {
        struct iovec a, b;
        int c_ret, r_ret;

        /* Same pointer → 0 */
        a = (struct iovec) { .iov_base = (void*)"hello", .iov_len = 5 };
        c_ret = iovec_memcmp(&a, &a);
        r_ret = rs_iovec_memcmp(to_rs_c(&a), to_rs_c(&a));
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);

        /* Equal contents */
        a = (struct iovec) { .iov_base = (void*)"hello", .iov_len = 5 };
        b = (struct iovec) { .iov_base = (void*)"hello", .iov_len = 5 };
        c_ret = iovec_memcmp(&a, &b);
        r_ret = rs_iovec_memcmp(to_rs_c(&a), to_rs_c(&b));
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);

        /* a < b */
        a = (struct iovec) { .iov_base = (void*)"abc", .iov_len = 3 };
        b = (struct iovec) { .iov_base = (void*)"abd", .iov_len = 3 };
        c_ret = iovec_memcmp(&a, &b);
        r_ret = rs_iovec_memcmp(to_rs_c(&a), to_rs_c(&b));
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* a > b */
        a = (struct iovec) { .iov_base = (void*)"abd", .iov_len = 3 };
        b = (struct iovec) { .iov_base = (void*)"abc", .iov_len = 3 };
        c_ret = iovec_memcmp(&a, &b);
        r_ret = rs_iovec_memcmp(to_rs_c(&a), to_rs_c(&b));
        assert_se(c_ret > 0);
        assert_se(r_ret > 0);

        /* Shorter prefix */
        a = (struct iovec) { .iov_base = (void*)"ab", .iov_len = 2 };
        b = (struct iovec) { .iov_base = (void*)"abc", .iov_len = 3 };
        c_ret = iovec_memcmp(&a, &b);
        r_ret = rs_iovec_memcmp(to_rs_c(&a), to_rs_c(&b));
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);

        /* Longer prefix */
        a = (struct iovec) { .iov_base = (void*)"abc", .iov_len = 3 };
        b = (struct iovec) { .iov_base = (void*)"ab", .iov_len = 2 };
        c_ret = iovec_memcmp(&a, &b);
        r_ret = rs_iovec_memcmp(to_rs_c(&a), to_rs_c(&b));
        assert_se(c_ret > 0);
        assert_se(r_ret > 0);

        /* NULL vs NULL */
        c_ret = iovec_memcmp(NULL, NULL);
        r_ret = rs_iovec_memcmp(NULL, NULL);
        assert_se(c_ret == 0);
        assert_se(r_ret == 0);

        /* NULL vs non-empty */
        a = (struct iovec) { .iov_base = (void*)"x", .iov_len = 1 };
        c_ret = iovec_memcmp(NULL, &a);
        r_ret = rs_iovec_memcmp(NULL, to_rs_c(&a));
        assert_se(c_ret < 0);
        assert_se(r_ret < 0);
}

/* RUST-CONTRACT: iovec-memdup */
/* RUST-CONTRACT: iovec-done-and-memdup */
/* ── iovec_memdup ──────────────────────────────────────────────────────── */

static void test_iovec_memdup(void) {
        struct iovec src, c_ret;
        struct rs_IoVec rs_ret;
        const char *data = "hello world";

        /* Normal copy */
        src = (struct iovec) { .iov_base = (void*)data, .iov_len = 11 };
        assert_se(iovec_memdup(&src, &c_ret) == &c_ret);
        assert_se(c_ret.iov_len == 11);
        assert_se(c_ret.iov_base != src.iov_base);
        assert_se(memcmp(c_ret.iov_base, data, 11) == 0);
        free(c_ret.iov_base);

        assert_se(rs_iovec_memdup(to_rs_c(&src), &rs_ret) == &rs_ret);
        assert_se(rs_ret.iov_len == 11);
        assert_se(rs_ret.iov_base != src.iov_base);
        assert_se(memcmp(rs_ret.iov_base, data, 11) == 0);
        free(rs_ret.iov_base);

        /* source may alias ret: both implementations must copy before write */
        c_ret = (struct iovec) { .iov_base = (void*)data, .iov_len = 11 };
        assert_se(iovec_memdup(&c_ret, &c_ret) == &c_ret);
        assert_se(c_ret.iov_len == 11);
        assert_se(c_ret.iov_base != (void*) data);
        assert_se(memcmp(c_ret.iov_base, data, 11) == 0);
        free(c_ret.iov_base);

        rs_ret = (struct rs_IoVec) { .iov_base = (void*)data, .iov_len = 11 };
        assert_se(rs_iovec_memdup(&rs_ret, &rs_ret) == &rs_ret);
        assert_se(rs_ret.iov_len == 11);
        assert_se(rs_ret.iov_base != (void*) data);
        assert_se(memcmp(rs_ret.iov_base, data, 11) == 0);
        free(rs_ret.iov_base);

        /* Not set (NULL base) → empty */
        src = (struct iovec) { .iov_base = NULL, .iov_len = 0 };
        assert_se(iovec_memdup(&src, &c_ret) == &c_ret);
        assert_se(c_ret.iov_len == 0);

        assert_se(rs_iovec_memdup(to_rs_c(&src), &rs_ret) == &rs_ret);
        assert_se(rs_ret.iov_len == 0);

        /* Zero length with non-NULL base → empty (iovec_is_set returns false) */
        src = (struct iovec) { .iov_base = (void*)data, .iov_len = 0 };
        assert_se(iovec_memdup(&src, &c_ret) == &c_ret);
        assert_se(c_ret.iov_len == 0);

        assert_se(rs_iovec_memdup(to_rs_c(&src), &rs_ret) == &rs_ret);
        assert_se(rs_ret.iov_len == 0);

        /* NULL source → empty */
        assert_se(iovec_memdup(NULL, &c_ret) == &c_ret);
        assert_se(c_ret.iov_len == 0);

        assert_se(rs_iovec_memdup(NULL, &rs_ret) == &rs_ret);
        assert_se(rs_ret.iov_len == 0);
}

static void test_iovec_done_and_memdup(void) {
        const struct iovec same = IOVEC_MAKE((void*) "old", STRLEN("old"));
        const struct iovec replacement = IOVEC_MAKE((void*) "new", STRLEN("new"));
        struct iovec cv = IOVEC_MAKE_STRING(strdup("old"));
        struct rs_IoVec rv = {
                .iov_base = strdup("old"),
                .iov_len = STRLEN("old"),
        };

        assert_se(cv.iov_base);
        assert_se(rv.iov_base);
        assert_se(iovec_done_and_memdup(&cv, &same) == 0);
        assert_se(rs_iovec_done_and_memdup(&rv, to_rs_c(&same)) == 0);
        assert_se(memcmp(cv.iov_base, "old", STRLEN("old")) == 0);
        assert_se(memcmp(rv.iov_base, "old", STRLEN("old")) == 0);

        assert_se(iovec_done_and_memdup(&cv, &replacement) == 1);
        assert_se(rs_iovec_done_and_memdup(&rv, to_rs_c(&replacement)) == 1);
        assert_se(memcmp(cv.iov_base, "new", STRLEN("new")) == 0);
        assert_se(memcmp(rv.iov_base, "new", STRLEN("new")) == 0);
        iovec_done(&cv);
        rs_iovec_done(&rv);
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_iovec_is_set();
        test_iovec_is_valid();
        test_iovec_done();
        test_iovec_done_many_and_free();
        test_iovec_alloc();
        test_iovec_erase();
        test_iovec_total_size();
        test_iovec_inc_many();
        test_iovec_make_string();
        test_iovec_memcmp();
        test_iovec_memdup();
        test_iovec_done_and_memdup();

        return 0;
}
