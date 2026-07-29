/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C iovec_wrapper vs Rust rs_IoVecWrapper */

#include <string.h>

#include "alloc-util.h"
#include "iovec-wrapper.h"
#include "rust/iovec_wrapper.h"
#include "tests.h"

/* RUST-CONTRACT: iovec-wrapper-cleanup */
/* RUST-CONTRACT: iovec-wrapper-put */
/* RUST-CONTRACT: iovec-wrapper-rebase */
/* RUST-CONTRACT: iovec-wrapper-query */

_Static_assert(sizeof(struct iovec_wrapper) == sizeof(struct rs_IoVecWrapper));
_Static_assert(_Alignof(struct iovec_wrapper) == _Alignof(struct rs_IoVecWrapper));

static struct iovec_wrapper* new_c_wrapper(void) {
        return new0(struct iovec_wrapper, 1);
}

static struct rs_IoVecWrapper* new_rust_wrapper(void) {
        return new0(struct rs_IoVecWrapper, 1);
}

/* Helper: cast const C iovec_wrapper to rs_IoVecWrapper (same layout) */
static const struct rs_IoVecWrapper* to_rs_c(const struct iovec_wrapper *w) {
        return (const struct rs_IoVecWrapper*) w;
}

/* ── iovw_free / iovw_free_free ─────────────────────────────────────────── */

static void test_iovw_new_free(void) {
        struct iovec_wrapper *c_w = new_c_wrapper();
        struct rs_IoVecWrapper *r_w = new_rust_wrapper();

        assert_se(c_w != NULL);
        assert_se(r_w != NULL);
        assert_se(c_w->iovec == NULL);
        assert_se(r_w->iovec == NULL);
        assert_se(c_w->count == 0);
        assert_se(r_w->count == 0);

        assert_se(iovw_free(c_w) == NULL);
        assert_se(rs_iovw_free(r_w) == NULL);

        /* NULL input */
        assert_se(iovw_free(NULL) == NULL);
        assert_se(rs_iovw_free(NULL) == NULL);
}

static void test_iovw_free_free(void) {
        struct iovec_wrapper *c_w = new_c_wrapper();
        struct rs_IoVecWrapper *r_w = new_rust_wrapper();

        iovw_put(c_w, strdup("hello"), 5);
        rs_iovw_put(r_w, strdup("hello"), 5);

        /* free_free frees data pointers, array, and wrapper */
        assert_se(iovw_free_free(c_w) == NULL);
        assert_se(rs_iovw_free_free(r_w) == NULL);

        /* NULL input */
        assert_se(iovw_free_free(NULL) == NULL);
        assert_se(rs_iovw_free_free(NULL) == NULL);
}

/* ── iovw_put / iovw_size / iovw_isempty ──────────────────────────────── */

static void test_iovw_put_size(void) {
        char a[] = "hello";
        char b[] = "world";

        struct iovec_wrapper *c_w = new_c_wrapper();
        struct rs_IoVecWrapper *r_w = new_rust_wrapper();

        /* Empty */
        assert_se(iovw_isempty(c_w));
        assert_se(rs_iovw_isempty(to_rs_c(c_w)));
        assert_se(iovw_size(c_w) == 0);
        assert_se(rs_iovw_size(to_rs_c(c_w)) == 0);

        /* Add one entry */
        iovw_put(c_w, a, 5);
        rs_iovw_put(r_w, a, 5);
        assert_se(!iovw_isempty(c_w));
        assert_se(!rs_iovw_isempty(to_rs_c(c_w)));
        assert_se(iovw_size(c_w) == 5);
        assert_se(rs_iovw_size(to_rs_c(c_w)) == 5);

        /* Add another */
        iovw_put(c_w, b, 5);
        rs_iovw_put(r_w, b, 5);
        assert_se(iovw_size(c_w) == 10);
        assert_se(rs_iovw_size(to_rs_c(c_w)) == 10);

        /* Zero-length put is a no-op */
        iovw_put(c_w, a, 0);
        rs_iovw_put(r_w, a, 0);
        assert_se(iovw_size(c_w) == 10);
        assert_se(rs_iovw_size(to_rs_c(c_w)) == 10);

        iovw_free(c_w);
        rs_iovw_free(r_w);
}

/* ── iovw_done / iovw_done_free ──────────────────────────────────────── */

static void test_iovw_done(void) {
        char data[] = "hello";
        struct iovec_wrapper *c_w = new_c_wrapper();
        struct rs_IoVecWrapper *r_w = new_rust_wrapper();

        iovw_put(c_w, data, 5);
        rs_iovw_put(r_w, data, 5);

        /* done: frees the iovec array but NOT the data pointers */
        iovw_done(c_w);
        rs_iovw_done(r_w);
        assert_se(c_w->iovec == NULL);
        assert_se(r_w->iovec == NULL);
        assert_se(c_w->count == 0);
        assert_se(r_w->count == 0);

        /* done_free: frees iovec array AND data pointers */
        iovw_put(c_w, strdup("test"), 4);
        rs_iovw_put(r_w, strdup("test"), 4);
        iovw_done_free(c_w);
        rs_iovw_done_free(r_w);
        assert_se(c_w->iovec == NULL);
        assert_se(r_w->iovec == NULL);

        iovw_free(c_w);
        rs_iovw_free(r_w);
}

/* ── iovw_rebase ──────────────────────────────────────────────────────── */

static void test_iovw_rebase(void) {
        char old_buf[64], new_buf[64];
        struct iovec_wrapper *c_w = new_c_wrapper();
        struct rs_IoVecWrapper *r_w = new_rust_wrapper();

        /* Point iovec entries into old_buf. */
        iovw_put(c_w, old_buf + 10, 5);
        iovw_put(c_w, old_buf + 30, 5);
        rs_iovw_put(r_w, old_buf + 10, 5);
        rs_iovw_put(r_w, old_buf + 30, 5);

        iovw_rebase(c_w, old_buf, new_buf);
        rs_iovw_rebase(r_w, old_buf, new_buf);

        assert_se(c_w->iovec[0].iov_base == new_buf + 10);
        assert_se(r_w->iovec[0].iov_base == new_buf + 10);
        assert_se(c_w->iovec[1].iov_base == new_buf + 30);
        assert_se(r_w->iovec[1].iov_base == new_buf + 30);

        iovw_free(c_w);
        rs_iovw_free(r_w);
}

/* ── Main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_iovw_new_free();
        test_iovw_free_free();
        test_iovw_put_size();
        test_iovw_done();
        test_iovw_rebase();

        return 0;
}
