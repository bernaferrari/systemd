/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C vs Rust for remaining untested functions */

#include <string.h>
#include <stdlib.h>
#include <sys/uio.h>

#include "tests.h"
#include "user-record.h"
#include "iovec-util.h"
#include "rust/shared_facades/validation.h"
#include "rust/iovec_util.h"

/* ── suitable_blob_filename ──────────────────────────────────────── */

static void test_suitable_blob_filename_valid(void) {
        const char *valid[] = {
                "foo",
                "foo-bar",
                "foo_bar",
                "foo.bar",
                "Foo-Bar",
                "0",
                "a",
                "A-B-C",
                "~",
                "hello-123_world",
        };
        for (int i = 0; i < (int)ELEMENTSOF(valid); i++) {
                int c = suitable_blob_filename(valid[i]);
                int r = rs_suitable_blob_filename(valid[i]);
                assert_se(c == r);
                assert_se(c > 0);
        }
}

static void test_suitable_blob_filename_dot(void) {
        /* Must not start with '.' */
        assert_se(!suitable_blob_filename("."));
        assert_se(!rs_suitable_blob_filename("."));

        assert_se(!suitable_blob_filename(".hidden"));
        assert_se(!rs_suitable_blob_filename(".hidden"));

        assert_se(!suitable_blob_filename(".."));
        assert_se(!rs_suitable_blob_filename(".."));
}

static void test_suitable_blob_filename_empty(void) {
        assert_se(!suitable_blob_filename(""));
        assert_se(!rs_suitable_blob_filename(""));
}

static void test_suitable_blob_filename_slash(void) {
        /* Slashes are not valid filename chars */
        assert_se(!suitable_blob_filename("foo/bar"));
        assert_se(!rs_suitable_blob_filename("foo/bar"));

        assert_se(!suitable_blob_filename("/foo"));
        assert_se(!rs_suitable_blob_filename("/foo"));
}

static void test_suitable_blob_filename_special(void) {
        /* Special chars not in URI_UNRESERVED */
        assert_se(!suitable_blob_filename("foo bar"));
        assert_se(!rs_suitable_blob_filename("foo bar"));

        assert_se(!suitable_blob_filename("foo@bar"));
        assert_se(!rs_suitable_blob_filename("foo@bar"));

        assert_se(!suitable_blob_filename("foo:bar"));
        assert_se(!rs_suitable_blob_filename("foo:bar"));

        assert_se(!suitable_blob_filename("foo!bar"));
        assert_se(!rs_suitable_blob_filename("foo!bar"));
}

static void test_suitable_blob_filename_null(void) {
        /* filename_is_valid returns false for NULL */
        assert_se(!suitable_blob_filename(NULL));
        assert_se(!rs_suitable_blob_filename(NULL));
}

/* ── iovec_done ───────────────────────────────────────────────────── */

static void test_iovec_done_basic(void) {
        struct iovec c_iov = {};
        struct rs_IoVec r_iov = {};

        c_iov.iov_base = strdup("hello");
        c_iov.iov_len = 5;
        r_iov.iov_base = strdup("hello");
        r_iov.iov_len = 5;

        iovec_done(&c_iov);
        rs_iovec_done(&r_iov);

        assert_se(c_iov.iov_base == NULL);
        assert_se(c_iov.iov_len == 0);
        assert_se(r_iov.iov_base == NULL);
        assert_se(r_iov.iov_len == 0);
}

static void test_iovec_done_null(void) {
        /* C has assert(iovec) — only test Rust with NULL */
        rs_iovec_done(NULL);
}

static void test_iovec_done_empty(void) {
        struct iovec c_iov = {};
        struct rs_IoVec r_iov = {};

        /* iov_base = NULL, iov_len = 0 — mfree(NULL) is safe */
        c_iov.iov_base = NULL;
        c_iov.iov_len = 0;
        r_iov.iov_base = NULL;
        r_iov.iov_len = 0;

        iovec_done(&c_iov);
        rs_iovec_done(&r_iov);

        assert_se(c_iov.iov_base == NULL);
        assert_se(r_iov.iov_base == NULL);
}

/* ── iovec_done_many_and_free ─────────────────────────────────────── */

static void test_iovec_done_many_and_free_basic(void) {
        /* Allocate an array of 3 iovecs */
        struct iovec *c_iovs = calloc(3, sizeof(struct iovec));
        struct rs_IoVec *r_iovs = calloc(3, sizeof(struct rs_IoVec));

        c_iovs[0].iov_base = strdup("hello");
        c_iovs[0].iov_len = 5;
        c_iovs[1].iov_base = strdup("world");
        c_iovs[1].iov_len = 5;
        c_iovs[2].iov_base = strdup("foo");
        c_iovs[2].iov_len = 3;

        r_iovs[0].iov_base = strdup("hello");
        r_iovs[0].iov_len = 5;
        r_iovs[1].iov_base = strdup("world");
        r_iovs[1].iov_len = 5;
        r_iovs[2].iov_base = strdup("foo");
        r_iovs[2].iov_len = 3;

        iovec_done_many_and_free(c_iovs, 3);
        rs_iovec_done_many_and_free(r_iovs, 3);

        /* All memory is freed; just verify no crash */
}

static void test_iovec_done_many_and_free_null(void) {
        /* C has no NULL guard — only test Rust with NULL */
        rs_iovec_done_many_and_free(NULL, 5);
}

static void test_iovec_done_many_and_free_zero(void) {
        struct iovec *c_iovs = calloc(3, sizeof(struct iovec));
        struct rs_IoVec *r_iovs = calloc(3, sizeof(struct rs_IoVec));

        c_iovs[0].iov_base = strdup("hello");
        c_iovs[0].iov_len = 5;
        r_iovs[0].iov_base = strdup("hello");
        r_iovs[0].iov_len = 5;

        /* n=0 → no entries freed, but array is freed */
        iovec_done_many_and_free(c_iovs, 0);
        rs_iovec_done_many_and_free(r_iovs, 0);
}

int main(int argc, char *argv[]) {
        test_suitable_blob_filename_valid();
        test_suitable_blob_filename_dot();
        test_suitable_blob_filename_empty();
        test_suitable_blob_filename_slash();
        test_suitable_blob_filename_special();
        test_suitable_blob_filename_null();
        test_iovec_done_basic();
        test_iovec_done_null();
        test_iovec_done_empty();
        test_iovec_done_many_and_free_basic();
        test_iovec_done_many_and_free_null();
        test_iovec_done_many_and_free_zero();

        return 0;
}
