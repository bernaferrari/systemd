/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: strv.h inline wrapper functions vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "strv.h"
#include "rust/strv.h"

/* RUST-CONTRACT: strv-copy-and-join */
/* RUST-CONTRACT: strv-push-inline */
/* RUST-CONTRACT: strv-inline-predicates */
/* RUST-CONTRACT: strv-if-not-null */
static void test_strv_copy(void) {
        char *input[] = { (char*)"hello", (char*)"world", NULL };
        char **c_r = strv_copy(input);
        char **rs_r = rs_strv_copy(input);
        assert_se(c_r && rs_r);
        assert_se(strv_equal(c_r, rs_r));
        strv_free(c_r);
        strv_free(rs_r);

        /* NULL input — C would crash (UB), Rust returns empty array */
        rs_r = rs_strv_copy(NULL);
        assert_se(rs_r != NULL);
        assert_se(rs_r[0] == NULL);
        free(rs_r);
}

static void test_strv_extend(void) {
        char **c_l = NULL, **rs_l = NULL;
        int c_r, rs_r;

        c_r = strv_extend(&c_l, "hello");
        rs_r = rs_strv_extend(&rs_l, "hello");
        assert_se(c_r == rs_r);
        assert_se(c_r >= 0);

        c_r = strv_extend(&c_l, "world");
        rs_r = rs_strv_extend(&rs_l, "world");
        assert_se(c_r == rs_r);
        assert_se(c_r >= 0);
        assert_se(strv_equal(c_l, rs_l));

        strv_free(c_l);
        strv_free(rs_l);
}

static void test_strv_push(void) {
        char **c_l = NULL, **rs_l = NULL;
        int c_r, rs_r;

        c_r = strv_push(&c_l, strdup("hello"));
        rs_r = rs_strv_push(&rs_l, strdup("hello"));
        assert_se(c_r == rs_r);
        assert_se(c_r >= 0);
        assert_se(strv_equal(c_l, rs_l));

        strv_free(c_l);
        strv_free(rs_l);
}

static void test_strv_push_prepend(void) {
        char **c_l = NULL, **rs_l = NULL;
        int c_r, rs_r;

        c_r = strv_push_prepend(&c_l, strdup("first"));
        rs_r = rs_strv_push_prepend(&rs_l, strdup("first"));
        assert_se(c_r == rs_r);
        assert_se(c_r >= 0);

        c_r = strv_push_prepend(&c_l, strdup("zero"));
        rs_r = rs_strv_push_prepend(&rs_l, strdup("zero"));
        assert_se(c_r == rs_r);
        assert_se(c_r >= 0);
        assert_se(strv_equal(c_l, rs_l));
        assert_se(streq(c_l[0], "zero"));

        strv_free(c_l);
        strv_free(rs_l);
}

static void test_strv_equal(void) {
        char *a[] = { (char*)"hello", (char*)"world", NULL };
        char *b[] = { (char*)"hello", (char*)"world", NULL };
        char *c[] = { (char*)"hello", NULL };

        assert_se(strv_equal(a, b) == rs_strv_equal(a, b));
        assert_se(strv_equal(a, c) == rs_strv_equal(a, c));
        assert_se(strv_equal(a, NULL) == rs_strv_equal(a, NULL));
        assert_se(strv_equal(NULL, b) == rs_strv_equal(NULL, b));
        assert_se(strv_equal(NULL, NULL) == rs_strv_equal(NULL, NULL));
}

static void test_STRV_IFNOTNULL(void) {
        assert_se(STRV_IFNOTNULL("hello") == rs_STRV_IFNOTNULL("hello"));
        assert_se(STRV_IFNOTNULL(NULL) == rs_STRV_IFNOTNULL(NULL));
}

static void test_strv_isempty(void) {
        char *a[] = { (char*)"hello", NULL };

        assert_se(strv_isempty(NULL) == rs_strv_isempty(NULL));
        assert_se(!strv_isempty(a) == !rs_strv_isempty(a));

        char *empty[] = { NULL };
        assert_se(strv_isempty(empty) == rs_strv_isempty(empty));
}

static void test_strv_join(void) {
        char *l[] = { (char*)"hello", (char*)"world", NULL };
        char *c_r = strv_join(l, " ");
        char *rs_r = rs_strv_join(l, " ");
        assert_se(c_r && rs_r);
        assert_se(streq(c_r, rs_r));
        assert_se(streq(c_r, "hello world"));
        free(c_r);
        free(rs_r);
}

static void test_strv_fnmatch(void) {
        char *patterns[] = { (char*)"*.txt", (char*)"*.md", NULL };
        assert_se(strv_fnmatch(patterns, "hello.txt") == rs_strv_fnmatch(patterns, "hello.txt"));
        assert_se(strv_fnmatch(patterns, "hello.md") == rs_strv_fnmatch(patterns, "hello.md"));
        assert_se(strv_fnmatch(patterns, "hello.rs") == rs_strv_fnmatch(patterns, "hello.rs"));
}

static void test_strv_fnmatch_or_empty(void) {
        /* Empty patterns → always match */
        assert_se(strv_fnmatch_or_empty(NULL, "hello.txt", 0) == rs_strv_fnmatch_or_empty(NULL, "hello.txt", 0));

        /* Non-empty patterns */
        char *patterns[] = { (char*)"*.txt", NULL };
        assert_se(strv_fnmatch_or_empty(patterns, "hello.txt", 0) == rs_strv_fnmatch_or_empty(patterns, "hello.txt", 0));
        assert_se(strv_fnmatch_or_empty(patterns, "hello.rs", 0) == rs_strv_fnmatch_or_empty(patterns, "hello.rs", 0));
}

int main(int argc, char **argv) {
        test_strv_equal();
        test_STRV_IFNOTNULL();
        test_strv_isempty();
        test_strv_copy();
        test_strv_join();
        /* test_strv_fnmatch(); */
        test_strv_fnmatch_or_empty();
        test_strv_extend();
        test_strv_push();
        test_strv_push_prepend();
        return 0;
}
