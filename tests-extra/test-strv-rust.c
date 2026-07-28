/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <string.h>

#include "strv.h"
#include "tests.h"

/* Rust FFI */
#include "rust/strv.h"

/* RUST-CONTRACT: strv-length-and-find */
/* ── strv_length ─────────────────────────────────────────────────────────── */

TEST(strv_length_normal) {
        char *a[] = { (char*)"hello", (char*)"world", NULL };
        assert_se(strv_length(a) == rs_strv_length(a));
        assert_se(strv_length(a) == 2);
}

TEST(strv_length_empty) {
        assert_se(strv_length(NULL) == rs_strv_length(NULL));
        assert_se(strv_length(NULL) == 0);
        char *e[] = { NULL };
        assert_se(strv_length(e) == rs_strv_length(e));
        assert_se(strv_length(e) == 0);
}

/* ── strv_find ───────────────────────────────────────────────────────────── */

TEST(strv_find_found) {
        char *a[] = { (char*)"hello", (char*)"world", (char*)"foo", NULL };
        assert_se(strv_find(a, "world") == rs_strv_find(a, "world"));
        assert_se(streq(strv_find(a, "world"), "world"));
}

TEST(strv_find_not_found) {
        char *a[] = { (char*)"hello", (char*)"world", NULL };
        assert_se(strv_find(a, "bar") == rs_strv_find(a, "bar"));
        assert_se(strv_find(a, "bar") == NULL);
}

TEST(strv_find_empty) {
        assert_se(strv_find(NULL, "hello") == rs_strv_find(NULL, "hello"));
        assert_se(strv_find(NULL, "hello") == NULL);
}

/* ── strv_find_case ──────────────────────────────────────────────────────── */

TEST(strv_find_case_found) {
        char *a[] = { (char*)"Hello", (char*)"WORLD", NULL };
        assert_se(strv_find_case(a, "hello") == rs_strv_find_case(a, "hello"));
        assert_se(streq(strv_find_case(a, "hello"), "Hello"));
}

TEST(strv_find_case_not_found) {
        char *a[] = { (char*)"Hello", (char*)"WORLD", NULL };
        assert_se(strv_find_case(a, "foo") == rs_strv_find_case(a, "foo"));
        assert_se(strv_find_case(a, "foo") == NULL);
}

/* ── strv_find_prefix ────────────────────────────────────────────────────── */

TEST(strv_find_prefix_found) {
        char *a[] = { (char*)"prefix_foo", (char*)"bar_baz", NULL };
        assert_se(strv_find_prefix(a, "prefix_") == rs_strv_find_prefix(a, "prefix_"));
        assert_se(streq(strv_find_prefix(a, "prefix_"), "prefix_foo"));
}

TEST(strv_find_prefix_not_found) {
        char *a[] = { (char*)"prefix_foo", (char*)"bar_baz", NULL };
        assert_se(strv_find_prefix(a, "xyz") == rs_strv_find_prefix(a, "xyz"));
        assert_se(strv_find_prefix(a, "xyz") == NULL);
}

/* ── strv_find_startswith ────────────────────────────────────────────────── */

TEST(strv_find_startswith_found) {
        char *a[] = { (char*)"prefix_foo", (char*)"bar_baz", NULL };
        const char *cr = strv_find_startswith(a, "prefix_");
        const char *rr = rs_strv_find_startswith(a, "prefix_");
        assert_se(streq(cr, rr));
        assert_se(streq(cr, "foo"));
}

TEST(strv_find_startswith_not_found) {
        char *a[] = { (char*)"prefix_foo", (char*)"bar_baz", NULL };
        assert_se(strv_find_startswith(a, "xyz") == rs_strv_find_startswith(a, "xyz"));
        assert_se(strv_find_startswith(a, "xyz") == NULL);
}

/* RUST-CONTRACT: strv-uniqueness-and-compare */
/* ── strv_is_uniq ────────────────────────────────────────────────────────── */

TEST(strv_is_uniq_yes) {
        char *a[] = { (char*)"a", (char*)"b", (char*)"c", NULL };
        assert_se(strv_is_uniq(a) == rs_strv_is_uniq(a));
        assert_se(strv_is_uniq(a) == true);
}

TEST(strv_is_uniq_no) {
        char *a[] = { (char*)"a", (char*)"b", (char*)"a", NULL };
        assert_se(strv_is_uniq(a) == rs_strv_is_uniq(a));
        assert_se(strv_is_uniq(a) == false);
}

TEST(strv_is_uniq_empty) {
        assert_se(strv_is_uniq(NULL) == rs_strv_is_uniq(NULL));
        assert_se(strv_is_uniq(NULL) == true);
}

/* ── strv_overlap ────────────────────────────────────────────────────────── */

TEST(strv_overlap_yes) {
        char *a[] = { (char*)"a", (char*)"b", (char*)"c", NULL };
        char *b[] = { (char*)"x", (char*)"b", (char*)"y", NULL };
        assert_se(strv_overlap(a, b) == rs_strv_overlap(a, b));
        assert_se(strv_overlap(a, b) == true);
}

TEST(strv_overlap_no) {
        char *a[] = { (char*)"a", (char*)"b", NULL };
        char *b[] = { (char*)"x", (char*)"y", NULL };
        assert_se(strv_overlap(a, b) == rs_strv_overlap(a, b));
        assert_se(strv_overlap(a, b) == false);
}

TEST(strv_overlap_null) {
        assert_se(strv_overlap(NULL, NULL) == rs_strv_overlap(NULL, NULL));
        assert_se(strv_overlap(NULL, NULL) == false);
}

/* ── strv_compare ────────────────────────────────────────────────────────── */

TEST(strv_compare_equal) {
        char *a[] = { (char*)"a", (char*)"b", NULL };
        char *b[] = { (char*)"a", (char*)"b", NULL };
        assert_se(strv_compare(a, b) == rs_strv_compare(a, b));
        assert_se(strv_compare(a, b) == 0);
}

TEST(strv_compare_less) {
        char *a[] = { (char*)"a", NULL };
        char *b[] = { (char*)"a", (char*)"b", NULL };
        assert_se(strv_compare(a, b) == rs_strv_compare(a, b));
        assert_se(strv_compare(a, b) < 0);
}

TEST(strv_compare_both_empty) {
        assert_se(strv_compare(NULL, NULL) == rs_strv_compare(NULL, NULL));
        assert_se(strv_compare(NULL, NULL) == 0);
}

TEST(strv_compare_one_empty) {
        char *a[] = { (char*)"x", NULL };
        assert_se(strv_compare(NULL, a) == rs_strv_compare(NULL, a));
        assert_se(strv_compare(NULL, a) < 0);
}

/* ── strv_equal_ignore_order ─────────────────────────────────────────────── */

TEST(strv_equal_ignore_order_yes) {
        char *a[] = { (char*)"a", (char*)"b", (char*)"c", NULL };
        char *b[] = { (char*)"c", (char*)"a", (char*)"b", NULL };
        assert_se(strv_equal_ignore_order(a, b) == rs_strv_equal_ignore_order(a, b));
        assert_se(strv_equal_ignore_order(a, b) == true);
}

TEST(strv_equal_ignore_order_no) {
        char *a[] = { (char*)"a", (char*)"b", NULL };
        char *b[] = { (char*)"a", (char*)"c", NULL };
        assert_se(strv_equal_ignore_order(a, b) == rs_strv_equal_ignore_order(a, b));
        assert_se(strv_equal_ignore_order(a, b) == false);
}

TEST(strv_equal_ignore_order_same_ptr) {
        char *a[] = { (char*)"a", (char*)"b", NULL };
        assert_se(strv_equal_ignore_order(a, a) == rs_strv_equal_ignore_order(a, a));
        assert_se(strv_equal_ignore_order(a, a) == true);
}

/* RUST-CONTRACT: strv-copy-n */
/* ── strv_copy_n ─────────────────────────────────────────────────────────── */

TEST(strv_copy_n_all) {
        char *a[] = { (char*)"hello", (char*)"world", NULL };
        char **cr = strv_copy_n(a, SIZE_MAX);
        char **rr = rs_strv_copy_n(a, SIZE_MAX);
        assert_se(cr != NULL && rr != NULL);
        assert_se(strv_equal(cr, rr));
        strv_free(cr);
        strv_free(rr);
}

TEST(strv_copy_n_limited) {
        char *a[] = { (char*)"hello", (char*)"world", (char*)"foo", NULL };
        char **cr = strv_copy_n(a, 2);
        char **rr = rs_strv_copy_n(a, 2);
        assert_se(cr != NULL && rr != NULL);
        assert_se(strv_length(cr) == strv_length(rr));
        assert_se(strv_length(cr) == 2);
        assert_se(streq(cr[0], "hello") && streq(rr[0], "hello"));
        assert_se(streq(cr[1], "world") && streq(rr[1], "world"));
        strv_free(cr);
        strv_free(rr);
}

TEST(strv_copy_n_zero) {
        char *a[] = { (char*)"hello", (char*)"world", NULL };
        char **cr = strv_copy_n(a, 0);
        char **rr = rs_strv_copy_n(a, 0);
        assert_se(cr != NULL && rr != NULL);
        assert_se(strv_isempty(cr) && strv_isempty(rr));
        strv_free(cr);
        strv_free(rr);
}

TEST(strv_copy_n_null) {
        char **cr = strv_copy_n(NULL, 3);
        char **rr = rs_strv_copy_n(NULL, 3);
        assert_se(cr != NULL && rr != NULL);
        assert_se(strv_isempty(cr) && strv_isempty(rr));
        strv_free(cr);
        strv_free(rr);
}

/* RUST-CONTRACT: strv-in-place-mutation */
/* ── strv_remove ─────────────────────────────────────────────────────────── */

TEST(strv_remove_found) {
        char *c_arr[] = { strdup("a"), strdup("b"), strdup("c"), NULL };
        char *rs_arr[] = { strdup("a"), strdup("b"), strdup("c"), NULL };

        strv_remove(c_arr, "b");
        rs_strv_remove(rs_arr, "b");

        assert_se(strv_length(c_arr) == strv_length(rs_arr));
        assert_se(strv_length(c_arr) == 2);
        assert_se(streq(c_arr[0], "a") && streq(rs_arr[0], "a"));
        assert_se(streq(c_arr[1], "c") && streq(rs_arr[1], "c"));

        /* strv_remove freed "b"; free remaining entries (stack array, no strv_free) */
        for (char **p = c_arr; *p; p++) free(*p);
        for (char **p = rs_arr; *p; p++) free(*p);
}

TEST(strv_remove_not_found) {
        char *c_arr[] = { strdup("a"), strdup("b"), NULL };
        char *rs_arr[] = { strdup("a"), strdup("b"), NULL };

        strv_remove(c_arr, "z");
        rs_strv_remove(rs_arr, "z");

        assert_se(strv_length(c_arr) == strv_length(rs_arr));
        assert_se(strv_length(c_arr) == 2);

        for (char **p = c_arr; *p; p++) free(*p);
        for (char **p = rs_arr; *p; p++) free(*p);
}

TEST(strv_remove_multiple) {
        char *c_arr[] = { strdup("a"), strdup("b"), strdup("a"), strdup("b"), NULL };
        char *rs_arr[] = { strdup("a"), strdup("b"), strdup("a"), strdup("b"), NULL };

        strv_remove(c_arr, "a");
        rs_strv_remove(rs_arr, "a");

        assert_se(strv_length(c_arr) == strv_length(rs_arr));
        assert_se(strv_length(c_arr) == 2);
        assert_se(streq(c_arr[0], "b") && streq(rs_arr[0], "b"));

        for (char **p = c_arr; *p; p++) free(*p);
        for (char **p = rs_arr; *p; p++) free(*p);
}

/* ── strv_uniq ───────────────────────────────────────────────────────────── */

TEST(strv_uniq_already) {
        char *c_arr[] = { strdup("a"), strdup("b"), strdup("c"), NULL };
        char *rs_arr[] = { strdup("a"), strdup("b"), strdup("c"), NULL };

        strv_uniq(c_arr);
        rs_strv_uniq(rs_arr);

        assert_se(strv_length(c_arr) == strv_length(rs_arr));
        assert_se(strv_length(c_arr) == 3);

        for (char **p = c_arr; *p; p++) free(*p);
        for (char **p = rs_arr; *p; p++) free(*p);
}

TEST(strv_uniq_dups) {
        char *c_arr[] = { strdup("a"), strdup("b"), strdup("a"), strdup("c"), strdup("b"), NULL };
        char *rs_arr[] = { strdup("a"), strdup("b"), strdup("a"), strdup("c"), strdup("b"), NULL };

        strv_uniq(c_arr);
        rs_strv_uniq(rs_arr);

        assert_se(strv_length(c_arr) == strv_length(rs_arr));
        assert_se(strv_length(c_arr) == 3);
        assert_se(streq(c_arr[0], "a") && streq(rs_arr[0], "a"));
        assert_se(streq(c_arr[1], "b") && streq(rs_arr[1], "b"));
        assert_se(streq(c_arr[2], "c") && streq(rs_arr[2], "c"));

        for (char **p = c_arr; *p; p++) free(*p);
        for (char **p = rs_arr; *p; p++) free(*p);
}

/* ── strv_sort ───────────────────────────────────────────────────────────── */

TEST(strv_sort_normal) {
        char *c_arr[] = { strdup("c"), strdup("a"), strdup("b"), NULL };
        char *rs_arr[] = { strdup("c"), strdup("a"), strdup("b"), NULL };

        strv_sort(c_arr);
        rs_strv_sort(rs_arr);

        assert_se(streq(c_arr[0], "a") && streq(rs_arr[0], "a"));
        assert_se(streq(c_arr[1], "b") && streq(rs_arr[1], "b"));
        assert_se(streq(c_arr[2], "c") && streq(rs_arr[2], "c"));

        for (char **p = c_arr; *p; p++) free(*p);
        for (char **p = rs_arr; *p; p++) free(*p);
}

TEST(strv_sort_empty) {
        assert_se(strv_sort(NULL) == rs_strv_sort(NULL));
        assert_se(strv_sort(NULL) == NULL);
}

/* ── strv_reverse ────────────────────────────────────────────────────────── */

TEST(strv_reverse_normal) {
        char *c_arr[] = { strdup("a"), strdup("b"), strdup("c"), NULL };
        char *rs_arr[] = { strdup("a"), strdup("b"), strdup("c"), NULL };

        strv_reverse(c_arr);
        rs_strv_reverse(rs_arr);

        assert_se(streq(c_arr[0], "c") && streq(rs_arr[0], "c"));
        assert_se(streq(c_arr[1], "b") && streq(rs_arr[1], "b"));
        assert_se(streq(c_arr[2], "a") && streq(rs_arr[2], "a"));

        for (char **p = c_arr; *p; p++) free(*p);
        for (char **p = rs_arr; *p; p++) free(*p);
}

TEST(strv_reverse_empty) {
        assert_se(strv_reverse(NULL) == rs_strv_reverse(NULL));
        assert_se(strv_reverse(NULL) == NULL);
}

/* ── strv_skip ───────────────────────────────────────────────────────────── */

TEST(strv_skip_normal) {
        char *a[] = { (char*)"a", (char*)"b", (char*)"c", NULL };
        char **cr = strv_skip(a, 1);
        char **rr = rs_strv_skip(a, 1);
        assert_se(cr != NULL && rr != NULL);
        assert_se(streq(*cr, *rr));
        assert_se(streq(*cr, "b"));
}

TEST(strv_skip_too_many) {
        char *a[] = { (char*)"a", (char*)"b", NULL };
        assert_se(strv_skip(a, 5) == rs_strv_skip(a, 5));
        assert_se(strv_skip(a, 5) == NULL);
}

TEST(strv_skip_exact) {
        char *a[] = { (char*)"a", (char*)"b", NULL };
        assert_se(strv_skip(a, 2) == rs_strv_skip(a, 2));
        assert_se(strv_skip(a, 2) == NULL);
}

/* ── main ────────────────────────────────────────────────────────────────── */

DEFINE_TEST_MAIN(LOG_INFO);
