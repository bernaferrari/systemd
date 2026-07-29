/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Shadow test: verify Rust sort-util port matches C behavior exactly.
 * This test links against both the C (via libshared) and Rust (via
 * libsystemd_basic_rs.a) implementations and compares outputs for
 * every ported function.
 */

#include <stdlib.h>
#include <string.h>

#include "sort-util.h"
#include "rust/sort_util.h"
#include "tests.h"

/* ── cmp_int / cmp_uint16 ─────────────────────────────────────────────── */
/* RUST-CONTRACT: sort-comparators */

TEST(cmp_int_c_vs_rs) {
        int a = 1, b = 2;
        ASSERT_EQ(cmp_int(&a, &b), rs_cmp_int(&a, &b));
        ASSERT_EQ(cmp_int(&b, &a), rs_cmp_int(&b, &a));
        ASSERT_EQ(cmp_int(&a, &a), rs_cmp_int(&a, &a));

        /* Edge: INT_MIN vs INT_MAX */
        int lo = INT_MIN, hi = INT_MAX;
        ASSERT_EQ(cmp_int(&lo, &hi), rs_cmp_int(&lo, &hi));
        ASSERT_EQ(cmp_int(&hi, &lo), rs_cmp_int(&hi, &lo));
}

TEST(cmp_uint16_c_vs_rs) {
        uint16_t a = 1, b = 2;
        ASSERT_EQ(cmp_uint16(&a, &b), rs_cmp_uint16(&a, &b));
        ASSERT_EQ(cmp_uint16(&b, &a), rs_cmp_uint16(&b, &a));
        ASSERT_EQ(cmp_uint16(&a, &a), rs_cmp_uint16(&a, &a));

        /* Edge: 0 vs UINT16_MAX */
        uint16_t lo = 0, hi = UINT16_MAX;
        ASSERT_EQ(cmp_uint16(&lo, &hi), rs_cmp_uint16(&lo, &hi));
        ASSERT_EQ(cmp_uint16(&hi, &lo), rs_cmp_uint16(&hi, &lo));
}

/* ── qsort_safe ───────────────────────────────────────────────────────── */
/* RUST-CONTRACT: sort-qsort-safe */

static int cmp_int_ptr(const void *a, const void *b) {
        int va = *(const int*)a, vb = *(const int*)b;
        return (va < vb) ? -1 : (va > vb) ? 1 : 0;
}

TEST(qsort_safe_basic_c_vs_rs) {
        int c_arr[] = { 5, 3, 1, 4, 2 };
        int rs_arr[] = { 5, 3, 1, 4, 2 };

        qsort_safe(c_arr, 5, sizeof(int), cmp_int_ptr);
        rs_qsort_safe(rs_arr, 5, sizeof(int), cmp_int_ptr);

        ASSERT_EQ(memcmp(c_arr, rs_arr, sizeof(c_arr)), 0);
        ASSERT_EQ(rs_arr[0], 1);
        ASSERT_EQ(rs_arr[4], 5);
}

TEST(qsort_safe_duplicates_c_vs_rs) {
        int c_arr[] = { 3, 1, 3, 2, 1 };
        int rs_arr[] = { 3, 1, 3, 2, 1 };

        qsort_safe(c_arr, 5, sizeof(int), cmp_int_ptr);
        rs_qsort_safe(rs_arr, 5, sizeof(int), cmp_int_ptr);

        ASSERT_EQ(memcmp(c_arr, rs_arr, sizeof(c_arr)), 0);
}

TEST(qsort_safe_empty_c_vs_rs) {
        /* Both should be no-ops with NULL base */
        qsort_safe(NULL, 0, sizeof(int), cmp_int_ptr);
        rs_qsort_safe(NULL, 0, sizeof(int), cmp_int_ptr);
}

TEST(qsort_safe_single_c_vs_rs) {
        int c_arr[] = { 42 };
        int rs_arr[] = { 42 };

        qsort_safe(c_arr, 1, sizeof(int), cmp_int_ptr);
        rs_qsort_safe(rs_arr, 1, sizeof(int), cmp_int_ptr);

        ASSERT_EQ(c_arr[0], rs_arr[0]);
}

TEST(qsort_safe_large_c_vs_rs) {
        /* 100 elements */
        int c_arr[100], rs_arr[100];
        for (int i = 0; i < 100; i++) {
                c_arr[i] = 99 - i;
                rs_arr[i] = 99 - i;
        }

        qsort_safe(c_arr, 100, sizeof(int), cmp_int_ptr);
        rs_qsort_safe(rs_arr, 100, sizeof(int), cmp_int_ptr);

        ASSERT_EQ(memcmp(c_arr, rs_arr, sizeof(c_arr)), 0);
        for (int i = 0; i < 100; i++)
                ASSERT_EQ(rs_arr[i], i);
}

/* ── qsort_r_safe ─────────────────────────────────────────────────────── */
/* RUST-CONTRACT: sort-qsort-r-safe */

static int cmp_int_userdata(const int *a, const int *b, void *userdata) {
        int reverse = *(int*)userdata;
        if (reverse)
                return (*b < *a) ? -1 : (*b > *a) ? 1 : 0;
        return (*a < *b) ? -1 : (*a > *b) ? 1 : 0;
}

TEST(qsort_r_safe_basic_c_vs_rs) {
        int c_arr[] = { 5, 3, 1, 4, 2 };
        int rs_arr[] = { 5, 3, 1, 4, 2 };
        int reverse = 0;

        qsort_r_safe(c_arr, 5, sizeof(int), (comparison_userdata_fn_t)cmp_int_userdata, &reverse);
        rs_qsort_r_safe(rs_arr, 5, sizeof(int), (comparison_userdata_fn_t)cmp_int_userdata, &reverse);

        ASSERT_EQ(memcmp(c_arr, rs_arr, sizeof(c_arr)), 0);
}

TEST(qsort_r_safe_reverse_c_vs_rs) {
        int c_arr[] = { 5, 3, 1, 4, 2 };
        int rs_arr[] = { 5, 3, 1, 4, 2 };
        int reverse = 1;

        qsort_r_safe(c_arr, 5, sizeof(int), (comparison_userdata_fn_t)cmp_int_userdata, &reverse);
        rs_qsort_r_safe(rs_arr, 5, sizeof(int), (comparison_userdata_fn_t)cmp_int_userdata, &reverse);

        ASSERT_EQ(memcmp(c_arr, rs_arr, sizeof(c_arr)), 0);
        ASSERT_EQ(rs_arr[0], 5);
        ASSERT_EQ(rs_arr[4], 1);
}

/* ── xbsearch_r ───────────────────────────────────────────────────────── */
/* RUST-CONTRACT: sort-xbsearch-r */

static int cmp_int_search(const int *key, const int *elem, void *userdata) {
        return (*key < *elem) ? -1 : (*key > *elem) ? 1 : 0;
}

TEST(xbsearch_r_found_c_vs_rs) {
        int arr[] = { 10, 20, 30, 40, 50 };
        int key = 30;

        int *c_result = xbsearch_r(&key, arr, 5, sizeof(int), (comparison_userdata_fn_t) cmp_int_search, NULL);
        int *rs_result = (int*)rs_xbsearch_r(&key, arr, 5, sizeof(int), (comparison_userdata_fn_t)cmp_int_search, NULL);

        if (c_result)
                ASSERT_NOT_NULL(rs_result);
        else
                ASSERT_NULL(rs_result);

        if (c_result && rs_result)
                ASSERT_EQ(*c_result, *rs_result);
}

TEST(xbsearch_r_not_found_c_vs_rs) {
        int arr[] = { 10, 20, 30, 40, 50 };
        int key = 25;

        int *c_result = xbsearch_r(&key, arr, 5, sizeof(int), (comparison_userdata_fn_t) cmp_int_search, NULL);
        int *rs_result = (int*)rs_xbsearch_r(&key, arr, 5, sizeof(int), (comparison_userdata_fn_t)cmp_int_search, NULL);

        ASSERT_NULL(c_result);
        ASSERT_NULL(rs_result);
}

TEST(xbsearch_r_first_c_vs_rs) {
        int arr[] = { 10, 20, 30, 40, 50 };
        int key = 10;

        int *c_result = xbsearch_r(&key, arr, 5, sizeof(int), (comparison_userdata_fn_t) cmp_int_search, NULL);
        int *rs_result = (int*)rs_xbsearch_r(&key, arr, 5, sizeof(int), (comparison_userdata_fn_t)cmp_int_search, NULL);

        ASSERT_NOT_NULL(c_result);
        ASSERT_NOT_NULL(rs_result);
        ASSERT_EQ(*c_result, *rs_result);
}

TEST(xbsearch_r_last_c_vs_rs) {
        int arr[] = { 10, 20, 30, 40, 50 };
        int key = 50;

        int *c_result = xbsearch_r(&key, arr, 5, sizeof(int), (comparison_userdata_fn_t) cmp_int_search, NULL);
        int *rs_result = (int*)rs_xbsearch_r(&key, arr, 5, sizeof(int), (comparison_userdata_fn_t)cmp_int_search, NULL);

        ASSERT_NOT_NULL(c_result);
        ASSERT_NOT_NULL(rs_result);
        ASSERT_EQ(*c_result, *rs_result);
}

TEST(xbsearch_r_empty_c_vs_rs) {
        int key = 1;
        int *c_result = xbsearch_r(&key, (int[]){}, 0, sizeof(int), (comparison_userdata_fn_t) cmp_int_search, NULL);
        int *rs_result = (int*)rs_xbsearch_r(&key, (int[]){}, 0, sizeof(int), (comparison_userdata_fn_t)cmp_int_search, NULL);

        ASSERT_NULL(c_result);
        ASSERT_NULL(rs_result);
}

TEST(xbsearch_r_large_c_vs_rs) {
        /* Search every element in a 100-element sorted array */
        int arr[100];
        for (int i = 0; i < 100; i++)
                arr[i] = i * 2;

        for (int i = 0; i < 100; i++) {
                int key = i * 2;
                int *c_result = xbsearch_r(&key, arr, 100, sizeof(int), (comparison_userdata_fn_t) cmp_int_search, NULL);
                int *rs_result = (int*)rs_xbsearch_r(&key, arr, 100, sizeof(int), (comparison_userdata_fn_t)cmp_int_search, NULL);

                ASSERT_NOT_NULL(c_result);
                ASSERT_NOT_NULL(rs_result);
                ASSERT_EQ(*c_result, *rs_result);
        }

        /* Not found cases */
        for (int key = 1; key < 200; key += 2) {
                int *c_result = xbsearch_r(&key, arr, 100, sizeof(int), (comparison_userdata_fn_t) cmp_int_search, NULL);
                int *rs_result = (int*)rs_xbsearch_r(&key, arr, 100, sizeof(int), (comparison_userdata_fn_t)cmp_int_search, NULL);

                ASSERT_NULL(c_result);
                ASSERT_NULL(rs_result);
        }
}

/* ── bsearch_safe ─────────────────────────────────────────────────────── */
/* RUST-CONTRACT: sort-bsearch-safe */

static int cmp_int_bsearch_typed(const int *a, const int *b) {
        return (*a < *b) ? -1 : (*a > *b) ? 1 : 0;
}

TEST(bsearch_safe_found_c_vs_rs) {
        int arr[] = { 10, 20, 30, 40, 50 };
        int key = 20;

        int *c_result = bsearch_safe_internal(&key, arr, 5, sizeof(int), (comparison_fn_t) cmp_int_bsearch_typed);
        int *rs_result = (int*)rs_bsearch_safe_internal(&key, arr, 5, sizeof(int), (comparison_fn_t)cmp_int_bsearch_typed);

        ASSERT_NOT_NULL(c_result);
        ASSERT_NOT_NULL(rs_result);
        ASSERT_EQ(*c_result, *rs_result);
}

TEST(bsearch_safe_not_found_c_vs_rs) {
        int arr[] = { 10, 20, 30, 40, 50 };
        int key = 99;

        int *c_result = bsearch_safe_internal(&key, arr, 5, sizeof(int), (comparison_fn_t) cmp_int_bsearch_typed);
        int *rs_result = (int*)rs_bsearch_safe_internal(&key, arr, 5, sizeof(int), (comparison_fn_t)cmp_int_bsearch_typed);

        ASSERT_NULL(c_result);
        ASSERT_NULL(rs_result);
}

TEST(bsearch_safe_empty_c_vs_rs) {
        int key = 42;
        int *c_result = bsearch_safe_internal(&key, (int[]){}, 0, sizeof(int), (comparison_fn_t) cmp_int_bsearch_typed);
        int *rs_result = (int*)rs_bsearch_safe_internal(&key, (int[]){}, 0, sizeof(int), (comparison_fn_t)cmp_int_bsearch_typed);

        ASSERT_NULL(c_result);
        ASSERT_NULL(rs_result);
}

DEFINE_TEST_MAIN(LOG_INFO);
