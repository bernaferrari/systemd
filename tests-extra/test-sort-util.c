/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "sort-util.h"
#include "tests.h"

static int cmp_int_ptr(const void *a, const void *b) {
        return CMP(*(const int*)a, *(const int*)b);
}

static int cmp_int_typed(const int *a, const int *b) {
        return CMP(*a, *b);
}

TEST(qsort_safe_basic) {
        int arr[] = { 5, 3, 1, 4, 2 };
        qsort_safe(arr, 5, sizeof(int), cmp_int_ptr);
        ASSERT_EQ(arr[0], 1);
        ASSERT_EQ(arr[1], 2);
        ASSERT_EQ(arr[2], 3);
        ASSERT_EQ(arr[3], 4);
        ASSERT_EQ(arr[4], 5);
}

TEST(qsort_safe_single) {
        int arr[] = { 42 };
        qsort_safe(arr, 1, sizeof(int), cmp_int_ptr);
        ASSERT_EQ(arr[0], 42);
}

TEST(qsort_safe_empty) {
        int *arr = NULL;
        /* Should be a no-op */
        qsort_safe(arr, 0, sizeof(int), cmp_int_ptr);
}

TEST(qsort_safe_already_sorted) {
        int arr[] = { 1, 2, 3, 4, 5 };
        qsort_safe(arr, 5, sizeof(int), cmp_int_ptr);
        ASSERT_EQ(arr[0], 1);
        ASSERT_EQ(arr[4], 5);
}

TEST(qsort_safe_reverse) {
        int arr[] = { 5, 4, 3, 2, 1 };
        qsort_safe(arr, 5, sizeof(int), cmp_int_ptr);
        ASSERT_EQ(arr[0], 1);
        ASSERT_EQ(arr[4], 5);
}

TEST(qsort_safe_duplicates) {
        int arr[] = { 3, 1, 3, 2, 1 };
        qsort_safe(arr, 5, sizeof(int), cmp_int_ptr);
        ASSERT_EQ(arr[0], 1);
        ASSERT_EQ(arr[1], 1);
        ASSERT_EQ(arr[2], 2);
        ASSERT_EQ(arr[3], 3);
        ASSERT_EQ(arr[4], 3);
}

static int cmp_int_with_userdata(const int *a, const int *b, void *userdata) {
        /* Allow reversing via userdata */
        int reverse = *(int*)userdata;
        if (reverse)
                return CMP(*b, *a);
        return CMP(*a, *b);
}

TEST(qsort_r_safe_basic) {
        int arr[] = { 5, 3, 1, 4, 2 };
        int reverse = 0;
        qsort_r_safe(arr, 5, sizeof(int), (comparison_userdata_fn_t)cmp_int_with_userdata, &reverse);
        ASSERT_EQ(arr[0], 1);
        ASSERT_EQ(arr[4], 5);
}

TEST(qsort_r_safe_reverse) {
        int arr[] = { 5, 3, 1, 4, 2 };
        int reverse = 1;
        qsort_r_safe(arr, 5, sizeof(int), (comparison_userdata_fn_t)cmp_int_with_userdata, &reverse);
        ASSERT_EQ(arr[0], 5);
        ASSERT_EQ(arr[4], 1);
}

TEST(cmp_int) {
        int a = 1, b = 2;
        ASSERT_LT(cmp_int(&a, &b), 0);
        ASSERT_GT(cmp_int(&b, &a), 0);
        ASSERT_EQ(cmp_int(&a, &a), 0);
}

TEST(cmp_uint16) {
        uint16_t a = 1, b = 2;
        ASSERT_LT(cmp_uint16(&a, &b), 0);
        ASSERT_GT(cmp_uint16(&b, &a), 0);
        ASSERT_EQ(cmp_uint16(&a, &a), 0);
}

static int cmp_int_search(const int *key, const int *elem, void *userdata) {
        return CMP(*key, *elem);
}

TEST(xbsearch_r_found) {
        int arr[] = { 10, 20, 30, 40, 50 };
        int key = 30;
        int *result = typesafe_bsearch_r(&key, arr, 5, cmp_int_search, NULL);
        ASSERT_NOT_NULL(result);
        ASSERT_EQ(*result, 30);
}

TEST(xbsearch_r_not_found) {
        int arr[] = { 10, 20, 30, 40, 50 };
        int key = 25;
        int *result = typesafe_bsearch_r(&key, arr, 5, cmp_int_search, NULL);
        ASSERT_NULL(result);
}

TEST(xbsearch_r_empty) {
        int key = 1;
        int *result = typesafe_bsearch_r(&key, (int[]){}, 0, cmp_int_search, NULL);
        ASSERT_NULL(result);
}

TEST(bsearch_safe_found) {
        int arr[] = { 10, 20, 30, 40, 50 };
        int key = 20;
        int *result = typesafe_bsearch(&key, arr, 5, cmp_int_typed);
        ASSERT_NOT_NULL(result);
        ASSERT_EQ(*result, 20);
}

TEST(bsearch_safe_not_found) {
        int arr[] = { 10, 20, 30, 40, 50 };
        int key = 99;
        int *result = typesafe_bsearch(&key, arr, 5, cmp_int_typed);
        ASSERT_NULL(result);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
