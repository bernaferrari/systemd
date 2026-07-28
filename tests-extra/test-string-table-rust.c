/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Shadow test: verify Rust string-table port matches C behavior exactly.
 * This test links against both the C (via libshared) and Rust (via
 * libsystemd_basic_rs.a) implementations and compares outputs for
 * every ported function.
 */

#include <stdlib.h>

#include "string-table.h"
#include "rust/string_table.h"
#include "tests.h"

/* RUST-CONTRACT: string-table-to-string */
/* RUST-CONTRACT: string-table-from-string */
/* RUST-CONTRACT: string-table-from-string-with-boolean */
/* RUST-CONTRACT: string-table-to-string-fallback */
/* RUST-CONTRACT: string-table-from-string-fallback */

/* ── Test table ───────────────────────────────────────────────────────── */

static const char *const test_table[] = {
        "zero",
        "one",
        "two",
        "three",
        "four",
};

#define TEST_TABLE_LEN ELEMENTSOF(test_table)

/* ── lookup_to_string ─────────────────────────────────────────────────── */

TEST(lookup_to_string_valid_c_vs_rs) {
        for (size_t i = 0; i < TEST_TABLE_LEN; i++) {
                const char *c_str = string_table_lookup_to_string(test_table, TEST_TABLE_LEN, i);
                const char *rs_str = rs_string_table_lookup_to_string(test_table, TEST_TABLE_LEN, i);

                ASSERT_NOT_NULL(c_str);
                ASSERT_NOT_NULL(rs_str);
                ASSERT_STREQ(c_str, rs_str);
        }
}

TEST(lookup_to_string_out_of_range_c_vs_rs) {
        ASSERT_NULL(string_table_lookup_to_string(test_table, TEST_TABLE_LEN, -1));
        ASSERT_NULL(rs_string_table_lookup_to_string(test_table, TEST_TABLE_LEN, -1));

        ASSERT_NULL(string_table_lookup_to_string(test_table, TEST_TABLE_LEN, TEST_TABLE_LEN));
        ASSERT_NULL(rs_string_table_lookup_to_string(test_table, TEST_TABLE_LEN, TEST_TABLE_LEN));

        ASSERT_NULL(string_table_lookup_to_string(test_table, TEST_TABLE_LEN, TEST_TABLE_LEN + 1));
        ASSERT_NULL(rs_string_table_lookup_to_string(test_table, TEST_TABLE_LEN, TEST_TABLE_LEN + 1));
}

/* ── lookup_from_string ───────────────────────────────────────────────── */

TEST(lookup_from_string_valid_c_vs_rs) {
        for (size_t i = 0; i < TEST_TABLE_LEN; i++) {
                ssize_t c_ret = string_table_lookup_from_string(test_table, TEST_TABLE_LEN, test_table[i]);
                ssize_t rs_ret = rs_string_table_lookup_from_string(test_table, TEST_TABLE_LEN, test_table[i]);

                ASSERT_EQ(c_ret, rs_ret);
                ASSERT_GE(c_ret, 0);
                ASSERT_EQ((size_t)c_ret, i);
        }
}

TEST(lookup_from_string_not_found_c_vs_rs) {
        ssize_t c_ret = string_table_lookup_from_string(test_table, TEST_TABLE_LEN, "nonexistent");
        ssize_t rs_ret = rs_string_table_lookup_from_string(test_table, TEST_TABLE_LEN, "nonexistent");

        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_LT(c_ret, 0);
}

TEST(lookup_from_string_null_c_vs_rs) {
        ssize_t c_ret = string_table_lookup_from_string(test_table, TEST_TABLE_LEN, NULL);
        ssize_t rs_ret = rs_string_table_lookup_from_string(test_table, TEST_TABLE_LEN, NULL);

        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_LT(c_ret, 0);
}

/* ── lookup_from_string_with_boolean ──────────────────────────────────── */

TEST(lookup_from_string_with_boolean_true_c_vs_rs) {
        /* "yes" should map to yes=3 */
        ssize_t c_ret = string_table_lookup_from_string_with_boolean(test_table, TEST_TABLE_LEN, "yes", 3);
        ssize_t rs_ret = rs_string_table_lookup_from_string_with_boolean(test_table, TEST_TABLE_LEN, "yes", 3);

        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_EQ(c_ret, 3);
}

TEST(lookup_from_string_with_boolean_false_c_vs_rs) {
        /* "no" should map to 0 */
        ssize_t c_ret = string_table_lookup_from_string_with_boolean(test_table, TEST_TABLE_LEN, "no", 3);
        ssize_t rs_ret = rs_string_table_lookup_from_string_with_boolean(test_table, TEST_TABLE_LEN, "no", 3);

        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_EQ(c_ret, 0);
}

TEST(lookup_from_string_with_boolean_name_c_vs_rs) {
        /* "two" should find index 2 */
        ssize_t c_ret = string_table_lookup_from_string_with_boolean(test_table, TEST_TABLE_LEN, "two", 3);
        ssize_t rs_ret = rs_string_table_lookup_from_string_with_boolean(test_table, TEST_TABLE_LEN, "two", 3);

        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_EQ(c_ret, 2);
}

TEST(lookup_from_string_with_boolean_null_c_vs_rs) {
        ssize_t c_ret = string_table_lookup_from_string_with_boolean(test_table, TEST_TABLE_LEN, NULL, 3);
        ssize_t rs_ret = rs_string_table_lookup_from_string_with_boolean(test_table, TEST_TABLE_LEN, NULL, 3);

        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_LT(c_ret, 0);
}

/* ── lookup_to_string_fallback ────────────────────────────────────────── */

TEST(lookup_to_string_fallback_valid_c_vs_rs) {
        _cleanup_free_ char *c_str = NULL;
        _cleanup_free_ char *rs_str = NULL;

        int c_ret = string_table_lookup_to_string_fallback(test_table, TEST_TABLE_LEN, 1, 100, &c_str);
        int rs_ret = rs_string_table_lookup_to_string_fallback(test_table, TEST_TABLE_LEN, 1, 100, &rs_str);

        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_GE(c_ret, 0);
        ASSERT_STREQ(c_str, rs_str);
        ASSERT_STREQ(c_str, "one");
}

TEST(lookup_to_string_fallback_numeric_c_vs_rs) {
        _cleanup_free_ char *c_str = NULL;
        _cleanup_free_ char *rs_str = NULL;

        /* Index beyond table — should return "5" */
        int c_ret = string_table_lookup_to_string_fallback(test_table, TEST_TABLE_LEN, 5, 100, &c_str);
        int rs_ret = rs_string_table_lookup_to_string_fallback(test_table, TEST_TABLE_LEN, 5, 100, &rs_str);

        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_GE(c_ret, 0);
        ASSERT_STREQ(c_str, rs_str);
        ASSERT_STREQ(c_str, "5");
}

TEST(lookup_to_string_fallback_out_of_range_c_vs_rs) {
        _cleanup_free_ char *c_str = NULL;
        _cleanup_free_ char *rs_str = NULL;

        /* Beyond max */
        int c_ret = string_table_lookup_to_string_fallback(test_table, TEST_TABLE_LEN, 101, 100, &c_str);
        int rs_ret = rs_string_table_lookup_to_string_fallback(test_table, TEST_TABLE_LEN, 101, 100, &rs_str);

        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_LT(c_ret, 0);
}

/* ── lookup_from_string_fallback ──────────────────────────────────────── */

TEST(lookup_from_string_fallback_name_c_vs_rs) {
        ssize_t c_ret = string_table_lookup_from_string_fallback(test_table, TEST_TABLE_LEN, "three", 100);
        ssize_t rs_ret = rs_string_table_lookup_from_string_fallback(test_table, TEST_TABLE_LEN, "three", 100);

        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_EQ(c_ret, 3);
}

TEST(lookup_from_string_fallback_numeric_c_vs_rs) {
        ssize_t c_ret = string_table_lookup_from_string_fallback(test_table, TEST_TABLE_LEN, "7", 100);
        ssize_t rs_ret = rs_string_table_lookup_from_string_fallback(test_table, TEST_TABLE_LEN, "7", 100);

        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_EQ(c_ret, 7);
}

TEST(lookup_from_string_fallback_numeric_overflow_c_vs_rs) {
        ssize_t c_ret = string_table_lookup_from_string_fallback(test_table, TEST_TABLE_LEN, "999", 10);
        ssize_t rs_ret = rs_string_table_lookup_from_string_fallback(test_table, TEST_TABLE_LEN, "999", 10);

        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_LT(c_ret, 0);
}

TEST(lookup_from_string_fallback_null_c_vs_rs) {
        ssize_t c_ret = string_table_lookup_from_string_fallback(test_table, TEST_TABLE_LEN, NULL, 100);
        ssize_t rs_ret = rs_string_table_lookup_from_string_fallback(test_table, TEST_TABLE_LEN, NULL, 100);

        ASSERT_EQ(c_ret, rs_ret);
        ASSERT_LT(c_ret, 0);
}

DEFINE_TEST_MAIN(LOG_INFO);
