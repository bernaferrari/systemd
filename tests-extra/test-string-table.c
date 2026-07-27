/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "string-table.h"
#include "string-util.h"
#include "tests.h"

static const char *const test_table[] = {
        "first",
        "second",
        "third",
        NULL,
};

static const char *const test_table_with_nulls[] = {
        "alpha",
        NULL,
        "gamma",
        "delta",
};

TEST(lookup_to_string_valid) {
        ASSERT_STREQ(string_table_lookup_to_string(test_table, 3, 0), "first");
        ASSERT_STREQ(string_table_lookup_to_string(test_table, 3, 1), "second");
        ASSERT_STREQ(string_table_lookup_to_string(test_table, 3, 2), "third");
}

TEST(lookup_to_string_out_of_range) {
        ASSERT_NULL(string_table_lookup_to_string(test_table, 3, -1));
        ASSERT_NULL(string_table_lookup_to_string(test_table, 3, 3));
        ASSERT_NULL(string_table_lookup_to_string(test_table, 3, 100));
}

TEST(lookup_from_string_valid) {
        ASSERT_EQ(string_table_lookup_from_string(test_table, 3, "first"), 0);
        ASSERT_EQ(string_table_lookup_from_string(test_table, 3, "second"), 1);
        ASSERT_EQ(string_table_lookup_from_string(test_table, 3, "third"), 2);
}

TEST(lookup_from_string_not_found) {
        ASSERT_EQ(string_table_lookup_from_string(test_table, 3, "nonexistent"), -EINVAL);
        ASSERT_EQ(string_table_lookup_from_string(test_table, 3, ""), -EINVAL);
        ASSERT_EQ(string_table_lookup_from_string(test_table, 3, NULL), -EINVAL);
}

TEST(lookup_from_string_with_boolean) {
        /* "first" is in the table at index 0 */
        ASSERT_EQ(string_table_lookup_from_string_with_boolean(test_table, 3, "first", 0), 0);
        /* Boolean true returns the "yes" index */
        ASSERT_EQ(string_table_lookup_from_string_with_boolean(test_table, 3, "yes", 1), 1);
        ASSERT_EQ(string_table_lookup_from_string_with_boolean(test_table, 3, "true", 1), 1);
        ASSERT_EQ(string_table_lookup_from_string_with_boolean(test_table, 3, "1", 1), 1);
        /* Boolean false returns 0 */
        ASSERT_EQ(string_table_lookup_from_string_with_boolean(test_table, 3, "no", 1), 0);
        ASSERT_EQ(string_table_lookup_from_string_with_boolean(test_table, 3, "false", 1), 0);
        ASSERT_EQ(string_table_lookup_from_string_with_boolean(test_table, 3, "0", 1), 0);
        /* NULL returns error */
        ASSERT_EQ(string_table_lookup_from_string_with_boolean(test_table, 3, NULL, 1), -EINVAL);
        /* Non-boolean string not in table returns error */
        ASSERT_EQ(string_table_lookup_from_string_with_boolean(test_table, 3, "nonexistent", 1), -EINVAL);
}

TEST(lookup_to_string_fallback) {
        _cleanup_free_ char *ret = NULL;

        /* Valid index with string */
        ASSERT_OK(string_table_lookup_to_string_fallback(test_table, 3, 0, 10, &ret));
        ASSERT_STREQ(ret, "first");

        ret = mfree(ret);

        /* Valid index with NULL entry */
        ASSERT_OK(string_table_lookup_to_string_fallback(test_table_with_nulls, 4, 1, 10, &ret));
        ASSERT_STREQ(ret, "1");

        ret = mfree(ret);

        /* Index beyond table but within max */
        ASSERT_OK(string_table_lookup_to_string_fallback(test_table, 3, 5, 10, &ret));
        ASSERT_STREQ(ret, "5");

        ret = mfree(ret);

        /* Out of range */
        ASSERT_EQ(string_table_lookup_to_string_fallback(test_table, 3, -1, 10, &ret), -ERANGE);
        ASSERT_EQ(string_table_lookup_to_string_fallback(test_table, 3, 11, 10, &ret), -ERANGE);
}

TEST(lookup_from_string_fallback) {
        /* Valid string */
        ASSERT_EQ(string_table_lookup_from_string_fallback(test_table, 3, "first", 10), 0);

        /* Numeric fallback */
        ASSERT_EQ(string_table_lookup_from_string_fallback(test_table, 3, "5", 10), 5);

        /* Numeric out of range */
        ASSERT_EQ(string_table_lookup_from_string_fallback(test_table, 3, "11", 10), -EINVAL);

        /* Invalid */
        ASSERT_EQ(string_table_lookup_from_string_fallback(test_table, 3, NULL, 10), -EINVAL);
        ASSERT_EQ(string_table_lookup_from_string_fallback(test_table, 3, "abc", 10), -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
