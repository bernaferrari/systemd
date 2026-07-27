/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "set.h"
#include "tests.h"

TEST(set_basics) {
        _cleanup_set_free_ Set *s = NULL;

        s = set_new(&string_hash_ops);
        ASSERT_NOT_NULL(s);
        ASSERT_TRUE(set_isempty(s));
        ASSERT_EQ(set_size(s), 0u);

        /* Put */
        ASSERT_OK(set_put(s, (void*)"foo"));
        ASSERT_EQ(set_size(s), 1u);
        ASSERT_FALSE(set_isempty(s));

        ASSERT_OK(set_put(s, (void*)"bar"));
        ASSERT_EQ(set_size(s), 2u);

        /* Duplicate put */
        ASSERT_OK(set_put(s, (void*)"foo"));
        ASSERT_EQ(set_size(s), 2u); /* still 2 */

        /* Contains */
        ASSERT_TRUE(set_contains(s, (void*)"foo"));
        ASSERT_TRUE(set_contains(s, (void*)"bar"));
        ASSERT_FALSE(set_contains(s, (void*)"baz"));

        /* Remove */
        ASSERT_TRUE(set_remove(s, (void*)"foo"));
        ASSERT_EQ(set_size(s), 1u);
        ASSERT_FALSE(set_contains(s, (void*)"foo"));
}

TEST(set_equal) {
        _cleanup_set_free_ Set *a = NULL, *b = NULL;

        a = set_new(&string_hash_ops);
        b = set_new(&string_hash_ops);
        ASSERT_NOT_NULL(a);
        ASSERT_NOT_NULL(b);

        /* Empty sets are equal */
        ASSERT_TRUE(set_equal(a, b));

        set_put(a, (void*)"foo");
        set_put(b, (void*)"foo");
        ASSERT_TRUE(set_equal(a, b));

        set_put(a, (void*)"bar");
        ASSERT_FALSE(set_equal(a, b));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
