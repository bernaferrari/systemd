/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hashmap.h"
#include "tests.h"

TEST(hashmap_basics) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;

        m = hashmap_new(&string_hash_ops);
        ASSERT_NOT_NULL(m);
        ASSERT_TRUE(hashmap_isempty(m));
        ASSERT_EQ(hashmap_size(m), 0u);

        /* Insert */
        ASSERT_OK(hashmap_put(m, "key1", INT_TO_PTR(1)));
        ASSERT_EQ(hashmap_size(m), 1u);
        ASSERT_FALSE(hashmap_isempty(m));

        ASSERT_OK(hashmap_put(m, "key2", INT_TO_PTR(2)));
        ASSERT_EQ(hashmap_size(m), 2u);

        /* Lookup */
        ASSERT_EQ(PTR_TO_INT(hashmap_get(m, "key1")), 1);
        ASSERT_EQ(PTR_TO_INT(hashmap_get(m, "key2")), 2);
        ASSERT_NULL(hashmap_get(m, "nonexistent"));

        /* Contains */
        ASSERT_TRUE(hashmap_contains(m, "key1"));
        ASSERT_FALSE(hashmap_contains(m, "nonexistent"));

        /* Remove */
        ASSERT_EQ(PTR_TO_INT(hashmap_remove(m, "key1")), 1);
        ASSERT_EQ(hashmap_size(m), 1u);
        ASSERT_FALSE(hashmap_contains(m, "key1"));

        /* Buckets */
        ASSERT_GT(hashmap_buckets(m), 0u);
}

TEST(ordered_hashmap_basics) {
        _cleanup_ordered_hashmap_free_ OrderedHashmap *m = NULL;

        m = ordered_hashmap_new(&string_hash_ops);
        ASSERT_NOT_NULL(m);
        ASSERT_TRUE(ordered_hashmap_isempty(m));

        ASSERT_OK(ordered_hashmap_put(m, "a", INT_TO_PTR(1)));
        ASSERT_OK(ordered_hashmap_put(m, "b", INT_TO_PTR(2)));

        ASSERT_EQ(ordered_hashmap_size(m), 2u);
        ASSERT_EQ(PTR_TO_INT(ordered_hashmap_get(m, "a")), 1);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
