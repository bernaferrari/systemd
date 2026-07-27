/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hashmap.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(hashmap_basic_ops) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;
        m = hashmap_new(&string_hash_ops);
        assert_se(m);

        assert_se(hashmap_put(m, "key1", INT_TO_PTR(1)) >= 0);
        assert_se(hashmap_put(m, "key2", INT_TO_PTR(2)) >= 0);
        assert_se(hashmap_put(m, "key3", INT_TO_PTR(3)) >= 0);

        assert_se(hashmap_size(m) == 3);
        assert_se(!hashmap_isempty(m));
        assert_se(hashmap_get(m, "key1") == INT_TO_PTR(1));
        assert_se(hashmap_get(m, "key2") == INT_TO_PTR(2));
        assert_se(hashmap_get(m, "key3") == INT_TO_PTR(3));
        assert_se(hashmap_get(m, "nonexistent") == NULL);

        assert_se(hashmap_contains(m, "key1"));
        assert_se(!hashmap_contains(m, "nonexistent"));
}

TEST(hashmap_update) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;
        m = hashmap_new(&string_hash_ops);
        assert_se(m);

        assert_se(hashmap_put(m, "key", INT_TO_PTR(1)) >= 0);
        assert_se(hashmap_update(m, "key", INT_TO_PTR(2)) >= 0);
        assert_se(hashmap_get(m, "key") == INT_TO_PTR(2));

        assert_se(hashmap_update(m, "nonexistent", INT_TO_PTR(3)) < 0);
}

TEST(hashmap_replace) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;
        m = hashmap_new(&string_hash_ops);
        assert_se(m);

        assert_se(hashmap_replace(m, "key", INT_TO_PTR(1)) >= 0);
        assert_se(hashmap_get(m, "key") == INT_TO_PTR(1));

        assert_se(hashmap_replace(m, "key", INT_TO_PTR(2)) >= 0);
        assert_se(hashmap_get(m, "key") == INT_TO_PTR(2));
}

TEST(hashmap_remove) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;
        m = hashmap_new(&string_hash_ops);
        assert_se(m);

        assert_se(hashmap_put(m, "key", INT_TO_PTR(1)) >= 0);
        assert_se(hashmap_remove(m, "key") == INT_TO_PTR(1));
        assert_se(hashmap_size(m) == 0);
        assert_se(hashmap_remove(m, "nonexistent") == NULL);
}

TEST(hashmap_remove_value) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;
        m = hashmap_new(&string_hash_ops);
        assert_se(m);

        assert_se(hashmap_put(m, "key", INT_TO_PTR(1)) >= 0);
        assert_se(hashmap_remove_value(m, "key", INT_TO_PTR(1)) != NULL);
        assert_se(hashmap_size(m) == 0);

        /* Wrong value */
        assert_se(hashmap_put(m, "key2", INT_TO_PTR(2)) >= 0);
        assert_se(hashmap_remove_value(m, "key2", INT_TO_PTR(99)) == NULL);
        assert_se(hashmap_size(m) == 1);
}

TEST(hashmap_steal_first) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;
        m = hashmap_new(&string_hash_ops);
        assert_se(m);

        assert_se(hashmap_put(m, "key", INT_TO_PTR(42)) >= 0);
        void *stolen = hashmap_steal_first(m);
        assert_se(stolen == INT_TO_PTR(42));
        assert_se(hashmap_isempty(m));
}

TEST(hashmap_clear) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;
        m = hashmap_new(&string_hash_ops);
        assert_se(m);

        assert_se(hashmap_put(m, "key1", INT_TO_PTR(1)) >= 0);
        assert_se(hashmap_put(m, "key2", INT_TO_PTR(2)) >= 0);
        hashmap_clear(m);
        assert_se(hashmap_isempty(m));
}

TEST(hashmap_iterate) {
        _cleanup_hashmap_free_ Hashmap *m = NULL;
        m = hashmap_new(&string_hash_ops);
        assert_se(m);

        assert_se(hashmap_put(m, "key1", INT_TO_PTR(1)) >= 0);
        assert_se(hashmap_put(m, "key2", INT_TO_PTR(2)) >= 0);

        int count = 0;
        const char *key;
        void *val;
        HASHMAP_FOREACH_KEY(val, key, m)
                count++;
        assert_se(count == 2);
}

TEST(hashmap_strdup_free) {
        /* Test with allocated strings as values using _free_ ops */
        Hashmap *m = hashmap_new(&string_hash_ops_free);
        assert_se(m);

        assert_se(hashmap_put(m, strdup("key1"), strdup("val1")) >= 0);
        assert_se(hashmap_put(m, strdup("key2"), strdup("val2")) >= 0);

        assert_se(streq(hashmap_get(m, "key1"), "val1"));
        assert_se(streq(hashmap_get(m, "key2"), "val2"));

        /* string_hash_ops_free frees both key and value */
        hashmap_free(m);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
