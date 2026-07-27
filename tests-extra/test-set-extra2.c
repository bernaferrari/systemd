/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "set.h"
#include "string-util.h"
#include "tests.h"

TEST(set_basic_ops) {
        _cleanup_set_free_ Set *s = NULL;
        s = set_new(&string_hash_ops);
        assert_se(s);

        assert_se(set_put(s, (void*)"item1") >= 0);
        assert_se(set_put(s, (void*)"item2") >= 0);
        assert_se(set_put(s, (void*)"item3") >= 0);

        assert_se(set_size(s) == 3);
        assert_se(!set_isempty(s));
        assert_se(set_contains(s, (void*)"item1"));
        assert_se(!set_contains(s, (void*)"nonexistent"));

        /* Duplicate */
        assert_se(set_put(s, (void*)"item1") == 0);
        assert_se(set_size(s) == 3);
}

TEST(set_remove) {
        _cleanup_set_free_ Set *s = NULL;
        s = set_new(&string_hash_ops);
        assert_se(s);

        assert_se(set_put(s, (void*)"item") >= 0);
        assert_se(set_remove(s, (void*)"item") != NULL);
        assert_se(set_isempty(s));
        assert_se(set_remove(s, (void*)"nonexistent") == NULL);
}

TEST(set_steal_first) {
        _cleanup_set_free_ Set *s = NULL;
        s = set_new(&string_hash_ops);
        assert_se(s);

        assert_se(set_put(s, (void*)"item") >= 0);
        void *stolen = set_steal_first(s);
        assert_se(stolen);
        assert_se(set_isempty(s));
}

TEST(set_clear) {
        _cleanup_set_free_ Set *s = NULL;
        s = set_new(&string_hash_ops);
        assert_se(s);

        assert_se(set_put(s, (void*)"a") >= 0);
        assert_se(set_put(s, (void*)"b") >= 0);
        set_clear(s);
        assert_se(set_isempty(s));
}

TEST(set_iterate) {
        _cleanup_set_free_ Set *s = NULL;
        s = set_new(&string_hash_ops);
        assert_se(s);

        assert_se(set_put(s, (void*)"a") >= 0);
        assert_se(set_put(s, (void*)"b") >= 0);

        int count = 0;
        void *item;
        SET_FOREACH(item, s)
                count++;
        assert_se(count == 2);
}

TEST(set_merge) {
        _cleanup_set_free_ Set *a = NULL, *b = NULL;
        a = set_new(&string_hash_ops);
        b = set_new(&string_hash_ops);
        assert_se(a && b);

        assert_se(set_put(a, (void*)"x") >= 0);
        assert_se(set_put(a, (void*)"y") >= 0);
        assert_se(set_put(b, (void*)"y") >= 0);
        assert_se(set_put(b, (void*)"z") >= 0);

        assert_se(set_merge(a, b) >= 0);
        assert_se(set_size(a) == 3);
        assert_se(set_contains(a, (void*)"x"));
        assert_se(set_contains(a, (void*)"y"));
        assert_se(set_contains(a, (void*)"z"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
