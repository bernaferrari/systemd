/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "strv.h"
#include "tests.h"

TEST(strv_find_closest_basic) {
        char *list[] = { (char*) "alpha", (char*) "bravo", (char*) "charlie", NULL };

        /* Exact match returns the matching string */
        assert_se(streq_ptr(strv_find_closest(list, "alpha"), "alpha"));
        assert_se(streq_ptr(strv_find_closest(list, "bravo"), "bravo"));

        /* Close typo will suggest the closest match */
        char *r = strv_find_closest(list, "alph");
        assert_se(r != NULL);
        /* "alph" is a prefix of "alpha" → returns "alpha" */
        assert_se(streq(r, "alpha"));
}

TEST(strv_find_first_field_basic) {
        /* strv_find_first_field uses STRV_FOREACH_PAIR on haystack */
        /* haystack is [key1, val1, key2, val2, ...] */
        char *needles[] = { (char*) "zzz", (char*) "bar", NULL };
        char *haystack[] = { (char*) "bar", (char*) "value_bar", (char*) "baz", (char*) "value_baz", NULL };

        /* "bar" key found in haystack with value "value_bar" */
        char *r = strv_find_first_field(needles, haystack);
        assert_se(r != NULL);
        assert_se(streq(r, "value_bar"));
}

TEST(strv_copy_n_basic) {
        char *list[] = { (char*) "one", (char*) "two", (char*) "three", NULL };

        _cleanup_strv_free_ char **copy = strv_copy_n(list, 2);
        assert_se(strv_length(copy) == 2);
        assert_se(streq(copy[0], "one"));
        assert_se(streq(copy[1], "two"));

        /* Copy more than available */
        _cleanup_strv_free_ char **copy2 = strv_copy_n(list, 10);
        assert_se(strv_length(copy2) == 3);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
