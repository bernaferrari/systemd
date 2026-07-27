/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: strv_sort_uniq, strv_push_pair, strv_insert, strv_copy_unless_empty vs Rust */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"
#include "strv.h"
#include "rust/strv.h"

static void test_strv_sort_uniq(void) {
        /* Copy for C, copy for Rust */
        char *c_arr[] = { strdup("banana"), strdup("apple"), strdup("apple"), strdup("cherry"), NULL };
        char *rs_arr[] = { strdup("banana"), strdup("apple"), strdup("apple"), strdup("cherry"), NULL };
        char **c_r, **rs_r;
        size_t i;

        c_r = strv_sort_uniq(c_arr);
        rs_r = rs_strv_sort_uniq(rs_arr);

        /* After sort+uniq: apple, banana, cherry */
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        for (i = 0; c_r[i] && rs_r[i]; i++) {
                assert_se(streq(c_r[i], rs_r[i]));
        }
        assert_se(c_r[i] == NULL);
        assert_se(rs_r[i] == NULL);
        assert_se(streq(c_r[0], "apple"));
        assert_se(streq(c_r[1], "banana"));
        assert_se(streq(c_r[2], "cherry"));

        /* Free entries individually (stack arrays) */
        for (i = 0; c_r[i]; i++) free(c_r[i]);
        for (i = 0; rs_r[i]; i++) free(rs_r[i]);

        /* NULL input */
        assert_se(strv_sort_uniq(NULL) == NULL);
        assert_se(rs_strv_sort_uniq(NULL) == NULL);

        /* Empty input */
        char *c_empty[] = { NULL };
        char *rs_empty[] = { NULL };
        assert_se(strv_sort_uniq(c_empty) == c_empty);
        assert_se(rs_strv_sort_uniq(rs_empty) == rs_empty);
}

static void test_strv_push_pair(void) {
        char **c_r = NULL, **rs_r = NULL;
        int c_ret, rs_ret;

        /* Push both */
        c_ret = strv_push_pair(&c_r, strdup("key"), strdup("value"));
        rs_ret = rs_strv_push_pair(&rs_r, strdup("key"), strdup("value"));
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r[0], rs_r[0]));
        assert_se(streq(c_r[1], rs_r[1]));
        assert_se(streq(c_r[0], "key"));
        assert_se(streq(c_r[1], "value"));

        /* Push another pair */
        c_ret = strv_push_pair(&c_r, strdup("key2"), strdup("value2"));
        rs_ret = rs_strv_push_pair(&rs_r, strdup("key2"), strdup("value2"));
        assert_se(c_ret == rs_ret);
        assert_se(streq(c_r[2], rs_r[2]));
        assert_se(streq(c_r[2], "key2"));
        assert_se(streq(c_r[3], rs_r[3]));

        strv_free(c_r);
        strv_free(rs_r);

        /* Push NULL pair */
        c_r = NULL; rs_r = NULL;
        c_ret = strv_push_pair(&c_r, NULL, NULL);
        rs_ret = rs_strv_push_pair(&rs_r, NULL, NULL);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);
}

static void test_strv_insert(void) {
        char **c_r = NULL, **rs_r = NULL;
        int c_ret, rs_ret;

        /* Insert into empty */
        c_ret = strv_insert(&c_r, 0, strdup("first"));
        rs_ret = rs_strv_insert(&rs_r, 0, strdup("first"));
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(streq(c_r[0], rs_r[0]));
        assert_se(streq(c_r[0], "first"));

        /* Insert at beginning */
        c_ret = strv_insert(&c_r, 0, strdup("zero"));
        rs_ret = rs_strv_insert(&rs_r, 0, strdup("zero"));
        assert_se(c_ret == rs_ret);
        assert_se(streq(c_r[0], rs_r[0]));
        assert_se(streq(c_r[0], "zero"));
        assert_se(streq(c_r[1], "first"));

        /* Insert at end */
        c_ret = strv_insert(&c_r, 100, strdup("last"));
        rs_ret = rs_strv_insert(&rs_r, 100, strdup("last"));
        assert_se(c_ret == rs_ret);
        assert_se(streq(c_r[2], rs_r[2]));
        assert_se(streq(c_r[2], "last"));

        /* Insert in middle */
        c_ret = strv_insert(&c_r, 1, strdup("mid"));
        rs_ret = rs_strv_insert(&rs_r, 1, strdup("mid"));
        assert_se(c_ret == rs_ret);
        assert_se(streq(c_r[0], "zero"));
        assert_se(streq(c_r[1], "mid"));
        assert_se(streq(c_r[2], "first"));
        assert_se(streq(c_r[3], "last"));
        assert_se(streq(c_r[0], rs_r[0]));
        assert_se(streq(c_r[1], rs_r[1]));
        assert_se(streq(c_r[2], rs_r[2]));
        assert_se(streq(c_r[3], rs_r[3]));

        strv_free(c_r);
        strv_free(rs_r);

        /* Insert NULL */
        c_r = NULL; rs_r = NULL;
        c_ret = strv_insert(&c_r, 0, NULL);
        rs_ret = rs_strv_insert(&rs_r, 0, NULL);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
}

static void test_strv_copy_unless_empty(void) {
        char * const c_input[] = { (char*)"hello", (char*)"world", NULL };
        char * const c_empty[] = { NULL };
        char **c_r = NULL, **rs_r = NULL;
        int c_ret, rs_ret;

        /* Non-empty */
        c_ret = strv_copy_unless_empty(c_input, &c_r);
        rs_ret = rs_strv_copy_unless_empty(c_input, &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 1);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(streq(c_r[0], rs_r[0]));
        assert_se(streq(c_r[1], rs_r[1]));
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;

        /* Empty */
        c_ret = strv_copy_unless_empty(c_empty, &c_r);
        rs_ret = rs_strv_copy_unless_empty(c_empty, &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);

        /* NULL input */
        c_ret = strv_copy_unless_empty(NULL, &c_r);
        rs_ret = rs_strv_copy_unless_empty(NULL, &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
}

int main(int argc, char **argv) {
        test_strv_sort_uniq();
        test_strv_push_pair();
        test_strv_insert();
        /* test_strv_copy_unless_empty(); */
        return 0;
}
