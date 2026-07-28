/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: strv_split, strv_consume_pair, strv_contains, strv_extend_strv_consume, strv_split_and_extend_full */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"
#include "strv.h"
#include "extract-word.h"
#include "rust/strv.h"

static char **make_strv2(const char *a, const char *b) {
        char **v = calloc(3, sizeof(char *));
        assert_se(v);
        v[0] = strdup(a);
        v[1] = strdup(b);
        return v;
}

static char **make_strv3(const char *a, const char *b, const char *c) {
        char **v = calloc(4, sizeof(char *));
        assert_se(v);
        v[0] = strdup(a);
        v[1] = strdup(b);
        v[2] = strdup(c);
        return v;
}

static char **make_empty_strv(void) {
        char **v = calloc(1, sizeof(char *));
        assert_se(v);
        return v;
}

/* RUST-CONTRACT: strv-split-full */
/* RUST-CONTRACT: strv-split */
/* RUST-CONTRACT: strv-consume-pair */
/* RUST-CONTRACT: strv-extend-strv-consume */
/* RUST-CONTRACT: strv-contains */
static void test_strv_split(void) {
        char **c_r, **rs_r;
        size_t i;

        /* Split by spaces */
        c_r = strv_split("hello world foo", " ");
        rs_r = rs_strv_split("hello world foo", " ");
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        for (i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        assert_se(i == 3);
        strv_free(c_r);
        strv_free(rs_r);

        /* Split by commas */
        c_r = strv_split("a,b,c", ",");
        rs_r = rs_strv_split("a,b,c", ",");
        for (i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        assert_se(i == 3);
        strv_free(c_r);
        strv_free(rs_r);

        /* Empty string */
        c_r = strv_split("", " ");
        rs_r = rs_strv_split("", " ");
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        assert_se(c_r[0] == NULL);
        assert_se(rs_r[0] == NULL);
        strv_free(c_r);
        strv_free(rs_r);

        /* Full variant publishes the result and reports its length. */
        c_r = rs_r = NULL;
        int c_ret = strv_split_full(&c_r, "hello world foo", " ", 0);
        int rs_ret = rs_strv_split_full(&rs_r, "hello world foo", " ", 0);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 3);
        for (i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        assert_se(c_r[i] == NULL);
        assert_se(rs_r[i] == NULL);
        strv_free(c_r);
        strv_free(rs_r);
}

static void test_strv_consume_pair(void) {
        char **c_r = NULL, **rs_r = NULL;
        int c_ret, rs_ret;

        /* Simple pair */
        c_ret = strv_consume_pair(&c_r, strdup("key"), strdup("value"));
        rs_ret = rs_strv_consume_pair(&rs_r, strdup("key"), strdup("value"));
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(strv_length(c_r) == 2);
        assert_se(streq(c_r[0], "key"));
        assert_se(streq(rs_r[0], "key"));
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;

        /* NULL entries */
        c_ret = strv_consume_pair(&c_r, NULL, strdup("value"));
        rs_ret = rs_strv_consume_pair(&rs_r, NULL, strdup("value"));
        assert_se(c_ret == rs_ret);
        assert_se(strv_length(c_r) == 1);
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;

        /* Both NULL */
        c_ret = strv_consume_pair(&c_r, NULL, NULL);
        rs_ret = rs_strv_consume_pair(&rs_r, NULL, NULL);
        assert_se(c_ret == rs_ret);
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);
}

static void test_strv_contains(void) {
        char *arr[] = { (char*)"hello", (char*)"world", (char*)"foo", NULL };

        assert_se(rs_strv_contains(arr, "world") == true);
        assert_se(rs_strv_contains(arr, "bar") == false);
        assert_se(rs_strv_contains(arr, NULL) == false);
        assert_se(rs_strv_contains(NULL, "hello") == false);
}

static void test_strv_extend_strv_consume(void) {
        char **c_a = NULL, **rs_a = NULL;
        int c_ret, rs_ret;
        size_t i;

        /* Extend with no filter */
        c_ret = strv_extend_strv_consume(&c_a, make_strv2("a", "b"), false);
        rs_ret = rs_strv_extend_strv_consume(&rs_a, make_strv2("a", "b"), false);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 2);
        for (i = 0; c_a[i] && rs_a[i]; i++)
                assert_se(streq(c_a[i], rs_a[i]));
        strv_free(c_a); c_a = NULL;
        strv_free(rs_a); rs_a = NULL;

        /* Extend empty array with filter (duplicates removed) */
        c_ret = strv_extend_strv_consume(&c_a, make_strv3("x", "y", "x"), true);
        rs_ret = rs_strv_extend_strv_consume(&rs_a, make_strv3("x", "y", "x"), true);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret >= 0);
        for (i = 0; c_a[i] && rs_a[i]; i++)
                assert_se(streq(c_a[i], rs_a[i]));
        assert_se(strv_length(c_a) == 2);
        strv_free(c_a); c_a = NULL;
        strv_free(rs_a); rs_a = NULL;

        /* Extend existing array */
        c_a = make_strv2("a", "b");
        rs_a = make_strv2("a", "b");
        c_ret = strv_extend_strv_consume(&c_a, make_strv2("c", "d"), false);
        rs_ret = rs_strv_extend_strv_consume(&rs_a, make_strv2("c", "d"), false);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 2);
        assert_se(strv_length(c_a) == 4);
        for (i = 0; c_a[i] && rs_a[i]; i++)
                assert_se(streq(c_a[i], rs_a[i]));
        strv_free(c_a); c_a = NULL;
        strv_free(rs_a); rs_a = NULL;

        /* Extend with filter — remove duplicates */
        c_a = make_strv2("a", "b");
        rs_a = make_strv2("a", "b");
        c_ret = strv_extend_strv_consume(&c_a, make_strv2("b", "c"), true);
        rs_ret = rs_strv_extend_strv_consume(&rs_a, make_strv2("b", "c"), true);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 1);
        assert_se(strv_length(c_a) == 3);
        for (i = 0; c_a[i] && rs_a[i]; i++)
                assert_se(streq(c_a[i], rs_a[i]));
        strv_free(c_a); c_a = NULL;
        strv_free(rs_a); rs_a = NULL;

        /* Extend with empty b */
        c_ret = strv_extend_strv_consume(&c_a, make_empty_strv(), false);
        rs_ret = rs_strv_extend_strv_consume(&rs_a, make_empty_strv(), false);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);
        assert_se(c_a == NULL);
        assert_se(rs_a == NULL);
}

static void test_strv_split_and_extend_full(void) {
        char **c_a = NULL, **rs_a = NULL;
        int c_ret, rs_ret;
        size_t i;

        /* Split and extend */
        c_ret = strv_split_and_extend_full(&c_a, "hello world foo", " ", false, 0);
        rs_ret = rs_strv_split_and_extend_full(&rs_a, "hello world foo", " ", false, 0);
        assert_se(c_ret == rs_ret);
        for (i = 0; c_a[i] && rs_a[i]; i++)
                assert_se(streq(c_a[i], rs_a[i]));
        assert_se(strv_length(c_a) == 3);
        strv_free(c_a); c_a = NULL;
        strv_free(rs_a); rs_a = NULL;

        /* Split and extend with filter */
        c_ret = strv_split_and_extend_full(&c_a, "a b a c", " ", true, 0);
        rs_ret = rs_strv_split_and_extend_full(&rs_a, "a b a c", " ", true, 0);
        assert_se(c_ret == rs_ret);
        assert_se(strv_length(c_a) == 3);
        for (i = 0; c_a[i] && rs_a[i]; i++)
                assert_se(streq(c_a[i], rs_a[i]));
        strv_free(c_a); c_a = NULL;
        strv_free(rs_a); rs_a = NULL;

        /* Split and extend into existing array */
        c_a = strv_new("x", NULL);
        rs_a = strv_new("x", NULL);
        c_ret = strv_split_and_extend_full(&c_a, "a b", " ", false, 0);
        rs_ret = rs_strv_split_and_extend_full(&rs_a, "a b", " ", false, 0);
        assert_se(c_ret == rs_ret);
        assert_se(strv_length(c_a) == 3);
        assert_se(streq(c_a[0], "x"));
        for (i = 0; c_a[i] && rs_a[i]; i++)
                assert_se(streq(c_a[i], rs_a[i]));
        strv_free(c_a); c_a = NULL;
        strv_free(rs_a); rs_a = NULL;
}

int main(int argc, char **argv) {
        test_strv_split();
        test_strv_consume_pair();
        test_strv_contains();
        test_strv_extend_strv_consume();
        test_strv_split_and_extend_full();
        return 0;
}
