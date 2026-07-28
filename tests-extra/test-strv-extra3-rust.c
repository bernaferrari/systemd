/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: strv_filter_prefix, strv_extend_strv vs Rust */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"
#include "strv.h"
#include "rust/strv.h"

/* RUST-CONTRACT: strv-filter-prefix */
/* RUST-CONTRACT: strv-extend-strv */
static void test_strv_filter_prefix(void) {
        char * const input[] = { (char*)"hello", (char*)"helpful", (char*)"world", (char*)"helper", NULL };
        char **c_r, **rs_r;
        size_t i;

        /* Filter by "help" */
        c_r = strv_filter_prefix(input, "help");
        rs_r = rs_strv_filter_prefix(input, "help");
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        for (i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        assert_se(c_r[i] == NULL);
        assert_se(rs_r[i] == NULL);
        /* Should have 2 entries: helpful, helper (NOT "hello" — startswith, not contains) */
        assert_se(i == 2);
        assert_se(streq(c_r[0], "helpful"));
        assert_se(streq(c_r[1], "helper"));
        strv_free(c_r);
        strv_free(rs_r);

        /* NULL is an empty prefix in current C, and returns a full owned copy. */
        c_r = strv_filter_prefix(input, NULL);
        rs_r = rs_strv_filter_prefix(input, NULL);
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        for (i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        assert_se(i == 4);
        strv_free(c_r);
        strv_free(rs_r);

        /* Empty prefix returns full copy */
        c_r = strv_filter_prefix(input, "");
        rs_r = rs_strv_filter_prefix(input, "");
        assert_se(c_r != NULL);
        assert_se(rs_r != NULL);
        for (i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        assert_se(i == 4);
        strv_free(c_r);
        strv_free(rs_r);

        /* No matches — C returns NULL */
        c_r = strv_filter_prefix(input, "zzz");
        rs_r = rs_strv_filter_prefix(input, "zzz");
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);

        /* NULL input — C returns NULL */
        c_r = strv_filter_prefix(NULL, "a");
        rs_r = rs_strv_filter_prefix(NULL, "a");
        assert_se(c_r == NULL);
        assert_se(rs_r == NULL);
}

static void test_strv_extend_strv(void) {
        char * const src[] = { (char*)"one", (char*)"two", (char*)"three", NULL };
        char **c_r = NULL, **rs_r = NULL;
        int c_ret, rs_ret;

        /* Simple extend */
        c_ret = strv_extend_strv(&c_r, src, false);
        rs_ret = rs_strv_extend_strv(&rs_r, src, false);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 3);
        for (size_t i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        assert_se(streq(c_r[0], "one"));
        assert_se(streq(c_r[1], "two"));
        assert_se(streq(c_r[2], "three"));
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;

        /* Extend with duplicates filtered */
        char * const dup_src[] = { (char*)"one", (char*)"one", (char*)"two", NULL };
        c_ret = strv_extend_strv(&c_r, dup_src, true);
        rs_ret = rs_strv_extend_strv(&rs_r, dup_src, true);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 2);
        assert_se(streq(c_r[0], "one"));
        assert_se(streq(c_r[1], "two"));
        for (size_t i = 0; c_r[i] && rs_r[i]; i++)
                assert_se(streq(c_r[i], rs_r[i]));
        strv_free(c_r); c_r = NULL;
        strv_free(rs_r); rs_r = NULL;

        /* Extend with empty source */
        char * const empty_src[] = { NULL };
        c_ret = strv_extend_strv(&c_r, empty_src, false);
        rs_ret = rs_strv_extend_strv(&rs_r, empty_src, false);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);

        /* NULL source */
        c_ret = strv_extend_strv(&c_r, NULL, false);
        rs_ret = rs_strv_extend_strv(&rs_r, NULL, false);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 0);

        /* Filtering includes entries already in the destination and prior
         * entries from the source, while preserving first-seen order. */
        c_r = strv_new("one");
        rs_r = strv_new("one");
        assert_se(c_r && rs_r);
        c_ret = strv_extend_strv(&c_r, dup_src, true);
        rs_ret = rs_strv_extend_strv(&rs_r, dup_src, true);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret == 1);
        assert_se(streq(c_r[0], "one") && streq(c_r[1], "two") && c_r[2] == NULL);
        assert_se(streq(rs_r[0], "one") && streq(rs_r[1], "two") && rs_r[2] == NULL);
        strv_free(c_r);
        strv_free(rs_r);
}

int main(int argc, char **argv) {
        test_strv_filter_prefix();
        test_strv_extend_strv();
        return 0;
}
