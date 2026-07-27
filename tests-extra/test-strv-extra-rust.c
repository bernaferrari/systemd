/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: strv extra functions vs Rust */

#include <assert.h>
#include "tests.h"
#include "strv.h"
#include "rust/strv.h"

static void test_strv_find_closest(void) {
        char * const list[] = { (char*)"hello", (char*)"world", (char*)"help", (char*)"hallo", NULL };

        /* Exact prefix match: "hel" → "hello" (distance 2 remaining) */
        assert_se(strv_find_closest(list, "hel") == rs_strv_find_closest(list, "hel"));

        /* Levenshtein match: "helo" → should find closest */
        assert_se(strv_find_closest(list, "helo") == rs_strv_find_closest(list, "helo"));

        /* Exact match */
        assert_se(strv_find_closest(list, "world") == rs_strv_find_closest(list, "world"));

        /* No close match → NULL */
        assert_se(strv_find_closest(list, "xyz") == rs_strv_find_closest(list, "xyz"));

        /* Empty list */
        char * const empty[] = { NULL };
        assert_se(strv_find_closest(empty, "hello") == rs_strv_find_closest(empty, "hello"));
}

static void test_startswith_strv(void) {
        char * const prefixes[] = { (char*)"foo", (char*)"bar", (char*)"baz", NULL };

        assert_se(startswith_strv("foobar", prefixes) == rs_startswith_strv_internal("foobar", prefixes));
        assert_se(startswith_strv("bazqux", prefixes) == rs_startswith_strv_internal("bazqux", prefixes));
        assert_se(startswith_strv("qux", prefixes) == rs_startswith_strv_internal("qux", prefixes));
        assert_se(startswith_strv("foo", prefixes) == rs_startswith_strv_internal("foo", prefixes));
}

static void test_endswith_strv(void) {
        char * const suffixes[] = { (char*)".service", (char*)".socket", (char*)".target", NULL };

        assert_se(endswith_strv("foo.service", suffixes) == rs_endswith_strv_internal("foo.service", suffixes));
        assert_se(endswith_strv("bar.socket", suffixes) == rs_endswith_strv_internal("bar.socket", suffixes));
        assert_se(endswith_strv("baz.path", suffixes) == rs_endswith_strv_internal("baz.path", suffixes));
        assert_se(endswith_strv(".service", suffixes) == rs_endswith_strv_internal(".service", suffixes));
}

static void test_strv_join_full(void) {
        char *c_r, *rs_r;

        /* Simple join with space */
        char * const list1[] = { (char*)"one", (char*)"two", (char*)"three", NULL };
        c_r = strv_join_full(list1, " ", NULL, false);
        rs_r = rs_strv_join_full(list1, " ", NULL, false);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Join with comma and prefix */
        char * const list2[] = { (char*)"a", (char*)"b", NULL };
        c_r = strv_join_full(list2, ", ", "--", false);
        rs_r = rs_strv_join_full(list2, ", ", "--", false);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* NULL separator defaults to space */
        c_r = strv_join_full(list1, NULL, NULL, false);
        rs_r = rs_strv_join_full(list1, NULL, NULL, false);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Escape separator */
        char * const list3[] = { (char*)"a,b", (char*)"c", NULL };
        c_r = strv_join_full(list3, ",", NULL, true);
        rs_r = rs_strv_join_full(list3, ",", NULL, true);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);

        /* Empty list */
        char * const empty[] = { NULL };
        c_r = strv_join_full(empty, " ", NULL, false);
        rs_r = rs_strv_join_full(empty, " ", NULL, false);
        assert_se(streq(c_r, rs_r));
        free(c_r); free(rs_r);
}

int main(int argc, char **argv) {
        test_strv_find_closest();
        test_startswith_strv();
        test_endswith_strv();
        test_strv_join_full();
        return 0;
}
