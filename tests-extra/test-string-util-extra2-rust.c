/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: free_and_strndup vs Rust */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"
#include "rust/string_util.h"

static void test_free_and_strndup(void) {
        char *c_p = NULL;
        char *rs_p = NULL;

        /* Both NULL → 0 */
        assert_se(free_and_strndup(&c_p, NULL, 0) == rs_free_and_strndup(&rs_p, NULL, 0));
        assert_se(c_p == NULL);
        assert_se(rs_p == NULL);

        /* Set from NULL */
        assert_se(free_and_strndup(&c_p, "hello world", 5) == rs_free_and_strndup(&rs_p, "hello world", 5));
        assert_se(streq(c_p, rs_p));
        free(c_p); c_p = NULL;
        free(rs_p); rs_p = NULL;

        /* Set from NULL, l > strlen(s) */
        assert_se(free_and_strndup(&c_p, "hi", 10) == rs_free_and_strndup(&rs_p, "hi", 10));
        assert_se(streq(c_p, rs_p));
        free(c_p);
        free(rs_p);

        /* Same content → 0 (no change) */
        c_p = strdup("hello");
        rs_p = strdup("hello");
        assert_se(free_and_strndup(&c_p, "hello world", 5) == rs_free_and_strndup(&rs_p, "hello world", 5));
        assert_se(streq(c_p, rs_p));
        free(c_p);
        free(rs_p);

        /* Different content → 1 (changed) */
        c_p = strdup("hello");
        rs_p = strdup("hello");
        assert_se(free_and_strndup(&c_p, "world", 5) == rs_free_and_strndup(&rs_p, "world", 5));
        assert_se(streq(c_p, rs_p));
        free(c_p);
        free(rs_p);

        /* Change to NULL */
        c_p = strdup("hello");
        rs_p = strdup("hello");
        assert_se(free_and_strndup(&c_p, NULL, 0) == rs_free_and_strndup(&rs_p, NULL, 0));
        assert_se(c_p == NULL);
        assert_se(rs_p == NULL);
}

int main(int argc, char **argv) {
        test_free_and_strndup();
        return 0;
}
