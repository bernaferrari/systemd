/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: make_cstring vs Rust */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"
#include "rust/string_util.h"

/* Convenience: call C version and check return */
static int c_make_cstring(const char *s, size_t n, MakeCStringMode mode, char **ret) {
        return make_cstring(s, n, mode, ret);
}

static void test_make_cstring_simple(void) {
        char *c_r = NULL, *rs_r = NULL;
        int c_ret, rs_ret;

        /* Simple string, no trailing NUL */
        c_ret = c_make_cstring("hello", 5, MAKE_CSTRING_REFUSE_TRAILING_NUL, &c_r);
        rs_ret = rs_make_cstring("hello", 5, MAKE_CSTRING_REFUSE_TRAILING_NUL, &rs_r);
        assert_se(c_ret == rs_ret);
        if (c_ret >= 0) {
                assert_se(streq(c_r, rs_r));
                assert_se(streq(c_r, "hello"));
        }
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* With ALLOW mode */
        c_ret = c_make_cstring("hello", 5, MAKE_CSTRING_ALLOW_TRAILING_NUL, &c_r);
        rs_ret = rs_make_cstring("hello", 5, MAKE_CSTRING_ALLOW_TRAILING_NUL, &rs_r);
        assert_se(c_ret == rs_ret);
        if (c_ret >= 0) {
                assert_se(streq(c_r, rs_r));
        }
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* With REQUIRE mode — should fail (no trailing NUL) */
        c_ret = c_make_cstring("hello", 5, MAKE_CSTRING_REQUIRE_TRAILING_NUL, &c_r);
        rs_ret = rs_make_cstring("hello", 5, MAKE_CSTRING_REQUIRE_TRAILING_NUL, &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret < 0);
        free(c_r); free(rs_r);
}

static void test_make_cstring_with_trailing_nul(void) {
        char *c_r = NULL, *rs_r = NULL;
        int c_ret, rs_ret;

        /* String with explicit trailing NUL, REFUSE mode */
        c_ret = c_make_cstring("hello\0", 6, MAKE_CSTRING_REFUSE_TRAILING_NUL, &c_r);
        rs_ret = rs_make_cstring("hello\0", 6, MAKE_CSTRING_REFUSE_TRAILING_NUL, &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret < 0); /* REFUSE rejects trailing NUL */
        free(c_r); free(rs_r);

        /* String with explicit trailing NUL, ALLOW mode */
        c_ret = c_make_cstring("hello\0", 6, MAKE_CSTRING_ALLOW_TRAILING_NUL, &c_r);
        rs_ret = rs_make_cstring("hello\0", 6, MAKE_CSTRING_ALLOW_TRAILING_NUL, &rs_r);
        assert_se(c_ret == rs_ret);
        if (c_ret >= 0) {
                assert_se(streq(c_r, rs_r));
                assert_se(streq(c_r, "hello"));
        }
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* String with explicit trailing NUL, REQUIRE mode */
        c_ret = c_make_cstring("hello\0", 6, MAKE_CSTRING_REQUIRE_TRAILING_NUL, &c_r);
        rs_ret = rs_make_cstring("hello\0", 6, MAKE_CSTRING_REQUIRE_TRAILING_NUL, &rs_r);
        assert_se(c_ret == rs_ret);
        if (c_ret >= 0) {
                assert_se(streq(c_r, rs_r));
                assert_se(streq(c_r, "hello"));
        }
        free(c_r); free(rs_r);
}

static void test_make_cstring_embedded_nul(void) {
        char *c_r = NULL, *rs_r = NULL;
        int c_ret, rs_ret;

        /* Embedded NUL byte (not at end) — should fail */
        c_ret = c_make_cstring("hel\0lo", 6, MAKE_CSTRING_ALLOW_TRAILING_NUL, &c_r);
        rs_ret = rs_make_cstring("hel\0lo", 6, MAKE_CSTRING_ALLOW_TRAILING_NUL, &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret < 0);
        free(c_r); free(rs_r);
}

static void test_make_cstring_empty(void) {
        char *c_r = NULL, *rs_r = NULL;
        int c_ret, rs_ret;

        /* Empty string (n=0), REFUSE mode */
        c_ret = c_make_cstring("", 0, MAKE_CSTRING_REFUSE_TRAILING_NUL, &c_r);
        rs_ret = rs_make_cstring("", 0, MAKE_CSTRING_REFUSE_TRAILING_NUL, &rs_r);
        assert_se(c_ret == rs_ret);
        if (c_ret >= 0) {
                assert_se(streq(c_r, rs_r));
                assert_se(streq(c_r, ""));
        }
        free(c_r); c_r = NULL; free(rs_r); rs_r = NULL;

        /* Empty string, REQUIRE mode — should fail */
        c_ret = c_make_cstring("", 0, MAKE_CSTRING_REQUIRE_TRAILING_NUL, &c_r);
        rs_ret = rs_make_cstring("", 0, MAKE_CSTRING_REQUIRE_TRAILING_NUL, &rs_r);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret < 0);
        free(c_r); free(rs_r);

        /* NULL with n=0 */
        c_ret = c_make_cstring(NULL, 0, MAKE_CSTRING_REFUSE_TRAILING_NUL, &c_r);
        rs_ret = rs_make_cstring(NULL, 0, MAKE_CSTRING_REFUSE_TRAILING_NUL, &rs_r);
        assert_se(c_ret == rs_ret);
        if (c_ret >= 0) {
                assert_se(streq(c_r, rs_r));
                assert_se(streq(c_r, ""));
        }
        free(c_r); free(rs_r);
}

static void test_make_cstring_ret_null(void) {
        int c_ret, rs_ret;

        /* ret=NULL — just validation, no allocation */
        c_ret = c_make_cstring("hello", 5, MAKE_CSTRING_REFUSE_TRAILING_NUL, NULL);
        rs_ret = rs_make_cstring("hello", 5, MAKE_CSTRING_REFUSE_TRAILING_NUL, NULL);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret >= 0);

        c_ret = c_make_cstring("hello", 5, MAKE_CSTRING_REQUIRE_TRAILING_NUL, NULL);
        rs_ret = rs_make_cstring("hello", 5, MAKE_CSTRING_REQUIRE_TRAILING_NUL, NULL);
        assert_se(c_ret == rs_ret);
        assert_se(c_ret < 0);
}

int main(int argc, char **argv) {
        test_make_cstring_simple();
        test_make_cstring_with_trailing_nul();
        test_make_cstring_embedded_nul();
        test_make_cstring_empty();
        test_make_cstring_ret_null();
        return 0;
}
