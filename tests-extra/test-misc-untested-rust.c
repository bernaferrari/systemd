/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C vs Rust for remaining untested pure functions */

#include <string.h>

#include "tests.h"
#include "fd-util.h"
#include "rust/path_util.h"

/* ── fdname_is_valid ────────────────────────────────────────────────── */

static void test_fdname_is_valid_null(void) {
        assert_se(!fdname_is_valid(NULL));
        assert_se(!rs_fdname_is_valid(NULL));
}

static void test_fdname_is_valid_empty(void) {
        assert_se(fdname_is_valid("") == rs_fdname_is_valid(""));
        assert_se(fdname_is_valid("") == true);
}

static void test_fdname_is_valid_simple(void) {
        assert_se(fdname_is_valid("foo") == rs_fdname_is_valid("foo"));
        assert_se(fdname_is_valid("foo") == true);

        assert_se(fdname_is_valid("0") == rs_fdname_is_valid("0"));
        assert_se(fdname_is_valid("0") == true);

        assert_se(fdname_is_valid("abc123") == rs_fdname_is_valid("abc123"));
        assert_se(fdname_is_valid("abc123") == true);
}

static void test_fdname_is_valid_with_colon(void) {
        /* Colon is explicitly forbidden */
        assert_se(!fdname_is_valid("foo:bar"));
        assert_se(!rs_fdname_is_valid("foo:bar"));

        assert_se(!fdname_is_valid(":foo"));
        assert_se(!rs_fdname_is_valid(":foo"));

        assert_se(!fdname_is_valid("foo:"));
        assert_se(!rs_fdname_is_valid("foo:"));
}

static void test_fdname_is_valid_control_chars(void) {
        char buf[8];
        buf[0] = 0x01;
        memcpy(buf + 1, "foo", 4);
        buf[5] = '\0';
        assert_se(!fdname_is_valid(buf));
        assert_se(!rs_fdname_is_valid(buf));

        buf[0] = 0x1f;
        memcpy(buf + 1, "bar", 4);
        buf[5] = '\0';
        assert_se(!fdname_is_valid(buf));
        assert_se(!rs_fdname_is_valid(buf));

        buf[0] = 0x7f;
        memcpy(buf + 1, "baz", 4);
        buf[5] = '\0';
        assert_se(!fdname_is_valid(buf));
        assert_se(!rs_fdname_is_valid(buf));
}

static void test_fdname_is_valid_high_byte(void) {
        /* Bytes >= 127 are rejected */
        char buf[8];
        buf[0] = (char)0x80;
        memcpy(buf + 1, "x", 2);
        buf[3] = '\0';
        assert_se(!fdname_is_valid(buf));
        assert_se(!rs_fdname_is_valid(buf));

        buf[0] = (char)0xff;
        memcpy(buf + 1, "y", 2);
        buf[3] = '\0';
        assert_se(!fdname_is_valid(buf));
        assert_se(!rs_fdname_is_valid(buf));
}

static void test_fdname_is_valid_spaces(void) {
        /* Spaces are allowed (they're printable ASCII) */
        assert_se(fdname_is_valid("foo bar") == rs_fdname_is_valid("foo bar"));
        assert_se(fdname_is_valid("foo bar") == true);
}

static void test_fdname_is_valid_special_chars(void) {
        /* Various printable ASCII chars should be valid */
        assert_se(fdname_is_valid("foo.bar") == rs_fdname_is_valid("foo.bar"));
        assert_se(fdname_is_valid("foo-bar") == rs_fdname_is_valid("foo-bar"));
        assert_se(fdname_is_valid("foo_bar") == rs_fdname_is_valid("foo_bar"));
        assert_se(fdname_is_valid("foo/bar") == rs_fdname_is_valid("foo/bar"));
        assert_se(fdname_is_valid("foo=bar") == rs_fdname_is_valid("foo=bar"));
        assert_se(fdname_is_valid("foo@bar") == rs_fdname_is_valid("foo@bar"));
}

int main(int argc, char *argv[]) {
        test_fdname_is_valid_null();
        test_fdname_is_valid_empty();
        test_fdname_is_valid_simple();
        test_fdname_is_valid_with_colon();
        test_fdname_is_valid_control_chars();
        test_fdname_is_valid_high_byte();
        test_fdname_is_valid_spaces();
        test_fdname_is_valid_special_chars();

        return 0;
}
