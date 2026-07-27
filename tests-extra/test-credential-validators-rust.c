/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>

#include "tests.h"
#include "rust/credential_validators.h"

/* C functions are in libshared (not linkable), so use expected-value assertions */

/* ── credential_name_valid ─────────────────────────────────────────────── */

static void test_credential_name_valid_null(void) {
        assert_se(!rs_credential_name_valid(NULL));
}

static void test_credential_name_valid_empty(void) {
        assert_se(!rs_credential_name_valid(""));
}

static void test_credential_name_valid_simple(void) {
        assert_se(rs_credential_name_valid("mycred"));
}

static void test_credential_name_valid_with_hyphen(void) {
        assert_se(rs_credential_name_valid("my-cred"));
}

static void test_credential_name_valid_with_underscore(void) {
        assert_se(rs_credential_name_valid("my_cred"));
}

static void test_credential_name_valid_with_dot(void) {
        assert_se(rs_credential_name_valid("my.cred"));
}

static void test_credential_name_valid_with_slash(void) {
        assert_se(!rs_credential_name_valid("my/cred"));
}

static void test_credential_name_valid_with_dotdot(void) {
        assert_se(!rs_credential_name_valid(".."));
}

/* ── credential_glob_valid ─────────────────────────────────────────────── */

static void test_credential_glob_valid_null(void) {
        assert_se(!rs_credential_glob_valid(NULL));
}

static void test_credential_glob_valid_empty(void) {
        assert_se(!rs_credential_glob_valid(""));
}

static void test_credential_glob_valid_simple(void) {
        assert_se(rs_credential_glob_valid("mycred"));
}

static void test_credential_glob_valid_trailing_wildcard(void) {
        assert_se(rs_credential_glob_valid("mycred*"));
}

static void test_credential_glob_valid_full_wildcard(void) {
        assert_se(rs_credential_glob_valid("*"));
}

static void test_credential_glob_valid_prefix_with_hyphen(void) {
        assert_se(rs_credential_glob_valid("my-cred*"));
}

static void test_credential_glob_invalid_question_mark(void) {
        assert_se(!rs_credential_glob_valid("mycred?"));
}

static void test_credential_glob_invalid_bracket(void) {
        assert_se(!rs_credential_glob_valid("mycred[abc]"));
}

static void test_credential_glob_invalid_wildcard_not_at_end(void) {
        assert_se(!rs_credential_glob_valid("*mycred"));
}

static void test_credential_glob_invalid_multiple_wildcards(void) {
        assert_se(!rs_credential_glob_valid("my*cred*"));
}

int main(int argc, char *argv[]) {
        test_credential_name_valid_null();
        test_credential_name_valid_empty();
        test_credential_name_valid_simple();
        test_credential_name_valid_with_hyphen();
        test_credential_name_valid_with_underscore();
        test_credential_name_valid_with_dot();
        test_credential_name_valid_with_slash();
        test_credential_name_valid_with_dotdot();
        test_credential_glob_valid_null();
        test_credential_glob_valid_empty();
        test_credential_glob_valid_simple();
        test_credential_glob_valid_trailing_wildcard();
        test_credential_glob_valid_full_wildcard();
        test_credential_glob_valid_prefix_with_hyphen();
        test_credential_glob_invalid_question_mark();
        test_credential_glob_invalid_bracket();
        test_credential_glob_invalid_wildcard_not_at_end();
        test_credential_glob_invalid_multiple_wildcards();

        return 0;
}
