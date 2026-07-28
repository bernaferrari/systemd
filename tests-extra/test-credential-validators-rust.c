/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <assert.h>
#include <limits.h>
#include <string.h>

#include "tests.h"
#include "creds-util.h"
#include "rust/credential_validators.h"

static void assert_credential_name_matches(const char *name) {
        assert_se(credential_name_valid(name) == rs_credential_name_valid(name));
}

static void assert_credential_glob_matches(const char *name) {
        assert_se(credential_glob_valid(name) == rs_credential_glob_valid(name));
}

/* ── credential_name_valid ─────────────────────────────────────────────── */
/* RUST-CONTRACT: credential-name-validation */

static void test_credential_name_valid_null(void) {
        assert_credential_name_matches(NULL);
}

static void test_credential_name_valid_empty(void) {
        assert_credential_name_matches("");
}

static void test_credential_name_valid_simple(void) {
        assert_credential_name_matches("mycred");
}

static void test_credential_name_valid_with_hyphen(void) {
        assert_credential_name_matches("my-cred");
}

static void test_credential_name_valid_with_underscore(void) {
        assert_credential_name_matches("my_cred");
}

static void test_credential_name_valid_with_dot(void) {
        assert_credential_name_matches("my.cred");
}

static void test_credential_name_valid_with_slash(void) {
        assert_credential_name_matches("my/cred");
}

static void test_credential_name_valid_with_dotdot(void) {
        assert_credential_name_matches("..");
}

static void test_credential_name_valid_c_string_bytes(void) {
        const char non_ascii[] = { (char) 0xff, 0 };
        char longest[NAME_MAX + 2];

        memset(longest, 'x', sizeof(longest) - 1);
        longest[sizeof(longest) - 1] = 0;

        assert_credential_name_matches(non_ascii);
        assert_credential_name_matches(longest);
        longest[sizeof(longest) - 2] = 0;
        assert_credential_name_matches(longest);
}

/* ── credential_glob_valid ─────────────────────────────────────────────── */
/* RUST-CONTRACT: credential-glob-validation */

static void test_credential_glob_valid_null(void) {
        assert_credential_glob_matches(NULL);
}

static void test_credential_glob_valid_empty(void) {
        assert_credential_glob_matches("");
}

static void test_credential_glob_valid_simple(void) {
        assert_credential_glob_matches("mycred");
}

static void test_credential_glob_valid_trailing_wildcard(void) {
        assert_credential_glob_matches("mycred*");
}

static void test_credential_glob_valid_full_wildcard(void) {
        assert_credential_glob_matches("*");
}

static void test_credential_glob_valid_prefix_with_hyphen(void) {
        assert_credential_glob_matches("my-cred*");
}

static void test_credential_glob_invalid_question_mark(void) {
        assert_credential_glob_matches("mycred?");
}

static void test_credential_glob_invalid_bracket(void) {
        assert_credential_glob_matches("mycred[abc]");
}

static void test_credential_glob_invalid_wildcard_not_at_end(void) {
        assert_credential_glob_matches("*mycred");
}

static void test_credential_glob_invalid_multiple_wildcards(void) {
        assert_credential_glob_matches("my*cred*");
}

static void test_credential_glob_valid_c_string_bytes(void) {
        const char non_ascii[] = { (char) 0xff, 0 };
        char longest[NAME_MAX + 2];

        memset(longest, 'x', sizeof(longest) - 1);
        longest[sizeof(longest) - 1] = 0;

        assert_credential_glob_matches(non_ascii);
        assert_credential_glob_matches(longest);
        longest[sizeof(longest) - 2] = '*';
        assert_credential_glob_matches(longest);
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
        test_credential_name_valid_c_string_bytes();
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
        test_credential_glob_valid_c_string_bytes();

        return 0;
}
