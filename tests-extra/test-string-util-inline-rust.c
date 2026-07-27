/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C string-util inline functions vs native Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"
#include "string-util.h"
#include "rust/string_util.h"

static void test_strnull(void) {
        assert_se(streq(rs_strnull(NULL), strnull(NULL)));
        assert_se(streq(rs_strnull("hello"), strnull("hello")));
        assert_se(streq(rs_strnull(""), strnull("")));
}

static void test_strna(void) {
        assert_se(streq(rs_strna(NULL), strna(NULL)));
        assert_se(streq(rs_strna("hello"), strna("hello")));
        assert_se(streq(rs_strna(""), strna("")));
}

static void test_true_false(void) {
        assert_se(streq(rs_true_false(true), true_false(true)));
        assert_se(streq(rs_true_false(false), true_false(false)));
}

static void test_plus_minus(void) {
        assert_se(streq(rs_plus_minus(true), plus_minus(true)));
        assert_se(streq(rs_plus_minus(false), plus_minus(false)));
}

static void test_one_zero(void) {
        assert_se(streq(rs_one_zero(true), one_zero(true)));
        assert_se(streq(rs_one_zero(false), one_zero(false)));
}

static void test_enable_disable(void) {
        assert_se(streq(rs_enable_disable(true), enable_disable(true)));
        assert_se(streq(rs_enable_disable(false), enable_disable(false)));
}

static void test_enabled_disabled(void) {
        assert_se(streq(rs_enabled_disabled(true), enabled_disabled(true)));
        assert_se(streq(rs_enabled_disabled(false), enabled_disabled(false)));
}

static void test_empty_to_na(void) {
        assert_se(streq(rs_empty_to_na(NULL), empty_to_na(NULL)));
        assert_se(streq(rs_empty_to_na(""), empty_to_na("")));
        assert_se(streq(rs_empty_to_na("hello"), empty_to_na("hello")));
}

static void test_empty_to_dash(void) {
        assert_se(streq(rs_empty_to_dash(NULL), empty_to_dash(NULL)));
        assert_se(streq(rs_empty_to_dash(""), empty_to_dash("")));
        assert_se(streq(rs_empty_to_dash("hello"), empty_to_dash("hello")));
}

static void test_empty_or_dash(void) {
        assert_se(rs_empty_or_dash(NULL) == empty_or_dash(NULL));
        assert_se(rs_empty_or_dash("") == empty_or_dash(""));
        assert_se(rs_empty_or_dash("-") == empty_or_dash("-"));
        assert_se(rs_empty_or_dash("hello") == empty_or_dash("hello"));
        assert_se(rs_empty_or_dash("--") == empty_or_dash("--"));
        assert_se(rs_empty_or_dash("a-") == empty_or_dash("a-"));
}

static void test_empty_or_dash_to_null(void) {
        /* empty_or_dash_to_null is a statement-expression macro in C that
         * preserves const-ness; we can only test the non-const case */
        assert_se(rs_empty_or_dash_to_null(NULL) == NULL);
        assert_se(rs_empty_or_dash_to_null("") == NULL);
        assert_se(rs_empty_or_dash_to_null("-") == NULL);
        assert_se(streq(rs_empty_or_dash_to_null("hello"), "hello"));
}

int main(int argc, char **argv) {
        test_strnull();
        test_strna();
        test_true_false();
        test_plus_minus();
        test_one_zero();
        test_enable_disable();
        test_enabled_disabled();
        test_empty_to_na();
        test_empty_to_dash();
        test_empty_or_dash();
        test_empty_or_dash_to_null();
        return 0;
}
