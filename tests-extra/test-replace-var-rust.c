/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C replace_var vs Rust rs_replace_var */

#include <string.h>

#include "replace-var.h"
#include "rust/replace_var.h"
#include "string-util.h"

static char *test_lookup(const char *variable, void *userdata) {
        if (streq(variable, "FOO"))
                return strdup("hello");
        if (streq(variable, "BAR"))
                return strdup("world");
        if (streq(variable, "EMPTY"))
                return strdup("");
        return strdup("UNKNOWN");
}

/* ── basic replacement ────────────────────────────────────────────────── */

static void test_replace_var_basic(void) {
        const char *text = "Hello @FOO@, welcome to @BAR@!";
        char *c_result = replace_var(text, test_lookup, NULL);
        char *r_result = rs_replace_var(text, test_lookup, NULL);

        assert_se(c_result != NULL);
        assert_se(r_result != NULL);
        assert_se(streq(c_result, r_result));
        assert_se(streq(c_result, "Hello hello, welcome to world!"));

        free(c_result);
        free(r_result);
}

/* ── empty replacement ────────────────────────────────────────────────── */

static void test_replace_var_empty_replacement(void) {
        const char *text = "before@EMPTY@after";
        char *c_result = replace_var(text, test_lookup, NULL);
        char *r_result = rs_replace_var(text, test_lookup, NULL);

        assert_se(c_result != NULL);
        assert_se(r_result != NULL);
        assert_se(streq(c_result, r_result));
        assert_se(streq(c_result, "beforeafter"));

        free(c_result);
        free(r_result);
}

/* ── no variables ─────────────────────────────────────────────────────── */

static void test_replace_var_no_variables(void) {
        const char *text = "No variables here!";
        char *c_result = replace_var(text, test_lookup, NULL);
        char *r_result = rs_replace_var(text, test_lookup, NULL);

        assert_se(c_result != NULL);
        assert_se(r_result != NULL);
        assert_se(streq(c_result, r_result));
        assert_se(streq(c_result, "No variables here!"));

        free(c_result);
        free(r_result);
}

/* ── partial match (not uppercase) ────────────────────────────────────── */

static void test_replace_var_partial_match(void) {
        const char *text = "@foo@ is not replaced, @FOO@ is";
        char *c_result = replace_var(text, test_lookup, NULL);
        char *r_result = rs_replace_var(text, test_lookup, NULL);

        assert_se(c_result != NULL);
        assert_se(r_result != NULL);
        assert_se(streq(c_result, r_result));
        assert_se(streq(c_result, "@foo@ is not replaced, hello is"));

        free(c_result);
        free(r_result);
}

/* ── multiple same variable ───────────────────────────────────────────── */

static void test_replace_var_multiple_same(void) {
        const char *text = "@FOO@ @FOO@ @FOO@";
        char *c_result = replace_var(text, test_lookup, NULL);
        char *r_result = rs_replace_var(text, test_lookup, NULL);

        assert_se(c_result != NULL);
        assert_se(r_result != NULL);
        assert_se(streq(c_result, r_result));
        assert_se(streq(c_result, "hello hello hello"));

        free(c_result);
        free(r_result);
}

/* ── Main ─────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
        test_replace_var_basic();
        test_replace_var_empty_replacement();
        test_replace_var_no_variables();
        test_replace_var_partial_match();
        test_replace_var_multiple_same();

        return 0;
}
