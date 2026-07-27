/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "specifier.h"
#include "string-util.h"
#include "tests.h"

static int test_lookup(char specifier, const void *data, const char *root, const void *userdata, char **ret) {
        const char *val = data;
        if (!val)
                return -ENOENT;
        return strdup_to(ret, val);
}

TEST(specifier_printf_plain) {
        _cleanup_free_ char *result = NULL;
        int r;

        /* No specifiers */
        r = specifier_printf("hello world", SIZE_MAX, (const Specifier[]){{}}, NULL, NULL, &result);
        assert_se(r >= 0);
        assert_se(streq(result, "hello world"));
}

TEST(specifier_printf_escaped_percent) {
        _cleanup_free_ char *result = NULL;
        int r;

        /* %% → % */
        r = specifier_printf("100%%", SIZE_MAX, (const Specifier[]){{}}, NULL, NULL, &result);
        assert_se(r >= 0);
        assert_se(streq(result, "100%"));
}

TEST(specifier_printf_custom) {
        _cleanup_free_ char *result = NULL;
        int r;

        const Specifier table[] = {
                { 'n', test_lookup, (void*)"testname" },
                { 'v', test_lookup, (void*)"1.0" },
                {}
        };

        r = specifier_printf("name=%n version=%v", SIZE_MAX, table, NULL, NULL, &result);
        assert_se(r >= 0);
        assert_se(streq(result, "name=testname version=1.0"));
}

TEST(specifier_printf_empty_replacement) {
        _cleanup_free_ char *result = NULL;
        int r;

        /* Empty replacement is skipped */
        const Specifier table[] = {
                { 'e', test_lookup, (void*)"" },
                { 'n', test_lookup, (void*)"name" },
                {}
        };

        r = specifier_printf("a%en", SIZE_MAX, table, NULL, NULL, &result);
        assert_se(r >= 0);
        assert_se(streq(result, "an"));
}

TEST(specifier_printf_unknown_specifier) {
        _cleanup_free_ char *result = NULL;

        /* Known letter with no lookup → EBADSLT */
        const Specifier table[] = {
                { 'a', test_lookup, (void*)"value" },
                {}
        };

        assert_se(specifier_printf("%b", SIZE_MAX, table, NULL, NULL, &result) == -EBADSLT);
}

TEST(specifier_printf_trailing_percent) {
        _cleanup_free_ char *result = NULL;
        int r;

        /* String ending with single % */
        r = specifier_printf("test%", SIZE_MAX, (const Specifier[]){{}}, NULL, NULL, &result);
        assert_se(r >= 0);
        assert_se(streq(result, "test%"));
}

TEST(specifier_printf_max_length) {
        _cleanup_free_ char *result = NULL;

        const Specifier table[] = {
                { 'x', test_lookup, (void*)"longvalue" },
                {}
        };

        /* Should fail when result exceeds max_length */
        assert_se(specifier_printf("%x", 5, table, NULL, NULL, &result) == -ENAMETOOLONG);
}

TEST(specifier_string) {
        _cleanup_free_ char *result = NULL;
        int r;

        /* specifier_string with valid data */
        r = specifier_string('s', "hello", NULL, NULL, &result);
        assert_se(r >= 0);
        assert_se(streq(result, "hello"));

        result = mfree(result);
        /* specifier_string with empty data → empty_to_null → NULL → strdup_to(NULL) → result is NULL */
        const char *empty = "";
        r = specifier_string('s', empty, NULL, NULL, &result);
        assert_se(r >= 0);
        assert_se(result == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
