/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "replace-var.h"
#include "string-util.h"
#include "tests.h"

static char *test_lookup(const char *variable, void *userdata) {
        if (streq(variable, "FOO"))
                return strdup("bar");
        if (streq(variable, "NUMBER"))
                return strdup("42");
        if (streq(variable, "EMPTY"))
                return strdup("");
        return NULL;
}

TEST(replace_var_basic) {
        _cleanup_free_ char *result = NULL;

        /* No variables */
        result = replace_var("hello world", test_lookup, NULL);
        assert_se(result);
        assert_se(streq(result, "hello world"));
        result = mfree(result);

        /* Single variable */
        result = replace_var("hello @FOO@ world", test_lookup, NULL);
        assert_se(result);
        assert_se(streq(result, "hello bar world"));
        result = mfree(result);

        /* Multiple variables */
        result = replace_var("@FOO@ = @NUMBER@", test_lookup, NULL);
        assert_se(result);
        assert_se(streq(result, "bar = 42"));
        result = mfree(result);

        /* Empty replacement */
        result = replace_var("before@EMPTY@after", test_lookup, NULL);
        assert_se(result);
        assert_se(streq(result, "beforeafter"));
        result = mfree(result);

        /* Only variable */
        result = replace_var("@FOO@", test_lookup, NULL);
        assert_se(result);
        assert_se(streq(result, "bar"));
        result = mfree(result);

        /* Unknown variable → lookup returns NULL → function returns NULL */
        result = replace_var("@UNKNOWN@", test_lookup, NULL);
        assert_se(result == NULL);
}

TEST(replace_var_no_match) {
        _cleanup_free_ char *result = NULL;

        /* Not a valid variable (lowercase) */
        result = replace_var("hello @foo@ world", test_lookup, NULL);
        assert_se(result);
        assert_se(streq(result, "hello @foo@ world"));
        result = mfree(result);

        /* Single @ is not a variable */
        result = replace_var("price: $100@2pcs", test_lookup, NULL);
        assert_se(result);
        assert_se(streq(result, "price: $100@2pcs"));
        result = mfree(result);

        /* @@ with nothing between */
        result = replace_var("hello@@world", test_lookup, NULL);
        assert_se(result);
        assert_se(streq(result, "hello@@world"));
        result = mfree(result);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
