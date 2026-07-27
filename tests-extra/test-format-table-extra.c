/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-table.h"
#include "string-util.h"
#include "tests.h"

TEST(table_mangle_to_json_field_name_basic) {
        _cleanup_free_ char *s = NULL;

        /* Spaces → underscores */
        s = table_mangle_to_json_field_name("hello world");
        assert_se(s);
        assert_se(streq(s, "hello_world"));
        s = mfree(s);

        /* Dashes → underscores */
        s = table_mangle_to_json_field_name("foo-bar-baz");
        assert_se(s);
        assert_se(streq(s, "foo_bar_baz"));
        s = mfree(s);

        /* Already clean */
        s = table_mangle_to_json_field_name("simple");
        assert_se(s);
        assert_se(streq(s, "simple"));
        s = mfree(s);

        /* Mixed special chars → underscores */
        s = table_mangle_to_json_field_name("a b-c.d");
        assert_se(s);
        assert_se(!strchr(s, ' '));
        assert_se(!strchr(s, '-'));
        s = mfree(s);

        /* CamelCase words → first letter lowercase */
        s = table_mangle_to_json_field_name("Hello World");
        assert_se(s);
        assert_se(s[0] == 'h'); /* first letter lowercased */
        s = mfree(s);

        /* All uppercase word stays uppercase */
        s = table_mangle_to_json_field_name("UUID");
        assert_se(s);
        assert_se(streq(s, "UUID"));
        s = mfree(s);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
