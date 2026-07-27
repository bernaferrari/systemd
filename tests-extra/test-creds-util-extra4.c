/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "creds-util.h"
#include "tests.h"

TEST(credential_name_valid_basic) {
        /* Valid names */
        assert_se(credential_name_valid("foo"));
        assert_se(credential_name_valid("a"));
        assert_se(credential_name_valid("hello-world"));
        assert_se(credential_name_valid("test.cred"));
        assert_se(credential_name_valid(".hidden"));

        /* Invalid: empty */
        assert_se(!credential_name_valid(""));

        /* Invalid: contains slash (rejected by filename_is_valid) */
        assert_se(!credential_name_valid("foo/bar"));

        /* Invalid: contains colon (rejected by fdname_is_valid) */
        assert_se(!credential_name_valid("foo:bar"));

        /* Invalid: dot and dot-dot (rejected by filename_is_valid) */
        assert_se(!credential_name_valid("."));
        assert_se(!credential_name_valid(".."));
}

TEST(credential_glob_valid_basic) {
        /* Simple valid name (delegates to credential_name_valid) */
        assert_se(credential_glob_valid("foo"));
        assert_se(credential_glob_valid("hello"));

        /* Complete wildcard */
        assert_se(credential_glob_valid("*"));

        /* Trailing asterisk with valid prefix */
        assert_se(credential_glob_valid("prefix*"));

        /* Invalid: empty */
        assert_se(!credential_glob_valid(""));

        /* Invalid: question mark glob */
        assert_se(!credential_glob_valid("foo?"));

        /* Invalid: bracket glob */
        assert_se(!credential_glob_valid("foo[bar]"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
