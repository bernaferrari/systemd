/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "user-record.h"

TEST(suitable_blob_filename) {
        /* Valid filenames */
        assert_se(suitable_blob_filename("test") > 0);
        assert_se(suitable_blob_filename("my-blob") > 0);
        assert_se(suitable_blob_filename("file123") > 0);
        assert_se(suitable_blob_filename("abc_def") > 0);
        assert_se(suitable_blob_filename("a") > 0);

        /* Invalid: empty */
        assert_se(suitable_blob_filename("") == 0);

        /* Invalid: starts with dot */
        assert_se(suitable_blob_filename(".hidden") == 0);
        assert_se(suitable_blob_filename("..") == 0);

        /* Invalid: contains special chars */
        assert_se(suitable_blob_filename("test/file") == 0);
        assert_se(suitable_blob_filename("test file") == 0);
        assert_se(suitable_blob_filename("test@blob") == 0);

        /* Invalid: just a dot or parent ref */
        assert_se(suitable_blob_filename(".") == 0);
}

TEST(userdb_match_is_set_null) {
        /* NULL match is not set */
        assert_se(!userdb_match_is_set(NULL));
}

TEST(user_name_fuzzy_match_basic) {
        const char *names[] = { "John Doe", "Jane Smith" };

        /* Exact match */
        assert_se(user_name_fuzzy_match(names, ELEMENTSOF(names), STRV_MAKE("John Doe")));

        /* Case-insensitive match */
        assert_se(user_name_fuzzy_match(names, ELEMENTSOF(names), STRV_MAKE("john doe")));

        /* Substring match */
        assert_se(user_name_fuzzy_match(names, ELEMENTSOF(names), STRV_MAKE("john")));

        /* No match */
        assert_se(!user_name_fuzzy_match(names, ELEMENTSOF(names), STRV_MAKE("Bob")));

        /* Empty matches list */
        assert_se(!user_name_fuzzy_match(names, ELEMENTSOF(names), STRV_MAKE(NULL)));

        /* NULL names array with n_names=0 */
        assert_se(!user_name_fuzzy_match(NULL, 0, STRV_MAKE("test")));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
