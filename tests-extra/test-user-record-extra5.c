/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "strv.h"
#include "tests.h"
#include "user-record.h"

TEST(suitable_blob_filename) {
        /* Valid filenames */
        assert_se(suitable_blob_filename("hello") > 0);
        assert_se(suitable_blob_filename("file.txt") > 0);
        assert_se(suitable_blob_filename("my-blob") > 0);
        assert_se(suitable_blob_filename("a") > 0);

        /* Invalid: empty */
        assert_se(suitable_blob_filename("") == 0);

        /* Invalid: starts with dot */
        assert_se(suitable_blob_filename(".hidden") == 0);
        assert_se(suitable_blob_filename("..") == 0);

        /* Invalid: contains non-URI-unreserved chars (space, /, etc.) */
        assert_se(suitable_blob_filename("my file") == 0);
        assert_se(suitable_blob_filename("dir/file") == 0);
        assert_se(suitable_blob_filename("file?query") == 0);
}

TEST(user_name_fuzzy_match) {
        const char *names[] = { "JohnDoe", "JaneSmith" };
        const char *names2[] = { "systemd-network" };
        _cleanup_strv_free_ char **matches1 = NULL;
        _cleanup_strv_free_ char **matches2 = NULL;

        matches1 = strv_new("johndoe");
        assert_se(matches1);

        /* Exact lowercase match */
        assert_se(user_name_fuzzy_match(names, 1, matches1) == true);

        /* Substring match */
        strv_free(matches1);
        matches1 = strv_new("john");
        assert_se(matches1);
        assert_se(user_name_fuzzy_match(names, 1, matches1) == true);

        /* No match */
        strv_free(matches1);
        matches1 = strv_new("zzzzz");
        assert_se(matches1);
        assert_se(user_name_fuzzy_match(names, 1, matches1) == false);

        /* Case insensitive */
        strv_free(matches1);
        matches1 = strv_new("JOHNDOE");
        assert_se(matches1);
        assert_se(user_name_fuzzy_match(names, 1, matches1) == true);

        /* Multiple names, match on second */
        strv_free(matches1);
        matches1 = strv_new("jane");
        assert_se(matches1);
        assert_se(user_name_fuzzy_match(names, 2, matches1) == true);

        /* Fuzzy match (Levenshtein distance < 3, needle >= 5 chars) */
        strv_free(matches1);
        matches1 = strv_new("systemd-netwerk"); /* one char diff from "systemd-network" */
        assert_se(matches1);
        assert_se(user_name_fuzzy_match(names2, 1, matches1) == true);

        /* Empty matches → no match */
        matches2 = strv_new(NULL);
        assert_se(user_name_fuzzy_match(names, 1, matches2) == false);

        /* Zero names → no match */
        assert_se(user_name_fuzzy_match(NULL, 0, matches1) == false);
}

TEST(userdb_match_is_set) {
        /* Default/initialized match has disposition_mask=ALL, which means NOT set */
        UserDBMatch m_default = USERDB_MATCH_NULL;
        assert_se(userdb_match_is_set(&m_default) == false);

        /* NULL → false */
        assert_se(userdb_match_is_set(NULL) == false);

        /* With fuzzy_names set → true */
        UserDBMatch m2 = USERDB_MATCH_NULL;
        m2.fuzzy_names = strv_new("test");
        assert_se(userdb_match_is_set(&m2) == true);
        m2.fuzzy_names = strv_free(m2.fuzzy_names);

        /* With disposition_mask not equal to ALL → true (something was filtered) */
        UserDBMatch m3 = USERDB_MATCH_NULL;
        m3.disposition_mask = 0;
        assert_se(userdb_match_is_set(&m3) == true);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
