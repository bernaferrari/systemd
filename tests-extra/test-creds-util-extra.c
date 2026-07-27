/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "creds-util.h"
#include "tests.h"

TEST(credential_name_valid) {
        ASSERT_TRUE(credential_name_valid("valid.name"));
        ASSERT_TRUE(credential_name_valid("simple"));
        ASSERT_FALSE(credential_name_valid(""));
        ASSERT_FALSE(credential_name_valid(NULL));
}

TEST(credential_glob_valid) {
        /* Plain names are valid globs (no wildcard) */
        ASSERT_TRUE(credential_glob_valid("cred"));
        ASSERT_TRUE(credential_name_valid("cred"));
        /* Trailing asterisk is valid */
        ASSERT_TRUE(credential_glob_valid("cred.*"));
        /* Empty is invalid */
        ASSERT_FALSE(credential_glob_valid(""));
        /* Asterisk not at end is invalid */
        ASSERT_FALSE(credential_glob_valid("cred.*.suffix"));
        ASSERT_FALSE(credential_glob_valid("cred*.name"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
