/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "boot-entry.h"
#include "tests.h"

TEST(boot_entry_token_valid_basic) {
        /* Valid tokens: valid UTF-8, safe string, valid filename */
        assert_se(boot_entry_token_valid("mytoken"));
        assert_se(boot_entry_token_valid("Linux"));
        assert_se(boot_entry_token_valid("1234"));
        assert_se(boot_entry_token_valid("a"));

        /* Invalid: empty string (not valid filename) */
        assert_se(!boot_entry_token_valid(""));

        /* Invalid: contains control characters (not safe) */
        assert_se(!boot_entry_token_valid("abc\x1" "def"));

        /* Invalid: contains path separator */
        assert_se(!boot_entry_token_valid("abc/def"));

        /* Invalid: . and .. are not valid filenames */
        assert_se(!boot_entry_token_valid("."));
        assert_se(!boot_entry_token_valid(".."));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
