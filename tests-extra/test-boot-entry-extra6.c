/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "boot-entry.h"
#include "string-util.h"
#include "tests.h"

TEST(boot_entry_token_valid) {
        /* Valid tokens */
        assert_se(boot_entry_token_valid("test"));
        assert_se(boot_entry_token_valid("my-token"));
        assert_se(boot_entry_token_valid("Machine123"));
        assert_se(boot_entry_token_valid("a"));

        /* Invalid: empty */
        assert_se(!boot_entry_token_valid(""));

        /* Invalid: path separator */
        assert_se(!boot_entry_token_valid("test/token"));

        /* Invalid: not valid UTF-8 */
        assert_se(!boot_entry_token_valid("\xff\xfe"));

        /* Invalid: dot-dot */
        assert_se(!boot_entry_token_valid(".."));

        /* Valid: starts with dot (filename_is_valid allows it) */
        assert_se(boot_entry_token_valid(".hidden"));

        /* Boot entry token type roundtrip */
        assert_se(streq(boot_entry_token_type_to_string(BOOT_ENTRY_TOKEN_MACHINE_ID), "machine-id"));
        assert_se(streq(boot_entry_token_type_to_string(BOOT_ENTRY_TOKEN_OS_IMAGE_ID), "os-image-id"));
        assert_se(streq(boot_entry_token_type_to_string(BOOT_ENTRY_TOKEN_OS_ID), "os-id"));
        assert_se(streq(boot_entry_token_type_to_string(BOOT_ENTRY_TOKEN_LITERAL), "literal"));
        assert_se(streq(boot_entry_token_type_to_string(BOOT_ENTRY_TOKEN_AUTO), "auto"));

        assert_se(boot_entry_token_type_from_string("machine-id") == BOOT_ENTRY_TOKEN_MACHINE_ID);
        assert_se(boot_entry_token_type_from_string("os-image-id") == BOOT_ENTRY_TOKEN_OS_IMAGE_ID);
        assert_se(boot_entry_token_type_from_string("os-id") == BOOT_ENTRY_TOKEN_OS_ID);
        assert_se(boot_entry_token_type_from_string("literal") == BOOT_ENTRY_TOKEN_LITERAL);
        assert_se(boot_entry_token_type_from_string("auto") == BOOT_ENTRY_TOKEN_AUTO);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
