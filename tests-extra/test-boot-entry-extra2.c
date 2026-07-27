/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "boot-entry.h"
#include "tests.h"

TEST(boot_entry_token_type_to_from_string) {
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
        assert_se(boot_entry_token_type_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
