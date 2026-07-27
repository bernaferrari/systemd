/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "boot-entry.h"
#include "tests.h"

TEST(boot_entry_token_type_to_string) {
        ASSERT_STREQ(boot_entry_token_type_to_string(BOOT_ENTRY_TOKEN_MACHINE_ID), "machine-id");
        ASSERT_STREQ(boot_entry_token_type_to_string(BOOT_ENTRY_TOKEN_OS_IMAGE_ID), "os-image-id");
        ASSERT_STREQ(boot_entry_token_type_to_string(BOOT_ENTRY_TOKEN_OS_ID), "os-id");
        ASSERT_STREQ(boot_entry_token_type_to_string(BOOT_ENTRY_TOKEN_LITERAL), "literal");
        ASSERT_STREQ(boot_entry_token_type_to_string(BOOT_ENTRY_TOKEN_AUTO), "auto");
}

TEST(boot_entry_token_type_from_string) {
        ASSERT_EQ(boot_entry_token_type_from_string("machine-id"), BOOT_ENTRY_TOKEN_MACHINE_ID);
        ASSERT_EQ(boot_entry_token_type_from_string("os-image-id"), BOOT_ENTRY_TOKEN_OS_IMAGE_ID);
        ASSERT_EQ(boot_entry_token_type_from_string("os-id"), BOOT_ENTRY_TOKEN_OS_ID);
        ASSERT_EQ(boot_entry_token_type_from_string("literal"), BOOT_ENTRY_TOKEN_LITERAL);
        ASSERT_EQ(boot_entry_token_type_from_string("auto"), BOOT_ENTRY_TOKEN_AUTO);
        ASSERT_EQ(boot_entry_token_type_from_string("invalid"), _BOOT_ENTRY_TOKEN_TYPE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
