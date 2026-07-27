/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootspec.h"
#include "tests.h"

TEST(boot_entry_type_to_string) {
        ASSERT_STREQ(boot_entry_type_to_string(BOOT_ENTRY_TYPE1), "type1");
        ASSERT_STREQ(boot_entry_type_to_string(BOOT_ENTRY_TYPE2), "type2");
        ASSERT_STREQ(boot_entry_type_to_string(BOOT_ENTRY_LOADER), "loader");
        ASSERT_STREQ(boot_entry_type_to_string(BOOT_ENTRY_AUTO), "auto");
}

TEST(boot_entry_type_from_string) {
        ASSERT_EQ(boot_entry_type_from_string("type1"), BOOT_ENTRY_TYPE1);
        ASSERT_EQ(boot_entry_type_from_string("type2"), BOOT_ENTRY_TYPE2);
        ASSERT_EQ(boot_entry_type_from_string("loader"), BOOT_ENTRY_LOADER);
        ASSERT_EQ(boot_entry_type_from_string("auto"), BOOT_ENTRY_AUTO);
        ASSERT_EQ(boot_entry_type_from_string("invalid"), _BOOT_ENTRY_TYPE_INVALID);
}

TEST(boot_entry_source_to_string) {
        ASSERT_STREQ(boot_entry_source_to_string(BOOT_ENTRY_ESP), "esp");
        ASSERT_STREQ(boot_entry_source_to_string(BOOT_ENTRY_XBOOTLDR), "xbootldr");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
