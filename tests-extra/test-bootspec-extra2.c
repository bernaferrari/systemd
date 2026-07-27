/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootspec.h"
#include "string-util.h"
#include "tests.h"

TEST(boot_entry_type_to_string) {
        assert_se(streq(boot_entry_type_to_string(BOOT_ENTRY_TYPE1), "type1"));
        assert_se(streq(boot_entry_type_to_string(BOOT_ENTRY_TYPE2), "type2"));
        assert_se(streq(boot_entry_type_to_string(BOOT_ENTRY_LOADER), "loader"));
        assert_se(streq(boot_entry_type_to_string(BOOT_ENTRY_AUTO), "auto"));
}

TEST(boot_entry_type_from_string) {
        assert_se(boot_entry_type_from_string("type1") == BOOT_ENTRY_TYPE1);
        assert_se(boot_entry_type_from_string("type2") == BOOT_ENTRY_TYPE2);
        assert_se(boot_entry_type_from_string("loader") == BOOT_ENTRY_LOADER);
        assert_se(boot_entry_type_from_string("auto") == BOOT_ENTRY_AUTO);
        assert_se(boot_entry_type_from_string("invalid") == _BOOT_ENTRY_TYPE_INVALID);
}

TEST(boot_entry_type_description_to_string) {
        const char *s;

        s = boot_entry_type_description_to_string(BOOT_ENTRY_TYPE1);
        assert_se(s && strstr(s, "Type #1"));

        s = boot_entry_type_description_to_string(BOOT_ENTRY_TYPE2);
        assert_se(s && strstr(s, "Type #2"));

        s = boot_entry_type_description_to_string(BOOT_ENTRY_LOADER);
        assert_se(s && strstr(s, "Boot Loader"));

        s = boot_entry_type_description_to_string(BOOT_ENTRY_AUTO);
        assert_se(s && strstr(s, "Automatic"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
