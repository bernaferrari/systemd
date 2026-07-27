/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootspec.h"
#include "string-util.h"
#include "tests.h"

TEST(boot_entry_type_to_from_string) {
        assert_se(streq(boot_entry_type_to_string(BOOT_ENTRY_TYPE1), "type1"));
        assert_se(streq(boot_entry_type_to_string(BOOT_ENTRY_TYPE2), "type2"));
        assert_se(streq(boot_entry_type_to_string(BOOT_ENTRY_LOADER), "loader"));
        assert_se(streq(boot_entry_type_to_string(BOOT_ENTRY_AUTO), "auto"));

        assert_se(boot_entry_type_from_string("type1") == BOOT_ENTRY_TYPE1);
        assert_se(boot_entry_type_from_string("type2") == BOOT_ENTRY_TYPE2);
        assert_se(boot_entry_type_from_string("loader") == BOOT_ENTRY_LOADER);
        assert_se(boot_entry_type_from_string("auto") == BOOT_ENTRY_AUTO);
        assert_se(boot_entry_type_from_string("invalid") < 0);
}

TEST(boot_entry_type_description_to_string) {
        assert_se(streq(boot_entry_type_description_to_string(BOOT_ENTRY_TYPE1),
                         "Boot Loader Specification Type #1 (.conf)"));
        assert_se(streq(boot_entry_type_description_to_string(BOOT_ENTRY_TYPE2),
                         "Boot Loader Specification Type #2 (UKI, .efi)"));
        assert_se(streq(boot_entry_type_description_to_string(BOOT_ENTRY_LOADER),
                         "Reported by Boot Loader"));
        assert_se(streq(boot_entry_type_description_to_string(BOOT_ENTRY_AUTO),
                         "Automatic"));
        assert_se(boot_entry_type_description_to_string(999) == NULL);
}

TEST(boot_entry_source_description_to_string) {
        assert_se(streq(boot_entry_source_description_to_string(BOOT_ENTRY_ESP),
                         "EFI System Partition"));
        assert_se(streq(boot_entry_source_description_to_string(BOOT_ENTRY_XBOOTLDR),
                         "Extended Boot Loader Partition"));
        assert_se(boot_entry_source_description_to_string(999) == NULL);
}

TEST(boot_entry_source_to_string) {
        assert_se(streq(boot_entry_source_to_string(BOOT_ENTRY_ESP), "esp"));
        assert_se(streq(boot_entry_source_to_string(BOOT_ENTRY_XBOOTLDR), "xbootldr"));
        assert_se(boot_entry_source_to_string(999) == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
