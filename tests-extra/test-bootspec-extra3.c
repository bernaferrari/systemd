/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bootspec.h"
#include "string-util.h"
#include "tests.h"

TEST(boot_entry_source_to_string) {
        const char *s;

        s = boot_entry_source_to_string(BOOT_ENTRY_ESP);
        assert_se(s && streq(s, "esp"));

        s = boot_entry_source_to_string(BOOT_ENTRY_XBOOTLDR);
        assert_se(s && streq(s, "xbootldr"));
}

TEST(boot_entry_source_description_to_string) {
        const char *s;

        s = boot_entry_source_description_to_string(BOOT_ENTRY_ESP);
        assert_se(s && strstr(s, "EFI System Partition"));

        s = boot_entry_source_description_to_string(BOOT_ENTRY_XBOOTLDR);
        assert_se(s && strstr(s, "Extended Boot Loader"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
