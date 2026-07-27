/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-loader.h"
#include "tests.h"

TEST(efi_loader_entry_name_valid) {
        ASSERT_TRUE(efi_loader_entry_name_valid("linux"));
        ASSERT_TRUE(efi_loader_entry_name_valid("linux-5.15.0"));
        ASSERT_TRUE(efi_loader_entry_name_valid("entry+test"));
        ASSERT_FALSE(efi_loader_entry_name_valid(""));
        ASSERT_FALSE(efi_loader_entry_name_valid(NULL));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
