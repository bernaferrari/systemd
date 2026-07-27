/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-loader.h"
#include "string-util.h"
#include "tests.h"

TEST(efi_loader_entry_name_valid) {
        /* Valid names */
        assert_se(efi_loader_entry_name_valid("linux") == true);
        assert_se(efi_loader_entry_name_valid("Linux123") == true);
        assert_se(efi_loader_entry_name_valid("my-entry") == true);
        assert_se(efi_loader_entry_name_valid("entry.conf") == true);
        assert_se(efi_loader_entry_name_valid("a_b") == true);
        assert_se(efi_loader_entry_name_valid("entry@spec") == true);
        assert_se(efi_loader_entry_name_valid("entry+special") == true);
        assert_se(efi_loader_entry_name_valid(".hidden") == true); /* dot is in charset */

        /* Invalid: empty */
        assert_se(efi_loader_entry_name_valid("") == false);

        /* Invalid: contains space */
        assert_se(efi_loader_entry_name_valid("my entry") == false);

        /* Invalid: contains slash */
        assert_se(efi_loader_entry_name_valid("dir/file") == false);

        /* Invalid: starts with dot but contains special chars outside allowed set */
        assert_se(efi_loader_entry_name_valid("entry#1") == false);
        assert_se(efi_loader_entry_name_valid("entry!bang") == false);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
