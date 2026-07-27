/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efi-loader.h"
#include "string-util.h"
#include "tests.h"

TEST(efi_loader_entry_name_valid) {
        /* Valid names */
        assert_se(efi_loader_entry_name_valid("Linux"));
        assert_se(efi_loader_entry_name_valid("linux-6.1"));
        assert_se(efi_loader_entry_name_valid("entry.conf"));
        assert_se(efi_loader_entry_name_valid("my+os"));
        assert_se(efi_loader_entry_name_valid("test_entry"));
        assert_se(efi_loader_entry_name_valid("a"));

        /* Invalid names */
        assert_se(!efi_loader_entry_name_valid(""));       /* empty */
        assert_se(!efi_loader_entry_name_valid("."));      /* dot only */
        assert_se(!efi_loader_entry_name_valid(".."));     /* double dot */
        assert_se(!efi_loader_entry_name_valid("my entry")); /* space */
        assert_se(!efi_loader_entry_name_valid("my/os"));  /* slash */
}

DEFINE_TEST_MAIN(LOG_DEBUG);
