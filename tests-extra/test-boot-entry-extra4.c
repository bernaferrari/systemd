/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "boot-entry.h"
#include "string-util.h"
#include "tests.h"

TEST(boot_entry_token_type_roundtrip) {
        for (int i = 0; i < _BOOT_ENTRY_TOKEN_TYPE_MAX; i++) {
                const char *s = boot_entry_token_type_to_string(i);
                assert_se(s);
                BootEntryTokenType v = boot_entry_token_type_from_string(s);
                assert_se(v == i);
        }
}

TEST(boot_entry_token_type_from_string_invalid) {
        assert_se(boot_entry_token_type_from_string("nonsense") == _BOOT_ENTRY_TOKEN_TYPE_INVALID);
        assert_se(boot_entry_token_type_from_string("") == _BOOT_ENTRY_TOKEN_TYPE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
