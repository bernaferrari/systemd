/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "boot-entry.h"
#include "string-util.h"
#include "tests.h"

TEST(boot_entry_token_valid_basic) {
        /* Valid tokens */
        assert_se(boot_entry_token_valid("test"));
        assert_se(boot_entry_token_valid("my-token"));
        assert_se(boot_entry_token_valid("a"));
        assert_se(boot_entry_token_valid("Machine123"));

        /* Invalid: empty */
        assert_se(!boot_entry_token_valid(""));

        /* Invalid: path separator */
        assert_se(!boot_entry_token_valid("a/b"));

        /* Invalid: dot */
        assert_se(!boot_entry_token_valid("."));

        /* Invalid: double dot */
        assert_se(!boot_entry_token_valid(".."));
}

TEST(parse_boot_entry_token_type) {
        BootEntryTokenType type = _BOOT_ENTRY_TOKEN_TYPE_INVALID;
        _cleanup_free_ char *token = NULL;
        int r;

        r = parse_boot_entry_token_type("machine-id", &type, &token);
        assert_se(r >= 0);
        assert_se(type == BOOT_ENTRY_TOKEN_MACHINE_ID);
        assert_se(token == NULL);

        r = parse_boot_entry_token_type("os-id", &type, &token);
        assert_se(r >= 0);
        assert_se(type == BOOT_ENTRY_TOKEN_OS_ID);
        assert_se(token == NULL);

        r = parse_boot_entry_token_type("os-image-id", &type, &token);
        assert_se(r >= 0);
        assert_se(type == BOOT_ENTRY_TOKEN_OS_IMAGE_ID);
        assert_se(token == NULL);

        /* Literal token: must use literal: prefix */
        token = mfree(token);
        r = parse_boot_entry_token_type("literal:mytoken", &type, &token);
        assert_se(r >= 0);
        assert_se(type == BOOT_ENTRY_TOKEN_LITERAL);
        assert_se(streq(token, "mytoken"));

        /* "auto" is not accepted by parse_boot_entry_token_type */
        token = mfree(token);
        r = parse_boot_entry_token_type("auto", &type, &token);
        assert_se(r < 0);

        /* Unknown string */
        r = parse_boot_entry_token_type("unknown", &type, &token);
        assert_se(r < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
