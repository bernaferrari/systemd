/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C boot-entry.c boot_entry_token_valid vs Rust */

#include <assert.h>
#include <string.h>
#include "tests.h"

/* C headers */
#include "boot-entry.h"

/* Rust FFI */
#include "rust/shared_facades/validation.h"

/* -- boot_entry_token_valid ----------------------------------------------- */

static void test_boot_entry_token_valid(void) {
        /* Valid tokens: alphanumeric, safe chars, valid filenames */
        assert_se(boot_entry_token_valid("abc") == rs_boot_entry_token_valid("abc"));
        assert_se(boot_entry_token_valid("abc") == true);

        assert_se(boot_entry_token_valid("my-token") == rs_boot_entry_token_valid("my-token"));
        assert_se(boot_entry_token_valid("my-token") == true);

        assert_se(boot_entry_token_valid("token_123") == rs_boot_entry_token_valid("token_123"));
        assert_se(boot_entry_token_valid("token_123") == true);

        assert_se(boot_entry_token_valid("a.b.c") == rs_boot_entry_token_valid("a.b.c"));
        assert_se(boot_entry_token_valid("a.b.c") == true);

        /* Invalid tokens */
        assert_se(boot_entry_token_valid("") == rs_boot_entry_token_valid(""));
        assert_se(boot_entry_token_valid("") == false);

        assert_se(boot_entry_token_valid("token/") == rs_boot_entry_token_valid("token/"));
        assert_se(boot_entry_token_valid("token/") == false);

        assert_se(boot_entry_token_valid("../evil") == rs_boot_entry_token_valid("../evil"));
        assert_se(boot_entry_token_valid("../evil") == false);

        /* Both implementations reject NULL before UTF-8 validation. */
        assert_se(boot_entry_token_valid(NULL) == rs_boot_entry_token_valid(NULL));
        assert_se(rs_boot_entry_token_valid(NULL) == false);

        /* STRING_FILENAME requires valid UTF-8, but not ASCII-only input. */
        assert_se(boot_entry_token_valid("caf\xc3\xa9") == rs_boot_entry_token_valid("caf\xc3\xa9"));
        assert_se(boot_entry_token_valid("caf\xc3\xa9") == true);
        assert_se(boot_entry_token_valid("bad*glob") == rs_boot_entry_token_valid("bad*glob"));
        assert_se(boot_entry_token_valid("bad*glob") == false);
}

int main(int argc, char **argv) {
        test_boot_entry_token_valid();
        return 0;
}
