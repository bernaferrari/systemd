/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <string.h>

#include "efivars.h"
#include "tests.h"

TEST(efi_tilt_backslashes_basic) {
        _cleanup_free_ char *s = strdup("foo\\bar\\baz");

        efi_tilt_backslashes(s);
        ASSERT_STREQ(s, "foo/bar/baz");
}

TEST(efi_tilt_backslashes_none) {
        _cleanup_free_ char *s = strdup("foo/bar/baz");

        efi_tilt_backslashes(s);
        ASSERT_STREQ(s, "foo/bar/baz");
}

TEST(efi_tilt_backslashes_empty) {
        _cleanup_free_ char *s = strdup("");

        efi_tilt_backslashes(s);
        ASSERT_STREQ(s, "");
}

TEST(efi_tilt_backslashes_consecutive) {
        _cleanup_free_ char *s = strdup("a\\\\b");

        efi_tilt_backslashes(s);
        ASSERT_STREQ(s, "a//b");
}

TEST(efi_tilt_backslashes_leading) {
        _cleanup_free_ char *s = strdup("\\path");

        efi_tilt_backslashes(s);
        ASSERT_STREQ(s, "/path");
}

TEST(efi_tilt_backslashes_trailing) {
        _cleanup_free_ char *s = strdup("path\\");

        efi_tilt_backslashes(s);
        ASSERT_STREQ(s, "path/");
}

TEST(efi_variable_macros) {
        /* Verify EFI vendor variable string macros produce correct format */
        const char *global = EFI_GLOBAL_VARIABLE_STR("BootOrder");
        ASSERT_TRUE(startswith(global, "BootOrder-"));

        const char *loader = EFI_LOADER_VARIABLE_STR("LoaderEntrySelected");
        ASSERT_TRUE(startswith(loader, "LoaderEntrySelected-"));

        const char *systemd = EFI_SYSTEMD_VARIABLE_STR("StubInfo");
        ASSERT_TRUE(startswith(systemd, "StubInfo-"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
