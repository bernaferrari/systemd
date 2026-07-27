/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "efivars.h"
#include "string-util.h"
#include "tests.h"

TEST(is_efi_boot_basic) {
        bool b = is_efi_boot();
        log_debug("is_efi_boot: %d", b);
}

TEST(is_efi_secure_boot_basic) {
        bool b = is_efi_secure_boot();
        log_debug("is_efi_secure_boot: %d", b);
}

TEST(efi_get_secure_boot_mode_basic) {
        SecureBootMode m = efi_get_secure_boot_mode();
        log_debug("efi_get_secure_boot_mode: %d", m);
}

TEST(efi_get_variable_basic) {
        _cleanup_free_ void *val = NULL;
        size_t size = 0;
        uint32_t attr = 0;
        int r = efi_get_variable("SecureBoot", &attr, &val, &size);
        log_debug("efi_get_variable(SecureBoot): %d", r);
}

TEST(efi_get_variable_string_basic) {
        _cleanup_free_ char *val = NULL;
        int r = efi_get_variable_string("SecureBoot", &val);
        log_debug("efi_get_variable_string: %d", r);
}

TEST(efi_tilt_backslashes_basic) {
        char s[] = "test\\path\\name";
        char *r = efi_tilt_backslashes(s);
        assert_se(r == s);
        assert_se(streq(s, "test/path/name"));

        char s2[] = "no-backslash";
        r = efi_tilt_backslashes(s2);
        assert_se(streq(s2, "no-backslash"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
