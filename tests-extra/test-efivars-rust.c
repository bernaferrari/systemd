/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Shadow test: C secure_boot_mode_to_string/decode_secure_boot_mode/efi_tilt_backslashes vs Rust */

#include "tests.h"
#include "efivars.h"
#include "string-util.h"
#include "rust/efivars_util.h"

/* RUST-CONTRACT: secure-boot-mode-string */
static void test_secure_boot_mode_to_string(void) {
        const char *cr, *rr;

        /* Valid modes */
        for (int m = 0; m < _SECURE_BOOT_MAX; m++) {
                cr = secure_boot_mode_to_string(m);
                rr = rs_secure_boot_mode_to_string(m);
                assert_se(cr && rr);
                assert_se(streq(cr, rr));
        }

        /* Verify specific strings */
        assert_se(streq(rs_secure_boot_mode_to_string(SECURE_BOOT_UNSUPPORTED), "unsupported"));
        assert_se(streq(rs_secure_boot_mode_to_string(SECURE_BOOT_DISABLED), "disabled"));
        assert_se(streq(rs_secure_boot_mode_to_string(SECURE_BOOT_UNKNOWN), "unknown"));
        assert_se(streq(rs_secure_boot_mode_to_string(SECURE_BOOT_AUDIT), "audit"));
        assert_se(streq(rs_secure_boot_mode_to_string(SECURE_BOOT_DEPLOYED), "deployed"));
        assert_se(streq(rs_secure_boot_mode_to_string(SECURE_BOOT_SETUP), "setup"));
        assert_se(streq(rs_secure_boot_mode_to_string(SECURE_BOOT_USER), "user"));
        assert_se(streq(rs_secure_boot_mode_to_string(SECURE_BOOT_TAINTED), "tainted"));

        /* Invalid: negative */
        cr = secure_boot_mode_to_string(-1);
        rr = rs_secure_boot_mode_to_string(-1);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        cr = secure_boot_mode_to_string(-EINVAL);
        rr = rs_secure_boot_mode_to_string(-EINVAL);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        /* Invalid: out of range */
        cr = secure_boot_mode_to_string(_SECURE_BOOT_MAX);
        rr = rs_secure_boot_mode_to_string(_SECURE_BOOT_MAX);
        assert_se(cr == NULL);
        assert_se(rr == NULL);

        cr = secure_boot_mode_to_string(100);
        rr = rs_secure_boot_mode_to_string(100);
        assert_se(cr == NULL);
        assert_se(rr == NULL);
}

typedef struct {
        bool secure, audit, deployed, setup, moksb;
        SecureBootMode expected;
} DecodeTestCase;

/* RUST-CONTRACT: secure-boot-mode-decoding */
static void test_decode_secure_boot_mode(void) {
        /* All 32 combinations of 5 bools */
        static const DecodeTestCase cases[] = {
                /* secure  audit  deployed  setup  moksb   expected */
                { false,  false, false,    false, false,  SECURE_BOOT_DISABLED },
                { false,  false, false,    false, true,   SECURE_BOOT_DISABLED },
                { false,  false, false,    true,  false,  SECURE_BOOT_SETUP },
                { false,  false, false,    true,  true,   SECURE_BOOT_SETUP },
                { false,  false, true,     false, false,  SECURE_BOOT_UNKNOWN },
                { false,  false, true,     false, true,   SECURE_BOOT_UNKNOWN },
                { false,  false, true,     true,  false,  SECURE_BOOT_UNKNOWN },
                { false,  false, true,     true,  true,   SECURE_BOOT_UNKNOWN },
                { false,  true,  false,    false, false,  SECURE_BOOT_UNKNOWN },
                { false,  true,  false,    false, true,   SECURE_BOOT_UNKNOWN },
                { false,  true,  false,    true,  false,  SECURE_BOOT_AUDIT },
                { false,  true,  false,    true,  true,   SECURE_BOOT_AUDIT },
                { false,  true,  true,     false, false,  SECURE_BOOT_UNKNOWN },
                { false,  true,  true,     false, true,   SECURE_BOOT_UNKNOWN },
                { false,  true,  true,     true,  false,  SECURE_BOOT_UNKNOWN },
                { false,  true,  true,     true,  true,   SECURE_BOOT_UNKNOWN },
                { true,   false, false,    false, false,  SECURE_BOOT_USER },
                { true,   false, false,    false, true,   SECURE_BOOT_TAINTED },
                { true,   false, false,    true,  false,  SECURE_BOOT_UNKNOWN },
                { true,   false, false,    true,  true,   SECURE_BOOT_TAINTED },
                { true,   false, true,     false, false,  SECURE_BOOT_DEPLOYED },
                { true,   false, true,     false, true,   SECURE_BOOT_TAINTED },
                { true,   false, true,     true,  false,  SECURE_BOOT_UNKNOWN },
                { true,   false, true,     true,  true,   SECURE_BOOT_TAINTED },
                { true,   true,  false,    false, false,  SECURE_BOOT_UNKNOWN },
                { true,   true,  false,    false, true,   SECURE_BOOT_TAINTED },
                { true,   true,  false,    true,  false,  SECURE_BOOT_UNKNOWN },
                { true,   true,  false,    true,  true,   SECURE_BOOT_TAINTED },
                { true,   true,  true,     false, false,  SECURE_BOOT_UNKNOWN },
                { true,   true,  true,     false, true,   SECURE_BOOT_TAINTED },
                { true,   true,  true,     true,  false,  SECURE_BOOT_UNKNOWN },
                { true,   true,  true,     true,  true,   SECURE_BOOT_TAINTED },
        };

        for (size_t i = 0; i < ELEMENTSOF(cases); i++) {
                SecureBootMode cr = decode_secure_boot_mode(
                                cases[i].secure, cases[i].audit,
                                cases[i].deployed, cases[i].setup, cases[i].moksb);
                int rr = rs_decode_secure_boot_mode(
                                cases[i].secure, cases[i].audit,
                                cases[i].deployed, cases[i].setup, cases[i].moksb);
                assert_se(cr == rr);
                assert_se(cr == cases[i].expected);
        }
}

/* RUST-CONTRACT: efi-path-separator */
static void test_efi_tilt_backslashes(void) {
        /* Both modify in-place and return the same pointer */
        _cleanup_free_ char *r1 = strdup("foo\\bar\\baz");
        assert_se(r1);
        assert_se(streq(efi_tilt_backslashes(r1), "foo/bar/baz"));

        r1 = mfree(r1);
        r1 = strdup("foo\\bar\\baz");
        assert_se(streq(rs_efi_tilt_backslashes(r1), "foo/bar/baz"));

        /* Already forward slashes — no change */
        r1 = mfree(r1);
        r1 = strdup("foo/bar/baz");
        assert_se(streq(rs_efi_tilt_backslashes(r1), "foo/bar/baz"));

        /* Empty string */
        r1 = mfree(r1);
        r1 = strdup("");
        assert_se(streq(rs_efi_tilt_backslashes(r1), ""));

        /* No backslashes at all */
        r1 = mfree(r1);
        r1 = strdup("noslashes");
        assert_se(streq(rs_efi_tilt_backslashes(r1), "noslashes"));

        /* Single backslash */
        r1 = mfree(r1);
        r1 = strdup("\\");
        assert_se(streq(rs_efi_tilt_backslashes(r1), "/"));

        /* NULL input */
        assert_se(rs_efi_tilt_backslashes(NULL) == NULL);
}

int main(int argc, char **argv) {
        test_secure_boot_mode_to_string();
        test_decode_secure_boot_mode();
        test_efi_tilt_backslashes();
        return 0;
}
