/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "securebits-util.h"
#include "string-util.h"
#include "tests.h"

TEST(secure_bits_to_string_alloc_basic) {
        _cleanup_free_ char *s = NULL;

        assert_se(secure_bits_to_string_alloc(SECBIT_KEEP_CAPS, &s) >= 0);
        assert_se(streq(s, "keep-caps"));
        s = mfree(s);

        assert_se(secure_bits_to_string_alloc(SECBIT_NO_SETUID_FIXUP, &s) >= 0);
        assert_se(streq(s, "no-setuid-fixup"));
        s = mfree(s);

        assert_se(secure_bits_to_string_alloc(SECBIT_NOROOT, &s) >= 0);
        assert_se(streq(s, "noroot"));
        s = mfree(s);

        assert_se(secure_bits_to_string_alloc(SECBIT_KEEP_CAPS_LOCKED, &s) >= 0);
        assert_se(streq(s, "keep-caps-locked"));
        s = mfree(s);

        assert_se(secure_bits_to_string_alloc(SECBIT_NO_SETUID_FIXUP_LOCKED, &s) >= 0);
        assert_se(streq(s, "no-setuid-fixup-locked"));
        s = mfree(s);

        assert_se(secure_bits_to_string_alloc(SECBIT_NOROOT_LOCKED, &s) >= 0);
        assert_se(streq(s, "noroot-locked"));
}

TEST(secure_bits_roundtrip) {
        /* Test that from_string(to_string(x)) == x for known bits */
        const char *names[] = {
                "keep-caps", "no-setuid-fixup", "noroot",
                "keep-caps-locked", "no-setuid-fixup-locked", "noroot-locked",
        };

        for (size_t i = 0; i < ELEMENTSOF(names); i++) {
                int val = secure_bits_from_string(names[i]);
                assert_se(val >= 0);
                _cleanup_free_ char *s = NULL;
                assert_se(secure_bits_to_string_alloc(val, &s) >= 0);
                assert_se(streq(s, names[i]));
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
