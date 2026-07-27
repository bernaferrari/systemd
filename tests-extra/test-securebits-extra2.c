/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/securebits.h>

#include "securebits-util.h"
#include "string-util.h"
#include "strv.h"
#include "tests.h"

TEST(secure_bits_to_strv) {
        _cleanup_strv_free_ char **sv = NULL;
        int r;

        /* No bits set */
        r = secure_bits_to_strv(0, &sv);
        assert_se(r >= 0);
        assert_se(strv_isempty(sv));

        sv = strv_free(sv);
        /* Single bit */
        r = secure_bits_to_strv(1 << SECURE_KEEP_CAPS, &sv);
        assert_se(r >= 0);
        assert_se(strv_length(sv) == 1);
        assert_se(streq(sv[0], "keep-caps"));

        sv = strv_free(sv);
        /* Multiple bits */
        r = secure_bits_to_strv(
                        (1 << SECURE_NOROOT) | (1 << SECURE_NOROOT_LOCKED), &sv);
        assert_se(r >= 0);
        assert_se(strv_length(sv) == 2);
        assert_se(streq(sv[0], "noroot"));
        assert_se(streq(sv[1], "noroot-locked"));
}

TEST(secure_bits_to_string_alloc) {
        _cleanup_free_ char *s = NULL;
        int r;

        /* No bits */
        r = secure_bits_to_string_alloc(0, &s);
        assert_se(r >= 0);
        assert_se(streq(s, ""));

        s = mfree(s);
        /* Single bit */
        r = secure_bits_to_string_alloc(1 << SECURE_NO_SETUID_FIXUP, &s);
        assert_se(r >= 0);
        assert_se(streq(s, "no-setuid-fixup"));

        s = mfree(s);
        /* Multiple bits */
        r = secure_bits_to_string_alloc(
                        (1 << SECURE_KEEP_CAPS) | (1 << SECURE_KEEP_CAPS_LOCKED),
                        &s);
        assert_se(r >= 0);
        assert_se(streq(s, "keep-caps keep-caps-locked"));
}

TEST(secure_bits_from_string) {
        /* Empty */
        assert_se(secure_bits_from_string("") == 0);

        /* Single bit */
        assert_se(secure_bits_from_string("keep-caps") == (1 << SECURE_KEEP_CAPS));
        assert_se(secure_bits_from_string("noroot") == (1 << SECURE_NOROOT));
        assert_se(secure_bits_from_string("no-setuid-fixup") == (1 << SECURE_NO_SETUID_FIXUP));

        /* Multiple bits */
        int bits = secure_bits_from_string("keep-caps noroot");
        assert_se(FLAGS_SET(bits, 1 << SECURE_KEEP_CAPS));
        assert_se(FLAGS_SET(bits, 1 << SECURE_NOROOT));

        /* Unknown word is ignored */
        assert_se(secure_bits_from_string("unknown") == 0);
}

TEST(secure_bits_roundtrip) {
        for (int bit = SECURE_KEEP_CAPS; bit <= SECURE_NOROOT_LOCKED; bit++) {
                int val = 1 << bit;
                _cleanup_free_ char *s = NULL;
                int r;

                r = secure_bits_to_string_alloc(val, &s);
                assert_se(r >= 0);
                assert_se(!isempty(s));

                int parsed = secure_bits_from_string(s);
                assert_se(parsed == val);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
