/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cryptsetup-util.h"
#include "string-util.h"
#include "tests.h"

TEST(mangle_none_basic) {
        /* NULL input returns NULL */
        assert_se(mangle_none(NULL) == NULL);

        /* Empty string returns NULL */
        assert_se(mangle_none("") == NULL);

        /* "-" returns NULL */
        assert_se(mangle_none("-") == NULL);

        /* "none" returns NULL */
        assert_se(mangle_none("none") == NULL);

        /* Non-empty strings are returned as-is */
        assert_se(streq(mangle_none("foo"), "foo"));
        assert_se(streq(mangle_none("aes-xts-plain64"), "aes-xts-plain64"));
        assert_se(streq(mangle_none("sha256"), "sha256"));
        assert_se(streq(mangle_none("some-option"), "some-option"));

        /* "None" (capitalized) is NOT special */
        assert_se(streq_ptr(mangle_none("None"), "None"));

        /* "NONE" (uppercase) is NOT special */
        assert_se(streq_ptr(mangle_none("NONE"), "NONE"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
