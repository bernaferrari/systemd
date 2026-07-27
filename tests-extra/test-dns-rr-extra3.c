/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-rr.h"
#include "string-util.h"
#include "tests.h"

TEST(sshfp_key_type_from_string_basic) {
        assert_se(sshfp_key_type_from_string("SHA-1") == SSHFP_KEY_TYPE_SHA1);
        assert_se(sshfp_key_type_from_string("SHA-256") == SSHFP_KEY_TYPE_SHA256);
        assert_se(sshfp_key_type_from_string("invalid") == -EINVAL);

        /* Numeric fallback */
        assert_se(sshfp_key_type_from_string("1") == 1);
        assert_se(sshfp_key_type_from_string("2") == 2);
}

TEST(sshfp_key_type_roundtrip) {
        for (int i = 0; i < _SSHFP_KEY_TYPE_MAX_DEFINED; i++) {
                _cleanup_free_ char *s = NULL;
                if (sshfp_key_type_to_string_alloc(i, &s) >= 0) {
                        int v = sshfp_key_type_from_string(s);
                        assert_se(v == i);
                }
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
