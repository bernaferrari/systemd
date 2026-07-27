/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-rr.h"
#include "tests.h"

TEST(dnssec_algorithm) {
        _cleanup_free_ char *s = NULL;

        ASSERT_OK(dnssec_algorithm_to_string_alloc(DNSSEC_ALGORITHM_RSASHA1, &s));
        ASSERT_NOT_NULL(s);
        s = mfree(s);

        ASSERT_OK(dnssec_algorithm_to_string_alloc(DNSSEC_ALGORITHM_RSASHA256, &s));
        ASSERT_NOT_NULL(s);
        s = mfree(s);

        ASSERT_OK(dnssec_algorithm_to_string_alloc(DNSSEC_ALGORITHM_ED25519, &s));
        ASSERT_NOT_NULL(s);
        s = mfree(s);

        /* Unknown algorithm returns error */
        ASSERT_EQ(dnssec_algorithm_to_string_alloc(999, &s), -ERANGE);
}

TEST(dnssec_digest) {
        _cleanup_free_ char *s = NULL;

        ASSERT_OK(dnssec_digest_to_string_alloc(DNSSEC_DIGEST_SHA1, &s));
        ASSERT_NOT_NULL(s);
        s = mfree(s);

        ASSERT_OK(dnssec_digest_to_string_alloc(DNSSEC_DIGEST_SHA256, &s));
        ASSERT_NOT_NULL(s);
        s = mfree(s);

        ASSERT_OK(dnssec_digest_to_string_alloc(DNSSEC_DIGEST_SHA384, &s));
        ASSERT_NOT_NULL(s);
        s = mfree(s);

        /* Unknown digest returns error */
        ASSERT_EQ(dnssec_digest_to_string_alloc(999, &s), -ERANGE);
}

TEST(sshfp_algorithm) {
        _cleanup_free_ char *s = NULL;

        ASSERT_OK(sshfp_algorithm_to_string_alloc(SSHFP_ALGORITHM_RSA, &s));
        ASSERT_NOT_NULL(s);
        s = mfree(s);

        ASSERT_OK(sshfp_algorithm_to_string_alloc(SSHFP_ALGORITHM_ECDSA, &s));
        ASSERT_NOT_NULL(s);
        s = mfree(s);

        /* Unknown returns error */
        ASSERT_EQ(sshfp_algorithm_to_string_alloc(999, &s), -ERANGE);
}

TEST(sshfp_key_type) {
        _cleanup_free_ char *s = NULL;

        ASSERT_OK(sshfp_key_type_to_string_alloc(SSHFP_KEY_TYPE_SHA1, &s));
        ASSERT_NOT_NULL(s);
        s = mfree(s);

        ASSERT_OK(sshfp_key_type_to_string_alloc(SSHFP_KEY_TYPE_SHA256, &s));
        ASSERT_NOT_NULL(s);
        s = mfree(s);

        /* Unknown returns error */
        ASSERT_EQ(sshfp_key_type_to_string_alloc(999, &s), -ERANGE);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
