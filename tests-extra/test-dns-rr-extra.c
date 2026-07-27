/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-rr.h"
#include "tests.h"

TEST(dnssec_algorithm_to_string) {
        _cleanup_free_ char *s = NULL;
        /* WITH_FALLBACK: _to_string_alloc returns int */
        ASSERT_OK(dnssec_algorithm_to_string_alloc(DNSSEC_ALGORITHM_RSASHA1, &s));
        ASSERT_STREQ(s, "RSASHA1");
        s = mfree(s);
        ASSERT_OK(dnssec_algorithm_to_string_alloc(DNSSEC_ALGORITHM_RSASHA256, &s));
        ASSERT_STREQ(s, "RSASHA256");
        s = mfree(s);
        ASSERT_OK(dnssec_algorithm_to_string_alloc(DNSSEC_ALGORITHM_ED25519, &s));
        ASSERT_STREQ(s, "ED25519");
}

TEST(dnssec_algorithm_from_string) {
        ASSERT_EQ(dnssec_algorithm_from_string("RSASHA1"), DNSSEC_ALGORITHM_RSASHA1);
        ASSERT_EQ(dnssec_algorithm_from_string("RSASHA256"), DNSSEC_ALGORITHM_RSASHA256);
        ASSERT_EQ(dnssec_algorithm_from_string("ED25519"), DNSSEC_ALGORITHM_ED25519);
        /* WITH_FALLBACK: numeric values accepted */
        ASSERT_EQ(dnssec_algorithm_from_string("5"), 5);
        ASSERT_EQ(dnssec_algorithm_from_string("invalid"), -EINVAL);
}

TEST(dnssec_digest_to_string) {
        _cleanup_free_ char *s = NULL;
        ASSERT_OK(dnssec_digest_to_string_alloc(DNSSEC_DIGEST_SHA1, &s));
        ASSERT_STREQ(s, "SHA-1");
        s = mfree(s);
        ASSERT_OK(dnssec_digest_to_string_alloc(DNSSEC_DIGEST_SHA256, &s));
        ASSERT_STREQ(s, "SHA-256");
}

TEST(dnssec_digest_from_string) {
        ASSERT_EQ(dnssec_digest_from_string("SHA-1"), DNSSEC_DIGEST_SHA1);
        ASSERT_EQ(dnssec_digest_from_string("SHA-256"), DNSSEC_DIGEST_SHA256);
        ASSERT_EQ(dnssec_digest_from_string("invalid"), -EINVAL);
}

TEST(sshfp_algorithm_to_string) {
        _cleanup_free_ char *s = NULL;
        ASSERT_OK(sshfp_algorithm_to_string_alloc(SSHFP_ALGORITHM_RSA, &s));
        ASSERT_STREQ(s, "RSA");
        s = mfree(s);
        ASSERT_OK(sshfp_algorithm_to_string_alloc(SSHFP_ALGORITHM_ED25519, &s));
        ASSERT_STREQ(s, "Ed25519");
}

TEST(sshfp_algorithm_from_string) {
        ASSERT_EQ(sshfp_algorithm_from_string("RSA"), SSHFP_ALGORITHM_RSA);
        ASSERT_EQ(sshfp_algorithm_from_string("Ed25519"), SSHFP_ALGORITHM_ED25519);
        ASSERT_EQ(sshfp_algorithm_from_string("invalid"), -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
