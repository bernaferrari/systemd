/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "dns-rr.h"
#include "string-util.h"
#include "tests.h"

TEST(dnssec_algorithm_from_string) {
        /* from_string */
        assert_se(dnssec_algorithm_from_string("RSASHA1") == DNSSEC_ALGORITHM_RSASHA1);
        assert_se(dnssec_algorithm_from_string("RSASHA256") == DNSSEC_ALGORITHM_RSASHA256);
        assert_se(dnssec_algorithm_from_string("ECDSAP256SHA256") == DNSSEC_ALGORITHM_ECDSAP256SHA256);
        assert_se(dnssec_algorithm_from_string("ED25519") == DNSSEC_ALGORITHM_ED25519);
        assert_se(dnssec_algorithm_from_string("ED448") == DNSSEC_ALGORITHM_ED448);

        /* Numeric fallback (WITH_FALLBACK) — must be <= 255 */
        assert_se(dnssec_algorithm_from_string("200") == 200);
}

TEST(dnssec_algorithm_to_string_alloc) {
        _cleanup_free_ char *s = NULL;

        /* Known value */
        assert_se(dnssec_algorithm_to_string_alloc(DNSSEC_ALGORITHM_RSASHA1, &s) >= 0);
        assert_se(streq(s, "RSASHA1"));

        /* Unknown but within range → numeric string */
        s = mfree(s);
        assert_se(dnssec_algorithm_to_string_alloc(200, &s) >= 0);
        assert_se(s && strlen(s) > 0);

        /* Out of range → -ERANGE */
        s = mfree(s);
        assert_se(dnssec_algorithm_to_string_alloc(300, &s) == -ERANGE);
}

TEST(dnssec_digest_from_string) {
        assert_se(dnssec_digest_from_string("SHA-1") == DNSSEC_DIGEST_SHA1);
        assert_se(dnssec_digest_from_string("SHA-256") == DNSSEC_DIGEST_SHA256);
        assert_se(dnssec_digest_from_string("SHA-384") == DNSSEC_DIGEST_SHA384);

        /* Numeric fallback */
        assert_se(dnssec_digest_from_string("100") == 100);
}

TEST(dnssec_digest_to_string_alloc) {
        _cleanup_free_ char *s = NULL;
        assert_se(dnssec_digest_to_string_alloc(DNSSEC_DIGEST_SHA256, &s) >= 0);
        assert_se(streq(s, "SHA-256"));

        /* Unknown but within range → numeric string */
        s = mfree(s);
        assert_se(dnssec_digest_to_string_alloc(100, &s) >= 0);
        assert_se(s && strlen(s) > 0);

        /* Out of range */
        s = mfree(s);
        assert_se(dnssec_digest_to_string_alloc(300, &s) == -ERANGE);
}

TEST(sshfp_algorithm_from_string) {
        assert_se(sshfp_algorithm_from_string("RSA") == SSHFP_ALGORITHM_RSA);
        assert_se(sshfp_algorithm_from_string("DSA") == SSHFP_ALGORITHM_DSA);
        assert_se(sshfp_algorithm_from_string("ECDSA") == SSHFP_ALGORITHM_ECDSA);
        assert_se(sshfp_algorithm_from_string("Ed25519") == SSHFP_ALGORITHM_ED25519);
        assert_se(sshfp_algorithm_from_string("Ed448") == SSHFP_ALGORITHM_ED448);

        /* Numeric fallback */
        assert_se(sshfp_algorithm_from_string("50") == 50);
}

TEST(sshfp_algorithm_to_string_alloc) {
        _cleanup_free_ char *s = NULL;
        assert_se(sshfp_algorithm_to_string_alloc(SSHFP_ALGORITHM_RSA, &s) >= 0);
        assert_se(streq(s, "RSA"));
}

TEST(sshfp_key_type_from_string) {
        assert_se(sshfp_key_type_from_string("SHA-1") == SSHFP_KEY_TYPE_SHA1);
        assert_se(sshfp_key_type_from_string("SHA-256") == SSHFP_KEY_TYPE_SHA256);

        /* Numeric fallback */
        assert_se(sshfp_key_type_from_string("10") == 10);
}

TEST(sshfp_key_type_to_string_alloc) {
        _cleanup_free_ char *s = NULL;
        assert_se(sshfp_key_type_to_string_alloc(SSHFP_KEY_TYPE_SHA1, &s) >= 0);
        assert_se(streq(s, "SHA-1"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
