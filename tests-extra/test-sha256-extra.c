/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sha256.h"
#include "tests.h"

TEST(sha256_is_valid) {
        /* Valid 64-char hex string */
        ASSERT_TRUE(sha256_is_valid("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        /* Too short */
        ASSERT_FALSE(sha256_is_valid("e3b0c44298fc1c14"));
        /* Too long */
        ASSERT_FALSE(sha256_is_valid("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85500"));
        /* Contains non-hex chars */
        ASSERT_FALSE(sha256_is_valid("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85g"));
        /* Empty */
        ASSERT_FALSE(sha256_is_valid(""));
        /* NULL */
        ASSERT_FALSE(sha256_is_valid(NULL));
}

TEST(parse_sha256) {
        uint8_t hash[SHA256_DIGEST_SIZE];
        /* All zeros */
        ASSERT_OK(parse_sha256("0000000000000000000000000000000000000000000000000000000000000000", hash));
        ASSERT_EQ(hash[0], 0);
        ASSERT_EQ(hash[31], 0);
        /* Invalid input */
        ASSERT_EQ(parse_sha256("notvalid", hash), -EINVAL);
        ASSERT_EQ(parse_sha256(NULL, hash), -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
