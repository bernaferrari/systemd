/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "hmac.h"
#include "sha256.h"
#include "tests.h"

TEST(hmac_sha256_basic) {
        /* RFC 4231 Test Case 2: HMAC-SHA256 with key "Jefe" */
        const char *key = "Jefe";
        const char *data = "what do ya want for nothing?";
        uint8_t res[SHA256_DIGEST_SIZE];

        hmac_sha256(key, strlen(key), data, strlen(data), res);

        uint8_t expected[] = {
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
                0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
                0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
                0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
        };
        assert_se(memcmp(res, expected, SHA256_DIGEST_SIZE) == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
