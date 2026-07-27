/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "hostname-util.h"
#include "tests.h"

TEST(valid_ldh_char) {
        /* Letters */
        ASSERT_TRUE(valid_ldh_char('a'));
        ASSERT_TRUE(valid_ldh_char('Z'));

        /* Digits */
        ASSERT_TRUE(valid_ldh_char('0'));
        ASSERT_TRUE(valid_ldh_char('9'));

        /* Hyphen */
        ASSERT_TRUE(valid_ldh_char('-'));

        /* Invalid */
        ASSERT_FALSE(valid_ldh_char('.'));
        ASSERT_FALSE(valid_ldh_char('_'));
        ASSERT_FALSE(valid_ldh_char(' '));
        ASSERT_FALSE(valid_ldh_char('\0'));
}

TEST(hostname_is_valid) {
        /* Simple valid hostnames */
        ASSERT_TRUE(hostname_is_valid("localhost", 0));
        ASSERT_TRUE(hostname_is_valid("myhost", 0));
        ASSERT_TRUE(hostname_is_valid("my-host", 0));
        ASSERT_TRUE(hostname_is_valid("my.host", 0));
        ASSERT_TRUE(hostname_is_valid("a", 0));

        /* Empty is invalid */
        ASSERT_FALSE(hostname_is_valid("", 0));

        /* Leading dot is invalid */
        ASSERT_FALSE(hostname_is_valid(".myhost", 0));

        /* Trailing hyphen is invalid */
        ASSERT_FALSE(hostname_is_valid("myhost-", 0));

        /* Leading hyphen is invalid */
        ASSERT_FALSE(hostname_is_valid("-myhost", 0));

        /* Trailing dot needs flag */
        ASSERT_FALSE(hostname_is_valid("my.host.", 0));
        ASSERT_TRUE(hostname_is_valid("my.host.", VALID_HOSTNAME_TRAILING_DOT));

        /* Single trailing dot (not multi-label) */
        ASSERT_FALSE(hostname_is_valid("host.", VALID_HOSTNAME_TRAILING_DOT));

        /* Underscore is invalid */
        ASSERT_FALSE(hostname_is_valid("my_host", 0));

        /* .host special case */
        ASSERT_FALSE(hostname_is_valid(".host", 0));
        ASSERT_TRUE(hostname_is_valid(".host", VALID_HOSTNAME_DOT_HOST));

        /* Question mark needs flag */
        ASSERT_FALSE(hostname_is_valid("my?host", 0));
        ASSERT_TRUE(hostname_is_valid("my?host", VALID_HOSTNAME_QUESTION_MARK));
}

TEST(hostname_cleanup) {
        char buf[256];

        /* Normal hostname unchanged */
        strcpy(buf, "myhost");
        ASSERT_STREQ(hostname_cleanup(buf), "myhost");

        /* Strips leading dots */
        strcpy(buf, "...myhost");
        ASSERT_STREQ(hostname_cleanup(buf), "myhost");

        /* Strips leading hyphens */
        strcpy(buf, "--myhost");
        ASSERT_STREQ(hostname_cleanup(buf), "myhost");

        /* Strips single trailing dot */
        strcpy(buf, "myhost.");
        ASSERT_STREQ(hostname_cleanup(buf), "myhost");

        /* Strips single trailing hyphen */
        strcpy(buf, "myhost-");
        ASSERT_STREQ(hostname_cleanup(buf), "myhost");

        /* Collapses consecutive dots */
        strcpy(buf, "my...host");
        ASSERT_STREQ(hostname_cleanup(buf), "my.host");

        /* Removes invalid chars (underscore) */
        strcpy(buf, "my_host");
        ASSERT_STREQ(hostname_cleanup(buf), "myhost");

        /* Handles empty result */
        strcpy(buf, "---...");
        ASSERT_STREQ(hostname_cleanup(buf), "");
}

TEST(is_localhost) {
        ASSERT_TRUE(is_localhost("localhost"));
        ASSERT_TRUE(is_localhost("localhost."));
        ASSERT_TRUE(is_localhost("localhost.localdomain"));
        ASSERT_TRUE(is_localhost("localhost.localdomain."));
        ASSERT_TRUE(is_localhost("my.localhost"));
        ASSERT_TRUE(is_localhost("my.localhost.localdomain"));
        ASSERT_TRUE(is_localhost("MY.LOCALHOST")); /* case insensitive */

        ASSERT_FALSE(is_localhost("myhost"));
        ASSERT_FALSE(is_localhost("notlocalhost"));
        ASSERT_FALSE(is_localhost(""));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
