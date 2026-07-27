/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-nodes.h"
#include "string-util.h"
#include "tests.h"

TEST(allow_listed_char_for_devnode_basic) {
        /* Alphanumeric chars are allowed */
        assert_se(allow_listed_char_for_devnode('a', NULL));
        assert_se(allow_listed_char_for_devnode('Z', NULL));
        assert_se(allow_listed_char_for_devnode('0', NULL));
        /* Chars from "#+-.:=@_" are always allowed */
        assert_se(allow_listed_char_for_devnode('#', NULL));
        assert_se(allow_listed_char_for_devnode('+', NULL));
        assert_se(allow_listed_char_for_devnode('-', NULL));
        assert_se(allow_listed_char_for_devnode('.', NULL));
        assert_se(allow_listed_char_for_devnode(':', NULL));
        assert_se(allow_listed_char_for_devnode('=', NULL));
        assert_se(allow_listed_char_for_devnode('@', NULL));
        assert_se(allow_listed_char_for_devnode('_', NULL));
        /* Some chars are NOT allowed */
        assert_se(!allow_listed_char_for_devnode('/', NULL));
        assert_se(!allow_listed_char_for_devnode(' ', NULL));
        /* NUL is "found" by strchr in the allowed string */
        assert_se(allow_listed_char_for_devnode('\0', NULL));
        /* Additional allowed chars */
        assert_se(allow_listed_char_for_devnode('!', "!"));
        assert_se(!allow_listed_char_for_devnode('!', NULL));
}

TEST(encode_devnode_name_basic) {
        char encoded[NAME_MAX + 1];
        assert_se(encode_devnode_name("/dev/sda1", encoded, sizeof(encoded)) >= 0);
        assert_se(!isempty(encoded));
        log_debug("encode_devnode_name: %s", encoded);
}

TEST(encode_devnode_name_simple) {
        char encoded[NAME_MAX + 1];
        assert_se(encode_devnode_name("sda1", encoded, sizeof(encoded)) >= 0);
        log_debug("encode_devnode_name(sda1): %s", encoded);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
