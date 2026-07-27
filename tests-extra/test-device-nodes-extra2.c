/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-nodes.h"
#include "string-util.h"
#include "tests.h"

TEST(allow_listed_char_for_devnode) {
        /* Digits and letters are allowed */
        assert_se(allow_listed_char_for_devnode('a', NULL));
        assert_se(allow_listed_char_for_devnode('Z', NULL));
        assert_se(allow_listed_char_for_devnode('0', NULL));
        assert_se(allow_listed_char_for_devnode('9', NULL));

        /* Special allowed chars */
        assert_se(allow_listed_char_for_devnode('#', NULL));
        assert_se(allow_listed_char_for_devnode('+', NULL));
        assert_se(allow_listed_char_for_devnode('-', NULL));
        assert_se(allow_listed_char_for_devnode('.', NULL));
        assert_se(allow_listed_char_for_devnode(':', NULL));
        assert_se(allow_listed_char_for_devnode('=', NULL));
        assert_se(allow_listed_char_for_devnode('@', NULL));
        assert_se(allow_listed_char_for_devnode('_', NULL));

        /* Disallowed chars */
        assert_se(!allow_listed_char_for_devnode(' ', NULL));
        assert_se(!allow_listed_char_for_devnode('/', NULL));
        assert_se(!allow_listed_char_for_devnode('!', NULL));
        assert_se(!allow_listed_char_for_devnode('\\', NULL));

        /* Additional allowed chars */
        assert_se(allow_listed_char_for_devnode(' ', " /"));
        assert_se(allow_listed_char_for_devnode('/', " /"));
        assert_se(!allow_listed_char_for_devnode('!', " /"));
}

TEST(encode_devnode_name) {
        char buf[256];

        /* Plain ASCII name */
        assert_se(encode_devnode_name("sda1", buf, sizeof(buf)) == 0);
        assert_se(streq(buf, "sda1"));

        /* Name with special allowed chars */
        assert_se(encode_devnode_name("dm-0", buf, sizeof(buf)) == 0);
        assert_se(streq(buf, "dm-0"));

        /* Name with characters that need encoding */
        assert_se(encode_devnode_name("a b", buf, sizeof(buf)) == 0);
        assert_se(streq(buf, "a\\x20b"));

        /* Backslash is encoded */
        assert_se(encode_devnode_name("a\\b", buf, sizeof(buf)) == 0);
        assert_se(streq(buf, "a\\x5cb"));

        /* Buffer too small */
        assert_se(encode_devnode_name("toolong", buf, 4) == -EINVAL);

        /* NULL inputs */
        assert_se(encode_devnode_name(NULL, buf, sizeof(buf)) == -EINVAL);
        assert_se(encode_devnode_name("test", NULL, sizeof(buf)) == -EINVAL);

        /* Empty string */
        assert_se(encode_devnode_name("", buf, sizeof(buf)) == 0);
        assert_se(streq(buf, ""));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
