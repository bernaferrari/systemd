/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "device-nodes.h"
#include "tests.h"

TEST(encode_devnode_name) {
        char buf[256];
        ssize_t r;
        r = encode_devnode_name("sda", buf, sizeof(buf));
        ASSERT_OK(r);
        ASSERT_STREQ(buf, "sda");
        r = encode_devnode_name("foo/bar", buf, sizeof(buf));
        ASSERT_OK(r);
        ASSERT_STREQ(buf, "foo\\x2fbar");
        r = encode_devnode_name("foo\\bar", buf, sizeof(buf));
        ASSERT_OK(r);
        ASSERT_STREQ(buf, "foo\\x5cbar");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
