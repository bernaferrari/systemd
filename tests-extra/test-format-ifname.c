/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>

#include "format-ifname.h"
#include "tests.h"

TEST(format_ifname_invalid_index) {
        char buf[IF_NAMESIZE];

        /* Zero or negative ifindex should fail */
        ASSERT_EQ(format_ifname_full(0, 0, buf), -EINVAL);
        ASSERT_EQ(format_ifname_full(-1, 0, buf), -EINVAL);
        ASSERT_EQ(format_ifname_full(-42, 0, buf), -EINVAL);
}

TEST(format_ifname_with_ifindex_flag) {
        char buf[IF_NAMESIZE];

        /* A non-existent interface should still work with FORMAT_IFNAME_IFINDEX */
        ASSERT_OK(format_ifname_full(99999, FORMAT_IFNAME_IFINDEX, buf));
        /* Should contain the number 99999 */
        ASSERT_STREQ(buf, "99999");
}

TEST(format_ifname_with_percent_flag) {
        char buf[IF_NAMESIZE];

        ASSERT_OK(format_ifname_full(42, FORMAT_IFNAME_IFINDEX_WITH_PERCENT, buf));
        ASSERT_STREQ(buf, "%42");
}

TEST(format_ifname_alloc_invalid) {
        _cleanup_free_ char *ret = NULL;

        ASSERT_EQ(format_ifname_full_alloc(0, 0, &ret), -EINVAL);
        ASSERT_NULL(ret);
}

TEST(format_ifname_alloc_with_flag) {
        _cleanup_free_ char *ret = NULL;

        ASSERT_OK(format_ifname_full_alloc(99999, FORMAT_IFNAME_IFINDEX, &ret));
        ASSERT_NOT_NULL(ret);
        ASSERT_STREQ(ret, "99999");
}

TEST(format_ifname_macros) {
        /* These macros should work without crashing */
        const char *s;

        s = FORMAT_IFNAME(99999);
        ASSERT_NOT_NULL(s);

        s = FORMAT_IFNAME_FULL(42, FORMAT_IFNAME_IFINDEX);
        ASSERT_NOT_NULL(s);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
