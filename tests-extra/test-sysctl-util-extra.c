/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sysctl-util.h"
#include "tests.h"

TEST(sysctl_normalize) {
        char buf[256];

        /* Dot-separated: dots become slashes, slashes become dots */
        strncpy(buf, "net.ipv4.conf.all.rp_filter", sizeof(buf));
        sysctl_normalize(buf);
        ASSERT_STREQ(buf, "net/ipv4/conf/all/rp_filter");

        /* Slash-separated: no change (first separator is slash) */
        strncpy(buf, "net/ipv4/conf/all/rp_filter", sizeof(buf));
        sysctl_normalize(buf);
        ASSERT_STREQ(buf, "net/ipv4/conf/all/rp_filter");

        /* Already dot-separated */
        strncpy(buf, "kernel.osrelease", sizeof(buf));
        sysctl_normalize(buf);
        ASSERT_STREQ(buf, "kernel/osrelease");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
