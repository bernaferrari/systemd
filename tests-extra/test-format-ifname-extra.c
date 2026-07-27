/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>

#include "format-ifname.h"
#include "string-util.h"
#include "tests.h"

TEST(format_ifname_basic) {
        char buf[IF_NAMESIZE];
        int r = format_ifname(1, buf);
        if (r >= 0)
                log_debug("format_ifname(1): %s", buf);

        r = format_ifname(0, buf);
        assert_se(r < 0); /* 0 is not valid */
}

TEST(format_ifname_alloc_basic) {
        _cleanup_free_ char *name = NULL;
        int r = format_ifname_alloc(1, &name);
        if (r >= 0) {
                assert_se(!isempty(name));
                log_debug("format_ifname_alloc(1): %s", name);
        }
}

TEST(format_ifname_full_basic) {
        char buf[IF_NAMESIZE];
        int r = format_ifname_full(1, FORMAT_IFNAME_IFINDEX, buf);
        if (r >= 0)
                log_debug("format_ifname_full(1, IFINDEX): %s", buf);

        r = format_ifname_full(1, FORMAT_IFNAME_IFINDEX_WITH_PERCENT, buf);
        if (r >= 0)
                log_debug("format_ifname_full(1, WITH_PERCENT): %s", buf);
}

TEST(format_ifname_full_alloc_basic) {
        _cleanup_free_ char *name = NULL;
        int r = format_ifname_full_alloc(1, FORMAT_IFNAME_IFINDEX, &name);
        if (r >= 0) {
                assert_se(!isempty(name));
                log_debug("format_ifname_full_alloc(1): %s", name);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
