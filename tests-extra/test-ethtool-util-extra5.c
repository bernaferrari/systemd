/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/ethtool.h>

#include "ethtool-util.h"
#include "string-util.h"
#include "tests.h"

TEST(duplex_roundtrip) {
        assert_se(streq(duplex_to_string(DUP_FULL), "full"));
        assert_se(streq(duplex_to_string(DUP_HALF), "half"));

        assert_se(duplex_from_string("full") == DUP_FULL);
        assert_se(duplex_from_string("half") == DUP_HALF);

        /* Invalid */
        assert_se(duplex_from_string("invalid") == _DUP_INVALID);
        assert_se(duplex_from_string("") == _DUP_INVALID);
}

TEST(wol_options_to_string_alloc) {
        _cleanup_free_ char *s = NULL;

        /* WAKE_PHY */
        assert_se(wol_options_to_string_alloc(WAKE_PHY, &s) > 0);
        assert_se(s && streq(s, "phy"));

        s = mfree(s);
        /* WAKE_MAGIC */
        assert_se(wol_options_to_string_alloc(WAKE_MAGIC, &s) > 0);
        assert_se(s && streq(s, "magic"));

        s = mfree(s);
        /* Multiple options combined */
        assert_se(wol_options_to_string_alloc(WAKE_PHY | WAKE_MAGIC, &s) > 0);
        assert_se(s && strstr(s, "phy") && strstr(s, "magic"));

        s = mfree(s);
        /* No options (0) means "off" */
        assert_se(wol_options_to_string_alloc(0, &s) > 0);
        assert_se(s && streq(s, "off"));

        s = mfree(s);
        /* UINT32_MAX is "not changed" → returns 0 with NULL */
        assert_se(wol_options_to_string_alloc(UINT32_MAX, &s) == 0);
        assert_se(s == NULL);
}

TEST(port_roundtrip) {
        assert_se(streq(port_to_string(NET_DEV_PORT_TP), "tp"));
        assert_se(streq(port_to_string(NET_DEV_PORT_AUI), "aui"));
        assert_se(streq(port_to_string(NET_DEV_PORT_MII), "mii"));
        assert_se(streq(port_to_string(NET_DEV_PORT_FIBRE), "fibre"));
        assert_se(streq(port_to_string(NET_DEV_PORT_BNC), "bnc"));

        assert_se(port_from_string("tp") == NET_DEV_PORT_TP);
        assert_se(port_from_string("fibre") == NET_DEV_PORT_FIBRE);
        assert_se(port_from_string("bnc") == NET_DEV_PORT_BNC);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
