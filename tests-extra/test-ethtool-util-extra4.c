/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ethtool-util.h"
#include "string-util.h"
#include "tests.h"

TEST(duplex_to_from_string) {
        assert_se(streq(duplex_to_string(DUP_FULL), "full"));
        assert_se(streq(duplex_to_string(DUP_HALF), "half"));

        assert_se(duplex_from_string("full") == DUP_FULL);
        assert_se(duplex_from_string("half") == DUP_HALF);
        assert_se(duplex_from_string("invalid") < 0);
}

TEST(port_to_from_string) {
        assert_se(streq(port_to_string(NET_DEV_PORT_TP), "tp"));
        assert_se(streq(port_to_string(NET_DEV_PORT_AUI), "aui"));
        assert_se(streq(port_to_string(NET_DEV_PORT_MII), "mii"));
        assert_se(streq(port_to_string(NET_DEV_PORT_FIBRE), "fibre"));
        assert_se(streq(port_to_string(NET_DEV_PORT_BNC), "bnc"));

        assert_se(port_from_string("tp") == NET_DEV_PORT_TP);
        assert_se(port_from_string("fibre") == NET_DEV_PORT_FIBRE);
        assert_se(port_from_string("bnc") == NET_DEV_PORT_BNC);
        assert_se(port_from_string("invalid") < 0);
}

TEST(mdi_to_string) {
        /* TO_STRING only */
        assert_se(streq(mdi_to_string(ETH_TP_MDI_INVALID), "unknown"));
        assert_se(streq(mdi_to_string(ETH_TP_MDI), "mdi"));
        assert_se(streq(mdi_to_string(ETH_TP_MDI_X), "mdi-x"));
        assert_se(streq(mdi_to_string(ETH_TP_MDI_AUTO), "auto"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
