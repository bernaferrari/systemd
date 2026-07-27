/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "ethtool-util.h"
#include "tests.h"

TEST(duplex_to_string) {
        ASSERT_STREQ(duplex_to_string(DUP_HALF), "half");
        ASSERT_STREQ(duplex_to_string(DUP_FULL), "full");
}

TEST(duplex_from_string) {
        ASSERT_EQ(duplex_from_string("half"), DUP_HALF);
        ASSERT_EQ(duplex_from_string("full"), DUP_FULL);
        ASSERT_EQ(duplex_from_string("invalid"), _DUP_INVALID);
}

TEST(port_to_string) {
        ASSERT_STREQ(port_to_string(NET_DEV_PORT_TP), "tp");
        ASSERT_STREQ(port_to_string(NET_DEV_PORT_AUI), "aui");
        ASSERT_STREQ(port_to_string(NET_DEV_PORT_MII), "mii");
        ASSERT_STREQ(port_to_string(NET_DEV_PORT_FIBRE), "fibre");
        ASSERT_STREQ(port_to_string(NET_DEV_PORT_BNC), "bnc");
}

TEST(port_from_string) {
        ASSERT_EQ(port_from_string("tp"), NET_DEV_PORT_TP);
        ASSERT_EQ(port_from_string("mii"), NET_DEV_PORT_MII);
        ASSERT_EQ(port_from_string("fibre"), NET_DEV_PORT_FIBRE);
        ASSERT_EQ(port_from_string("invalid"), _NET_DEV_PORT_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
