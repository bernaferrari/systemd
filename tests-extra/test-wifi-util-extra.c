/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/nl80211.h>

#include "wifi-util.h"
#include "tests.h"

TEST(nl80211_iftype_to_string) {
        ASSERT_STREQ(nl80211_iftype_to_string(NL80211_IFTYPE_ADHOC), "ad-hoc");
        ASSERT_STREQ(nl80211_iftype_to_string(NL80211_IFTYPE_STATION), "station");
        ASSERT_STREQ(nl80211_iftype_to_string(NL80211_IFTYPE_AP), "ap");
        ASSERT_STREQ(nl80211_iftype_to_string(NL80211_IFTYPE_AP_VLAN), "ap-vlan");
        ASSERT_STREQ(nl80211_iftype_to_string(NL80211_IFTYPE_WDS), "wds");
        ASSERT_STREQ(nl80211_iftype_to_string(NL80211_IFTYPE_MONITOR), "monitor");
        ASSERT_STREQ(nl80211_iftype_to_string(NL80211_IFTYPE_MESH_POINT), "mesh-point");
        ASSERT_STREQ(nl80211_iftype_to_string(NL80211_IFTYPE_P2P_CLIENT), "p2p-client");
        ASSERT_STREQ(nl80211_iftype_to_string(NL80211_IFTYPE_P2P_GO), "p2p-go");
        ASSERT_STREQ(nl80211_iftype_to_string(NL80211_IFTYPE_P2P_DEVICE), "p2p-device");
        ASSERT_STREQ(nl80211_iftype_to_string(NL80211_IFTYPE_OCB), "ocb");
        ASSERT_STREQ(nl80211_iftype_to_string(NL80211_IFTYPE_NAN), "nan");
}

TEST(nl80211_iftype_from_string) {
        assert_se(nl80211_iftype_from_string("ad-hoc") == NL80211_IFTYPE_ADHOC);
        assert_se(nl80211_iftype_from_string("station") == NL80211_IFTYPE_STATION);
        assert_se(nl80211_iftype_from_string("ap") == NL80211_IFTYPE_AP);
        assert_se(nl80211_iftype_from_string("monitor") == NL80211_IFTYPE_MONITOR);
        assert_se(nl80211_iftype_from_string("mesh-point") == NL80211_IFTYPE_MESH_POINT);
        assert_se(nl80211_iftype_from_string("p2p-client") == NL80211_IFTYPE_P2P_CLIENT);
        assert_se(nl80211_iftype_from_string("p2p-go") == NL80211_IFTYPE_P2P_GO);
}

TEST(nl80211_cmd_to_string) {
        /* TO_STRING only, no from_string */
        ASSERT_STREQ(nl80211_cmd_to_string(NL80211_CMD_GET_WIPHY), "get_wiphy");
        ASSERT_STREQ(nl80211_cmd_to_string(NL80211_CMD_SET_WIPHY), "set_wiphy");
        ASSERT_STREQ(nl80211_cmd_to_string(NL80211_CMD_NEW_INTERFACE), "new_interface");
        ASSERT_STREQ(nl80211_cmd_to_string(NL80211_CMD_GET_STATION), "get_station");
        ASSERT_STREQ(nl80211_cmd_to_string(NL80211_CMD_START_AP), "start_ap");
        ASSERT_STREQ(nl80211_cmd_to_string(NL80211_CMD_CONNECT), "connect");
        ASSERT_STREQ(nl80211_cmd_to_string(NL80211_CMD_DISCONNECT), "disconnect");
        ASSERT_STREQ(nl80211_cmd_to_string(NL80211_CMD_SCAN_ABORTED), "scan_aborted");
        ASSERT_STREQ(nl80211_cmd_to_string(NL80211_CMD_FRAME), "frame");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
