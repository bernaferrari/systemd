/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "wifi-util.h"

TEST(nl80211_iftype_roundtrip) {
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_ADHOC), "ad-hoc"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_STATION), "station"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_AP), "ap"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_AP_VLAN), "ap-vlan"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_WDS), "wds"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_MONITOR), "monitor"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_MESH_POINT), "mesh-point"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_P2P_CLIENT), "p2p-client"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_P2P_GO), "p2p-go"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_P2P_DEVICE), "p2p-device"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_OCB), "ocb"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_NAN), "nan"));

        assert_se(nl80211_iftype_from_string("ad-hoc") == NL80211_IFTYPE_ADHOC);
        assert_se(nl80211_iftype_from_string("station") == NL80211_IFTYPE_STATION);
        assert_se(nl80211_iftype_from_string("ap") == NL80211_IFTYPE_AP);
        assert_se(nl80211_iftype_from_string("ap-vlan") == NL80211_IFTYPE_AP_VLAN);
        assert_se(nl80211_iftype_from_string("wds") == NL80211_IFTYPE_WDS);
        assert_se(nl80211_iftype_from_string("monitor") == NL80211_IFTYPE_MONITOR);
        assert_se(nl80211_iftype_from_string("mesh-point") == NL80211_IFTYPE_MESH_POINT);
        assert_se(nl80211_iftype_from_string("p2p-client") == NL80211_IFTYPE_P2P_CLIENT);
        assert_se(nl80211_iftype_from_string("p2p-go") == NL80211_IFTYPE_P2P_GO);
        assert_se(nl80211_iftype_from_string("p2p-device") == NL80211_IFTYPE_P2P_DEVICE);
        assert_se(nl80211_iftype_from_string("ocb") == NL80211_IFTYPE_OCB);
        assert_se(nl80211_iftype_from_string("nan") == NL80211_IFTYPE_NAN);
}

TEST(nl80211_cmd_to_string) {
        assert_se(streq(nl80211_cmd_to_string(NL80211_CMD_ASSOCIATE), "associate"));
        assert_se(streq(nl80211_cmd_to_string(NL80211_CMD_AUTHENTICATE), "authenticate"));
        assert_se(streq(nl80211_cmd_to_string(NL80211_CMD_CONNECT), "connect"));
        assert_se(streq(nl80211_cmd_to_string(NL80211_CMD_DISCONNECT), "disconnect"));
        assert_se(streq(nl80211_cmd_to_string(NL80211_CMD_JOIN_IBSS), "join_ibss"));
        assert_se(streq(nl80211_cmd_to_string(NL80211_CMD_NEW_STATION), "new_station"));
        assert_se(streq(nl80211_cmd_to_string(NL80211_CMD_NEW_INTERFACE), "new_interface"));
        assert_se(streq(nl80211_cmd_to_string(NL80211_CMD_SET_INTERFACE), "set_interface"));
        assert_se(streq(nl80211_cmd_to_string(NL80211_CMD_NEW_KEY), "new_key"));
        assert_se(streq(nl80211_cmd_to_string(NL80211_CMD_START_AP), "start_ap"));
        assert_se(streq(nl80211_cmd_to_string(NL80211_CMD_RELOAD_REGDB), "reload_regdb"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
