/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <net/if.h>
#include <linux/nl80211.h>

#include "string-util.h"
#include "tests.h"
#include "wifi-util.h"

TEST(nl80211_iftype_to_from_string) {
        /* to_string */
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_ADHOC), "ad-hoc"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_STATION), "station"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_AP), "ap"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_MONITOR), "monitor"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_MESH_POINT), "mesh-point"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_P2P_CLIENT), "p2p-client"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_P2P_GO), "p2p-go"));
        assert_se(streq(nl80211_iftype_to_string(NL80211_IFTYPE_P2P_DEVICE), "p2p-device"));

        /* from_string */
        assert_se(nl80211_iftype_from_string("ad-hoc") == NL80211_IFTYPE_ADHOC);
        assert_se(nl80211_iftype_from_string("station") == NL80211_IFTYPE_STATION);
        assert_se(nl80211_iftype_from_string("ap") == NL80211_IFTYPE_AP);
        assert_se(nl80211_iftype_from_string("monitor") == NL80211_IFTYPE_MONITOR);
        assert_se(nl80211_iftype_from_string("mesh-point") == NL80211_IFTYPE_MESH_POINT);
}

TEST(nl80211_cmd_to_string) {
        /* to_string only (from_string not generated for TO_STRING variant) */
        assert_se(streq(nl80211_cmd_to_string(NL80211_CMD_GET_WIPHY), "get_wiphy"));
        assert_se(streq(nl80211_cmd_to_string(NL80211_CMD_SET_WIPHY), "set_wiphy"));
        assert_se(streq(nl80211_cmd_to_string(NL80211_CMD_NEW_WIPHY), "new_wiphy"));
        assert_se(streq(nl80211_cmd_to_string(NL80211_CMD_DEL_WIPHY), "del_wiphy"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
