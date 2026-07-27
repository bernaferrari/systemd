/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "wifi-util.h"

TEST(nl80211_iftype_to_from_string) {
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
        assert_se(nl80211_iftype_from_string("monitor") == NL80211_IFTYPE_MONITOR);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
