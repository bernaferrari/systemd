/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bridge-util.h"
#include "string-util.h"
#include "tests.h"

TEST(bridge_state_to_from_string) {
        assert_se(streq(bridge_state_to_string(NETDEV_BRIDGE_STATE_DISABLED), "disabled"));
        assert_se(streq(bridge_state_to_string(NETDEV_BRIDGE_STATE_LISTENING), "listening"));
        assert_se(streq(bridge_state_to_string(NETDEV_BRIDGE_STATE_LEARNING), "learning"));
        assert_se(streq(bridge_state_to_string(NETDEV_BRIDGE_STATE_FORWARDING), "forwarding"));

        assert_se(bridge_state_from_string("disabled") == NETDEV_BRIDGE_STATE_DISABLED);
        assert_se(bridge_state_from_string("listening") == NETDEV_BRIDGE_STATE_LISTENING);
        assert_se(bridge_state_from_string("learning") == NETDEV_BRIDGE_STATE_LEARNING);
        assert_se(bridge_state_from_string("forwarding") == NETDEV_BRIDGE_STATE_FORWARDING);
        assert_se(bridge_state_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
