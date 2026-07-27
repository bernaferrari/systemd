/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_bridge.h>

#include "bridge-util.h"
#include "tests.h"

TEST(bridge_state_to_string) {
        ASSERT_STREQ(bridge_state_to_string(NETDEV_BRIDGE_STATE_DISABLED), "disabled");
        ASSERT_STREQ(bridge_state_to_string(NETDEV_BRIDGE_STATE_LISTENING), "listening");
        ASSERT_STREQ(bridge_state_to_string(NETDEV_BRIDGE_STATE_LEARNING), "learning");
        ASSERT_STREQ(bridge_state_to_string(NETDEV_BRIDGE_STATE_FORWARDING), "forwarding");
}

TEST(bridge_state_from_string) {
        ASSERT_EQ(bridge_state_from_string("disabled"), NETDEV_BRIDGE_STATE_DISABLED);
        ASSERT_EQ(bridge_state_from_string("listening"), NETDEV_BRIDGE_STATE_LISTENING);
        ASSERT_EQ(bridge_state_from_string("learning"), NETDEV_BRIDGE_STATE_LEARNING);
        ASSERT_EQ(bridge_state_from_string("forwarding"), NETDEV_BRIDGE_STATE_FORWARDING);
        ASSERT_EQ(bridge_state_from_string("invalid"), _NETDEV_BRIDGE_STATE_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
