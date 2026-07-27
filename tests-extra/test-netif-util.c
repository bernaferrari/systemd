/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/if_link.h>

#include "ipvlan-util.h"
#include "macvlan-util.h"
#include "geneve-util.h"
#include "tests.h"

TEST(ipvlan_mode_to_string) {
        ASSERT_STREQ(ipvlan_mode_to_string(NETDEV_IPVLAN_MODE_L2), "L2");
        ASSERT_STREQ(ipvlan_mode_to_string(NETDEV_IPVLAN_MODE_L3), "L3");
        ASSERT_STREQ(ipvlan_mode_to_string(NETDEV_IPVLAN_MODE_L3S), "L3S");
}

TEST(ipvlan_mode_from_string) {
        ASSERT_EQ(ipvlan_mode_from_string("L2"), NETDEV_IPVLAN_MODE_L2);
        ASSERT_EQ(ipvlan_mode_from_string("L3"), NETDEV_IPVLAN_MODE_L3);
        ASSERT_EQ(ipvlan_mode_from_string("L3S"), NETDEV_IPVLAN_MODE_L3S);
        ASSERT_EQ(ipvlan_mode_from_string("invalid"), _NETDEV_IPVLAN_MODE_INVALID);
}

TEST(ipvlan_flags_to_string) {
        ASSERT_STREQ(ipvlan_flags_to_string(NETDEV_IPVLAN_FLAGS_BRIGDE), "bridge");
        ASSERT_STREQ(ipvlan_flags_to_string(NETDEV_IPVLAN_FLAGS_PRIVATE), "private");
        ASSERT_STREQ(ipvlan_flags_to_string(NETDEV_IPVLAN_FLAGS_VEPA), "vepa");
}

TEST(ipvlan_flags_from_string) {
        ASSERT_EQ(ipvlan_flags_from_string("bridge"), NETDEV_IPVLAN_FLAGS_BRIGDE);
        ASSERT_EQ(ipvlan_flags_from_string("private"), NETDEV_IPVLAN_FLAGS_PRIVATE);
        ASSERT_EQ(ipvlan_flags_from_string("vepa"), NETDEV_IPVLAN_FLAGS_VEPA);
        ASSERT_EQ(ipvlan_flags_from_string("invalid"), _NETDEV_IPVLAN_FLAGS_INVALID);
}

TEST(macvlan_mode_to_string) {
        ASSERT_STREQ(macvlan_mode_to_string(NETDEV_MACVLAN_MODE_PRIVATE), "private");
        ASSERT_STREQ(macvlan_mode_to_string(NETDEV_MACVLAN_MODE_VEPA), "vepa");
        ASSERT_STREQ(macvlan_mode_to_string(NETDEV_MACVLAN_MODE_BRIDGE), "bridge");
        ASSERT_STREQ(macvlan_mode_to_string(NETDEV_MACVLAN_MODE_PASSTHRU), "passthru");
        ASSERT_STREQ(macvlan_mode_to_string(NETDEV_MACVLAN_MODE_SOURCE), "source");
}

TEST(macvlan_mode_from_string) {
        ASSERT_EQ(macvlan_mode_from_string("private"), NETDEV_MACVLAN_MODE_PRIVATE);
        ASSERT_EQ(macvlan_mode_from_string("vepa"), NETDEV_MACVLAN_MODE_VEPA);
        ASSERT_EQ(macvlan_mode_from_string("bridge"), NETDEV_MACVLAN_MODE_BRIDGE);
        ASSERT_EQ(macvlan_mode_from_string("passthru"), NETDEV_MACVLAN_MODE_PASSTHRU);
        ASSERT_EQ(macvlan_mode_from_string("source"), NETDEV_MACVLAN_MODE_SOURCE);
        ASSERT_EQ(macvlan_mode_from_string("invalid"), _NETDEV_MACVLAN_MODE_INVALID);
}

TEST(geneve_df_to_string) {
        ASSERT_STREQ(geneve_df_to_string(NETDEV_GENEVE_DF_UNSET), "unset");
        ASSERT_STREQ(geneve_df_to_string(NETDEV_GENEVE_DF_SET), "set");
        ASSERT_STREQ(geneve_df_to_string(NETDEV_GENEVE_DF_INHERIT), "inherit");
}

TEST(geneve_df_from_string) {
        ASSERT_EQ(geneve_df_from_string("unset"), NETDEV_GENEVE_DF_UNSET);
        ASSERT_EQ(geneve_df_from_string("set"), NETDEV_GENEVE_DF_SET);
        ASSERT_EQ(geneve_df_from_string("inherit"), NETDEV_GENEVE_DF_INHERIT);
        ASSERT_EQ(geneve_df_from_string("invalid"), _NETDEV_GENEVE_DF_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
