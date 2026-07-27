/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "netif-sriov.h"
#include "tests.h"

TEST(sr_iov_attribute_to_string) {
        ASSERT_STREQ(sr_iov_attribute_to_string(SR_IOV_VF_MAC), "MAC address");
        ASSERT_STREQ(sr_iov_attribute_to_string(SR_IOV_VF_SPOOFCHK), "spoof check");
        ASSERT_STREQ(sr_iov_attribute_to_string(SR_IOV_VF_RSS_QUERY_EN), "RSS query");
        ASSERT_STREQ(sr_iov_attribute_to_string(SR_IOV_VF_TRUST), "trust");
        ASSERT_STREQ(sr_iov_attribute_to_string(SR_IOV_VF_LINK_STATE), "link state");
        ASSERT_STREQ(sr_iov_attribute_to_string(SR_IOV_VF_VLAN_LIST), "vlan list");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
