/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-util.h"
#include "string-util.h"
#include "tests.h"

TEST(bus_transport_to_string) {
        assert_se(streq(bus_transport_to_string(BUS_TRANSPORT_LOCAL), "local"));
        assert_se(streq(bus_transport_to_string(BUS_TRANSPORT_REMOTE), "remote"));
        assert_se(streq(bus_transport_to_string(BUS_TRANSPORT_MACHINE), "machine"));
        assert_se(streq(bus_transport_to_string(BUS_TRANSPORT_CAPSULE), "capsule"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
