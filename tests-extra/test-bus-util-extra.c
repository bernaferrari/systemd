/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-util.h"
#include "tests.h"

/* bus_transport uses TO_STRING only */
TEST(bus_transport) {
        ASSERT_STREQ(bus_transport_to_string(BUS_TRANSPORT_LOCAL), "local");
        ASSERT_STREQ(bus_transport_to_string(BUS_TRANSPORT_REMOTE), "remote");
        ASSERT_STREQ(bus_transport_to_string(BUS_TRANSPORT_MACHINE), "machine");
        ASSERT_STREQ(bus_transport_to_string(BUS_TRANSPORT_CAPSULE), "capsule");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
