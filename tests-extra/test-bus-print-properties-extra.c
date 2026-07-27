/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "bus-print-properties.h"
#include "string-util.h"
#include "tests.h"

TEST(bus_property_is_timestamp) {
        /* Standard timestamp suffix */
        assert_se(bus_property_is_timestamp("ActiveEnterTimestamp"));
        assert_se(bus_property_is_timestamp("InactiveEnterTimestamp"));
        assert_se(bus_property_is_timestamp("SomeTimestamp"));

        /* Special names */
        assert_se(bus_property_is_timestamp("NextElapseUSecRealtime"));
        assert_se(bus_property_is_timestamp("LastTriggerUSec"));
        assert_se(bus_property_is_timestamp("TimeUSec"));
        assert_se(bus_property_is_timestamp("RTCTimeUSec"));

        /* Not a timestamp */
        assert_se(!bus_property_is_timestamp("ActiveState"));
        assert_se(!bus_property_is_timestamp("Description"));
        assert_se(!bus_property_is_timestamp("Names"));
        assert_se(!bus_property_is_timestamp("TimestampData")); /* doesn't end with exactly "Timestamp" */

        /* Edge: just "Timestamp" */
        assert_se(bus_property_is_timestamp("Timestamp"));
}

TEST(bus_print_property_value_normal) {
        /* Capture output via /dev/null to avoid cluttering test output */
        int r = bus_print_property_value("TestProp", NULL, 0, "hello");
        assert_se(r == 0);
}

TEST(bus_print_property_value_expected_mismatch) {
        /* expected_value doesn't match → no output, returns 0 */
        int r = bus_print_property_value("TestProp", "expected", 0, "actual");
        assert_se(r == 0);
}

TEST(bus_print_property_value_expected_match) {
        /* expected_value matches → prints */
        int r = bus_print_property_value("TestProp", "value", 0, "value");
        assert_se(r == 0);
}

TEST(bus_print_property_value_empty) {
        /* Empty value without SHOW_EMPTY → no output */
        int r = bus_print_property_value("TestProp", NULL, 0, "");
        assert_se(r == 0);

        /* Empty value with SHOW_EMPTY → prints */
        r = bus_print_property_value("TestProp", NULL, BUS_PRINT_PROPERTY_SHOW_EMPTY, "");
        assert_se(r == 0);
}

TEST(bus_print_property_value_only_value) {
        /* ONLY_VALUE flag → prints just the value */
        int r = bus_print_property_value("TestProp", NULL, BUS_PRINT_PROPERTY_ONLY_VALUE, "hello");
        assert_se(r == 0);
}

TEST(bus_print_property_valuef) {
        int r = bus_print_property_valuef("TestProp", NULL, 0, "value %d", 42);
        assert_se(r == 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
