/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-util.h"
#include "sd-bus.h"
#include "tests.h"

TEST(bus_error_is_unknown_service_null) {
        /* NULL error should return false */
        assert_se(!bus_error_is_unknown_service(NULL));
}

TEST(bus_error_is_connection_null) {
        /* NULL error should return false */
        assert_se(!bus_error_is_connection(NULL));
}

TEST(bus_error_is_unknown_service_empty) {
        const sd_bus_error e = SD_BUS_ERROR_NULL;
        assert_se(!bus_error_is_unknown_service(&e));
}

TEST(bus_error_is_connection_empty) {
        const sd_bus_error e = SD_BUS_ERROR_NULL;
        assert_se(!bus_error_is_connection(&e));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
