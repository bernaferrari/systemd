/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "metrics.h"
#include "tests.h"

TEST(metric_family_type_to_string) {
        ASSERT_STREQ(metric_family_type_to_string(METRIC_FAMILY_TYPE_COUNTER), "counter");
        ASSERT_STREQ(metric_family_type_to_string(METRIC_FAMILY_TYPE_GAUGE), "gauge");
        ASSERT_STREQ(metric_family_type_to_string(METRIC_FAMILY_TYPE_STRING), "string");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
