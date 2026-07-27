/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "metrics.h"
#include "string-util.h"
#include "tests.h"

TEST(metric_family_type_to_string) {
        /* TO_STRING only */
        assert_se(streq(metric_family_type_to_string(METRIC_FAMILY_TYPE_COUNTER), "counter"));
        assert_se(streq(metric_family_type_to_string(METRIC_FAMILY_TYPE_GAUGE), "gauge"));
        assert_se(streq(metric_family_type_to_string(METRIC_FAMILY_TYPE_STRING), "string"));

        /* Unknown */
        assert_se(metric_family_type_to_string(999) == NULL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
