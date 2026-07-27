/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "gpt.h"
#include "string-util.h"
#include "tests.h"

TEST(gpt_partition_label_valid) {
        /* Short label should be valid */
        assert_se(gpt_partition_label_valid("root") > 0);
        assert_se(gpt_partition_label_valid("System") > 0);
        assert_se(gpt_partition_label_valid("a") > 0);

        /* Empty string */
        assert_se(gpt_partition_label_valid("") >= 0);
}

TEST(gpt_partition_type_from_string_basic) {
        GptPartitionType t;
        int r;

        /* Try parsing a known type name */
        r = gpt_partition_type_from_string("x86-64-root", &t);
        if (r >= 0) {
                assert_se(streq(t.name, "x86-64-root"));
                assert_se(t.designator == PARTITION_ROOT);
        }
}

TEST(gpt_header_has_signature_basic) {
        GptHeader h = {};

        /* Empty header → no signature */
        assert_se(!gpt_header_has_signature(&h));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
