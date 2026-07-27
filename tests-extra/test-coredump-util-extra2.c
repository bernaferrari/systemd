/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "coredump-util.h"
#include "tests.h"

TEST(coredump_filter_to_from_string) {
        /* Test known values */
        const char *s = coredump_filter_to_string(COREDUMP_FILTER_PRIVATE_ANONYMOUS);
        ASSERT_NOT_NULL(s);

        s = coredump_filter_to_string(COREDUMP_FILTER_SHARED_ANONYMOUS);
        ASSERT_NOT_NULL(s);

        s = coredump_filter_to_string(COREDUMP_FILTER_PRIVATE_FILE_BACKED);
        ASSERT_NOT_NULL(s);

        /* from_string */
        ASSERT_GE(coredump_filter_from_string("private-anonymous"), 0);
        ASSERT_GE(coredump_filter_from_string("shared-anonymous"), 0);
        ASSERT_GE(coredump_filter_from_string("private-file-backed"), 0);
        ASSERT_LT(coredump_filter_from_string("invalid"), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
