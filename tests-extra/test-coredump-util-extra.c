/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "coredump-util.h"
#include "tests.h"

TEST(coredump_filter_to_string) {
        ASSERT_STREQ(coredump_filter_to_string(COREDUMP_FILTER_PRIVATE_ANONYMOUS), "private-anonymous");
        ASSERT_STREQ(coredump_filter_to_string(COREDUMP_FILTER_SHARED_ANONYMOUS), "shared-anonymous");
        ASSERT_STREQ(coredump_filter_to_string(COREDUMP_FILTER_PRIVATE_FILE_BACKED), "private-file-backed");
        ASSERT_STREQ(coredump_filter_to_string(COREDUMP_FILTER_SHARED_FILE_BACKED), "shared-file-backed");
        ASSERT_STREQ(coredump_filter_to_string(COREDUMP_FILTER_ELF_HEADERS), "elf-headers");
        ASSERT_STREQ(coredump_filter_to_string(COREDUMP_FILTER_PRIVATE_HUGE), "private-huge");
        ASSERT_STREQ(coredump_filter_to_string(COREDUMP_FILTER_SHARED_HUGE), "shared-huge");
        ASSERT_STREQ(coredump_filter_to_string(COREDUMP_FILTER_PRIVATE_DAX), "private-dax");
        ASSERT_STREQ(coredump_filter_to_string(COREDUMP_FILTER_SHARED_DAX), "shared-dax");
}

TEST(coredump_filter_from_string) {
        ASSERT_EQ(coredump_filter_from_string("private-anonymous"), COREDUMP_FILTER_PRIVATE_ANONYMOUS);
        ASSERT_EQ(coredump_filter_from_string("shared-anonymous"), COREDUMP_FILTER_SHARED_ANONYMOUS);
        ASSERT_EQ(coredump_filter_from_string("elf-headers"), COREDUMP_FILTER_ELF_HEADERS);
        ASSERT_EQ(coredump_filter_from_string("invalid"), _COREDUMP_FILTER_INVALID);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
