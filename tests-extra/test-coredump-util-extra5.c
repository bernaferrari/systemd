/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "string-util.h"
#include "tests.h"
#include "coredump-util.h"

TEST(coredump_filter_to_from_string_basic) {
        assert_se(streq(coredump_filter_to_string(COREDUMP_FILTER_PRIVATE_ANONYMOUS), "private-anonymous"));
        assert_se(streq(coredump_filter_to_string(COREDUMP_FILTER_SHARED_ANONYMOUS), "shared-anonymous"));
        assert_se(streq(coredump_filter_to_string(COREDUMP_FILTER_PRIVATE_FILE_BACKED), "private-file-backed"));
        assert_se(streq(coredump_filter_to_string(COREDUMP_FILTER_SHARED_FILE_BACKED), "shared-file-backed"));
        assert_se(streq(coredump_filter_to_string(COREDUMP_FILTER_ELF_HEADERS), "elf-headers"));
        assert_se(streq(coredump_filter_to_string(COREDUMP_FILTER_PRIVATE_HUGE), "private-huge"));
        assert_se(streq(coredump_filter_to_string(COREDUMP_FILTER_SHARED_HUGE), "shared-huge"));
        assert_se(streq(coredump_filter_to_string(COREDUMP_FILTER_PRIVATE_DAX), "private-dax"));
        assert_se(streq(coredump_filter_to_string(COREDUMP_FILTER_SHARED_DAX), "shared-dax"));

        assert_se(coredump_filter_from_string("private-anonymous") == COREDUMP_FILTER_PRIVATE_ANONYMOUS);
        assert_se(coredump_filter_from_string("shared-anonymous") == COREDUMP_FILTER_SHARED_ANONYMOUS);
        assert_se(coredump_filter_from_string("elf-headers") == COREDUMP_FILTER_ELF_HEADERS);
        assert_se(coredump_filter_from_string("invalid") < 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
