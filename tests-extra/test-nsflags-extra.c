/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "nsflags.h"
#include "tests.h"

TEST(namespace_single_flag_to_string) {
        ASSERT_NOT_NULL(namespace_single_flag_to_string(CLONE_NEWNS));
        ASSERT_NOT_NULL(namespace_single_flag_to_string(CLONE_NEWUTS));
        ASSERT_NOT_NULL(namespace_single_flag_to_string(CLONE_NEWIPC));
        ASSERT_NOT_NULL(namespace_single_flag_to_string(CLONE_NEWUSER));
        ASSERT_NOT_NULL(namespace_single_flag_to_string(CLONE_NEWPID));
        ASSERT_NOT_NULL(namespace_single_flag_to_string(CLONE_NEWNET));
        ASSERT_NOT_NULL(namespace_single_flag_to_string(CLONE_NEWCGROUP));

        /* Invalid flag */
        ASSERT_NULL(namespace_single_flag_to_string(0));
        ASSERT_NULL(namespace_single_flag_to_string(UINT64_MAX));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
