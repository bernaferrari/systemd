/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "mstack.h"
#include "tests.h"

TEST(mstack_mount_type_to_string) {
        ASSERT_STREQ(mstack_mount_type_to_string(MSTACK_ROOT), "root");
        ASSERT_STREQ(mstack_mount_type_to_string(MSTACK_LAYER), "layer");
        ASSERT_STREQ(mstack_mount_type_to_string(MSTACK_RW), "rw");
        ASSERT_STREQ(mstack_mount_type_to_string(MSTACK_BIND), "bind");
        ASSERT_STREQ(mstack_mount_type_to_string(MSTACK_ROBIND), "robind");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
