/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"
#include "mstack.h"

TEST(mstack_mount_type_to_string) {
        assert_se(streq(mstack_mount_type_to_string(MSTACK_ROOT), "root"));
        assert_se(streq(mstack_mount_type_to_string(MSTACK_LAYER), "layer"));
        assert_se(streq(mstack_mount_type_to_string(MSTACK_RW), "rw"));
        assert_se(streq(mstack_mount_type_to_string(MSTACK_BIND), "bind"));
        assert_se(streq(mstack_mount_type_to_string(MSTACK_ROBIND), "robind"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
