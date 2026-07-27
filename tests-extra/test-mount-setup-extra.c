/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "mount-setup.h"
#include "tests.h"

TEST(mount_point_is_api) {
        ASSERT_TRUE(mount_point_is_api("/proc"));
        ASSERT_TRUE(mount_point_is_api("/sys"));
        ASSERT_TRUE(mount_point_is_api("/dev"));
        ASSERT_TRUE(mount_point_is_api("/run"));
        ASSERT_FALSE(mount_point_is_api("/home"));
        ASSERT_FALSE(mount_point_is_api("/var"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
