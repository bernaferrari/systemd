/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "btrfs-util.h"
#include "tests.h"

TEST(btrfs_validate_subvolume_name) {
        ASSERT_OK(btrfs_validate_subvolume_name("valid_name"));
        ASSERT_OK(btrfs_validate_subvolume_name("subvol1"));
        ASSERT_EQ(btrfs_validate_subvolume_name(""), -EINVAL);
        ASSERT_EQ(btrfs_validate_subvolume_name("."), -EINVAL);
        ASSERT_EQ(btrfs_validate_subvolume_name(".."), -EINVAL);
        ASSERT_EQ(btrfs_validate_subvolume_name("has/slash"), -EINVAL);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
