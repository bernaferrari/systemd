/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "mountpoint-util.h"
#include "tests.h"
#include <sys/mount.h>

TEST(fstype_is_network) {
        /* Network filesystems */
        ASSERT_TRUE(fstype_is_network("nfs"));
        ASSERT_TRUE(fstype_is_network("nfs4"));
        ASSERT_TRUE(fstype_is_network("cifs"));
        ASSERT_TRUE(fstype_is_network("smb3"));
        ASSERT_TRUE(fstype_is_network("fuse.sshfs"));

        /* Non-network filesystems */
        ASSERT_FALSE(fstype_is_network("ext4"));
        ASSERT_FALSE(fstype_is_network("xfs"));
        ASSERT_FALSE(fstype_is_network("btrfs"));
        ASSERT_FALSE(fstype_is_network("tmpfs"));
}

TEST(fstype_is_ro) {
        /* Read-only filesystems */
        ASSERT_TRUE(fstype_is_ro("cramfs"));
        ASSERT_TRUE(fstype_is_ro("erofs"));
        ASSERT_TRUE(fstype_is_ro("iso9660"));

        /* Read-write filesystems */
        ASSERT_FALSE(fstype_is_ro("ext4"));
        ASSERT_FALSE(fstype_is_ro("tmpfs"));
}

TEST(mount_propagation_flag_to_string) {
        ASSERT_STREQ(mount_propagation_flag_to_string(MS_SHARED), "shared");
        ASSERT_STREQ(mount_propagation_flag_to_string(MS_SLAVE), "slave");
        ASSERT_STREQ(mount_propagation_flag_to_string(MS_PRIVATE), "private");
        ASSERT_STREQ(mount_propagation_flag_to_string(0), "");

        /* Invalid combination */
        ASSERT_NULL(mount_propagation_flag_to_string(MS_SHARED|MS_SLAVE));
}

TEST(mount_propagation_flag_from_string) {
        unsigned long flag;

        ASSERT_OK(mount_propagation_flag_from_string("shared", &flag));
        ASSERT_EQ(flag, (unsigned long) MS_SHARED);

        ASSERT_OK(mount_propagation_flag_from_string("slave", &flag));
        ASSERT_EQ(flag, (unsigned long) MS_SLAVE);

        ASSERT_OK(mount_propagation_flag_from_string("private", &flag));
        ASSERT_EQ(flag, (unsigned long) MS_PRIVATE);

        /* Empty string = 0 */
        ASSERT_OK(mount_propagation_flag_from_string("", &flag));
        ASSERT_EQ(flag, 0ul);

        /* Invalid */
        ASSERT_LT(mount_propagation_flag_from_string("invalid", &flag), 0);
}

TEST(mount_propagation_flag_is_valid) {
        ASSERT_TRUE(mount_propagation_flag_is_valid(0));
        ASSERT_TRUE(mount_propagation_flag_is_valid(MS_SHARED));
        ASSERT_TRUE(mount_propagation_flag_is_valid(MS_SLAVE));
        ASSERT_TRUE(mount_propagation_flag_is_valid(MS_PRIVATE));

        /* Invalid: combined flags */
        ASSERT_FALSE(mount_propagation_flag_is_valid(MS_SHARED|MS_SLAVE));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
