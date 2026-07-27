/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>

#include "mountpoint-util.h"
#include "string-util.h"
#include "tests.h"

TEST(fstype_is_network) {
        assert_se(fstype_is_network("nfs"));
        assert_se(fstype_is_network("nfs4"));
        assert_se(fstype_is_network("cifs"));
        assert_se(fstype_is_network("smb3"));
        assert_se(fstype_is_network("sshfs"));

        /* fuse.nfs should also be network */
        assert_se(fstype_is_network("fuse.nfs"));

        /* Not network filesystems */
        assert_se(!fstype_is_network("ext4"));
        assert_se(!fstype_is_network("tmpfs"));
        assert_se(!fstype_is_network("vfat"));
}

TEST(fstype_can_fmask_dmask) {
        /* vfat definitely supports fmask/dmask */
        assert_se(fstype_can_fmask_dmask("vfat"));

        /* ext4 does not have fmask/dmask (has standard Unix perms) */
        assert_se(!fstype_can_fmask_dmask("ext4"));

        /* tmpfs doesn't have fmask/dmask */
        assert_se(!fstype_can_fmask_dmask("tmpfs"));
}

TEST(mount_propagation_flag_to_string) {
        assert_se(streq(mount_propagation_flag_to_string(MS_SHARED), "shared"));
        assert_se(streq(mount_propagation_flag_to_string(MS_SLAVE), "slave"));
        assert_se(streq(mount_propagation_flag_to_string(MS_PRIVATE), "private"));
        assert_se(streq(mount_propagation_flag_to_string(0), ""));

        /* Invalid combination returns NULL */
        assert_se(mount_propagation_flag_to_string(MS_SHARED|MS_SLAVE) == NULL);
}

TEST(mount_propagation_flag_from_string) {
        unsigned long flag;

        assert_se(mount_propagation_flag_from_string("shared", &flag) >= 0);
        assert_se(flag == MS_SHARED);

        assert_se(mount_propagation_flag_from_string("slave", &flag) >= 0);
        assert_se(flag == MS_SLAVE);

        assert_se(mount_propagation_flag_from_string("private", &flag) >= 0);
        assert_se(flag == MS_PRIVATE);

        /* Empty string → 0 */
        assert_se(mount_propagation_flag_from_string("", &flag) >= 0);
        assert_se(flag == 0);

        /* Invalid name */
        assert_se(mount_propagation_flag_from_string("invalid", &flag) == -EINVAL);
}

TEST(mount_propagation_flag_is_valid) {
        assert_se(mount_propagation_flag_is_valid(0));
        assert_se(mount_propagation_flag_is_valid(MS_SHARED));
        assert_se(mount_propagation_flag_is_valid(MS_PRIVATE));
        assert_se(mount_propagation_flag_is_valid(MS_SLAVE));

        /* Invalid flags */
        assert_se(!mount_propagation_flag_is_valid(MS_SHARED|MS_SLAVE));
        assert_se(!mount_propagation_flag_is_valid(999));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
