/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>

#include "mountpoint-util.h"
#include "string-util.h"
#include "tests.h"

TEST(fstype_is_network_check) {
        /* Various network filesystems */
        assert_se(fstype_is_network("nfs"));
        assert_se(fstype_is_network("nfs4"));
        assert_se(fstype_is_network("cifs"));
        assert_se(fstype_is_network("fuse.sshfs"));

        /* Additional non-database network fs */
        assert_se(fstype_is_network("davfs"));
        assert_se(fstype_is_network("glusterfs"));

        /* Non-network */
        assert_se(!fstype_is_network("ext4"));
        assert_se(!fstype_is_network("tmpfs"));
        assert_se(!fstype_is_network("proc"));
        assert_se(!fstype_is_network("9p"));
}

TEST(fstype_can_fmask_dmask_basic) {
        assert_se(fstype_can_fmask_dmask("vfat"));
        assert_se(!fstype_can_fmask_dmask("ext4"));
        assert_se(!fstype_can_fmask_dmask("tmpfs"));
}

TEST(path_below_api_vfs_various) {
        assert_se(path_below_api_vfs("/proc"));
        assert_se(path_below_api_vfs("/sys"));
        assert_se(path_below_api_vfs("/dev"));
        assert_se(path_below_api_vfs("/proc/1/mountinfo"));
        assert_se(path_below_api_vfs("/dev/null"));
        assert_se(!path_below_api_vfs("/home"));
        assert_se(!path_below_api_vfs("/var"));
        assert_se(!path_below_api_vfs("/etc"));
        assert_se(!path_below_api_vfs("/run"));
        assert_se(!path_below_api_vfs("/tmp"));
}

TEST(mount_propagation_flag_basic) {
        assert_se(streq(mount_propagation_flag_to_string(MS_SHARED), "shared"));
        assert_se(streq(mount_propagation_flag_to_string(MS_SLAVE), "slave"));
        assert_se(streq(mount_propagation_flag_to_string(MS_PRIVATE), "private"));

        unsigned long flag;
        assert_se(mount_propagation_flag_from_string("shared", &flag) >= 0);
        assert_se(flag == MS_SHARED);
        assert_se(mount_propagation_flag_from_string("slave", &flag) >= 0);
        assert_se(flag == MS_SLAVE);
        assert_se(mount_propagation_flag_from_string("private", &flag) >= 0);
        assert_se(flag == MS_PRIVATE);
        assert_se(mount_propagation_flag_from_string("invalid", &flag) < 0);

        assert_se(mount_propagation_flag_is_valid(MS_SHARED));
        assert_se(mount_propagation_flag_is_valid(MS_SLAVE));
        assert_se(mount_propagation_flag_is_valid(MS_PRIVATE));
        assert_se(mount_propagation_flag_is_valid(0));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
